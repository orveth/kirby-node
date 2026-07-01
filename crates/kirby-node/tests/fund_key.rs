//! End-to-end tests for the `fund-key` funding flow (Layer 0 + Layer 1) against the offline
//! [`common::MockNode`] (a hand-rolled loopback HTTP mock — NEVER the live api.routstr.com).
//! They drive the ACTUAL `kirby-node` binary (via `CARGO_BIN_EXE_kirby-node`) so the JSON
//! surface, the exit-code contract (F10), the early-bolt11 ordering, the 0600 keyfile +
//! sidecars (F2/F8/F9), and the Layer-1 emit-config are all exercised as a driving agent
//! sees them. The library-level funding functions are unit-tested in `src/funding.rs`; the
//! security teeth that live in the CLI wiring are asserted here.
//!
//! Security teeth (each RED-on-revert — the comment states how reverting makes it RED):
//!   (c) topup without a bearer key is refused (purpose=topup requires api_key);
//!   (d) balance/topup use the BOUND node_url — a mismatched override without the flag is
//!       refused (F9);
//!   (e) the minted `sk-` never appears on stdout/stderr (it only lands in the 0600 keyfile);
//!   (#1) the capability invoice_id never appears on stdout from `create`;
//!   (#4) the BOUND node_url sidecar is written only AFTER the key lands (not at create);
//!   (#6) an https-or-loopback check refuses a bearer call to a plaintext non-loopback node;
//!   (#8) `poll` propagates a 401/403 as an auth failure, not a misleading unpaid-timeout;
//!   (F9r) balance refuses a SYMLINKED or WRONG-MODE node_url sidecar (hardened read, fail closed);
//!   (F6p) `poll` refuses a plaintext non-loopback RESOLVED node_url (poll's require_secure gate);
//!   (F7x) `create` refuses (does NOT clobber) an existing pending sidecar (O_EXCL, no strand).
//! Teeth (a) write_key_atomic refuses to overwrite a DIFFERENT key, (b) the keyfile is
//! 0600 raw sk- (boot.rs compat), plus the write_sidecar/idempotent-read/redaction/hardened-read/
//! O_EXCL-pending/inode-cleanup teeth are the `src/funding.rs` unit teeth.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{InvoiceBehavior, InvoiceCreate, MockNode, StatusStep};

/// The compiled `kirby-node` binary under test (cargo sets this env for integration tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_kirby-node")
}

/// A fresh unique temp dir for one test's keyfiles/config (removed by the caller).
fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("kirby-fundkey-it-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `kirby-node fund-key <args...>` and return (exit_code, stdout, stderr). Tracing goes
/// to stderr (RUST_LOG defaults off); the JSON contract is on stdout.
fn run_fund_key(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin())
        .arg("fund-key")
        .args(args)
        .output()
        .expect("spawn kirby-node");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The last non-empty stdout line parsed as JSON (the final result object).
fn last_json(stdout: &str) -> serde_json::Value {
    let line = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("{}");
    serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("stdout tail is not JSON: {e}\nstdout:\n{stdout}"))
}

fn file_mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Write the 0600 pending-invoice sidecar `create` would write (JSON: invoice_id + node_url),
/// so a `poll` test can resolve both without a live `create`.
fn write_pending(key_out: &Path, invoice_id: &str, node_url: &str) {
    let sidecar = key_out.with_file_name(format!(
        "{}.invoice",
        key_out.file_name().unwrap().to_str().unwrap()
    ));
    let json = serde_json::json!({ "invoice_id": invoice_id, "node_url": node_url }).to_string();
    std::fs::write(&sidecar, format!("{json}\n")).unwrap();
    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
}

// ---- create -> poll (the primary agent-native split path) ----------------------------

/// TOOTH (#1 + #4): `create` persists the invoice_id + node_url to a 0600 pending sidecar but
/// (a) NEVER prints the capability invoice_id on stdout, and (b) does NOT write the BOUND
/// node_url sidecar (that lands only after `poll` writes the key). Reverting the create handler
/// to emit `invoice_id` in its JSON makes the #1 assertion RED; reverting it to write the bound
/// node_url binding at create makes the #4 assertion RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_persists_pending_state_without_leaking_invoice_id_or_binding() {
    let dir = temp_dir("create");
    let key_out = dir.join("brain.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        create: InvoiceCreate::Ok {
            invoice_id: "inv-XYZ-CAP".into(),
            bolt11: "lnbcCREATE".into(),
        },
        ..Default::default()
    })
    .await;

    let (code, stdout, stderr) = run_fund_key(&[
        "create",
        "--amount-sats",
        "2000",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
    ]);
    assert_eq!(code, 0, "create is non-blocking success; stdout:\n{stdout}");
    let j = last_json(&stdout);
    assert_eq!(j["status"], "invoice-created");
    assert_eq!(j["bolt11"], "lnbcCREATE");
    assert_eq!(
        j["amount_sats"], 2000,
        "the response echoes the requested amount"
    );

    // (#1) the capability invoice_id is NEVER on stdout/stderr, nor as a JSON field.
    assert!(
        j.get("invoice_id").is_none(),
        "create must NOT carry the invoice_id in its JSON"
    );
    assert!(
        !stdout.contains("inv-XYZ-CAP") && !stderr.contains("inv-XYZ-CAP"),
        "the invoice_id must not leak to stdout/stderr"
    );

    // F2: the invoice_id + node_url are persisted to a 0600 JSON sidecar beside key_out.
    let invoice_sidecar = dir.join("brain.key.invoice");
    let pending: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&invoice_sidecar).unwrap().trim()).unwrap();
    assert_eq!(pending["invoice_id"], "inv-XYZ-CAP");
    assert_eq!(pending["node_url"], node.url());
    assert_eq!(
        file_mode(&invoice_sidecar),
        0o600,
        "the pending-invoice sidecar is 0600"
    );

    // (#4) the BOUND node_url sidecar is NOT written at create (only after the key lands).
    let url_sidecar = dir.join("brain.key.node_url");
    assert!(
        !url_sidecar.exists(),
        "the bound node_url sidecar must not exist before the key is written (#4)"
    );
    // The key itself does NOT exist yet (poll writes it).
    assert!(
        !key_out.exists(),
        "create does not write the key; poll does"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `create` refuses to write a NEW invoice onto a path that already holds a key (F7): a usage
/// error, no network call. Reverting the `key_out.exists()` guard makes this RED (a second
/// invoice would be created against an already-funded key path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_refuses_an_existing_key_out() {
    let dir = temp_dir("create-exists");
    let key_out = dir.join("brain.key");
    std::fs::write(&key_out, "sk-already-here\n").unwrap();
    // A closed loopback url: if the guard were reverted the failure would be a NETWORK error
    // (refused connect), never a live call — but the guard makes it a clean usage refusal first.
    let (code, stdout, _e) = run_fund_key(&[
        "create",
        "--amount-sats",
        "2000",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        "http://127.0.0.1:1",
    ]);
    assert_eq!(
        code, 9,
        "create onto an existing key path is a usage refusal; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "usage-error");
    // The existing key is untouched.
    assert_eq!(
        std::fs::read_to_string(&key_out).unwrap().trim(),
        "sk-already-here"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_mints_key_writes_0600_and_probes_balance() {
    let dir = temp_dir("poll");
    let key_out = dir.join("brain.key");

    let node = MockNode::start_with_invoices(InvoiceBehavior {
        // First poll pending, second poll pays + mints the key; balance probes 1234 sats.
        status_script: vec![
            StatusStep::pending(),
            StatusStep::paid_with_key("sk-minted-777"),
        ],
        ..Default::default()
    })
    .await;
    node.set_balance_msats(1_234_000);
    // Persist the pending sidecar (invoice_id + node_url) so poll finds BOTH — no --invoice-id,
    // no --node-url.
    write_pending(&key_out, "inv-POLL", &node.url());

    let (code, stdout, stderr) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(
        code, 0,
        "poll succeeds when the key mints; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let j = last_json(&stdout);
    assert_eq!(j["status"], "funded");
    assert_eq!(
        j["balance_sats"], 1234,
        "F6: the reported balance is the PROBED balance"
    );

    // (b) boot.rs compat: the keyfile is 0600 and holds ONLY the raw sk- (+ newline).
    let raw = std::fs::read_to_string(&key_out).unwrap();
    assert_eq!(raw, "sk-minted-777\n");
    assert_eq!(file_mode(&key_out), 0o600);

    // (#4) the bound node_url sidecar was written (after the key), and the pending sidecar was
    // cleared once the key landed (the capability is no longer needed).
    let url_sidecar = dir.join("brain.key.node_url");
    assert_eq!(
        std::fs::read_to_string(&url_sidecar).unwrap().trim(),
        node.url()
    );
    assert!(
        !dir.join("brain.key.invoice").exists(),
        "the pending-invoice sidecar is cleared once the key is written"
    );

    // (e) the minted sk- NEVER appears on stdout or stderr.
    assert!(
        !stdout.contains("sk-minted-777"),
        "the sk- must not leak to stdout"
    );
    assert!(
        !stderr.contains("sk-minted-777"),
        "the sk- must not leak to stderr"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// TOOTH (#8): `poll` propagates a 401/403 IMMEDIATELY as an auth failure (exit 6), NOT a
/// misleading unpaid-timeout (exit 2). Reverting `poll_invoice` to swallow every non-Ok status
/// into a transient-retry-then-UnpaidTimeout makes this RED (it would loop and exit 2). The
/// status endpoint returns 401 on every poll.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_propagates_auth_error_not_timeout() {
    let dir = temp_dir("poll-auth");
    let key_out = dir.join("brain.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        status_http: Some(401),
        ..Default::default()
    })
    .await;
    write_pending(&key_out, "inv-AUTH", &node.url());

    let (code, stdout, _stderr) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(
        code, 6,
        "a 401 on the status poll is an auth failure (exit 6), not a timeout; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "auth-failure");
    assert!(!key_out.exists(), "no key on an auth failure");
    std::fs::remove_dir_all(&dir).ok();
}

/// `poll` refuses a `--node-url` that differs from the pending sidecar's node_url unless the
/// override flag is set (the invoice lives on the node it was created against). Reverting
/// `resolve_pending_node_url` (using the override unconditionally) makes this RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_refuses_mismatched_node_url_without_override() {
    let dir = temp_dir("poll-mismatch");
    let key_out = dir.join("brain.key");
    // The pending sidecar pins one node; a different --node-url without the flag is refused.
    write_pending(&key_out, "inv-M", "https://api.routstr.com");
    let (code, stdout, _e) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        "https://evil.example.com",
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(
        code, 9,
        "a mismatched --node-url without the override is a usage refusal; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "usage-error");
    std::fs::remove_dir_all(&dir).ok();
}

/// `poll` with no pending sidecar (and no `create` first) is a usage error, not a crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_without_pending_state_is_usage_error() {
    let dir = temp_dir("poll-nopending");
    let key_out = dir.join("brain.key");
    let (code, stdout, _e) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(
        code, 9,
        "no pending invoice state is a usage error; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "usage-error");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_expired_maps_to_exit_3() {
    let dir = temp_dir("expired");
    let key_out = dir.join("brain.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        status_script: vec![StatusStep::terminal("expired")],
        ..Default::default()
    })
    .await;
    write_pending(&key_out, "inv-exp", &node.url());
    let (code, stdout, _e) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(code, 3, "expired -> exit 3; stdout:\n{stdout}");
    assert_eq!(last_json(&stdout)["status"], "expired");
    assert!(
        !key_out.exists(),
        "no key is written on a terminal-fail status"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_failed_maps_to_exit_4() {
    let dir = temp_dir("failed");
    let key_out = dir.join("brain.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        status_script: vec![StatusStep::terminal("failed")],
        ..Default::default()
    })
    .await;
    write_pending(&key_out, "inv-fail", &node.url());
    let (code, stdout, _e) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(code, 4, "failed -> exit 4; stdout:\n{stdout}");
    assert_eq!(last_json(&stdout)["status"], "failed-payment");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- provision (one-shot) + Layer 1 emit-config --------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_emits_bolt11_early_then_funds_and_writes_config() {
    let dir = temp_dir("provision");
    let key_out = dir.join("brain.key");
    let config_out = dir.join("agent.toml");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        create: InvoiceCreate::Ok {
            invoice_id: "inv-PROV".into(),
            bolt11: "lnbcPROVISION".into(),
        },
        status_script: vec![
            StatusStep::pending(),
            StatusStep::paid_with_key("sk-prov-key"),
        ],
        ..Default::default()
    })
    .await;
    node.set_balance_msats(50_000_000); // 50_000 sats confirmed

    let (code, stdout, stderr) = run_fund_key(&[
        "provision",
        "--amount-sats",
        "50000",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
        "--timeout-secs",
        "60",
        "--emit-config",
        config_out.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 0,
        "provision funds; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // F10: the bolt11 line is emitted BEFORE the funded line (early JSONL ordering).
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        first["status"], "invoice-created",
        "the bolt11 line comes first"
    );
    assert_eq!(first["bolt11"], "lnbcPROVISION");
    assert!(
        first.get("invoice_id").is_none(),
        "the early line must NOT carry the bearer invoice_id"
    );
    let funded = last_json(&stdout);
    assert_eq!(funded["status"], "funded");
    assert_eq!(funded["balance_sats"], 50000);

    // (e) the sk- never leaks.
    assert!(!stdout.contains("sk-prov-key") && !stderr.contains("sk-prov-key"));

    // Layer 1: the emitted config is a valid minimal routstr_key agent config whose
    // treasury initial_sats is the CONFIRMED probed balance (F6), pointing at key_out.
    let toml = std::fs::read_to_string(&config_out).unwrap();
    assert!(toml.contains("workload = \"capable\""));
    assert!(toml.contains("backend = \"routstr_key\""));
    assert!(toml.contains(&format!("api_key_path = \"{}\"", key_out.display())));
    assert!(toml.contains(&format!("node_url = \"{}\"", node.url())));
    assert!(
        toml.contains("initial_sats = 50000"),
        "treasury seeded from the probed balance (F6)"
    );
    // The bearer key is NEVER inlined into the config.
    assert!(
        !toml.contains("sk-prov-key"),
        "the config must not inline the bearer key"
    );

    // The emitted config parses AND validates as a runnable Standalone agent config
    // (KirbyConfig::load validates for ConfigRole::Standalone — the full money-path battery).
    kirby_node::config::KirbyConfig::load(&config_out)
        .expect("emitted config loads + validates as a runnable single agent");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_emit_config_fits_max_cost_to_a_tiny_balance() {
    // A tiny funded balance (below the default 64-sat per-call cap) must still emit a config
    // that VALIDATES: the per-think cap is fit to the balance so `max_cost_sats <= initial_sats`.
    let dir = temp_dir("tiny");
    let key_out = dir.join("brain.key");
    let config_out = dir.join("agent.toml");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        status_script: vec![StatusStep::paid_with_key("sk-tiny-key")],
        ..Default::default()
    })
    .await;
    node.set_balance_msats(10_000); // 10 sats confirmed (< 64)

    let (code, stdout, stderr) = run_fund_key(&[
        "provision",
        "--amount-sats",
        "10",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
        "--timeout-secs",
        "60",
        "--emit-config",
        config_out.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 0,
        "tiny provision funds; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let toml = std::fs::read_to_string(&config_out).unwrap();
    assert!(
        toml.contains("initial_sats = 10"),
        "seeded from the 10-sat probed balance"
    );
    assert!(
        toml.contains("max_cost_sats = 10"),
        "the per-think cap is fit to the tiny balance"
    );
    // Crucially, the emitted config still validates (max_cost_sats <= initial_sats).
    kirby_node::config::KirbyConfig::load(&config_out)
        .expect("a tiny-balance emitted config still validates");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- topup (bearer-authed, balance-rise confirmation) --------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn topup_authenticates_with_key_and_confirms_credit() {
    let dir = temp_dir("topup");
    let key_path = dir.join("brain.key");
    std::fs::write(&key_path, "sk-existing-key\n").unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let node = MockNode::start_with_invoices(InvoiceBehavior {
        create: InvoiceCreate::Ok {
            invoice_id: "inv-TOPUP".into(),
            bolt11: "lnbcTOPUP".into(),
        },
        // The status poll stays pending (a topup mints no key); the credit lands as a
        // balance RAISE on the second poll step.
        status_script: vec![
            StatusStep::pending(),
            StatusStep::credited(9_000_000), // -> 9000 sats after credit
        ],
        ..Default::default()
    })
    .await;
    node.set_balance_msats(1_000_000); // 1000 sats before topup

    // Bind the node_url beside the key so F9 lets the topup proceed without --node-url. The
    // binding is 0600 (as `write_node_url_binding` always writes it); the hardened sidecar
    // reader refuses a wrong-mode binding, so a bare 0644 `write` would fail closed here.
    let binding = dir.join("brain.key.node_url");
    std::fs::write(&binding, format!("{}\n", node.url())).unwrap();
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code, stdout, stderr) = run_fund_key(&[
        "topup",
        "--amount-sats",
        "8000",
        "--key-path",
        key_path.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(
        code, 0,
        "topup confirms the credit; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The bolt11 is emitted early; the final line reports the new probed balance.
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(lines[0]).unwrap()["bolt11"],
        "lnbcTOPUP"
    );
    assert_eq!(
        last_json(&stdout)["balance_sats"],
        9000,
        "the new balance after the credit"
    );

    // The create invoice was purpose=topup AND carried the bearer key on Authorization.
    let create_req = node
        .first_request_matching("/v1/balance/lightning/invoice")
        .expect("a create-invoice request was sent");
    let body: serde_json::Value = serde_json::from_slice(&create_req.body).unwrap();
    assert_eq!(
        body["purpose"], "topup",
        "the topup invoice uses purpose=topup"
    );
    assert_eq!(
        create_req.authorization.as_deref(),
        Some("Bearer sk-existing-key"),
        "the topup invoice is authenticated with the existing bearer key"
    );
    // (e) the key never leaks to stdout/stderr.
    assert!(!stdout.contains("sk-existing-key") && !stderr.contains("sk-existing-key"));

    std::fs::remove_dir_all(&dir).ok();
}

/// TOOTH (c): topup without a bearer key is refused (purpose=topup REQUIRES api_key).
/// Reverting the guard in `funding::create_invoice` (the `purpose=="topup" && api_key.is_none()`
/// check) — or letting the CLI proceed without loading the key — makes this RED: the flow
/// would send an UNAUTHENTICATED topup invoice (or panic on the missing key) instead of a
/// clean usage refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn topup_without_a_bearer_key_is_refused() {
    let dir = temp_dir("topup-nokey");
    let key_path = dir.join("missing.key"); // does not exist
                                            // Bind a url so F9 is satisfied and the failure is specifically the missing bearer.
                                            // The binding is 0600 (the hardened reader refuses a wrong-mode binding), so the
                                            // failure is the missing bearer key, not a wrong-mode sidecar.
    let binding = dir.join("missing.key.node_url");
    std::fs::write(&binding, "https://api.routstr.com\n").unwrap();
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code, stdout, _stderr) = run_fund_key(&[
        "topup",
        "--amount-sats",
        "1000",
        "--key-path",
        key_path.to_str().unwrap(),
    ]);
    // Loading the (absent) key fails as an auth error BEFORE any network call.
    assert_eq!(
        code, 6,
        "a topup with no usable key is an auth failure; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "auth-failure");
    std::fs::remove_dir_all(&dir).ok();
}

/// TOOTH (d): balance/topup use the BOUND node_url — a mismatched override without the
/// explicit flag is refused (F9). Reverting `funding::resolve_bound_node_url` (returning the
/// override unconditionally) makes this RED: the bearer key would be sent to an arbitrary
/// server. With `--allow-node-url-override` the override is permitted (and warned).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balance_refuses_mismatched_node_url_without_override() {
    let dir = temp_dir("bind-refuse");
    let key_path = dir.join("brain.key");
    std::fs::write(&key_path, "sk-bound-key\n").unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // The key is bound to routstr.com (0600, as production writes it — the hardened reader
    // refuses a wrong-mode binding, so the refusal below is the mismatch, not a bad mode).
    let binding = dir.join("brain.key.node_url");
    std::fs::write(&binding, "https://api.routstr.com\n").unwrap();
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();

    // A DIFFERENT --node-url without the flag -> refused (usage error, before any network).
    let (code, stdout, _e) = run_fund_key(&[
        "balance",
        "--key-path",
        key_path.to_str().unwrap(),
        "--node-url",
        "https://evil.example.com",
    ]);
    assert_eq!(
        code, 9,
        "a mismatched override without the flag is a usage refusal; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "usage-error");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balance_uses_bound_url_and_reads_sats() {
    let dir = temp_dir("balance-ok");
    let key_path = dir.join("brain.key");
    std::fs::write(&key_path, "sk-balance-key\n").unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let node = MockNode::start_with_invoices(InvoiceBehavior::default()).await;
    node.set_balance_msats(4_242_000); // 4242 sats
                                       // Bind the mock's url so balance needs no --node-url and never risks a wrong server.
                                       // 0600, as `write_node_url_binding` writes it (the hardened reader refuses 0644).
    let binding = dir.join("brain.key.node_url");
    std::fs::write(&binding, format!("{}\n", node.url())).unwrap();
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code, stdout, stderr) =
        run_fund_key(&["balance", "--key-path", key_path.to_str().unwrap()]);
    assert_eq!(
        code, 0,
        "balance reads; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(last_json(&stdout)["balance_sats"], 4242);
    // The probe authenticated with the bearer key, sent to the BOUND url.
    let req = node
        .first_request_matching("/v1/balance/info")
        .expect("a balance-info request");
    assert_eq!(req.authorization.as_deref(), Some("Bearer sk-balance-key"));
    assert!(!stdout.contains("sk-balance-key") && !stderr.contains("sk-balance-key"));
    std::fs::remove_dir_all(&dir).ok();
}

// ---- https-before-bearer enforcement (#6) --------------------------------------------

/// TOOTH (#6): a bearer call to a plaintext NON-loopback node_url is refused (usage error, exit
/// 9) BEFORE any network call — a bearer `sk-` must never cross plaintext http. Reverting the
/// `require_secure_node_url` call sites in `funding.rs` makes this RED: `balance` would attempt
/// the bearer call over plain http (exit != 9). `balance` is the smallest bearer call. The
/// bound node is a plaintext-http NON-loopback address in TEST-NET-1 (192.0.2.0/24, RFC 5737,
/// unroutable) so that even a REVERTED build never reaches a real host — the point is the
/// refusal, and the address is guaranteed to belong to no real service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balance_refuses_plaintext_nonloopback_node_url() {
    let dir = temp_dir("http-refuse");
    let key_path = dir.join("brain.key");
    std::fs::write(&key_path, "sk-plaintext-key\n").unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // A plaintext-http NON-loopback host (TEST-NET-1, unroutable — never a real service). The
    // binding is 0600 (as production writes it) so the flow READS it and reaches the https-guard
    // — the target of this tooth. (A wrong-mode binding would fail closed at the hardened read
    // first, exit 8, masking the https-guard; that fail-closed read is F9r's tooth.)
    let binding = dir.join("brain.key.node_url");
    std::fs::write(&binding, "http://192.0.2.1\n").unwrap();
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code, stdout, _e) = run_fund_key(&["balance", "--key-path", key_path.to_str().unwrap()]);
    assert_eq!(
        code, 9,
        "a plaintext non-loopback bearer target is a usage refusal; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "usage-error");
    // The bearer key never left the machine (the refusal happens with no network call at all).
    std::fs::remove_dir_all(&dir).ok();
}

// ---- network failure exit code -------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_against_a_closed_node_is_network_failure() {
    let dir = temp_dir("closed");
    let key_out = dir.join("brain.key");
    // Bind then drop a listener -> nothing is listening -> connect refused.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let (code, stdout, _e) = run_fund_key(&[
        "create",
        "--amount-sats",
        "1000",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &format!("http://127.0.0.1:{port}"),
    ]);
    assert_eq!(
        code, 5,
        "a connect failure -> network-failure (exit 5); stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "network-failure");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- hardened sidecar reads + O_EXCL stranding (F9r / F6p / F7x) ----------------------

/// TOOTH (F9r): `balance` refuses a SYMLINKED or WRONG-MODE `<key>.node_url` binding through
/// the CLI. The binding decides where the bearer `sk-` is sent, so `balance` resolves it via
/// the hardened sidecar reader (`resolve_bound_node_url` -> `read_node_url_binding` ->
/// `read_sidecar_hardened` -> `read_regular_0600_nofollow`): a symlink fails the `O_NOFOLLOW`
/// open, a wrong-mode file fails the `fstat` mode==0600 check, and either surfaces as a
/// KEY_WRITE_FAILURE (exit 8) BEFORE the key is loaded or any network call is made — never
/// following the tampered binding to a different server.
///
/// RED-on-revert: reverting `read_sidecar_hardened` / `read_regular_0600_nofollow` to a plain
/// `std::fs::read_to_string` makes this RED — the symlink would be FOLLOWED (reading the
/// planted target) and the 0644 file TRUSTED, so `resolve_bound_node_url` would return the
/// tampered url and `balance` would carry on (exit != 8). Both planted targets hold a plaintext
/// NON-loopback url (TEST-NET-1, unroutable), so even a reverted build never reaches a real
/// host — it would refuse at the https-guard (exit 9), still != 8 (a clean RED).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balance_refuses_symlinked_or_wrong_mode_node_url_binding() {
    let dir = temp_dir("bind-hardened");
    let key_path = dir.join("brain.key");
    std::fs::write(&key_path, "sk-hardened-key\n").unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let binding = dir.join("brain.key.node_url");

    // (1) A SYMLINKED binding -> refused (fail closed), never followed to the planted target.
    // The target holds a plaintext non-loopback url so a reverted (followed) read cannot reach
    // a real server (it would refuse at the https-guard), and the point — the refusal — holds.
    let evil = dir.join("evil-url.txt");
    std::fs::write(&evil, "http://192.0.2.1\n").unwrap();
    std::os::unix::fs::symlink(&evil, &binding).unwrap();
    let (code, stdout, _e) = run_fund_key(&["balance", "--key-path", key_path.to_str().unwrap()]);
    assert_eq!(
        code, 8,
        "a symlinked node_url binding is a key-write-failure (fail closed), never followed; \
         stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "key-write-failure");
    std::fs::remove_file(&binding).unwrap();

    // (2) A WRONG-MODE (0644) binding -> refused (fail closed), never trusted.
    std::fs::write(&binding, "http://192.0.2.1\n").unwrap();
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, stdout, _e) = run_fund_key(&["balance", "--key-path", key_path.to_str().unwrap()]);
    assert_eq!(
        code, 8,
        "a wrong-mode (0644) node_url binding is a key-write-failure (fail closed); \
         stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "key-write-failure");

    std::fs::remove_dir_all(&dir).ok();
}

/// TOOTH (F6p): `poll` refuses a plaintext NON-loopback RESOLVED node_url through the CLI. The
/// pending sidecar pins the node the invoice was created against; `poll` reads it and calls
/// `poll_invoice`, which enforces the ONE https-or-loopback transport policy
/// (`require_secure_node_url`) BEFORE building the status URL (the `invoice_id` is a bearer
/// capability on the create path — a poll exchanges it for the `sk-`, so it must never cross
/// plaintext non-loopback http). Here the pending node_url is `http://192.0.2.1` (TEST-NET-1,
/// unroutable) so even a reverted build never touches a real server.
///
/// RED-on-revert: removing the `require_secure_node_url(node_url)?` call at the top of
/// `poll_invoice` makes this RED — `poll` would proceed to send the capability `invoice_id`
/// to a plaintext non-loopback host (a connect attempt -> network-failure exit 5, or worse a
/// real leak against a routable host), instead of the clean usage refusal (exit 9) with no
/// network call at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_refuses_plaintext_nonloopback_resolved_node_url() {
    let dir = temp_dir("poll-http");
    let key_out = dir.join("brain.key");
    // A pending sidecar pinning a plaintext NON-loopback host (TEST-NET-1, never a real
    // service). No --node-url: the resolved url is exactly this tampered/unsafe pending node_url.
    write_pending(&key_out, "inv-HTTP-CAP", "http://192.0.2.1");

    let (code, stdout, _e) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(
        code, 9,
        "a plaintext non-loopback resolved node_url is a usage refusal (poll's https-guard), \
         with NO network call; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "usage-error");
    // The capability invoice_id never left the machine, and no key was written.
    assert!(
        !key_out.exists(),
        "no key is written on the https-guard refusal"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// TOOTH (F7x): the FULL stranding scenario end-to-end (the important one). A first `create`
/// writes the 0600 pending sidecar; a SECOND `create` on the SAME `--key-out` REFUSES (exit 9)
/// and does NOT clobber the pending capability, pointing the operator at `poll`; THEN `poll`
/// RESUMES from the existing pending sidecar and PROVISIONS the key (the mock pays the invoice).
/// This proves a paid-but-unpolled invoice is never stranded by a re-`create`.
///
/// Two guards defend this behavior, in order: the CLI's `refuse_if_pending_invoice` (main.rs,
/// checked before any network call) is the FIRST to fire, and `write_invoice_state`'s O_EXCL
/// create-new (`write_sidecar_exclusive`) is the belt-and-suspenders backstop that refuses the
/// clobber even if the pre-check were bypassed. Because both hold, this end-to-end tooth stays
/// green while EITHER stands; the O_EXCL guard is additionally isolated RED-on-revert by the
/// `funding.rs` unit tooth `write_invoice_state_refuses_an_existing_pending_sidecar` (reverting
/// O_EXCL to the overwriting `write_sidecar` flips THAT unit tooth RED). RED-on-revert here:
/// reverting BOTH the `refuse_if_pending_invoice` pre-check AND O_EXCL makes the second create
/// overwrite the pending sidecar (its invoice_id changes) — flipping the "unchanged invoice_id"
/// assertion RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_refuses_second_create_then_poll_resumes_and_provisions() {
    let dir = temp_dir("strand");
    let key_out = dir.join("brain.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        create: InvoiceCreate::Ok {
            invoice_id: "inv-F7X-FIRST".into(),
            bolt11: "lnbcFIRST".into(),
        },
        // The resume poll: first pending, then paid + minted key.
        status_script: vec![
            StatusStep::pending(),
            StatusStep::paid_with_key("sk-strand-key"),
        ],
        ..Default::default()
    })
    .await;
    node.set_balance_msats(7_777_000); // 7777 sats confirmed after payment

    // (1) First create: writes the 0600 pending sidecar (invoice_id + node_url), no key yet.
    let (code, stdout, _e) = run_fund_key(&[
        "create",
        "--amount-sats",
        "2000",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
    ]);
    assert_eq!(code, 0, "the first create succeeds; stdout:\n{stdout}");
    assert_eq!(last_json(&stdout)["status"], "invoice-created");
    let invoice_sidecar = dir.join("brain.key.invoice");
    let first: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&invoice_sidecar).unwrap().trim()).unwrap();
    assert_eq!(
        first["invoice_id"], "inv-F7X-FIRST",
        "the pending sidecar holds the first invoice's capability"
    );

    // (2) Second create on the SAME key-out: REFUSED, and the pending sidecar is UNCHANGED
    // (the paid-but-unpolled capability is never clobbered — no stranding).
    let (code, stdout, _e) = run_fund_key(&[
        "create",
        "--amount-sats",
        "2000",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
    ]);
    assert_eq!(
        code, 9,
        "a second create over a pending sidecar is a usage refusal; stdout:\n{stdout}"
    );
    let j = last_json(&stdout);
    assert_eq!(j["status"], "usage-error");
    assert!(
        j["error"].as_str().unwrap_or("").contains("poll"),
        "the refusal points the operator at `poll` to resume; error: {}",
        j["error"]
    );
    let after: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&invoice_sidecar).unwrap().trim()).unwrap();
    assert_eq!(
        after["invoice_id"], "inv-F7X-FIRST",
        "the pending sidecar's capability is UNCHANGED after the refused second create (no clobber)"
    );

    // (3) Poll resumes from the existing pending sidecar and provisions the key.
    let (code, stdout, stderr) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--timeout-secs",
        "60",
    ]);
    assert_eq!(
        code, 0,
        "poll resumes the pending invoice and mints the key; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let j = last_json(&stdout);
    assert_eq!(j["status"], "funded");
    assert_eq!(j["balance_sats"], 7777, "the probed balance after payment");

    // The 0600 key landed, and the pending capability was cleared once it did.
    let raw = std::fs::read_to_string(&key_out).unwrap();
    assert_eq!(raw, "sk-strand-key\n");
    assert_eq!(file_mode(&key_out), 0o600, "the minted key is 0600");
    assert!(
        !invoice_sidecar.exists(),
        "the pending sidecar is cleared once the key is written"
    );
    // The minted key never leaks.
    assert!(!stdout.contains("sk-strand-key") && !stderr.contains("sk-strand-key"));

    std::fs::remove_dir_all(&dir).ok();
}
