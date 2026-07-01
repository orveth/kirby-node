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
//!   (e) the minted `sk-` never appears on stdout/stderr (it only lands in the 0600 keyfile).
//! Teeth (a) write_key_atomic refuses to overwrite a DIFFERENT key and (b) the keyfile is
//! 0600 raw sk- (boot.rs compat) are the `src/funding.rs` unit teeth.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{InvoiceBehavior, InvoiceCreate, MockNode, RecoverResult, StatusStep};

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

// ---- create -> poll (the primary agent-native split path) ----------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_persists_invoice_state_and_binds_node_url() {
    let dir = temp_dir("create");
    let key_out = dir.join("brain.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        create: InvoiceCreate::Ok {
            invoice_id: "inv-XYZ".into(),
            bolt11: "lnbcCREATE".into(),
        },
        ..Default::default()
    })
    .await;

    let (code, stdout, _stderr) = run_fund_key(&[
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

    // F2: the invoice_id is persisted to a 0600 sidecar beside key_out (NOT the keyfile).
    let invoice_sidecar = dir.join("brain.key.invoice");
    assert_eq!(
        std::fs::read_to_string(&invoice_sidecar).unwrap().trim(),
        "inv-XYZ"
    );
    assert_eq!(
        file_mode(&invoice_sidecar),
        0o600,
        "the invoice_id sidecar is 0600"
    );
    // F9: the node_url is bound beside the (future) key.
    let url_sidecar = dir.join("brain.key.node_url");
    assert_eq!(
        std::fs::read_to_string(&url_sidecar).unwrap().trim(),
        node.url()
    );
    // The key itself does NOT exist yet (poll writes it).
    assert!(
        !key_out.exists(),
        "create does not write the key; poll does"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_mints_key_writes_0600_and_probes_balance() {
    let dir = temp_dir("poll");
    let key_out = dir.join("brain.key");
    // Persist an invoice_id so poll finds it without --invoice-id.
    std::fs::write(dir.join("brain.key.invoice"), "inv-POLL\n").unwrap();

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

    let (code, stdout, stderr) = run_fund_key(&[
        "poll",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_expired_maps_to_exit_3() {
    let dir = temp_dir("expired");
    let key_out = dir.join("brain.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        status_script: vec![StatusStep::terminal("expired")],
        ..Default::default()
    })
    .await;
    let (code, stdout, _e) = run_fund_key(&[
        "poll",
        "--invoice-id",
        "inv-exp",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
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
    let (code, stdout, _e) = run_fund_key(&[
        "poll",
        "--invoice-id",
        "inv-fail",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
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

    // Bind the node_url beside the key so F9 lets the topup proceed without --node-url.
    std::fs::write(dir.join("brain.key.node_url"), format!("{}\n", node.url())).unwrap();

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
    std::fs::write(
        dir.join("missing.key.node_url"),
        "https://api.routstr.com\n",
    )
    .unwrap();

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
    // The key is bound to routstr.com.
    std::fs::write(dir.join("brain.key.node_url"), "https://api.routstr.com\n").unwrap();

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
    std::fs::write(dir.join("brain.key.node_url"), format!("{}\n", node.url())).unwrap();

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

// ---- recover (break-glass) -----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_requires_break_glass_flag() {
    let dir = temp_dir("recover-gate");
    let key_out = dir.join("rec.key");
    // Without --break-glass -> refused (usage), no network call.
    let (code, stdout, _e) = run_fund_key(&[
        "recover",
        "--bolt11",
        "lnbcRECOVER",
        "--key-out",
        key_out.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 9,
        "recover without --break-glass is refused; stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "usage-error");
    assert!(!key_out.exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_with_break_glass_writes_key_and_warns() {
    let dir = temp_dir("recover-ok");
    let key_out = dir.join("rec.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        recover: RecoverResult::Key(Some("sk-recovered-key".into())),
        ..Default::default()
    })
    .await;
    node.set_balance_msats(7_000_000);

    let (code, stdout, stderr) = run_fund_key(&[
        "recover",
        "--bolt11",
        "lnbcRECOVER",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
        "--break-glass",
    ]);
    assert_eq!(
        code, 0,
        "recover with --break-glass writes the key; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(last_json(&stdout)["status"], "funded");
    // The recovered key landed 0600, raw.
    assert_eq!(
        std::fs::read_to_string(&key_out).unwrap(),
        "sk-recovered-key\n"
    );
    assert_eq!(file_mode(&key_out), 0o600);
    // A loud break-glass warning is on stderr; the key is NOT on stdout/stderr.
    assert!(
        stderr.to_lowercase().contains("warning"),
        "recover warns loudly on stderr"
    );
    assert!(!stdout.contains("sk-recovered-key") && !stderr.contains("sk-recovered-key"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_unrecoverable_maps_to_failed_payment() {
    let dir = temp_dir("recover-none");
    let key_out = dir.join("rec.key");
    let node = MockNode::start_with_invoices(InvoiceBehavior {
        recover: RecoverResult::Key(None), // node cannot recover it
        ..Default::default()
    })
    .await;
    let (code, stdout, _e) = run_fund_key(&[
        "recover",
        "--bolt11",
        "lnbcNONE",
        "--key-out",
        key_out.to_str().unwrap(),
        "--node-url",
        &node.url(),
        "--break-glass",
    ]);
    assert_eq!(
        code, 4,
        "an unrecoverable key -> failed-payment (exit 4); stdout:\n{stdout}"
    );
    assert_eq!(last_json(&stdout)["status"], "failed-payment");
    assert!(!key_out.exists());
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
