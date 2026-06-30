//! Bootstrap a prepaid Routstr API key by paying a Lightning invoice to the node (the
//! mint-independent funding path for `backend = "routstr_key"`). It creates an invoice
//! (`POST /v1/balance/lightning/invoice` with `purpose: "create"`), PRINTS the bolt11 for
//! a human to pay, polls the invoice status until the node mints the key, and writes the
//! returned `sk-…` bearer key to a keyfile (0600) that `brain.api_key_path` then points at.
//!
//! The key is bearer money: it is written to a 0600 file and is never printed in full
//! (only a short prefix, for confirmation). The money is custodial on the node thereafter;
//! a `POST /v1/balance/refund` later drains the residual back to ecash (recoverable).
//!
//! Run it (after deciding the amount + node):
//!     nix develop --command bash -c \
//!       'cargo run -p kirby-node --example routstr_create_key -- \
//!          https://api.routstr.com 2000 /var/lib/kirby/brain-api.key'
//!
//! Args (positional, with env fallbacks):
//!     1  node_url      (env ROUTSTR_NODE_URL)      e.g. https://api.routstr.com
//!     2  amount_sats   (env ROUTSTR_AMOUNT_SATS)   1..=1_000_000
//!     3  key_out_path  (env ROUTSTR_KEY_OUT)       where to write the sk-… key (0600)
//!
//! It prints the bolt11 to pay, then blocks polling for payment (default up to ~20 min),
//! and exits 0 once the key is written. Pay the printed invoice from any wallet.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;

/// `POST /v1/balance/lightning/invoice` request body (the node's `InvoiceCreateRequest`).
#[derive(serde::Serialize)]
struct InvoiceCreateRequest<'a> {
    amount_sats: u64,
    /// "create" mints a NEW key; "topup" funds an existing one (not used here).
    purpose: &'a str,
}

/// `POST /v1/balance/lightning/invoice` response (`InvoiceCreateResponse`).
#[derive(serde::Deserialize)]
struct InvoiceCreateResponse {
    invoice_id: String,
    bolt11: String,
    amount_sats: u64,
}

/// `GET /v1/balance/lightning/invoice/{id}/status` response (`InvoiceStatusResponse`). The
/// `api_key` is null until the invoice is paid; its presence is the real "done" signal.
#[derive(serde::Deserialize)]
struct InvoiceStatusResponse {
    status: String,
    #[serde(default)]
    api_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (node_url, amount_sats, key_out) = parse_args()?;
    let node_url = node_url.trim_end_matches('/').to_string();

    // The node-facing HTTP client: redirects disabled (a redirect would leak the minted
    // bearer key to another host) and a sane per-request timeout.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("build HTTP client")?;

    // 1) Create the invoice (purpose=create -> a fresh key on payment).
    let create: InvoiceCreateResponse = http
        .post(format!("{node_url}/v1/balance/lightning/invoice"))
        .json(&InvoiceCreateRequest {
            amount_sats,
            purpose: "create",
        })
        .send()
        .await
        .context("POST /v1/balance/lightning/invoice")?
        .error_for_status()
        .context("invoice creation returned a non-success status")?
        .json()
        .await
        .context("parse InvoiceCreateResponse")?;

    println!("\n=== Routstr prepaid key bootstrap ===");
    println!("node:        {node_url}");
    println!("amount:      {} sat (invoice says {})", amount_sats, create.amount_sats);
    println!("invoice_id:  {}", create.invoice_id);
    println!("\nPAY THIS LIGHTNING INVOICE (bolt11):\n");
    println!("{}\n", create.bolt11);
    println!("Waiting for payment… (polling {}/status)", create.invoice_id);

    // 2) Poll for payment. The node returns the minted api_key once paid; a terminal
    //    "expired"/"failed" status stops the wait.
    let poll_interval = Duration::from_secs(5);
    let max_attempts = 240; // ~20 min at 5s
    let mut api_key: Option<String> = None;
    for attempt in 1..=max_attempts {
        tokio::time::sleep(poll_interval).await;
        let status: InvoiceStatusResponse = match http
            .get(format!(
                "{node_url}/v1/balance/lightning/invoice/{}/status",
                create.invoice_id
            ))
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => match resp.json().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("  (attempt {attempt}: status body parse failed: {e}; retrying)");
                    continue;
                }
            },
            Err(e) => {
                eprintln!("  (attempt {attempt}: status request failed: {e}; retrying)");
                continue;
            }
        };
        if let Some(key) = status.api_key {
            api_key = Some(key);
            break;
        }
        let s = status.status.to_ascii_lowercase();
        if s == "expired" || s == "failed" || s == "error" {
            anyhow::bail!("invoice {} reached terminal status {:?} before payment", create.invoice_id, status.status);
        }
        if attempt % 6 == 0 {
            println!("  …still waiting (status={:?}, {}s elapsed)", status.status, attempt * 5);
        }
    }

    let api_key = api_key.context(
        "timed out waiting for payment; the key was not minted. Re-run, or recover with \
         POST /v1/balance/lightning/recover {bolt11} once paid.",
    )?;

    // 3) Write the bearer key to a 0600 keyfile (bearer money — never world-readable).
    write_key_0600(&key_out, &api_key)?;

    let prefix: String = api_key.chars().take(8).collect();
    println!("\n✓ key minted and written to {key_out} (0600)");
    println!("  key prefix: {prefix}… (full key NOT printed)");
    println!("\nPoint the agent at it:\n  [brain]\n  backend = \"routstr_key\"\n  node_url = \"{node_url}\"\n  api_key_path = \"{key_out}\"\n");
    Ok(())
}

/// Positional args with env fallbacks. Fails with a usage line if any is missing/invalid.
fn parse_args() -> anyhow::Result<(String, u64, String)> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let node_url = args
        .first()
        .cloned()
        .or_else(|| std::env::var("ROUTSTR_NODE_URL").ok())
        .context("missing node_url (arg 1 or ROUTSTR_NODE_URL), e.g. https://api.routstr.com")?;
    let amount_sats: u64 = args
        .get(1)
        .cloned()
        .or_else(|| std::env::var("ROUTSTR_AMOUNT_SATS").ok())
        .context("missing amount_sats (arg 2 or ROUTSTR_AMOUNT_SATS)")?
        .parse()
        .context("amount_sats must be a positive integer")?;
    if amount_sats == 0 || amount_sats > 1_000_000 {
        anyhow::bail!("amount_sats must be in 1..=1_000_000 (the node's invoice bounds), got {amount_sats}");
    }
    let key_out = args
        .get(2)
        .cloned()
        .or_else(|| std::env::var("ROUTSTR_KEY_OUT").ok())
        .context("missing key_out_path (arg 3 or ROUTSTR_KEY_OUT)")?;
    Ok((node_url, amount_sats, key_out))
}

/// Write `key` to `path` with mode 0600 (owner-only), creating/truncating. The trailing
/// newline keeps the file editor-friendly; the loader trims it.
fn write_key_0600(path: &str, key: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for {path}"))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {path} for writing (0600)"))?;
    writeln!(f, "{key}").with_context(|| format!("write key to {path}"))?;
    Ok(())
}
