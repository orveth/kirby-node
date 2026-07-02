//! The Routstr FUNDING primitive: turn "N sats" into a funded prepaid bearer key
//! (`sk-…`) either by creating a Lightning invoice (the creator pays it, then we poll the
//! node until it mints the key) OR by redeeming a Cashu ECASH token the creator already holds.
//! A pure Routstr HTTP client — no cluster, no relay, no mint. It backs both the `fund-key`
//! CLI (the agent-native surface) and any in-process caller.
//!
//! The endpoints and response shapes mirror what the daemon already speaks
//! ([`crate::rail::RoutstrKeyBrain`]):
//!   - LN create: `POST {node}/v1/balance/lightning/invoice` body
//!     `{amount_sats, purpose}` → `{invoice_id, bolt11, amount_sats, expires_at?}`.
//!     `purpose = "create"` is UNAUTHENTICATED and mints a NEW key on payment;
//!     `purpose = "topup"` is AUTHENTICATED with the existing `sk-` and credits its balance.
//!   - LN poll: `GET {node}/v1/balance/lightning/invoice/{id}/status` →
//!     `{status, api_key?}`. A non-null `api_key` is the real "paid + minted" signal;
//!     `expired|failed|error` are terminal-fail states.
//!   - ecash create: `GET {node}/v1/balance/create?initial_balance_token=<cashu>[&balance_limit=<int>]`
//!     → a loose JSON object carrying the minted `sk-` (redeems the token into a NEW key in one
//!     call, no invoice/poll dance). GET-only (Routstr exposes no POST variant), so the token
//!     rides the URL query — a documented bearer-in-logs exposure; the `topup` POST is cleaner.
//!   - ecash topup: `POST {node}/v1/balance/topup` body `{cashu_token}` (Bearer `sk-`) → credits
//!     the existing key. The token is in the request BODY (not the URL), so no query-log exposure.
//!   - balance: `GET {node}/v1/balance/info` (Bearer `sk-`) → `{balance}` in MILLISATS.
//!
//! # Bearer-money discipline
//! The minted `sk-` is bearer money. It only ever lands in a 0600 keyfile (never a log,
//! never stdout, never a TOML). The HTTP client is built with redirects DISABLED (a redirect
//! would leak a `Bearer` header to another host) and finite timeouts, exactly as
//! [`crate::rail::RoutstrKeyBrain`] does. `invoice_id` is itself a capability on the
//! unauthenticated create path (it is what a `poll` exchanges for the `sk-`), so it is
//! persisted to a 0600 sidecar and never logged (F2). Before any bearer call or node_url
//! binding the target url is checked against the ONE https-or-real-loopback policy
//! ([`crate::config::is_https_or_localhost`]) so a bearer secret never crosses plaintext http.
//!
//! There is deliberately NO `recover` primitive: a paid invoice's `bolt11` is public (it is
//! handed to wallets / QR / NWC), so a bolt11-only recover would return bearer money to anyone
//! who saw the invoice, and Routstr's recover-auth is unverified (C7). The 0600 invoice-state
//! sidecar makes `create → poll` crash-resumable, so recover is rarely needed; it is DEFERRED.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::config::is_https_or_localhost;

/// The invoice-amount bounds the node enforces (`1..=1_000_000` sats). Rejected before any
/// network call so a bad amount never reaches the node.
pub const MIN_AMOUNT_SATS: u64 = 1;
pub const MAX_AMOUNT_SATS: u64 = 1_000_000;

/// The default Routstr node the CLI targets when `--node-url` is not given.
pub const DEFAULT_NODE_URL: &str = "https://api.routstr.com";

/// The connect / per-call timeouts for the funding client (the example's 10s / 30s).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The poll cadence and default wait budget (the example's 5s × 240 ≈ 20 min).
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(20 * 60);

// ---- Wire types (serde) --------------------------------------------------------------

/// `POST /v1/balance/lightning/invoice` request body. `purpose = "create"` mints a NEW key
/// on payment (unauthenticated); `purpose = "topup"` credits an EXISTING key (authenticated
/// with that key's `sk-`). Serialized OUT (the request body), so it keeps `Serialize`; it
/// carries no secret (the bearer key rides the `Authorization` header, never this body).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InvoiceCreateRequest {
    pub amount_sats: u64,
    pub purpose: String,
}

/// `POST /v1/balance/lightning/invoice` response. `expires_at` / `payment_hash` are
/// spec-optional (a node that omits them still deserializes).
///
/// `invoice_id` is capability-sensitive on the create path (a `poll` exchanges it for the
/// `sk-`), so this type is NEVER serialized out (no `Serialize` derive → it cannot be printed
/// as JSON), and its `Debug` REDACTS the `invoice_id` (a `{:?}` of a response — e.g. in an
/// `assert_eq!` failure or a stray log — never leaks the capability).
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
pub struct InvoiceCreateResponse {
    pub invoice_id: String,
    pub bolt11: String,
    pub amount_sats: u64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub payment_hash: Option<String>,
}

impl std::fmt::Debug for InvoiceCreateResponse {
    /// Redacts `invoice_id` (the create-path capability). `bolt11` is public (handed to
    /// wallets/QR), so it is shown; `invoice_id` prints as `<redacted>`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvoiceCreateResponse")
            .field("invoice_id", &"<redacted>")
            .field("bolt11", &self.bolt11)
            .field("amount_sats", &self.amount_sats)
            .field("expires_at", &self.expires_at)
            .field("payment_hash", &self.payment_hash)
            .finish()
    }
}

/// `GET /v1/balance/lightning/invoice/{id}/status` response. `api_key` is null until the
/// invoice is paid; its presence — not `status` — is the authoritative "minted" signal.
///
/// `api_key` is the minted bearer key, so this type is NEVER serialized out (no `Serialize`
/// derive), and its `Debug` REDACTS `api_key` (a `{:?}` of a status — an `assert_eq!` failure
/// or a stray log — never leaks the key).
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
pub struct InvoiceStatusResponse {
    pub status: String,
    #[serde(default)]
    pub api_key: Option<String>,
}

impl std::fmt::Debug for InvoiceStatusResponse {
    /// Redacts `api_key` (the minted bearer key). `status` is not sensitive and is shown;
    /// `api_key` prints as `Some(<redacted>)` when present, `None` otherwise.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = self.api_key.as_ref().map(|_| "<redacted>");
        f.debug_struct("InvoiceStatusResponse")
            .field("status", &self.status)
            .field("api_key", &redacted)
            .finish()
    }
}

/// `GET /v1/balance/info` response. `balance` is the SPENDABLE balance in MILLISATOSHIS
/// (the node's authoritative figure; `1 sat = 1000 msats`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct BalanceInfo {
    pub balance: u64,
}

/// `POST /v1/balance/topup` request body: the Cashu ecash token to redeem into an EXISTING
/// key's balance (the `TopupRequest` shape — `{cashu_token: string}`). The token is bearer
/// money, so this type REDACTS it in `Debug` (a `{:?}` — an `assert_eq!` failure or a stray
/// log — never leaks the token). It is serialized OUT as the request body (so it keeps
/// `Serialize`); the bearer `sk-` that authorizes the credit rides the `Authorization`
/// header, never this body.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct TopupRequest {
    pub cashu_token: String,
}

impl std::fmt::Debug for TopupRequest {
    /// Redacts `cashu_token` (bearer money).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopupRequest")
            .field("cashu_token", &"<redacted>")
            .finish()
    }
}

/// The loose `GET /v1/balance/create` response (`additionalProperties: true` in the OpenAPI
/// — an arbitrary JSON object). The minted `sk-` field name is EMPIRICAL: it is most likely
/// `api_key` (mirroring the LN status path), confirmed at the C6 live smoke; this type
/// tolerantly extracts it (see [`extract_minted_key`]). It carries the minted bearer key, so
/// it is NEVER serialized out (no `Serialize` derive) and its `Debug` REDACTS the extracted
/// key (a `{:?}` never leaks it). Deserialized as a free `serde_json::Value` so an unexpected
/// shape parses rather than failing.
#[derive(Clone, serde::Deserialize)]
pub struct EcashCreateResponse {
    /// The whole loose object, kept so [`extract_minted_key`] can search known field names.
    #[serde(flatten)]
    pub raw: serde_json::Map<String, serde_json::Value>,
}

impl std::fmt::Debug for EcashCreateResponse {
    /// Redacts any extracted `sk-` (bearer money); shows only the set of top-level KEYS
    /// present (their names, never their values — a value could be the minted key).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<&str> = self.raw.keys().map(|k| k.as_str()).collect();
        f.debug_struct("EcashCreateResponse")
            .field("keys", &keys)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

// ---- Outcomes + errors ---------------------------------------------------------------

/// The distinct ways a fund/topup/poll flow can end. Maps 1:1 to the stable CLI exit codes
/// (F10) via [`FundingError::exit_code`] / [`FundOutcome::exit_code`], so a driving agent
/// branches on the process exit alone.
#[derive(Debug)]
pub enum FundingError {
    /// The wait budget elapsed with the invoice still unpaid (not a terminal-fail state).
    UnpaidTimeout,
    /// The node reported a terminal `expired` status.
    Expired,
    /// The node reported a terminal `failed`/`error` status (payment failed node-side).
    FailedPayment,
    /// A transport failure, non-2xx status, or malformed body — anything network/HTTP.
    Network(String),
    /// The node rejected the credential (401/403) — a bad/empty/unfunded/revoked key.
    Auth(String),
    /// The custodial balance is too low for the requested operation (a topup-side guard).
    InsufficientBalance(String),
    /// Writing the keyfile / sidecar failed (permissions, an existing DIFFERENT key, …).
    KeyWrite(String),
    /// A caller/argument error caught before any network call (bad amount, bad url binding).
    Usage(String),
}

impl std::fmt::Display for FundingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FundingError::UnpaidTimeout => {
                write!(
                    f,
                    "timed out waiting for payment; the invoice is still unpaid"
                )
            }
            FundingError::Expired => write!(f, "the invoice expired before it was paid"),
            FundingError::FailedPayment => write!(f, "the invoice reached a terminal failed state"),
            FundingError::Network(e) => write!(f, "network/HTTP failure: {e}"),
            FundingError::Auth(e) => write!(f, "authentication failure: {e}"),
            FundingError::InsufficientBalance(e) => write!(f, "insufficient balance: {e}"),
            FundingError::KeyWrite(e) => write!(f, "key-write failure: {e}"),
            FundingError::Usage(e) => write!(f, "usage error: {e}"),
        }
    }
}

impl std::error::Error for FundingError {}

/// The stable process exit codes (F10). `0` is the only success; every failure has a
/// DISTINCT non-zero code so a driving agent branches on the exit alone. These values are a
/// contract — do not renumber.
pub mod exit_code {
    pub const FUNDED: i32 = 0;
    pub const UNPAID_TIMEOUT: i32 = 2;
    pub const EXPIRED: i32 = 3;
    pub const FAILED_PAYMENT: i32 = 4;
    pub const NETWORK_FAILURE: i32 = 5;
    pub const AUTH_FAILURE: i32 = 6;
    pub const INSUFFICIENT_BALANCE: i32 = 7;
    pub const KEY_WRITE_FAILURE: i32 = 8;
    pub const USAGE_ERROR: i32 = 9;
}

impl FundingError {
    /// The distinct exit code for this failure (F10).
    pub fn exit_code(&self) -> i32 {
        match self {
            FundingError::UnpaidTimeout => exit_code::UNPAID_TIMEOUT,
            FundingError::Expired => exit_code::EXPIRED,
            FundingError::FailedPayment => exit_code::FAILED_PAYMENT,
            FundingError::Network(_) => exit_code::NETWORK_FAILURE,
            FundingError::Auth(_) => exit_code::AUTH_FAILURE,
            FundingError::InsufficientBalance(_) => exit_code::INSUFFICIENT_BALANCE,
            FundingError::KeyWrite(_) => exit_code::KEY_WRITE_FAILURE,
            FundingError::Usage(_) => exit_code::USAGE_ERROR,
        }
    }

    /// The stable machine tag for the JSON `status` field on the error paths.
    pub fn status_tag(&self) -> &'static str {
        match self {
            FundingError::UnpaidTimeout => "unpaid-timeout",
            FundingError::Expired => "expired",
            FundingError::FailedPayment => "failed-payment",
            FundingError::Network(_) => "network-failure",
            FundingError::Auth(_) => "auth-failure",
            FundingError::InsufficientBalance(_) => "insufficient-balance",
            FundingError::KeyWrite(_) => "key-write-failure",
            FundingError::Usage(_) => "usage-error",
        }
    }
}

/// The success of a poll/provision/topup that landed money: the confirmed on-node balance
/// and (for the mint paths) where the key was written. `balance_sats` is the PROBED balance
/// after payment (F6: seed treasury from THIS, never the requested amount).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundOutcome {
    pub key_path: Option<PathBuf>,
    pub balance_sats: u64,
}

impl FundOutcome {
    /// Success is always exit 0 (F10).
    pub fn exit_code(&self) -> i32 {
        exit_code::FUNDED
    }
}

/// The shape returned by [`create_invoice`]: the bolt11 to pay plus the `invoice_id` the
/// caller must persist (via [`write_invoice_state`]) to later poll for the key.
pub type CreateOutcome = InvoiceCreateResponse;

// ---- The HTTP client -----------------------------------------------------------------

/// Build the funding HTTP client: redirects DISABLED (a redirect would leak a `Bearer`
/// header to another host — the MED-3 concern, identical to the brain's discipline) and the
/// finite connect/call timeouts. One client is reused across a flow's calls.
fn build_client() -> Result<reqwest::Client, FundingError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(CALL_TIMEOUT)
        .build()
        .map_err(|e| FundingError::Network(format!("build HTTP client: {e}")))
}

/// Trim a trailing `/` from a node URL so `{node}/v1/...` never doubles the slash.
fn normalize_node_url(node_url: &str) -> String {
    node_url.trim_end_matches('/').to_string()
}

/// Enforce the ONE bearer-transport policy ([`crate::config::is_https_or_localhost`]) BEFORE
/// any bearer/secret call or node_url binding: `https://` always, plain `http://` only to a
/// real loopback host. A bearer `sk-` (or the create POST, which the paid invoice's key is
/// later bound to) must never cross plaintext non-loopback http — that is a usage error caught
/// before the network. Sharing config's validator keeps the CLI and config-load in one policy.
fn require_secure_node_url(node_url: &str) -> Result<(), FundingError> {
    if is_https_or_localhost(node_url) {
        Ok(())
    } else {
        Err(FundingError::Usage(format!(
            "refusing to send a bearer secret to a non-https node_url ({node_url}); \
             a plain-http node_url is allowed only for a real loopback host \
             (localhost / 127.0.0.1 / ::1)"
        )))
    }
}

/// Validate the invoice amount against the node's `1..=1_000_000` bounds BEFORE any network
/// call (a bad amount is a usage error, never a wasted round-trip).
pub fn validate_amount(amount_sats: u64) -> Result<(), FundingError> {
    if !(MIN_AMOUNT_SATS..=MAX_AMOUNT_SATS).contains(&amount_sats) {
        return Err(FundingError::Usage(format!(
            "amount_sats must be in {MIN_AMOUNT_SATS}..={MAX_AMOUNT_SATS} (the node's invoice bounds), got {amount_sats}"
        )));
    }
    Ok(())
}

/// Map a non-success HTTP status to the right [`FundingError`] variant: 401/403 → `Auth`
/// (a bad credential), everything else → `Network` (transport/server). `context` names the
/// call site for the message (never the bearer key).
fn status_error(context: &str, status: reqwest::StatusCode) -> FundingError {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        FundingError::Auth(format!("{context} returned {status}"))
    } else {
        FundingError::Network(format!("{context} returned a non-success status: {status}"))
    }
}

// ---- Layer 0 operations --------------------------------------------------------------

/// Create a Lightning invoice for `amount_sats`. `purpose = "create"` mints a NEW key on
/// payment and is UNAUTHENTICATED (pass `api_key = None`); `purpose = "topup"` credits an
/// EXISTING key and REQUIRES its `sk-` (pass `api_key = Some(sk)`). Non-blocking: it returns
/// the `{invoice_id, bolt11, amount_sats, expires_at?}` the caller pays + polls. The amount
/// is bounds-checked first.
///
/// The returned `invoice_id` is bearer-sensitive on the create path (it is what a poll
/// exchanges for the `sk-`): the caller MUST persist it via [`write_invoice_state`] and MUST
/// NOT log it (F2).
pub async fn create_invoice(
    node_url: &str,
    amount_sats: u64,
    purpose: &str,
    api_key: Option<&str>,
) -> Result<InvoiceCreateResponse, FundingError> {
    validate_amount(amount_sats)?;
    if purpose == "topup" && api_key.is_none() {
        return Err(FundingError::Usage(
            "a topup invoice (purpose=\"topup\") requires the existing bearer key (--key-path)"
                .to_string(),
        ));
    }
    // The paid invoice's key is later bound to this node_url (topup sends the bearer key here
    // directly); enforce https-or-loopback BEFORE the POST so a bearer secret never crosses
    // plaintext http and no key is bound to a plaintext-http node.
    require_secure_node_url(node_url)?;
    let http = build_client()?;
    let node = normalize_node_url(node_url);
    let mut req = http
        .post(format!("{node}/v1/balance/lightning/invoice"))
        .json(&InvoiceCreateRequest {
            amount_sats,
            purpose: purpose.to_string(),
        });
    // The bearer key (topup) is attached via `Authorization: Bearer …` and NEVER logged; a
    // reqwest error renders the URL but not our headers, so it cannot leak.
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    let resp = req
        .send()
        .await
        .map_err(|_| FundingError::Network("create-invoice request failed".to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(status_error("invoice creation", status));
    }
    resp.json()
        .await
        .map_err(|_| FundingError::Network("parse invoice-create response failed".to_string()))
}

/// Poll `invoice_id` until the node mints the key, the invoice reaches a terminal-fail
/// state, or `timeout` elapses. On success it returns the minted `api_key` string (bearer
/// money — the caller writes it to a 0600 keyfile, never logs it). Errors map to the
/// terminal outcomes: `expired` → [`FundingError::Expired`], `failed`/`error` →
/// [`FundingError::FailedPayment`], budget elapsed → [`FundingError::UnpaidTimeout`].
///
/// `on_wait` is invoked periodically with `(elapsed_secs)` so a CLI can print progress
/// WITHOUT this function knowing about stdout/JSON (it never prints the `invoice_id`).
///
/// Error discipline: a 401/403 propagates IMMEDIATELY as [`FundingError::Auth`] (a bad
/// credential will not fix itself by retrying). Transient failures (5xx, timeouts, a parse
/// error) keep retrying to the deadline, but the LAST such error is remembered: if the final
/// attempt failed the loop surfaces THAT error, not a bare [`FundingError::UnpaidTimeout`]
/// (so a persistently-down node reports network-failure, not a misleading "unpaid"). No
/// surfaced error carries the status URL (which embeds the capability `invoice_id`) — the
/// helper builds it from fixed context strings and never the reqwest error's `Display`.
pub async fn poll_invoice(
    node_url: &str,
    invoice_id: &str,
    timeout: Duration,
    mut on_wait: impl FnMut(u64),
) -> Result<String, FundingError> {
    // The `invoice_id` is a bearer capability on the create path (a poll exchanges it for the
    // `sk-`), so it must never cross plaintext non-loopback http — enforce the ONE transport
    // policy BEFORE building the status URL (a tampered pending sidecar or an
    // `--allow-node-url-override http://…` must not leak the capability). create/balance already
    // guard; this closes the poll gap (F6).
    require_secure_node_url(node_url)?;
    let http = build_client()?;
    let node = normalize_node_url(node_url);
    let url = format!("{node}/v1/balance/lightning/invoice/{invoice_id}/status");
    let deadline = tokio::time::Instant::now() + timeout;
    // The most recent attempt's transient failure (None once an attempt succeeds). Surfaced at
    // the deadline if the FINAL attempt failed, so a dead node reports its real error rather
    // than a bare unpaid-timeout.
    let mut last_transient: Option<FundingError>;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        match fetch_status(&http, &url).await {
            Ok(status) => {
                if let Some(key) = status.api_key {
                    return Ok(key);
                }
                match status.status.to_ascii_lowercase().as_str() {
                    "expired" => return Err(FundingError::Expired),
                    "failed" | "error" => return Err(FundingError::FailedPayment),
                    _ => {}
                }
                // A clean attempt clears any prior transient error.
                last_transient = None;
            }
            // A 401/403 will not resolve by retrying — surface it now.
            Err(auth @ FundingError::Auth(_)) => return Err(auth),
            // A transient request/parse/5xx failure is not terminal — remember it and retry.
            Err(transient) => last_transient = Some(transient),
        }
        if tokio::time::Instant::now() >= deadline {
            // If the final attempt failed, surface THAT error; otherwise the invoice is
            // simply still unpaid.
            return Err(last_transient.unwrap_or(FundingError::UnpaidTimeout));
        }
        let elapsed = timeout
            .saturating_sub(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .as_secs();
        on_wait(elapsed);
    }
}

/// One status GET (a helper so [`poll_invoice`] can classify each attempt). Errors use a
/// FIXED context string, never the reqwest error's `Display` (which renders the request URL —
/// and the status URL embeds the capability `invoice_id`).
async fn fetch_status(
    http: &reqwest::Client,
    url: &str,
) -> Result<InvoiceStatusResponse, FundingError> {
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|_| FundingError::Network("invoice-status request failed".to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(status_error("invoice status", status));
    }
    resp.json()
        .await
        .map_err(|_| FundingError::Network("parse invoice-status response failed".to_string()))
}

/// Fetch the prepaid key's spendable balance in SATS (the node reports MILLISATS; floor to
/// whole spendable sats). Authenticates with the `sk-` (Bearer, never logged). A bad/empty
/// key surfaces as [`FundingError::Auth`]. This is the source of the CONFIRMED balance the
/// treasury is seeded from (F6).
pub async fn fetch_balance_sats(node_url: &str, api_key: &str) -> Result<u64, FundingError> {
    // The bearer `sk-` rides the Authorization header — never over plaintext non-loopback http.
    require_secure_node_url(node_url)?;
    let http = build_client()?;
    let node = normalize_node_url(node_url);
    let resp = http
        .get(format!("{node}/v1/balance/info"))
        .bearer_auth(api_key)
        .send()
        .await
        .map_err(|_| FundingError::Network("balance-info request failed".to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(status_error("balance-info", status));
    }
    let info: BalanceInfo = resp
        .json()
        .await
        .map_err(|_| FundingError::Network("parse balance-info response failed".to_string()))?;
    // msats -> whole spendable sats (a fractional sat is not spendable, so floor).
    Ok(info.balance / 1000)
}

// ---- Ecash operations (redeem a Cashu token → funded key / credit) -------------------

/// The candidate field names the minted `sk-` may appear under in the loose
/// `GET /v1/balance/create` response, in priority order. `api_key` is the empirical primary
/// (it mirrors the LN status path's `api_key`, confirmed at the C6 smoke); the others are
/// tolerant fallbacks a differently-named field would still be caught by.
const MINTED_KEY_FIELDS: &[&str] = &["api_key", "sk", "key", "token", "apiKey", "api_token"];

/// Extract the minted `sk-` from the loose ecash-create response (tolerant, F-empirical). It
/// tries the known field names ([`MINTED_KEY_FIELDS`]) in order and returns the first non-empty
/// STRING value; failing that, it accepts any top-level string value that looks like a Routstr
/// key (`sk-…`), so an unexpected-but-obvious field name still funds. Returns `None` if nothing
/// key-shaped is present (the caller maps that to a Network error — a malformed response).
fn extract_minted_key(raw: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    for field in MINTED_KEY_FIELDS {
        if let Some(s) = raw.get(*field).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    // Fallback: any top-level string value that is shaped like an `sk-…` key.
    raw.values()
        .filter_map(|v| v.as_str())
        .find(|s| s.starts_with("sk-"))
        .map(|s| s.to_string())
}

/// Create a funded key FROM a Cashu ecash token in ONE call:
/// `GET {node}/v1/balance/create?initial_balance_token=<token>[&balance_limit=<int>]` redeems
/// the token into a NEW prepaid key and returns the minted `sk-`. No invoice/poll dance (the
/// token redeems synchronously). `require_secure_node_url` is enforced FIRST (the token is
/// bearer money and the minted key is later bound to this node_url). An empty token is a usage
/// error caught before the network. The `sk-` is bearer money — the caller writes it to a 0600
/// keyfile, never logs it; the response type redacts it in `Debug`.
///
/// # Bearer-in-URL exposure
/// This is a **GET with the token in the query string**, so the Cashu token (bearer money) can
/// land in server/proxy access logs. Routstr exposes NO POST variant for create-from-token, so
/// the exposure is unavoidable here — treat a create token as BURNED ON USE. The
/// [`topup_from_token`] POST (token in the body) is the cleaner primitive when crediting an
/// existing key. reqwest's `.query(&[..])` URL-encodes the token so it is transmitted safely
/// even with reserved characters (the exposure is the logging, not malformed transport).
pub async fn create_from_token(
    node_url: &str,
    token: &str,
    balance_limit: Option<u64>,
) -> Result<String, FundingError> {
    if token.trim().is_empty() {
        return Err(FundingError::Usage(
            "an ecash create requires a non-empty cashu token (--from-token)".to_string(),
        ));
    }
    // The minted key is later bound to this node_url (and the token is bearer money crossing
    // the wire), so enforce https-or-loopback BEFORE the GET — no bearer secret over plaintext
    // non-loopback http, and no key bound to a plaintext-http node.
    require_secure_node_url(node_url)?;
    let http = build_client()?;
    let node = normalize_node_url(node_url);
    // Build the query with reqwest's typed `.query`, which percent-encodes each value — the
    // token (a base64-ish string that can contain reserved chars) is URL-encoded correctly.
    // `balance_limit`, when set, ties to the capped child-key concept (a future per-agent budget).
    let mut req = http
        .get(format!("{node}/v1/balance/create"))
        .query(&[("initial_balance_token", token)]);
    if let Some(limit) = balance_limit {
        req = req.query(&[("balance_limit", limit.to_string())]);
    }
    let resp = req
        .send()
        .await
        // A reqwest error renders the request URL — which embeds the bearer token on this GET —
        // so use a FIXED context string, never the error's `Display`, so the token cannot leak.
        .map_err(|_| FundingError::Network("ecash create-from-token request failed".to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(status_error("ecash create", status));
    }
    let parsed: EcashCreateResponse = resp
        .json()
        .await
        .map_err(|_| FundingError::Network("parse ecash create response failed".to_string()))?;
    extract_minted_key(&parsed.raw).ok_or_else(|| {
        // The response parsed but held no key-shaped field. Name the KEYS present (their names
        // are not secret) so a field-name mismatch is diagnosable, but never a value (a value
        // could be the minted key). This is the empirical-field-name guard for the C6 smoke.
        let keys: Vec<&str> = parsed.raw.keys().map(|k| k.as_str()).collect();
        FundingError::Network(format!(
            "ecash create response carried no recognizable sk- field (top-level keys: {keys:?}); \
             the minted-key field name is empirical — confirm it at the live smoke"
        ))
    })
}

/// Credit an EXISTING key's balance FROM a Cashu ecash token:
/// `POST {node}/v1/balance/topup` body `{cashu_token}` authenticated with the key's `sk-`
/// (`Authorization: Bearer …`). The token is in the request BODY (not the URL), so there is no
/// query-log exposure — this is the cleaner ecash primitive. `require_secure_node_url` is
/// enforced FIRST (the bearer `sk-` and the token both cross the wire). An empty token is a
/// usage error caught before the network. On a non-2xx, a 401/403 maps to
/// [`FundingError::Auth`] (a bad/unfunded key) and everything else to [`FundingError::Network`].
/// Neither the token nor the `sk-` is ever logged (the token rides the redacting [`TopupRequest`]
/// body; the `sk-` rides the `Authorization` header).
pub async fn topup_from_token(
    node_url: &str,
    api_key: &str,
    token: &str,
) -> Result<(), FundingError> {
    if token.trim().is_empty() {
        return Err(FundingError::Usage(
            "an ecash topup requires a non-empty cashu token (--from-token)".to_string(),
        ));
    }
    // The bearer `sk-` (and the token) cross the wire — never over plaintext non-loopback http.
    require_secure_node_url(node_url)?;
    let http = build_client()?;
    let node = normalize_node_url(node_url);
    let resp = http
        .post(format!("{node}/v1/balance/topup"))
        .bearer_auth(api_key)
        .json(&TopupRequest {
            cashu_token: token.to_string(),
        })
        .send()
        .await
        .map_err(|_| FundingError::Network("ecash topup request failed".to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(status_error("ecash topup", status));
    }
    Ok(())
}

// ---- Keyfile + sidecar persistence (F8 / F9 / F2) ------------------------------------

/// The sidecar path for the bound `node_url` (F9): `<key>.node_url` beside the keyfile. The
/// keyfile itself STAYS the raw `sk-` (boot.rs compat), so the url binding lives here.
pub fn node_url_sidecar_path(key_path: &Path) -> PathBuf {
    sidecar_path(key_path, "node_url")
}

/// The sidecar path for the persisted PENDING-invoice state (F2): `<key>.invoice` beside the
/// keyfile. Written 0600, never logged; it holds the capability a `poll` exchanges for the key
/// PLUS the node_url the invoice was created against (so `poll` targets the right node).
pub fn invoice_state_path(key_path: &Path) -> PathBuf {
    sidecar_path(key_path, "invoice")
}

/// Append `.ext` to the keyfile's full name (so `brain.key` → `brain.key.node_url`), never
/// REPLACING the extension (which would collide `brain.key` and `brain.node_url`).
fn sidecar_path(key_path: &Path, ext: &str) -> PathBuf {
    let mut name = key_path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(ext);
    key_path.with_file_name(name)
}

/// Write the bearer key to `path` with hardened, atomic-ish semantics (F8):
/// `O_CREAT | O_EXCL | O_NOFOLLOW` + mode 0600, create the parent dir, `fsync` the file and
/// the parent dir. The file holds ONLY the raw `sk-…\n` (boot.rs loads a RAW trimmed key on
/// one line — that compat is a hard requirement).
///
/// If the target already exists, the write FAILS unless the existing file's content
/// fingerprint (sha256) matches the key being written — an idempotent re-provision of the
/// SAME key succeeds; overwriting a DIFFERENT key is refused (O_EXCL + fingerprint). The
/// parent-dir handling and 0600 mode also apply to the SAME-key re-write path.
pub fn write_key_atomic(path: &Path, key: &str) -> Result<(), FundingError> {
    let parent = ensure_parent_dir(path)?;

    // Fresh create: O_CREAT|O_EXCL|O_NOFOLLOW so an existing file (or a symlink planted at
    // the path) is never followed or clobbered. This is the F8 guard.
    let create = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path);

    match create {
        Ok(mut f) => {
            let write_and_sync = (|| {
                // The `.mode(0o600)` on the O_EXCL create is masked by the process umask, so a
                // restrictive umask (e.g. 0277) could create the FUNDED key as 0400 — which the
                // hardened reader (which requires exactly 0600) would then reject. fchmod the
                // OPENED fd to exactly 0600 BEFORE writing (mirroring `write_sidecar_exclusive`),
                // binding the mode to the same inode that is written — the key is 0600 regardless
                // of umask.
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| FundingError::KeyWrite(format!("chmod key file 0600: {e}")))?;
                writeln!(f, "{key}")
                    .map_err(|e| FundingError::KeyWrite(format!("write key: {e}")))?;
                f.sync_all()
                    .map_err(|e| FundingError::KeyWrite(format!("fsync key file: {e}")))?;
                fsync_dir(&parent)
            })();
            if let Err(e) = write_and_sync {
                // LEAVE the partial file in place: a path-based unlink here would be a TOCTOU (an
                // entry swapped between the failed write and the cleanup would delete a DIFFERENT
                // file). A lingering partial is safe — the NEXT write_key_atomic's O_EXCL create
                // refuses to reopen it and its fingerprint-mismatch refusal means it can never be
                // silently trusted as a key. The operator removes it by hand before retrying.
                return Err(FundingError::KeyWrite(format!(
                    "{e}; a PARTIAL keyfile may remain at {} — remove it by hand before retrying \
                     (the next attempt's O_EXCL create refuses to reopen it)",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Idempotent re-provision: succeed IFF the existing content is the SAME key;
            // refuse to overwrite a DIFFERENT one (never silently clobber bearer money). The
            // existing file is read through an O_NOFOLLOW|O_RDONLY fd that is fstat-checked to
            // be a regular file mode 0600 — never following a symlink and never trusting a
            // wrong-mode (e.g. world-readable, or an attacker-planted) file's content.
            let existing = read_existing_key_hardened(path)?;
            if fingerprint(existing.trim()) == fingerprint(key) {
                Ok(())
            } else {
                Err(FundingError::KeyWrite(format!(
                    "refusing to overwrite {}: a DIFFERENT key already exists there (fingerprint mismatch)",
                    path.display()
                )))
            }
        }
        Err(e) => Err(FundingError::KeyWrite(format!(
            "open {} O_EXCL 0600: {e}",
            path.display()
        ))),
    }
}

/// Read an existing keyfile for the idempotent-fingerprint compare WITHOUT following a symlink
/// or trusting a wrong-mode file. Delegates to [`read_regular_0600_nofollow`], which opens
/// `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`, `fstat`s the fd (so the checks bind to the SAME inode
/// that is read — no TOCTOU), requires a regular file mode exactly 0600, then reads from THAT
/// fd (never [`std::fs::read_to_string`], which would re-open by path and follow a symlink). A
/// symlink at the path fails the open (`ELOOP`); a non-regular or non-0600 file is refused.
fn read_existing_key_hardened(path: &Path) -> Result<String, FundingError> {
    read_regular_0600_nofollow(path, "key")
}

/// Read the bearer `sk-` from a keyfile for a bearer call (`balance`/`topup`, and any in-process
/// inference load) through the SAME hardened path as the idempotent-fingerprint read: the shared
/// [`read_regular_0600_nofollow`] opens `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`, `fstat`s the fd to
/// require a regular file mode exactly 0600, and reads from THAT fd. A plain
/// [`std::fs::read_to_string`] here would FOLLOW a symlink planted at `--key-path` and send the
/// resolved file's `sk-` to the node — the bearer-secret redirection this closes. The returned
/// content is the RAW file (caller trims); a symlink fails the open (`ELOOP`), a non-regular or
/// non-0600 file is refused. This completes the discipline: EVERY key read is hardened.
pub fn read_key_file(path: &Path) -> Result<String, FundingError> {
    read_regular_0600_nofollow(path, "key")
}

/// Read a security-relevant sidecar (`<key>.node_url` / `<key>.invoice`) WITHOUT following a
/// symlink or trusting a wrong-mode file — the read-side mirror of [`write_sidecar`] and the
/// same hardened model as [`read_existing_key_hardened`]. A sidecar carries a bearer-routing
/// binding (`node_url`) or a capability (`invoice_id`); a plain [`std::fs::read_to_string`]
/// would FOLLOW a symlink and accept a wrong-mode file, so an attacker who swaps the sidecar
/// for a symlink to `https://evil` (or a world-writable file) could redirect the bearer `sk-`
/// or make a `poll` trust a tampered node_url. This opens `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`,
/// `fstat`s the fd (checks bound to the read inode), requires a regular file mode exactly 0600
/// (the mode `write_sidecar` always leaves), and reads from THAT fd.
///
/// `Ok(None)` means the sidecar is ABSENT (no file at the path); `Ok(Some(_))` is a safe read;
/// `Err(_)` means the sidecar EXISTS but is unsafe (symlink / wrong-mode / unreadable) — a
/// present-but-tampered sidecar FAILS CLOSED at every caller, never falling through to a default.
fn read_sidecar_hardened(path: &Path) -> Result<Option<String>, FundingError> {
    match read_regular_0600_nofollow(path, "sidecar") {
        Ok(contents) => Ok(Some(contents)),
        // A missing sidecar is a normal "absent" — distinct from a present-but-unsafe one.
        Err(FundingError::KeyWrite(_)) if !path_exists_nofollow(path) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether a path resolves to an entry WITHOUT following a final symlink (`lstat`): a dangling
/// or planted symlink still counts as "exists" (so a symlinked sidecar is treated as
/// present-but-unsafe, never as absent). Used to split "sidecar absent" from "sidecar present
/// but the hardened open refused it".
fn path_exists_nofollow(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Open `path` with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`, `fstat` the fd to require a regular
/// file mode exactly 0600, and read its full contents from THAT fd (never re-opening by path).
/// The shared hardened-read core behind the keyfile and the sidecars: binding the type/mode
/// checks to the same inode that is read closes the TOCTOU, and `O_NOFOLLOW` refuses a symlink
/// planted at the path (a bearer-secret redirection). `what` names the file in errors.
fn read_regular_0600_nofollow(path: &Path, what: &str) -> Result<String, FundingError> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            FundingError::KeyWrite(format!(
                "open existing {what} {} O_RDONLY|O_NOFOLLOW: {e}",
                path.display()
            ))
        })?;
    let meta = f
        .metadata()
        .map_err(|e| FundingError::KeyWrite(format!("fstat existing {what}: {e}")))?;
    if !meta.file_type().is_file() {
        return Err(FundingError::KeyWrite(format!(
            "existing {what} {} is not a regular file (refusing to trust it)",
            path.display()
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o600 {
        return Err(FundingError::KeyWrite(format!(
            "existing {what} {} has mode {:#o}, expected 0600 (refusing to trust a wrong-mode {what})",
            path.display(),
            mode
        )));
    }
    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .map_err(|e| FundingError::KeyWrite(format!("read existing {what}: {e}")))?;
    Ok(contents)
}

/// The persisted PENDING-invoice state (F2): the capability `invoice_id` a `poll` exchanges
/// for the `sk-`, PLUS the `node_url` the invoice was created against. `poll` reads BOTH from
/// here so it targets the node the invoice actually lives on (never defaulting to
/// `api.routstr.com` against a custom node). Deserialize-only + a redacting `Debug` (the
/// `invoice_id` is a capability), mirroring the wire types.
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
pub struct PendingInvoice {
    pub invoice_id: String,
    pub node_url: String,
}

impl std::fmt::Debug for PendingInvoice {
    /// Redacts `invoice_id` (the capability); `node_url` is not sensitive and is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInvoice")
            .field("invoice_id", &"<redacted>")
            .field("node_url", &self.node_url)
            .finish()
    }
}

/// Write a FRESH PENDING-invoice state (invoice_id + node_url) to its 0600 sidecar (F2/F7).
/// Both are stored as JSON (`{"invoice_id":..,"node_url":..}`); the invoice_id is bearer-
/// sensitive on the create path (the poll exchanges it for the `sk-`), so it is never logged.
///
/// This is `O_EXCL` create-NEW: it REFUSES if a pending sidecar already exists — an existing
/// pending sidecar is a paid-but-unpolled invoice whose funds would be STRANDED if a fresh
/// `create` overwrote its capability (there is no `recover`). The caller (`create`/`provision`)
/// turns that refusal into "run `fund-key poll` to resume". It is deliberately DISTINCT from
/// [`write_node_url_binding`]/[`write_sidecar`], which legitimately overwrite the node_url
/// binding after the key lands. `poll` clears the pending sidecar only after the key is written,
/// so a clean resume re-reads it and the O_EXCL create applies only to a genuinely new invoice.
/// The node_url is normalized so a later `poll` compares apples to apples.
pub fn write_invoice_state(
    key_path: &Path,
    invoice_id: &str,
    node_url: &str,
) -> Result<(), FundingError> {
    // Build the JSON literal directly (the type is Deserialize-only + redacting-Debug, so it
    // is never serialized out); this is written to a 0600 file, never stdout.
    let json = serde_json::json!({
        "invoice_id": invoice_id,
        "node_url": normalize_node_url(node_url),
    })
    .to_string();
    write_sidecar_exclusive(&invoice_state_path(key_path), &json)
}

/// Read the persisted PENDING-invoice state (F2) through the hardened sidecar reader (F9):
/// `Ok(None)` if the sidecar is ABSENT, `Ok(Some(_))` if it is present + safe + parseable,
/// `Err(_)` if it EXISTS but is unsafe (symlink / wrong-mode). The `invoice_id` is the
/// capability a `poll` exchanges for the `sk-`, so a present-but-tampered sidecar must fail
/// closed here (never be treated as "no pending invoice" and silently re-created over). A
/// present-but-UNPARSEABLE (or empty-field) sidecar is a hard error too, not a silent absence:
/// it still shadows a possibly-paid invoice, so create/provision must refuse rather than clobber.
pub fn read_invoice_state(key_path: &Path) -> Result<Option<PendingInvoice>, FundingError> {
    let path = invoice_state_path(key_path);
    let raw = match read_sidecar_hardened(&path)? {
        Some(raw) => raw,
        None => return Ok(None),
    };
    let pending: PendingInvoice = serde_json::from_str(raw.trim()).map_err(|e| {
        FundingError::Usage(format!(
            "the pending-invoice sidecar {} exists but is not valid JSON ({e}); \
             refusing to overwrite a possibly-paid invoice — inspect or remove it by hand",
            path.display()
        ))
    })?;
    if pending.invoice_id.trim().is_empty() || pending.node_url.trim().is_empty() {
        return Err(FundingError::Usage(format!(
            "the pending-invoice sidecar {} exists but is missing invoice_id/node_url; \
             refusing to overwrite it — inspect or remove it by hand",
            path.display()
        )));
    }
    Ok(Some(pending))
}

/// Clear the PENDING-invoice state once the key is safely written (the invoice is claimed;
/// keeping the capability around is needless exposure). Absence is fine — a `NotFound` is `Ok`
/// (idempotent). Any OTHER unlink failure is PROPAGATED, not swallowed: a silent failure would
/// leave the `invoice_id` capability on disk while the caller reports "funded", so the caller
/// must surface it (the key is already written, so the caller warns rather than failing the op).
pub fn clear_invoice_state(key_path: &Path) -> Result<(), FundingError> {
    let path = invoice_state_path(key_path);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(FundingError::KeyWrite(format!(
            "clear pending-invoice sidecar {}: {e}",
            path.display()
        ))),
    }
}

/// Bind the `node_url` beside the key (F9). Written 0600, no-symlink-follow. The keyfile
/// stays the raw `sk-`; this sidecar is what `balance`/`topup` read to avoid ever sending
/// the bearer key to a different server.
pub fn write_node_url_binding(key_path: &Path, node_url: &str) -> Result<(), FundingError> {
    write_sidecar(
        &node_url_sidecar_path(key_path),
        &normalize_node_url(node_url),
    )
}

/// Read the bound `node_url` for a key (F9) through the hardened sidecar reader: `Ok(None)` if
/// the binding is ABSENT, `Ok(Some(url))` if present + safe + non-empty, `Err(_)` if it EXISTS
/// but is unsafe (symlink / wrong-mode) or is present-but-empty. The binding decides where the
/// bearer `sk-` is sent, so a plain [`std::fs::read_to_string`] here would follow a symlink to
/// `https://evil` (or accept a world-writable file) and redirect the secret; a present-but-empty
/// binding is a hard error too (never silently fall through to a default/override when a binding
/// file is present-but-broken).
pub fn read_node_url_binding(key_path: &Path) -> Result<Option<String>, FundingError> {
    let path = node_url_sidecar_path(key_path);
    let raw = match read_sidecar_hardened(&path)? {
        Some(raw) => raw,
        None => return Ok(None),
    };
    let url = raw.trim().to_string();
    if url.is_empty() {
        return Err(FundingError::Usage(format!(
            "the node_url binding {} exists but is empty; refusing to fall through to a default \
             (a present-but-broken binding must not silently send the bearer key elsewhere)",
            path.display()
        )));
    }
    Ok(Some(url))
}

/// The effective `node_url` for a `balance`/`topup` on an existing key (F9): the BOUND url
/// wins. An explicit `override_url` is refused unless `allow_override` is set (never send a
/// bearer key to a different server by accident); when allowed, it is used and the caller is
/// expected to warn. With no binding, the given url is used as-is.
pub fn resolve_bound_node_url(
    key_path: &Path,
    override_url: Option<&str>,
    allow_override: bool,
) -> Result<String, FundingError> {
    // FAIL CLOSED: if the binding sidecar is present-but-unsafe (symlink/wrong-mode/empty), the
    // `?` surfaces that error rather than treating it as "no binding" and falling through to an
    // override/default — a tampered binding must never redirect the bearer key.
    let bound = read_node_url_binding(key_path)?;
    match (bound, override_url) {
        (Some(bound), Some(over)) => {
            if normalize_node_url(over) == bound {
                Ok(bound)
            } else if allow_override {
                Ok(normalize_node_url(over))
            } else {
                Err(FundingError::Usage(format!(
                    "the requested --node-url ({}) does not match the key's bound node_url ({}); \
                     sending a bearer key to a different server needs an explicit override flag",
                    normalize_node_url(over),
                    bound
                )))
            }
        }
        (Some(bound), None) => Ok(bound),
        (None, Some(over)) => Ok(normalize_node_url(over)),
        (None, None) => Err(FundingError::Usage(
            "no node_url is bound to this key and none was given".to_string(),
        )),
    }
}

/// sha256 hex of a string (the keyfile idempotency fingerprint). Comparing digests, not raw
/// keys, keeps the plaintext key out of any comparison-path temporaries beyond the read.
fn fingerprint(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    hex::encode(digest)
}

/// Create the keyfile's parent directory (0700-ish via umask; the KEY itself is 0600) and
/// return it for the post-write `fsync`. A path with no parent (a bare filename) uses `.`.
fn ensure_parent_dir(path: &Path) -> Result<PathBuf, FundingError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    match parent {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| {
                FundingError::KeyWrite(format!("create parent dir {}: {e}", dir.display()))
            })?;
            Ok(dir.to_path_buf())
        }
        None => Ok(PathBuf::from(".")),
    }
}

/// `fsync` a directory so a freshly-created entry (the keyfile) is durable across a crash.
fn fsync_dir(dir: &Path) -> Result<(), FundingError> {
    let handle = std::fs::File::open(dir).map_err(|e| {
        FundingError::KeyWrite(format!("open parent dir {} to fsync: {e}", dir.display()))
    })?;
    handle
        .sync_all()
        .map_err(|e| FundingError::KeyWrite(format!("fsync parent dir {}: {e}", dir.display())))
}

/// Write a small 0600 sidecar (invoice_id / node_url), no-symlink-follow. A sidecar carries a
/// capability (the `invoice_id`) or a security-relevant binding (the `node_url`), so it must be
/// 0600 EVEN WHEN THE FILE ALREADY EXISTS: mode `0o600` on the open flags only applies to a
/// fresh create, so a pre-existing 0644 sidecar would keep 0644 and leak world-readable. This
/// opens `O_CREAT | O_WRONLY | O_NOFOLLOW | O_CLOEXEC` (never following a symlink), `fstat`s
/// the fd to require a regular file, `fchmod`s it to exactly 0600 (binding the mode to the same
/// inode that is written — no path re-open, no TOCTOU), then truncates, writes, and `fsync`s
/// BOTH the file and its parent dir (so the entry + content are durable). Overwrite of an
/// existing sidecar is permitted (a fresh create replaces a stale one for the same key-out).
fn write_sidecar(path: &Path, contents: &str) -> Result<(), FundingError> {
    let parent = ensure_parent_dir(path)?;
    // O_WRONLY|O_CREAT|O_NOFOLLOW but NOT O_TRUNC: fstat + fchmod BEFORE truncating, so a
    // pre-existing wrong-mode/irregular file is caught and re-permissioned, not clobbered blind.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            FundingError::KeyWrite(format!("open sidecar {} 0600: {e}", path.display()))
        })?;
    let meta = f
        .metadata()
        .map_err(|e| FundingError::KeyWrite(format!("fstat sidecar: {e}")))?;
    if !meta.file_type().is_file() {
        return Err(FundingError::KeyWrite(format!(
            "sidecar {} is not a regular file",
            path.display()
        )));
    }
    // Enforce 0600 on the OPEN fd (covers a pre-existing 0644 file the mode-on-create missed).
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| FundingError::KeyWrite(format!("chmod sidecar 0600: {e}")))?;
    // Truncate any prior (possibly longer) content, then write.
    f.set_len(0)
        .map_err(|e| FundingError::KeyWrite(format!("truncate sidecar: {e}")))?;
    write_and_sync_sidecar(&f, &parent, contents)
}

/// Write a 0600 sidecar that must NOT already exist (F7): `O_CREAT | O_EXCL | O_WRONLY |
/// O_NOFOLLOW | O_CLOEXEC`. Unlike [`write_sidecar`] (which overwrites), this REFUSES an
/// existing file — used for the PENDING-invoice sidecar, whose capability must never be
/// clobbered over a paid-but-unpolled invoice (that would strand the funds). O_EXCL also makes
/// a symlink at the path fail the create, so no separate O_NOFOLLOW read is needed. On success
/// it writes + `fsync`s the file and its parent dir.
///
/// The `.mode(0o600)` on the open flags is masked by the process umask, so a restrictive umask
/// could create the pending sidecar as (e.g.) 0400/0000; the hardened reader
/// ([`read_regular_0600_nofollow`]) then rejects a non-0600 sidecar and poll-resume would fail.
/// So it `fstat`s + `fchmod`s the OPENED fd to exactly 0600 BEFORE writing (mirroring
/// [`write_sidecar`]), binding the mode to the same inode that is written — the sidecar is 0600
/// regardless of umask.
fn write_sidecar_exclusive(path: &Path, contents: &str) -> Result<(), FundingError> {
    let parent = ensure_parent_dir(path)?;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                FundingError::Usage(format!(
                    "a pending invoice already exists at {} — resume it with \
                     `fund-key poll --key-out {}` (do NOT re-create; overwriting the pending \
                     capability would strand a paid-but-unpolled invoice)",
                    path.display(),
                    // The key path is this sidecar's path minus the `.invoice` suffix.
                    path.with_extension("").display()
                ))
            } else {
                FundingError::KeyWrite(format!(
                    "open pending sidecar {} O_EXCL 0600: {e}",
                    path.display()
                ))
            }
        })?;
    // O_EXCL created a fresh regular file (an existing file/symlink would have failed the open),
    // so no fstat file-type re-check is needed here — but fchmod the OPEN fd to exactly 0600 to
    // defeat a restrictive umask, so the hardened reader accepts the sidecar on poll-resume.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| FundingError::KeyWrite(format!("chmod pending sidecar 0600: {e}")))?;
    write_and_sync_sidecar(&f, &parent, contents)
}

/// Write `contents` (+ newline) to an already-open sidecar fd and `fsync` BOTH the file and its
/// parent dir (the durable-write tail shared by [`write_sidecar`] and [`write_sidecar_exclusive`]).
fn write_and_sync_sidecar(
    f: &std::fs::File,
    parent: &Path,
    contents: &str,
) -> Result<(), FundingError> {
    // `impl Write for &File`: write through a `&File` so the caller keeps ownership of the fd.
    let mut w: &std::fs::File = f;
    w.write_all(format!("{contents}\n").as_bytes())
        .map_err(|e| FundingError::KeyWrite(format!("write sidecar: {e}")))?;
    f.sync_all()
        .map_err(|e| FundingError::KeyWrite(format!("fsync sidecar: {e}")))?;
    fsync_dir(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- serde round-trips ----------------------------------------------------------

    #[test]
    fn invoice_create_request_round_trips() {
        let req = InvoiceCreateRequest {
            amount_sats: 2000,
            purpose: "create".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"amount_sats":2000,"purpose":"create"}"#);
        let back: InvoiceCreateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn invoice_create_response_parses_with_and_without_optionals() {
        // Full shape (spec optionals present).
        let full = r#"{"invoice_id":"id-1","bolt11":"lnbc1...","amount_sats":2000,"expires_at":1720000000,"payment_hash":"abcd"}"#;
        let r: InvoiceCreateResponse = serde_json::from_str(full).unwrap();
        assert_eq!(r.invoice_id, "id-1");
        assert_eq!(r.amount_sats, 2000);
        assert_eq!(r.expires_at, Some(1720000000));
        // Minimal shape (a node that omits the optionals still deserializes).
        let min = r#"{"invoice_id":"id-2","bolt11":"lnbc2...","amount_sats":5}"#;
        let r2: InvoiceCreateResponse = serde_json::from_str(min).unwrap();
        assert_eq!(r2.invoice_id, "id-2");
        assert_eq!(r2.expires_at, None);
        assert_eq!(r2.payment_hash, None);
    }

    #[test]
    fn invoice_status_response_null_and_present_api_key() {
        let unpaid = r#"{"status":"pending","api_key":null}"#;
        let s: InvoiceStatusResponse = serde_json::from_str(unpaid).unwrap();
        assert_eq!(s.status, "pending");
        assert_eq!(s.api_key, None);
        let paid = r#"{"status":"paid","api_key":"sk-xyz"}"#;
        let s2: InvoiceStatusResponse = serde_json::from_str(paid).unwrap();
        assert_eq!(s2.api_key.as_deref(), Some("sk-xyz"));
        // A status with no api_key field at all (default None).
        let bare = r#"{"status":"pending"}"#;
        let s3: InvoiceStatusResponse = serde_json::from_str(bare).unwrap();
        assert_eq!(s3.api_key, None);
    }

    #[test]
    fn balance_info_parses_msats() {
        let b: BalanceInfo = serde_json::from_str(r#"{"balance":2500400}"#).unwrap();
        assert_eq!(b.balance, 2500400);
    }

    // ---- secret redaction in Debug (#2) ---------------------------------------------

    #[test]
    fn secrets_are_redacted_in_debug() {
        // TOOTH (#2): the secret-bearing response types must NOT print their secret via
        // `{:?}` (an assert_eq! failure or a stray log renders Debug). Reverting to a derived
        // `#[derive(Debug)]` makes this RED — the raw invoice_id / api_key would appear.
        let created = InvoiceCreateResponse {
            invoice_id: "inv-SECRET-CAP".into(),
            bolt11: "lnbcPUBLIC".into(),
            amount_sats: 2000,
            expires_at: None,
            payment_hash: None,
        };
        let d = format!("{created:?}");
        assert!(
            !d.contains("inv-SECRET-CAP"),
            "the capability invoice_id must not appear in Debug: {d}"
        );
        assert!(d.contains("<redacted>"), "invoice_id is redacted: {d}");
        assert!(d.contains("lnbcPUBLIC"), "the public bolt11 is still shown");

        let status = InvoiceStatusResponse {
            status: "paid".into(),
            api_key: Some("sk-SECRET-KEY".into()),
        };
        let d = format!("{status:?}");
        assert!(
            !d.contains("sk-SECRET-KEY"),
            "the minted api_key must not appear in Debug: {d}"
        );
        assert!(d.contains("<redacted>"), "api_key is redacted: {d}");
        assert!(d.contains("paid"), "the non-secret status is still shown");

        let pending = PendingInvoice {
            invoice_id: "inv-PENDING-CAP".into(),
            node_url: "https://api.routstr.com".into(),
        };
        let d = format!("{pending:?}");
        assert!(
            !d.contains("inv-PENDING-CAP"),
            "the pending invoice_id must not appear in Debug: {d}"
        );
        assert!(d.contains("https://api.routstr.com"), "node_url is shown");
    }

    // ---- amount validation ----------------------------------------------------------

    #[test]
    fn amount_zero_is_rejected() {
        let err = validate_amount(0).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::USAGE_ERROR);
    }

    #[test]
    fn amount_over_max_is_rejected() {
        assert!(validate_amount(MAX_AMOUNT_SATS + 1).is_err());
    }

    #[test]
    fn amount_at_bounds_is_accepted() {
        assert!(validate_amount(MIN_AMOUNT_SATS).is_ok());
        assert!(validate_amount(MAX_AMOUNT_SATS).is_ok());
    }

    // ---- exit-code + status-tag mapping (F10) ---------------------------------------

    #[test]
    fn exit_codes_are_distinct_and_stable() {
        use FundingError::*;
        let cases = [
            (UnpaidTimeout, exit_code::UNPAID_TIMEOUT, "unpaid-timeout"),
            (Expired, exit_code::EXPIRED, "expired"),
            (FailedPayment, exit_code::FAILED_PAYMENT, "failed-payment"),
            (
                Network(String::new()),
                exit_code::NETWORK_FAILURE,
                "network-failure",
            ),
            (Auth(String::new()), exit_code::AUTH_FAILURE, "auth-failure"),
            (
                InsufficientBalance(String::new()),
                exit_code::INSUFFICIENT_BALANCE,
                "insufficient-balance",
            ),
            (
                KeyWrite(String::new()),
                exit_code::KEY_WRITE_FAILURE,
                "key-write-failure",
            ),
            (Usage(String::new()), exit_code::USAGE_ERROR, "usage-error"),
        ];
        let mut seen = std::collections::HashSet::new();
        for (err, code, tag) in cases {
            assert_eq!(err.exit_code(), code, "code for {tag}");
            assert_eq!(err.status_tag(), tag);
            assert!(
                seen.insert(code),
                "exit code {code} ({tag}) is not distinct"
            );
            assert_ne!(
                code,
                exit_code::FUNDED,
                "no failure may collide with FUNDED=0"
            );
        }
        assert_eq!(
            FundOutcome {
                key_path: None,
                balance_sats: 1
            }
            .exit_code(),
            exit_code::FUNDED
        );
    }

    // ---- keyfile write semantics (F8) -----------------------------------------------

    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "kirby-funding-test-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_key_atomic_writes_raw_sk_0600() {
        // The keyfile must hold ONLY the raw `sk-…` (boot.rs `load_api_key` trims + loads a
        // raw one-line key). A trailing newline is fine (boot trims it); no other content.
        let dir = temp_dir("raw");
        let key_path = dir.join("brain.key");
        write_key_atomic(&key_path, "sk-live-abc123").unwrap();

        let raw = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(
            raw, "sk-live-abc123\n",
            "the keyfile is exactly the raw sk- + newline"
        );
        assert_eq!(raw.trim(), "sk-live-abc123");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the keyfile is mode 0600");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_key_atomic_same_key_is_idempotent() {
        let dir = temp_dir("idem");
        let key_path = dir.join("brain.key");
        write_key_atomic(&key_path, "sk-same").unwrap();
        // Re-provisioning the SAME key succeeds (idempotent).
        write_key_atomic(&key_path, "sk-same").unwrap();
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().trim(),
            "sk-same"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_key_atomic_refuses_to_overwrite_a_different_key() {
        // Reverting the O_EXCL + fingerprint guard (e.g. opening with .create(true) +
        // .truncate(true)) makes this RED: a DIFFERENT existing key would be clobbered
        // instead of refused, silently destroying bearer money.
        let dir = temp_dir("overwrite");
        let key_path = dir.join("brain.key");
        write_key_atomic(&key_path, "sk-original").unwrap();
        let err = write_key_atomic(&key_path, "sk-attacker").unwrap_err();
        assert_eq!(err.exit_code(), exit_code::KEY_WRITE_FAILURE);
        // The original key is intact — never clobbered.
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().trim(),
            "sk-original"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_key_atomic_creates_missing_parent_dirs() {
        let dir = temp_dir("parent");
        let key_path = dir.join("nested/deep/brain.key");
        write_key_atomic(&key_path, "sk-nested").unwrap();
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().trim(),
            "sk-nested"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_key_atomic_does_not_follow_a_symlink() {
        // O_NOFOLLOW: a symlink planted at the key path is refused, never written THROUGH
        // to its target (a classic bearer-key redirection attack). Reverting O_NOFOLLOW
        // would let the write follow the link and land the key at the attacker's target.
        let dir = temp_dir("symlink");
        let target = dir.join("target.key");
        std::fs::write(&target, "sk-victim\n").unwrap();
        let link = dir.join("link.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = write_key_atomic(&link, "sk-through-link").unwrap_err();
        assert_eq!(err.exit_code(), exit_code::KEY_WRITE_FAILURE);
        // The symlink target is untouched.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap().trim(),
            "sk-victim"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_key_atomic_idempotent_read_rejects_wrong_mode_file() {
        // TOOTH (#5): the AlreadyExists idempotent-read branch must NOT trust a wrong-mode
        // file. An existing 0644 file holding the SAME key content is REFUSED (a
        // world-readable "key" is not a key we hardened). Reverting to `std::fs::read_to_string`
        // + no fstat mode check makes this RED — the old code would return Ok (idempotent
        // success) on the 0644 file, silently blessing a world-readable bearer key.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("idem-wrongmode");
        let key_path = dir.join("brain.key");
        std::fs::write(&key_path, "sk-same\n").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = write_key_atomic(&key_path, "sk-same").unwrap_err();
        assert_eq!(err.exit_code(), exit_code::KEY_WRITE_FAILURE);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_key_atomic_idempotent_read_does_not_follow_a_symlink() {
        // TOOTH (#5): the idempotent-read branch must read through an O_NOFOLLOW fd, never
        // `std::fs::read_to_string` (which re-opens by path and FOLLOWS a symlink). Here the
        // key path is a symlink to a 0600 file whose content MATCHES the key being written; the
        // OLD read_to_string would follow it, read "sk-same", and return Ok (a false idempotent
        // success on a redirected path). O_NOFOLLOW refuses instead.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("idem-symlink");
        let target = dir.join("real.key");
        std::fs::write(&target, "sk-same\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("brain.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // create_new O_NOFOLLOW fails ELOOP (AlreadyExists? no — a generic error), and the
        // idempotent read fd is also O_NOFOLLOW → either way this is a KeyWrite refusal, never
        // a followed read.
        let err = write_key_atomic(&link, "sk-same").unwrap_err();
        assert_eq!(err.exit_code(), exit_code::KEY_WRITE_FAILURE);
        std::fs::remove_dir_all(&dir).ok();
    }

    // The "leave the partial on a fresh-create write failure" contract (no path-unlink) and the
    // empty-key fingerprint-mismatch guard are asserted in
    // `write_key_atomic_leaves_a_partial_file_and_never_path_unlinks` below.

    // ---- https-before-bearer enforcement (#6) ---------------------------------------

    #[test]
    fn require_secure_node_url_refuses_plaintext_nonloopback() {
        // TOOTH (#6): a bearer secret must never be prepared for a plaintext non-loopback
        // node_url. Reverting `require_secure_node_url` (or dropping its call sites) makes the
        // funding calls proceed to send a bearer over plaintext http. Loopback + https pass.
        assert!(require_secure_node_url("https://api.routstr.com").is_ok());
        assert!(require_secure_node_url("http://127.0.0.1:7777").is_ok());
        assert!(require_secure_node_url("http://localhost:8080").is_ok());
        let err = require_secure_node_url("http://api.routstr.com").unwrap_err();
        assert_eq!(
            err.exit_code(),
            exit_code::USAGE_ERROR,
            "plaintext non-loopback is a usage refusal before any network call"
        );
        // The userinfo-bypass host is resolved correctly (true host = evil.com → refused).
        assert!(require_secure_node_url("http://localhost:pw@evil.com/").is_err());
    }

    // ---- node_url binding (F9) ------------------------------------------------------

    #[test]
    fn node_url_binding_round_trips_and_sidecar_is_0600() {
        let dir = temp_dir("bind");
        let key_path = dir.join("brain.key");
        write_node_url_binding(&key_path, "https://api.routstr.com/").unwrap();
        // Trailing slash is normalized away on write.
        assert_eq!(
            read_node_url_binding(&key_path).unwrap().as_deref(),
            Some("https://api.routstr.com")
        );
        // The sidecar sits BESIDE the key with a distinct name (keyfile stays raw sk-).
        assert_eq!(
            node_url_sidecar_path(&key_path),
            dir.join("brain.key.node_url")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(node_url_sidecar_path(&key_path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the node_url sidecar is 0600");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_bound_node_url_refuses_mismatched_override_without_flag() {
        // F9: balance/topup use the BOUND url. A mismatched --node-url without the explicit
        // override flag is REFUSED (never send a bearer key to a different server). Reverting
        // the guard (returning the override unconditionally) makes this RED.
        let dir = temp_dir("resolve");
        let key_path = dir.join("brain.key");
        write_node_url_binding(&key_path, "https://api.routstr.com").unwrap();

        // Mismatched override, no flag -> refused.
        let err =
            resolve_bound_node_url(&key_path, Some("https://evil.example.com"), false).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::USAGE_ERROR);

        // Same override as the binding -> allowed (no-op).
        let same =
            resolve_bound_node_url(&key_path, Some("https://api.routstr.com/"), false).unwrap();
        assert_eq!(same, "https://api.routstr.com");

        // Mismatched override WITH the flag -> allowed (caller warns).
        let over =
            resolve_bound_node_url(&key_path, Some("https://evil.example.com"), true).unwrap();
        assert_eq!(over, "https://evil.example.com");

        // No override -> the bound url.
        let bound = resolve_bound_node_url(&key_path, None, false).unwrap();
        assert_eq!(bound, "https://api.routstr.com");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn invoice_state_round_trips_invoice_id_and_node_url_0600() {
        let dir = temp_dir("invoice");
        let key_path = dir.join("brain.key");
        // The pending state holds BOTH the invoice_id AND the node_url it was created against
        // (so poll targets the right node). The node_url is normalized (trailing slash gone).
        write_invoice_state(&key_path, "inv-abc-123", "https://custom.node.example/").unwrap();
        let pending = read_invoice_state(&key_path)
            .unwrap()
            .expect("pending state parses");
        assert_eq!(pending.invoice_id, "inv-abc-123");
        assert_eq!(pending.node_url, "https://custom.node.example");
        assert_eq!(invoice_state_path(&key_path), dir.join("brain.key.invoice"));
        // It is JSON on disk (not a bare string), so poll can recover node_url from it.
        let raw = std::fs::read_to_string(invoice_state_path(&key_path)).unwrap();
        assert!(raw.contains("\"invoice_id\""));
        assert!(raw.contains("\"node_url\""));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(invoice_state_path(&key_path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o600,
                "the invoice_id sidecar is 0600 (it is capability-sensitive)"
            );
        }
        // clear removes it and returns Ok; a second clear on the now-absent sidecar is also Ok
        // (NotFound is idempotent, not an error).
        clear_invoice_state(&key_path).unwrap();
        assert!(read_invoice_state(&key_path).unwrap().is_none());
        clear_invoice_state(&key_path).expect("clearing an absent sidecar is Ok (idempotent)");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_sidecar_enforces_0600_on_an_existing_wider_mode_file() {
        // TOOTH (#3/write_sidecar): a pre-existing 0644 sidecar must be re-permissioned to 0600
        // on write — the mode-on-create flag alone would leave 0644 (world-readable). Exercised
        // via the node_url binding, which legitimately OVERWRITES its sidecar (the pending-invoice
        // sidecar is O_EXCL create-new and refuses an existing file, so it cannot test overwrite).
        // Reverting to the create-only `.mode(0o600)` (no fchmod on the open fd) makes this RED:
        // the file would stay 0644.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("sidecar-mode");
        let key_path = dir.join("brain.key");
        let sidecar = node_url_sidecar_path(&key_path);
        // Plant a world-readable sidecar with stale content.
        std::fs::write(&sidecar, "stale\n").unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
            0o644,
            "precondition: the planted sidecar is 0644"
        );
        // Writing a fresh binding must drop it to 0600 AND replace the content.
        write_node_url_binding(&key_path, "https://api.routstr.com").unwrap();
        assert_eq!(
            std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
            0o600,
            "an existing wider-mode sidecar is re-permissioned to 0600"
        );
        assert_eq!(
            read_node_url_binding(&key_path).unwrap().as_deref(),
            Some("https://api.routstr.com")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_sidecar_refuses_to_follow_a_symlink() {
        // Complements the 0600 tooth: O_NOFOLLOW means a symlink planted at the sidecar path is
        // refused, never written THROUGH to its target. Exercised via the node_url binding (the
        // overwriting sidecar). Reverting O_NOFOLLOW would clobber the target's content + mode.
        let dir = temp_dir("sidecar-symlink");
        let key_path = dir.join("brain.key");
        let sidecar = node_url_sidecar_path(&key_path);
        let target = dir.join("target.txt");
        std::fs::write(&target, "victim\n").unwrap();
        std::os::unix::fs::symlink(&target, &sidecar).unwrap();
        let err = write_node_url_binding(&key_path, "https://api.routstr.com").unwrap_err();
        assert_eq!(err.exit_code(), exit_code::KEY_WRITE_FAILURE);
        // The symlink target is untouched.
        assert_eq!(std::fs::read_to_string(&target).unwrap().trim(), "victim");
        std::fs::remove_dir_all(&dir).ok();
    }

    // The "O_EXCL pending sidecar is exactly 0600 even under a restrictive umask" tooth lives in
    // the integration suite (`tests/fund_key.rs::create_pending_sidecar_is_0600_under_restrictive_umask`):
    // it drives `fund-key create` in a CHILD process whose umask is set via `pre_exec`, so the
    // restrictive umask is isolated to that child and never races the (thread-parallel) unit tests
    // — a process-global `libc::umask` in a unit test breaks every concurrent test that creates a
    // file or directory.

    #[test]
    fn write_invoice_state_refuses_an_existing_pending_sidecar() {
        // TOOTH (F2/F7): the PENDING-invoice write is O_EXCL create-new — it REFUSES if a pending
        // sidecar already exists, so a fresh create/provision can never overwrite the capability
        // of a paid-but-unpolled invoice (which would strand the funds; there is no `recover`).
        // Reverting `write_invoice_state` to the overwriting `write_sidecar` makes this RED: the
        // second write would clobber the first invoice_id instead of refusing.
        let dir = temp_dir("invoice-excl");
        let key_path = dir.join("brain.key");
        write_invoice_state(&key_path, "inv-FIRST", "https://api.routstr.com").unwrap();
        let err =
            write_invoice_state(&key_path, "inv-SECOND", "https://api.routstr.com").unwrap_err();
        assert_eq!(
            err.exit_code(),
            exit_code::USAGE_ERROR,
            "an existing pending sidecar is a usage refusal (resume via poll), not a clobber"
        );
        // The FIRST invoice_id is intact — never overwritten.
        let pending = read_invoice_state(&key_path).unwrap().unwrap();
        assert_eq!(
            pending.invoice_id, "inv-FIRST",
            "the original pending capability survives (no clobber)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_sidecar_hardened_fails_closed_on_symlink_and_wrong_mode() {
        // TOOTH (F9 read side): the hardened sidecar reader must FAIL CLOSED (Err, not None) on a
        // present-but-unsafe sidecar — a symlink or a wrong-mode file — so a tampered node_url
        // binding never redirects the bearer key and a tampered pending sidecar never silently
        // reads as "absent". Reverting the readers to `std::fs::read_to_string` makes this RED:
        // the symlink would be FOLLOWED (returning the target's content) and the 0644 file trusted.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("read-hardened");
        let key_path = dir.join("brain.key");

        // (1) A symlinked node_url binding -> Err (fail closed), not a followed read.
        let bind = node_url_sidecar_path(&key_path);
        let evil = dir.join("evil.txt");
        std::fs::write(&evil, "https://evil.example.com\n").unwrap();
        std::os::unix::fs::symlink(&evil, &bind).unwrap();
        assert!(
            read_node_url_binding(&key_path).is_err(),
            "a symlinked node_url binding fails closed (never follows to the evil target)"
        );
        std::fs::remove_file(&bind).unwrap();

        // (2) A wrong-mode (0644) node_url binding -> Err (fail closed).
        std::fs::write(&bind, "https://api.routstr.com\n").unwrap();
        std::fs::set_permissions(&bind, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            read_node_url_binding(&key_path).is_err(),
            "a wrong-mode node_url binding fails closed"
        );
        std::fs::remove_file(&bind).unwrap();

        // (3) A wrong-mode pending sidecar -> Err (fail closed), distinct from absent (Ok(None)).
        let inv = invoice_state_path(&key_path);
        let json =
            serde_json::json!({"invoice_id":"inv-x","node_url":"https://api.routstr.com"}).to_string();
        std::fs::write(&inv, format!("{json}\n")).unwrap();
        std::fs::set_permissions(&inv, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            read_invoice_state(&key_path).is_err(),
            "a wrong-mode pending sidecar fails closed (not silently absent)"
        );

        // Sanity: a genuinely absent sidecar is Ok(None), not an error.
        std::fs::remove_file(&inv).unwrap();
        assert!(read_invoice_state(&key_path).unwrap().is_none());
        assert!(read_node_url_binding(&key_path).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_bound_node_url_fails_closed_on_tampered_binding() {
        // TOOTH (F9): resolve_bound_node_url must FAIL CLOSED when the binding sidecar is present
        // but unsafe — never fall through to the override/default (which would send the bearer key
        // to an attacker-chosen host). Here a wrong-mode binding is present AND an override is
        // given: the resolve must ERROR, not return the override. Reverting the reader to a
        // read_to_string that returns None on a wrong-mode file makes this RED (it would return
        // the override url).
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("resolve-tampered");
        let key_path = dir.join("brain.key");
        let bind = node_url_sidecar_path(&key_path);
        std::fs::write(&bind, "https://api.routstr.com\n").unwrap();
        std::fs::set_permissions(&bind, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = resolve_bound_node_url(&key_path, Some("https://attacker.example.com"), true)
            .expect_err("a present-but-tampered binding must fail closed");
        assert_eq!(err.exit_code(), exit_code::KEY_WRITE_FAILURE);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_key_atomic_leaves_a_partial_file_and_never_path_unlinks() {
        // TOOTH (fresh-create TOCTOU elimination): on a fresh-create write/fsync FAILURE,
        // write_key_atomic must LEAVE the partial file in place — it must NOT unlink by path (a
        // path-based unlink here is a TOCTOU: an entry swapped between the failed write and the
        // cleanup would delete a DIFFERENT file). Forcing a real fsync failure on a
        // normal fd is not portable, so the write-failure branch is covered BY INSPECTION (the
        // error path now returns without any `remove_file(path)`), and this asserts the two
        // observable safety consequences that make "leave the partial" safe:
        //
        //  (1) a partial/empty keyfile is a fingerprint MISMATCH (never silently equals a real
        //      key), so a lingering partial is refused, not trusted; and
        //  (2) the next write_key_atomic on that path hits O_EXCL AlreadyExists and — because the
        //      content differs — refuses with a fingerprint-mismatch error, never clobbering it.
        //
        // Reverting to a path-based unlink would remove this file (breaking the by-inspection
        // contract); the assertions below independently guarantee a leftover partial is safe.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("leave-partial");
        let key_path = dir.join("brain.key");
        // Simulate a partial/empty keyfile left behind by a crashed write (0600, as the create
        // flags would have set it before the write failed).
        std::fs::write(&key_path, "").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // (1)+(2): the next attempt REFUSES (O_EXCL AlreadyExists -> fingerprint mismatch), never
        // trusting or clobbering the lingering partial.
        let err = write_key_atomic(&key_path, "sk-real").unwrap_err();
        assert_eq!(
            err.exit_code(),
            exit_code::KEY_WRITE_FAILURE,
            "a lingering partial is refused by the next O_EXCL+fingerprint write, never trusted"
        );
        // The partial is still present (we never path-unlink it), and the real key never landed.
        assert!(key_path.exists(), "the lingering partial is left in place");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            "",
            "the partial is untouched (no clobber) and the real key was not written"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_invoice_state_is_ok_on_absent_and_errs_on_unlink_failure() {
        // TOOTH (F4 clear): clear_invoice_state returns Ok when the sidecar is ABSENT (NotFound is
        // idempotent) and Err on any OTHER unlink failure — a silent failure would leave the
        // invoice_id capability on disk while poll/provision report "funded". Reverting to
        // `let _ = remove_file(...)` (swallowing the error) makes the read-only-parent case RED
        // (it would return Ok despite the file surviving).
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("clear-result");
        let key_path = dir.join("brain.key");

        // (1) Absent sidecar -> Ok (idempotent NotFound).
        clear_invoice_state(&key_path).expect("clearing an absent sidecar is Ok");

        // (2) Present sidecar under a READ-ONLY parent dir -> the unlink fails (EACCES/EPERM) and
        // the error is PROPAGATED, not swallowed. (Skipped when running as root, where directory
        // write bits are not enforced and the unlink would succeed.)
        let sub = dir.join("locked");
        std::fs::create_dir_all(&sub).unwrap();
        let locked_key = sub.join("brain.key");
        write_invoice_state(&locked_key, "inv-LINGER", "https://api.routstr.com").unwrap();
        let sidecar = invoice_state_path(&locked_key);
        assert!(sidecar.exists(), "precondition: the pending sidecar exists");
        // Make the PARENT dir read-only so removing the entry within it fails.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();
        let running_as_root = std::fs::write(sub.join(".root-probe"), b"x").is_ok();
        // Clean the probe (if any) before asserting.
        let _ = std::fs::remove_file(sub.join(".root-probe"));
        if !running_as_root {
            let err = clear_invoice_state(&locked_key)
                .expect_err("an unlink failure must propagate, not be swallowed");
            assert_eq!(err.exit_code(), exit_code::KEY_WRITE_FAILURE);
            assert!(
                sidecar.exists(),
                "the capability still lingers on disk (the error is why the caller must warn)"
            );
        }
        // Restore write so the temp dir can be cleaned up.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn create_invoice_topup_requires_a_key() {
        // TOOTH: a topup (purpose="topup") with no bearer key is a USAGE error caught BEFORE
        // any network call. The url is a closed loopback (nothing listening), so reverting the
        // guard makes this RED via a NETWORK error (a refused connection) rather than a USAGE
        // refusal — and NEVER via a live api.routstr.com call.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(create_invoice("http://127.0.0.1:1", 100, "topup", None))
            .unwrap_err();
        assert_eq!(err.exit_code(), exit_code::USAGE_ERROR);
    }

    // ---- ecash: minted-key extraction + secret redaction + empty-token guards -------

    #[test]
    fn extract_minted_key_finds_the_empirical_field_and_tolerates_others() {
        // The empirical primary is `api_key` (mirroring the LN status path).
        let m: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"api_key":"sk-ecash-primary","balance":2000}"#).unwrap();
        assert_eq!(extract_minted_key(&m).as_deref(), Some("sk-ecash-primary"));

        // A tolerant fallback field name still funds.
        let m: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"key":"sk-ecash-fallback"}"#).unwrap();
        assert_eq!(extract_minted_key(&m).as_deref(), Some("sk-ecash-fallback"));

        // An UNKNOWN field name whose value is nonetheless `sk-…`-shaped is still caught.
        let m: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"surprise_field":"sk-shaped-value","x":1}"#).unwrap();
        assert_eq!(extract_minted_key(&m).as_deref(), Some("sk-shaped-value"));

        // An empty string in the primary field is NOT accepted (a blank is not a key); nothing
        // key-shaped -> None (the caller maps that to a Network/malformed error).
        let m: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"api_key":"","detail":"nope"}"#).unwrap();
        assert_eq!(extract_minted_key(&m), None);
    }

    #[test]
    fn ecash_secret_types_redact_in_debug() {
        // TOOTH: the ecash secret-bearing types must NOT print their secret via `{:?}`
        // (an assert failure or a stray log renders Debug). Reverting either custom `Debug`
        // to a derived one makes this RED — the raw cashu token / minted sk- would appear.
        let req = TopupRequest {
            cashu_token: "cashuBSECRET-TOKEN".into(),
        };
        let d = format!("{req:?}");
        assert!(
            !d.contains("cashuBSECRET-TOKEN"),
            "the cashu token must not appear in Debug: {d}"
        );
        assert!(d.contains("<redacted>"), "the token is redacted: {d}");

        let raw: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"api_key":"sk-ECASH-SECRET","balance":10}"#).unwrap();
        let resp = EcashCreateResponse { raw };
        let d = format!("{resp:?}");
        assert!(
            !d.contains("sk-ECASH-SECRET"),
            "the minted sk- must not appear in Debug: {d}"
        );
        assert!(d.contains("<redacted>"), "the key is redacted: {d}");
        // The KEY NAMES (not values) are shown for diagnosis.
        assert!(d.contains("api_key"), "the field names are shown: {d}");
    }

    #[test]
    fn create_from_token_rejects_an_empty_token() {
        // TOOTH: an empty cashu token is a USAGE error caught BEFORE any network call. The url is
        // a closed loopback (nothing listening), so reverting the empty-token guard makes this RED
        // via a NETWORK error (a refused connection), never a live api.routstr.com call.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(create_from_token("http://127.0.0.1:1", "   ", None))
            .unwrap_err();
        assert_eq!(err.exit_code(), exit_code::USAGE_ERROR);
    }

    #[test]
    fn topup_from_token_rejects_an_empty_token() {
        // TOOTH: an empty cashu token is a USAGE error caught BEFORE any network call (same
        // closed-loopback guarantee as above — never a live call).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(topup_from_token("http://127.0.0.1:1", "sk-key", ""))
            .unwrap_err();
        assert_eq!(err.exit_code(), exit_code::USAGE_ERROR);
    }
}
