//! Shared test support for the RoutstrBrain layers (brain-routstr §8). This file lives
//! in a SUBDIRECTORY of `tests/`, so cargo does NOT compile it as its own test binary;
//! `mod common;` pulls it into a layer test. It provides two dependency-free,
//! offline-safe doubles so Layer A runs with ZERO mint and ZERO network beyond loopback:
//!   - [`MockNode`]: a tiny hand-rolled tokio HTTP server standing in for a Routstr node
//!     (no wiremock dep — works in a sealed build). It records the request it received
//!     (so a test can assert the JSON shape + the `X-Cashu` header) and replies per a
//!     configured [`NodeBehavior`] for the completion endpoint and [`RefundBehavior`]
//!     for the RIP-01 refund endpoint.
//!   - [`StubEcash`]: a deterministic [`EcashProvider`] (no mint) that models minting a
//!     token worth the cap, redeeming a foreign `ecash:<n>` token for `n` sats, and
//!     revoking our own send (success or "consumed").
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kirby_node::rail::{EcashProvider, OperationId, SendHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---- MockNode: an offline HTTP mock for the Routstr completion + refund endpoints ----

/// How the mock answers `POST /v1/chat/completions`.
#[derive(Clone)]
pub enum NodeBehavior {
    /// 200 with `reply` as `choices[0].message.content`; `change_token`, if set, is
    /// returned in the `X-Cashu` response header.
    Reply {
        reply: String,
        change_token: Option<String>,
    },
    /// 200 with `reply`, but FIRST the mock REDEEMS the `X-Cashu` bearer it received via
    /// `redeem` — consuming the brain's token at the mint the way a real Routstr node does —
    /// and returns the change token the hook yields in the `X-Cashu` response header. This
    /// proves node-CONSUMPTION (the sent token was real, spendable, and is now spent), not
    /// just the brain's local cost bookkeeping.
    Redeem {
        reply: String,
        redeem: RedeemHook,
    },
    /// A non-2xx status (e.g. 402 payment rejected, 500 model error).
    Status(u16),
    /// 200 with a body that is NOT valid completion JSON (malformed / missing content).
    Malformed,
    /// Accept the connection but never respond (a black hole) — the client times out.
    Hang,
}

/// An async hook the round-trip mock invokes with the `X-Cashu` bearer token it received,
/// so the mock REDEEMS (consumes) that token at the mint like a real Routstr node would,
/// and returns the change token to hand back in the `X-Cashu` response header. Defined
/// transport-only (`String` -> `String`): the cdk redeem logic lives in the layer test,
/// keeping this module mint-free and dependency-light.
pub type RedeemHook =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = String> + Send>> + Send + Sync>;

/// How the mock answers `POST /v1/wallet/refund` (the RIP-01 refund).
#[derive(Clone)]
pub enum RefundBehavior {
    /// No refund offered (404) — the recovery falls through to eating the remainder.
    None,
    /// 200 returning `token` in the `X-Cashu` response header (a refund token to redeem).
    Token(String),
}

/// One request the mock received (for shape assertions).
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub x_cashu: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// A running offline mock Routstr node.
pub struct MockNode {
    base_url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    _shutdown: tokio::task::JoinHandle<()>,
}

impl MockNode {
    /// Bind on an ephemeral loopback port and serve `completion` on the completions
    /// endpoint and `refund` on the refund endpoint until dropped.
    pub async fn start(completion: NodeBehavior, refund: RefundBehavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock node");
        let addr = listener.local_addr().expect("mock node local addr");
        let base_url = format!("http://127.0.0.1:{}", addr.port());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_task = requests.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let behavior = completion.clone();
                let refund = refund.clone();
                let recorder = requests_for_task.clone();
                tokio::spawn(async move {
                    handle_conn(stream, behavior, refund, recorder).await;
                });
            }
        });
        MockNode {
            base_url,
            requests,
            _shutdown: handle,
        }
    }

    /// Convenience: a node that returns `reply` + a `change_token` and no refund.
    pub async fn replying(reply: &str, change_token: Option<&str>) -> Self {
        MockNode::start(
            NodeBehavior::Reply {
                reply: reply.to_string(),
                change_token: change_token.map(|s| s.to_string()),
            },
            RefundBehavior::None,
        )
        .await
    }

    /// Convenience: a node that REDEEMS the `X-Cashu` bearer it receives (proving
    /// consumption at the mint) and returns the change token the hook yields. The
    /// real-mint round-trip counterpart to [`MockNode::replying`].
    pub async fn redeeming(reply: &str, redeem: RedeemHook) -> Self {
        MockNode::start(
            NodeBehavior::Redeem {
                reply: reply.to_string(),
                redeem,
            },
            RefundBehavior::None,
        )
        .await
    }

    /// The base URL to point `RoutstrBrain` at (loopback http — allowed for tests).
    pub fn url(&self) -> String {
        self.base_url.clone()
    }

    /// Every request the node received, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// The first request to the completions endpoint (the assertion target).
    pub fn completion_request(&self) -> Option<RecordedRequest> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.path.contains("/v1/chat/completions"))
            .cloned()
    }
}

impl Drop for MockNode {
    fn drop(&mut self) {
        self._shutdown.abort();
    }
}

async fn handle_conn(
    mut stream: tokio::net::TcpStream,
    completion: NodeBehavior,
    refund: RefundBehavior,
    recorder: Arc<Mutex<Vec<RecordedRequest>>>,
) {
    // Read until the end of the headers, then drain the Content-Length body so the full
    // request is consumed before we respond (avoids an RST that would truncate the reply).
    let mut data: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(_) => return,
        }
        if let Some(pos) = find_subsequence(&data, b"\r\n\r\n") {
            break pos;
        }
        if data.len() > 1_000_000 {
            return;
        }
    };

    let head = String::from_utf8_lossy(&data[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut x_cashu = None;
    let mut content_type = None;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name.as_str() {
                "x-cashu" => x_cashu = Some(value.to_string()),
                "content-type" => content_type = Some(value.to_string()),
                "content-length" => content_length = value.parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    // Drain the body (anything past the header terminator).
    let mut body = data[header_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    // Keep a copy of the received bearer for the redeem path (the record moves it).
    let x_cashu_received = x_cashu.clone();
    recorder.lock().unwrap().push(RecordedRequest {
        method,
        path: path.clone(),
        x_cashu,
        content_type,
        body,
    });

    // Dispatch by endpoint.
    if path.contains("/v1/wallet/refund") {
        match refund {
            RefundBehavior::None => {
                write_response(&mut stream, 404, "Not Found", &[], b"").await;
            }
            RefundBehavior::Token(token) => {
                write_response(&mut stream, 200, "OK", &[("X-Cashu", &token)], b"{}").await;
            }
        }
        return;
    }

    // The completions endpoint.
    match completion {
        NodeBehavior::Reply {
            reply,
            change_token,
        } => {
            let body = serde_json::json!({
                "id": "mock-cmpl",
                "object": "chat.completion",
                "choices": [{ "index": 0, "message": { "role": "assistant", "content": reply } }],
            })
            .to_string();
            let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
            if let Some(ref tok) = change_token {
                headers.push(("X-Cashu", tok));
            }
            write_response(&mut stream, 200, "OK", &headers, body.as_bytes()).await;
        }
        NodeBehavior::Redeem { reply, redeem } => {
            // Like a real Routstr node: REDEEM (consume) the X-Cashu bearer at the mint
            // before replying, then hand back the change token the hook minted from it.
            let bearer = x_cashu_received.unwrap_or_default();
            let change_token = redeem(bearer).await;
            let body = serde_json::json!({
                "id": "mock-cmpl",
                "object": "chat.completion",
                "choices": [{ "index": 0, "message": { "role": "assistant", "content": reply } }],
            })
            .to_string();
            let headers: Vec<(&str, &str)> = vec![
                ("Content-Type", "application/json"),
                ("X-Cashu", &change_token),
            ];
            write_response(&mut stream, 200, "OK", &headers, body.as_bytes()).await;
        }
        NodeBehavior::Status(code) => {
            write_response(&mut stream, code, "Error", &[], b"{\"error\":\"mock\"}").await;
        }
        NodeBehavior::Malformed => {
            write_response(
                &mut stream,
                200,
                "OK",
                &[("Content-Type", "application/json")],
                b"this is not the json you are looking for",
            )
            .await;
        }
        NodeBehavior::Hang => {
            // Never respond; let the client's deadline fire. Hold the connection open.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    let _ = stream.write_all(body).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---- StubEcash: a deterministic, mint-free EcashProvider for Layer A -----------------

/// A synthetic ecash token the stub mints/redeems: `ecash:<sats>`. The [`MockNode`]
/// hands the SAME string back as the change/refund token, so [`StubEcash::redeem_foreign`]
/// recovers exactly `<sats>` — coupling the wire mock to the ledger double deterministically.
fn synthetic_token(sats: u64) -> String {
    format!("ecash:{sats}")
}

fn parse_synthetic(token: &str) -> Option<u64> {
    token.strip_prefix("ecash:").and_then(|s| s.parse::<u64>().ok())
}

struct StubEcashInner {
    fail_mint: bool,
    hang_mint: bool,
    revoke_succeeds: bool,
    minted: Mutex<HashMap<OperationId, u64>>,
    op_counter: AtomicU64,
    mint_calls: AtomicU64,
    revoke_calls: AtomicU64,
    redeem_calls: AtomicU64,
    recover_calls: AtomicU64,
}

/// A clone-able handle to a deterministic ecash provider (the clones share state, so a
/// test can keep a handle to assert call counts after moving one into `RoutstrBrain`).
#[derive(Clone)]
pub struct StubEcash {
    inner: Arc<StubEcashInner>,
}

impl StubEcash {
    fn with(fail_mint: bool, hang_mint: bool, revoke_succeeds: bool) -> Self {
        StubEcash {
            inner: Arc::new(StubEcashInner {
                fail_mint,
                hang_mint,
                revoke_succeeds,
                minted: Mutex::new(HashMap::new()),
                op_counter: AtomicU64::new(1),
                mint_calls: AtomicU64::new(0),
                revoke_calls: AtomicU64::new(0),
                redeem_calls: AtomicU64::new(0),
                recover_calls: AtomicU64::new(0),
            }),
        }
    }

    /// Healthy: mints fine, and a revoke of an un-consumed send recovers its full value.
    pub fn healthy() -> Self {
        Self::with(false, false, true)
    }

    /// The mint itself fails (pre-mint failure: no sats ever leave the wallet).
    pub fn failing_mint() -> Self {
        Self::with(true, false, false)
    }

    /// The mint hangs forever (a wallet-op hang for the kill-window test).
    pub fn hanging_mint() -> Self {
        Self::with(false, true, false)
    }

    /// Mints fine, but a revoke FAILS (models the node having already consumed the
    /// token, so the same-wallet reclaim is not possible — the recovery falls to refund).
    pub fn revoke_fails() -> Self {
        Self::with(false, false, false)
    }

    pub fn mint_calls(&self) -> u64 {
        self.inner.mint_calls.load(Ordering::SeqCst)
    }
    pub fn revoke_calls(&self) -> u64 {
        self.inner.revoke_calls.load(Ordering::SeqCst)
    }
    pub fn redeem_calls(&self) -> u64 {
        self.inner.redeem_calls.load(Ordering::SeqCst)
    }
    pub fn recover_calls(&self) -> u64 {
        self.inner.recover_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl EcashProvider for StubEcash {
    async fn mint_send_token(&self, amount_sats: u64) -> anyhow::Result<SendHandle> {
        self.inner.mint_calls.fetch_add(1, Ordering::SeqCst);
        if self.inner.hang_mint {
            // Hang past any sane test deadline; the caller's timeout drops this future.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        if self.inner.fail_mint {
            anyhow::bail!("stub mint failure (no sats spent)");
        }
        let op = OperationId::from_u128(self.inner.op_counter.fetch_add(1, Ordering::SeqCst) as u128);
        self.inner.minted.lock().unwrap().insert(op, amount_sats);
        Ok(SendHandle {
            token: synthetic_token(amount_sats),
            operation_id: op,
        })
    }

    async fn redeem_foreign(&self, token: &str) -> anyhow::Result<u64> {
        self.inner.redeem_calls.fetch_add(1, Ordering::SeqCst);
        parse_synthetic(token)
            .ok_or_else(|| anyhow::anyhow!("stub cannot redeem non-synthetic token {token:?}"))
    }

    async fn revoke_send(&self, op: &OperationId) -> anyhow::Result<u64> {
        self.inner.revoke_calls.fetch_add(1, Ordering::SeqCst);
        if !self.inner.revoke_succeeds {
            anyhow::bail!("stub revoke failed (token already consumed by the node)");
        }
        let amount = self.inner.minted.lock().unwrap().get(op).copied().unwrap_or(0);
        Ok(amount)
    }

    async fn recover_incomplete_sagas(&self) -> anyhow::Result<()> {
        self.inner.recover_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Bind an ephemeral loopback port, capture it, and release it — for handing a free port
/// to a fixture (e.g. the fake mint) that needs a fixed port. A small bind-race window,
/// acceptable for tests.
pub async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind for free port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

// ---- A local fakewallet mint (Layer B): a real cdk-mintd HTTP mint, no real money -----
//
// Mirrors the fixture the brokered_act.rs / full_loop.rs G5 tests stand up (trimmed to
// the fakewallet + sqlite features; cdk-mintd is a dev-dependency). Layer B uses it to
// run REAL cdk wallet ops (prepare_send/confirm/receive/revoke_send) end-to-end with no
// real money and no real Routstr.
pub mod mint_fixture {
    use std::sync::Arc;
    use std::time::Duration;

    use cdk::nuts::CurrencyUnit;
    use tokio::sync::Notify;

    /// A running local fakewallet mint.
    pub struct FakeMint {
        port: u16,
        shutdown: Arc<Notify>,
        handle: tokio::task::JoinHandle<()>,
        _work_dir: TempDir,
    }

    impl FakeMint {
        /// Boot the mint on `port` and wait (bounded) for it to serve `/v1/info`.
        pub async fn start(port: u16) -> anyhow::Result<Self> {
            let work_dir = TempDir::new(&format!("kirby-routstr-mint-{port}"));
            let settings = fake_wallet_settings(port);
            let shutdown = Arc::new(Notify::new());

            let work_dir_path = work_dir.path().to_path_buf();
            let shutdown_for_task = shutdown.clone();
            let handle = tokio::spawn(async move {
                let shutdown_future = async move {
                    shutdown_for_task.notified().await;
                };
                if let Err(e) = cdk_mintd::run_mintd_with_shutdown(
                    &work_dir_path,
                    &settings,
                    shutdown_future,
                    None,
                    None,
                    vec![],
                )
                .await
                {
                    eprintln!("local fakewallet mint exited with error: {e}");
                }
            });

            wait_ready(port, Duration::from_secs(30)).await?;
            Ok(FakeMint {
                port,
                shutdown,
                handle,
                _work_dir: work_dir,
            })
        }

        /// The mint's base URL.
        pub fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// Signal the mint to shut down and await its task.
        pub async fn shutdown(self) {
            self.shutdown.notify_waiters();
            let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
        }
    }

    async fn wait_ready(port: u16, timeout: Duration) -> anyhow::Result<()> {
        let url = format!("http://127.0.0.1:{port}");
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Ok(wallet) = kirby_node::mint_rig::build_wallet(&url).await {
                if wallet.fetch_mint_info().await.is_ok() {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("local fakewallet mint on port {port} did not become ready in time");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    fn fake_wallet_settings(port: u16) -> cdk_mintd::config::Settings {
        let info = cdk_mintd::config::Info {
            url: format!("http://127.0.0.1:{port}"),
            listen_host: "127.0.0.1".to_string(),
            listen_port: port,
            seed: None,
            mnemonic: Some(
                "eye survey guilt napkin crystal cup whisper salt luggage manage unveil loyal"
                    .to_string(),
            ),
            signatory_url: None,
            signatory_certs: None,
            input_fee_ppk: None,
            use_keyset_v2: None,
            http_cache: Default::default(),
            logging: Default::default(),
            enable_info_page: None,
            quote_ttl: None,
        };

        let fake_wallet = cdk_mintd::config::FakeWallet {
            supported_units: vec![CurrencyUnit::Sat],
            fee_percent: 0.0,
            reserve_fee_min: 1.into(),
            ..Default::default()
        };

        cdk_mintd::config::Settings {
            info,
            ln: vec![cdk_mintd::config::Ln {
                ln_backend: cdk_mintd::config::LnBackend::FakeWallet,
                ..Default::default()
            }],
            fake_wallet: Some(fake_wallet),
            ..Default::default()
        }
    }

    /// A unique temp directory removed on drop (the mint's sqlite db lives here).
    pub struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("{prefix}-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&path).expect("create mint work dir");
            TempDir { path }
        }
        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

