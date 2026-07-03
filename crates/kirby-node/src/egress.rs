//! C-EGRESS: the HTTP egress actuator (the `http.fetch` Actuate kind) and its NON-RELAXABLE SSRF
//! guard.
//!
//! This is the first door that lets untrusted, genome-chosen bytes leave the host to a
//! genome-chosen destination — the highest-blast-radius capability on the roadmap. The
//! security-critical logic is isolated here as ONE auditable surface with direct unit teeth.
//!
//! Money-confinement invariant: [`HttpEgressActuator`] holds ONLY a policy + a DNS resolver seam
//! (it builds a fresh `reqwest` client per fetch). It holds NO key material — the DM/publish keys
//! live in `NostrActuator`, the ecash wallet seed + FROST shares live behind other traits this
//! module never touches. So a compromised or injected fetch can never sign a sighash, melt ecash,
//! or read a secret; the only spend it can cause is the metered debit for the fetch itself, capped
//! at the budget like every act. A new door, reasoned about in isolation, that cannot reach custody.
//!
//! The guard, in order (a fetch that fails ANY step is refused and debits 0):
//!   1. scheme == https (no http/file/gopher/ftp), no URL userinfo;
//!   2. method in the policy set (Increment 1: GET/HEAD only — safe, idempotent reads);
//!   3. host on the `[egress] host_allowlist` (exact, case-insensitive), and NOT a refused infra
//!      host (the fleet relay / the mint — belt-and-suspenders, even if a future deploy allowlists
//!      them);
//!   4. RESOLVE the host, and REJECT if ANY resolved IP is in the non-relaxable denied floor
//!      (loopback / RFC1918 / link-local + cloud metadata / ULA / CGNAT / unspecified / multicast /
//!      broadcast / benchmark), then PIN the vetted IP for the connect (reqwest never re-resolves,
//!      closing the DNS-rebinding / TOCTOU window);
//!   5. redirects DISABLED (a 3xx returns to the genome unfollowed; it must re-request the target,
//!      which re-runs the FULL guard — closes redirect-to-metadata);
//!   6. the response body is bounded by a host cap (finite worst case = pre-authorizable cost), and
//!      metered DAEMON-SIDE (the eBPF VM-TAP meter never sees a C-EGRESS byte — the VM never egresses).
//!
//! The IP-range check ([`ip_is_denied`]) and the request screen ([`screen_request`]) are PURE
//! functions with direct unit teeth; DNS resolution is the one impurity, behind the injectable
//! [`EgressResolver`] seam so the resolve-then-pin rebinding tooth is deterministic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kirby_proto::{HttpFetch, HttpHeader, HttpResponse};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::rail::{Actuator, RailOutcome};

/// Response headers surfaced back to the genome; everything else (Set-Cookie, WWW-Authenticate,
/// Location, ...) is DROPPED. Fetched content is untrusted, and the return path must not smuggle
/// auth/cookie/redirect state to the brain. Lowercase for case-insensitive matching.
const RESP_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "content-language",
    "date",
    "last-modified",
    "etag",
    "cache-control",
    "expires",
];

/// Request headers the genome may set; everything else is DROPPED. Fail-closed (an ALLOWLIST, not a
/// denylist) so a new smuggling/auth header can never ride through. No Host/Authorization/Cookie —
/// the daemon owns the connection; the genome cannot inject credentials or override the authority.
const REQ_HEADER_ALLOWLIST: &[&str] = &[
    "accept",
    "accept-language",
    "user-agent",
    "if-none-match",
    "if-modified-since",
];

/// The connect timeout for an egress fetch (bounds a stalled TCP/TLS handshake). The overall
/// request timeout is the policy `timeout_ms`.
const EGRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------------------------
// The NON-RELAXABLE SSRF floor (PURE — direct unit teeth).
// ---------------------------------------------------------------------------------------------

/// `true` => `ip` must NEVER be the target of an egress fetch, regardless of the host allowlist or
/// any config knob. The heart of the C-EGRESS security model, and a hardcoded floor: no deployment
/// can allowlist past it. PURE — the DNS resolution that feeds it is the one impurity (behind
/// [`EgressResolver`]).
///
/// Covers, for both v4 and v6 (and v4-in-v6, which is unwrapped and re-checked):
///   - loopback (`127.0.0.0/8`, `::1`)
///   - RFC1918 private (`10/8`, `172.16/12`, `192.168/16`)
///   - link-local (`169.254.0.0/16` — INCLUDING the `169.254.169.254` cloud-metadata IP — and `fe80::/10`)
///   - ULA (`fc00::/7`)
///   - CGNAT / RFC6598 shared (`100.64.0.0/10`)
///   - unspecified (`0.0.0.0/8`, `::`)
///   - multicast, broadcast
///   - benchmark (`198.18.0.0/15`, RFC2544)
pub(crate) fn ip_is_denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_denied(v4),
        IpAddr::V6(v6) => {
            // A v4-mapped (`::ffff:a.b.c.d`) or v4-compatible (`::a.b.c.d`) address can smuggle a
            // denied v4 target through a v6 literal — unwrap and re-check against the v4 floor.
            if let Some(v4) = v6.to_ipv4() {
                return v4_is_denied(v4);
            }
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
        }
    }
}

fn v4_is_denied(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()            // 127.0.0.0/8
        || v4.is_private()      // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()   // 169.254.0.0/16 (incl. 169.254.169.254 metadata)
        || v4.is_broadcast()    // 255.255.255.255
        || v4.is_multicast()    // 224.0.0.0/4
        || v4.is_unspecified()  // 0.0.0.0
        || o[0] == 0            // 0.0.0.0/8 ("this network")
        || (o[0] == 100 && (64..=127).contains(&o[1]))     // 100.64.0.0/10 CGNAT (RFC6598)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmark (RFC2544)
}

/// `fc00::/7` — unique-local addresses (the v6 analogue of RFC1918). `Ipv6Addr::is_unique_local`
/// is unstable, so match the top 7 bits by hand.
fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    (v6.octets()[0] & 0xfe) == 0xfc
}

/// `fe80::/10` — link-local unicast. `Ipv6Addr::is_unicast_link_local` is unstable, so match the
/// top 10 bits by hand.
fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    let o = v6.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// Given the addresses a host resolved to, return the vetted IP to PIN, or `Err` if the host is
/// unsafe: it resolved to nothing, or ANY resolved IP is in the denied floor. Rejecting if ANY (not
/// merely all) IP is denied is deliberate — a rebinding attacker mixes a public and a private A
/// record, so we refuse the whole host. PURE (the resolution that produces `ips` is the impurity).
pub(crate) fn screen_resolved_ips(ips: &[IpAddr]) -> Result<IpAddr, String> {
    if ips.is_empty() {
        return Err("host resolved to no addresses".to_string());
    }
    for ip in ips {
        if ip_is_denied(*ip) {
            return Err(format!(
                "host resolves to a denied address ({ip}); the non-relaxable SSRF floor refuses it"
            ));
        }
    }
    Ok(ips[0])
}

// ---------------------------------------------------------------------------------------------
// The egress policy + the cheap (DNS-free) request screen (PURE — direct unit teeth).
// ---------------------------------------------------------------------------------------------

/// The daemon-side egress policy the actuator enforces, built from `[egress]` config + the host's
/// own relay/mint hosts. Immutable after boot; the genome never sees or sets it. Hosts are stored
/// lowercased, methods uppercased, so matching is case-insensitive.
#[derive(Clone, Debug)]
pub struct EgressPolicy {
    /// Explicit hosts the agent may reach (exact match). Empty = deny all (a valid "on but locked
    /// down" state). Still subject to the SSRF floor.
    pub host_allowlist: Vec<String>,
    /// Permitted methods (Increment 1: a subset of {GET, HEAD}).
    pub methods: Vec<String>,
    /// The host cap on a response body; the caller can only go smaller. Makes the worst-case cost
    /// finite + pre-authorizable.
    pub max_response_bytes: u32,
    /// The host request timeout; the caller can only go smaller.
    pub timeout_ms: u32,
    /// The fixed floor cost (sats) per fetch — a fetch is never free (a flood is self-limiting).
    pub sats_per_request: u64,
    /// The per-KiB cost (sats) on the response body actually read.
    pub sats_per_kib: u64,
    /// The token-bucket cap on fetches per minute (DoS-by-volume guard).
    pub rate_per_min: u32,
    /// Hosts refused EVEN IF allowlisted (belt-and-suspenders): the fleet relay + the mint. Even a
    /// future public-relay deploy can't let the genome speak to the relay/mint via egress.
    pub refused_hosts: Vec<String>,
}

impl EgressPolicy {
    /// Build the runtime policy from `[egress]` config, adding the host's own relay/mint hosts to
    /// the refused set. `refused_hosts` are bare hostnames (already extracted from the relay/mint
    /// URLs); empties are dropped.
    pub fn from_config(cfg: &crate::config::EgressConfig, refused_hosts: Vec<String>) -> Self {
        EgressPolicy {
            host_allowlist: cfg
                .host_allowlist
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            methods: cfg.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
            max_response_bytes: cfg.max_response_bytes,
            timeout_ms: cfg.timeout_ms,
            sats_per_request: cfg.sats_per_request,
            sats_per_kib: cfg.sats_per_kib,
            rate_per_min: cfg.rate_per_min,
            refused_hosts: refused_hosts
                .into_iter()
                .filter(|h| !h.is_empty())
                .map(|h| h.to_ascii_lowercase())
                .collect(),
        }
    }
}

/// A parsed, policy-approved target — everything checkable WITHOUT DNS. The IP-level SSRF floor is
/// applied AFTER resolution (`screen_resolved_ips`), in `actuate`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScreenedRequest {
    pub method: String, // uppercased, in policy.methods
    pub host: String,   // lowercased
    pub port: u16,
    pub url: String,
}

/// The cheap, DNS-free pre-flight guard: scheme == https, no userinfo, a parseable host, method in
/// the policy set (and {GET,HEAD}), host on the allowlist, host not a refused infra host. Returns
/// `Err` (a FREE denial, debit 0) on any violation. PURE.
pub(crate) fn screen_request(
    policy: &EgressPolicy,
    fetch: &HttpFetch,
) -> Result<ScreenedRequest, String> {
    // Method: GET/HEAD only (structural floor), AND in the configured policy set.
    let method = fetch.method.trim().to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return Err(format!(
            "method {:?} not permitted (Increment 1 is GET/HEAD only)",
            fetch.method
        ));
    }
    if !policy.methods.iter().any(|m| m == &method) {
        return Err(format!("method {method} is not in the egress policy method set"));
    }

    // URL: absolute https, a host, no userinfo (the `https://user:pass@host` authority trick).
    let url = fetch.url.trim();
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("unparseable url: {e}"))?;
    if parsed.scheme() != "https" {
        return Err(format!(
            "scheme {:?} not permitted (https only in Increment 1)",
            parsed.scheme()
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("url must not contain userinfo (user:pass@host)".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "url has no host".to_string())?
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);

    // Host allowlist (exact), then the refused infra hosts (relay/mint) even if allowlisted.
    if !policy.host_allowlist.iter().any(|h| h == &host) {
        return Err(format!("host {host:?} is not on the egress allowlist"));
    }
    if policy.refused_hosts.iter().any(|h| h == &host) {
        return Err(format!(
            "host {host:?} is a refused infra host (the fleet relay / the mint) — never reachable via egress"
        ));
    }

    Ok(ScreenedRequest {
        method,
        host,
        port,
        url: url.to_string(),
    })
}

// ---------------------------------------------------------------------------------------------
// The per-minute token bucket (the DoS-by-volume / cost-bomb rate guard).
// ---------------------------------------------------------------------------------------------

/// A monotonic token bucket: `capacity` tokens refill linearly over 60s. Interior-mutable (the
/// actuator is `&self`). The clock is passed in (`Instant`) so the teeth are deterministic.
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate_per_min: u32, now: Instant) -> Self {
        let cap = rate_per_min.max(1) as f64;
        TokenBucket {
            capacity: cap,
            tokens: cap,
            per_sec: cap / 60.0,
            last: now,
        }
    }

    /// Try to consume one token at `now`. `true` => allowed; `false` => rate-limited.
    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The DNS resolver seam (the one impurity; injectable for the rebinding tooth).
// ---------------------------------------------------------------------------------------------

/// Resolves a host to its IP addresses. The default resolves via the host resolver; a test injects
/// a fixed map to prove the resolve-then-screen path (the rebinding tooth) deterministically.
#[async_trait]
pub(crate) trait EgressResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// The production resolver: the host's own DNS via `tokio::net::lookup_host`.
pub(crate) struct SystemResolver;

#[async_trait]
impl EgressResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        let addrs = tokio::net::lookup_host((host, port)).await?;
        Ok(addrs.map(|sa| sa.ip()).collect())
    }
}

// ---------------------------------------------------------------------------------------------
// The actuator.
// ---------------------------------------------------------------------------------------------

/// The HTTP egress actuator: performs the `http.fetch` Actuate kind host-side, behind the SSRF
/// guard, metered daemon-side. A SEPARATE struct from `NostrActuator` (no key material co-habits
/// the egress client), composed alongside it by a kind-router (see `rail::CompositeActuator`).
pub struct HttpEgressActuator {
    policy: EgressPolicy,
    resolver: Arc<dyn EgressResolver>,
    bucket: Mutex<TokenBucket>,
}

impl HttpEgressActuator {
    /// The production actuator: the host DNS resolver.
    pub fn new(policy: EgressPolicy) -> Self {
        Self::with_resolver(policy, Arc::new(SystemResolver))
    }

    /// Inject a resolver (the rebinding tooth substitutes a fixed-IP resolver).
    pub(crate) fn with_resolver(policy: EgressPolicy, resolver: Arc<dyn EgressResolver>) -> Self {
        let bucket = TokenBucket::new(policy.rate_per_min, Instant::now());
        HttpEgressActuator {
            policy,
            resolver,
            bucket: Mutex::new(bucket),
        }
    }

    /// The WORST-CASE cost (sats) of one fetch: the floor + the FULL response cap metered per KiB.
    /// This is what the gateway gates against the budget (finite + pre-authorizable BECAUSE the
    /// response is capped). The actual debit is `<=` this.
    fn worst_case_cost(&self) -> u64 {
        let kib = (self.policy.max_response_bytes as u64).div_ceil(1024);
        self.policy
            .sats_per_request
            .saturating_add(kib.saturating_mul(self.policy.sats_per_kib))
    }

    /// The ACTUAL cost (sats) for a response of `body_len` bytes: the floor + the bytes read,
    /// metered per KiB (rounded up).
    fn meter(&self, body_len: usize) -> u64 {
        let kib = (body_len as u64).div_ceil(1024);
        self.policy
            .sats_per_request
            .saturating_add(kib.saturating_mul(self.policy.sats_per_kib))
    }

    /// The effective response cap: the caller may go smaller than the host cap, never larger. A
    /// caller value of 0 means "use the host default".
    fn effective_response_cap(&self, caller: u32) -> u32 {
        if caller == 0 {
            self.policy.max_response_bytes
        } else {
            caller.min(self.policy.max_response_bytes)
        }
    }

    /// The effective timeout: the caller may go smaller than the host timeout, never larger. A
    /// caller value of 0 means "use the host default".
    fn effective_timeout(&self, caller: u32) -> Duration {
        let ms = if caller == 0 {
            self.policy.timeout_ms
        } else {
            caller.min(self.policy.timeout_ms)
        };
        Duration::from_millis(ms.max(1) as u64)
    }
}

/// Read a response body, bounded to `cap` bytes. Returns the bytes read and whether the body was
/// truncated (hit the cap with more remaining). A mid-stream read error returns the partial body
/// read so far (logged) rather than failing the whole fetch — the metered cost reflects what was read.
async fn read_bounded(mut resp: reqwest::Response, cap: usize) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    let mut truncated = false;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > cap {
                    let take = cap.saturating_sub(body.len());
                    body.extend_from_slice(&chunk[..take]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break, // clean EOF
            Err(e) => {
                tracing::warn!(error = %e, "http.fetch: error reading response body; returning the partial read");
                break;
            }
        }
    }
    (body, truncated)
}

/// The opaque audit proof recorded in the debit ledger: `status` (4 bytes, big-endian) followed by
/// `sha256(body)` (32 bytes). Content-addresses WHAT was fetched without storing the payload (the
/// body rides the receipt's `http_response` field, not the ledger).
fn fetch_proof(status: u32, body: &[u8]) -> Vec<u8> {
    let mut proof = Vec::with_capacity(4 + 32);
    proof.extend_from_slice(&status.to_be_bytes());
    let digest = Sha256::digest(body);
    proof.extend_from_slice(&digest);
    proof
}

/// Collect the ALLOWLISTED response headers into typed pairs; everything else is dropped.
fn allowlisted_response_headers(headers: &reqwest::header::HeaderMap) -> Vec<HttpHeader> {
    headers
        .iter()
        .filter(|(name, _)| RESP_HEADER_ALLOWLIST.contains(&name.as_str()))
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|v| HttpHeader {
                name: name.as_str().to_string(),
                value: v.to_string(),
            })
        })
        .collect()
}

#[async_trait]
impl Actuator for HttpEgressActuator {
    fn cost(&self, kind: &str) -> u64 {
        if kind == kirby_proto::ACTUATE_KIND_HTTP_FETCH {
            self.worst_case_cost()
        } else {
            // Not our kind: refuse OVER_BUDGET at the gate (fail-closed), never perform.
            u64::MAX
        }
    }

    /// Egress cost is VARIABLE: the estimate is a worst-case UPPER BOUND, not the exact cost. This
    /// tells the gateway to gate on the worst case then debit the ACTUAL (perform-then-debit),
    /// rather than reserve the worst case before performing — the debit-only ledger has no refund,
    /// so a worst-case reservation could not be settled down to the actual. Safe because a GET/HEAD
    /// is idempotent (a lost-response retry re-fetches harmlessly under a fresh key).
    fn cost_is_exact(&self, _kind: &str) -> bool {
        false
    }

    fn validate(&self, kind: &str, payload: &[u8]) -> Result<(), String> {
        if kind != kirby_proto::ACTUATE_KIND_HTTP_FETCH {
            return Err(format!("unknown actuator kind {kind:?}"));
        }
        let fetch =
            HttpFetch::decode(payload).map_err(|e| format!("undecodable HttpFetch payload: {e}"))?;
        // The cheap, DNS-free guard. The IP-level SSRF floor runs in `actuate` (it needs DNS). A
        // FREE denial (debit 0) on any violation.
        screen_request(&self.policy, &fetch).map(|_| ())
    }

    async fn actuate(&self, kind: &str, payload: &[u8], cap_sats: u64) -> RailOutcome {
        if kind != kirby_proto::ACTUATE_KIND_HTTP_FETCH {
            tracing::warn!(kind, "HttpEgressActuator asked for an unknown kind; refusing");
            return RailOutcome::UpstreamFailed;
        }
        // DEFENSE IN DEPTH (a new entry point): decode + re-run the cheap guard, never trusting
        // that `validate` ran.
        let fetch = match HttpFetch::decode(payload) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "http.fetch: undecodable payload; refusing");
                return RailOutcome::UpstreamFailed;
            }
        };
        let screened = match screen_request(&self.policy, &fetch) {
            Ok(s) => s,
            Err(reason) => {
                tracing::warn!(%reason, "http.fetch refused by the egress guard; debiting nothing");
                return RailOutcome::UpstreamFailed;
            }
        };

        // RATE LIMIT (DoS-by-volume): consume one token. A rate-denied fetch performs nothing and
        // debits nothing.
        {
            let mut bucket = self.bucket.lock().expect("egress rate bucket poisoned");
            if !bucket.try_take(Instant::now()) {
                tracing::warn!(host = %screened.host, "http.fetch DENIED by the per-minute rate limit; debiting nothing");
                return RailOutcome::UpstreamFailed;
            }
        }

        // RESOLVE-THEN-CHECK: resolve host-side, refuse if ANY resolved IP is in the SSRF floor,
        // then PIN the vetted IP so reqwest connects to exactly it (no re-resolution — closes the
        // DNS-rebinding / TOCTOU window).
        let ips = match self.resolver.resolve(&screened.host, screened.port).await {
            Ok(ips) => ips,
            Err(e) => {
                tracing::warn!(host = %screened.host, error = %e, "http.fetch: DNS resolution failed; refusing");
                return RailOutcome::UpstreamFailed;
            }
        };
        let vetted = match screen_resolved_ips(&ips) {
            Ok(ip) => ip,
            Err(reason) => {
                tracing::warn!(host = %screened.host, %reason, "http.fetch DENIED by the SSRF floor; debiting nothing");
                return RailOutcome::UpstreamFailed;
            }
        };

        // Build a per-request client that PINS host->vetted IP, DISABLES redirects, and clamps the
        // timeout. A fresh client (rather than a shared one) is how we pin a specific vetted IP for
        // THIS host without a global resolver override; egress is low-frequency (rate-capped).
        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(EGRESS_CONNECT_TIMEOUT)
            .timeout(self.effective_timeout(fetch.timeout_ms))
            .resolve(&screened.host, SocketAddr::new(vetted, screened.port))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "http.fetch: failed to build the egress client; refusing");
                return RailOutcome::UpstreamFailed;
            }
        };

        let method = if screened.method == "HEAD" {
            reqwest::Method::HEAD
        } else {
            reqwest::Method::GET
        };
        let mut req = client.request(method, &screened.url);
        // Forward ONLY allowlisted request headers; drop the rest (fail-closed).
        for h in &fetch.headers {
            if REQ_HEADER_ALLOWLIST.contains(&h.name.to_ascii_lowercase().as_str()) {
                req = req.header(&h.name, &h.value);
            }
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(host = %screened.host, error = %e, "http.fetch: request failed; debiting nothing");
                return RailOutcome::UpstreamFailed;
            }
        };

        let status = resp.status().as_u16() as u32;
        let final_url = resp.url().to_string();
        let resp_headers = allowlisted_response_headers(resp.headers());
        let cap = self.effective_response_cap(fetch.max_response_bytes) as usize;
        let (body, truncated) = read_bounded(resp, cap).await;

        // METER daemon-side: floor + per-KiB of the bytes actually read, clamped to `cap_sats`
        // (D-20 — never debit past the reserved worst case).
        let actual_cost = self.meter(body.len()).min(cap_sats);
        let proof = fetch_proof(status, &body);
        let http_response = HttpResponse {
            status,
            headers: resp_headers,
            body,
            truncated,
            final_url,
        };
        tracing::info!(
            host = %screened.host,
            status,
            bytes = http_response.body.len(),
            truncated,
            actual_cost,
            "http.fetch performed (the agent's first voice to the whole internet)"
        );
        RailOutcome::Performed {
            actual_cost,
            proof,
            completion: Vec::new(),
            http_response: Some(http_response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- SSRF floor (ip_is_denied) — the heart of the guard ----

    #[test]
    fn ssrf_floor_denies_loopback() {
        assert!(ip_is_denied(ip("127.0.0.1")));
        assert!(ip_is_denied(ip("127.0.0.53")));
        assert!(ip_is_denied(ip("::1")));
    }

    #[test]
    fn ssrf_floor_denies_cloud_metadata_and_link_local() {
        // The cloud-metadata IP (credential-theft SSRF, the top risk).
        assert!(ip_is_denied(ip("169.254.169.254")));
        assert!(ip_is_denied(ip("169.254.0.1")));
        assert!(ip_is_denied(ip("fe80::1")));
    }

    #[test]
    fn ssrf_floor_denies_rfc1918_private() {
        assert!(ip_is_denied(ip("10.0.0.1")));
        assert!(ip_is_denied(ip("172.16.0.1")));
        assert!(ip_is_denied(ip("172.31.255.255")));
        assert!(ip_is_denied(ip("192.168.1.1")));
    }

    #[test]
    fn ssrf_floor_denies_ula_cgnat_unspecified_multicast() {
        assert!(ip_is_denied(ip("fc00::1"))); // ULA
        assert!(ip_is_denied(ip("fd12:3456::1"))); // ULA
        assert!(ip_is_denied(ip("100.64.0.1"))); // CGNAT
        assert!(ip_is_denied(ip("100.127.255.255"))); // CGNAT top
        assert!(ip_is_denied(ip("0.0.0.0"))); // unspecified
        assert!(ip_is_denied(ip("0.1.2.3"))); // 0.0.0.0/8
        assert!(ip_is_denied(ip("::"))); // v6 unspecified
        assert!(ip_is_denied(ip("224.0.0.1"))); // multicast
        assert!(ip_is_denied(ip("255.255.255.255"))); // broadcast
        assert!(ip_is_denied(ip("198.18.0.1"))); // benchmark
    }

    #[test]
    fn ssrf_floor_denies_v4_mapped_and_compatible_v6_smuggling() {
        // ::ffff:169.254.169.254 must be caught by unwrapping to the v4 floor.
        assert!(ip_is_denied(ip("::ffff:169.254.169.254")));
        assert!(ip_is_denied(ip("::ffff:127.0.0.1")));
        assert!(ip_is_denied(ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn ssrf_floor_allows_public_addresses() {
        // Genuinely public IPs are NOT denied (the guard is a floor, not a blanket deny).
        assert!(!ip_is_denied(ip("1.1.1.1")));
        assert!(!ip_is_denied(ip("8.8.8.8")));
        assert!(!ip_is_denied(ip("93.184.216.34"))); // example.com
        assert!(!ip_is_denied(ip("2606:4700:4700::1111"))); // cloudflare v6
    }

    #[test]
    fn ssrf_boundaries_172_16_and_100_64() {
        // 172.15/172.32 are PUBLIC; only 172.16/12 is private.
        assert!(!ip_is_denied(ip("172.15.255.255")));
        assert!(!ip_is_denied(ip("172.32.0.0")));
        // 100.63 / 100.128 are PUBLIC; only 100.64/10 is CGNAT.
        assert!(!ip_is_denied(ip("100.63.255.255")));
        assert!(!ip_is_denied(ip("100.128.0.0")));
    }

    // ---- screen_resolved_ips (rebinding refusal) ----

    #[test]
    fn resolved_screen_rejects_any_denied_ip() {
        // A rebinding attacker mixes a public + a private A record — the whole host is refused.
        let mixed = [ip("1.1.1.1"), ip("169.254.169.254")];
        assert!(screen_resolved_ips(&mixed).is_err());
        // Empty resolution is refused.
        assert!(screen_resolved_ips(&[]).is_err());
        // All-public resolves to the first vetted IP.
        let ok = [ip("1.1.1.1"), ip("8.8.8.8")];
        assert_eq!(screen_resolved_ips(&ok).unwrap(), ip("1.1.1.1"));
    }

    // ---- screen_request (the cheap DNS-free guard) ----

    fn test_policy() -> EgressPolicy {
        EgressPolicy {
            host_allowlist: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string(), "HEAD".to_string()],
            max_response_bytes: 262_144,
            timeout_ms: 10_000,
            sats_per_request: 1,
            sats_per_kib: 1,
            rate_per_min: 30,
            refused_hosts: vec!["relay.internal".to_string()],
        }
    }

    fn fetch(method: &str, url: &str) -> HttpFetch {
        HttpFetch {
            method: method.to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            max_response_bytes: 0,
            timeout_ms: 0,
        }
    }

    #[test]
    fn screen_accepts_allowlisted_https_get() {
        let p = test_policy();
        let s = screen_request(&p, &fetch("GET", "https://api.example.com/v1/price")).unwrap();
        assert_eq!(s.host, "api.example.com");
        assert_eq!(s.method, "GET");
        assert_eq!(s.port, 443);
    }

    #[test]
    fn screen_rejects_non_https_scheme() {
        let p = test_policy();
        assert!(screen_request(&p, &fetch("GET", "http://api.example.com/")).is_err());
        assert!(screen_request(&p, &fetch("GET", "file:///etc/passwd")).is_err());
        assert!(screen_request(&p, &fetch("GET", "gopher://api.example.com/")).is_err());
    }

    #[test]
    fn screen_rejects_non_allowlisted_host() {
        let p = test_policy();
        assert!(screen_request(&p, &fetch("GET", "https://evil.com/")).is_err());
    }

    #[test]
    fn screen_rejects_refused_infra_host_even_if_shaped_ok() {
        let mut p = test_policy();
        // Even if the relay host were somehow allowlisted, it is refused.
        p.host_allowlist.push("relay.internal".to_string());
        assert!(screen_request(&p, &fetch("GET", "https://relay.internal/")).is_err());
    }

    #[test]
    fn screen_rejects_disallowed_method_and_userinfo() {
        let p = test_policy();
        assert!(screen_request(&p, &fetch("POST", "https://api.example.com/")).is_err());
        assert!(screen_request(&p, &fetch("DELETE", "https://api.example.com/")).is_err());
        // userinfo authority trick.
        assert!(screen_request(&p, &fetch("GET", "https://user:pass@api.example.com/")).is_err());
    }

    #[test]
    fn screen_is_case_insensitive_on_host_and_method() {
        let p = test_policy();
        let s = screen_request(&p, &fetch("get", "https://API.Example.COM/x")).unwrap();
        assert_eq!(s.host, "api.example.com");
        assert_eq!(s.method, "GET");
    }

    // ---- token bucket (rate limit) ----

    #[test]
    fn token_bucket_caps_then_refills() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(2, t0);
        assert!(b.try_take(t0)); // 1st ok
        assert!(b.try_take(t0)); // 2nd ok (capacity 2)
        assert!(!b.try_take(t0)); // 3rd denied — bucket empty
                                  // After 60s the bucket has fully refilled.
        assert!(b.try_take(t0 + Duration::from_secs(60)));
    }

    // ---- metering ----

    #[test]
    fn metering_floor_plus_per_kib_rounds_up() {
        let a = HttpEgressActuator::new(test_policy());
        assert_eq!(a.meter(0), 1); // floor only
        assert_eq!(a.meter(1), 2); // floor + 1 KiB (rounded up from 1 byte)
        assert_eq!(a.meter(1024), 2); // floor + exactly 1 KiB
        assert_eq!(a.meter(1025), 3); // floor + 2 KiB
        // Worst case = floor + full cap metered per KiB (256 KiB => 256).
        assert_eq!(a.worst_case_cost(), 1 + 256);
    }

    #[test]
    fn effective_caps_never_widen() {
        let a = HttpEgressActuator::new(test_policy());
        // caller 0 => host default.
        assert_eq!(a.effective_response_cap(0), 262_144);
        // caller smaller => caller.
        assert_eq!(a.effective_response_cap(1024), 1024);
        // caller larger => clamped to host (never widened).
        assert_eq!(a.effective_response_cap(999_999), 262_144);
        assert_eq!(a.effective_timeout(0), Duration::from_millis(10_000));
        assert_eq!(a.effective_timeout(500), Duration::from_millis(500));
        assert_eq!(a.effective_timeout(999_999), Duration::from_millis(10_000));
    }

    // ---- actuate-level rebinding tooth (injected resolver returning a denied IP) ----

    struct FixedResolver(Vec<IpAddr>);
    #[async_trait]
    impl EgressResolver for FixedResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn actuate_rejects_host_that_resolves_to_metadata_ip() {
        // The rebinding tooth: an ALLOWLISTED, well-shaped https host whose DNS resolves to the
        // cloud-metadata IP is DENIED at the resolve-then-check step, performs no request, debits 0.
        let policy = test_policy();
        let resolver = Arc::new(FixedResolver(vec![ip("169.254.169.254")]));
        let actuator = HttpEgressActuator::with_resolver(policy, resolver);
        let payload = fetch("GET", "https://api.example.com/steal").encode_to_vec();
        let outcome = actuator
            .actuate(kirby_proto::ACTUATE_KIND_HTTP_FETCH, &payload, 500)
            .await;
        assert!(matches!(outcome, RailOutcome::UpstreamFailed));
    }

    #[tokio::test]
    async fn actuate_refuses_unknown_kind() {
        let actuator = HttpEgressActuator::new(test_policy());
        let payload = fetch("GET", "https://api.example.com/x").encode_to_vec();
        let outcome = actuator.actuate("nostr.publish", &payload, 500).await;
        assert!(matches!(outcome, RailOutcome::UpstreamFailed));
    }

    #[test]
    fn validate_is_a_free_denial_on_bad_shape() {
        let actuator = HttpEgressActuator::new(test_policy());
        // non-allowlisted host
        let bad = fetch("GET", "https://evil.com/").encode_to_vec();
        assert!(actuator
            .validate(kirby_proto::ACTUATE_KIND_HTTP_FETCH, &bad)
            .is_err());
        // wrong kind
        assert!(actuator.validate("nostr.publish", &bad).is_err());
        // good shape passes validate (the IP floor is applied later, in actuate)
        let good = fetch("GET", "https://api.example.com/ok").encode_to_vec();
        assert!(actuator
            .validate(kirby_proto::ACTUATE_KIND_HTTP_FETCH, &good)
            .is_ok());
    }

    #[test]
    fn cost_is_variable_and_unknown_kind_is_over_budget() {
        let a = HttpEgressActuator::new(test_policy());
        assert_eq!(a.cost(kirby_proto::ACTUATE_KIND_HTTP_FETCH), 1 + 256);
        assert_eq!(a.cost("nostr.publish"), u64::MAX);
        assert!(!a.cost_is_exact(kirby_proto::ACTUATE_KIND_HTTP_FETCH));
    }
}
