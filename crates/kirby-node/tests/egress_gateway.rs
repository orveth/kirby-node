//! C-EGRESS money-path teeth (the `http.fetch` Actuate kind), driven against the host-side gateway
//! directly — no relay, no microVM, no network. These prove the VARIABLE-COST fork of
//! `authorize_actuate`: unlike a fixed-cost Nostr publish (reserve-before-perform), an egress fetch
//! gates on the WORST case, performs, and debits the ACTUAL (`<=` worst case), because the
//! debit-only ledger cannot refund a worst-case reservation down to the actual.
//!
//! A `VariableEgressActuator` stands in for the real `HttpEgressActuator`: it reports
//! `cost_is_exact() == false` (the variable-cost signal) and returns a controllable actual cost +
//! `http_response`, so these teeth are deterministic. The real actuator's SSRF floor / resolve-then-
//! pin / rate limit / metering are unit-tested in `src/egress.rs`; here the concern is the gateway's
//! money accounting on the variable path.
//!
//! Coverage (red-on-revert noted):
//!   - deny-by-default: no `http.fetch` token => DENIED_NOT_ALLOWLISTED, debit 0 .. `deny_by_default_*`
//!   - egress debits the ACTUAL (not the worst case) + threads `http_response` .. `debits_actual_*`
//!     (RED if `cost_is_exact` is reverted to true — the reserve path would debit the worst case)
//!   - over-budget worst case => DENIED_OVER_BUDGET, debit 0, nothing dispatched .. `over_budget_*`
//!   - worst case over treasury => DENIED_INSUFFICIENT_TREASURY, debit 0 .. `insufficient_treasury_*`
//!   - never-overspend across a drain (the treasury floor holds) ............... `never_overspends_*`
//!   - a duplicate (same-key) fetch is a single debit, no re-served body ....... `duplicate_*`

use std::sync::{Arc, Mutex};

use kirby_node::egress::{EgressPolicy, HttpEgressActuator};
use kirby_node::gateway::{GatewayService, Session};
use kirby_node::rail::{
    Actuator, CompositeRail, MockRail, RailOutcome, StubBrain, BRAIN_COMPLETION_DESTINATION,
    MEMORY_DESTINATION,
};
use kirby_node::treasury::Treasury;
use kirby_proto::capability_request::Act;
use kirby_proto::{
    Actuate, CapabilityRequest, HttpFetch, HttpResponse, Outcome, ACTUATE_KIND_HTTP_FETCH,
};
use prost::Message;

/// A faithful VARIABLE-COST egress sink. Reports `cost_is_exact() == false` (so the gateway takes
/// the perform-then-debit-actual path) and a `worst_case` estimate; on `actuate` it returns a
/// controllable `actual` cost (clamped to `cap_sats`, D-20) plus a canned `http_response`. Records
/// how many `actuate` calls the gateway dispatched (0 => denied before perform).
#[derive(Clone)]
struct VariableEgressActuator {
    worst_case: u64,
    actual: u64,
    dispatched: Arc<Mutex<usize>>,
}

impl VariableEgressActuator {
    fn new(worst_case: u64, actual: u64) -> Self {
        VariableEgressActuator { worst_case, actual, dispatched: Arc::new(Mutex::new(0)) }
    }
    fn dispatch_count(&self) -> usize {
        *self.dispatched.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl Actuator for VariableEgressActuator {
    fn cost(&self, kind: &str) -> u64 {
        if kind == ACTUATE_KIND_HTTP_FETCH {
            self.worst_case
        } else {
            u64::MAX
        }
    }

    fn cost_is_exact(&self, _kind: &str) -> bool {
        // The variable-cost signal: the gateway must gate on the worst case then debit the actual.
        false
    }

    fn validate(&self, kind: &str, payload: &[u8]) -> Result<(), String> {
        if kind != ACTUATE_KIND_HTTP_FETCH {
            return Err(format!("unknown kind {kind:?}"));
        }
        HttpFetch::decode(payload).map(|_| ()).map_err(|e| format!("bad HttpFetch: {e}"))
    }

    async fn actuate(&self, kind: &str, _payload: &[u8], cap_sats: u64) -> RailOutcome {
        *self.dispatched.lock().unwrap() += 1;
        if kind != ACTUATE_KIND_HTTP_FETCH {
            return RailOutcome::UpstreamFailed;
        }
        let http_response = HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"PRICE=42".to_vec(),
            truncated: false,
            final_url: "https://api.example.com/price".to_string(),
        };
        RailOutcome::Performed {
            // D-20: the actual is clamped to the cap (the reserved worst case), never above it.
            actual_cost: self.actual.min(cap_sats),
            proof: b"status+hash".to_vec(),
            completion: Vec::new(),
            http_response: Some(http_response),
        }
    }
}

/// A capable-style gateway with the variable egress actuator attached, over a temporary treasury.
/// `fetch_allowed` controls whether the `http.fetch` token is in the allowlist (deny-by-default).
fn egress_gateway(
    initial_sats: u64,
    fetch_allowed: bool,
    worst_case: u64,
    actual: u64,
) -> (GatewayService, VariableEgressActuator) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let actuator = VariableEgressActuator::new(worst_case, actual);
    let rail = CompositeRail::new(Arc::new(MockRail::new()), Arc::new(StubBrain::new(64)))
        .with_actuator(Arc::new(actuator.clone()));
    let mut allow =
        vec![BRAIN_COMPLETION_DESTINATION.to_string(), MEMORY_DESTINATION.to_string()];
    if fetch_allowed {
        allow.push(ACTUATE_KIND_HTTP_FETCH.to_string());
    }
    let session = Session {
        task_descriptor: "egress-gateway-test".into(),
        budget_sats: initial_sats,
        allowlisted_destinations: allow,
        allowlisted_inbound_kinds: Vec::new(),
    };
    let service = GatewayService::new(treasury, Arc::new(rail), session);
    (service, actuator)
}

/// An `Actuate` (`http.fetch`) request. The genome sets `budget_sats == max_cost_sats`.
fn fetch_req(key: &str, max_cost_sats: u64) -> CapabilityRequest {
    let payload = HttpFetch {
        method: "GET".to_string(),
        url: "https://api.example.com/price".to_string(),
        headers: Vec::new(),
        max_response_bytes: 0,
        timeout_ms: 0,
    }
    .encode_to_vec();
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::Actuate(Actuate {
            kind: ACTUATE_KIND_HTTP_FETCH.to_string(),
            payload,
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

#[tokio::test]
async fn deny_by_default_fetch_without_token_is_denied() {
    // Deny-by-default: a workload WITHOUT the http.fetch token (egress disabled) is denied at the
    // allowlist step; ZERO dispatched to the actuator, debit 0, treasury untouched.
    let (svc, actuator) = egress_gateway(1_000, /* fetch_allowed = */ false, 257, 5);
    let r = svc.authorize_capability(&fetch_req("f1", 500)).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedNotAllowlisted as i32,
        "no http.fetch token => DENIED_NOT_ALLOWLISTED (deny-by-default)"
    );
    assert_eq!(r.cost_sats, 0, "a denied fetch debits nothing");
    assert_eq!(r.treasury_remaining, 1_000, "treasury untouched");
    assert_eq!(actuator.dispatch_count(), 0, "ZERO fetches reached the actuator");
    assert!(r.http_response.is_none(), "no response on a denial");
}

#[tokio::test]
async fn debits_actual_not_worstcase_and_threads_response() {
    // THE variable-cost tooth: worst case = 257 (the gate input), ACTUAL = 5 (what a small response
    // really cost). The gateway must debit the ACTUAL 5, not the reserved worst case, and thread the
    // typed http_response back for the brain. RED if `cost_is_exact` is reverted to true (the reserve
    // path would debit the worst case 257), or if the receipt no longer threads http_response.
    let (svc, _actuator) = egress_gateway(1_000, true, /* worst_case */ 257, /* actual */ 5);
    let r = svc.authorize_capability(&fetch_req("f1", 500)).await.unwrap();
    assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32, "an allowlisted fetch performs");
    assert_eq!(r.cost_sats, 5, "debits the ACTUAL cost (5), NOT the reserved worst case (257)");
    assert_eq!(r.treasury_remaining, 995, "treasury drops by EXACTLY the actual metered amount");
    let resp = r.http_response.expect("the typed HTTP response rides the receipt");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"PRICE=42", "the fetched body comes back for the brain");
}

#[tokio::test]
async fn over_budget_worstcase_is_denied_debits_zero() {
    // The worst-case gate: budget (100) < worst case (257) => DENIED_OVER_BUDGET before perform.
    // Nothing dispatched, debit 0. The worst case being finite (a capped response) is WHY this is
    // pre-authorizable at all.
    let (svc, actuator) = egress_gateway(1_000, true, /* worst_case */ 257, 5);
    let r = svc.authorize_capability(&fetch_req("f1", /* max_cost/budget */ 100)).await.unwrap();
    assert_eq!(r.outcome, Outcome::DeniedOverBudget as i32, "worst case over budget => denied");
    assert_eq!(r.cost_sats, 0, "debit 0");
    assert_eq!(r.treasury_remaining, 1_000, "treasury untouched");
    assert_eq!(actuator.dispatch_count(), 0, "nothing performed");
}

#[tokio::test]
async fn insufficient_treasury_worstcase_is_denied_debits_zero() {
    // The no-overspend gate: worst case (257) > treasury (100) => DENIED_INSUFFICIENT_TREASURY
    // before perform, debit 0. The gate refuses a fetch the treasury could not cover even at worst
    // case, so the debit-actual step can never drive the balance negative.
    let (svc, actuator) = egress_gateway(/* treasury */ 100, true, /* worst_case */ 257, 5);
    let r = svc.authorize_capability(&fetch_req("f1", 500)).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "worst case over treasury => denied"
    );
    assert_eq!(r.cost_sats, 0, "debit 0");
    assert_eq!(r.treasury_remaining, 100, "treasury untouched");
    assert_eq!(actuator.dispatch_count(), 0, "nothing performed");
}

#[tokio::test]
async fn never_overspends_treasury_across_a_drain() {
    // No-overspend, structurally: repeated fetches (distinct keys) drain the treasury by the actual
    // each time, and once the treasury can no longer cover the WORST case the gate denies with debit
    // 0 — the balance is monotonically non-negative throughout, and NEVER dips below where a single
    // atomic debit_and_record left it. (Concurrency-safety of that single debit is proven in
    // treasury.rs; here the gate+debit sequence is shown to respect the floor.)
    let worst_case = 100;
    let actual = 30;
    let (svc, _a) = egress_gateway(/* treasury */ 250, true, worst_case, actual);
    // Fetch 1: 250 -> 220 (debits 30). Fetch 2: 220 -> 190. ... until remaining < worst_case (100),
    // at which point the gate denies (debit 0). With actual=30 the debits are 30,30,30,30,30 until
    // remaining=100, then a fetch needs worst_case=100 <= 100 so it still performs -> 70; then
    // remaining 70 < 100 => denied.
    let mut remaining = 250u64;
    for i in 0..10 {
        let r = svc.authorize_capability(&fetch_req(&format!("drain-{i}"), 500)).await.unwrap();
        if r.outcome == Outcome::AuthorizedAndPerformed as i32 {
            remaining -= actual;
            assert_eq!(r.cost_sats, actual, "each performed fetch debits the actual");
            assert_eq!(r.treasury_remaining, remaining, "treasury tracks the actual debits exactly");
        } else {
            assert_eq!(
                r.outcome,
                Outcome::DeniedInsufficientTreasury as i32,
                "once the worst case exceeds the treasury the fetch is denied (no overspend)"
            );
            assert_eq!(r.cost_sats, 0, "a denied fetch debits nothing");
            assert_eq!(r.treasury_remaining, remaining, "treasury unchanged on a denial");
            assert!(remaining < worst_case, "denied only because remaining < the worst case");
            return;
        }
    }
    panic!("the treasury should have been drained below the worst case within 10 fetches");
}

#[tokio::test]
async fn duplicate_fetch_is_single_debit_and_serves_no_body() {
    // A same-key replay dedupes to ONE debit (STEP1), and because the response body is NOT persisted
    // in the ledger, the replay returns no http_response — a safe/idempotent GET re-fetches under a
    // fresh key to read the body again.
    let (svc, _a) = egress_gateway(1_000, true, 257, 5);
    let first = svc.authorize_capability(&fetch_req("dup", 500)).await.unwrap();
    assert_eq!(first.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(first.treasury_remaining, 995);
    let replay = svc.authorize_capability(&fetch_req("dup", 500)).await.unwrap();
    assert_eq!(replay.outcome, Outcome::DuplicateIgnored as i32, "same key dedupes");
    assert_eq!(replay.treasury_remaining, 995, "no second debit (single debit for one logical fetch)");
    assert!(replay.http_response.is_none(), "the body is not re-served on a replay (not persisted)");
}

#[tokio::test]
async fn concurrent_fetches_never_perform_then_unpaid() {
    // codex-1 / no-concurrent-debit: two CONCURRENT distinct-key fetches on a treasury sized for
    // exactly ONE (worst_case 100, treasury 100, actual 60 => 2*60 > 100). The egress_debit_gate
    // serializes the [re-read balance -> gate -> perform -> debit] sequence, so EXACTLY ONE performs
    // + debits its actual and the other is DENIED_INSUFFICIENT_TREASURY *before* performing (debit 0).
    // WITHOUT the lock both would pass the stale gate, both perform, and the loser would be a
    // performed-but-UNPAID fetch — i.e. dispatch_count would be 2. This tooth is RED without the
    // serialization.
    let (svc, actuator) = egress_gateway(/* treasury */ 100, true, /* worst_case */ 100, /* actual */ 60);
    let (fa, fb) = (fetch_req("c-a", 500), fetch_req("c-b", 500));
    let (ra, rb) = tokio::join!(
        svc.authorize_capability(&fa),
        svc.authorize_capability(&fb),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(
        actuator.dispatch_count(),
        1,
        "only ONE fetch reached the actuator — the other was denied BEFORE performing (no performed-but-unpaid)"
    );
    let (perf_r, deny_r) = if ra.outcome == Outcome::AuthorizedAndPerformed as i32 {
        (&ra, &rb)
    } else {
        (&rb, &ra)
    };
    assert_eq!(perf_r.outcome, Outcome::AuthorizedAndPerformed as i32, "one fetch performed");
    assert_eq!(perf_r.cost_sats, 60, "the performed fetch debited its actual");
    assert_eq!(
        deny_r.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "the other was denied (before performing) — the treasury couldn't cover a second worst case"
    );
    assert_eq!(deny_r.cost_sats, 0, "the denied fetch debited nothing");
    assert_eq!(perf_r.treasury_remaining, 40, "treasury dropped by EXACTLY the one actual debit (100-60)");
}

// ---- RUNTIME SMOKE (network-gated, #[ignore]): the REAL HttpEgressActuator end-to-end ----
//
// Run with: cargo test -p kirby-node --test egress_gateway -- --ignored
// These hit a real public host (example.com) through the REAL SSRF guard + resolve-then-pin +
// reqwest, so they need network and are #[ignore]d out of the standard gate. They prove the charter's
// runtime smoke: an ALLOWLISTED https host fetches successfully and the treasury drops by EXACTLY the
// daemon-metered amount; a public host NOT on the allowlist is refused (debit 0).

fn real_egress_policy(allow_host: &str) -> EgressPolicy {
    EgressPolicy {
        host_allowlist: vec![allow_host.to_string()],
        methods: vec!["GET".to_string(), "HEAD".to_string()],
        max_response_bytes: 262_144,
        timeout_ms: 10_000,
        sats_per_request: 1,
        sats_per_kib: 1,
        rate_per_min: 30,
        refused_hosts: Vec::new(),
    }
}

fn real_egress_gateway(initial_sats: u64, allow_host: &str) -> GatewayService {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let actuator = HttpEgressActuator::new(real_egress_policy(allow_host));
    let rail = CompositeRail::new(Arc::new(MockRail::new()), Arc::new(StubBrain::new(64)))
        .with_actuator(Arc::new(actuator));
    let session = Session {
        task_descriptor: "egress-real-smoke".into(),
        budget_sats: initial_sats,
        allowlisted_destinations: vec![
            BRAIN_COMPLETION_DESTINATION.to_string(),
            MEMORY_DESTINATION.to_string(),
            ACTUATE_KIND_HTTP_FETCH.to_string(),
        ],
        allowlisted_inbound_kinds: Vec::new(),
    };
    GatewayService::new(treasury, Arc::new(rail), session)
}

fn real_fetch_req(key: &str, url: &str, max_cost_sats: u64) -> CapabilityRequest {
    let payload = HttpFetch {
        method: "GET".to_string(),
        url: url.to_string(),
        headers: Vec::new(),
        max_response_bytes: 0,
        timeout_ms: 0,
    }
    .encode_to_vec();
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::Actuate(Actuate {
            kind: ACTUATE_KIND_HTTP_FETCH.to_string(),
            payload,
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

#[tokio::test]
#[ignore = "network: hits example.com through the real SSRF guard + reqwest"]
async fn real_fetch_allowlisted_succeeds_and_debits_exactly() {
    let svc = real_egress_gateway(10_000, "example.com");
    let r = svc
        .authorize_capability(&real_fetch_req("smoke-1", "https://example.com/", 5_000))
        .await
        .unwrap();
    assert_eq!(
        r.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "an allowlisted public host fetches"
    );
    let resp = r.http_response.expect("the typed HTTP response rides the receipt");
    assert_eq!(resp.status, 200, "example.com returns 200");
    assert!(!resp.body.is_empty(), "a non-empty body came back for the brain");
    // The daemon-side meter: sats_per_request(1) + ceil(bytes/1024) * sats_per_kib(1).
    let expected = 1 + (resp.body.len() as u64).div_ceil(1024);
    assert_eq!(r.cost_sats, expected, "debited EXACTLY the daemon-metered amount");
    assert_eq!(
        r.treasury_remaining,
        10_000 - expected,
        "treasury dropped by exactly the metered amount"
    );
    eprintln!(
        "SMOKE ok: fetched {} bytes, debited {} sats, treasury {} -> {}",
        resp.body.len(),
        r.cost_sats,
        10_000,
        r.treasury_remaining
    );
}

#[tokio::test]
#[ignore = "network: proves a public but NON-allowlisted host is refused by the guard"]
async fn real_fetch_non_allowlisted_host_is_denied() {
    // The http.fetch token IS granted (egress on) and the host is public, but it is NOT on the host
    // allowlist — the actuator's guard refuses it (validate) => UpstreamFailed, debit 0.
    let svc = real_egress_gateway(10_000, "example.com");
    let r = svc
        .authorize_capability(&real_fetch_req("smoke-2", "https://www.wikipedia.org/", 5_000))
        .await
        .unwrap();
    assert_eq!(r.outcome, Outcome::UpstreamFailed as i32, "a non-allowlisted host is guard-refused");
    assert_eq!(r.cost_sats, 0, "a guarded-out fetch debits nothing");
    assert_eq!(r.treasury_remaining, 10_000, "treasury untouched");
    eprintln!("SMOKE ok: non-allowlisted host refused, debit {}", r.cost_sats);
}
