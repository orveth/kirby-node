//! POST actuator daemon-side teeth (the agent's first OUTWARD voice): the `Actuate`
//! (`nostr.publish`) act on the generic gateway path. These drive the host-side gateway directly
//! (the same "direct service-method calls" the brain/memory teeth use), so they prove the contract
//! WITHOUT a relay or a microVM: fast, deterministic, in the standard gate.
//!
//! The REAL relay publish (`NostrActuator::publish_note` reaching a live relay, signed by the node
//! key) is the gated e2e (a real microVM run with a relay); here a faithful `RecordingActuator`
//! stands in as the "nostr sink" -- it runs the SAME daemon-side guard the real actuator runs
//! (`validate_nostr_publish`) and records the CLEAN note it would publish, so a guarded-out payload
//! records NOTHING. Proving the gateway against this sink (call count + recorded content) is
//! stronger than an outcome predicate.
//!
//! Coverage:
//!   - P3 allowlist at DISPATCH (a non-allowlisted kind issues ZERO publishes) .. `non_allowlisted_*`
//!   - P3 per-kind gating (only the exact allowlisted kind passes) .............. `only_the_exact_*`
//!   - P2 one publish carrying the payload ...................................... `allowlisted_post_*`
//!   - P3 daemon re-sanitize + kind=1-only at dispatch .......................... `daemon_*`
//!   - P4 metered + soft-skip-when-broke + over-budget .......................... `publish_is_metered`, `*_broke`, `*_over_budget`
//!   - the pure daemon guard (re-sanitize/re-cap/kind-restrict) ................. `validate_nostr_publish_*`

use std::sync::{Arc, Mutex};

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::rail::{
    validate_nostr_publish, Actuator, CompositeRail, MockRail, RailOutcome, StubBrain,
    BRAIN_COMPLETION_DESTINATION, MEMORY_DESTINATION,
};
use kirby_node::treasury::Treasury;
use kirby_proto::capability_request::Act;
use kirby_proto::{
    Actuate, CapabilityRequest, NostrPublish, Outcome, ACTUATE_KIND_NOSTR_PUBLISH, MAX_NOTE_BYTES,
    NOSTR_KIND_TEXT_NOTE,
};
use prost::Message;

/// One dispatched actuate call: (envelope kind, raw payload, cap_sats).
type DispatchedCall = (String, Vec<u8>, u64);

/// A faithful recording outward-actuator SINK. It runs the SAME daemon-side guard the real
/// `NostrActuator` runs (`validate_nostr_publish`: decode + restrict kind to 1 + re-sanitize), then
/// "publishes" by recording the CLEAN content (no relay needed). It also records the raw
/// (kind, payload, cap) of every `actuate` call the gateway dispatched. So:
///   - a publish DENIED upstream (allowlist/budget/treasury) leaves `dispatched` empty -- the
///     gateway never reached the actuator;
///   - a publish GUARDED OUT here (wrong inner kind / bad content) is `dispatched` but NOT
///     `published` -- the daemon refused it at the actuate entry point.
#[derive(Clone)]
struct RecordingActuator {
    /// The CLEAN content of each note that PASSED the daemon guard and would be published.
    published: Arc<Mutex<Vec<String>>>,
    /// The raw (kind, payload, cap_sats) of every `actuate` call the gateway dispatched.
    dispatched: Arc<Mutex<Vec<DispatchedCall>>>,
    /// The fixed host cost this actuator charges for a publish.
    cost: u64,
}

impl RecordingActuator {
    fn new(cost: u64) -> Self {
        RecordingActuator {
            published: Arc::new(Mutex::new(Vec::new())),
            dispatched: Arc::new(Mutex::new(Vec::new())),
            cost,
        }
    }
    /// The clean notes that passed the guard (the actuator would publish these).
    fn published(&self) -> Vec<String> {
        self.published.lock().unwrap().clone()
    }
    /// How many `actuate` calls the gateway dispatched (0 => denied before perform).
    fn dispatch_count(&self) -> usize {
        self.dispatched.lock().unwrap().len()
    }
    /// The raw payload of the first dispatched call (for asserting the gateway passed it through).
    fn first_payload(&self) -> Option<Vec<u8>> {
        self.dispatched.lock().unwrap().first().map(|(_, p, _)| p.clone())
    }
}

#[async_trait::async_trait]
impl Actuator for RecordingActuator {
    fn cost(&self, kind: &str) -> u64 {
        if kind == ACTUATE_KIND_NOSTR_PUBLISH {
            self.cost
        } else {
            u64::MAX
        }
    }

    async fn actuate(&self, kind: &str, payload: &[u8], cap_sats: u64) -> RailOutcome {
        self.dispatched.lock().unwrap().push((kind.to_string(), payload.to_vec(), cap_sats));
        if kind != ACTUATE_KIND_NOSTR_PUBLISH {
            return RailOutcome::UpstreamFailed;
        }
        // The SAME daemon-side guard the real NostrActuator runs (defense in depth at the actuate
        // entry point). On refusal nothing is "published"; on success record the CLEAN content.
        match validate_nostr_publish(payload) {
            Ok(clean) => {
                self.published.lock().unwrap().push(clean);
                RailOutcome::Performed {
                    actual_cost: self.cost.min(cap_sats),
                    proof: b"recorded-event-id-hex".to_vec(),
                    completion: Vec::new(),
                }
            }
            Err(_) => RailOutcome::UpstreamFailed,
        }
    }
}

/// A capable-style gateway: a `CompositeRail` (`MockRail` + `StubBrain`) with the
/// `RecordingActuator` attached, over a temporary treasury. `publish_allowed` controls whether the
/// `nostr.publish` token is in the allowlist (per-kind gating). Returns the service + the recording
/// handle (the handle shares the actuator's state with the one inside the rail).
fn actuator_gateway(
    initial_sats: u64,
    cost: u64,
    publish_allowed: bool,
) -> (GatewayService, RecordingActuator) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let actuator = RecordingActuator::new(cost);
    let rail = CompositeRail::new(Arc::new(MockRail::new()), Arc::new(StubBrain::new(64)))
        .with_actuator(Arc::new(actuator.clone()));
    let mut allow = vec![
        BRAIN_COMPLETION_DESTINATION.to_string(),
        MEMORY_DESTINATION.to_string(),
    ];
    if publish_allowed {
        allow.push(ACTUATE_KIND_NOSTR_PUBLISH.to_string());
    }
    let session = Session {
        task_descriptor: "post-actuator-test".into(),
        budget_sats: initial_sats,
        allowlisted_destinations: allow,
    };
    let service = GatewayService::new(treasury, Arc::new(rail), session);
    (service, actuator)
}

/// An `Actuate` (`nostr.publish`) request carrying `content` as a kind-1 `NostrPublish`. The
/// genome sets `budget_sats == max_cost_sats` (the per-act authorized ceiling).
fn post_req(key: &str, content: &str, max_cost_sats: u64) -> CapabilityRequest {
    post_req_inner_kind(key, NOSTR_KIND_TEXT_NOTE as u32, content, max_cost_sats)
}

/// As [`post_req`], with an explicit INNER nostr kind (to exercise the daemon's kind=1 restriction
/// independently of the envelope `nostr.publish` kind that the allowlist gates).
fn post_req_inner_kind(
    key: &str,
    inner_kind: u32,
    content: &str,
    max_cost_sats: u64,
) -> CapabilityRequest {
    let payload = NostrPublish { kind: inner_kind, content: content.to_string(), tags: Vec::new() }
        .encode_to_vec();
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::Actuate(Actuate {
            kind: ACTUATE_KIND_NOSTR_PUBLISH.to_string(),
            payload,
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

/// An `Actuate` with an arbitrary ENVELOPE kind (to exercise per-kind allowlist gating).
fn actuate_req_with_kind(key: &str, envelope_kind: &str, max_cost_sats: u64) -> CapabilityRequest {
    let payload = NostrPublish {
        kind: NOSTR_KIND_TEXT_NOTE as u32,
        content: "hi".into(),
        tags: Vec::new(),
    }
    .encode_to_vec();
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::Actuate(Actuate {
            kind: envelope_kind.to_string(),
            payload,
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

// ---- P3: allowlist enforced at DISPATCH (proven against the recording sink) ----

#[tokio::test]
async fn non_allowlisted_workload_issues_zero_publishes_at_dispatch() {
    // A workload WITHOUT the nostr.publish token: the Actuate is denied at the allowlist step, and
    // the actuator sink records ZERO dispatched calls (proven against the sink, not just the
    // outcome). This is the load-bearing membrane: no token, no voice.
    let (svc, actuator) = actuator_gateway(1_000, 1, /* publish_allowed = */ false);
    let r = svc.authorize_capability(&post_req("p1", "hello world", 64)).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedNotAllowlisted as i32,
        "a workload without the nostr.publish token is denied at the allowlist"
    );
    assert_eq!(r.cost_sats, 0, "a denied publish debits nothing");
    assert_eq!(
        actuator.dispatch_count(),
        0,
        "ZERO publishes reached the actuator (the guard ran BEFORE perform, not as a predicate)"
    );
    assert!(actuator.published().is_empty(), "nothing was published");
}

#[tokio::test]
async fn only_the_exact_allowlisted_kind_passes() {
    // Per-kind gating: a workload allowlisted for nostr.publish still cannot route a DIFFERENT
    // envelope kind. Only the exact token passes; zero dispatched for the wrong kind.
    let (svc, actuator) = actuator_gateway(1_000, 1, /* publish_allowed = */ true);
    let r = svc.authorize_capability(&actuate_req_with_kind("p1", "evil.kind", 64)).await.unwrap();
    assert_eq!(r.outcome, Outcome::DeniedNotAllowlisted as i32, "a non-allowlisted kind is denied");
    assert_eq!(actuator.dispatch_count(), 0, "a non-allowlisted kind dispatches nothing");
}

// ---- P2: an allowlisted POST dispatches EXACTLY ONE publish carrying the payload ----

#[tokio::test]
async fn allowlisted_post_dispatches_exactly_one_publish_with_the_payload() {
    let (svc, actuator) = actuator_gateway(1_000, 1, true);
    let content = "the relay has been quiet for three ticks";
    let r = svc.authorize_capability(&post_req("p1", content, 64)).await.unwrap();
    assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32, "an allowlisted publish performs");
    assert!(!r.proof.is_empty(), "the receipt carries the event-id proof");
    // EXACTLY ONE publish reached the actuator, carrying the genome's kind-1 payload.
    assert_eq!(actuator.dispatch_count(), 1, "exactly one publish dispatched this act");
    let payload = actuator.first_payload().expect("the payload reached the actuator");
    let np = NostrPublish::decode(payload.as_slice()).expect("payload decodes to NostrPublish");
    assert_eq!(np.kind, NOSTR_KIND_TEXT_NOTE as u32, "a kind:1 note");
    assert_eq!(np.content, content, "the genome's content reached the actuator");
    // It passed the daemon guard and would be published, clean.
    assert_eq!(actuator.published(), vec![content.to_string()]);
}

// ---- P3: the DAEMON independently re-sanitizes + restricts the kind AT DISPATCH ----

#[tokio::test]
async fn daemon_resanitizes_dirty_content_at_dispatch() {
    // Even if the genome sent dirty content (control char + U+2028 + newline), the daemon-side
    // guard at the actuate entry point cleans it before publishing (it never trusts the genome).
    let (svc, actuator) = actuator_gateway(1_000, 1, true);
    let r = svc
        .authorize_capability(&post_req("p1", "hi\u{0}\u{2028}there\nworld", 64))
        .await
        .unwrap();
    assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(
        actuator.published(),
        vec!["hi there world".to_string()],
        "the daemon re-sanitized the content to one clean line before publishing"
    );
}

#[tokio::test]
async fn daemon_refuses_a_non_text_note_kind_at_dispatch() {
    // The envelope kind is allowlisted (nostr.publish), so the gateway dispatches; but the INNER
    // nostr kind is 2, which the daemon guard restricts (MVP: kind 1 only). The actuator refuses
    // -> UpstreamFailed, nothing published, debit 0. (Dispatched, but guarded out at the daemon.)
    let (svc, actuator) = actuator_gateway(1_000, 1, true);
    let r = svc.authorize_capability(&post_req_inner_kind("p1", 2, "metadata", 64)).await.unwrap();
    assert_eq!(r.outcome, Outcome::UpstreamFailed as i32, "a disallowed inner kind is refused");
    assert_eq!(r.cost_sats, 0, "a guarded-out publish debits nothing");
    assert_eq!(actuator.dispatch_count(), 1, "it reached the actuator (envelope kind allowlisted)");
    assert!(actuator.published().is_empty(), "but the daemon refused it: NOTHING published");
}

#[tokio::test]
async fn daemon_refuses_empty_and_oversize_content_at_dispatch() {
    // Whitespace/control-only content (empty after the guard) and an over-cap note are both refused
    // daemon-side, nothing published.
    let (svc, actuator) = actuator_gateway(1_000, 1, true);
    let empty = svc.authorize_capability(&post_req("p1", "   \u{0}\u{2028}  ", 64)).await.unwrap();
    assert_eq!(empty.outcome, Outcome::UpstreamFailed as i32, "empty-after-guard is refused");
    let big_note = "x".repeat(MAX_NOTE_BYTES + 1);
    let big = svc.authorize_capability(&post_req("p2", &big_note, 64)).await.unwrap();
    assert_eq!(big.outcome, Outcome::UpstreamFailed as i32, "over-cap is refused, never truncated");
    assert!(actuator.published().is_empty(), "neither was published");
}

// ---- P4: per-kind metering on the generic estimate->budget->perform->debit path ----

#[tokio::test]
async fn publish_is_metered_the_fixed_cost_is_debited() {
    let (svc, _actuator) = actuator_gateway(1_000, /* cost = */ 3, true);
    let r = svc.authorize_capability(&post_req("p1", "a worthy thought", 64)).await.unwrap();
    assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(r.cost_sats, 3, "the fixed publish cost is debited");
    assert_eq!(r.treasury_remaining, 997, "the treasury drained by exactly the publish cost");
}

#[tokio::test]
async fn publish_when_broke_is_a_soft_skip_and_publishes_nothing() {
    // Treasury (2) below the publish cost (5): the gate denies INSUFFICIENT_TREASURY BEFORE perform
    // -- a SOFT SKIP (the THINK stays the only death gate). Nothing is dispatched or published.
    let (svc, actuator) = actuator_gateway(/* treasury = */ 2, /* cost = */ 5, true);
    let r = svc.authorize_capability(&post_req("p1", "hi", 64)).await.unwrap();
    assert_eq!(r.outcome, Outcome::DeniedInsufficientTreasury as i32, "broke -> denied (soft skip)");
    assert_eq!(r.cost_sats, 0, "a broke publish debits nothing");
    assert_eq!(actuator.dispatch_count(), 0, "a broke publish dispatches nothing");
}

#[tokio::test]
async fn publish_over_authorized_budget_is_denied_over_budget_and_publishes_nothing() {
    // The fixed publish cost (10) exceeds the genome's authorized per-act budget (2):
    // DENIED_OVER_BUDGET (a loud config error), nothing published. Proves the known fixed cost is
    // gated against budget_sats and NOT silently clamped down + undercharged (the act_max=None
    // design, like memory's "never clamp the host cost to the ceiling").
    let (svc, actuator) = actuator_gateway(1_000, /* cost = */ 10, true);
    let r = svc.authorize_capability(&post_req("p1", "hi", /* max_cost < cost = */ 2)).await.unwrap();
    assert_eq!(r.outcome, Outcome::DeniedOverBudget as i32, "cost > ceiling -> over budget");
    assert_eq!(r.cost_sats, 0);
    assert_eq!(actuator.dispatch_count(), 0, "an over-budget publish dispatches nothing");
}

// ---- the pure daemon guard (re-sanitize / re-cap / kind=1-only), unit-tested directly ----

#[test]
fn validate_nostr_publish_passes_clean_kind1_and_resanitizes_dirty() {
    let clean = NostrPublish {
        kind: NOSTR_KIND_TEXT_NOTE as u32,
        content: "a clean note".into(),
        tags: Vec::new(),
    }
    .encode_to_vec();
    assert_eq!(validate_nostr_publish(&clean).unwrap(), "a clean note");

    // The daemon re-sanitizes even when the genome did not (control + U+2028 + newline -> clean).
    let dirty = NostrPublish {
        kind: NOSTR_KIND_TEXT_NOTE as u32,
        content: "hi\u{0}\u{2028}there\nworld".into(),
        tags: Vec::new(),
    }
    .encode_to_vec();
    assert_eq!(validate_nostr_publish(&dirty).unwrap(), "hi there world");
}

#[test]
fn validate_nostr_publish_refuses_disallowed_kind_empty_and_oversize() {
    // kind != 1 is refused (MVP restricts to a public text note).
    let kind2 = NostrPublish { kind: 2, content: "x".into(), tags: Vec::new() }.encode_to_vec();
    let e = validate_nostr_publish(&kind2).unwrap_err();
    assert!(e.contains("kind"), "the refusal names the kind restriction: {e}");
    // Empty-after-guard content is refused.
    let empty =
        NostrPublish { kind: 1, content: "  \u{0}  ".into(), tags: Vec::new() }.encode_to_vec();
    assert!(validate_nostr_publish(&empty).is_err());
    // Over-cap content is refused (never truncated).
    let big = NostrPublish { kind: 1, content: "x".repeat(MAX_NOTE_BYTES + 1), tags: Vec::new() }
        .encode_to_vec();
    assert!(validate_nostr_publish(&big).is_err());
    // The boundary (exactly the cap) passes.
    let at = NostrPublish { kind: 1, content: "x".repeat(MAX_NOTE_BYTES), tags: Vec::new() }
        .encode_to_vec();
    assert_eq!(validate_nostr_publish(&at).unwrap().len(), MAX_NOTE_BYTES);
}
