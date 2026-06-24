//! Brain-stub teeth tests (the MIND chunk): the `Completion` brokered act, the
//! `CompositeRail`/`StubBrain` seam, the idempotent completion body, and the
//! fail-closed brain-mode membrane. These drive the host-side gateway directly
//! (the scope blesses "direct service-method calls"), so they prove the contract
//! WITHOUT booting a microVM: fast, deterministic, run in the standard gate.
//!
//! The full `workload="brain"` boot through the REAL `metered_run`/`boot` path (the
//! CompositeRail, done-criteria #4) is `brain_vm_boots_thinks_and_dies_when_broke`
//! below: it boots a real Firecracker microVM, so like every real-VM test here it
//! SKIPs (green) when `KIRBY_GENOME_IMAGE` is unset, and must be run on-harness with
//! the image set to exercise the integrated death-by-thinking (host-side halt, F4).
//!
//! Coverage maps to the spec §6 done-criteria + R1/R3:
//!   - round-trip + monotonic drain (#1, #2) ........ `brain_completion_performs_roundtrips_and_drains`
//!   - StubBrain performs it, not MockRail (#4, F3) .. `completion_routes_to_brain_not_base_rail`
//!   - idempotent completion body (#3, F2) ........... `completion_body_survives_idempotent_replay`
//!   - old-shape ledger record decodes (R1) .......... `old_shape_performed_record_still_deserializes`
//!   - non-Completion denied in brain mode (R3) ...... `brain_mode_allowlist_denies_non_completion`
//!   - CompositeRail backstop refuses spends (R3) .... `composite_rail_refuses_non_completion_backstop`
//!   - the death trigger: think over runway (#2) ..... `think_over_runway_is_denied_insufficient_treasury`

use std::sync::Arc;
use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::config::BrainConfig;
use kirby_node::gateway::{GatewayService, Session};
use kirby_node::metered_run::{self, MeteredRunConfig, Terminated};
use kirby_node::rail::{
    CompositeRail, MockRail, Rail, RailOutcome, StubBrain, BRAIN_COMPLETION_DESTINATION,
};
use kirby_node::treasury::{PerformedRecord, Treasury};
use kirby_proto::capability_request::Act;
use kirby_proto::{CapabilityRequest, ChatMessage, Completion, Outcome, SettleEcash};

/// A brain-mode gateway: a [`CompositeRail`] (base `MockRail` + `StubBrain`) and an
/// allowlist holding EXACTLY the brain completion sentinel (R3 — the brain only
/// thinks; it can reach nothing else). Returns the service plus the base `MockRail`
/// handle so a test can assert the base rail was NEVER performed (the completion went
/// to the brain, F3).
fn brain_gateway(initial_sats: u64, bytes_per_sat: u64) -> (GatewayService, MockRail) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let base = MockRail::new();
    let base_handle = base.clone();
    let rail = CompositeRail::new(Arc::new(base), Arc::new(StubBrain::new(bytes_per_sat)));
    let session = Session {
        task_descriptor: "brain-test".into(),
        budget_sats: initial_sats,
        // R3: brain mode allowlists ONLY the completion sentinel (NOT additive to a
        // mint), so any non-Completion act is denied at the allowlist step.
        allowlisted_destinations: vec![BRAIN_COMPLETION_DESTINATION.to_string()],
    };
    let service = GatewayService::new(treasury, Arc::new(rail), session);
    (service, base_handle)
}

/// A `Completion` capability request: `budget_sats == max_cost_sats` (R4, the genome
/// authorizes exactly the per-call cap), keyed by `key`, with a system + user turn.
fn completion_req(key: &str, max_cost_sats: u64, user: &str) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::Completion(Completion {
            model: "anthropic/claude-sonnet-4.6".into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "I am a Kirby agent.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: user.into(),
                },
            ],
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

// ---- #1 + #2: the completion performs, the WORDS round-trip, the treasury drains ----

/// A `Completion` is AUTHORIZED_AND_PERFORMED, returns the assistant reply TEXT
/// (not just a proof — these are the words the brain needs back), debits a non-zero
/// cost within the cap, and across successive thinks the treasury drains
/// MONOTONICALLY (the metabolism of thinking, visible on the 31000 face).
#[tokio::test]
async fn brain_completion_performs_roundtrips_and_drains() {
    let initial = 10_000u64;
    let cap = 200u64;
    let (svc, _base) = brain_gateway(initial, 16);

    let mut prev_remaining = svc.treasury_remaining().unwrap();
    assert_eq!(prev_remaining, initial);

    for tick in 1..=5u64 {
        let user = format!("tick {tick}: what is my next move to survive?");
        let receipt = svc
            .authorize_capability(&completion_req(&format!("think-{tick}"), cap, &user))
            .await
            .unwrap();

        assert_eq!(
            receipt.outcome,
            Outcome::AuthorizedAndPerformed as i32,
            "tick {tick} should be performed"
        );
        // The WORDS come back (done-criteria #1: the contract returns words).
        assert!(!receipt.completion.is_empty(), "completion text must be returned");
        let reply = String::from_utf8(receipt.completion.clone()).expect("reply is utf8");
        assert!(
            reply.contains("stub-brain") && reply.contains(&user),
            "the canned reply echoes the user turn deterministically; got {reply:?}"
        );
        // Non-zero (the runway visibly falls) and within the cap (D-20).
        assert!(receipt.cost_sats > 0, "a think is never free");
        assert!(receipt.cost_sats <= cap, "actual cost is capped at max_cost_sats");

        // Monotonic drain: each think strictly lowers the treasury by its cost.
        assert!(
            receipt.treasury_remaining < prev_remaining,
            "tick {tick}: treasury must fall ({} !< {prev_remaining})",
            receipt.treasury_remaining
        );
        assert_eq!(
            receipt.treasury_remaining,
            prev_remaining - receipt.cost_sats,
            "the drain equals the metered cost exactly"
        );
        prev_remaining = receipt.treasury_remaining;
    }
}

// ---- #4 / F3: the Completion is performed by the StubBrain, NOT the base MockRail ----

/// The `CompositeRail` routes a `Completion` to the `StubBrain` (its proof is the
/// brain-act fact), and the base `MockRail` is NEVER performed — proving the brain
/// act does not fall through to the generic rail (F3, done-criteria #4).
#[tokio::test]
async fn completion_routes_to_brain_not_base_rail() {
    let (svc, base) = brain_gateway(10_000, 16);

    let receipt = svc
        .authorize_capability(&completion_req("route-1", 200, "think"))
        .await
        .unwrap();

    assert_eq!(receipt.outcome, Outcome::AuthorizedAndPerformed as i32);
    // The proof is the StubBrain's brain-act fact, not the MockRail's mock receipt.
    let proof = String::from_utf8(receipt.proof.clone()).unwrap_or_default();
    assert!(
        proof.starts_with("brain-completion:"),
        "the proof is the brain backend's, got {proof:?}"
    );
    assert!(
        !proof.starts_with("mock-receipt:"),
        "the completion must NOT be performed by the base MockRail"
    );
    assert_eq!(
        base.perform_count(),
        0,
        "the base rail must NEVER perform a Completion (it routed to the brain)"
    );
}

// ---- #3 / F2 + R1: the completion body survives an idempotent (resume) replay ----

/// F2/R1: a re-issue of an already-performed key returns DUPLICATE_IGNORED with the
/// SAME assistant words byte-for-byte (the ledger persists the completion), the same
/// cost, and the same balance — and performs nothing a second time. This is the
/// post-resume replay: the brain gets the words back, not just the proof.
#[tokio::test]
async fn completion_body_survives_idempotent_replay() {
    let (svc, base) = brain_gateway(10_000, 16);
    let req = completion_req("resume-key-K", 200, "what should I do to survive?");

    // First issue: performed, capture the words + cost + balance.
    let first = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(first.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert!(!first.completion.is_empty());
    let words = first.completion.clone();
    let cost = first.cost_sats;
    let remaining = first.treasury_remaining;
    assert_eq!(base.perform_count(), 0, "Completion routed to the brain");

    // Re-issue the SAME key (the resume replay): DUPLICATE_IGNORED, identical body.
    let replay = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(
        replay.outcome,
        Outcome::DuplicateIgnored as i32,
        "a re-issued key dedupes against the persisted ledger"
    );
    assert_eq!(replay.completion, words, "the words come back byte-for-byte (F2)");
    assert_eq!(replay.cost_sats, cost, "no second debit");
    assert_eq!(
        replay.treasury_remaining, remaining,
        "the balance is unchanged on a duplicate"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        remaining,
        "the treasury was debited exactly once across the replay"
    );
}

/// R1 (ledger backcompat): an OLD-shape `PerformedRecord` — the
/// `{cost_sats, treasury_remaining_after, proof}` rows already persisted in sled
/// before the `completion` field existed — still deserializes on resume, decoding
/// with an EMPTY completion (the `#[serde(default)]`), never a decode error. Without
/// the default, every pre-brain agent would fail to resume.
#[test]
fn old_shape_performed_record_still_deserializes() {
    // Exactly the JSON shape the pre-brain code wrote (no `completion` key).
    let old_json = r#"{"cost_sats":42,"treasury_remaining_after":958,"proof":[1,2,3,4]}"#;
    let record: PerformedRecord =
        serde_json::from_str(old_json).expect("old-shape record must still deserialize (R1)");
    assert_eq!(record.cost_sats, 42);
    assert_eq!(record.treasury_remaining_after, 958);
    assert_eq!(record.proof, vec![1, 2, 3, 4]);
    assert!(
        record.completion.is_empty(),
        "an old record decodes with an empty completion, not a decode error"
    );
}

// ---- R3: the brain-mode membrane is fail-closed (the brain only thinks) ----

/// R3: in brain mode the allowlist holds ONLY the completion sentinel, so a
/// non-Completion act (here an ecash settle) is DENIED_NOT_ALLOWLISTED at the gateway
/// allowlist step and performs nothing. A buggy or hostile brain genome cannot smuggle
/// a spend through the brain rail.
#[tokio::test]
async fn brain_mode_allowlist_denies_non_completion() {
    let (svc, base) = brain_gateway(10_000, 16);
    let settle = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "sneaky-settle".into(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: "mint.test.local".into(),
            amount: 64,
            recipient_or_quote: "smuggle".into(),
        })),
        budget_sats: 256,
    };

    let receipt = svc.authorize_capability(&settle).await.unwrap();

    assert_eq!(
        receipt.outcome,
        Outcome::DeniedNotAllowlisted as i32,
        "a non-Completion destination is not on the brain allowlist"
    );
    assert_eq!(receipt.cost_sats, 0, "a denial debits nothing");
    assert_eq!(base.perform_count(), 0, "nothing was performed");
    assert_eq!(svc.treasury_remaining().unwrap(), 10_000, "balance untouched");
}

/// R3 backstop (defense-in-depth): even calling `CompositeRail::perform` DIRECTLY
/// with a non-Completion act (i.e. if the allowlist were misconfigured) refuses it —
/// it returns `UpstreamFailed` and never touches the base rail. The brain rail
/// performs ONLY completions.
#[tokio::test]
async fn composite_rail_refuses_non_completion_backstop() {
    let base = MockRail::new();
    let base_handle = base.clone();
    let rail = CompositeRail::new(Arc::new(base), Arc::new(StubBrain::new(16)));
    let settle = Act::SettleEcash(SettleEcash {
        mint_id: "mint.test.local".into(),
        amount: 64,
        recipient_or_quote: "smuggle".into(),
    });

    let outcome = rail.perform(&settle, 256).await;

    assert!(
        matches!(outcome, RailOutcome::UpstreamFailed),
        "the brain rail refuses a non-Completion act (R3 backstop)"
    );
    assert_eq!(
        base_handle.perform_count(),
        0,
        "the refused act never reached the base rail"
    );
}

// ---- #2: the death trigger — a think the runway cannot cover is DENIED ----

/// The death trigger (done-criteria #2): when the per-call cap exceeds the remaining
/// treasury, the think is DENIED_INSUFFICIENT_TREASURY and nothing is debited. This is
/// the outcome the genome's brain loop parks on (it does NOT exit; the daemon halts the
/// VM host-side — the host-halt mechanism itself is exercised by the VM e2e below).
#[tokio::test]
async fn think_over_runway_is_denied_insufficient_treasury() {
    // 50 sats left, but a single think authorizes a 200-sat cap: it cannot be afforded.
    let (svc, base) = brain_gateway(50, 16);

    let receipt = svc
        .authorize_capability(&completion_req("last-gasp", 200, "am I still alive?"))
        .await
        .unwrap();

    assert_eq!(
        receipt.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "a think the treasury cannot cover is denied (earn-or-die)"
    );
    assert_eq!(receipt.cost_sats, 0, "a denied think debits nothing");
    assert_eq!(receipt.treasury_remaining, 50, "the runway is unchanged on denial");
    assert_eq!(base.perform_count(), 0, "nothing performed");
}

// ---- #4 + #2 (e2e): boot workload="brain" through the REAL metered_run/boot path ----

/// Done-criteria #4 + #2, the integrated form: a real `kirby`-style boot with
/// `workload = "brain"` runs the MIND loop through the SAME `metered_run`/`boot`
/// path the daemon uses — `boot_and_observe` injects the `CompositeRail`
/// (`StubBrain` performs the `Completion`, base `MockRail` is bypassed), the
/// allowlist is exclusively the brain sentinel, the genome thinks on a tick draining
/// the treasury, and when it can no longer afford a think it PARKS (`idle_forever`,
/// F4) while the daemon's meter — watching the SAME treasury counter (D-9) — HALTS
/// the VM. Death is the host-side halt, not the genome exiting.
///
/// This boots a real Firecracker microVM, so (like every real-VM test in this crate)
/// it SKIPs green without `KIRBY_GENOME_IMAGE`. Run on-harness with the image set:
///   `KIRBY_GENOME_IMAGE=$(nix build .#genome-image --print-out-paths) cargo test \
///    -p kirby-node --test brain_loop -- --include-ignored brain_vm_boots`
#[tokio::test]
async fn brain_vm_boots_thinks_and_dies_when_broke() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP brain_vm_boots_thinks_and_dies_when_broke: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the real-microVM MIND e2e (done-criteria #2/#4)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    // A small budget and a fast, cheap think so the brain drains the treasury to a
    // budget-death within a few seconds: ~budget/max_cost_sats thinks, one per tick.
    let budget: u64 = 600;
    let brain = BrainConfig {
        model: "anthropic/claude-sonnet-4.6".to_string(),
        max_cost_sats: 64,
        tick_secs: 1,
        bytes_per_sat: 16,
        // The routstr-only fields default (backend = Stub); this e2e exercises the stub.
        ..BrainConfig::default()
    };

    let boot = BootConfig {
        image,
        node_id: format!("braintest-{}", std::process::id()),
        task: "brain-e2e".to_string(),
        budget_sats: budget,
        initial_sats: budget,
        // R3: brain mode allowlists EXCLUSIVELY the completion sentinel.
        allow: vec![BRAIN_COMPLETION_DESTINATION.to_string()],
        guest_cid: 27,
        gateway_port: 5027,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        workload: Some("brain".to_string()),
        // `Some(brain)` selects the CompositeRail (StubBrain) in boot_and_observe (F3)
        // and writes the brain knobs onto the genome's kernel cmdline.
        brain: Some(brain),
        memory: None,
        diarist: None,
        social: None,
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
        lease_fence: None,
    };

    let config = MeteredRunConfig {
        boot,
        tick: Duration::from_millis(100),
        // A safety ceiling well above the expected ~10s drain. If the meter never
        // saw the drained treasury (a broken wire) the run would hit this and the
        // terminal-state assertion below would fail loudly (NOT a false pass).
        max_run: Duration::from_secs(60),
        agent_state: None,
        rates: kirby_node::meter::BurnRates::default(),
    };

    let outcome = metered_run::run(config).await.expect("brain metered run completed");

    // The VM ended in Terminated{budget_exhausted}: the brain thought the treasury
    // dry and the daemon halted the VM when a meter tick could no longer be covered
    // (D-9 shared counter). NOT the safety ceiling, NOT the genome exiting.
    assert_eq!(
        outcome.terminated,
        Terminated::BudgetExhausted,
        "the brain must think itself to a budget-death halt, got {:?} after {} ticks",
        outcome.terminated,
        outcome.ticks
    );
    // The kill was daemon-initiated: the brain parked (idle_forever, F4); it did not
    // exit on its own. The daemon halted the VM host-side.
    assert!(
        outcome.daemon_initiated_kill,
        "the budget-death halt must be daemon-initiated (the genome parked, the daemon killed it)"
    );
    // The treasury drained to ~0 (the brain spent its runway thinking). The brain's
    // gateway debits dominate the drain (the meter's own CPU burn is incidental), so
    // unlike the burn workload the drain is NOT accounted by `burned_sats`; assert the
    // treasury emptied to within one think's cap (64) plus a meter tick of slack.
    let drain_floor: u64 = 128;
    assert!(
        outcome.remaining_at_halt <= drain_floor,
        "the treasury must drain to ~0 (<= {drain_floor}); got {} — the brain spent its runway",
        outcome.remaining_at_halt
    );

    eprintln!(
        "BRAIN e2e PASS: terminal={:?} ; remaining_at_halt={} (budget={budget}) ; \
         daemon_initiated_kill={} ; meter_ticks={}",
        outcome.terminated, outcome.remaining_at_halt, outcome.daemon_initiated_kill, outcome.ticks,
    );
}
