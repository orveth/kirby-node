//! Capable-loop teeth (the agentic kernel, build-spec slice 1): the genome-side COMPOSITION of
//! the two brokered acts the daemon already performs, `Completion` (PLAN/THINK) + `Memory`
//! (RECALL / ACT / VERIFY), on ONE gateway. These drive the host-side gateway directly (the
//! scope blesses "direct service-method calls"), so they prove the CONTRACT the capable loop
//! relies on WITHOUT booting a microVM: fast, deterministic, in the standard gate.
//!
//! Division of labor (deliberate, per the keeper's steer): the load-bearing SELF-CORRECTION and
//! INPUT-GUARD teeth run the REAL loop iteration (`capable::capable_tick`) against a mock gateway
//! and live in `kirby-genome/src/capable.rs` `#[cfg(test)]` (fast, ungated, in-process). THIS
//! file proves the daemon-side CONTRACT those teeth assume: a gateway with `brain = Some` AND a
//! memory backend AND both sentinels serves BOTH acts with correct SEPARATE metering, a VERIFY
//! GET reads back the GROUND TRUTH (matching OR diverging from intent), the metabolism gates hold
//! (denied THINK = death, the two write denials split), and the membrane is fail-closed.
//!
//! Coverage:
//!   - one tick: RECALL free, THINK drains, ACT drains, VERIFY confirms ... `one_tick_recall_free_think_act_drain_verify_confirms`
//!   - VERIFY reads back the ground truth; divergence is exposed (K2 contract) `verify_readback_exposes_a_corrupted_write`
//!   - a dropped write reads back not-found (K2 contract) ................. `verify_readback_of_a_dropped_write_is_not_found`
//!   - the capable slug is a VALID namespaced slug .......................... `capable_slug_is_accepted`
//!   - write replays idempotently off the ONE seq (F1) .................... `same_seq_write_replays_idempotently`
//!   - death is the unaffordable THINK; recall stays free (F4) ............ `death_is_the_unaffordable_think_recall_stays_free`
//!   - ACT over the ceiling = DENIED_OVER_BUDGET (F5 loud) ................ `act_over_ceiling_is_denied_over_budget`
//!   - ACT while broke = DENIED_INSUFFICIENT_TREASURY (F5 soft) ........... `act_insufficient_treasury_is_broke`
//!   - a fact round-trips through memory .................................. `fact_round_trips_to_memory`
//!   - the membrane is fail-closed (both acts, nothing else) ............. `capable_allowlist_serves_both_acts_denies_others`
//!   - (e2e, gated) boot workload="capable" through metered_run .......... `capable_vm_boots_plans_acts_verifies_and_dies_when_broke`

use std::sync::Arc;
use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::config::{AgentConfig, BrainConfig, MemoryConfig};
use kirby_node::gateway::{GatewayService, Session};
use kirby_node::metered_run::{self, MeteredRunConfig, Terminated};
use kirby_node::rail::{
    CompositeRail, MockRail, StubBrain, StubMemory, BRAIN_COMPLETION_DESTINATION,
    MEMORY_DESTINATION,
};
use kirby_node::treasury::Treasury;
use kirby_proto::capability_request::Act;
use kirby_proto::{CapabilityRequest, ChatMessage, Completion, Memory, MemoryOp, Outcome, SettleEcash};

/// A capable-mode gateway: the CompositeRail (base `MockRail` + `StubBrain`) serves the
/// `Completion` PLAN, a `StubMemory` backend serves the `Memory` RECALL/ACT/VERIFY, and the
/// allowlist holds BOTH sentinels (and ONLY those, fail-closed). This is the both-acts-on-one-
/// gateway composition the capable loop depends on, identical to the diarist's. Returns the
/// service plus a `StubMemory` handle (shares the store, for `peek`).
fn capable_gateway(
    initial_sats: u64,
    brain_bytes_per_sat: u64,
    mem_bytes_per_sat: u64,
) -> (GatewayService, StubMemory) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let rail = CompositeRail::new(
        Arc::new(MockRail::new()),
        Arc::new(StubBrain::new(brain_bytes_per_sat)),
    );
    let backend = StubMemory::new(mem_bytes_per_sat);
    let backend_handle = backend.clone();
    let session = Session {
        task_descriptor: "capable-test".into(),
        budget_sats: initial_sats,
        // BOTH sentinels: the capable agent thinks AND writes/reads, and can reach nothing else.
        allowlisted_destinations: vec![
            BRAIN_COMPLETION_DESTINATION.to_string(),
            MEMORY_DESTINATION.to_string(),
        ],
        allowlisted_inbound_kinds: Vec::new(),
    };
    let service =
        GatewayService::new(treasury, Arc::new(rail), session).with_memory_backend(Arc::new(backend));
    (service, backend_handle)
}

/// A capable fact slug: mirrors `capable::CAPABLE_NAMESPACE` (`mem/capable/...`, a VALID slug).
fn capable_slug(name: &str) -> String {
    format!("mem/capable/{name}")
}

/// A PLAN request (`Completion`), keyed on the seq (`capable-think-{seq}`), budget == max (R4).
fn think_req(seq: u64, max_cost_sats: u64) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("capable-think-{seq}"),
        act: Some(Act::Completion(Completion {
            model: "anthropic/claude-sonnet-4.6".into(),
            messages: vec![
                ChatMessage { role: "system".into(), content: "You are The Steward.".into() },
                ChatMessage {
                    role: "user".into(),
                    content: format!("this is action {seq}, decide and act."),
                },
            ],
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

/// An ACT request (`Memory` SET) to a capable slug, keyed on the seq (`mem-write-{seq}`, the
/// shared scheme, F1).
fn set_req(seq: u64, slug: &str, value: &[u8], max_cost_sats: u64) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("mem-write-{seq}"),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: slug.to_string(),
            value: value.to_vec(),
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

/// A VERIFY/RECALL GET request (a free read), keyed uniquely per call.
fn get_req(seq: u64, slug: &str) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("capable-get-{slug}-{seq}"),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Get as i32,
            slug: slug.to_string(),
            value: Vec::new(),
            max_cost_sats: 0,
        })),
        budget_sats: 0,
    }
}

/// A RECALL LS request (a free read), keyed uniquely per call.
fn ls_req(seq: u64) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("capable-ls-{seq}"),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Ls as i32,
            slug: String::new(),
            value: Vec::new(),
            max_cost_sats: 0,
        })),
        budget_sats: 0,
    }
}

// ---- K1 (contract): one tick -- RECALL free, THINK drains, ACT drains, VERIFY confirms ----

/// A single capable tick driven through ONE gateway: RECALL (LS/GET) is free and moves nothing;
/// the PLAN (Completion) debits; the ACT (Memory SET to a capable slug) debits by the host cost;
/// the VERIFY (free GET) reads the SAME bytes back. This is the cycle the loop closes (K1), with
/// both acts metered SEPARATELY (read free, think + write drain).
#[tokio::test]
async fn one_tick_recall_free_think_act_drain_verify_confirms() {
    let (svc, _store) = capable_gateway(100_000, 16, 16);
    let start = svc.treasury_remaining().unwrap();
    let slug = capable_slug("relay-quiet");
    let fact = b"the relay has been quiet for three ticks";

    // 1. RECALL -- a free LS (empty namespace on tick 1). Zero debit.
    let ls = svc.authorize_capability(&ls_req(1)).await.unwrap();
    assert_eq!(ls.outcome, Outcome::AuthorizedAndPerformed as i32, "the RECALL LS is served");
    assert_eq!(ls.cost_sats, 0, "RECALL is a free read");
    assert_eq!(svc.treasury_remaining().unwrap(), start, "RECALL does not drain the treasury");

    // 2. PLAN -- a Completion debits and returns the plan WORDS.
    let think = svc.authorize_capability(&think_req(1, 200)).await.unwrap();
    assert_eq!(think.outcome, Outcome::AuthorizedAndPerformed as i32, "the PLAN is served");
    assert!(!think.completion.is_empty(), "the PLAN returns WORDS the genome parses into an Action");
    assert!(think.cost_sats > 0, "a think is never free");
    let after_think = think.treasury_remaining;
    assert_eq!(after_think, start - think.cost_sats, "the think drained by exactly its metered cost");

    // 3. ACT -- a Memory SET to the capable slug debits by the host storage cost.
    let act = svc.authorize_capability(&set_req(1, &slug, fact, 1_000)).await.unwrap();
    assert_eq!(
        act.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "the ACT to the namespaced capable slug is served"
    );
    assert!(act.cost_sats > 0, "a write is never free");
    assert_eq!(
        act.treasury_remaining,
        after_think - act.cost_sats,
        "the act drained by exactly the host write cost (metered SEPARATELY from the think)"
    );

    // 4. VERIFY -- a free GET reads back the SAME bytes (the loop's classify_verify -> Confirmed).
    let verify = svc.authorize_capability(&get_req(2, &slug)).await.unwrap();
    assert_eq!(verify.outcome, Outcome::AuthorizedAndPerformed as i32, "the VERIFY read is served");
    assert_eq!(verify.cost_sats, 0, "VERIFY is a free read");
    let mem = verify.memory.as_ref().expect("a memory result rides back");
    assert!(mem.found, "the just-written fact is present");
    assert_eq!(mem.value, fact, "VERIFY reads back VERBATIM -> the loop confirms the cycle (K1)");
}

// ---- K2 (contract): VERIFY reads the GROUND TRUTH; divergence is exposed ----

/// The detection signal of self-correction (K2): when the bytes that actually landed DIVERGE
/// from what the agent intended, the VERIFY read-back EXPOSES the divergence. Here the gateway
/// faithfully returns the divergent bytes; the loop's `classify_verify` turns that into a
/// Mismatch (proven in `capable.rs::tests::tick_detects_a_verify_mismatch_and_surfaces_it_for_retry`).
#[tokio::test]
async fn verify_readback_exposes_a_corrupted_write() {
    let (svc, _store) = capable_gateway(100_000, 16, 16);
    let slug = capable_slug("relay-quiet");
    let intended = b"the relay has been quiet for three ticks";
    let corrupted = b"GARBLED"; // what actually landed (a corrupted/divergent write)

    let act = svc.authorize_capability(&set_req(1, &slug, corrupted, 1_000)).await.unwrap();
    assert_eq!(act.outcome, Outcome::AuthorizedAndPerformed as i32);

    let verify = svc.authorize_capability(&get_req(2, &slug)).await.unwrap();
    let mem = verify.memory.as_ref().expect("a memory result rides back");
    assert!(mem.found, "the (corrupted) write is present");
    assert_ne!(
        mem.value, intended,
        "the VERIFY read-back EXPOSES the divergence from intent (the signal the loop turns into Mismatch)"
    );
    assert_eq!(mem.value, corrupted, "VERIFY returns the actual ground truth, not the intent");
}

/// A DROPPED write reads back not-found: the VERIFY GET of a slug that never stored returns
/// `found = false` (the loop's `classify_verify` -> Unconfirmed, the retry signal).
#[tokio::test]
async fn verify_readback_of_a_dropped_write_is_not_found() {
    let (svc, _store) = capable_gateway(100_000, 16, 16);
    let verify = svc.authorize_capability(&get_req(1, &capable_slug("never-written"))).await.unwrap();
    assert_eq!(verify.outcome, Outcome::AuthorizedAndPerformed as i32, "the VERIFY read is served");
    let mem = verify.memory.as_ref().expect("a memory result rides back");
    assert!(!mem.found, "a dropped/absent write reads back not-found (-> Unconfirmed)");
}

// ---- the capable slug is a VALID namespaced slug the daemon accepts ----

/// `mem/capable/...` lives in the `mem/` namespace, so the daemon's `is_valid_slug` ACCEPTS it
/// and the fact persists. (The genome-side guard additionally restricts writes to THIS namespace
/// only; that positive allowlist is teeth-tested in `capable.rs`.)
#[tokio::test]
async fn capable_slug_is_accepted() {
    let (svc, store) = capable_gateway(100_000, 16, 16);
    let slug = capable_slug("observations");
    let good = svc.authorize_capability(&set_req(1, &slug, b"fact", 1_000)).await.unwrap();
    assert_eq!(
        good.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "mem/capable/... is a valid slug the daemon serves"
    );
    assert!(store.peek(&slug).is_some(), "the fact is stored under the namespaced slug");
}

// ---- F1: the write replays idempotently off the ONE seq (exactly-once across resume) ----

/// The ACT key is the monotonic `seq` (`mem-write-{seq}`). A resume re-issue of the SAME seq is
/// DUPLICATE_IGNORED with NO second debit (F1 -- exactly-once), the resume-safety the capable
/// loop inherits by keying off the checkpointed seq, identical to the diarist/memory workloads.
#[tokio::test]
async fn same_seq_write_replays_idempotently() {
    let (svc, _store) = capable_gateway(100_000, 16, 16);
    let slug = capable_slug("x");

    let w1 = svc.authorize_capability(&set_req(1, &slug, b"fact", 1_000)).await.unwrap();
    assert_eq!(w1.outcome, Outcome::AuthorizedAndPerformed as i32);
    let after_w1 = w1.treasury_remaining;

    let w1_replay = svc.authorize_capability(&set_req(1, &slug, b"fact", 1_000)).await.unwrap();
    assert_eq!(
        w1_replay.outcome,
        Outcome::DuplicateIgnored as i32,
        "a resumed write dedupes on its seq-key (F1: exactly-once)"
    );
    assert_eq!(w1_replay.treasury_remaining, after_w1, "no second debit for the replayed write");
}

// ---- K3 (contract): death is the unaffordable THINK; a broke agent still RECALLs ----

/// The capable agent "dies when it can't afford to THINK" (F4). With a treasury too small to
/// cover a think, the PLAN is DENIED -- the death gate (the genome parks, the daemon halts the
/// VM). A RECALL stays FREE even then: a broke agent can still read its past.
#[tokio::test]
async fn death_is_the_unaffordable_think_recall_stays_free() {
    let (svc, _store) = capable_gateway(1, 1, 1);

    let think = svc.authorize_capability(&think_req(1, 200)).await.unwrap();
    assert_eq!(
        think.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "an unaffordable PLAN is DENIED -- the capable agent's death gate (F4)"
    );
    assert_eq!(think.cost_sats, 0, "a denied think debits nothing");

    let ls = svc.authorize_capability(&ls_req(1)).await.unwrap();
    assert_eq!(ls.outcome, Outcome::AuthorizedAndPerformed as i32, "RECALL stays served when broke");
    assert_eq!(ls.cost_sats, 0, "RECALL stays free when broke");
}

// ---- K3 (contract): the two ACT denials are DISTINCT (the loop splits loud vs soft) ----

/// F5 (the LOUD half): a write whose HOST cost exceeds the `[memory].max_cost_sats` ceiling is
/// DENIED_OVER_BUDGET -- the loop maps this to a LOUD config error (a permanent misconfiguration).
#[tokio::test]
async fn act_over_ceiling_is_denied_over_budget() {
    let (svc, store) = capable_gateway(100_000, 16, 1); // mem_bytes_per_sat = 1: host cost = bytes
    let slug = capable_slug("x");
    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "mem-write-1".into(),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: slug.clone(),
            value: b"observation".to_vec(),
            max_cost_sats: 5, // below the (slug + value) host cost; budget generous so ceiling binds
        })),
        budget_sats: 1_000,
    };
    let r = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedOverBudget as i32,
        "host cost over the ceiling is DENIED_OVER_BUDGET (the loop's LOUD config error)"
    );
    assert_eq!(r.cost_sats, 0, "a denied write debits nothing");
    assert!(store.peek(&slug).is_none(), "nothing stored on a refused write");
}

/// F5 (the SOFT half): a write the TREASURY cannot cover (with a generous ceiling) is
/// DENIED_INSUFFICIENT_TREASURY -- the loop maps this to a SOFT skip ("can recall, can't
/// record"), NOT death. A RECALL stays free.
#[tokio::test]
async fn act_insufficient_treasury_is_broke() {
    let (svc, _store) = capable_gateway(2, 16, 1);
    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "mem-write-1".into(),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: capable_slug("x"),
            value: b"observation".to_vec(),
            max_cost_sats: 1_000,
        })),
        budget_sats: 1_000,
    };
    let r = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "broke (treasury < host cost) is DENIED_INSUFFICIENT_TREASURY (the loop's SOFT skip)"
    );
    let ls = svc.authorize_capability(&ls_req(1)).await.unwrap();
    assert_eq!(ls.cost_sats, 0, "a broke capable agent can still RECALL its past");
}

// ---- a fact round-trips through the store (VERIFY returns what ACT wrote) ----

/// The capable agent's record: what it ACTs, it can VERIFY/RECALL. A fact written under a capable
/// slug round-trips VERBATIM through a free GET. (On a real EngramStore the value is NIP-AE
/// self-encrypted on the relay; the StubMemory exercises the round-trip contract.)
#[tokio::test]
async fn fact_round_trips_to_memory() {
    let (svc, _store) = capable_gateway(100_000, 16, 16);
    let slug = capable_slug("runway");
    let fact = b"my runway is shrinking and I am acting to record it accurately";

    let w = svc.authorize_capability(&set_req(3, &slug, fact, 1_000)).await.unwrap();
    assert_eq!(w.outcome, Outcome::AuthorizedAndPerformed as i32, "the fact is recorded");

    let g = svc.authorize_capability(&get_req(9, &slug)).await.unwrap();
    assert_eq!(g.outcome, Outcome::AuthorizedAndPerformed as i32, "the recall is served");
    assert_eq!(g.cost_sats, 0, "the recall is free");
    let mem = g.memory.as_ref().expect("a memory result rides back");
    assert!(mem.found, "the entry is present");
    assert_eq!(mem.value, fact, "the recalled fact round-trips VERBATIM");
}

// ---- the membrane is fail-closed: the agent thinks + writes, and reaches nothing else ----

/// In capable mode the allowlist holds EXACTLY the two sentinels, so BOTH the PLAN (Completion)
/// and the ACT (Memory) are served, but a THIRD act (an ecash spend) is DENIED_NOT_ALLOWLISTED.
/// A buggy or hostile genome cannot smuggle a money-path act through the capable workload (slice 1
/// adds reach to exactly two acts, nothing more).
#[tokio::test]
async fn capable_allowlist_serves_both_acts_denies_others() {
    let (svc, _store) = capable_gateway(100_000, 16, 16);

    let think = svc.authorize_capability(&think_req(1, 200)).await.unwrap();
    assert_eq!(think.outcome, Outcome::AuthorizedAndPerformed as i32, "Completion is allowlisted");

    let act = svc.authorize_capability(&set_req(1, &capable_slug("x"), b"f", 1_000)).await.unwrap();
    assert_eq!(act.outcome, Outcome::AuthorizedAndPerformed as i32, "Memory is allowlisted");

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
    let r = svc.authorize_capability(&settle).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedNotAllowlisted as i32,
        "a non-capable act is DENIED at the allowlist step (the membrane is fail-closed)"
    );
    assert_eq!(r.cost_sats, 0, "a denied act debits nothing");
}

// ---- (e2e): boot workload="capable" through the REAL metered_run/boot path ----

/// The integrated form: a real `kirby`-style boot with `workload = "capable"` runs the capable
/// loop through the SAME `metered_run`/`boot` path the daemon uses. `boot_and_observe` builds the
/// CompositeRail from `brain = Some` AND injects the StubMemory from `memory = Some` onto ONE
/// gateway, the allowlist holds BOTH sentinels, and the genome PLANs / parses / (ACTs) / VERIFYs
/// on a tick, draining the treasury (think drains, reads free) until it can no longer afford to
/// live and the daemon's meter HALTS the VM. Death is the host-side halt, not the genome exiting.
///
/// NOTE on the stub brain: `StubBrain` returns canned PROSE, not the capable line-grammar, so in
/// this e2e each tick the parser sees non-grammar text and produces a SAFE no-op (Invalid/NOTE)
/// rather than a write. That is itself valuable end-to-end evidence: the parser NEVER panics on
/// real (non-grammar) brain output IN A REAL microVM, and the THINK still drains to a
/// budget-death halt (metabolism + no-panic + death across the full stack). The SET/VERIFY/
/// self-correction cycle is exercised deterministically by the in-process `capable_tick` teeth in
/// `kirby-genome/src/capable.rs` (where the brain output can be scripted as real grammar).
///
/// Boots a real Firecracker microVM, so (like every real-VM test in this crate) it SKIPs green
/// without `KIRBY_GENOME_IMAGE`. Run on-harness with the image set:
///   `KIRBY_GENOME_IMAGE=$(nix build .#genome-image --print-out-paths) cargo test \
///    -p kirby-node --test capable_loop -- --include-ignored capable_vm_boots`
#[tokio::test]
async fn capable_vm_boots_plans_acts_verifies_and_dies_when_broke() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP capable_vm_boots_plans_acts_verifies_and_dies_when_broke: set KIRBY_GENOME_IMAGE \
             to the `nix build .#genome-image` output to run the real-microVM capable-loop e2e"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    // A small budget so the agent drains to a budget-death halt in a few seconds. The brain +
    // memory are stubs (deterministic, no money, no relay); the capable loop PLANs each tick.
    let budget: u64 = 800;
    let brain = BrainConfig { max_cost_sats: 64, ..BrainConfig::default() };
    let memory = MemoryConfig {
        max_cost_sats: 256, // a generous per-write ceiling (host cost stays well under it)
        ..MemoryConfig::default()
    };
    // The capable workload reuses the agent cadence/recall cmdline knobs (slice 1, no new
    // daemon plumbing): `tick_secs` drives the loop cadence, `recall_count` the RECALL depth.
    let agent = AgentConfig { tick_secs: 1, recall_count: 3 };

    let boot = BootConfig {
        image,
        node_id: format!("capabletest-{}", std::process::id()),
        task: "capable-e2e".to_string(),
        budget_sats: budget,
        initial_sats: budget,
        // The capable workload allowlists BOTH sentinels (it composes the two acts).
        allow: vec![
            kirby_node::rail::BRAIN_COMPLETION_DESTINATION.to_string(),
            kirby_node::rail::MEMORY_DESTINATION.to_string(),
        ],
        guest_cid: 32,
        gateway_port: 5032,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        workload: Some("capable".to_string()),
        // `Some(brain)` selects the CompositeRail(StubBrain); `Some(memory)` injects StubMemory;
        // `Some(agent)` carries the cadence/recall knobs onto the genome cmdline (reused).
        brain: Some(brain),
        memory: Some(memory),
        agent: Some(agent),
        social: None,
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
        lease_fence: None,
    };

    let config = MeteredRunConfig {
        boot,
        tick: Duration::from_millis(100),
        max_run: Duration::from_secs(60),
        agent_state: None,
        rates: kirby_node::meter::BurnRates::default(),
    };

    let outcome = metered_run::run(config).await.expect("capable metered run completed");

    assert_eq!(
        outcome.terminated,
        Terminated::BudgetExhausted,
        "the capable agent must live then drain to a budget-death halt, got {:?} after {} ticks",
        outcome.terminated,
        outcome.ticks
    );
    assert!(
        outcome.daemon_initiated_kill,
        "the budget-death halt must be daemon-initiated (the genome parked / drained, the daemon killed it)"
    );

    eprintln!(
        "CAPABLE e2e PASS: terminal={:?} ; remaining_at_halt={} (budget={budget}) ; \
         daemon_initiated_kill={} ; meter_ticks={}",
        outcome.terminated, outcome.remaining_at_halt, outcome.daemon_initiated_kill, outcome.ticks,
    );
}
