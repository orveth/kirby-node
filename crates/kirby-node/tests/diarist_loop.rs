//! Diarist teeth (the first PERSISTENT Kirby): the genome-side COMPOSITION of the two
//! brokered acts the daemon already performs — `Completion` (THINK) + `Memory` (RECALL /
//! REMEMBER) — on ONE gateway. These drive the host-side gateway directly (the scope blesses
//! "direct service-method calls"), so they prove the contract WITHOUT booting a microVM:
//! fast, deterministic, run in the standard gate. The genome's pure helpers (slug grammar,
//! seq-keying, prompt assembly) are unit-tested in `kirby-genome/src/diarist.rs`.
//!
//! The headline claim under test: a gateway with `brain = Some` (the CompositeRail) AND a
//! memory backend AND an allowlist holding BOTH sentinels serves BOTH acts together, with
//! correct SEPARATE metering — so the diarist composes with no new daemon act/rail/metering.
//!
//! Coverage maps to the spec §8 + the Codex folds:
//!   - one tick: RECALL free, THINK drains, REMEMBER drains ......... `one_tick_recall_free_think_and_remember_drain`
//!   - the diary slug is a VALID namespaced slug (F1) .............. `diary_slug_is_accepted_bare_diary_is_invalid`
//!   - think + write replay idempotently off the ONE seq (F1/F2) ... `same_seq_think_and_write_replay_idempotently`
//!   - death is the unaffordable THINK; recall stays free (F4) ..... `death_is_the_unaffordable_think_recall_stays_free`
//!   - REMEMBER over the ceiling = DENIED_OVER_BUDGET (F5 loud) .... `remember_over_ceiling_is_denied_over_budget`
//!   - REMEMBER while broke = DENIED_INSUFFICIENT_TREASURY (F5 soft) `remember_insufficient_treasury_is_broke`
//!   - a reflection round-trips through memory .................... `reflection_round_trips_to_memory`
//!   - the membrane is fail-closed (both acts, nothing else) ...... `diarist_allowlist_serves_both_acts_denies_others`
//!   - (e2e, gated) boot workload="diarist" through metered_run ... `diarist_vm_boots_recalls_thinks_remembers_and_dies_when_broke`

use std::sync::Arc;
use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::config::{BrainConfig, DiaristConfig, MemoryConfig};
use kirby_node::gateway::{GatewayService, Session};
use kirby_node::metered_run::{self, MeteredRunConfig, Terminated};
use kirby_node::rail::{
    CompositeRail, MockRail, StubBrain, StubMemory, BRAIN_COMPLETION_DESTINATION,
    MEMORY_DESTINATION,
};
use kirby_node::treasury::Treasury;
use kirby_proto::capability_request::Act;
use kirby_proto::{CapabilityRequest, ChatMessage, Completion, Memory, MemoryOp, Outcome, SettleEcash};

/// A diarist-mode gateway: the CompositeRail (base `MockRail` + `StubBrain`) serves the
/// `Completion` THINK, a `StubMemory` backend serves the `Memory` RECALL/REMEMBER, and the
/// allowlist holds BOTH sentinels (and ONLY those — the membrane is fail-closed). This is the
/// both-acts-on-one-gateway composition the diarist depends on. Returns the service plus a
/// `StubMemory` handle (shares the store, for `peek`).
fn diarist_gateway(
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
        task_descriptor: "diarist-test".into(),
        budget_sats: initial_sats,
        // BOTH sentinels: the diarist thinks AND remembers, and can reach nothing else.
        allowlisted_destinations: vec![
            BRAIN_COMPLETION_DESTINATION.to_string(),
            MEMORY_DESTINATION.to_string(),
        ],
    };
    let service =
        GatewayService::new(treasury, Arc::new(rail), session).with_memory_backend(Arc::new(backend));
    (service, backend_handle)
}

/// The diarist's journal slug for entry `seq` — mirrors `diarist::diary_slug` (F1: the `mem/`
/// namespace + 20-digit zero-pad).
fn diary_slug(seq: u64) -> String {
    format!("mem/diary/entry-{seq:020}")
}

/// A THINK request (`Completion`), keyed on the seq (`diarist-think-{seq}`, F2), budget ==
/// max_cost_sats (R4).
fn think_req(seq: u64, max_cost_sats: u64, recent: &str) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("diarist-think-{seq}"),
        act: Some(Act::Completion(Completion {
            model: "anthropic/claude-sonnet-4.6".into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "You are The Diarist.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: format!("recent: {recent}; this is tick {seq}, reflect."),
                },
            ],
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

/// A REMEMBER request (`Memory` SET) to the diary slug, keyed on the seq (`mem-write-{seq}`,
/// F1, matching the memory workload's scheme).
fn remember_req(seq: u64, value: &[u8], max_cost_sats: u64) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("mem-write-{seq}"),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: diary_slug(seq),
            value: value.to_vec(),
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    }
}

/// A RECALL LS request (a free read), keyed uniquely per call.
fn ls_req(seq: u64) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("diarist-ls-{seq}"),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Ls as i32,
            slug: String::new(),
            value: Vec::new(),
            max_cost_sats: 0,
        })),
        budget_sats: 0,
    }
}

/// A RECALL GET request (a free read), keyed uniquely per call.
fn get_req(seq: u64, slug: &str) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: format!("diarist-get-{slug}-{seq}"),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Get as i32,
            slug: slug.to_string(),
            value: Vec::new(),
            max_cost_sats: 0,
        })),
        budget_sats: 0,
    }
}

// ---- one tick: RECALL is free, THINK drains, REMEMBER drains (the §8 unit-tier core) ----

/// A single diarist tick driven through ONE gateway: the RECALL (LS/GET) is free and moves
/// nothing; the THINK (Completion) debits and returns the reflection WORDS; the REMEMBER
/// (Memory SET to the diary slug) debits by the host cost. This is the headline composition:
/// both acts served by one gateway, metered SEPARATELY (read free, think + write drain).
#[tokio::test]
async fn one_tick_recall_free_think_and_remember_drain() {
    let (svc, _store) = diarist_gateway(100_000, 16, 16);
    let start = svc.treasury_remaining().unwrap();

    // 1. RECALL — a free LS then GET (empty journal on tick 1). Zero debit.
    let ls = svc.authorize_capability(&ls_req(1)).await.unwrap();
    assert_eq!(ls.outcome, Outcome::AuthorizedAndPerformed as i32, "the RECALL LS is served");
    assert_eq!(ls.cost_sats, 0, "RECALL is a free read");
    assert_eq!(svc.treasury_remaining().unwrap(), start, "RECALL does not drain the treasury");

    // 2. THINK — a Completion debits and returns the reflection words.
    let think = svc.authorize_capability(&think_req(1, 200, "(empty)")).await.unwrap();
    assert_eq!(think.outcome, Outcome::AuthorizedAndPerformed as i32, "the THINK is served");
    assert!(!think.completion.is_empty(), "the THINK returns the reflection WORDS (not just a proof)");
    assert!(think.cost_sats > 0, "a think is never free");
    let after_think = think.treasury_remaining;
    assert_eq!(after_think, start - think.cost_sats, "the think drained by exactly its metered cost");

    // 3. REMEMBER — a Memory SET to the diary slug debits by the host storage cost.
    let reply = think.completion.clone();
    let remember = svc.authorize_capability(&remember_req(1, &reply, 1_000)).await.unwrap();
    assert_eq!(
        remember.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "the REMEMBER to the namespaced diary slug is served (F1)"
    );
    assert!(remember.cost_sats > 0, "a write is never free");
    assert_eq!(
        remember.treasury_remaining,
        after_think - remember.cost_sats,
        "the remember drained by exactly the host write cost (metered SEPARATELY from the think)"
    );
}

// ---- F1: the diary slug is a VALID namespaced slug; a bare `diary/...` is InvalidSlug ----

/// The Codex F1 fix: `mem/diary/entry-...` lives in the `mem/` namespace, so the daemon's
/// `is_valid_slug` ACCEPTS it and the reflection persists. A BARE `diary/entry-...` (the
/// spec's original, pre-fix slug) is `InvalidSlug` → the write would be rejected and NOTHING
/// would ever persist. This pins the fix at the gateway.
#[tokio::test]
async fn diary_slug_is_accepted_bare_diary_is_invalid() {
    let (svc, store) = diarist_gateway(100_000, 16, 16);

    // The fix: the namespaced slug is accepted and stored.
    let good = svc.authorize_capability(&remember_req(1, b"reflection", 1_000)).await.unwrap();
    assert_eq!(
        good.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "mem/diary/entry-... is a valid slug (F1)"
    );
    assert!(
        store.peek(&diary_slug(1)).is_some(),
        "the reflection is stored under the namespaced slug"
    );

    // The bug the fix avoids: a bare `diary/entry-...` has no `mem/` prefix → InvalidSlug.
    let bad_req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "mem-write-bad".into(),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: "diary/entry-1".into(),
            value: b"x".to_vec(),
            max_cost_sats: 1_000,
        })),
        budget_sats: 1_000,
    };
    let bad = svc.authorize_capability(&bad_req).await.unwrap();
    assert_ne!(
        bad.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "a bare diary/... slug is InvalidSlug — the F1 bug the diarist's slug avoids"
    );
    assert_eq!(bad.cost_sats, 0, "a refused write debits nothing");
}

// ---- F1/F2: think + write replay idempotently off the ONE checkpointed seq ----

/// Both act keys are driven off the ONE monotonic seq. A resume re-issue of the SAME seq
/// dedupes: the THINK returns the SAME persisted reflection words with NO second debit (F2 —
/// no key collision, no re-inference), and the WRITE is DUPLICATE_IGNORED with NO second
/// debit (F1 — exactly-once). This is the resume-safety the diarist inherits by keying off
/// the checkpointed seq instead of a resettable tick.
#[tokio::test]
async fn same_seq_think_and_write_replay_idempotently() {
    let (svc, _store) = diarist_gateway(100_000, 16, 16);

    // THINK seq 1, then RE-ISSUE the same think key (the resume replay).
    let t1 = svc.authorize_capability(&think_req(1, 200, "x")).await.unwrap();
    assert_eq!(t1.outcome, Outcome::AuthorizedAndPerformed as i32);
    let words = t1.completion.clone();
    let after_t1 = t1.treasury_remaining;

    let t1_replay = svc.authorize_capability(&think_req(1, 200, "x")).await.unwrap();
    assert_eq!(
        t1_replay.outcome,
        Outcome::DuplicateIgnored as i32,
        "a resumed think dedupes on its seq-key (F2: no collision, no re-inference)"
    );
    assert_eq!(t1_replay.completion, words, "the SAME reflection words ride back (the ledger persists them)");
    assert_eq!(t1_replay.treasury_remaining, after_t1, "no second debit for the replayed think");

    // REMEMBER seq 1, then RE-ISSUE the same write key.
    let w1 = svc.authorize_capability(&remember_req(1, &words, 1_000)).await.unwrap();
    assert_eq!(w1.outcome, Outcome::AuthorizedAndPerformed as i32);
    let after_w1 = w1.treasury_remaining;

    let w1_replay = svc.authorize_capability(&remember_req(1, &words, 1_000)).await.unwrap();
    assert_eq!(
        w1_replay.outcome,
        Outcome::DuplicateIgnored as i32,
        "a resumed write dedupes on its seq-key (F1: exactly-once)"
    );
    assert_eq!(w1_replay.treasury_remaining, after_w1, "no second debit for the replayed write");
}

// ---- F4: death is the unaffordable THINK; a broke diarist still RECALLs (reads are free) ----

/// gudnuf's framing: the diarist "dies when it can't afford to THINK". With a treasury too
/// small to cover a think, the THINK is DENIED — the death gate (the genome would park and the
/// daemon would halt the VM, F4). A RECALL stays FREE even then: a broke mind can still read
/// its past, it just cannot think a new thought.
#[tokio::test]
async fn death_is_the_unaffordable_think_recall_stays_free() {
    // bytes_per_sat = 1 so the think's host cost (~tens of bytes) far exceeds a 1-sat
    // treasury; the generous 200-sat ceiling means the TREASURY (not the budget) is the
    // binding gate, so this is the realistic broke-death, DENIED_INSUFFICIENT_TREASURY.
    let (svc, _store) = diarist_gateway(1, 1, 1);

    let think = svc.authorize_capability(&think_req(1, 200, "x")).await.unwrap();
    assert_eq!(
        think.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "an unaffordable THINK is DENIED — the diarist's death gate (F4)"
    );
    assert_eq!(think.cost_sats, 0, "a denied think debits nothing");

    // Even broke, a RECALL is free: the dying mind can still read its journal.
    let ls = svc.authorize_capability(&ls_req(1)).await.unwrap();
    assert_eq!(ls.outcome, Outcome::AuthorizedAndPerformed as i32, "RECALL stays served when broke");
    assert_eq!(ls.cost_sats, 0, "RECALL stays free when broke");
}

// ---- F5: the two REMEMBER denials are DISTINCT (the diarist splits them) ----

/// F5 (the LOUD half): a write whose HOST cost exceeds the `[memory].max_cost_sats` ceiling is
/// DENIED_OVER_BUDGET — the real cost is NEVER clamped down. The diarist maps this to a LOUD
/// config error (the ceiling is misconfigured, a permanent fault), NOT the soft broke-skip.
#[tokio::test]
async fn remember_over_ceiling_is_denied_over_budget() {
    let (svc, store) = diarist_gateway(100_000, 16, 1); // mem_bytes_per_sat = 1: host cost = slug+value bytes
    // The diary slug (36 bytes) + value (10) = 46 host cost, but the ceiling is only 5. The
    // budget is generous (1000) so the CEILING — not the budget — is the binding gate.
    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "mem-write-1".into(),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: diary_slug(1),
            value: b"reflection".to_vec(),
            max_cost_sats: 5,
        })),
        budget_sats: 1_000,
    };
    let r = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedOverBudget as i32,
        "host cost over the ceiling is DENIED_OVER_BUDGET (F5: the diarist treats this as a LOUD config error)"
    );
    assert_eq!(r.cost_sats, 0, "a denied write debits nothing");
    assert!(store.peek(&diary_slug(1)).is_none(), "nothing stored on a refused write");
}

/// F5 (the SOFT half): a write the TREASURY cannot cover (with a generous ceiling) is
/// DENIED_INSUFFICIENT_TREASURY — genuinely broke. The diarist maps this to a SOFT skip ("can
/// recall, can't record"), NOT death and NOT a loud config error. A RECALL stays free.
#[tokio::test]
async fn remember_insufficient_treasury_is_broke() {
    // A 2-sat treasury cannot cover the ~46-sat host write cost; the ceiling is generous
    // (1000) so the TREASURY is the binding gate → DENIED_INSUFFICIENT_TREASURY.
    let (svc, _store) = diarist_gateway(2, 16, 1);
    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "mem-write-1".into(),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: diary_slug(1),
            value: b"reflection".to_vec(),
            max_cost_sats: 1_000,
        })),
        budget_sats: 1_000,
    };
    let r = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "broke (treasury < host cost) is DENIED_INSUFFICIENT_TREASURY (F5: the diarist treats this as a SOFT skip)"
    );
    // The soft path's promise: a broke diarist still RECALLs (reads are free).
    let ls = svc.authorize_capability(&ls_req(1)).await.unwrap();
    assert_eq!(ls.cost_sats, 0, "a broke diarist can still RECALL its past");
}

// ---- a reflection round-trips through the store (RECALL returns what REMEMBER wrote) ----

/// The diarist's purpose: what it REMEMBERs, it can RECALL. A reflection written under the
/// diary slug round-trips VERBATIM through a free GET. (On a real EngramStore the value is
/// NIP-AE self-encrypted on the relay; the StubMemory exercises the round-trip contract.)
#[tokio::test]
async fn reflection_round_trips_to_memory() {
    let (svc, _store) = diarist_gateway(100_000, 16, 16);
    let reflection = b"today I noticed my runway shrinking, and I am strangely at peace";

    let w = svc.authorize_capability(&remember_req(3, reflection, 1_000)).await.unwrap();
    assert_eq!(w.outcome, Outcome::AuthorizedAndPerformed as i32, "the reflection is recorded");

    let g = svc.authorize_capability(&get_req(9, &diary_slug(3))).await.unwrap();
    assert_eq!(g.outcome, Outcome::AuthorizedAndPerformed as i32, "the recall is served");
    assert_eq!(g.cost_sats, 0, "the recall is free");
    let mem = g.memory.as_ref().expect("a memory result rides back");
    assert!(mem.found, "the entry is present");
    assert_eq!(mem.value, reflection, "the recalled reflection round-trips VERBATIM");
}

// ---- the membrane is fail-closed: the diarist thinks + remembers, and reaches nothing else ----

/// In diarist mode the allowlist holds EXACTLY the two sentinels, so BOTH the THINK
/// (Completion) and the REMEMBER (Memory) are served, but a THIRD act (an ecash spend) is
/// DENIED_NOT_ALLOWLISTED — a buggy or hostile genome cannot smuggle a spend through the
/// diarist workload. The composition adds reach to exactly two acts, nothing more.
#[tokio::test]
async fn diarist_allowlist_serves_both_acts_denies_others() {
    let (svc, _store) = diarist_gateway(100_000, 16, 16);

    let think = svc.authorize_capability(&think_req(1, 200, "x")).await.unwrap();
    assert_eq!(think.outcome, Outcome::AuthorizedAndPerformed as i32, "Completion is allowlisted");

    let remember = svc.authorize_capability(&remember_req(1, b"r", 1_000)).await.unwrap();
    assert_eq!(remember.outcome, Outcome::AuthorizedAndPerformed as i32, "Memory is allowlisted");

    // A third act (an ecash settle) is NOT on the diarist allowlist.
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
        "a non-diarist act is DENIED at the allowlist step (the membrane is fail-closed)"
    );
    assert_eq!(r.cost_sats, 0, "a denied act debits nothing");
}

// ---- (e2e): boot workload="diarist" through the REAL metered_run/boot path ----

/// The integrated form: a real `kirby`-style boot with `workload = "diarist"` runs the
/// diarist loop through the SAME `metered_run`/`boot` path the daemon uses — `boot_and_observe`
/// builds the CompositeRail from `brain = Some` AND injects the StubMemory from `memory = Some`
/// onto ONE gateway, the allowlist holds BOTH sentinels, and the genome RECALLs / THINKs /
/// REMEMBERs on a tick, draining the treasury (think + write drain, reads free) until it can no
/// longer afford to live and the daemon's meter — watching the SAME treasury counter — HALTS
/// the VM. Death is the host-side halt, not the genome exiting.
///
/// This uses the DEFAULT meter rates so the always-on VM rent guarantees a deterministic
/// budget-exhaustion halt (the F4 rent-vs-think tuning is a deploy concern, the `[meter]`
/// block). It boots a real Firecracker microVM, so (like every real-VM test in this crate) it
/// SKIPs green without `KIRBY_GENOME_IMAGE`. Run on-harness with the image set:
///   `KIRBY_GENOME_IMAGE=$(nix build .#genome-image --print-out-paths) cargo test \
///    -p kirby-node --test diarist_loop -- --include-ignored diarist_vm_boots`
#[tokio::test]
async fn diarist_vm_boots_recalls_thinks_remembers_and_dies_when_broke() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP diarist_vm_boots_recalls_thinks_remembers_and_dies_when_broke: set \
             KIRBY_GENOME_IMAGE to the `nix build .#genome-image` output to run the real-microVM \
             persistent-diarist e2e"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    // A small budget so the agent drains to a budget-death halt in a few seconds. The brain +
    // memory are stubs (deterministic, no money, no relay); the diarist RECALLs/THINKs/REMEMBERs
    // each tick.
    let budget: u64 = 800;
    let brain = BrainConfig {
        max_cost_sats: 64,
        ..BrainConfig::default()
    };
    let memory = MemoryConfig {
        max_cost_sats: 256, // a generous per-write ceiling (host cost stays well under it)
        // No relay set => the in-memory StubMemory (this e2e exercises the loop + the wseq
        // checkpoint, not a live relay; the EngramStore round-trip is scripts/engram-store-test.sh).
        ..MemoryConfig::default()
    };
    let diarist = DiaristConfig {
        tick_secs: 1,
        recall_count: 3,
    };

    let boot = BootConfig {
        image,
        node_id: format!("diaristtest-{}", std::process::id()),
        task: "diarist-e2e".to_string(),
        budget_sats: budget,
        initial_sats: budget,
        // The diarist workload allowlists BOTH sentinels (it composes the two acts).
        allow: vec![
            kirby_node::rail::BRAIN_COMPLETION_DESTINATION.to_string(),
            kirby_node::rail::MEMORY_DESTINATION.to_string(),
        ],
        guest_cid: 31,
        gateway_port: 5031,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        workload: Some("diarist".to_string()),
        // `Some(brain)` selects the CompositeRail(StubBrain); `Some(memory)` injects StubMemory;
        // `Some(diarist)` carries the cadence/recall knobs onto the genome cmdline.
        brain: Some(brain),
        memory: Some(memory),
        diarist: Some(diarist),
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    let config = MeteredRunConfig {
        boot,
        tick: Duration::from_millis(100),
        // A safety ceiling well above the expected ~10s drain; if the meter never saw the
        // drained treasury the run would hit this and the assertion below would fail loudly.
        max_run: Duration::from_secs(60),
        agent_state: None,
        // Default synthetic rates: the always-on VM rent guarantees the budget exhausts.
        rates: kirby_node::meter::BurnRates::default(),
    };

    let outcome = metered_run::run(config).await.expect("diarist metered run completed");

    assert_eq!(
        outcome.terminated,
        Terminated::BudgetExhausted,
        "the diarist must live then drain to a budget-death halt, got {:?} after {} ticks",
        outcome.terminated,
        outcome.ticks
    );
    assert!(
        outcome.daemon_initiated_kill,
        "the budget-death halt must be daemon-initiated (the genome parked / drained, the daemon killed it)"
    );

    eprintln!(
        "DIARIST e2e PASS: terminal={:?} ; remaining_at_halt={} (budget={budget}) ; \
         daemon_initiated_kill={} ; meter_ticks={}",
        outcome.terminated, outcome.remaining_at_halt, outcome.daemon_initiated_kill, outcome.ticks,
    );
}
