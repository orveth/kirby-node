//! Memory-stub teeth tests (the durable-mind-state Chunk-1): the `Memory` brokered act,
//! the `MemoryBackend`/`StubMemory` seam, the read/write metering FORK, and the
//! write-seq idempotency that fixes the content-addressing bug. These drive the host-side
//! gateway directly (the scope blesses "direct service-method calls"), so they prove the
//! contract WITHOUT booting a microVM: fast, deterministic, run in the standard gate.
//!
//! The full `workload="memory"` boot through the REAL `metered_run`/`boot` path is
//! `memory_vm_boots_records_and_dies_when_broke` below: it boots a real Firecracker
//! microVM, so like every real-VM test here it SKIPs (green) when `KIRBY_GENOME_IMAGE` is
//! unset, and must be run on-harness with the image set.
//!
//! Coverage maps to the design doc teeth (§11/§12) + the charter's required set:
//!   - F1 headline negative control (SET A -> RM -> SET A ends = A) .. `reset_after_remove_is_applied_not_deduped`
//!   - GET is free + writes NO ledger row (G3) ..................... `read_is_free_and_writes_no_ledger_row`
//!   - SET drains by the HOST-computed cost ......................... `write_drains_by_host_cost`
//!   - replayed-same-wseq SET = exactly ONE debit (F1/G6) ........... `same_wseq_write_replay_debits_once`
//!   - broke agent recalls (free read) but cannot record (G3/§12) ... `broke_agent_reads_but_cannot_write`
//!   - write cost is a CEILING, never clamped down (G2) ............. `write_cost_over_ceiling_is_denied_not_clamped`
//!   - LS enumerates the live slugs (free) ......................... `ls_enumerates_slugs_free`
//!   - a malformed request is denied before any work (G5) .......... `malformed_request_is_denied_debit_zero`
//!   - memory-mode allowlist denies a non-memory act (fail-closed) .. `memory_mode_allowlist_denies_non_memory`
//!   - a Memory act on a no-backend gateway fails closed ........... `memory_act_without_backend_fails_closed`
//!   - StubMemory models the G6 same-wseq re-perform ............... `stub_memory_models_same_wseq_reperform`
//!   - old-shape ledger records (incl brain-era) still decode (R1) .. `old_shape_records_still_deserialize`

use std::sync::Arc;
use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::config::MemoryConfig;
use kirby_node::gateway::{GatewayService, Session};
use kirby_node::metered_run::{self, MeteredRunConfig, Terminated};
use kirby_node::rail::{MemoryBackend, MockRail, StubMemory, WriteCommit, MEMORY_DESTINATION};
use kirby_node::treasury::{PerformedRecord, Treasury};
use kirby_proto::capability_request::Act;
use kirby_proto::{CapabilityRequest, Memory, MemoryOp, Outcome, SettleEcash, WriteStatus};

/// A memory-mode gateway: a `StubMemory` backend, the base `MockRail` (which memory acts
/// NEVER touch -- the gateway performs memory itself), and an allowlist holding EXACTLY
/// the memory sentinel (fail-closed: a non-memory act is denied at the allowlist step).
/// Returns the service plus a `StubMemory` handle (shares the store, for `peek`) and a
/// `Treasury` handle (shares the ledger, to assert read-bypasses-the-ledger).
fn memory_gateway(initial_sats: u64, bytes_per_sat: u64) -> (GatewayService, StubMemory, Treasury) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let treasury_handle = treasury.clone();
    let backend = StubMemory::new(bytes_per_sat);
    let backend_handle = backend.clone();
    let session = Session {
        task_descriptor: "memory-test".into(),
        budget_sats: initial_sats,
        allowlisted_destinations: vec![MEMORY_DESTINATION.to_string()],
    };
    let service = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_memory_backend(Arc::new(backend));
    (service, backend_handle, treasury_handle)
}

/// Build a Memory request with explicit budget (so a test can make `max_cost_sats` the
/// binding ceiling independently of the request budget).
fn mem_req(
    key: &str,
    op: MemoryOp,
    slug: &str,
    value: &[u8],
    max_cost_sats: u64,
    budget_sats: u64,
) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::Memory(Memory {
            op: op as i32,
            slug: slug.into(),
            value: value.to_vec(),
            max_cost_sats,
        })),
        budget_sats,
    }
}

/// A SET keyed by `key` (a write; `budget_sats == max_cost_sats`, mirroring the genome).
fn set_req(key: &str, slug: &str, value: &[u8], max_cost_sats: u64) -> CapabilityRequest {
    mem_req(key, MemoryOp::Set, slug, value, max_cost_sats, max_cost_sats)
}
/// An RM keyed by `key` (a write).
fn rm_req(key: &str, slug: &str, max_cost_sats: u64) -> CapabilityRequest {
    mem_req(key, MemoryOp::Rm, slug, &[], max_cost_sats, max_cost_sats)
}
/// A GET keyed by `key` (a free read).
fn get_req(key: &str, slug: &str) -> CapabilityRequest {
    mem_req(key, MemoryOp::Get, slug, &[], 0, 0)
}
/// An LS keyed by `key` (a free read).
fn ls_req(key: &str) -> CapabilityRequest {
    mem_req(key, MemoryOp::Ls, "", &[], 0, 0)
}

// ---- THE HEADLINE F1 NEGATIVE CONTROL: SET A -> RM -> SET A ends = A, not deduped ----

/// The bug the write-seq fix exists to prevent (design doc 10 F1 / 12 teeth): with a
/// CONTENT-addressed idempotency key, `SET x=A` then `RM x` then a later INTENTIONAL
/// `SET x=A` would hit the SAME key as the first SET and replay the old receipt WITHOUT
/// writing -- so `x` would stay deleted. With the monotonic WRITE-SEQ key, the third SET
/// is a DISTINCT act, is APPLIED (not deduped), and `x` ends = A. The treasury drains
/// once per write (three writes, three debits).
#[tokio::test]
async fn reset_after_remove_is_applied_not_deduped() {
    let (svc, store, _treasury) = memory_gateway(10_000, 1);
    let slug = "mem/x";
    let value = b"A";

    // wseq 1: SET x=A.
    let r1 = svc
        .authorize_capability(&set_req("mem-write-1", slug, value, 1_000))
        .await
        .unwrap();
    assert_eq!(r1.outcome, Outcome::AuthorizedAndPerformed as i32, "first SET performed");
    assert!(r1.cost_sats > 0, "a write is never free");

    // wseq 2: RM x (tombstone the value we just wrote).
    let r2 = svc
        .authorize_capability(&rm_req("mem-write-2", slug, 1_000))
        .await
        .unwrap();
    assert_eq!(r2.outcome, Outcome::AuthorizedAndPerformed as i32, "RM performed");
    assert_eq!(
        r2.memory.as_ref().unwrap().write_status,
        WriteStatus::Removed as i32,
        "RM of an existing slug reports Removed"
    );
    assert_eq!(store.peek(slug), None, "after RM the slug is gone");

    // wseq 3: SET x=A AGAIN under a DISTINCT key. The content (op+slug+value) is IDENTICAL
    // to wseq 1 -- a content-addressed key would falsely dedupe this and leave x deleted.
    let r3 = svc
        .authorize_capability(&set_req("mem-write-3", slug, value, 1_000))
        .await
        .unwrap();
    assert_eq!(
        r3.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "the re-SET is a NEW act (distinct wseq), NOT a DUPLICATE_IGNORED -- the F1 fix"
    );

    // THE TOOTH: x ends = A (the re-SET was applied, not deduped away).
    assert_eq!(
        store.peek(slug).as_deref(),
        Some(value.as_slice()),
        "x must end = A: the re-SET after the RM was APPLIED (content-addressing would have left it deleted)"
    );

    // And the treasury drained once per write (three distinct debits, none deduped).
    let expected_drain = r1.cost_sats + r2.cost_sats + r3.cost_sats;
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        10_000 - expected_drain,
        "each of the three writes debited exactly once"
    );
}

// ---- READS ARE FREE + leave NO ledger row (design doc 12 G3) ----

/// A GET is AUTHORIZED_AND_PERFORMED at ZERO debit, returns the structured value
/// (round-trip), and writes NO ledger row -- while the SET that preceded it DID record a
/// row (only writes record). Free, unique-keyed reads must not grow the dedupe ledger.
#[tokio::test]
async fn read_is_free_and_writes_no_ledger_row() {
    let (svc, _store, treasury) = memory_gateway(10_000, 4);

    // Seed a value with a write (this DOES record a ledger row, keyed by its wseq).
    let set = svc
        .authorize_capability(&set_req("mem-write-1", "core", b"hello", 1_000))
        .await
        .unwrap();
    assert_eq!(set.outcome, Outcome::AuthorizedAndPerformed as i32);
    let after_write = svc.treasury_remaining().unwrap();

    // GET it back: free (cost 0), balance unchanged, the VALUE round-trips.
    let get = svc
        .authorize_capability(&get_req("mem-get-core-1", "core"))
        .await
        .unwrap();
    assert_eq!(get.outcome, Outcome::AuthorizedAndPerformed as i32, "the read is served");
    assert_eq!(get.cost_sats, 0, "a read is FREE (zero debit, G3)");
    assert_eq!(get.treasury_remaining, after_write, "a read does not move the treasury");
    let result = get.memory.as_ref().expect("a memory result rides back");
    assert!(result.found, "the slug is present");
    assert_eq!(result.value, b"hello", "the read returns the stored VALUE, not just a hash");
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        after_write,
        "the treasury is unchanged across the read"
    );

    // THE TOOTH: the read left NO ledger row (G3), while the write DID record one.
    assert!(
        treasury.lookup("mem-get-core-1").unwrap().is_none(),
        "a free read must NOT write a dedupe-ledger row (else the ledger grows unbounded)"
    );
    assert!(
        treasury.lookup("mem-write-1").unwrap().is_some(),
        "a write DOES record a ledger row (only writes record)"
    );
}

// ---- A WRITE drains by the HOST-computed cost (design doc 12 G2) ----

/// A SET debits exactly the HOST-computed storage cost (a pure function of the op bytes),
/// and the treasury falls by that amount. The host -- not the caller -- prices the write.
#[tokio::test]
async fn write_drains_by_host_cost() {
    let bytes_per_sat = 4;
    let (svc, store, _treasury) = memory_gateway(10_000, bytes_per_sat);

    let value = b"hello world";
    let req = set_req("mem-write-1", "core", value, 1_000);
    // The host's price for this exact write (slug + value bytes, ceil-divided).
    let Some(Act::Memory(m)) = req.act.as_ref() else { unreachable!() };
    let host_cost = store.write_cost(m);
    assert!(host_cost > 0);

    let receipt = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(receipt.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(receipt.cost_sats, host_cost, "the debit equals the HOST-computed cost");
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        10_000 - host_cost,
        "the treasury drained by exactly the host cost"
    );
}

// ---- replayed-same-wseq SET = exactly ONE debit (design doc 10 F1 / 12 G6) ----

/// Re-issuing a SET under the SAME write-seq key (the resume retry) returns
/// DUPLICATE_IGNORED with the SAME structured result and cost, and debits NOTHING a
/// second time -- the exactly-once-across-resume property the second treasury needs.
#[tokio::test]
async fn same_wseq_write_replay_debits_once() {
    let (svc, _store, _treasury) = memory_gateway(10_000, 4);
    let req = set_req("mem-write-1", "core", b"durable", 1_000);

    let first = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(first.outcome, Outcome::AuthorizedAndPerformed as i32);
    let cost = first.cost_sats;
    let remaining = first.treasury_remaining;
    let result = first.memory.clone();

    // Re-issue the SAME wseq key (the resume replay): DUPLICATE_IGNORED, identical result.
    let replay = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(
        replay.outcome,
        Outcome::DuplicateIgnored as i32,
        "a re-issued write-seq dedupes against the persisted ledger"
    );
    assert_eq!(replay.cost_sats, cost, "no second debit");
    assert_eq!(replay.treasury_remaining, remaining, "the balance is unchanged on a duplicate");
    assert_eq!(replay.memory, result, "the SAME structured result rides back (not just the proof)");
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        remaining,
        "the treasury was debited exactly once across the replay"
    );
}

// ---- broke agent: recalls its past (free read) but cannot record (write DENIED) ----

/// design doc 12 corollary: a broke mind loses the ability to FORM memories, not access to
/// its past. Fund exactly one write; after it the treasury is 0. A GET still serves (free,
/// recalls the value), but the next SET is DENIED_INSUFFICIENT_TREASURY.
#[tokio::test]
async fn broke_agent_reads_but_cannot_write() {
    // bytes_per_sat = 1, so SET core=b"v" costs ("core" 4 + "v" 1) = 5. Fund exactly 5.
    let (svc, _store, _treasury) = memory_gateway(5, 1);

    let set = svc
        .authorize_capability(&set_req("mem-write-1", "core", b"v", 1_000))
        .await
        .unwrap();
    assert_eq!(set.outcome, Outcome::AuthorizedAndPerformed as i32, "the one affordable write lands");
    assert_eq!(svc.treasury_remaining().unwrap(), 0, "the treasury is now empty");

    // Broke, but a READ is free: the agent still recalls its past.
    let get = svc.authorize_capability(&get_req("mem-get-core-1", "core")).await.unwrap();
    assert_eq!(get.outcome, Outcome::AuthorizedAndPerformed as i32, "a broke agent can still READ");
    assert_eq!(get.cost_sats, 0);
    assert_eq!(get.memory.as_ref().unwrap().value, b"v", "it recalls the value it stored while funded");

    // But a WRITE can no longer be afforded.
    let blocked = svc
        .authorize_capability(&set_req("mem-write-2", "mem/new", b"more", 1_000))
        .await
        .unwrap();
    assert_eq!(
        blocked.outcome,
        Outcome::DeniedInsufficientTreasury as i32,
        "a broke agent cannot FORM a new memory (write DENIED)"
    );
    assert_eq!(blocked.cost_sats, 0, "a denied write debits nothing");
}

// ---- the write cost is a CEILING, never clamped down (design doc 12 G2) ----

/// A write whose HOST-computed cost EXCEEDS the caller's `max_cost_sats` is
/// DENIED_OVER_BUDGET -- the real cost is NEVER clamped down to the cap (which would
/// silently under-charge the store). Nothing is debited and nothing is stored.
#[tokio::test]
async fn write_cost_over_ceiling_is_denied_not_clamped() {
    let (svc, store, _treasury) = memory_gateway(10_000, 1);

    // host cost = ("core" 4 + "hello" 5) = 9, but the caller's ceiling is only 5. The
    // budget is generous (1000), so the CEILING -- not the budget -- is the binding gate.
    let req = mem_req("mem-write-1", MemoryOp::Set, "core", b"hello", 5, 1_000);
    let receipt = svc.authorize_capability(&req).await.unwrap();

    assert_eq!(
        receipt.outcome,
        Outcome::DeniedOverBudget as i32,
        "a host cost above the ceiling is DENIED (NEVER clamped down to the cap, G2)"
    );
    assert_eq!(receipt.cost_sats, 0, "a denied write debits nothing");
    assert_eq!(svc.treasury_remaining().unwrap(), 10_000, "the treasury is untouched");
    assert_eq!(store.peek("core"), None, "the store was NOT mutated by a refused write");
}

// ---- LS enumerates the live slugs (a free read) ----

#[tokio::test]
async fn ls_enumerates_slugs_free() {
    let (svc, _store, _treasury) = memory_gateway(10_000, 4);
    svc.authorize_capability(&set_req("mem-write-1", "core", b"a", 1_000)).await.unwrap();
    svc.authorize_capability(&set_req("mem-write-2", "mem/b", b"b", 1_000)).await.unwrap();
    let before = svc.treasury_remaining().unwrap();

    let ls = svc.authorize_capability(&ls_req("mem-ls-1")).await.unwrap();
    assert_eq!(ls.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(ls.cost_sats, 0, "LS is a free read");
    let mut slugs = ls.memory.as_ref().unwrap().slugs.clone();
    slugs.sort();
    assert_eq!(slugs, vec!["core".to_string(), "mem/b".to_string()], "LS lists the live slugs");
    assert_eq!(svc.treasury_remaining().unwrap(), before, "LS does not debit");
}

// ---- a malformed request is denied before any work (design doc 12 G5) ----

/// An invalid slug is rejected before cost-classification: debit 0, nothing stored. (The
/// stub maps a backend/validation fault to UPSTREAM_FAILED -- a dedicated DENIED_MALFORMED
/// is a clean Chunk-2 addition; the BEHAVIOR here is correct: refused, no debit, no write.)
#[tokio::test]
async fn malformed_request_is_denied_debit_zero() {
    let (svc, store, _treasury) = memory_gateway(10_000, 4);
    // "notcore" is neither "core" nor "mem/..." -- an invalid slug (G5).
    let req = set_req("mem-write-1", "notcore", b"v", 1_000);
    let receipt = svc.authorize_capability(&req).await.unwrap();

    assert_ne!(
        receipt.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "a malformed request must not be performed"
    );
    assert_eq!(receipt.cost_sats, 0, "a malformed request debits nothing");
    assert_eq!(svc.treasury_remaining().unwrap(), 10_000, "the treasury is untouched");
    assert_eq!(store.peek("notcore"), None, "nothing was stored");
}

// ---- the memory-mode membrane is fail-closed (the agent only remembers) ----

/// In memory mode the allowlist holds ONLY the memory sentinel, so a non-memory act (here
/// an ecash settle) is DENIED_NOT_ALLOWLISTED at the gateway allowlist step and performs
/// nothing -- a buggy or hostile genome cannot smuggle a spend through the memory workload.
#[tokio::test]
async fn memory_mode_allowlist_denies_non_memory() {
    let (svc, _store, _treasury) = memory_gateway(10_000, 4);
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
        "a non-memory destination is not on the memory allowlist"
    );
    assert_eq!(receipt.cost_sats, 0);
    assert_eq!(svc.treasury_remaining().unwrap(), 10_000, "balance untouched");
}

/// A Memory act on a gateway with NO memory backend wired (a misconfiguration) fails
/// closed: debit 0, perform nothing -- it never silently succeeds.
#[tokio::test]
async fn memory_act_without_backend_fails_closed() {
    let treasury = Treasury::open_temporary(10_000).expect("treasury");
    let session = Session {
        task_descriptor: "no-memory".into(),
        budget_sats: 10_000,
        allowlisted_destinations: vec![MEMORY_DESTINATION.to_string()],
    };
    // NOTE: no `.with_memory_backend(..)` -- the backend is absent.
    let svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session);

    let receipt = svc
        .authorize_capability(&set_req("mem-write-1", "core", b"v", 1_000))
        .await
        .unwrap();
    assert_ne!(
        receipt.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "a Memory act with no backend must NOT succeed"
    );
    assert_eq!(receipt.cost_sats, 0, "fail-closed debits nothing");
    assert_eq!(svc.treasury_remaining().unwrap(), 10_000, "balance untouched");
}

// ---- StubMemory models the G6 same-wseq re-perform (design doc 12 G6) ----

/// At the BACKEND level (the gateway STEP-1 dedupe normally short-circuits a same-key
/// replay before perform, so this exercises the crash-window contract Chunk-2 inherits): a
/// re-perform of the SAME write token reports `AlreadyCommittedSameWseq` and reproduces the
/// SAME result, and the cost is RECOMPUTABLE (a pure function), so the single debit is
/// exact -- never zero (which would leave a write stored-but-unpaid), never twice.
#[tokio::test]
async fn stub_memory_models_same_wseq_reperform() {
    let store = StubMemory::new(4);
    let m = Memory {
        op: MemoryOp::Set as i32,
        slug: "core".into(),
        value: b"v".to_vec(),
        max_cost_sats: 1_000,
    };

    let first = store.write(&m, "mem-write-1").await.expect("first write");
    assert_eq!(first.committed, WriteCommit::Stored, "the first perform stores a new event");
    assert_eq!(first.result.write_status, WriteStatus::Stored as i32);

    // Re-perform the SAME write token: AlreadyCommittedSameWseq, SAME result.
    let replay = store.write(&m, "mem-write-1").await.expect("re-perform");
    assert_eq!(
        replay.committed,
        WriteCommit::AlreadyCommittedSameWseq,
        "a same-token re-perform reports AlreadyCommittedSameWseq (the effect already landed)"
    );
    assert_eq!(replay.result, first.result, "the re-perform reproduces the SAME result");

    // The cost is a pure function of the op bytes -- recomputable, identical across the
    // re-perform, so the daemon debits the original cost exactly once (G6).
    assert!(store.write_cost(&m) > 0);
    assert_eq!(store.write_cost(&m), store.write_cost(&m), "the host cost is deterministic");
}

// ---- an unreachable store -> UPSTREAM_FAILED, debit 0 (design doc 10 F6 injectable failure) ----

/// When the backend cannot reach the store (Chunk-2: a down relay; Chunk-1: the injected
/// `StubMemory::unreachable` failure), a write is UPSTREAM_FAILED and debits nothing -- a
/// hung/failed store never silently charges or black-holes the agent.
#[tokio::test]
async fn unreachable_store_is_upstream_failed_debit_zero() {
    let treasury = Treasury::open_temporary(10_000).expect("treasury");
    let session = Session {
        task_descriptor: "mem-unreachable".into(),
        budget_sats: 10_000,
        allowlisted_destinations: vec![MEMORY_DESTINATION.to_string()],
    };
    let svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_memory_backend(Arc::new(StubMemory::unreachable(4)));

    let receipt = svc
        .authorize_capability(&set_req("mem-write-1", "core", b"v", 1_000))
        .await
        .unwrap();
    assert_eq!(
        receipt.outcome,
        Outcome::UpstreamFailed as i32,
        "an unreachable store fails upstream"
    );
    assert_eq!(receipt.cost_sats, 0, "a failed write debits nothing");
    assert_eq!(svc.treasury_remaining().unwrap(), 10_000, "the treasury is untouched");
}

// ---- ledger backcompat: old-shape records (incl brain-era) still decode (R1) ----

/// The `memory` field is `#[serde(default)]` and LAST, so EVERY older `PerformedRecord`
/// still deserializes on resume: a pre-brain row (no `completion`, no `memory`) and a
/// brain-era row (a `completion`, no `memory`) both decode with an empty `memory`, never a
/// decode error. Without the default, every pre-memory agent would fail to resume.
#[test]
fn old_shape_records_still_deserialize() {
    // A pre-brain row: neither `completion` nor `memory`.
    let pre_brain = r#"{"cost_sats":42,"treasury_remaining_after":958,"proof":[1,2,3,4]}"#;
    let rec: PerformedRecord =
        serde_json::from_str(pre_brain).expect("pre-brain record must still deserialize");
    assert_eq!(rec.cost_sats, 42);
    assert!(rec.completion.is_empty(), "a pre-brain record decodes with an empty completion");
    assert!(rec.memory.is_empty(), "a pre-brain record decodes with an empty memory");

    // A brain-era row: a `completion` but no `memory`.
    let brain_era =
        r#"{"cost_sats":7,"treasury_remaining_after":3,"proof":[],"completion":[9,9]}"#;
    let rec: PerformedRecord =
        serde_json::from_str(brain_era).expect("brain-era record must still deserialize");
    assert_eq!(rec.completion, vec![9, 9], "the brain completion survives");
    assert!(rec.memory.is_empty(), "a brain-era record decodes with an empty memory");
}

// ---- (e2e): boot workload="memory" through the REAL metered_run/boot path ----

/// The integrated form: a real `kirby`-style boot with `workload = "memory"` runs the
/// memory loop through the SAME `metered_run`/`boot` path the daemon uses -- `boot_and_observe`
/// injects the `StubMemory` backend onto the gateway, the allowlist is exclusively the
/// memory sentinel, the genome forms memories on a tick draining the treasury (writes are
/// metered, reads are free), and when it can no longer afford a write it PARKS
/// (`idle_forever`, F4) while the daemon's meter -- watching the SAME treasury counter
/// (D-9) -- HALTS the VM. Death is the host-side halt, not the genome exiting.
///
/// This boots a real Firecracker microVM, so (like every real-VM test in this crate) it
/// SKIPs green without `KIRBY_GENOME_IMAGE`. Run on-harness with the image set:
///   `KIRBY_GENOME_IMAGE=$(nix build .#genome-image --print-out-paths) cargo test \
///    -p kirby-node --test memory_loop -- --include-ignored memory_vm_boots`
#[tokio::test]
async fn memory_vm_boots_records_and_dies_when_broke() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP memory_vm_boots_records_and_dies_when_broke: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the real-microVM durable-mind-state e2e"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    // A small budget and cheap writes so the agent drains to a budget-death in a few
    // seconds: each write costs ~tens of sats (bytes_per_sat=1), so ~budget/cost writes.
    let budget: u64 = 600;
    let memory = MemoryConfig {
        max_cost_sats: 256, // a generous per-write ceiling (host cost stays well under it)
        tick_secs: 1,
        bytes_per_sat: 1,
    };

    let boot = BootConfig {
        image,
        node_id: format!("memtest-{}", std::process::id()),
        task: "memory-e2e".to_string(),
        budget_sats: budget,
        initial_sats: budget,
        // The memory workload allowlists EXCLUSIVELY the memory sentinel.
        allow: vec![MEMORY_DESTINATION.to_string()],
        guest_cid: 29,
        gateway_port: 5029,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        workload: Some("memory".to_string()),
        brain: None,
        // `Some(memory)` selects the StubMemory backend in boot_and_observe and writes the
        // memory knobs onto the genome's kernel cmdline.
        memory: Some(memory),
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
    };

    let outcome = metered_run::run(config).await.expect("memory metered run completed");

    assert_eq!(
        outcome.terminated,
        Terminated::BudgetExhausted,
        "the agent must write itself to a budget-death halt, got {:?} after {} ticks",
        outcome.terminated,
        outcome.ticks
    );
    assert!(
        outcome.daemon_initiated_kill,
        "the budget-death halt must be daemon-initiated (the genome parked, the daemon killed it)"
    );
    let drain_floor: u64 = 300;
    assert!(
        outcome.remaining_at_halt <= drain_floor,
        "the treasury must drain to ~0 (<= {drain_floor}); got {} — the agent spent its runway recording",
        outcome.remaining_at_halt
    );

    eprintln!(
        "MEMORY e2e PASS: terminal={:?} ; remaining_at_halt={} (budget={budget}) ; \
         daemon_initiated_kill={} ; meter_ticks={}",
        outcome.terminated, outcome.remaining_at_halt, outcome.daemon_initiated_kill, outcome.ticks,
    );
}
