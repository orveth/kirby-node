//! EngramStore + daemon-side teeth (durable mind-state Chunk-2). These prove the
//! Chunk-2 additions to the merged Chunk-1 seam, split by what needs a relay:
//!
//!   - NETWORK-FREE (the standard gate, here): the gateway's wseq_floor boot barrier
//!     (R2-7) and the R2-4 content-aware dedupe -- the daemon-authoritative guards that
//!     make resume-idempotency real on a PERSISTENT store. Driven directly against the
//!     gateway over a shared treasury (a "restart" = a fresh gateway over the SAME
//!     persisted ledger), plus the EngramStore's host write_cost (= per-copy x N).
//!
//!   - LIVE multi-relay (write / read / LWW-reconcile / tombstone / K-of-N): the real
//!     NIP-AE round-trip needs running relays, so -- exactly like the nerve presence
//!     round-trip (`scripts/nerve-presence-test.sh`) -- it is an `#[ignore]`d test
//!     (`engram_live_multi_relay_round_trip`) driven by `scripts/engram-store-test.sh`,
//!     NOT part of the default `cargo test` gate. The encrypt-to-self / K_self
//!     determinism / LWW-reconcile LOGIC is already covered network-free by the
//!     `engram` module unit tests (`src/engram.rs`).
//!
//! Maps to the design doc §16 teeth:
//!   - wseq-checkpoint-across-restart (the persistent F1 control) -> `wseq_floor_*`
//!   - no-double-debit / content-aware dedupe (R2-4) -> `request_hash_*`
//!   - multi-relay write_cost = per-copy x N -> `engram_store_write_cost_*`
//!   - live multi-relay write/read/LWW round-trip -> `engram_live_multi_relay_round_trip` (ignored)

use std::sync::Arc;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::nerve::NodeIdentity;
use kirby_node::rail::{EngramStore, MemoryBackend, MockRail, StubMemory, MEMORY_DESTINATION};
use kirby_node::treasury::Treasury;
use kirby_proto::capability_request::Act;
use kirby_proto::{CapabilityRequest, Memory, MemoryOp, Outcome};

/// A memory-mode gateway OVER A GIVEN treasury (so two gateways can share ONE persisted
/// ledger -- the way a resume rebuilds the gateway over the surviving treasury). The
/// `with_memory_backend` call seeds the wseq_floor from that ledger (R2-7).
fn gateway_over(treasury: Treasury) -> GatewayService {
    let session = Session {
        task_descriptor: "engram-test".into(),
        budget_sats: u64::MAX,
        allowlisted_destinations: vec![MEMORY_DESTINATION.to_string()],
        allowlisted_inbound_kinds: Vec::new(),
    };
    GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_memory_backend(Arc::new(StubMemory::new(1)))
}

fn set_req(key: &str, slug: &str, value: &[u8]) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: slug.into(),
            value: value.to_vec(),
            max_cost_sats: 1_000,
        })),
        budget_sats: 1_000,
    }
}

// ---- R2-4: content-aware dedupe (no double-debit; refuse a key reused for new content) ----

/// The R2-4 tooth (design doc §16): STEP-1 dedupe is keyed by `idempotency_key`, but a
/// Memory write ALSO carries a hash of its effective request. A re-issue of the SAME key
/// with the SAME content is a legitimate replay -> `DUPLICATE_IGNORED`, ONE debit. A
/// re-issue of the same key with DIFFERENT content is a wseq desync / stale-checkpoint
/// collision -> REFUSED (debit 0), never silently served the prior (wrong) result.
#[tokio::test]
async fn request_hash_dedupes_same_content_but_refuses_different_content() {
    let treasury = Treasury::open_temporary(10_000).unwrap();
    let svc = gateway_over(treasury);

    // wseq 1: SET mem/x = A -> performed, drains.
    let r1 = svc
        .authorize_capability(&set_req("mem-write-1", "mem/x", b"A"))
        .await
        .unwrap();
    assert_eq!(r1.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert!(r1.cost_sats > 0);
    let after_first = svc.treasury_remaining().unwrap();

    // Re-issue mem-write-1 with the SAME content: a legitimate replay -> DUPLICATE_IGNORED,
    // NO second debit (the balance is unchanged).
    let dup = svc
        .authorize_capability(&set_req("mem-write-1", "mem/x", b"A"))
        .await
        .unwrap();
    assert_eq!(
        dup.outcome,
        Outcome::DuplicateIgnored as i32,
        "same key + same content is the resume-replay -> DUPLICATE_IGNORED"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        after_first,
        "a same-content replay debits NOTHING (exactly-once, no double-debit)"
    );

    // Re-issue mem-write-1 with DIFFERENT content (B, or a different slug): a key reused
    // for a different request. THE TOOTH: refused (debit 0), not served the stale A.
    let conflict = svc
        .authorize_capability(&set_req("mem-write-1", "mem/x", b"B"))
        .await
        .unwrap();
    assert_eq!(
        conflict.outcome,
        Outcome::Unspecified as i32,
        "same key + DIFFERENT content (wseq desync) is REFUSED by R2-4, not deduped"
    );
    assert_eq!(conflict.cost_sats, 0, "a refused conflict debits nothing");
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        after_first,
        "the refused conflict left the treasury untouched"
    );
}

// ---- R2-7: the wseq_floor boot barrier (the persistent F1 control across a restart) ----

/// The persistent-store F1 control (design doc §16): after a RESTART the daemon is the
/// write-seq AUTHORITY. It recomputes `wseq_floor = 1 + max(mem-write-* in the ledger)`
/// from the SURVIVING treasury, and refuses a FRESH write whose seq is BELOW the floor --
/// a regressed/stale-checkpoint genome reusing an already-superseded seq for new content.
/// A write AT/ABOVE the floor (a correctly-resumed genome) performs.
#[tokio::test]
async fn wseq_floor_rejects_a_below_floor_seq_after_restart() {
    let treasury = Treasury::open_temporary(10_000).unwrap();

    // --- pre-restart gateway: commit mem-write-1 and mem-write-3 (a GAP at 2) ---
    {
        let gw1 = gateway_over(treasury.clone());
        let a = gw1
            .authorize_capability(&set_req("mem-write-1", "mem/a", b"a"))
            .await
            .unwrap();
        assert_eq!(a.outcome, Outcome::AuthorizedAndPerformed as i32);
        let c = gw1
            .authorize_capability(&set_req("mem-write-3", "mem/c", b"c"))
            .await
            .unwrap();
        assert_eq!(c.outcome, Outcome::AuthorizedAndPerformed as i32);
    }

    // --- RESTART: a fresh gateway over the SAME (persisted) treasury. with_memory_backend
    // reseeds wseq_floor = 1 + max(mem-write-3) = 4 from the ledger. ---
    let gw2 = gateway_over(treasury.clone());
    let before = gw2.treasury_remaining().unwrap();

    // A FRESH write at seq 2 (< floor 4, and NOT in the ledger -- the gap): the regressed
    // genome reusing a superseded seq. THE TOOTH: refused (debit 0).
    let regressed = gw2
        .authorize_capability(&set_req("mem-write-2", "mem/regressed", b"new"))
        .await
        .unwrap();
    assert_eq!(
        regressed.outcome,
        Outcome::Unspecified as i32,
        "a fresh write BELOW the wseq_floor (regressed/stale-checkpoint genome) is refused (R2-7)"
    );
    assert_eq!(regressed.cost_sats, 0);
    assert_eq!(
        gw2.treasury_remaining().unwrap(),
        before,
        "the refused below-floor write left the treasury untouched"
    );

    // A write AT/ABOVE the floor (a correctly-resumed genome continuing past its restored
    // wseq) performs -- the floor refuses regression, never legitimate forward progress.
    let forward = gw2
        .authorize_capability(&set_req("mem-write-4", "mem/d", b"d"))
        .await
        .unwrap();
    assert_eq!(
        forward.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "a write at/above the recomputed floor performs (forward progress is allowed)"
    );
}

/// The floor only ever RISES (R2-7): once a high seq commits at runtime, a later FRESH
/// write at a lower seq is refused even without a restart -- the in-memory floor advanced
/// past it. (Defends against an in-session wseq regression, not just a cross-restart one.)
#[tokio::test]
async fn wseq_floor_advances_at_runtime() {
    let treasury = Treasury::open_temporary(10_000).unwrap();
    let svc = gateway_over(treasury);

    // Commit mem-write-1, then jump to mem-write-9 (a correctly-advancing genome). The
    // floor advances to 10.
    assert_eq!(
        svc.authorize_capability(&set_req("mem-write-1", "mem/a", b"a"))
            .await
            .unwrap()
            .outcome,
        Outcome::AuthorizedAndPerformed as i32
    );
    assert_eq!(
        svc.authorize_capability(&set_req("mem-write-9", "mem/i", b"i"))
            .await
            .unwrap()
            .outcome,
        Outcome::AuthorizedAndPerformed as i32
    );

    // A FRESH write at seq 5 (< the advanced floor 10, not in the ledger): refused.
    let regressed = svc
        .authorize_capability(&set_req("mem-write-5", "mem/e", b"e"))
        .await
        .unwrap();
    assert_eq!(
        regressed.outcome,
        Outcome::Unspecified as i32,
        "a fresh write below the runtime-advanced floor is refused (R2-7 monotonicity)"
    );
}

// ---- EngramStore host write_cost: the ONE-TIME storage cost scales by copy-count N ----

/// Build an EngramStore over `relays` from a throwaway identity keyfile. The relay URLs
/// need not be reachable -- `connect` registers + initiates connection in the background
/// and returns immediately, and `write_cost` is a PURE host computation (no network).
async fn engram_store(relays: &[String], bytes_per_sat: u64) -> EngramStore {
    // A unique temp keyfile per call (deterministic name from the relay count + bps so
    // parallel tests don't collide; NodeIdentity generates + persists if absent).
    let key_path = std::env::temp_dir().join(format!(
        "kirby-engram-test-{}-{}.nostr.key",
        relays.len(),
        bytes_per_sat
    ));
    let identity = NodeIdentity::load_or_create(&key_path).expect("create test identity");
    EngramStore::connect(identity.keys().clone(), relays, None, bytes_per_sat)
        .await
        .expect("connect engram store")
}

/// The EngramStore's host-computed `write_cost` (design doc §16): a ONE-TIME storage cost
/// = the per-copy byte cost (`ceil(bytes / bytes_per_sat)`, min 1) times the copy-count N
/// (the relay-set size). Durability is paid for at write time, by copy count -- no rent.
#[tokio::test]
async fn engram_store_write_cost_scales_by_copy_count() {
    let set = |slug: &str, value: &[u8]| Memory {
        op: MemoryOp::Set as i32,
        slug: slug.into(),
        value: value.to_vec(),
        max_cost_sats: 0,
    };
    // 15 payload bytes ("mem/x" = 5 + 10 value); bytes_per_sat = 16 -> ceil = 1 per copy.
    let m = set("mem/x", b"0123456789");

    let one_relay = engram_store(&["ws://127.0.0.1:65010".into()], 16).await;
    assert_eq!(one_relay.write_cost(&m), 1, "N=1: one copy, 1 sat");

    let three_relays = engram_store(
        &[
            "ws://127.0.0.1:65011".into(),
            "ws://127.0.0.1:65012".into(),
            "ws://127.0.0.1:65013".into(),
        ],
        16,
    )
    .await;
    assert_eq!(
        three_relays.write_cost(&m),
        3,
        "N=3: the same engram costs 3x (one copy per relay) -- durability is write-time copy count"
    );

    // An RM (no value) still costs >= N (a tombstone is a write to every relay).
    let rm = Memory {
        op: MemoryOp::Rm as i32,
        slug: "mem/x".into(),
        value: Vec::new(),
        max_cost_sats: 0,
    };
    assert_eq!(three_relays.write_cost(&rm), 3, "a tombstone costs N (>= 1 per copy)");
}

// ---- LIVE multi-relay round-trip (ignored: needs running relays; see the e2e script) ----

/// The live NIP-AE round-trip over a real relay set: SET -> GET (value round-trips,
/// self-decrypted) -> RM -> GET (absent, tombstoned) -> SET a second slug -> LS (lists the
/// live slug). Proves multi-relay write/read + LWW-reconcile + tombstones + K-of-N end to
/// end. IGNORED by default (it needs relays, like the nerve presence round-trip); run via
/// `scripts/engram-store-test.sh`, which launches relays and sets `KIRBY_ENGRAM_RELAYS`.
#[tokio::test]
#[ignore = "needs running relays; run scripts/engram-store-test.sh (KIRBY_ENGRAM_RELAYS)"]
async fn engram_live_multi_relay_round_trip() {
    let relays: Vec<String> = std::env::var("KIRBY_ENGRAM_RELAYS")
        .expect("set KIRBY_ENGRAM_RELAYS=ws://...,ws://... (scripts/engram-store-test.sh does this)")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert!(!relays.is_empty(), "KIRBY_ENGRAM_RELAYS must list >=1 relay");

    let store = engram_store(&relays, 16).await;
    // Let the relay connections establish before the first write.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let get = |slug: &str| Memory {
        op: MemoryOp::Get as i32,
        slug: slug.into(),
        value: Vec::new(),
        max_cost_sats: 0,
    };

    // SET core = A.
    let set_core = Memory {
        op: MemoryOp::Set as i32,
        slug: "core".into(),
        value: b"durable-A".to_vec(),
        max_cost_sats: 0,
    };
    store.write(&set_core, "mem-write-1").await.expect("SET core");

    // GET core -> the value round-trips (self-decrypted from the relay set).
    let got = store.read(&get("core")).await.expect("GET core");
    assert!(got.found, "core is found after the SET");
    assert_eq!(got.value, b"durable-A", "GET returns the self-decrypted value");

    // RM core -> a tombstone wins the LWW (later created_at).
    let rm_core = Memory {
        op: MemoryOp::Rm as i32,
        slug: "core".into(),
        value: Vec::new(),
        max_cost_sats: 0,
    };
    store.write(&rm_core, "mem-write-2").await.expect("RM core");
    let after_rm = store.read(&get("core")).await.expect("GET core after RM");
    assert!(!after_rm.found, "core reads ABSENT after the tombstone (LWW drops it)");

    // SET a second slug, then LS lists exactly the live slug.
    let set_x = Memory {
        op: MemoryOp::Set as i32,
        slug: "mem/x".into(),
        value: b"v".to_vec(),
        max_cost_sats: 0,
    };
    store.write(&set_x, "mem-write-3").await.expect("SET mem/x");
    let ls = store
        .read(&Memory { op: MemoryOp::Ls as i32, slug: String::new(), value: Vec::new(), max_cost_sats: 0 })
        .await
        .expect("LS");
    assert!(ls.slugs.contains(&"mem/x".to_string()), "LS lists the live slug");
    assert!(!ls.slugs.contains(&"core".to_string()), "LS omits the tombstoned slug");
}
