//! Batch-1 fast-ungated money-path invariants (gap report 2/3/7): the four
//! enforcement points that were HW/LIVE-only before this file. All run in a plain
//! `cargo test` with NO genome image, NO KVM, NO root, NO network beyond loopback:
//!
//!  (a) GATEWAY LEASE FENCE (G8 STEP 0), mock-isolated: a `LeaseHandle` whose
//!      committed lease names ANOTHER node at a higher term yields `FenceVerdict::
//!      Fenced`; wired into the gateway debit path it must return
//!      DENIED_NOT_ACTIVE_LEASE, cost 0, and perform NOTHING (the rail count stays
//!      0). Complements `no_split_brain.rs::g8_gateway_debit_path_is_lease_fenced`
//!      (which kills a real leader to advance the term); this isolates ONLY the
//!      fence verdict -> gateway deny, with no election/handoff orchestration.
//!  (b) D-20 REAL-RAIL CLAMP: the pure `rail::clamp_spend` (the exact fn
//!      `CdkEcashRail::perform` calls at BOTH clamp sites) never returns more than
//!      the cap, so the real melt can never overspend past the gateway-checked
//!      estimate -- proven WITHOUT a live mint.
//!  (c) CONCURRENT DEBIT RACE: two tokio tasks issuing the SAME idempotency_key
//!      against ONE gateway/treasury -> exactly one performs, debited once, balance
//!      never negative (the in-transaction Duplicate guard, D-9).
//!  (d) CRASH-WINDOW wseq IDEMPOTENCY: drop the gateway BEFORE a checkpoint, rebuild
//!      a fresh gateway over the SAME persisted treasury+ledger, reissue the same
//!      wseq/idempotency_key -> DUPLICATE_IGNORED, no double-perform, debited once
//!      total across the crash.

use std::sync::Arc;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::raft_lease::{bring_up_cluster, ActiveLease, FenceVerdict, LeaseNode};
use kirby_node::rail::{self, MockRail};
use kirby_node::treasury::Treasury;
use kirby_proto::capability_request::Act;
use kirby_proto::{CapabilityRequest, Outcome, SettleEcash};

const MINT: &str = "mint.test.local";

/// A SettleEcash request on the allowlisted mint for `amount`, authorizing `budget`
/// for the act, keyed by `key`.
fn settle_req(key: &str, amount: u64, budget: u64) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: MINT.into(),
            amount,
            recipient_or_quote: "q".into(),
        })),
        budget_sats: budget,
    }
}

fn test_session() -> Session {
    Session {
        task_descriptor: "money-path-batch1".into(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec![MINT.to_string()],
        allowlisted_inbound_kinds: Vec::new(),
    }
}

// ---- (a) gateway lease fence, mock-isolated -----------------------------------------

/// (a) G8 STEP 0, mock-isolated: a single lease node whose committed lease has been
/// caught up to ANOTHER holder at a HIGHER term is `Fenced` (it believes it is active
/// at its own start term, but the committed lease moved on). Wired into the gateway as
/// the debit fence, a RequestCapability must be DENIED_NOT_ACTIVE_LEASE, cost 0, and
/// the rail must perform NOTHING. This isolates the fence verdict -> gateway deny path
/// WITHOUT bringing up a 3-node cluster or killing a leader (that full handoff is
/// covered by no_split_brain.rs); no genome image, no real election.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gateway_fences_debit_when_lease_moved_to_another_node() {
    // The stale node believes it was active at term T (1); the committed lease has
    // since moved to a DIFFERENT node (2) at the higher term T+1 (2). A revived stale
    // node learns this committed lease as it catches up on rejoin.
    let believed_term = 1u64;
    let node = LeaseNode::start(7, "127.0.0.1:0").await.expect("start lease node");
    let handle = node.handle();
    handle
        .catch_up_committed_lease(ActiveLease { node_id: 2, term: believed_term + 1 })
        .await;

    // Sanity: the fence itself rejects this node at its believed term (the committed
    // lease names node 2 @ T+1, not node 7).
    let verdict = handle.fence(believed_term).await;
    assert!(
        matches!(
            verdict,
            FenceVerdict::Fenced { committed_term: 2, committed_holder: 2, believed_term: 1 }
        ),
        "the stale node must be fenced by the higher committed term held by another node: {verdict:?}"
    );
    assert!(!verdict.may_act(), "a fenced node must not act");

    // Wire that fenced handle into the gateway debit path.
    let treasury = Treasury::open_temporary(1_000_000).expect("open temporary treasury");
    let start = treasury.remaining().unwrap();
    let rail = MockRail::new();
    let rail_handle = rail.clone();
    let gateway = GatewayService::new(treasury, Arc::new(rail), test_session())
        .with_lease_fence(handle, believed_term);

    // Any debit through the fenced gateway is refused at STEP 0, before perform.
    let receipt = gateway
        .authorize_capability(&settle_req("fenced-act", 500, 500))
        .await
        .expect("authorize returns a receipt, not an error");

    assert_eq!(
        receipt.outcome,
        Outcome::DeniedNotActiveLease as i32,
        "a fenced node's gateway must DENY_NOT_ACTIVE_LEASE"
    );
    assert_eq!(receipt.cost_sats, 0, "a fenced debit costs 0 (no double-burn)");
    assert_eq!(
        gateway.treasury_remaining().unwrap(),
        start,
        "the treasury is UNCHANGED by a fenced debit"
    );
    assert_eq!(
        rail_handle.perform_count(),
        0,
        "the rail must NOT perform when the node is fenced (deny is BEFORE perform, STEP 0)"
    );
    assert!(receipt.proof.is_empty(), "no proof on a fenced denial");

    node.shutdown().await;
}

/// (a, control): the SAME wiring, but the node genuinely holds the committed lease at
/// its believed term, so the fence is `Active` and the gateway debits normally. This
/// pins that the fence DENY above is the lease moving, not the fence rejecting every
/// request (a fence that denied unconditionally would also pass the test above).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gateway_allows_debit_when_node_holds_the_lease() {
    // The node genuinely holds the committed lease AND is the Raft leader, which is the
    // ONLY way a node is legitimately active (it granted itself the lease AS the leader).
    // The fence now requires leadership in addition to holder+term (the S1 Codex
    // hardening: a holder that lost leadership must be fenced), so this Active control
    // uses a real single-node leader rather than a mock catch_up of a never-leader node.
    let bring_up = bring_up_cluster(&[7]).await.expect("bring up single-node cluster");
    let node = bring_up.nodes.into_iter().next().expect("the single node");
    let handle = node.handle();
    let granted = node.grant_lease(7).await.expect("grant self the default-slot lease");
    let believed_term = granted.term;
    assert!(
        matches!(handle.fence(believed_term).await, FenceVerdict::Active { term } if term == believed_term),
        "the leader holds the committed lease at its term: it must be Active"
    );

    let treasury = Treasury::open_temporary(1_000_000).expect("open temporary treasury");
    let rail = MockRail::new();
    let rail_handle = rail.clone();
    let gateway = GatewayService::new(treasury, Arc::new(rail), test_session())
        .with_lease_fence(handle, believed_term);

    let receipt = gateway
        .authorize_capability(&settle_req("active-act", 300, 300))
        .await
        .expect("authorize");
    assert_eq!(
        receipt.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "the active lease-holder's gateway must authorize + perform"
    );
    assert_eq!(receipt.cost_sats, 300, "the active node debited the act cost");
    assert_eq!(gateway.treasury_remaining().unwrap(), 1_000_000 - 300);
    assert_eq!(rail_handle.perform_count(), 1, "the active node performed exactly once");

    node.shutdown().await;
}

// ---- (b) D-20 real-rail clamp (no mint) ---------------------------------------------

/// (b) D-20: the real rail's spend clamp (`rail::clamp_spend`, the exact fn
/// `CdkEcashRail::perform` calls at both its pre-settle and post-settle clamp sites)
/// NEVER yields more than the cap. Proven without a live mint: the melt amount is
/// `clamp_spend(requested, cap)` <= cap for every requested/cap pairing, so the mint
/// can never debit past the gateway-checked estimate. This is the fast-ungated stand-in
/// for the HW/LIVE-only `CdkEcashRail` melt-clamp.
#[test]
fn b_real_rail_clamp_never_exceeds_cap() {
    // The load-bearing invariant: actual spend <= cap, always.
    // Over-cap request: clamped down to the cap.
    assert_eq!(rail::clamp_spend(1_000, 300), 300, "an over-cap amount clamps to the cap");
    // Within-cap request: the natural amount stands (not silently inflated to the cap).
    assert_eq!(rail::clamp_spend(120, 300), 120, "a within-cap amount is unchanged");
    // Exactly the cap.
    assert_eq!(rail::clamp_spend(300, 300), 300);
    // A zero cap clamps any request to zero (perform then refuses a 0 spend upstream).
    assert_eq!(rail::clamp_spend(999_999, 0), 0, "a zero cap clamps to zero");

    // The general invariant across a sweep of (requested, cap) pairs: the clamped
    // spend is never above the cap, and never above the requested amount either (the
    // clamp only ever reduces, never invents spend).
    for requested in [0u64, 1, 50, 300, 301, 1_000, u64::MAX] {
        for cap in [0u64, 1, 50, 300, 1_000, u64::MAX] {
            let clamped = rail::clamp_spend(requested, cap);
            assert!(
                clamped <= cap,
                "D-20 VIOLATED: clamp_spend({requested}, {cap}) = {clamped} exceeds the cap"
            );
            assert!(
                clamped <= requested,
                "clamp_spend({requested}, {cap}) = {clamped} exceeds the requested amount"
            );
        }
    }
}

// ---- (c) concurrent debit race ------------------------------------------------------

/// (c) D-9 race: two concurrent tasks issuing the SAME idempotency_key against ONE
/// gateway/treasury. Both may pass the STEP-1 pre-check (the key is absent) and both may
/// reach `rail.perform` -- but the in-transaction dedupe (`debit_and_record`'s
/// `DebitOutcome::Duplicate`) collapses them to EXACTLY ONE DEBIT: one task gets
/// AUTHORIZED_AND_PERFORMED, the other DUPLICATE_IGNORED, the balance falls by the cost
/// exactly ONCE and never goes negative, and both receipts agree on the post-debit
/// balance. The money invariant is the single DEBIT (the rail's settle is the idempotent
/// act keyed by the same idempotency_key, so a second perform is harmless and the debit
/// is what must not double). A single-threaded test cannot reach this in-txn guard,
/// which is exactly the gap (report item 7).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c_concurrent_same_key_debits_exactly_once() {
    let initial = 1_000u64;
    let cost = 300u64;
    let treasury = Treasury::open_temporary(initial).expect("open temporary treasury");
    let rail = MockRail::new();
    let rail_handle = rail.clone();
    // One shared gateway (cheap to clone; clones share the same treasury + rail).
    let gateway = Arc::new(GatewayService::new(treasury, Arc::new(rail), test_session()));

    // Fire both tasks against the SAME key concurrently.
    let g1 = gateway.clone();
    let g2 = gateway.clone();
    let t1 = tokio::spawn(async move {
        g1.authorize_capability(&settle_req("race-key", cost, cost)).await
    });
    let t2 = tokio::spawn(async move {
        g2.authorize_capability(&settle_req("race-key", cost, cost)).await
    });
    let r1 = t1.await.expect("task 1 joined").expect("authorize 1");
    let r2 = t2.await.expect("task 2 joined").expect("authorize 2");

    // Exactly one PERFORMED and at most one DUPLICATE: never two performs.
    let performed = [&r1, &r2]
        .iter()
        .filter(|r| r.outcome == Outcome::AuthorizedAndPerformed as i32)
        .count();
    let duplicate = [&r1, &r2]
        .iter()
        .filter(|r| r.outcome == Outcome::DuplicateIgnored as i32)
        .count();
    assert_eq!(performed, 1, "exactly one task performs the act: {:?}/{:?}", r1.outcome, r2.outcome);
    assert_eq!(duplicate, 1, "the other task gets DUPLICATE_IGNORED");

    // The rail's idempotent settle may run once or twice (both tasks can pass the
    // STEP-1 pre-check before either commits), but it must NEVER exceed the two racers:
    // there is no spurious third perform.
    let performs = rail_handle.perform_count();
    assert!(
        performs == 1 || performs == 2,
        "the rail performed {performs} times; under a 2-way race it must be 1 or 2 (the in-txn guard collapses the DEBIT, not necessarily the idempotent perform)"
    );

    // The load-bearing money invariant: debited EXACTLY once. The balance fell by
    // exactly `cost`, never negative, regardless of how many times the idempotent rail
    // ran -- the in-transaction Duplicate guard is what enforces the single debit.
    let remaining = gateway.treasury_remaining().unwrap();
    assert_eq!(remaining, initial - cost, "debited exactly once (no double-debit, no missed debit)");
    assert!(remaining <= initial, "balance never rose");

    // Both receipts agree on the post-debit balance (the genome is never told a number
    // that disagrees with the host counter).
    assert_eq!(r1.treasury_remaining, remaining);
    assert_eq!(r2.treasury_remaining, remaining);
}

// ---- (d) crash-window wseq idempotency ----------------------------------------------

/// (d) The crash window (report item 7): a key is performed and debited, then the
/// daemon "crashes" BEFORE any checkpoint -- modeled by DROPPING the gateway and the
/// treasury handle. A fresh gateway is rebuilt over the SAME persisted treasury+ledger
/// (the resume path, as `idempotent_across_resume_persisted` reopens the store) with a
/// BRAND-NEW rail. Reissuing the same wseq/idempotency_key must return DUPLICATE_IGNORED
/// with NO second perform (the new rail's count stays 0) and the treasury debited ONCE
/// total across the crash. This proves the persisted ledger -- not in-memory state lost
/// to the crash -- fences the replay.
#[tokio::test]
async fn d_crash_window_reissue_is_duplicate_no_double_perform() {
    let dir = tempdir();
    let path = dir.path().join("treasury");
    let initial = 1_000u64;
    let cost = 400u64;
    let key = "mem-write-1";

    // Pre-crash: perform the key once, debiting `cost`, then DROP everything (the
    // crash: no checkpoint, no graceful shutdown -- just the handles going away).
    let (post_cost, post_remaining) = {
        let treasury = Treasury::open(&path, initial).expect("open persisted treasury");
        let rail = MockRail::new();
        let rail_handle = rail.clone();
        let gateway = GatewayService::new(treasury, Arc::new(rail), test_session());

        let r = gateway
            .authorize_capability(&settle_req(key, cost, cost))
            .await
            .expect("pre-crash authorize");
        assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32, "the first act performs");
        assert_eq!(r.cost_sats, cost);
        assert_eq!(rail_handle.perform_count(), 1, "performed once pre-crash");
        assert_eq!(gateway.treasury_remaining().unwrap(), initial - cost);
        (r.cost_sats, r.treasury_remaining)
        // gateway, treasury handle, and rail all drop here: the "crash".
    };
    assert_eq!(post_remaining, initial - cost);

    // Post-crash resume: rebuild a fresh gateway over the SAME persisted store, with a
    // NEW rail whose perform count starts at 0 (the pre-crash rail is gone, so any
    // second perform would be visible here). Reissue the SAME key.
    {
        // The seed is deliberately huge to prove it is IGNORED on resume (the persisted
        // balance is authoritative, never silently refilled).
        let treasury = Treasury::open(&path, 999_999).expect("reopen persisted treasury");
        assert_eq!(
            treasury.remaining().unwrap(),
            initial - cost,
            "the persisted post-debit balance survived the crash; the seed is ignored"
        );
        let rail = MockRail::new();
        let rail_handle = rail.clone();
        let gateway = GatewayService::new(treasury, Arc::new(rail), test_session());

        let r = gateway
            .authorize_capability(&settle_req(key, cost, cost))
            .await
            .expect("post-crash reissue");
        assert_eq!(
            r.outcome,
            Outcome::DuplicateIgnored as i32,
            "the reissued key after the crash is a DUPLICATE (the persisted ledger fences it)"
        );
        assert_eq!(r.cost_sats, post_cost, "the prior cost is returned verbatim");
        assert_eq!(r.treasury_remaining, post_remaining, "the prior post-debit balance is returned");
        assert_eq!(
            rail_handle.perform_count(),
            0,
            "the rebuilt rail must NOT perform the act a second time across the crash"
        );
        assert_eq!(
            gateway.treasury_remaining().unwrap(),
            initial - cost,
            "debited ONCE total across the crash window (no double-debit)"
        );
    }
}

// ---- a tiny temp-dir helper (no external dev-dependency, the treasury_gateway idiom)--

struct TempDir {
    path: std::path::PathBuf,
}
impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "kirby-batch1-{}-{}-{}",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    TempDir { path }
}
