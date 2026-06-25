//! G8 / F9 (the no-split-brain fence): the consensus keystone, now RELAY-NATIVE +
//! FROST-signed (build-spec `build-spec-kirby-failover-relay-lease-20260625.md`). The loopback
//! Raft cluster was CUT (it was same-host only; plain-TCP Raft cannot form across NAT);
//! the lease is now a FROST-signed Nostr event published to the relay, latest-term-wins. The
//! INVARIANT under test is UNCHANGED: for each agent, AT MOST ONE node is active at the latest
//! term, and ONLY that node runs the genome + debits the treasury; a node on a stale term (or
//! one that lost the relay) is term-fenced and refuses. Only the MECHANISM swapped (a higher
//! FROST-signed term supersedes, instead of a Raft-committed grant).
//!
//! Two layers (the genome-image-gated VM handoff that rode the deleted `nosplitbrain_run` is
//! removed; the lease-driven VM handoff capstone lives in `full_loop.rs`):
//!  - `g8_lease_no_split_brain_relay`: the lease/fence mechanics on the relay-lease authority,
//!    WITHOUT the genome image (fast, always runs). It proves the initial claim, the failover
//!    supersede (a node claims term+1, the old holder is fenced), the at-most-one-node-debits
//!    money-path (simulated against ONE shared treasury gated by the fence), and the
//!    linearizability witness (never two actives at the latest term).
//!  - `g8_gateway_debit_path_is_lease_fenced`: the SAME fence wired INTO the gateway debit
//!    path -- the active holder's gateway debits, the superseded node's gateway returns
//!    DENIED_NOT_ACTIVE_LEASE and debits 0. The gateway itself fences the money path.

use std::sync::Arc;

use kirby_custody::cosign_net::NostrEvent;
use kirby_node::gateway::{GatewayService, Session};
use kirby_node::lease::{FenceVerdict, LeaseAuthority, LeaseNodeId};
use kirby_node::quorum_signer::{local_quorum_from_keyset, QuorumSigner};
use kirby_node::rail::{MockRail, Rail};
use kirby_node::relay_lease::RelayLeaseAuthority;
use kirby_node::treasury::{DebitOutcome, Treasury};
use kirby_proto::{capability_request::Act, CapabilityRequest, Outcome, SettleEcash};

/// The single-agent (DEFAULT) slot the spike fences on.
const AGENT: &str = "";

/// A fresh real 2-of-3 trusted-dealer quorum (the agent's FROST group key Q). Failover
/// transfers the keystore WITH the agent, so each node's authority holds the SAME Q.
fn quorum() -> Arc<QuorumSigner> {
    let ks = kirby_custody::generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
    Arc::new(local_quorum_from_keyset(&ks).expect("build co-located quorum signer"))
}

/// Build a node `id`'s authority holding the agent's quorum `q` (so it can claim + observe).
fn node(id: LeaseNodeId, q: Arc<QuorumSigner>) -> RelayLeaseAuthority {
    RelayLeaseAuthority::single_agent(id, AGENT, q)
}

/// Broadcast `event` to every node (the relay delivers each claim to all observers).
async fn broadcast(event: &NostrEvent, nodes: &[&RelayLeaseAuthority]) {
    for n in nodes {
        n.observe(event).await;
    }
}

/// The per-agent linearizability witness: the set of node ids that EACH believe they are
/// active for the agent right now. The G8 assertion is that this set NEVER exceeds size 1.
async fn observe_active(nodes: &[(LeaseNodeId, &RelayLeaseAuthority)]) -> Vec<LeaseNodeId> {
    let mut active = Vec::new();
    for (id, a) in nodes {
        if a.active_term_for(AGENT).await.is_some() {
            active.push(*id);
        }
    }
    active
}

/// A lease-gated treasury debit (the money-path the lease gates, G8): debit only if the
/// fence says this node holds the lease at a current-enough term. A fenced node returns `None`
/// and the treasury is untouched.
async fn debit_if_active(
    authority: &RelayLeaseAuthority,
    believed_term: u64,
    treasury: &Treasury,
    amount: u64,
) -> Option<DebitOutcome> {
    match authority.fence_for(AGENT, believed_term).await {
        FenceVerdict::Active { .. } => Some(treasury.debit_metered(amount).expect("debit shared treasury")),
        FenceVerdict::Fenced { .. } => None,
    }
}

/// G8 (relay-lease, no image): node A claims the lease @ T=1 and is the active node; a follower
/// is fenced and debits nothing; node B claims @ T+1=2 (the failover supersede); the old holder
/// A is fenced (no double-burn); the treasury is debited by at-most-one-node per term; and no
/// observed instant shows two actives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g8_lease_no_split_brain_relay() {
    // The ONE shared persisted treasury (D-9): the active node debits THIS store, and a
    // handed-off node continues the SAME balance. A fenced node never reaches it.
    let treasury = Treasury::open_temporary(1_000_000).expect("open shared treasury");
    let start_balance = treasury.remaining().unwrap();

    let q = quorum();
    let node_a = node(1, q.clone());
    let node_b = node(2, q.clone()); // failover transfers the keystore -> B holds the SAME Q.
    let node_c = node(3, q.clone()); // a follower (never claims).
    let all = [(1u64, &node_a), (2, &node_b), (3, &node_c)];

    // ---- A CLAIMS the lease @ T=1: it is the active node, the genome's birthplace. ----
    let lease1 = node_a.claim(AGENT, 1).await.expect("A signs term-1 lease");
    broadcast(&lease1, &[&node_a, &node_b, &node_c]).await;
    let term_t = 1u64;

    assert!(observe_active(&all).await.len() <= 1, "at most one active after the claim");
    assert_eq!(node_a.active_term_for(AGENT).await, Some(term_t), "A active @ T");
    assert_eq!(node_b.active_term_for(AGENT).await, None, "B not active under A's lease");

    // A debits the shared treasury through the fence (it is active @ T).
    let d1 = debit_if_active(&node_a, term_t, &treasury, 100).await;
    assert!(matches!(d1, Some(DebitOutcome::Debited { .. })), "the active node debits @ T");
    let balance_after_active = treasury.remaining().unwrap();
    assert_eq!(balance_after_active, start_balance - 100, "exactly one debit of 100");

    // A follower (node 3) attempting a debit at the old term is FENCED (it never held the
    // lease) -> the treasury is untouched.
    let d_follower = debit_if_active(&node_c, term_t, &treasury, 999_999).await;
    assert!(d_follower.is_none(), "a non-active follower is fenced");
    assert_eq!(treasury.remaining().unwrap(), balance_after_active, "a fenced follower debited nothing");

    // ---- FAILOVER: B CLAIMS @ T+1=2 (latest-term-wins supersedes A). ----
    let lease2 = node_b.claim(AGENT, 2).await.expect("B signs term-2 lease");
    broadcast(&lease2, &[&node_a, &node_b, &node_c]).await;
    let term_t1 = 2u64;
    assert!(term_t1 > term_t, "the failover claims a strictly higher term");

    assert!(observe_active(&all).await.len() <= 1, "at most one active across the boundary");
    assert_eq!(node_b.active_term_for(AGENT).await, Some(term_t1), "B active @ T+1");

    // The new active node debits the SAME shared treasury (D-9 continuation).
    let d2 = debit_if_active(&node_b, term_t1, &treasury, 50).await;
    assert!(matches!(d2, Some(DebitOutcome::Debited { .. })), "the new active node debits @ T+1");
    let balance_after_handoff = treasury.remaining().unwrap();
    assert_eq!(balance_after_handoff, balance_after_active - 50, "the handoff continues the same counter");

    // ---- The OLD holder A, still believing term T, is now FENCED (no double-burn). ----
    match node_a.fence_for(AGENT, term_t).await {
        FenceVerdict::Fenced { committed_term, committed_holder, believed_term } => {
            assert_eq!(committed_term, term_t1);
            assert_eq!(committed_holder, 2);
            assert_eq!(believed_term, term_t);
        }
        v => panic!("A must be fenced after the term-2 supersede, got {v:?}"),
    }
    let d_stale = debit_if_active(&node_a, term_t, &treasury, 777_777).await;
    assert!(d_stale.is_none(), "the superseded node A must NOT debit (fenced; no double-burn)");
    assert_eq!(
        treasury.remaining().unwrap(),
        balance_after_handoff,
        "the treasury is UNCHANGED by the fenced old holder (at-most-one-node-debits, no double-burn)"
    );

    // ---- The money-path invariant: total debited = the active debits (100 + 50), never the
    // fenced attempts (999_999 + 777_777). No double-count. ----
    let total_debited = start_balance - treasury.remaining().unwrap();
    assert_eq!(
        total_debited, 150,
        "the treasury was debited by at-most-one-node (100 @ T + 50 @ T+1 = 150); the fenced \
         follower and the superseded holder debited NOTHING (no double-burn)"
    );
}

/// G8 (the money-path binding, IN-BAND, no image): the relay-lease fence wired INTO the gateway
/// debit path. Two gateways share ONE treasury: the ACTIVE node's gateway (it holds the latest
/// lease at its term) debits a `RequestCapability`; the SUPERSEDED node's gateway (active at the
/// OLD term T, but the lease has moved to T+1) returns `DENIED_NOT_ACTIVE_LEASE` and debits 0.
/// This proves the no-double-burn invariant is enforced by the GATEWAY itself: at most one node
/// (the latest lease-holder) ever debits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g8_gateway_debit_path_is_lease_fenced() {
    // The ONE shared treasury (D-9). Both gateways point at it; only the active one may move it.
    let treasury = Treasury::open_temporary(1_000_000).expect("shared treasury");
    let start = treasury.remaining().unwrap();

    let q = quorum();
    let node_a = node(1, q.clone());
    let node_b = node(2, q.clone());

    // A claims the lease @ T=1 and both observe it.
    let lease1 = node_a.claim(AGENT, 1).await.expect("A claims term 1");
    node_a.observe(&lease1).await;
    node_b.observe(&lease1).await;
    let term_t = 1u64;

    let session = Session {
        task_descriptor: "g8-gateway-fence".to_string(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec!["mint.test.local".to_string()],
        allowlisted_inbound_kinds: Vec::new(),
    };
    let rail: Arc<dyn Rail> = Arc::new(MockRail::new());

    // The ACTIVE node's gateway: lease-fenced at term T. NOTE: the authority is moved into the
    // gateway, so rebuild a sibling authority for A from the SAME Q for any later reads.
    let active_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence(node_a, term_t);

    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "g8-active-act".to_string(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: "mint.test.local".to_string(),
            amount: 100,
            recipient_or_quote: "q".to_string(),
        })),
        budget_sats: 100,
    };
    let receipt = active_gateway.authorize_capability(&req).await.expect("authorize on active node");
    assert_eq!(
        receipt.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "the ACTIVE lease-holder's gateway must authorize + perform the debit (it holds the lease @ T)"
    );
    assert_eq!(receipt.cost_sats, 100, "the active node debited the act cost");
    let after_active = treasury.remaining().unwrap();
    assert_eq!(after_active, start - 100, "the active node's debit moved the shared treasury");

    // ---- FAILOVER: B claims @ T+1=2. The original node A's gateway is now STALE (it was
    // active at T; the latest lease is {B, T+1}). A's gateway (still fenced at T) must DENY. ----
    let lease2 = node_b.claim(AGENT, 2).await.expect("B claims term 2");
    node_b.observe(&lease2).await; // B folds in its own claim so it reads itself active.
    // The stale node's authority observes the superseding lease (the relay delivered it). We
    // built A's authority INTO active_gateway, so model the stale gateway with a fresh authority
    // for A that has observed both leases (the same node id, same Q, caught up off the relay).
    let stale_a = node(1, q.clone());
    stale_a.observe(&lease1).await;
    stale_a.observe(&lease2).await;
    assert!(
        matches!(stale_a.fence_for(AGENT, term_t).await, FenceVerdict::Fenced { committed_term: 2, .. }),
        "A is fenced by the higher term T+1"
    );

    let stale_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence(stale_a, term_t);
    let stale_req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "g8-stale-act".to_string(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: "mint.test.local".to_string(),
            amount: 500_000,
            recipient_or_quote: "q".to_string(),
        })),
        budget_sats: 500_000,
    };
    let stale_receipt = stale_gateway.authorize_capability(&stale_req).await.expect("authorize on stale node");
    assert_eq!(
        stale_receipt.outcome,
        Outcome::DeniedNotActiveLease as i32,
        "the STALE node's gateway must DENY_NOT_ACTIVE_LEASE (it no longer holds the latest term)"
    );
    assert_eq!(stale_receipt.cost_sats, 0, "a fenced debit costs 0 (no double-burn)");
    assert_eq!(
        treasury.remaining().unwrap(),
        after_active,
        "the shared treasury is UNCHANGED by the fenced node (at-most-one-node-debits)"
    );

    // Sanity: the new active node B (holding T+1) is genuinely active.
    assert_eq!(node_b.active_term_for(AGENT).await, Some(2), "B active @ T+1");
}
