//! TEETH for the relay-native FROST-signed lease (#9, build-spec
//! `build-spec-kirby-failover-relay-lease-20260625.md` chunk a, gates F9-1/2/3 + per-agent
//! isolation). These are HOST-SIDE and need NO live relay: a tiny in-test mock relay
//! (addressable latest-wins store) stands in for the wire, and the load-bearing crypto
//! (FROST-sign the lease under Q, verify under Q on observe) runs in-process.
//!
//! What is proven:
//!   * F9-1 at-most-one-active: node A claims term 1 (A active); node B claims term 2
//!     (latest-wins) -> A's `fence_for(agent, 1)` is Fenced, B is active at 2.
//!   * F9-2 forge-rejection: a lease signed by a NON-agent key is REJECTED on observe (it
//!     never becomes the active lease); only a lease FROST-signed under the agent's own Q
//!     is accepted.
//!   * F9-3 stale stand-down: a lease past its TTL (or a relay that stops delivering) ->
//!     `fence_for` returns Fenced and `active_term_for` returns None.
//!   * per-agent isolation: a lease for agent X never affects agent Y's fence.

use std::collections::HashMap;
use std::sync::Arc;

use kirby_custody::cosign_net::NostrEvent;
use kirby_node::quorum_signer::{local_quorum_from_keyset, QuorumSigner};
use kirby_node::lease::{FenceVerdict, LeaseAuthority, LeaseNodeId};
use kirby_node::relay_lease::{RelayLeaseAuthority, LEASE_TTL_SECS};

/// A tiny in-test mock relay: an ADDRESSABLE event store keyed by `(pubkey, kind, d)` that
/// keeps the latest published event per key (mirroring how a Nostr relay treats an
/// addressable kind). It is NOT the wire -- it just lets a test publish a signed lease and
/// fetch it back to feed `observe`, with no network. Latest-wins on the relay is by
/// `created_at`; the term-monotonic latest-wins lives in the authority's `observe`.
#[derive(Default)]
struct MockRelay {
    events: HashMap<(String, u32, String), NostrEvent>,
}

impl MockRelay {
    fn new() -> Self {
        Self::default()
    }

    /// Publish an event (addressable replace by `(pubkey, kind, d)`).
    fn publish(&mut self, event: NostrEvent) {
        let d = event
            .tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some("d"))
            .and_then(|t| t.get(1).cloned())
            .unwrap_or_default();
        let key = (event.pubkey.clone(), event.kind, d);
        self.events.insert(key, event);
    }

    /// The current stored lease event for an agent under a given quorum pubkey, if any.
    fn latest_for(&self, pubkey: &str, kind: u32, agent_id: &str) -> Option<NostrEvent> {
        self.events
            .get(&(pubkey.to_string(), kind, agent_id.to_string()))
            .cloned()
    }
}

const LEASE_KIND: u32 = kirby_proto::KIND_KIRBY_LEASE as u32;

/// A fresh real 2-of-3 trusted-dealer keyset + its co-located quorum signer (its FROST
/// group key Q). A different keyset yields a different Q -- used for the forge test.
fn quorum() -> Arc<QuorumSigner> {
    let ks = kirby_custody::generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
    Arc::new(local_quorum_from_keyset(&ks).expect("build co-located quorum signer"))
}

/// Build an observe-only authority for `node_id` that knows `agent_id`'s expected Q (so it
/// can verify + fence) but holds NO signer of its own (it cannot claim). Mirrors a node
/// watching an agent whose shares another node holds.
fn observer(node_id: LeaseNodeId, agent_id: &str, q: [u8; 32]) -> RelayLeaseAuthority {
    let mut expected = HashMap::new();
    expected.insert(agent_id.to_string(), q);
    RelayLeaseAuthority::new(node_id, None, expected)
}

/// F9-1 AT-MOST-ONE-ACTIVE (supersede by a higher term). Node A (holds the agent's quorum)
/// claims term 1 and is active; node B claims term 2 (latest-wins). After both observe both
/// leases: A's fence for its believed term 1 is FENCED (it sees the higher term 2 by another
/// holder), and B is active at term 2. The relay-lease enforces the SAME at-most-one-active
/// invariant the loopback-Raft handle did, by monotonic-term latest-wins.
#[tokio::test]
async fn f9_1_at_most_one_active_supersede() {
    let agent = "agent-alpha";
    let q = quorum();
    let q_bytes = q.q_bytes();

    // Node 1 holds the quorum and claims term 1.
    let node_a = RelayLeaseAuthority::single_agent(1, agent, q.clone());
    // Node 2 ALSO holds the same agent's quorum (failover transfers the keystore with the
    // agent, build-spec F9-2 note) and claims term 2.
    let node_b = RelayLeaseAuthority::single_agent(2, agent, q.clone());

    let mut relay = MockRelay::new();

    // A claims term 1 and publishes.
    let lease1 = node_a.claim(agent, 1).await.expect("A signs term-1 lease");
    relay.publish(lease1.clone());
    // Both nodes observe the term-1 lease.
    assert!(node_a.observe(&lease1).await, "A observes its own term-1 lease");
    assert!(node_b.observe(&lease1).await, "B observes A's term-1 lease");

    // A is active at term 1; B is not active (lease names A).
    assert_eq!(node_a.active_term_for(agent).await, Some(1), "A active at term 1");
    assert_eq!(node_b.active_term_for(agent).await, None, "B not active under A's lease");
    assert!(node_a.fence_for(agent, 1).await.may_act(), "A may act at term 1");

    // FAILOVER: B claims term 2 and publishes (latest-wins on the relay too).
    let lease2 = node_b.claim(agent, 2).await.expect("B signs term-2 lease");
    relay.publish(lease2.clone());
    let stored = relay.latest_for(&hex::encode(q_bytes), LEASE_KIND, agent).expect("relay holds latest");
    assert_eq!(stored.id, lease2.id, "relay's addressable latest is the term-2 lease");

    // Both observe the term-2 lease.
    assert!(node_a.observe(&lease2).await, "A observes the superseding term-2 lease");
    assert!(node_b.observe(&lease2).await, "B observes its own term-2 lease");

    // A, still believing term 1, is now FENCED (a higher term by another holder superseded it).
    match node_a.fence_for(agent, 1).await {
        FenceVerdict::Fenced { committed_term, committed_holder, believed_term } => {
            assert_eq!(committed_term, 2);
            assert_eq!(committed_holder, 2);
            assert_eq!(believed_term, 1);
        }
        v => panic!("A must be fenced after the term-2 supersede, got {v:?}"),
    }
    assert!(!node_a.fence_for(agent, 1).await.may_act(), "A must NOT act after supersede");
    assert_eq!(node_a.active_term_for(agent).await, None, "A no longer active");

    // B is active at term 2.
    assert_eq!(node_b.active_term_for(agent).await, Some(2), "B active at term 2");
    assert!(node_b.fence_for(agent, 2).await.may_act(), "B may act at term 2");
}

/// F9-1 OBSERVE-ONLY-FORWARD: a stale (lower-or-equal term) lease never moves the observed
/// term backward. After observing term 2, re-observing a term-1 lease is IGNORED and the
/// active term stays 2.
#[tokio::test]
async fn f9_1_observe_only_forward_never_regresses() {
    let agent = "agent-mono";
    let q = quorum();
    let node = RelayLeaseAuthority::single_agent(1, agent, q.clone());

    let lease1 = node.claim(agent, 1).await.expect("term-1 lease");
    let lease2 = node.claim(agent, 2).await.expect("term-2 lease");

    assert!(node.observe(&lease2).await, "term 2 accepted");
    assert_eq!(node.active_term_for(agent).await, Some(2));
    // Re-observing the OLDER term-1 lease must be ignored (observe-only-forward).
    assert!(!node.observe(&lease1).await, "older term-1 lease is rejected (no regress)");
    assert_eq!(node.active_term_for(agent).await, Some(2), "term stays at 2");
    // Re-observing the SAME term is also ignored (strictly-newer wins only).
    let lease2b = node.claim(agent, 2).await.expect("another term-2 lease");
    assert!(!node.observe(&lease2b).await, "equal term is not strictly newer -> ignored");
}

/// F9-2 FORGE-REJECTION: a lease event signed by a NON-agent key (a different keypair /
/// different quorum) is REJECTED on observe -- it never becomes the active lease. Only a
/// lease FROST-signed under the agent's OWN Q is accepted. A node cannot forge a claim for
/// an agent whose shares it does not hold.
#[tokio::test]
async fn f9_2_forged_lease_is_rejected_on_observe() {
    let agent = "agent-victim";
    let real_q = quorum();
    let forger_q = quorum(); // a DIFFERENT quorum (different Q) -- the attacker's key.
    assert_ne!(real_q.q_bytes(), forger_q.q_bytes(), "the two quorums must differ");

    // An observer that knows the agent's REAL Q (it would accept only the real quorum).
    let node = observer(7, agent, real_q.q_bytes());

    // The forger signs a perfectly well-formed lease for the SAME agent_id, naming itself
    // holder at a high term -- but under its OWN Q, not the agent's.
    let forged = forger_q
        .sign_nostr_event_with_tags(
            LEASE_KIND,
            1_750_000_000,
            &[
                vec!["d".into(), agent.into()],
                vec!["t".into(), "kirby".into()],
                vec!["a".into(), agent.into()],
                vec!["node".into(), "99".into()],
            ],
            &serde_json::to_string(&serde_json::json!({
                "agent_id": agent,
                "holder_node_id": 99u64,
                "term": 99u64,
                "issued_at": 1_750_000_000u64,
            }))
            .unwrap(),
        )
        .expect("the forger CAN sign under its own Q (but it is the wrong Q)");

    // The forged lease verifies under the FORGER's Q (it is a real signature) but NOT under
    // the agent's Q -- so the agent's observer REJECTS it.
    assert!(
        !node.observe(&forged).await,
        "a lease signed by a non-agent key must be rejected on observe (F9-2)"
    );
    assert_eq!(node.active_term_for(agent).await, None, "no forged lease became active");
    assert_eq!(node.active_lease_for(agent).await, None, "no active lease at all");

    // Sanity: the SAME-shaped lease from the REAL quorum IS accepted (the only difference is
    // which Q signed it).
    let real = real_q
        .sign_nostr_event_with_tags(
            LEASE_KIND,
            1_750_000_000,
            &[
                vec!["d".into(), agent.into()],
                vec!["t".into(), "kirby".into()],
                vec!["a".into(), agent.into()],
                vec!["node".into(), "5".into()],
            ],
            &serde_json::to_string(&serde_json::json!({
                "agent_id": agent,
                "holder_node_id": 5u64,
                "term": 1u64,
                "issued_at": 1_750_000_000u64,
            }))
            .unwrap(),
        )
        .expect("the real quorum signs under the agent's Q");
    // (issued_at is far in the past, so this lease is stale by TTL -> it verifies + is
    // accepted as observed, but it does not authorize anyone; see f9_3 for the TTL gate.)
    assert!(node.observe(&real).await, "a lease under the agent's real Q is accepted on observe");
}

/// F9-2b TAMPER-REJECTION: a lease whose CONTENT was mutated after signing (so the id no
/// longer matches the signed fields) is rejected -- the id/sig recheck catches it.
#[tokio::test]
async fn f9_2b_tampered_content_is_rejected() {
    let agent = "agent-tamper";
    let q = quorum();
    let node = RelayLeaseAuthority::single_agent(1, agent, q.clone());

    let mut lease = q
        .sign_nostr_event_with_tags(
            LEASE_KIND,
            kirby_node_now(),
            &[
                vec!["d".into(), agent.into()],
                vec!["t".into(), "kirby".into()],
                vec!["a".into(), agent.into()],
                vec!["node".into(), "1".into()],
            ],
            &serde_json::to_string(&serde_json::json!({
                "agent_id": agent, "holder_node_id": 1u64, "term": 1u64, "issued_at": kirby_node_now(),
            }))
            .unwrap(),
        )
        .expect("real lease");
    // Mutate the content (bump the term) WITHOUT re-signing: the id no longer matches.
    lease.content = serde_json::to_string(&serde_json::json!({
        "agent_id": agent, "holder_node_id": 1u64, "term": 9999u64, "issued_at": kirby_node_now(),
    }))
    .unwrap();
    assert!(!node.observe(&lease).await, "a content-tampered lease must be rejected");
    assert_eq!(node.active_term_for(agent).await, None, "tampered lease never became active");
}

/// F9-3 STALE STAND-DOWN: a lease past its TTL no longer authorizes its holder. The same
/// path covers a relay that stops delivering -- the lease ages out (its `issued_at` falls
/// further behind wall-clock now) and the node stands down rather than acting on a stale
/// term. We claim a lease, observe it, confirm it is active, then claim/observe one whose
/// `issued_at` is older than the TTL and confirm the node is fenced + not active.
#[tokio::test]
async fn f9_3_stale_lease_stands_down() {
    let agent = "agent-stale";
    let q = quorum();
    let node = RelayLeaseAuthority::single_agent(1, agent, q.clone());

    // A fresh lease (issued_at = now) is active.
    let fresh = node.claim(agent, 1).await.expect("fresh lease");
    assert!(node.observe(&fresh).await);
    assert_eq!(node.active_term_for(agent).await, Some(1), "fresh lease active");
    assert!(node.fence_for(agent, 1).await.may_act(), "fresh lease may act");

    // A lease whose issued_at is well past the TTL (simulating the relay going silent: the
    // holder could not refresh, so its last lease aged out). Sign it directly with an old
    // issued_at and a NEWER term (so observe accepts it as the latest), then confirm it does
    // NOT authorize.
    let stale_issued = kirby_node_now().saturating_sub(LEASE_TTL_SECS + 5);
    let stale = q
        .sign_nostr_event_with_tags(
            LEASE_KIND,
            stale_issued,
            &[
                vec!["d".into(), agent.into()],
                vec!["t".into(), "kirby".into()],
                vec!["a".into(), agent.into()],
                vec!["node".into(), "1".into()],
            ],
            &serde_json::to_string(&serde_json::json!({
                "agent_id": agent, "holder_node_id": 1u64, "term": 2u64, "issued_at": stale_issued,
            }))
            .unwrap(),
        )
        .expect("stale lease");
    assert!(node.observe(&stale).await, "the stale lease is still a VALID signature -> observed");

    // But it does NOT authorize: stand-down (F9-3).
    assert_eq!(node.active_term_for(agent).await, None, "stale lease -> not active (stand down)");
    assert!(node.active_lease_for(agent).await.is_none(), "stale lease -> no active lease");
    match node.fence_for(agent, 2).await {
        FenceVerdict::Fenced { committed_term, committed_holder, believed_term } => {
            assert_eq!(committed_term, 2, "evidence carries the stale lease's term");
            assert_eq!(committed_holder, 1);
            assert_eq!(believed_term, 2);
        }
        v => panic!("a stale lease must fence (stand down), got {v:?}"),
    }
    assert!(!node.fence_for(agent, 2).await.may_act(), "must NOT act on a stale term");
}

/// PER-AGENT ISOLATION: a lease for agent X never affects agent Y's fence (mirrors the
/// loopback-Raft handle's per-agent semantics). A multi-agent observer holds each agent's Q
/// independently; observing X's lease leaves Y with no lease (Fenced/None for Y).
#[tokio::test]
async fn per_agent_isolation() {
    let agent_x = "agent-x";
    let agent_y = "agent-y";
    let qx = quorum();
    let qy = quorum();

    // One node observes BOTH agents (it knows each agent's distinct Q).
    let mut expected = HashMap::new();
    expected.insert(agent_x.to_string(), qx.q_bytes());
    expected.insert(agent_y.to_string(), qy.q_bytes());
    let node = RelayLeaseAuthority::new(1, None, expected);

    // A claimant node for X (holds X's quorum) claims X at term 1.
    let x_holder = RelayLeaseAuthority::single_agent(1, agent_x, qx.clone());
    let x_lease = x_holder.claim(agent_x, 1).await.expect("X term-1 lease");
    assert!(node.observe(&x_lease).await, "X's lease observed");

    // X is now active (for node 1, which is X's holder), but Y is entirely unaffected.
    assert_eq!(node.active_term_for(agent_x).await, Some(1), "X active at term 1");
    assert_eq!(node.active_lease_for(agent_y).await, None, "Y has no lease (isolated from X)");
    assert_eq!(node.active_term_for(agent_y).await, None, "Y not active (isolated)");
    match node.fence_for(agent_y, 1).await {
        FenceVerdict::Fenced { committed_term, committed_holder, .. } => {
            assert_eq!(committed_term, 0, "Y has no lease -> zero evidence");
            assert_eq!(committed_holder, 0);
        }
        v => panic!("Y must be fenced (no lease), got {v:?}"),
    }
    // And a lease for X under X's Q does NOT verify as a lease for Y (different agent_id +
    // different expected Q): feeding X's event but claiming it is Y's is impossible since
    // observe keys off the signed content's agent_id.
}

/// A node that holds NO quorum for an agent cannot CLAIM a lease (F9-2 at the source: the
/// only way to mint a valid lease is to hold the shares).
#[tokio::test]
async fn observe_only_node_cannot_claim() {
    let agent = "agent-noquorum";
    let q = quorum();
    let node = observer(1, agent, q.q_bytes());
    let res = node.claim(agent, 1).await;
    assert!(res.is_err(), "a node with no quorum must not be able to claim");
    assert!(
        format!("{}", res.unwrap_err()).contains("holds no quorum"),
        "the error should explain the missing quorum"
    );
}

/// Wall-clock now in unix seconds (the test's freshness clock; matches the module's
/// internal `now_secs`).
fn kirby_node_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
