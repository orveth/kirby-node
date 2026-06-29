//! Fleet-host S1 gates (non-gated, relay-lease + the live gateway fence):
//!
//!  - G-LEASE-ISOLATION: claiming `{A, node1}` does NOT touch agent B's lease, and two agents'
//!    leases advance independently. TEETH: a claim for A that mutated B would change B's
//!    observed entry (asserted unchanged); the per-agent active-holder set is size <= 1 for
//!    EACH agent (the per-agent two_actives invariant, mirroring the global G8 witness).
//!
//!  - G-FENCE-LIVE: a gateway whose tenant agent does NOT hold its lease debits 0 / returns
//!    DENIED_NOT_ACTIVE_LEASE. TEETH (the regression against the zero-caller state): the SAME
//!    request on an UNFENCED gateway is NOT denied-for-lease, proving the per-agent fence attach
//!    is load-bearing, not dead; and the fence is keyed to the TENANT's agent, so holding agent
//!    B's lease does not authorize an agent-A gateway.
//!
//! The mechanism is now the relay-native FROST-signed lease (the loopback Raft cluster was
//! CUT); the per-agent INVARIANTS are unchanged. Both run WITHOUT the genome image.

use std::collections::HashMap;
use std::sync::Arc;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::lease::{LeaseAuthority, LeaseNodeId};
use kirby_node::quorum_signer::{local_quorum_from_keyset, QuorumSigner};
use kirby_node::rail::{MockRail, Rail};
use kirby_node::relay_lease::RelayLeaseAuthority;
use kirby_node::treasury::Treasury;
use kirby_proto::{capability_request::Act, CapabilityRequest, Outcome, SettleEcash};

/// A fresh real 2-of-3 trusted-dealer quorum (an agent's FROST group key Q). Distinct agents
/// get DISTINCT quorums (a node cannot forge one agent's lease under another's Q).
fn quorum() -> Arc<QuorumSigner> {
    let ks = kirby_custody::generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
    Arc::new(local_quorum_from_keyset(&ks).expect("build co-located quorum signer"))
}

/// A node-`id` holder authority for one agent, holding that agent's quorum `q`.
fn holder(id: LeaseNodeId, agent: &str, q: Arc<QuorumSigner>) -> RelayLeaseAuthority {
    RelayLeaseAuthority::single_agent(id, agent, q)
}

/// G-LEASE-ISOLATION: claiming agent A's lease leaves agent B's lease untouched, and the two
/// agents' leases advance independently. A multi-agent observer holds each agent's distinct Q;
/// observing A's lease never produces a lease for B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g_lease_isolation_two_agents_advance_independently() {
    let qa = quorum();
    let qb = quorum();

    // A node-1 holder for each agent (it holds both quorums; failover transfers the keystore).
    let a_holder1 = holder(1, "agent-a", qa.clone());
    let a_holder2 = holder(2, "agent-a", qa.clone()); // node 2 also holds A's quorum (failover).
    let b_holder1 = holder(1, "agent-b", qb.clone());

    // An OBSERVER node that knows BOTH agents' Qs (the per-agent linearizability witness reads
    // through it). It holds no signer of its own.
    let mut expected = HashMap::new();
    expected.insert("agent-a".to_string(), qa.q_bytes());
    expected.insert("agent-b".to_string(), qb.q_bytes());
    let observer = RelayLeaseAuthority::new(9, None, expected);

    // Claim ONLY agent-A @ term 1; broadcast to the observer.
    let a_lease1 = a_holder1.claim("agent-a", 1).await.expect("claim A");
    observer.observe(&a_lease1).await;
    a_holder1.observe(&a_lease1).await;

    // Agent-B has no lease yet (A's claim did not create or touch B).
    assert!(
        observer.active_lease_for("agent-b").await.is_none(),
        "claiming agent A created/touched agent B's lease (isolation violated)"
    );
    let a_lease = observer.active_lease_for("agent-a").await.expect("A's lease is observed");
    assert_eq!(a_lease.node_id, 1);
    assert_eq!(a_lease.term, 1);

    // Now claim agent-B @ term 1. A's observed lease must be byte-identical afterward.
    let b_lease1 = b_holder1.claim("agent-b", 1).await.expect("claim B");
    observer.observe(&b_lease1).await;
    let a_after_b = observer.active_lease_for("agent-a").await.unwrap();
    assert_eq!(a_after_b, a_lease, "claiming B mutated A's observed lease (isolation violated)");
    let b_before = observer.active_lease_for("agent-b").await;

    // Per-agent linearizability witness: for EACH agent, at most one node is active.
    // (The observer holds no signer, so it is never itself "active"; the witness is the
    // observed holder being unique per agent.)
    assert_eq!(observer.active_lease_for("agent-a").await.map(|l| l.node_id), Some(1));
    assert_eq!(observer.active_lease_for("agent-b").await.map(|l| l.node_id), Some(1));

    // The two agents advance independently: failover A to node 2 @ term 2. B's entry stays put.
    let a_lease2 = a_holder2.claim("agent-a", 2).await.expect("re-claim A at T+1");
    observer.observe(&a_lease2).await;
    assert!(a_lease2_term(&a_lease2) > a_lease.term, "A's lease advanced to a higher term");
    let a_now = observer.active_lease_for("agent-a").await.unwrap();
    assert_eq!(a_now.node_id, 2, "A's lease moved to node 2 on failover");
    assert_eq!(a_now.term, 2);

    // B's observed lease is unchanged by A's failover.
    assert_eq!(
        observer.active_lease_for("agent-b").await,
        b_before,
        "A's failover advanced agent B's lease (isolation violated)"
    );
}

/// Read a claimed lease event's term (from its signed content).
fn a_lease2_term(event: &kirby_custody::cosign_net::NostrEvent) -> u64 {
    let v: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    v["term"].as_u64().unwrap()
}

/// G-FENCE-LIVE: a per-agent fenced gateway whose tenant agent does NOT hold its lease returns
/// DENIED_NOT_ACTIVE_LEASE and debits 0; the SAME request on an UNFENCED gateway is NOT
/// denied-for-lease (the regression against the zero-caller state); and the fence is keyed to
/// the tenant's OWN agent (holding agent B's lease does not authorize an agent-A gateway).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g_fence_live_per_agent_fenced_gateway_denies_and_debits_zero() {
    let treasury = Treasury::open_temporary(1_000_000).expect("treasury");
    let start = treasury.remaining().unwrap();

    let qb = quorum();
    // The node holds agent-B's lease (claimed @ term 1), but NOT agent-A's. We build TWO
    // authorities for the node (one per agent fence) -- a real multi-agent node would hold one
    // authority observing both, but the gateway fence is keyed per-agent, so separate
    // single-agent authorities model the same per-agent isolation cleanly.
    let b_holder = holder(1, "agent-b", qb.clone());
    let b_lease = b_holder.claim("agent-b", 1).await.expect("claim B");
    b_holder.observe(&b_lease).await;
    let term_b = 1u64;

    let session = Session {
        task_descriptor: "g-fence-live".to_string(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec!["mint.test.local".to_string()],
        allowlisted_inbound_kinds: Vec::new(),
    };
    let rail: Arc<dyn Rail> = Arc::new(MockRail::new());

    let req = |key: &str| CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.to_string(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: "mint.test.local".to_string(),
            amount: 100,
            recipient_or_quote: "q".to_string(),
        })),
        budget_sats: 100,
    };

    // (1) A gateway for TENANT agent-A, fenced on agent-A, on a node that holds NO agent-A
    // lease (an observer that knows A's Q but has observed no A lease). STEP 0 fences:
    // DENIED_NOT_ACTIVE_LEASE, debit 0.
    let qa = quorum();
    let mut a_expected = HashMap::new();
    a_expected.insert("agent-a".to_string(), qa.q_bytes());
    let a_authority = RelayLeaseAuthority::new(1, None, a_expected);
    let agent_a_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence_for(a_authority, "agent-a".to_string(), term_b);
    let r_a = agent_a_gateway.authorize_capability(&req("a-act")).await.expect("authorize A");
    assert_eq!(
        r_a.outcome,
        Outcome::DeniedNotActiveLease as i32,
        "an agent-A gateway on a node holding no agent-A lease must DENY_NOT_ACTIVE_LEASE"
    );
    assert_eq!(r_a.cost_sats, 0, "a fenced debit costs 0");
    assert_eq!(treasury.remaining().unwrap(), start, "the fenced tenant must not move the treasury");

    // (2) TEETH / regression against the zero-caller state: the SAME request on an UNFENCED
    // gateway (no fence attached, exactly the pre-S1 production state) is NOT denied-for-lease.
    let unfenced_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone());
    let r_unfenced = unfenced_gateway.authorize_capability(&req("unfenced-act")).await.expect("authorize unfenced");
    assert_ne!(
        r_unfenced.outcome,
        Outcome::DeniedNotActiveLease as i32,
        "an UNFENCED gateway must NOT deny-for-lease (proves the fence in (1) is wired, not dead)"
    );
    assert_eq!(
        r_unfenced.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "the unfenced gateway performs the act (the act itself is valid)"
    );

    // (3) The fence is keyed to the TENANT's agent: a gateway for tenant agent-B, fenced on
    // agent-B, on the node that DOES hold agent-B's lease at term_b, is AUTHORIZED. So the deny
    // in (1) was specifically because A's lease was not held, not a blanket refusal.
    let agent_b_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence_for(b_holder, "agent-b".to_string(), term_b);
    let r_b = agent_b_gateway.authorize_capability(&req("b-act")).await.expect("authorize B");
    assert_eq!(
        r_b.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "an agent-B gateway on the node holding agent-B's lease at the started term must authorize"
    );
    assert_eq!(r_b.cost_sats, 100, "the active tenant debited the act cost");
}

/// G-4 FAILOVER BUG 2 (ghost accumulation): a claimed lease carries a NIP-40 `expiration` tag set
/// to `issued_at + LEASE_EXPIRATION_TTL_MULTIPLE * LEASE_TTL_SECS`, so a NIP-40-aware relay drops a
/// dead agent's last lease instead of retaining it forever as a takeover-candidate ghost. TEETH:
/// the tag is present; its value is exactly the documented multiple past the SIGNED `issued_at`;
/// it outlasts the staleness TTL (a live agent surviving a few missed heartbeats is never dropped);
/// and the claim STILL self-verifies under Q — `claim()` re-derives + verifies the NIP-01 id before
/// returning, so an `Ok` here proves the added expiration tag did not break the FROST signature.
#[tokio::test]
async fn claimed_lease_carries_nip40_expiration_tag() {
    use kirby_node::relay_lease::{LEASE_EXPIRATION_TTL_MULTIPLE, LEASE_TTL_SECS};

    let q = quorum();
    let h = holder(1, "agent-exp", q);
    // claim() FROST-signs the lease AND re-verifies it under Q before returning, so this Ok proves
    // the expiration tag is part of the signed NIP-01 id and the event still verifies.
    let lease = h.claim("agent-exp", 1).await.expect("claim a lease (self-verifies under Q)");

    let issued_at = {
        let v: serde_json::Value = serde_json::from_str(&lease.content).expect("lease content JSON");
        v["issued_at"].as_u64().expect("signed issued_at")
    };
    let expiration = lease
        .tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some("expiration"))
        .and_then(|t| t.get(1))
        .expect("the claimed lease must carry a NIP-40 expiration tag")
        .parse::<u64>()
        .expect("expiration is a unix-seconds integer");
    assert_eq!(
        expiration,
        issued_at + LEASE_EXPIRATION_TTL_MULTIPLE * LEASE_TTL_SECS,
        "expiration must be issued_at + MULTIPLE*TTL (a live heartbeat keeps it fresh; a dead lease expires)"
    );
    assert!(
        expiration > issued_at + LEASE_TTL_SECS,
        "expiration must outlast the staleness TTL so a live agent's lease is never relay-dropped"
    );
}

// G-FENCE-LIVE note (#9): the fence is the relay-native latest-term-wins check. A node is
// active for an agent iff it holds that agent's latest non-stale lease; a node that never
// claimed the agent's lease (or whose term was superseded, or whose lease went stale) is
// FENCED and cannot pass the live debit gate. The partitioned-alive old-holder case is OUT of
// the crash-only MVP scope (build-spec section 5); §5's relay-unreachable -> stand-down (a
// stale lease ages out -> Fenced) is the cheap partition fail-safe, covered in relay_lease.rs.
