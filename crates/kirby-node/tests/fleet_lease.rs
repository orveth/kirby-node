//! Fleet-host S1 gates (non-gated, pure Raft + the live gateway fence):
//!
//!  - G-LEASE-ISOLATION: granting `{A, node1}` does NOT touch agent B's lease, and two
//!    agents' leases advance independently on a real 3-node loopback cluster. TEETH: a
//!    grant for A that mutated B would change B's committed entry (asserted unchanged);
//!    the per-agent active-holder set is size <= 1 for EACH agent (the per-agent
//!    two_actives invariant, mirroring the global G8 witness).
//!
//!  - G-FENCE-LIVE: a gateway whose tenant agent does NOT hold its lease debits 0 /
//!    returns DENIED_NOT_ACTIVE_LEASE. TEETH (the regression against the zero-caller
//!    state): the SAME request on an UNFENCED gateway is NOT denied-for-lease, proving
//!    the per-agent fence attach is load-bearing, not dead; and the fence is keyed to
//!    the TENANT's agent, so holding agent B's lease does not authorize an agent-A
//!    gateway.
//!
//! Both run WITHOUT the genome image (pure Raft + the in-process gateway core).

use std::sync::Arc;
use std::time::Duration;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::raft_lease::{
    bring_up_cluster, observe_active_nodes_for, LeaseHandle, LeaseNodeId,
};
use kirby_node::rail::{MockRail, Rail};
use kirby_node::treasury::Treasury;
use kirby_proto::{capability_request::Act, CapabilityRequest, Outcome, SettleEcash};

const NODE_IDS: [LeaseNodeId; 3] = [1, 2, 3];

fn handle_for(handles: &[LeaseHandle], id: LeaseNodeId) -> &LeaseHandle {
    handles.iter().find(|h| h.id() == id).expect("handle for node id")
}

/// G-LEASE-ISOLATION: on a real 3-node cluster, granting agent A's lease to the leader
/// leaves agent B's lease untouched, and the two agents' leases advance independently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g_lease_isolation_two_agents_advance_independently() {
    let bring_up = bring_up_cluster(&NODE_IDS).await.expect("bring up 3-node cluster");
    let leader = bring_up.leader;
    let nodes = bring_up.nodes;
    let handles: Vec<LeaseHandle> = nodes.iter().map(|n| n.handle()).collect();
    let leader_node = nodes.iter().find(|n| n.id() == leader).unwrap();

    // Grant ONLY agent-A to the leader. Agent-B has no lease yet.
    let granted_a = leader_node.grant_lease_for("agent-a", leader).await.expect("grant A");
    assert_eq!(granted_a.node_id, leader);

    // Agent-B's committed lease must still be absent on every node (A's grant did not
    // create or touch B).
    for h in &handles {
        assert!(
            h.active_lease_for("agent-b").await.is_none(),
            "granting agent A created/touched agent B's lease (isolation violated)"
        );
    }
    // And A IS committed for the leader, at some term.
    let a_lease = handle_for(&handles, leader)
        .active_lease_for("agent-a")
        .await
        .expect("A's lease is committed");
    assert_eq!(a_lease.node_id, leader);

    // Now grant agent-B to the SAME leader. A's lease must be byte-identical afterward.
    let granted_b = leader_node.grant_lease_for("agent-b", leader).await.expect("grant B");
    assert_eq!(granted_b.node_id, leader);
    let a_after_b = handle_for(&handles, leader).active_lease_for("agent-a").await.unwrap();
    assert_eq!(a_after_b, a_lease, "granting B mutated A's committed lease (isolation violated)");

    // Per-agent linearizability witness: for EACH agent, at most one node is active.
    let active_a = observe_active_nodes_for(&handles, "agent-a").await;
    let active_b = observe_active_nodes_for(&handles, "agent-b").await;
    assert!(active_a.len() <= 1, "two nodes active for agent A: {active_a:?}");
    assert!(active_b.len() <= 1, "two nodes active for agent B: {active_b:?}");

    // The two agents advance independently: re-grant A at a higher term (kill the
    // leader, the majority elects a new leader, grant A to it). B's entry stays put.
    let b_before = handle_for(&handles, leader).active_lease_for("agent-b").await;
    let mut nodes = nodes;
    let killed = leader;
    let killed_node = {
        let idx = nodes.iter().position(|n| n.id() == killed).unwrap();
        nodes.remove(idx)
    };
    killed_node.shutdown().await;
    let survivors: Vec<LeaseNodeId> = NODE_IDS.iter().copied().filter(|&id| id != killed).collect();
    let new_leader = nodes
        .iter()
        .find(|n| survivors.contains(&n.id()))
        .unwrap()
        .wait_for_leader_in(Some(&survivors), Duration::from_secs(10))
        .await
        .expect("majority elects a new leader");
    let regrant_a = nodes
        .iter()
        .find(|n| n.id() == new_leader)
        .unwrap()
        .grant_lease_for("agent-a", new_leader)
        .await
        .expect("re-grant A to the new leader at T+1");
    assert!(regrant_a.term > a_lease.term, "A's lease must advance to a higher term");

    // B's committed lease (on a SURVIVOR) is unchanged by A's failover.
    let survivor_handle = handle_for(&handles, new_leader);
    if let Some(b_now) = survivor_handle.active_lease_for("agent-b").await {
        // B may have been observed via catch-up; whatever it is, it must equal what it
        // was before A's failover (A's handoff never advanced B).
        if let Some(b_before) = b_before {
            assert_eq!(b_now, b_before, "A's failover advanced agent B's lease (isolation violated)");
        }
    }

    for n in nodes {
        n.shutdown().await;
    }
}

/// G-FENCE-LIVE: a per-agent fenced gateway whose tenant agent does NOT hold its lease
/// returns DENIED_NOT_ACTIVE_LEASE and debits 0; the SAME request on an UNFENCED gateway
/// is NOT denied-for-lease (the regression against today's zero-caller state); and the
/// fence is keyed to the tenant's OWN agent (holding agent B's lease does not authorize
/// an agent-A gateway).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g_fence_live_per_agent_fenced_gateway_denies_and_debits_zero() {
    let treasury = Treasury::open_temporary(1_000_000).expect("treasury");
    let start = treasury.remaining().unwrap();

    let bring_up = bring_up_cluster(&NODE_IDS).await.expect("bring up cluster");
    let leader = bring_up.leader;
    let nodes = bring_up.nodes;
    let handles: Vec<LeaseHandle> = nodes.iter().map(|n| n.handle()).collect();
    let leader_node = nodes.iter().find(|n| n.id() == leader).unwrap();

    // The leader holds agent-B's lease, but NOT agent-A's.
    let granted_b = leader_node.grant_lease_for("agent-b", leader).await.expect("grant B");
    let term_b = granted_b.term;

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

    // (1) A gateway for TENANT agent-A, fenced on agent-A, on the node that holds only
    // agent-B's lease. The tenant does NOT hold ITS agent's lease, so STEP 0 fences:
    // DENIED_NOT_ACTIVE_LEASE, debit 0. (This is the live attach path; vm_term is the
    // term the node would have held A at, here 0 since it never did.)
    let agent_a_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence_for(handle_for(&handles, leader).clone(), "agent-a".to_string(), term_b);
    let r_a = agent_a_gateway.authorize_capability(&req("a-act")).await.expect("authorize A");
    assert_eq!(
        r_a.outcome,
        Outcome::DeniedNotActiveLease as i32,
        "an agent-A gateway on a node holding only agent-B's lease must DENY_NOT_ACTIVE_LEASE"
    );
    assert_eq!(r_a.cost_sats, 0, "a fenced debit costs 0");
    assert_eq!(treasury.remaining().unwrap(), start, "the fenced tenant must not move the treasury");

    // (2) TEETH / regression against the zero-caller state: the SAME request on an
    // UNFENCED gateway (no fence attached, exactly the pre-S1 production state) is NOT
    // denied-for-lease. If the fence were not actually wired, (1) would behave like
    // this too; the contrast proves the per-agent fence attach is load-bearing.
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

    // (3) The fence is keyed to the TENANT's agent: a gateway for tenant agent-B, fenced
    // on agent-B, on the node that DOES hold agent-B's lease at term_b, is AUTHORIZED.
    // So the deny in (1) was specifically because A's lease was not held, not a blanket
    // refusal.
    let agent_b_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence_for(handle_for(&handles, leader).clone(), "agent-b".to_string(), term_b);
    let r_b = agent_b_gateway.authorize_capability(&req("b-act")).await.expect("authorize B");
    assert_eq!(
        r_b.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "an agent-B gateway on the node holding agent-B's lease at the started term must authorize"
    );
    assert_eq!(r_b.cost_sats, 100, "the active tenant debited the act cost");

    // Sanity: agent-A's lease was never created by any of this (no cross-agent leakage).
    assert!(
        handle_for(&handles, leader).active_lease_for("agent-a").await.is_none(),
        "agent-A's lease must remain absent (no cross-agent leakage)"
    );
    for n in nodes {
        n.shutdown().await;
    }
}

// G-FENCE-LIVE leadership-gate note (Codex-S1 HIGH fix): `fence_for` was hardened to
// require leadership in addition to holder+term, mirroring `active_term_for`, so a node
// that still holds an agent's committed lease but has LOST LEADERSHIP is FENCED (it cannot
// pass the live debit gate). The ONLY way a node loses leadership while staying alive and
// still naming itself as the committed holder is a NETWORK PARTITION (openraft will not
// demote a healthy leader on demand, and a quorum-less node cannot elect a successor, so
// neither kill-the-others nor a forced election reproduces a demoted-but-alive holder
// deterministically in this harness). A partitioned-alive old leader is explicitly OUT of
// the crash-only MVP scope (see build-spec-kirby-failover-supervisor.md section 5); a full
// e2e teeth for it needs the partition-simulation harness deferred to failover S5/S6. The
// gate itself is verified by code-consistency with `active_term_for` (the established
// active-node check, which the no_split_brain g8 tests exercise as leader+holder) and by
// the no-regression of all existing lease tests after the fix.
