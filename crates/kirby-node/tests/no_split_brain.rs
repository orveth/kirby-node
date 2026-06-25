//! C-9 test (gate G8): the openraft lease + no-split-brain (spec 3.5, 4.3, D-4,
//! D-14, D-17, red-team gate 1). The consensus keystone: an embedded 3-node Raft
//! grants `active_lease { node, term }`; ONLY the node that is BOTH the Raft leader
//! AND holds the lease at the current committed term runs the genome and debits the
//! treasury; a revived stale node is term-fenced and refuses.
//!
//! This file has TWO layers:
//!  - `g8_lease_no_split_brain_pure_raft`: the PURE-RAFT lease/fence mechanics on a
//!    real 3-node loopback cluster, WITHOUT the genome image (fast, always runs). It
//!    proves bring-up + election, the committed lease, survive-one-loss (kill the
//!    active node, the 2-of-3 majority elects a new leader and commits the lease at
//!    T+1), the term-fence (the revived stale node refuses), at-most-one-node-debits
//!    (the money-path invariant simulated against ONE shared treasury gated by the
//!    fence), and the linearizability witness (never two actives per committed term).
//!  - `g8_handoff_restores_the_vm`: the FULL handoff where the new active node
//!    RESTORES the killed node's genome snapshot (the C-7 path) and continues. This
//!    needs the genome image, so it SKIPS cleanly (green) when `KIRBY_GENOME_IMAGE`
//!    is unset.

use std::sync::Arc;
use std::time::Duration;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::raft_lease::{
    bring_up_cluster, observe_active_nodes, FenceVerdict, LeaseHandle, LeaseNodeId,
};
use kirby_node::rail::{MockRail, Rail};
use kirby_node::treasury::{DebitOutcome, Treasury};
use kirby_proto::{capability_request::Act, CapabilityRequest, Outcome, SettleEcash};

/// The three spike node ids (D-14: a true 2-of-3 majority survives losing one).
const NODE_IDS: [LeaseNodeId; 3] = [1, 2, 3];

/// Find the node in `nodes` with the given id (the harness drives nodes by id, since
/// a kill consumes one and shifts the vector).
fn handle_for(handles: &[LeaseHandle], id: LeaseNodeId) -> &LeaseHandle {
    handles.iter().find(|h| h.id() == id).expect("handle for node id")
}

/// Poll until exactly one node reports itself active (leader AND committed-lease
/// holder), returning its id, or panic after the deadline. Used after a grant to
/// wait for the lease to settle. ALSO asserts the linearizability witness on every
/// poll: at no observed instant do TWO nodes report active.
async fn await_single_active(handles: &[LeaseHandle], timeout: Duration) -> LeaseNodeId {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let active = observe_active_nodes(handles).await;
        assert!(
            active.len() <= 1,
            "LINEARIZABILITY VIOLATED: two nodes both report active at once: {active:?}"
        );
        if active.len() == 1 {
            return *active.iter().next().unwrap();
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("no single active node settled within the timeout (active set: {active:?})");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The active node debits the SHARED treasury through the fence (the money-path the
/// lease gates): it checks "do I hold the lease at the current term?" and only then
/// debits. Returns the debit outcome, or `None` if it was FENCED (refused before any
/// debit). This is the spike-scale shape of "the lease gates the debit": a fenced
/// node returns None and the treasury is untouched.
async fn debit_if_active(
    handle: &LeaseHandle,
    believed_term: u64,
    treasury: &Treasury,
    amount: u64,
) -> Option<DebitOutcome> {
    match handle.fence(believed_term).await {
        FenceVerdict::Active { .. } => Some(
            treasury
                .debit_metered(amount)
                .expect("debit on the shared treasury"),
        ),
        FenceVerdict::Fenced { .. } => None,
    }
}

/// G8 (pure-Raft, no image): bring up a 3-node lease cluster, elect a leader, grant
/// the lease, kill the active node, assert the majority commits the lease at T+1
/// (survive-one-loss), revive the stale node and assert it is fenced, and assert the
/// money-path + linearizability invariants. This runs WITHOUT the genome image.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g8_lease_no_split_brain_pure_raft() {
    // The ONE shared persisted treasury (D-9): the active node debits THIS store, and
    // a resumed/handed-off node continues the SAME balance. A fenced node never
    // reaches it. The money-path invariant is asserted against this single counter.
    let treasury_dir = std::env::temp_dir().join(format!("kirby-g8-treasury-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&treasury_dir);
    let treasury = Treasury::open(&treasury_dir, 1_000_000).expect("open shared treasury");
    let start_balance = treasury.remaining().unwrap();

    // ---- BRING UP the 3-node cluster (D-14) ----
    let bring_up = bring_up_cluster(&NODE_IDS).await.expect("bring up 3-node lease cluster");
    let leader = bring_up.leader;
    let mut nodes = bring_up.nodes;
    let handles: Vec<LeaseHandle> = nodes.iter().map(|n| n.handle()).collect();
    eprintln!("G8: 3-node lease cluster up; elected leader = node {leader}");
    assert!(NODE_IDS.contains(&leader), "the elected leader must be one of the cluster nodes");

    // ---- GRANT the lease to the leader: it becomes the active node @ term T ----
    // Only the leader can grant (a committed Raft write). The active node is the
    // leader that holds the lease at the current term.
    let granted = {
        let leader_node = nodes.iter().find(|n| n.id() == leader).expect("leader node");
        leader_node.grant_lease(leader).await.expect("grant the lease to the leader")
    };
    let term_t = granted.term;
    eprintln!("G8: lease granted -> active_lease{{node={}, term={}}} (committed)", granted.node_id, term_t);
    assert_eq!(granted.node_id, leader, "the lease must be granted to the leader (the active node)");

    // The active node settles to exactly one: the leader. (Asserts no-two-actives.)
    let active = await_single_active(&handles, Duration::from_secs(5)).await;
    assert_eq!(active, leader, "the single active node must be the leader that holds the lease");

    // The active node debits the shared treasury through the fence (it is active @ T).
    let d1 = debit_if_active(handle_for(&handles, leader), term_t, &treasury, 100).await;
    assert!(
        matches!(d1, Some(DebitOutcome::Debited { .. })),
        "the active node must debit the treasury (it holds the lease @ T)"
    );
    let balance_after_active_debit = treasury.remaining().unwrap();
    assert_eq!(balance_after_active_debit, start_balance - 100, "exactly one debit of 100 happened");

    // A NON-active node (a follower) attempting to debit at the OLD term is fenced
    // out: it never reaches the treasury. (The money-path: only the lease-holder
    // debits.) Pick a follower id.
    let follower = NODE_IDS.iter().copied().find(|&id| id != leader).expect("a follower id");
    let d_follower = debit_if_active(handle_for(&handles, follower), term_t, &treasury, 999_999).await;
    assert!(d_follower.is_none(), "a non-active follower must be fenced (it does not hold the lease)");
    assert_eq!(treasury.remaining().unwrap(), balance_after_active_debit, "a fenced follower debited nothing");

    // ---- KILL the active node (the leader). The 2-of-3 majority must carry on. ----
    eprintln!("G8: KILLING the active node (node {leader}) -> the majority must elect a new leader and re-grant the lease");
    let killed = leader;
    // Remove and shut down the killed node (its RPC server aborts, so peers see it
    // unreachable, which triggers the election).
    let killed_node = {
        let idx = nodes.iter().position(|n| n.id() == killed).expect("killed node index");
        nodes.remove(idx)
    };
    killed_node.shutdown().await;
    // The killed node's handle stays in `handles` (a revived stale node still has its
    // old beliefs); it now reads is_leader=false (its engine is shut), so it cannot be
    // active. That models the kill: it is not active while down.

    // The surviving two nodes elect a new leader (survive-one-loss, D-14). Wait on a
    // survivor's metrics.
    let survivor_ids: Vec<LeaseNodeId> = NODE_IDS.iter().copied().filter(|&id| id != killed).collect();
    let new_leader = {
        let survivor = nodes.iter().find(|n| survivor_ids.contains(&n.id())).expect("a survivor node");
        // Wait for a leader IN the survivor set: a follower's metrics still cache the
        // dead leader id until the new election commits, so filter to a live survivor.
        survivor
            .wait_for_leader_in(Some(&survivor_ids), Duration::from_secs(10))
            .await
            .expect("the 2-of-3 majority must elect a new leader after the kill (survive-one-loss)")
    };
    eprintln!("G8: survive-one-loss: the majority elected a new leader = node {new_leader}");
    assert!(survivor_ids.contains(&new_leader), "the new leader must be one of the survivors");
    assert_ne!(new_leader, killed, "the new leader must not be the killed node");

    // ---- The new active node GRANTS itself the lease at the NEW term (T+1 or more) ----
    // The handoff is a committed Raft write at a strictly higher term. This is the
    // fenced handoff: the new term supersedes T.
    let regranted = {
        let new_leader_node = nodes.iter().find(|n| n.id() == new_leader).expect("new leader node");
        new_leader_node.grant_lease(new_leader).await.expect("the new leader grants itself the lease")
    };
    let term_t1 = regranted.term;
    eprintln!("G8: handoff committed -> active_lease{{node={}, term={}}} (T+1: {} > {})", regranted.node_id, term_t1, term_t1, term_t);
    assert_eq!(regranted.node_id, new_leader, "the lease must move to the new active node");
    assert!(
        term_t1 > term_t,
        "the handoff must commit the lease at a STRICTLY HIGHER term (T+1): got {term_t1}, was {term_t}"
    );

    // The single active node is now the new leader (no two actives across the boundary).
    let active2 = await_single_active(
        &handles.iter().filter(|h| h.id() != killed).cloned().collect::<Vec<_>>(),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(active2, new_leader, "the single active node after the handoff is the new leader");

    // The new active node debits the SAME shared treasury (D-9 continuation): the
    // money-path continues on the one counter, not a fresh one.
    let d2 = debit_if_active(handle_for(&handles, new_leader), term_t1, &treasury, 50).await;
    assert!(
        matches!(d2, Some(DebitOutcome::Debited { .. })),
        "the new active node must debit the SAME treasury (D-9 continuation)"
    );
    let balance_after_handoff_debit = treasury.remaining().unwrap();
    assert_eq!(
        balance_after_handoff_debit,
        balance_after_active_debit - 50,
        "the handoff debit continues the same counter (no double-store)"
    );

    // ---- REVIVE the killed node, still believing the OLD term T. It must be FENCED. ----
    // This is the core no-double-execute proof: a stale node that comes back believing
    // it is still active @ T sees the committed term T+1 (the lease moved) and REFUSES
    // to run/debit. We model the revive by restarting its engine; even if it rejoins
    // as a follower, the fence (committed term > believed term) blocks it.
    eprintln!("G8: REVIVING node {killed} still believing term {term_t} (the stale resume) -> it must be FENCED");
    let revived = kirby_node::raft_lease::LeaseNode::start(killed, "127.0.0.1:0")
        .await
        .expect("revive the killed node");
    let revived_handle = revived.handle();
    // The revived node CATCHES UP on rejoin: it learns the authoritative committed
    // lease the majority holds (in the real engine this arrives via the leader's
    // append-entries). Read it from a survivor and feed it in, so the fence sees the
    // HIGHER committed term T+1 (faithful to spec 4.3: "sees the higher committed
    // term"), not merely "no lease".
    let authoritative = handle_for(&handles, new_leader)
        .active_lease()
        .await
        .expect("the surviving majority holds the committed lease");
    assert_eq!(authoritative.term, term_t1, "the authoritative committed lease is at T+1");
    revived_handle.catch_up_committed_lease(authoritative).await;
    // The revived node believes term T; the committed term it now sees is T+1 > T.
    let stale_verdict = revived_handle.fence(term_t).await;
    eprintln!("G8: revived stale node fence verdict = {stale_verdict:?}");
    assert!(
        matches!(stale_verdict, FenceVerdict::Fenced { committed_term, .. } if committed_term == term_t1),
        "the revived stale node (believing T={term_t}) MUST be fenced by the higher committed term T+1={term_t1}: {stale_verdict:?}"
    );
    assert!(!stale_verdict.may_act(), "a fenced node must not act");

    // And it must not be able to debit: a fenced node never reaches the treasury, so no
    // SECOND VM's worth of burn is double-counted.
    let d_stale = debit_if_active(&revived_handle, term_t, &treasury, 777_777).await;
    assert!(d_stale.is_none(), "the revived stale node must NOT debit (fenced; no double-burn)");
    assert_eq!(
        treasury.remaining().unwrap(),
        balance_after_handoff_debit,
        "the treasury is UNCHANGED by the fenced stale node (at-most-one-node-debits, no double-burn)"
    );

    // ---- The money-path invariant overall: the treasury was debited by AT MOST ONE
    // node per term, and the total is exactly the active debits (100 + 50), never the
    // fenced/follower attempts (999_999 + 777_777). No double-count. ----
    let total_debited = start_balance - treasury.remaining().unwrap();
    assert_eq!(
        total_debited, 150,
        "the treasury was debited by at-most-one-node (100 @ T by the leader + 50 @ T+1 by the new leader = 150); \
         the fenced follower and the revived stale node debited NOTHING (no double-burn)"
    );

    eprintln!(
        "G8 PASS (pure-Raft): 3-node cluster; leader {leader} active @ T={term_t}; killed leader; \
         survive-one-loss -> new leader {new_leader} active @ T+1={term_t1}; revived stale node FENCED; \
         treasury debited by at-most-one-node ({total_debited} total, no double-burn); no two actives observed. \
         No split-brain proven (D-4, gate G8)."
    );

    // Tear the cluster down.
    revived.shutdown().await;
    for n in nodes {
        n.shutdown().await;
    }
    let _ = std::fs::remove_dir_all(&treasury_dir);
}

/// G8 (the full handoff restores the VM): the new active node RESTORES the killed
/// node's genome snapshot (the C-7 path) and continues. Needs the genome image, so it
/// SKIPS cleanly (green) when `KIRBY_GENOME_IMAGE` is unset. The pure-Raft test above
/// proves the lease/fence mechanics; this proves the lease DRIVES the C-7 restore so
/// the failover keeps the genome alive on the surviving majority.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g8_handoff_restores_the_vm() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP g8_handoff_restores_the_vm: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the full lease-driven VM handoff (gate G8)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);

    let outcome = kirby_node::nosplitbrain_run::run_lease_driven_handoff(
        kirby_node::nosplitbrain_run::NoSplitBrainConfig::new(image_dir),
    )
    .await
    .expect("the lease-driven handoff run completed");

    eprintln!(
        "G8 evidence (VM handoff): elected_leader={} active_term_t={} killed_node={} \
         new_leader={} handoff_term_t1={} node2_restored_running={} post_resume_round_trip={} \
         revived_stale_fenced={} treasury {} -> {} (one counter, D-9) total_debited={} \
         two_actives_ever_observed={}",
        outcome.elected_leader,
        outcome.term_t,
        outcome.killed_node,
        outcome.new_leader,
        outcome.term_t1,
        outcome.node2_restored_running,
        outcome.post_resume_round_trip,
        outcome.revived_stale_fenced,
        outcome.treasury_before,
        outcome.treasury_after,
        outcome.total_debited,
        outcome.two_actives_ever_observed,
    );

    // survive-one-loss: the majority elected a new leader, distinct from the killed one.
    assert_ne!(outcome.new_leader, outcome.killed_node, "the new leader must not be the killed node");
    assert!(outcome.term_t1 > outcome.term_t, "the handoff committed the lease at a strictly higher term (T+1)");

    // The lease DROVE the C-7 restore: node 2 brought the genome back from the snapshot
    // and it survived (the post-resume round-trip).
    assert!(outcome.node2_restored_running, "(handoff) node 2 must restore the killed node's VM to Running from the snapshot");
    assert!(outcome.post_resume_round_trip, "(handoff) the genome must survive the move (post-resume round-trip on the new active node)");

    // The revived stale node is fenced (no second VM, no double-execute).
    assert!(outcome.revived_stale_fenced, "the revived stale node must be fenced (no second VM runs)");

    // The money-path: at-most-one-node-debits; the treasury is the SAME counter (D-9).
    assert!(outcome.treasury_after <= outcome.treasury_before, "the treasury only falls (one counter, D-9)");
    assert_eq!(
        outcome.total_debited,
        outcome.treasury_before - outcome.treasury_after,
        "the total debited equals the drop on the single shared treasury (no double-store)"
    );

    // Linearizability: at NO observed term boundary did two nodes report active.
    assert!(
        !outcome.two_actives_ever_observed,
        "LINEARIZABILITY: at no committed term may two nodes be active at once"
    );

    assert!(outcome.passed(), "G8 (VM handoff) must pass: {outcome:?}");
    eprintln!(
        "G8 PASS (VM handoff): the lease drove the C-7 restore on the surviving majority; \
         the genome continued on the new active node; the revived stale node was fenced; \
         the treasury was debited by at-most-one-node on one counter; no two actives. \
         No-split-brain + lease-driven failover proven (D-4, D-14, gate G8)."
    );
}

/// G8 (the money-path binding, IN-BAND, no image): the lease fence wired INTO the
/// gateway debit path (spec 3.5, 4.3, gate G8). Two gateways share ONE treasury: the
/// ACTIVE node's gateway (it holds the committed lease at its term) debits a
/// `RequestCapability`; the FENCED node's gateway (it was active at the OLD term T,
/// but the lease has moved to T+1) returns `DENIED_NOT_ACTIVE_LEASE` and debits 0.
/// This proves the no-double-burn invariant is enforced by the GATEWAY itself, not
/// only the orchestration: at most one node (the active lease-holder) ever debits.
/// Runs WITHOUT the genome image (pure consensus + gateway logic).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g8_gateway_debit_path_is_lease_fenced() {
    // The ONE shared treasury (D-9). Both gateways point at it; only the active one
    // may move it.
    let treasury = Treasury::open_temporary(1_000_000).expect("shared treasury");
    let start = treasury.remaining().unwrap();

    // Bring up the cluster, elect a leader, and grant it the lease @ T.
    let bring_up = bring_up_cluster(&NODE_IDS).await.expect("bring up cluster");
    let leader = bring_up.leader;
    let nodes = bring_up.nodes;
    let handles: Vec<LeaseHandle> = nodes.iter().map(|n| n.handle()).collect();
    let granted = nodes
        .iter()
        .find(|n| n.id() == leader)
        .unwrap()
        .grant_lease(leader)
        .await
        .expect("grant lease to leader");
    let term_t = granted.term;
    let _ = await_single_active(&handles, Duration::from_secs(5)).await;

    let session = Session {
        task_descriptor: "g8-gateway-fence".to_string(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec!["mint.test.local".to_string()],
        allowlisted_inbound_kinds: Vec::new(),
    };
    let rail: Arc<dyn Rail> = Arc::new(MockRail::new());

    // The ACTIVE node's gateway: lease-fenced at term T (the term it is active at).
    let active_handle = handle_for(&handles, leader).clone();
    let active_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence(active_handle, term_t);

    // A capability the active node issues: a small ecash settle to the allowlisted
    // mint, within budget and treasury.
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

    // Now FENCE the situation with a REAL term advance: KILL the leader so the
    // surviving 2-of-3 majority elects a NEW leader at a STRICTLY HIGHER term T+1 and
    // grants itself the lease. (The term advances on a real election, not on a
    // re-grant through the same leader, which would stay at T.) The original leader's
    // gateway is then stale (it was active at T, the committed lease is now {new, T+1}).
    let mut nodes = nodes; // take ownership to remove the killed node
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
        .expect("the majority elects a new leader after the kill");
    let regrant = nodes
        .iter()
        .find(|n| n.id() == new_leader)
        .unwrap()
        .grant_lease(new_leader)
        .await
        .expect("the new leader grants itself the lease at T+1");
    assert!(regrant.term > term_t, "the handoff must commit the lease at a higher term (T+1)");

    // The original (killed, now revived-as-stale) leader's gateway is STALE: it was
    // active at T, but the committed lease is {new_leader, T+1}. It catches up on
    // rejoin (learns the committed T+1). A RequestCapability through its (still
    // lease-fenced-at-T) gateway must be DENIED_NOT_ACTIVE_LEASE and debit 0.
    let stale_handle = handle_for(&handles, killed).clone();
    if let Some(authoritative) = handle_for(&handles, new_leader).active_lease().await {
        stale_handle.catch_up_committed_lease(authoritative).await;
    }
    let stale_gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone())
        .with_lease_fence(stale_handle, term_t);
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
    eprintln!(
        "G8 in-band: stale node gateway outcome = {} (expected DENIED_NOT_ACTIVE_LEASE={})",
        stale_receipt.outcome,
        Outcome::DeniedNotActiveLease as i32
    );
    assert_eq!(
        stale_receipt.outcome,
        Outcome::DeniedNotActiveLease as i32,
        "the STALE node's gateway must DENY_NOT_ACTIVE_LEASE (it no longer holds the lease at the current term)"
    );
    assert_eq!(stale_receipt.cost_sats, 0, "a fenced debit costs 0 (no double-burn)");
    assert_eq!(
        treasury.remaining().unwrap(),
        after_active,
        "the shared treasury is UNCHANGED by the fenced node (at-most-one-node-debits, no double-burn)"
    );

    eprintln!(
        "G8 PASS (in-band money-path): the ACTIVE lease-holder's gateway debited (100); \
         after the handoff to T+1 the stale node's gateway returned DENIED_NOT_ACTIVE_LEASE \
         and debited 0. The gateway itself fences the debit path: at-most-one-node-debits, \
         no double-burn (D-4, gate G8)."
    );

    for n in nodes {
        n.shutdown().await;
    }
}
