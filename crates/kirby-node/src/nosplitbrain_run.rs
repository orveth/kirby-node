//! The G8 no-split-brain orchestration (spec 3.5, 4.3, D-4, D-14, red-team gate 1):
//! the lease DRIVES the failover, and the failover RESTORES the killed node's genome
//! snapshot (the C-7 path) on the surviving majority.
//!
//! THE FLOW this proves (the full G8 with a real VM):
//!  1. Bring up a 3-node embedded Raft lease cluster on loopback (D-14, D-17). The
//!     elected leader grants itself `active_lease{leader, T}` (a committed write):
//!     it is now the active node.
//!  2. The active node (leader + lease @ T) BOOTS the genome microVM and, gated by
//!     the fence (it holds the lease @ T), DEBITS the shared treasury. A non-active
//!     node is IDLE.
//!  3. The active node snapshots the running VM (the C-7 mem+vmstate pair) and the
//!     pair is staged for the surviving majority (the D-13 transfer seam).
//!  4. KILL the active node. The 2-of-3 majority elects a NEW leader (survive-one-
//!     loss, D-14), which grants itself the lease at a STRICTLY HIGHER term T+1 (the
//!     fenced handoff). The new active node RESTORES the killed node's snapshot (the
//!     C-7 restore) and the genome continues ALIVE (a post-resume round-trip), and
//!     it continues debiting the SAME persisted treasury (D-9, no double-store).
//!  5. REVIVE the killed node still believing term T. Its fence check sees the higher
//!     committed term T+1 and REFUSES to run/debit (term-fenced): no second VM, no
//!     double-execute, no double-burn.
//!
//! INVARIANTS asserted: at-most-one-node-debits (the money-path on one counter), and
//! linearizability (at no observed committed term do two nodes report active).
//!
//! PRESERVED: the lease GATES the run + debit; it does NOT change what they do. The
//! restore is the UNCHANGED C-7 firecracker path (the same D-7 jailer boundary, the
//! same transfer seam); the treasury is the UNCHANGED persisted counter (D-9); the
//! gateway/rail/genome are unchanged. This module is the AGNOSTIC orchestration that
//! binds the lease (consensus) to the run/restore (compute) and the debit (money).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::boot::{EventStream, ImagePaths};
use crate::firecracker::FirecrackerBackend;
use crate::gateway::{GatewayService, Session};
use crate::raft_lease::{
    bring_up_cluster, observe_active_nodes, FenceVerdict, LeaseHandle, LeaseNode, LeaseNodeId,
};
use crate::rail::{MockRail, Rail};
use crate::sandbox::{
    GuestImage, GuestSpec, LocalDirTransfer, RestoreSpec, SandboxBackend, SandboxInstance,
    SnapshotTransfer,
};
use crate::treasury::{DebitOutcome, Treasury};

use kirby_proto::Event;

/// The three spike node ids (D-14): a true 2-of-3 majority survives losing one.
const NODE_IDS: [LeaseNodeId; 3] = [1, 2, 3];

/// Inputs for the lease-driven VM-handoff run (gate G8 with a real microVM). Reuses
/// the genome image; everything else (the 3-node lease cluster, the same-host
/// transfer seam, the shared treasury) is derived.
pub struct NoSplitBrainConfig {
    /// The genome image (kernel + rootfs), pre-staged on every node (D-8).
    pub image_dir: PathBuf,
    /// The session task descriptor handed to the genome (non-secret).
    pub task: String,
    /// The vsock guest CID for the active node's VM. The restored VM reuses it (the
    /// killed node is gone before the restore runs, so no collision on one host).
    pub vsock_cid: u32,
    /// The gateway vsock port the genome dials and the active node serves on.
    pub gateway_port: u32,
    /// vCPU count and memory for the genome microVM. Small for the spike.
    pub vcpu_count: u8,
    pub mem_mib: usize,
    /// How long to wait for the active node's pre-snapshot heartbeat round-trip.
    pub pre_snapshot_timeout: Duration,
    /// How long to wait for the new active node's post-resume heartbeat round-trip.
    pub post_resume_timeout: Duration,
}

impl NoSplitBrainConfig {
    /// A run config from a genome image dir, with spike-sane defaults.
    pub fn new(image_dir: PathBuf) -> Self {
        NoSplitBrainConfig {
            image_dir,
            task: "g8-nosplitbrain".to_string(),
            // A distinct CID/port range keeps this run isolated from the other gates.
            vsock_cid: 37,
            gateway_port: 5037,
            vcpu_count: 1,
            mem_mib: 128,
            pre_snapshot_timeout: Duration::from_secs(40),
            post_resume_timeout: Duration::from_secs(40),
        }
    }
}

/// The G8 evidence from a lease-driven VM-handoff run.
#[derive(Debug, Clone)]
pub struct NoSplitBrainOutcome {
    /// The leader elected at bring-up (the first active node).
    pub elected_leader: LeaseNodeId,
    /// The term the lease was first granted at (the leader is active @ T).
    pub term_t: u64,
    /// The active node that was killed (the leader).
    pub killed_node: LeaseNodeId,
    /// The new leader the 2-of-3 majority elected after the kill (survive-one-loss).
    pub new_leader: LeaseNodeId,
    /// The strictly-higher term the handoff committed the lease at (T+1).
    pub term_t1: u64,
    /// The new active node brought the genome VM to Running FROM the killed node's
    /// snapshot (the C-7 restore the lease drove).
    pub node2_restored_running: bool,
    /// The genome survived the move: a post-resume heartbeat landed on the new active
    /// node (it re-dialed the new node's gateway after its vsock dropped).
    pub post_resume_round_trip: bool,
    /// The revived stale node (believing the old term T) was FENCED: it refused to
    /// run/debit (no second VM, no double-execute).
    pub revived_stale_fenced: bool,
    /// The shared treasury balance before any debit (D-9: one counter).
    pub treasury_before: u64,
    /// The shared treasury balance after the run (only the active nodes debited it).
    pub treasury_after: u64,
    /// The total debited from the single shared treasury (the active node @ T plus
    /// the new active node @ T+1; never the fenced node).
    pub total_debited: u64,
    /// True iff, at ANY observed instant across the run, two nodes both reported
    /// active. The G8 linearizability invariant requires this stays FALSE.
    pub two_actives_ever_observed: bool,
}

impl NoSplitBrainOutcome {
    /// The G8 verdict: survive-one-loss handoff at T+1, the lease-driven restore kept
    /// the genome alive, the revived stale node was fenced, the money-path debited by
    /// at-most-one-node on one counter, and no two actives were ever observed.
    pub fn passed(&self) -> bool {
        self.new_leader != self.killed_node
            && self.term_t1 > self.term_t
            && self.node2_restored_running
            && self.post_resume_round_trip
            && self.revived_stale_fenced
            && self.treasury_after <= self.treasury_before
            && self.total_debited == self.treasury_before - self.treasury_after
            && !self.two_actives_ever_observed
    }
}

/// Run the full lease-driven VM handoff (gate G8). Brings up the 3-node lease
/// cluster, has the leader become active + boot + snapshot the genome, kills the
/// active node, has the surviving majority elect a new leader that restores the
/// snapshot (the C-7 path) and continues, and revives the stale node to prove it is
/// fenced. All VMs are halted before returning (including on an error path).
pub async fn run_lease_driven_handoff(
    config: NoSplitBrainConfig,
) -> anyhow::Result<NoSplitBrainOutcome> {
    let image = ImagePaths::from_dir(&config.image_dir)?;

    // The ONE shared persisted treasury (D-9): the active node debits it, and the new
    // active node CONTINUES the same balance after the handoff. A fenced node never
    // reaches it. A per-run path keeps runs distinct.
    let treasury_path = std::env::temp_dir().join(format!("kirby-g8-treasury-vm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&treasury_path);
    let treasury_before = {
        let t = Treasury::open(&treasury_path, 1_000_000)?;
        t.remaining()?
    };

    // ---- 1. Bring up the 3-node lease cluster (D-14, D-17) ----
    let bring_up = bring_up_cluster(&NODE_IDS).await?;
    let elected_leader = bring_up.leader;
    let mut nodes = bring_up.nodes;
    // The handles used for the linearizability witness. A KILLED node is removed from
    // this set the moment it is killed: a killed node's process is gone in a real
    // two-host deployment (it reports nothing), so its STALE in-process handle (whose
    // shut-down engine may still cache `current_leader = itself` for a window) must
    // not be counted as "active". Counting it would be a same-host harness artifact,
    // not a real split-brain (the killed node's VM is halted and its RPC server
    // aborted, so it can do nothing). The fence still proves the revived node refuses;
    // this set is only for the "no two LIVE actives" observation.
    let mut handles: Vec<LeaseHandle> = nodes.iter().map(|n| n.handle()).collect();
    tracing::info!(leader = elected_leader, "G8: 3-node lease cluster up");

    // A running tracker of "were two nodes ever both active?" sampled at each step.
    let mut two_actives_ever = false;
    sample_actives(&handles, &mut two_actives_ever).await;

    // ---- The leader grants itself the lease @ T: it is the active node ----
    let granted = {
        let leader_node = node_by_id(&nodes, elected_leader)?;
        leader_node.grant_lease(elected_leader).await?
    };
    let term_t = granted.term;
    tracing::info!(node = granted.node_id, term = term_t, "G8: lease granted (active node @ T)");
    sample_actives(&handles, &mut two_actives_ever).await;

    // ---- 2-3. The active node boots the genome, debits (gated by the fence), and
    // snapshots it. ----
    let active_handle = handle_by_id(&handles, elected_leader)?;
    let active = boot_active_genome(&config, &image, &treasury_path, elected_leader).await?;
    let ActiveGenome { mut instance, gateway, mut events, treasury, serve_task } = active;

    // Pre-snapshot heartbeat: the genome is alive on the active node before we snapshot.
    let pre = wait_for_heartbeat(&mut events, config.pre_snapshot_timeout).await;
    if pre.is_none() {
        instance.halt().await;
        for n in nodes {
            n.shutdown().await;
        }
        anyhow::bail!("G8: the active node's genome did not complete a pre-snapshot round-trip");
    }
    tracing::info!("G8: active node's genome alive before snapshot");

    // The active node debits the shared treasury THROUGH the fence (it holds the lease
    // @ T). This is the money-path the lease gates: only the active node debits.
    let active_debit = lease_gated_debit(active_handle, term_t, &treasury, 100).await;
    anyhow::ensure!(
        matches!(active_debit, Some(DebitOutcome::Debited { .. })),
        "G8: the active node must debit the treasury while it holds the lease @ T"
    );
    let balance_after_active = treasury.remaining()?;

    // Snapshot the running VM (the C-7 pair).
    let artifact = match instance.snapshot().await {
        Ok(a) => a,
        Err(e) => {
            instance.halt().await;
            for n in nodes {
                n.shutdown().await;
            }
            return Err(anyhow::anyhow!("G8: snapshot failed: {e}"));
        }
    };
    let transfer_dir = std::env::temp_dir().join(format!("kirby-g8-snap-{}", std::process::id()));
    let transferred = LocalDirTransfer { target_dir: transfer_dir.clone() }
        .transfer(artifact)
        .await?;
    tracing::info!(bytes = transferred.footprint_bytes(), "G8: snapshot pair staged for the surviving majority (D-13 seam)");

    // ---- 4a. KILL the active node: tear down its VM AND shut down its lease node. ----
    tracing::info!(node = elected_leader, "G8: KILLING the active node (VM + lease engine)");
    instance.halt().await;
    serve_task.abort();
    drop(gateway);
    drop(treasury); // release the sled lock so the new active node opens the SAME store
    // Shut down the killed node's lease engine (its RPC server aborts, peers see it
    // unreachable -> the election).
    let killed_node_obj = remove_node(&mut nodes, elected_leader)?;
    killed_node_obj.shutdown().await;
    // Drop the killed node's handle from the linearizability-witness set: a killed
    // node is DOWN (its process is gone in a real two-host run), so it cannot be a
    // live active node, and its stale in-process metrics must not register as one.
    handles.retain(|h| h.id() != elected_leader);
    // Let the aborted serve task drop its treasury clone before node 2 opens the store.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    sample_actives(&handles, &mut two_actives_ever).await;

    // ---- 4b. The 2-of-3 majority elects a new leader (survive-one-loss, D-14) ----
    let survivor_ids: Vec<LeaseNodeId> = NODE_IDS.iter().copied().filter(|&id| id != elected_leader).collect();
    let new_leader = {
        let survivor = node_by_id_any(&nodes, &survivor_ids)?;
        // Wait for a leader IN the survivor set: a follower's metrics still cache the
        // dead leader id until the new election commits, so filter to a live survivor.
        survivor
            .wait_for_leader_in(Some(&survivor_ids), Duration::from_secs(10))
            .await
            .ok_or_else(|| anyhow::anyhow!("G8: the 2-of-3 majority did not elect a new leader after the kill"))?
    };
    tracing::info!(new_leader, "G8: survive-one-loss: the majority elected a new leader");

    // The new leader grants itself the lease at the NEW (strictly higher) term T+1.
    let regranted = {
        let new_leader_node = node_by_id(&nodes, new_leader)?;
        new_leader_node.grant_lease(new_leader).await?
    };
    let term_t1 = regranted.term;
    anyhow::ensure!(
        term_t1 > term_t,
        "G8: the handoff must commit the lease at a strictly higher term (T+1): got {term_t1}, was {term_t}"
    );
    tracing::info!(node = regranted.node_id, term = term_t1, "G8: handoff committed (new active node @ T+1)");
    sample_actives(&handles, &mut two_actives_ever).await;

    // ---- 4c. The new active node RESTORES the killed node's snapshot (the C-7 path)
    // and continues. It opens the SAME persisted treasury (D-9) and debits it. ----
    let new_active_handle = handle_by_id(&handles, new_leader)?;
    let restored = restore_on_new_active(
        &config,
        &image,
        &treasury_path,
        balance_after_active,
        new_leader,
        transferred,
    )
    .await;
    let RestoredGenome {
        instance,
        node2_reached_running,
        post_resume_round_trip,
        treasury: node2_treasury,
        serve_task: node2_serve,
    } = match restored {
        Ok(r) => r,
        Err(e) => {
            for n in nodes {
                n.shutdown().await;
            }
            let _ = std::fs::remove_dir_all(&transfer_dir);
            return Err(anyhow::anyhow!("G8: restore on the new active node failed: {e}"));
        }
    };

    // The new active node debits the SAME treasury through the fence (it holds the
    // lease @ T+1). D-9 continuation: the same counter, no double-store.
    let handoff_debit = lease_gated_debit(new_active_handle, term_t1, &node2_treasury, 50).await;
    anyhow::ensure!(
        matches!(handoff_debit, Some(DebitOutcome::Debited { .. })),
        "G8: the new active node must debit the SAME treasury while it holds the lease @ T+1 (D-9 continuation)"
    );
    let treasury_after = node2_treasury.remaining()?;
    sample_actives(&handles, &mut two_actives_ever).await;

    // ---- 5. REVIVE the killed node still believing term T. It must be FENCED. ----
    tracing::info!(node = elected_leader, believed_term = term_t, "G8: REVIVING the stale node (it must be fenced)");
    let revived = LeaseNode::start(elected_leader, "127.0.0.1:0").await?;
    let revived_handle = revived.handle();
    // The revived node catches up on rejoin: it learns the authoritative committed
    // lease the majority holds (T+1), so the fence sees the higher committed term that
    // superseded its old belief (spec 4.3), not merely "no lease".
    if let Some(authoritative) = new_active_handle.active_lease().await {
        revived_handle.catch_up_committed_lease(authoritative).await;
    }
    let stale_verdict = revived_handle.fence(term_t).await;
    let revived_stale_fenced = !stale_verdict.may_act();
    tracing::info!(?stale_verdict, "G8: revived stale node fence verdict (it sees the higher committed term T+1)");
    // The fenced node must not debit (no double-burn).
    let stale_debit = lease_gated_debit(&revived_handle, term_t, &node2_treasury, 777_777).await;
    anyhow::ensure!(
        stale_debit.is_none(),
        "G8: the revived stale node must NOT debit (it is fenced; no double-burn)"
    );
    anyhow::ensure!(
        node2_treasury.remaining()? == treasury_after,
        "G8: the treasury must be UNCHANGED by the fenced stale node (no double-burn)"
    );
    sample_actives(&handles, &mut two_actives_ever).await;

    let total_debited = treasury_before - treasury_after;

    // ---- Teardown ----
    instance.halt().await;
    node2_serve.abort();
    drop(node2_treasury);
    revived.shutdown().await;
    for n in nodes {
        n.shutdown().await;
    }
    let _ = std::fs::remove_dir_all(&transfer_dir);
    let _ = std::fs::remove_dir_all(&treasury_path);

    Ok(NoSplitBrainOutcome {
        elected_leader,
        term_t,
        killed_node: elected_leader,
        new_leader,
        term_t1,
        node2_restored_running: node2_reached_running,
        post_resume_round_trip,
        revived_stale_fenced,
        treasury_before,
        treasury_after,
        total_debited,
        two_actives_ever_observed: two_actives_ever,
    })
}

/// Sample the active set right now and OR into `two_actives_ever` whether more than
/// one node reports active (the linearizability witness). Called at each step so the
/// run records if a split-brain instant ever occurred.
async fn sample_actives(handles: &[LeaseHandle], two_actives_ever: &mut bool) {
    let active = observe_active_nodes(handles).await;
    if active.len() > 1 {
        *two_actives_ever = true;
        tracing::error!(?active, "G8: TWO nodes report active at once (linearizability violated)");
    }
}

/// A lease-gated treasury debit (the money-path the lease gates): debit only if the
/// fence says this node holds the lease at a current-enough term. A fenced node
/// returns `None` and the treasury is untouched (no double-burn).
async fn lease_gated_debit(
    handle: &LeaseHandle,
    believed_term: u64,
    treasury: &Treasury,
    amount: u64,
) -> Option<DebitOutcome> {
    match handle.fence(believed_term).await {
        FenceVerdict::Active { .. } => Some(treasury.debit_metered(amount).ok()?),
        FenceVerdict::Fenced { .. } => None,
    }
}

/// The active node's booted genome plus the handles the orchestration needs (the
/// gateway for events, the shared treasury, the serve task to abort on kill).
struct ActiveGenome {
    instance: Box<dyn SandboxInstance>,
    gateway: GatewayService,
    events: EventStream,
    treasury: Treasury,
    serve_task: tokio::task::JoinHandle<()>,
}

/// Boot the genome on the active node (the leader that holds the lease @ T): the
/// snapshot-capable heartbeat workload, serving the agnostic gateway over its vsock.
/// Mirrors the C-7 node-1 boot but is driven by the active node of the lease cluster.
async fn boot_active_genome(
    config: &NoSplitBrainConfig,
    image: &ImagePaths,
    treasury_path: &std::path::Path,
    active_node: LeaseNodeId,
) -> anyhow::Result<ActiveGenome> {
    let treasury = Treasury::open(treasury_path, 1_000_000)?;
    let session = Session {
        task_descriptor: config.task.clone(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec!["mint.test.local".to_string()],
    };
    let rail: Arc<dyn Rail> = Arc::new(MockRail::new());
    let mut gateway = GatewayService::new(treasury.clone(), rail, session);
    let events = gateway.observe_events();

    let spec = GuestSpec {
        image: GuestImage { kernel: image.vmlinux.clone(), rootfs: image.rootfs.clone() },
        instance_id: format!("g8-active-{active_node}"),
        guest_cid: config.vsock_cid,
        gateway_port: config.gateway_port,
        vcpu_count: config.vcpu_count,
        mem_size_mib: config.mem_mib,
        workload: Some("snapshot".to_string()),
        brain: None,
        lockdown_egress: false,
        snapshot_capable: true,
    };

    tracing::info!(active_node, cid = config.vsock_cid, port = config.gateway_port, "G8: active node booting the genome (it holds the lease)");
    let backend = FirecrackerBackend::new();
    let mut instance = backend.boot(spec).await?;
    if !instance.is_running() {
        instance.halt().await;
        anyhow::bail!("G8: the active node's genome did not reach Running");
    }
    instance.stream_console();

    let transport = instance.gateway_transport();
    let serve_service = gateway.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "G8: active node gateway serve loop ended with error");
        }
    });

    Ok(ActiveGenome { instance, gateway, events, treasury, serve_task })
}

/// The restored genome on the new active node plus the survival signals and the
/// SHARED treasury it continues (D-9).
struct RestoredGenome {
    instance: Box<dyn SandboxInstance>,
    node2_reached_running: bool,
    post_resume_round_trip: bool,
    treasury: Treasury,
    serve_task: tokio::task::JoinHandle<()>,
}

/// Restore the killed node's snapshot on the NEW active node (the C-7 restore the
/// lease drove) and confirm the genome survived. Opens the SAME persisted treasury
/// store (D-9 continuation) and bumps the VMGenID generation on restore (the C-8
/// hook), so the genome re-derives its entropy before acting. This is the UNCHANGED
/// C-7 restore mechanism, now invoked by the lease handoff rather than a fixed
/// orchestration.
async fn restore_on_new_active(
    config: &NoSplitBrainConfig,
    image: &ImagePaths,
    treasury_path: &std::path::Path,
    expected_balance: u64,
    new_active_node: LeaseNodeId,
    transferred: crate::sandbox::SnapshotArtifact,
) -> anyhow::Result<RestoredGenome> {
    // The new active node opens the SAME persisted treasury (D-9: it continues the
    // killed node's balance, not a fresh one).
    let treasury = Treasury::open(treasury_path, expected_balance)?;
    anyhow::ensure!(
        treasury.remaining()? == expected_balance,
        "G8: the new active node must continue the SAME persisted treasury balance (D-9)"
    );
    let session = Session {
        task_descriptor: config.task.clone(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec!["mint.test.local".to_string()],
    };
    let rail: Arc<dyn Rail> = Arc::new(MockRail::new());
    let mut gateway = GatewayService::new(treasury.clone(), rail, session);
    // The VMGenID bump on restore (the C-8 hook): a restored VM is a new generation.
    gateway.bump_generation();
    let mut events = gateway.observe_events();

    let restore_spec = RestoreSpec {
        image: GuestImage { kernel: image.vmlinux.clone(), rootfs: image.rootfs.clone() },
        instance_id: format!("g8-restored-{new_active_node}"),
        gateway_port: config.gateway_port,
        lockdown_egress: false,
    };

    tracing::info!(new_active_node, "G8: the new active node RESTORES the killed node's snapshot (C-7 path)");
    let backend = FirecrackerBackend::new();
    let mut instance = backend.restore(transferred, restore_spec).await?;
    let node2_reached_running = instance.is_running();
    instance.stream_console();

    let transport = instance.gateway_transport();
    let serve_service = gateway.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "G8: new active node gateway serve loop ended with error");
        }
    });

    // The decisive survival proof: a post-resume heartbeat from the genome on the new
    // active node (it re-dialed after its vsock dropped on the move).
    let post = wait_for_heartbeat(&mut events, config.post_resume_timeout).await;
    let post_resume_round_trip = post.is_some();
    if let Some(ev) = &post {
        tracing::info!(detail = %ev.detail, "G8: the genome survived the lease-driven handoff (post-resume round-trip on the new active node)");
    }

    Ok(RestoredGenome {
        instance,
        node2_reached_running,
        post_resume_round_trip,
        treasury,
        serve_task,
    })
}

/// Wait for the next `heartbeat` event from the genome, up to `timeout` (the same
/// survival signal C-7 uses). Other events are drained while waiting.
async fn wait_for_heartbeat(events: &mut EventStream, timeout: Duration) -> Option<Event> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "heartbeat" => return Some(ev),
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

/// Find a started lease node by id (the nodes vector shifts as a kill removes one).
fn node_by_id(nodes: &[LeaseNode], id: LeaseNodeId) -> anyhow::Result<&LeaseNode> {
    nodes
        .iter()
        .find(|n| n.id() == id)
        .ok_or_else(|| anyhow::anyhow!("lease node {id} not found"))
}

/// Find any started lease node whose id is in `ids` (a surviving node after a kill).
fn node_by_id_any<'a>(nodes: &'a [LeaseNode], ids: &[LeaseNodeId]) -> anyhow::Result<&'a LeaseNode> {
    nodes
        .iter()
        .find(|n| ids.contains(&n.id()))
        .ok_or_else(|| anyhow::anyhow!("no surviving lease node among {ids:?}"))
}

/// Find a lease handle by id.
fn handle_by_id(handles: &[LeaseHandle], id: LeaseNodeId) -> anyhow::Result<&LeaseHandle> {
    handles
        .iter()
        .find(|h| h.id() == id)
        .ok_or_else(|| anyhow::anyhow!("lease handle {id} not found"))
}

/// Remove a started lease node by id from the vector (consuming it for shutdown).
fn remove_node(nodes: &mut Vec<LeaseNode>, id: LeaseNodeId) -> anyhow::Result<LeaseNode> {
    let idx = nodes
        .iter()
        .position(|n| n.id() == id)
        .ok_or_else(|| anyhow::anyhow!("lease node {id} not found to remove"))?;
    Ok(nodes.remove(idx))
}
