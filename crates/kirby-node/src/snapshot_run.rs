//! Snapshot + cross-node resume orchestration (spec D-8, 4.1, section 5 transfer
//! seam, gate G6): the spike's hardest seam.
//!
//! "Node 1" boots the genome microVM (CPU-template normalized so the snapshot can
//! restore on a compatible different CPU), then the daemon SNAPSHOTS the running
//! VM (pause + write the mem+vmstate pair), TRANSFERS the pair to "node 2" (the
//! D-13 same-host seam: a second jail/dir on this host), KILLS node 1's VMM, and
//! "node 2" RESTORES a fresh jailed VMM from the transferred pair and resumes it.
//! The genome continues ALIVE across the move: its vsock dropped, so it re-dials
//! the node-2 gateway and completes a post-resume GetSessionContext/ReportEvent
//! round-trip (the machine-checkable proof it survived). On restore the VMGenID
//! generation BUMPS and node 2's gateway `bump_generation()` fires (the hook C-8
//! uses to make the genome re-derive its entropy; C-7 does NOT do the full
//! re-derive, that is C-8/G7).
//!
//! This module is the AGNOSTIC orchestration: it speaks the [`crate::sandbox`]
//! seam (snapshot -> transfer -> restore), the agnostic gateway, and the
//! persisted treasury. The backend MECHANICS (pause, create-snapshot with the
//! T2CL template, the fresh jailed restore) live behind the backend. The same-host
//! harness proves the LOGIC; the two-host cross-CPU run (D-15) is a transfer-seam
//! swap, not a rework.
//!
//! PRESERVED: the single persisted treasury (D-9) carries across the move (node 2
//! opens the SAME store path, so a resumed VM continues debiting the same balance);
//! the D-7 jailer boundary holds on BOTH the source boot and the restore (the
//! restore runs under the jailer too, via the FIX-1 discovered sudo); the agnostic
//! core (gateway/treasury/rail/genome) is unchanged.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kirby_proto::Event;

use crate::boot::{BootConfig, EventStream};
use crate::firecracker::FirecrackerBackend;
use crate::gateway::{GatewayService, Session};
use crate::rail::{MockRail, Rail};
use crate::sandbox::{
    GuestImage, GuestSpec, LocalDirTransfer, RestoreSpec, SandboxBackend, SandboxInstance,
    SnapshotTransfer,
};
use crate::treasury::Treasury;

/// Inputs for a snapshot + cross-node resume run. Reuses the boot config for node
/// 1 (the genome boots there); node 2 derives its own instance id, gateway port,
/// and snapshot inbox from it. The transfer is same-host by default (D-13).
pub struct SnapshotRunConfig {
    /// The node-1 boot config (the genome boots here, snapshot-capable + the
    /// `snapshot` heartbeat workload). `snapshot_capable` is forced on by `new`.
    pub boot: BootConfig,
    /// The node-2 instance id (its jail, cgroup, TAP, vsock all derive from it).
    /// Distinct from node 1's so the same-host harness keeps the two separate.
    pub node2_id: String,
    /// The gateway vsock port node 2 serves the restored genome on. MUST equal node
    /// 1's gateway port: the genome read the port from its kernel cmdline ONCE at
    /// boot (node 1's port) and that value is frozen in the snapshot, so the restored
    /// genome re-dials the SAME port. Node 2 has its own distinct vsock uds (a
    /// separate jail), so it can serve on that port without colliding with node 1
    /// (which is killed before node 2 starts).
    pub node2_gateway_port: u32,
    /// The directory node 1's snapshot pair is transferred into (node 2's inbox),
    /// modeling the move from node 1 to node 2 (D-13 same-host seam).
    pub transfer_dir: PathBuf,
    /// How long to wait for node 1's pre-snapshot heartbeat round-trip.
    pub pre_snapshot_timeout: Duration,
    /// How long to wait for node 2's post-resume heartbeat round-trip.
    pub post_resume_timeout: Duration,
}

impl SnapshotRunConfig {
    /// A snapshot run derived from a node-1 boot config. Forces the node-1 boot to
    /// be snapshot-capable (the T2CL template) with the `snapshot` heartbeat
    /// workload (the correct genome that re-derives its entropy on resume, gate G7),
    /// and derives node-2's id/port/inbox.
    pub fn new(boot: BootConfig) -> Self {
        Self::with_workload(boot, "snapshot")
    }

    /// As [`new`], but with the `resume-noredrive` NEGATIVE-CONTROL genome workload:
    /// the deliberately-broken genome that REUSES its pre-snapshot fingerprint after
    /// the resume (the catastrophic nonce-reuse the G7 gate must catch). Used by the
    /// G7 test to prove the gate has teeth: this run produces `fingerprint_post ==
    /// fingerprint_pre`, which the correct genome (from [`new`]) never does. It still
    /// survives the move (G6 holds), so the only difference under test is the reuse.
    pub fn new_negative_control(boot: BootConfig) -> Self {
        Self::with_workload(boot, "resume-noredrive")
    }

    /// Build a snapshot run with a specific genome workload. Forces snapshot
    /// capability (the T2CL template) and derives node-2's id/port/inbox; the
    /// workload selects the correct (`snapshot`) or negative-control
    /// (`resume-noredrive`) genome.
    fn with_workload(mut boot: BootConfig, workload: &str) -> Self {
        boot.snapshot_capable = true;
        boot.workload = Some(workload.to_string());
        let node2_id = format!("{}-n2", boot.node_id);
        // Node 2 serves on the SAME port the genome dials (node 1's gateway port,
        // frozen in the snapshot via the genome's kernel cmdline). Node 2's distinct
        // vsock uds (a separate jail) means no collision with node 1, which is killed
        // before node 2 starts.
        let node2_gateway_port = boot.gateway_port;
        let transfer_dir = std::env::temp_dir().join(format!("kirby-snapshot-{}", boot.node_id));
        SnapshotRunConfig {
            boot,
            node2_id,
            node2_gateway_port,
            transfer_dir,
            pre_snapshot_timeout: Duration::from_secs(40),
            post_resume_timeout: Duration::from_secs(40),
        }
    }
}

/// The G6 evidence from a snapshot + cross-node resume run.
#[derive(Debug, Clone)]
pub struct SnapshotRunOutcome {
    /// Node 1's pre-snapshot heartbeat round-trip landed (the genome was alive and
    /// talking before the snapshot).
    pub pre_snapshot_round_trip: bool,
    /// The snapshot mem+vmstate footprint that crossed the transfer seam, in bytes.
    pub snapshot_bytes: u64,
    /// Node 1's VMM was killed after the snapshot (the source node is gone).
    pub node1_killed: bool,
    /// Node 2 brought the VM to Running FROM the snapshot (not a cold boot).
    pub node2_reached_running: bool,
    /// Node 2 observed a post-resume heartbeat round-trip from the genome (the
    /// genome SURVIVED the move and reconnected to node 2's gateway). This is the
    /// decisive G6 proof.
    pub post_resume_round_trip: bool,
    /// The post-resume heartbeat detail node 2 saw (carries the beat number, the
    /// task, and the generation the genome saw), for the evidence line.
    pub post_resume_detail: Option<String>,
    /// The VMGenID generation node 1's gateway was at before the snapshot.
    pub generation_pre: u64,
    /// The VMGenID generation node 2's gateway is at after the restore bump (must
    /// be `generation_pre + 1`: the bump fired on restore, the C-8 hook).
    pub generation_post: u64,
    /// The treasury balance node 1 had (the persisted store node 2 continues, D-9).
    pub treasury_pre: u64,
    /// The treasury balance node 2 sees after opening the SAME persisted store
    /// (equal to `treasury_pre`: a resumed VM continues the same treasury, D-9).
    pub treasury_post: u64,
    /// The entropy fingerprint `H(nonce || gen)` the genome reported on node 1
    /// BEFORE the snapshot (derived from a fresh GetEntropyNonce at the
    /// pre-snapshot generation). The G7 instrument (spec 3.4, 4.4).
    pub fingerprint_pre: Option<String>,
    /// The entropy fingerprint the genome reported on node 2 AFTER the resume
    /// (re-derived from a fresh GetEntropyNonce at the bumped generation). For the
    /// correct genome this DIFFERS from `fingerprint_pre` (the re-derive proof); for
    /// the negative control it EQUALS it (the reuse the gate catches). The G7 verdict.
    pub fingerprint_post: Option<String>,
    /// True iff node 2 observed the genome call GetEntropyNonce at the bumped
    /// generation AFTER the resume and BEFORE its first post-resume act (the
    /// post-resume `heartbeat` ReportEvent). The G7 ordering signal: the genome
    /// re-derived before acting, not after. The daemon's gateway feeds an
    /// `entropy_nonce_call` observer event ahead of the heartbeat act.
    pub entropy_call_before_post_resume_act: bool,
}

impl SnapshotRunOutcome {
    /// The G6 verdict: node 2 reached Running from the snapshot, the genome did a
    /// post-resume round-trip (it survived), and the generation bumped on restore.
    /// UNCHANGED by C-8: G6 is about SURVIVAL, so the negative-control genome (which
    /// also survives the move, it just reuses its fingerprint) still passes G6.
    pub fn passed(&self) -> bool {
        self.pre_snapshot_round_trip
            && self.node1_killed
            && self.node2_reached_running
            && self.post_resume_round_trip
            && self.generation_post == self.generation_pre + 1
            && self.treasury_post == self.treasury_pre
    }

    /// The G7 verdict (spec 7-G7, the entropy-re-derive gate): the genome
    /// re-derived its ephemeral secret on resume. It requires, all from this run:
    /// the pre-snapshot and post-resume fingerprints both landed AND DIFFER
    /// (`fingerprint_pre != fingerprint_post`, the entropy was genuinely re-derived,
    /// not reused); the VMGenID generation bumped (`generation_post ==
    /// generation_pre + 1`); and the genome CALLED GetEntropyNonce after the resume
    /// BEFORE acting (the ordering signal). The negative-control genome FAILS this
    /// (its fingerprints are equal), which is exactly what the gate must catch. G6
    /// (survival) is a precondition: a genome that did not survive cannot re-derive.
    pub fn g7_passed(&self) -> bool {
        let (Some(pre), Some(post)) = (&self.fingerprint_pre, &self.fingerprint_post) else {
            return false;
        };
        self.passed()
            && pre != post
            && self.generation_post == self.generation_pre + 1
            && self.entropy_call_before_post_resume_act
    }

    /// True iff the genome REUSED its pre-snapshot fingerprint after the resume
    /// (`fingerprint_pre == fingerprint_post`), the catastrophic nonce-reuse G7
    /// exists to catch. The G7 test asserts this is TRUE for the negative-control
    /// genome and FALSE for the correct one, proving the gate has teeth.
    pub fn fingerprints_equal(&self) -> bool {
        match (&self.fingerprint_pre, &self.fingerprint_post) {
            (Some(pre), Some(post)) => pre == post,
            _ => false,
        }
    }
}

/// Run the full G6 flow: boot node 1, snapshot it, transfer the pair, kill node 1,
/// restore on node 2, and confirm the genome survived with a post-resume round-trip
/// and the generation bumped. Both VMs are halted before returning (including on an
/// error path), so no jail or TAP leaks.
pub async fn run(config: SnapshotRunConfig) -> anyhow::Result<SnapshotRunOutcome> {
    run_with_rail(config, Arc::new(MockRail::new())).await
}

/// As [`run`], but the caller supplies the [`Rail`] the gateways use (the spike's
/// G6 uses the mock rail; the brokered act is C-6/G5). Both node 1 and node 2 use
/// the same rail kind; the rail is host-side and per-node and is NOT moved by the
/// snapshot (only the VM mem+vmstate pair moves), matching D-9 and the C-6 note.
pub async fn run_with_rail(
    config: SnapshotRunConfig,
    rail: Arc<dyn Rail>,
) -> anyhow::Result<SnapshotRunOutcome> {
    // The persisted, daemon-owned treasury (D-9). Node 1 and node 2 share ONE
    // store PATH so a resumed VM continues debiting the SAME balance (the D-9
    // continuation the spec requires). A per-run path keeps runs distinct.
    let treasury_path = std::env::temp_dir().join(format!("kirby-treasury-snap-{}", config.boot.node_id));
    let _ = std::fs::remove_dir_all(&treasury_path); // a clean store per run

    // ---- NODE 1: boot the genome, snapshot it, transfer, kill ----
    let node1 = boot_node1(&config, &treasury_path, rail.clone()).await?;
    let Node1Booted {
        mut instance,
        gateway,
        mut events,
        treasury,
        serve_task,
    } = node1;

    // The pre-snapshot heartbeat round-trip: the genome is alive and talking on
    // node 1 before we snapshot it. The heartbeat carries the entropy fingerprint
    // (derived from a fresh GetEntropyNonce before the act), captured here as
    // `fingerprint_pre` (the G7 baseline).
    let pre_heartbeat = wait_for_heartbeat(&mut events, config.pre_snapshot_timeout).await;
    let pre_snapshot_round_trip = pre_heartbeat.is_some();
    let fingerprint_pre = pre_heartbeat.as_ref().and_then(|e| parse_fingerprint(&e.detail));
    let generation_pre = gateway.vm_generation();
    let treasury_pre = treasury.remaining()?;
    tracing::info!(
        fingerprint_pre = fingerprint_pre.as_deref().unwrap_or("<none>"),
        "node 1: pre-snapshot entropy fingerprint captured (G7 baseline)"
    );
    tracing::info!(
        pre_snapshot_round_trip,
        generation_pre,
        treasury_pre,
        "node 1: genome alive before snapshot"
    );
    if !pre_snapshot_round_trip {
        instance.halt().await;
        anyhow::bail!("node 1: genome did not complete a pre-snapshot heartbeat round-trip");
    }

    // Snapshot the running VM (pause + write the mem+vmstate pair). The VM is left
    // paused; we restore on node 2 BEFORE killing it.
    tracing::info!("node 1: snapshotting the running VM (pause + create-snapshot, T2CL-normalized)");
    let artifact = match instance.snapshot().await {
        Ok(a) => a,
        Err(e) => {
            instance.halt().await;
            return Err(anyhow::anyhow!("node 1: snapshot failed: {e}"));
        }
    };
    let snapshot_class = artifact.class;
    tracing::info!(
        ?snapshot_class,
        bytes = artifact.footprint_bytes(),
        "node 1: snapshot created"
    );

    // Transfer the mem+vmstate pair to node 2's inbox (D-13 same-host seam). Only
    // the pair crosses; the rootfs is pre-staged on node 2 (the same image dir).
    let transfer = LocalDirTransfer { target_dir: config.transfer_dir.clone() };
    let transferred = match transfer.transfer(artifact).await {
        Ok(a) => a,
        Err(e) => {
            instance.halt().await;
            return Err(anyhow::anyhow!("snapshot transfer failed: {e}"));
        }
    };
    let snapshot_bytes = transferred.footprint_bytes();
    tracing::info!(
        bytes = snapshot_bytes,
        dir = %config.transfer_dir.display(),
        "snapshot pair transferred to node 2 (D-13 same-host seam)"
    );

    // KILL node 1's VMM: the source node is gone. The restore on node 2 must bring
    // the genome back from the transferred snapshot alone.
    tracing::info!("node 1: KILLING the VMM (the source node is gone; node 2 must restore)");
    instance.halt().await;
    let node1_killed = true;

    // Release node 1's hold on the persisted treasury so node 2 can open the SAME
    // store (D-9 continuation). In a true two-host run node 1's whole process is
    // gone, which frees the sled lock; the same-host harness must drop node 1's
    // gateway + treasury handles AND its serve task explicitly. generation_pre and
    // treasury_pre were already captured above.
    serve_task.abort();
    drop(gateway);
    drop(treasury);
    // Give the aborted serve task a tick to drop its gateway clone (and the sled
    // handle inside it) before node 2 opens the same store.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ---- NODE 2: restore from the transferred pair, confirm survival ----
    let image = GuestImage {
        kernel: config.boot.image.vmlinux.clone(),
        rootfs: config.boot.image.rootfs.clone(),
    };
    // Node 2 opens the SAME persisted treasury store (D-9: a resumed VM continues
    // the same balance). Its session/allowlist mirror node 1's (the same genome).
    let node2_treasury = Treasury::open(&treasury_path, treasury_pre)?;
    let treasury_post = node2_treasury.remaining()?;
    let session = Session {
        task_descriptor: config.boot.task.clone(),
        budget_sats: config.boot.budget_sats,
        allowlisted_destinations: config.boot.allow.clone(),
    };
    let mut node2_gateway = GatewayService::new(node2_treasury, rail, session);
    // The VMGenID bump on restore (the C-8 hook): a restored VM is a NEW generation,
    // so node 2's gateway bumps its generation. The genome (re-dialing node 2)
    // observes the bumped generation via GetEntropyNonce and (C-8) re-derives its
    // entropy before acting. C-7 wires the bump; C-8 does the full re-derive.
    // Node 2 starts a fresh gateway at generation_pre, then bumps to generation_pre+1
    // so the post-resume generation is exactly one past the pre-snapshot one.
    for _ in 0..generation_pre {
        node2_gateway.bump_generation();
    }
    let generation_post = node2_gateway.bump_generation();
    tracing::info!(
        generation_pre,
        generation_post,
        "node 2: VMGenID generation bumped on restore (the C-8 re-derive hook)"
    );

    // Observe node 2's events so we can await the post-resume heartbeat.
    let mut node2_events = node2_gateway.observe_events();

    let restore_spec = RestoreSpec {
        image,
        instance_id: config.node2_id.clone(),
        gateway_port: config.node2_gateway_port,
        lockdown_egress: config.boot.lockdown_egress,
    };

    tracing::info!(node2_id = %config.node2_id, "node 2: restoring the VM from the transferred snapshot (fresh jailed VMM)");
    let backend = FirecrackerBackend::new();
    let mut node2_instance = match backend.restore(transferred, restore_spec).await {
        Ok(i) => i,
        Err(e) => {
            return Err(anyhow::anyhow!("node 2: restore failed: {e}"));
        }
    };

    let node2_reached_running = node2_instance.is_running();
    tracing::info!(node2_reached_running, "node 2: VM state after restore");
    node2_instance.stream_console();

    // Serve a FRESH gateway over node 2's vsock transport so the genome (re-dialing
    // after the vsock dropped on the move) reconnects and the post-resume round-trip
    // lands. The gateway SERVICE is identical; only the transport differs.
    let transport = node2_instance.gateway_transport();
    let serve_service = node2_gateway.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "node 2 gateway serve loop ended with error");
        }
    });

    // The decisive G6 + G7 proof: node 2 observes a post-resume heartbeat round-trip
    // from the genome. The genome's vsock dropped on the move; it re-dialed node 2's
    // gateway; this heartbeat is the SAME genome continuing alive on node 2. Node 2's
    // observer is fresh (created on restore), so its stream starts clean post-restore:
    // the genome calls GetEntropyNonce (the daemon feeds an `entropy_nonce_call` event
    // at the bumped generation) and THEN reports the heartbeat, so the ordering signal
    // (entropy call before the act) is observable. We wait for the heartbeat AND record
    // whether an entropy call at `generation_post` preceded it (G7 ordering).
    let post = wait_for_post_resume_heartbeat(
        &mut node2_events,
        generation_post,
        config.post_resume_timeout,
    )
    .await;
    let post_resume_round_trip = post.heartbeat.is_some();
    let fingerprint_post = post
        .heartbeat
        .as_ref()
        .and_then(|e| parse_fingerprint(&e.detail));
    let post_resume_detail = post.heartbeat.map(|e| e.detail);
    let entropy_call_before_post_resume_act = post.entropy_call_before_act;
    tracing::info!(
        post_resume_round_trip,
        fingerprint_post = fingerprint_post.as_deref().unwrap_or("<none>"),
        entropy_call_before_post_resume_act,
        detail = post_resume_detail.as_deref().unwrap_or("<none>"),
        "node 2: post-resume round-trip + entropy re-derive (the genome survived the move and re-derived)"
    );

    // Tear down node 2's VM (the demonstration is complete).
    node2_instance.halt().await;

    Ok(SnapshotRunOutcome {
        pre_snapshot_round_trip,
        snapshot_bytes,
        node1_killed,
        node2_reached_running,
        post_resume_round_trip,
        post_resume_detail,
        generation_pre,
        generation_post,
        treasury_pre,
        treasury_post,
        fingerprint_pre,
        fingerprint_post,
        entropy_call_before_post_resume_act,
    })
}

/// Node 1's booted state: the instance, its gateway (for the generation + bump),
/// the event stream (for the heartbeat), the shared treasury, and the gateway serve
/// task handle (aborted before node 2 opens the SAME store, so node 1's sled lock is
/// released; in a true two-host run node 1's whole process is gone, which releases it
/// for free, but the same-host harness must drop node 1's handles explicitly).
struct Node1Booted {
    instance: Box<dyn SandboxInstance>,
    gateway: GatewayService,
    events: EventStream,
    treasury: Treasury,
    serve_task: tokio::task::JoinHandle<()>,
}

/// Boot node 1: the snapshot-capable genome with the heartbeat workload, serving
/// the agnostic gateway over its vsock transport. Mirrors `boot::boot_and_observe`
/// but keeps the gateway handle (for the generation) and does not wait for a
/// "hello" (the heartbeat workload reports `heartbeat` events, not a one-shot
/// hello). The treasury is the shared persisted store (D-9).
async fn boot_node1(
    config: &SnapshotRunConfig,
    treasury_path: &std::path::Path,
    rail: Arc<dyn Rail>,
) -> anyhow::Result<Node1Booted> {
    let treasury = Treasury::open(treasury_path, config.boot.initial_sats)?;
    let session = Session {
        task_descriptor: config.boot.task.clone(),
        budget_sats: config.boot.budget_sats,
        allowlisted_destinations: config.boot.allow.clone(),
    };
    let mut gateway = GatewayService::new(treasury.clone(), rail, session);
    if let Some(checkpoint) = config.boot.restore_checkpoint.clone() {
        gateway = gateway.with_restore_checkpoint(checkpoint);
    }
    let events = gateway.observe_events();

    let spec = GuestSpec {
        image: GuestImage {
            kernel: config.boot.image.vmlinux.clone(),
            rootfs: config.boot.image.rootfs.clone(),
        },
        instance_id: config.boot.node_id.clone(),
        guest_cid: config.boot.guest_cid,
        gateway_port: config.boot.gateway_port,
        vcpu_count: config.boot.vcpu_count,
        mem_size_mib: config.boot.mem_size_mib,
        workload: config.boot.workload.clone(),
        brain: config.boot.brain.clone(),
        lockdown_egress: config.boot.lockdown_egress,
        snapshot_capable: config.boot.snapshot_capable,
    };

    tracing::info!(
        node_id = %config.boot.node_id,
        cid = config.boot.guest_cid,
        port = config.boot.gateway_port,
        "node 1: booting the snapshot-capable genome (T2CL template, heartbeat workload)"
    );
    let backend = FirecrackerBackend::new();
    let mut instance = backend.boot(spec).await?;

    if !instance.is_running() {
        instance.halt().await;
        anyhow::bail!("node 1: guest did not reach the running state");
    }
    instance.stream_console();

    // Serve the gateway over node 1's vsock transport so the genome's heartbeat
    // round-trips land.
    let transport = instance.gateway_transport();
    let serve_service = gateway.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "node 1 gateway serve loop ended with error");
        }
    });

    Ok(Node1Booted { instance, gateway, events, treasury, serve_task })
}

/// Wait for the next `heartbeat` event from the genome, up to `timeout`. Other
/// events are drained while waiting. A heartbeat is a completed GetSessionContext +
/// ReportEvent round-trip, so observing one proves the genome is alive and talking
/// to THIS daemon (node 1 before the snapshot, node 2 after the restore).
async fn wait_for_heartbeat(events: &mut EventStream, timeout: Duration) -> Option<Event> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "heartbeat" => return Some(ev),
            Ok(Some(_)) => continue, // some other event; keep waiting
            Ok(None) => return None,  // observer dropped
            Err(_) => return None,    // timed out
        }
    }
}

/// The post-resume observation (G6 + G7): the first heartbeat the genome reported on
/// node 2 after the restore, plus whether an `entropy_nonce_call` at the bumped
/// generation was observed BEFORE that heartbeat act (the G7 ordering signal).
struct PostResumeObservation {
    /// The first post-resume `heartbeat` event (G6 survival proof; its detail carries
    /// `fingerprint_post`). None if none arrived before the timeout.
    heartbeat: Option<Event>,
    /// True iff a `entropy_nonce_call` event at `generation_post` was seen before the
    /// heartbeat above (the genome re-derived AFTER the resume and BEFORE acting, G7).
    entropy_call_before_act: bool,
}

/// Wait for the genome's first post-resume `heartbeat` on node 2, recording whether
/// the genome called GetEntropyNonce at `generation_post` BEFORE that heartbeat act
/// (the G7 ordering proof). Node 2's observer is fresh (created on restore), so its
/// stream starts clean: the restored genome re-dials, calls GetEntropyNonce (the
/// daemon feeds an `entropy_nonce_call` event tagged with the generation), derives
/// its fingerprint, then reports the heartbeat. So the natural stream order is the
/// entropy call (at the bumped generation) AHEAD of the heartbeat act. We require the
/// entropy call to be at exactly `generation_post` so a stale pre-bump call cannot
/// satisfy the ordering. Other events are drained while waiting.
async fn wait_for_post_resume_heartbeat(
    events: &mut EventStream,
    generation_post: u64,
    timeout: Duration,
) -> PostResumeObservation {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut entropy_call_at_post_gen = false;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return PostResumeObservation { heartbeat: None, entropy_call_before_act: false };
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "entropy_nonce_call" => {
                // Record an entropy call AT the bumped generation: the genome
                // re-derived at the post-resume generation. A call at any other
                // generation does not count toward the post-resume ordering.
                if parse_generation(&ev.detail) == Some(generation_post) {
                    entropy_call_at_post_gen = true;
                }
            }
            Ok(Some(ev)) if ev.kind == "heartbeat" => {
                // The first post-resume heartbeat act. The ordering holds iff an
                // entropy call at the bumped generation was seen before it.
                return PostResumeObservation {
                    heartbeat: Some(ev),
                    entropy_call_before_act: entropy_call_at_post_gen,
                };
            }
            Ok(Some(_)) => continue, // some other event; keep waiting
            Ok(None) => {
                return PostResumeObservation { heartbeat: None, entropy_call_before_act: false }
            }
            Err(_) => {
                return PostResumeObservation { heartbeat: None, entropy_call_before_act: false }
            }
        }
    }
}

/// Parse the entropy fingerprint hex out of a heartbeat detail line. The genome's
/// heartbeat detail is `beat=N task=T gen_seen=G fingerprint=<hex> fp_gen=G`; this
/// extracts the `fingerprint=` value (the G7 instrument). Returns None if absent.
fn parse_fingerprint(detail: &str) -> Option<String> {
    detail
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("fingerprint="))
        .map(|s| s.to_string())
}

/// Parse the `generation=<n>` value out of an `entropy_nonce_call` event detail.
/// Returns None if absent or unparseable.
fn parse_generation(detail: &str) -> Option<u64> {
    detail
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("generation="))
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::{parse_fingerprint, parse_generation};

    /// The fingerprint parser pulls the `fingerprint=` hex out of the genome's
    /// heartbeat detail, ignoring the other fields.
    #[test]
    fn parse_fingerprint_extracts_the_hex() {
        let detail = "beat=2 task=g7-demo gen_seen=1 fingerprint=deadbeef fp_gen=1";
        assert_eq!(parse_fingerprint(detail).as_deref(), Some("deadbeef"));
        // A pre-C-8 heartbeat (no fingerprint field) yields None.
        assert_eq!(parse_fingerprint("beat=1 task=t gen_seen=0"), None);
    }

    /// The generation parser pulls the `generation=` value out of the
    /// `entropy_nonce_call` detail the daemon feeds for the ordering signal.
    #[test]
    fn parse_generation_extracts_the_value() {
        assert_eq!(parse_generation("generation=1"), Some(1));
        assert_eq!(parse_generation("generation=0"), Some(0));
        assert_eq!(parse_generation("something else"), None);
    }
}
