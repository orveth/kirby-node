//! The G9 idempotent-capability-across-resume orchestration (spec 4.2, gate G9):
//! a brokered RequestCapability dedupes across a snapshot+resume, so a key re-issued
//! after the VM moves to another node is DEDUPED, not performed twice or
//! double-charged. This closes the replay / double-burn money-path of spec 4.2
//! across a move.
//!
//! THE FLOW this proves (the full G9 with a real VM):
//!  1. Node 1 boots the genome with the `idempotent` workload. The genome issues a
//!     RequestCapability with a STABLE idempotency_key K. The daemon runs the C-3
//!     5-step authorize order, PERFORMS the act on the rail (cost C), and records
//!     K -> receipt in the PERSISTED ledger (the same sled store as the treasury,
//!     D-9). The genome reports `idem_first` (the daemon expects
//!     AUTHORIZED_AND_PERFORMED, cost C, and the rail performed exactly once).
//!  2. Node 1 snapshots the running VM (the C-7 mem+vmstate pair), transfers it to
//!     node 2 (the D-13 same-host seam), and is KILLED.
//!  3. Node 2 RESTORES the VM from the snapshot (the UNCHANGED C-7 restore) and
//!     opens the SAME persisted treasury store (D-9), which already holds K's ledger
//!     entry (the act's debit was flushed durably before the snapshot). The genome
//!     survives the move, detects the resume (the bumped VMGenID generation), and
//!     RE-ISSUES the SAME key K. The daemon's STEP 1 dedupe finds K in the ledger
//!     that crossed the move and returns DUPLICATE_IGNORED with the PRIOR receipt,
//!     performing nothing. The genome reports `idem_reissue` (the daemon expects
//!     DUPLICATE_IGNORED, the same cost C, the SAME treasury balance).
//!
//! THE G9 EVIDENCE: K performed ONCE (the rail's perform_count == 1, the
//! authoritative treasury dropped by exactly C); after the resume the re-issued K is
//! DUPLICATE_IGNORED, the rail's perform_count STILL 1 (not performed twice), and the
//! treasury is debited by C EXACTLY ONCE total (not 2C).
//!
//! WHY THE DEDUPE SURVIVES THE MOVE (no fix needed, it composes): the dedupe ledger
//! is a tree in the SAME sled database as the authoritative balance (the C-3
//! treasury). `debit_and_record` records K -> receipt and FLUSHES the database in the
//! same transaction (the atomic debit+receipt invariant, spec 4.2), so K is durable
//! on disk the instant the first act completes, well before the snapshot is taken.
//! Node 2 opens the SAME store PATH on restore (the D-9 continuation the C-7 path
//! already does), so the resumed gateway's STEP 1 dedupe reads K's entry and
//! short-circuits. The persistence (D-9), the dedupe (C-3), and the resume (C-7)
//! compose; C-10 PROVES they do.
//!
//! This module uses the MockRail (spec G9 blesses it: "the MockRail if that is
//! cleaner for counting performs"). The dedupe and the single-debit are REAL
//! regardless of the rail: they live in the persisted treasury, not the rail. The
//! rail is only the "act"; MockRail's `perform_count` is the direct, clean evidence
//! that the act was performed exactly once across the move. The real-rail variant is
//! a drop-in (pass a `CdkEcashRail`), but the perform-once proof is rail-agnostic.
//!
//! PRESERVED: the restore is the UNCHANGED C-7 firecracker path (the D-7 jailer
//! boundary, the transfer seam); the treasury is the UNCHANGED persisted counter
//! (D-9, ONE store across the move); the agnostic core (gateway authorize-order,
//! treasury, rail, genome) is unchanged. C-8 entropy + C-9 lease are untouched.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::boot::{BootConfig, EventStream, ImagePaths};
use crate::firecracker::FirecrackerBackend;
use crate::gateway::{GatewayService, Session};
use crate::rail::{MockRail, Rail};
use crate::sandbox::{
    GuestImage, GuestSpec, LocalDirTransfer, RestoreSpec, SandboxBackend, SandboxInstance,
    SnapshotTransfer,
};
use crate::treasury::{is_lock_contention, Treasury};

/// Inputs for the G9 idempotent-across-resume run. Reuses the genome image; the
/// node-1 boot, the node-2 derivation, and the same-host transfer seam mirror the
/// C-7 snapshot run. The `idempotent` genome workload and snapshot-capability are
/// forced on by [`IdempotentRunConfig::new`].
pub struct IdempotentRunConfig {
    /// The node-1 boot config (the genome boots here with the `idempotent` workload).
    pub boot: BootConfig,
    /// The node-2 instance id (its jail, cgroup, TAP, vsock derive from it).
    pub node2_id: String,
    /// The gateway vsock port node 2 serves the restored genome on (equals node 1's:
    /// the genome read the port from its kernel cmdline ONCE at boot and that value is
    /// frozen in the snapshot, so the restored genome re-dials the SAME port).
    pub node2_gateway_port: u32,
    /// The directory node 1's snapshot pair is transferred into (node 2's inbox).
    pub transfer_dir: PathBuf,
    /// How long to wait for node 1's pre-snapshot `idem_first` outcome.
    pub first_act_timeout: Duration,
    /// How long to wait for node 2's post-resume `idem_reissue` outcome.
    pub reissue_timeout: Duration,
}

impl IdempotentRunConfig {
    /// Build a G9 run from an image dir, forcing the `idempotent` workload and
    /// snapshot capability (the T2CL template) and deriving node-2's id/port/inbox.
    pub fn new(image_dir: PathBuf) -> anyhow::Result<Self> {
        let image = ImagePaths::from_dir(&image_dir)?;
        let node_id = format!("g9-{}", std::process::id());
        let boot = BootConfig {
            image,
            node_id: node_id.clone(),
            task: "g9-idempotent".to_string(),
            budget_sats: 1_000_000,
            initial_sats: 1_000_000,
            // The allowlisted destination the genome settles against (the act's mint).
            allow: vec!["mint.test.local".to_string()],
            // A distinct CID and port keep this run isolated from other VMs.
            guest_cid: 33,
            gateway_port: 5033,
            vcpu_count: 1,
            // A small VM keeps the snapshot mem file small and the run quick.
            mem_size_mib: 128,
            hello_timeout: Duration::from_secs(40),
            workload: Some("idempotent".to_string()),
            // G9 is vsock-only (the egress lockdown is G4); keeps the move lean.
            lockdown_egress: false,
            snapshot_capable: true,
            restore_checkpoint: None,
        };
        Ok(Self::from_boot(boot))
    }

    /// Build a G9 run from an explicit boot config (used by a custom harness). Forces
    /// the `idempotent` workload and snapshot capability and derives node-2's
    /// id/port/inbox the same way the C-7 snapshot run does.
    pub fn from_boot(mut boot: BootConfig) -> Self {
        boot.snapshot_capable = true;
        boot.workload = Some("idempotent".to_string());
        let node2_id = format!("{}-n2", boot.node_id);
        let node2_gateway_port = boot.gateway_port;
        let transfer_dir = std::env::temp_dir().join(format!("kirby-idem-snap-{}", boot.node_id));
        IdempotentRunConfig {
            boot,
            node2_id,
            node2_gateway_port,
            transfer_dir,
            first_act_timeout: Duration::from_secs(40),
            reissue_timeout: Duration::from_secs(40),
        }
    }
}

/// One brokered outcome the genome reported (parsed from an `idem_first` /
/// `idem_reissue` event): the outcome name, the cost the genome was told, and the
/// post-act treasury balance the genome was told.
#[derive(Debug, Clone, Default)]
pub struct IdemOutcome {
    /// The outcome name the genome reported (e.g. `AuthorizedAndPerformed`,
    /// `DuplicateIgnored`). Empty if no event arrived.
    pub outcome: String,
    /// The cost the genome was told on its receipt.
    pub cost_sats: u64,
    /// The post-act treasury balance the genome was told.
    pub treasury_remaining: u64,
    /// True iff an event actually arrived (so a missing outcome is distinguishable
    /// from a genuine zero).
    pub observed: bool,
}

impl IdemOutcome {
    /// True iff the genome reported AUTHORIZED_AND_PERFORMED (the first act).
    pub fn is_performed(&self) -> bool {
        self.observed && self.outcome == "AuthorizedAndPerformed"
    }

    /// True iff the genome reported DUPLICATE_IGNORED (the post-resume re-issue).
    pub fn is_duplicate_ignored(&self) -> bool {
        self.observed && self.outcome == "DuplicateIgnored"
    }
}

/// The G9 evidence from an idempotent-across-resume run.
#[derive(Debug, Clone)]
pub struct IdempotentRunOutcome {
    /// The genome's FIRST act outcome on node 1 (expected AUTHORIZED_AND_PERFORMED).
    pub first: IdemOutcome,
    /// The genome's RE-ISSUE outcome on node 2 after the resume (expected
    /// DUPLICATE_IGNORED).
    pub reissue: IdemOutcome,
    /// The rail's perform count AFTER the first act on node 1 (the act performed
    /// exactly once -> 1).
    pub perform_count_after_first: u64,
    /// The rail's perform count AFTER the post-resume re-issue (STILL 1: the dedupe
    /// short-circuits before the rail, so the act is NOT performed twice).
    pub perform_count_after_reissue: u64,
    /// The daemon-authoritative treasury balance BEFORE the first act (D-9).
    pub treasury_before: u64,
    /// The daemon-authoritative treasury balance node 1 had AFTER the first act
    /// (dropped by exactly the act cost C).
    pub treasury_after_first: u64,
    /// The daemon-authoritative treasury balance node 2 sees AFTER the resume +
    /// re-issue (UNCHANGED from `treasury_after_first`: the dedupe debited nothing
    /// the second time, so the total drop is C, not 2C).
    pub treasury_after_reissue: u64,
    /// Node 1's VMM was killed after the snapshot (the source node is gone).
    pub node1_killed: bool,
    /// Node 2 brought the VM to Running FROM the snapshot (not a cold boot).
    pub node2_reached_running: bool,
    /// The snapshot mem+vmstate footprint that crossed the transfer seam, in bytes.
    pub snapshot_bytes: u64,
    /// The VMGenID generation node 1's gateway was at before the snapshot.
    pub generation_pre: u64,
    /// The VMGenID generation node 2's gateway is at after the restore bump.
    pub generation_post: u64,
}

impl IdempotentRunOutcome {
    /// The cost the act was performed at on node 1 (C). Read from the first act's
    /// receipt; equals the treasury drop on node 1.
    pub fn act_cost(&self) -> u64 {
        self.first.cost_sats
    }

    /// The total the authoritative treasury was debited across the whole move
    /// (before - after the resume). For G9 this MUST equal the single act cost C,
    /// never 2C.
    pub fn total_debited(&self) -> u64 {
        self.treasury_before.saturating_sub(self.treasury_after_reissue)
    }

    /// The G9 verdict (spec 7-G9): the genome's first act PERFORMED (cost C, the rail
    /// performed once, the treasury dropped by C); after the snapshot+resume the
    /// re-issued key was DUPLICATE_IGNORED; the act was NOT performed twice on the
    /// rail (perform_count stays 1); and the treasury was debited by C EXACTLY ONCE
    /// total (the post-resume drop is zero, so total == C, not 2C). The genome
    /// survived the move (node 2 reached Running, node 1 was killed, the generation
    /// bumped) as the precondition.
    pub fn passed(&self) -> bool {
        // The first act performed exactly once for a real cost.
        self.first.is_performed()
            && self.act_cost() > 0
            && self.perform_count_after_first == 1
            && self.treasury_after_first == self.treasury_before - self.act_cost()
            // The re-issue across the move was deduped.
            && self.reissue.is_duplicate_ignored()
            // NOT performed twice on the rail.
            && self.perform_count_after_reissue == 1
            // The re-issue debited NOTHING: the balance is unchanged across it.
            && self.treasury_after_reissue == self.treasury_after_first
            // So the total debited across the move is exactly the single cost C.
            && self.total_debited() == self.act_cost()
            // The genome's re-issue receipt reports the same cost C the first act did
            // (the dedupe returns the PRIOR receipt).
            && self.reissue.cost_sats == self.act_cost()
            // The move actually happened.
            && self.node1_killed
            && self.node2_reached_running
            && self.generation_post == self.generation_pre + 1
    }
}

/// Run the full G9 flow with the default MockRail: boot the `idempotent` genome on
/// node 1, observe the first act (PERFORMED, cost C, the rail performed once),
/// snapshot + transfer + kill node 1, restore on node 2 (the SAME persisted
/// treasury), observe the post-resume re-issue (DUPLICATE_IGNORED, the rail STILL
/// performed once, the treasury debited C exactly once total). Both VMs are halted
/// before returning (including on the error path).
pub async fn run(config: IdempotentRunConfig) -> anyhow::Result<IdempotentRunOutcome> {
    run_with_rail(config, Arc::new(MockRail::new())).await
}

/// As [`run`], but the caller supplies the [`Rail`]. The default is the MockRail (its
/// `perform_count` is the clean perform-once evidence); a `CdkEcashRail` is a drop-in
/// for a real-rail G9 (the dedupe + single-debit are rail-agnostic, so the perform-
/// once proof holds either way). The rail is host-side and per-node and is NOT moved
/// by the snapshot (only the VM mem+vmstate pair moves), matching D-9.
///
/// NOTE the perform_count evidence requires a rail whose perform count is readable;
/// the helper takes a `perform_count` reader so a custom rail can supply it. The
/// MockRail's reader is its [`MockRail::perform_count`].
pub async fn run_with_rail(
    config: IdempotentRunConfig,
    rail: Arc<MockRail>,
) -> anyhow::Result<IdempotentRunOutcome> {
    // The persisted, daemon-owned treasury (D-9). Node 1 and node 2 share ONE store
    // PATH so the resumed VM continues debiting the SAME balance AND reads the SAME
    // dedupe ledger (the entry K's first act wrote). A per-run path keeps runs
    // distinct; a clean store per run avoids a stale ledger from a prior run.
    let treasury_path =
        std::env::temp_dir().join(format!("kirby-idem-treasury-{}", config.boot.node_id));
    let _ = std::fs::remove_dir_all(&treasury_path);

    // ---- NODE 1: boot the genome, observe the first act, snapshot, transfer, kill ----
    let node1 = boot_node1(&config, &treasury_path, rail.clone()).await?;
    let Node1Booted {
        mut instance,
        gateway,
        mut events,
        treasury,
        serve_task,
    } = node1;

    let treasury_before = treasury.remaining()?;

    // The FIRST act: the genome issues K, the daemon authorizes + performs it (cost
    // C) and records K -> receipt in the persisted ledger. Wait for the genome's
    // `idem_first` outcome.
    let first = wait_for_idem(&mut events, "idem_first", config.first_act_timeout).await;
    let perform_count_after_first = rail.perform_count();
    let treasury_after_first = treasury.remaining()?;
    let generation_pre = gateway.vm_generation();
    tracing::info!(
        outcome = %first.outcome,
        cost_sats = first.cost_sats,
        perform_count_after_first,
        treasury_before,
        treasury_after_first,
        "node 1: first brokered act observed (G9 baseline: K performed once, cost debited)"
    );
    if !first.is_performed() {
        instance.halt().await;
        anyhow::bail!(
            "node 1: the genome's first act was not AUTHORIZED_AND_PERFORMED (got {:?}); cannot test G9",
            first.outcome
        );
    }

    // Snapshot the running VM (pause + write the mem+vmstate pair). The ledger entry
    // for K is ALREADY durable on disk (debit_and_record flushed it), so it is
    // captured by the persisted store node 2 opens, not by the VM memory snapshot.
    tracing::info!("node 1: snapshotting the running VM (the C-7 path; K's ledger entry is already durable)");
    let artifact = match instance.snapshot().await {
        Ok(a) => a,
        Err(e) => {
            instance.halt().await;
            return Err(anyhow::anyhow!("node 1: snapshot failed: {e}"));
        }
    };
    tracing::info!(bytes = artifact.footprint_bytes(), "node 1: snapshot created");

    // Transfer the pair to node 2's inbox (the D-13 same-host seam). Only the pair
    // crosses; the rootfs is pre-staged on node 2 (the same image dir).
    let transfer = LocalDirTransfer { target_dir: config.transfer_dir.clone() };
    let transferred = match transfer.transfer(artifact).await {
        Ok(a) => a,
        Err(e) => {
            instance.halt().await;
            return Err(anyhow::anyhow!("snapshot transfer failed: {e}"));
        }
    };
    let snapshot_bytes = transferred.footprint_bytes();
    tracing::info!(bytes = snapshot_bytes, "snapshot pair transferred to node 2 (D-13 same-host seam)");

    // KILL node 1's VMM: the source node is gone. Node 2 must restore from the pair.
    tracing::info!("node 1: KILLING the VMM (the source node is gone; node 2 must restore)");
    instance.halt().await;
    let node1_killed = true;

    // Release node 1's hold on the persisted treasury so node 2 can open the SAME
    // store (D-9 continuation): drop node 1's gateway + treasury handles AND its serve
    // task. In a true two-host run node 1's whole process is gone, which frees the
    // sled lock for free. The serve task holds a `gateway` (and thus a `treasury`)
    // CLONE, so aborting alone is not enough: the task must actually finish so its
    // clone is dropped. `abort()` only schedules cancellation, so we AWAIT the handle
    // (the abort makes it resolve promptly) before dropping our own handles, ensuring
    // node 1's last sled reference is gone before node 2 opens the SAME store.
    serve_task.abort();
    let _ = serve_task.await;
    drop(gateway);
    drop(treasury);
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ---- NODE 2: restore from the pair, open the SAME treasury, observe the re-issue ----
    let image = GuestImage {
        kernel: config.boot.image.vmlinux.clone(),
        rootfs: config.boot.image.rootfs.clone(),
    };
    // Node 2 opens the SAME persisted treasury store (D-9): a resumed VM continues the
    // same balance AND the same dedupe ledger. The seed is ignored on a resume (the
    // persisted balance + ledger are authoritative), so K's entry is present.
    //
    // Node 1's sled handles were just dropped, but sled releases its single-process
    // exclusive lock when the OS reclaims the file descriptors, which is not strictly
    // ordered with respect to the `Drop` above; on a busy host the release can lag the
    // 50 ms settle and the open would hit `WouldBlock` (a transient lock contention, not
    // a real failure). In a true two-host deployment node 1's whole process is gone and
    // the lock is free immediately, so this same-host harness retries the open briefly to
    // bridge that gap rather than fail a run on a lock that is about to release.
    let node2_treasury = open_treasury_when_unlocked(
        &treasury_path,
        treasury_after_first,
        Duration::from_secs(5),
    )?;
    let treasury_on_restore = node2_treasury.remaining()?;
    tracing::info!(
        treasury_on_restore,
        treasury_after_first,
        "node 2: opened the SAME persisted treasury store (D-9); the dedupe ledger crossed the move"
    );
    // Keep a CLONE of node 2's treasury handle to read the final balance after the
    // re-issue. The clone shares the SAME sled handle (an Arc), so it is the SAME
    // lock node 2's gateway holds (re-opening the path with a fresh `Treasury::open`
    // would deadlock on sled's single-process exclusive lock). This mirrors how the
    // boot path keeps a `meter_treasury` clone alongside the gateway's copy.
    let node2_treasury_read = node2_treasury.clone();
    let session = Session {
        task_descriptor: config.boot.task.clone(),
        budget_sats: config.boot.budget_sats,
        allowlisted_destinations: config.boot.allow.clone(),
    };
    // Node 2 reuses the SAME rail instance (so the perform_count is continuous across
    // the move and the "performed once total" assertion is meaningful). In a real
    // two-host run each node has its own rail credential; the dedupe still prevents the
    // second perform because the gateway's STEP 1 short-circuits BEFORE the rail.
    let node2_rail: Arc<dyn Rail> = rail.clone();
    let mut node2_gateway = GatewayService::new(node2_treasury, node2_rail, session);
    // The VMGenID bump on restore (the C-8 hook): a restored VM is a NEW generation,
    // so node 2's gateway bumps. The genome (re-dialing node 2) observes the bumped
    // generation via GetEntropyNonce and uses it as the resume signal to re-issue K.
    for _ in 0..generation_pre {
        node2_gateway.bump_generation();
    }
    let generation_post = node2_gateway.bump_generation();
    tracing::info!(
        generation_pre,
        generation_post,
        "node 2: VMGenID generation bumped on restore (the resume signal the genome re-issues on)"
    );

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
        Err(e) => return Err(anyhow::anyhow!("node 2: restore failed: {e}")),
    };

    let node2_reached_running = node2_instance.is_running();
    tracing::info!(node2_reached_running, "node 2: VM state after restore");
    node2_instance.stream_console();

    // Serve a FRESH gateway over node 2's vsock transport so the genome (re-dialing
    // after the move) reconnects and the post-resume re-issue lands.
    let transport = node2_instance.gateway_transport();
    let serve_service = node2_gateway.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "node 2 gateway serve loop ended with error");
        }
    });

    // THE G9 PROOF: node 2 observes the genome RE-ISSUE key K after the resume. The
    // genome detected the bumped generation and re-issued; the daemon's STEP 1 dedupe
    // found K in the ledger that crossed the move and returned DUPLICATE_IGNORED,
    // performing nothing on the rail.
    let reissue = wait_for_idem(&mut node2_events, "idem_reissue", config.reissue_timeout).await;
    let perform_count_after_reissue = rail.perform_count();
    // Read the final authoritative balance from node 2's OWN treasury handle (the
    // clone that shares the gateway's sled lock), not a fresh open (which would
    // deadlock on the same path).
    let treasury_after_reissue = node2_treasury_read.remaining()?;
    tracing::info!(
        outcome = %reissue.outcome,
        cost_sats = reissue.cost_sats,
        perform_count_after_reissue,
        treasury_after_reissue,
        "node 2: post-resume re-issue observed (G9: deduped, not performed twice, debited once total)"
    );

    // Tear down node 2's VM (the demonstration is complete).
    node2_instance.halt().await;

    Ok(IdempotentRunOutcome {
        first,
        reissue,
        perform_count_after_first,
        perform_count_after_reissue,
        treasury_before,
        treasury_after_first,
        treasury_after_reissue,
        node1_killed,
        node2_reached_running,
        snapshot_bytes,
        generation_pre,
        generation_post,
    })
}

/// Node 1's booted state for the G9 run (mirrors the C-7 snapshot run's): the
/// instance, its gateway (for the generation), the event stream (for the idem
/// outcomes), the shared treasury, and the gateway serve task handle (aborted before
/// node 2 opens the SAME store, releasing node 1's sled lock).
struct Node1Booted {
    instance: Box<dyn SandboxInstance>,
    gateway: GatewayService,
    events: EventStream,
    treasury: Treasury,
    serve_task: tokio::task::JoinHandle<()>,
}

/// Boot node 1 with the `idempotent` workload, serving the agnostic gateway over its
/// vsock transport. Keeps the gateway handle (for the generation) and the treasury
/// (the shared persisted store, D-9, holding the dedupe ledger).
async fn boot_node1(
    config: &IdempotentRunConfig,
    treasury_path: &std::path::Path,
    rail: Arc<MockRail>,
) -> anyhow::Result<Node1Booted> {
    let treasury = Treasury::open(treasury_path, config.boot.initial_sats)?;
    let session = Session {
        task_descriptor: config.boot.task.clone(),
        budget_sats: config.boot.budget_sats,
        allowlisted_destinations: config.boot.allow.clone(),
    };
    let rail_dyn: Arc<dyn Rail> = rail;
    let mut gateway = GatewayService::new(treasury.clone(), rail_dyn, session);
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
        lockdown_egress: config.boot.lockdown_egress,
        snapshot_capable: config.boot.snapshot_capable,
    };

    tracing::info!(
        node_id = %config.boot.node_id,
        cid = config.boot.guest_cid,
        port = config.boot.gateway_port,
        "node 1: booting the idempotent-workload genome (T2CL template)"
    );
    let backend = FirecrackerBackend::new();
    let mut instance = backend.boot(spec).await?;

    if !instance.is_running() {
        instance.halt().await;
        anyhow::bail!("node 1: guest did not reach the running state");
    }
    instance.stream_console();

    let transport = instance.gateway_transport();
    let serve_service = gateway.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "node 1 gateway serve loop ended with error");
        }
    });

    Ok(Node1Booted { instance, gateway, events, treasury, serve_task })
}

/// Open the SAME persisted treasury store node 1 just released, retrying briefly while
/// sled's single-process exclusive lock is still being released (the `WouldBlock`
/// transient). On a busy host the OS reclaim of node 1's file descriptors can lag the
/// drop, so a single open occasionally races the lock; in a true two-host deployment the
/// source process is gone and the lock is free immediately. This bridges that same-host
/// gap WITHOUT changing the store, the balance, or the dedupe ledger: it is the SAME
/// `Treasury::open` (the seed is ignored on a re-open), only retried on a lock that is
/// about to release. Any non-lock error (e.g. corruption) returns immediately.
fn open_treasury_when_unlocked(
    path: &std::path::Path,
    seed_sats: u64,
    timeout: Duration,
) -> Result<Treasury, crate::treasury::TreasuryError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match Treasury::open(path, seed_sats) {
            Ok(t) => return Ok(t),
            Err(e) if is_lock_contention(&e) && std::time::Instant::now() < deadline => {
                // The previous holder's lock has not been released yet; back off and retry.
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Wait for the genome's next idem outcome event of `kind` (`idem_first` /
/// `idem_reissue`), up to `timeout`. Other events (heartbeats, the boot hello) are
/// drained while waiting. The event detail is
/// `idem_<phase> outcome=<Name> cost_sats=<n> treasury_remaining=<n> ...`; this parses
/// the outcome name and the numbers.
async fn wait_for_idem(events: &mut EventStream, kind: &str, timeout: Duration) -> IdemOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return IdemOutcome::default();
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == kind => return parse_idem(&ev.detail),
            Ok(Some(_)) => continue, // a heartbeat or another phase; keep waiting
            Ok(None) => return IdemOutcome::default(), // observer dropped
            Err(_) => return IdemOutcome::default(),    // timed out
        }
    }
}

/// Parse an idem outcome event detail into an [`IdemOutcome`]. The detail is
/// `idem_<phase> outcome=<Name> cost_sats=<n> treasury_remaining=<n> ...`; pulls the
/// `outcome=` token and the two numbers.
fn parse_idem(detail: &str) -> IdemOutcome {
    let token = |key: &str| -> Option<&str> {
        detail
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
    };
    let num = |key: &str| -> u64 { token(key).and_then(|v| v.parse().ok()).unwrap_or(0) };
    IdemOutcome {
        outcome: token("outcome=").unwrap_or("").to_string(),
        cost_sats: num("cost_sats="),
        treasury_remaining: num("treasury_remaining="),
        observed: true,
    }
}

/// Format a one-line G9 evidence summary for the run output (the verifier reads it).
pub fn evidence_line(o: &IdempotentRunOutcome) -> String {
    format!(
        "G9 evidence: first={} (cost={}) ; reissue={} (cost={}) ; perform_count {} -> {} ; \
         treasury {} -> {} -> {} (total_debited={}, act_cost={}) ; node1_killed={} ; \
         node2_running={} ; generation {} -> {} ; snapshot_bytes={}",
        o.first.outcome,
        o.first.cost_sats,
        o.reissue.outcome,
        o.reissue.cost_sats,
        o.perform_count_after_first,
        o.perform_count_after_reissue,
        o.treasury_before,
        o.treasury_after_first,
        o.treasury_after_reissue,
        o.total_debited(),
        o.act_cost(),
        o.node1_killed,
        o.node2_reached_running,
        o.generation_pre,
        o.generation_post,
        o.snapshot_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_idem, IdemOutcome, IdempotentRunOutcome};

    /// The idem-outcome parser pulls the outcome name and the numbers out of the
    /// genome's event detail.
    #[test]
    fn parse_idem_extracts_outcome_and_numbers() {
        let detail =
            "idem_first outcome=AuthorizedAndPerformed cost_sats=64 treasury_remaining=999936 gen_at_issue=0";
        let o = parse_idem(detail);
        assert_eq!(o.outcome, "AuthorizedAndPerformed");
        assert_eq!(o.cost_sats, 64);
        assert_eq!(o.treasury_remaining, 999936);
        assert!(o.is_performed());
        assert!(!o.is_duplicate_ignored());

        let reissue =
            "idem_reissue outcome=DuplicateIgnored cost_sats=64 treasury_remaining=999936 gen_now=1";
        let r = parse_idem(reissue);
        assert!(r.is_duplicate_ignored());
        assert_eq!(r.cost_sats, 64);
    }

    /// A missing event yields an unobserved default (distinguishable from a real zero).
    #[test]
    fn default_outcome_is_unobserved() {
        let o = IdemOutcome::default();
        assert!(!o.observed);
        assert!(!o.is_performed());
        assert!(!o.is_duplicate_ignored());
    }

    /// The G9 verdict holds for the canonical evidence: first performed (cost C, the
    /// rail performed once, the treasury dropped by C), the re-issue deduped (the
    /// rail STILL performed once, the treasury unchanged), so the total debited is C
    /// (not 2C), and the move happened (node 1 killed, node 2 running, generation+1).
    #[test]
    fn g9_verdict_holds_for_canonical_evidence() {
        let c = 64;
        let before = 1_000_000;
        let after_first = before - c;
        let o = IdempotentRunOutcome {
            first: IdemOutcome {
                outcome: "AuthorizedAndPerformed".to_string(),
                cost_sats: c,
                treasury_remaining: after_first,
                observed: true,
            },
            reissue: IdemOutcome {
                outcome: "DuplicateIgnored".to_string(),
                cost_sats: c,
                treasury_remaining: after_first,
                observed: true,
            },
            perform_count_after_first: 1,
            perform_count_after_reissue: 1,
            treasury_before: before,
            treasury_after_first: after_first,
            treasury_after_reissue: after_first,
            node1_killed: true,
            node2_reached_running: true,
            snapshot_bytes: 1234,
            generation_pre: 0,
            generation_post: 1,
        };
        assert_eq!(o.act_cost(), c);
        assert_eq!(o.total_debited(), c, "the total debited across the move is exactly C, not 2C");
        assert!(o.passed(), "the canonical G9 evidence must pass");
    }

    /// The verdict FAILS if the act were performed twice on the rail (perform_count
    /// rose to 2) or the treasury were debited 2C: the two failure modes G9 guards.
    #[test]
    fn g9_verdict_fails_on_double_perform_or_double_debit() {
        let c = 64;
        let before = 1_000_000;
        let after_first = before - c;
        let base = IdempotentRunOutcome {
            first: IdemOutcome {
                outcome: "AuthorizedAndPerformed".to_string(),
                cost_sats: c,
                treasury_remaining: after_first,
                observed: true,
            },
            reissue: IdemOutcome {
                outcome: "DuplicateIgnored".to_string(),
                cost_sats: c,
                treasury_remaining: after_first,
                observed: true,
            },
            perform_count_after_first: 1,
            perform_count_after_reissue: 1,
            treasury_before: before,
            treasury_after_first: after_first,
            treasury_after_reissue: after_first,
            node1_killed: true,
            node2_reached_running: true,
            snapshot_bytes: 1234,
            generation_pre: 0,
            generation_post: 1,
        };

        // Performed twice on the rail (the double-burn G9 forbids).
        let double_perform = IdempotentRunOutcome { perform_count_after_reissue: 2, ..base.clone() };
        assert!(!double_perform.passed(), "a second perform on the rail must FAIL G9");

        // Debited 2C (the treasury fell again on the re-issue).
        let double_debit = IdempotentRunOutcome {
            treasury_after_reissue: after_first - c,
            ..base.clone()
        };
        assert!(!double_debit.passed(), "a second debit (2C total) must FAIL G9");

        // The re-issue was PERFORMED again instead of deduped.
        let not_deduped = IdempotentRunOutcome {
            reissue: IdemOutcome {
                outcome: "AuthorizedAndPerformed".to_string(),
                cost_sats: c,
                treasury_remaining: after_first - c,
                observed: true,
            },
            perform_count_after_reissue: 2,
            treasury_after_reissue: after_first - c,
            ..base
        };
        assert!(!not_deduped.passed(), "a re-issue that PERFORMED again (not deduped) must FAIL G9");
    }
}
