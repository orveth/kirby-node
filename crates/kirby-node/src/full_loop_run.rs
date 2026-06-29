//! The C-11 capstone: the full-loop orchestration (spec C-11, gate G10 reproducibility
//! and clean-cut, composing G1-G9). ONE genome, ONE lease-driven failover, the WHOLE
//! survival arc end to end, proving the slices COMPOSE into one living organism.
//!
//! The previous chunks each proved ONE gate in its OWN test on its OWN VM. C-11 is
//! DIFFERENT: it is the SINGLE CONTINUOUS SCENARIO on ONE genome instance across ONE
//! failover, the thing the slices individually do NOT prove (that the whole chain
//! holds together end to end). This is "the loop," the demo.
//!
//! THE SURVIVAL ARC, in order, on ONE genome (each step asserted by the G11 test):
//!  1. BOOT (G1): the active lease-holder boots the genome microVM under the jailer;
//!     the genome completes a GetSessionContext round-trip over vsock (Running + the
//!     boot/heartbeat event).
//!  2. METER reads non-zero (G2 meter half, NOT death): the genome burns a little CPU;
//!     the daemon's cgroup meter accumulates > 0 and debits the treasury, but the
//!     budget is left with ample runway so the VM SURVIVES (the full-loop proves the
//!     LIVING organism; the budget-DEATH halt is G2's own separate terminal test).
//!  3. EGRESS DENIED throughout (G4): the genome attempts a raw outbound and it FAILS;
//!     the eBPF TAP egress counter shows ~0 IP bytes left the VM, asserted once
//!     mid-loop.
//!  4. BROKERED ACT (G5, the agency proof): the genome issues a RequestCapability with
//!     idempotency_key K = settle ecash on the LOCAL CDK fakewallet mint; the daemon
//!     authorizes it, PERFORMS it for real (the mint shows the spend), debits cost C
//!     (the treasury drops by exactly C), the VM issues NO raw network for it (the TAP
//!     egress stays ~0), and the rail credential never crosses vsock.
//!  5. SNAPSHOT + KILL + RESUME ON NODE 2 (G6, lease-driven, G8): the active node
//!     snapshots the running VM (CPU-template applied), the mem+state pair moves to the
//!     new active node, the source node is KILLED, the surviving 2-of-3 majority elects
//!     a new leader at T+1 that RESTORES the snapshot -> Running, and the genome
//!     completes a post-resume round-trip (survived the move).
//!  6. ENTROPY RE-DERIVED (G7): the post-resume fingerprint != the pre-snapshot one AND
//!     the generation bumped (VMGenID) AND the genome called GetEntropyNonce after
//!     resume before acting.
//!  7. IDEMPOTENT REPLAY (G9): the resumed genome re-issues the SAME key K; it is
//!     DUPLICATE_IGNORED, the act is NOT performed twice on the mint, and the treasury
//!     is debited by C EXACTLY ONCE total (not 2C).
//!  8. NO SPLIT-BRAIN (G8): the new active node claims the relay lease at T+1
//!     (latest-term-wins); reviving the source node still believing term T, it
//!     REFUSES to run/debit (term-fenced), no second VM, the treasury debited by at
//!     most one node, and no observed term boundary shows two actives.
//!
//! This module composes the EXISTING machinery, already individually green: the
//! [`crate::relay_lease`] lease/fence (G8), the [`crate::sandbox`] snapshot/transfer/
//! restore primitives the [`crate::firecracker`] backend implements (G6, the SAME
//! UNCHANGED C-7 path), the [`crate::gateway`] authorize order + the persisted
//! [`crate::treasury`] (G3/G5/G9), the real [`crate::rail::CdkEcashRail`] + the local
//! mint the C-6 path uses (G5), the [`crate::meter`] cgroup meter (G2), and the
//! [`crate::meter_egress`] eBPF TAP byte meter (G4). It reinvents nothing; C-11 is the
//! INTEGRATION of slices that already exist.
//!
//! PRESERVED: the agnostic core (gateway authorize-order, treasury economics, rail,
//! genome) is unchanged; the lease GATES the run + debit (it does not change what they
//! do); the restore is the UNCHANGED C-7 firecracker path (the D-7 jailer boundary, the
//! transfer seam); D-9 holds (ONE persisted treasury + ONE dedupe ledger across the
//! move, no double-store); C-8 entropy + C-9 lease are intact.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kirby_proto::Event;

use crate::boot::{EventStream, ImagePaths};
use crate::firecracker::FirecrackerBackend;
use crate::gateway::{GatewayService, Session};
use crate::meter::{Meter, MeterConfig};
use crate::meter_egress::EgressMeter;
use crate::lease::{FenceVerdict, LeaseAuthority, LeaseNodeId};
use crate::rail::Rail;
use crate::sandbox::{
    GuestImage, GuestSpec, LocalDirTransfer, MeterSource, RestoreSpec, SandboxBackend,
    SandboxInstance, SnapshotTransfer,
};
use crate::treasury::{DebitOutcome, Treasury};

/// The three spike node ids (D-14): a true 2-of-3 majority survives losing one.
const NODE_IDS: [LeaseNodeId; 3] = [1, 2, 3];

/// Inputs for the C-11 full-loop run. Reuses the genome image; the 3-node lease
/// cluster, the same-host transfer seam, the shared treasury, and the per-VM TAP are
/// all derived. The caller supplies the rail and the allowlisted mint id (the brokered
/// act's destination, gate G5).
pub struct FullLoopConfig {
    /// The genome image (kernel + rootfs), pre-staged on every node (D-8).
    pub image_dir: PathBuf,
    /// The session task descriptor handed to the genome (non-secret).
    pub task: String,
    /// The allowlisted destination the brokered act settles against (the local mint
    /// URL, gate G5). Both the active node and the restored node use it.
    pub allow_mint: String,
    /// The vsock guest CID for the active node's VM. The restored VM reuses it (the
    /// killed node is gone before the restore runs, so no collision on one host).
    pub vsock_cid: u32,
    /// The gateway vsock port the genome dials and the active node serves on. The
    /// restored genome re-dials the SAME port (it read it from its kernel cmdline once
    /// at boot, frozen in the snapshot).
    pub gateway_port: u32,
    /// vCPU count and memory for the genome microVM. Small for the spike (keeps the
    /// snapshot mem file small and the run quick).
    pub vcpu_count: u8,
    pub mem_mib: usize,
    /// The starting treasury balance, large enough that the brokered act (cost C) and
    /// the metered CPU burn leave ample runway (the full-loop proves SURVIVAL, not the
    /// budget-death halt, which is G2's own test).
    pub initial_sats: u64,
    /// How long to wait for the genome's brokered act (`idem_first`) on the active node.
    pub first_act_timeout: Duration,
    /// How long to wait for the new active node's post-resume heartbeat round-trip.
    pub post_resume_timeout: Duration,
    /// How long to wait for the resumed genome's re-issue (`idem_reissue`).
    pub reissue_timeout: Duration,
    /// The metering tick (the cgroup CPU/memory meter, gate G2 survival half).
    pub meter_tick: Duration,
    /// The eBPF reporting tick for the privileged egress meter child (gate G4).
    pub egress_tick: Duration,
}

impl FullLoopConfig {
    /// A full-loop run config from a genome image dir and the allowlisted mint URL,
    /// with spike-sane defaults. The CID/port range is distinct from the other gates
    /// so the run is isolated.
    pub fn new(image_dir: PathBuf, allow_mint: String) -> Self {
        FullLoopConfig {
            image_dir,
            task: "c11-full-loop".to_string(),
            allow_mint,
            vsock_cid: 41,
            gateway_port: 5041,
            vcpu_count: 1,
            mem_mib: 128,
            // Ample runway: the act costs a handful of sats and the metered CPU burn is
            // small, so 1_000_000 leaves the VM alive (survival, not budget-death).
            initial_sats: 1_000_000,
            first_act_timeout: Duration::from_secs(40),
            post_resume_timeout: Duration::from_secs(40),
            reissue_timeout: Duration::from_secs(40),
            meter_tick: Duration::from_millis(100),
            egress_tick: Duration::from_millis(100),
        }
    }
}

/// One brokered outcome the genome reported (parsed from an `idem_first` /
/// `idem_reissue` event): the outcome name, the cost the genome was told, the
/// post-act balance, and the rail proof length.
#[derive(Debug, Clone, Default)]
pub struct ActOutcome {
    /// The outcome name the genome reported (e.g. `AuthorizedAndPerformed`,
    /// `DuplicateIgnored`). Empty if no event arrived.
    pub outcome: String,
    /// The cost the genome was told on its receipt (sats).
    pub cost_sats: u64,
    /// The post-act treasury balance the genome was told.
    pub treasury_remaining: u64,
    /// The length of the rail proof the genome received (the mint preimage on the
    /// first act; the prior receipt's proof on the dedupe).
    pub proof_len: u64,
    /// True iff an event actually arrived (so a missing outcome is distinguishable from
    /// a genuine zero).
    pub observed: bool,
}

impl ActOutcome {
    /// True iff the genome reported AUTHORIZED_AND_PERFORMED (the first act, gate G5).
    pub fn is_performed(&self) -> bool {
        self.observed && self.outcome == "AuthorizedAndPerformed"
    }

    /// True iff the genome reported DUPLICATE_IGNORED (the post-resume re-issue, G9).
    pub fn is_duplicate_ignored(&self) -> bool {
        self.observed && self.outcome == "DuplicateIgnored"
    }
}

/// The full G11 evidence: one field (or group) per composed gate, all from ONE run.
#[derive(Debug, Clone)]
pub struct FullLoopOutcome {
    // ---- G8 (lease / no-split-brain): the consensus frame the whole loop runs in ----
    /// The leader elected at bring-up (the first active node, the genome's birthplace).
    pub elected_leader: LeaseNodeId,
    /// The term the lease was first granted at (the active node is active @ T).
    pub term_t: u64,
    /// The active node that was killed (the leader) after the snapshot.
    pub killed_node: LeaseNodeId,
    /// The new leader the 2-of-3 majority elected after the kill (survive-one-loss).
    pub new_leader: LeaseNodeId,
    /// The strictly-higher term the handoff committed the lease at (T+1).
    pub term_t1: u64,
    /// The revived stale node (believing the old term T) was FENCED: it refused to
    /// run/debit (no second VM, no double-execute, gate G8).
    pub revived_stale_fenced: bool,
    /// True iff, at ANY observed instant across the run, two nodes both reported active
    /// (the G8 linearizability invariant requires this stays FALSE).
    pub two_actives_ever_observed: bool,

    // ---- G1 (boot) ----
    /// The genome completed a boot/heartbeat round-trip on the active node (Running +
    /// the vsock GetSessionContext round-trip landed).
    pub boot_round_trip: bool,

    // ---- G2 (meter half: non-zero burn, SURVIVAL not death) ----
    /// The cgroup CPU/memory meter accumulated > 0 sats on the active node (the genome
    /// burned real CPU; the host meter billed it). NOT exhausted: the VM survives.
    pub metered_burn_sats: u64,
    /// The treasury balance right after the metered burn (dropped from the start by the
    /// burn, but with ample runway remaining, so the VM is alive).
    pub treasury_after_meter: u64,

    // ---- G4 (egress denied, asserted once mid-loop) ----
    /// The genome reported its raw-egress probe DENIED (no leak), parsed from its
    /// `raw_egress_result` event.
    pub egress_denied: bool,
    /// The eBPF classifier's cumulative egress bytes the VM put on its TAP during the
    /// loop. ~0 under the lockdown (gate G4 + G5(iv)): no real IP traffic flowed, and
    /// the brokered act left via the daemon HOST net, not the VM TAP.
    pub ebpf_egress_bytes: u64,

    // ---- G5 (the brokered act, the agency proof) ----
    /// The genome's FIRST act outcome on the active node (expected
    /// AUTHORIZED_AND_PERFORMED).
    pub first: ActOutcome,
    /// The rail's wallet balance BEFORE the brokered act (the host-only credential).
    pub wallet_before: u64,
    /// The rail's wallet balance AFTER the brokered act (it DROPPED: the settle was
    /// real, the mint moved the wallet's proofs, gate G5(ii)).
    pub wallet_after: u64,
    /// The count of the wallet's pre-act input proofs the MINT shows SPENT after the
    /// act (> 0 = a real settle on the real mint, not a mock, gate G5(ii)).
    pub mint_spent_proof_count: u64,
    /// The daemon-authoritative treasury balance BEFORE the brokered act (D-9).
    pub treasury_before_act: u64,
    /// The daemon-authoritative treasury balance AFTER the brokered act (dropped by
    /// exactly the act cost C, gate G5(iii)).
    pub treasury_after_act: u64,

    // ---- G6 (snapshot + cross-node resume, lease-driven) ----
    /// The new active node brought the genome VM to Running FROM the killed node's
    /// snapshot (the C-7 restore the lease drove, not a cold boot).
    pub node2_reached_running: bool,
    /// The genome survived the move: a post-resume heartbeat landed on the new active
    /// node (it re-dialed the new node's gateway after its vsock dropped).
    pub post_resume_round_trip: bool,
    /// The snapshot mem+vmstate footprint that crossed the transfer seam, in bytes.
    pub snapshot_bytes: u64,

    // ---- G7 (entropy re-derived on resume) ----
    /// The entropy fingerprint the genome reported on the active node BEFORE the
    /// snapshot (derived from a fresh GetEntropyNonce at the pre-snapshot generation).
    pub fingerprint_pre: Option<String>,
    /// The entropy fingerprint the genome reported on the new active node AFTER the
    /// resume (re-derived from a fresh GetEntropyNonce at the bumped generation). For a
    /// correct genome this DIFFERS from `fingerprint_pre` (gate G7).
    pub fingerprint_post: Option<String>,
    /// The VMGenID generation the active node's gateway was at before the snapshot.
    pub generation_pre: u64,
    /// The VMGenID generation the new active node's gateway is at after the restore
    /// bump (must be `generation_pre + 1`).
    pub generation_post: u64,
    /// True iff the new active node observed the genome call GetEntropyNonce at the
    /// bumped generation AFTER the resume and BEFORE its first post-resume act (gate
    /// G7 ordering: re-derived before acting).
    pub entropy_call_before_post_resume_act: bool,

    // ---- G9 (idempotent replay across resume) ----
    /// The genome's RE-ISSUE outcome on the new active node after the resume (expected
    /// DUPLICATE_IGNORED).
    pub reissue: ActOutcome,
    /// The rail's perform count AFTER the first act (the act performed exactly once: 1).
    pub perform_count_after_first: u64,
    /// The rail's perform count AFTER the post-resume re-issue (STILL 1: the dedupe
    /// short-circuits before the rail, so the act is NOT performed twice).
    pub perform_count_after_reissue: u64,
    /// The daemon-authoritative treasury balance the new active node sees AFTER the
    /// resume + re-issue (UNCHANGED from `treasury_after_act` by the dedupe, so the act
    /// cost C is debited EXACTLY ONCE total across the move, not 2C).
    pub treasury_after_reissue: u64,
}

impl FullLoopOutcome {
    /// The act cost C (the brokered act's cost on the active node). Equals the treasury
    /// drop the act caused.
    pub fn act_cost(&self) -> u64 {
        self.first.cost_sats
    }

    /// The treasury drop the brokered act caused on the active node (must equal C, G5(iii)).
    /// The act debits C; the boot heartbeats never bill (ReportEvent is advisory, G3c), so
    /// the drop from the boot balance to the post-act balance is exactly the act cost C.
    pub fn act_treasury_drop(&self) -> u64 {
        self.treasury_before_act.saturating_sub(self.treasury_after_act)
    }

    /// What the post-resume re-issue of K ADDED to the treasury drop across the move (G9).
    /// After node 1 acted (C) and metered (a small CPU burn), the handoff balance is
    /// `treasury_after_meter`; node 2 opens the SAME store and the re-issue is DEDUPED, so
    /// it debits NOTHING and the post-reissue balance EQUALS the handoff balance. This MUST
    /// be 0 (the act is not performed or charged a second time, no 2C).
    pub fn reissue_added_debit(&self) -> u64 {
        self.treasury_after_meter.saturating_sub(self.treasury_after_reissue)
    }

    /// The composite G11 verdict: every composed gate held in ONE continuous run. This
    /// is the whole-organism proof, not any single slice.
    pub fn passed(&self, ebpf_zero_ceiling: u64) -> bool {
        // G1: the genome booted and round-tripped.
        self.boot_round_trip
            // G2 (meter half): the host meter billed real CPU (> 0), with the VM still
            // alive (the treasury fell but kept ample runway: this is survival, not the
            // budget-death halt). We assert burn > 0 and a non-zero remaining.
            && self.metered_burn_sats > 0
            && self.treasury_after_meter > 0
            // G4: the genome's raw egress was DENIED and the eBPF TAP egress stayed ~0.
            && self.egress_denied
            && self.ebpf_egress_bytes <= ebpf_zero_ceiling
            // G5: the brokered act AUTHORIZED + PERFORMED for real (the mint moved), a
            // non-zero cost C debited, the treasury dropped by exactly C, and the VM
            // issued no raw network for it (the eBPF ~0 above).
            && self.first.is_performed()
            && self.act_cost() > 0
            && self.act_treasury_drop() == self.act_cost()
            && self.wallet_after < self.wallet_before
            && self.mint_spent_proof_count > 0
            && self.first.proof_len > 0
            // G8: survive-one-loss handoff at T+1, the revived stale node fenced, no two
            // actives ever observed.
            && self.new_leader != self.killed_node
            && self.term_t1 > self.term_t
            && self.revived_stale_fenced
            && !self.two_actives_ever_observed
            // G6: the new active node restored the VM from the snapshot and the genome
            // survived the move.
            && self.node2_reached_running
            && self.post_resume_round_trip
            // G7: the entropy was re-derived (the fingerprints differ), the generation
            // bumped, and the genome called GetEntropyNonce after resume before acting.
            && self.fingerprints_differ()
            && self.generation_post == self.generation_pre + 1
            && self.entropy_call_before_post_resume_act
            // G9: the re-issue across the move was DEDUPED, the act NOT performed twice
            // on the rail, and the re-issue debited NOTHING (the handoff balance is
            // unchanged across the move, so the act is charged C ONCE total, not 2C).
            && self.reissue.is_duplicate_ignored()
            && self.perform_count_after_first == 1
            && self.perform_count_after_reissue == 1
            && self.treasury_after_reissue == self.treasury_after_meter
            && self.reissue_added_debit() == 0
            && self.reissue.cost_sats == self.act_cost()
    }

    /// True iff the pre-snapshot and post-resume fingerprints both landed AND DIFFER
    /// (the entropy was genuinely re-derived on resume, gate G7).
    pub fn fingerprints_differ(&self) -> bool {
        match (&self.fingerprint_pre, &self.fingerprint_post) {
            (Some(pre), Some(post)) => pre != post,
            _ => false,
        }
    }
}

/// Run the WHOLE C-11 survival arc on ONE genome across ONE lease-driven failover.
/// Composes the lease cluster (G8), the active-node boot of the `full-loop` genome
/// with a locked-down TAP + the real rail (G1/G4/G5), the cgroup CPU meter (G2
/// survival) and the eBPF TAP egress meter (G4), the brokered act (G5), the snapshot +
/// kill + lease-driven restore on the new active node (G6), the entropy fingerprint
/// capture (G7), the dedupe-across-resume re-issue (G9), and the revive-and-fence of
/// the stale node (G8). All VMs and lease nodes are torn down before returning
/// (including on an error path).
///
/// The `rail` is the real [`crate::rail::CdkEcashRail`] over a funded wallet (the C-6
/// path); the SAME rail instance is used on the active node and the restored node so
/// the perform_count is continuous across the move (the "performed once total" G9
/// proof is meaningful). The mint is booted by the G11 test (cdk-mintd, dev-only).
///
/// `perform_count` is a cheap reader of the rail's perform count (e.g. the
/// `CdkEcashRail::perform_count`), so the orchestration can prove the act was performed
/// EXACTLY ONCE across the move (1 -> 1) without depending on the concrete rail type.
/// The G5(ii) wallet-balance + mint-spent-proof checks are filled by the TEST directly
/// against the rail and the mint (the brokered_act pattern), so the returned outcome
/// leaves `wallet_before`/`wallet_after`/`mint_spent_proof_count` at 0 for the test to
/// populate before asserting `passed`.
pub async fn run(
    config: FullLoopConfig,
    rail: Arc<dyn Rail>,
    perform_count: impl Fn() -> u64,
) -> anyhow::Result<FullLoopOutcome> {
    let image = ImagePaths::from_dir(&config.image_dir)?;

    // The ONE shared persisted treasury (D-9): the active node's gateway debits it, the
    // cgroup meter debits it, and the new active node CONTINUES the same balance + the
    // same dedupe ledger after the handoff. A fenced node never reaches it. A per-run
    // path keeps runs distinct; a clean store per run avoids a stale ledger.
    let treasury_path =
        std::env::temp_dir().join(format!("kirby-c11-treasury-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&treasury_path);

    // ---- G8 frame: the relay-lease fabric over the 3 node ids (#9) ----
    // The loopback Raft cluster was CUT; failover now rides the relay-native FROST-signed
    // lease. The first node is the initial active holder (no leader election -- latest-term-wins
    // is the linearization). A KILLED node is dropped from the live observer set so its stale
    // in-process authority is not counted as a live active node (the C-9 same-host note).
    let mut fabric = LeaseFabric::new(&NODE_IDS)?;
    let elected_leader = NODE_IDS[0];
    tracing::info!(leader = elected_leader, "C11: relay-lease fabric up (the consensus frame the loop runs in)");

    let mut two_actives_ever = false;
    fabric.sample_actives(&mut two_actives_ever).await;

    // The first node CLAIMS the lease @ T=1: it is the active node, the genome's birthplace.
    let term_t = fabric.claim(elected_leader, 1).await?;
    tracing::info!(node = elected_leader, term = term_t, "C11: lease claimed (active node @ T; it may run + debit)");
    fabric.sample_actives(&mut two_actives_ever).await;
    let active_handle = fabric.authority(elected_leader)?;

    // ---- STEPS 1-4 on the active node: BOOT (G1), the locked-down TAP + real rail,
    // METER (G2 survival), EGRESS DENIED (G4), the BROKERED ACT (G5). ----
    let booted = boot_active_node(&config, &image, &treasury_path, elected_leader, rail.clone()).await;
    let ActiveNode {
        mut instance,
        gateway,
        mut events,
        treasury,
        serve_task,
    } = match booted {
        Ok(b) => b,
        Err(e) => {
            return Err(e);
        }
    };

    // Resolve the per-VM TAP (lockdown was forced on) and attach the eBPF egress meter
    // (gate G4 + G5(iv) instrument) and the cgroup CPU/memory meter (gate G2 survival
    // half). On any failure: halt the VM (the in-memory lease fabric drops on its own).
    let setup = setup_meters(&config, instance.as_ref(), treasury.clone()).await;
    let (egress_meter, mut cpu_meter) = match setup {
        Ok(m) => m,
        Err(e) => {
            instance.halt().await;
            return Err(e);
        }
    };

    // The authoritative treasury BEFORE anything debits it (D-9).
    let treasury_at_boot = treasury.remaining()?;

    // STEPS 1, 3-front, 4 (G1, G4, G5) in ONE observation pass (no event discarded): the
    // `full-loop` genome, once up, attempts a raw egress (G4), issues the brokered act
    // with key K (G5), then heartbeats with the entropy fingerprint (G1 + G7 baseline).
    // We drain events until we have captured ALL of: the boot/heartbeat round-trip (G1 +
    // `fingerprint_pre`), the `raw_egress_result` (G4), and the `idem_first` act (G5).
    // A single drain is required because these arrive interleaved and a separate
    // boot-wait would discard the act/egress events it skipped past.
    let generation_pre = gateway.vm_generation();
    let observed = observe_active_arc(&mut events, config.first_act_timeout).await;
    let boot_round_trip = observed.boot_round_trip;
    let fingerprint_pre = observed.fingerprint_pre.clone();
    let egress_denied = observed.egress_denied;
    let first = observed.act.clone();
    let treasury_after_act = treasury.remaining()?;
    // The act debited from the boot balance (nothing else debits before the meter ticks
    // run below; the act and the boot heartbeats do not debit the treasury, only the
    // metered CPU does). treasury_before_act is the boot balance.
    let treasury_before_act = treasury_at_boot;
    let perform_count_after_first = perform_count();
    if !boot_round_trip {
        teardown_active(instance, egress_meter, cpu_meter, serve_task, gateway, treasury).await;
        anyhow::bail!("C11: the active node's genome did not complete a boot round-trip (G1)");
    }
    tracing::info!(
        boot_round_trip,
        fingerprint_pre = fingerprint_pre.as_deref().unwrap_or("<none>"),
        generation_pre,
        egress_denied,
        act = %first.outcome,
        "C11: G1 boot + G4 egress denied + G5 brokered act observed in one pass (the genome is alive and acted)"
    );

    // STEP 2 (G2 meter half): tick the cgroup CPU/memory meter a few times while the
    // genome runs. It accumulates > 0 sats (the genome's heartbeat loop burns real CPU)
    // and debits the treasury, but we tick only a FEW times so the budget keeps ample
    // runway: the VM SURVIVES (the full-loop is the LIVING organism; budget-DEATH is
    // G2's own test). The lease gates the debit: the active node holds the lease @ T, so
    // metering it is exactly the active node billing its own genome.
    anyhow::ensure!(
        matches!(active_handle.fence_for(LOOP_AGENT, term_t).await, FenceVerdict::Active { .. }),
        "C11: the active node must hold the lease @ T to meter + debit its genome (G8)"
    );
    let metered_burn_sats = meter_a_little(&mut cpu_meter, 12).await;
    let treasury_after_meter = treasury.remaining()?;
    tracing::info!(
        metered_burn_sats,
        treasury_after_meter,
        "C11: G2 meter half: the cgroup meter billed real CPU (> 0) and the VM SURVIVES (ample runway, not budget-death)"
    );

    // G4 + G5(iv): the eBPF TAP egress counter, read once mid-loop. ~0 IP bytes: the
    // genome's raw egress was dropped AND the brokered act left via the daemon HOST net,
    // not the VM TAP. Read it now (before the snapshot), then shut the eBPF meter down.
    let ebpf_egress_bytes = egress_meter.egress_bytes();
    tracing::info!(
        outcome = %first.outcome,
        cost_sats = first.cost_sats,
        treasury_before_act,
        treasury_after_act,
        egress_denied,
        ebpf_egress_bytes,
        "C11: G5 brokered act observed + G4 egress denied (eBPF TAP egress ~0; the act left via the daemon HOST net)"
    );
    // The eBPF meter is no longer needed (the egress evidence is captured); detach it
    // before the snapshot so the privileged child does not linger across the move.
    egress_meter.shutdown().await;

    if !first.is_performed() {
        instance.halt().await;
        cpu_meter_drop(cpu_meter);
        serve_task.abort();
        drop(gateway);
        drop(treasury);
        anyhow::bail!(
            "C11: the active node's genome did not AUTHORIZE_AND_PERFORM the brokered act (got {:?}); cannot run the loop (G5)",
            first.outcome
        );
    }

    // ---- STEP 5a (G6): snapshot the running VM (the C-7 pair). ----
    tracing::info!("C11: snapshotting the running VM (the C-7 path; K's ledger entry is already durable on disk)");
    let artifact = match instance.snapshot().await {
        Ok(a) => a,
        Err(e) => {
            instance.halt().await;
            cpu_meter_drop(cpu_meter);
            serve_task.abort();
            drop(gateway);
            drop(treasury);
            return Err(anyhow::anyhow!("C11: snapshot failed: {e}"));
        }
    };
    let transfer_dir = std::env::temp_dir().join(format!("kirby-c11-snap-{}", std::process::id()));
    let transferred = LocalDirTransfer { target_dir: transfer_dir.clone() }
        .transfer(artifact)
        .await?;
    let snapshot_bytes = transferred.footprint_bytes();
    tracing::info!(bytes = snapshot_bytes, "C11: snapshot pair staged for the surviving majority (D-13 seam)");

    // ---- STEP 5b (G8): KILL the active node (its VM; drop it from the live lease set). ----
    tracing::info!(node = elected_leader, "C11: KILLING the active node (VM + lease holder); the surviving majority must carry the genome");
    instance.halt().await;
    cpu_meter_drop(cpu_meter); // release the meter's treasury clone (the sled lock)
    serve_task.abort();
    drop(gateway);
    drop(treasury); // release the sled lock so the new active node opens the SAME store
    fabric.kill(elected_leader);
    // Let the aborted serve task drop its treasury clone before node 2 opens the store.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    fabric.sample_actives(&mut two_actives_ever).await;

    // ---- STEP 5c (G8): a surviving node CLAIMS the lease at T+1 (the failover takeover). ----
    // The relay-lease has no leader election -- a survivor publishes term+1 and latest-wins
    // supersedes the dead holder's term (the relay-native equivalent of survive-one-loss).
    let new_leader = NODE_IDS
        .iter()
        .copied()
        .find(|&id| id != elected_leader)
        .ok_or_else(|| anyhow::anyhow!("C11: no surviving node to take over after the kill (G8)"))?;
    let term_t1 = fabric.claim(new_leader, term_t + 1).await?;
    anyhow::ensure!(
        term_t1 > term_t,
        "C11: the handoff must claim the lease at a strictly higher term (T+1): got {term_t1}, was {term_t} (G8)"
    );
    tracing::info!(new_leader, term = term_t1, "C11: survive-one-loss handoff claimed (new active node @ T+1)");
    fabric.sample_actives(&mut two_actives_ever).await;

    // ---- STEP 5d (G6): the new active node RESTORES the snapshot (the C-7 path) and
    // continues. It opens the SAME persisted treasury (D-9, the ledger crossed). The
    // handoff balance is `treasury_after_meter` (the act debited C + the cgroup metered a
    // small CPU burn, both before the snapshot); node 2 continues THAT balance. ----
    let restored = restore_on_new_active(
        &config,
        &image,
        &treasury_path,
        treasury_after_meter,
        new_leader,
        generation_pre,
        rail.clone(),
        transferred,
    )
    .await;
    let RestoredNode {
        instance,
        node2_reached_running,
        post,
        treasury: node2_treasury,
        treasury_read: node2_treasury_read,
        serve_task: node2_serve,
        events: mut node2_events,
    } = match restored {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&transfer_dir);
            return Err(anyhow::anyhow!("C11: restore on the new active node failed: {e}"));
        }
    };

    // The post-resume observation (G6 survival + G7 ordering + fingerprint_post).
    let post_resume_round_trip = post.heartbeat.is_some();
    let fingerprint_post = post.heartbeat.as_ref().and_then(|e| parse_fingerprint(&e.detail));
    let entropy_call_before_post_resume_act = post.entropy_call_before_act;
    let generation_post = post.generation_post;
    tracing::info!(
        node2_reached_running,
        post_resume_round_trip,
        fingerprint_post = fingerprint_post.as_deref().unwrap_or("<none>"),
        entropy_call_before_post_resume_act,
        generation_pre,
        generation_post,
        "C11: G6 the genome survived the lease-driven move + G7 it re-derived its entropy on the new active node"
    );

    // ---- STEP 7 (G9): the resumed genome RE-ISSUES key K -> DUPLICATE_IGNORED. ----
    let reissue = wait_for_act(&mut node2_events, "idem_reissue", config.reissue_timeout).await;
    let perform_count_after_reissue = perform_count();
    let treasury_after_reissue = node2_treasury_read.remaining()?;
    tracing::info!(
        outcome = %reissue.outcome,
        cost_sats = reissue.cost_sats,
        perform_count_after_first,
        perform_count_after_reissue,
        treasury_after_reissue,
        "C11: G9 the resumed genome re-issued K -> deduped, NOT performed twice, debited C once total"
    );

    // ---- STEP 8 (G8): REVIVE the killed node still believing term T. It must be FENCED. ----
    tracing::info!(node = elected_leader, believed_term = term_t, "C11: REVIVING the source node (stale, believing T); it must be FENCED (no second VM, G8)");
    // The revived node comes back as a FRESH authority that catches up on the latest published
    // lease via the relay (term T+1, another holder), so its fence sees the higher term that
    // superseded its old belief (spec 4.3), not merely "no lease".
    let revived_handle = fabric.revive_stale(elected_leader).await?;
    let stale_verdict = revived_handle.fence_for(LOOP_AGENT, term_t).await;
    let revived_stale_fenced = !stale_verdict.may_act();
    tracing::info!(?stale_verdict, "C11: revived stale node fence verdict (it sees the higher term T+1)");
    // The fenced node must not debit (no double-burn).
    let stale_debit = lease_gated_debit(&revived_handle, term_t, &node2_treasury, 777_777).await;
    anyhow::ensure!(
        stale_debit.is_none(),
        "C11: the revived stale node must NOT debit (it is fenced; no double-burn, G8)"
    );
    anyhow::ensure!(
        node2_treasury.remaining()? == treasury_after_reissue,
        "C11: the treasury must be UNCHANGED by the fenced stale node (no double-burn, G8)"
    );
    fabric.sample_actives(&mut two_actives_ever).await;

    // ---- Teardown ----
    instance.halt().await;
    node2_serve.abort();
    drop(node2_treasury);
    drop(node2_treasury_read);
    let _ = std::fs::remove_dir_all(&transfer_dir);
    let _ = std::fs::remove_dir_all(&treasury_path);

    Ok(FullLoopOutcome {
        elected_leader,
        term_t,
        killed_node: elected_leader,
        new_leader,
        term_t1,
        revived_stale_fenced,
        two_actives_ever_observed: two_actives_ever,
        boot_round_trip,
        metered_burn_sats,
        treasury_after_meter,
        egress_denied,
        ebpf_egress_bytes,
        first,
        // The G5(ii) wallet-balance + mint-spent-proof checks are populated by the test
        // directly against the rail and the mint (the brokered_act pattern); the
        // orchestration leaves them at 0 for the test to fill before asserting `passed`.
        wallet_before: 0,
        wallet_after: 0,
        mint_spent_proof_count: 0,
        treasury_before_act,
        treasury_after_act,
        node2_reached_running,
        post_resume_round_trip,
        snapshot_bytes,
        fingerprint_pre,
        fingerprint_post,
        generation_pre,
        generation_post,
        entropy_call_before_post_resume_act,
        reissue,
        perform_count_after_first,
        perform_count_after_reissue,
        treasury_after_reissue,
    })
}

/// Format a one-line G11 evidence summary (the verifier reads it).
pub fn evidence_line(o: &FullLoopOutcome) -> String {
    format!(
        "G11 evidence: boot_round_trip={} ; metered_burn={} (treasury_after_meter={}) ; \
         egress_denied={} ebpf_egress_bytes={} ; act={} (cost={} proof_len={}) ; \
         wallet {} -> {} mint_spent_proofs={} ; treasury_before_act={} treasury_after_act={} ; \
         leader={} term_t={} killed={} new_leader={} term_t1={} revived_stale_fenced={} two_actives_ever={} ; \
         node2_running={} post_resume_round_trip={} snapshot_bytes={} ; \
         fingerprint_pre={} fingerprint_post={} generation {} -> {} entropy_call_before_act={} ; \
         reissue={} perform_count {} -> {} treasury_after_reissue={} (reissue_added_debit={}, act_cost={})",
        o.boot_round_trip,
        o.metered_burn_sats,
        o.treasury_after_meter,
        o.egress_denied,
        o.ebpf_egress_bytes,
        o.first.outcome,
        o.first.cost_sats,
        o.first.proof_len,
        o.wallet_before,
        o.wallet_after,
        o.mint_spent_proof_count,
        o.treasury_before_act,
        o.treasury_after_act,
        o.elected_leader,
        o.term_t,
        o.killed_node,
        o.new_leader,
        o.term_t1,
        o.revived_stale_fenced,
        o.two_actives_ever_observed,
        o.node2_reached_running,
        o.post_resume_round_trip,
        o.snapshot_bytes,
        o.fingerprint_pre.as_deref().unwrap_or("<none>"),
        o.fingerprint_post.as_deref().unwrap_or("<none>"),
        o.generation_pre,
        o.generation_post,
        o.entropy_call_before_post_resume_act,
        o.reissue.outcome,
        o.perform_count_after_first,
        o.perform_count_after_reissue,
        o.treasury_after_reissue,
        o.reissue_added_debit(),
        o.act_cost(),
    )
}

// ---------------------------------------------------------------------------
// The active-node boot (G1, G4, G5) and the meter attach (G2, G4).
// ---------------------------------------------------------------------------

/// The active node's booted genome plus the handles the orchestration needs.
struct ActiveNode {
    instance: Box<dyn SandboxInstance>,
    gateway: GatewayService,
    events: EventStream,
    treasury: Treasury,
    serve_task: tokio::task::JoinHandle<()>,
}

/// Boot the `full-loop` genome on the active node (the lease leader @ T): a
/// snapshot-capable, EGRESS-LOCKED-DOWN VM with the real rail injected, serving the
/// agnostic gateway over its vsock. Mirrors the C-7/C-9 active boot but forces the TAP
/// lockdown (so the egress G4 + the brokered-act G5(iv) hold) and the `full-loop`
/// workload, and injects the real rail (so the brokered act settles for real, G5).
async fn boot_active_node(
    config: &FullLoopConfig,
    image: &ImagePaths,
    treasury_path: &std::path::Path,
    active_node: LeaseNodeId,
    rail: Arc<dyn Rail>,
) -> anyhow::Result<ActiveNode> {
    let treasury = Treasury::open(treasury_path, config.initial_sats)?;
    let session = Session {
        task_descriptor: config.task.clone(),
        budget_sats: config.initial_sats,
        allowlisted_destinations: vec![config.allow_mint.clone()],
        allowlisted_inbound_kinds: Vec::new(),
    };
    let mut gateway = GatewayService::new(treasury.clone(), rail, session);
    let events = gateway.observe_events();

    let spec = GuestSpec {
        image: GuestImage { kernel: image.vmlinux.clone(), rootfs: image.rootfs.clone() },
        instance_id: format!("c11-active-{active_node}"),
        guest_cid: config.vsock_cid,
        gateway_port: config.gateway_port,
        vcpu_count: config.vcpu_count,
        mem_size_mib: config.mem_mib,
        workload: Some("full-loop".to_string()),
        // Not the brain workload: no brain rail, no brain cmdline params.
        brain: None,
        memory: None,
        agent: None,
        // The egress lockdown is ON throughout (gate G4 + G5(iv)): the VM gets a TAP it
        // can ATTEMPT egress on, the host kernel drops it, and the eBPF meter counts ~0.
        lockdown_egress: true,
        // Snapshot-capable (the T2CL template) so it can be snapshotted + resumed (G6).
        snapshot_capable: true,
    };

    tracing::info!(active_node, cid = config.vsock_cid, port = config.gateway_port, "C11: active node booting the `full-loop` genome (locked-down TAP + real rail; it holds the lease)");
    let backend = FirecrackerBackend::new();
    let mut instance = backend.boot(spec).await?;
    if !instance.is_running() {
        instance.halt().await;
        anyhow::bail!("C11: the active node's genome did not reach Running (G1)");
    }
    instance.stream_console();

    let transport = instance.gateway_transport();
    let serve_service = gateway.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "C11: active node gateway serve loop ended with error");
        }
    });

    Ok(ActiveNode { instance, gateway, events, treasury, serve_task })
}

/// Attach the eBPF TAP egress meter (gate G4 + G5(iv)) and the cgroup CPU/memory meter
/// (gate G2 survival half) to the active node's running VM. Both read host-authoritative
/// sources (the TAP byte counter, the VM's dedicated cgroup), never the genome's
/// self-reported numbers (G3c). Fails loudly if the egress control or the cgroup is
/// missing (the meters are part of the contract, never a silent zero-bill).
async fn setup_meters(
    config: &FullLoopConfig,
    instance: &dyn SandboxInstance,
    treasury: Treasury,
) -> anyhow::Result<(EgressMeter, Meter)> {
    // The per-VM TAP (lockdown was forced on). Resolve the metered interface name.
    let tap_name = match instance.egress_control() {
        Some(egress) => egress.iface_name().to_string(),
        None => anyhow::bail!("C11: no egress control on the active node's VM (lockdown_egress was not honored)"),
    };
    // The same NOPASSWD sudo the jailer launches through (the D-7 boundary, not weakened).
    let sudo_bin = crate::prereqs::resolve_sudo()
        .map_err(|e| e.context("C11: could not resolve sudo for the eBPF egress meter"))?;
    let egress_meter = EgressMeter::spawn(&tap_name, sudo_bin, config.egress_tick)
        .await
        .map_err(|e| anyhow::anyhow!("C11: eBPF egress meter attach failed: {e}"))?;

    // The cgroup CPU/memory meter on the VM's dedicated cgroup (the jailer placed it
    // under the daemon's delegated slice; the read is rootless). attach() fails loudly
    // on a bad placement, so metering reads a real cgroup, never a silent zero.
    let cgroup_rel_path = match instance.meter_source() {
        MeterSource::CgroupV2 { rel_path } => rel_path,
        // full_loop_run is the Firecracker/cgroup-only C11 path (cfg linux); the
        // VZ-only allocation source can never legitimately reach here.
        MeterSource::Allocation { .. } => anyhow::bail!(
            "full_loop_run (C11) is cgroup/Firecracker-only; the allocation meter source is VZ-only and unsupported here"
        ),
    };
    let meter_config = MeterConfig {
        cgroup_rel_path,
        tick: config.meter_tick,
        rates: Default::default(),
    };
    let cpu_meter = Meter::attach(&meter_config, treasury)
        .map_err(|e| anyhow::anyhow!("C11: cgroup meter attach failed: {e}"))?;

    Ok((egress_meter, cpu_meter))
}

/// Tick the cgroup meter `ticks` times (a tick interval between reads), accumulating
/// the metered burn and debiting the treasury, and return the total burned. This is
/// the G2 SURVIVAL half: a FEW ticks bill > 0 sats of real CPU but leave ample runway,
/// so the VM does NOT hit the budget-death halt (that is G2's own terminal test). A
/// refused (over-budget) tick would mean the runway was misconfigured; we do not expect
/// one here and keep ticking through `Debited`.
async fn meter_a_little(meter: &mut Meter, ticks: u64) -> u64 {
    let tick = meter.tick_interval();
    for _ in 0..ticks {
        tokio::time::sleep(tick).await;
        match meter.tick_once() {
            Ok(DebitOutcome::Debited { .. }) => {}
            Ok(DebitOutcome::Insufficient { .. }) => {
                // The budget ran out unexpectedly early (the runway was too small). Stop
                // ticking; the caller still reads burned_sats and the (now small)
                // remaining. The G11 verdict asserts remaining > 0, so this would fail
                // loudly rather than silently passing.
                tracing::warn!("C11: the cgroup meter exhausted the budget during the survival ticks (runway too small)");
                break;
            }
            Ok(DebitOutcome::Duplicate(_)) => {}
            Err(e) => {
                tracing::warn!(error = %e, "C11: a metering tick errored; stopping the survival ticks");
                break;
            }
        }
    }
    meter.burned_sats()
}

/// Drop the cgroup meter (releasing its treasury clone, which shares the sled lock).
/// Taking the egress meter out first would let the caller shut it down; here the egress
/// meter is shut down separately, so this just drops the CPU meter.
fn cpu_meter_drop(meter: Meter) {
    drop(meter);
}

/// Tear down the active node fully on an early-error path (the VM, both meters, the
/// serve task, and the gateway + treasury handles).
async fn teardown_active(
    instance: Box<dyn SandboxInstance>,
    egress_meter: EgressMeter,
    cpu_meter: Meter,
    serve_task: tokio::task::JoinHandle<()>,
    gateway: GatewayService,
    treasury: Treasury,
) {
    egress_meter.shutdown().await;
    instance.halt().await;
    cpu_meter_drop(cpu_meter);
    serve_task.abort();
    drop(gateway);
    drop(treasury);
}

// ---------------------------------------------------------------------------
// The restore on the new active node (G6, G7), opening the SAME treasury (D-9).
// ---------------------------------------------------------------------------

/// The restored genome on the new active node plus the survival signals and the SHARED
/// treasury it continues (D-9).
struct RestoredNode {
    instance: Box<dyn SandboxInstance>,
    node2_reached_running: bool,
    post: PostResumeObservation,
    treasury: Treasury,
    /// A CLONE of node 2's treasury handle (shares the gateway's sled lock) to read the
    /// final balance after the re-issue (re-opening the path would deadlock on sled's
    /// single-process exclusive lock).
    treasury_read: Treasury,
    serve_task: tokio::task::JoinHandle<()>,
    events: EventStream,
}

/// Restore the killed node's snapshot on the NEW active node (the C-7 restore the lease
/// drove) and observe the post-resume heartbeat (G6 survival) and the entropy ordering
/// (G7). Opens the SAME persisted treasury store (D-9 continuation, the ledger crossed)
/// and bumps the VMGenID generation on restore (the C-8 hook). The UNCHANGED C-7 restore
/// mechanism, invoked by the lease handoff.
#[allow(clippy::too_many_arguments)]
async fn restore_on_new_active(
    config: &FullLoopConfig,
    image: &ImagePaths,
    treasury_path: &std::path::Path,
    expected_balance: u64,
    new_active_node: LeaseNodeId,
    generation_pre: u64,
    rail: Arc<dyn Rail>,
    transferred: crate::sandbox::SnapshotArtifact,
) -> anyhow::Result<RestoredNode> {
    // The new active node opens the SAME persisted treasury (D-9: it continues the
    // killed node's balance AND its dedupe ledger, not a fresh one). The seed is ignored
    // on a re-open (the persisted balance + ledger are authoritative), so K's entry is
    // present.
    let treasury = Treasury::open(treasury_path, expected_balance)?;
    anyhow::ensure!(
        treasury.remaining()? == expected_balance,
        "C11: the new active node must continue the SAME persisted treasury balance (D-9)"
    );
    let treasury_read = treasury.clone();
    let session = Session {
        task_descriptor: config.task.clone(),
        budget_sats: config.initial_sats,
        allowlisted_destinations: vec![config.allow_mint.clone()],
        allowlisted_inbound_kinds: Vec::new(),
    };
    let mut gateway = GatewayService::new(treasury.clone(), rail, session);
    // The VMGenID bump on restore (the C-8 hook): a restored VM is a new generation.
    // Start the fresh gateway at generation_pre, then bump to generation_pre + 1 so the
    // post-resume generation is exactly one past the pre-snapshot one (the resume signal
    // the genome re-issues + re-derives on).
    for _ in 0..generation_pre {
        gateway.bump_generation();
    }
    let generation_post = gateway.bump_generation();
    let mut events = gateway.observe_events();

    let restore_spec = RestoreSpec {
        image: GuestImage { kernel: image.vmlinux.clone(), rootfs: image.rootfs.clone() },
        instance_id: format!("c11-restored-{new_active_node}"),
        gateway_port: config.gateway_port,
        // Keep the egress lockdown on the restored VM too (a fresh TAP + nftables on the
        // new node), so egress stays default-deny after the resume (G4 holds post-move).
        lockdown_egress: true,
    };

    tracing::info!(new_active_node, generation_post, "C11: the new active node RESTORES the killed node's snapshot (C-7 path); generation bumped");
    let backend = FirecrackerBackend::new();
    let mut instance = backend.restore(transferred, restore_spec).await?;
    let node2_reached_running = instance.is_running();
    instance.stream_console();

    let transport = instance.gateway_transport();
    let serve_service = gateway.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = crate::boot::serve_gateway_over_pub(serve_service, transport).await {
            tracing::error!(error = %e, "C11: new active node gateway serve loop ended with error");
        }
    });

    // The decisive G6 + G7 observation: the first post-resume heartbeat (survival) and
    // whether an entropy call at the bumped generation preceded it (the re-derive-before
    // -act ordering). Node 2's observer is fresh, so its stream starts clean post-restore.
    let post =
        wait_for_post_resume_heartbeat(&mut events, generation_post, config.post_resume_timeout).await;
    if let Some(ev) = &post.heartbeat {
        tracing::info!(detail = %ev.detail, "C11: the genome survived the lease-driven handoff (post-resume round-trip on the new active node)");
    }

    Ok(RestoredNode {
        instance,
        node2_reached_running,
        post,
        treasury,
        treasury_read,
        serve_task,
        events,
    })
}

// ---------------------------------------------------------------------------
// Observation helpers (events, fingerprints, the egress + act outcomes).
// ---------------------------------------------------------------------------

/// What ONE observation pass over the active node's event stream gathered: the boot
/// round-trip (G1), the pre-snapshot entropy fingerprint (G7 baseline), whether the raw
/// egress was DENIED (G4), and the brokered-act outcome (G5). The `full-loop` genome
/// emits these INTERLEAVED (egress attempts, the egress result, the brokered `idem_first`,
/// then heartbeats), so a SINGLE drain captures all of them; a separate boot-wait would
/// discard the act/egress events it skipped past. The G5(ii) mint-spent-proof +
/// wallet-balance checks are done by the test directly against the mint, not here.
struct ActiveArcObservation {
    /// At least one `heartbeat` arrived (the genome booted, dialed vsock, and round-
    /// tripped, G1).
    boot_round_trip: bool,
    /// The entropy fingerprint from the first heartbeat (the G7 pre-snapshot baseline).
    fingerprint_pre: Option<String>,
    /// The genome's raw egress was DENIED (no leak, G4), from its `raw_egress_result`.
    egress_denied: bool,
    /// The brokered act outcome (`idem_first`, expected AUTHORIZED_AND_PERFORMED, G5).
    act: ActOutcome,
}

/// Drain the active node's event stream until it has captured the boot heartbeat (G1 +
/// `fingerprint_pre`) AND the brokered act (`idem_first`, G5), recording whether the
/// `raw_egress_result` was DENIED (G4) along the way, up to `timeout`. Returns as soon as
/// BOTH the heartbeat and the act have arrived (the genome sends the egress result and
/// the act before its first heartbeat, so by the time a heartbeat lands the egress + act
/// are already captured; we still wait for both to be safe against reordering).
async fn observe_active_arc(events: &mut EventStream, timeout: Duration) -> ActiveArcObservation {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut boot_round_trip = false;
    let mut fingerprint_pre = None;
    let mut egress_denied = false;
    let mut act = ActOutcome::default();
    loop {
        // Return once we have BOTH the boot round-trip and the brokered act.
        if boot_round_trip && act.observed {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "raw_egress_result" => {
                egress_denied = ev.detail.contains("DENIED") && !ev.detail.contains("LEAKED");
            }
            Ok(Some(ev)) if ev.kind == "idem_first" => {
                act = parse_act(&ev.detail);
            }
            Ok(Some(ev)) if ev.kind == "heartbeat" => {
                if !boot_round_trip {
                    boot_round_trip = true;
                    fingerprint_pre = parse_fingerprint(&ev.detail);
                }
            }
            Ok(Some(_)) => continue, // an egress attempt, the boot hello, etc.
            Ok(None) => break,        // observer dropped
            Err(_) => break,          // window elapsed
        }
    }
    ActiveArcObservation { boot_round_trip, fingerprint_pre, egress_denied, act }
}

/// Wait for the genome's next act outcome event of `kind` (`idem_reissue`) on the new
/// active node, up to `timeout`. Other events (heartbeats) are drained.
async fn wait_for_act(events: &mut EventStream, kind: &str, timeout: Duration) -> ActOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return ActOutcome::default();
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == kind => return parse_act(&ev.detail),
            Ok(Some(_)) => continue,
            Ok(None) => return ActOutcome::default(),
            Err(_) => return ActOutcome::default(),
        }
    }
}

/// Parse an act outcome event detail into an [`ActOutcome`]. The detail is
/// `idem_<phase> outcome=<Name> cost_sats=<n> treasury_remaining=<n> [proof_len=<n>] ...`;
/// pulls the `outcome=` token and the numbers.
fn parse_act(detail: &str) -> ActOutcome {
    let token = |key: &str| -> Option<&str> {
        detail.split_whitespace().find_map(|tok| tok.strip_prefix(key))
    };
    let num = |key: &str| -> u64 { token(key).and_then(|v| v.parse().ok()).unwrap_or(0) };
    ActOutcome {
        outcome: token("outcome=").unwrap_or("").to_string(),
        cost_sats: num("cost_sats="),
        treasury_remaining: num("treasury_remaining="),
        proof_len: num("proof_len="),
        observed: true,
    }
}

/// The post-resume observation (G6 + G7): the first post-resume heartbeat (survival),
/// whether an `entropy_nonce_call` at the bumped generation preceded it (the ordering),
/// and the bumped generation itself.
struct PostResumeObservation {
    heartbeat: Option<Event>,
    entropy_call_before_act: bool,
    generation_post: u64,
}

/// Wait for the genome's first post-resume `heartbeat` on the new active node, recording
/// whether it called GetEntropyNonce at `generation_post` BEFORE that heartbeat act (the
/// G7 ordering). The restored genome re-dials, calls GetEntropyNonce (the daemon feeds an
/// `entropy_nonce_call` event tagged with the generation), derives its fingerprint, then
/// reports the heartbeat, so the natural stream order is the entropy call (at the bumped
/// generation) AHEAD of the heartbeat act. Other events are drained.
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
            return PostResumeObservation {
                heartbeat: None,
                entropy_call_before_act: false,
                generation_post,
            };
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "entropy_nonce_call" => {
                if parse_generation(&ev.detail) == Some(generation_post) {
                    entropy_call_at_post_gen = true;
                }
            }
            Ok(Some(ev)) if ev.kind == "heartbeat" => {
                return PostResumeObservation {
                    heartbeat: Some(ev),
                    entropy_call_before_act: entropy_call_at_post_gen,
                    generation_post,
                };
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                return PostResumeObservation {
                    heartbeat: None,
                    entropy_call_before_act: false,
                    generation_post,
                }
            }
            Err(_) => {
                return PostResumeObservation {
                    heartbeat: None,
                    entropy_call_before_act: false,
                    generation_post,
                }
            }
        }
    }
}

/// Parse the entropy fingerprint hex out of a heartbeat detail line. The `full-loop`
/// heartbeat detail is `beat=N task=T gen_seen=G fingerprint=<hex> fp_gen=G`; extracts
/// the `fingerprint=` value (the G7 instrument). None if absent.
fn parse_fingerprint(detail: &str) -> Option<String> {
    detail
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("fingerprint="))
        .map(|s| s.to_string())
}

/// Parse the `generation=<n>` value out of an `entropy_nonce_call` event detail.
fn parse_generation(detail: &str) -> Option<u64> {
    detail
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("generation="))
        .and_then(|v| v.parse().ok())
}

// ---------------------------------------------------------------------------
// Relay-lease harness (#9): the in-process stand-in for the relay-native lease the
// full-loop's failover rides. The loopback Raft cluster was CUT; this drives the
// SAME relay-lease mechanism (claim -> publish -> observe; latest-term-wins; stale
// stand-down) the production path uses, on an in-memory relay so the gated VM run needs
// no live relay. The agent's failover transfers the keystore WITH the agent (F9-2 note),
// so every node's authority holds the SAME agent quorum Q.
// ---------------------------------------------------------------------------

use std::collections::HashMap as LeaseHashMap;
use std::sync::Arc as LeaseArc;

use crate::quorum_signer::QuorumSigner;
use crate::relay_lease::RelayLeaseAuthority;
use kirby_custody::cosign_net::NostrEvent;

// The G-4 autonomous-failover tick + its harness helpers are exercised ONLY by
// `failover_loop_tests`, so they (and the symbols they alone pull in) are `#[cfg(test)]` —
// gating keeps the non-test library build free of dead-code / unused-import warnings.
#[cfg(test)]
use std::collections::{BTreeMap as LeaseBTreeMap, HashSet as LeaseHashSet};
#[cfg(test)]
use crate::failover_detect::detect_takeovers;
#[cfg(test)]
use crate::relay_lease::{LeaseContent, ObservedLeaseRecord, LEASE_TTL_SECS};

/// The agent the full-loop's single genome runs as (the DEFAULT single-agent slot).
const LOOP_AGENT: &str = crate::lease::DEFAULT_AGENT;

/// A tiny in-process addressable relay (mirrors the relay_lease.rs test MockRelay): keeps the
/// latest published lease event per `(pubkey, kind, d)`. NOT the wire -- it lets the harness
/// publish a signed lease and re-feed it to every node's `observe`, with no network.
#[derive(Default)]
struct LeaseRelay {
    events: LeaseHashMap<(String, u32, String), NostrEvent>,
}

impl LeaseRelay {
    fn publish(&mut self, event: NostrEvent) {
        let d = event
            .tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some("d"))
            .and_then(|t| t.get(1).cloned())
            .unwrap_or_default();
        self.events.insert((event.pubkey.clone(), event.kind, d), event);
    }
}

/// The relay-lease fabric for the full-loop: one shared in-memory relay plus a per-node
/// [`RelayLeaseAuthority`], each holding the agent's SAME quorum Q (failover carries the
/// keystore with the agent). A `claim` FROST-signs the lease, publishes it, and re-observes it
/// on EVERY live node, so each node's fence reflects the latest term -- the relay-native
/// equivalent of the loopback-Raft committed lease, latest-term-wins.
struct LeaseFabric {
    relay: LeaseRelay,
    authorities: LeaseHashMap<LeaseNodeId, LeaseArc<RelayLeaseAuthority>>,
    /// Node ids whose authority should still observe (a killed node is dropped so its stale
    /// in-process authority is not counted as a live active node, the C-9 same-host note).
    live: Vec<LeaseNodeId>,
    q: LeaseArc<QuorumSigner>,
}

impl LeaseFabric {
    /// Build a fabric for `node_ids`: generate ONE agent quorum (the agent's Q) and give every
    /// node an authority that holds it (so any node can claim on failover).
    fn new(node_ids: &[LeaseNodeId]) -> anyhow::Result<Self> {
        let ks = kirby_custody::generate_dealer_keyset(2, 3)
            .map_err(|e| anyhow::anyhow!("full-loop lease: 2-of-3 dealer keygen: {e}"))?;
        let q = LeaseArc::new(
            crate::quorum_signer::local_quorum_from_keyset(&ks)
                .map_err(|e| anyhow::anyhow!("full-loop lease: build quorum signer: {e}"))?,
        );
        let mut authorities = LeaseHashMap::new();
        for &id in node_ids {
            authorities.insert(
                id,
                LeaseArc::new(RelayLeaseAuthority::single_agent(id, LOOP_AGENT, q.clone())),
            );
        }
        Ok(Self { relay: LeaseRelay::default(), authorities, live: node_ids.to_vec(), q })
    }

    /// This node's authority (cloned Arc) for wiring into the gateway fence.
    fn authority(&self, id: LeaseNodeId) -> anyhow::Result<LeaseArc<RelayLeaseAuthority>> {
        self.authorities
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("lease authority for node {id} not found"))
    }

    /// CLAIM the agent's lease for `id` at `term`: FROST-sign + publish + re-observe on every
    /// live node. Returns the claimed term.
    async fn claim(&mut self, id: LeaseNodeId, term: u64) -> anyhow::Result<u64> {
        let event = self.authority(id)?.claim(LOOP_AGENT, term).await?;
        self.relay.publish(event.clone());
        for &live_id in &self.live {
            if let Some(a) = self.authorities.get(&live_id) {
                a.observe(&event).await;
            }
        }
        Ok(term)
    }

    /// KILL a node: drop it from the live observer set (its stale authority must not count as
    /// a live active node).
    fn kill(&mut self, id: LeaseNodeId) {
        self.live.retain(|&n| n != id);
    }

    /// REVIVE a killed node as a STALE authority: a FRESH authority (no observed lease) that
    /// learns the latest lease via `observe` (the relay catch-up), so its fence sees the higher
    /// term that superseded its old belief. Returns it WITHOUT adding it back to `live`.
    async fn revive_stale(&self, id: LeaseNodeId) -> anyhow::Result<LeaseArc<RelayLeaseAuthority>> {
        let revived = LeaseArc::new(RelayLeaseAuthority::single_agent(id, LOOP_AGENT, self.q.clone()));
        // Catch up on the latest published lease (the relay delivers it on rejoin).
        let d = LOOP_AGENT.to_string();
        if let Some(event) = self.relay.events.get(&(hex::encode(self.q.q_bytes()), kirby_proto::KIND_KIRBY_LEASE as u32, d)) {
            revived.observe(event).await;
        }
        Ok(revived)
    }

    /// Seed a FRESH "liveness" lease for a SEPARATE agent into the shared relay (the detecting
    /// node's own healthy, heartbeating agent). It carries a DISTINCT `d`/agent_id so it never
    /// collides with `LOOP_AGENT` (the failover target) and, being fresh, is never itself a
    /// takeover candidate. Its sole job is to make a survivor's observed snapshot NON-blind: a
    /// single-agent fabric whose only lease just went stale would (correctly) trip the
    /// observer-blind fail-safe and stand down, exactly as the pure detector's tests include a
    /// fresh `live` peer beside the stale one. This is the in-harness equivalent of that peer.
    ///
    /// It is built STRUCTURALLY (content JSON + the `d` tag), not FROST-signed: the detection tick
    /// reads the relay map structurally (the same cooperative-fleet trust level
    /// `FleetLeaseObserver` uses — NOT a security boundary), so no signature is needed. It is
    /// published only into the relay map, never `observe`d into the verifying authorities.
    #[cfg(test)]
    fn seed_liveness(&mut self, agent_id: &str, holder: LeaseNodeId, term: u64, issued_at: u64) {
        let content = LeaseContent {
            agent_id: agent_id.to_string(),
            holder_node_id: holder,
            term,
            issued_at,
        };
        let json = serde_json::to_string(&content).expect("serialize liveness lease content");
        // A structurally-valid lease event: real kind + the `d` addressable tag agreeing with the
        // content's agent_id (the only fields the structural snapshot read consults). The pubkey is
        // the shared Q hex (so the relay key is well-formed); the id/sig are placeholders because
        // the detection tick does not verify them (see the doc above).
        let event = NostrEvent {
            id: String::new(),
            pubkey: hex::encode(self.q.q_bytes()),
            created_at: issued_at,
            kind: kirby_proto::KIND_KIRBY_LEASE as u32,
            tags: vec![vec!["d".to_string(), agent_id.to_string()]],
            content: json,
            sig: String::new(),
        };
        self.relay.publish(event);
    }

    /// AGE an already-published lease in the shared relay by rewriting its content `issued_at` to
    /// `issued_at` (the structural snapshot read judges staleness against this signed field). This
    /// is the in-harness equivalent of TIME PASSING with no heartbeat: a dead peer's lease was
    /// issued a while ago and has not been refreshed, so it reads STALE at a `now` that is the
    /// PRESENT — WITHOUT having to push the detection clock far past the real wall-clock `issued_at`
    /// the fabric `claim` stamps (which would also make a fresh takeover lease look stale to the
    /// next tick and break single-winner). The detection clock and the `claim` clock stay aligned at
    /// ~real wall-clock; only the dead lease is backdated. Returns whether a lease was found + aged.
    #[cfg(test)]
    fn age_lease(&mut self, agent_id: &str, issued_at: u64) -> bool {
        let key = (
            hex::encode(self.q.q_bytes()),
            kirby_proto::KIND_KIRBY_LEASE as u32,
            agent_id.to_string(),
        );
        let Some(event) = self.relay.events.get(&key) else {
            return false;
        };
        let Ok(mut content) = serde_json::from_str::<LeaseContent>(&event.content) else {
            return false;
        };
        content.issued_at = issued_at;
        let json = serde_json::to_string(&content).expect("re-serialize aged lease content");
        let mut aged = event.clone();
        aged.content = json;
        self.relay.events.insert(key, aged);
        true
    }

    /// Build THIS node's observed-lease snapshot the way `detect_takeovers` consumes it: decode
    /// every lease event currently in the shared relay map into an [`ObservedLeaseRecord`] keyed by
    /// its `d`/agent_id (latest-wins is already enforced by the relay's addressable `(pubkey,
    /// kind, d)` overwrite — one event per agent). `RelayLeaseAuthority` exposes no
    /// `observed_snapshot()` (its observed map is private and only ever TTL-filtered), so per the
    /// chunk brief the snapshot is built from the fabric's lease map. The read is STRUCTURAL (no Q
    /// verification), matching the cooperative-fleet trust level the detector reasons over.
    #[cfg(test)]
    fn observed_snapshot_from_relay(&self) -> LeaseBTreeMap<String, ObservedLeaseRecord> {
        let mut snap = LeaseBTreeMap::new();
        for ((_pubkey, kind, d), event) in &self.relay.events {
            if *kind != kirby_proto::KIND_KIRBY_LEASE as u32 {
                continue;
            }
            let content: LeaseContent = match serde_json::from_str(&event.content) {
                Ok(c) => c,
                Err(_) => continue,
            };
            // The `d` addressable key must agree with the signed content's agent_id (mirrors the
            // observer's structural check); a mis-addressed event is dropped.
            if d.as_str() != content.agent_id.as_str() {
                continue;
            }
            snap.insert(
                content.agent_id,
                ObservedLeaseRecord {
                    holder_node_id: content.holder_node_id,
                    term: content.term,
                    issued_at: content.issued_at,
                },
            );
        }
        snap
    }

    /// AUTONOMOUS FAILOVER TICK (the G-4 loop, in-process): for `node_id`, build its observed-lease
    /// snapshot from the relay, run the VERIFIED pure decision
    /// [`detect_takeovers`] over it (the node hosts NOTHING in this single-agent harness — a
    /// survivor takes over the dead peer's agent, never one it already runs), and for EACH verdict
    /// perform the SAME real fabric `claim(node_id, beat_term)` the C11 fence arc uses (FROST-sign
    /// the lease at the beat term, publish it, re-observe on every live node). The FABRIC — not the
    /// test script — decides AND acts. Returns what was claimed (`(agent_id, term)` per verdict) so
    /// tests can assert the autonomous takeover.
    ///
    /// `now`/the TTL/the grace window judge staleness; `grace_state` is the per-agent continuous-
    /// staleness dwell threaded across ticks (consulted + updated in place by the pure decision).
    /// The observer-blind fail-safe is enforced INSIDE `detect_takeovers`: a snapshot with no fresh
    /// lease yields zero verdicts and this claims nothing.
    #[cfg(test)]
    async fn run_detection_tick(
        &mut self,
        node_id: LeaseNodeId,
        now: u64,
        grace_state: &mut LeaseBTreeMap<String, u64>,
    ) -> anyhow::Result<Vec<(String, u64)>> {
        let snapshot = self.observed_snapshot_from_relay();
        // The set of agents this node already hosts (never taken over). In the single-agent fabric
        // a survivor that is NOT yet the lease holder hosts nothing; the test sets this explicitly.
        let hosted: LeaseHashSet<String> = self
            .authorities
            .get(&node_id)
            .map(|_| LeaseHashSet::new())
            .unwrap_or_default();
        let verdicts = detect_takeovers(
            &snapshot,
            node_id,
            &hosted,
            now,
            LEASE_TTL_SECS,
            crate::failover_detect::DEFAULT_TAKEOVER_GRACE_SECS,
            crate::failover_detect::DEFAULT_FAILOVER_MAX_LEASE_AGE_SECS,
            grace_state,
        );
        let mut claimed = Vec::new();
        for verdict in verdicts {
            // The SAME real fabric claim the C11 path uses. The fabric is single-agent
            // (`LOOP_AGENT`), so a real verdict is always for that agent; assert it so a future
            // multi-agent fabric does not silently mis-claim under the hardcoded `claim` agent.
            anyhow::ensure!(
                verdict.agent_id == LOOP_AGENT,
                "the single-agent fabric can only act on a verdict for LOOP_AGENT, got {:?}",
                verdict.agent_id
            );
            let term = self.claim(node_id, verdict.beat_term).await?;
            claimed.push((verdict.agent_id, term));
        }
        Ok(claimed)
    }

    /// Sample the active set over the LIVE nodes and OR into `two_actives_ever` whether more
    /// than one reports active (the linearizability witness, G8).
    async fn sample_actives(&self, two_actives_ever: &mut bool) {
        let mut active = Vec::new();
        for &id in &self.live {
            if let Some(a) = self.authorities.get(&id) {
                if a.active_term_for(LOOP_AGENT).await.is_some() {
                    active.push(id);
                }
            }
        }
        if active.len() > 1 {
            *two_actives_ever = true;
            tracing::error!(?active, "C11: TWO nodes report active at once (linearizability violated, G8)");
        }
    }
}

/// A lease-gated treasury debit (the money-path the lease gates, G8): debit only if the
/// authority's fence says this node holds the lease at a current-enough term. A fenced node
/// returns `None` and the treasury is untouched (no double-burn).
async fn lease_gated_debit(
    authority: &RelayLeaseAuthority,
    believed_term: u64,
    treasury: &Treasury,
    amount: u64,
) -> Option<DebitOutcome> {
    match authority.fence_for(LOOP_AGENT, believed_term).await {
        FenceVerdict::Active { .. } => Some(treasury.debit_metered(amount).ok()?),
        FenceVerdict::Fenced { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_act, parse_fingerprint, parse_generation, ActOutcome, FullLoopOutcome};

    /// The act-outcome parser pulls the outcome name, cost, balance, and proof length
    /// out of the genome's event detail (the `idem_first` / `idem_reissue` lines).
    #[test]
    fn parse_act_extracts_fields() {
        let first =
            "idem_first outcome=AuthorizedAndPerformed cost_sats=64 treasury_remaining=999936 proof_len=32 gen_at_issue=0";
        let o = parse_act(first);
        assert_eq!(o.outcome, "AuthorizedAndPerformed");
        assert_eq!(o.cost_sats, 64);
        assert_eq!(o.treasury_remaining, 999936);
        assert_eq!(o.proof_len, 32);
        assert!(o.is_performed());
        assert!(!o.is_duplicate_ignored());

        let reissue =
            "idem_reissue outcome=DuplicateIgnored cost_sats=64 treasury_remaining=999936 gen_now=1";
        let r = parse_act(reissue);
        assert!(r.is_duplicate_ignored());
        assert_eq!(r.cost_sats, 64);
    }

    /// The fingerprint and generation parsers pull their fields out of the heartbeat /
    /// entropy-call details.
    #[test]
    fn parsers_extract_fingerprint_and_generation() {
        let hb = "beat=2 task=c11 gen_seen=1 fingerprint=deadbeef fp_gen=1";
        assert_eq!(parse_fingerprint(hb).as_deref(), Some("deadbeef"));
        assert_eq!(parse_fingerprint("beat=1 task=t gen_seen=0"), None);
        assert_eq!(parse_generation("generation=1"), Some(1));
        assert_eq!(parse_generation("nope"), None);
    }

    /// Build the canonical PASSING outcome (every composed gate held) for the verdict
    /// tests.
    fn canonical() -> FullLoopOutcome {
        // The real ordering on the active node: boot -> the brokered act debits C ->
        // the cgroup meter bills a small CPU burn. So before_act = the boot balance,
        // after_act = boot - C, after_meter = after_act - burn (the handoff balance),
        // and after_reissue = after_meter (the deduped re-issue debits nothing).
        let c = 64;
        let start = 1_000_000;
        let after_act = start - c; // the brokered act debited C
        let after_meter = after_act - 40; // then the cgroup burned 40 sats (survival, > 0)
        FullLoopOutcome {
            elected_leader: 1,
            term_t: 1,
            killed_node: 1,
            new_leader: 3,
            term_t1: 2,
            revived_stale_fenced: true,
            two_actives_ever_observed: false,
            boot_round_trip: true,
            metered_burn_sats: 40,
            treasury_after_meter: after_meter,
            egress_denied: true,
            ebpf_egress_bytes: 0,
            first: ActOutcome {
                outcome: "AuthorizedAndPerformed".to_string(),
                cost_sats: c,
                treasury_remaining: after_act,
                proof_len: 32,
                observed: true,
            },
            wallet_before: 1000,
            wallet_after: 936,
            mint_spent_proof_count: 1,
            treasury_before_act: start,
            treasury_after_act: after_act,
            node2_reached_running: true,
            post_resume_round_trip: true,
            snapshot_bytes: 134_231_859,
            fingerprint_pre: Some("aaaa".to_string()),
            fingerprint_post: Some("bbbb".to_string()),
            generation_pre: 0,
            generation_post: 1,
            entropy_call_before_post_resume_act: true,
            reissue: ActOutcome {
                outcome: "DuplicateIgnored".to_string(),
                cost_sats: c,
                treasury_remaining: after_meter,
                proof_len: 32,
                observed: true,
            },
            perform_count_after_first: 1,
            perform_count_after_reissue: 1,
            treasury_after_reissue: after_meter,
        }
    }

    /// The canonical whole-organism evidence passes the composite G11 verdict.
    #[test]
    fn g11_verdict_holds_for_canonical_evidence() {
        let o = canonical();
        assert_eq!(o.act_cost(), 64);
        assert_eq!(o.act_treasury_drop(), 64, "the act debited exactly C on the active node");
        assert_eq!(
            o.reissue_added_debit(),
            0,
            "the deduped re-issue added NOTHING to the drop across the move (the act is charged C once, not 2C)"
        );
        assert!(o.fingerprints_differ(), "the entropy was re-derived (the fingerprints differ)");
        assert!(o.passed(8192), "the canonical whole-loop evidence must pass G11");
    }

    /// The verdict FAILS if ANY composed gate fails: this pins that the capstone is a
    /// CONJUNCTION (the slices must ALL hold in the one run, not just some).
    #[test]
    fn g11_verdict_fails_if_any_gate_fails() {
        // G2 survival violated: the meter billed nothing (burn 0).
        let no_burn = FullLoopOutcome { metered_burn_sats: 0, ..canonical() };
        assert!(!no_burn.passed(8192), "a zero metered burn must FAIL G2's meter half");

        // G2 survival violated: the VM did not survive (treasury drained to 0).
        let dead = FullLoopOutcome { treasury_after_meter: 0, ..canonical() };
        assert!(!dead.passed(8192), "a drained treasury (no survival) must FAIL the full-loop");

        // G4 violated: the egress leaked.
        let leaked = FullLoopOutcome { egress_denied: false, ..canonical() };
        assert!(!leaked.passed(8192), "an egress leak must FAIL G4");

        // G4 violated: the eBPF counter shows real traffic.
        let flowed = FullLoopOutcome { ebpf_egress_bytes: 1_000_000, ..canonical() };
        assert!(!flowed.passed(8192), "real VM egress bytes must FAIL G4/G5(iv)");

        // G5 violated: the act was not performed for real (the mint did not move).
        let no_mint = FullLoopOutcome { mint_spent_proof_count: 0, ..canonical() };
        assert!(!no_mint.passed(8192), "a settle the mint did not honor must FAIL G5(ii)");

        // G5 violated: the treasury did not drop by C.
        let wrong_debit = FullLoopOutcome { treasury_after_act: 999_960, ..canonical() };
        assert!(!wrong_debit.passed(8192), "a treasury drop != C must FAIL G5(iii)");

        // G6 violated: the genome did not survive the move.
        let not_resumed = FullLoopOutcome { post_resume_round_trip: false, ..canonical() };
        assert!(!not_resumed.passed(8192), "no post-resume round-trip must FAIL G6");

        // G7 violated: the entropy was reused (the fingerprints are equal).
        let reused = FullLoopOutcome {
            fingerprint_post: Some("aaaa".to_string()),
            ..canonical()
        };
        assert!(!reused.passed(8192), "equal fingerprints (entropy reuse) must FAIL G7");

        // G7 violated: the generation did not bump.
        let no_bump = FullLoopOutcome { generation_post: 0, ..canonical() };
        assert!(!no_bump.passed(8192), "no generation bump must FAIL G7");

        // G9 violated: the re-issue was performed again (not deduped). The handoff
        // balance is 1_000_000 - 64 (act) - 40 (meter) = 999_896; a second perform would
        // debit another C, dropping it to 999_832 (so reissue_added_debit = 64, not 0).
        let double = FullLoopOutcome {
            reissue: ActOutcome {
                outcome: "AuthorizedAndPerformed".to_string(),
                cost_sats: 64,
                treasury_remaining: 999_832,
                proof_len: 32,
                observed: true,
            },
            perform_count_after_reissue: 2,
            treasury_after_reissue: 999_832,
            ..canonical()
        };
        assert!(!double.passed(8192), "a re-issue performed again (2C) must FAIL G9");

        // G8 violated: the revived stale node was NOT fenced.
        let not_fenced = FullLoopOutcome { revived_stale_fenced: false, ..canonical() };
        assert!(!not_fenced.passed(8192), "an un-fenced stale node must FAIL G8");

        // G8 violated: two actives were observed.
        let split = FullLoopOutcome { two_actives_ever_observed: true, ..canonical() };
        assert!(!split.passed(8192), "two observed actives must FAIL G8 (linearizability)");
    }
}

/// THE AUTONOMOUS G-4 FAILOVER LOOP, proven IN-PROCESS over the real `LeaseFabric` (fast,
/// ungated — no VM/relay/HW). These exercise `LeaseFabric::run_detection_tick`: the FABRIC ITSELF
/// (running the VERIFIED `detect_takeovers` decision and performing the SAME real `claim` the C11
/// fence arc uses) detects a dead peer, claims `term + 1`, and the revival is FENCED — the C11
/// fence arc, now DETECTOR-TRIGGERED rather than test-script-driven. Safety-critical: the race +
/// fence assertions are the no-split-brain guarantee.
#[cfg(test)]
mod failover_loop_tests {
    use super::{LeaseFabric, LOOP_AGENT, NODE_IDS};
    use crate::failover_detect::DEFAULT_TAKEOVER_GRACE_SECS;
    use crate::lease::{FenceVerdict, LeaseAuthority};
    use crate::relay_lease::LEASE_TTL_SECS;
    use std::collections::BTreeMap;

    /// A distinct, fresh "liveness" agent so a survivor's snapshot is NON-blind (its own healthy,
    /// heartbeating agent beside the dead peer's stale lease). Non-empty, so it never collides with
    /// `LOOP_AGENT` (the empty single-agent sentinel = the failover target).
    const LIVENESS_AGENT: &str = "survivor-self";

    /// Read the real wall-clock `issued_at` the fabric stamped on `LOOP_AGENT`'s latest lease.
    /// The fabric `claim` stamps `now_secs()` (real wall clock), so the tests anchor their
    /// detection clock to THIS value and AGE the dead lease backward from it (rather than pushing
    /// the detection clock far into the future). That keeps the detection clock and the `claim`
    /// clock aligned at ~real wall-clock, so a takeover lease the fabric freshly claims reads FRESH
    /// to the next tick (the property single-winner-on-race depends on).
    fn loop_agent_issued_at(fabric: &LeaseFabric) -> u64 {
        fabric
            .observed_snapshot_from_relay()
            .get(LOOP_AGENT)
            .expect("LOOP_AGENT lease present in the relay")
            .issued_at
    }

    /// The amount we backdate a dead peer's lease so it is CONTINUOUSLY stale past TTL + grace as of
    /// `now` (with a margin), making it takeover-eligible in a single eligible tick.
    const STALE_BY: u64 = LEASE_TTL_SECS + DEFAULT_TAKEOVER_GRACE_SECS + 5;

    /// TEST 1 (the WHOLE loop, autonomous): node 1 holds agent A (`LOOP_AGENT`) at term T. KILL
    /// node 1; its lease ages past TTL + the grace dwell. Node 2's `run_detection_tick`
    /// AUTONOMOUSLY claims A at T+1 (the fabric decided + acted — no test script told it to).
    /// Reviving node 1 still believing T, it reads `fence_for(A, T) == Fenced` and NO observed
    /// boundary ever showed two actives. This is C11's fence arc, now DETECTOR-driven.
    #[tokio::test]
    async fn autonomous_detect_takeover_then_revival_is_fenced() {
        let mut fabric = LeaseFabric::new(&NODE_IDS).expect("build the lease fabric");
        let term_t = 1u64;
        let mut two_actives_ever = false;

        // Node 1 claims A at T (the live holder), observed on every live node.
        fabric.claim(1, term_t).await.expect("node 1 claims A @ T");
        fabric.sample_actives(&mut two_actives_ever).await;
        // Anchor the detection clock at the present (the real wall-clock the claim stamped).
        let now = loop_agent_issued_at(&fabric);

        // KILL node 1: it drops out of the live observer set and stops heartbeating A.
        fabric.kill(1);
        fabric.sample_actives(&mut two_actives_ever).await;

        // Node 2 is a healthy survivor: seed its own FRESH liveness lease (issued at `now`, 0s old)
        // so its observed snapshot is NOT blind — otherwise the single stale agent would correctly
        // trip the observer-blind fail-safe (proven separately in `observer_blind_tick_claims_nothing`).
        fabric.seed_liveness(LIVENESS_AGENT, 2, 1, now);

        // A is now stale past TTL + the grace dwell as of `now` (node 1 stopped heartbeating).
        assert!(fabric.age_lease(LOOP_AGENT, now - STALE_BY), "age A past TTL + grace");

        // FIRST detection tick with a FRESH dwell map: even though A is long stale, this is the
        // FIRST tick that SEES it stale, so the grace dwell only SEEDS (continuous-staleness = 0) —
        // the fabric claims NOTHING. This proves the dwell gates a takeover on first sighting.
        let mut gs_fresh = BTreeMap::new();
        let claimed = fabric.run_detection_tick(2, now, &mut gs_fresh).await.expect("first-sighting tick");
        assert!(
            claimed.is_empty(),
            "the first tick that sees A stale only seeds the dwell ⇒ NO takeover yet, got {claimed:?}"
        );
        assert_eq!(gs_fresh.get(LOOP_AGENT).copied(), Some(now), "the dwell seeded at first-seen-stale");
        fabric.sample_actives(&mut two_actives_ever).await;

        // SECOND tick, with the dwell ALREADY satisfied (the fabric has seen A continuously stale for
        // >= the grace window across prior ticks — modeled by a pre-seeded first-seen-stale a full
        // grace window in the past). Node 2 AUTONOMOUSLY takes A over at T+1 — the fabric's OWN
        // decision + its OWN real `claim` (the SAME claim the C11 fence arc uses). The takeover lease
        // is claimed at the present wall clock, so it is fresh (0s old at `now`), not the knife-edge
        // a far-future detection clock would create.
        let mut gs_dwelt = BTreeMap::new();
        gs_dwelt.insert(LOOP_AGENT.to_string(), now - DEFAULT_TAKEOVER_GRACE_SECS);
        let claimed = fabric.run_detection_tick(2, now, &mut gs_dwelt).await.expect("post-dwell tick");
        assert_eq!(
            claimed,
            vec![(LOOP_AGENT.to_string(), term_t + 1)],
            "node 2 must AUTONOMOUSLY claim A at the OBSERVED term + 1 (T+1) once past the grace dwell"
        );
        fabric.sample_actives(&mut two_actives_ever).await;

        // Node 2 is now genuinely the active holder at T+1 (its own fence confirms it; the takeover
        // lease was claimed at the present wall clock, so it is fresh).
        let n2 = fabric.authority(2).expect("node 2 authority");
        assert!(
            matches!(n2.fence_for(LOOP_AGENT, term_t + 1).await, FenceVerdict::Active { term } if term == term_t + 1),
            "after the autonomous takeover node 2 holds A @ T+1 (Active)"
        );

        // REVIVE node 1 still believing T: it catches up on the latest lease (T+1, held by node 2)
        // and is FENCED — the no-split-brain guarantee, now reached via the detector, not a script.
        let revived = fabric.revive_stale(1).await.expect("revive node 1 stale");
        let verdict = revived.fence_for(LOOP_AGENT, term_t).await;
        assert!(
            matches!(verdict, FenceVerdict::Fenced { committed_term, committed_holder, believed_term }
                if committed_term == term_t + 1 && committed_holder == 2 && believed_term == term_t),
            "the revived node believing T must be FENCED by the T+1 lease node 2 took over (got {verdict:?})"
        );
        fabric.sample_actives(&mut two_actives_ever).await;

        assert!(
            !two_actives_ever,
            "NO observed boundary may ever show two active nodes (no split-brain across the autonomous failover)"
        );
    }

    /// TEST 2 (single-winner-on-race, thundering-herd containment): TWO survivors (nodes 2 and 3)
    /// BOTH run `run_detection_tick` on the SAME stale agent A in the SAME round. The relay's
    /// latest-wins (observe-only-forward by strictly-newer term) settles EXACTLY ONE T+1 holder; the
    /// second survivor's tick observes the winner's FRESH T+1 lease, no longer judges A stale, and
    /// stands DOWN (the detector's own freshness check, fed by the relay's latest-wins, contains the
    /// herd). The loser reads `Fenced` and NO observed boundary shows two actives. This is the race
    /// the spec calls out, contained by the monotonic-term latest-wins.
    ///
    /// On the in-process serialization: the fabric's relay is synchronous + shared, so node 3's tick
    /// observes node 2's claim the instant it lands. The genuine production race (two snapshots taken
    /// before either claim) is ALSO contained by the SAME mechanism — observe-only-forward rejects
    /// the second equal-term claim — which `relay_lease`'s `observe_latest_wins_by_monotonic_term`
    /// proves directly. Here we prove the FABRIC-LEVEL invariant: however many survivors run the loop
    /// on the same stale agent, exactly ONE T+1 holder emerges and the rest are fenced.
    #[tokio::test]
    async fn single_winner_when_two_survivors_race_the_same_stale_agent() {
        let mut fabric = LeaseFabric::new(&NODE_IDS).expect("build the lease fabric");
        let term_t = 4u64;
        let mut two_actives_ever = false;

        fabric.claim(1, term_t).await.expect("node 1 claims A @ T");
        let now = loop_agent_issued_at(&fabric);
        fabric.kill(1);

        // A is continuously stale past TTL + grace as of `now`; both survivors are healthy (each has
        // its own fresh liveness lease at `now`, so neither is observer-blind).
        assert!(fabric.age_lease(LOOP_AGENT, now - STALE_BY), "age A past TTL + grace");
        fabric.seed_liveness("survivor-2-self", 2, 1, now);
        fabric.seed_liveness("survivor-3-self", 3, 1, now);

        // Pre-seed BOTH nodes' dwell so a single same-round tick is eligible to fire — each has
        // ALREADY seen A continuously stale across the grace window. The race is two READY survivors
        // acting in the same round, which is exactly what the single-winner rule must contain.
        let mut gs2 = BTreeMap::new();
        gs2.insert(LOOP_AGENT.to_string(), now - STALE_BY);
        let mut gs3 = gs2.clone();

        // Node 2 ticks FIRST: it observes A stale, claims T+1, and (observe-only-forward) becomes the
        // observed holder at T+1 on every live node. The claim stamps the present wall clock, so the
        // T+1 lease is FRESH at `now`.
        let c2 = fabric.run_detection_tick(2, now, &mut gs2).await.expect("node 2 tick");
        assert_eq!(c2, vec![(LOOP_AGENT.to_string(), term_t + 1)], "node 2 claims A @ T+1 (the takeover)");
        fabric.sample_actives(&mut two_actives_ever).await;

        // Node 3 ticks in the SAME round: its snapshot now carries node 2's FRESH T+1 lease, so A is
        // no longer stale to it — the detector stands node 3 DOWN (it claims NOTHING). The relay's
        // latest-wins is what made A fresh-again for node 3; this is the herd collapsing to one.
        let c3 = fabric.run_detection_tick(3, now, &mut gs3).await.expect("node 3 tick");
        assert!(
            c3.is_empty(),
            "the second survivor must NOT double-take-over: it observes the winner's fresh T+1 and stands down (got {c3:?})"
        );
        fabric.sample_actives(&mut two_actives_ever).await;

        // EXACTLY ONE T+1 holder survives across the live nodes (the single winner). Count nodes that
        // report Active at T+1; the loser must read Fenced, not Active.
        let mut active_holders = Vec::new();
        for &id in &NODE_IDS {
            if id == 1 {
                continue; // node 1 was killed
            }
            let auth = fabric.authority(id).expect("authority");
            if let FenceVerdict::Active { term } = auth.fence_for(LOOP_AGENT, term_t + 1).await {
                active_holders.push((id, term));
            }
        }
        assert_eq!(
            active_holders.len(),
            1,
            "EXACTLY ONE survivor may hold A @ T+1 after the race (single-winner), got {active_holders:?}"
        );
        assert_eq!(active_holders[0], (2, term_t + 1), "the first claimer (node 2) is the single winner");

        // The loser (node 3) is FENCED out by node 2's T+1 lease.
        let loser = fabric.authority(3).expect("node 3 authority");
        let loser_verdict = loser.fence_for(LOOP_AGENT, term_t + 1).await;
        assert!(
            matches!(loser_verdict, FenceVerdict::Fenced { committed_holder, .. } if committed_holder == 2),
            "the losing survivor must be FENCED by the winner's lease (got {loser_verdict:?})"
        );

        assert!(
            !two_actives_ever,
            "the thundering herd must collapse to ONE active holder — no two actives ever (no split-brain)"
        );
    }

    /// TEST 3 (observer-blind carry-through): a node whose observed snapshot has NO fresh lease this
    /// round (its relay link is, as far as it can tell, down — every lease aged out together) runs
    /// `run_detection_tick` and claims NOTHING. The fail-safe (enforced inside `detect_takeovers`)
    /// holds THROUGH the fabric tick: a blind node never mass-false-takes-over the fleet.
    #[tokio::test]
    async fn observer_blind_tick_claims_nothing() {
        let mut fabric = LeaseFabric::new(&NODE_IDS).expect("build the lease fabric");
        let term_t = 7u64;

        fabric.claim(1, term_t).await.expect("node 1 claims A @ T");
        let now = loop_agent_issued_at(&fabric);
        fabric.kill(1);

        // A is stale past TTL + grace, and — crucially — NO liveness lease is seeded, so the ONLY
        // observed lease (A) is stale: NOTHING is fresh, exactly the signature of THIS node's own
        // relay link being down. Pre-seed the dwell so that, were the fail-safe absent, A WOULD be
        // eligible — proving it is the fail-safe (not the dwell) that suppresses the takeover.
        assert!(fabric.age_lease(LOOP_AGENT, now - STALE_BY), "age A past TTL + grace");
        let mut gs = BTreeMap::new();
        gs.insert(LOOP_AGENT.to_string(), now - STALE_BY);

        let claimed = fabric.run_detection_tick(2, now, &mut gs).await.expect("blind tick");
        assert!(
            claimed.is_empty(),
            "an observer-blind tick (no fresh lease anywhere) must claim NOTHING — the fail-safe holds through the fabric (got {claimed:?})"
        );
        // The blind tick must leave the grace map UNTOUCHED (a blind tick is not trustworthy
        // evidence of staleness, so it must neither advance NOR clear the dwell — otherwise a
        // recovered link would either mass-take-over or have lost its progress). The entry we
        // pre-seeded is therefore unchanged, NOT cleared.
        assert_eq!(
            gs.get(LOOP_AGENT).copied(),
            Some(now - STALE_BY),
            "a blind tick must leave the grace map untouched (the pre-seeded dwell is preserved as-is)"
        );

        // And the blind tick must NOT have created a fresh T+1 holder: node 2's fence still sees no
        // fresh lease for A (no takeover happened).
        let n2 = fabric.authority(2).expect("node 2 authority");
        assert!(
            matches!(n2.fence_for(LOOP_AGENT, term_t + 1).await, FenceVerdict::Fenced { .. }),
            "no takeover occurred: node 2 holds no fresh T+1 lease for A"
        );
    }
}
