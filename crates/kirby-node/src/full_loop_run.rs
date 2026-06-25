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
