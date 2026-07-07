//! The C-2 boot orchestration (gate G1): boot the genome guest through the
//! sandbox backend, serve the agnostic gateway over its vsock transport, and
//! observe the genome's boot round-trip.
//!
//! This ties the pieces together so both the daemon binary (`kirby-node boot`)
//! and the integration test drive the SAME path: prepare the gateway with an
//! event observer, boot the guest through a [`SandboxBackend`] (Firecracker today),
//! serve the gateway on the instance's [`GatewayTransport`], and wait for the
//! genome's "hello" event (`session=<task>`) to arrive over vsock. That arriving
//! event is the machine-checkable G1 proof the genome booted and completed a
//! `GetSessionContext` round-trip.
//!
//! This module is the AGNOSTIC orchestration: it speaks the [`crate::sandbox`]
//! seam (`GuestSpec` in, `SandboxInstance` out), the agnostic gateway, treasury,
//! and rail. The backend MECHANICS (which binaries, the jail, the cgroup parent,
//! the TAP) live behind the backend; this module never names a Firecracker type.
//!
//! Everything past boot plus the vsock round-trip is out of C-2 scope: metering
//! and the budget halt (C-4), the brokered act (C-6), snapshot and resume (C-7),
//! the entropy re-derive (C-8), and consensus (C-9).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kirby_proto::Event;

use crate::checkpoint::{CheckpointArtifact, LatestCheckpoint};
use crate::config::BrainBackendKind;
#[cfg(target_os = "linux")]
use crate::firecracker::FirecrackerBackend;
use crate::gateway::{GatewayService, Session};
// NodeIdentity (the ONE key rooting identity/presence/memory) backs the real EngramStore
// when a memory relay set is configured. `nerve` is cross-platform (host-side nostr-sdk).
use crate::nerve::NodeIdentity;
use crate::rail::{
    Actuator, BrainBackend, CashuSettlement, CdkEcash, CompositeRail, EngramStore, LightningSettlement,
    MemoryBackend, MockRail, NostrActuator, Rail, RoutstrBrain, RoutstrKeyBrain, SettlementProvider,
    SledStrandedSink, StubBrain, StubMemory,
};
use crate::sandbox::{GatewayTransport, GuestImage, GuestSpec, SandboxBackend, SandboxInstance};
use crate::treasury::Treasury;
#[cfg(target_os = "macos")]
use crate::vz::VzBackend;

/// Where the genome image artifacts live (built by `nix build .#genome-image`).
/// Resolved from `--image-dir` or the `KIRBY_GENOME_IMAGE` env var, both of
/// which point at the image output (containing vmlinux and rootfs.squashfs).
#[derive(Clone)]
pub struct ImagePaths {
    pub vmlinux: PathBuf,
    pub rootfs: PathBuf,
}

impl ImagePaths {
    /// Resolve the image artifacts from an image directory (the `genome-image`
    /// nix output). The directory holds `vmlinux` and `rootfs.squashfs`.
    pub fn from_dir(image_dir: &std::path::Path) -> anyhow::Result<Self> {
        let vmlinux = image_dir.join("vmlinux");
        let rootfs = image_dir.join("rootfs.squashfs");
        if !vmlinux.exists() {
            anyhow::bail!("vmlinux not found at {}", vmlinux.display());
        }
        if !rootfs.exists() {
            anyhow::bail!("rootfs.squashfs not found at {}", rootfs.display());
        }
        Ok(ImagePaths { vmlinux, rootfs })
    }
}

/// Inputs for one boot demonstration.
#[derive(Clone)]
pub struct BootConfig {
    pub image: ImagePaths,
    pub node_id: String,
    pub task: String,
    pub budget_sats: u64,
    pub initial_sats: u64,
    pub allow: Vec<String>,
    pub guest_cid: u32,
    pub gateway_port: u32,
    pub vcpu_count: u8,
    pub mem_size_mib: usize,
    /// How long to wait for the genome's boot hello event after the VM is up.
    pub hello_timeout: Duration,
    /// The genome workload the daemon requests on the kernel command line. `None`
    /// idles after the boot round-trip (C-2 / G1); `Some("burn")` runs the C-4
    /// metering workload (allocate memory + spin CPU) so the meter trips the halt
    /// (G2); `Some("app-checkpoint")` submits portable logical state for resume;
    /// `Some("raw-egress")` runs the C-5 egress probe (attempt direct outbound,
    /// which must fail, gate G4).
    pub workload: Option<String>,
    /// The `[brain]` knobs for the MIND workload (brain-stub). `Some` only when
    /// `workload = Some("brain")`: it both selects the brain rail
    /// (`CompositeRail { base: MockRail, brain: StubBrain }`, F3) and travels to the
    /// genome on the kernel command line via [`crate::sandbox::GuestSpec::brain`].
    /// `None` for every other workload (the plain `MockRail`, no brain cmdline).
    pub brain: Option<crate::config::BrainConfig>,
    /// The `[memory]` knobs for the durable-mind-state workload (memory-stub). `Some`
    /// only when `workload = Some("memory")`: it both selects the memory backend
    /// (`StubMemory`, injected onto the gateway via `with_memory_backend`) and travels the
    /// genome-side knobs (`max_cost_sats`, `tick_secs`) to the genome on the kernel
    /// command line. `None` for every other workload (no memory backend, no memory cmdline).
    pub memory: Option<crate::config::MemoryConfig>,
    /// The `[agent]` knobs for the CAPABLE workload. `Some` only when
    /// `workload = Some("capable")`, alongside BOTH `brain` and `memory` being `Some` (the
    /// capable agent composes the `Completion` rail + the `Memory` backend on one gateway). It
    /// carries the loop cadence + recall depth to the genome on the kernel command line
    /// (`kirby.diarist_*=`), the same way the brain/memory knobs travel. `None` otherwise.
    pub agent: Option<crate::config::AgentConfig>,
    /// The outward-actuator config (the agent's voice). `Some` only for the `capable` workload:
    /// `boot_and_observe` builds a `NostrActuator` from it (node identity key + the relay set) and
    /// attaches it to the `CompositeRail` (`with_actuator`), so an `Act::Actuate` is signed +
    /// published daemon-side. `None` for every other workload, so the rail performs ZERO publishes.
    pub social: Option<crate::config::SocialConfig>,
    /// The C-EGRESS policy (the `http.fetch` actuator). `Some` ONLY when `[egress] enabled` for the
    /// capable workload: `boot_and_observe` builds an `HttpEgressActuator` from it and composes it
    /// ALONGSIDE the `NostrActuator` (a kind-router), so an `Act::Actuate{http.fetch}` is guarded +
    /// performed daemon-side behind the SSRF floor. `None` (the default, deny-by-default) => the
    /// `http.fetch` token is not granted and the rail performs ZERO fetches.
    pub egress: Option<crate::egress::EgressPolicy>,
    /// The `[nip60]` wallet-backup config (relays + write quorum). NIP-60 is OPT-IN: with an empty
    /// relay set, `build_routstr_brain` wires NO Nip60Store and the wallet opens exactly as before;
    /// when relays are configured it connects a store, seeds the NUT-13 counter floor from the
    /// 17375 head BEFORE opening the wallet, and publishes the config — the cross-machine money-
    /// continuity backup. Ignored by every non-`routstr` backend (only the Cashu wallet path).
    pub nip60: crate::config::Nip60Config,
    /// The node relay URL — the single-relay DEV fallback for [`crate::config::Nip60Config::resolve`]
    /// when `[nip60]` lists no relays of its own.
    pub fleet_relay: String,
    /// Wire a per-VM TAP into the VM and lock it down with nftables default-deny
    /// egress (C-5, spec 3.7, gate G4). When true, the VM gets a network interface
    /// it can ATTEMPT egress on, the host kernel drops that egress (counted), and
    /// an eBPF TC classifier meters the bytes. When false (the C-2/C-4 default),
    /// the VM is vsock-only (no TAP), already egress-isolated structurally.
    pub lockdown_egress: bool,
    /// Boot the VM so it can be SNAPSHOTTED and resumed on another node (C-7, gate
    /// G6): the backend applies the cross-CPU template (T2CL) at create. The
    /// C-2..C-6 default is false (no template, no snapshot).
    pub snapshot_capable: bool,
    /// Optional app-level checkpoint to hand to a freshly booted genome through
    /// `GetSessionContext`. This is the portable Linux<->macOS resume path: the
    /// backend performs an ordinary cold boot, while the shared gateway tells the
    /// genome which logical state blob to rehydrate.
    pub restore_checkpoint: Option<CheckpointArtifact>,
    /// The OPTIONAL per-agent lease fence for the LIVE run path (fleet-host S1, spec
    /// 2.2). `None` is the single-agent default: the gateway is UNFENCED exactly as
    /// before (a bare `kirby run` is byte-identical). `Some` is a fleet tenant: the
    /// gateway built here attaches `with_lease_fence_for(handle, agent_id, vm_term)`, so
    /// STEP 0 of `authorize_capability` denies + debits 0 unless this node holds the
    /// agent's lease. This is where the previously-zero-caller fence becomes wired into a
    /// real run (gate G-FENCE-LIVE): live money is fenced only because of this attach.
    pub lease_fence: Option<crate::gateway::LeaseFence>,
    /// INC2a: the agent's shared co-sign COORDINATOR. For a DISTRIBUTED FROST keystore
    /// (placement.json present) it holds the ONE [`crate::relay_transport::CoordinatorRelayHub`]
    /// that both the voice actuator and the DM path load their `QuorumSigner` through -- the SAME
    /// instance the beacon signer uses in `run_agent`, so every sign site shares one hub routes-map
    /// and holder set (cross-talk-free by construction). For a co-located / non-FROST boot it holds
    /// no hub ([`crate::relay_transport::AgentCosign::none`]); every load is byte-identical to before.
    pub cosign: std::sync::Arc<crate::relay_transport::AgentCosign>,
}

/// The gateway event receiver the genome's `ReportEvent`s arrive on (diagnostic
/// only, never billed, G3c). Returned by `boot_and_observe` so a caller can read
/// post-boot events (the C-5 raw-egress probe outcomes, gate G4).
pub type EventStream = tokio::sync::mpsc::UnboundedReceiver<Event>;

/// Aborts the detached gateway serve task when the run tears down. The serve task
/// holds a `GatewayService` clone, and that clone holds a `Treasury` Arc, which
/// holds the sled exclusive lock on the per-node treasury dir. `serve_gateway_over`
/// is a listener loop that never returns on its own (the genome legitimately
/// reconnects during a live run), so without this the task outlives the VM and
/// pins the treasury lock indefinitely. A same-process resume on the same `node_id`
/// (the G-run-3 sequence) then cannot reopen the treasury (sled `WouldBlock`).
///
/// Dropping this guard aborts the task; the runtime then drops the serve task's
/// `GatewayService` (and its `Treasury` Arc), releasing the lock. The abort is
/// asynchronous, so the next [`open_treasury_retrying`] absorbs the brief window
/// until the dropped Arc actually frees the lock. The money / authorize-order /
/// dedupe logic is untouched: this only ends a listener task, it never debits.
///
/// Bound by every caller (as `_serve_guard`) so it lives exactly as long as the
/// run that owns the VM, then drops at run-end alongside the instance halt.
#[must_use = "dropping the ServeGuard aborts the gateway serve task and frees the treasury lock; bind it for the run's lifetime"]
pub struct ServeGuard {
    handle: tokio::task::AbortHandle,
    /// Held so the NIP-17 DM inbound task (task #12) shuts down gracefully when the run ends:
    /// dropping this sender fires `run_dm_inbound`'s shutdown arm, so it disconnects its relay
    /// client and returns. `None` when the DM path is not enabled (no task was spawned).
    _dm_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// Held so the Cut A (#115) NIP-60 backup flusher publishes ONE FINAL snapshot at ABRUPT
    /// teardown — the drop-fired "estate" flush FALLBACK. Dropping this sender fires a spawned
    /// shutdown task's `flush()` (see the `Some(flusher)` wiring below). This is now the
    /// PANIC/KILL fallback ONLY: on the GRACEFUL path the run driver calls [`Self::flush_estate`]
    /// (awaited to completion) BEFORE this guard drops, which CONSUMES the dirty flag, so the
    /// drop-fired task then no-ops (`!dirty`) — no double publish. It survives to cover a panic /
    /// abrupt unwind where `flush_estate` was never reached, on a best-effort basis (a detached
    /// task can still lose the race with process exit — which is exactly why the graceful path no
    /// longer relies on it). `None` when no cdk-wallet brain configured a flusher.
    _nip60_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// The Cut A (#115) NIP-60 backup flusher itself, held so the GRACEFUL teardown can AWAIT one
    /// final "estate" flush via [`Self::flush_estate`] (rather than racing process exit through the
    /// detached drop task above). `None` when no cdk-wallet brain configured a flusher.
    nip60_flusher: Option<Arc<crate::rail::Nip60BackupFlusher>>,
    /// Cut B (#115): the handles for a best-effort re-publish of the CURRENT kind:17375 counter
    /// mirror at graceful teardown (via [`Self::flush_estate`], AFTER the proof flush). The boot
    /// 17375 publish is a ONE-SHOT snapshot; this re-captures the counter mirror as it stands at
    /// death (the shadow map has observed every increment this run) so a graceful death never leaves
    /// the relay's counter floor behind the wallet's true derivation counter. Populated ONLY when
    /// `[nip60]` is configured (the SAME opt-in gate as `nip60_flusher`); `None` for a bare /
    /// non-nip60 host → no counter estate publish, unchanged behavior.
    nip60_counter_estate: Option<Nip60CounterEstate>,
    /// #62 (earn-loop deployability): the settlement-poller task handle, aborted in `Drop` exactly
    /// like `handle` (the serve task) so the poller shuts down cleanly with the daemon. `Some` only
    /// when settlement is wired (an earn agent); `None` for every non-earn agent, whose boot spawns
    /// NO poller and is byte-identical.
    settle_poller: Option<tokio::task::AbortHandle>,
}

/// The handles a graceful teardown needs to re-publish the current kind:17375 counter mirror
/// (Cut B, #115): the NIP-60 store to publish through, the counter decorator whose
/// `keyset_counters()` is the current mirror, and the wallet's mint URL for the config's mint list.
type Nip60CounterEstate = (
    Arc<crate::nip60::Nip60Store>,
    Arc<crate::nip60_counter::Nip60CounterDb>,
    String,
);

impl ServeGuard {
    /// AWAIT one final NIP-60 backup "estate" flush at graceful teardown (#115 codex #3). Called by
    /// the run driver AFTER the metered run returns for any GRACEFUL reason (die-when-broke /
    /// BudgetExhausted, or the `max_run_secs` safety ceiling) and BEFORE this guard drops, so the
    /// last-interval mutation's snapshot is guaranteed PUBLISHED (awaited to completion), not raced
    /// against process exit by the detached drop-fired task. Best-effort: an error is logged and
    /// NEVER propagated (the cdk wallet is already the truth; the next boot re-snapshots). A no-op
    /// when no flusher is configured. Because `flush()` CONSUMES the dirty flag, the subsequent
    /// drop-fired fallback observes `!dirty` and does nothing — so a graceful teardown publishes
    /// EXACTLY ONCE.
    pub async fn flush_estate(&self) {
        if let Some(flusher) = &self.nip60_flusher {
            if let Err(e) = flusher.flush().await {
                tracing::warn!(
                    error = %e,
                    "NIP-60 estate flush at graceful teardown failed (spend truth is unaffected; the next boot re-snapshots)"
                );
            } else {
                tracing::debug!("NIP-60 estate flush at graceful teardown complete (awaited)");
            }
        }
        // Cut B (#115): AFTER the proof flush, re-publish the CURRENT counter mirror (kind:17375).
        // The boot publish is a one-shot; the shadow has since observed every increment this run, so
        // this captures the true high-water counter at death — a graceful death then never leaves the
        // relay's counter floor behind the wallet (which would let a same-seed reconstruct re-derive
        // already-spent NUT-13 secrets). BEST-EFFORT + fail-soft (same posture as the proof flush): a
        // publish error is logged, NEVER panics or blocks teardown. Ordered after the proof flush so
        // the counter that ships reflects any last-interval mutation's proofs the flush just backed up.
        //
        // #125 BOUNDARY (freshness, NOT collision — do not delete/reorder this arm without reading):
        // this estate publish covers GRACEFUL death (die-when-broke + the max_run ceiling); the next
        // boot's publish covers reboot. What is NOT covered: counter advances lost to an ABRUPT death
        // (panic / SIGKILL) after the last publish. That residual is SAFE because B1 (the union-max
        // seed at open, mint_rig.rs) makes the published floor COMPLETE — so the lost advances are a
        // CONTIGUOUS run of used counters ABOVE a present floor, never an omission-to-zero: a
        // fresh-store NUT-13 restore scans forward through them (no unused gap to trip gap_limit) and
        // the mint (NUT-07) rejects any re-issued secret → post-restore derivation FRICTION, never a
        // double-spend / phantom / missed proof. Periodic + abrupt-death re-publish is deferred to
        // #125 (aligned with #123's abrupt-death residual class).
        if let Some((store, counter_db, mint_url)) = &self.nip60_counter_estate {
            if let Err(e) = store
                .publish_wallet_config(counter_db.keyset_counters(), vec![mint_url.clone()])
                .await
            {
                tracing::warn!(
                    error = %e,
                    "NIP-60 counter estate publish at graceful teardown failed (advisory; the mint remains truth and the next boot re-seeds the floor)"
                );
            } else {
                tracing::debug!("NIP-60 counter estate publish at graceful teardown complete (awaited)");
            }
        }
    }

    /// TEST-ONLY: build a `ServeGuard` carrying just a NIP-60 flusher, so the estate-flush behavior
    /// (codex #3) is exercisable WITHOUT booting a VM. The abort handle wraps a trivial spawned task
    /// (never observed); the DM/nip60-shutdown senders are `None` (no fallback task in the test).
    #[cfg(test)]
    pub(crate) fn for_estate_test(nip60_flusher: Arc<crate::rail::Nip60BackupFlusher>) -> Self {
        let noop = tokio::spawn(async {});
        ServeGuard {
            handle: noop.abort_handle(),
            _dm_shutdown: None,
            _nip60_shutdown: None,
            nip60_flusher: Some(nip60_flusher),
            nip60_counter_estate: None,
            settle_poller: None,
        }
    }

    /// TEST-ONLY (Cut B, #115): build a `ServeGuard` carrying ONLY the counter-estate bundle (no
    /// proof flusher), so the graceful-teardown 17375 re-publish is exercisable WITHOUT booting a
    /// VM. `flush_estate()` then publishes the given store's config from the counter decorator's
    /// current mirror. RED-on-revert target for T5.
    #[cfg(test)]
    pub(crate) fn for_counter_estate_test(estate: Nip60CounterEstate) -> Self {
        let noop = tokio::spawn(async {});
        ServeGuard {
            handle: noop.abort_handle(),
            _dm_shutdown: None,
            _nip60_shutdown: None,
            nip60_flusher: None,
            nip60_counter_estate: Some(estate),
            settle_poller: None,
        }
    }
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        self.handle.abort();
        // #62: abort the settlement poller alongside the serve task so it stops polling the mint
        // the instant the run tears down (no orphaned task pinning the wallet/treasury).
        if let Some(poller) = &self.settle_poller {
            poller.abort();
        }
        // `_dm_shutdown` drops with the struct -> the DM inbound task's shutdown arm fires.
        // `_nip60_shutdown` drops with the struct -> the ABRUPT-death fallback flush fires (a
        // detached task). On the graceful path `flush_estate` already ran + consumed `dirty`, so
        // that fallback no-ops (`!dirty`); it exists only for a panic/kill that skipped it.
    }
}

/// Spawn the #62 SETTLEMENT POLLER task and return its [`tokio::task::AbortHandle`] (bound onto the
/// [`ServeGuard`] so it aborts cleanly at teardown). Every `interval` it runs ONE
/// [`GatewayService::pending_settlement_sweep`] cycle on `service`: enumerate the DAEMON's durable
/// ISSUED-but-uncredited charge set ([`crate::treasury::Treasury::issued_uncredited_charge_ids`])
/// and `settle_charge(&id, "")` each — the mint poll → mint → treasury credit → `PaymentSettled`
/// enqueue the genome waits on. Per-charge errors are CLASSIFIED inside the sweep (a still-UNPAID
/// quote logs at DEBUG and continues; a real mint/store/treasury fault logs at WARN), so the loop
/// never dies. Shared by boot (below, gated on a wired settlement) AND the deployable-path teeth,
/// so both drive the SAME production trigger — not a bespoke test path.
///
/// WHY THIS EXISTS — the earn-loop deployability GAP this closes:
/// [`GatewayService::settle_charge`] is the ONLY code that polls the mint (`check_mint_quote_status`),
/// mints, credits the treasury (`credit_verified`), and enqueues the `PaymentSettled` inbox event the
/// genome's oracle_tick settlement branch waits for. Before this task it had NO production caller
/// (every caller was a test), so a deployed daemon never settled a paid charge: the customer paid,
/// the mint was never polled → no credit → no answer. This task is the missing production trigger.
///
/// ── PART-A CLASS-CLOSURE TABLE (#62; ships in the diff — kirby's gate audits it row-by-row) ──────
/// Method: for every pub/pub(crate) fn that mutates money/treasury/wallet/charge/lifecycle state,
/// grepped all callers, classified test vs prod, traced transitive prod-reachability. The
/// "settle_charge shape" is EXACTLY ONE prod-dead subtree; no other money/lifecycle fn is
/// test-only-driven.
///
/// | fn (file:line)                             | callers                          | prod path? | disposition |
/// |--------------------------------------------|----------------------------------|------------|-------------|
/// | GatewayService::settle_charge (gateway.rs) | driven by pending_settlement_sweep ← poller | **GAP** (pre-#62) | **WIRED** (this poller, via the treasury issued-charge index) |
/// | Treasury::issued_uncredited_charge_ids (treasury.rs) | pending_settlement_sweep ← poller | REACHABLE | the durable poll source — the dedicated `issued_charges` tree (#62 ruling) |
/// | GatewayService::settle_inner (gateway.rs)  | only settle_charge               | GAP (transitive) | closed by wiring settle_charge |
/// | Treasury::credit_verified (treasury.rs)    | prod = ONLY settle_inner; 7 test | GAP (transitive) | closed by wiring settle_charge |
/// | SettlementProvider::verify_settlement      | prod = ONLY settle_inner         | GAP (transitive) | closed by wiring settle_charge |
/// | push_typed(PaymentSettled) (gateway.rs)    | that kind ONLY in settle_inner   | **GAP** (that kind) | closed by wiring settle_charge |
/// | SettlementProvider::issue                  | authorize_issue_charge ← RPC     | REACHABLE  | not a gap |
/// | authorize_issue_charge (gateway.rs)        | dispatch ← RPC                   | REACHABLE  | not a gap |
/// | Treasury::debit_and_record / debit_metered / reconcile_to_observed | prod authorize/meter/boot-G4 | REACHABLE | not a gap |
/// | EcashProvider::mint_send_token             | prod actuator + nip60 delegate   | REACHABLE  | not a gap |
/// | mint_rig::mint_into_wallet_operator_pays   | prod fund-wallet CLI             | REACHABLE  | not a gap (separate FUND path) |
///
/// CLOSURE CONCLUSION: wiring a single production trigger for `settle_charge` closes the ENTIRE
/// class — `credit_verified` and `verify_settlement` become prod-reachable transitively.
///
/// ── PART-B MULTI-WRITE-SEAM CLASS SWEEP (#62 follow-up; ships in the diff — audited row-by-row) ──
/// Method: enumerated EVERY place in the touched money paths (treasury.rs, gateway.rs, boot.rs)
/// where two-or-more writes must land TOGETHER for correctness, then classified each: WRAPPED in one
/// sled tx, already-atomic, or deferred-with-reason. Motivation: a two-write ISSUE seam
/// (`debit_and_record` + a separate `record_issued_charge`) had a crash window that stranded a
/// payable charge unindexed (took-money-never-answered). This sweep proves no sibling seam hides the
/// SAME shape one write over.
///
/// | seam (path)                         | the writes                                   | atomic?         | disposition |
/// |-------------------------------------|----------------------------------------------|-----------------|-------------|
/// | ISSUE (gateway authorize_issue_charge → treasury) | ledger row + `issued_charges` poll-index | **WAS 2 writes** | **WRAPPED** — `Treasury::record_charge_atomic` commits both in ONE tx over (balance, ledger, issued_charges). THIS cut. |
/// | DEBIT generic act (treasury debit_and_record)     | balance − cost  + ledger row             | YES (one tx)    | already-atomic — one `.transaction((balance, ledger))`. Unchanged (a non-charge act must NOT write `issued_charges`). |
/// | METER tick (treasury debit_metered)               | balance − burn (NO ledger row)           | N/A (single write) | not a seam — one balance write, no paired write (rent leaves no ledger row). |
/// | CREDIT / settle (treasury credit_verified)        | balance + amount + `credit_ledger` row   | YES (one tx)    | already-atomic — one `.transaction((balance, credit_ledger))` (incl. the terminal-overflow marker branch). |
/// | RECONCILE (treasury reconcile_to_observed)        | balance := observed (single tx set)      | YES (one tx)    | already-atomic — single balance set. |
/// | SETTLE deliver (gateway settle_inner)             | `credit_verified` (sled) + PaymentSettled ENQUEUE | **NO — and correctly so** | NOT wrappable: PaymentSettled is an IN-MEMORY inbox push, not a 2nd sled write, so it cannot join a sled tx. The credit-durable / push-in-memory crash window (credited-but-unanswered) = **TASK #50** (durable dead-letter store; gates unattended-live). Deferred, out of this cut. |
/// | INDEX-only (treasury record_issued_charge)        | `issued_charges` insert (single write)   | N/A (single write) | not a seam standalone; the ISSUE seam above now writes the index INSIDE the ledger tx. Kept pub for the direct-index unit tooth; no prod caller pairs it with a second write anymore. |
///
/// PART-B CONCLUSION: every multi-write seam in the touched paths is either ONE sled tx (ISSUE now
/// wrapped; DEBIT / CREDIT / RECONCILE already were) or a documented deferral (SETTLE's in-memory
/// PaymentSettled push → #50). No un-wrapped, un-justified two-sled-write seam remains.
///
/// ── FINAL DESIGN + CLASS-CLOSURE DISPOSITIONS (kirby's ruling — the dedicated issued-charge index)
/// The poll source is the DAEMON's dedicated, durable `issued_charges` sled tree
/// ([`crate::treasury::Treasury::issued_uncredited_charge_ids`]) — charge_id -> a plain method-tag
/// byte, written ONLY by `authorize_issue_charge` (the single IssueCharge act) via
/// `record_issued_charge`, minus `credit_ledger`, filtered to the Lightning rail. It is NOT a scan
/// of the `ledger`'s `proof` field. A cold cross-model review found the `ledger` `proof` is
/// POLYMORPHIC — non-charge acts write it too (gateway.rs generic/brain, memory, capability rows;
/// only the IssueCharge path writes a `ChargeIssued` proof) — so a ledger scan had to HEURISTICALLY
/// (decode + round-trip guard) tell a charge proof from a colliding non-charge proof, and a false
/// positive would FALSELY CREDIT a non-charge act. The dedicated tree removes the heuristic: a
/// non-charge act simply has no key in `issued_charges`, so it is excluded by construction.
///
/// The five poll-source / settlement issues the review enumerated, and their dispositions:
///   #2 FALSE-CREDIT via the polymorphic `ledger` `proof` — CLOSED HERE, structurally: a non-charge
///      act is never written to `issued_charges`, so it can never be polled or credited. No heuristic.
///   #4 CASHU-WRONG-RAIL (a Cashu charge polled on the Lightning `settle_charge(id, "")` path) —
///      CLOSED HERE: the charge's rail is stored in the index and the poller filters to Lightning
///      (a Cashu charge is settled by token evidence, never a mint-quote poll).
///   #1 CREDITED-BUT-UNANSWERED (the credit is durable but the `PaymentSettled` push is in-memory,
///      so a crash after credit / before delivery drops the genome's answer) — deferred to the
///      existing TASK #50 (a durable pending-charge / dead-letter store; gates unattended-live).
///   #3 CRASH-MINTED PROOFS SPENDABLE before the Issued-recovery credit wins — follow-up TASK #73.
///   #5 UNBOUNDED unpaid-charge POLL GROWTH (an unpaid charge is retained and re-polled forever) —
///      follow-up TASK #74 (expiry / backoff / cap on the poll set).
///
/// The crash-window RE-POLL that makes an already-paid charge recoverable still holds: an ISSUED-
/// but-uncredited charge KEEPS its `issued_charges` key (no `credit_ledger` row) until it is
/// credited, so the poller re-polls it and `settle_charge` credits the HELD proofs via
/// `verify_settlement`'s Issued-recovery branch (no re-mint). BACK-COMPAT: a charge issued by a
/// PRIOR binary (before the `issued_charges` tree existed) has no key here, so it is not polled —
/// acceptable, a re-fire issues a fresh (indexed) charge. Idempotency: `credit_verified` is
/// idempotent on charge_id and the mint is idempotent per quote, so the poller never double-credits.
pub fn spawn_settlement_poller(
    service: GatewayService,
    interval: Duration,
) -> tokio::task::AbortHandle {
    let handle = tokio::spawn(async move {
        // `tokio::time::interval` fires the FIRST tick IMMEDIATELY, so a charge already paid when
        // the daemon comes up (e.g. paid while it was down) settles on the first cycle rather than
        // after a full interval elapses.
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            service.pending_settlement_sweep().await;
        }
    });
    handle.abort_handle()
}

/// The outcome of a boot demonstration (the G1 evidence).
pub struct BootOutcome {
    /// The VM reached Running.
    pub reached_running: bool,
    /// The genome's boot hello event, if it arrived in time. Its detail is
    /// `session=<task>` (the G1 assertion target).
    pub hello: Option<Event>,
    /// The session context the gateway handed the genome (the budget snapshot).
    pub budget_sats: u64,
    /// Shared handle to checkpoints this boot's gateway accepted from the genome.
    /// Most boot/meter/egress paths ignore it; app-checkpoint resume uses it to
    /// persist the exact logical-state blob the daemon accepted.
    pub checkpoints: LatestCheckpoint,
}

/// Open the daemon treasury, tolerating a transient sled exclusive-lock (the FIX-4
/// race): when a prior holder on the same `node_id` (e.g. a just-finished bootstrap
/// run, before a `resume` run) drops its sled handle, the OS file-descriptor reclaim
/// can lag, so a back-to-back open occasionally races the lock. Retry ONLY on lock
/// contention, up to `timeout`; any other error (corruption, real I/O) returns at once.
/// Same store, balance, and dedupe ledger; only the open is retried.
async fn open_treasury_retrying(
    path: &std::path::Path,
    seed_sats: u64,
    timeout: Duration,
) -> Result<Treasury, crate::treasury::TreasuryError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match Treasury::open(path, seed_sats) {
            Ok(t) => return Ok(t),
            Err(e)
                if crate::treasury::is_lock_contention(&e)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Boot the genome through the sandbox backend, serve the agnostic gateway over
/// its vsock transport, and wait for the boot hello event (gate G1). Returns the
/// booted instance (so the caller halts it after inspecting the outcome), the
/// outcome, the daemon-owned treasury (so a metered run, C-4, debits the SAME
/// counter the gateway uses, D-9), the gateway event receiver (so the caller
/// can keep reading post-boot genome events, e.g. the C-5 raw-egress probe
/// outcomes, gate G4), and a [`ServeGuard`] the caller binds for the run's
/// lifetime (its drop aborts the gateway serve task so the treasury lock is
/// freed for a same-process resume). On a boot failure the guest is halted here
/// and the error is returned.
///
/// Uses the mock rail (the C-2/C-4/C-5 paths do no real brokered act); the C-6
/// brokered act injects the real rail via [`boot_and_observe_with_rail`]. The MIND
/// workload (brain-stub F3) injects a [`CompositeRail`] instead: a `Completion` act
/// routes to the [`StubBrain`] (the daemon's inference backend), every other act to
/// the base `MockRail` (and in brain mode the gateway allowlist denies non-Completion
/// acts before they reach it, R3). Selected by `config.brain`, which is `Some` iff
/// the workload is `brain`.
pub async fn boot_and_observe(
    config: BootConfig,
) -> anyhow::Result<(Box<dyn SandboxInstance>, BootOutcome, Treasury, EventStream, ServeGuard)> {
    // The outward actuators (the agent's voice + its reach). Built once if the workload configured
    // them (the capable workload), then attached to the CompositeRail below. None for every other
    // workload, so the rail performs ZERO outward acts.
    //
    // The Nostr actuator (the `nostr.*` kinds) holds the DM/publish key material; the HTTP egress
    // actuator (the `http.fetch` kind) holds a reqwest client + the SSRF policy and NO key material.
    // They are SEPARATE structs — composed by a kind-router when both are present — so the egress
    // client and the DM/publish keys never co-habit ("a new entry point needs its own guards").
    let nostr_actuator: Option<Arc<dyn Actuator>> = match &config.social {
        Some(social) => Some(build_nostr_actuator(social, &config.cosign).await?),
        None => None,
    };
    // Deny-by-default: `config.egress` is `Some` ONLY when `[egress] enabled` (set in run_agent).
    let egress_actuator: Option<Arc<dyn Actuator>> = config.egress.as_ref().map(|policy| {
        Arc::new(crate::egress::HttpEgressActuator::new(policy.clone())) as Arc<dyn Actuator>
    });
    let actuator: Option<Arc<dyn Actuator>> = match egress_actuator {
        // No egress door: the Nostr actuator alone (or None) — byte-identical to pre-egress.
        None => nostr_actuator,
        // Egress enabled: a kind-router routes `http.fetch` -> egress and `nostr.*` -> nostr.
        Some(egress) => Some(Arc::new(crate::rail::CompositeActuator::new(
            nostr_actuator,
            Some(egress),
        ))),
    };
    let rail: Arc<dyn Rail> = match &config.brain {
        // The REAL brain (brain-routstr): a CompositeRail whose brain is a RoutstrBrain
        // over a funded, persistent cdk wallet. Building it opens the wallet, recovers
        // any incomplete sagas, and reconciles wallet >= treasury BEFORE the VM boots
        // (REFUSE-TO-BOOT on a shortfall, R2-5), so a real `Completion` is served by a
        // real Routstr node, paid from the treasury.
        Some(brain) if brain.backend == BrainBackendKind::Routstr => {
            let treasury_remaining = peek_treasury_remaining(&config).await?;
            let (brain_backend, nip60_flusher, nip60_counter_estate, settlement_provider) =
                build_routstr_brain(brain, treasury_remaining, &config.nip60, &config.fleet_relay)
                    .await?;
            // Carry the Cut A (#115) backup flusher AND the Cut B counter-estate bundle (both `Some`
            // only when NIP-60 is configured) into the run so a graceful shutdown fires ONE final
            // proof-snapshot flush AND re-publishes the current 17375 counter mirror (both via the
            // ServeGuard's awaited `flush_estate`, below).
            return boot_and_observe_with_rail(
                config,
                Arc::new(attach_actuator(
                    CompositeRail::new(Arc::new(MockRail::new()), brain_backend),
                    actuator,
                )),
                nip60_flusher,
                nip60_counter_estate,
                settlement_provider,
            )
            .await;
        }
        // The prepaid API-KEY brain (mint-independent fallback): a CompositeRail whose
        // brain is a RoutstrKeyBrain over a node-held custodial balance. Building it loads
        // the bearer key and probes /v1/balance/info to validate the key works and read the
        // custodial balance (REFUSE-TO-BOOT on an unusable key). The custodial key balance is
        // the AUTHORITATIVE spendable truth here (the EXTERNAL-BALANCE-IS-TRUTH model), so
        // instead of asserting the counter is already backed we RECONCILE the metabolism
        // counter to the probed balance (G4): reconcile-DOWN degrades the budget to real
        // money (an external spend the counter had not seen); reconcile-UP lets a topped-up
        // agent think again. No wallet/mint/saga: the key is the only credential.
        Some(brain) if brain.backend == BrainBackendKind::RoutstrKey => {
            let (brain_backend, balance_sats) = build_routstr_key_brain(brain).await?;
            match g4_reconcile_action(balance_sats) {
                G4Action::Reconcile(observed) => {
                    // Open the SAME per-node treasury the gateway will use, SET the counter to
                    // the observed custodial balance, then drop the handle BEFORE
                    // `boot_and_observe_with_rail` reopens it (sequential; the reconcile does its
                    // own txn + db.flush before the drop, and `open_treasury_retrying` absorbs the
                    // brief sled/flock reclaim lag). After the SET, counter == balance.
                    let treasury = open_treasury_retrying(
                        &treasury_path_for(&config.node_id),
                        config.initial_sats,
                        Duration::from_secs(5),
                    )
                    .await?;
                    let outcome = treasury.reconcile_to_observed(observed)?;
                    drop(treasury);
                    tracing::info!(
                        ?outcome,
                        balance_sats,
                        "G4: reconciled the metabolism counter to the custodial key balance"
                    );
                }
                G4Action::SkipZero => {
                    tracing::warn!(
                        "G4: prepaid key balance probed 0 sat; not zeroing the counter \
                         (fetch_balance floors sub-sat dust to 0, and a spurious 0 must not kill \
                         a funded agent) — the key gates real spend, so die-when-broke fires at \
                         first spend if truly empty"
                    );
                }
            }
            Arc::new(attach_actuator(
                CompositeRail::new(Arc::new(MockRail::new()), brain_backend),
                actuator,
            ))
        }
        // The stub brain (unchanged): deterministic, no network, no money.
        Some(brain) => Arc::new(attach_actuator(
            CompositeRail::new(
                Arc::new(MockRail::new()),
                Arc::new(StubBrain::new(brain.bytes_per_sat)),
            ),
            actuator,
        )),
        None => {
            // No brain => a bare MockRail (no CompositeRail to hold the actuator). The capable
            // workload always has a brain, so this only fires for a misconfig (social + no brain);
            // the dropped actuator is harmless (a publish would be DENIED_NOT_ALLOWLISTED anyway).
            if actuator.is_some() {
                tracing::warn!(
                    "a social actuator was configured but the workload has no brain (no CompositeRail to hold it); it is dropped"
                );
            }
            Arc::new(MockRail::new())
        }
    };
    // The non-Routstr arms configure no NIP-60 backup flusher NOR counter estate (only the real
    // cdk-wallet brain has a wallet + counter mirror to back up); the Routstr arm returns early above
    // carrying both.
    boot_and_observe_with_rail(config, rail, None, None, None).await
}

/// Attach an optional outward [`Actuator`] to a [`CompositeRail`] (the agent's voice), returning
/// the rail unchanged when there is none. Keeps the `boot_and_observe` brain match readable.
fn attach_actuator(rail: CompositeRail, actuator: Option<Arc<dyn Actuator>>) -> CompositeRail {
    match actuator {
        Some(actuator) => rail.with_actuator(actuator),
        None => rail,
    }
}

/// Build the [`NostrActuator`] (the agent's outward voice) from the social config: load the node
/// identity keyfile (the SAME key presence/memory use, so a published note is signed by the
/// agent's own npub, the F3 one-key invariant) and connect a nostr-sdk client to the relay set.
/// Mirrors `build_routstr_brain`'s shape (a backend built before the VM boots).
async fn build_nostr_actuator(
    social: &crate::config::SocialConfig,
    cosign: &crate::relay_transport::AgentCosign,
) -> anyhow::Result<Arc<dyn Actuator>> {
    // S3d FROST-TENANT BRANCH: when a per-agent keystore dir is configured, the agent's voice is
    // its SOVEREIGN 2-of-3 quorum (Q SIGNS EVERYTHING), NOT a node-local key. Load the
    // `QuorumSigner` from the provisioned keystore and build a FROST-mode actuator, so
    // `publish_note` signs via the PERSISTENT Q (the keystore's Q across restarts), the aggregate
    // is published as a pre-signed event. A FROST tenant has no node-local signing key, so
    // `key_path` is intentionally NOT consulted on this branch.
    use anyhow::Context as _;
    // Build the base actuator (its PUBLISH voice): a FROST quorum (Q signs) OR a single local key.
    // Keep the quorum `Arc` when FROST so the born-unified DM path below can REUSE it for the QSigner.
    let (mut actuator, frost_quorum) = if let Some(keystore_dir) = social.frost_keystore_dir.as_deref() {
        // INC2a: load through the shared `AgentCosign` seam (co-located = fresh signer, byte-identical;
        // distributed = the ONE hub-backed signer the beacon signer also uses).
        let quorum = cosign.load_signer().with_context(|| {
            format!(
                "load per-agent FROST quorum signer from keystore {} (S3d)",
                keystore_dir.display()
            )
        })?;
        let actuator =
            NostrActuator::connect_frost(quorum.clone(), &social.relays, social.cost_sats).await?;
        (actuator, Some(quorum))
    } else {
        // SINGLE-KEY PATH (byte-identical, G-CLEAN): the node identity keyfile is pinned to the
        // node identity by run_agent (so a note is signed by the agent's own npub). A missing pin
        // is a boot-wiring bug: fail loud, not a silent throwaway key (which would publish under an
        // unfollowable ephemeral identity).
        let key_path = social.key_path.clone().ok_or_else(|| {
            anyhow::anyhow!("SocialConfig.key_path must be pinned to the node identity (boot-wiring bug)")
        })?;
        let identity = NodeIdentity::load_or_create(&key_path)?;
        let actuator =
            NostrActuator::connect(identity.keys().clone(), &social.relays, social.cost_sats).await?;
        (actuator, None)
    };

    // The DM-reply identity. BORN-UNIFIED (P1, scope B, gated on `dm_under_q`): the DM identity IS
    // the FROST key Q -- attach a QSigner so NIP-17 replies seal under Q via threshold ECDH (no
    // plain dm_keys). Requires the FROST keystore + quorum (Q must exist). OTHERWISE the dedicated
    // plain dm_keys (task #12): NIP-17 replies sign with THIS key, key-isolated from the voice/money
    // planes. Only ONE is attached; `dm_under_q` defaults false so a live agent is byte-identical.
    if social.dm_under_q {
        let keystore_dir = social.frost_keystore_dir.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "dm_under_q is set but no FROST keystore is provisioned (frost_keystore_dir); \
                 the DM identity cannot be Q without the group key -- refusing to start"
            )
        })?;
        let quorum = frost_quorum.ok_or_else(|| {
            anyhow::anyhow!("dm_under_q requires FROST publish mode (boot-wiring bug)")
        })?;
        // INC2a co-gate: `load_ecdh` FAILS CLOSED LOUD on a DISTRIBUTED keystore (cross-machine ECDH
        // is Inc3). A co-located keystore is unchanged.
        let ecdh = Arc::new(cosign.load_ecdh().with_context(|| {
            format!("load QuorumEcdh from keystore {} (dm_under_q)", keystore_dir.display())
        })?);
        let qsigner: Arc<dyn nostr_sdk::NostrSigner> =
            Arc::new(crate::qsigner::QSigner::new(ecdh, quorum));
        actuator = actuator.with_dm_q_signer(qsigner);
        tracing::info!("NostrActuator: DM identity is the FROST group key Q (born-unified, dm_under_q)");
    } else if let Some(dm_path) = social.dm_key_path.as_deref() {
        let dm_identity = NodeIdentity::load_or_create(dm_path)?;
        actuator = actuator.with_dm_keys(dm_identity.keys().clone());
    }
    Ok(Arc::new(actuator))
}

/// The env var that overrides the durable state root (set from `[node].state_root` at
/// config load, and set by tests to an explicit temp dir). Documented as the seam between
/// the config field and the free-function path helpers below (which have no config handle).
pub const STATE_ROOT_ENV: &str = "KIRBY_STATE_ROOT";

/// The DURABLE state root all persistent key/treasury material lives under.
///
/// FIX 2 (durability): key material and the treasury counter MUST NOT live under
/// `std::env::temp_dir()` -- on a host with a tmpfs `/tmp` that is permanent loss of a
/// sovereign key on the next reboot. This resolves a durable root, in order:
///   1. `$KIRBY_STATE_ROOT` (set from the `[node].state_root` config field at load, and by
///      tests to an explicit temp dir). The configurable knob.
///   2. `$XDG_DATA_HOME/kirby` (the XDG durable data location).
///   3. `$HOME/.local/share/kirby` (the XDG default when `$XDG_DATA_HOME` is unset).
///   4. LAST RESORT (LOUD): `./.kirby-state` under the CWD -- still durable (it survives a
///      reboot), never temp_dir. Warns so the operator sets a real root.
///
/// `std::env::temp_dir()` is NEVER used for key/treasury material (it was the pre-fix bug).
pub fn state_root() -> PathBuf {
    if let Ok(v) = std::env::var(STATE_ROOT_ENV) {
        let v = v.trim();
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        let xdg = xdg.trim();
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("kirby");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let home = home.trim();
        if !home.is_empty() {
            return PathBuf::from(home).join(".local/share/kirby");
        }
    }
    tracing::warn!(
        "KIRBY_STATE_ROOT/XDG_DATA_HOME/HOME all unset; falling back to ./.kirby-state for \
         DURABLE key + treasury material. This is still reboot-durable (NOT temp_dir), but set \
         [node].state_root (or $KIRBY_STATE_ROOT) to a real data directory."
    );
    PathBuf::from(".kirby-state")
}

/// The per-node treasury store path (the daemon-owned counter, D-9). A per-node store
/// under the DURABLE [`state_root`] keeps two node processes distinct on one host AND
/// survives a reboot (FIX 2: NEVER temp_dir for the treasury counter).
pub fn treasury_path_for(node_id: &str) -> PathBuf {
    state_root().join(format!("treasury-{node_id}"))
}

/// The per-AGENT treasury store path (fleet-host S0, spec 2.1): DB-per-agent, so each
/// fleet tenant takes its OWN sled exclusive dir lock (boot.rs documents the lock at
/// `boot_and_observe`) and there is ZERO cross-tenant contention. The single-agent
/// default keeps using [`treasury_path_for`] (per node_id) verbatim, so a bare
/// `kirby run` is unchanged; only a fleet supervisor reaches for this per-agent path.
/// Agent-keyed TREES inside one sled were rejected (spec 2.1): they would re-serialize
/// every tenant behind one lock, re-introducing the coupling DB-per-agent avoids.
/// Under the DURABLE [`state_root`] (FIX 2: NEVER temp_dir for treasury material).
pub fn treasury_path_for_agent(agent_id: &str) -> PathBuf {
    state_root().join(format!("treasury-agent-{agent_id}"))
}

/// The per-agent DURABLE state directory (fleet-host money isolation, #74): a sibling of
/// the per-agent treasury counter ([`treasury_path_for`]) and FROST keystore
/// ([`crate::keyset_provisioning::keystore_dir_for`]) under the same durable [`state_root`],
/// keyed by the same unique `instance_id`. It homes the per-tenant key/money material that
/// must SURVIVE A REAP (and a reboot): the sovereign Cashu wallet store + its spend seed,
/// and the purpose-scoped key material the agent loads onto its planes (the DM key, the
/// wallet key). The supervisor points the child's `identity.treasury_dir` here in
/// `derive_tenant_config`; WITHOUT it `treasury_dir()` falls back to `key_path.parent()` =
/// the shared per-node config dir, so every tenant's dm/wallet key resolved to the SAME
/// path (a cross-tenant key collision). Distinct PREFIX from the sled-counter dir
/// (`treasury-{id}`) and the keystore dir (`keystore-{id}`, which `reap_orphan` deletes) —
/// the only cleanup that touches a per-instance dir under [`state_root`] targets
/// `keystore-{id}`, so the wallet + keys here are NOT lost on a crash-reap.
pub fn agent_state_dir_for(instance_id: &str) -> PathBuf {
    state_root().join(format!("agent-{instance_id}"))
}

/// R2 read-quorum gate: determines whether the boot-time reconcile was authoritative
/// (served >= read_k distinct relays) and controls the solvency check posture.
///
/// - `Assert`: the read was authoritative → run `assert_wallet_backs_counter` UNCHANGED
///   (fail-closed if wallet < counter, as before R2).
/// - `ProceedNonAuthoritative`: the read was below-quorum → the thin wallet balance is a
///   LOWER BOUND, not proven insolvency → proceed with a loud warning. The rollover gate
///   (§4, `read_established`) blocks any backup publish until >=k re-establishes authority.
pub enum SolvencyGate {
    Assert,
    ProceedNonAuthoritative,
}

/// Decide the solvency posture from the read's authoritativeness. Pure and testable.
/// (G4 zero-skip extended to money-reads: a below-quorum shortfall must not brick a funded agent.)
pub fn solvency_gate(authoritative: bool) -> SolvencyGate {
    if authoritative {
        SolvencyGate::Assert
    } else {
        SolvencyGate::ProceedNonAuthoritative
    }
}

/// The §2.8 boot solvency authority: authoritative ONLY when BOTH the token read reached quorum
/// AND the NUT-13 counter was established. Pure so the T10 false-broke tooth exercises it directly.
///
/// ⚠️ The composition is the FIX: keying solvency on the TOKEN read ALONE (the pre-config-plane
/// behavior) false-brokes a fresh box whose token read hit quorum but whose config read was
/// below-quorum (counter deferred → restore-receive no-op'd → wallet transiently 0 → Assert →
/// `assert_wallet_backs_counter(0, initial_sats)` bails, self-heal unreachable). ANDing in
/// `counter_established` routes that reachable seam to ProceedNonAuthoritative instead. This does
/// NOT blur die-when-broke — the runtime meter (meter.rs), not this boot-only check, owns genuine
/// death (§2.8).
pub fn boot_solvency_authoritative(nip60_read_authoritative: bool, counter_established: bool) -> bool {
    nip60_read_authoritative && counter_established
}

/// The §2.3 write-back gate: publish the 17375 counter head ONLY when the config read reached
/// read-quorum. Below-quorum → skip (never republish a potentially-thin head that would regress the
/// true head — finding-2, propagating). Pure so the T1 tooth exercises it directly.
pub fn should_publish_config(config_authoritative: bool) -> bool {
    config_authoritative
}

/// Finding-3 (config-plane REVISION) retry completeness + R2-#2 token-plane convergence:
/// [`try_establish_counter`] reports ESTABLISHED (`Ok(true)` — which STOPS the bounded retry loop)
/// ONLY when ALL THREE hold: the counter was established, the TOKEN read reached quorum
/// (`read_established` — R2-#2), AND the recovery-drain (`mint_unissued_quotes`) succeeded.
///
/// - drain-fail (finding-3): a Paid-but-unissued mint quote would be stranded until the next full
///   boot; keep retrying (idempotent) until the drain succeeds.
/// - token below-quorum (R2-#2): the counter may establish (state-3, a head present) on a
///   below-quorum token read, but `read_established` then stays false → the rollover gate is blocked
///   FOREVER if the loop exits. So convergence REQUIRES the token plane too — keep backing off until
///   the token read also reaches ≥k (flipping `read_established`), then converge.
///
/// Establishment (fast_forward lift-up-only), the token read, and the drain
/// (mint_unissued_quotes self-skips already-issued/0) are all IDEMPOTENT, so re-running is safe.
/// Pure so the T14/T16 teeth exercise it directly.
pub fn retry_established(counter_established: bool, read_established: bool, drain_ok: bool) -> bool {
    counter_established && read_established && drain_ok
}

/// ROUND-4 K4 — the retry RESUME-SKIP decision: whether [`try_establish_counter`] should PROCEED to
/// restore/drain/convergence, given whether the counter was ALREADY established and (only for a
/// not-yet-established counter) the fresh establish decision.
///
/// ★ WHY: an ALREADY-established counter (RESUME, or a prior retry attempt established the floor) must
/// NOT re-run the establish DECISION. `try_establish_counter` calls `establish_if_sound` with
/// `resume=false`, so on a still-BELOW-quorum config read it would DEFER (state 2) and wrongly cause an
/// early return — wedging a boot whose ONLY remaining gap is the token plane (the counter is already
/// established; token quorum just needs to recover). An already-established counter proceeds
/// UNCONDITIONALLY; only a not-yet-established counter is gated on its fresh establish decision.
/// Pure so the T25 tooth exercises it directly.
pub fn retry_should_proceed(already_established: bool, fresh_establish: bool) -> bool {
    already_established || fresh_establish
}

/// ROUND-5 K3-corr — the `token_empty` signal the ESTABLISH decision consumes. It MUST be the RAW
/// token-presence (`raw_events_empty`: were ANY 7375 events served, decodable or not), NOT
/// `fetched_ids.is_empty()`.
///
/// ★ WHY (the regression K3 introduced): K3 correctly made `fetched_ids` decoded-ONLY (so an
/// undecryptable id never seeds the deletion set). But `fetched_ids.is_empty()` then means "no
/// DECODABLE events" — so an ALL-undecryptable self-authored 7375 read (a real, unreadable backup)
/// looks empty. Feeding that as `token_empty=true` to `establish_if_sound` (with config_authoritative +
/// token_authoritative) establishes-at-0 despite unread proofs → derive from index 0 = NUT-13 REUSE.
/// `decode_ok=false` blocks recovery_complete but NOT the establish (which reads token_empty). The raw
/// presence signal fixes it precisely: events-served-but-undecodable → NOT empty → defer; a genuinely
/// empty read (no events served) → empty → establish-at-0 still works for a new agent. Both boot
/// establish sites (healthy + retry) route through here so a single change regresses both. Pure so T28
/// exercises it directly.
pub fn token_plane_empty(read: &crate::nip60::ReconcileRead) -> bool {
    read.raw_events_empty
}

/// ROUND-3 F1 / ROUND-4 K1-corr — the STRICT-DRAIN POST-STATE decision → `drain_ok` (an input to
/// `recovery_complete`).
///
/// ★ WHY THE POST-STATE, NOT THE RETURN CODE: CDK's `mint_unissued_quotes` (issue/mod.rs:340)
/// SWALLOWS per-quote check/mint errors (warn + continue) and returns `Ok(total_minted)`. So its
/// `Ok(0)` is AMBIGUOUS — EITHER "no unissued quotes" OR "quotes existed but ALL failed (mint
/// down)". The old `minted.is_some()` proxy treated the mint-down case as success → a premature
/// `recovery_complete` while Paid-but-unissued quotes stayed stranded (never re-drained).
///
/// ★ ROUND-4 K1-corr — MINTABLE-ONLY, not a raw count: `get_unissued_mint_quotes` INCLUDES normal
/// open UNPAID quotes (cdk returns bolt11 quotes with `amount_issued = 0`, unpaid included), so the
/// ROUND-3 `len() == 0` over-strict rule NEVER cleared while any open unpaid charge existed → recovery
/// wedged forever on a routine unpaid quote. The GENUINE signal is: after the drain, RE-CHECK each
/// still-unissued quote's state and count only the MINTABLE-BUT-UNMINTED leftovers (a paid quote the
/// mint failed to issue = the mint-down case). Confirmed-UNPAID zero-mintable quotes are IGNORED (a
/// normal open charge must not wedge recovery); a per-quote CHECK ERROR is fail-closed. This function
/// takes that already-reduced `mintable_after` count so it stays pure + trivially testable.
///
/// `mintable_after` (produced by [`mintable_remaining`] from the post-drain per-quote verdicts):
/// - `Some(0)` — no MINTABLE-but-unminted quote remains → genuinely drained → `true`. Covers the
///   finding-4 DURABILITY case (a new agent with nothing to drain) AND a normal open UNPAID quote
///   (K1-corr — an unpaid charge must NOT wedge recovery) AND a successful drain.
/// - `Some(n > 0)` — a paid/mintable-but-unminted leftover REMAINS (the mint-down case) → NOT
///   drained → `false` → defer + the bounded retry re-drives + self-heals when the mint recovers.
/// - `None` — a per-quote state check errored OR the post-state query itself FAILED → cannot confirm
///   → `false` (fail-closed).
///
/// Pure so the T20 (post-state gate) / T18 (drain-of-nothing) / T19 (mint-down safe-defer) / T23
/// (K1-corr unpaid-doesn't-wedge) teeth exercise the decision directly; BOTH boot drain sites route
/// through [`strict_drain_unissued_after`] → [`mintable_remaining`] → this function.
pub fn drain_complete(mintable_after: Option<usize>) -> bool {
    matches!(mintable_after, Some(0))
}

/// The post-drain state of one still-unissued mint quote (ROUND-4 K1-corr), from RE-CHECKING it with
/// the mint after `mint_unissued_quotes` ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteDrainState {
    /// `amount_mintable > 0` — a PAID/mintable quote the mint failed to issue (the mint-down leftover).
    /// A working mint would have drained it, so its presence means the drain is NOT complete.
    MintableUnminted,
    /// `amount_mintable == 0` and confirmed unpaid (or fully issued) — a NORMAL open charge. IGNORED:
    /// a routine unpaid quote must NOT wedge recovery (the ROUND-3 `len==0` over-strict bug K1-corr fixes).
    ConfirmedUnpaid,
    /// The per-quote state RE-CHECK itself errored — we cannot confirm the quote is not mintable →
    /// fail-closed (treat the whole drain as unconfirmable).
    CheckErrored,
}

/// ROUND-4 K1-corr — fold the post-drain per-quote verdicts into the [`drain_complete`] input.
/// Returns `Some(count of MintableUnminted)` when EVERY quote was cleanly classified (mintable or
/// confirmed-unpaid), or `None` (fail-closed) if ANY quote's re-check errored. Confirmed-UNPAID quotes
/// are NOT counted — a normal open unpaid charge must not wedge recovery. Pure so T23 exercises it.
///
/// RED-on-revert: count ALL still-unissued quotes (`Some(verdicts.len())`, the ROUND-3 `len==0`
/// model) instead of only the mintable leftovers → a lone ConfirmedUnpaid quote yields `Some(1)` →
/// `drain_complete` false → recovery wedges on a routine unpaid charge → T23 RED.
pub fn mintable_remaining(verdicts: &[QuoteDrainState]) -> Option<usize> {
    if verdicts.iter().any(|v| matches!(v, QuoteDrainState::CheckErrored)) {
        return None; // a state check errored → cannot confirm the drain (fail-closed)
    }
    Some(
        verdicts
            .iter()
            .filter(|v| matches!(v, QuoteDrainState::MintableUnminted))
            .count(),
    )
}

/// ROUND-3 F1 / ROUND-4 K1-corr — run the recovery-drain, then VERIFY THE POST-STATE (MINTABLE-only).
/// Calls `mint_unissued_quotes` for its EFFECT (mint whatever is mintable) but IGNORES its
/// degrade-prone return, then reads the durable still-unissued quotes for this wallet's mint/unit and
/// RE-CHECKS each one's state with the mint, classifying it via [`QuoteDrainState`]. Returns the
/// [`mintable_remaining`] fold (`None` if the post-state query itself failed → treated as not-drained
/// by [`drain_complete`], fail-closed). Applied at BOTH boot drain sites (healthy path + bounded retry).
async fn strict_drain_unissued_after(wallet: &cdk::wallet::Wallet) -> Option<usize> {
    match wallet.mint_unissued_quotes().await {
        Ok(minted) => {
            if u64::from(minted) > 0 {
                tracing::info!(minted = %minted, "recovery-drain: minted deferred Paid-but-unissued quotes");
            }
        }
        Err(e) => {
            // CDK already swallows per-quote errors; a top-level Err is rarer (e.g. the store read
            // itself failed). Either way the POST-STATE re-check below is authoritative — we do not
            // trust this return.
            tracing::warn!(error = %e, "recovery-drain: mint_unissued_quotes errored; the post-state get_unissued re-check is authoritative");
        }
    }
    // POST-STATE: `Wallet::get_unissued_mint_quotes` already retains only this mint_url + unit. A query
    // failure is fail-closed (cannot confirm the drain).
    let remaining = match wallet.get_unissued_mint_quotes().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "recovery-drain: post-state get_unissued_mint_quotes failed — cannot confirm the drain; DEFERRING recovery (fail-closed)");
            return None;
        }
    };
    // ★ K1-corr — MINTABLE-only: RE-CHECK each still-unissued quote with the mint. A paid/mintable
    // leftover (mint-down) or a check error is fail-closed; a confirmed-unpaid zero-mintable quote (a
    // normal open charge) is IGNORED so it does not wedge recovery.
    let mut verdicts = Vec::with_capacity(remaining.len());
    for quote in remaining {
        let verdict = match wallet.check_mint_quote(&quote.id).await {
            Ok(q) if u64::from(q.amount_mintable()) > 0 => QuoteDrainState::MintableUnminted,
            Ok(_) => QuoteDrainState::ConfirmedUnpaid,
            Err(e) => {
                tracing::warn!(quote_id = %quote.id, error = %e, "recovery-drain: post-state re-check of an unissued quote errored — cannot confirm not-mintable; DEFERRING recovery (fail-closed)");
                QuoteDrainState::CheckErrored
            }
        };
        verdicts.push(verdict);
    }
    mintable_remaining(&verdicts)
}

/// The §7.2 wallet<->counter reconcile decision (brain-routstr R2-3/R2-5): the wallet
/// must back every sat the metabolism counter believes it has, so the gateway never
/// authorizes a think the wallet can't fund. The invariant is `>=`, NEVER `==` (R2-3:
/// the excess over the counter is the wallet/mint fee reserve, §4). On a shortfall this
/// REFUSES TO BOOT (R2-5) — the safe, loud interim; the graceful counter clamp-down
/// (`reconcile_down_to`) needs a durable treasury mutation and is DEFERRED to the
/// gateway-hardening chunk (the same class as the §5.1 crash-journal).
pub fn assert_wallet_backs_counter(wallet_balance: u64, treasury_remaining: u64) -> anyhow::Result<()> {
    if wallet_balance < treasury_remaining {
        anyhow::bail!(
            "RoutstrBrain refuses to boot: wallet_balance ({wallet_balance} sat) < \
             treasury_remaining ({treasury_remaining} sat). The wallet must back every sat the \
             metabolism counter believes it has (brain-routstr §7.2 R2-3/R2-5; the counter \
             clamp-down is deferred to the gateway-hardening chunk). Fund the wallet to >= the \
             treasury (plus fee headroom) before resuming."
        );
    }
    Ok(())
}

/// ROUND-3 F3 — the bounded-retry SPAWN condition. Spawn the convergence retry whenever the token
/// read was NON-authoritative (`!read_established`) OR recovery is INCOMPLETE (`!recovery_complete`),
/// NOT only when the counter is unestablished (the pre-F3 `!is_established()`).
///
/// ★ WHY: an ALREADY-established boot (state-3: a non-empty config floor established) with a
/// below-quorum TOKEN read would, under the old `!established` gate, NEVER spawn a retry →
/// `read_established` stuck false → `recovery_complete` never opens → the rollover gate blocked the
/// WHOLE run (new mutations not NIP-60-backed). Keying the spawn on read/recovery incompleteness
/// covers that case: the retry re-reads the token plane and completes restore + drain + the latch.
/// Pure so the T22 tooth exercises it directly.
pub fn should_spawn_config_retry(read_established: bool, recovery_complete: bool) -> bool {
    !read_established || !recovery_complete
}

/// The config-plane bounded read-retry schedule (§2.4). The base interval (attempt 0), the cap on
/// a single interval, and the bounded attempt count — a BOUNDED, OBSERVABLE window that self-heals
/// on a ≥k read and never wedges silent-forever.
const CONFIG_RETRY_BASE: Duration = Duration::from_secs(2);
const CONFIG_RETRY_MAX_INTERVAL: Duration = Duration::from_secs(60);
const CONFIG_RETRY_MAX_ATTEMPTS: u32 = 12;

/// The config-plane retry BACKOFF (§2.4, T6): a BOUNDED exponential — `base` doubled each attempt,
/// capped at `max`, and NEVER below `base`. ★ HARD money-safety requirement: the retry must BACK
/// OFF, never SPIN — the runtime meter (meter.rs:565) debits the treasury every tick independent of
/// the wallet, so a hot retry loop would raise measured CPU burn and hasten REAL death. A non-zero
/// floor (`>= base`) is exactly what keeps a defer window from debiting faster than baseline idle.
/// Pure + total so the T6 tooth exercises it directly.
pub fn config_retry_backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    let factor = 1u64.checked_shl(attempt.min(32)).unwrap_or(u64::MAX);
    let secs = base.as_secs().saturating_mul(factor);
    Duration::from_secs(secs).clamp(base, max)
}

/// ONE config-plane establishment attempt (§2.4): re-read both planes per-relay and, if sound,
/// ESTABLISH the counter and re-drive the full recovery path. Returns `Ok(true)` ONLY when the
/// attempt fully CONVERGED (established AND token ≥k AND drain OK — R2-#2), `Ok(false)` otherwise
/// (the retry loop backs off and tries again).
///
/// ORDERING (§2.6b — establishment PRECEDES the re-driven restore-receive so it derives at correct
/// indices): (1) read the CONFIG plane (`load_config_quorum`) AND the TOKEN plane
/// (`reconcile_on_load_with_ids` — flips `read_established`, yields the restore candidates);
/// (2) route the establish DECISION through the ONE guarded choke point
/// ([`crate::nip60_counter::Nip60CounterDb::establish_if_sound`] — R2-#1: the SAME guard the initial
/// open uses, so the retry can NOT establish-at-0 on config quorum alone), which seeds the true
/// floor + fast-forwards the inner counter (gate-exempt) + flips the establishment latch when sound;
/// (3) re-drive the restore-receive (now unblocked); (4) drain deferred Paid-but-unissued mint
/// quotes via `mint_unissued_quotes`; (5) on full convergence, mark recovery COMPLETE (R2-#3 —
/// opens the store's publish + rollover gates). A DEFER at step 2 (below-quorum config, or an
/// empty floor with a present/below-quorum token plane) seeds/lifts NOTHING and returns `Ok(false)`.
pub(crate) async fn try_establish_counter(
    store: &crate::nip60::Nip60Store,
    counter_db: &crate::nip60_counter::Nip60CounterDb,
    wallet: &cdk::wallet::Wallet,
) -> anyhow::Result<bool> {
    let cr = store.load_config_quorum().await?;
    // ★ R2-#1 + R2-#2: read the TOKEN plane BEFORE the establish decision, so (a) the SINGLE guarded
    // establish choke point can consume the token plane's authority (finding-4, token-quorum-symmetric
    // — the retry must NOT establish-at-0 on config quorum alone), and (b) the read flips the store's
    // `read_established` (the rollover gate's token-quorum half) + yields the restore candidates. The
    // READ derives nothing, so it is safe before establishment (§2.6b — only the IMPORT must follow).
    let read = store.reconcile_on_load_with_ids().await?;
    let token_authoritative = read.authoritative;
    // §K3-corr (ROUND-5): token_empty for the ESTABLISH decision is the RAW presence signal (via
    // `token_plane_empty`), NOT `fetched_ids.is_empty()`. Still ANDed with `token_authoritative` in
    // the four-condition guard (quorum symmetry preserved — a below-quorum read defers regardless).
    let token_empty = token_plane_empty(&read);
    // §K3: fold the decode-degraded signal into restore_ok below (an undecryptable self-authored 7375
    // event → the candidate set is incomplete → recovery must not converge).
    let decode_ok = read.decode_ok;
    // §category (d): the config floor read's HOLEY signal (a dropped/unparseable keyset). The retry
    // reads only the config plane (no local read), so floor_complete here reflects the config source;
    // the local source is guarded at the initial open (open_persistent_wallet).
    let (floor, config_floor_dropped) =
        cr.config.as_ref().map(|c| c.counters_by_id_checked()).unwrap_or_default();
    let floor_complete = !config_floor_dropped;
    // ★ ROUND-4 K4 — RESUME-SKIP: an already-established counter (RESUME, or a prior attempt) must NOT
    // re-run the establish DECISION — with resume=false + a still-below-quorum config it would DEFER
    // (state 2) and wrongly early-return, wedging a boot whose only gap is the token plane. Only a
    // NOT-yet-established counter routes the decision through the ONE guarded choke point
    // (`establish_if_sound` — R2-#1, the SAME guard the initial open uses; establish-at-0 fires only
    // when the token plane is quorum-confirmed empty, and a holey floor defers — category (d)).
    let already_established = counter_db.is_established();
    let fresh_establish = if already_established {
        false // skip the decision entirely (K4) — proceed straight to restore/drain/convergence
    } else {
        counter_db
            .establish_if_sound(
                floor,
                false,
                cr.config_authoritative,
                token_authoritative,
                token_empty,
                floor_complete,
            )
            .await
            .map_err(|e| anyhow::anyhow!("config-plane retry: establish decision: {e}"))?
    };
    if !retry_should_proceed(already_established, fresh_establish) {
        return Ok(false); // below quorum, unproven-empty token plane, or holey floor — back off and retry
    }
    // Re-drive the restore-receive now that derivations are unblocked (§2.6b). Degrades internally,
    // but returns an EXPLICIT outcome (ROUND-3 F2): `restore_ok` is a GENUINE success signal (incl. a
    // genuinely-empty restore), NEVER a degraded-to-0 proxy — a DEGRADED restore must NOT converge.
    // §K3: AND-in `decode_ok` — an undecryptable self-authored backup makes the candidate set
    // incomplete, so recovery must not converge (the real backup is preserved, retry re-drives).
    let restore_outcome =
        crate::nip60_reconcile::restore_from_relay_backup(Ok(read.candidates), wallet).await;
    let restore_ok = restore_outcome.is_ok() && decode_ok;
    // Drain any deferred Paid-but-unissued mint quotes (recovery-mint through the now-open choke
    // point; safe to call blindly — re-checks with the mint, self-skips amount_mintable()==0).
    // §finding-3 RETRY COMPLETENESS + ROUND-3 F1: the drain is part of recovery, and `drain_ok` is
    // the POST-STATE (get_unissued EMPTY-after), NOT the degrade-prone `mint_unissued_quotes` return.
    // On a not-drained POST-STATE (mint-down Ok(0), quotes remain) we do NOT report converged so the
    // bounded loop keeps backing off + re-drives (idempotent) until the quotes are genuinely drained.
    let unissued_after = strict_drain_unissued_after(wallet).await;
    let drain_ok = drain_complete(unissued_after);
    // ★★★ INVARIANT (ROUND-3, do NOT weaken): EVERY input to `recovery_complete` MUST be a
    // GENUINE-success signal — an explicit outcome (`restore_ok` via `RestoreOutcome`) or a verified
    // POST-STATE (`drain_ok` via `get_unissued`; `read_established` via the token quorum) — NEVER a
    // library return code that degrades failure to a success-looking/benign value. CDK's
    // `mint_unissued_quotes` `Ok(0)` and restore's adopt-nothing-`0` BOTH degrade failure to benign;
    // this gate has been re-opened 3× by that exact trap. A future maintainer adding a recovery
    // component MUST feed a genuine signal here, not a return code.
    //
    // R2-#2 + F1 + F2 convergence: established AND token ≥k (`token_authoritative` ==
    // `read_established`) AND the POST-STATE drain is clean AND the restore genuinely succeeded. A
    // below-quorum token read, an un-drained post-state, or a degraded restore must NOT converge
    // (else `recovery_complete` opens against a not-fully-recovered wallet → empty-rollover del-chains
    // the real backup). On FULL convergence, mark recovery COMPLETE (opens PUBLISH + ROLLOVER).
    let converged =
        retry_established(counter_db.is_established(), token_authoritative, drain_ok) && restore_ok;
    if converged {
        counter_db.mark_recovery_complete();
    }
    Ok(converged)
}

/// Read the AUTHORITATIVE `treasury_remaining` before wiring the brain wallet to it, so
/// the §7.2 reconcile compares the wallet against the real counter: bootstrap seeds
/// `initial_sats`; resume keeps the persisted balance (the seed arg is honored only on
/// first creation). Opens the SAME per-node store the gateway will use, reads remaining,
/// and drops it; [`boot_and_observe_with_rail`] reopens via [`open_treasury_retrying`],
/// which absorbs the brief sled lock-release lag (the same FIX-4 back-to-back-open race).
async fn peek_treasury_remaining(config: &BootConfig) -> anyhow::Result<u64> {
    let path = treasury_path_for(&config.node_id);
    let treasury =
        open_treasury_retrying(&path, config.initial_sats, Duration::from_secs(5)).await?;
    let remaining = treasury.remaining()?;
    drop(treasury);
    Ok(remaining)
}

/// Run boot-time cdk saga recovery under a timeout `budget`, DEGRADING (warn + continue)
/// instead of hanging when the budget elapses. Saga reconcile (R2-4) recovers proofs
/// stranded by a prior crash mid send/receive/swap/melt; it is cdk's only network-bound
/// boot step and cdk's HTTP client carries no request timeout, so an unreachable mint would
/// otherwise block boot FOREVER — before the agent VM ever launches (#84).
///
/// On timeout we boot anyway: the wallet-backs-counter shortfall guard that runs next
/// ([`assert_wallet_backs_counter`]) reconciles against the LOCAL balance, so a degraded
/// boot is still conservative (never over-claims) and still REFUSES on a real shortfall. The
/// stranded proofs persist in the cdk localstore and reconcile on the next boot that reaches
/// the mint — deferred, not lost. (Saga recovery has a single caller, this boot step; the
/// runtime per-think reclaim in [`crate::rail::RoutstrBrain`] is a DIFFERENT mechanism — it
/// recovers the CURRENT think's token, it does not re-run saga reconcile.)
///
/// A real saga error from a REACHABLE mint (resolves within the budget) still propagates →
/// boot refuses, preserving the strict R2-4/R2-5 stance.
async fn recover_sagas_within<F>(recover: F, budget: Duration) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    match tokio::time::timeout(budget, recover).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::warn!(
                budget_secs = budget.as_secs(),
                "boot saga recovery timed out (mint unreachable?); booting on the \
                 locally-backed balance — stranded proofs persist and reconcile on the next \
                 mint-reachable boot, rather than hanging boot forever (#84)"
            );
            Ok(())
        }
    }
}

/// Build the [`RoutstrBrain`] backend for `backend = "routstr"` (brain-routstr §7): open
/// the persistent, funded wallet, recover incomplete cdk sagas FIRST (R2-4), then assert
/// the wallet backs the counter (`wallet_balance >= treasury_remaining`, NOT `==` — the
/// excess is the fee reserve, R2-3) and REFUSE TO BOOT on a shortfall (R2-5; the graceful
/// counter clamp-down is deferred to the gateway-hardening chunk). Then construct the
/// brain over the wallet with the configured kill-window timeouts.
async fn build_routstr_brain(
    brain: &crate::config::BrainConfig,
    treasury_remaining: u64,
    nip60: &crate::config::Nip60Config,
    fleet_relay: &str,
) -> anyhow::Result<(
    Arc<dyn BrainBackend>,
    Option<Arc<crate::rail::Nip60BackupFlusher>>,
    // Cut B (#115): the counter-estate bundle for the graceful-teardown 17375 re-publish
    // (store + counter decorator + mint url). `Some` exactly when `[nip60]` is configured; threaded
    // into the ServeGuard so `flush_estate` re-publishes the current counter mirror at death.
    Option<Nip60CounterEstate>,
    // Inc 1b (D1/D2): the earn-loop SETTLEMENT provider, built HERE (where the host-held wallet
    // lives) and threaded to the gateway attach. `Some(Cashu|Lightning)` per `[brain]
    // settlement_method`; `None` when unset (no provider wired — byte-identical to pre-1b). The
    // wallet stays buried inside this function; only the provider (a trait object) escapes.
    Option<Arc<dyn SettlementProvider>>,
)> {
    let db_path = Path::new(&brain.wallet_db_path);
    // Resolve the wallet spend seed ONCE through the WalletKey seam (interim: the byte-identical
    // sibling `<db_path>.seed` keyfile, load-or-create 0600, per-agent; the reconstruct-on-lease
    // keyring swaps the variant here with no change below). Resolving it here lets us derive the
    // NIP-60 event key from the SAME seed and load the counter floor BEFORE the wallet opens.
    let seed = crate::mint_rig::WalletKey::sibling_seed_of(db_path).resolve_seed()?;

    // NIP-60 cross-machine wallet backup — OPT-IN: only when `[nip60]` lists relays. Connect the
    // store and LOAD the NUT-13 counter floor from the 17375 head BEFORE opening the wallet, so the
    // counter mirror is SEEDED with the floor before any publish — a later publish can then never
    // regress the counter below what the relay recorded (the no-regress MONEY-MUST). No relays →
    // no store, empty floor, the wallet opens exactly as a non-NIP-60 agent.
    //
    // ★ config-plane REVISION (structural prerequisite): the store is built OWNED + MUTABLE here (NOT
    // yet `Arc`-wrapped). The token-plane READ (7375, quorum) is SPLIT from the token IMPORT and run
    // EARLY (below), so the establish decision (finding 4) can consume the token plane's authority;
    // and after the wallet opens we inject the counter-establishment latch into the store (findings
    // 1+2) before `Arc`-wrapping + sharing it with the flusher.
    let mut nip60_store = if nip60.relays.is_empty() {
        None
    } else {
        let event_key = crate::nip60_key::derive_nip60_event_key(&seed);
        // §2.8b: FAIL-CLOSED on a quorum-intersection violation (read_k + write_k > n) BEFORE
        // connecting — a config that can't guarantee read/write overlap must never boot the
        // establishment machinery into a state where fresh-box establish-at-0 (§2.2 state 4) is
        // unsound (index reuse via a weak write quorum). Default majority both sides satisfies it.
        let (relays, write_k, read_k, durability) = nip60.resolve_checked(fleet_relay)?;
        if let Some(warning) = durability.warning() {
            tracing::warn!(nip60_durability = %warning, "NIP-60 wallet backup: sub-quorum durability");
        }
        // POSTURE VISIBILITY (R1 / D3): log the RESOLVED relay set + the durability TIER, not just
        // n/k, so the backup posture is auditable in every boot log — an operator can SEE at a
        // glance which relays their money durability rides and whether that set clears the >=3
        // quorum. Deliberately COUNT-only (n/k/tier + the URLs), NO per-relay team/non-team marker:
        // a "this one's mine" flag would be operator self-attestation the daemon can't verify —
        // enforcement theater. The tier is the honest, machine-derived verdict.
        tracing::info!(
            relays = ?relays,
            n = relays.len(),
            k = write_k,
            read_k,
            tier = ?durability,
            "NIP-60 wallet backup relay posture"
        );
        // Owned (Arc-wrapped after the latch injection below); the Cut A (#115) background backup
        // flusher shares the store once it is `Arc`-wrapped (all its methods take `&self`).
        Some(
            crate::nip60::Nip60Store::connect(
                &event_key,
                &relays,
                Some(write_k),
                Some(read_k),
                brain.effective_mint_allowlist(),
            )
            .await?,
        )
    };

    // ★ config-plane REVISION — BOTH plane reads run BEFORE the wallet opens (structural
    // prerequisite): the CONFIG read (17375 floor + quorum, §2.1) AND the TOKEN read (7375 proofs +
    // quorum) so the establish decision (finding 4) can consume both planes' authority. The token
    // READ is split from the token IMPORT: the READ (`ReconcileRead` — served/fetched_ids/authoritative)
    // does NOT need the wallet; only the IMPORT (`restore_from_relay_backup` → receive_proofs) does,
    // and it stays AFTER the wallet opens (step 3). Both reads reuse the Cut A per-relay primitive
    // (`fetch_events_per_relay`) so they are quorum-aware.
    //   config_authoritative — the 17375 floor read reached read-quorum (drives states 2/3/4).
    //   token_authoritative  — the 7375 token read reached read-quorum (served >= read_k).
    //   token_empty          — the token read fetched NO token events (fetched_ids empty).
    // establish-at-0 (state 4) fires ONLY when config_authoritative AND config-head-absent AND
    // token_authoritative AND token_empty (finding 4, token-quorum-symmetric). With no store (NIP-60
    // off) the local wallet is authoritative by definition and genuinely-new (all true).
    let initial_counters;
    let config_authoritative;
    let token_authoritative;
    let token_empty;
    // §category (d) HOLEY-FLOOR: whether the config floor read dropped any (unparseable-hex) keyset —
    // threaded into `open_persistent_wallet` so a holey config floor defers establishment.
    let config_floor_dropped;
    // The early token READ result, carried to the IMPORT (step 3) so the read is not repeated: the
    // candidates (to import), fetched_ids (flusher live-id seed), and quorum metadata (solvency).
    let token_read: Option<anyhow::Result<crate::nip60::ReconcileRead>>;
    match &nip60_store {
        Some(store) => {
            let cr = store.load_config_quorum().await?;
            let (counters, dropped) =
                cr.config.as_ref().map(|c| c.counters_by_id_checked()).unwrap_or_default();
            initial_counters = counters;
            config_floor_dropped = dropped;
            config_authoritative = cr.config_authoritative;
            // EARLY token read (quorum-aware). Errors degrade to below-quorum (defer establish-at-0);
            // the read verdict flips the store's `read_established` (unblocks the rollover gate later).
            let read = store.reconcile_on_load_with_ids().await;
            match &read {
                Ok(r) => {
                    token_authoritative = r.authoritative;
                    // §K3-corr (ROUND-5): RAW presence (via `token_plane_empty`), NOT
                    // `fetched_ids.is_empty()` (decoded-only post-K3) — an all-undecryptable read holds
                    // a real unreadable backup and must NOT establish-at-0 (index-0 = NUT-13 reuse).
                    // Still gated by the separate `token_authoritative` term (quorum symmetry intact).
                    token_empty = token_plane_empty(r);
                }
                Err(_) => {
                    // A failed token read cannot confirm empty → treat as below-quorum: DEFER
                    // establish-at-0 (never establish against a plane we could not read).
                    token_authoritative = false;
                    token_empty = false;
                }
            }
            token_read = Some(read);
        }
        None => {
            initial_counters = std::collections::HashMap::new();
            config_floor_dropped = false;
            config_authoritative = true;
            token_authoritative = true;
            token_empty = true;
            token_read = None;
        }
    }

    // 1) Open the PERSISTENT wallet (file store + persisted seed, §7.1; funded out-of-band, §11),
    //    with the counter mirror SEEDED by the loaded floor — this seed PRECEDES the config publish
    //    in step 4 (the no-regress ordering). `config_authoritative` gates the four-state
    //    establishment (§2.2): on a fresh box a below-quorum read leaves the counter DEFERRED
    //    (latch false → choke-point blocks derivations until the bounded retry lands a ≥k read).
    let (wallet, counter_db) = crate::mint_rig::open_persistent_wallet(
        &brain.mint_url,
        db_path,
        seed,
        initial_counters,
        config_authoritative,
        token_authoritative,
        token_empty,
        config_floor_dropped,
    )
    .await?;
    let ecash = CdkEcash::new(wallet.clone());

    // Inc 1b (D1/D2): the earn-loop SETTLEMENT provider is built LATER (after the NIP-60 flusher
    // exists) so a Lightning/Cashu provider can be handed the flusher's `BackupDirtyNotifier` — a
    // settlement mint/receive writes proofs straight into the raw wallet (bypassing the
    // Nip60BackedEcash decorator), so without that notifier the freshly-minted proofs would never
    // flip the backup `dirty` flag and would be LOST on a failover restore (Fix 1 / real sats-loss).
    // See the construction after the `(backend, flusher)` match below.

    // ★ config-plane REVISION (findings 1+2) + R2-#3 (TWO-LATCH): SHARE the RECOVERY-COMPLETE latch
    // INTO the store BEFORE it is `Arc`-wrapped + handed to the flusher, so the choke-point funnel
    // (`publish_config`) and the rollover gate read the SAME recovery state. The store's write gates
    // are RE-KEYED off the derivation-establishment latch onto recovery-completion: publish/rollover
    // open ONLY after the wallet is fully restored (restore AND drain both succeed), marked on the
    // healthy path (below) or by the bounded retry — never against a transiently-empty wallet.
    if let Some(store) = &mut nip60_store {
        store.set_recovery_complete(counter_db.recovery_complete_handle());
    }
    // Freeze the store into an `Arc` now that the latch is wired (all further uses share this Arc).
    let nip60_store = nip60_store.map(Arc::new);

    // 2) Recover incomplete cdk sagas FIRST (R2-4), BEFORE measuring the balance: a prior
    //    crash/timeout mid send/receive can strand reserved/pending proofs or leave a
    //    revocable token; reconciling first would burn budget for recoverable sats. Bounded
    //    by `recovery_timeout_secs` and degraded (not failed) on timeout so an unreachable
    //    mint cannot hang boot before the VM launches (#84); see `recover_sagas_within`.
    use crate::rail::EcashProvider as _;
    recover_sagas_within(
        ecash.recover_incomplete_sagas(),
        Duration::from_secs(brain.recovery_timeout_secs),
    )
    .await?;

    // 3) Restore-from-backup (N2): pull the relay-backed proof events into the wallet BEFORE the
    //    solvency check, so a fresh box (empty local store — e.g. a cross-machine takeover) restores
    //    its balance and does not false-die. reconcile_import is NUT-07-gated + FAIL-CLOSED +
    //    NOVEL-ONLY, and restore_from_relay_backup DEGRADES (log + continue) on any error so an
    //    unreachable mint/relay never fails boot — the solvency check (step 4) is the real money
    //    gate. Counter safety: open_persistent_wallet (step 1) fast-forwards the INNER NUT-13
    //    derivation counter to the loaded floor (fast_forward_inner_to_floor — the with_counters
    //    shadow seed alone does NOT move what cdk derives from), so receive_proofs here derives swap
    //    outputs from >= floor (no reused-secret collision); the mint-swap is the single-writer
    //    arbiter, so a lost double-restore race fails-closed (imports nothing) rather than
    //    double-spending.
    // The token-event ids the reconcile saw — the Cut A (#115) backup flusher SEEDS its live-id
    // set with these so the first flush del-chains ALL prior events into one clean new snapshot.
    // Empty with no store; the reconcile error path degrades to empty (a fresh backup then simply
    // supersedes nothing).
    let mut nip60_initial_live_ids: Vec<String> = Vec::new();
    // R2 condition (a): track whether the load-time reconcile was authoritative (served >=
    // read_k distinct relays). A below-quorum read is a LOWER BOUND — we proceed but flag it
    // so the rollover gate (condition b) blocks a potentially-shrunken backup publish until a
    // >=k read re-establishes authority. Default true when NIP-60 is not configured (no relay
    // reads → local wallet is authoritative by definition).
    // ★ config-plane REVISION: the token READ already ran EARLY (before the wallet opened); here we
    // consume its result to drive the IMPORT. The IMPORT (`restore_from_relay_backup` →
    // receive_proofs) needs the wallet and stays here (step 3, after saga recovery), AND is
    // implicitly gated by `counter_established`: during defer the derivation trips the choke point
    // and the restore no-ops (degrades log-and-continue), re-driven by the bounded retry on a ≥k read.
    let nip60_read_authoritative;
    let nip60_read_info;
    // ★ ROUND-3 F2: capture the EXPLICIT restore outcome (a GENUINE success signal, incl. a
    // genuinely-empty restore) — NOT a degraded-to-0 proxy — so the recovery_complete gate (step 4b)
    // can require `restore_ok` and a FAILED restore stays deferred (the real backup is preserved).
    let nip60_restore_ok;
    match token_read {
        Some(Ok(read)) => {
            nip60_initial_live_ids = read.fetched_ids.clone();
            nip60_read_authoritative = read.authoritative;
            nip60_read_info = Some((read.served, read.total, read.read_k));
            // §K3: capture the decode-degraded signal BEFORE moving `candidates`. An undecryptable
            // self-authored 7375 event makes the candidate set incomplete → force restore_ok=false so
            // recovery_complete stays closed (the real backup is preserved; the retry re-drives).
            let decode_ok = read.decode_ok;
            let restore_outcome =
                crate::nip60_reconcile::restore_from_relay_backup(Ok(read.candidates), wallet.as_ref())
                    .await;
            nip60_restore_ok = restore_outcome.is_ok() && decode_ok;
        }
        Some(Err(e)) => {
            nip60_read_authoritative = false;
            nip60_read_info = None;
            let restore_outcome =
                crate::nip60_reconcile::restore_from_relay_backup(Err(e), wallet.as_ref()).await;
            nip60_restore_ok = restore_outcome.is_ok(); // Degraded → false
        }
        None => {
            // NIP-60 off: no relay restore to run → trivially "recovered" (nothing to gate).
            nip60_read_authoritative = true;
            nip60_read_info = None;
            nip60_restore_ok = true;
        }
    }

    // 4) Solvency check: the wallet must back every sat the counter believes it has. REFUSE
    //    TO BOOT on a shortfall (R2-5) — loud and safe — rather than letting the genome
    //    see repeated UPSTREAM_FAILED when the counter authorizes a think the wallet
    //    can't fund.
    //    R2 condition (a): a below-quorum read is a LOWER BOUND; do not treat a thin wallet
    //    balance as proven insolvency — proceed non-authoritatively (the rollover gate holds
    //    until >=k re-establishes; die-when-broke fires on a real spend shortfall).
    let wallet_balance = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    // §2.8 solvency posture: authoritative ONLY when BOTH the token read reached quorum AND the
    // NUT-13 counter was established (config-plane). A restore-deferred fresh box (counter NOT
    // established) has a transiently-0 wallet (§2.6b: the restore-receive tripped the choke-point
    // gate and no-op'd), so treating it as authoritative would false-broke bail even when the token
    // read hit quorum — the reachable failover false-death seam (§2.8, T10). Deferring the assert
    // does NOT blur die-when-broke: that lives in the runtime METER (meter.rs), not this boot-only
    // refuse-to-start check; a genuinely-broke agent still dies at runtime when the treasury hits 0.
    let counter_established = counter_db.is_established();
    let solvency_authoritative =
        boot_solvency_authoritative(nip60_read_authoritative, counter_established);
    match solvency_gate(solvency_authoritative) {
        SolvencyGate::Assert => assert_wallet_backs_counter(wallet_balance, treasury_remaining)?,
        SolvencyGate::ProceedNonAuthoritative => {
            let (served, total, read_k) = nip60_read_info.unwrap_or((0, 0, 0));
            tracing::warn!(
                served,
                total,
                read_k,
                counter_established,
                wallet_balance,
                treasury_remaining,
                "boot: restore below read-quorum ({served}/{total}, need {read_k}) OR counter \
                 deferred (established={counter_established}); wallet {wallet_balance} vs counter \
                 {treasury_remaining} is a LOWER BOUND, NOT treating as insolvent — proceeding \
                 non-authoritative, scheduling read-retry (stalled: below-quorum config, awaiting k relays)",
            );
            // boot PROCEEDS; read_established / counter_established stay false => rollover gate (§4)
            // + choke-point gate (§2.2) hold; the bounded retry re-establishes on a ≥k read.
        }
    }

    // 4b) ★ R2-#3 (TWO-LATCH) — open the RECOVERY-COMPLETE latch (which gates the store's PUBLISH +
    //    ROLLOVER write paths) on the HEALTHY-boot path, ONLY after restore (step 3) AND the
    //    recovery-drain below both complete. On a DEFERRED fresh-box boot the counter is NOT
    //    established (the wallet is transiently-empty and the choke point is closed), so we do NOT
    //    open the gate here — the bounded retry (§2.4) marks recovery complete after IT completes
    //    restore+drain. Scoped to a configured NIP-60 store (the only place publish/rollover — and
    //    thus recovery_complete — matter); with no store there is nothing to gate.
    //
    //    The drain (`mint_unissued_quotes`) is the recovery half symmetric to the retry path
    //    (finding-3): it recovers Paid-but-unissued mint quotes through the now-open choke point,
    //    idempotent + self-skipping when there is nothing to mint (a cheap `Ok(0)` on a normal
    //    resume). On a drain FAILURE recovery_complete stays false → the 17375 config publish (step
    //    5) + the flusher's rollover stay deferred THIS run (money-safe: never publish/rollover
    //    against a not-fully-recovered wallet); the next boot re-drives. Placed AFTER the solvency
    //    check so that check sees the same balance as before (no behavior change to §7.2).
    if nip60_store.is_some() && counter_db.is_established() {
        // ROUND-3 F1: `drain_ok` is the POST-STATE (get_unissued EMPTY-after), NOT the degrade-prone
        // `mint_unissued_quotes` return. A new agent with no quotes → empty → true; quotes-remain
        // (mint-down Ok(0)) → non-empty → false → defer + the bounded retry self-heals.
        let unissued_after = strict_drain_unissued_after(wallet.as_ref()).await;
        let drain_ok = drain_complete(unissued_after);
        // ★★★ INVARIANT (ROUND-3, do NOT weaken): EVERY input to `recovery_complete` MUST be a
        // GENUINE-success signal — an explicit outcome (`restore_ok` via `RestoreOutcome`) or a
        // verified POST-STATE (`drain_ok` via `get_unissued`; `read_established`/`nip60_read_authoritative`
        // via the token quorum) — NEVER a library return code that degrades failure to a
        // success-looking/benign value. CDK's `mint_unissued_quotes` `Ok(0)` and restore's
        // adopt-nothing-`0` BOTH degrade failure to benign; this gate has been re-opened 3× by that
        // exact trap. A future maintainer adding a recovery component MUST feed a genuine signal here.
        //
        // F2 unified precondition: recovery_complete = `restore_ok AND drain_ok AND read_established`
        // (all genuine post-state, no degraded-0). Any false → recovery stays CLOSED → the 17375
        // config publish (step 5) + the flusher rollover DEFER this run (money-safe: never
        // publish/rollover against a not-fully-recovered wallet); the bounded retry (step 5b) re-drives.
        if drain_ok && nip60_restore_ok && nip60_read_authoritative {
            counter_db.mark_recovery_complete();
        } else {
            tracing::warn!(
                restore_ok = nip60_restore_ok,
                drain_ok,
                read_established = nip60_read_authoritative,
                "boot: recovery NOT complete on the healthy path (restore_ok AND drain_ok AND \
                 read_established required, all genuine post-state) — recovery_complete NOT set, so \
                 the 17375 config publish + the flusher rollover stay deferred this run (money-safe: \
                 no backup against a not-fully-recovered wallet); the bounded retry re-drives (idempotent)"
            );
        }
    }

    // 5) Publish the NIP-60 wallet-config (mints + the NUT-13 counters). ORDERED AFTER the
    //    with_counters seed at open (step 1) AND the restore-import (step 3), so the published
    //    counter is >= the loaded floor AND reflects any proofs restored this boot (no regression).
    //    Best-effort: a failure is logged, NOT fatal (the mint remains truth; the next counter
    //    change re-publishes).
    //    §2.3 WRITE-BACK GATE: publish the counter head ONLY when the config read was authoritative
    //    (≥k). A below-quorum config read may have loaded a THIN floor; republishing it as a NEW
    //    17375 head would REGRESS the true head (a lower head on the reached relays) — poisoning
    //    every future boot (finding-2, propagating). Below-quorum → skip the publish, keep the
    //    existing head, warn; the bounded retry re-publishes once a ≥k read re-establishes.
    if let Some(store) = &nip60_store {
        if should_publish_config(config_authoritative) {
            if let Err(e) = store
                .publish_wallet_config(counter_db.keyset_counters(), vec![brain.mint_url.clone()])
                .await
            {
                tracing::warn!(
                    error = %e,
                    "NIP-60 boot config publish failed (advisory; the seeded floor re-publishes on the next change)"
                );
            }
        } else {
            tracing::warn!(
                "NIP-60 boot config publish SKIPPED: below config read-quorum — refusing to \
                 republish a potentially-thin counter head (never regress the true head, §2.3); \
                 the bounded retry re-publishes once a ≥k read re-establishes authority"
            );
        }
    }

    // §2.4 BOUNDED READ-RETRY: spawn a bounded backoff task that re-reads BOTH planes per-relay and,
    // on a ≥k read, establishes the floor + re-drives restore + drains deferred mints + marks
    // recovery complete (`try_establish_counter`). Boot PROCEEDS (the agent survives on its existing
    // balance; the runtime meter still owns die-when-broke) — self-healing on ≥k. On bound-expiry it
    // proceeds on existing balance, the stall stays visible (never a silent wedge).
    //
    // ★ ROUND-3 F3 — SPAWN CONDITION: spawn whenever the token read was NON-authoritative OR recovery
    // is INCOMPLETE, NOT only when the counter is unestablished. An ALREADY-established boot (state-3:
    // a non-empty config floor, counter established) with a below-quorum TOKEN read would otherwise
    // NEVER re-read → `read_established` stuck false → `recovery_complete` never opens → the rollover
    // gate is blocked the WHOLE run (new mutations not NIP-60-backed). Retrying on incomplete-recovery
    // re-reads the token plane and completes the read/restore/drain/latch when relays recover.
    if let Some(store) = &nip60_store {
        if should_spawn_config_retry(nip60_read_authoritative, counter_db.is_recovery_complete()) {
            tracing::warn!(
                read_established = nip60_read_authoritative,
                established = counter_db.is_established(),
                recovery_complete = counter_db.is_recovery_complete(),
                "stalled: config/token below quorum OR recovery incomplete — spawning the bounded \
                 config-plane read-retry (§2.4, F3); derivations/rollover remain gated until a ≥k read \
                 completes restore + drain (recovery_complete)"
            );
            let store = store.clone();
            let counter_db_retry = counter_db.clone();
            let wallet_retry = wallet.clone();
            tokio::spawn(async move {
                for attempt in 0..CONFIG_RETRY_MAX_ATTEMPTS {
                    let delay =
                        config_retry_backoff(attempt, CONFIG_RETRY_BASE, CONFIG_RETRY_MAX_INTERVAL);
                    tokio::time::sleep(delay).await;
                    match try_establish_counter(&store, &counter_db_retry, &wallet_retry).await {
                        Ok(true) => {
                            tracing::info!(
                                attempt,
                                "config-plane retry: counter ESTABLISHED on a ≥k read — derivations \
                                 unblocked, floor fast-forwarded, restore re-driven, deferred mints drained"
                            );
                            return;
                        }
                        Ok(false) => tracing::warn!(
                            attempt,
                            "stalled: below-quorum config, awaiting k relays (retry attempt {attempt} \
                             still below quorum; backing off)"
                        ),
                        Err(e) => tracing::warn!(
                            attempt,
                            error = %e,
                            "config-plane retry attempt errored (will back off and retry)"
                        ),
                    }
                }
                tracing::warn!(
                    "config-plane retry: bound expired still below quorum — proceeding on the \
                     existing balance, minting/derivation stays BLOCKED (money-safe), the stall \
                     stays visible; re-establishes on the next boot that reaches ≥k"
                );
            });
        }
    }

    // 6) Build the brain over the funded wallet, with the configured kill-window. When NIP-60 is
    //    configured, WRAP the ecash provider in the Cut A (#115) backup decorator: it marks a
    //    shared dirty flag after each successful wallet mutation (cheap, on the spend hot path —
    //    NO relay I/O there) and a background flusher republishes the current-unspent snapshot on
    //    the [nip60].backup_flush_secs cadence (best-effort, off the hot path). The wallet is the
    //    truth and is durable before any backup; a backup publish can never block or fail a spend.
    //    With no store the bare CdkEcash is used unchanged (no decorator, no flusher).
    let (backend, flusher): (Arc<dyn BrainBackend>, Option<Arc<crate::rail::Nip60BackupFlusher>>) =
        match &nip60_store {
            Some(store) => {
                let (decorated, flusher) = crate::rail::Nip60BackedEcash::with_flusher(
                    ecash,
                    wallet.clone(),
                    store.clone(),
                    brain.mint_url.clone(),
                    "sat".to_string(),
                    nip60_initial_live_ids,
                );
                let routstr = RoutstrBrain::new(
                    brain.node_url.clone(),
                    decorated,
                    Duration::from_secs(brain.request_timeout_secs),
                    Duration::from_secs(brain.recovery_timeout_secs),
                )?;
                // Spawn the periodic backup flush (best-effort; the handle is detached — the task
                // lives for the run and a failure logs + retries next tick). The returned Arc is
                // kept for a FINAL shutdown flush (below), so a graceful death publishes the last
                // snapshot even if a mutation landed inside the last flush interval.
                let _periodic = flusher.clone().spawn_periodic(nip60.backup_flush_interval());
                (Arc::new(routstr), Some(flusher))
            }
            None => {
                let routstr = RoutstrBrain::new(
                    brain.node_url.clone(),
                    ecash,
                    Duration::from_secs(brain.request_timeout_secs),
                    Duration::from_secs(brain.recovery_timeout_secs),
                )?;
                (Arc::new(routstr), None)
            }
        };
    // Inc 1b (D1/D2 + Fix 1): build the earn-loop SETTLEMENT provider over the SAME host-held wallet,
    // selected by `[brain] settlement_method`. Built HERE (after the flusher) so it can be handed the
    // flusher's `BackupDirtyNotifier`: a settlement mint/receive writes proofs directly into the raw
    // wallet (NOT through the Nip60BackedEcash decorator), so the notifier is the ONLY thing that
    // flips the backup `dirty` flag for those proofs — without it a stranger's freshly-minted proofs
    // would not be mirrored to the relay backup until a later spend, and would be LOST on a failover
    // restore (Fix 1, real sats-loss). `None` (the default) wires NO provider — byte-identical to
    // pre-1b (IssueCharge fails closed). When NIP-60 is not configured there is no flusher and thus
    // no notifier (`None`) — correct: there is no relay backup to mirror to. The wallet is returned
    // as a trait object so it never escapes to the gateway. A Lightning provider also gets a DURABLE
    // sled-backed stranded-quote sink (D4), beside the wallet db under the durable treasury dir.
    let backup_notifier = flusher.as_ref().map(|f| f.dirty_notifier());
    let settlement_provider: Option<Arc<dyn SettlementProvider>> = match brain.settlement_method {
        None => None,
        Some(crate::config::SettlementMethod::Cashu) => {
            tracing::info!("Inc 1b: wiring the CASHU settlement provider over the treasury wallet");
            let mut provider = CashuSettlement::new(wallet.clone());
            if let Some(notifier) = backup_notifier.clone() {
                provider = provider.with_backup_notifier(notifier);
            }
            Some(Arc::new(provider))
        }
        Some(crate::config::SettlementMethod::Lightning) => {
            // Durable stranded-quote sink beside the wallet db (per-agent, under the durable
            // treasury dir). REFUSE TO BOOT if it cannot open: a Lightning agent that cannot durably
            // record a stranded real sat must not take live payments (D4 money-safety).
            let stranded_path = Path::new(&brain.wallet_db_path).with_extension("stranded");
            let sink = SledStrandedSink::open(&stranded_path).map_err(|e| {
                anyhow::anyhow!(
                    "Inc 1b: refusing to boot a Lightning-settlement agent — could not open the \
                     durable stranded-quote sink at {}: {e}",
                    stranded_path.display()
                )
            })?;
            tracing::info!(
                stranded_path = %stranded_path.display(),
                "Inc 1b: wiring the LIGHTNING (bolt11) settlement provider over the treasury wallet \
                 with a durable sled-backed stranded-quote sink"
            );
            let mut provider =
                LightningSettlement::new(wallet.clone()).with_stranded_sink(Arc::new(sink));
            if let Some(notifier) = backup_notifier.clone() {
                provider = provider.with_backup_notifier(notifier);
            }
            Some(Arc::new(provider))
        }
    };

    // Cut B (#115): the counter-estate bundle for the graceful-teardown 17375 re-publish, built
    // ONLY when NIP-60 is configured (same gate as the flusher). `counter_db` is the SAME decorator
    // the wallet writes through, so its `keyset_counters()` at death is the live high-water mirror.
    let counter_estate = nip60_store
        .as_ref()
        .map(|store| (store.clone(), counter_db.clone(), brain.mint_url.clone()));
    Ok((backend, flusher, counter_estate, settlement_provider))
}

/// Build the [`RoutstrKeyBrain`] backend for `backend = "routstr_key"` (the prepaid,
/// mint-independent path): load the bearer key from its keyfile, construct the brain, then
/// probe `/v1/balance/info` to BOTH validate the key works AND read the custodial balance.
/// REFUSE TO BOOT on an unusable key (a bad/empty/unfunded key surfaces as a balance-probe
/// error) — the agent cannot think without a working key. Returns the brain PLUS the probed
/// `balance_sats`, so the G4 caller (`boot_and_observe`) can reconcile the metabolism
/// counter to the custodial-key truth (RAISE on a topup, LOWER on an external spend) instead
/// of asserting the counter is already backed. No wallet, no mint, no saga recovery: the key
/// is the only credential, and the money already left at funding time.
async fn build_routstr_key_brain(
    brain: &crate::config::BrainConfig,
) -> anyhow::Result<(Arc<dyn BrainBackend>, u64)> {
    // 1) Load the bearer key from its FILE (never inline in the logged/serialized config —
    //    it is bearer money, the same discipline as the wallet seed / dm key).
    let api_key = load_api_key(&brain.api_key_path)?;

    // 2) Build the brain (HTTP client with redirects disabled + the per-call kill-window).
    let key_brain = RoutstrKeyBrain::new(
        brain.node_url.clone(),
        api_key,
        brain.max_tokens,
        Duration::from_secs(brain.request_timeout_secs),
    )?;

    // 3) Probe the balance: this BOTH validates the key (a bad/empty/unfunded key returns
    //    non-2xx, surfaced as an error) and reads the custodial balance. REFUSE TO BOOT if
    //    the probe fails (don't boot a brain that cannot think). The custodial balance is the
    //    authoritative spendable truth; the G4 caller reconciles the counter to it (a probe
    //    error refuses here, so the reconcile below only ever runs on a successful probe).
    let balance_sats = key_brain.fetch_balance_sats().await.map_err(|e| {
        anyhow::anyhow!(
            "RoutstrKeyBrain refuses to boot: could not read the prepaid key balance from \
             the node ({e}). The agent cannot think without a working, funded key."
        )
    })?;

    let backend: Arc<dyn BrainBackend> = Arc::new(key_brain);
    Ok((backend, balance_sats))
}

/// The G4 boot reconcile decision for the prepaid API-key path (the pure, unit-testable core
/// of the caller arm in [`boot_and_observe`]). The custodial key balance is the authoritative
/// spendable truth (the EXTERNAL-BALANCE-IS-TRUTH model), so a SUCCESSFUL, NON-ZERO probe SETS
/// the metabolism counter to it via [`crate::treasury::Treasury::reconcile_to_observed`]
/// ([`G4Action::Reconcile`]) — RAISING on a topup, LOWERING on an external spend the counter
/// had not seen. A probed `0` is NOT trusted to zero the counter ([`G4Action::SkipZero`]):
/// [`crate::rail::RoutstrKeyBrain::fetch_balance_sats`] FLOORS sub-sat dust to 0, and a
/// spurious 0 must not brick a funded agent — the key gates real spend, so die-when-broke
/// still fires at first spend if the key is truly empty. (A probe ERROR never reaches here:
/// `build_routstr_key_brain` refuses to boot on it.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G4Action {
    /// Reconcile the counter to this observed custodial balance (a non-zero probe): SET it,
    /// both directions (RAISE on a topup, LOWER on an external spend).
    Reconcile(u64),
    /// The probe read 0 sat: SKIP the reconcile (do NOT zero the counter) and proceed, because
    /// a floored-dust / spurious 0 must not kill a funded agent.
    SkipZero,
}

/// The G4 reconcile decision (see [`G4Action`]): a non-zero balance reconciles the counter to
/// it; a `0` reading skips (never zeroes the counter). Pure so the money-critical decision is
/// unit-tested WITHOUT a live balance probe or a real treasury; the caller arm wires to it.
pub fn g4_reconcile_action(balance_sats: u64) -> G4Action {
    if balance_sats > 0 {
        G4Action::Reconcile(balance_sats)
    } else {
        G4Action::SkipZero
    }
}

/// Load the prepaid bearer key from its keyfile: open `O_NOFOLLOW` (a symlink planted at the
/// path is REFUSED, never followed to a different file — a bearer-key redirection guard, #117),
/// read the file, trim surrounding whitespace/newline (an editor- or `printf`-written key usually
/// has a trailing newline), and reject an empty result. A loose file mode (not 0600) is WARNED,
/// not rejected: a strict requirement would refuse an existing manually-created keyfile (often
/// 0644) and could brick a live agent on redeploy; fund-key provisions its keys 0600, so
/// strict-0600 convergence comes naturally. The key is bearer money — it lives in a FILE (never
/// inline in the logged/serialized config) and is never logged here.
fn load_api_key(path: &str) -> anyhow::Result<String> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| anyhow::anyhow!("open brain.api_key_path {path:?} (O_NOFOLLOW): {e}"))?;
    // WARN — do NOT reject — on a loose file mode; signal the tightening, never the key's bytes.
    if let Ok(meta) = f.metadata() {
        let mode = meta.mode() & 0o777;
        if mode != 0o600 {
            tracing::warn!(
                path,
                mode = format!("{mode:#o}"),
                "brain.api_key_path is not mode 0600 (a bearer key should be owner-only) — \
                 proceeding; fund-key provisions keys 0600"
            );
        }
    }
    let mut raw = String::new();
    f.read_to_string(&mut raw)
        .map_err(|e| anyhow::anyhow!("read brain.api_key_path {path:?}: {e}"))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        anyhow::bail!(
            "brain.api_key_path {path:?} is empty (expected a prepaid Routstr bearer key, e.g. sk-…)"
        );
    }
    Ok(key)
}

/// The inbound-event allowlist for a boot session. NIP-17 DMs (task #12) permit `DirectMessage`;
/// a wired settlement provider (Inc 1b) permits `PaymentSettled` so the earn/oracle loop's
/// settled-poll is DELIVERABLE through the gateway (`PollInbox` delivers only
/// `want_kinds ∩ allowlist`, gateway.rs) — without this a settlement-wired agent enqueues a
/// `PaymentSettled` on a credit that the genome can never poll. Kept as a free fn so the boot
/// wiring and its tooth share ONE source of truth. An agent with neither DMs nor settlement gets
/// an EMPTY allowlist (inbound disabled, default-deny) — byte-identical to pre-1b.
pub(crate) fn boot_inbound_allowlist(
    dm_enabled: bool,
    settlement_wired: bool,
) -> Vec<kirby_proto::InboundKind> {
    let mut kinds = Vec::new();
    if dm_enabled {
        kinds.push(kirby_proto::InboundKind::DirectMessage);
    }
    if settlement_wired {
        kinds.push(kirby_proto::InboundKind::PaymentSettled);
    }
    kinds
}

/// Whether to attach the gateway's [`InboundQueue`](crate::nerve::InboundQueue). BOTH inbound
/// producers need it: the NIP-17 DM task feeds it (DM path) and `settle_charge` enqueues
/// `PaymentSettled` onto it (settlement path) — so it is attached when EITHER is wired. ★The DM
/// TASK spawn stays SEPARATELY `dm_enabled`-gated below (a settlement-only, DM-disabled agent
/// attaches the queue for the settled-poll but must NOT reach the DM task's `dm_key_path.expect`).
pub(crate) fn boot_attaches_inbound_queue(dm_enabled: bool, settlement_wired: bool) -> bool {
    dm_enabled || settlement_wired
}

/// As [`boot_and_observe`], but the caller supplies the [`Rail`] the gateway's
/// perform step (spec 3.2 step 4) uses. The C-6 brokered act (gate G5) passes the
/// real [`crate::rail::CdkEcashRail`] so a genome `RequestCapability` settles ecash
/// on the local mint; the other chunks use the mock rail. Everything else (the
/// gateway service, the treasury, the authorize order, the metering) is identical.
///
/// The backend is selected by platform: Firecracker on Linux, VZ on macOS. The
/// daemon boots through the [`SandboxBackend`] trait, never through a concrete VM
/// type, so the gateway/treasury/rail wiring stays shared.
pub async fn boot_and_observe_with_rail(
    config: BootConfig,
    rail: Arc<dyn Rail>,
    // The Cut A (#115) NIP-60 backup flusher, when a real cdk-wallet brain configured one. Kept
    // alive for the run and given a FINAL flush at graceful teardown (wired into the ServeGuard's
    // drop below). `None` for every non-wallet path (nothing to back up). Only `boot_and_observe`'s
    // Routstr arm passes `Some`.
    nip60_flusher: Option<Arc<crate::rail::Nip60BackupFlusher>>,
    // The Cut B (#115) counter-estate bundle (store + counter decorator + mint url), `Some` on the
    // same NIP-60-configured Routstr path as `nip60_flusher`. Carried into the ServeGuard so the
    // awaited `flush_estate` re-publishes the CURRENT 17375 counter mirror at graceful death. `None`
    // for every other path → no counter estate publish, unchanged behavior.
    nip60_counter_estate: Option<Nip60CounterEstate>,
    // Inc 1b (D1): the earn-loop SETTLEMENT provider, when the config selected one (`[brain]
    // settlement_method`). `Some` only on the Routstr path that built it over the host-held wallet;
    // `None` for every other path (api-key/stub/mock/test), leaving IssueCharge fail-closed exactly
    // as before. Attached to the gateway below via `with_settlement_provider_dyn`.
    settlement: Option<Arc<dyn SettlementProvider>>,
) -> anyhow::Result<(Box<dyn SandboxInstance>, BootOutcome, Treasury, EventStream, ServeGuard)> {
    // The persisted, daemon-owned treasury (D-9). A per-node temp store keeps two
    // node processes distinct on one host. The session is the non-secret snapshot
    // the genome pulls at boot (spec 3.1).
    let treasury_path = treasury_path_for(&config.node_id);
    let treasury = open_treasury_retrying(&treasury_path, config.initial_sats, Duration::from_secs(5)).await?;
    // The NIP-17 DM path (task #12) is enabled when the social config pins a dedicated DM keyfile
    // OR the born-unified gate is set (P1, `dm_under_q`: the DM identity is Q, so a true Q-only
    // config may leave `dm_key_path` unset). It allowlists inbound DIRECT_MESSAGE (the inbound
    // mirror of the nostr.dm_reply outbound token) and attaches an InboundQueue the gateway's
    // PollInbox drains + the run_dm_inbound task feeds.
    let dm_enabled = config
        .social
        .as_ref()
        .map(|s| s.dm_key_path.is_some() || s.dm_under_q)
        .unwrap_or(false);
    // Inc 1b (FIX 1): a wired settlement provider makes `PaymentSettled` allowlisted + the inbound
    // queue attached, so the earn/oracle loop's settled-poll is deliverable in production. Read
    // `.is_some()` BEFORE `settlement` is moved into the gateway attach below.
    let settlement_wired = settlement.is_some();
    let session = Session {
        task_descriptor: config.task.clone(),
        budget_sats: config.budget_sats,
        allowlisted_destinations: config.allow.clone(),
        allowlisted_inbound_kinds: boot_inbound_allowlist(dm_enabled, settlement_wired),
    };
    // The meter and the gateway share ONE treasury instance (one authoritative
    // counter, D-9): metered ticks and capability spends debit the same balance.
    let meter_treasury = treasury.clone();
    let mut service = GatewayService::new(treasury, rail, session);
    // Inc 1b (D1): attach the earn-loop settlement provider (built over the host-held wallet in
    // `build_routstr_brain`). Without one, IssueCharge fails closed (debit 0) exactly as before —
    // so a non-configured agent is byte-identical to pre-1b. This is the wiring 1a proved missing.
    if let Some(provider) = settlement {
        service = service.with_settlement_provider_dyn(provider);
    }
    // Attach the inbound queue (the consumer side) when DMs are enabled OR a settlement provider is
    // wired: the run_dm_inbound task (DM path) and `settle_charge`'s PaymentSettled enqueue
    // (settlement path) both feed the SAME handle. The DM TASK spawn stays `dm_enabled`-gated below
    // — a settlement-only, DM-disabled agent attaches the queue but spawns no DM task.
    let inbox_queue = if boot_attaches_inbound_queue(dm_enabled, settlement_wired) {
        let queue = crate::nerve::InboundQueue::new();
        service = service.with_inbound_queue(queue.clone());
        Some(queue)
    } else {
        None
    };
    if let Some(checkpoint) = config.restore_checkpoint.clone() {
        service = service.with_restore_checkpoint(checkpoint);
    }
    // The durable-mind-state workload injects a memory backend onto the gateway (the
    // Memory act is performed here, not through the rail -- its metering forks, design doc
    // 11/12). `Some` only for `workload = memory`; otherwise a Memory act fails closed.
    // An EMPTY relay set => the in-memory `StubMemory` (test/dev, Chunk-1 shape, all
    // current tests); a configured relay set => the real NIP-AE `EngramStore` (Chunk-2),
    // signing + self-encrypting engrams with the node identity key over the nerve.
    if let Some(mem) = &config.memory {
        let backend: Arc<dyn MemoryBackend> = if mem.relays.is_empty() {
            Arc::new(StubMemory::new(mem.bytes_per_sat))
        } else {
            // The identity keyfile (the ONE key rooting identity/presence/memory, design
            // doc §2): the configured path, else a default beside this node's treasury.
            let key_path = mem
                .key_path
                .clone()
                .unwrap_or_else(|| treasury_path.with_extension("nostr.key"));
            let identity = NodeIdentity::load_or_create(&key_path)?;
            Arc::new(
                EngramStore::connect(
                    identity.keys().clone(),
                    &mem.relays,
                    mem.write_k,
                    mem.bytes_per_sat,
                )
                .await?,
            )
        };
        service = service.with_memory_backend(backend);
    }

    // Attach the PER-AGENT lease fence to the LIVE gateway (fleet-host S1, spec 2.2,
    // gate G-FENCE-LIVE). This is the wiring that makes the proven-but-dead fence
    // (gateway.rs: zero production callers before this) actually protect live money:
    // when a fleet supervisor supplies a fence, STEP 0 of `authorize_capability` denies
    // + debits 0 unless THIS node holds the tenant agent's committed lease at the
    // started term. `None` (the single-agent default) leaves the gateway unfenced
    // exactly as before, so a bare `kirby run` is byte-identical.
    if let Some(fence) = config.lease_fence.clone() {
        // `fence.handle` is already an `Arc<dyn LeaseAuthority>` (the trait seam), so attach
        // it through `with_lease_authority` rather than re-boxing a concrete handle.
        service = service.with_lease_authority(fence.handle, fence.agent_id, fence.vm_term);
    }

    // Observe ReportEvents so we can await the genome's boot hello (G1).
    let mut events = service.observe_events();

    // The backend-neutral guest spec. The backend translates it into its own
    // launch (the Firecracker backend builds the jail, the cgroup parent, and the
    // per-VM TAP from it); this orchestration never names a Firecracker type.
    let spec = GuestSpec {
        image: GuestImage {
            kernel: config.image.vmlinux.clone(),
            rootfs: config.image.rootfs.clone(),
        },
        instance_id: config.node_id.clone(),
        guest_cid: config.guest_cid,
        gateway_port: config.gateway_port,
        vcpu_count: config.vcpu_count,
        mem_size_mib: config.mem_size_mib,
        workload: config.workload.clone(),
        // The brain knobs travel to the genome on the kernel command line (the
        // backend writes `kirby.brain_*=` when this is Some, brain-stub §4).
        brain: config.brain.clone(),
        // The memory knobs travel the same way (`kirby.memory_*=` when Some).
        memory: config.memory.clone(),
        // The agent cadence/recall knobs travel the same way (`kirby.diarist_*=` when Some).
        // `AgentConfig` is `Copy`, so this copies (no clone needed).
        agent: config.agent,
        lockdown_egress: config.lockdown_egress,
        snapshot_capable: config.snapshot_capable,
    };

    tracing::info!(
        node_id = %config.node_id,
        cid = config.guest_cid,
        port = config.gateway_port,
        backend = backend_label(),
        "booting genome guest through the sandbox backend"
    );

    let backend = default_backend();
    let mut instance = backend.boot(spec).await?;

    // The boot evidence: the guest reached Running.
    let reached_running = instance.is_running();
    tracing::info!(reached_running, "guest state after start");
    if !reached_running {
        instance.halt().await;
        anyhow::bail!("guest did not reach the running state");
    }

    // Stream the guest serial console (supplementary boot evidence).
    instance.stream_console();

    // Serve the agnostic gateway over the instance's vsock transport so the
    // genome's boot round-trip lands. The genome (already booting) retries
    // connecting until this listener is bound. The gateway SERVICE is identical on
    // every backend; only the transport it binds is backend-specific.
    let transport = instance.gateway_transport();
    let serve_service = service.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = serve_gateway_over(serve_service, transport).await {
            tracing::error!(error = %e, "gateway serve loop ended with error");
        }
    });
    // #62 (earn-loop deployability): spawn the SETTLEMENT POLLER right after the serve task, and
    // ONLY when settlement is wired (the SAME `settlement_wired` gate the inbox/allowlist use above,
    // boot.rs — additive discipline: a non-earn agent spawns NOTHING here and boots byte-identically).
    // This is the missing production trigger for `settle_charge` — see `spawn_settlement_poller`'s
    // doc (with the Part-A closure table). The cadence is the optional `[brain] settle_poll_secs`
    // knob (default 10s), clamped to >= 1s; when no `[brain]` block exists we fall back to the
    // default (settlement is only ever wired on the Routstr path, which always has a `[brain]`).
    let settle_poller = if settlement_wired {
        let poll_secs = config
            .brain
            .as_ref()
            .map(|b| b.settle_poll_secs)
            .unwrap_or_else(crate::config::default_brain_settle_poll_secs)
            .max(1);
        tracing::info!(
            settle_poll_secs = poll_secs,
            "settlement wired — spawning the #62 settlement poller (mint-poll → mint → credit → PaymentSettled)"
        );
        Some(spawn_settlement_poller(service.clone(), Duration::from_secs(poll_secs)))
    } else {
        None
    };
    // Spawn the NIP-17 DM inbound subscription (task #12) when DMs are enabled: publish the agent's
    // kind:10050 inbox-relay list (best-effort -- a relay hiccup must not fail boot), then run the
    // producer that feeds the gateway's inbox queue. The task is torn down with the run via the
    // oneshot sender held in the ServeGuard (dropping it fires run_dm_inbound's shutdown arm).
    // ★ The DM inbound task is DM-gated (dm_enabled), NOT merely queue-gated: a settlement-only,
    // DM-disabled agent has `inbox_queue = Some(..)` (for the settled-poll) but MUST NOT spawn the
    // DM task or reach its `dm_key_path.expect` below. Requiring `dm_enabled` here keeps the DM
    // path exactly as before while the queue serves PaymentSettled.
    let dm_shutdown = match (dm_enabled, inbox_queue, config.social.as_ref()) {
        (true, Some(queue), Some(social)) => {
            // The NIP-17 DM identity, built ONCE (used for the kind:10050 publish + run_dm_inbound).
            // BORN-UNIFIED (P1, gated on `dm_under_q` + a FROST keystore): the identity IS the group
            // key Q -- a QSigner so the 10050 signs under Q and inbound DMs unwrap under Q via
            // threshold ECDH. Else the dedicated plain dm_keys (pre-P1, byte-identical).
            let (dm_signer, dm_me): (std::sync::Arc<dyn nostr_sdk::NostrSigner>, nostr_sdk::PublicKey) =
                if social.dm_under_q {
                    // Explicit fail-closed: dm_under_q requires a provisioned FROST keystore (the
                    // shared `AgentCosign` also enforces this, but this names the dm_under_q intent).
                    let _keystore_dir = social.frost_keystore_dir.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "dm_under_q requires a provisioned FROST keystore for the DM identity Q"
                        )
                    })?;
                    // INC2a: through the shared `AgentCosign` seam. `load_ecdh` FAILS CLOSED LOUD on a
                    // DISTRIBUTED keystore (cross-machine ECDH is Inc3, the co-gate); co-located is
                    // unchanged. `load_signer` gives the ONE shared signer (distributed) or a fresh
                    // one (co-located).
                    let ecdh = std::sync::Arc::new(config.cosign.load_ecdh()?);
                    let quorum = config.cosign.load_signer()?;
                    let q = ecdh.q_public_key()?;
                    tracing::info!(
                        "NIP-17 DM identity is the FROST key Q (born-unified, dm_under_q; DMs seal/unwrap under Q)"
                    );
                    (std::sync::Arc::new(crate::qsigner::QSigner::new(ecdh, quorum)), q)
                } else {
                    // `dm_enabled` (which gated `inbox_queue` to `Some`) implies `dm_key_path` is `Some`.
                    let dm_path = social
                        .dm_key_path
                        .as_deref()
                        .expect("dm_enabled implies a configured dm_key_path");
                    let dm_identity = NodeIdentity::load_or_create(dm_path)?;
                    tracing::info!(
                        dm_npub = %dm_identity.npub(),
                        "NIP-17 DM identity loaded (a plain key, distinct from the publish voice)"
                    );
                    // CANONICAL SOCIAL profile (kind:0, #76): the plain-dm_keys path ONLY. Under
                    // born-unified Q the kind:0-under-Q profile is deferred to the npub cutover
                    // (scope A) -- a kind:0 under a plain key would name the wrong identity. Best-effort.
                    let profile_name = config.task.strip_prefix("kirby-run-").unwrap_or(&config.task);
                    let profile_json = serde_json::json!({ "name": profile_name }).to_string();
                    match crate::nerve::publish_metadata_profile(&dm_identity, &social.relays, &profile_json).await {
                        Ok(id) => tracing::info!(event_id = %id, "published the kind:0 canonical social profile"),
                        Err(e) => tracing::warn!(error = %e, "kind:0 profile publish failed (continuing)"),
                    }
                    (std::sync::Arc::new(dm_identity.keys().clone()), dm_identity.public_key())
                };

            // Publish the kind:10050 inbox-relay list under the DM identity (Q via the QSigner, or the
            // plain key). Best-effort -- a relay hiccup must not fail boot; the agent still receives DMs.
            match crate::nerve::publish_inbox_relay_list(dm_signer.clone(), &social.relays).await {
                Ok(id) => tracing::info!(event_id = %id, "published the kind:10050 DM-inbox relay list"),
                Err(e) => tracing::warn!(error = %e, "kind:10050 publish failed (continuing; the agent still receives DMs)"),
            }

            let (tx, rx) = tokio::sync::oneshot::channel();
            let relays = social.relays.clone();
            // #103: the DM backfill sweep interval (0 disables it). Copied out before the move.
            let dm_backfill_secs = social.dm_backfill_secs;
            tokio::spawn(async move {
                if let Err(e) =
                    crate::nerve::run_dm_inbound(dm_signer, dm_me, &relays, queue, dm_backfill_secs, rx)
                        .await
                {
                    tracing::error!(error = %e, "DM inbound task ended with error");
                }
            });
            Some(tx)
        }
        _ => None,
    };

    // Cut A (#115): the ABRUPT-death NIP-60 backup flush FALLBACK ("estate" flush). If a cdk-wallet
    // brain configured a flusher, spawn a detached task that waits on a shutdown signal, then does
    // ONE last best-effort `flush()`. The signal fires when the `ServeGuard` (and thus
    // `_nip60_shutdown`) drops at run-end. This is now the PANIC/KILL fallback ONLY: the GRACEFUL
    // path awaits `ServeGuard::flush_estate()` before the guard drops (codex #3), which consumes the
    // dirty flag, so this detached task then no-ops (`!dirty`) — no double publish. It survives to
    // cover an abrupt unwind that skipped `flush_estate`. The guard ALSO keeps a clone of the
    // flusher (below) so the awaited graceful flush is possible. Best-effort: errors logged, never
    // propagated (the wallet is already truth). `None` => no task, no sender, no flusher.
    let nip60_shutdown = nip60_flusher.as_ref().map(|flusher| {
        let flusher = flusher.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            // Resolves on an explicit signal OR (the drop path) when the sender is dropped: either
            // way the receiver completes and we do the fallback flush (a no-op if `flush_estate`
            // already consumed the dirty flag on the graceful path).
            let _ = rx.await;
            if let Err(e) = flusher.flush().await {
                tracing::warn!(
                    error = %e,
                    "NIP-60 abrupt-death fallback backup flush failed (spend truth is unaffected; the next boot re-snapshots)"
                );
            } else {
                tracing::debug!("NIP-60 abrupt-death fallback backup flush complete (or no-op if the graceful estate flush already ran)");
            }
        });
        tx
    });

    // The serve task holds a GatewayService clone (and thus a Treasury Arc, holding
    // the sled lock). It is a listener loop that never returns on its own, so it
    // must be aborted at run-end to release the lock; the ServeGuard does that on
    // drop. The caller binds it for the run's lifetime.
    let serve_guard = ServeGuard {
        handle: serve_task.abort_handle(),
        _dm_shutdown: dm_shutdown,
        _nip60_shutdown: nip60_shutdown,
        // Held for the AWAITED graceful estate flush (codex #3). `nip60_shutdown` above already
        // consumed a clone into the abrupt-death fallback task; this keeps the original `Option`.
        nip60_flusher,
        // Cut B (#115): the current-counter-mirror re-publish at graceful death, awaited inside the
        // SAME `flush_estate` after the proof flush.
        nip60_counter_estate,
        // #62: the settlement poller handle (Some only when settlement is wired), aborted in Drop.
        settle_poller,
    };

    // Wait for the genome's boot hello event (session=<task>). This is the G1
    // round-trip proof: the genome connected over vsock, pulled the session
    // context, and reported hello.
    let hello = wait_for_hello(&mut events, &config.task, config.hello_timeout).await;
    match &hello {
        Some(ev) => {
            tracing::info!(detail = %ev.detail, "genome boot hello received (G1 round-trip proven)")
        }
        None => tracing::warn!("genome boot hello did NOT arrive before the timeout"),
    }

    let outcome = BootOutcome {
        reached_running,
        hello,
        budget_sats: config.budget_sats,
        checkpoints: service.checkpoint_handle(),
    };
    Ok((instance, outcome, meter_treasury, events, serve_guard))
}

/// Serve the agnostic [`GatewayService`] over a guest's backend-specific
/// [`GatewayTransport`]. The gateway is identical on every backend; this dispatch
/// is the one place the host-side listen mechanism differs. Firecracker is the
/// only transport today; a macOS VZ endpoint adds a match arm here.
async fn serve_gateway_over(
    service: GatewayService,
    transport: GatewayTransport,
) -> anyhow::Result<()> {
    serve_gateway_over_pub(service, transport).await
}

/// The public form of [`serve_gateway_over`] so other orchestrations (the C-7
/// snapshot run serves a fresh gateway over the restored guest's transport) reuse
/// the one transport-dispatch site. Adding a backend means one match arm here, for
/// every caller.
pub async fn serve_gateway_over_pub(
    service: GatewayService,
    transport: GatewayTransport,
) -> anyhow::Result<()> {
    match transport {
        GatewayTransport::FirecrackerVsockUds { uds_base, port } => {
            service.serve_firecracker_vsock(&uds_base, port).await
        }
        #[cfg(target_os = "macos")]
        GatewayTransport::VzVsockProxyUds { uds_path, port } => {
            tracing::info!(path = %uds_path.display(), port, "NodeGateway serving over VZ helper proxy");
            service.serve_unix_socket(&uds_path).await
        }
    }
}

#[cfg(target_os = "linux")]
fn default_backend() -> impl SandboxBackend {
    FirecrackerBackend::new()
}

#[cfg(target_os = "macos")]
fn default_backend() -> impl SandboxBackend {
    VzBackend::new()
}

#[cfg(target_os = "linux")]
fn backend_label() -> &'static str {
    "firecracker"
}

#[cfg(target_os = "macos")]
fn backend_label() -> &'static str {
    "vz"
}

/// Wait for the genome's boot hello event with the expected `session=<task>`
/// detail, up to `timeout`. Other events (none expected at boot in C-2) are
/// drained while waiting.
async fn wait_for_hello(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    task: &str,
    timeout: Duration,
) -> Option<Event> {
    let expected_detail = format!("session={task}");
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "hello" && ev.detail == expected_detail => return Some(ev),
            Ok(Some(_)) => continue, // some other event; keep waiting for hello
            Ok(None) => return None, // observer dropped
            Err(_) => return None,   // timed out
        }
    }
}

#[cfg(test)]
mod routstr_key_boot_tests {
    use super::{g4_reconcile_action, load_api_key, G4Action};

    /// A unique temp path for a test keyfile (no shared `tests/common` here — this is a
    /// `src` unit test, so we mint our own temp path the same way the harness does).
    fn temp_key_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("kirby-rk-key-{tag}-{}-{}", std::process::id(), n))
    }

    #[test]
    fn load_api_key_reads_and_trims_surrounding_whitespace() {
        let path = temp_key_path("trim");
        std::fs::write(&path, "  sk-abc123\n\n").unwrap();
        let key = load_api_key(path.to_str().unwrap()).expect("a non-empty keyfile loads");
        assert_eq!(key, "sk-abc123", "surrounding whitespace + trailing newline are trimmed");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_api_key_rejects_an_empty_file() {
        let path = temp_key_path("empty");
        std::fs::write(&path, "   \n").unwrap();
        let err = load_api_key(path.to_str().unwrap()).expect_err("a whitespace-only key is rejected");
        assert!(err.to_string().contains("is empty"), "got: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_api_key_rejects_a_missing_file() {
        let path = temp_key_path("missing"); // never created
        let err = load_api_key(path.to_str().unwrap()).expect_err("a missing keyfile errors");
        assert!(err.to_string().contains("brain.api_key_path"), "got: {err}");
    }

    #[test]
    fn load_api_key_refuses_a_symlink() {
        // TOOTH (#117): O_NOFOLLOW refuses a symlink planted at brain.api_key_path — a bearer-key
        // redirection guard. Reverting to std::fs::read_to_string (which follows symlinks) makes
        // this RED: the key would be read THROUGH the symlink to its target.
        use std::os::unix::fs::symlink;
        let target = temp_key_path("symlink-target");
        std::fs::write(&target, "sk-redirected\n").unwrap();
        let link = temp_key_path("symlink-link");
        symlink(&target, &link).unwrap();
        let err = load_api_key(link.to_str().unwrap())
            .expect_err("a symlinked keyfile is refused (O_NOFOLLOW), never followed");
        assert!(err.to_string().contains("O_NOFOLLOW"), "got: {err}");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn load_api_key_warns_but_accepts_a_loose_mode() {
        // A manually-created keyfile is often 0644; load_api_key WARNS (does not reject) so a
        // strict-0600 requirement cannot brick a live agent on redeploy. The key still loads.
        use std::os::unix::fs::PermissionsExt;
        let path = temp_key_path("loose-mode");
        std::fs::write(&path, "sk-loose\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let key = load_api_key(path.to_str().unwrap())
            .expect("a 0644 keyfile is accepted (mode is warned, not rejected)");
        assert_eq!(key, "sk-loose");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn g4_reconciles_a_nonzero_balance_to_that_observed_truth() {
        // Any non-zero probe SETS the counter to the balance (the reconcile itself, tested for
        // BOTH directions against the real treasury in `treasury::tests`, decides RAISE vs LOWER
        // vs Unchanged). Here we only assert the decision carries the exact observed sats through.
        assert_eq!(g4_reconcile_action(1), G4Action::Reconcile(1), "the 1-sat boundary reconciles");
        assert_eq!(
            g4_reconcile_action(50_000),
            G4Action::Reconcile(50_000),
            "a topped-up balance reconciles UP to the observed truth"
        );
        assert_eq!(
            g4_reconcile_action(42),
            G4Action::Reconcile(42),
            "a partly-spent balance reconciles DOWN to the observed truth (never a refuse)"
        );
    }

    #[test]
    fn g4_skips_zeroing_the_counter_on_a_zero_probe() {
        // A successful 0-sat probe is NOT trusted to zero the counter (floored sub-sat dust /
        // a spurious 0 must not brick a funded agent); skip + proceed. The key gates real spend.
        assert_eq!(
            g4_reconcile_action(0),
            G4Action::SkipZero,
            "a 0 reading must SKIP the reconcile, never zero the counter"
        );
    }
}

#[cfg(test)]
mod boot_saga_recovery_tests {
    use super::recover_sagas_within;
    use std::time::Duration;

    /// #84: an unreachable mint makes cdk saga recovery hang (cdk's HTTP client carries no
    /// request timeout). The boot wrapper must DEGRADE — return `Ok` within the budget — so
    /// boot proceeds (onto the local-balance shortfall guard) instead of blocking forever. A
    /// never-resolving future stands in for the hung network call.
    ///
    /// RED-on-revert: drop the `timeout` wrap in `recover_sagas_within` (await the future
    /// directly) and this test HANGS — the pending future never completes — so the suite
    /// times out. That hang IS the bug #84 fixes.
    #[tokio::test]
    async fn degrades_to_ok_when_recovery_hangs() {
        let hung = std::future::pending::<anyhow::Result<()>>();
        let out = recover_sagas_within(hung, Duration::from_millis(50)).await;
        assert!(
            out.is_ok(),
            "a hung (unreachable-mint) saga recovery must degrade to Ok so boot continues"
        );
    }

    /// A real saga error from a REACHABLE mint (resolves well within the budget) still
    /// propagates → boot refuses (the strict R2-4/R2-5 stance is preserved on a mint we
    /// CAN reach; only unreachability degrades).
    ///
    /// RED-on-revert: if the wrapper degraded on the `Ok` arm too (swallowed all errors),
    /// this would be `Ok` and the assertion fails.
    #[tokio::test]
    async fn propagates_a_real_saga_error_within_budget() {
        let failed = async {
            Err::<(), anyhow::Error>(anyhow::anyhow!("recover_incomplete_sagas: mint rejected swap"))
        };
        let out = recover_sagas_within(failed, Duration::from_secs(30)).await;
        let err = out.expect_err("a real saga error within budget must propagate (refuse to boot)");
        assert!(err.to_string().contains("mint rejected swap"), "got: {err}");
    }

    /// A clean recovery (healthy mint, resolves immediately) returns `Ok` and boot proceeds
    /// — the byte-identical happy path (the timeout is a ceiling, not an added delay).
    #[tokio::test]
    async fn passes_through_a_clean_recovery() {
        let ok = async { Ok::<(), anyhow::Error>(()) };
        let out = recover_sagas_within(ok, Duration::from_secs(30)).await;
        assert!(out.is_ok(), "a clean recovery passes through unchanged");
    }
}

#[cfg(test)]
mod config_plane_tests {
    use super::*;

    // ---- T1 (config-plane §2.3): the write-back gate skips the config publish below read-quorum. -
    //
    // A below-quorum config read may have loaded a THIN 17375 floor; republishing it as a NEW head
    // would REGRESS the true head on the reached relays (finding-2, propagating). The gate is wired
    // through `should_publish_config`, so boot only calls `publish_wallet_config` when it returns
    // true.
    //
    // RED-on-revert: change `should_publish_config` to always return `true` → boot publishes the
    // thin head below quorum → this `assert!(!...)` fails.
    #[test]
    fn t1_write_back_gate_skips_publish_below_config_quorum() {
        assert!(
            !should_publish_config(false),
            "below config read-quorum → the 17375 counter head is NOT republished (never regress \
             the true head, §2.3)"
        );
        assert!(
            should_publish_config(true),
            "an authoritative (≥k) config read → the head IS republished as before"
        );
    }

    // ---- T14 (config-plane REVISION, finding-3): the retry is not "converged" until the drain
    // succeeds. `try_establish_counter` reports converged (`Ok(true)`, which STOPS the bounded loop)
    // ONLY when the counter established AND the recovery-drain (`mint_unissued_quotes`) succeeded (with
    // the token read ≥k — held true here to isolate the drain dimension). A drain FAILURE returns
    // false so the loop keeps backing off and re-drives until the drain succeeds — a Paid-but-unissued
    // quote must not be stranded until the next full boot.
    //
    // RED-on-revert: drop `&& drain_ok` from `retry_established`, or make `try_establish_counter`
    // return `Ok(true)` unconditionally on drain-fail → `retry_established(true, true, false)` becomes
    // true → the loop STOPS on a drain failure → this `assert!(!...)` fails.
    #[test]
    fn t14_retry_not_established_until_drain_succeeds() {
        // Converged: counter established, token read ≥k, AND the drain succeeded → converge (stop).
        assert!(
            retry_established(true, true, true),
            "established + token ≥k + drain OK → the retry converges (Ok(true), loop stops)"
        );
        // ★ Drain FAILED (even though the counter established + token ≥k): NOT converged → keep retrying.
        assert!(
            !retry_established(true, true, false),
            "counter established + token ≥k but the drain FAILED → NOT converged → the bounded loop \
             keeps backing off + re-drives (drop `&& drain_ok` → this is true → RED)"
        );
        // Counter not established → never converged, regardless of the other dimensions.
        assert!(
            !retry_established(false, true, true),
            "counter not established → never converged"
        );
        assert!(!retry_established(false, false, false), "none → not converged");
    }

    // ---- T16 (config-plane ROUND-2, R2-#2): the retry does not CONVERGE (does not exit the loop)
    // until the TOKEN read reaches ≥k (`read_established`). The counter may establish (state-3, a head
    // present) on a below-quorum token read, but then `read_established` stays false → the rollover
    // gate is blocked FOREVER if the loop exits. So convergence REQUIRES the token plane too: keep
    // retrying (backoff) until the token read also reaches ≥k.
    //
    // RED-on-revert: drop the `read_established` term from `retry_established` (convergence ignores the
    // token plane) → `retry_established(true, false, true)` becomes true → the loop EXITS Ok(true) with
    // `read_established` stuck false → rollover blocked forever → this `assert!(!...)` fails.
    #[test]
    fn t16_retry_convergence_requires_the_token_plane() {
        // Established + drain OK but the TOKEN read is BELOW quorum → NOT converged → keep retrying
        // (so `read_established` can flip on a later ≥k read and the rollover gate can eventually open).
        assert!(
            !retry_established(true, false, true),
            "established + drain OK but token BELOW quorum → NOT converged → the loop keeps retrying \
             (drop the read_established term → this is true → loop exits rollover-blocked → RED)"
        );
        // All three (established + token ≥k + drain OK) → converge.
        assert!(
            retry_established(true, true, true),
            "established + token ≥k + drain OK → converge"
        );
    }

    // ---- T23 (config-plane ROUND-4, K1-corr — MINTABLE-only drain; unpaid-doesn't-wedge): a NORMAL
    // open UNPAID quote present + NO paid/mintable-but-unminted leftover → the drain is COMPLETE
    // (drain_ok=TRUE, recovery OPENS). The ROUND-3 `len==0` rule counted the unpaid quote and wedged
    // recovery forever. `mintable_remaining` counts ONLY the mintable-but-unminted leftovers (the
    // mint-down case) and IGNORES confirmed-unpaid quotes; a per-quote check error is fail-closed.
    //
    // RED-on-revert: change `mintable_remaining` to count ALL still-unissued quotes (`Some(verdicts.len())`,
    // the ROUND-3 len==0 model) → a lone ConfirmedUnpaid quote yields Some(1) → `drain_complete` false
    // → the "unpaid doesn't wedge" assert fails → RED (recovery wedges on a routine unpaid charge).
    #[test]
    fn t23_unpaid_quote_does_not_wedge_the_drain() {
        use QuoteDrainState::*;
        // A normal open UNPAID quote, nothing mintable → mintable_remaining = Some(0) → drained → OPEN.
        assert_eq!(mintable_remaining(&[ConfirmedUnpaid]), Some(0), "an unpaid quote is IGNORED");
        assert!(
            drain_complete(mintable_remaining(&[ConfirmedUnpaid])),
            "K1-corr: a normal open UNPAID quote must NOT wedge recovery (revert to len==0 → Some(1) → RED)"
        );
        // Several unpaid quotes + no mintable leftover → still drained.
        assert!(
            drain_complete(mintable_remaining(&[ConfirmedUnpaid, ConfirmedUnpaid])),
            "multiple unpaid charges still do not wedge recovery"
        );
        // A paid/mintable-but-unminted leftover (mint-down) → NOT drained → defer.
        assert_eq!(mintable_remaining(&[MintableUnminted]), Some(1), "a mintable leftover counts");
        assert!(
            !drain_complete(mintable_remaining(&[ConfirmedUnpaid, MintableUnminted])),
            "a paid/mintable-but-unminted leftover (mint-down) still DEFERS recovery"
        );
        // A per-quote check error → None → fail-closed defer.
        assert_eq!(mintable_remaining(&[CheckErrored]), None, "a check error is fail-closed (None)");
        assert!(
            !drain_complete(mintable_remaining(&[ConfirmedUnpaid, CheckErrored])),
            "a per-quote check error defers recovery (fail-closed)"
        );
    }

    // ---- T25 (config-plane ROUND-4, K4 — retry RESUME-SKIP): an ALREADY-established counter (RESUME,
    // or a prior attempt established the floor) whose only remaining gap is the token plane must
    // PROCEED to restore/drain/convergence on the retry — NOT early-return on a fresh establish
    // decision that (with resume=false + a still-below-quorum config) would DEFER. So recovery can
    // COMPLETE once token quorum recovers. `try_establish_counter` routes this through
    // `retry_should_proceed(already_established, fresh_establish)`.
    //
    // RED-on-revert: revert to gating on the fresh establish decision ALONE (ignore already_established,
    // i.e. `retry_should_proceed = fresh_establish`) → for an already-established counter whose fresh
    // decision defers, `retry_should_proceed(true, false)` becomes false → early return → recovery
    // NEVER completes → the SEAM assert fails → RED.
    #[test]
    fn t25_retry_resume_skip_proceeds_when_already_established() {
        // THE SEAM: already established, but a fresh establish decision would DEFER (below-quorum
        // config on resume=false). The retry MUST still proceed (only the token plane needs to heal).
        assert!(
            retry_should_proceed(true, false),
            "already-established + fresh-decision-would-defer → PROCEED (revert to `fresh_establish` alone → false → RED)"
        );
        // Not yet established: proceed iff the fresh decision established.
        assert!(retry_should_proceed(false, true), "not established + fresh establish → proceed");
        assert!(!retry_should_proceed(false, false), "not established + fresh defer → back off");
        // Already established + fresh decision also true → proceed (trivially).
        assert!(retry_should_proceed(true, true), "already established → proceed");

        // Counterfactual bite: the OLD gate (fresh decision alone) skips the seam the NEW gate catches.
        let fresh_establish = false;
        assert!(
            !fresh_establish && retry_should_proceed(true, fresh_establish),
            "the OLD `fresh_establish`-only gate would early-return where K4 proceeds"
        );
    }

    // ---- T6 (config-plane §2.4): the retry BACKS OFF, never SPINS. -------------------------------
    //
    // The runtime meter debits the treasury every tick independent of the wallet, so a hot retry
    // loop would raise measured CPU burn and hasten REAL death. `config_retry_backoff` must return a
    // NON-ZERO, BOUNDED, MONOTONICALLY-NON-DECREASING delay — the mechanism that keeps a defer
    // window from debiting faster than baseline idle.
    //
    // RED-on-revert: change `config_retry_backoff` to return `Duration::ZERO` (a spin) → the
    // `>= base` / `> 0` assertions fail.
    #[test]
    fn t6_config_retry_backs_off_never_spins() {
        let base = Duration::from_secs(2);
        let max = Duration::from_secs(60);
        let mut prev = Duration::ZERO;
        for attempt in 0..14u32 {
            let d = config_retry_backoff(attempt, base, max);
            // NEVER a spin: strictly positive and at least the base interval.
            assert!(d >= base, "attempt {attempt}: backoff {d:?} must be >= base {base:?} (never a spin)");
            assert!(d > Duration::ZERO, "attempt {attempt}: backoff must be non-zero (never a spin)");
            // BOUNDED: capped at max.
            assert!(d <= max, "attempt {attempt}: backoff {d:?} must be <= max {max:?} (bounded)");
            // MONOTONIC non-decreasing (exponential ramp), so it is not a fixed hot interval.
            assert!(d >= prev, "attempt {attempt}: backoff must not decrease");
            prev = d;
        }
        // The ramp actually grows before the cap (attempt 0 base=2s, attempt 2 = 8s), then caps.
        assert_eq!(config_retry_backoff(0, base, max), Duration::from_secs(2));
        assert_eq!(config_retry_backoff(2, base, max), Duration::from_secs(8));
        assert_eq!(config_retry_backoff(30, base, max), max, "far-out attempts cap at max");
    }

    // ---- T10 (config-plane §2.8): the solvency false-broke FIX — restore-deferred proceeds. ------
    //
    // The reachable seam: fresh-box + config-below-quorum (counter DEFERRED, `counter_established` =
    // false, restore-receive no-op'd, wallet transiently 0) + token-read ≥k (`nip60_read_authoritative`
    // = true). Keying solvency on the TOKEN read ALONE takes the Assert branch →
    // `assert_wallet_backs_counter(0, initial_sats)` bails → boot aborts, self-heal unreachable
    // (FALSE-BROKE). ANDing in `counter_established` routes it to ProceedNonAuthoritative instead.
    //
    // RED-on-revert: change `boot_solvency_authoritative` to return `nip60_read_authoritative` (the
    // token-only pre-fix behavior) → the seam takes Assert → the bail below fires → this test's
    // "boot proceeds" expectation fails (it goes RED at the `matches!(... ProceedNonAuthoritative)`
    // assertion, and the demonstrated Assert-path bail proves the abort).
    #[test]
    fn t10_solvency_false_broke_fix_restore_deferred_proceeds() {
        // Established path (resume / ≥k restore ran / new-at-0): Assert as before, die-when-broke
        // intact at boot for a genuinely-broke agent.
        assert!(
            boot_solvency_authoritative(true, true),
            "token ≥k AND counter established → authoritative (Assert, unchanged)"
        );
        assert!(matches!(solvency_gate(boot_solvency_authoritative(true, true)), SolvencyGate::Assert));

        // THE SEAM: token ≥k but counter DEFERRED → NOT authoritative → ProceedNonAuthoritative.
        assert!(
            !boot_solvency_authoritative(true, false),
            "token ≥k but counter DEFERRED → NOT authoritative (the false-broke seam)"
        );
        assert!(
            matches!(
                solvency_gate(boot_solvency_authoritative(true, false)),
                SolvencyGate::ProceedNonAuthoritative
            ),
            "restore-deferred fresh box must PROCEED (no false-broke bail), self-healing on ≥k"
        );

        // Prove the counterfactual bite: had we taken Assert on this seam, a transiently-0 wallet vs
        // a nonzero seeded treasury WOULD bail (this is exactly what the fix routes around).
        assert!(
            assert_wallet_backs_counter(0, 50_000).is_err(),
            "the Assert path on a transiently-0 wallet bails — the false-broke the fix prevents"
        );
    }
}

#[cfg(test)]
mod bolt11_settlement_inbound_wiring_tests {
    //! FIX 1 (bolt11 1b rev2): production must be able to DELIVER `PaymentSettled` to the genome.
    //! Boot allowlists `PaymentSettled` and attaches the inbound queue WHENEVER a settlement
    //! provider is wired (not only when DMs are enabled), so the oracle/earn loop's settled-poll
    //! (`poll_one_oracle_event` / `poll_one_payment_settled`, want_kinds:[PaymentSettled]) is
    //! deliverable. This drives the SAME `boot_inbound_allowlist` + `boot_attaches_inbound_queue`
    //! the boot path uses — for a settlement-wired, DM-DISABLED agent — and asserts a queued
    //! `PaymentSettled` polls back through the gateway.
    //!
    //! RED-on-revert: change `boot_inbound_allowlist` to omit `PaymentSettled` (or
    //! `boot_attaches_inbound_queue` to `dm_enabled` only) and the poll returns an EMPTY batch:
    //! the settled notice is undeliverable in production — exactly the latent trap this fix closes.
    use super::{boot_attaches_inbound_queue, boot_inbound_allowlist};
    use crate::gateway::{GatewayService, Session};
    use crate::nerve::InboundQueue;
    use crate::rail::MockRail;
    use crate::treasury::Treasury;
    use kirby_proto::node_gateway_server::NodeGateway;
    use kirby_proto::{InboundKind, InboxRequest, PaymentSettled};
    use prost::Message as _;
    use std::sync::Arc;

    #[test]
    fn allowlist_and_queue_track_settlement_and_dm_independently() {
        // Neither: inbound disabled (default-deny, byte-identical to pre-1b).
        assert!(boot_inbound_allowlist(false, false).is_empty());
        assert!(!boot_attaches_inbound_queue(false, false));
        // Settlement only: PaymentSettled allowlisted + queue attached, but NO DirectMessage.
        let s = boot_inbound_allowlist(false, true);
        assert!(s.contains(&InboundKind::PaymentSettled) && !s.contains(&InboundKind::DirectMessage));
        assert!(boot_attaches_inbound_queue(false, true));
        // DM only: DirectMessage allowlisted + queue attached, but NO PaymentSettled.
        let d = boot_inbound_allowlist(true, false);
        assert!(d.contains(&InboundKind::DirectMessage) && !d.contains(&InboundKind::PaymentSettled));
        assert!(boot_attaches_inbound_queue(true, false));
        // Both: both kinds allowlisted.
        let b = boot_inbound_allowlist(true, true);
        assert!(b.contains(&InboundKind::DirectMessage) && b.contains(&InboundKind::PaymentSettled));
    }

    #[tokio::test]
    async fn settlement_wired_dm_disabled_agent_delivers_payment_settled() {
        // A settlement-only agent: DMs OFF, a settlement provider wired.
        let dm_enabled = false;
        let settlement_wired = true;

        let treasury = Treasury::open_temporary(1_000).expect("open temporary treasury");
        let session = Session {
            task_descriptor: "settlement-only".into(),
            budget_sats: 1_000,
            allowlisted_destinations: Vec::new(),
            allowlisted_inbound_kinds: boot_inbound_allowlist(dm_enabled, settlement_wired),
        };
        let queue = InboundQueue::new();
        let mut service = GatewayService::new(treasury, Arc::new(MockRail::new()), session);
        if boot_attaches_inbound_queue(dm_enabled, settlement_wired) {
            service = service.with_inbound_queue(queue.clone());
        }

        // The daemon enqueues a PaymentSettled on a genuine credit (the `settle_charge` path).
        let payload =
            PaymentSettled { charge_id: "charge-xyz".into(), verified_sats: 21 }.encode_to_vec();
        queue.push_typed(
            InboundKind::PaymentSettled,
            payload,
            String::new(),
            0,
            "charge-xyz".into(),
        );

        // The genome's settled-poll: want_kinds narrowed to [PaymentSettled].
        let resp = service
            .poll_inbox(tonic::Request::new(InboxRequest {
                schema_version: kirby_proto::SCHEMA_VERSION,
                want_kinds: vec![InboundKind::PaymentSettled as i32],
                ack_seq: 0,
                wait_ms: 0,
            }))
            .await
            .expect("poll_inbox")
            .into_inner();

        assert_eq!(
            resp.events.len(),
            1,
            "the queued PaymentSettled is deliverable end-to-end for a settlement-wired agent \
             (RED if the allowlist omits PaymentSettled or the queue is not attached)"
        );
        let ev = &resp.events[0];
        assert_eq!(ev.kind, InboundKind::PaymentSettled as i32);
        let decoded = PaymentSettled::decode(ev.payload.as_slice()).expect("decode PaymentSettled");
        assert_eq!(decoded.verified_sats, 21);
        assert_eq!(decoded.charge_id, "charge-xyz");
    }
}
