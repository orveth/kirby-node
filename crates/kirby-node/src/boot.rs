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
    Actuator, BrainBackend, CdkEcash, CompositeRail, EngramStore, MemoryBackend, MockRail,
    NostrActuator, Rail, RoutstrBrain, RoutstrKeyBrain, StubBrain, StubMemory,
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
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        self.handle.abort();
        // `_dm_shutdown` drops with the struct -> the DM inbound task's shutdown arm fires.
    }
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
    // The outward actuator (the agent's voice): built once if the workload configured it (the
    // capable workload, `config.social = Some`), then attached to the CompositeRail below. None
    // for every other workload, so the rail performs ZERO publishes.
    let actuator: Option<Arc<dyn Actuator>> = match &config.social {
        Some(social) => Some(build_nostr_actuator(social).await?),
        None => None,
    };
    let rail: Arc<dyn Rail> = match &config.brain {
        // The REAL brain (brain-routstr): a CompositeRail whose brain is a RoutstrBrain
        // over a funded, persistent cdk wallet. Building it opens the wallet, recovers
        // any incomplete sagas, and reconciles wallet >= treasury BEFORE the VM boots
        // (REFUSE-TO-BOOT on a shortfall, R2-5), so a real `Completion` is served by a
        // real Routstr node, paid from the treasury.
        Some(brain) if brain.backend == BrainBackendKind::Routstr => {
            let treasury_remaining = peek_treasury_remaining(&config).await?;
            let brain_backend =
                build_routstr_brain(brain, treasury_remaining, &config.nip60, &config.fleet_relay)
                    .await?;
            Arc::new(attach_actuator(
                CompositeRail::new(Arc::new(MockRail::new()), brain_backend),
                actuator,
            ))
        }
        // The prepaid API-KEY brain (mint-independent fallback): a CompositeRail whose
        // brain is a RoutstrKeyBrain over a node-held custodial balance. Building it loads
        // the bearer key and probes /v1/balance/info to (a) validate the key works and (b)
        // assert the balance backs the treasury counter BEFORE the VM boots (REFUSE-TO-BOOT
        // on a shortfall or unusable key — the same loud-and-safe stance as the Cashu path).
        // No wallet/mint/saga: the key is the only credential.
        Some(brain) if brain.backend == BrainBackendKind::RoutstrKey => {
            let treasury_remaining = peek_treasury_remaining(&config).await?;
            let brain_backend = build_routstr_key_brain(brain, treasury_remaining).await?;
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
    boot_and_observe_with_rail(config, rail).await
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
) -> anyhow::Result<Arc<dyn Actuator>> {
    // S3d FROST-TENANT BRANCH: when a per-agent keystore dir is configured, the agent's voice is
    // its SOVEREIGN 2-of-3 quorum (Q SIGNS EVERYTHING), NOT a node-local key. Load the
    // `QuorumSigner` from the provisioned keystore and build a FROST-mode actuator, so
    // `publish_note` signs via the PERSISTENT Q (the keystore's Q across restarts), the aggregate
    // is published as a pre-signed event. A FROST tenant has no node-local signing key, so
    // `key_path` is intentionally NOT consulted on this branch.
    // Build the base actuator (its PUBLISH voice): a FROST quorum (Q signs) OR a single local key.
    let mut actuator = if let Some(keystore_dir) = social.frost_keystore_dir.as_deref() {
        use anyhow::Context as _;
        let quorum = crate::keyset_provisioning::load_quorum_signer_at(keystore_dir)
            .with_context(|| {
                format!(
                    "load per-agent FROST quorum signer from keystore {} (S3d)",
                    keystore_dir.display()
                )
            })?;
        NostrActuator::connect_frost(Arc::new(quorum), &social.relays, social.cost_sats).await?
    } else {
        // SINGLE-KEY PATH (byte-identical, G-CLEAN): the node identity keyfile is pinned to the
        // node identity by run_agent (so a note is signed by the agent's own npub). A missing pin
        // is a boot-wiring bug: fail loud, not a silent throwaway key (which would publish under an
        // unfollowable ephemeral identity).
        let key_path = social.key_path.clone().ok_or_else(|| {
            anyhow::anyhow!("SocialConfig.key_path must be pinned to the node identity (boot-wiring bug)")
        })?;
        let identity = NodeIdentity::load_or_create(&key_path)?;
        NostrActuator::connect(identity.keys().clone(), &social.relays, social.cost_sats).await?
    };

    // Attach the DEDICATED PLAIN DM key (task #12) when the DM path is enabled. The DM reply signs
    // with THIS key, NEVER the publish identity (Q in FROST mode) -- NIP-17 is ECDH, which a
    // threshold key cannot do, and the money plane must never touch the DM plane. A separate keyfile
    // = key isolation (a DM-path compromise costs only DM privacy). This local keyfile is the
    // interim; the fleet's Shamir-shared SK_social (#26) swaps in behind this SAME seam later.
    if let Some(dm_path) = social.dm_key_path.as_deref() {
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
) -> anyhow::Result<Arc<dyn BrainBackend>> {
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
    let nip60_store = if nip60.relays.is_empty() {
        None
    } else {
        let event_key = crate::nip60_key::derive_nip60_event_key(&seed);
        let (relays, write_k, durability) = nip60.resolve(fleet_relay);
        if let Some(warning) = durability.warning() {
            tracing::warn!(nip60_durability = %warning, "NIP-60 wallet backup: sub-quorum durability");
        }
        tracing::info!(n = relays.len(), k = write_k, "NIP-60 wallet backup enabled");
        Some(
            crate::nip60::Nip60Store::connect(
                &event_key,
                &relays,
                Some(write_k),
                brain.effective_mint_allowlist(),
            )
            .await?,
        )
    };

    // The counter floor loaded from the 17375 head (empty with no store / a fresh wallet).
    let initial_counters = match &nip60_store {
        Some(store) => store
            .load_config()
            .await?
            .map(|config| config.counters_by_id())
            .unwrap_or_default(),
        None => std::collections::HashMap::new(),
    };

    // 1) Open the PERSISTENT wallet (file store + persisted seed, §7.1; funded out-of-band, §11),
    //    with the counter mirror SEEDED by the loaded floor — this seed PRECEDES the config publish
    //    in step 4 (the no-regress ordering).
    let (wallet, counter_db) =
        crate::mint_rig::open_persistent_wallet(&brain.mint_url, db_path, seed, initial_counters)
            .await?;
    let ecash = CdkEcash::new(wallet.clone());

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
    if let Some(store) = &nip60_store {
        let _restored = crate::nip60_reconcile::restore_from_relay_backup(
            store.reconcile_on_load().await,
            wallet.as_ref(),
        )
        .await;
    }

    // 4) Solvency check: the wallet must back every sat the counter believes it has. REFUSE
    //    TO BOOT on a shortfall (R2-5) — loud and safe — rather than letting the genome
    //    see repeated UPSTREAM_FAILED when the counter authorizes a think the wallet
    //    can't fund.
    let wallet_balance = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert_wallet_backs_counter(wallet_balance, treasury_remaining)?;

    // 5) Publish the NIP-60 wallet-config (mints + the NUT-13 counters). ORDERED AFTER the
    //    with_counters seed at open (step 1) AND the restore-import (step 3), so the published
    //    counter is >= the loaded floor AND reflects any proofs restored this boot (no regression).
    //    Best-effort: a failure is logged, NOT fatal (the mint remains truth; the next counter
    //    change re-publishes).
    if let Some(store) = &nip60_store {
        if let Err(e) = store
            .publish_wallet_config(counter_db.keyset_counters(), vec![brain.mint_url.clone()])
            .await
        {
            tracing::warn!(
                error = %e,
                "NIP-60 boot config publish failed (advisory; the seeded floor re-publishes on the next change)"
            );
        }
    }

    // 6) Build the brain over the funded wallet, with the configured kill-window.
    let routstr = RoutstrBrain::new(
        brain.node_url.clone(),
        ecash,
        Duration::from_secs(brain.request_timeout_secs),
        Duration::from_secs(brain.recovery_timeout_secs),
    )?;
    let backend: Arc<dyn BrainBackend> = Arc::new(routstr);
    Ok(backend)
}

/// Build the [`RoutstrKeyBrain`] backend for `backend = "routstr_key"` (the prepaid,
/// mint-independent path): load the bearer key from its keyfile, construct the brain, then
/// probe `/v1/balance/info` to BOTH validate the key works AND assert the custodial
/// balance backs the treasury counter (`balance_sats >= treasury_remaining`). REFUSE TO
/// BOOT on an unusable key (a bad/empty/unfunded key surfaces as a balance-probe error) or
/// a shortfall — the same loud-and-safe stance as [`build_routstr_brain`]'s wallet
/// reconcile, mirrored for the custodial balance. No wallet, no mint, no saga recovery:
/// the key is the only credential, and the money already left at funding time.
async fn build_routstr_key_brain(
    brain: &crate::config::BrainConfig,
    treasury_remaining: u64,
) -> anyhow::Result<Arc<dyn BrainBackend>> {
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
    //    the probe fails (don't boot a brain that cannot think) ...
    let balance_sats = key_brain.fetch_balance_sats().await.map_err(|e| {
        anyhow::anyhow!(
            "RoutstrKeyBrain refuses to boot: could not read the prepaid key balance from \
             the node ({e}). The agent cannot think without a working, funded key."
        )
    })?;
    // ... or the custodial balance does not back the counter.
    assert_balance_backs_counter(balance_sats, treasury_remaining)?;

    let backend: Arc<dyn BrainBackend> = Arc::new(key_brain);
    Ok(backend)
}

/// The custodial-balance analog of [`assert_wallet_backs_counter`] for the prepaid
/// API-key path: the node-held balance must back every sat the metabolism counter believes
/// it has (`balance_sats >= treasury_remaining`, `>=` NOT `==`), or the brain REFUSES TO
/// BOOT (loud + safe, the same stance as the Cashu wallet reconcile). There is no fee
/// reserve to subtract here — the per-think charge is debited server-side from this same
/// balance, so the whole balance backs the counter.
pub fn assert_balance_backs_counter(balance_sats: u64, treasury_remaining: u64) -> anyhow::Result<()> {
    if balance_sats < treasury_remaining {
        anyhow::bail!(
            "RoutstrKeyBrain refuses to boot: prepaid key balance ({balance_sats} sat) < \
             treasury_remaining ({treasury_remaining} sat). The custodial balance must back \
             every sat the metabolism counter believes it has. Top up the key (POST \
             /v1/balance/topup) or lower funding.initial_sats before resuming."
        );
    }
    Ok(())
}

/// Load the prepaid bearer key from its keyfile: read the file, trim surrounding
/// whitespace/newline (an editor- or `printf`-written key usually has a trailing newline),
/// and reject an empty result. The key is bearer money — it lives in a FILE (never inline
/// in the logged/serialized config) and is never logged here.
fn load_api_key(path: &str) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read brain.api_key_path {path:?}: {e}"))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        anyhow::bail!(
            "brain.api_key_path {path:?} is empty (expected a prepaid Routstr bearer key, e.g. sk-…)"
        );
    }
    Ok(key)
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
) -> anyhow::Result<(Box<dyn SandboxInstance>, BootOutcome, Treasury, EventStream, ServeGuard)> {
    // The persisted, daemon-owned treasury (D-9). A per-node temp store keeps two
    // node processes distinct on one host. The session is the non-secret snapshot
    // the genome pulls at boot (spec 3.1).
    let treasury_path = treasury_path_for(&config.node_id);
    let treasury = open_treasury_retrying(&treasury_path, config.initial_sats, Duration::from_secs(5)).await?;
    // The NIP-17 DM path (task #12) is enabled when the social config pins a dedicated DM keyfile.
    // It allowlists inbound DIRECT_MESSAGE (the inbound mirror of the nostr.dm_reply outbound token)
    // and attaches an InboundQueue the gateway's PollInbox drains + the run_dm_inbound task feeds.
    let dm_enabled = config.social.as_ref().and_then(|s| s.dm_key_path.as_ref()).is_some();
    let session = Session {
        task_descriptor: config.task.clone(),
        budget_sats: config.budget_sats,
        allowlisted_destinations: config.allow.clone(),
        allowlisted_inbound_kinds: if dm_enabled {
            vec![kirby_proto::InboundKind::DirectMessage]
        } else {
            Vec::new()
        },
    };
    // The meter and the gateway share ONE treasury instance (one authoritative
    // counter, D-9): metered ticks and capability spends debit the same balance.
    let meter_treasury = treasury.clone();
    let mut service = GatewayService::new(treasury, rail, session);
    // Attach the inbound queue (the consumer side) when DMs are enabled; the run_dm_inbound task
    // (spawned after the VM is up) feeds the SAME handle.
    let inbox_queue = if dm_enabled {
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
    // Spawn the NIP-17 DM inbound subscription (task #12) when DMs are enabled: publish the agent's
    // kind:10050 inbox-relay list (best-effort -- a relay hiccup must not fail boot), then run the
    // producer that feeds the gateway's inbox queue. The task is torn down with the run via the
    // oneshot sender held in the ServeGuard (dropping it fires run_dm_inbound's shutdown arm).
    let dm_shutdown = match (inbox_queue, config.social.as_ref()) {
        (Some(queue), Some(social)) => {
            // `dm_enabled` (which gated `inbox_queue` to `Some`) implies `dm_key_path` is `Some`.
            let dm_path =
                social.dm_key_path.as_deref().expect("dm_enabled implies a configured dm_key_path");
            let dm_identity = NodeIdentity::load_or_create(dm_path)?;
            tracing::info!(
                dm_npub = %dm_identity.npub(),
                "NIP-17 DM identity loaded (the npub a client DMs; a plain key, distinct from the publish voice)"
            );
            match crate::nerve::publish_inbox_relay_list(&dm_identity, &social.relays).await {
                Ok(id) => tracing::info!(event_id = %id, "published the kind:10050 DM-inbox relay list"),
                Err(e) => {
                    tracing::warn!(error = %e, "kind:10050 publish failed (continuing; the agent still receives DMs)")
                }
            }
            // CANONICAL SOCIAL profile (P1, #76): publish a kind:0 under the SAME canonical (DM)
            // key so a reader who resolves this agent to its social npub sees a human-legible name.
            // Best-effort (a relay hiccup must not fail boot), alongside the 10050. P1 minimal
            // content: `{"name":"<agent_id>"}` (the agent_id is the run task minus the launcher's
            // `kirby-run-` prefix; fall back to the full task if the prefix is ever absent).
            let profile_name = config.task.strip_prefix("kirby-run-").unwrap_or(&config.task);
            let profile_json =
                serde_json::json!({ "name": profile_name }).to_string();
            match crate::nerve::publish_metadata_profile(&dm_identity, &social.relays, &profile_json)
                .await
            {
                Ok(id) => tracing::info!(event_id = %id, "published the kind:0 canonical social profile"),
                Err(e) => {
                    tracing::warn!(error = %e, "kind:0 profile publish failed (continuing; discovery still works via the 31000 binding)")
                }
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            let relays = social.relays.clone();
            // #103: the DM backfill sweep interval (0 disables it). Copied out before the move.
            let dm_backfill_secs = social.dm_backfill_secs;
            tokio::spawn(async move {
                if let Err(e) =
                    crate::nerve::run_dm_inbound(&dm_identity, &relays, queue, dm_backfill_secs, rx)
                        .await
                {
                    tracing::error!(error = %e, "DM inbound task ended with error");
                }
            });
            Some(tx)
        }
        _ => None,
    };

    // The serve task holds a GatewayService clone (and thus a Treasury Arc, holding
    // the sled lock). It is a listener loop that never returns on its own, so it
    // must be aborted at run-end to release the lock; the ServeGuard does that on
    // drop. The caller binds it for the run's lifetime.
    let serve_guard = ServeGuard {
        handle: serve_task.abort_handle(),
        _dm_shutdown: dm_shutdown,
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
    use super::{assert_balance_backs_counter, load_api_key};

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
        assert!(err.to_string().contains("read brain.api_key_path"), "got: {err}");
    }

    #[test]
    fn balance_backs_counter_ok_at_or_above_and_refuses_below() {
        // The `>=` boundary backs the counter; excess is fine (no fee reserve to subtract).
        assert!(assert_balance_backs_counter(100, 100).is_ok(), "the >= boundary backs the counter");
        assert!(assert_balance_backs_counter(101, 100).is_ok(), "excess balance is fine");
        // Short by a single sat: REFUSE TO BOOT, naming both figures.
        let err = assert_balance_backs_counter(99, 100).expect_err("a shortfall must refuse to boot");
        let msg = err.to_string();
        assert!(msg.contains("refuses to boot"), "got: {msg}");
        assert!(msg.contains("99") && msg.contains("100"), "names both figures: {msg}");
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
