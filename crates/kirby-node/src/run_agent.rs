//! The `kirby run` sovereign-fleet run sequence (the fleet-MVP keystone).
//!
//! This is the WIRING that takes a node from a config file to a live sovereign
//! Kirby agent in the Nostr fleet, composing pieces that already exist:
//!
//! 1. Load + validate the config; resolve the backend by platform (unless pinned).
//! 2. Load-or-mint the node identity ([`crate::nerve::NodeIdentity::load_or_create`]).
//! 3. Resolve the ONE signer (the FROST quorum key Q for a tenant, else the node key) that
//!    signs all the agent's public Nostr output. The agent does NOT beacon node presence —
//!    the persistent node daemon owns the stable node identity + its presence beacon; the
//!    agent surfaces via its 9100 lifecycle + 31000 agent-state instead.
//! 4. bootstrap: fund to born + emit a 9100 `born` ([`crate::nerve::publish_lifecycle`]).
//!    resume: restore the agent from the latest checkpoint (the app-checkpoint
//!    restore path), skipping born.
//! 5. Boot the agent in the sandbox via the selected backend (the existing boot
//!    path; backend chosen by platform).
//! 6. Run the v0 app-checkpoint workload. It submits a portable logical checkpoint
//!    for resume, then stays alive while the host-authoritative meter charges VM
//!    time.
//! 7. Meter; on budget exhaustion HALT (the existing budget-death path) and emit a
//!    9100 `died` with reason `broke`. Clean shutdown emits an honest stop reason.
//!
//! A sovereign node is its OWN single agent: it does NOT join a Raft voter set, so
//! there is no cluster orchestration here. The 9100 lifecycle is the single-agent
//! form (born once on this node's boot, died once on this node's budget-death or
//! clean shutdown), NOT the cluster's at-most-once-across-fleet dedup.
//!
//!
//! The full run boots a real microVM (it needs the host prereqs, the genome image,
//! and a reachable relay), so the keeper drives it on the harness. The gate tests
//! in `tests/run_agent.rs` codify G-run-1..3 and skip cleanly when the
//! `KIRBY_GENOME_IMAGE` env var is unset.

use std::path::PathBuf;
use std::time::Duration;

use crate::checkpoint::{CheckpointArtifact, CheckpointStore, LocalDirCheckpointStore};
use crate::config::{GenomeImage, KirbyConfig, ResolvedBackend, RunMode};
use crate::nerve::{self, NodeIdentity};

/// The default metering tick for the v0 workload's die-when-broke path.
const DEFAULT_METER_TICK: Duration = Duration::from_millis(100);
/// The default safety ceiling for the metered v0 workload (a guard so a run that
/// never exhausts cannot loop forever; the agent normally dies well before this).
const DEFAULT_MAX_RUN: Duration = Duration::from_secs(600);
/// The default vCPU count for the v0 agent.
const DEFAULT_VCPU: u8 = 1;
/// The default memory (MiB) for the v0 agent.
const DEFAULT_MEM_MIB: usize = 128;
/// The default vsock guest CID for the v0 agent.
const DEFAULT_CID: u32 = 3;
/// The default vsock gateway port for the v0 agent.
const DEFAULT_PORT: u32 = 5000;
/// The default boot-hello timeout.
const DEFAULT_HELLO_TIMEOUT: Duration = Duration::from_secs(40);

/// Read a `u32` env var, returning `None` if unset or unparseable. Used ONLY by the
/// fleet supervisor's per-tenant CID/port override (fleet-host S2); absent for every
/// non-fleet run, so the single-agent path keeps its compile-time defaults.
fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok().and_then(|v| v.trim().parse::<u32>().ok())
}

/// The lifecycle event a run emits. `born` on a bootstrap boot, `died` on a
/// budget-death or clean shutdown. Carried in the outcome so a test can assert the
/// run reached the expected lifecycle milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// Emitted once when a bootstrap agent boots (reason "funded").
    Born,
    /// Emitted once when the agent's budget is exhausted or it shuts down.
    Died(DeathReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeathReason {
    /// Budget exhausted.
    Broke,
    /// Clean stop or safety ceiling before budget exhaustion.
    Stopped,
}

impl DeathReason {
    fn as_str(self) -> &'static str {
        match self {
            DeathReason::Broke => "broke",
            DeathReason::Stopped => "stopped",
        }
    }
}

/// The reason a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// The agent's budget was exhausted; the daemon halted it (die-when-broke, the
    /// G-run-2 terminal state).
    BudgetExhausted,
    /// The run was stopped cleanly (a signal, or the safety ceiling) before the
    /// budget ran out.
    Stopped,
    /// A resume run restored the agent and observed the restore (G-run-3); the run
    /// then ends without a metered death (resume is "continue", not "die").
    Resumed,
}

/// The outcome of a `kirby run` sequence (the gate evidence).
#[derive(Debug, Clone)]
pub struct RunAgentOutcome {
    /// The npub the node minted/loaded (its stable fleet identity).
    pub npub: String,
    /// The backend the run resolved to (firecracker or vz).
    pub backend: ResolvedBackend,
    /// The run mode (bootstrap or resume).
    pub mode: RunMode,
    /// Whether the agent reached Running in the sandbox.
    pub reached_running: bool,
    /// Whether a `born` lifecycle event was emitted (bootstrap only).
    pub born_emitted: bool,
    /// Whether a `died` lifecycle event was emitted (budget-death or clean shutdown).
    pub died_emitted: bool,
    /// On a resume run, whether the agent observed the restore checkpoint.
    pub restore_seen: bool,
    /// Total sats metered/burned over the run (the die-when-broke evidence).
    pub burned_sats: u64,
    /// Treasury balance at the end (within one tick of zero on a budget-death).
    pub remaining_sats: u64,
    /// How the run ended.
    pub end_reason: EndReason,
}

impl RunAgentOutcome {
    /// G-run-1 (bootstrap birth): the agent reached Running and a `born` was emitted.
    pub fn bootstrap_birth_passed(&self) -> bool {
        self.mode == RunMode::Bootstrap && self.reached_running && self.born_emitted
    }

    /// G-run-2 (die-when-broke): the run ended in BudgetExhausted with a `died`
    /// emitted and a non-zero metered burn (the meter read real usage).
    pub fn die_when_broke_passed(&self) -> bool {
        self.end_reason == EndReason::BudgetExhausted && self.died_emitted && self.burned_sats > 0
    }

    /// G-run-3 (resume): a resume run restored the agent and observed the restore,
    /// without emitting a born (resume is continue, not birth).
    pub fn resume_passed(&self) -> bool {
        self.mode == RunMode::Resume
            && self.reached_running
            && self.restore_seen
            && !self.born_emitted
    }
}

/// A one-line evidence string for the gate logs.
pub fn evidence_line(o: &RunAgentOutcome) -> String {
    format!(
        "KIRBY-RUN mode={:?} backend={} npub={} reached_running={} born={} died={} restore_seen={} burned_sats={} remaining_sats={} end={:?}",
        o.mode,
        o.backend,
        o.npub,
        o.reached_running,
        o.born_emitted,
        o.died_emitted,
        o.restore_seen,
        o.burned_sats,
        o.remaining_sats,
        o.end_reason,
    )
}

/// Resolved, ready-to-run inputs for one `kirby run` sequence. Built from a
/// [`KirbyConfig`] plus the resolved local genome-image directory.
#[derive(Debug, Clone)]
pub struct RunAgentConfig {
    pub config: KirbyConfig,
    /// The local genome image directory (resolved from `genome_image`; a URL source
    /// is fetched+cached upstream, currently a documented stub).
    pub image_dir: PathBuf,
    /// The metering tick for the v0 workload's die-when-broke path.
    pub meter_tick: Duration,
    /// The safety ceiling so a run cannot loop forever.
    pub max_run: Duration,
    /// vsock guest CID for the agent.
    pub guest_cid: u32,
    /// vsock gateway port for the agent.
    pub gateway_port: u32,
    /// vCPU count for the agent.
    pub vcpu_count: u8,
    /// Memory (MiB) for the agent.
    pub mem_size_mib: usize,
    /// How long to wait for the genome boot hello.
    pub hello_timeout: Duration,
    /// The checkpoint store dir for resume mode (defaults under the treasury dir).
    pub checkpoint_dir: PathBuf,
    /// `--no-frost` escape hatch: when set, the single-node path SKIPS the FROST-by-default
    /// auto-provision and keeps the legacy node-key dev signer. Default `false` (FROST is the
    /// default boot path). The fleet path is unaffected (it always sets `frost_keystore_dir`).
    pub no_frost: bool,
}

impl RunAgentConfig {
    /// Build the run inputs from a validated [`KirbyConfig`], resolving the genome
    /// image to a local directory (a URL source fetch is a documented stub) and
    /// defaulting the sandbox parameters.
    pub fn from_config(config: KirbyConfig) -> anyhow::Result<Self> {
        config.validate()?;
        let image_dir = config.genome_image.resolve_local_dir()?;
        GenomeImage::validate_local_arch(&image_dir, config.resolved_backend())?;
        let checkpoint_dir = config
            .identity
            .treasury_dir()
            .join(format!("checkpoints-{}", config.agent_id));
        // The fleet supervisor (fleet-host S2) launches each tenant as a `kirby agent`
        // CHILD and must hand it the per-tenant CID/port the S0 allocator assigned, so N
        // tenant VMs on one host stay distinct (one genome per CID, sandbox.rs:363-366).
        // It passes them through these env vars; when UNSET (every non-fleet `kirby agent`
        // and `kirby run`) the values are byte-identical to the pre-fleet DEFAULT_CID /
        // DEFAULT_PORT, so the single-agent path is unchanged (G-CLEAN).
        let guest_cid = env_u32("KIRBY_GUEST_CID").unwrap_or(DEFAULT_CID);
        let gateway_port = env_u32("KIRBY_GATEWAY_PORT").unwrap_or(DEFAULT_PORT);
        // The metered-run safety ceiling is configurable (#69) so a long-lived die-when-broke
        // agent isn't force-stopped at the 600s default before its treasury drains. Unset =>
        // DEFAULT_MAX_RUN; a 0 is rejected by `config.validate()` (called above), so this is
        // always > 0.
        let max_run = config
            .max_run_secs
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_MAX_RUN);
        Ok(RunAgentConfig {
            config,
            image_dir,
            meter_tick: DEFAULT_METER_TICK,
            max_run,
            guest_cid,
            gateway_port,
            vcpu_count: DEFAULT_VCPU,
            mem_size_mib: DEFAULT_MEM_MIB,
            hello_timeout: DEFAULT_HELLO_TIMEOUT,
            checkpoint_dir,
            // FROST is the DEFAULT single-node boot path; `--no-frost` flips this true (set by
            // the CLI after construction). Defaulting false here keeps every other constructor +
            // the fleet path on the FROST/sovereign-Q default.
            no_frost: false,
        })
    }

    /// The resolved backend for the current host.
    pub fn backend(&self) -> ResolvedBackend {
        self.config.resolved_backend()
    }
}

/// Load-or-mint this node's identity and resolve the key path from the config.
fn load_identity(config: &KirbyConfig) -> anyhow::Result<NodeIdentity> {
    let treasury_dir = config.identity.treasury_dir();
    std::fs::create_dir_all(&treasury_dir).ok();
    let key_path = NodeIdentity::resolve_key_path(Some(&config.identity.key_path), &treasury_dir);
    NodeIdentity::load_or_create(&key_path)
}

/// S3e: build the agent's [`BeaconSigner`] -- the ONE key all its PUBLIC Nostr output
/// (voice + presence + lifecycle + agent-state) is signed under.
///
/// For a FROST tenant (`identity.frost_keystore_dir` is `Some`, set by the supervisor's
/// `derive_tenant_config`) the beacons sign under the SAME 2-of-3 quorum key Q the
/// actuator's voice uses -- loaded from the SAME per-agent keystore via the SAME
/// `load_quorum_signer_at` the actuator (`build_nostr_actuator`) uses, so there is ONE
/// signer = the agent's identity for ALL its Nostr output ("Q signs everything"). For a
/// bare `kirby run`/`kirby agent` (`None`) it is the node key -- byte-identical to the
/// pre-S3e beacon path (G-CLEAN).
fn beacon_signer(
    config: &KirbyConfig,
    identity: &NodeIdentity,
) -> anyhow::Result<crate::nerve::BeaconSigner> {
    match config.identity.frost_keystore_dir.as_deref() {
        Some(keystore_dir) => {
            use anyhow::Context as _;
            let quorum = crate::keyset_provisioning::load_quorum_signer_at(keystore_dir)
                .with_context(|| {
                    format!(
                        "load per-agent FROST quorum signer from keystore {} for the beacons (S3e)",
                        keystore_dir.display()
                    )
                })?;
            Ok(crate::nerve::BeaconSigner::Frost(std::sync::Arc::new(quorum)))
        }
        None => Ok(crate::nerve::BeaconSigner::NodeKey(identity.clone())),
    }
}

/// Build the periodic 31000 agent-state emitter (the live "Kirby face") for this
/// run, signed by the node identity. The emitter publishes the LIVE treasury +
/// runway on the presence cadence; the `backend` is the resolved sandbox label. Used
/// by the metered (bootstrap) loop; resume emits its state directly (no meter loop).
fn agent_state_emitter(
    signer: crate::nerve::BeaconSigner,
    config: &KirbyConfig,
    backend: ResolvedBackend,
) -> crate::metered_run::AgentStateEmitter {
    crate::metered_run::AgentStateEmitter {
        signer,
        relay_url: config.relay.url.clone(),
        agent_id: config.agent_id.clone(),
        node_id: config.node_id.clone(),
        backend: backend.label().to_string(),
        interval: Duration::from_secs(config.relay.presence_interval_secs),
        budget_sats: config.funding.initial_sats,
    }
}

/// Emit ONE 31000 agent-state event (best-effort; logs on failure, never aborts the
/// run). Used for the milestone states the metered loop does not cover: the terminal
/// "dead" at budget-death, and the running state on the resume path. `runway_secs` is
/// `None` (null) when no burn rate applies (resume; the final dead state).
async fn emit_agent_state(
    signer: &crate::nerve::BeaconSigner,
    config: &KirbyConfig,
    backend: ResolvedBackend,
    treasury_sats: u64,
    runway_secs: Option<u64>,
    lifecycle: &str,
) {
    let content = nerve::AgentStateContent::sovereign(
        &config.agent_id,
        treasury_sats,
        runway_secs,
        lifecycle,
        backend.label(),
    );
    if let Err(e) =
        nerve::publish_agent_state(signer, &config.relay.url, &config.node_id, &content).await
    {
        tracing::warn!(error = %e, lifecycle, "failed to publish 31000 agent-state");
    }
}

/// Emit a single 9100 lifecycle event, logging (not failing the run) on a publish
/// error. Returns whether the publish landed (the gate evidence). Lifecycle is a
/// milestone log, not a correctness dependency, so a transient relay hiccup must
/// not abort an otherwise-live agent.
async fn emit_lifecycle(
    signer: &crate::nerve::BeaconSigner,
    config: &KirbyConfig,
    which: Lifecycle,
    treasury_sats: u64,
) -> bool {
    let (event, reason) = match which {
        Lifecycle::Born => ("born", "funded"),
        Lifecycle::Died(reason) => ("died", reason.as_str()),
    };
    match nerve::publish_lifecycle(
        signer,
        &config.relay.url,
        &config.agent_id,
        &config.node_id,
        event,
        treasury_sats,
        reason,
    )
    .await
    {
        Ok(_id) => true,
        Err(e) => {
            tracing::warn!(error = %e, event, "failed to publish 9100 lifecycle event");
            false
        }
    }
}

/// F3 (the EngramStore self-encrypt key): the diarist's journal is encrypted-to-self on the
/// relays, and that MUST use the NODE IDENTITY key — the ONE key that also roots presence and
/// the nerve (design §2). If `[memory].key_path` is unset, `EngramStore` would default to a
/// `/tmp/kirby-treasury-{node_id}.nostr.key` throwaway, so thoughts written this run become
/// UNRECOVERABLE after a reboot (encrypted under an ephemeral key). Pin it to the resolved
/// identity key by construction (the SAME `resolve_key_path` the run identity uses, so a
/// directory `key_path` resolves to its `node.nostr.key` file), rather than trusting the
/// operator to remember the §9 config pin. An explicit `[memory].key_path` is honored as-is.
/// (Only matters when `[memory].relays` is non-empty, i.e. the real store; the StubMemory
/// ignores the key.)
fn pin_diarist_memory_key(
    memory: &crate::config::MemoryConfig,
    identity: &crate::config::IdentityConfig,
) -> crate::config::MemoryConfig {
    let mut pinned = memory.clone();
    if pinned.key_path.is_none() {
        pinned.key_path = Some(NodeIdentity::resolve_key_path(
            Some(&identity.key_path),
            &identity.treasury_dir(),
        ));
    }
    pinned
}

/// The genome [`BootConfig`] for the v0 agent, shared by bootstrap and resume.
/// `workload` is the real genome workload from `kirby.toml`; `restore_checkpoint`
/// is set for resume.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn agent_boot_config(
    run: &RunAgentConfig,
    restore_checkpoint: Option<CheckpointArtifact>,
) -> anyhow::Result<crate::boot::BootConfig> {
    use crate::boot::{BootConfig, ImagePaths};
    use crate::config::Workload;
    let image = ImagePaths::from_dir(&run.image_dir)?;
    let cfg = &run.config;
    // The allowlist and the brain config are workload-scoped. For the MIND workload
    // the allowlist is EXCLUSIVELY the brain completion sentinel (brain-stub R3): the
    // brain only thinks, so it can reach NOTHING else (a non-Completion act is denied
    // at the gateway allowlist step, fail-closed), and the `[brain]` knobs ride to the
    // genome via the kernel cmdline. Every other workload keeps the test-mint allowlist
    // and carries no brain config (the plain MockRail, no brain cmdline params).
    // The durable-mind-state (memory) workload, like the brain, is workload-scoped: its
    // allowlist is EXCLUSIVELY the memory sentinel (it can reach nothing else), and the
    // `[memory]` knobs ride to the genome via the cmdline. The StubMemory backend is
    // injected onto the gateway in `boot_and_observe` when `boot.memory` is Some.
    // The CAPABLE agent is the both-acts workload: its allowlist holds BOTH sentinels and it
    // carries `brain` + `memory` + `agent`, so `boot_and_observe` builds the Completion
    // rail (CompositeRail, stub or routstr) AND injects the Memory backend on ONE gateway,
    // and all three cmdline blocks travel. This is the only config-wiring the capable agent
    // needs (no new daemon act/rail/metering/nerve code — the two acts compose on orthogonal
    // seams).
    let (allow, brain, memory, agent) = match cfg.workload {
        Workload::Capable => (
            // The capable loop is the both-acts workload PLUS the outward voice: the brain +
            // memory sentinels AND the nostr.publish actuator token in the allowlist, so
            // boot_and_observe builds the Completion rail, injects the Memory backend, AND attaches
            // the NostrActuator on ONE gateway. The actuator/EngramStore keys are pinned to the
            // node identity by construction (capable facts are self-encrypted to the node, and a
            // published note is signed by the node npub: the F3 one-key invariant). Per-kind
            // gating: ONLY because nostr.publish is on this allowlist can a capable agent publish.
            vec![
                crate::rail::BRAIN_COMPLETION_DESTINATION.to_string(),
                crate::rail::MEMORY_DESTINATION.to_string(),
                kirby_proto::ACTUATE_KIND_NOSTR_PUBLISH.to_string(),
                // The PRIVATE voice token (task #12): only because nostr.dm_reply is on this
                // allowlist can a capable agent answer a DM (per-kind gating, like nostr.publish).
                kirby_proto::ACTUATE_KIND_NOSTR_DM_REPLY.to_string(),
            ],
            Some(cfg.brain.clone()),
            Some(pin_diarist_memory_key(&cfg.memory, &cfg.identity)),
            Some(cfg.agent),
        ),
        _ => (vec!["mint.test.local".to_string()], None, None, None),
    };
    // The outward actuator config (the agent's voice): ONLY the capable workload publishes (the
    // first outward voice). Derived, not a toml section (MVP): the node's presence relay + the
    // node identity key (pinned, so a note is signed by the agent's own npub, the F3 one-key
    // invariant) + a small fixed cost. None for every other workload, so they publish nothing.
    let social = match cfg.workload {
        Workload::Capable => Some(crate::config::SocialConfig {
            relays: vec![cfg.relay.url.clone()],
            key_path: Some(NodeIdentity::resolve_key_path(
                Some(&cfg.identity.key_path),
                &cfg.identity.treasury_dir(),
            )),
            cost_sats: crate::config::DEFAULT_POST_COST_SATS,
            // FIX 3 (FROST-tenant wiring): read the provisioned keystore dir from the child's
            // config. A FROST tenant's `derive_tenant_config` (fleet_supervisor.rs) set
            // `identity.frost_keystore_dir = Some(<keystore>)`, which survives serialization into
            // this child's `kirby.toml`; here it flows into `SocialConfig.frost_keystore_dir` so
            // `build_nostr_actuator` takes the FROST branch and the voice signs via the sovereign
            // 2-of-3 Q. A bare `kirby run`/`kirby agent` leaves it `None`, keeping the
            // byte-identical single-key path (G-CLEAN). (Previously hardcoded `None`, so the FROST
            // branch was dead in the real flow — the gap three reviews flagged.)
            frost_keystore_dir: cfg.identity.frost_keystore_dir.clone(),
            // The NIP-17 DM identity (task #12): a DEDICATED plain keyfile beside the treasury,
            // SEPARATE from the voice/memory key and from the FROST Q (NIP-44 is ECDH; a threshold
            // key cannot decrypt). `load_or_create` mints it on first boot. This is the interim;
            // the fleet's Shamir-shared SK_social (#26) swaps in behind `with_dm_keys` later.
            dm_key_path: Some(cfg.identity.treasury_dir().join("social.dm.key")),
        }),
        _ => None,
    };
    Ok(BootConfig {
        image,
        node_id: cfg.node_id.clone(),
        task: format!("kirby-run-{}", cfg.agent_id),
        budget_sats: cfg.funding.initial_sats,
        initial_sats: cfg.funding.initial_sats,
        allow,
        guest_cid: run.guest_cid,
        gateway_port: run.gateway_port,
        vcpu_count: run.vcpu_count,
        mem_size_mib: run.mem_size_mib,
        hello_timeout: run.hello_timeout,
        workload: Some(cfg.workload.genome_workload().to_string()),
        brain,
        memory,
        agent,
        social,
        // Sovereign single-agent v0 is vsock-only (no TAP egress lockdown; that is
        // the C-5 lane). The membrane still holds structurally (no guest network).
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint,
        lease_fence: None,
    })
}

/// Run the full `kirby run` sequence to completion. Returns the gate evidence.
///
/// This boots a REAL microVM (it needs the host prereqs + the genome image + a
/// reachable relay), so it is the keeper-on-harness path; the unit tests cover the
/// config/identity/lifecycle-shape logic, and the integration tests (G-run-1..3)
/// drive this with `KIRBY_GENOME_IMAGE` set.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn run(mut run: RunAgentConfig) -> anyhow::Result<RunAgentOutcome> {
    // 1. Resolve the backend (auto by platform unless pinned; validated already).
    let backend = run.backend();
    let mode = run.config.mode;
    tracing::info!(
        backend = %backend,
        mode = ?mode,
        agent_id = %run.config.agent_id,
        node_id = %run.config.node_id,
        relay = %run.config.relay.url,
        "kirby run: starting the sovereign agent"
    );

    // 2. Load-or-mint the node identity (the stable fleet npub).
    let identity = load_identity(&run.config)?;

    // 2b. FROST-BY-DEFAULT (single-node sovereign quorum): a bare `kirby agent` (no fleet
    // supervisor to provision a keystore) now auto-provisions — or idempotently RELOADS — its
    // OWN per-agent 2-of-3 FROST keystore and signs under its sovereign quorum key Q by DEFAULT.
    // The fleet path already sets `identity.frost_keystore_dir`; only the single-node path
    // arrives here with it `None`. `--no-frost` (run.no_frost) keeps the legacy node-key dev path.
    //
    // SAFETY: `provision_keyset_at` is idempotent + fail-closed (FIX 1): if the identity anchor
    // (`group_pubkeys.json`) already exists it RELOADS the same Q and validates all 3 shares,
    // NEVER regenerating; only a truly-empty keystore generates. So calling it on EVERY boot is
    // safe — first spawn provisions, every later boot reloads the same Q (G-IDENTITY-PERSISTS).
    //
    // The keystore is keyed by the SAME id the single-node treasury is keyed by (`node_id`, via
    // `boot::treasury_path_for`), so `keystore-<node_id>` sits beside `treasury-<node_id>` under
    // the same durable state_root and is stable across reboots. Setting
    // `identity.frost_keystore_dir = Some(..)` then routes both `beacon_signer` and the
    // `SocialConfig` construction down the existing FROST branch unchanged ("Q signs everything").
    if run.config.identity.frost_keystore_dir.is_none() && !run.no_frost {
        use anyhow::Context as _;
        let keystore_dir =
            crate::keyset_provisioning::keystore_dir_for(&run.config.node_id);
        crate::keyset_provisioning::provision_keyset_at(&keystore_dir).with_context(|| {
            format!(
                "FROST-by-default: provision-or-reload the single-node per-agent 2-of-3 keystore \
                 at {} (keyed by node_id {}; idempotent/fail-closed — first spawn mints the \
                 sovereign Q, every later boot reloads the SAME Q). Use --no-frost for the legacy \
                 node-key dev path.",
                keystore_dir.display(),
                run.config.node_id
            )
        })?;
        run.config.identity.frost_keystore_dir = Some(keystore_dir);
    }

    // S3e: resolve the ONE signer for ALL public Nostr output (voice + the three
    // beacons). For a FROST tenant this is the sovereign quorum key Q (the SAME keystore
    // the actuator loads); otherwise the node key. Build it ONCE and thread it through
    // presence + lifecycle + agent-state, so every public event is signed under the
    // agent's identity Q ("Q signs everything").
    let signer = beacon_signer(&run.config, &identity)?;
    // The agent's PUBLIC identity npub: Q for a FROST tenant, the node key otherwise.
    let npub = signer.npub();
    tracing::info!(npub = %npub, frost = matches!(signer, crate::nerve::BeaconSigner::Frost(_)), "agent identity ready (beacons + voice sign under this key)");

    // 3-7. Drive the mode-specific path. The agent does NOT beacon node presence — that is the
    // persistent node daemon's job (it owns the stable node identity + its 10100 beacon). The
    // agent's liveness surfaces via its 31000 agent-state (the live "Kirby face") + its 9100
    // lifecycle, both signed under `signer` (the agent's FROST quorum key Q for a tenant).
    match mode {
        RunMode::Bootstrap => run_bootstrap(&run, &signer, backend, npub.clone()).await,
        RunMode::Resume => run_resume(&run, &signer, backend, npub.clone()).await,
    }
}

/// Bootstrap: fund to born (emit 9100 born), boot the agent, run the v0 metered
/// workload, and HALT on budget exhaustion (emit 9100 died). Reuses the existing
/// budget-death/meter path ([`crate::metered_run::run`]) wholesale.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_bootstrap(
    run: &RunAgentConfig,
    signer: &crate::nerve::BeaconSigner,
    backend: ResolvedBackend,
    npub: String,
) -> anyhow::Result<RunAgentOutcome> {
    use crate::metered_run::{self, MeteredRunConfig, Terminated};

    let funding = run.config.funding.initial_sats;

    // 4. Fund to born: the treasury is seeded at boot with initial_sats; emit the
    // 9100 born (reason "funded") at this funding milestone.
    let born_emitted = emit_lifecycle(signer, &run.config, Lifecycle::Born, funding).await;

    // 5-7. Boot the agent, run the v0 metered workload, persist the checkpoint it
    // submits, and halt on exhaustion. The metered run boots the agent through the
    // selected backend, attaches the host meter, and pauses-then-kills the VM when
    // cumulative burn reaches the budget.
    let boot = agent_boot_config(run, None)?;
    let metered = MeteredRunConfig {
        boot,
        tick: run.meter_tick,
        max_run: run.max_run,
        // Emit the live 31000 "Kirby face" on the presence cadence during the run,
        // sourcing the live treasury + burn rate from the meter loop.
        agent_state: Some(agent_state_emitter(signer.clone(), &run.config, backend)),
        // The synthetic VM-rent rates from the `[meter]` block (F4): the deploy tunes the
        // memory rent down so an always-on diarist VM does not rent-death before it thinks.
        rates: crate::meter::BurnRates::from(&run.config.meter),
    };
    let outcome = metered_run::run(metered).await?;

    if run.config.workload.submits_checkpoint() {
        let checkpoint = outcome.latest_checkpoint.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "bootstrap: workload {} did not submit an app checkpoint; resume would have no state",
                run.config.workload.genome_workload()
            )
        })?;
        let store = LocalDirCheckpointStore::new(run.checkpoint_dir.clone());
        let reference = store.put(&checkpoint)?;
        tracing::info!(
            sha256 = %reference.sha256,
            len = reference.len,
            dir = %run.checkpoint_dir.display(),
            "bootstrap: stored app checkpoint for future resume"
        );
    }

    let end_reason = match outcome.terminated {
        Terminated::BudgetExhausted => EndReason::BudgetExhausted,
        Terminated::Stopped => EndReason::Stopped,
    };

    let (death_reason, lifecycle_treasury) = match end_reason {
        // Report the REAL leftover the meter saw at halt, not a hardcoded 0. For a rent-driven
        // death this is a sub-tick remainder (~0); for the diarist's FLOOR-HALT it is the
        // sub-think leftover — it died because it could no longer GUARANTEE a think, with sats
        // still in the till. Emitting the true balance is honesty for the death-beacon.
        EndReason::BudgetExhausted => (DeathReason::Broke, outcome.remaining_at_halt),
        EndReason::Stopped => (DeathReason::Stopped, outcome.remaining_at_halt),
        EndReason::Resumed => unreachable!("bootstrap cannot end as resumed"),
    };
    let died_emitted = emit_lifecycle(
        signer,
        &run.config,
        Lifecycle::Died(death_reason),
        lifecycle_treasury,
    )
    .await;

    // The terminal 31000 "dead" face, emitted once when the agent is gone (alongside
    // the 9100 died), AFTER which the node stops emitting agent-state. runway is null
    // at death (no forward burn). Both deaths carry the real leftover the meter reported:
    // ~0 for a rent-driven budget-death, the sub-think remainder for the diarist's floor-halt.
    emit_agent_state(
        signer,
        &run.config,
        backend,
        lifecycle_treasury,
        None,
        "dead",
    )
    .await;

    Ok(RunAgentOutcome {
        npub,
        backend,
        mode: RunMode::Bootstrap,
        // The metered run only returns once the VM reached Running and was metered
        // to death (or the ceiling); a boot failure errors out above.
        reached_running: true,
        born_emitted,
        died_emitted,
        restore_seen: false,
        burned_sats: outcome.burned_sats,
        remaining_sats: outcome.remaining_at_halt,
        end_reason,
    })
}

/// Resume: restore the agent from the latest app-checkpoint (rejoin = resume), skip
/// born. Reuses the app-checkpoint restore path (a fresh boot whose gateway hands
/// the genome the stored logical-state blob through `GetSessionContext`).
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_resume(
    run: &RunAgentConfig,
    signer: &crate::nerve::BeaconSigner,
    backend: ResolvedBackend,
    npub: String,
) -> anyhow::Result<RunAgentOutcome> {
    use crate::boot;

    // Load the latest checkpoint from the durable store (the rejoin state). With no
    // stored checkpoint there is nothing to resume from: a clear error, not a born.
    let checkpoint = latest_stored_checkpoint(&run.checkpoint_dir)?;
    tracing::info!(
        sha256 = %checkpoint.reference.sha256,
        len = checkpoint.reference.len,
        "resume: restoring the agent from the latest checkpoint"
    );

    // 5. Boot FRESH with the checkpoint in GetSessionContext (no born; the agent
    // already lived, it is continuing). The genome rehydrates the logical state and
    // reports a restore-seen event.
    let boot = agent_boot_config(run, Some(checkpoint.clone()))?;
    let (vm, outcome, treasury, mut events, _serve_guard) = boot::boot_and_observe(boot).await?;
    if !outcome.reached_running {
        vm.halt().await;
        anyhow::bail!("resume: agent did not reach Running");
    }

    // The agent is alive again: emit a live 31000 "running" face so the UI flips off
    // "pending" on resume too. There is no metered burn loop on the resume path (the
    // run only confirms the restore, then tears down), so runway is null. The
    // treasury balance is the daemon-owned authoritative one (the persisted balance
    // on resume, which the seed does not refill), best-effort.
    let treasury_sats = treasury.remaining().unwrap_or(run.config.funding.initial_sats);
    emit_agent_state(
        signer,
        &run.config,
        backend,
        treasury_sats,
        None,
        "running",
    )
    .await;

    // 6. Observe the restore (the agent saw its prior logical state). v0 then runs
    // present + heartbeat; we confirm the restore, then tear down cleanly.
    let restore_seen = wait_for_restore_seen(&mut events, &checkpoint, run.hello_timeout).await;
    vm.halt().await;

    // The terminal 31000 "dead" face, emitted once as the resume demonstration run
    // tears the agent down (alongside the 9100 died below), after which the node
    // stops emitting agent-state.
    emit_agent_state(signer, &run.config, backend, treasury_sats, None, "dead").await;

    // A resume run ends as "continue", not a budget-death, so it emits died only on
    // its own clean shutdown here (the agent is being torn down at the end of this
    // demonstration run).
    let died_emitted = emit_lifecycle(
        signer,
        &run.config,
        Lifecycle::Died(DeathReason::Stopped),
        run.config.funding.initial_sats,
    )
    .await;

    Ok(RunAgentOutcome {
        npub,
        backend,
        mode: RunMode::Resume,
        reached_running: outcome.reached_running,
        born_emitted: false,
        died_emitted,
        restore_seen,
        burned_sats: 0,
        remaining_sats: run.config.funding.initial_sats,
        end_reason: EndReason::Resumed,
    })
}

/// Read the latest checkpoint from the durable local store. The newest file (by
/// modified time) is the latest logical state. Errors clearly if the store is empty
/// (resume has nothing to restore).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn latest_stored_checkpoint(dir: &std::path::Path) -> anyhow::Result<CheckpointArtifact> {
    let store = LocalDirCheckpointStore::new(dir.to_path_buf());
    let read_dir = std::fs::read_dir(dir).map_err(|e| {
        anyhow::anyhow!(
            "resume: no checkpoint store at {} ({e}); a bootstrap run must have produced a \
             checkpoint first",
            dir.display()
        )
    })?;
    let mut newest: Option<(std::time::SystemTime, kirby_proto::CheckpointRef)> = None;
    for entry in read_dir.flatten() {
        let meta = match entry.metadata() {
            Ok(m) if m.is_file() => m,
            _ => continue,
        };
        let sha = entry.file_name().to_string_lossy().to_string();
        // Files are named by their lowercase-hex SHA-256 (64 chars). Skip anything
        // that is not a checkpoint blob name.
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        let reference = kirby_proto::CheckpointRef {
            sha256: sha,
            len: meta.len(),
        };
        if newest.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
            newest = Some((modified, reference));
        }
    }
    let (_, reference) = newest
        .ok_or_else(|| anyhow::anyhow!("resume: checkpoint store {} is empty", dir.display()))?;
    Ok(store.get(&reference)?)
}

/// Wait for the genome's `checkpoint_restore_seen` event matching the restored
/// checkpoint (the resume proof), up to `timeout`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_for_restore_seen(
    events: &mut crate::boot::EventStream,
    checkpoint: &CheckpointArtifact,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(event)) if event.kind == "checkpoint_restore_seen" => {
                return event
                    .detail
                    .contains(&format!("sha256={}", checkpoint.reference.sha256))
                    && event
                        .detail
                        .contains(&format!("len={}", checkpoint.reference.len));
            }
            Ok(Some(_)) => continue,
            Ok(None) => return false,
            Err(_) => return false,
        }
    }
}

/// On a host where the sandbox backend is not built (neither Linux nor macOS), the
/// full run is unavailable. The config/identity/lifecycle logic still builds and is
/// unit-tested; this is only the microVM-boot entry point.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn run(_run: RunAgentConfig) -> anyhow::Result<RunAgentOutcome> {
    anyhow::bail!("`kirby run` boots a sandbox; supported on Linux/Firecracker and macOS/VZ only")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Backend, FundingConfig, GenomeImage, IdentityConfig, RelayConfig, Workload,
    };
    use std::path::PathBuf;

    fn test_root() -> PathBuf {
        // A per-call unique dir (pid + a process-wide counter) so parallel tests do
        // not race on the shared `img/manifest.env` under one PID-keyed dir.
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("kirby-run-test-{}-{}", std::process::id(), n));
        let image = root.join("img");
        std::fs::create_dir_all(&image).unwrap();
        std::fs::write(
            image.join("manifest.env"),
            format!(
                "arch={}\n",
                match Backend::auto_for_host() {
                    ResolvedBackend::Vz => "aarch64",
                    ResolvedBackend::Firecracker => "x86_64",
                }
            ),
        )
        .unwrap();
        root
    }

    fn test_config(mode: RunMode) -> KirbyConfig {
        let root = test_root();
        KirbyConfig {
            identity: IdentityConfig {
                key_path: root.join("node.key"),
                treasury_dir: Some(root.clone()),
                frost_keystore_dir: None,
            },
            relay: RelayConfig {
                url: "ws://127.0.0.1:7777".to_string(),
                presence_interval_secs: 15,
                presence_stale_after_secs: 45,
            },
            backend: Backend::Auto,
            genome_image: GenomeImage::Path(root.join("img")),
            workload: Workload::AppCheckpoint,
            brain: Default::default(),
            memory: Default::default(),
            agent: Default::default(),
            meter: Default::default(),
            mode,
            funding: FundingConfig {
                initial_sats: 3_000,
            },
            agent_id: "agent-0".to_string(),
            node_id: "node-1".to_string(),
            fleet: Default::default(),
            state_root: None,
            max_run_secs: None,
        }
    }

    /// F3 (the ONE-key invariant): an unset `[memory].key_path` for the diarist is pinned to
    /// the RESOLVED node identity key (so the journal self-encrypts under the same key that
    /// roots presence/nerve, recoverable after a reboot — not an ephemeral /tmp key). An
    /// explicit operator key is honored as-is.
    #[test]
    fn diarist_memory_key_pins_to_identity_when_unset() {
        let identity = crate::config::IdentityConfig {
            key_path: PathBuf::from("/var/lib/kirby/node.nostr.key"),
            treasury_dir: None,
            frost_keystore_dir: None,
        };

        // Unset => pinned to the resolved identity key (the SAME resolution the run uses).
        let mem = crate::config::MemoryConfig::default();
        assert!(mem.key_path.is_none(), "the default memory key is unset");
        let pinned = pin_diarist_memory_key(&mem, &identity);
        let expected =
            NodeIdentity::resolve_key_path(Some(&identity.key_path), &identity.treasury_dir());
        assert_eq!(
            pinned.key_path,
            Some(expected),
            "an unset memory key pins to the resolved node identity key (F3)"
        );

        // Explicit => honored, never overridden (the operator's override wins).
        let explicit = PathBuf::from("/custom/journal.key");
        let mem2 = crate::config::MemoryConfig {
            key_path: Some(explicit.clone()),
            ..crate::config::MemoryConfig::default()
        };
        let pinned2 = pin_diarist_memory_key(&mem2, &identity);
        assert_eq!(pinned2.key_path, Some(explicit), "an explicit memory key is not overridden");
    }

    #[test]
    fn run_config_resolves_local_image_and_defaults() {
        let run = RunAgentConfig::from_config(test_config(RunMode::Bootstrap)).unwrap();
        assert!(run.image_dir.ends_with("img"));
        assert_eq!(run.meter_tick, DEFAULT_METER_TICK);
        assert_eq!(run.vcpu_count, DEFAULT_VCPU);
        // An unset max_run_secs falls back to the 600s default ceiling (#69, byte-identical
        // to the pre-knob behavior).
        assert_eq!(run.max_run, DEFAULT_MAX_RUN);
        // The checkpoint dir lives under the treasury dir, keyed by the agent id.
        assert!(run.checkpoint_dir.ends_with("checkpoints-agent-0"));
    }

    /// #69: an explicit `max_run_secs` overrides the hardcoded 600s ceiling — the knob that
    /// lets a long-lived die-when-broke run reach its treasury-drain instead of being
    /// force-stopped at the default. RED-on-revert: restore the hardcoded
    /// `max_run: DEFAULT_MAX_RUN` in `from_config` and the override is ignored → 1234s !=
    /// 600s and this fails.
    #[test]
    fn max_run_secs_overrides_the_default_ceiling() {
        let mut cfg = test_config(RunMode::Bootstrap);
        cfg.max_run_secs = Some(1234);
        let run = RunAgentConfig::from_config(cfg).unwrap();
        assert_eq!(
            run.max_run,
            Duration::from_secs(1234),
            "an explicit max_run_secs is honored (not the 600s default)"
        );
    }

    /// #69: `max_run_secs = 0` is rejected at load — a zero ceiling would stop a run before
    /// it does any work. `from_config` calls `validate()` first, so the bad config never
    /// builds a run.
    #[test]
    fn max_run_secs_zero_is_rejected() {
        let mut cfg = test_config(RunMode::Bootstrap);
        cfg.max_run_secs = Some(0);
        let err = RunAgentConfig::from_config(cfg).unwrap_err();
        assert!(err.to_string().contains("max_run_secs must be > 0"), "got: {err}");
    }

    #[test]
    fn run_config_url_image_is_a_stub_error() {
        let mut cfg = test_config(RunMode::Bootstrap);
        cfg.genome_image = GenomeImage::Url("https://example.com/img.tar".to_string());
        let err = RunAgentConfig::from_config(cfg).unwrap_err();
        assert!(err.to_string().contains("not yet implemented"));
    }

    #[test]
    fn bootstrap_birth_gate_predicate() {
        let outcome = RunAgentOutcome {
            npub: "npub1test".to_string(),
            backend: ResolvedBackend::Firecracker,
            mode: RunMode::Bootstrap,
            reached_running: true,
            born_emitted: true,
            died_emitted: false,
            restore_seen: false,
            burned_sats: 0,
            remaining_sats: 3_000,
            end_reason: EndReason::Stopped,
        };
        assert!(outcome.bootstrap_birth_passed());
        // No born -> not a birth.
        let no_born = RunAgentOutcome {
            born_emitted: false,
            ..outcome.clone()
        };
        assert!(!no_born.bootstrap_birth_passed());
    }

    #[test]
    fn die_when_broke_gate_predicate() {
        let outcome = RunAgentOutcome {
            npub: "npub1test".to_string(),
            backend: ResolvedBackend::Firecracker,
            mode: RunMode::Bootstrap,
            reached_running: true,
            born_emitted: true,
            died_emitted: true,
            restore_seen: false,
            burned_sats: 2_900,
            remaining_sats: 100,
            end_reason: EndReason::BudgetExhausted,
        };
        assert!(outcome.die_when_broke_passed());
        // Zero burn (meter read nothing) -> fails.
        let zero_burn = RunAgentOutcome {
            burned_sats: 0,
            ..outcome.clone()
        };
        assert!(!zero_burn.die_when_broke_passed());
        // Stopped (not exhausted) -> fails.
        let stopped = RunAgentOutcome {
            end_reason: EndReason::Stopped,
            ..outcome
        };
        assert!(!stopped.die_when_broke_passed());
    }

    #[test]
    fn resume_gate_predicate() {
        let outcome = RunAgentOutcome {
            npub: "npub1test".to_string(),
            backend: ResolvedBackend::Vz,
            mode: RunMode::Resume,
            reached_running: true,
            born_emitted: false,
            died_emitted: true,
            restore_seen: true,
            burned_sats: 0,
            remaining_sats: 3_000,
            end_reason: EndReason::Resumed,
        };
        assert!(outcome.resume_passed());
        // A born on a resume run is wrong (resume is continue, not birth).
        let with_born = RunAgentOutcome {
            born_emitted: true,
            ..outcome.clone()
        };
        assert!(!with_born.resume_passed());
        // No restore seen -> fails.
        let no_restore = RunAgentOutcome {
            restore_seen: false,
            ..outcome
        };
        assert!(!no_restore.resume_passed());
    }
}
