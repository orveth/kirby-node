//! The `kirby run` config file (the fleet-MVP keystone, `kirby.toml`).
//!
//! `kirby run` reads ONE TOML file that takes a node from nothing to a live
//! sovereign Kirby agent in the Nostr fleet. A teammate edits `identity`, `relay`,
//! and `genome_image`, and everything else defaults. This module is pure parsing,
//! validation, and platform-aware backend resolution; the run sequence that drives
//! these settings lives in [`crate::run_agent`].
//!
//! A sovereign node is its OWN single agent. It does NOT join a Raft voter set, so
//! this config has NO cluster fields (no peer set, no lease); the Raft cluster is a
//! separate, internal resilience showcase. v0 "contribute" is a checkpoint-aware
//! metered agent workload plus host-side presence beacons; earn workloads are the
//! layer after this milestone.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The full `kirby run` configuration, parsed from `kirby.toml`.
///
/// Example (top-level scalar keys come BEFORE any `[table]`, per TOML):
/// ```toml
/// backend = "auto"                              # auto | firecracker | vz
/// genome_image = { path = "/var/lib/kirby/genome-image" }
/// workload = "app-checkpoint"                   # v0
/// mode = "bootstrap"                            # bootstrap | resume
///
/// [identity]
/// key_path = "/var/lib/kirby/node.nostr.key"
/// treasury_dir = "/var/lib/kirby/treasury"
///
/// [relay]
/// url = "ws://185.18.221.222:7777"
///
/// [funding]
/// initial_sats = 1000000                        # play-money for the spike
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KirbyConfig {
    /// The node's Nostr identity (mint-if-absent) and treasury directory.
    pub identity: IdentityConfig,
    /// The fleet relay this node beacons and emits lifecycle to.
    pub relay: RelayConfig,
    /// Which sandbox backend to boot the agent in. Defaults to [`Backend::Auto`].
    #[serde(default)]
    pub backend: Backend,
    /// The genome image to boot: a local path, or (TODO) a prebuilt-artifact URL to
    /// fetch and cache. See [`GenomeImage`].
    pub genome_image: GenomeImage,
    /// The v0 workload the agent runs once alive. Defaults to [`Workload::AppCheckpoint`].
    #[serde(default)]
    pub workload: Workload,
    /// The `[brain]` knobs for the capable agent's THINK (the `Completion` rail). Used only
    /// when `workload = "capable"`; defaults so a bare `[brain]` (or none) runs.
    #[serde(default)]
    pub brain: BrainConfig,
    /// The `[memory]` knobs for the capable agent's durable mind-state (the `Memory` ACT).
    /// Used only when `workload = "capable"`; defaults so a bare `[memory]` (or none) runs.
    #[serde(default)]
    pub memory: MemoryConfig,
    /// The `[agent]` knobs for the CAPABLE workload (the agentic kernel). Defaults so a
    /// bare `[agent]` (or none) runs. The agent's inference is configured by `[brain]`
    /// and its store by `[memory]` (it REUSES both verbatim); this block carries only the
    /// agent-specific loop cadence and recall depth (the cmdline still carries them as the
    /// existing `kirby.diarist_*` keys).
    #[serde(default)]
    pub agent: AgentConfig,
    /// The `[meter]` knobs: the synthetic VM-rent burn rates (CPU + memory + egress).
    /// Defaults match [`crate::meter::BurnRates::default`] so existing runs are
    /// unchanged; a deploy LOWERS the memory rate so an always-on VM does not drain its
    /// treasury to a rent-death before it can think/journal (the F4 finding — at the
    /// default 1 sat/MiB-s a small VM dies in ~30-60s purely from rent).
    #[serde(default)]
    pub meter: MeterRatesConfig,
    /// bootstrap (fund to born) or resume (restore from the latest checkpoint).
    /// Defaults to [`RunMode::Bootstrap`].
    #[serde(default)]
    pub mode: RunMode,
    /// Initial treasury funding (play-money for the spike, D-3; real funds gated).
    #[serde(default)]
    pub funding: FundingConfig,
    /// The agent id this node's single agent runs under (the `["a",X]` lifecycle
    /// tag and the metering/treasury label). Defaults to [`default_agent_id`].
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    /// This node's human label (the `["node",X]` lifecycle tag and the presence
    /// beacon's node_id). Defaults to [`default_node_id`].
    #[serde(default = "default_node_id")]
    pub node_id: String,
    /// The OPTIONAL multi-tenant fleet-host block (fleet-host S0). Every field
    /// defaults, so a bare config (or none) leaves a single-agent `kirby run`
    /// byte-identical to its pre-fleet behavior: nothing reads `fleet` unless the
    /// fleet supervisor is explicitly started (a later slice). This block only
    /// carries the allocator base + the per-host tenant ceiling for now.
    #[serde(default)]
    pub fleet: FleetConfig,
    /// The DURABLE state root that ALL persistent key + treasury material lives under
    /// (FIX 2). The per-agent FROST keystore and the treasury counter resolve under this
    /// root, so a custody key / balance survives a reboot. When unset (the default) the
    /// node resolves a durable default at startup (`$XDG_DATA_HOME/kirby`, else
    /// `$HOME/.local/share/kirby`); it is NEVER `std::env::temp_dir()` (a tmpfs `/tmp`
    /// would silently destroy a sovereign key on reboot — the pre-fix bug). Set this to
    /// pin an explicit durable directory (or, in tests, an explicit temp dir). At config
    /// load this is exported to `$KIRBY_STATE_ROOT` for the free-function path helpers
    /// ([`crate::boot::treasury_path_for`], [`crate::keyset_provisioning::keystore_dir_for`]).
    #[serde(default)]
    pub state_root: Option<PathBuf>,
}

/// The `[fleet]` config block (fleet-host S0): the knobs the fleet supervisor uses
/// to host many tenants on one node. Every field defaults so an absent `[fleet]`
/// block (the single-agent default) is unchanged. This block is INERT until a fleet
/// supervisor is explicitly started; `Command::Run` / `kirby run` never read it.
///
/// `base_cid` seeds the monotonic CID allocator (one genome per guest CID,
/// sandbox.rs:363-366); it starts HIGH because vsock reserves CIDs 0, 1, and 2.
/// `max_tenants` is the per-host tenant ceiling (you cannot host what the host
/// cannot fit): the allocator hands out at most this many distinct slots and then
/// rejects on exhaustion. `gateway_port_base` seeds the per-tenant gateway vsock
/// port (sandbox.rs:367-368), allocated alongside the CID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetConfig {
    /// The base guest CID the allocator counts up from (tenant n gets `base_cid + n`).
    /// Defaults to [`default_fleet_base_cid`] (well above the vsock-reserved 0..=2).
    #[serde(default = "default_fleet_base_cid")]
    pub base_cid: u32,
    /// The per-host tenant ceiling. The allocator hands out at most this many slots
    /// and rejects further requests as exhausted. Defaults to [`default_fleet_max_tenants`].
    #[serde(default = "default_fleet_max_tenants")]
    pub max_tenants: u32,
    /// The base gateway vsock port the allocator counts up from (tenant n gets
    /// `gateway_port_base + n`). Defaults to [`default_fleet_gateway_port_base`].
    #[serde(default = "default_fleet_gateway_port_base")]
    pub gateway_port_base: u32,
    /// The STATIC, operator-declared tenants the fleet supervisor launches (fleet-host
    /// S2). Empty by default, so an absent `[fleet]` block (or one with no `[[fleet.tenants]]`
    /// entries) hosts NO tenants and a bare `kirby run` is unchanged. The spawn control-plane
    /// (a later slice) adds tenants dynamically; S2 launches exactly this static set. Each
    /// entry names one agent the supervisor allocates resources for, grants a per-agent lease
    /// to, and launches as a child process.
    #[serde(default)]
    pub tenants: Vec<TenantConfig>,
    /// The DYNAMIC spawn control-plane (#11): subscribe to signed `KIND_KIRBY_SPAWN_REQUEST`
    /// events on the relay and spawn agents on demand (create an agent on this node from a
    /// signed event, no node access required). A `kirby fleet` node ALWAYS runs this (there is
    /// no enable flag); it is gated by the `operators` / `image_allowlist` fields below, not
    /// toggled off. See [`SpawnConfig`].
    #[serde(default)]
    pub spawn: SpawnConfig,
}

/// The spawn control-plane config (#11). A `kirby fleet` node ALWAYS listens for
/// `KIND_KIRBY_SPAWN_REQUEST` (31003) on the relay and, for each verified+authorized request,
/// spawns the agent on this node — listen-and-spawn is the node's purpose, not an opt-in
/// (gudnuf). The authz fields are the MVP gate (pops deferred): `operators` is an OPTIONAL
/// operator-pubkey allowlist bounded by a per-requester rate limit, and `image_allowlist`
/// names the pre-staged images this node will run (default-deny an unknown image).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnConfig {
    /// The operator pubkeys (hex) allowed to spawn (the three-keys operator key). A signature
    /// proves WHICH key signed, not WHETHER it may spawn. NON-EMPTY => enforce (only a listed
    /// key may spawn). EMPTY => OPEN — accept any signer (the MVP DoS vector gudnuf explicitly
    /// accepts until pops is the gate; the node logs a loud warning on startup). pops (pay-to-
    /// spawn) replaces this allowlist as the real anti-spam gate, dropping into the same seam.
    #[serde(default)]
    pub operators: Vec<String>,
    /// The pre-staged genome `image_ref`s this node will run (default-deny an unknown image).
    /// Empty means no image is accepted (spawn nothing) — set it to the node's staged image.
    #[serde(default)]
    pub image_allowlist: Vec<String>,
    /// Max spawns accepted per `rate_window_secs` per operator (anti-spam). Default 10.
    #[serde(default = "default_spawn_max_per_window")]
    pub max_per_window: u32,
    /// The rate-limit window in seconds. Default 60.
    #[serde(default = "default_spawn_rate_window_secs")]
    pub rate_window_secs: u64,
    /// The maximum declarative seed amount (sats) a single spawn may fund an agent with, so one
    /// request cannot over-seed the host. Default 1_000_000 (the play-money tenant default).
    #[serde(default = "default_spawn_max_seed_sats")]
    pub max_seed_sats: u64,
    /// AUTOMATIC FAILOVER (G-4): how often, in seconds, this node scans the leases it observes for
    /// a peer that went dark and (if it holds the agent's quorum + passes the same admission gates
    /// a fresh spawn passes) takes the agent over. Default 5s (≈ the reap cadence). A scan is
    /// cheap (a snapshot + a pure decision); the claim/launch side-effect is the only slow part and
    /// is kept off the select! loop's critical path. The observer-blind fail-safe inside
    /// `detect_takeovers` is what keeps a node whose own relay link dropped from mass-false-taking-
    /// over the fleet — see `crate::failover_detect`.
    #[serde(default = "default_spawn_failover_scan_secs")]
    pub failover_scan_secs: u64,
    /// AUTOMATIC FAILOVER (G-4): how long, in seconds, a peer's lease must be CONTINUOUSLY stale
    /// (past the TTL) before this node takes it over — the grace window layered ON TOP of the lease
    /// TTL, absorbing a brief relay blip / a holder slow to heartbeat without prematurely double-
    /// spawning. Default = the lease TTL (`crate::relay_lease::LEASE_TTL_SECS`, 30s) per
    /// `failover_detect::DEFAULT_TAKEOVER_GRACE_SECS`; this is a MONEY dial (it trades change-
    /// stranding against the false-failover rate), so the operator can retune it.
    #[serde(default = "default_spawn_takeover_grace_secs")]
    pub takeover_grace_secs: u64,
    /// AUTOMATIC FAILOVER (G-4): the UPPER age bound, in seconds, past which a stale lease is treated
    /// as an ANCIENT GHOST and IGNORED rather than failed over (ghost accumulation, failover bug 2).
    /// A genuine failover acts shortly after a lease goes stale (≈ TTL + grace, ~60s); a lease stale
    /// for many multiples of the TTL is a dead past-run agent's retained lease (e.g. on a relay that
    /// does not honor the NIP-40 `expiration` the lease carries). Default = 300s
    /// (`failover_detect::DEFAULT_FAILOVER_MAX_LEASE_AGE_SECS`, 10× the TTL): well above a real
    /// takeover's ~60s, far below the hours an accumulated ghost reaches. Raise it toward `u64::MAX`
    /// to disable the client-side backstop and rely solely on relay NIP-40 expiry.
    #[serde(default = "default_spawn_failover_max_lease_age_secs")]
    pub failover_max_lease_age_secs: u64,
}

/// Default anti-spam rate: 10 spawns per operator per window.
pub const fn default_spawn_max_per_window() -> u32 {
    10
}
/// Default rate-limit window: 60 seconds.
pub const fn default_spawn_rate_window_secs() -> u64 {
    60
}
/// Default per-spawn seed ceiling (the play-money tenant default).
pub const fn default_spawn_max_seed_sats() -> u64 {
    1_000_000
}
/// Default failover scan cadence: 5 seconds (≈ the reap cadence; a scan is a cheap snapshot + a
/// pure decision, so a tight cadence is fine).
pub const fn default_spawn_failover_scan_secs() -> u64 {
    5
}
/// Default takeover grace window: the lease TTL (kept in sync with
/// `crate::relay_lease::LEASE_TTL_SECS` = 30 and `failover_detect::DEFAULT_TAKEOVER_GRACE_SECS`).
/// Defined here as a literal so the config block stays self-contained (config must not depend on
/// relay internals); a `debug_assert` in the failover wiring guards the two from drifting.
pub const fn default_spawn_takeover_grace_secs() -> u64 {
    30
}
/// Default failover age bound: 300s (kept in sync with
/// `crate::failover_detect::DEFAULT_FAILOVER_MAX_LEASE_AGE_SECS` = 10 × `LEASE_TTL_SECS`). A literal
/// here so the config block stays self-contained (config must not depend on failover internals); a
/// `debug_assert` in the failover wiring guards the two from drifting.
pub const fn default_spawn_failover_max_lease_age_secs() -> u64 {
    300
}

impl Default for SpawnConfig {
    fn default() -> Self {
        SpawnConfig {
            operators: Vec::new(),
            image_allowlist: Vec::new(),
            max_per_window: default_spawn_max_per_window(),
            rate_window_secs: default_spawn_rate_window_secs(),
            max_seed_sats: default_spawn_max_seed_sats(),
            failover_scan_secs: default_spawn_failover_scan_secs(),
            takeover_grace_secs: default_spawn_takeover_grace_secs(),
            failover_max_lease_age_secs: default_spawn_failover_max_lease_age_secs(),
        }
    }
}

/// One operator-declared fleet tenant (fleet-host S2): the static description of an agent
/// the supervisor hosts. The supervisor turns this into an allocated resource triple (CID
/// /instance_id/gateway_port), a per-agent treasury path, a per-agent lease grant, and a
/// child `kirby agent` process. Only `agent_id` is required; the rest reuse the host's
/// defaults so a teammate declares a tenant with one line. The `agent_id` is validated
/// (non-empty, charset, length) the same as the top-level `agent_id`, because it feeds
/// filesystem treasury paths + host interface names.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantConfig {
    /// The agent id for this tenant (the lease-map key, the treasury-path label, the
    /// instance-id stem `kirby-<agent_id>`). Must be unique within the fleet and valid as
    /// a path/interface component (validated like the top-level `agent_id`).
    pub agent_id: String,
    /// Initial treasury balance for this tenant (play-money), seeded on first creation of
    /// the tenant's per-agent treasury. Defaults to [`default_tenant_initial_sats`].
    #[serde(default = "default_tenant_initial_sats")]
    pub initial_sats: u64,
}

/// The default per-tenant initial treasury balance (play-money for the fleet MVP).
pub const fn default_tenant_initial_sats() -> u64 {
    1_000_000
}

/// Validate an agent/node/tenant label that feeds filesystem treasury paths, host
/// instance ids (jail / cgroup / TAP names), and lease-map keys: non-empty,
/// length-capped, no path separators or traversal, identifier charset only. The empty
/// string is reserved as the single-agent lease slot sentinel (lease::DEFAULT_AGENT)
/// and must never be a configured label. Shared by the top-level `agent_id`/`node_id` and
/// every fleet tenant id (the new fleet entry points re-port this guard rather than
/// trusting the input; Codex deep, S1 review).
pub fn validate_agent_label(label: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} must be non-empty");
    }
    if value.len() > 64 {
        anyhow::bail!("{label} must be <= 64 chars (got {})", value.len());
    }
    if value == "." || value == ".." {
        anyhow::bail!("{label} must not be a path component (got {value:?})");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!(
            "{label} must contain only ASCII alphanumerics, '-', '_', or '.' (got {value:?}); it feeds filesystem paths and host interface names"
        );
    }
    Ok(())
}

/// The base guest CID the fleet allocator counts up from. 100 is well above the
/// vsock-reserved range (CIDs 0, 1, 2 are reserved by the vsock layer), so the first
/// tenant's CID never collides with a reserved value.
pub const fn default_fleet_base_cid() -> u32 {
    100
}
/// The default per-host tenant ceiling.
pub const fn default_fleet_max_tenants() -> u32 {
    16
}
/// The base gateway vsock port the fleet allocator counts up from.
pub const fn default_fleet_gateway_port_base() -> u32 {
    9000
}

impl Default for FleetConfig {
    fn default() -> Self {
        FleetConfig {
            base_cid: default_fleet_base_cid(),
            max_tenants: default_fleet_max_tenants(),
            gateway_port_base: default_fleet_gateway_port_base(),
            tenants: Vec::new(),
            spawn: SpawnConfig::default(),
        }
    }
}

/// The node identity (Nostr key) and treasury directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityConfig {
    /// Path to this node's BIP340 Nostr secret key. Minted (0600) on first run,
    /// loaded thereafter, so the node keeps the SAME npub across restarts. May be a
    /// file path or a directory (the key lands at `<dir>/node.nostr.key`).
    pub key_path: PathBuf,
    /// The persisted treasury directory (the daemon-owned, unforgeable balance,
    /// D-9). Defaults to the parent dir of `key_path` when omitted.
    #[serde(default)]
    pub treasury_dir: Option<PathBuf>,
    /// FIX 3 (FROST-tenant wiring): the per-agent FROST keystore dir the fleet supervisor
    /// provisioned for THIS tenant. When `Some`, the agent's outward voice signs via its
    /// sovereign 2-of-3 Q loaded from this keystore (the FROST branch in
    /// [`crate::boot::build_nostr_actuator`]); when `None` (the single-agent default) the
    /// voice signs with the node key (the byte-identical single-key path, G-CLEAN). The
    /// supervisor sets this in `derive_tenant_config` so it survives serialization into the
    /// child's `kirby.toml`; `agent_boot_config` reads it to build the child's `SocialConfig`.
    #[serde(default)]
    pub frost_keystore_dir: Option<PathBuf>,
}

impl IdentityConfig {
    /// The treasury directory, defaulting to the key path's parent when unset.
    pub fn treasury_dir(&self) -> PathBuf {
        self.treasury_dir.clone().unwrap_or_else(|| {
            self.key_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        })
    }
}

/// The fleet relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayConfig {
    /// The relay websocket URL (e.g. `ws://185.18.221.222:7777`).
    pub url: String,
    /// Seconds between presence beacon re-publishes (replaceable; bumps last-seen).
    #[serde(default = "default_presence_interval")]
    pub presence_interval_secs: u64,
    /// Seconds after which a peer with no fresh beacon is presumed dead (STALE).
    #[serde(default = "default_presence_stale_after")]
    pub presence_stale_after_secs: u64,
}

/// The sandbox backend selector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Resolve by platform: VZ on macOS-aarch64, Firecracker on Linux.
    #[default]
    Auto,
    /// Force the Firecracker backend (Linux).
    Firecracker,
    /// Force the Apple Virtualization (VZ) backend (macOS).
    Vz,
}

/// The concrete backend this build resolved [`Backend`] to. A `kirby run` validates
/// that the resolved backend matches the host before booting; the resolution itself
/// is a runtime `cfg!` check, never a compile-time hard fail on the non-native
/// backend (so the crate builds on both platforms with one code path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedBackend {
    Firecracker,
    Vz,
}

impl ResolvedBackend {
    pub fn label(self) -> &'static str {
        match self {
            ResolvedBackend::Firecracker => "firecracker",
            ResolvedBackend::Vz => "vz",
        }
    }
}

impl std::fmt::Display for ResolvedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl Backend {
    /// The auto-resolution rule: VZ on macOS-aarch64, Firecracker otherwise. Uses
    /// `cfg!` so it is a plain runtime branch (the non-native backend is never a
    /// compile-time hard fail; the boot path's own `cfg`-gated backend slots in).
    pub fn auto_for_host() -> ResolvedBackend {
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            ResolvedBackend::Vz
        } else {
            ResolvedBackend::Firecracker
        }
    }

    /// Resolve this selector to a concrete backend for the current host. `Auto`
    /// follows [`Backend::auto_for_host`]; a pinned backend is taken verbatim (the
    /// run-time host-match check is [`KirbyConfig::validate`]).
    pub fn resolve(self) -> ResolvedBackend {
        match self {
            Backend::Auto => Backend::auto_for_host(),
            Backend::Firecracker => ResolvedBackend::Firecracker,
            Backend::Vz => ResolvedBackend::Vz,
        }
    }
}

/// The genome image source: a local path, or a prebuilt-artifact URL to fetch+cache.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenomeImage {
    /// A local image directory (the `nix build .#genome-image` output, holding
    /// `vmlinux` and `rootfs.squashfs`).
    Path(PathBuf),
    /// A prebuilt-artifact URL to fetch and cache locally. The fetch is a TODO stub
    /// for this milestone (the published-artifact piece lands alongside the prebuilt
    /// arm64 image); for now a `url`-form config errors with a clear message.
    Url(String),
}

impl GenomeImage {
    /// Resolve to a local image directory, fetching+caching a URL source if needed.
    /// The URL fetch is NOT YET implemented (a documented stub for this milestone),
    /// so a `url` source returns a clear error pointing at the local-path form.
    pub fn resolve_local_dir(&self) -> anyhow::Result<PathBuf> {
        match self {
            GenomeImage::Path(p) => Ok(p.clone()),
            GenomeImage::Url(u) => anyhow::bail!(
                "genome_image URL fetch is not yet implemented (TODO: fetch+cache the \
                 prebuilt artifact). Set genome_image to a local path = {{ path = \
                 \"/path/to/genome-image\" }} for now (url was {u:?})"
            ),
        }
    }
}

/// The v0 workload. The daemon publishes presence for the node; the genome workload
/// is the checkpoint-aware agent loop so bootstrap can seed resume.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Workload {
    /// The v0 agent workload: submit a portable app checkpoint, then stay alive
    /// while the host meter charges VM time. The daemon beacons fleet presence.
    #[serde(rename = "app-checkpoint")]
    #[default]
    AppCheckpoint,
    /// The CAPABLE workload (the agentic kernel): the genome runs ONE PLAN, ACT, VERIFY, learn
    /// iteration per tick. It PLANs one decision (`Completion` via the brain, the life-gating
    /// act), ACTs on its OWN durable memory (at most one `Memory` SET into `mem/capable/...`,
    /// guarded genome-side), VERIFYs the effect (a free `Memory` GET read-back), and learns
    /// (feeds the verified verdict into the next plan). The new muscle is SELF-CORRECTION: a
    /// read-back mismatch is detected and surfaced for a retry. It is a genome-side COMPOSITION
    /// of the two acts the daemon already performs and REUSES the `[brain]`, `[memory]`, and
    /// `[agent]` config (same allowlist, same cmdline knobs), so it needs no new daemon act,
    /// rail, metering, crypto, or nerve code. THINK is the life-gating act (earn-or-die, F4).
    Capable,
}

impl Workload {
    /// Kernel command-line workload understood by the current genome.
    pub fn genome_workload(self) -> &'static str {
        match self {
            Workload::AppCheckpoint => "app-checkpoint",
            Workload::Capable => "capable",
        }
    }

    /// Whether bootstrap must persist a genome-submitted checkpoint for resume.
    pub fn submits_checkpoint(self) -> bool {
        match self {
            Workload::AppCheckpoint => true,
            // The capable loop persists its monotonic `seq` through the SAME wseq-keyed Memory
            // write (the ACT), so a restart continues PAST the last entry rather than re-issuing
            // an old write/think key (F1/F2).
            Workload::Capable => true,
        }
    }
}

/// Which inference backend serves a `Completion` (brain-routstr §6). `stub` is the
/// deterministic, no-network, no-money backend (the default, so an existing `[brain]`
/// block with no `backend` key still parses); `routstr` is the REAL Cashu-paid Routstr
/// inference backend (the daemon mints an X-Cashu token from the treasury wallet, POSTs
/// the completion, redeems the change). Swapping is a config change, not a genome/proto
/// change (done-criteria #6).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BrainBackendKind {
    /// The deterministic stub backend (default; backcompat).
    #[default]
    Stub,
    /// The real Cashu-paid Routstr inference backend (per-request X-Cashu ecash; the
    /// sovereign, self-custody default — the agent pays its own way per think).
    Routstr,
    /// The prepaid Routstr API-KEY backend: a balance-bearing bearer key (funded by
    /// paying a Lightning invoice to the node, `purpose: "create"`) on the
    /// `Authorization` header. MINT-INDEPENDENT (no Cashu mint involved), so it serves
    /// real thinks even when the treasury wallet's mint is unreachable — the resilience
    /// fallback that coexists with `Routstr` (the sovereign default). The balance is a
    /// CUSTODIAL one the node holds; the daemon holds only the bearer key. A `refund`
    /// drains the residual back to ecash, so custody is recoverable, not one-way.
    RoutstrKey,
}

/// The `[brain]` config block (brain-stub): the knobs for the MIND workload. The
/// genome reads `model`, `max_cost_sats`, and `tick_secs` from the kernel command
/// line (the daemon writes them when the workload is `brain`); the daemon's
/// `StubBrain` reads `bytes_per_sat` (its simulated-cost knob). Every field has a
/// sane default so a bare `[brain]` (or none, when `workload = "capable"`) runs.
///
/// This is the swap-ready surface: `RoutstrBrain` reads the SAME `model` and per-call
/// `max_cost_sats`, so pointing the agent at a real model is a config change, not a
/// genome or proto change (done-criteria #6). The `routstr`-only fields (`node_url`,
/// `mint_url`, `wallet_db_path`, the timeouts, `fee_headroom_sats`) all default so a
/// `stub` `[brain]` block is unaffected; they are required (validated) iff
/// `backend = "routstr"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrainConfig {
    /// The model the brain "thinks" with. Passed through to the `Completion` act
    /// (cosmetic for the stub, which ignores it; load-bearing for `RoutstrBrain`).
    #[serde(default = "default_brain_model")]
    pub model: String,
    /// The per-call budget cap (sats) the genome sets as `budget_sats` on every
    /// Completion (R4). The gate enforces `actual <= max_cost_sats <= treasury`.
    #[serde(default = "default_brain_max_cost_sats")]
    pub max_cost_sats: u64,
    /// Seconds the brain sleeps between thoughts (the think cadence).
    #[serde(default = "default_brain_tick_secs")]
    pub tick_secs: u64,
    /// The `StubBrain` cost knob: simulated cost is `ceil(total_bytes / bytes_per_sat)`
    /// sats per think (min 1), so the treasury visibly drains. Daemon-side only.
    /// STUB-ONLY (ignored by the routstr backend, which pays the real metered price).
    #[serde(default = "default_brain_bytes_per_sat")]
    pub bytes_per_sat: u64,
    /// Which backend serves a Completion: `stub` (default) or `routstr` (brain-routstr).
    #[serde(default)]
    pub backend: BrainBackendKind,
    /// (routstr) The pinned Routstr node base URL the `brain.completion` sentinel maps
    /// to (e.g. `https://api.routstr.com`). Required iff `backend = "routstr"`.
    #[serde(default)]
    pub node_url: String,
    /// (routstr) The mint the treasury wallet holds + spends ecash at (the node's
    /// accepted mint, §11). Required iff `backend = "routstr"`.
    #[serde(default)]
    pub mint_url: String,
    /// (routstr) The PERSISTENT wallet store path (cdk-sqlite file). The wallet SEED
    /// persists alongside it (§7.1); funded proofs survive a reboot. Required iff
    /// `backend = "routstr"`.
    #[serde(default)]
    pub wallet_db_path: String,
    /// (routstr_key) PATH to the prepaid bearer API key (the file holds the raw
    /// `sk-…` secret on a single line). The key is bearer money on the `Authorization`
    /// header, so it is treated like the dm key / wallet seed: it lives in a FILE, NEVER
    /// inline in the config (which is logged/serialized), and is loaded at boot. Required
    /// iff `backend = "routstr_key"`; ignored by every other backend.
    #[serde(default)]
    pub api_key_path: String,
    /// (routstr_key) The `max_tokens` the prepaid-key brain sends on every completion. It
    /// bounds the reply length AND — critically — Routstr's up-front per-request
    /// RESERVATION: without it the node reserves the model's MAX completion cost per
    /// in-flight request, and the agent's concurrent brain/memory/diarist loops stack
    /// those reservations until the key's "available" is exhausted (a 402 on a funded
    /// key). Default 1024 (ample for the capable loop's small JSON action replies; ~133
    /// msat reserve on granite vs ~17 000). The Cashu backend ignores it (its X-Cashu
    /// token amount already bounds the reserve). Must be > 0 iff `backend = "routstr_key"`.
    #[serde(default = "default_brain_max_tokens")]
    pub max_tokens: u32,
    /// (routstr) The MAIN-path kill-window seconds (mint -> POST -> parse -> redeem
    /// change). The meter cannot preempt an in-flight call, so this deadline IS the
    /// kill bound for thinking (§5).
    #[serde(default = "default_brain_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// (routstr) The CLEANUP (revoke/refund) budget seconds, separate from the main
    /// path so recovery is never cancelled by the main deadline (§5 R2-2).
    #[serde(default = "default_brain_recovery_timeout_secs")]
    pub recovery_timeout_secs: u64,
    /// (routstr) The wallet fee reserve: the live wallet is funded
    /// `funding.initial_sats + fee_headroom_sats` to cover mint/swap fees, so the boot
    /// invariant `wallet_balance >= treasury_remaining` holds with headroom (§4/§7.2
    /// R2-3). Measured in Layer B (fake mint) / Layer C (real mint).
    #[serde(default = "default_brain_fee_headroom_sats")]
    pub fee_headroom_sats: u64,
}

fn default_brain_model() -> String {
    "anthropic/claude-sonnet-4.6".to_string()
}
fn default_brain_max_cost_sats() -> u64 {
    64
}
fn default_brain_tick_secs() -> u64 {
    5
}
fn default_brain_bytes_per_sat() -> u64 {
    16
}
fn default_brain_request_timeout_secs() -> u64 {
    30
}
fn default_brain_recovery_timeout_secs() -> u64 {
    10
}
fn default_brain_fee_headroom_sats() -> u64 {
    8
}
fn default_brain_max_tokens() -> u32 {
    1024
}

impl Default for BrainConfig {
    fn default() -> Self {
        BrainConfig {
            model: default_brain_model(),
            max_cost_sats: default_brain_max_cost_sats(),
            tick_secs: default_brain_tick_secs(),
            bytes_per_sat: default_brain_bytes_per_sat(),
            backend: BrainBackendKind::default(),
            node_url: String::new(),
            mint_url: String::new(),
            wallet_db_path: String::new(),
            api_key_path: String::new(),
            max_tokens: default_brain_max_tokens(),
            request_timeout_secs: default_brain_request_timeout_secs(),
            recovery_timeout_secs: default_brain_recovery_timeout_secs(),
            fee_headroom_sats: default_brain_fee_headroom_sats(),
        }
    }
}

/// The `[memory]` config block (memory-stub, Chunk-1): the knobs for the durable-mind-
/// state workload. The genome reads `max_cost_sats` (its per-WRITE ceiling) and
/// `tick_secs` (the op cadence) from the kernel command line (the daemon writes them when
/// the workload is `capable`); the daemon's `StubMemory` reads `bytes_per_sat` (its
/// host-computed storage-cost knob). Every field has a sane default so a bare `[memory]`
/// (or none, when `workload = "capable"`) runs.
///
/// This is the swap-ready surface: the real `EngramStore` (Chunk-2) reads the SAME
/// `max_cost_sats` ceiling, so pointing the agent at the real nerve-backed store is a
/// config + backend change, not a genome or proto change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryConfig {
    /// The per-WRITE budget CEILING (sats) the genome sets as `max_cost_sats` on every
    /// SET/RM (design doc 12 G2). The gate refuses a write whose HOST-computed cost
    /// exceeds it (it is NEVER clamped down). Reads ignore it (reads are free).
    #[serde(default = "default_memory_max_cost_sats")]
    pub max_cost_sats: u64,
    /// Seconds the memory loop sleeps between scripted ops (the op cadence).
    #[serde(default = "default_memory_tick_secs")]
    pub tick_secs: u64,
    /// The storage-cost knob: a write costs `ceil((slug+value bytes) / bytes_per_sat)`
    /// sats per copy (min 1), so the treasury visibly drains per write. `StubMemory`
    /// charges that; `EngramStore` multiplies it by the copy-count N. Daemon-side only.
    #[serde(default = "default_memory_bytes_per_sat")]
    pub bytes_per_sat: u64,
    /// The nerve relay set the real `EngramStore` (Chunk-2) writes engrams to (the
    /// NIP-65 write relays). EMPTY (the default) selects the in-memory `StubMemory`
    /// (test/dev); a NON-EMPTY set selects the real `EngramStore`. The set SIZE is the
    /// copy-count N -- the write-time durability (design doc §16: no ongoing rent, so
    /// durability is purely how many relays a write reaches). The first of the two
    /// collapsed economics dials gudnuf tunes post-merge (own relay + >=1 durable).
    #[serde(default)]
    pub relays: Vec<String>,
    /// The K-of-N ack threshold a WRITE must reach to count as stored (the second
    /// economics dial, design doc §16). `None` => strict majority `floor(N/2)+1`.
    #[serde(default)]
    pub write_k: Option<usize>,
    /// The identity keyfile the `EngramStore` signs + self-encrypts engrams with -- the
    /// ONE key that roots identity/presence/memory (design doc §2; the same BIP340 key
    /// the nerve uses). `None` => a default beside the treasury. Ignored when `relays`
    /// is empty (`StubMemory` needs no key).
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

fn default_memory_max_cost_sats() -> u64 {
    64
}
fn default_memory_tick_secs() -> u64 {
    5
}
fn default_memory_bytes_per_sat() -> u64 {
    16
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            max_cost_sats: default_memory_max_cost_sats(),
            tick_secs: default_memory_tick_secs(),
            bytes_per_sat: default_memory_bytes_per_sat(),
            // Empty relay set => the in-memory StubMemory (test/dev default); the real
            // EngramStore is opt-in via a configured `[memory].relays`.
            relays: Vec::new(),
            write_k: None,
            key_path: None,
        }
    }
}

/// The internally-derived config for the OUTWARD actuator (the agent's voice), built at boot for
/// the `capable` workload. NOT a `kirby.toml` section in the MVP: the relay is the node's presence
/// relay and the cost is a small default, so it is derived from `[relay]` + `[identity]` rather
/// than configured (a dedicated `[social]` block is post-MVP). It selects + configures the
/// `NostrActuator` (boot.rs) and is `None` for every workload with no outward act, so a
/// Brain/Memory/Diarist gateway performs ZERO publishes.
#[derive(Debug, Clone)]
pub struct SocialConfig {
    /// The relay(s) the daemon publishes the agent's notes to (defaults to the node's presence
    /// relay, so a note is followable alongside its presence beacon).
    pub relays: Vec<String>,
    /// The node identity keyfile to SIGN published notes with -- the ONE key rooting
    /// identity/presence/memory (design §2). Pinned to the node identity by construction
    /// (run_agent), so a note is signed by the agent's own npub; an explicit path is honored.
    pub key_path: Option<PathBuf>,
    /// The fixed host cost (sats) of one publish: metered like a memory write so the agent cannot
    /// spam the world for free (min 1).
    pub cost_sats: u64,
    /// S3d: when `Some`, this agent is a FROST tenant -- its voice is signed by the per-agent
    /// 2-of-3 quorum loaded from this keystore dir (its sovereign Q), NOT a node-local single key.
    /// `build_nostr_actuator` loads a `QuorumSigner` from here and builds a FROST-mode actuator
    /// (`NostrActuator::connect_frost`). `None` (the default for every non-fleet `kirby run`) keeps
    /// the byte-identical single-key path: `key_path` is loaded and the actuator signs with it.
    /// A FROST tenant has NO node-local signing key, so `key_path` is unused when this is `Some`.
    pub frost_keystore_dir: Option<PathBuf>,
    /// The DEDICATED PLAIN DM identity keyfile (task #12). `Some` enables the NIP-17 DM path: the
    /// daemon loads this plain keypair to NIP-44-DECRYPT inbound gift wraps, sign reply wraps, and
    /// publish the kind:10050 inbox-relay list, and `build_nostr_actuator` attaches it via
    /// `with_dm_keys`. It is SEPARATE from `key_path` (the voice/memory key) AND from the FROST Q:
    /// NIP-17 is ECDH, which a threshold key cannot do, so the DM identity MUST be a plain key the
    /// daemon holds in full (DM npub != Q in FROST mode, by design). This local keyfile is the
    /// interim; the fleet's Shamir-shared `SK_social` (reconstruct-on-lease, task #26) swaps in
    /// behind the SAME `with_dm_keys` seam later. `None` disables the DM path (no queue, no 10050).
    pub dm_key_path: Option<PathBuf>,
}

/// The default fixed publish cost (sats): small + non-zero so a post costs the agent (no free
/// spam) without dominating the think cost (which stays the death gate). Tunable post-MVP.
pub const DEFAULT_POST_COST_SATS: u64 = 1;

/// The `[agent]` config block (the capable agent): the ONLY agent-loop-specific knobs.
/// The agent's inference backend is `[brain]` (model, backend, max_cost_sats, the routstr
/// fields) and its store is `[memory]` (relays, key_path, max_cost_sats) — reused verbatim,
/// no nesting — so the daemon passes `cfg.brain`/`cfg.memory` straight through. This block
/// adds only the loop cadence and the recall depth. Every field defaults so a bare `[agent]`
/// (or none) runs. (The cmdline still carries these as the existing `kirby.diarist_*` keys.)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    /// Seconds the agent sleeps between ticks (the ONE plan+act cadence). This OVERRIDES
    /// `[brain].tick_secs` / `[memory].tick_secs` for the capable workload (which become
    /// unused — the agent has a single loop, not two).
    #[serde(default = "default_agent_tick_secs")]
    pub tick_secs: u64,
    /// How many recent facts to RECALL (a free `Memory` LS + GET) into each plan prompt, so
    /// the agent reasons WITH its recent past, not blind.
    #[serde(default = "default_agent_recall_count")]
    pub recall_count: usize,
}

fn default_agent_tick_secs() -> u64 {
    60
}
fn default_agent_recall_count() -> usize {
    5
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            tick_secs: default_agent_tick_secs(),
            recall_count: default_agent_recall_count(),
        }
    }
}

/// The `[meter]` config block: the synthetic VM-rent burn rates, exposed so a deploy can
/// tune always-on rent. `kirby run` ALWAYS meters CPU + memory time against the treasury
/// (the unforgeable host bill), so even a SLEEPING VM drains continuously. At the default
/// `mem_sats_per_mib_sec = 1` a 128 MiB VM burns ~128 sat/s, draining a ~3900-sat wallet
/// to a rent-death in ~30s — before it journals anything, via the meter halt rather than
/// the think-denial (the F4 finding). Lowering the memory rate (and shrinking the VM)
/// makes think + write the dominant, visible drains, so the agent lives a satisfying
/// while and the proximate death is the unaffordable THINK (the intended demo). Each
/// field mirrors [`crate::meter::BurnRates`]; the defaults are byte-identical to its
/// `Default`, so an absent `[meter]` block leaves every existing run unchanged.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeterRatesConfig {
    /// Sats per microsecond of cgroup CPU time, as a fraction num/den (default 1/1000 =
    /// 1 sat per millisecond of CPU).
    #[serde(default = "default_cpu_sats_per_usec_num")]
    pub cpu_sats_per_usec_num: u64,
    #[serde(default = "default_cpu_sats_per_usec_den")]
    pub cpu_sats_per_usec_den: u64,
    /// Sats per MiB of resident memory per second (default 1). THE diarist rent dial —
    /// lower this (e.g. to a small fraction via the num/den CPU pattern is not needed
    /// here; the integer is the knob) so a sleeping VM does not rent-death.
    #[serde(default = "default_mem_sats_per_mib_sec")]
    pub mem_sats_per_mib_sec: u64,
    /// Sats per egress byte, as a fraction num/den (default 1/1 = 1 sat per byte). Under
    /// the default-deny lockdown egress is ~0, so this is normally a no-op.
    #[serde(default = "default_egress_sats_per_byte_num")]
    pub egress_sats_per_byte_num: u64,
    #[serde(default = "default_egress_sats_per_byte_den")]
    pub egress_sats_per_byte_den: u64,
}

fn default_cpu_sats_per_usec_num() -> u64 {
    1
}
fn default_cpu_sats_per_usec_den() -> u64 {
    1000
}
fn default_mem_sats_per_mib_sec() -> u64 {
    1
}
fn default_egress_sats_per_byte_num() -> u64 {
    1
}
fn default_egress_sats_per_byte_den() -> u64 {
    1
}

impl Default for MeterRatesConfig {
    fn default() -> Self {
        MeterRatesConfig {
            cpu_sats_per_usec_num: default_cpu_sats_per_usec_num(),
            cpu_sats_per_usec_den: default_cpu_sats_per_usec_den(),
            mem_sats_per_mib_sec: default_mem_sats_per_mib_sec(),
            egress_sats_per_byte_num: default_egress_sats_per_byte_num(),
            egress_sats_per_byte_den: default_egress_sats_per_byte_den(),
        }
    }
}

/// bootstrap (fund to born) or resume (restore from the latest checkpoint).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    /// Fund to born: seed the treasury, boot the agent, emit a 9100 `born`.
    #[default]
    Bootstrap,
    /// Restore the agent from the latest app-checkpoint (rejoin = resume), skipping
    /// born (the agent already lived; it is continuing, not being born).
    Resume,
}

/// Initial treasury funding (play-money for the spike).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FundingConfig {
    /// Initial treasury balance in sats, seeded only on first creation (a resume
    /// from an existing store keeps its persisted balance, D-9). Play-money per the
    /// spike discipline (D-3); real funds are gated.
    pub initial_sats: u64,
}

impl Default for FundingConfig {
    fn default() -> Self {
        FundingConfig {
            initial_sats: default_initial_sats(),
        }
    }
}

fn default_agent_id() -> String {
    "agent-0".to_string()
}
fn default_node_id() -> String {
    "node-1".to_string()
}
fn default_presence_interval() -> u64 {
    15
}
fn default_presence_stale_after() -> u64 {
    45
}
fn default_initial_sats() -> u64 {
    1_000_000
}

/// Whether `url` is safe to send the X-Cashu bearer token to in the clear: `https://`
/// (TLS protects the bearer regardless of host) always, or plain `http://` ONLY when the
/// TRUE host is loopback (a same-host node / tests). Any other plain-http host is refused
/// (brain-routstr §3 MED-3).
///
/// The host is taken from a real URL parse, NOT a substring split. A naive
/// `split([':', '/'])` reads `http://localhost:pw@evil.com/` as host "localhost" and would
/// leak the cleartext bearer to evil.com (the userinfo bypass: `localhost:pw@` is userinfo,
/// the real host is `evil.com`). `Url::host_str()` resolves the authority correctly
/// (userinfo stripped, true host = evil.com → refused) and also accepts IPv6 loopback
/// (`http://[::1]:7780`), which the old split mishandled. Unparseable or non-http(s) URLs
/// fail closed (refused).
fn is_https_or_localhost(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false; // unparseable → fail closed
    };
    match parsed.scheme() {
        // TLS protects the bearer in transit regardless of host.
        "https" => true,
        // Plain http: the bearer crosses the wire in cleartext, so ONLY a real loopback
        // host is acceptable. Strip any IPv6 brackets so "[::1]" and "::1" both match.
        "http" => {
            let host = parsed.host_str().unwrap_or("");
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            matches!(host, "localhost" | "127.0.0.1" | "::1")
        }
        _ => false,
    }
}

impl KirbyConfig {
    /// Parse a [`KirbyConfig`] from a TOML string.
    pub fn from_toml_str(s: &str) -> anyhow::Result<Self> {
        let cfg: KirbyConfig =
            toml::from_str(s).map_err(|e| anyhow::anyhow!("parse kirby config TOML: {e}"))?;
        cfg.validate()?;
        cfg.apply_state_root_env();
        Ok(cfg)
    }

    /// Export `[node].state_root` (FIX 2) to `$KIRBY_STATE_ROOT` so the free-function path
    /// helpers ([`crate::boot::treasury_path_for`], [`crate::keyset_provisioning::keystore_dir_for`])
    /// resolve under the configured DURABLE root. A no-op when unset (the helpers then resolve
    /// their own durable default — never temp_dir). Idempotent; safe to call on every config load.
    pub fn apply_state_root_env(&self) {
        if let Some(root) = &self.state_root {
            // SAFETY: process-wide config bootstrap, before any agent/treasury work; single-threaded
            // at this point in the run/agent/fleet entry paths.
            unsafe {
                std::env::set_var(crate::boot::STATE_ROOT_ENV, root);
            }
        }
    }

    /// Load a [`KirbyConfig`] from a TOML file path.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read kirby config {}: {e}", path.display()))?;
        Self::from_toml_str(&text)
    }

    /// Validate the config against the current host: the relay URL is a websocket,
    /// the funding is non-zero, and a PINNED backend matches this platform (a `vz`
    /// config on Linux, or a `firecracker` config on macOS, is refused early with a
    /// clear message rather than failing deep in the boot path). `auto` always
    /// passes (it resolves to the native backend).
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(self.relay.url.starts_with("ws://") || self.relay.url.starts_with("wss://")) {
            anyhow::bail!(
                "relay.url must be a websocket URL (ws:// or wss://), got {:?}",
                self.relay.url
            );
        }
        // Tenant identifiers feed filesystem treasury paths (treasury_path_for_agent),
        // host instance ids (jail / cgroup / TAP names), and lease-map keys, so they must
        // be safe: non-empty, length-capped, and restricted to an identifier charset with
        // no path separators or traversal. The empty string is reserved as the
        // single-agent lease slot sentinel (lease::DEFAULT_AGENT) and must never be a
        // configured tenant id. An unvalidated id is a path-traversal / collision footgun
        // at the new fleet entry points (Codex deep, S1 review).
        for (label, value) in [("agent_id", &self.agent_id), ("node_id", &self.node_id)] {
            validate_agent_label(label, value)?;
        }
        // Fleet tenants (fleet-host S2) feed the SAME treasury paths / instance ids / lease
        // keys as the top-level agent_id, so each tenant id is validated identically, AND
        // the tenant set must be free of duplicate agent_ids (a dup would collide on the
        // treasury path, the lease entry, and the allocator's at-most-once-per-agent slot).
        // The static set must also fit the per-host ceiling (max_tenants); a config that
        // declares more tenants than the host can fit is rejected at load, not discovered
        // mid-launch. These are new fleet entry points, so they re-port the agent_id guards
        // rather than trusting the input (feedback_new_entry_point_needs_input_guards).
        let mut seen = std::collections::BTreeSet::new();
        for tenant in &self.fleet.tenants {
            validate_agent_label("fleet.tenants.agent_id", &tenant.agent_id)?;
            if !seen.insert(tenant.agent_id.as_str()) {
                anyhow::bail!(
                    "fleet.tenants has a duplicate agent_id {:?}; each tenant must be unique (it keys the treasury path, the lease entry, and the resource slot)",
                    tenant.agent_id
                );
            }
            if tenant.initial_sats == 0 {
                anyhow::bail!(
                    "fleet.tenants[{:?}].initial_sats must be > 0 (a tenant needs a budget to live)",
                    tenant.agent_id
                );
            }
        }
        if (self.fleet.tenants.len() as u64) > self.fleet.max_tenants as u64 {
            anyhow::bail!(
                "fleet.tenants declares {} tenants but fleet.max_tenants is {} (the per-host ceiling); raise max_tenants or remove tenants",
                self.fleet.tenants.len(),
                self.fleet.max_tenants
            );
        }
        // FAILOVER WINDOW SANITY (G-4): a takeover fires only on a lease that is BOTH stale past
        // `takeover_grace_secs + LEASE_TTL_SECS` AND younger than `failover_max_lease_age_secs` (the
        // ancient-ghost upper bound). If the upper bound is at or below the lower bound, the
        // actionable window is EMPTY and AUTOMATIC FAILOVER SILENTLY NEVER FIRES — a dead peer's
        // agent is never recovered, with no error to tell the operator. Reject such a config at load
        // so a money-critical safety feature cannot be turned off by a typo'd dial. (The control
        // plane always runs, so this is always validated.)
        let failover_window_floor =
            self.fleet.spawn.takeover_grace_secs + crate::relay_lease::LEASE_TTL_SECS;
        if self.fleet.spawn.failover_max_lease_age_secs <= failover_window_floor {
            anyhow::bail!(
                "fleet.spawn.failover_max_lease_age_secs ({}) must be GREATER than takeover_grace_secs ({}) + the lease TTL ({}) = {}; \
                 otherwise the takeover window is empty and automatic failover silently never fires (raise failover_max_lease_age_secs)",
                self.fleet.spawn.failover_max_lease_age_secs,
                self.fleet.spawn.takeover_grace_secs,
                crate::relay_lease::LEASE_TTL_SECS,
                failover_window_floor,
            );
        }
        if self.funding.initial_sats == 0 {
            anyhow::bail!("funding.initial_sats must be > 0 (the agent needs a budget to live)");
        }
        // The capable agent must be able to afford at least one think, or it dies before it
        // thinks once: a zero per-call cap is always DENIED_OVER_BUDGET, and a cap above the
        // treasury is always DENIED_INSUFFICIENT_TREASURY (D-20). Its THINK is a `Completion`
        // (the life-gating act) and it reuses `[brain]`, so a capable agent that cannot afford
        // its first think is a config error caught at load, not a born-then-instantly-dead VM.
        if matches!(self.workload, Workload::Capable) {
            if self.brain.max_cost_sats == 0 {
                anyhow::bail!(
                    "brain.max_cost_sats must be > 0 (a zero per-call cap means every think is DENIED_OVER_BUDGET)"
                );
            }
            if self.brain.max_cost_sats > self.funding.initial_sats {
                anyhow::bail!(
                    "brain.max_cost_sats ({}) must be <= funding.initial_sats ({}) so the agent can afford its first think",
                    self.brain.max_cost_sats,
                    self.funding.initial_sats
                );
            }
            // The real (routstr) backend needs a node, a mint, and a persistent wallet
            // store: a `routstr` brain missing any of these is a config error caught at
            // load, not a runtime panic deep in boot (brain-routstr §6). The stub backend
            // ignores all of these.
            if self.brain.backend == BrainBackendKind::Routstr {
                if self.brain.node_url.trim().is_empty() {
                    anyhow::bail!(
                        "brain.node_url must be set when brain.backend = \"routstr\" (the pinned Routstr node)"
                    );
                }
                if self.brain.mint_url.trim().is_empty() {
                    anyhow::bail!(
                        "brain.mint_url must be set when brain.backend = \"routstr\" (the treasury wallet's mint)"
                    );
                }
                if self.brain.wallet_db_path.trim().is_empty() {
                    anyhow::bail!(
                        "brain.wallet_db_path must be set when brain.backend = \"routstr\" (the persistent wallet store)"
                    );
                }
                // The X-Cashu token is bearer money: a non-local node MUST be https, or
                // the bearer ecash would cross plaintext http (brain-routstr §3 MED-3).
                if !is_https_or_localhost(&self.brain.node_url) {
                    anyhow::bail!(
                        "brain.node_url must be https:// for a non-localhost node (the X-Cashu bearer token must not cross plaintext http); got {:?}",
                        self.brain.node_url
                    );
                }
            }
            // The prepaid API-KEY backend needs a node and a keyfile, but NO mint/wallet
            // (the balance is custodial on the node, not local ecash). The bearer key is
            // money on the `Authorization` header, so the same https-or-loopback rule
            // applies: a non-local node MUST be https or the key would cross plaintext http.
            else if self.brain.backend == BrainBackendKind::RoutstrKey {
                if self.brain.node_url.trim().is_empty() {
                    anyhow::bail!(
                        "brain.node_url must be set when brain.backend = \"routstr_key\" (the pinned Routstr node)"
                    );
                }
                if self.brain.api_key_path.trim().is_empty() {
                    anyhow::bail!(
                        "brain.api_key_path must be set when brain.backend = \"routstr_key\" (the file holding the prepaid bearer key)"
                    );
                }
                if self.brain.max_tokens == 0 {
                    anyhow::bail!(
                        "brain.max_tokens must be > 0 when brain.backend = \"routstr_key\" (it bounds the reply AND Routstr's per-request reservation; 0 would reserve the model max and 402 under load)"
                    );
                }
                if !is_https_or_localhost(&self.brain.node_url) {
                    anyhow::bail!(
                        "brain.node_url must be https:// for a non-localhost node (the prepaid bearer key must not cross plaintext http); got {:?}",
                        self.brain.node_url
                    );
                }
            }
        }
        // The capable agent must be able to afford at least one WRITE (its ACT), or it can
        // recall (reads are free) but never FORM a memory: a zero per-write ceiling is always
        // DENIED_OVER_BUDGET. It ACTs through the Memory write and reuses `[memory]`, so it
        // gets the SAME guard (F5: the capable validation must apply BOTH the brain and the
        // memory ceiling check, else every WRITE is DENIED_OVER_BUDGET — a config error).
        // (No <= initial_sats check: reads stay free, so a broke agent still lives; the write
        // cost is host-computed per op.)
        if matches!(self.workload, Workload::Capable) && self.memory.max_cost_sats == 0 {
            anyhow::bail!(
                "memory.max_cost_sats must be > 0 (a zero per-write ceiling means every write is DENIED_OVER_BUDGET)"
            );
        }
        // The capable demo is BOOTSTRAP-ONLY. A capable `resume` currently boots, confirms the
        // checkpoint restore, and tears down WITHOUT entering the metered loop (run_agent::
        // run_resume) — so the FLOOR-HALT death mechanism, which is armed only inside the
        // metered run, never arms. A resumed capable agent would be a deathless agent: it could
        // fall below the per-think floor (unable to afford another thought) yet never be halted.
        // Reject the combination cleanly at load rather than silently running that zombie.
        // Metered-resume for the capable agent is a follow-up; lifting this guard is part of it.
        if matches!(self.workload, Workload::Capable) && self.mode == RunMode::Resume {
            anyhow::bail!(
                "workload = \"{}\" does not support mode = \"resume\" yet: the capable demo is \
                 bootstrap-only (a resumed agent skips the metered loop and never arms its \
                 floor-halt death mechanism). Use mode = \"bootstrap\"; metered-resume is a \
                 follow-up.",
                self.workload.genome_workload()
            );
        }
        // A pinned backend must match the host. `auto` resolves to the native one,
        // so it never trips this. This is a RUNTIME check (cfg!), not a compile-time
        // hard fail, so the crate builds on both platforms.
        let native = Backend::auto_for_host();
        match self.backend {
            Backend::Auto => {}
            Backend::Firecracker if native != ResolvedBackend::Firecracker => anyhow::bail!(
                "backend = \"firecracker\" but this host resolves to {native}; \
                 the Firecracker backend needs Linux (use backend = \"auto\" or run on Linux)"
            ),
            Backend::Vz if native != ResolvedBackend::Vz => anyhow::bail!(
                "backend = \"vz\" but this host resolves to {native}; \
                 the VZ backend needs macOS-aarch64 (use backend = \"auto\" or run on a Mac)"
            ),
            _ => {}
        }
        Ok(())
    }

    /// The concrete backend this config resolves to for the current host.
    pub fn resolved_backend(&self) -> ResolvedBackend {
        self.backend.resolve()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenomeArch {
    Aarch64,
    X86_64,
}

impl GenomeArch {
    fn label(self) -> &'static str {
        match self {
            GenomeArch::Aarch64 => "aarch64",
            GenomeArch::X86_64 => "x86_64",
        }
    }
}

impl ResolvedBackend {
    fn expected_genome_arch(self) -> GenomeArch {
        match self {
            ResolvedBackend::Vz => GenomeArch::Aarch64,
            ResolvedBackend::Firecracker => GenomeArch::X86_64,
        }
    }
}

impl GenomeImage {
    /// Validate a resolved local image directory against the selected backend before
    /// boot. Prefer `manifest.env` because the prebuilt artifact publishes it; fall
    /// back to the ELF machine field in `vmlinux` for local/dev images.
    pub fn validate_local_arch(image_dir: &Path, backend: ResolvedBackend) -> anyhow::Result<()> {
        let actual = read_genome_arch(image_dir)?;
        let expected = backend.expected_genome_arch();
        if actual != expected {
            anyhow::bail!(
                "genome_image arch mismatch for backend {backend}: expected {}, got {} at {}",
                expected.label(),
                actual.label(),
                image_dir.display()
            );
        }
        Ok(())
    }
}

fn read_genome_arch(image_dir: &Path) -> anyhow::Result<GenomeArch> {
    let manifest = image_dir.join("manifest.env");
    if manifest.exists() {
        let text = std::fs::read_to_string(&manifest)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", manifest.display()))?;
        if let Some(arch) = text.lines().find_map(|line| line.strip_prefix("arch=")) {
            return parse_arch_label(arch.trim()).ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported genome image arch {arch:?} in {}",
                    manifest.display()
                )
            });
        }
    }

    let kernel = image_dir.join("vmlinux");
    let bytes =
        std::fs::read(&kernel).map_err(|e| anyhow::anyhow!("read {}: {e}", kernel.display()))?;
    read_elf_arch(&bytes).ok_or_else(|| {
        anyhow::anyhow!(
            "could not determine genome image arch from {}",
            kernel.display()
        )
    })
}

fn parse_arch_label(label: &str) -> Option<GenomeArch> {
    match label {
        "aarch64" | "arm64" => Some(GenomeArch::Aarch64),
        "x86_64" | "amd64" => Some(GenomeArch::X86_64),
        _ => None,
    }
}

fn read_elf_arch(bytes: &[u8]) -> Option<GenomeArch> {
    if bytes.get(0..4) != Some(b"\x7fELF") || bytes.get(5) != Some(&1) {
        return None;
    }
    let machine = u16::from_le_bytes([*bytes.get(18)?, *bytes.get(19)?]);
    match machine {
        62 => Some(GenomeArch::X86_64),
        183 => Some(GenomeArch::Aarch64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal well-formed config (the three fields a teammate edits + defaults).
    /// Top-level scalar keys (genome_image) come BEFORE any `[table]` header, per
    /// TOML rules (a key after `[relay]` would belong to that table).
    fn minimal_toml() -> &'static str {
        r#"
            genome_image = { path = "/tmp/kirby/genome-image" }

            [identity]
            key_path = "/tmp/kirby/node.nostr.key"

            [relay]
            url = "ws://127.0.0.1:7777"
        "#
    }

    #[test]
    fn minimal_config_parses_with_defaults() {
        let cfg = KirbyConfig::from_toml_str(minimal_toml()).unwrap();
        assert_eq!(
            cfg.identity.key_path,
            PathBuf::from("/tmp/kirby/node.nostr.key")
        );
        // treasury_dir defaults to the key path's parent.
        assert_eq!(cfg.identity.treasury_dir(), PathBuf::from("/tmp/kirby"));
        assert_eq!(cfg.relay.url, "ws://127.0.0.1:7777");
        assert_eq!(cfg.relay.presence_interval_secs, 15);
        assert_eq!(cfg.relay.presence_stale_after_secs, 45);
        assert_eq!(cfg.backend, Backend::Auto);
        assert_eq!(cfg.workload, Workload::AppCheckpoint);
        assert_eq!(cfg.mode, RunMode::Bootstrap);
        assert_eq!(cfg.funding.initial_sats, 1_000_000);
        assert_eq!(cfg.agent_id, "agent-0");
        assert_eq!(cfg.node_id, "node-1");
        assert_eq!(
            cfg.genome_image,
            GenomeImage::Path(PathBuf::from("/tmp/kirby/genome-image"))
        );
    }

    #[test]
    fn validate_rejects_unsafe_tenant_ids() {
        // A valid minimal config validates.
        let ok = KirbyConfig::from_toml_str(minimal_toml()).unwrap();
        assert!(ok.validate().is_ok(), "the minimal config must validate");

        // A path-traversal agent_id is rejected (it feeds treasury_path_for_agent +
        // instance ids + lease keys).
        let mut traversal = KirbyConfig::from_toml_str(minimal_toml()).unwrap();
        traversal.agent_id = "../evil".to_string();
        assert!(traversal.validate().is_err(), "a path-traversal agent_id must be rejected");

        // The reserved empty sentinel (DEFAULT_AGENT) is not a valid configured id.
        let mut empty = KirbyConfig::from_toml_str(minimal_toml()).unwrap();
        empty.agent_id = String::new();
        assert!(empty.validate().is_err(), "the empty agent_id must be rejected");

        // A path separator in node_id is rejected too.
        let mut bad_node = KirbyConfig::from_toml_str(minimal_toml()).unwrap();
        bad_node.node_id = "a/b".to_string();
        assert!(bad_node.validate().is_err(), "a node_id with a path separator must be rejected");
    }

    #[test]
    fn full_config_parses_all_fields() {
        let toml = r#"
            agent_id = "agent-7"
            node_id = "mac-mini"
            backend = "auto"
            workload = "app-checkpoint"
            mode = "resume"
            genome_image = { url = "https://example.com/kirby-arm64.tar" }

            [identity]
            key_path = "/var/lib/kirby/keys"
            treasury_dir = "/var/lib/kirby/treasury"

            [relay]
            url = "wss://relay.example.com"
            presence_interval_secs = 30
            presence_stale_after_secs = 90

            [funding]
            initial_sats = 250000
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.agent_id, "agent-7");
        assert_eq!(cfg.node_id, "mac-mini");
        assert_eq!(cfg.mode, RunMode::Resume);
        assert_eq!(cfg.relay.presence_interval_secs, 30);
        assert_eq!(cfg.relay.presence_stale_after_secs, 90);
        assert_eq!(cfg.funding.initial_sats, 250000);
        assert_eq!(
            cfg.identity.treasury_dir(),
            PathBuf::from("/var/lib/kirby/treasury")
        );
        assert_eq!(
            cfg.genome_image,
            GenomeImage::Url("https://example.com/kirby-arm64.tar".to_string())
        );
    }

    #[test]
    fn non_websocket_relay_is_rejected() {
        let toml = r#"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "http://127.0.0.1:7777"
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("websocket URL"),
            "expected a websocket-URL validation error, got: {err}"
        );
    }

    #[test]
    fn zero_funding_is_rejected() {
        let toml = r#"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 0
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("initial_sats must be > 0"),
            "expected a zero-funding validation error, got: {err}"
        );
    }

    // ---- brain-stub: the [brain] validation guard (the spending membrane's
    // "afford at least one think" gate). It is load-bearing — it closes the
    // think-for-free path (a zero or over-treasury per-call cap) — so it has teeth:
    // reject the two bad shapes for the BRAIN reason (not an unrelated field), and
    // ACCEPT the valid shape (so the tests prove the guard discriminates, rather than
    // erroring unconditionally). Each sets a valid funding/relay so ONLY the brain
    // guard can be the failing check.

    #[test]
    fn brain_zero_max_cost_sats_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            max_cost_sats = 0
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        // Rejected for THE brain reason (a zero per-call cap), not funding/backend/relay.
        assert!(
            err.to_string().contains("brain.max_cost_sats must be > 0"),
            "expected the brain zero-cap validation error, got: {err}"
        );
    }

    #[test]
    fn brain_max_cost_sats_over_treasury_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 100
            [brain]
            max_cost_sats = 200
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        // Rejected for THE brain reason (cap exceeds the treasury → can't afford the
        // first think), pinned to the brain field + funding so it is not the
        // zero-funding guard ("initial_sats must be > 0") or another field.
        let msg = err.to_string();
        assert!(
            msg.contains("brain.max_cost_sats") && msg.contains("funding.initial_sats"),
            "expected the brain cap-over-treasury validation error, got: {err}"
        );
    }

    #[test]
    fn brain_valid_max_cost_sats_is_accepted() {
        // The negative control: a well-formed brain config (0 < max_cost_sats <=
        // initial_sats) must PASS validation — proving the guard rejects only the bad
        // shapes above, not the brain workload unconditionally.
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            max_cost_sats = 64
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).expect("a valid brain config must validate");
        assert_eq!(cfg.workload, Workload::Capable);
        assert_eq!(cfg.brain.max_cost_sats, 64, "the brain block parsed");
    }

    /// The diarist demo is BOOTSTRAP-ONLY: a `diarist` + `resume` config is rejected cleanly at
    /// load. A resumed diarist would skip the metered loop and never arm its floor-halt death
    /// mechanism (a deathless agent), so the combination is refused until metered-resume lands.
    /// The negative control: the SAME config with `bootstrap` validates — proving the guard
    /// discriminates on the mode, not the diarist workload at large. Brain/memory/funding are
    /// all valid here, so ONLY the bootstrap-only guard can be the failing check.
    #[test]
    fn diarist_resume_is_rejected_bootstrap_is_accepted() {
        let toml = |mode: &str| {
            format!(
                r#"
                workload = "capable"
                mode = "{mode}"
                genome_image = {{ path = "/tmp/k/img" }}
                [identity]
                key_path = "/tmp/k/node.key"
                [relay]
                url = "ws://127.0.0.1:7777"
                [funding]
                initial_sats = 1000
                [brain]
                max_cost_sats = 64
                [memory]
                max_cost_sats = 8
            "#
            )
        };

        // diarist + resume => rejected for THE resume reason (bootstrap-only).
        let err = KirbyConfig::from_toml_str(&toml("resume")).unwrap_err();
        assert!(
            err.to_string().contains("does not support mode = \"resume\""),
            "expected the diarist bootstrap-only validation error, got: {err}"
        );

        // diarist + bootstrap => validates (the guard rejects only the unsupported mode).
        let cfg = KirbyConfig::from_toml_str(&toml("bootstrap"))
            .expect("a diarist bootstrap config must validate");
        assert_eq!(cfg.workload, Workload::Capable);
        assert_eq!(cfg.mode, RunMode::Bootstrap);
    }

    // ---- brain-routstr: the `backend = "routstr"` validation guards (the real-mode
    // required fields + the bearer-token-over-https rule). Each sets a valid
    // funding/relay/cap so ONLY the routstr guard under test can be the failing check,
    // and the negative controls PASS so the guards are proven to discriminate.

    #[test]
    fn brain_backend_defaults_to_stub_for_backcompat() {
        // An existing `[brain]` block with no `backend` key parses as Stub, and the
        // routstr-only fields are NOT required (backcompat: a stub brain still runs).
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            max_cost_sats = 64
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).expect("a stub brain must validate");
        assert_eq!(cfg.brain.backend, BrainBackendKind::Stub);
        assert!(cfg.brain.node_url.is_empty(), "routstr fields default empty for the stub");
    }

    #[test]
    fn brain_routstr_missing_node_url_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr"
            max_cost_sats = 64
            mint_url = "https://mint.example.com"
            wallet_db_path = "/var/lib/kirby/brain-wallet.sqlite"
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("brain.node_url must be set"),
            "expected the routstr missing-node_url error, got: {err}"
        );
    }

    #[test]
    fn brain_routstr_missing_mint_url_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr"
            max_cost_sats = 64
            node_url = "https://api.routstr.com"
            wallet_db_path = "/var/lib/kirby/brain-wallet.sqlite"
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("brain.mint_url must be set"),
            "expected the routstr missing-mint_url error, got: {err}"
        );
    }

    #[test]
    fn brain_routstr_missing_wallet_db_path_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr"
            max_cost_sats = 64
            node_url = "https://api.routstr.com"
            mint_url = "https://mint.example.com"
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("brain.wallet_db_path must be set"),
            "expected the routstr missing-wallet_db_path error, got: {err}"
        );
    }

    #[test]
    fn brain_routstr_plain_http_nonlocal_node_is_rejected() {
        // A non-localhost node MUST be https (the X-Cashu bearer must not cross plaintext).
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr"
            max_cost_sats = 64
            node_url = "http://api.routstr.com"
            mint_url = "https://mint.example.com"
            wallet_db_path = "/var/lib/kirby/brain-wallet.sqlite"
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("must be https://"),
            "expected the routstr plaintext-node rejection, got: {err}"
        );
    }

    #[test]
    fn brain_routstr_full_https_config_is_accepted() {
        // The negative control: a well-formed routstr brain (https node + all fields)
        // PASSES, proving the guards reject only the bad shapes, not routstr wholesale.
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr"
            max_cost_sats = 64
            node_url = "https://api.routstr.com"
            mint_url = "https://mint.minibits.cash/Bitcoin"
            wallet_db_path = "/var/lib/kirby/brain-wallet.sqlite"
            request_timeout_secs = 45
            recovery_timeout_secs = 12
            fee_headroom_sats = 16
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).expect("a valid routstr brain must validate");
        assert_eq!(cfg.brain.backend, BrainBackendKind::Routstr);
        assert_eq!(cfg.brain.node_url, "https://api.routstr.com");
        assert_eq!(cfg.brain.request_timeout_secs, 45);
        assert_eq!(cfg.brain.fee_headroom_sats, 16);
    }

    #[test]
    fn brain_routstr_localhost_http_is_accepted() {
        // Plain http is allowed ONLY for a loopback node (a same-host node / the Layer-B
        // test rig), so the mock-node tests can run without TLS.
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr"
            max_cost_sats = 64
            node_url = "http://127.0.0.1:8181"
            mint_url = "http://127.0.0.1:8086"
            wallet_db_path = "/var/lib/kirby/brain-wallet.sqlite"
        "#;
        let cfg =
            KirbyConfig::from_toml_str(toml).expect("a loopback-http routstr brain must validate");
        assert_eq!(cfg.brain.node_url, "http://127.0.0.1:8181");
    }

    #[test]
    fn brain_routstr_key_missing_node_url_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr_key"
            api_key_path = "/var/lib/kirby/brain-api.key"
        "#;
        let err = KirbyConfig::from_toml_str(toml).expect_err("routstr_key without node_url must be rejected");
        assert!(
            err.to_string().contains("brain.node_url must be set"),
            "expected the routstr_key missing-node_url error, got: {err}"
        );
    }

    #[test]
    fn brain_routstr_key_missing_api_key_path_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr_key"
            node_url = "https://api.routstr.com"
        "#;
        let err = KirbyConfig::from_toml_str(toml).expect_err("routstr_key without api_key_path must be rejected");
        assert!(
            err.to_string().contains("brain.api_key_path must be set"),
            "expected the routstr_key missing-api_key_path error, got: {err}"
        );
    }

    #[test]
    fn brain_routstr_key_plain_http_nonloopback_is_rejected() {
        // The bearer key is money on the Authorization header: a non-loopback node MUST be
        // https, exactly as the X-Cashu path requires.
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr_key"
            node_url = "http://api.routstr.com"
            api_key_path = "/var/lib/kirby/brain-api.key"
        "#;
        let err = KirbyConfig::from_toml_str(toml).expect_err("plain-http non-loopback routstr_key must be rejected");
        assert!(
            err.to_string().contains("must be https"),
            "expected the routstr_key plaintext-http error, got: {err}"
        );
    }

    #[test]
    fn brain_routstr_key_valid_config_needs_no_mint_or_wallet() {
        // The prepaid-key backend needs only a node + a keyfile — NO mint_url / wallet_db_path
        // (there is no local wallet). A loopback http node is accepted (the Layer-B test rig).
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr_key"
            max_cost_sats = 64
            node_url = "http://127.0.0.1:8181"
            api_key_path = "/var/lib/kirby/brain-api.key"
        "#;
        let cfg = KirbyConfig::from_toml_str(toml)
            .expect("a routstr_key brain with a node + keyfile must validate without a mint/wallet");
        assert_eq!(cfg.brain.backend, BrainBackendKind::RoutstrKey);
        assert_eq!(cfg.brain.api_key_path, "/var/lib/kirby/brain-api.key");
        assert!(cfg.brain.mint_url.is_empty(), "no mint is required for the prepaid-key backend");
        assert!(cfg.brain.wallet_db_path.is_empty(), "no wallet is required for the prepaid-key backend");
        assert_eq!(cfg.brain.max_tokens, 1024, "max_tokens defaults to 1024 (bounds the reserve)");
    }

    #[test]
    fn brain_routstr_key_zero_max_tokens_is_rejected() {
        // max_tokens=0 would make Routstr reserve the model max per request -> 402 under
        // the concurrent loops; a zero bound is a config error caught at load.
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr_key"
            node_url = "https://api.routstr.com"
            api_key_path = "/var/lib/kirby/brain-api.key"
            max_tokens = 0
        "#;
        let err = KirbyConfig::from_toml_str(toml).expect_err("max_tokens = 0 must be rejected");
        assert!(
            err.to_string().contains("brain.max_tokens must be > 0"),
            "expected the routstr_key zero-max_tokens error, got: {err}"
        );
    }

    #[test]
    fn is_https_or_localhost_resolves_true_host_not_userinfo() {
        // PASS: TLS (any host), and a REAL loopback host over plain http.
        assert!(is_https_or_localhost("https://api.routstr.com"));
        assert!(is_https_or_localhost("http://localhost:7780"));
        assert!(is_https_or_localhost("http://127.0.0.1:8181"));
        // IPv6 loopback over plain http — the old substring split mishandled the brackets
        // (it could never match), over-rejecting a legitimate same-host node.
        assert!(is_https_or_localhost("http://[::1]:7780"));
        assert!(is_https_or_localhost("http://[::1]"));

        // REJECT (the userinfo bypass): the TRUE host is evil.com, so the cleartext X-Cashu
        // bearer must NOT be sent. A naive split on ':'/'@' read these as "localhost" /
        // "127.0.0.1" and PASSED them — leaking the bearer to evil.com over plaintext http.
        assert!(!is_https_or_localhost("http://localhost:pw@evil.com/"));
        assert!(!is_https_or_localhost("http://localhost:pw@evil.com"));
        assert!(!is_https_or_localhost("http://127.0.0.1@evil.com"));
        assert!(!is_https_or_localhost("http://localhost%2f@evil.com"));
        // A plain non-loopback http host stays refused (the original MED-3 guard).
        assert!(!is_https_or_localhost("http://api.routstr.com"));
        // Unparseable or non-http(s) schemes fail closed.
        assert!(!is_https_or_localhost("not a url"));
        assert!(!is_https_or_localhost("ftp://localhost/x"));
    }

    // ---- diarist: it REUSES [brain] + [memory] and adds a minimal [diarist] block; its
    // validation applies BOTH the brain afford-a-think guard AND the memory afford-a-write
    // guard (F5), and the [diarist] knobs default so a bare block runs. ----

    /// A diarist config with no `[diarist]` block parses with the cadence/recall defaults,
    /// resolves to the "diarist" genome workload, and submits a checkpoint (resume cursor).
    #[test]
    fn diarist_config_parses_with_defaults() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            max_cost_sats = 64
            [memory]
            max_cost_sats = 64
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).expect("a valid diarist config must validate");
        assert_eq!(cfg.workload, Workload::Capable);
        assert_eq!(cfg.workload.genome_workload(), "capable");
        assert!(
            cfg.workload.submits_checkpoint(),
            "the capable agent persists its wseq cursor for resume continuity"
        );
        // The [agent] block defaulted (none present).
        assert_eq!(cfg.agent.tick_secs, 60);
        assert_eq!(cfg.agent.recall_count, 5);
    }

    /// FIX-1 (config reachability): the daemon CONFIG path can boot the capable loop, not only
    /// the test's cmdline knob. `workload = "capable"` round-trips to `Workload::Capable`, maps to
    /// the "capable" genome workload, submits a checkpoint (the wseq resume cursor), reuses the
    /// [brain] afford-a-think guard, and is bootstrap-only (resume rejected) exactly like the diarist.
    #[test]
    fn capable_config_round_trips_and_reuses_the_diarist_wiring() {
        let toml = |mode: &str| {
            format!(
                r#"
                workload = "capable"
                mode = "{mode}"
                genome_image = {{ path = "/tmp/k/img" }}
                [identity]
                key_path = "/tmp/k/node.key"
                [relay]
                url = "ws://127.0.0.1:7777"
                [funding]
                initial_sats = 1000
                [brain]
                max_cost_sats = 64
                [memory]
                max_cost_sats = 8
            "#
            )
        };

        // bootstrap: a valid capable config parses and resolves to the capable genome workload.
        let cfg = KirbyConfig::from_toml_str(&toml("bootstrap"))
            .expect("a valid capable config must validate");
        assert_eq!(cfg.workload, Workload::Capable);
        assert_eq!(cfg.workload.genome_workload(), "capable", "boots the capable genome arm");
        assert!(
            cfg.workload.submits_checkpoint(),
            "the capable loop persists its wseq cursor for resume continuity"
        );

        // resume: bootstrap-only, rejected at load (same as the diarist).
        let err = KirbyConfig::from_toml_str(&toml("resume")).unwrap_err();
        assert!(
            err.to_string().contains("does not support mode = \"resume\""),
            "capable is bootstrap-only, got: {err}"
        );

        // reuse: the [brain] afford-a-think guard applies to capable too (it reuses [brain]).
        let zero_brain = toml("bootstrap").replace("max_cost_sats = 64", "max_cost_sats = 0");
        assert!(
            KirbyConfig::from_toml_str(&zero_brain).is_err(),
            "capable reuses the brain afford-a-think guard (max_cost_sats = 0 rejected)"
        );
    }

    /// An explicit `[diarist]` block parses its two knobs.
    #[test]
    fn diarist_block_parses_explicit_knobs() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            max_cost_sats = 64
            [memory]
            max_cost_sats = 64
            [agent]
            tick_secs = 90
            recall_count = 8
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).expect("a valid agent config must validate");
        assert_eq!(cfg.agent.tick_secs, 90);
        assert_eq!(cfg.agent.recall_count, 8);
    }

    /// F5 (the brain half): a diarist whose brain cannot afford a think is rejected for THE
    /// brain reason — the same guard the brain workload gets, now gated on Diarist too.
    #[test]
    fn diarist_zero_brain_cap_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            max_cost_sats = 0
            [memory]
            max_cost_sats = 64
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("brain.max_cost_sats must be > 0"),
            "the diarist must inherit the brain afford-a-think guard, got: {err}"
        );
    }

    /// F5 (the memory half): a diarist whose write ceiling is zero is rejected for THE
    /// memory reason — without this, every REMEMBER would be DENIED_OVER_BUDGET (a config
    /// error). This is the half the original spec's reused-Brain-only guard MISSED.
    #[test]
    fn diarist_zero_memory_cap_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            max_cost_sats = 64
            [memory]
            max_cost_sats = 0
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("memory.max_cost_sats must be > 0"),
            "the diarist must ALSO inherit the memory afford-a-write guard (F5), got: {err}"
        );
    }

    /// The diarist reuses `[brain]`, so a `routstr` diarist missing a routstr field is
    /// rejected by the SAME real-mode guard the brain gets (proving it gates on Diarist).
    #[test]
    fn diarist_routstr_missing_node_url_is_rejected() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 1000
            [brain]
            backend = "routstr"
            max_cost_sats = 64
            mint_url = "https://mint.example.com"
            wallet_db_path = "/var/lib/kirby/diarist-wallet.sqlite"
            [memory]
            max_cost_sats = 64
        "#;
        let err = KirbyConfig::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("brain.node_url must be set"),
            "the diarist must inherit the routstr required-field guards, got: {err}"
        );
    }

    /// The negative control: a well-formed diarist (affordable think AND write) validates,
    /// proving the dual guard discriminates rather than rejecting the diarist wholesale.
    #[test]
    fn diarist_valid_config_is_accepted() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 5000
            [brain]
            max_cost_sats = 64
            [memory]
            max_cost_sats = 64
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).expect("a valid diarist config must validate");
        assert_eq!(cfg.workload, Workload::Capable);
        assert_eq!(cfg.brain.max_cost_sats, 64);
        assert_eq!(cfg.memory.max_cost_sats, 64);
    }

    // ---- [meter]: the synthetic-rent dial (F4). Defaults are byte-identical to
    // BurnRates::default so an absent block leaves every existing run unchanged; an
    // explicit block lowers the memory rate so a sleeping VM does not rent-death. ----

    /// An absent `[meter]` block yields the default rates (1 sat/ms CPU, 1 sat/MiB-s mem,
    /// 1 sat/egress-byte) — byte-identical to `meter::BurnRates::default` (the From impl in
    /// meter.rs is tested there field-by-field), so existing runs are unchanged.
    #[test]
    fn meter_defaults_match_burnrates() {
        let m = MeterRatesConfig::default();
        assert_eq!(m.cpu_sats_per_usec_num, 1);
        assert_eq!(m.cpu_sats_per_usec_den, 1000);
        assert_eq!(m.mem_sats_per_mib_sec, 1);
        assert_eq!(m.egress_sats_per_byte_num, 1);
        assert_eq!(m.egress_sats_per_byte_den, 1);
        // A config with no [meter] block carries those defaults.
        let cfg = KirbyConfig::from_toml_str(minimal_toml()).unwrap();
        assert_eq!(cfg.meter, MeterRatesConfig::default());
    }

    /// An explicit `[meter]` block tunes the rates — the deploy lever that drops the memory
    /// rent so think + write become the dominant drains (F4). Partial blocks default the
    /// rest, so a deploy can set ONLY the memory rate.
    #[test]
    fn meter_block_tunes_memory_rent() {
        let toml = r#"
            workload = "capable"
            genome_image = { path = "/tmp/k/img" }
            [identity]
            key_path = "/tmp/k/node.key"
            [relay]
            url = "ws://127.0.0.1:7777"
            [funding]
            initial_sats = 5000
            [brain]
            max_cost_sats = 64
            [memory]
            max_cost_sats = 64
            [meter]
            mem_sats_per_mib_sec = 0
        "#;
        let cfg = KirbyConfig::from_toml_str(toml).expect("a tuned-meter diarist must validate");
        // The deploy lowered the memory rent (here to 0 for an extreme demo); the untouched
        // CPU/egress rates kept their defaults.
        assert_eq!(cfg.meter.mem_sats_per_mib_sec, 0);
        assert_eq!(cfg.meter.cpu_sats_per_usec_num, 1);
        assert_eq!(cfg.meter.cpu_sats_per_usec_den, 1000);
    }

    #[test]
    fn auto_backend_resolves_by_platform() {
        // The native backend matches the build target: VZ on macOS-aarch64, else
        // Firecracker. This is the same rule `auto` follows.
        let native = Backend::Auto.resolve();
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            assert_eq!(native, ResolvedBackend::Vz);
        } else {
            assert_eq!(native, ResolvedBackend::Firecracker);
        }
    }

    #[test]
    fn pinned_backend_mismatch_is_rejected_on_this_host() {
        // Whichever backend is NOT native to this host must be refused when pinned.
        let native = Backend::auto_for_host();
        let foreign_backend = if native == ResolvedBackend::Firecracker {
            "vz"
        } else {
            "firecracker"
        };
        let toml = format!(
            r#"
                backend = "{foreign_backend}"
                genome_image = {{ path = "/tmp/k/img" }}
                [identity]
                key_path = "/tmp/k/node.key"
                [relay]
                url = "ws://127.0.0.1:7777"
            "#
        );
        let err = KirbyConfig::from_toml_str(&toml).unwrap_err();
        assert!(
            err.to_string().contains("this host resolves to"),
            "expected a pinned-backend host-mismatch error, got: {err}"
        );
    }

    #[test]
    fn genome_image_url_resolve_is_a_documented_stub() {
        let img = GenomeImage::Url("https://example.com/img.tar".to_string());
        let err = img.resolve_local_dir().unwrap_err();
        assert!(
            err.to_string().contains("not yet implemented"),
            "URL fetch must be a clear TODO stub, got: {err}"
        );
        // The local-path form resolves cleanly.
        let local = GenomeImage::Path(PathBuf::from("/tmp/img"));
        assert_eq!(
            local.resolve_local_dir().unwrap(),
            PathBuf::from("/tmp/img")
        );
    }

    #[test]
    fn genome_image_arch_validation_uses_manifest() {
        let dir = unique_temp_dir("kirby-config-arch-manifest");
        std::fs::create_dir_all(&dir).unwrap();
        let expected = Backend::auto_for_host().expected_genome_arch();
        std::fs::write(
            dir.join("manifest.env"),
            format!("arch={}\n", expected.label()),
        )
        .unwrap();

        GenomeImage::validate_local_arch(&dir, Backend::auto_for_host()).unwrap();
    }

    #[test]
    fn genome_image_arch_mismatch_is_rejected() {
        let dir = unique_temp_dir("kirby-config-arch-mismatch");
        std::fs::create_dir_all(&dir).unwrap();
        let native = Backend::auto_for_host();
        let wrong = match native.expected_genome_arch() {
            GenomeArch::Aarch64 => GenomeArch::X86_64,
            GenomeArch::X86_64 => GenomeArch::Aarch64,
        };
        std::fs::write(
            dir.join("manifest.env"),
            format!("arch={}\n", wrong.label()),
        )
        .unwrap();

        let err = GenomeImage::validate_local_arch(&dir, native).unwrap_err();
        assert!(
            err.to_string().contains("arch mismatch"),
            "expected an arch mismatch error, got: {err}"
        );
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{name}-{}", std::process::id()))
    }

    /// FIX 3 (G-4): `validate()` REJECTS a failover config whose `failover_max_lease_age_secs` is at
    /// or below `takeover_grace_secs + LEASE_TTL_SECS` — an EMPTY takeover window in which automatic
    /// failover would silently never fire — and ACCEPTS the config one second above that boundary.
    /// This guards a money-critical safety feature from being turned off by a typo'd dial.
    #[test]
    fn failover_window_must_be_non_empty_else_rejected() {
        use crate::relay_lease::LEASE_TTL_SECS;
        // A fixed grace; the window floor is grace + the lease TTL.
        let grace = 30u64;
        let floor = grace + LEASE_TTL_SECS;
        let cfg_toml = |max_age: u64| {
            format!(
                r#"
                genome_image = {{ path = "/tmp/k/img" }}
                [identity]
                key_path = "/tmp/k/node.key"
                [relay]
                url = "ws://127.0.0.1:7777"
                [fleet.spawn]
                takeover_grace_secs = {grace}
                failover_max_lease_age_secs = {max_age}
            "#
            )
        };

        // AT the floor: the window is empty (a lease can never be both old enough to fire and young
        // enough to not be a ghost) -> REJECT with a message that names the dial to raise.
        let err = KirbyConfig::from_toml_str(&cfg_toml(floor)).unwrap_err();
        assert!(
            err.to_string().contains("failover_max_lease_age_secs")
                && err.to_string().contains("silently never fires"),
            "an empty takeover window must be rejected with a clear message, got: {err}"
        );

        // BELOW the floor: also rejected (the window is negative).
        assert!(
            KirbyConfig::from_toml_str(&cfg_toml(floor - 1)).is_err(),
            "a below-floor max-lease-age must be rejected (empty window)"
        );

        // ONE SECOND ABOVE the floor: a (minimal) non-empty window -> ACCEPT.
        let cfg = KirbyConfig::from_toml_str(&cfg_toml(floor + 1))
            .expect("a failover window of exactly one second must validate (the accept boundary)");
        assert_eq!(cfg.fleet.spawn.failover_max_lease_age_secs, floor + 1);
        assert_eq!(cfg.fleet.spawn.takeover_grace_secs, grace);
    }
}
