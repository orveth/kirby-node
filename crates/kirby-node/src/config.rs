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
    /// The `[brain]` knobs for the MIND workload (brain-stub). Used only when
    /// `workload = "brain"`; defaults so a bare `[brain]` (or none) runs.
    #[serde(default)]
    pub brain: BrainConfig,
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
    /// The MIND workload (brain-stub): the genome runs a think -> pay -> meter ->
    /// repeat loop, issuing a brokered `Completion` act each tick. Thinking drains
    /// the treasury (the stub debits a deterministic simulated cost), so the agent
    /// dies when broke. Stub-first behind the daemon's `BrainBackend` seam (no real
    /// money, no network); the brain only thinks (no checkpoint, no other acts).
    Brain,
}

impl Workload {
    /// Kernel command-line workload understood by the current genome.
    pub fn genome_workload(self) -> &'static str {
        match self {
            Workload::AppCheckpoint => "app-checkpoint",
            Workload::Brain => "brain",
        }
    }

    /// Whether bootstrap must persist a genome-submitted checkpoint for resume.
    pub fn submits_checkpoint(self) -> bool {
        match self {
            Workload::AppCheckpoint => true,
            // The brain only thinks; it submits no app checkpoint (durable
            // mind-state is a named later chunk, not this stub).
            Workload::Brain => false,
        }
    }
}

/// The `[brain]` config block (brain-stub): the knobs for the MIND workload. The
/// genome reads `model`, `max_cost_sats`, and `tick_secs` from the kernel command
/// line (the daemon writes them when the workload is `brain`); the daemon's
/// `StubBrain` reads `bytes_per_sat` (its simulated-cost knob). Every field has a
/// sane default so a bare `[brain]` (or none, when `workload = "brain"`) runs.
///
/// This is the swap-ready surface: `RoutstrBrain` (the next chunk) reads the SAME
/// `model` and per-call `max_cost_sats`, so pointing the agent at a real model is a
/// config change, not a genome or proto change (done-criteria #6).
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
    #[serde(default = "default_brain_bytes_per_sat")]
    pub bytes_per_sat: u64,
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

impl Default for BrainConfig {
    fn default() -> Self {
        BrainConfig {
            model: default_brain_model(),
            max_cost_sats: default_brain_max_cost_sats(),
            tick_secs: default_brain_tick_secs(),
            bytes_per_sat: default_brain_bytes_per_sat(),
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

impl KirbyConfig {
    /// Parse a [`KirbyConfig`] from a TOML string.
    pub fn from_toml_str(s: &str) -> anyhow::Result<Self> {
        let cfg: KirbyConfig =
            toml::from_str(s).map_err(|e| anyhow::anyhow!("parse kirby config TOML: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
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
        if self.funding.initial_sats == 0 {
            anyhow::bail!("funding.initial_sats must be > 0 (the agent needs a budget to live)");
        }
        // The brain must be able to afford at least one think, or it dies before it
        // thinks once: a zero per-call cap is always DENIED_OVER_BUDGET, and a cap
        // above the treasury is always DENIED_INSUFFICIENT_TREASURY (D-20). Checked
        // only for the brain workload so non-brain configs are unaffected.
        if self.workload == Workload::Brain {
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
            workload = "brain"
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
            workload = "brain"
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
            workload = "brain"
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
        assert_eq!(cfg.workload, Workload::Brain);
        assert_eq!(cfg.brain.max_cost_sats, 64, "the brain block parsed");
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
}
