//! The kirby-node daemon binary (spec 5).
//!
//! A thin CLI over the `kirby_node` library: it parses arguments and drives the
//! library modules (the host-prereqs gate, the persisted treasury, the vsock
//! NodeGateway). One Tokio process per node. The VM-boot loop that drives a
//! genome to connect is C-2; the meters (C-4), egress (C-5), real rail (C-6),
//! and the relay-native lease (#9) land in later chunks.

use std::time::Duration;

use kirby_node::{app_checkpoint_run, boot, gateway, nerve, prereqs, rail, treasury};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kirby-node",
    about = "Kirby DKG-less compute spike: node daemon",
    version
)]
struct Cli {
    /// The subcommand to run. OPTIONAL: a bare `kirby-node` (no subcommand) runs the FLEET
    /// node (the product), so a zero-config `kirby-node` just works (M1). Pass an explicit
    /// subcommand for anything else.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Check the host satisfies every spike prerequisite for this platform
    /// (Linux/Firecracker or macOS/VZ). This gate must pass on the target host
    /// with output captured.
    Prereqs {
        /// Emit machine-readable JSON instead of the human report.
        #[arg(long)]
        json: bool,
    },
    /// Run the node daemon. It runs the prereqs gate, opens the persisted
    /// treasury (spec 3.2 / 4.2, D-9), and builds the vsock NodeGateway
    /// (spec 3.1). With `--serve-vsock` it binds the gateway listener and serves
    /// until killed; without it, it constructs the gateway, logs that it is
    /// ready, and exits (the VM-boot loop that drives a genome to connect is
    /// C-2). The meters (C-4), egress (C-5), real rail (C-6), and lease (C-9)
    /// land in later chunks.
    Run {
        /// This node's id within the cluster (spec 3.5 lease surface).
        #[arg(long, default_value = "node-1")]
        node_id: String,
        /// Path to the persisted treasury store (sled). Defaults to a per-node
        /// directory so two node processes on one host stay distinct.
        #[arg(long)]
        treasury_path: Option<std::path::PathBuf>,
        /// Initial treasury balance in sats, seeded only on first creation. A
        /// resume from an existing store keeps its persisted balance (D-9).
        #[arg(long, default_value_t = 1_000_000)]
        initial_sats: u64,
        /// The session task descriptor handed to the genome at boot (non-secret).
        #[arg(long, default_value = "kirby-spike-stub")]
        task: String,
        /// The per-session budget snapshot handed to the genome (non-secret).
        #[arg(long, default_value_t = 1_000_000)]
        budget_sats: u64,
        /// Allowlisted destinations for brokered acts (mint ids, endpoint hosts;
        /// spec 3.2 step 2). Repeatable.
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// The vsock guest CID this node's gateway is bound to (spec 3.1: one
        /// genome per CID). Only used with `--serve-vsock`.
        #[arg(long, default_value_t = 3)]
        vsock_cid: u32,
        /// The vsock port the gateway listens on. Only used with `--serve-vsock`.
        #[arg(long, default_value_t = 5000)]
        vsock_port: u32,
        /// Bind the vsock gateway listener and serve until killed. Without it the
        /// daemon builds the gateway, logs readiness, and exits.
        #[arg(long)]
        serve_vsock: bool,
        /// The Nostr relay websocket URL for the "nerve" presence/discovery layer
        /// (slice 1), e.g. `ws://127.0.0.1:7777`. When set, the daemon generates
        /// (or loads) this node's Nostr identity and runs the presence task:
        /// publishes a replaceable presence beacon on an interval and subscribes to
        /// the fleet. When UNSET, presence is OFF and the daemon behaves exactly as
        /// before (no behavior change).
        #[arg(long)]
        relay_url: Option<String>,
        /// Seconds between presence beacon re-publishes (replaceable; bumps
        /// last-seen). Only used with `--relay-url`.
        #[arg(long, default_value_t = 15)]
        presence_interval: u64,
        /// Seconds after which a peer with no fresh beacon is presumed dead (STALE).
        /// Defaults to 3 missed intervals. Only used with `--relay-url`.
        #[arg(long, default_value_t = 45)]
        presence_stale_after: u64,
        /// Path to this node's Nostr secret key (its stable cluster identity). May
        /// be a file or a directory (the key lands at `<dir>/node.nostr.key`).
        /// Defaults to the treasury directory. Generated with 0600 perms on first
        /// run, loaded thereafter (idempotent npub). Only used with `--relay-url`.
        #[arg(long)]
        nostr_key_path: Option<std::path::PathBuf>,
        /// An optional advertised endpoint string put in the presence beacon
        /// (informational in slice 1; all coordination goes via the relay).
        #[arg(long)]
        endpoint: Option<String>,
        /// Run ONLY the presence task: do not boot a microVM or serve the vsock
        /// gateway, just join the fleet over the relay and serve until killed. This
        /// is the VM-independent path the presence test uses (no KVM/Firecracker
        /// needed). Requires `--relay-url`.
        #[arg(long)]
        presence_only: bool,
    },
    /// Read the live fleet from a Nostr relay (the "nerve" read path, slice 1):
    /// connect, query every node's current presence beacon
    /// (`KIND_KIRBY_PRESENCE`), and print the fleet (npub, node_id, last-seen age,
    /// ALIVE/STALE) as readable lines AND machine-parseable JSON. No node identity
    /// is needed (a throwaway read-only key is used). `--watch` streams live
    /// updates instead of printing once and exiting. This is the deterministic
    /// artifact the test and the eventual front-end read.
    Presence {
        /// The Nostr relay websocket URL, e.g. `ws://127.0.0.1:7777`.
        #[arg(long)]
        relay_url: String,
        /// Seconds after which a node with no fresh beacon is shown as STALE.
        #[arg(long, default_value_t = 45)]
        stale_after: u64,
        /// Seconds to wait for the relay to return the stored beacons (the one-shot
        /// query bound). Ignored with `--watch`.
        #[arg(long, default_value_t = 4)]
        timeout_secs: u64,
        /// Stream live fleet updates until killed instead of printing once.
        #[arg(long)]
        watch: bool,
        /// Print ONLY the JSON array (the machine artifact), no human lines. Makes
        /// the output trivially parseable by scripts/tests.
        #[arg(long)]
        json: bool,
    },
    /// Boot the genome microVM from the content-addressed image and prove the
    /// vsock boot round-trip (gate G1). The daemon boots the VM under the jailer
    /// (launched via sudo, D-7), serves the gateway over the VM's Firecracker
    /// vsock, waits for the genome's boot "hello" event (session=<task>), logs
    /// the G1 evidence, then halts the VM. Exit 0 only if the VM reached Running
    /// AND the hello arrived.
    Boot {
        /// The genome image directory (the `nix build .#genome-image` output),
        /// holding vmlinux and rootfs.squashfs. Defaults to the
        /// KIRBY_GENOME_IMAGE env var if set.
        #[arg(long)]
        image_dir: Option<std::path::PathBuf>,
        /// This node's id (distinguishes per-node treasury, jail, and CID).
        #[arg(long, default_value = "node-1")]
        node_id: String,
        /// The session task descriptor handed to the genome at boot (non-secret).
        #[arg(long, default_value = "kirby-spike-stub")]
        task: String,
        /// The per-session budget snapshot handed to the genome (non-secret).
        #[arg(long, default_value_t = 1_000_000)]
        budget_sats: u64,
        /// Initial treasury balance, seeded only on first creation (D-9).
        #[arg(long, default_value_t = 1_000_000)]
        initial_sats: u64,
        /// Allowlisted destinations for brokered acts (spec 3.2 step 2).
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// The vsock guest CID for this VM (>= 3; one genome per CID).
        #[arg(long, default_value_t = 3)]
        vsock_cid: u32,
        /// The vsock port the genome dials and the gateway serves on.
        #[arg(long, default_value_t = 5000)]
        vsock_port: u32,
        /// vCPU count for the microVM.
        #[arg(long, default_value_t = 1)]
        vcpu_count: u8,
        /// Memory for the microVM, in MiB.
        #[arg(long, default_value_t = 128)]
        mem_mib: usize,
        /// Seconds to wait for the boot hello event after the VM is up.
        #[arg(long, default_value_t = 30)]
        hello_timeout_secs: u64,
        /// Keep the VM running after the round-trip (serve until killed) instead
        /// of halting it. Useful for manual inspection; the default halts so the
        /// command is a self-contained G1 demonstration.
        #[arg(long)]
        keep_running: bool,
    },
    /// Prove portable app-checkpoint handoff. Node 1 boots a checkpoint-aware
    /// genome and accepts its logical checkpoint over the gateway; node 2 boots
    /// fresh with that checkpoint in `GetSessionContext` and reports that it saw
    /// the restore state. This is the Linux<->macOS resume mechanism because no
    /// VM memory snapshot crosses the backend boundary.
    AppCheckpoint {
        /// The genome image directory (the `nix build .#genome-image` output).
        /// Defaults to the KIRBY_GENOME_IMAGE env var if set.
        #[arg(long)]
        image_dir: Option<std::path::PathBuf>,
        /// Node 1's id. Node 2 derives its id from this.
        #[arg(long, default_value = "node-1")]
        node_id: String,
        /// The session task descriptor handed to the genome at boot.
        #[arg(long, default_value = "kirby-app-checkpoint-stub")]
        task: String,
        /// The vsock guest CID for node 1's VM. Node 2 uses this + 1.
        #[arg(long, default_value_t = 3)]
        vsock_cid: u32,
        /// The vsock port node 1's gateway serves on. Node 2 uses this + 1.
        #[arg(long, default_value_t = 5000)]
        vsock_port: u32,
        /// vCPU count for each fresh boot.
        #[arg(long, default_value_t = 1)]
        vcpu_count: u8,
        /// Memory for each fresh boot, in MiB.
        #[arg(long, default_value_t = 128)]
        mem_mib: usize,
        /// Seconds to wait for node 1's checkpoint submission.
        #[arg(long, default_value_t = 40)]
        checkpoint_secs: u64,
        /// Seconds to wait for node 2's restore observation.
        #[arg(long, default_value_t = 40)]
        restore_secs: u64,
    },
    /// The fleet-MVP keystone (`kirby run`): take a node from nothing to a live
    /// sovereign Kirby agent in the Nostr fleet, reading ONE config file
    /// (`kirby.toml`). It loads-or-mints the node identity, joins the fleet
    /// (presence + heartbeat), bootstraps (fund to born, emit a 9100 born) or
    /// resumes (restore the agent from the latest checkpoint, skip born), boots the
    /// agent in the sandbox via the config's backend (`auto` = VZ on macOS-aarch64
    /// else Firecracker), runs the v0 workload (present + heartbeat with a trivial
    /// metered loop), meters, and on budget exhaustion HALTS (die-when-broke) and
    /// emits a 9100 died. A teammate edits identity + relay + genome_image in the
    /// config and runs this; everything else defaults. This is the single-agent
    /// sovereign-fleet path, NOT the Raft cluster.
    Agent {
        /// Path to the config file (TOML, e.g. `kirby.toml`). OPTIONAL: loads `./kirby.toml` if
        /// present; an explicit `--config` that does not exist is an error. NOTE: unlike
        /// `kirby-node fleet`, a single agent has no useful zero-config — it needs a FUNDED
        /// config (validated in full), so with no config it synthesizes the fleet template and
        /// then fails on the empty `[brain] api_key_path`. Provide a funded config, or run
        /// `kirby-node fleet` for the zero-config node.
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// Escape hatch to the legacy node-key dev signer. By DEFAULT a single-node agent
        /// auto-provisions (or idempotently reloads) its own per-agent 2-of-3 FROST keystore
        /// and signs under its sovereign quorum key Q. `--no-frost` skips that and keeps the
        /// plain node-key path. (The fleet path always provisions FROST regardless.)
        #[arg(long)]
        no_frost: bool,
    },
    /// Run the FLEET SUPERVISOR (fleet-host S2): host the N operator-declared tenants in
    /// the config's `[fleet]` block as child `kirby agent` processes, each with its own
    /// allocated CID / instance_id / gateway_port (the S0 allocator), its own per-agent
    /// treasury (DB-per-agent), and its own per-agent Raft lease granted to this node (S1).
    /// The supervisor then MONITORS child lifecycle (the dead-tenant detection is the
    /// failover hook for S5/S6; S2 only tracks it). This is OFF by default: `Run` /
    /// `kirby run` / `Agent` are byte-identical when the supervisor is not started, so a
    /// single-agent node is unchanged (G-CLEAN). A config with NO `[[fleet.tenants]]`
    /// entries hosts nothing.
    Fleet {
        /// Path to the `kirby run` config file (TOML); its `[fleet]` block declares the
        /// tenants to host. OPTIONAL: when omitted, load `./kirby.toml` if present, else
        /// synthesize the zero-config fleet defaults (M2) — this is the bare `kirby-node`
        /// path. An explicit `--config` that does not exist is an error.
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// This node's lease id within the agents' cluster (the supervisor grants each
        /// tenant's lease to this id). The MVP forms a single-node lease cluster.
        #[arg(long, default_value_t = 1)]
        node_id: u64,
    },
    /// OPERATOR TRIGGER: build, sign, and publish a `KIND_KIRBY_SPAWN_REQUEST` (31003) to the
    /// relay — ask any listening node to spawn an agent (the spawn control-plane #11 trigger).
    /// Signs with the operator key (the three-keys creator key); a node that allowlists this
    /// key (or runs open) and has the named image + capacity will claim + launch the agent.
    SpawnRequest {
        /// The relay to publish the request to (the fleet's shared relay).
        #[arg(long)]
        relay: String,
        /// Path to the operator's Nostr secret key (bech32 `nsec...` or 64-char hex). Minted
        /// (0600) on first use and reused after, so the operator keeps a stable pubkey. Its
        /// pubkey (printed) is what a node's `[fleet.spawn] operators` allowlist names.
        #[arg(long, default_value = "operator.nostr.key")]
        operator_key: std::path::PathBuf,
        /// The requested agent identity (the `d` tag; charset/len validated like any agent id).
        #[arg(long)]
        agent_id: String,
        /// The genome image_ref the target node must have pre-staged (and allowlist).
        #[arg(long)]
        image_ref: String,
        /// The declarative seed amount (sats) to fund the agent's treasury with (deposit-and-meter).
        #[arg(long, default_value_t = 50_000)]
        seed_sats: u64,
        /// Optional non-secret genome config as a JSON string (task/brain/budget descriptor).
        #[arg(long)]
        genome_config: Option<String>,
    },
    /// INTERNAL (not for direct use): the privileged eBPF egress-byte meter, run
    /// by the daemon through sudo (the D-7 path) because loading and attaching
    /// eBPF needs CAP_BPF the unprivileged daemon lacks. It loads the embedded TC
    /// classifier, attaches it to the TAP's clsact ingress hook (the VM-egress direction), and prints the
    /// live byte counter to stdout on a tick until killed. The daemon parses that
    /// stream to bill egress bytes. The genome never invokes this.
    EbpfEgress {
        /// The TAP device to meter (the VM's network interface).
        #[arg(long)]
        iface: String,
        /// The reporting tick in milliseconds.
        #[arg(long, default_value_t = 100)]
        tick_ms: u64,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // M1: a bare `kirby-node` (no subcommand) runs the FLEET node — the product — so a
    // zero-config `kirby-node` just works. The `fleet` command's own `--config`/`--node-id`
    // defaults apply (None config => find `./kirby.toml` or synthesize zero-config defaults).
    let command = cli.command.unwrap_or(Command::Fleet {
        config: None,
        node_id: 1,
    });

    match command {
        Command::Prereqs { json } => {
            let report = prereqs::check();
            if json {
                println!("{}", report.to_json());
            } else {
                report.print_human();
            }
            // The gate fails the process if any hard requirement is unmet, so
            // CI and the verifier get a non-zero exit on a bad host.
            if report.all_satisfied() {
                Ok(())
            } else {
                std::process::exit(1);
            }
        }
        Command::Run {
            node_id,
            treasury_path,
            initial_sats,
            task,
            budget_sats,
            allow,
            vsock_cid,
            vsock_port,
            serve_vsock,
            relay_url,
            presence_interval,
            presence_stale_after,
            nostr_key_path,
            endpoint,
            presence_only,
        } => {
            init_tracing();
            run_daemon(RunArgs {
                node_id,
                treasury_path,
                initial_sats,
                task,
                budget_sats,
                allow,
                vsock_cid,
                vsock_port,
                serve_vsock,
                relay_url,
                presence_interval,
                presence_stale_after,
                nostr_key_path,
                endpoint,
                presence_only,
            })
        }
        Command::Presence {
            relay_url,
            stale_after,
            timeout_secs,
            watch,
            json,
        } => {
            init_tracing();
            run_presence_cmd(relay_url, stale_after, timeout_secs, watch, json)
        }
        Command::Boot {
            image_dir,
            node_id,
            task,
            budget_sats,
            initial_sats,
            allow,
            vsock_cid,
            vsock_port,
            vcpu_count,
            mem_mib,
            hello_timeout_secs,
            keep_running,
        } => {
            init_tracing();
            run_boot(BootArgs {
                image_dir,
                node_id,
                task,
                budget_sats,
                initial_sats,
                allow,
                vsock_cid,
                vsock_port,
                vcpu_count,
                mem_mib,
                hello_timeout_secs,
                keep_running,
            })
        }
        Command::AppCheckpoint {
            image_dir,
            node_id,
            task,
            vsock_cid,
            vsock_port,
            vcpu_count,
            mem_mib,
            checkpoint_secs,
            restore_secs,
        } => {
            init_tracing();
            run_app_checkpoint(AppCheckpointArgs {
                image_dir,
                node_id,
                task,
                vsock_cid,
                vsock_port,
                vcpu_count,
                mem_mib,
                checkpoint_secs,
                restore_secs,
            })
        }
        Command::Agent { config, no_frost } => {
            init_tracing();
            run_agent_cmd(config, no_frost)
        }
        Command::Fleet { config, node_id } => {
            init_tracing();
            run_fleet_supervisor_cmd(config, node_id)
        }
        Command::SpawnRequest { relay, operator_key, agent_id, image_ref, seed_sats, genome_config } => {
            init_tracing();
            run_spawn_request_cmd(relay, operator_key, agent_id, image_ref, seed_sats, genome_config)
        }
        Command::EbpfEgress { iface, tick_ms } => run_ebpf_egress(iface, tick_ms),
    }
}

/// The `kirby run` keystone: load the config, then run the sovereign-agent sequence
/// (identity, fleet-join, bootstrap-or-resume, boot, meter, die). Prints the gate
/// evidence line. Exits non-zero if the agent never reached Running so the keeper's
/// harness run fails loudly on a broken boot.
#[tokio::main]
async fn run_agent_cmd(
    config_path: Option<std::path::PathBuf>,
    no_frost: bool,
) -> anyhow::Result<()> {
    use kirby_node::config::{ConfigRole, KirbyConfig};
    use kirby_node::run_agent::{self, RunAgentConfig};

    // A single `agent` BOOTS an agent from its own config, so it validates as Standalone (the
    // full battery, incl. the brain money-path checks). With no --config and no ./kirby.toml it
    // synthesizes the zero-config default, which fails Standalone validation (the routstr_key
    // template has no api_key_path) — a single agent needs a funded, explicit config.
    let config = KirbyConfig::load_or_default(config_path.as_deref(), ConfigRole::Standalone)?;
    tracing::info!(config = ?config_path, "loaded kirby run config");
    let mut run = RunAgentConfig::from_config(config)?;
    // FROST is the single-node default; `--no-frost` keeps the legacy node-key dev path.
    run.no_frost = no_frost;
    let outcome = run_agent::run(run).await?;
    println!("{}", run_agent::evidence_line(&outcome));
    if outcome.reached_running {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// The fleet supervisor entry (fleet-host S2): load the config, form a single-node lease
/// cluster for this node, build the persisted allocator + the real process launcher, launch
/// every static tenant, then MONITOR child lifecycle until killed. OFF unless `kirby fleet`
/// is invoked, so the single-agent path is byte-identical (G-CLEAN).
#[tokio::main]
async fn run_fleet_supervisor_cmd(
    config_path: Option<std::path::PathBuf>,
    node_id: u64,
) -> anyhow::Result<()> {
    use std::sync::Arc;

    use anyhow::Context as _;
    use kirby_node::config::{ConfigRole, KirbyConfig};
    use kirby_node::fleet::Allocator;
    use kirby_node::fleet_reconcile::LaunchRegistry;
    use kirby_node::fleet_supervisor::{FleetSupervisor, ProcessTenantLauncher};
    use kirby_node::relay_lease::{RelayLeaseGrantor, RelayLeasePublisher};
    use kirby_node::spawn::SledSpawnLedger;

    // The fleet HOST holds no money and boots no agent from its own [brain] (that block is the
    // tenant template), so it validates as FleetHost — skipping the brain money-path presence
    // checks the zero-config routstr_key template would otherwise trip (M5). With no --config and
    // no ./kirby.toml, this synthesizes the zero-config fleet defaults (the bare `kirby-node` path).
    let config = KirbyConfig::load_or_default(config_path.as_deref(), ConfigRole::FleetHost)?;
    tracing::info!(config = ?config_path, tenants = config.fleet.tenants.len(), "loaded fleet config");

    // The relay-native lease grantor (#9): the supervisor CLAIMS each tenant's per-agent lease
    // by FROST-signing a Lease event (under the tenant's OWN quorum Q, loaded from the keystore
    // it provisions) and publishing it to the SAME fleet relay the nerve uses. No loopback Raft
    // cluster -- the relay does the NAT traversal, so this is the cross-machine failover floor.
    let publisher = std::sync::Arc::new(
        RelayLeasePublisher::connect(&config.relay.url)
            .await
            .context("connect the relay-lease publisher to the fleet relay")?,
    );
    let grantor = std::sync::Arc::new(RelayLeaseGrantor::new(node_id, publisher));

    // The persisted allocator: restart-safe CIDs (never re-hand a live CID). Stored under
    // the node's treasury dir alongside the per-tenant treasuries.
    let alloc_dir = config.identity.treasury_dir();
    std::fs::create_dir_all(&alloc_dir).ok();
    // Take an EXCLUSIVE interprocess lock on the allocator dir BEFORE load_or_new, so a second
    // concurrent `kirby fleet` fails fast instead of independently loading the same JSON state
    // and double-allocating the same CID/port (the allocator file itself is unlocked). The
    // guard is bound for the supervisor's lifetime; dropping it at process exit frees the lock.
    let _alloc_lock = kirby_node::fleet::FleetAllocatorLock::acquire(&alloc_dir)?;
    let alloc_path = alloc_dir.join("fleet-allocator.json");
    let allocator = Allocator::load_or_new(&config.fleet, &alloc_path)?;

    // The durable spawn ledger (#11): opened HERE (once) rather than inside the control-plane
    // loop, so the startup reconcile (below) can CLEAR a reaped orphan's ledger entry (letting a
    // future spawn request re-spawn that agent_id) using the SAME handle the loop later uses —
    // sled takes an exclusive dir lock, so it must be opened exactly once and threaded through.
    let ledger = Arc::new(
        SledSpawnLedger::open(alloc_dir.join("spawn-ledger"))
            .context("open the durable spawn ledger")?,
    );

    // The DURABLE PID sidecar (re-adopt/reap, G-3): reload the launch records this node persisted
    // before any restart, so the startup reconcile can probe its orphans PID-reuse-safe. Snapshot
    // the persisted agent ids BEFORE the registry is moved into the supervisor (the reconcile
    // queries each one's lease). The supervisor OWNS the registry from here on (recording new
    // launches, forgetting reaped ones).
    let registry_path = alloc_dir.join("fleet-launch-registry.json");
    let launch_registry = LaunchRegistry::load_or_new(&registry_path)?;
    let persisted_agent_ids: Vec<String> =
        launch_registry.all().into_iter().map(|r| r.agent_id).collect();

    // The real launcher spawns each tenant as a child `kirby agent` (the existing
    // single-agent path) with the allocated CID/port; derived per-tenant configs land under
    // the node's config dir.
    let binary = std::env::current_exe()?;
    let config_dir = alloc_dir.join("fleet-tenant-configs");
    let launcher = Arc::new(ProcessTenantLauncher::new(config.clone(), binary, config_dir));

    // Capture the spawn control-plane config + relay url BEFORE `config` is moved into the
    // supervisor (the dynamic spawn-consumer, #11; off unless `[fleet.spawn] enabled = true`).
    let spawn_cfg = config.fleet.spawn.clone();
    let spawn_relay_url = config.relay.url.clone();
    let spawn_max_tenants = config.fleet.max_tenants as usize;

    // N1 — NODE presence: the persistent daemon beacons its OWN node-level presence (signed by
    // the durable node identity key, NOT any agent's FROST key) on the fleet relay, on the
    // presence interval and independent of any agent. This is what makes a node show up as ONE
    // stable entry across restarts (spawned agents no longer beacon presence; they surface via
    // their 31000 agent-state). Built from `config` BEFORE it is moved into the supervisor; the
    // shutdown sender is held until the control-plane loop below returns (the daemon's lifetime),
    // so the beacon runs for as long as the node does.
    let node_presence = {
        let treasury_dir = config.identity.treasury_dir();
        std::fs::create_dir_all(&treasury_dir).ok();
        let key_path =
            nerve::NodeIdentity::resolve_key_path(config.identity.key_path.as_deref(), &treasury_dir);
        let identity = nerve::NodeIdentity::load_or_create(&key_path)?;
        tracing::info!(
            npub = %identity.npub(),
            node_id = %config.node_id,
            relay = %config.relay.url,
            "starting NODE presence (the persistent fleet node beacon)"
        );
        let cfg = nerve::PresenceConfig {
            relay_url: config.relay.url.clone(),
            node_id: config.node_id.clone(),
            endpoint: None,
            interval: Duration::from_secs(config.relay.presence_interval_secs),
            stale_after: Duration::from_secs(config.relay.presence_stale_after_secs),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(nerve::run_presence(
            nerve::BeaconSigner::NodeKey(identity),
            cfg,
            shutdown_rx,
        ));
        (shutdown_tx, handle)
    };

    let mut supervisor = FleetSupervisor::new(node_id, config, allocator, grantor, launcher)
        .with_launch_registry(launch_registry);

    // RECONCILE persisted state with reality (re-adopt/reap, G-3, closes the orphan-zombie),
    // BEFORE launching any static tenant or entering the listen loop. A killed supervisor leaves
    // its tenant VMs running (reparented to init) but un-presenced; on restart we re-adopt the
    // healthy orphans this node still owns (re-track them so the heartbeat resumes their lease +
    // presence — a bounce becomes invisible to the fleet) and reap the rest (kill + release the
    // slot + clean the abandoned keystore + clear the ledger). No-op on a first start (an empty
    // registry).
    if !persisted_agent_ids.is_empty() {
        if let Err(e) = reconcile_fleet_on_startup(
            &mut supervisor,
            node_id,
            &persisted_agent_ids,
            &spawn_relay_url,
            ledger.as_ref(),
        )
        .await
        {
            // A reconcile failure (e.g. the relay is unreachable to learn the leases) must not
            // crash the supervisor: log it and proceed. The orphans keep running; the next reap
            // tick + a later restart get another chance. Failing open here is safer than refusing
            // to start the node at all.
            tracing::error!(error = %e, "FLEET reconcile on startup failed; proceeding without it (orphans keep running)");
        }
    }

    let records = supervisor.launch_all().await?;
    for r in &records {
        println!(
            "FLEET tenant launched: agent_id={} cid={} port={} instance_id={} lease_term={} treasury={}",
            r.agent_id,
            r.allocation.guest_cid,
            r.allocation.gateway_port,
            r.allocation.instance_id,
            r.lease_term,
            r.treasury_path.display()
        );
    }
    println!("FLEET supervisor: {} static tenant(s) launched; entering listen-and-spawn", records.len());

    // The spawn control-plane (#11) ALWAYS runs: a Kirby node's purpose is to listen on the
    // relay for signed KIND_KIRBY_SPAWN_REQUEST events and spawn agents on demand (gudnuf —
    // listen-and-spawn is the behavior, not an opt-in). A node behind a LAN/NAT makes only
    // OUTBOUND connections here (subscribe + the lease/presence publish the launch triggers),
    // so it hosts spawned agents with no inbound port. Runs until killed; reaps dead tenants on
    // a tick so a spawned-agent death frees capacity. (Static `[fleet.tenants]`, if any, were
    // launched above and are monitored by the same reap tick.)
    let result = run_spawn_control_plane(
        supervisor,
        node_id,
        spawn_cfg,
        &spawn_relay_url,
        spawn_max_tenants,
        ledger,
    )
    .await;

    // Stop the node presence beacon cleanly (best-effort; on a hard kill the process just exits).
    let (presence_shutdown, presence_handle) = node_presence;
    let _ = presence_shutdown.send(());
    let _ = presence_handle.await;
    result
}

/// RECONCILE the supervisor's persisted state with reality on `kirby fleet` startup
/// (re-adopt/reap, G-3): the relay-facing glue around the pure decision. Connects a READ-ONLY
/// client to the fleet relay, subscribes to the agents' retained `KIND_KIRBY_LEASE` events, drains
/// them into a [`kirby_node::relay_lease::FleetLeaseObserver`] for a brief settle window so the
/// node learns the CURRENT fleet leases (the relay RETAINS the latest addressable lease per
/// agent), resolves each persisted agent's FRESH lease into a sync
/// [`kirby_node::fleet_reconcile::LeaseSnapshot`], then hands `(probe, snapshot, ledger)` to
/// [`kirby_node::fleet_supervisor::FleetSupervisor::apply_reconcile`] (which does the re-adopt /
/// reap side effects). The liveness probe is the real PID-reuse-safe `/proc` probe.
async fn reconcile_fleet_on_startup(
    supervisor: &mut kirby_node::fleet_supervisor::FleetSupervisor,
    node_id: kirby_node::lease::LeaseNodeId,
    persisted_agent_ids: &[String],
    relay_url: &str,
    ledger: &kirby_node::spawn::SledSpawnLedger,
) -> anyhow::Result<()> {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Context as _;
    use nostr_sdk::prelude::*;

    use kirby_node::fleet_reconcile::{
        LeaseObservation, LeaseSnapshot, OrphanLivenessProbe, ProcLivenessProbe,
    };
    use kirby_node::relay_lease::FleetLeaseObserver;
    use kirby_proto::KIND_KIRBY_LEASE;

    tracing::info!(
        agents = persisted_agent_ids.len(),
        "FLEET reconcile: probing {} persisted orphan(s) for re-adopt/reap",
        persisted_agent_ids.len()
    );

    // Subscribe to the retained lease events so we learn which agents are still held + by whom.
    let observer = Arc::new(FleetLeaseObserver::new(node_id));
    let client = Client::builder().signer(Keys::generate()).build();
    // Disable the 55s keepalive ping (nerve::add_relay_no_ping): on a laggy path this
    // observer would self-kill and go blind, which a failover-detection loop reads as
    // "every peer is stale" -> mass false takeover.
    nerve::add_relay_no_ping(&client, relay_url)
        .await
        .with_context(|| format!("add fleet relay {relay_url} for reconcile lease observe"))?;
    client.connect().await;
    let filter = Filter::new().kind(Kind::from(KIND_KIRBY_LEASE));
    // Capture the subscription id so we recognise THIS subscription's EOSE.
    let sub = client
        .subscribe(filter, None)
        .await
        .context("subscribe to KIND_KIRBY_LEASE for reconcile")?;
    let sub_id = sub.val;

    // THE FALSE-REAP FENCE (drain the RETAINED leases, then WAIT FOR EOSE — not a fixed timer).
    // The relay sends every RETAINED (stored) lease and then an EOSE ("end of stored events");
    // until that EOSE lands, an ABSENT lease might just be a not-yet-delivered retained event, NOT
    // a dead agent. A reap is DESTRUCTIVE (kills the VM + DELETES the keystore = the agent's FROST
    // identity), so we must NOT trust absence until the observation is CONFIRMED COMPLETE. We fold
    // each observed lease into the occupancy view and stop on EOSE; a bounded backstop timeout
    // guards against a relay that is reachable but slow / never sends EOSE — in which case the
    // observation stays INCOMPLETE and the reconcile fails SAFE (skips) below.
    let mut notifications = client.notifications();
    let backstop = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(backstop);
    let mut eose_received = false;
    loop {
        tokio::select! {
            _ = &mut backstop => {
                // Reachable-but-slow / no EOSE: leave `eose_received = false` => fail safe below.
                tracing::warn!(
                    relay = relay_url,
                    "FLEET reconcile: lease observation backstop elapsed WITHOUT an EOSE; the \
                     retained-lease snapshot is INCOMPLETE so it cannot be trusted for absence"
                );
                break;
            }
            notif = notifications.recv() => match notif {
                Ok(RelayPoolNotification::Event { event, .. }) => {
                    if event.kind.as_u16() == KIND_KIRBY_LEASE {
                        observer.observe_occupancy(&event).await;
                    }
                }
                // EOSE for OUR subscription: the relay has delivered every retained lease — the
                // snapshot is now AUTHORITATIVE. Stop draining; absence now genuinely means gone.
                Ok(RelayPoolNotification::Message {
                    message: RelayMessage::EndOfStoredEvents(id),
                    ..
                }) if *id == sub_id => {
                    eose_received = true;
                    break;
                }
                Ok(RelayPoolNotification::Shutdown) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }

    // Resolve each persisted agent's FRESH lease (judged at NOW against the TTL) into a sync
    // snapshot — the pure reconcile decision then needs no await.
    let mut snapshot = LeaseSnapshot::new();
    for agent_id in persisted_agent_ids {
        if let Some(lease) =
            kirby_node::lease::SpawnFenceView::active_lease_for(observer.as_ref(), agent_id).await
        {
            snapshot.insert(agent_id, lease);
        }
    }

    // Done observing; drop the reconcile client (the control-plane loop opens its own).
    let _ = client.shutdown().await;

    // Execute the decision GUARDED by observation completeness: re-adopt healthy orphans + reap
    // the rest ONLY if EOSE confirmed the snapshot is complete; otherwise FAIL SAFE (skip — never
    // reap an alive agent on unconfirmed lease data). Reaped ledger entries clear through the SAME
    // ledger handle the control-plane loop uses.
    let obs = if eose_received { LeaseObservation::Complete } else { LeaseObservation::Incomplete };
    let probe: Arc<dyn OrphanLivenessProbe> = Arc::new(ProcLivenessProbe);
    let summary = supervisor.apply_reconcile(probe, &snapshot, obs, Some(ledger));

    if summary.skipped_unconfirmed {
        println!(
            "FLEET reconcile: SKIPPED (fail-safe) — no EOSE from the relay, so the lease snapshot \
             was incomplete; orphans left running, a later restart with a healthy relay reconciles them"
        );
    } else if summary.is_empty() {
        println!("FLEET reconcile: nothing to reconcile (no live orphans found for the persisted set)");
    } else {
        for agent_id in &summary.readopted {
            println!("FLEET reconcile: RE-ADOPTED orphan agent_id={agent_id} (heartbeat resumes its lease+presence)");
        }
        for (agent_id, reason) in &summary.reaped {
            println!("FLEET reconcile: REAPED orphan agent_id={agent_id} ({reason})");
        }
    }
    Ok(())
}

/// The dynamic spawn control-plane loop (#11): subscribe to `KIND_KIRBY_SPAWN_REQUEST` on the
/// relay and feed each event to the [`kirby_node::spawn::SpawnConsumer`], which applies the
/// full trust boundary (verify -> image-allowlist -> operator-authz + rate-limit -> funding ->
/// capacity -> durable reserve) before claiming + launching through the supervisor. The relay
/// subscription is the ONLY new I/O; all policy lives in the (unit-tested) consumer. Reaps dead
/// tenants on a tick so a spawned-agent death frees capacity for the next spawn. Runs until
/// killed (a spawn host is long-lived; it does NOT auto-exit when its static tenants die).
async fn run_spawn_control_plane(
    supervisor: kirby_node::fleet_supervisor::FleetSupervisor,
    node_id: kirby_node::lease::LeaseNodeId,
    spawn_cfg: kirby_node::config::SpawnConfig,
    relay_url: &str,
    max_tenants: usize,
    ledger: std::sync::Arc<kirby_node::spawn::SledSpawnLedger>,
) -> anyhow::Result<()> {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::Context as _;
    use nostr_sdk::prelude::*;

    use std::collections::BTreeMap;

    use kirby_node::failover_detect::{detect_takeovers, drop_backed_off_verdicts};
    use kirby_node::keyset_provisioning::{keystore_dir_for, keystore_loadable_at};
    use kirby_node::relay_lease::{FleetLeaseObserver, LEASE_TTL_SECS};
    use kirby_node::spawn::{
        AllowlistAuthorizer, SeedFunder, SpawnConsumer, SpawnOutcome, TakeoverAdmission,
    };
    use kirby_proto::{KIND_KIRBY_LEASE, KIND_KIRBY_SPAWN_REQUEST};

    // Build the consumer from config (MVP authz: operator allowlist + rate limit; pops later).
    let operators: HashSet<String> = spawn_cfg.operators.iter().cloned().collect();
    let images: HashSet<String> = spawn_cfg.image_allowlist.iter().cloned().collect();
    if operators.is_empty() {
        tracing::warn!(
            "FLEET spawn: OPEN — no operator allowlist set, so ANY signer may spawn an agent on \
             this node (the MVP DoS vector; pops will be the real gate). Set [fleet.spawn] \
             operators to lock it down to specific keys."
        );
        println!("FLEET spawn: WARNING — OPEN to any requester (no operator allowlist). MVP only.");
    }
    let authorizer = Arc::new(AllowlistAuthorizer::new(
        operators,
        spawn_cfg.max_per_window,
        spawn_cfg.rate_window_secs,
    ));
    let funder = Arc::new(SeedFunder::new(spawn_cfg.max_seed_sats));
    // The durable spawn ledger is opened ONCE by `run_fleet_supervisor_cmd` (so the startup
    // reconcile can clear reaped entries) and threaded in here — sled holds an exclusive dir lock,
    // so it must not be re-opened.
    // The CLAIM-BEFORE-LAUNCH fence read-side (closes G-1): a cooperative occupancy view of the
    // fleet's leases, folded from the KIND_KIRBY_LEASE events the loop observes. Before launching,
    // the consumer asks it whether ANOTHER node already holds the agent and backs off if so (no
    // cross-node double-spawn). Shared (Arc) between the consumer's fence and the observe loop.
    let observer = Arc::new(FleetLeaseObserver::new(node_id));
    let consumer = SpawnConsumer::new(max_tenants, images, authorizer, funder, ledger)
        .with_fence(observer.clone())
        // #78: OPT-IN stale-request filter — drop a spawn request older than the configured
        // age (off when unset, byte-identical). Lets a long-lived node ignore parked ghosts.
        .with_request_max_age(spawn_cfg.request_max_age_secs);

    // Subscribe to spawn requests AND lease events on the relay (read-only: an ephemeral key
    // signs nothing). The lease subscription feeds the occupancy fence; the relay RETAINS the
    // latest addressable lease per agent, so on connect this node immediately learns which agents
    // its peers already hold.
    let client = Client::builder().signer(Keys::generate()).build();
    // Disable the 55s keepalive ping (nerve::add_relay_no_ping): this is the fleet's
    // long-lived lease observer; if it self-kills on a laggy path it goes blind, which a
    // failover-detection loop reads as "every peer is stale" -> mass false takeover.
    nerve::add_relay_no_ping(&client, relay_url)
        .await
        .with_context(|| format!("add fleet relay {relay_url} for spawn subscription"))?;
    client.connect().await;
    let filter = Filter::new().kinds([
        Kind::from(KIND_KIRBY_SPAWN_REQUEST),
        Kind::from(KIND_KIRBY_LEASE),
    ]);
    client
        .subscribe(filter, None)
        .await
        .context("subscribe to KIND_KIRBY_SPAWN_REQUEST + KIND_KIRBY_LEASE")?;
    let mut notifications = client.notifications();
    println!("FLEET spawn control-plane: listening for spawn requests + leases on {relay_url}");

    // Attach the READ-AFTER-WRITE LAUNCH FENCE (failover finding G-1, the double-LAUNCH): a relay
    // re-reader over a CLONE of this control-plane's already-connected client. The supervisor
    // consults it AFTER a takeover claims the lease and BEFORE it launches the VM, re-reading the
    // agent's surviving latest lease with a real round-trip so it launches ONLY if THIS node won
    // the term race (the loser of a two-survivor race aborts + releases its allocation; a later
    // tick re-settles). Wired HERE (not in `run_fleet_supervisor_cmd`) because the read needs the
    // connected relay client, which is built in this loop; the static-tenant `launch_all` ran
    // earlier with no confirmer (a node's own first launch does not race a peer — the spawn fence
    // covers cross-node spawns). A SHORT fetch timeout bounds the confirm so it never holds the
    // single-takeover-per-tick slot hostage to a slow relay (a timeout reads as empty -> fail closed).
    let lease_reader = Arc::new(kirby_node::relay_lease::RelayLeaseReader::new(
        client.clone(),
        Duration::from_secs(3),
    ));
    let mut supervisor = supervisor.with_lease_confirmer(
        lease_reader,
        kirby_node::fleet_supervisor::DEFAULT_LAUNCH_CONFIRM_SETTLE,
    );

    // The node's representative pre-staged image (the image a TAKEOVER would relaunch the agent on
    // — the node's OWN configured image, never attacker-supplied). Used by the failover admission
    // gate's image-allowlist check (the SAME default-deny the spawn path applies): an empty
    // allowlist (the node is staged to run nothing) yields `""`, which is not in the (empty)
    // allowlist, so a takeover is correctly suppressed on an image-incapable node.
    let node_image: String = spawn_cfg.image_allowlist.first().cloned().unwrap_or_default();

    // The G-4 takeover grace window (config dial, default = the lease TTL). A `debug_assert` guards
    // the config default from drifting from the lease TTL / the detector's documented default.
    let takeover_grace = spawn_cfg.takeover_grace_secs;
    debug_assert_eq!(
        kirby_node::config::default_spawn_takeover_grace_secs(),
        LEASE_TTL_SECS,
        "the takeover_grace config default must track LEASE_TTL_SECS (failover_detect::DEFAULT_TAKEOVER_GRACE_SECS)"
    );

    // The G-4 ghost age bound (config dial, default = 10× the TTL): a lease stale longer than this
    // is an ancient ghost (a dead past-run agent's retained lease) to ignore, not a recoverable
    // failover — the client-side backstop for the relay-pollution starvation bug (bug 2). A
    // `debug_assert` guards the config default from drifting from the detector's documented default.
    let max_lease_age = spawn_cfg.failover_max_lease_age_secs;
    debug_assert_eq!(
        kirby_node::config::default_spawn_failover_max_lease_age_secs(),
        kirby_node::failover_detect::DEFAULT_FAILOVER_MAX_LEASE_AGE_SECS,
        "the failover_max_lease_age config default must track failover_detect::DEFAULT_FAILOVER_MAX_LEASE_AGE_SECS"
    );

    // The per-agent CONTINUOUS-STALENESS dwell state the failover detector threads across scan
    // ticks (agent_id -> first-seen-stale `now`). OWNED by this loop and passed `&mut` into
    // `detect_takeovers` each tick: a candidate that recovers (goes fresh), becomes hosted, or
    // vanishes has its dwell cleared; the observer-blind fail-safe leaves it untouched on a blind
    // tick (so a recovered link does not instantly mass-take-over). Persisting it HERE (not inside
    // the arm) is what makes the dwell measure continuous staleness rather than restarting every tick.
    let mut grace_state: BTreeMap<String, u64> = BTreeMap::new();

    // The takeover-FAILURE backoff map (failover bug 3, allocation spin): agent_id -> the `now` its
    // last takeover LAUNCH failed. OWNED by this loop and consulted via `drop_backed_off_verdicts`
    // before selecting which verdict to act on, so one persistently-failing takeover (e.g. the
    // supervisor's "already allocated" idempotency error for an agent it launched-then-lost) cannot
    // monopolize the single-takeover-per-tick slot and starve healthy candidates. Pruned each tick.
    let mut takeover_backoff: BTreeMap<String, u64> = BTreeMap::new();
    let takeover_backoff_secs = kirby_node::failover_detect::DEFAULT_TAKEOVER_FAIL_BACKOFF_SECS;

    // Three cadences: reap dead tenants often (free slots quickly); heartbeat leases within the TTL
    // so a live agent's lease never goes stale (the keystone for the fence AND for failover); and
    // SCAN for dead PEERS to take over (G-4 automatic failover). The scan's snapshot+decision is
    // cheap; the claim/launch side-effect is bounded to ONE takeover per tick so a slow VM launch
    // never starves the reap/heartbeat/notification arms for long (the 30s lease TTL tolerates the
    // few-second stall a single launch can cause — see the failover_scan_tick arm).
    let mut reap_tick = tokio::time::interval(Duration::from_secs(2));
    let mut heartbeat_tick = tokio::time::interval(Duration::from_secs(10));
    let mut failover_scan_tick =
        tokio::time::interval(Duration::from_secs(spawn_cfg.failover_scan_secs.max(1)));
    loop {
        tokio::select! {
            _ = reap_tick.tick() => {
                // Reap dead spawned tenants so their CID/port slots free up for new spawns.
                let reaped = supervisor.reap_dead();
                for r in &reaped {
                    tracing::info!(agent_id = %r.agent_id, "FLEET spawn: reaped a dead tenant, slot freed");
                }
            }
            _ = heartbeat_tick.tick() => {
                // Re-publish every live tenant's lease so it stays within the TTL. The keystone:
                // without it a healthy agent's lease goes stale (~one TTL after launch), the
                // claim-before-launch fence goes blind, and a failover detector sees false deaths.
                supervisor.heartbeat_leases().await;
            }
            _ = failover_scan_tick.tick() => {
                // AUTOMATIC FAILOVER (G-4): take over a dead PEER's agent. THIS is the live-daemon
                // caller of the VERIFIED pure decision + the real FROST-claim + the agent launch —
                // a NEW money/safety entry point, so every admitted takeover passes the SAME
                // admission gates a fresh spawn passes (default-deny), via the SpawnConsumer chain.
                //
                // (1) DECIDE (fast, no launch I/O): build the observed-lease snapshot, run the pure
                //     `detect_takeovers` over it with this node's hosted set as the exclusion. The
                //     observer-blind fail-safe (no fresh lease => stand down, leave the dwell
                //     untouched) is enforced INSIDE the pure decision; `grace_state` (owned by this
                //     loop) is threaded `&mut` so the continuous-staleness dwell carries across ticks.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let snapshot = observer.observed_snapshot().await;
                let hosted: HashSet<String> =
                    supervisor.live_agent_ids().into_iter().collect();
                let verdicts = detect_takeovers(
                    &snapshot,
                    node_id,
                    &hosted,
                    now,
                    LEASE_TTL_SECS,
                    takeover_grace,
                    max_lease_age,
                    &mut grace_state,
                );

                // (1b) BACKOFF FILTER (failover bug 3, allocation spin): drop verdicts for agents
                //      whose last takeover LAUNCH failed within the backoff window, so a
                //      persistently-failing takeover (e.g. the supervisor's "already allocated"
                //      idempotency error) does not monopolize the single-takeover-per-tick slot and
                //      starve healthy candidates. Prune expired backoff entries first (memory
                //      hygiene); a backed-off agent is retried once its window elapses.
                takeover_backoff
                    .retain(|_, last_fail| now.saturating_sub(*last_fail) < takeover_backoff_secs);
                let verdicts =
                    drop_backed_off_verdicts(verdicts, &takeover_backoff, now, takeover_backoff_secs);

                // (2) GATE each verdict through the SAME admission chain a fresh spawn passes
                //     (default-deny, in order: keystore-loadable -> capacity -> image -> no-double-
                //     host fence), collecting the FIRST that is admitted. We act on at most ONE
                //     takeover per tick so a slow VM launch (the only slow step) does not starve the
                //     reap/heartbeat/notification arms — the next tick re-decides and takes the next
                //     (a multi-agent backlog drains over a few ticks; the 30s lease TTL tolerates the
                //     brief per-launch stall). Re-deciding next tick is safe + idempotent: a verdict
                //     we just took over leaves THIS node hosting the agent, so the detector's
                //     `hosted` exclusion drops it; one we could not admit is re-evaluated fresh.
                let mut admitted: Option<(String, u64)> = None;
                for verdict in &verdicts {
                    // Gate (a) input: can THIS node FROST-sign as the agent? Derive the agent's
                    // keystore dir the SAME way the supervisor does (instance_id_for(agent_id) ->
                    // keystore_dir_for) and test loadability WITHOUT materializing a signer. A
                    // DIFFERENT node (no keystore) is `false` => skipped (the cross-machine
                    // boundary, finding G-2). The supervisor reloads the SAME keystore on launch
                    // (idempotent provision -> same sovereign Q).
                    let keystore_dir = keystore_dir_for(
                        &kirby_node::fleet::instance_id_for(&verdict.agent_id),
                    );
                    let loadable = keystore_loadable_at(&keystore_dir);
                    match consumer
                        .admit_takeover(
                            &verdict.agent_id,
                            loadable,
                            &node_image,
                            supervisor.tenant_count(),
                        )
                        .await
                    {
                        TakeoverAdmission::Admit => {
                            admitted = Some((verdict.agent_id.clone(), verdict.beat_term));
                            break;
                        }
                        TakeoverAdmission::Skip(reason) => {
                            tracing::debug!(
                                agent_id = %verdict.agent_id, beat_term = verdict.beat_term,
                                %reason, "FLEET failover: takeover suppressed by an admission gate"
                            );
                        }
                    }
                }

                // (3) ACT (the side-effect at the edge): claim the lease at `beat_term` + launch the
                //     agent through the supervisor's EXISTING launch path (`launch_one_at_term`
                //     claims `beat_term` via the relay-lease grantor, then launches — the same
                //     allocate/provision/launch path a spawn uses, only the term differs).
                //
                //     SINGLE-WINNER ON THE LAUNCH PATH is enforced by the READ-AFTER-WRITE LAUNCH
                //     FENCE inside `provision_and_launch`: after the claim publishes, the supervisor
                //     re-reads the agent's surviving latest lease from the relay (the
                //     `RelayLeaseReader` attached above) and launches ONLY if THIS node holds it at
                //     `beat_term`. The monotonic-term lease ALONE does NOT prevent two survivors that
                //     both pass `detect_takeovers` from both claiming `beat_term` and both launching
                //     (it only fences the dead holder if it revives, and the equal-term cross-node
                //     tiebreak is otherwise unresolved); the relay's latest-wins collapse of the two
                //     same-Q addressable claims to ONE surviving holder, read back here, is what
                //     decides the winner — the loser's confirm DENIES its launch, releasing its
                //     allocation. A launch failure (including a denied confirm) releases its
                //     allocation inside `launch_one_at_term`; we back it off and let the next tick
                //     re-settle.
                if let Some((agent_id, beat_term)) = admitted {
                    let tenant = kirby_node::config::TenantConfig {
                        agent_id: agent_id.clone(),
                        initial_sats: kirby_node::config::default_tenant_initial_sats(),
                    };
                    match supervisor.launch_one_at_term(&tenant, beat_term).await {
                        Ok(record) => {
                            // Success: clear any prior backoff for this agent (it is now hosted).
                            takeover_backoff.remove(&agent_id);
                            println!(
                                "FLEET failover: TOOK OVER agent_id={agent_id} at beat_term={beat_term} \
                                 (npub={} cid={} port={})",
                                record.frost_npub, record.allocation.guest_cid, record.allocation.gateway_port
                            );
                            tracing::info!(
                                agent_id = %agent_id, beat_term, npub = %record.frost_npub,
                                "FLEET failover: autonomous takeover of a dead peer's agent"
                            );
                        }
                        Err(e) => {
                            // Record the failure time so a persistently-failing takeover (e.g. the
                            // supervisor's "already allocated" idempotency error) is BACKED OFF and
                            // does not starve healthy candidates next tick (failover bug 3). It is
                            // retried once the backoff window elapses.
                            takeover_backoff.insert(agent_id.clone(), now);
                            tracing::error!(
                                agent_id = %agent_id, beat_term, error = %e,
                                backoff_secs = takeover_backoff_secs,
                                "FLEET failover: takeover launch failed (allocation released; backing off this agent, will retry after the backoff window)"
                            );
                        }
                    }
                }
            }
            notif = notifications.recv() => {
                match notif {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        let kind = event.kind.as_u16();
                        if kind == KIND_KIRBY_LEASE {
                            // Fold a peer's (or our own) lease into the occupancy view the fence
                            // reads. Structural-only (no Q verify); see FleetLeaseObserver.
                            observer.observe_occupancy(&event).await;
                        } else if kind == KIND_KIRBY_SPAWN_REQUEST {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            match consumer.handle_event(&event, now, &mut supervisor).await {
                                SpawnOutcome::Launched { agent_id, frost_npub, lease_term } => {
                                    println!(
                                        "FLEET spawn: LAUNCHED agent_id={agent_id} npub={frost_npub} lease_term={lease_term}"
                                    );
                                }
                                other => {
                                    tracing::debug!(?other, "FLEET spawn: request not launched");
                                }
                            }
                        }
                    }
                    Ok(RelayPoolNotification::Shutdown) => {
                        tracing::warn!("FLEET spawn: relay pool shut down, exiting control-plane");
                        return Ok(());
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "FLEET spawn: notifications lagged; some requests skipped");
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

/// The operator-side spawn TRIGGER (#11): build, sign, and publish a `KIND_KIRBY_SPAWN_REQUEST`
/// (31003) to the relay. Loads-or-mints the operator key (0600), prints its pubkey (what a
/// node's `[fleet.spawn] operators` allowlist names), and publishes the signed request. Reuses
/// the shared `spawn::build_spawn_request_event` so the event shape matches exactly what the
/// consumer validates. The UI publishes the same event from a browser signer; this CLI is the
/// headless operator path (and the demo trigger).
#[tokio::main]
async fn run_spawn_request_cmd(
    relay: String,
    operator_key: std::path::PathBuf,
    agent_id: String,
    image_ref: String,
    seed_sats: u64,
    genome_config: Option<String>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use nostr_sdk::prelude::*;

    use kirby_node::spawn::{build_spawn_request_event, FundingRequest, SpawnRequest};

    // Load-or-mint the operator key (a stable pubkey across runs), 0600 on first write.
    let keys = if operator_key.exists() {
        let raw = std::fs::read_to_string(&operator_key)
            .with_context(|| format!("read operator key {}", operator_key.display()))?;
        Keys::parse(raw.trim()).context("parse operator key (expected nsec... or 64-char hex)")?
    } else {
        let keys = Keys::generate();
        if let Some(parent) = operator_key.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        std::fs::write(&operator_key, keys.secret_key().to_secret_hex())
            .with_context(|| format!("write new operator key {}", operator_key.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&operator_key, std::fs::Permissions::from_mode(0o600));
        }
        println!("minted a new operator key at {}", operator_key.display());
        keys
    };
    let operator_hex = keys.public_key().to_hex();
    println!("operator pubkey (hex): {operator_hex}");
    println!("operator npub:         {}", keys.public_key().to_bech32().unwrap_or_default());

    let genome_config = match genome_config {
        Some(s) => serde_json::from_str(&s).context("parse --genome-config as JSON")?,
        None => serde_json::Value::Null,
    };
    let req = SpawnRequest {
        agent_id: agent_id.clone(),
        genome_config,
        image_ref,
        funding: FundingRequest { seed_sats },
        // Bind the content requester to the signer (the consumer rejects a mismatch).
        requester_pubkey: operator_hex.clone(),
    };
    let event = build_spawn_request_event(&keys, &req).context("build the signed spawn request")?;
    let event_id = event.id.to_hex();

    let client = Client::builder().signer(keys.clone()).build();
    client.add_relay(&relay).await.with_context(|| format!("add relay {relay}"))?;
    client.connect().await;
    client
        .send_event(&event)
        .await
        .with_context(|| format!("publish spawn request to {relay}"))?;

    println!("published KIND_KIRBY_SPAWN_REQUEST (31003) for agent_id={agent_id} to {relay}");
    println!("event id: {event_id}");
    println!("a listening node that allowlists this operator (or runs open) + has image + capacity will spawn it.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_ebpf_egress(iface: String, tick_ms: u64) -> anyhow::Result<()> {
    // The privileged child (run via sudo). No tracing init: it logs to stderr in
    // plain lines the parent forwards. This blocks until killed.
    kirby_node::meter_egress::run_privileged_egress_meter(&iface, Duration::from_millis(tick_ms))
}

#[cfg(not(target_os = "linux"))]
fn run_ebpf_egress(_iface: String, _tick_ms: u64) -> anyhow::Result<()> {
    anyhow::bail!("the eBPF egress meter is only available on Linux")
}

/// Parsed `run` arguments, grouped so the daemon entry point takes one value.
struct RunArgs {
    node_id: String,
    treasury_path: Option<std::path::PathBuf>,
    initial_sats: u64,
    task: String,
    budget_sats: u64,
    allow: Vec<String>,
    vsock_cid: u32,
    vsock_port: u32,
    serve_vsock: bool,
    relay_url: Option<String>,
    presence_interval: u64,
    presence_stale_after: u64,
    nostr_key_path: Option<std::path::PathBuf>,
    endpoint: Option<String>,
    presence_only: bool,
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        // Logs go to STDERR so stdout is reserved for machine artifacts (e.g. the
        // `presence` JSON the test/front-end parse). tracing_subscriber's fmt
        // layer defaults to stdout, which would otherwise pollute that output.
        .with_writer(std::io::stderr)
        .init();
}

#[tokio::main]
async fn run_daemon(args: RunArgs) -> anyhow::Result<()> {
    use std::sync::Arc;

    tracing::info!(node_id = %args.node_id, "kirby-node daemon starting");

    // The node state directory (the treasury dir): also the default home for the node's Nostr
    // identity key. When `--treasury-path` is unset, fall back to a reboot-DURABLE per-node dir
    // under the same state root the boot path uses ($KIRBY_STATE_ROOT / XDG / $HOME, never
    // temp_dir) — keyed per node_id so two node processes on one host stay distinct (D-13
    // same-host harness). FIX 2: a key under a tmpfs `/tmp` becomes a NEW npub on the next reboot,
    // which makes a restarted node look like a brand-new node in the fleet/UI.
    let treasury_path = args
        .treasury_path
        .clone()
        .unwrap_or_else(|| boot::treasury_path_for(&args.node_id));

    // --presence-only: just join the fleet over the relay and serve until killed.
    // This is the VM-INDEPENDENT path (no prereqs gate, no KVM/Firecracker, no
    // treasury/gateway): presence is host-side and independent of VM lifecycle, so
    // the fleet-discovery slice is testable without a microVM (spec "Done").
    if args.presence_only {
        let relay_url = args.relay_url.clone().ok_or_else(|| {
            anyhow::anyhow!("--presence-only requires --relay-url (presence has nothing to join without a relay)")
        })?;
        // The node state dir holds the identity key even in presence-only mode.
        std::fs::create_dir_all(&treasury_path).ok();
        let key_path =
            nerve::NodeIdentity::resolve_key_path(args.nostr_key_path.as_deref(), &treasury_path);
        let identity = nerve::NodeIdentity::load_or_create(&key_path)?;
        tracing::info!(
            node_id = %args.node_id,
            npub = %identity.npub(),
            "presence-only: joining the fleet (no microVM)"
        );
        let cfg = nerve::PresenceConfig {
            relay_url,
            node_id: args.node_id.clone(),
            endpoint: args.endpoint.clone(),
            interval: Duration::from_secs(args.presence_interval),
            stale_after: Duration::from_secs(args.presence_stale_after),
        };
        // Run until SIGINT/SIGTERM, then shut the presence task down cleanly.
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        // The node daemon's own presence is node-level (signed by the node key, not a
        // FROST tenant key); byte-identical to pre-S3e (G-CLEAN).
        let task = tokio::spawn(nerve::run_presence(
            nerve::BeaconSigner::NodeKey(identity),
            cfg,
            shutdown_rx,
        ));
        wait_for_signal().await;
        let _ = shutdown_tx.send(());
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "presence task ended with error"),
            Err(e) => tracing::error!(error = %e, "presence task panicked"),
        }
        return Ok(());
    }

    // The daemon refuses to run on a host that fails the prereqs gate.
    let report = prereqs::check();
    if !report.all_satisfied() {
        tracing::error!("host prerequisites not satisfied; run `kirby-node prereqs` for detail");
        anyhow::bail!("host prerequisites not satisfied");
    }

    // Open the persisted, daemon-owned treasury (D-9). The balance is authoritative
    // on the host and is seeded only on first creation.
    let treasury = treasury::Treasury::open(&treasury_path, args.initial_sats)?;
    tracing::info!(
        path = %treasury_path.display(),
        remaining = treasury.remaining()?,
        "treasury opened"
    );

    // The "nerve" presence task (slice 1) runs alongside the daemon when a relay is
    // configured. It is host-side and unprivileged; it publishes this node's beacon
    // and tracks the fleet. When no relay is given, presence is OFF (no behavior
    // change). The shutdown sender is held for the lifetime of the serve path.
    let mut presence_handle: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    )> = None;
    if let Some(relay_url) = args.relay_url.clone() {
        let key_path =
            nerve::NodeIdentity::resolve_key_path(args.nostr_key_path.as_deref(), &treasury_path);
        let identity = nerve::NodeIdentity::load_or_create(&key_path)?;
        tracing::info!(npub = %identity.npub(), relay = %relay_url, "starting the presence task (nerve slice 1)");
        let cfg = nerve::PresenceConfig {
            relay_url,
            node_id: args.node_id.clone(),
            endpoint: args.endpoint.clone(),
            interval: Duration::from_secs(args.presence_interval),
            stale_after: Duration::from_secs(args.presence_stale_after),
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        // Node-level presence signs with the node key (not a FROST tenant key); G-CLEAN.
        let handle = tokio::spawn(nerve::run_presence(
            nerve::BeaconSigner::NodeKey(identity),
            cfg,
            rx,
        ));
        presence_handle = Some((tx, handle));
    }

    // Build the gateway service over the treasury and a rail. C-3 ships the mock
    // rail; C-6 swaps in the real rail (the CDK mint, D-16). The session is
    // the non-secret snapshot the genome pulls at boot.
    let session = gateway::Session {
        task_descriptor: args.task,
        budget_sats: args.budget_sats,
        allowlisted_destinations: args.allow,
        allowlisted_inbound_kinds: Vec::new(),
    };
    let rail = Arc::new(rail::MockRail::new());
    let service = gateway::GatewayService::new(treasury, rail, session);

    if args.serve_vsock {
        // Serve the gateway until killed over a raw AF_VSOCK listener. The
        // booted-VM path is `kirby-node boot` (it serves over the Firecracker
        // vsock Unix socket instead, spec 3.1 / C-2). The presence task (if any)
        // runs concurrently for the life of this serve.
        service.serve_vsock(args.vsock_cid, args.vsock_port).await?;
    } else if presence_handle.is_some() {
        // No vsock serve, but presence is running: keep the process alive (serving
        // the fleet) until a signal, then stop presence cleanly.
        tracing::info!(
            "gateway constructed; presence task running. Serving the fleet until killed (Ctrl-C)."
        );
        wait_for_signal().await;
    } else {
        // The gateway is constructed and ready, no presence, no vsock serve. The
        // VM-boot path is the `boot` subcommand (C-2). Exit cleanly so `run` can be
        // a readiness check without a microVM.
        tracing::info!(
            remaining = service.treasury_remaining()?,
            "gateway constructed and ready (use the `boot` subcommand to boot the genome microVM, --serve-vsock for a raw AF_VSOCK peer, or --relay-url to join the fleet)"
        );
    }

    // Stop the presence task cleanly if it was started.
    if let Some((tx, handle)) = presence_handle {
        let _ = tx.send(());
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "presence task ended with error"),
            Err(e) => tracing::error!(error = %e, "presence task panicked"),
        }
    }
    Ok(())
}

/// Wait for SIGINT or SIGTERM so a serve loop (presence-only, or presence + a
/// non-vsock run) exits cleanly on Ctrl-C or a `kill`.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The `presence` read subcommand: print the current fleet once (human + JSON), or
/// stream live updates with `--watch`.
#[tokio::main]
async fn run_presence_cmd(
    relay_url: String,
    stale_after: u64,
    timeout_secs: u64,
    watch: bool,
    json_only: bool,
) -> anyhow::Result<()> {
    let stale = Duration::from_secs(stale_after);
    if watch {
        let (_tx, rx) = tokio::sync::oneshot::channel();
        // _tx is dropped only at process exit; the watch runs until Ctrl-C.
        tokio::select! {
            r = nerve::watch_fleet(&relay_url, stale, rx) => { r?; }
            _ = wait_for_signal() => {}
        }
        Ok(())
    } else {
        let records =
            nerve::read_fleet_once(&relay_url, stale, Duration::from_secs(timeout_secs)).await?;
        if json_only {
            // Only the JSON array, so a script can parse stdout directly.
            println!("{}", nerve::format_fleet_json(&records));
        } else {
            println!("{}", nerve::format_fleet_human(&records));
            println!("{}", nerve::format_fleet_json(&records));
        }
        Ok(())
    }
}

/// Parsed `boot` arguments.
struct BootArgs {
    image_dir: Option<std::path::PathBuf>,
    node_id: String,
    task: String,
    budget_sats: u64,
    initial_sats: u64,
    allow: Vec<String>,
    vsock_cid: u32,
    vsock_port: u32,
    vcpu_count: u8,
    mem_mib: usize,
    hello_timeout_secs: u64,
    keep_running: bool,
}

#[tokio::main]
async fn run_boot(args: BootArgs) -> anyhow::Result<()> {
    // The daemon refuses to boot on a host that fails the prereqs gate (KVM,
    // vsock, jailer privilege, and the rest).
    let report = prereqs::check();
    if !report.all_satisfied() {
        tracing::error!("host prerequisites not satisfied; run `kirby-node prereqs` for detail");
        anyhow::bail!("host prerequisites not satisfied");
    }

    // Resolve the genome image (the content-addressed nix output).
    let image_dir = args
        .image_dir
        .or_else(|| std::env::var_os("KIRBY_GENOME_IMAGE").map(std::path::PathBuf::from))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no image: pass --image-dir or set KIRBY_GENOME_IMAGE to the genome-image output"
            )
        })?;
    let image = boot::ImagePaths::from_dir(&image_dir)?;

    let config = boot::BootConfig {
        image,
        node_id: args.node_id,
        task: args.task,
        budget_sats: args.budget_sats,
        initial_sats: args.initial_sats,
        allow: args.allow,
        guest_cid: args.vsock_cid,
        gateway_port: args.vsock_port,
        vcpu_count: args.vcpu_count,
        mem_size_mib: args.mem_mib,
        hello_timeout: Duration::from_secs(args.hello_timeout_secs),
        // The `boot` subcommand demonstrates G1 only; the genome idles after the
        // round-trip. The metered run (G2) is the `meter` subcommand.
        workload: None,
        brain: None,
        memory: None,
        agent: None,
        social: None,
        // No brain/wallet in the G1 demo → NIP-60 is inactive (empty relays, no store).
        nip60: Default::default(),
        fleet_relay: String::new(),
        // G1 is vsock-only (no TAP); the egress lockdown is the `egress`
        // subcommand (C-5, G4).
        lockdown_egress: false,
        // G1 does not snapshot (no CPU template); snapshot is the `snapshot`
        // subcommand (C-7, G6).
        snapshot_capable: false,
        restore_checkpoint: None,
        lease_fence: None,
    };

    let (vm, outcome, _treasury, _events, _serve_guard) = boot::boot_and_observe(config).await?;

    // The G1 verdict: the VM reached Running AND the boot hello round-trip
    // landed. Print a clear evidence line for the verifier.
    let hello_ok = outcome.hello.is_some();
    if let Some(hello) = &outcome.hello {
        println!(
            "G1 PASS: VM Running={} ; GetSessionContext round-trip ; hello event detail={:?} ; budget_sats={}",
            outcome.reached_running, hello.detail, outcome.budget_sats
        );
    } else {
        println!(
            "G1 FAIL: VM Running={} ; boot hello did NOT arrive (no vsock round-trip observed)",
            outcome.reached_running
        );
    }

    if args.keep_running {
        tracing::info!(
            "keep-running set: leaving the VM up (Ctrl-C to exit; jail is left for inspection)"
        );
        // Park so the spawned gateway server keeps serving. The VM stays up.
        futures::future::pending::<()>().await;
        Ok(())
    } else {
        // Halt the VM and clean the jail (daemon-initiated teardown).
        vm.halt().await;
        if outcome.reached_running && hello_ok {
            Ok(())
        } else {
            std::process::exit(1);
        }
    }
}

/// Parsed `app-checkpoint` arguments.
struct AppCheckpointArgs {
    image_dir: Option<std::path::PathBuf>,
    node_id: String,
    task: String,
    vsock_cid: u32,
    vsock_port: u32,
    vcpu_count: u8,
    mem_mib: usize,
    checkpoint_secs: u64,
    restore_secs: u64,
}

#[tokio::main]
async fn run_app_checkpoint(args: AppCheckpointArgs) -> anyhow::Result<()> {
    let report = prereqs::check();
    if !report.all_satisfied() {
        tracing::error!("host prerequisites not satisfied; run `kirby-node prereqs` for detail");
        anyhow::bail!("host prerequisites not satisfied");
    }

    let image_dir = args
        .image_dir
        .or_else(|| std::env::var_os("KIRBY_GENOME_IMAGE").map(std::path::PathBuf::from))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no image: pass --image-dir or set KIRBY_GENOME_IMAGE to the genome-image output"
            )
        })?;
    let image = boot::ImagePaths::from_dir(&image_dir)?;

    let boot_config = boot::BootConfig {
        image,
        node_id: args.node_id,
        task: args.task,
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec!["mint.test.local".to_string()],
        guest_cid: args.vsock_cid,
        gateway_port: args.vsock_port,
        vcpu_count: args.vcpu_count,
        mem_size_mib: args.mem_mib,
        hello_timeout: Duration::from_secs(args.checkpoint_secs),
        workload: Some("app-checkpoint".to_string()),
        brain: None,
        memory: None,
        agent: None,
        social: None,
        // No brain/wallet in the app-checkpoint demo → NIP-60 inactive.
        nip60: Default::default(),
        fleet_relay: String::new(),
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
        lease_fence: None,
    };
    let mut config = app_checkpoint_run::AppCheckpointRunConfig::new(boot_config);
    config.checkpoint_timeout = Duration::from_secs(args.checkpoint_secs);
    config.restore_timeout = Duration::from_secs(args.restore_secs);

    let outcome = app_checkpoint_run::run(config).await?;
    println!("{}", app_checkpoint_run::evidence_line(&outcome));

    if outcome.passed() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
