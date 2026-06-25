//! The kirby-node daemon binary (spec 5).
//!
//! A thin CLI over the `kirby_node` library: it parses arguments and drives the
//! library modules (the host-prereqs gate, the persisted treasury, the vsock
//! NodeGateway). One Tokio process per node. The VM-boot loop that drives a
//! genome to connect is C-2; the meters (C-4), egress (C-5), real rail (C-6),
//! and openraft lease (C-9) land in later chunks.

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
    #[command(subcommand)]
    command: Command,
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
        /// Path to the `kirby run` config file (TOML, e.g. `kirby.toml`).
        #[arg(long, default_value = "kirby.toml")]
        config: std::path::PathBuf,
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
        /// tenants to host.
        #[arg(long, default_value = "kirby.toml")]
        config: std::path::PathBuf,
        /// This node's lease id within the agents' cluster (the supervisor grants each
        /// tenant's lease to this id). The MVP forms a single-node lease cluster.
        #[arg(long, default_value_t = 1)]
        node_id: u64,
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

    match cli.command {
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
        Command::EbpfEgress { iface, tick_ms } => run_ebpf_egress(iface, tick_ms),
    }
}

/// The `kirby run` keystone: load the config, then run the sovereign-agent sequence
/// (identity, fleet-join, bootstrap-or-resume, boot, meter, die). Prints the gate
/// evidence line. Exits non-zero if the agent never reached Running so the keeper's
/// harness run fails loudly on a broken boot.
#[tokio::main]
async fn run_agent_cmd(config_path: std::path::PathBuf, no_frost: bool) -> anyhow::Result<()> {
    use kirby_node::config::KirbyConfig;
    use kirby_node::run_agent::{self, RunAgentConfig};

    let config = KirbyConfig::load(&config_path)?;
    tracing::info!(path = %config_path.display(), "loaded kirby run config");
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
    config_path: std::path::PathBuf,
    node_id: u64,
) -> anyhow::Result<()> {
    use std::sync::Arc;
    use std::time::Duration;

    use kirby_node::config::KirbyConfig;
    use kirby_node::fleet::Allocator;
    use kirby_node::fleet_supervisor::{FleetSupervisor, ProcessTenantLauncher};
    use kirby_node::raft_lease::LeaseNode;

    let config = KirbyConfig::load(&config_path)?;
    tracing::info!(path = %config_path.display(), tenants = config.fleet.tenants.len(), "loaded fleet config");

    // Form a single-node lease cluster for the supervisor (the agents' cluster). A real
    // multi-node fleet adds peers here; the MVP is single-node so the supervisor is leader
    // and can grant per-agent leases. A loopback port the OS picks.
    let lease_node = LeaseNode::start(node_id, "127.0.0.1:0").await?;
    lease_node
        .initialize_cluster(&[(node_id, lease_node.addr().to_string())])
        .await?;
    lease_node
        .wait_for_leader(Duration::from_secs(10))
        .await
        .ok_or_else(|| anyhow::anyhow!("fleet supervisor: lease cluster did not elect a leader"))?;

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

    // The real launcher spawns each tenant as a child `kirby agent` (the existing
    // single-agent path) with the allocated CID/port; derived per-tenant configs land under
    // the node's config dir.
    let binary = std::env::current_exe()?;
    let config_dir = alloc_dir.join("fleet-tenant-configs");
    let launcher = Arc::new(ProcessTenantLauncher::new(config.clone(), binary, config_dir));
    let grantor = Arc::new(lease_node);

    let mut supervisor = FleetSupervisor::new(node_id, config, allocator, grantor, launcher);
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
    println!("FLEET supervisor: {} tenant(s) launched, monitoring lifecycle", records.len());

    // Monitor: report dead tenants on a tick (the failover hook for S5/S6; S2 only tracks).
    // Runs until killed; exits cleanly when all tenants have died (nothing left to host).
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let dead = supervisor.dead_tenants();
        for agent_id in &dead {
            tracing::warn!(agent_id, "FLEET tenant EXITED (failover hook for S5/S6; S2 tracks only)");
        }
        if !dead.is_empty() && dead.len() == supervisor.tenant_count() {
            // Before shutting down, REAP every exited tenant so the persisted allocator does
            // not retain slots marked LIVE for dead CIDs/ports. Without this, a supervisor
            // restart would reload those slots as live and never re-hand them (leaked across
            // the restart).
            let reaped = supervisor.reap_dead();
            tracing::info!(
                reaped = reaped.len(),
                "FLEET supervisor: all tenants have exited; reaped dead allocator slots, shutting down"
            );
            return Ok(());
        }
    }
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

    // The node state directory (the treasury dir): also the default home for the
    // node's Nostr identity key. Default to a per-node directory under the OS temp
    // dir so two node processes on one host stay distinct (D-13 same-host harness).
    let treasury_path = args
        .treasury_path
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join(format!("kirby-treasury-{}", args.node_id)));

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
