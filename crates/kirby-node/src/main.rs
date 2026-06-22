//! The kirby-node daemon binary (spec 5).
//!
//! A thin CLI over the `kirby_node` library: it parses arguments and drives the
//! library modules (the host-prereqs gate, the persisted treasury, the vsock
//! NodeGateway). One Tokio process per node. The VM-boot loop that drives a
//! genome to connect is C-2; the meters (C-4), egress (C-5), real rail (C-6),
//! and openraft lease (C-9) land in later chunks.

use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use kirby_node::metered_run;
use kirby_node::{app_checkpoint_run, boot, gateway, nerve, prereqs, rail, treasury};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use kirby_node::{brokered_run, mint_rig};
#[cfg(target_os = "linux")]
use kirby_node::{egress_run, snapshot_run};

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
    /// Meter the genome microVM and HALT it on budget exhaustion (gate G2). The
    /// daemon boots the VM under the jailer, places it in a dedicated cgroup
    /// under the daemon's delegated user slice, runs the burn workload in the
    /// genome (allocate memory + spin CPU), meters CPU + memory on a tick against
    /// the treasury, and when cumulative burn reaches the budget PAUSES then
    /// KILLS the VM (daemon-initiated), recording terminated:budget_exhausted.
    /// Prints the G2 evidence (terminal state, metered burn ~= budget, remaining
    /// ~= 0, tick granularity). Egress-byte metering is deferred to C-5 (it rides
    /// with the per-VM TAP).
    Meter {
        /// The genome image directory (the `nix build .#genome-image` output).
        /// Defaults to the KIRBY_GENOME_IMAGE env var if set.
        #[arg(long)]
        image_dir: Option<std::path::PathBuf>,
        /// This node's id (distinguishes per-node treasury, jail, CID, cgroup).
        #[arg(long, default_value = "node-1")]
        node_id: String,
        /// The session task descriptor handed to the genome at boot.
        #[arg(long, default_value = "kirby-burn-stub")]
        task: String,
        /// The budget in sats. The VM is halted when metered burn reaches it.
        /// Also the treasury initial balance (so exhausting the budget drains the
        /// treasury to ~0, gate G2). Small so the run is quick.
        #[arg(long, default_value_t = 3_000)]
        budget_sats: u64,
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
        /// The metering tick in milliseconds. The halt is accurate to one tick.
        #[arg(long, default_value_t = 100)]
        tick_ms: u64,
        /// Seconds to wait for the genome's boot hello before metering.
        #[arg(long, default_value_t = 30)]
        hello_timeout_secs: u64,
        /// A safety ceiling in seconds: a run that never exhausts the budget
        /// (e.g. a non-burning genome) stops here rather than looping forever.
        #[arg(long, default_value_t = 120)]
        max_run_secs: u64,
    },
    /// Prove the per-VM egress lockdown and the egress-byte meter (gate G4). The
    /// daemon creates a per-VM TAP, locks it down with nftables default-deny
    /// egress (spec 3.7), wires it into the microVM, attaches the aya/eBPF TC
    /// classifier (egress-byte meter), and boots the genome with the raw-egress
    /// workload (attempt direct outbound). It asserts the attempts FAILED, the
    /// host nftables drop counter shows the drop, and the eBPF egress counter
    /// shows ~0 IP bytes left the TAP. Prints the G4 evidence, then halts the VM.
    Egress {
        /// The genome image directory (the `nix build .#genome-image` output).
        /// Defaults to the KIRBY_GENOME_IMAGE env var if set.
        #[arg(long)]
        image_dir: Option<std::path::PathBuf>,
        /// This node's id (distinguishes per-node TAP, jail, CID, cgroup).
        #[arg(long, default_value = "node-1")]
        node_id: String,
        /// The session task descriptor handed to the genome at boot.
        #[arg(long, default_value = "kirby-egress-stub")]
        task: String,
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
        /// Seconds to wait for the genome's boot hello before probing egress.
        #[arg(long, default_value_t = 30)]
        hello_timeout_secs: u64,
        /// Seconds to let the genome's egress probes run (and the meters settle)
        /// before reading the counters and halting.
        #[arg(long, default_value_t = 12)]
        probe_secs: u64,
    },
    /// Prove the brokered act (gate G5): the daemon performs a REAL ecash settle on
    /// a local CDK fakewallet mint over its OWN host networking, using a host-held
    /// credential (a funded cashu wallet) the genome never sees, metered +
    /// treasury-debited, with the sandboxed VM issuing ZERO raw network. The genome
    /// issues a `RequestCapability` ecash settle over vsock; the daemon authorizes
    /// it (the 5-step order), performs the real melt against the mint, meters +
    /// debits it, and returns the receipt. Linux proves raw-egress absence with the
    /// eBPF TAP meter. macOS VZ proves the MVP shape structurally by booting with no
    /// guest network device. The mint URL is passed as `--mint-url`; this subcommand
    /// expects a mint already running (the G5 TEST boots its own mint).
    Brokered {
        /// The genome image directory (the `nix build .#genome-image` output).
        /// Defaults to the KIRBY_GENOME_IMAGE env var if set.
        #[arg(long)]
        image_dir: Option<std::path::PathBuf>,
        /// The local CDK mint URL to settle against (e.g. http://127.0.0.1:8086).
        /// The daemon funds a wallet on it and settles a small amount. The mint
        /// must already be running.
        #[arg(long)]
        mint_url: String,
        /// The sats to fund the daemon's wallet with before the settle.
        #[arg(long, default_value_t = 1000)]
        fund_sats: u64,
        /// This node's id (distinguishes per-node TAP, jail, CID, cgroup).
        #[arg(long, default_value = "node-1")]
        node_id: String,
        /// The session task descriptor handed to the genome at boot.
        #[arg(long, default_value = "kirby-brokered-stub")]
        task: String,
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
        /// Seconds to wait for the genome's boot hello before the brokered act.
        #[arg(long, default_value_t = 30)]
        hello_timeout_secs: u64,
        /// Seconds to let the brokered act and the meters settle before reading
        /// the counters and halting.
        #[arg(long, default_value_t = 30)]
        act_secs: u64,
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
    /// Prove snapshot + cross-node resume (gate G6), the spike's hardest seam. The
    /// daemon boots the genome microVM on "node 1" (CPU-template normalized so the
    /// snapshot restores on a compatible different CPU), SNAPSHOTS the running VM
    /// (pause + mem+vmstate pair), TRANSFERS the pair to "node 2" (a second jail/dir
    /// on this host, the D-13 same-host seam), KILLS node 1's VMM, and "node 2"
    /// RESTORES a fresh jailed VMM from the transferred pair and resumes it. The
    /// genome continues ALIVE across the move: its vsock dropped, so it re-dials the
    /// node-2 gateway and completes a post-resume round-trip (the survival proof).
    /// The VMGenID generation bumps on restore (the C-8 re-derive hook). The single
    /// persisted treasury continues across the move (D-9). Prints the G6 evidence,
    /// then halts both VMs.
    Snapshot {
        /// The genome image directory (the `nix build .#genome-image` output).
        /// Defaults to the KIRBY_GENOME_IMAGE env var if set.
        #[arg(long)]
        image_dir: Option<std::path::PathBuf>,
        /// Node 1's id (distinguishes its jail, cgroup, CID; node 2 derives its own).
        #[arg(long, default_value = "node-1")]
        node_id: String,
        /// The session task descriptor handed to the genome at boot.
        #[arg(long, default_value = "kirby-snapshot-stub")]
        task: String,
        /// The vsock guest CID for node 1's VM (>= 3; node 2 reuses it after node 1
        /// is killed, so the two never run at once on the same CID).
        #[arg(long, default_value_t = 3)]
        vsock_cid: u32,
        /// The vsock port node 1's gateway serves on. Node 2 serves on this + 1.
        #[arg(long, default_value_t = 5000)]
        vsock_port: u32,
        /// vCPU count for the microVM.
        #[arg(long, default_value_t = 1)]
        vcpu_count: u8,
        /// Memory for the microVM, in MiB. Smaller = a smaller snapshot pair.
        #[arg(long, default_value_t = 128)]
        mem_mib: usize,
        /// Seconds to wait for node 1's pre-snapshot heartbeat round-trip.
        #[arg(long, default_value_t = 40)]
        pre_snapshot_secs: u64,
        /// Seconds to wait for node 2's post-resume heartbeat round-trip.
        #[arg(long, default_value_t = 40)]
        post_resume_secs: u64,
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
        Command::Meter {
            image_dir,
            node_id,
            task,
            budget_sats,
            vsock_cid,
            vsock_port,
            vcpu_count,
            mem_mib,
            tick_ms,
            hello_timeout_secs,
            max_run_secs,
        } => {
            init_tracing();
            run_meter(MeterArgs {
                image_dir,
                node_id,
                task,
                budget_sats,
                vsock_cid,
                vsock_port,
                vcpu_count,
                mem_mib,
                tick_ms,
                hello_timeout_secs,
                max_run_secs,
            })
        }
        Command::Egress {
            image_dir,
            node_id,
            task,
            vsock_cid,
            vsock_port,
            vcpu_count,
            mem_mib,
            hello_timeout_secs,
            probe_secs,
        } => {
            init_tracing();
            run_egress(EgressArgs {
                image_dir,
                node_id,
                task,
                vsock_cid,
                vsock_port,
                vcpu_count,
                mem_mib,
                hello_timeout_secs,
                probe_secs,
            })
        }
        Command::Brokered {
            image_dir,
            mint_url,
            fund_sats,
            node_id,
            task,
            vsock_cid,
            vsock_port,
            vcpu_count,
            mem_mib,
            hello_timeout_secs,
            act_secs,
        } => {
            init_tracing();
            run_brokered(BrokeredArgs {
                image_dir,
                mint_url,
                fund_sats,
                node_id,
                task,
                vsock_cid,
                vsock_port,
                vcpu_count,
                mem_mib,
                hello_timeout_secs,
                act_secs,
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
        Command::Snapshot {
            image_dir,
            node_id,
            task,
            vsock_cid,
            vsock_port,
            vcpu_count,
            mem_mib,
            pre_snapshot_secs,
            post_resume_secs,
        } => {
            init_tracing();
            run_snapshot(SnapshotArgs {
                image_dir,
                node_id,
                task,
                vsock_cid,
                vsock_port,
                vcpu_count,
                mem_mib,
                pre_snapshot_secs,
                post_resume_secs,
            })
        }
        Command::Agent { config } => {
            init_tracing();
            run_agent_cmd(config)
        }
        Command::EbpfEgress { iface, tick_ms } => run_ebpf_egress(iface, tick_ms),
    }
}

/// The `kirby run` keystone: load the config, then run the sovereign-agent sequence
/// (identity, fleet-join, bootstrap-or-resume, boot, meter, die). Prints the gate
/// evidence line. Exits non-zero if the agent never reached Running so the keeper's
/// harness run fails loudly on a broken boot.
#[tokio::main]
async fn run_agent_cmd(config_path: std::path::PathBuf) -> anyhow::Result<()> {
    use kirby_node::config::KirbyConfig;
    use kirby_node::run_agent::{self, RunAgentConfig};

    let config = KirbyConfig::load(&config_path)?;
    tracing::info!(path = %config_path.display(), "loaded kirby run config");
    let run = RunAgentConfig::from_config(config)?;
    let outcome = run_agent::run(run).await?;
    println!("{}", run_agent::evidence_line(&outcome));
    if outcome.reached_running {
        Ok(())
    } else {
        std::process::exit(1);
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
        let task = tokio::spawn(nerve::run_presence(identity, cfg, shutdown_rx));
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
        let handle = tokio::spawn(nerve::run_presence(identity, cfg, rx));
        presence_handle = Some((tx, handle));
    }

    // Build the gateway service over the treasury and a rail. C-3 ships the mock
    // rail; C-6 swaps in the real rail (the CDK mint, D-16). The session is
    // the non-secret snapshot the genome pulls at boot.
    let session = gateway::Session {
        task_descriptor: args.task,
        budget_sats: args.budget_sats,
        allowlisted_destinations: args.allow,
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
        // G1 is vsock-only (no TAP); the egress lockdown is the `egress`
        // subcommand (C-5, G4).
        lockdown_egress: false,
        // G1 does not snapshot (no CPU template); snapshot is the `snapshot`
        // subcommand (C-7, G6).
        snapshot_capable: false,
        restore_checkpoint: None,
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

/// Parsed `meter` arguments.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
struct MeterArgs {
    image_dir: Option<std::path::PathBuf>,
    node_id: String,
    task: String,
    budget_sats: u64,
    vsock_cid: u32,
    vsock_port: u32,
    vcpu_count: u8,
    mem_mib: usize,
    tick_ms: u64,
    hello_timeout_secs: u64,
    max_run_secs: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::main]
async fn run_meter(args: MeterArgs) -> anyhow::Result<()> {
    // The daemon refuses to run on a host that fails the prereqs gate.
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

    // Budget == initial treasury, so exhausting the budget drains the treasury
    // to ~0 (gate G2). The genome runs the burn workload so the meter reads real
    // CPU + memory usage.
    let boot_config = boot::BootConfig {
        image,
        node_id: args.node_id,
        task: args.task,
        budget_sats: args.budget_sats,
        initial_sats: args.budget_sats,
        allow: vec!["mint.test.local".to_string()],
        guest_cid: args.vsock_cid,
        gateway_port: args.vsock_port,
        vcpu_count: args.vcpu_count,
        mem_size_mib: args.mem_mib,
        hello_timeout: Duration::from_secs(args.hello_timeout_secs),
        workload: Some("burn".to_string()),
        brain: None,
        // G2 meters CPU + memory; the egress meter rides with the TAP in the
        // `egress` subcommand (C-5, G4). Vsock-only here.
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    let config = metered_run::MeteredRunConfig {
        boot: boot_config,
        tick: Duration::from_millis(args.tick_ms),
        max_run: Duration::from_secs(args.max_run_secs),
        // The standalone `metered-run` subcommand is the G2 gate harness, not a
        // fleet member: no 31000 agent-state emission (that is `kirby run`).
        agent_state: None,
    };

    let outcome = metered_run::run(config).await?;

    // The G2 verdict line for the verifier.
    let exhausted = outcome.terminated == metered_run::Terminated::BudgetExhausted;
    println!(
        "G2 {}: terminal={:?} ; metered_burn_sats={} (budget={}) ; remaining_at_halt={} ; \
         daemon_initiated_kill={} ; metered_cpu_usec={} ; ticks={} ; tick_granularity_ms={}",
        if exhausted { "PASS" } else { "FAIL" },
        outcome.terminated,
        outcome.burned_sats,
        outcome.budget_sats,
        outcome.remaining_at_halt,
        outcome.daemon_initiated_kill,
        outcome.cpu_usec,
        outcome.ticks,
        outcome.tick.as_millis(),
    );

    if exhausted {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run_meter(_args: MeterArgs) -> anyhow::Result<()> {
    anyhow::bail!("`kirby-node meter` is only supported on Linux/Firecracker and macOS/VZ")
}

/// Parsed `egress` arguments.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct EgressArgs {
    image_dir: Option<std::path::PathBuf>,
    node_id: String,
    task: String,
    vsock_cid: u32,
    vsock_port: u32,
    vcpu_count: u8,
    mem_mib: usize,
    hello_timeout_secs: u64,
    probe_secs: u64,
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn run_egress(args: EgressArgs) -> anyhow::Result<()> {
    // The daemon refuses to run on a host that fails the prereqs gate.
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

    // The egress run forces the per-VM TAP lockdown and the raw-egress workload.
    // The allowlist is irrelevant here (no brokered act, C-6); a placeholder
    // keeps the session well-formed.
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
        hello_timeout: Duration::from_secs(args.hello_timeout_secs),
        // Forced on by EgressRunConfig::new, set here for clarity.
        workload: Some("raw-egress".to_string()),
        brain: None,
        lockdown_egress: true,
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    let config =
        egress_run::EgressRunConfig::new(boot_config, Duration::from_secs(args.probe_secs));

    let outcome = egress_run::run(config).await?;

    // The "~0 IP bytes left the TAP" ceiling (shared with the G4 test).
    let ebpf_zero_ceiling = egress_run::EBPF_ZERO_CEILING_BYTES;
    let passed = outcome.passed(ebpf_zero_ceiling);

    // The G4 evidence lines for the verifier.
    println!(
        "G4 {}: raw_egress_denied={} ; nft_drop_packets={} ; nft_drop_bytes={} ; \
         ebpf_egress_bytes={} (<= {ebpf_zero_ceiling} = about 0 IP bytes left the TAP)",
        if passed { "PASS" } else { "FAIL" },
        outcome.raw_egress_denied,
        outcome.nft_drop.packets,
        outcome.nft_drop.bytes,
        outcome.ebpf_egress_bytes,
    );
    println!("  genome result: {}", outcome.result_detail);
    for probe in &outcome.probe_details {
        println!("  probe: {probe}");
    }

    if passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run_egress(_args: EgressArgs) -> anyhow::Result<()> {
    anyhow::bail!("`kirby-node egress` is Linux-only until the VZ pf/vmnet egress path lands")
}

/// Parsed `brokered` arguments.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
struct BrokeredArgs {
    image_dir: Option<std::path::PathBuf>,
    mint_url: String,
    fund_sats: u64,
    node_id: String,
    task: String,
    vsock_cid: u32,
    vsock_port: u32,
    vcpu_count: u8,
    mem_mib: usize,
    hello_timeout_secs: u64,
    act_secs: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::main]
async fn run_brokered(args: BrokeredArgs) -> anyhow::Result<()> {
    use std::sync::Arc;

    // The daemon refuses to run on a host that fails the prereqs gate.
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

    // Build + fund the daemon's wallet on the local mint (the rail credential,
    // host-only, never crosses vsock). Then the real rail over it.
    tracing::info!(mint = %args.mint_url, fund_sats = args.fund_sats, "funding the daemon wallet on the local mint");
    let wallet = mint_rig::build_wallet(&args.mint_url).await?;
    mint_rig::fund_wallet(wallet.clone(), args.fund_sats).await?;
    let funded = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    tracing::info!(balance = funded, "daemon wallet funded");
    let cdk_rail = Arc::new(rail::CdkEcashRail::new(
        wallet.clone(),
        args.mint_url.clone(),
    ));

    // The allowlist contains the mint URL so the brokered act authorizes (step 2).
    // The backend raw-egress profile + the `brokered` workload are forced on by
    // BrokeredRunConfig: Linux uses locked-down TAP/eBPF evidence; macOS VZ uses
    // the no-guest-network-device MVP proof.
    let boot_config = boot::BootConfig {
        image,
        node_id: args.node_id,
        task: args.task,
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec![args.mint_url.clone()],
        guest_cid: args.vsock_cid,
        gateway_port: args.vsock_port,
        vcpu_count: args.vcpu_count,
        mem_size_mib: args.mem_mib,
        hello_timeout: Duration::from_secs(args.hello_timeout_secs),
        workload: Some("brokered".to_string()),
        brain: None,
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    let config =
        brokered_run::BrokeredRunConfig::new(boot_config, Duration::from_secs(args.act_secs));
    let rail_dyn: Arc<dyn rail::Rail> = cdk_rail.clone();
    let outcome = brokered_run::run(config, rail_dyn).await?;

    let ebpf_zero_ceiling = brokered_egress_zero_ceiling();
    let passed = outcome.passed(ebpf_zero_ceiling);

    // The G5 evidence lines for the verifier.
    println!(
        "G5 {}: performed={} ; cost_sats={} ; treasury_before={} ; treasury_after={} ; \
         treasury_drop={} ; ebpf_egress_bytes={} (<= {ebpf_zero_ceiling}) ; raw_egress={} ; proof_len={}",
        if passed { "PASS" } else { "FAIL" },
        outcome.receipt.performed,
        outcome.receipt.cost_sats,
        outcome.treasury_before,
        outcome.treasury_after,
        outcome.treasury_drop(),
        outcome.ebpf_egress_bytes,
        outcome.raw_egress.summary(ebpf_zero_ceiling),
        outcome.receipt.proof_len,
    );
    println!("  genome result: {}", outcome.receipt.result_detail);

    // (ii) the REAL settle: the mint shows the wallet's input proofs spent.
    if let Ok(proofs) = cdk_rail.wallet().get_unspent_proofs().await {
        println!(
            "  wallet balance after settle: {} sat (was {funded})",
            cdk_rail.wallet_balance_sats().await
        );
        let _ = proofs; // unspent remaining; the spent ones are gone from the wallet
    }

    if passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn brokered_egress_zero_ceiling() -> u64 {
    egress_run::EBPF_ZERO_CEILING_BYTES
}

#[cfg(target_os = "macos")]
fn brokered_egress_zero_ceiling() -> u64 {
    0
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run_brokered(_args: BrokeredArgs) -> anyhow::Result<()> {
    anyhow::bail!("`kirby-node brokered` is only supported on Linux/Firecracker and macOS/VZ")
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
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
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

/// Parsed `snapshot` arguments.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct SnapshotArgs {
    image_dir: Option<std::path::PathBuf>,
    node_id: String,
    task: String,
    vsock_cid: u32,
    vsock_port: u32,
    vcpu_count: u8,
    mem_mib: usize,
    pre_snapshot_secs: u64,
    post_resume_secs: u64,
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn run_snapshot(args: SnapshotArgs) -> anyhow::Result<()> {
    // The daemon refuses to run on a host that fails the prereqs gate.
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

    // Node 1's boot config. SnapshotRunConfig::new forces snapshot_capable + the
    // `snapshot` heartbeat workload and derives node 2's id/port/inbox.
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
        hello_timeout: Duration::from_secs(args.pre_snapshot_secs),
        // Forced on by SnapshotRunConfig::new, set here for clarity.
        workload: Some("snapshot".to_string()),
        brain: None,
        // G6 is vsock-only (the egress lockdown is G4); the restore re-wires a
        // fresh TAP only if this is true. Vsock-only keeps the demo lean.
        lockdown_egress: false,
        snapshot_capable: true,
        restore_checkpoint: None,
    };

    let mut config = snapshot_run::SnapshotRunConfig::new(boot_config);
    config.pre_snapshot_timeout = Duration::from_secs(args.pre_snapshot_secs);
    config.post_resume_timeout = Duration::from_secs(args.post_resume_secs);

    let outcome = snapshot_run::run(config).await?;
    let passed = outcome.passed();

    // The G6 evidence lines for the verifier.
    println!(
        "G6 {}: node2_reached_running={} ; post_resume_round_trip={} ; node1_killed={} ; \
         generation {} -> {} (bumped on restore) ; treasury {} -> {} (continued, D-9) ; \
         snapshot_bytes={}",
        if passed { "PASS" } else { "FAIL" },
        outcome.node2_reached_running,
        outcome.post_resume_round_trip,
        outcome.node1_killed,
        outcome.generation_pre,
        outcome.generation_post,
        outcome.treasury_pre,
        outcome.treasury_post,
        outcome.snapshot_bytes,
    );
    if let Some(detail) = &outcome.post_resume_detail {
        println!("  node 2 post-resume heartbeat: {detail}");
    }

    if passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run_snapshot(_args: SnapshotArgs) -> anyhow::Result<()> {
    anyhow::bail!(
        "`kirby-node snapshot` is Linux/Firecracker-only; macOS resume uses app checkpoints"
    )
}
