//! The eBPF egress-byte meter (spec 3.3, D-7, gate G4): the userspace side of
//! the aya TC classifier on the VM's TAP.
//!
//! The kernel program (the `kirby-ebpf` crate) is built by build.rs and EMBEDDED
//! in the daemon binary (`include_bytes!`), so it travels with the daemon and is
//! reproducible (gate G10). At runtime it is loaded and attached to the TAP's
//! clsact ingress hook (the VM-egress direction), and a single-slot map accumulates
//! the bytes the VM emits.
//!
//! PRIVILEGE (the D-7 boundary, not weakened): `unprivileged_bpf_disabled=2` on
//! this host, so loading/attaching eBPF and reading its map all need CAP_BPF, and
//! the daemon runs unprivileged (uid 1001). So ALL privileged BPF work is done in
//! a child process run through the SAME sudo path the jailer uses: the daemon
//! re-execs itself as `kirby-node ebpf-egress --iface <tap>` under sudo. That
//! child loads + attaches the classifier, then PRINTS the live cumulative byte
//! counter to stdout on a tick and stays alive (keeping the program attached)
//! until the daemon kills it. The unprivileged daemon reads the child's stdout to
//! learn how many IP bytes left the TAP, and bills them per-byte against the
//! treasury (the same counter CPU and memory debit, D-9). No capability is added
//! to the daemon, the jailer is untouched, and the privileged step is isolated.

use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The compiled kernel-side eBPF object (built by build.rs from crates/kirby-ebpf
/// for bpfel-unknown-none), embedded so it travels with the daemon.
pub const EGRESS_BPF_OBJECT: &[u8] = include_bytes!(env!("KIRBY_EGRESS_BPF_OBJECT"));

/// The map name and program name in the eBPF object (must match the kernel crate).
const EGRESS_MAP: &str = "EGRESS_BYTES";
const EGRESS_PROG: &str = "kirby_egress";

/// The TC attach direction for the egress meter (gate G4). It MUST be INGRESS:
/// for a TAP the packets the GUEST transmits (the VM's egress) arrive at the host
/// as the device's ingress, so the VM-egress bytes are counted on the ingress
/// hook. Attaching the EGRESS hook would only see host-to-guest traffic and would
/// silently meter ~0 for real VM egress (a leak the counter would not catch). A
/// single source of truth so a fast test can assert the direction without a
/// kernel, and `run_privileged_egress_meter` cannot drift from it.
pub const EGRESS_METER_DIRECTION: EgressMeterDirection = EgressMeterDirection::Ingress;

/// The direction the egress meter classifier attaches on the TAP. Mirrors the two
/// `aya::programs::TcAttachType` variants that matter here, kernel-free so it is
/// assertable in a fast test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMeterDirection {
    /// The host RX path: where a TAP sees the GUEST's transmitted (egress) bytes.
    Ingress,
    /// The host TX path: host-to-guest only (WRONG for metering VM egress).
    Egress,
}

/// The stdout line prefix the privileged child prints the running byte total on.
/// The daemon parses `EGRESS_BYTES <n>` lines to read the live counter.
const EGRESS_LINE_PREFIX: &str = "EGRESS_BYTES ";

/// A handle the daemon holds to the privileged eBPF-meter child. It exposes the
/// latest cumulative egress-byte count (read from the child's stdout stream) and
/// kills the child (detaching the classifier) on teardown.
pub struct EgressMeter {
    /// The child `kirby-node ebpf-egress` process, run via sudo.
    child: tokio::process::Child,
    /// The latest cumulative egress bytes the child reported. Updated by a
    /// background task reading the child's stdout.
    bytes: Arc<AtomicU64>,
    /// The sudo binary, so teardown can SIGKILL the privileged child (it runs as
    /// root, so the daemon kills it via sudo, not directly).
    sudo_bin: std::path::PathBuf,
    /// The child's pid (the actual privileged process is the sudo child; killing
    /// the whole process group is the reliable detach, mirroring firecracker.rs).
    child_pid: Option<u32>,
}

impl EgressMeter {
    /// Spawn the privileged eBPF egress meter for `iface` (the VM TAP), via sudo
    /// re-execing this same daemon binary as `ebpf-egress`. The child loads +
    /// attaches the classifier and streams the live byte counter; this returns
    /// once the child has reported it is attached (or errors if it does not).
    pub async fn spawn(
        iface: &str,
        sudo_bin: std::path::PathBuf,
        tick: Duration,
    ) -> anyhow::Result<Self> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        // The privileged child is the `kirby-node` daemon binary re-exec'd as
        // `ebpf-egress`. In the daemon, current_exe() IS kirby-node. Under a test
        // harness, current_exe() is the TEST binary (which has no ebpf-egress
        // subcommand), so resolve the real kirby-node binary instead (a sibling in
        // the cargo target dir, or the env override).
        let self_exe = resolve_daemon_binary()
            .map_err(|e| anyhow::anyhow!("resolve the kirby-node binary for the eBPF meter child: {e}"))?;

        // The privileged child: `sudo -n kirby-node ebpf-egress --iface <tap>
        // --tick-ms <ms>`. It loads + attaches the classifier and prints
        // `EGRESS_BYTES <n>` per tick. Run through the same NOPASSWD sudo path the
        // jailer uses (D-7); the daemon stays unprivileged.
        let mut cmd = tokio::process::Command::new(&sudo_bin);
        cmd.arg("-n")
            .arg(&self_exe)
            .arg("ebpf-egress")
            .arg("--iface")
            .arg(iface)
            .arg("--tick-ms")
            .arg(tick.as_millis().to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn privileged eBPF egress meter via sudo: {e}"))?;
        let child_pid = child.id();

        let bytes = Arc::new(AtomicU64::new(0));

        // Stream stderr to tracing (the child logs attach progress and errors).
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::info!(target: "ebpf_egress", "{line}");
                }
            });
        }

        // Read the child's stdout: `attached` once, then `EGRESS_BYTES <n>` per
        // tick. Update the shared counter. Wait here for the first `attached`
        // line (or a stdout EOF, meaning the child failed) before returning.
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("eBPF meter child has no stdout pipe"))?;
        let bytes_for_task = bytes.clone();
        let (attached_tx, attached_rx) = tokio::sync::oneshot::channel::<bool>();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            let mut attached_tx = Some(attached_tx);
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(rest) = line.strip_prefix(EGRESS_LINE_PREFIX) {
                    if let Ok(n) = rest.trim().parse::<u64>() {
                        bytes_for_task.store(n, Ordering::SeqCst);
                    }
                } else if line.trim() == "attached" {
                    if let Some(tx) = attached_tx.take() {
                        let _ = tx.send(true);
                    }
                }
            }
            // stdout closed: if we never signalled attached, signal failure.
            if let Some(tx) = attached_tx.take() {
                let _ = tx.send(false);
            }
        });

        // Wait for the attach confirmation (bounded). The classifier load +
        // attach is fast; if it does not confirm, surface a clear error.
        let attached = tokio::time::timeout(Duration::from_secs(15), attached_rx)
            .await
            .map_err(|_| anyhow::anyhow!("eBPF egress meter did not attach within 15s"))?
            .map_err(|_| anyhow::anyhow!("eBPF egress meter stdout closed before attaching"))?;
        if !attached {
            anyhow::bail!(
                "eBPF egress meter child exited before attaching (see the ebpf_egress log lines); \
                 is bpf-linker present and does the host allow CAP_BPF via sudo?"
            );
        }

        tracing::info!(iface, "eBPF egress meter attached (privileged child via sudo); billing egress bytes per-byte");
        Ok(EgressMeter { child, bytes, sudo_bin, child_pid })
    }

    /// The latest cumulative egress bytes the eBPF classifier counted on the TAP.
    /// For G4 this stays ~0 (the nftables drop means almost nothing flows; a
    /// denied genome egress attempt is a few unanswered SYN/DNS packets).
    pub fn egress_bytes(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }

    /// Kill the privileged child (detaching the classifier and dropping the TAP's
    /// clsact program). The child runs as root via sudo, so kill it via sudo.
    pub async fn shutdown(mut self) {
        if let Some(pid) = self.child_pid {
            // The tracked child is the sudo process; the privileged kirby-node it
            // launched is its child. SIGTERM the sudo child; sudo forwards it, and
            // kill_on_drop plus the process exit tears the rest down. Also kill
            // via sudo by pid as a backstop (the real worker may outlive sudo).
            let _ = std::process::Command::new(&self.sudo_bin)
                .arg("-n")
                .args(["pkill", "-TERM", "-P", &pid.to_string()])
                .status();
        }
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

/// Resolve the `kirby-node` daemon binary to re-exec as the privileged
/// `ebpf-egress` child. In the daemon `current_exe()` is already kirby-node and
/// is returned directly. Under a test harness `current_exe()` is the test binary
/// (in `target/<profile>/deps/`), which has no `ebpf-egress` subcommand, so we
/// look for the `kirby-node` binary as a sibling (the cargo bin lives one level
/// up from `deps/`, or beside the test binary). `KIRBY_NODE_BIN` overrides both.
fn resolve_daemon_binary() -> anyhow::Result<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("KIRBY_NODE_BIN") {
        return Ok(std::path::PathBuf::from(p));
    }
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("current_exe: {e}"))?;
    // Already the daemon binary?
    if exe.file_name().and_then(|n| n.to_str()) == Some("kirby-node") {
        return Ok(exe);
    }
    // Test/other binary: try a sibling, and the parent dir (cargo puts test
    // binaries under target/<profile>/deps/ and the bin under target/<profile>/).
    let dir = exe.parent().ok_or_else(|| anyhow::anyhow!("binary has no parent dir"))?;
    for cand in [dir.join("kirby-node"), dir.join("../kirby-node")] {
        if cand.is_file() {
            return Ok(cand);
        }
    }
    anyhow::bail!(
        "could not locate the kirby-node binary next to {} (set KIRBY_NODE_BIN, or build the daemon)",
        exe.display()
    )
}

/// The body of the privileged `kirby-node ebpf-egress` subcommand: load + attach
/// the embedded classifier to `iface`'s clsact ingress hook (the VM-egress direction), then print the live
/// byte counter to stdout every `tick`. This runs as ROOT (the daemon spawned it
/// via sudo); it does all the CAP_BPF work so the daemon never needs the cap.
/// It runs until killed (keeping the classifier attached); on exit the TC program
/// is detached by the kernel when the clsact qdisc is removed or the fd closes.
pub fn run_privileged_egress_meter(iface: &str, tick: Duration) -> anyhow::Result<()> {
    use aya::programs::{tc, SchedClassifier, TcAttachType};
    use aya::maps::Array;
    use aya::{Ebpf, EbpfLoader};
    use std::io::Write;

    // Load the embedded object (built for bpfel-unknown-none). IMPORTANT: copy the
    // embedded bytes into a heap Vec before loading. `include_bytes!` yields a
    // `&'static [u8]` that is only 1-byte aligned, but aya's ELF parser casts the
    // header to `Elf64_Ehdr` (8-byte alignment), so loading the static slice
    // directly fails with "Invalid ELF header size or alignment". A heap Vec is
    // suitably aligned, so this copy is the fix (the object is ~1.6 KiB, the copy
    // is free).
    let obj = EGRESS_BPF_OBJECT.to_vec();
    let mut ebpf: Ebpf = EbpfLoader::new()
        .load(&obj)
        .map_err(|e| anyhow::anyhow!("load embedded eBPF egress object: {e}"))?;

    // Ensure the clsact qdisc exists on the TAP (idempotent), then attach the
    // classifier to the INGRESS hook. clsact is the standard attach point for a
    // TC classifier (the spec's "TC classifier per TAP", D-7). The INGRESS hook
    // is where the VM's egress is seen: for a TAP, the packets the GUEST
    // transmits arrive at the host as the device's ingress (the host RX path), so
    // metering the VM's outbound bytes means classifying ingress (the egress hook
    // would only see host-to-guest traffic). This matches the nftables ingress
    // hook the lockdown uses (network::VmTap).
    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = ebpf
        .program_mut(EGRESS_PROG)
        .ok_or_else(|| anyhow::anyhow!("eBPF object has no `{EGRESS_PROG}` program"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("program `{EGRESS_PROG}` is not a classifier: {e}"))?;
    program
        .load()
        .map_err(|e| anyhow::anyhow!("load classifier into the kernel: {e}"))?;
    // The direction is the single source of truth EGRESS_METER_DIRECTION (G4): the
    // TAP's INGRESS hook is the VM-egress direction; the egress hook would only see
    // host-to-guest. Map the const to aya's attach type so the two cannot drift.
    let attach_type = match EGRESS_METER_DIRECTION {
        EgressMeterDirection::Ingress => TcAttachType::Ingress,
        EgressMeterDirection::Egress => TcAttachType::Egress,
    };
    program
        .attach(iface, attach_type)
        .map_err(|e| anyhow::anyhow!("attach classifier to {iface} ingress (the VM-egress direction): {e}"))?;

    // Signal the parent we are attached (the daemon waits for this line).
    println!("attached");
    let _ = std::io::stdout().flush();
    eprintln!("eBPF egress classifier attached to {iface} (clsact ingress, the VM-egress direction); counting bytes");

    // The byte-counter map (single slot). Read it each tick and print the total.
    let counter = Array::<_, u64>::try_from(
        ebpf.map(EGRESS_MAP)
            .ok_or_else(|| anyhow::anyhow!("eBPF object has no `{EGRESS_MAP}` map"))?,
    )
    .map_err(|e| anyhow::anyhow!("open `{EGRESS_MAP}` as an Array map: {e}"))?;

    // Print the live total on a tick until killed (or until the parent closes our
    // stdout, which we detect as a write error and exit cleanly). The daemon
    // parses these lines. Keeping this process alive keeps the classifier attached
    // (the program fd and the clsact attachment live as long as `ebpf` is in
    // scope). The daemon also kills us via sudo and deletes the TAP (which removes
    // the clsact qdisc) on teardown; this self-exit-on-broken-pipe is the backstop
    // so an orphaned child (sudo cannot forward SIGKILL) does not linger.
    let mut out = std::io::stdout();
    loop {
        let total: u64 = counter.get(&0, 0).unwrap_or(0);
        if writeln!(out, "{EGRESS_LINE_PREFIX}{total}").is_err() || out.flush().is_err() {
            // The parent closed our stdout: it has torn us down. Exit cleanly so
            // the Ebpf handle drops and the classifier detaches.
            eprintln!("eBPF egress meter: parent closed stdout, exiting (classifier detaches)");
            return Ok(());
        }
        std::thread::sleep(tick);
    }
}
