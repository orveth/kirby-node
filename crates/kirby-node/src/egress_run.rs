//! The egress-lockdown demonstration and its G4 evidence (spec 3.7, 3.3, gate
//! G4). Shared by the `egress` subcommand and the G4 integration test so both
//! drive the SAME path.
//!
//! The flow: boot the genome with a per-VM TAP wired and locked down (nftables
//! default-deny egress), attach the aya/eBPF TC egress-byte classifier to the
//! TAP, and run the genome's raw-egress workload (it ATTEMPTS direct outbound:
//! connect to an external IP, hit 1.1.1.1, resolve a name). Then gather the G4
//! evidence:
//!   - the genome's raw-egress probes FAILED (its `raw_egress_result` event says
//!     DENIED: every direct outbound failed), reported over vsock (the only
//!     channel that works, which is itself the proof isolation holds);
//!   - the host nftables drop counter shows a non-zero drop (the host kernel
//!     dropped the VM's egress attempt);
//!   - the eBPF egress counter shows ~0 IP bytes left the TAP (nothing flowed).
//!
//! The VM is always halted (and the TAP plus nftables torn down) before
//! returning, including on the error path.

use std::time::Duration;

use kirby_proto::Event;

use crate::boot::{self, BootConfig};
use crate::meter_egress::EgressMeter;
use crate::sandbox::EgressDropCounter;

/// The "~0 IP bytes left the TAP" ceiling for G4 (spec 7). The genome's denied
/// egress attempt is a handful of unanswered SYN/ARP/DNS packets (well under a
/// KiB even with TCP SYN retransmits over the probe window); a flowing connection
/// would be kilobytes of payload and more. 8 KiB is a generous ceiling that still
/// separates "blocked" from "leaked" by orders of magnitude. Shared by the
/// `egress` subcommand and the G4 test so the bar is one number.
pub const EBPF_ZERO_CEILING_BYTES: u64 = 8192;

/// The G4 evidence from an egress-lockdown run.
#[derive(Debug, Clone)]
pub struct EgressRunOutcome {
    /// The genome reported its raw-egress probes were all DENIED (no leak). This
    /// is parsed from its `raw_egress_result` event (true = every direct outbound
    /// failed). If the genome never reported, this is false and `result_detail`
    /// says so (a G4 failure: we could not confirm the attempts failed).
    pub raw_egress_denied: bool,
    /// The genome's raw-egress result detail line (the evidence text).
    pub result_detail: String,
    /// Every raw-egress probe outcome the genome reported (each per-probe line).
    pub probe_details: Vec<String>,
    /// The host-kernel egress drop counter for the guest (packets, bytes).
    /// Non-zero packets is the host-kernel-enforced drop evidence (G4). On
    /// Firecracker this is the nftables `dropped_egress` counter, surfaced through
    /// the backend-neutral `EgressControl`.
    pub nft_drop: EgressDropCounter,
    /// The eBPF classifier's cumulative egress bytes the VM put on its TAP (the
    /// bytes it ATTEMPTED to egress, counted at the TAP ingress before nftables
    /// drops them). ~0 under the lockdown (G4: about 0 IP bytes, a few unanswered
    /// SYN/DNS packets, never a flowing connection).
    pub ebpf_egress_bytes: u64,
}

impl EgressRunOutcome {
    /// The G4 pass predicate: the genome's attempts were denied (no leak), the
    /// host nftables drop counter fired (the kernel dropped the egress), and the
    /// eBPF counter shows ~0 IP bytes (no real traffic flowed). The "~0" ceiling
    /// is generous (a couple KiB): the few unanswered SYN/ARP/DNS packets the VM
    /// emits before giving up are within it; a flowing connection (kilobytes of
    /// payload) is not. The eBPF and nftables counters tell the same story (the
    /// attempted bytes were all dropped).
    pub fn passed(&self, ebpf_zero_ceiling: u64) -> bool {
        self.raw_egress_denied
            && self.nft_drop.packets > 0
            && self.ebpf_egress_bytes <= ebpf_zero_ceiling
    }
}

/// Inputs for an egress-lockdown run (reuses the boot config). `lockdown_egress`
/// and the raw-egress workload are forced on here, so the caller need not set
/// them.
pub struct EgressRunConfig {
    pub boot: BootConfig,
    /// How long to let the genome's probes run and the meters settle before
    /// reading the counters.
    pub probe_window: Duration,
    /// The eBPF reporting tick for the privileged meter child.
    pub egress_tick: Duration,
}

impl EgressRunConfig {
    /// Build an egress-run config from a boot config, forcing the per-VM TAP
    /// lockdown on and the genome's raw-egress workload.
    pub fn new(mut boot: BootConfig, probe_window: Duration) -> Self {
        boot.lockdown_egress = true;
        boot.workload = Some("raw-egress".to_string());
        EgressRunConfig { boot, probe_window, egress_tick: Duration::from_millis(100) }
    }
}

/// Boot the locked-down VM, run the genome's raw-egress probes, and gather the G4
/// evidence. Always halts the VM (and tears down the TAP plus nftables) before
/// returning.
pub async fn run(config: EgressRunConfig) -> anyhow::Result<EgressRunOutcome> {
    let probe_window = config.probe_window;
    let egress_tick = config.egress_tick;

    // Boot with the TAP wired and locked down; keep the event stream so we can
    // read the genome's raw-egress probe outcomes.
    let (vm, outcome, _treasury, mut events, _serve_guard) =
        boot::boot_and_observe(config.boot).await?;
    if !outcome.reached_running {
        vm.halt().await;
        anyhow::bail!("egress run: VM did not reach Running");
    }

    // The egress control must exist (lockdown_egress was forced on). Resolve the
    // metered interface name and the sudo path so we can attach the eBPF egress
    // meter and read the drop counter. The interface is the backend's (a TAP on
    // Firecracker); the eBPF meter and the drop-counter read go through the
    // backend-neutral EgressControl.
    let tap_name = match vm.egress_control() {
        Some(egress) => egress.iface_name().to_string(),
        None => {
            vm.halt().await;
            anyhow::bail!("egress run: no egress control on the guest (lockdown_egress was not honored)");
        }
    };
    // The same working passwordless sudo the jailer launches through, discovered
    // at runtime (the D-7 boundary, not weakened); fails loud if none is found.
    // (On the real path this always resolves, since the VM only booted because
    // the backend resolved it; halt-then-bail to match the early-error idiom.)
    let sudo_bin = match crate::prereqs::resolve_sudo() {
        Ok(s) => s,
        Err(e) => {
            vm.halt().await;
            return Err(e.context("egress run: could not resolve sudo for the eBPF egress meter"));
        }
    };

    // Attach the aya/eBPF egress-byte meter to the TAP (the privileged child via
    // sudo). If it cannot attach, that is a hard error (the egress meter is part
    // of the G4 contract); halt and surface it.
    let egress_meter = match EgressMeter::spawn(&tap_name, sudo_bin, egress_tick).await {
        Ok(m) => m,
        Err(e) => {
            vm.halt().await;
            return Err(anyhow::anyhow!("egress run: eBPF egress meter attach failed: {e}"));
        }
    };

    tracing::info!(
        tap = %tap_name,
        "egress lockdown in force (nftables default-deny + eBPF meter); genome attempting raw egress (must fail, G4)"
    );

    // Collect the genome's raw-egress probe outcomes over the probe window. The
    // genome reports each probe (`raw_egress_attempt`) then a summary
    // (`raw_egress_result`); we key the verdict on the summary.
    let (raw_egress_denied, result_detail, probe_details) =
        collect_egress_outcome(&mut events, probe_window).await;

    // Read the G4 counters: the host-kernel egress drop counter (the kernel
    // dropped the VM's egress) and the eBPF egress byte counter (~0 IP bytes
    // flowed). The drop counter comes through the backend-neutral EgressControl.
    let nft_drop = vm
        .egress_control()
        .map(|e| e.drop_counter())
        .unwrap_or_default();
    let ebpf_egress_bytes = egress_meter.egress_bytes();

    tracing::info!(
        nft_drop_packets = nft_drop.packets,
        nft_drop_bytes = nft_drop.bytes,
        ebpf_egress_bytes,
        raw_egress_denied,
        "G4 evidence gathered; halting the VM and tearing down the TAP"
    );

    // Tear down: stop the eBPF meter child (detaches the classifier), then halt
    // the VM (which tears down the TAP and its nftables lockdown).
    egress_meter.shutdown().await;
    vm.halt().await;

    Ok(EgressRunOutcome {
        raw_egress_denied,
        result_detail,
        probe_details,
        nft_drop,
        ebpf_egress_bytes,
    })
}

/// Read the genome's raw-egress events over the probe window. Returns
/// (all_denied, summary_detail, per_probe_details). `all_denied` is true when the
/// genome's `raw_egress_result` event says DENIED (every probe failed). If no
/// summary arrives in the window, `all_denied` is false and the detail says so.
async fn collect_egress_outcome(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    window: Duration,
) -> (bool, String, Vec<String>) {
    let deadline = tokio::time::Instant::now() + window;
    let mut probe_details = Vec::new();
    let mut summary: Option<String> = None;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "raw_egress_attempt" => {
                probe_details.push(ev.detail);
            }
            Ok(Some(ev)) if ev.kind == "raw_egress_result" => {
                let denied = ev.detail.contains("DENIED") && !ev.detail.contains("LEAKED");
                summary = Some(ev.detail);
                // The summary is the last word; once we have it, we can stop early
                // (the probes are done). But keep draining any straggler probe
                // lines already queued without blocking.
                if denied {
                    while let Ok(ev) = events.try_recv() {
                        if ev.kind == "raw_egress_attempt" {
                            probe_details.push(ev.detail);
                        }
                    }
                    break;
                }
                break;
            }
            Ok(Some(_)) => continue, // some other event (e.g. a late hello); ignore
            Ok(None) => break,        // observer dropped
            Err(_) => break,          // window elapsed
        }
    }

    match summary {
        Some(detail) => {
            let denied = detail.contains("DENIED") && !detail.contains("LEAKED");
            (denied, detail, probe_details)
        }
        None => (
            false,
            "no raw_egress_result reported by the genome within the probe window (cannot confirm the attempts failed)".to_string(),
            probe_details,
        ),
    }
}
