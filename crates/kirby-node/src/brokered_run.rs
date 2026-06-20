//! The brokered-act demonstration and its G5 evidence (spec 3.2, D-6, D-16,
//! gate G5). Shared by the `brokered` subcommand and the G5 integration test so
//! both drive the SAME path.
//!
//! The flow proves D-6 agency: isolation preserved while agency is granted. The
//! genome asks the daemon to SETTLE ECASH on the mint over vsock
//! (`RequestCapability`). The daemon authorizes it against the treasury (the C-3
//! 5-step order), PERFORMS the real settle using a host-held credential the genome
//! never sees (the [`crate::rail::CdkEcashRail`] melts against the LOCAL mint over
//! the daemon's HOST networking), meters + debits it, and returns the receipt.
//!
//! The G5 evidence this orchestration gathers covers three of the five checks: the
//! daemon AUTHORIZED it (the genome's receipt outcome is AUTHORIZED_AND_PERFORMED,
//! which only the 5-step order produces, check i); a non-zero cost_sats was debited
//! and the daemon-owned treasury dropped by EXACTLY that, read before/after (check
//! iii); and the VM issued NO raw network for the act (check iv). Linux proves
//! check iv with the eBPF TC meter on the VM TAP staying ~0 during the settle,
//! reusing the C-5 meter and ceiling. macOS VZ's MVP proves check iv structurally:
//! the guest is booted vsock-only with no network device, so there is no raw IP
//! egress path for the act to use. The other two are asserted by the G5 test
//! directly: the settle is REAL, the rail's wallet balance dropping and the mint
//! showing the proofs spent (check ii); and the genome never received the
//! credential, the wire types carrying no credential field and the wallet living
//! only host-side (check v).
//!
//! The VM is halted before returning after a successful boot. On Linux, the TAP
//! eBPF meter is torn down before halt.

use std::time::Duration;

#[cfg(target_os = "linux")]
use anyhow::Context;
use kirby_proto::Event;

use crate::boot::{self, BootConfig};
#[cfg(target_os = "linux")]
use crate::meter_egress::EgressMeter;
use crate::sandbox::EgressDropCounter;

/// The brokered-act request the daemon performed, as the genome reported it
/// (parsed from the genome's `brokered_result` event). The numbers here are what
/// the GENOME was told on its receipt; the daemon-authoritative treasury drop is
/// carried separately on the outcome.
#[derive(Debug, Clone, Default)]
pub struct BrokeredReceipt {
    /// The genome's act was AUTHORIZED_AND_PERFORMED (the daemon authorized and
    /// performed the real settle). Parsed from the `brokered_result` summary.
    pub performed: bool,
    /// The metered cost the daemon debited for the act (sats), as the genome was
    /// told on its receipt. For G5(iii) this must be > 0.
    pub cost_sats: u64,
    /// The post-debit treasury balance the genome was told (the daemon-owned,
    /// authoritative value, D-9).
    pub treasury_remaining: u64,
    /// The length of the rail proof the genome received. The genome gets the
    /// rail's receipt bytes but never the credential; a non-zero length here is
    /// the mint's own receipt (the preimage) the daemon produced host-side.
    pub proof_len: u64,
    /// The genome's full result-summary line (the evidence text).
    pub result_detail: String,
}

/// The G5 evidence from a brokered-act run.
#[derive(Debug, Clone)]
pub struct BrokeredRunOutcome {
    /// What the genome reported about its brokered act (outcome, cost, balance).
    pub receipt: BrokeredReceipt,
    /// The daemon-authoritative treasury balance BEFORE the act (D-9). Read from
    /// the daemon-owned counter, not the genome.
    pub treasury_before: u64,
    /// The daemon-authoritative treasury balance AFTER the act. `treasury_before
    /// - treasury_after` is the real debit; G5(iii) asserts it equals cost_sats.
    pub treasury_after: u64,
    /// Backend-specific raw-egress proof for G5(iv). Linux carries TAP/eBPF
    /// evidence; macOS VZ carries the structural no-network-device proof.
    pub raw_egress: BrokeredRawEgressProof,
    /// Linux compatibility evidence: the eBPF classifier's cumulative egress
    /// bytes the VM put on its TAP during the run. ~0 for the brokered act (it
    /// left via the daemon's host networking, NOT the VM TAP), gate G5(iv).
    /// On macOS VZ no TAP exists, so this is 0 and `raw_egress` carries the
    /// no-network-device proof.
    pub ebpf_egress_bytes: u64,
    /// Linux compatibility evidence: the host-kernel egress drop counter for the
    /// VM (packets, bytes). On macOS VZ no TAP/pf path exists for the no-NIC MVP,
    /// so this is zero and `raw_egress` carries the structural proof.
    pub nft_drop: EgressDropCounter,
}

/// The raw-egress proof attached to a brokered run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokeredRawEgressProof {
    /// Linux/Firecracker: a locked-down TAP exists, and the eBPF classifier saw
    /// at most the verifier's zero ceiling during the brokered act.
    LinuxTap {
        ebpf_egress_bytes: u64,
        nft_drop: EgressDropCounter,
    },
    /// macOS/VZ MVP: no guest network device is attached. The only guest/daemon
    /// channel is virtio-vsock, so the brokered act cannot leave via guest IP.
    NoGuestNetworkDevice,
}

impl BrokeredRawEgressProof {
    pub fn passed(&self, ebpf_zero_ceiling: u64) -> bool {
        match self {
            BrokeredRawEgressProof::LinuxTap {
                ebpf_egress_bytes, ..
            } => *ebpf_egress_bytes <= ebpf_zero_ceiling,
            BrokeredRawEgressProof::NoGuestNetworkDevice => true,
        }
    }

    pub fn summary(&self, ebpf_zero_ceiling: u64) -> String {
        match self {
            BrokeredRawEgressProof::LinuxTap {
                ebpf_egress_bytes,
                nft_drop,
            } => format!(
                "linux_tap: ebpf_egress_bytes={ebpf_egress_bytes} (<= {ebpf_zero_ceiling}) ; nft_drop_packets={} ; nft_drop_bytes={}",
                nft_drop.packets, nft_drop.bytes
            ),
            BrokeredRawEgressProof::NoGuestNetworkDevice => {
                "vz_no_guest_network_device: raw IP egress structurally absent".to_string()
            }
        }
    }
}

impl BrokeredRunOutcome {
    /// The treasury actually dropped by this much (the daemon-authoritative debit).
    pub fn treasury_drop(&self) -> u64 {
        self.treasury_before.saturating_sub(self.treasury_after)
    }

    /// The G5 pass predicate for the checks this orchestration can see: (i) the
    /// daemon authorized + performed it, (iii) a non-zero cost was debited AND the
    /// authoritative treasury dropped by exactly that, and (iv) the VM TAP egress
    /// stayed ~0 (the act did not leave via the VM). (ii) the real-settle and (v)
    /// no-credential checks are asserted by the G5 test against the rail directly.
    pub fn passed(&self, ebpf_zero_ceiling: u64) -> bool {
        self.receipt.performed
            && self.receipt.cost_sats > 0
            && self.treasury_drop() == self.receipt.cost_sats
            && self.raw_egress.passed(ebpf_zero_ceiling)
    }
}

/// Inputs for a brokered-act run (reuses the boot config). The `brokered`
/// workload is forced on here. Linux also forces the per-VM TAP so the eBPF
/// egress meter can prove the act did not leave via the VM. macOS VZ forces a
/// vsock-only no-NIC guest, which is the MVP raw-egress proof.
pub struct BrokeredRunConfig {
    pub boot: BootConfig,
    /// How long to wait for the genome's brokered-act result and the meters to
    /// settle before reading the counters.
    pub act_window: Duration,
    /// The eBPF reporting tick for the privileged meter child.
    pub egress_tick: Duration,
}

impl BrokeredRunConfig {
    /// Build a brokered-run config from a boot config, forcing the backend's
    /// brokered-act raw-egress profile and the genome's `brokered` workload.
    pub fn new(mut boot: BootConfig, act_window: Duration) -> Self {
        if cfg!(target_os = "linux") {
            boot.lockdown_egress = true;
        } else if cfg!(target_os = "macos") {
            // VZ currently attaches no network device. Keep that explicit so the
            // Mac brokered MVP proves agency over vsock without opening raw IP.
            boot.lockdown_egress = false;
        }
        boot.workload = Some("brokered".to_string());
        BrokeredRunConfig {
            boot,
            act_window,
            egress_tick: Duration::from_millis(100),
        }
    }
}

/// Boot the locked-down VM with the real rail injected, let the genome issue the
/// brokered `RequestCapability`, and gather the G5 evidence. Always halts the VM
/// (and tears down the TAP plus the eBPF meter) before returning.
///
/// The `rail` is the real [`crate::rail::CdkEcashRail`]; the gateway's perform step
/// uses it to settle ecash on the local mint over host networking. The treasury the
/// daemon debits is the one [`boot::boot_and_observe_with_rail`] opens and returns,
/// so the before/after balance read here is the authoritative one (D-9).
pub async fn run(
    config: BrokeredRunConfig,
    rail: std::sync::Arc<dyn crate::rail::Rail>,
) -> anyhow::Result<BrokeredRunOutcome> {
    let act_window = config.act_window;
    let egress_tick = config.egress_tick;

    // Boot with the real rail injected; keep the event stream so we can read the
    // genome's brokered-act result. The returned treasury is the daemon-owned
    // counter the gateway debits (D-9).
    let (vm, outcome, treasury, mut events) =
        boot::boot_and_observe_with_rail(config.boot, rail).await?;
    if !outcome.reached_running {
        vm.halt().await;
        anyhow::bail!("brokered run: VM did not reach Running");
    }

    let result = async {
        // The authoritative treasury balance BEFORE the act (D-9). The genome
        // has not acted yet (it acts after the boot hello, which
        // boot_and_observe awaited), so this is the pre-act balance.
        let treasury_before = treasury.remaining()?;

        run_platform_brokered(
            &*vm,
            treasury_before,
            &treasury,
            &mut events,
            act_window,
            egress_tick,
        )
        .await
    }
    .await;

    vm.halt().await;
    result
}

#[cfg(target_os = "linux")]
async fn run_platform_brokered(
    vm: &dyn crate::sandbox::SandboxInstance,
    treasury_before: u64,
    treasury: &crate::treasury::Treasury,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    act_window: Duration,
    egress_tick: Duration,
) -> anyhow::Result<BrokeredRunOutcome> {
    // The authoritative treasury balance BEFORE the act (D-9). The genome has not
    // acted yet (it acts after the boot hello, which boot_and_observe awaited), so
    // this is the pre-act balance.
    // The egress control must exist (lockdown_egress was forced on). Resolve the
    // metered interface so we can attach the eBPF egress meter, the G5(iv)
    // instrument: it shows the VM TAP egress stays ~0 during the host-side settle.
    let tap_name = match vm.egress_control() {
        Some(egress) => egress.iface_name().to_string(),
        None => {
            anyhow::bail!(
                "brokered run: no egress control on the guest (lockdown_egress was not honored)"
            );
        }
    };
    // The same working passwordless sudo the jailer launches through, discovered
    // at runtime (the D-7 boundary, not weakened); fails loud if none is found.
    // (On the real path this always resolves, since the VM only booted because
    // the backend resolved it; halt-then-bail to match the early-error idiom.)
    let sudo_bin = match crate::prereqs::resolve_sudo() {
        Ok(s) => s,
        Err(e) => {
            return Err(e.context("brokered run: could not resolve sudo for the eBPF egress meter"))
        }
    };

    let egress_meter = match EgressMeter::spawn(&tap_name, sudo_bin, egress_tick).await {
        Ok(m) => m,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "brokered run: eBPF egress meter attach failed: {e}"
            ))
        }
    };

    tracing::info!(
        tap = %tap_name,
        treasury_before,
        "brokered act in flight: genome requesting an ecash settle over vsock; daemon performs it host-side (gate G5)"
    );

    // Collect the genome's brokered-act result over the window. The genome reports
    // a `brokered_request` then a `brokered_result` summary; we key on the result.
    let receipt = collect_brokered_outcome(events, act_window).await;

    // The authoritative treasury AFTER the act (D-9). The drop is the real debit.
    let treasury_after = treasury.remaining();

    // The eBPF egress counter: ~0 for the brokered act (it left via the daemon's
    // host networking, not the VM TAP), gate G5(iv).
    let ebpf_egress_bytes = egress_meter.egress_bytes();
    let nft_drop = vm
        .egress_control()
        .map(|e| e.drop_counter())
        .unwrap_or_default();
    let raw_egress = BrokeredRawEgressProof::LinuxTap {
        ebpf_egress_bytes,
        nft_drop,
    };

    tracing::info!(
        performed = receipt.performed,
        cost_sats = receipt.cost_sats,
        treasury_before,
        ?treasury_after = treasury_after.as_ref().ok(),
        ebpf_egress_bytes,
        "G5 evidence gathered; halting the VM and tearing down the TAP"
    );

    // Tear down the eBPF meter child (detaches the classifier). The caller halts
    // the VM afterward, which tears down the TAP and nftables lockdown.
    egress_meter.shutdown().await;
    let treasury_after = treasury_after?;

    Ok(BrokeredRunOutcome {
        receipt,
        treasury_before,
        treasury_after,
        raw_egress,
        ebpf_egress_bytes,
        nft_drop,
    })
}

#[cfg(target_os = "macos")]
async fn run_platform_brokered(
    vm: &dyn crate::sandbox::SandboxInstance,
    treasury_before: u64,
    treasury: &crate::treasury::Treasury,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    act_window: Duration,
    _egress_tick: Duration,
) -> anyhow::Result<BrokeredRunOutcome> {
    if let Some(egress) = vm.egress_control() {
        anyhow::bail!(
            "macOS VZ brokered MVP expected a vsock-only guest with no network device, but backend exposed egress interface {}",
            egress.iface_name()
        );
    }

    tracing::info!(
        treasury_before,
        "brokered act in flight: VZ genome requesting an ecash settle over vsock; daemon performs it host-side with no guest network device (gate G5)"
    );

    let receipt = collect_brokered_outcome(events, act_window).await;
    let treasury_after = treasury.remaining()?;

    tracing::info!(
        performed = receipt.performed,
        cost_sats = receipt.cost_sats,
        treasury_before,
        treasury_after,
        "G5 evidence gathered for macOS VZ no-NIC brokered act"
    );

    Ok(BrokeredRunOutcome {
        receipt,
        treasury_before,
        treasury_after,
        raw_egress: BrokeredRawEgressProof::NoGuestNetworkDevice,
        ebpf_egress_bytes: 0,
        nft_drop: EgressDropCounter::default(),
    })
}

/// Read the genome's brokered-act events over the window. Returns the parsed
/// receipt from the `brokered_result` summary. If no result arrives, the receipt
/// is the default (not performed) with a detail saying so.
async fn collect_brokered_outcome(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    window: Duration,
) -> BrokeredReceipt {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "brokered_result" => {
                return parse_brokered_result(&ev.detail);
            }
            Ok(Some(_)) => continue, // the request line or a late hello; keep waiting
            Ok(None) => break,       // observer dropped
            Err(_) => break,         // window elapsed
        }
    }
    BrokeredReceipt {
        result_detail:
            "no brokered_result reported by the genome within the act window (cannot confirm the act)"
                .to_string(),
        ..Default::default()
    }
}

/// Parse the genome's `brokered_result` summary line into a [`BrokeredReceipt`].
/// The genome formats it as either
/// `brokered_result PERFORMED: outcome=AUTHORIZED_AND_PERFORMED cost_sats=<n> treasury_remaining=<n> proof_len=<n>`
/// or a NOT_PERFORMED / FAILED line. We extract the `key=value` fields.
fn parse_brokered_result(detail: &str) -> BrokeredReceipt {
    let performed = detail.contains("PERFORMED") && !detail.contains("NOT_PERFORMED");
    let field = |key: &str| -> u64 {
        detail
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    BrokeredReceipt {
        performed,
        cost_sats: field("cost_sats="),
        treasury_remaining: field("treasury_remaining="),
        proof_len: field("proof_len="),
        result_detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_brokered_result;

    /// The performed-result parser extracts the cost, balance, and proof length.
    #[test]
    fn parse_performed_result() {
        let line = "brokered_result PERFORMED: outcome=AUTHORIZED_AND_PERFORMED cost_sats=8 treasury_remaining=992 proof_len=64";
        let r = parse_brokered_result(line);
        assert!(r.performed);
        assert_eq!(r.cost_sats, 8);
        assert_eq!(r.treasury_remaining, 992);
        assert_eq!(r.proof_len, 64);
    }

    /// A NOT_PERFORMED line is not counted as performed.
    #[test]
    fn parse_not_performed_result() {
        let line = "brokered_result NOT_PERFORMED: outcome=DeniedInsufficientTreasury cost_sats=0 treasury_remaining=5";
        let r = parse_brokered_result(line);
        assert!(!r.performed);
        assert_eq!(r.cost_sats, 0);
    }
}
