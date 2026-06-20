//! C-5 test (gate G4): the per-VM egress lockdown and the egress-byte meter.
//!
//! The daemon creates a per-VM TAP, locks it down with nftables default-deny
//! egress (spec 3.7), wires it into the microVM, attaches the aya/eBPF TC
//! egress-byte classifier, and boots the genome with the raw-egress workload
//! (the genome ATTEMPTS direct outbound: connect to an external IP, hit 1.1.1.1,
//! resolve a name). It then asserts:
//!
//! - the genome's raw-egress attempts FAILED (its `raw_egress_result` says
//!   DENIED: every direct outbound failed; reported over vsock, the only channel
//!   that works, which is itself the proof isolation holds while the gateway is
//!   reachable);
//! - the host nftables drop counter on the TAP shows a non-zero drop (the host
//!   kernel dropped the VM's egress attempt; the genome cannot touch this rule);
//! - the eBPF egress counter shows ~0 IP bytes left the TAP (nothing flowed; a
//!   few unanswered SYN/ARP/DNS packets are within the ~0 ceiling, a flowing
//!   connection would not be).
//!
//! This boots a REAL Firecracker microVM under the jailer with a real TAP, real
//! nftables, and a real eBPF program, so it needs the host prerequisites AND the
//! built genome image (the `KIRBY_GENOME_IMAGE` env var, the `nix build
//! .#genome-image` output). With the var unset it SKIPS (green), so `cargo test`
//! stays green on a host without the image; the verifier runs it with the var set
//! as the G4 producing command.

#![cfg(target_os = "linux")]

use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::egress_run::{self, EgressRunConfig};

/// G4: lock down the VM's egress and assert raw egress is denied, the host
/// nftables drop counter fired, and the eBPF egress counter shows ~0 IP bytes.
#[tokio::test]
async fn g4_raw_egress_denied_and_metered_about_zero() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP g4_raw_egress_denied_and_metered_about_zero: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the real-microVM egress-lockdown test (gate G4)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    let boot = BootConfig {
        image,
        node_id: format!("g4test-{}", std::process::id()),
        task: "g4-egress".to_string(),
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec!["mint.test.local".to_string()],
        // Distinct CID and port keep this test isolated from any other VM.
        guest_cid: 27,
        gateway_port: 5027,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        // Forced on by EgressRunConfig::new; set here for clarity.
        workload: Some("raw-egress".to_string()),
        lockdown_egress: true,
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    // A probe window long enough for the genome's four probes (each up to a 3s
    // connect timeout) plus the meters to settle.
    let config = EgressRunConfig::new(boot, Duration::from_secs(20));

    let outcome = egress_run::run(config).await.expect("egress run completed");

    // A clear evidence line in the test output (the verifier reads it).
    eprintln!(
        "G4 evidence: raw_egress_denied={} ; nft_drop_packets={} ; nft_drop_bytes={} ; \
         ebpf_egress_bytes={}",
        outcome.raw_egress_denied,
        outcome.nft_drop.packets,
        outcome.nft_drop.bytes,
        outcome.ebpf_egress_bytes,
    );
    eprintln!("  genome result: {}", outcome.result_detail);
    for probe in &outcome.probe_details {
        eprintln!("  probe: {probe}");
    }

    // The genome's raw-egress attempts FAILED (no leak): every direct outbound
    // was denied (no route / blocked). This is the genome-reported half of G4.
    assert!(
        outcome.raw_egress_denied,
        "the genome's raw-egress attempts must ALL fail (no route / blocked); got: {}",
        outcome.result_detail
    );

    // The genome actually made probe attempts (so "denied" is not vacuous: it
    // tried and was blocked, not "never tried").
    assert!(
        !outcome.probe_details.is_empty(),
        "the genome must have reported at least one raw-egress probe attempt"
    );

    // The host nftables drop counter fired: the host kernel dropped the VM's
    // egress packets (the host-kernel-enforced default-deny, spec 3.7). Non-zero
    // packets proves the VM DID emit egress and the host DID drop it.
    assert!(
        outcome.nft_drop.packets > 0,
        "the host nftables drop counter must show a non-zero drop (the kernel dropped the VM egress); \
         got {} packets / {} bytes",
        outcome.nft_drop.packets,
        outcome.nft_drop.bytes
    );

    // The eBPF egress counter shows ~0 IP bytes left the TAP. A few unanswered
    // SYN/ARP/DNS packets the VM emits before giving up are within the ceiling; a
    // flowing connection (kilobytes+) would blow past it. This is the "about 0 IP
    // bytes" half of G4.
    let ebpf_zero_ceiling = egress_run::EBPF_ZERO_CEILING_BYTES;
    assert!(
        outcome.ebpf_egress_bytes <= ebpf_zero_ceiling,
        "the eBPF egress counter must show ~0 IP bytes left the TAP (<= {ebpf_zero_ceiling}); \
         got {} bytes (a flowing connection would mean the lockdown leaked)",
        outcome.ebpf_egress_bytes
    );

    // The composite G4 pass.
    assert!(
        outcome.passed(ebpf_zero_ceiling),
        "G4 must pass: raw egress denied AND nftables dropped AND eBPF ~0 bytes"
    );

    eprintln!(
        "G4 PASS: raw egress denied (no route / blocked) ; nftables drop counter = {} packets ; \
         eBPF egress = {} bytes (~0 IP bytes left the TAP) ; vsock to the daemon is the only working channel",
        outcome.nft_drop.packets, outcome.ebpf_egress_bytes,
    );
}
