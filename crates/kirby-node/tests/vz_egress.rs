//! Chunk B (macOS VZ egress membrane, gate G4): a VZ guest booted with the egress
//! lockdown comes up AND exposes an honest [`EgressControl`].
//!
//! The VZ guest is vsock-only: the Swift helper configures NO `VZVirtioNetworkDevice`,
//! so there is structurally no egress path off-box. That makes the membrane
//! VACUOUS-TRUE: unlike the Firecracker TAP + nftables + eBPF path, there is no NIC
//! to default-deny and no drops to count. The proof is "there is no NIC", so the
//! drop counter is always zero and the interface name is "none". This test asserts
//! the contract: booting with `lockdown_egress = true` SUCCEEDS (it no longer bails)
//! and `egress_control()` returns `Some` with the no-NIC shape.
//!
//! macOS + Apple Silicon only (the VZ backend). Like the Firecracker boot tests it
//! needs the built aarch64 genome image via `KIRBY_GENOME_IMAGE`; without it the
//! test SKIPS with a visible message rather than failing, so `cargo test` stays
//! green on a host that has not staged the image.
#![cfg(target_os = "macos")]

use std::time::Duration;

use kirby_node::boot::{self, BootConfig, ImagePaths};

/// G4 (macOS): a lockdown-egress VZ boot succeeds and reports an honest no-NIC
/// egress control.
#[tokio::test]
async fn vz_lockdown_egress_boots_and_exposes_no_nic_egress_control() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP vz_lockdown_egress_boots_and_exposes_no_nic_egress_control: set \
             KIRBY_GENOME_IMAGE to the staged aarch64 genome image dir to run the real \
             VZ egress-membrane test (macOS gate G4)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    let config = BootConfig {
        image,
        node_id: format!("vzg4test-{}", std::process::id()),
        task: "vz-g4-egress-test".to_string(),
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec!["mint.test.local".to_string()],
        guest_cid: 19,
        gateway_port: 5019,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        workload: None,
        brain: None,
        memory: None,
        agent: None,
        social: None,
        // The Chunk B behavior under test: the egress lockdown is requested. On VZ
        // this is satisfied structurally by the no-NIC topology.
        nip60: Default::default(),
        fleet_relay: String::new(),
        lockdown_egress: true,
        snapshot_capable: false,
        restore_checkpoint: None,
        lease_fence: None,
    };

    let (vm, outcome, _treasury, _events, _serve_guard) = match boot::boot_and_observe(config).await {
        Ok(parts) => parts,
        Err(e) => panic!("boot_and_observe with lockdown_egress=true failed: {e:#}"),
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(
            outcome.reached_running,
            "the lockdown-egress VZ microVM did not reach Running"
        );

        // The Chunk B teeth: a lockdown-egress guest exposes an honest egress control.
        let egress = vm
            .egress_control()
            .expect("a lockdown-egress VZ guest must expose an EgressControl");
        assert_eq!(
            egress.iface_name(),
            "none",
            "the vsock-only VZ guest has no egress NIC, so the metered interface is \"none\""
        );
        let drops = egress.drop_counter();
        assert_eq!(
            (drops.packets, drops.bytes),
            (0, 0),
            "there is no NIC to drop on, so the drop counter is vacuously zero"
        );
    }));

    vm.halt().await;
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
