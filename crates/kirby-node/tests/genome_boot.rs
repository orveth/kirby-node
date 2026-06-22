//! C-2 boot test (gate G1): the daemon boots the genome microVM from the
//! content-addressed image, the genome comes up, and it completes a
//! `GetSessionContext` round-trip over vsock, reporting a boot "hello" event
//! tagged with the session task.
//!
//! This test boots a REAL Firecracker microVM under the jailer, so it needs the
//! host prerequisites (KVM, vsock, the jailer privilege path) AND the built
//! genome image. The image path is taken from the `KIRBY_GENOME_IMAGE` env var
//! (the `nix build .#genome-image` output, holding vmlinux and rootfs.squashfs).
//! If that var is unset the test SKIPS with a clear message rather than failing,
//! so `cargo test` stays green on a host that has not built the image; the
//! verifier runs it with the var set as the G1 producing command.

use std::time::Duration;

use kirby_node::boot::{self, BootConfig, ImagePaths};

/// G1: boot the genome and assert the vsock boot round-trip arrived.
#[tokio::test]
async fn g1_genome_boots_and_completes_session_context_round_trip() {
    // Resolve the image, or skip if it is not built/exported.
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP g1_genome_boots...: set KIRBY_GENOME_IMAGE to the `nix build .#genome-image` \
             output to run the real-microVM boot test (gate G1)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    let task = "g1-boot-test";
    // A distinct CID and port keep this test isolated from any other VM on the
    // host; a per-process node id keeps the jail and treasury unique.
    let config = BootConfig {
        image,
        node_id: format!("g1test-{}", std::process::id()),
        task: task.to_string(),
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec!["mint.test.local".to_string()],
        guest_cid: 17,
        gateway_port: 5017,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        // G1 only needs the boot round-trip; the genome idles after the hello.
        workload: None,
        brain: None,
        // G1 is vsock-only (no TAP / no egress lockdown; that is C-5 / G4).
        lockdown_egress: false,
        // G1 does not snapshot (no CPU template); snapshot is C-7 / G6.
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    let (vm, outcome, _treasury, _events, _serve_guard) = match boot::boot_and_observe(config).await
    {
        Ok(parts) => parts,
        Err(e) => panic!("boot_and_observe failed: {e:#}"),
    };

    // Always halt the VM and clean the jail, even if an assertion below fails.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The VM reached Running (the daemon booted it under the jailer).
        assert!(outcome.reached_running, "the microVM did not reach Running");

        // The boot round-trip arrived: a hello event with session=<task>. This
        // is the machine-checkable G1 proof that the genome connected over
        // vsock, pulled the session context, and reported hello.
        let hello = outcome
            .hello
            .as_ref()
            .expect("the genome boot hello event did not arrive over vsock (no round-trip)");
        assert_eq!(hello.kind, "hello", "the boot event is a hello");
        assert_eq!(
            hello.detail,
            format!("session={task}"),
            "the hello event carries the session task from GetSessionContext"
        );
    }));

    vm.halt().await;
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
