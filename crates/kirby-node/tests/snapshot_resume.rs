//! C-7 test (gate G6): snapshot + cross-node resume, the spike's hardest seam.
//!
//! The daemon boots the genome microVM on "node 1" (CPU-template normalized so the
//! snapshot can restore on a compatible different CPU), SNAPSHOTS the running VM
//! (pause + write the mem+vmstate pair), TRANSFERS the pair to "node 2" (a second
//! jail/dir on this host, the D-13 same-host seam), KILLS node 1's VMM, and "node
//! 2" RESTORES a fresh jailed VMM from the transferred pair and resumes it. The
//! genome continues ALIVE across the move: its vsock dropped, so it re-dials node
//! 2's gateway and completes a post-resume GetSessionContext/ReportEvent round-trip
//! (proving it survived). On restore the VMGenID generation bumps and node 2's
//! gateway `bump_generation()` fires (the hook C-8 uses to make the genome
//! re-derive its entropy; C-7 does NOT do the full re-derive, that is C-8/G7).
//!
//! This boots REAL Firecracker microVMs under the jailer (one snapshotted, one
//! restored), so it needs the host prerequisites AND the built genome image (the
//! `KIRBY_GENOME_IMAGE` env var, the `nix build .#genome-image` output). With the
//! var unset it SKIPS (green), so `cargo test` stays green on a host without the
//! image; the verifier runs it with the var set as the G6 producing command.
//!
//! G6 asserts, all from the producing run: node 2 reaches Running FROM the snapshot
//! (not a cold boot); the genome completes a post-resume round-trip on node 2 (it
//! survived the move and reconnected its vsock to node 2's gateway); the VMGenID
//! generation bumped on restore (generation_post equals generation_pre plus one);
//! node 1's VMM was killed (the source node is gone); and the single persisted
//! treasury continued across the move (D-9: node 2's balance equals node 1's).

#![cfg(target_os = "linux")]

use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::snapshot_run::{self, SnapshotRunConfig};

/// G6: snapshot the genome on node 1, kill node 1, restore on node 2, and assert
/// the genome survived the move with a post-resume round-trip and a generation bump.
#[tokio::test]
async fn g6_snapshot_and_resume_on_node2() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP g6_snapshot_and_resume_on_node2: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the real snapshot+resume test (gate G6)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    let boot = BootConfig {
        image,
        node_id: format!("g6test-{}", std::process::id()),
        task: "g6-snapshot".to_string(),
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec!["mint.test.local".to_string()],
        // Distinct CID and port keep this test isolated from any other VM. Node 2
        // serves on vsock_port + 1 (derived by SnapshotRunConfig::new).
        guest_cid: 31,
        gateway_port: 5031,
        vcpu_count: 1,
        // A small VM keeps the snapshot mem file small and the test quick.
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        // Forced on by SnapshotRunConfig::new; set here for clarity.
        workload: Some("snapshot".to_string()),
        brain: None,
        memory: None,
        // G6 is vsock-only (the egress lockdown is G4); keeps the move lean.
        lockdown_egress: false,
        snapshot_capable: true,
        restore_checkpoint: None,
    };

    let config = SnapshotRunConfig::new(boot);
    let outcome = snapshot_run::run(config).await.expect("snapshot run completed");

    // A clear evidence line in the test output (the verifier reads it).
    eprintln!(
        "G6 evidence: pre_snapshot_round_trip={} ; node1_killed={} ; node2_reached_running={} ; \
         post_resume_round_trip={} ; generation {} -> {} ; treasury {} -> {} ; snapshot_bytes={}",
        outcome.pre_snapshot_round_trip,
        outcome.node1_killed,
        outcome.node2_reached_running,
        outcome.post_resume_round_trip,
        outcome.generation_pre,
        outcome.generation_post,
        outcome.treasury_pre,
        outcome.treasury_post,
        outcome.snapshot_bytes,
    );
    if let Some(detail) = &outcome.post_resume_detail {
        eprintln!("  node 2 post-resume heartbeat: {detail}");
    }

    // The genome was alive on node 1 before the snapshot (a baseline round-trip).
    assert!(
        outcome.pre_snapshot_round_trip,
        "the genome must complete a pre-snapshot heartbeat round-trip on node 1"
    );

    // Node 1's VMM was killed: the source node is gone, so node 2 had to restore
    // the genome from the transferred snapshot alone (not from a live source VM).
    assert!(
        outcome.node1_killed,
        "node 1's VMM must be killed after the snapshot (the source node is gone)"
    );

    // (i) Node 2 reached Running FROM the snapshot (a real restore, not a cold boot).
    assert!(
        outcome.node2_reached_running,
        "(i) node 2 must bring the VM to Running FROM the snapshot"
    );

    // (ii) THE decisive G6 proof: the genome completed a post-resume round-trip on
    // node 2. Its vsock dropped on the move; it re-dialed node 2's gateway and
    // talked again. The genome SURVIVED the snapshot+transfer+kill+restore.
    assert!(
        outcome.post_resume_round_trip,
        "(ii) the genome must complete a post-resume round-trip on node 2 (it survived the move)"
    );

    // (iii) The VMGenID generation bumped on restore (the hook C-8 uses to make the
    // genome re-derive its entropy). C-7 wires the bump; C-8 does the full re-derive.
    assert_eq!(
        outcome.generation_post,
        outcome.generation_pre + 1,
        "(iii) the generation must bump by exactly 1 on restore (pre={}, post={})",
        outcome.generation_pre,
        outcome.generation_post,
    );

    // The single persisted treasury continued across the move (D-9): node 2 opened
    // the SAME store, so a resumed VM continues debiting the same balance.
    assert_eq!(
        outcome.treasury_post, outcome.treasury_pre,
        "the resumed VM must continue the SAME persisted treasury (D-9): node1={} node2={}",
        outcome.treasury_pre, outcome.treasury_post,
    );

    // The overall G6 verdict.
    assert!(outcome.passed(), "G6 must pass: {outcome:?}");

    eprintln!(
        "G6 PASS: node 2 restored the VM from the snapshot ; the genome survived the move \
         (post-resume round-trip on node 2) ; the VMGenID generation bumped {} -> {} ; \
         the persisted treasury continued ({}). Snapshot + cross-node resume proven (D-8, gate G6).",
        outcome.generation_pre, outcome.generation_post, outcome.treasury_post,
    );
}
