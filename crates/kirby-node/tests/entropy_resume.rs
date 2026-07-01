//! C-8 test (gate G7): entropy re-derived on resume, the D-5 anti-nonce-reuse gate.
//!
//! This is the spike-scale proof against the FROST-nonce-reuse / key-extraction
//! class: a genome that resumes from a snapshot MUST re-derive its entropy (call
//! GetEntropyNonce -> a FRESH nonce + the bumped VMGenID generation) BEFORE acting,
//! so a resumed VM never reuses a signing nonce. The genome stands this in with an
//! "entropy fingerprint" = H(nonce || vm_generation): re-deriving on resume changes
//! the fingerprint (fresh nonce, bumped generation), reusing it does not.
//!
//! Two tests, both driving the SAME real snapshot+cross-node-resume flow as G6 (boot
//! the genome on node 1, snapshot, transfer, kill node 1, restore on node 2):
//!
//!   1. THE CORRECT GENOME (the `snapshot` workload) PASSES G7. It re-derives the
//!      fingerprint from a fresh GetEntropyNonce before every act, so after the
//!      resume: (i) fingerprint_pre != fingerprint_post (entropy genuinely
//!      re-derived), (ii) generation_post == generation_pre + 1 (VMGenID bumped),
//!      and (iii) the genome CALLED GetEntropyNonce after the resume BEFORE acting
//!      (the daemon's gateway observes the call ahead of the post-resume heartbeat).
//!
//!   2. THE NEGATIVE CONTROL (the `resume-noredrive` workload) FAILS G7 the way the
//!      gate must catch: it derives its fingerprint ONCE before the snapshot and
//!      REUSES it after the resume, so fingerprint_post == fingerprint_pre (the
//!      catastrophic nonce-reuse). The test asserts this run's fingerprints are
//!      EQUAL and that g7_passed() is FALSE for it, while the correct genome's
//!      fingerprints DIFFER and g7_passed() is TRUE. Asserting both proves the gate
//!      detects a nonce-reuse, not merely that the happy path works.
//!
//! Like G6 this boots REAL Firecracker microVMs under the jailer, so it needs the
//! host prerequisites AND the built genome image (the `KIRBY_GENOME_IMAGE` env var,
//! the `nix build .#genome-image` output). With the var unset both tests SKIP
//! (green), so `cargo test` stays green on a host without the image; the verifier
//! runs them with the var set as the G7 producing commands.

#![cfg(target_os = "linux")]

use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::snapshot_run::{self, SnapshotRunConfig, SnapshotRunOutcome};

/// Resolve the genome image, or return None (the caller prints a SKIP and returns
/// green) so `cargo test` passes on a host without the image.
fn image_or_skip(test: &str) -> Option<ImagePaths> {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP {test}: set KIRBY_GENOME_IMAGE to the `nix build .#genome-image` \
             output to run the real entropy-re-derive test (gate G7)"
        );
        return None;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    Some(ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)"))
}

/// A node-1 boot config for an entropy-resume run. Distinct CID/port keep each test
/// isolated from any other VM. The treasury/budget mirror G6 (D-9 continuity is not
/// the focus here, but it must keep holding).
fn boot_config(image: ImagePaths, node_id: &str, task: &str, cid: u32, port: u32) -> BootConfig {
    BootConfig {
        image,
        node_id: format!("{node_id}-{}", std::process::id()),
        task: task.to_string(),
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec!["mint.test.local".to_string()],
        guest_cid: cid,
        gateway_port: port,
        vcpu_count: 1,
        // A small VM keeps the snapshot mem file small and the test quick.
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        // Forced on by SnapshotRunConfig; set here for clarity.
        workload: Some("snapshot".to_string()),
        brain: None,
        memory: None,
        // G7 is vsock-only (the egress lockdown is G4); keeps the move lean.
        agent: None,
        social: None,
        nip60: Default::default(),
        fleet_relay: String::new(),
        lockdown_egress: false,
        snapshot_capable: true,
        restore_checkpoint: None,
        lease_fence: None,
    }
}

/// A readable evidence line the verifier reads, for either genome variant.
fn print_evidence(label: &str, o: &SnapshotRunOutcome) {
    eprintln!(
        "{label} evidence: pre_snapshot_round_trip={} ; node1_killed={} ; \
         node2_reached_running={} ; post_resume_round_trip={} ; generation {} -> {} ; \
         fingerprint_pre={} ; fingerprint_post={} ; fingerprints_equal={} ; \
         entropy_call_before_post_resume_act={} ; treasury {} -> {}",
        o.pre_snapshot_round_trip,
        o.node1_killed,
        o.node2_reached_running,
        o.post_resume_round_trip,
        o.generation_pre,
        o.generation_post,
        o.fingerprint_pre.as_deref().unwrap_or("<none>"),
        o.fingerprint_post.as_deref().unwrap_or("<none>"),
        o.fingerprints_equal(),
        o.entropy_call_before_post_resume_act,
        o.treasury_pre,
        o.treasury_post,
    );
}

/// G7 (the correct genome): snapshot the genome on node 1, resume on node 2, and
/// assert the genome RE-DERIVED its entropy on resume: (i) the pre-snapshot and
/// post-resume fingerprints DIFFER, (ii) the VMGenID generation bumped by one, and
/// (iii) the genome called GetEntropyNonce after the resume before acting.
#[tokio::test]
async fn g7_entropy_redrive_on_resume() {
    let Some(image) = image_or_skip("g7_entropy_redrive_on_resume") else { return };

    // The CORRECT genome: the `snapshot` workload re-derives before every act.
    let boot = boot_config(image, "g7test", "g7-redrive", 41, 5041);
    let config = SnapshotRunConfig::new(boot);
    let outcome = snapshot_run::run(config).await.expect("entropy-resume run completed");

    print_evidence("G7", &outcome);
    if let Some(detail) = &outcome.post_resume_detail {
        eprintln!("  node 2 post-resume heartbeat: {detail}");
    }

    // The genome survived the move (G6 precondition: a genome that did not survive
    // cannot re-derive). Reuses the G6 verdict so G7 builds on a real resume.
    assert!(
        outcome.passed(),
        "G6 (survival) must hold as the G7 precondition: {outcome:?}"
    );

    // The fingerprints must have actually landed (a missing one is not a pass).
    let pre = outcome
        .fingerprint_pre
        .as_deref()
        .expect("the genome must report a pre-snapshot fingerprint");
    let post = outcome
        .fingerprint_post
        .as_deref()
        .expect("the genome must report a post-resume fingerprint");

    // (i) The entropy was genuinely RE-DERIVED: a fresh nonce + the bumped generation
    // yield a DIFFERENT fingerprint. Equal fingerprints would mean the resumed clone
    // reused its pre-snapshot ephemeral secret (the nonce-reuse the gate forbids).
    assert_ne!(
        pre, post,
        "(i) the post-resume fingerprint must DIFFER from the pre-snapshot one \
         (entropy genuinely re-derived; equal would be a nonce reuse)"
    );

    // (ii) The VMGenID generation bumped by exactly one on restore (the kernel
    // CSPRNG reseed signal the genome keys its re-derive on).
    assert_eq!(
        outcome.generation_post,
        outcome.generation_pre + 1,
        "(ii) the VMGenID generation must bump by exactly 1 on restore (pre={}, post={})",
        outcome.generation_pre,
        outcome.generation_post,
    );

    // (iii) The genome CALLED GetEntropyNonce after the resume BEFORE its first
    // post-resume act (the daemon observed the entropy call at the bumped generation
    // ahead of the post-resume heartbeat). It re-derived BEFORE acting, not after.
    assert!(
        outcome.entropy_call_before_post_resume_act,
        "(iii) the genome must call GetEntropyNonce after the resume BEFORE acting \
         (the re-derive-before-act ordering, observed at the bumped generation)"
    );

    // The overall G7 verdict (all three plus survival).
    assert!(outcome.g7_passed(), "G7 must pass for the correct genome: {outcome:?}");
    // And the gate must NOT read this as a reuse.
    assert!(
        !outcome.fingerprints_equal(),
        "the correct genome's fingerprints must NOT be equal (that is the reuse the gate catches)"
    );

    eprintln!(
        "G7 PASS (correct genome): entropy RE-DERIVED on resume ; fingerprint_pre={pre} != \
         fingerprint_post={post} ; VMGenID generation bumped {} -> {} ; GetEntropyNonce called \
         after resume before acting. The resumed VM did NOT reuse its pre-snapshot ephemeral \
         secret (spike-scale proof against the FROST-nonce-reuse class, D-5, gate G7).",
        outcome.generation_pre, outcome.generation_post,
    );
}

/// G7 NEGATIVE CONTROL (the broken genome): a genome that SKIPS the re-derive
/// (reuses its pre-snapshot fingerprint after resume) produces EQUAL fingerprints,
/// which is exactly what the gate catches. This proves the gate has teeth: it
/// DISTINGUISHES a re-deriving genome (g7_passed) from a reusing one (g7 fails,
/// fingerprints equal). The broken genome still SURVIVES the move (G6 holds), so the
/// only thing that differs from the correct run is the re-derive.
#[tokio::test]
async fn g7_negative_control_skip_redrive_fails() {
    let Some(image) = image_or_skip("g7_negative_control_skip_redrive_fails") else { return };

    // The BROKEN genome: the `resume-noredrive` workload reuses its pre-snapshot
    // fingerprint after the resume. Distinct CID/port from the correct-genome test.
    let boot = boot_config(image, "g7negtest", "g7-noredrive", 43, 5043);
    let config = SnapshotRunConfig::new_negative_control(boot);
    let outcome = snapshot_run::run(config).await.expect("negative-control resume run completed");

    print_evidence("G7-NEG", &outcome);
    if let Some(detail) = &outcome.post_resume_detail {
        eprintln!("  node 2 post-resume heartbeat: {detail}");
    }

    // The broken genome still SURVIVES the move: G6 holds (it reuses its fingerprint,
    // it does not die). So the difference under test is purely the re-derive, not
    // the snapshot/resume machinery.
    assert!(
        outcome.passed(),
        "the negative-control genome must still survive the move (G6 holds; only the re-derive differs): {outcome:?}"
    );
    // The generation still bumped (the daemon bumps it on restore regardless of the
    // genome's behavior; the genome simply ignored it).
    assert_eq!(
        outcome.generation_post,
        outcome.generation_pre + 1,
        "the VMGenID generation still bumps on restore even for the broken genome (pre={}, post={})",
        outcome.generation_pre,
        outcome.generation_post,
    );

    // Both fingerprints must have landed (so the equality assertion is meaningful).
    let pre = outcome
        .fingerprint_pre
        .as_deref()
        .expect("the broken genome must report a pre-snapshot fingerprint");
    let post = outcome
        .fingerprint_post
        .as_deref()
        .expect("the broken genome must report a post-resume fingerprint");

    // THE TEETH: the broken genome's post-resume fingerprint EQUALS its pre-snapshot
    // one. This is the catastrophic nonce-reuse (in the real system, a reused FROST
    // nonce that leaks the key share). It is EXACTLY what G7 fails on.
    assert_eq!(
        pre, post,
        "the negative control must REUSE its pre-snapshot fingerprint after resume \
         (post == pre): this is the nonce-reuse the gate exists to catch"
    );
    assert!(
        outcome.fingerprints_equal(),
        "the negative control's fingerprints must be EQUAL (the reuse the gate catches)"
    );

    // The gate FAILS for the broken genome: g7_passed() is FALSE because the
    // fingerprints did not differ. This is the gate doing its job.
    assert!(
        !outcome.g7_passed(),
        "G7 must FAIL for the negative-control genome (it reused its entropy): {outcome:?}"
    );

    eprintln!(
        "G7 NEGATIVE CONTROL PASS: the broken genome REUSED its entropy on resume \
         (fingerprint_pre={pre} == fingerprint_post={post}), so g7_passed()=false. The gate \
         CATCHES a nonce-reuse: the correct genome's fingerprints differ (g7_passed()=true) \
         while this one's are equal. G7 has teeth (it detects the FROST-nonce-reuse class, \
         not just the happy path)."
    );
}
