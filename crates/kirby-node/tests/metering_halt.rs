//! C-4 test (gate G2): host-authoritative metering and the budget-death HALT.
//!
//! The daemon boots the genome microVM, places it in a dedicated cgroup under
//! the daemon's delegated user slice, runs the burn workload in the genome
//! (allocate memory + spin CPU), meters CPU + memory on a tick against the
//! treasury, and when cumulative burn reaches the budget PAUSES then KILLS the
//! VM (daemon-initiated), recording `Terminated{budget_exhausted}`.
//!
//! This boots a REAL Firecracker microVM under the jailer, so it needs the host
//! prerequisites AND the built genome image (the `KIRBY_GENOME_IMAGE` env var,
//! the `nix build .#genome-image` output). With the var unset it SKIPS (green),
//! so `cargo test` stays green on a host without the image; the verifier runs it
//! with the var set as the G2 producing command.
//!
//! G2 asserts (all from the producing run):
//! - the VM ends in `Terminated{budget_exhausted}` (the daemon halted it);
//! - the kill was DAEMON-INITIATED (the genome did not cooperate, it burned
//!   until killed);
//! - the treasury drained to ~0, within ONE TICK's burn (the halt is accurate to
//!   one tick, not one instruction, spec section 11);
//! - metered burn was ~= the budget B and NOT zero (proving the meter read
//!   non-zero cgroup usage: `cpu.stat usage_usec` + `memory.current`).
//!
//! It also exercises G3c structurally: the burn genome lies over `ReportEvent`
//! (it reports cpu=0 while burning real CPU); the daemon ignores self-reported
//! numbers and bills the cgroup, so the VM is still billed and still halted.

use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::metered_run::{self, MeteredRunConfig, Terminated};

/// G2: meter the burn genome and assert the budget-death halt.
#[tokio::test]
async fn g2_meters_and_halts_on_budget() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP g2_meters_and_halts_on_budget: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the real-microVM metering test (gate G2)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    // A small budget so the burn exhausts it in a couple of seconds. Budget ==
    // initial treasury, so exhausting the budget drains the treasury to ~0.
    let budget: u64 = 3_000;
    let tick = Duration::from_millis(100);

    let boot = BootConfig {
        image,
        node_id: format!("g2test-{}", std::process::id()),
        task: "g2-burn".to_string(),
        budget_sats: budget,
        initial_sats: budget,
        allow: vec!["mint.test.local".to_string()],
        // Distinct CID and port keep this test isolated from any other VM.
        guest_cid: 19,
        gateway_port: 5019,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        // The burn workload: allocate measurable memory and spin the CPU so the
        // host meter reads non-zero cgroup usage (the G2 burn-not-zero property).
        workload: Some("burn".to_string()),
        brain: None,
        // G2 is vsock-only (CPU + memory metering); the egress meter and TAP are
        // C-5 (gate G4), exercised by the egress test.
        lockdown_egress: false,
        // G2 does not snapshot; snapshot + resume is C-7 (gate G6).
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    let config = MeteredRunConfig {
        boot,
        tick,
        // A safety ceiling well above the expected ~2s exhaustion; if the meter
        // read zero (a broken placement) the run would hit this and the
        // terminal-state assertion below would fail loudly (NOT a false pass).
        max_run: Duration::from_secs(60),
        // G2 metering-halt gate: no fleet observability needed here.
        agent_state: None,
    };

    let outcome = metered_run::run(config)
        .await
        .expect("metered run completed");

    // The VM ended in Terminated{budget_exhausted}: the daemon halted it on
    // budget exhaustion (NOT the safety ceiling, NOT the genome exiting).
    assert_eq!(
        outcome.terminated,
        Terminated::BudgetExhausted,
        "the VM must end in Terminated{{budget_exhausted}}, got {:?} after {} ticks",
        outcome.terminated,
        outcome.ticks
    );

    // The kill was daemon-initiated: the genome burned until the daemon killed
    // it; it did not cooperate in its own death (G2).
    assert!(
        outcome.daemon_initiated_kill,
        "the budget-death halt must be daemon-initiated (the daemon killed the VM)"
    );

    // Metered burn is NOT zero. Non-zero proves the meter read real cgroup usage
    // (cpu.stat usage_usec + memory.current); a zero burn would mean the
    // placement failed and we billed nothing.
    assert!(
        outcome.burned_sats > 0,
        "metered burn must be non-zero (the meter read real cgroup usage), got 0"
    );

    // Conservation: every sat of the budget is either debited (burned) or the
    // un-debitable remainder the refused (over-budget) tick reported. The budget
    // equals the treasury initial balance, so debited + remaining == budget. This
    // is the exact "treasury drained, burn accounts for it" invariant.
    assert_eq!(
        outcome.burned_sats + outcome.remaining_at_halt,
        budget,
        "metered burn ({}) plus remaining-at-halt ({}) must equal the budget ({budget})",
        outcome.burned_sats,
        outcome.remaining_at_halt
    );

    // The treasury drained to ~0, within ONE TICK's burn, and the burn reached
    // ~= the budget. The halt is accurate to one tick (spec section 11): the last
    // accepted tick left a remainder smaller than one tick's burn, and the
    // refused tick did not debit. One tick of the burn workload (a pinned vCPU
    // for 100 ms + ~32 MiB resident) is on the order of ~100 sats CPU plus a few
    // sats of mem-time; bound the leftover at a comfortable ceiling (10% of the
    // budget) so the test is robust on a loaded host while still asserting "~= 0"
    // (NOT "treasury left mostly full").
    let one_tick_ceiling = (budget / 10).max(200);
    assert!(
        outcome.remaining_at_halt <= one_tick_ceiling,
        "remaining at halt ({}) must be within ~one tick of zero (<= {one_tick_ceiling}); \
         the halt is accurate to one tick (spec section 11)",
        outcome.remaining_at_halt
    );
    // Equivalently, the burn reached within one tick of the full budget.
    assert!(
        outcome.burned_sats >= budget - one_tick_ceiling,
        "metered burn ({}) must have reached ~= the budget ({budget}, within one tick)",
        outcome.burned_sats
    );

    // A clear evidence line in the test output (the verifier reads it).
    eprintln!(
        "G2 PASS: terminal={:?} ; metered_burn_sats={} (budget={budget}) ; \
         remaining_at_halt={} ; daemon_initiated_kill={} ; ticks={} ; tick_ms={}",
        outcome.terminated,
        outcome.burned_sats,
        outcome.remaining_at_halt,
        outcome.daemon_initiated_kill,
        outcome.ticks,
        outcome.tick.as_millis(),
    );
}
