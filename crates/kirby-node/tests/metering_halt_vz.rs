//! Chunk D (gate G2 on macOS / Apple Virtualization): host-authoritative metering
//! and the budget-death HALT, proven against a REAL VZ microVM.
//!
//! This is the macOS-gated sibling of `metering_halt.rs` (the Linux/Firecracker G2
//! test). On macOS the sandbox backend resolves to VZ (`backend = auto` →
//! `default_backend()` selects Virtualization), and the host meter is the
//! ALLOCATION source (chunk D pt.2): a VZ guest's vCPU time is structurally
//! unmeterable at the host (billed to Hypervisor.framework, invisible to
//! `proc_pid_rusage`; `task_for_pid` SIP-blocked), so the meter bills the
//! RESERVATION — `vcpu_count × elapsed × rate`, i.e. usage billing assuming 100%
//! utilization — plus the memory cap. The Linux test reads cgroup `cpu.stat`; here
//! the same metered-run entry drives the VZ backend and the allocation meter instead.
//!
//! WHY this test exists: the VZ meter must have TEETH. This test boots a real burn
//! genome under VZ with a small budget + short tick and asserts the G2 properties
//! end-to-end:
//!   - the VM ends in `Terminated::BudgetExhausted` (the daemon halted it);
//!   - the kill was daemon-initiated (the genome burned until killed);
//!   - metered burn is NON-ZERO (the allocation meter accrued vcpu×elapsed + memory);
//!   - conservation: burned + remaining == budget;
//!   - the halt is accurate to ~one tick (treasury drained to ~0).
//!
//! NOTE: the former `g2_vz_busy_burns_more_than_idle` precision test is RETIRED. It
//! asserted busy > idle, a now-dead invariant: allocation billing is utilization-
//! blind BY DESIGN (a pinned vCPU and an idle vCPU bill identically — that is the
//! whole point of billing the reservation). The allocation TEETH now live as
//! deterministic unit tests on `AllocationMeterSource::sample_at` in `meter.rs`
//! (linear-in-elapsed, equal-elapsed-equal-bill, 2× scaling with vcpu_count) — no VM,
//! no flakiness. The end-to-end die-when-broke teeth remain here, below, unweakened.
//!
//! With `KIRBY_GENOME_IMAGE` unset the test SKIPS (green), same idiom as the Linux
//! test; the verifier runs it with the var pointed at the aarch64 genome image.

#![cfg(target_os = "macos")]

use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::metered_run::{self, MeteredRunConfig, MeteredRunOutcome, Terminated};

/// Resolve the genome image from `KIRBY_GENOME_IMAGE`, or `None` to SKIP (green).
fn image_or_skip(test: &str) -> Option<ImagePaths> {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP {test}: set KIRBY_GENOME_IMAGE to the aarch64 genome image dir \
             (vmlinux + rootfs.squashfs) to run the real-VZ metering test (gate G2, chunk D)"
        );
        return None;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    Some(ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)"))
}

/// Build a VZ boot config. `workload = Some("burn")` spins guest CPU; `None` idles
/// (the genome's default branch in kirby-genome/src/main.rs parks PID 1). Distinct
/// CID + port per call keep concurrent/serial VMs isolated.
fn vz_boot(
    image: ImagePaths,
    task: &str,
    budget: u64,
    workload: Option<&str>,
    cid: u32,
    port: u32,
) -> BootConfig {
    BootConfig {
        image,
        node_id: format!("{task}-{}", std::process::id()),
        task: task.to_string(),
        budget_sats: budget,
        initial_sats: budget,
        allow: vec!["mint.test.local".to_string()],
        guest_cid: cid,
        gateway_port: port,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(60),
        workload: workload.map(str::to_string),
        brain: None,
        memory: None,
        agent: None,
        social: None,
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
        lease_fence: None,
    }
}

async fn run(boot: BootConfig, tick: Duration, max_run: Duration) -> MeteredRunOutcome {
    let config = MeteredRunConfig {
        boot,
        tick,
        max_run,
        agent_state: None,
        rates: kirby_node::meter::BurnRates::default(),
    };
    metered_run::run(config)
        .await
        .expect("metered run completed")
}

/// G2 teeth on VZ: meter the burn genome and assert the budget-death halt.
#[tokio::test]
async fn g2_vz_meters_and_halts_on_budget() {
    let Some(image) = image_or_skip("g2_vz_meters_and_halts_on_budget") else {
        return;
    };

    // A small budget so the burn exhausts it within a couple of seconds. Budget ==
    // initial treasury, so exhausting the budget drains the treasury to ~0.
    let budget: u64 = 3_000;
    let tick = Duration::from_millis(100);

    let boot = vz_boot(image, "g2vz-burn", budget, Some("burn"), 29, 5029);
    let outcome = run(boot, tick, Duration::from_secs(90)).await;

    // The VM ended in Terminated::BudgetExhausted (the daemon halted it on budget
    // exhaustion, NOT the safety ceiling, NOT the genome exiting).
    assert_eq!(
        outcome.terminated,
        Terminated::BudgetExhausted,
        "VZ burn must end in Terminated::BudgetExhausted, got {:?} after {} ticks \
         (Stopped = meter never reached budget = undercounting guest CPU)",
        outcome.terminated,
        outcome.ticks
    );

    // The kill was daemon-initiated (the meter loop decided to halt).
    assert!(
        outcome.daemon_initiated_kill,
        "the budget-death halt must be daemon-initiated"
    );

    // Metered burn is NON-ZERO: proves the allocation meter accrued the reservation
    // (vcpu_count × elapsed for CPU + the memory cap) and debited the treasury. Zero
    // would mean the allocation source never advanced (a broken sample/attach).
    assert!(
        outcome.burned_sats > 0,
        "metered burn must be non-zero (allocation meter billed vcpu×elapsed + memory), got 0"
    );

    // Conservation: debited burn + remaining == budget (budget == initial treasury).
    assert_eq!(
        outcome.burned_sats + outcome.remaining_at_halt,
        budget,
        "burn ({}) + remaining ({}) must equal budget ({budget})",
        outcome.burned_sats,
        outcome.remaining_at_halt
    );

    // Halt accurate to ~one tick: treasury drained to ~0 (leftover < ~one tick's
    // burn), and burn reached ~= the full budget. 10% ceiling tolerates a loaded host.
    let one_tick_ceiling = (budget / 10).max(200);
    assert!(
        outcome.remaining_at_halt <= one_tick_ceiling,
        "remaining at halt ({}) must be within ~one tick of zero (<= {one_tick_ceiling})",
        outcome.remaining_at_halt
    );
    assert!(
        outcome.burned_sats >= budget - one_tick_ceiling,
        "metered burn ({}) must have reached ~= the budget ({budget}, within one tick)",
        outcome.burned_sats
    );

    eprintln!(
        "G2-VZ PASS: terminal={:?} ; metered_burn_sats={} (budget={budget}) ; \
         remaining_at_halt={} ; daemon_initiated_kill={} ; ticks={} ; tick_ms={}",
        outcome.terminated,
        outcome.burned_sats,
        outcome.remaining_at_halt,
        outcome.daemon_initiated_kill,
        outcome.ticks,
        outcome.tick.as_millis(),
    );
}
