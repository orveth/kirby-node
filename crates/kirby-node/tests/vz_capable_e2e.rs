//! Chunk E (macOS / Apple Virtualization): the LAST parity-backlog item — the
//! macOS-gated, full-lifecycle VZ end-to-end test. It is the macOS sibling of the
//! Linux `capable_vm_boots_plans_acts_verifies_and_dies_when_broke` e2e (the
//! `capable` arm of `metered_run`/`full_loop`), proving the WHOLE arc composes on the
//! VZ backend:
//!
//!   BOOT (G1) → GATEWAY round-trip → METERED `capable` RUN → BUDGET/HALT (G2).
//!
//! ONE genome microVM, booted under Apple `Virtualization.framework` (on macOS the
//! sandbox backend resolves to VZ: `backend = auto` → `default_backend()` selects
//! Virtualization), serving the agnostic gateway over vsock. The `capable` workload
//! composes the two brokered acts the daemon already performs — `Completion`
//! (PLAN/THINK) and `Memory` (RECALL/ACT/VERIFY) — on ONE gateway, draining the
//! treasury THINK by THINK until it can no longer afford to live, at which point the
//! daemon's meter HALTS the VM. The death is the host-side daemon halt, NOT the genome
//! exiting on its own.
//!
//! WHY this is the macOS sibling and not a copy: on VZ the `capable` workload runs at
//! ZERO synthetic rent, so the death mechanism is the FLOOR-HALT — the meter halts once
//! the treasury can no longer GUARANTEE the next think (remaining < `brain.max_cost_sats`,
//! the per-think D-20 cap). This is platform-independent (it is driven by the gateway's
//! THINK debits over vsock, not by any cgroup/host-process rent sample), so the SAME
//! `metered_run::run` entry that drives the Linux capable e2e drives the VZ one, and the
//! terminal `BudgetExhausted` + daemon-initiated kill assertions hold identically. What
//! is macOS-specific is only the backend the boot resolves to (VZ) and the meter SOURCE
//! it attaches (the VZ host-process/allocation source), both selected below the shared
//! `metered_run` seam — so this file touches NO shared code.
//!
//! As the stub brain (`StubBrain`) returns canned PROSE, not the capable line-grammar,
//! each tick the genome's parser sees non-grammar text and produces a SAFE no-op rather
//! than a write — itself valuable end-to-end evidence (the parser NEVER panics on real,
//! non-grammar brain output inside a REAL VZ microVM, and the THINK still drains to a
//! budget-death halt: metabolism + no-panic + death across the full VZ stack). The
//! SET/VERIFY self-correction cycle is exercised deterministically by the in-process
//! `capable_tick` teeth in `kirby-genome/src/capable.rs`.
//!
//! SKIP-green without the genome image: with `KIRBY_GENOME_IMAGE` unset (or its path
//! absent) the test prints a clearly visible `SKIP: chunk-e VZ e2e ...` line and PASSES
//! (returns early), so it is green on CI/dev boxes without an image. On a self-hosted
//! Mac runner with the image staged it boots a real VZ microVM and runs for real.
//!
//! macOS + Apple Silicon only (the VZ backend).
#![cfg(target_os = "macos")]

use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::config::{AgentConfig, BrainConfig, MemoryConfig};
use kirby_node::metered_run::{self, MeteredRunConfig, MeteredRunOutcome, Terminated};

/// Resolve the genome image from `KIRBY_GENOME_IMAGE`, or print a VISIBLE skip line and
/// return `None` so the test PASSES early. The skip message is the chunk-E sentinel the
/// verifier greps for on a box without the image.
fn image_or_skip() -> Option<ImagePaths> {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!("SKIP: chunk-e VZ e2e — KIRBY_GENOME_IMAGE not set");
        return None;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    if !image_dir.exists() {
        eprintln!(
            "SKIP: chunk-e VZ e2e — KIRBY_GENOME_IMAGE path does not exist ({})",
            image_dir.display()
        );
        return None;
    }
    Some(ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)"))
}

/// Drive the WHOLE arc on ONE VZ genome: BOOT (G1) → GATEWAY round-trip → METERED
/// `capable` RUN → BUDGET/HALT (G2). The death is the unaffordable THINK (the FLOOR-HALT
/// at `brain.max_cost_sats`), reached entirely through the gateway over vsock; the daemon
/// halts the VM. Mirrors the Linux capable e2e shape, gated to the VZ backend on macOS.
#[tokio::test]
async fn chunk_e_vz_boots_gateways_meters_capable_run_and_halts_when_broke() {
    let Some(image) = image_or_skip() else {
        return;
    };

    // A small budget so the agent lives, thinks a few times, then drains to a budget-death
    // halt within a few seconds. Budget == initial treasury so exhausting the budget drains
    // the treasury to its sub-think floor. The brain + memory are deterministic stubs (no
    // money, no relay); the capable loop PLANs each tick, draining the treasury THINK by
    // THINK until it cannot guarantee another think (the FLOOR-HALT death).
    let budget: u64 = 800;
    let brain = BrainConfig {
        max_cost_sats: 64,
        ..BrainConfig::default()
    };
    let memory = MemoryConfig {
        max_cost_sats: 256, // a generous per-write ceiling (host cost stays well under it)
        ..MemoryConfig::default()
    };
    // The capable workload reuses the agent cadence/recall cmdline knobs (no new daemon
    // plumbing): `tick_secs` drives the loop cadence, `recall_count` the RECALL depth.
    let agent = AgentConfig {
        tick_secs: 1,
        recall_count: 3,
    };

    let boot = BootConfig {
        image,
        node_id: format!("chunke-vz-{}", std::process::id()),
        task: "chunk-e-vz-capable-e2e".to_string(),
        budget_sats: budget,
        initial_sats: budget,
        // The capable workload allowlists BOTH sentinels (it composes the two acts) and can
        // reach nothing else (the membrane is fail-closed).
        allow: vec![
            kirby_node::rail::BRAIN_COMPLETION_DESTINATION.to_string(),
            kirby_node::rail::MEMORY_DESTINATION.to_string(),
        ],
        // A CID + port distinct from the other VZ tests so a real run is isolated.
        guest_cid: 33,
        gateway_port: 5033,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(60),
        workload: Some("capable".to_string()),
        // `Some(brain)` selects the CompositeRail(StubBrain); `Some(memory)` injects the
        // StubMemory; `Some(agent)` carries the cadence/recall knobs onto the genome cmdline.
        brain: Some(brain),
        memory: Some(memory),
        agent: Some(agent),
        social: None,
        nip60: Default::default(),
        fleet_relay: String::new(),
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
        lease_fence: None,
    };

    let config = MeteredRunConfig {
        boot,
        tick: Duration::from_millis(100),
        max_run: Duration::from_secs(90),
        agent_state: None,
        rates: kirby_node::meter::BurnRates::default(),
    };

    // BOOT (G1) + GATEWAY round-trip + METERED capable RUN, terminating in the BUDGET/HALT
    // (G2). `metered_run::run` boots the VZ microVM, serves the gateway over vsock, attaches
    // the host meter, and ticks until the FLOOR-HALT halts the VM. A non-completing run would
    // surface as an `Err` here (the boot failed) rather than a wrong terminal.
    let outcome: MeteredRunOutcome = metered_run::run(config)
        .await
        .expect("VZ capable metered run completed (boot → gateway → metered run → halt)");

    // BUDGET/HALT (G2): the VM ended in `Terminated::BudgetExhausted` — the daemon halted it
    // on the unaffordable-THINK floor, NOT the safety ceiling and NOT the genome exiting. A
    // `Stopped` here would mean the agent never drained to its think-floor within `max_run`
    // (the death gate never tripped), so the e2e arc did not close.
    assert_eq!(
        outcome.terminated,
        Terminated::BudgetExhausted,
        "the capable VZ agent must live then drain to a budget-death halt, got {:?} after {} ticks \
         (Stopped = the unaffordable-THINK floor was never reached = the death arc did not close)",
        outcome.terminated,
        outcome.ticks
    );

    // The kill was daemon-initiated: the genome parked / drained through the gateway, and the
    // daemon's meter loop decided to halt and killed the VM (the genome never exited on its own).
    assert!(
        outcome.daemon_initiated_kill,
        "the budget-death halt must be daemon-initiated (the genome drained, the daemon killed it)"
    );

    // The halt left a sub-think leftover: the treasury could no longer guarantee another think
    // (remaining < the per-think floor of 64). It is NOT necessarily zero (the capable loop runs
    // at zero synthetic rent, so the FLOOR-HALT moves no money — it halts on a sub-think balance),
    // and it must be strictly under the budget (the agent DID live and think first).
    assert!(
        outcome.remaining_at_halt < budget,
        "the agent must have lived and spent on THINKs before the halt (remaining {} < budget {budget})",
        outcome.remaining_at_halt
    );

    eprintln!(
        "CHUNK-E VZ e2e PASS: backend=vz ; terminal={:?} ; remaining_at_halt={} (budget={budget}) ; \
         daemon_initiated_kill={} ; meter_ticks={} ; tick_ms={}",
        outcome.terminated,
        outcome.remaining_at_halt,
        outcome.daemon_initiated_kill,
        outcome.ticks,
        outcome.tick.as_millis(),
    );
}
