//! The metered run and the budget-death HALT (spec 3.3, 4.1, gate G2).
//!
//! This is C-4's top-level orchestration: boot the genome microVM (reusing the
//! C-2 boot + gateway path), attach the host-authoritative meter to the VM's
//! dedicated cgroup, then tick: read `cpu.stat` + `memory.current`, convert to a
//! synthetic burn, and debit the daemon-owned treasury. When cumulative burn
//! reaches the genome's budget the treasury refuses a tick, and the daemon
//! HALTS the VM (pause then kill) and records the terminal state
//! `Terminated{budget_exhausted}`. The genome does NOT cooperate in its own
//! death: the daemon kills it. This is Kirby's death by exhaustion at spike
//! scale.
//!
//! The VM-lifecycle terminal state (spec 4.1) is owned here, by the daemon; the
//! genome can only make gateway calls, never drive a transition.

use std::time::Duration;

use crate::boot::{self, BootConfig};
use crate::checkpoint::CheckpointArtifact;
#[cfg(target_os = "macos")]
use crate::meter::HostProcessMeterConfig;
#[cfg(target_os = "linux")]
use crate::meter::MeterConfig;
use crate::meter::{Meter, MeterOutcome};
use crate::sandbox::MeterSource;
use crate::treasury::DebitOutcome;

/// The terminal state of the VM after a metered run (spec 4.1). The genome
/// cannot reach these; the daemon drives the transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminated {
    /// Cumulative metered burn reached the budget; the daemon paused then killed
    /// the VM (gate G2). This is the budget-death halt.
    BudgetExhausted,
    /// The run was stopped for another reason before exhaustion (e.g. a manual
    /// stop, or a failover kill in a later chunk).
    Stopped,
}

/// The G2 evidence from a metered run: the terminal state, the total metered
/// burn (`~= budget`, NOT zero, proving the meter read real cgroup usage), the
/// treasury balance at halt (within one tick of zero), the tick granularity the
/// halt is accurate to, and whether the daemon initiated the kill (it always
/// does here, the genome never cooperates).
#[derive(Debug, Clone)]
pub struct MeteredRunOutcome {
    pub terminated: Terminated,
    /// Total sats the host meter debited (the G2 metered-burn figure).
    pub burned_sats: u64,
    /// Cumulative CPU microseconds sampled by the host meter.
    pub cpu_usec: u64,
    /// The treasury balance reported by the refused (over-budget) tick: the
    /// leftover smaller than one tick's burn (G2: remaining `~= 0`).
    pub remaining_at_halt: u64,
    /// The budget the run was given (the burn is `~=` this, G2).
    pub budget_sats: u64,
    /// Ticks elapsed (the halt is accurate to ONE of these, spec section 11).
    pub ticks: u64,
    /// The sampling tick interval, so the report can state the granularity.
    pub tick: Duration,
    /// The daemon killed the VM (true here always): the budget-death halt is
    /// daemon-initiated, the genome did not exit on its own (G2).
    pub daemon_initiated_kill: bool,
    /// Latest app-checkpoint submitted by the genome during this metered run, if
    /// the selected workload is checkpoint-aware.
    pub latest_checkpoint: Option<CheckpointArtifact>,
}

/// Inputs for a metered run. Reuses the boot config and adds the meter tick (the
/// rates default unless overridden). The budget is `boot.budget_sats`, and the
/// treasury initial balance is `boot.initial_sats`; G2 sets both to the same B
/// so exhausting the budget drains the treasury to ~0.
pub struct MeteredRunConfig {
    pub boot: BootConfig,
    /// The metering tick. The halt is accurate to one of these (spec section 11).
    pub tick: Duration,
    /// A safety ceiling so a misconfigured run (e.g. an idle genome that never
    /// burns) cannot loop forever. Reaching it returns `Terminated::Stopped`.
    pub max_run: Duration,
}

impl MeteredRunConfig {
    /// A metered run with a 100 ms tick and a generous safety ceiling.
    pub fn new(boot: BootConfig) -> Self {
        MeteredRunConfig {
            boot,
            tick: Duration::from_millis(100),
            max_run: Duration::from_secs(120),
        }
    }
}

/// Boot the genome, meter it on a tick, and HALT it on budget exhaustion (gate
/// G2). Returns the G2 evidence. The VM is always halted (the daemon-initiated
/// teardown) before returning, including on the exhaustion path and on an error.
pub async fn run(config: MeteredRunConfig) -> anyhow::Result<MeteredRunOutcome> {
    let budget_sats = config.boot.budget_sats;
    let tick = config.tick;
    let max_run = config.max_run;

    // Boot the VM and serve the gateway (C-2 path); get the shared treasury so
    // the meter debits the SAME counter the gateway uses (D-9).
    let (vm, outcome, treasury, _events, _serve_guard) =
        boot::boot_and_observe(config.boot).await?;
    if !outcome.reached_running {
        vm.halt().await;
        anyhow::bail!("metered run: VM did not reach Running");
    }
    let checkpoints = outcome.checkpoints.clone();

    // Attach the backend-reported host meter source. The burn math and treasury
    // debit are shared; only the sample source differs by platform.
    let mut meter = match vm.meter_source() {
        #[cfg(target_os = "linux")]
        MeterSource::CgroupV2 { rel_path } => {
            let meter_config = MeterConfig {
                cgroup_rel_path: rel_path.clone(),
                tick,
                rates: Default::default(),
            };
            let meter = match Meter::attach(&meter_config, treasury) {
                Ok(m) => m,
                Err(e) => {
                    vm.halt().await;
                    return Err(anyhow::anyhow!(
                        "metered run: cgroup meter attach failed: {e}"
                    ));
                }
            };
            tracing::info!(
                budget_sats,
                tick_ms = tick.as_millis() as u64,
                cgroup = %rel_path.display(),
                "metering started from cgroup source (host-authoritative; ReportEvent numbers are never billed, G3c)"
            );
            meter
        }
        #[cfg(not(target_os = "linux"))]
        MeterSource::CgroupV2 { .. } => {
            vm.halt().await;
            anyhow::bail!("metered run: cgroup meter source is unsupported on this host")
        }
        #[cfg(target_os = "macos")]
        MeterSource::HostProcess {
            root_pid,
            service_pids,
            memory_mib,
        } => {
            let meter_config = HostProcessMeterConfig {
                root_pid,
                service_pids: service_pids.clone(),
                memory_mib,
                tick,
                rates: Default::default(),
            };
            let meter = match Meter::attach_host_process(&meter_config, treasury) {
                Ok(m) => m,
                Err(e) => {
                    vm.halt().await;
                    return Err(anyhow::anyhow!(
                        "metered run: host-process meter attach failed: {e}"
                    ));
                }
            };
            tracing::info!(
                budget_sats,
                tick_ms = tick.as_millis() as u64,
                root_pid,
                service_pids = ?service_pids,
                memory_mib,
                "metering started from macOS VZ host-process source (HostCoarse; memory is billed as cap-time)"
            );
            meter
        }
    };

    // The meter loop: tick, read the cgroup, debit. On the over-budget tick the
    // treasury refuses (Insufficient) and we HALT. A safety deadline bounds the
    // loop so a non-burning genome cannot hang the run.
    let meter_outcome = match tick_until_exhausted(&mut meter, max_run).await {
        Ok(outcome) => outcome,
        Err(e) => {
            vm.halt().await;
            return Err(anyhow::anyhow!("metered run: meter tick failed: {e}"));
        }
    };

    // The budget-death HALT: the daemon pauses then kills the VM (NOT the
    // genome cooperating). Done for both terminal paths so the jail is always
    // cleaned. This is the spec 4.1 transition to Terminated, owned by the daemon.
    tracing::info!(
        burned_sats = meter.burned_sats(),
        cpu_usec = meter.cpu_usec(),
        ticks = meter.ticks(),
        "budget reached: daemon HALTING the VM (pause then kill), recording terminated:budget_exhausted"
    );
    vm.halt().await;

    let (terminated, remaining_at_halt) = match meter_outcome {
        MeterOutcome::BudgetExhausted {
            remaining_at_halt, ..
        } => {
            tracing::info!("terminated:budget_exhausted (death by exhaustion, G2)");
            (Terminated::BudgetExhausted, remaining_at_halt)
        }
        MeterOutcome::Stopped { remaining, .. } => {
            tracing::warn!("metered run hit the safety ceiling before exhausting the budget");
            (Terminated::Stopped, remaining)
        }
    };

    let latest_checkpoint = checkpoints
        .latest()
        .map_err(|e| anyhow::anyhow!("metered run: read latest checkpoint: {e}"))?;

    Ok(MeteredRunOutcome {
        terminated,
        burned_sats: meter.burned_sats(),
        cpu_usec: meter.cpu_usec(),
        remaining_at_halt,
        budget_sats,
        ticks: meter.ticks(),
        tick,
        // The kill is always daemon-initiated: the meter loop decided to halt and
        // called vm.halt(); the genome never exits on its own (it idles/burns
        // until the daemon kills it). This is the G2 "daemon killed it" property.
        daemon_initiated_kill: true,
        latest_checkpoint,
    })
}

/// Tick the meter until the treasury refuses a tick (budget exhausted) or the
/// safety deadline elapses. Sleeps one tick between reads (the granularity the
/// halt is accurate to). Returns the meter outcome; the caller halts the VM.
async fn tick_until_exhausted(
    meter: &mut Meter,
    max_run: Duration,
) -> anyhow::Result<MeterOutcome> {
    let tick = meter.tick_interval();
    let deadline = tokio::time::Instant::now() + max_run;

    loop {
        tokio::time::sleep(tick).await;

        match meter.tick_once()? {
            DebitOutcome::Debited { remaining, .. } => {
                // Burn accrued; keep ticking. Trace occasionally for the log.
                if meter.ticks().is_multiple_of(10) {
                    tracing::debug!(
                        ticks = meter.ticks(),
                        burned_sats = meter.burned_sats(),
                        remaining,
                        "metering tick"
                    );
                }
            }
            DebitOutcome::Insufficient { remaining } => {
                // The over-budget tick: cumulative burn reached the budget. This
                // is the HALT trigger (spec 3.3 / 4.1, gate G2).
                return Ok(MeterOutcome::BudgetExhausted {
                    burned_sats: meter.burned_sats(),
                    remaining_at_halt: remaining,
                    ticks: meter.ticks(),
                });
            }
            // debit_metered never writes a ledger key, so it never returns
            // Duplicate; treat it defensively as a no-op continue.
            DebitOutcome::Duplicate(_) => {}
        }

        if tokio::time::Instant::now() >= deadline {
            return Ok(MeterOutcome::Stopped {
                burned_sats: meter.burned_sats(),
                remaining: meter.treasury_remaining_best_effort(),
                ticks: meter.ticks(),
            });
        }
    }
}
