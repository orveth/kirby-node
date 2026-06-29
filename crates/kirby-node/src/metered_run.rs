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
use crate::nerve;
use crate::sandbox::{MeterSource, SandboxInstance};
use crate::treasury::DebitOutcome;

/// The lifecycle phase carried in a periodic 31000 agent-state emission DURING a
/// metered run. The terminal "dead" state is emitted by the run sequence at
/// budget-death (alongside the 9100 died), not from inside this loop.
const LIFECYCLE_RUNNING: &str = "running";
const LIFECYCLE_DYING: &str = "dying";

/// The fraction of the initial budget below which the agent is "dying" (the live
/// "Kirby face" turns anxious). 15% of the budget, matching the contract's
/// "treasury below ~15%" guidance.
const DYING_TREASURY_FRACTION_NUM: u64 = 15;
const DYING_TREASURY_FRACTION_DEN: u64 = 100;
/// The runway (seconds-to-broke) below which the agent is "dying", matching the
/// contract's "runway below ~30s" guidance. Whichever of the two thresholds trips
/// first marks the agent dying.
const DYING_RUNWAY_SECS: u64 = 30;

/// Periodically emits the live 31000 agent-state event ("the Kirby face") during a
/// metered run, sourcing the LIVE treasury balance + burn rate from the meter loop.
/// Held by the metered run and ticked on its own cadence (the presence interval).
/// Best-effort: a publish error is logged, never aborts the agent (like the 9100
/// lifecycle). `None` for callers that do not want fleet observability (the gate
/// tests), so the money/meter path is byte-identical when it is absent.
pub struct AgentStateEmitter {
    /// The agent's beacon signer (the SAME key all its public events sign under: the
    /// node key, or the FROST quorum key Q for a FROST tenant -- "Q signs everything").
    pub signer: crate::nerve::BeaconSigner,
    /// The relay websocket URL.
    pub relay_url: String,
    /// The agent id (the addressable `d`-tag value).
    pub agent_id: String,
    /// The node id (the `["node",X]` tag value).
    pub node_id: String,
    /// The resolved backend label ("firecracker" | "vz").
    pub backend: String,
    /// How often to (re-)publish the live state (the presence cadence is fine: 31000
    /// is addressable/replaceable, so the relay keeps only the latest per agent).
    pub interval: Duration,
    /// The initial budget, for the "dying" treasury-fraction threshold.
    pub budget_sats: u64,
}

impl AgentStateEmitter {
    /// Decide the lifecycle phase from the live treasury + runway: "dying" when the
    /// treasury is below ~15% of the budget OR the runway is under ~30s, else
    /// "running". (The terminal "dead" is emitted by the run sequence, not here.)
    fn phase(&self, treasury_sats: u64, runway_secs: Option<u64>) -> &'static str {
        let dying_floor = self
            .budget_sats
            .saturating_mul(DYING_TREASURY_FRACTION_NUM)
            / DYING_TREASURY_FRACTION_DEN.max(1);
        let low_treasury = treasury_sats <= dying_floor;
        let low_runway = runway_secs.is_some_and(|r| r <= DYING_RUNWAY_SECS);
        if low_treasury || low_runway {
            LIFECYCLE_DYING
        } else {
            LIFECYCLE_RUNNING
        }
    }

    /// Publish one live 31000 agent-state event (best-effort; logs on failure).
    async fn emit(&self, treasury_sats: u64, runway_secs: Option<u64>) {
        let lifecycle = self.phase(treasury_sats, runway_secs);
        let content = nerve::AgentStateContent::sovereign(
            &self.agent_id,
            treasury_sats,
            runway_secs,
            lifecycle,
            &self.backend,
        );
        if let Err(e) =
            nerve::publish_agent_state(&self.signer, &self.relay_url, &self.node_id, &content)
                .await
        {
            tracing::warn!(error = %e, lifecycle, "failed to publish 31000 agent-state (will retry next interval)");
        }
    }
}

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
    /// Optional periodic 31000 agent-state emitter (the live "Kirby face"). When
    /// set, the meter loop publishes the LIVE treasury + runway on this emitter's
    /// cadence; when `None` (the gate tests), the money/meter path is byte-identical
    /// and no state is emitted. Best-effort: a publish error never aborts the run.
    pub agent_state: Option<AgentStateEmitter>,
    /// The synthetic VM-rent burn rates the meter bills CPU + memory time at. Sourced from
    /// the `[meter]` config block (F4): a deploy LOWERS `mem_sats_per_mib_sec` so an
    /// always-on VM does not rent-death before it can think/journal. Defaults to
    /// [`crate::meter::BurnRates::default`], so the gate tests (which build via
    /// [`MeteredRunConfig::new`]) and any default-rate run are byte-identical to before.
    pub rates: crate::meter::BurnRates,
}

impl MeteredRunConfig {
    /// A metered run with a 100 ms tick and a generous safety ceiling, no agent-state
    /// emission (the gate-test default).
    pub fn new(boot: BootConfig) -> Self {
        MeteredRunConfig {
            boot,
            tick: Duration::from_millis(100),
            max_run: Duration::from_secs(120),
            agent_state: None,
            rates: crate::meter::BurnRates::default(),
        }
    }
}

/// The FLOOR-HALT threshold for a run, derived from its boot config (the death mechanism for the
/// think-gated diarist + capable loops). Covers BOTH bootstrap and resume (it reads `config.boot`,
/// not the run mode).
fn diarist_halt_floor(boot: &BootConfig) -> u64 {
    halt_floor_for(boot.workload.as_deref(), boot.brain.as_ref().map(|b| b.max_cost_sats))
}

/// Pure core of the floor derivation (unit-testable without a full `BootConfig`). The diarist AND
/// the capable loop (both run at zero synthetic rent) get a floor, equal to the per-think D-20 cap
/// (`brain.max_cost_sats`): at or above the cap any think is affordable, so halting strictly below
/// it is a real death (no premature kill) and forecloses the rent=0 zombie where a think-gated
/// agent parks below its cap yet is never halted (FIX-5: capable is now routable, so it needs the
/// SAME death floor as the diarist). Every other workload gets `0` (disabled) and keeps relying on
/// synthetic rent for its halt, unchanged.
fn halt_floor_for(workload: Option<&str>, brain_max_cost_sats: Option<u64>) -> u64 {
    if matches!(workload, Some("diarist") | Some("capable")) {
        brain_max_cost_sats.unwrap_or(0)
    } else {
        0
    }
}

/// Boot the genome, meter it on a tick, and HALT it on budget exhaustion (gate
/// G2). Returns the G2 evidence. The VM is always halted (the daemon-initiated
/// teardown) before returning, including on the exhaustion path and on an error.
pub async fn run(config: MeteredRunConfig) -> anyhow::Result<MeteredRunOutcome> {
    let budget_sats = config.boot.budget_sats;
    let tick = config.tick;
    let max_run = config.max_run;
    let agent_state = config.agent_state;
    // The FLOOR-HALT threshold (the diarist's death mechanism). Captured BEFORE `config.boot`
    // is moved into the boot below. For the diarist (which runs at zero synthetic rent) this
    // is `brain.max_cost_sats` — the meter halts once the treasury can no longer guarantee a
    // think, turning the genome's park into a real daemon halt instead of a zombie. `0`
    // (every other workload) leaves the meter's behavior unchanged.
    let halt_floor_sats = diarist_halt_floor(&config.boot);

    // Boot the VM and serve the gateway (C-2 path); get the shared treasury so
    // the meter debits the SAME counter the gateway uses (D-9).
    // `vm` is `mut` so the metering loop can poll `is_alive(&mut self)` to detect an
    // externally-killed/crashed guest (G-4 failover bug 1); it is still moved into `halt()` below.
    let (mut vm, outcome, treasury, _events, _serve_guard) =
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
                rates: config.rates,
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
                rates: config.rates,
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
        MeterSource::Allocation {
            vcpu_count,
            mem_mib,
            start,
        } => {
            let meter_config = crate::meter::AllocationMeterConfig {
                vcpu_count,
                mem_mib,
                start,
                tick,
                rates: config.rates,
            };
            let meter = match Meter::attach_allocation(&meter_config, treasury) {
                Ok(m) => m,
                Err(e) => {
                    vm.halt().await;
                    return Err(anyhow::anyhow!(
                        "metered run: allocation meter attach failed: {e}"
                    ));
                }
            };
            tracing::info!(
                budget_sats,
                tick_ms = tick.as_millis() as u64,
                vcpu_count,
                mem_mib,
                "metering started from allocation source (chunk D pt.2; vCPU/memory reservation billed at 100% utilization)"
            );
            meter
        }
    };
    // Arm the FLOOR-HALT for the diarist (no-op when 0, i.e. every other workload). With zero
    // rent this is the diarist's death: the meter halts when remaining < brain.max_cost_sats.
    meter.set_halt_floor(halt_floor_sats);

    // The meter loop: tick, read the cgroup, debit. On the over-budget tick the
    // treasury refuses (Insufficient) and we HALT. A safety deadline bounds the
    // loop so a non-burning genome cannot hang the run. The optional agent-state
    // emitter publishes the LIVE treasury + runway on its cadence (best-effort
    // observability only; the money/meter path is unchanged).
    // Pass the live VM so the loop can detect an externally-killed/crashed guest and end the run
    // (G-4 failover bug 1). `vm` is otherwise untouched during the loop; the borrow ends when
    // `tick_until_exhausted` returns, before the `vm.halt()` teardown below.
    let meter_outcome = match tick_until_exhausted(&mut meter, Some(&mut *vm), max_run, agent_state.as_ref()).await {
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
            // Two ways to reach Stopped: the safety ceiling (`max_run`) elapsed, OR the guest VMM
            // exited and the loop ended the run early (G-4 failover bug 1 — logged distinctly at
            // the detection point above). Either way the daemon halts + records terminated:stopped.
            tracing::warn!("metered run ended before budget exhaustion (safety ceiling reached, or the guest VMM exited — see the prior log line)");
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
///
/// If `agent_state` is `Some`, also publishes the LIVE 31000 agent-state on its
/// cadence (immediately on the first tick so the UI flips off "pending" promptly,
/// then every `interval`), sourcing the live treasury + runway from the meter. The
/// emission is best-effort and additive: it reads the meter, never the money path.
async fn tick_until_exhausted(
    meter: &mut Meter,
    mut vm: Option<&mut dyn SandboxInstance>,
    max_run: Duration,
    agent_state: Option<&AgentStateEmitter>,
) -> anyhow::Result<MeterOutcome> {
    let tick = meter.tick_interval();
    let start = tokio::time::Instant::now();
    let deadline = start + max_run;
    // The next instant a 31000 agent-state should be published. The first emission
    // fires on the first tick (right after the meter has a reading) so the live face
    // appears quickly; thereafter on the emitter's interval.
    let mut next_emit = start;

    loop {
        tokio::time::sleep(tick).await;

        // G-4 failover bug 1 (proactive agent-death detection): end the run if the guest VMM has
        // EXITED (crashed or was killed externally). Without this the loop keeps ticking ~0 burn
        // until the budget/ceiling while the fleet supervisor heartbeats the dead agent's lease
        // every ~10s forever, so its lease never goes stale and no peer ever fails it over. Ending
        // the run makes the `kirby agent` process exit, which the supervisor's child-liveness reap
        // observes → it stops heartbeating → the lease goes stale → G-4 takes the agent over.
        // `vm` is `None` only in the in-process tick tests (no real VM to watch), where the loop
        // behaves exactly as before. The probe is a cheap cgroup-procs read (Firecracker).
        if let Some(inst) = vm.as_deref_mut() {
            if !inst.is_alive() {
                tracing::warn!(
                    ticks = meter.ticks(),
                    burned_sats = meter.burned_sats(),
                    "metered run: the guest VMM has EXITED (no live process in its cgroup); ending the run so the supervisor reaps this tenant and its lease goes stale (G-4 failover)"
                );
                return Ok(MeterOutcome::Stopped {
                    burned_sats: meter.burned_sats(),
                    remaining: meter.treasury_remaining_best_effort(),
                    ticks: meter.ticks(),
                });
            }
        }

        let (remaining, exhausted) = match meter.tick_once()? {
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
                (remaining, false)
            }
            DebitOutcome::Insufficient { remaining } => {
                // The over-budget tick: cumulative burn reached the budget. This
                // is the HALT trigger (spec 3.3 / 4.1, gate G2).
                (remaining, true)
            }
            // debit_metered never writes a ledger key, so it never returns
            // Duplicate; treat it defensively as a no-op continue.
            DebitOutcome::Duplicate(_) => (meter.treasury_remaining_best_effort(), false),
        };

        // Publish the live 31000 face on the emitter cadence (best-effort). Done
        // before the exhaustion return so the dying phase shows; the terminal "dead"
        // is emitted by the run sequence at budget-death. Skipped entirely when no
        // emitter is configured (the gate-test path, byte-identical money flow).
        if let Some(emitter) = agent_state {
            let now = tokio::time::Instant::now();
            if now >= next_emit {
                let runway_secs = estimate_runway_secs(remaining, meter.burned_sats(), start, now);
                emitter.emit(remaining, runway_secs).await;
                next_emit = now + emitter.interval;
            }
        }

        if exhausted {
            return Ok(MeterOutcome::BudgetExhausted {
                burned_sats: meter.burned_sats(),
                remaining_at_halt: remaining,
                ticks: meter.ticks(),
            });
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

/// Estimate seconds-to-broke at the current burn rate: `remaining / (burned /
/// elapsed_secs)`. Returns `None` (the contract's `null` runway) until a burn rate
/// is established (no elapsed time or nothing burned yet), so the UI never shows a
/// divide-by-zero or a bogus infinite runway on the first tick.
fn estimate_runway_secs(
    remaining_sats: u64,
    burned_sats: u64,
    start: tokio::time::Instant,
    now: tokio::time::Instant,
) -> Option<u64> {
    let elapsed_secs = now.duration_since(start).as_secs_f64();
    if elapsed_secs <= 0.0 || burned_sats == 0 {
        return None; // no established burn rate yet -> null runway
    }
    let burn_rate_per_sec = burned_sats as f64 / elapsed_secs;
    if burn_rate_per_sec <= 0.0 {
        return None;
    }
    Some((remaining_sats as f64 / burn_rate_per_sec) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emitter(budget_sats: u64) -> AgentStateEmitter {
        // A per-call unique dir (pid + a process-wide counter) so parallel tests do
        // not collide on the node key file (load_or_create uses create_new).
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "kirby-emitter-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = crate::nerve::NodeIdentity::load_or_create(&dir.join("node.key")).unwrap();
        AgentStateEmitter {
            signer: crate::nerve::BeaconSigner::NodeKey(identity),
            relay_url: "ws://127.0.0.1:7777".to_string(),
            agent_id: "agent-0".to_string(),
            node_id: "node-1".to_string(),
            backend: "firecracker".to_string(),
            interval: Duration::from_secs(15),
            budget_sats,
        }
    }

    /// The FLOOR-HALT derivation (the death mechanism for the think-gated demos): the diarist AND
    /// the capable loop floor at their per-think D-20 cap; every other workload keeps a 0 floor
    /// (disabled, rent-driven).
    #[test]
    fn halt_floor_is_the_per_think_cap_for_think_gated_workloads_zero_otherwise() {
        assert_eq!(halt_floor_for(Some("diarist"), Some(64)), 64, "the diarist floors at brain.max_cost_sats");
        // FIX-5: capable is routable + think-gated + zero-rent, so it floors at its per-think cap too.
        assert_eq!(halt_floor_for(Some("capable"), Some(64)), 64, "the capable loop floors at brain.max_cost_sats");
        // Every other workload keeps a 0 floor (disabled): synthetic rent drives their halt.
        assert_eq!(halt_floor_for(Some("brain"), Some(64)), 0);
        assert_eq!(halt_floor_for(Some("memory"), Some(64)), 0);
        assert_eq!(halt_floor_for(Some("burn"), Some(64)), 0);
        assert_eq!(halt_floor_for(None, Some(64)), 0, "an idle/unset workload is not floored");
        // A think-gated workload with no brain (validate() forbids it) floors at 0, no panic.
        assert_eq!(halt_floor_for(Some("diarist"), None), 0);
        assert_eq!(halt_floor_for(Some("capable"), None), 0);
    }

    #[test]
    fn runway_is_null_until_a_burn_rate_is_established() {
        let t0 = tokio::time::Instant::now();
        // No elapsed time yet -> null (no rate).
        assert_eq!(estimate_runway_secs(1_000, 0, t0, t0), None);
        // Elapsed but nothing burned yet -> null.
        let later = t0 + Duration::from_secs(1);
        assert_eq!(estimate_runway_secs(1_000, 0, t0, later), None);
    }

    #[test]
    fn runway_divides_remaining_by_burn_rate() {
        let t0 = tokio::time::Instant::now();
        let later = t0 + Duration::from_secs(2);
        // Burned 1000 sats over 2s = 500 sats/s; 1000 remaining -> 2s of runway.
        assert_eq!(estimate_runway_secs(1_000, 1_000, t0, later), Some(2));
        // 5000 remaining at the same 500 sats/s -> 10s.
        assert_eq!(estimate_runway_secs(5_000, 1_000, t0, later), Some(10));
    }

    #[test]
    fn phase_running_when_well_funded() {
        let e = emitter(10_000);
        // Plenty of treasury (above the 15% floor of 1500) and a long runway.
        assert_eq!(e.phase(8_000, Some(120)), LIFECYCLE_RUNNING);
        // A high treasury with an as-yet-unknown runway is still running.
        assert_eq!(e.phase(8_000, None), LIFECYCLE_RUNNING);
    }

    #[test]
    fn phase_dying_on_low_treasury_or_low_runway() {
        let e = emitter(10_000);
        // Treasury below 15% (1500) -> dying, regardless of runway.
        assert_eq!(e.phase(1_000, Some(120)), LIFECYCLE_DYING);
        assert_eq!(e.phase(1_500, None), LIFECYCLE_DYING);
        // Runway under 30s -> dying, even with treasury above the floor.
        assert_eq!(e.phase(8_000, Some(10)), LIFECYCLE_DYING);
        // Exactly at the runway threshold counts as dying (<=).
        assert_eq!(e.phase(8_000, Some(30)), LIFECYCLE_DYING);
    }

    /// THE rent=0 zombie-gone regression (the [HIGH] the 3-way review flagged), proving the
    /// FLOOR-HALT is a LIVE death mechanism, not dead code. The existing G2 path bills DEFAULT
    /// rent, so synthetic rent alone exhausts the budget in a tick and the floor-halt is never
    /// the trigger there (G2 would pass with the floor removed). This drives the INTEGRATED
    /// loop ([`tick_until_exhausted`]) over a mock meter source with the diarist's real deploy
    /// economics: ZERO synthetic rent, and a treasury drained ONLY by THINK spends (the
    /// capability ledger path — NOT metered rent) to a sub-think-floor balance.
    ///
    /// Two arms over the SAME drained state; only the floor differs:
    ///   - floor ARMED (= brain.max_cost_sats): the run HALTS at `BudgetExhausted` within a
    ///     tick, with a sub-floor leftover, NOT at the max_run ceiling — the daemon death.
    ///   - floor DISABLED (the negative control): with rent=0 the meter never refuses a tick,
    ///     so the run idles to the safety ceiling (`Stopped`) — the ZOMBIE the floor forecloses.
    ///
    /// This is the death-mechanism proof and it has TEETH: remove or break the floor-halt in
    /// `tick_once` and the armed arm degrades to the zombie arm (returns `Stopped`), tripping
    /// the armed arm's `panic!` and reddening the test.
    #[tokio::test(start_paused = true)]
    async fn rent_zero_diarist_halts_on_the_floor_and_zombies_without_it() {
        use crate::meter::BurnRates;
        use crate::treasury::Treasury;
        // `DebitOutcome` is already in scope via `use super::*` (the module imports it).

        // The diarist's deploy economics: ZERO synthetic rent (CPU, mem-time, and egress all
        // bill 0), so the meter NEVER exhausts on its own — the treasury falls only as the
        // genome THINKs/REMEMBERs through the gateway.
        let zero_rent = BurnRates {
            cpu_sats_per_usec_num: 0,
            cpu_sats_per_usec_den: 1,
            mem_sats_per_mib_sec: 0,
            egress_sats_per_byte_num: 0,
            egress_sats_per_byte_den: 1,
        };
        let floor: u64 = 64; // the per-think D-20 cap (brain.max_cost_sats)
        let think_cost: u64 = 64; // a worst-case think costs the whole cap (actual <= cap, D-20)
        let budget: u64 = 670; // a few thinks-worth, leaving a sub-think remainder when drained
        let tick = Duration::from_millis(10);
        // The safety ceiling: WITHOUT the floor a rent=0 run would tick here forever, so the
        // control arm terminates (as Stopped) at this bound. Virtual time (start_paused) makes
        // the tick count exact and the test instant.
        let max_run = Duration::from_millis(200);
        let ceiling_ticks = (max_run.as_millis() / tick.as_millis()) as u64;

        // Drain a fresh treasury via THINK spends — the capability ledger path
        // (`debit_and_record`), NOT metered rent — until it can no longer GUARANTEE the next
        // think (remaining < floor). This is the diarist having thought until it is a
        // sub-think-floor zombie candidate: still solvent, but unable to afford another thought.
        let drained_treasury = || {
            let t = Treasury::open_temporary(budget).expect("treasury opens");
            let mut i = 0u64;
            while t.remaining().expect("balance") >= floor {
                match t
                    .debit_and_record(
                        &format!("think-{i}"),
                        think_cost,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    )
                    .expect("debit")
                {
                    DebitOutcome::Debited { .. } => {}
                    DebitOutcome::Insufficient { remaining } => {
                        panic!("a THINK drain spend was unexpectedly refused (remaining={remaining})")
                    }
                    DebitOutcome::Duplicate(_) => {
                        panic!("a THINK drain spend hit a duplicate key (test bug: keys must be unique)")
                    }
                }
                i += 1;
            }
            let remaining = t.remaining().expect("balance");
            assert!(
                remaining < floor,
                "THINK spends drained below the per-think floor ({remaining} < {floor})"
            );
            assert!(
                remaining > 0,
                "but left a sub-think remainder, not exactly zero ({remaining}) — the zombie balance"
            );
            (t, remaining)
        };

        // --- ARM 1: floor ARMED (the diarist). The daemon HALTS the zombie candidate. ---
        let (treasury, drained) = drained_treasury();
        let mut meter = Meter::attach_mock(treasury, zero_rent, tick, 0, 0);
        meter.set_halt_floor(floor);
        let outcome = tick_until_exhausted(&mut meter, None, max_run, None)
            .await
            .expect("the meter loop runs");
        match outcome {
            MeterOutcome::BudgetExhausted {
                remaining_at_halt,
                burned_sats,
                ticks,
            } => {
                assert_eq!(
                    burned_sats, 0,
                    "rent=0: the meter billed nothing (the drain was THINK spends, not rent)"
                );
                assert!(
                    remaining_at_halt < floor,
                    "halts with a sub-think leftover ({remaining_at_halt}): the next think is not guaranteed"
                );
                assert_eq!(
                    remaining_at_halt, drained,
                    "rent=0: the floor-halt moved no money — remaining == the THINK-drained balance"
                );
                assert!(
                    ticks < ceiling_ticks,
                    "the floor halted promptly ({ticks} ticks), NOT at the max_run ceiling \
                     ({ceiling_ticks}) — this is a death, not a zombie"
                );
            }
            other => panic!(
                "FLOOR-HALT REGRESSION: a rent=0 diarist below the think-floor MUST halt at \
                 BudgetExhausted, got {other:?}. The floor-halt is removed or broken — this is \
                 the rent=0 zombie."
            ),
        }

        // --- ARM 2: floor DISABLED (the negative control). The rent=0 run ZOMBIES. ---
        // Identical drained state; ONLY the floor differs. With no floor the meter never
        // refuses a tick (rent=0), so the run idles to the safety ceiling. This is the zombie
        // the floor forecloses — and the proof ARM 1's halt came from the floor, not from rent.
        let (treasury, drained) = drained_treasury();
        let mut meter = Meter::attach_mock(treasury, zero_rent, tick, 0, 0);
        meter.set_halt_floor(0);
        let outcome = tick_until_exhausted(&mut meter, None, max_run, None)
            .await
            .expect("the meter loop runs");
        match outcome {
            MeterOutcome::Stopped {
                remaining,
                burned_sats,
                ticks,
            } => {
                assert_eq!(burned_sats, 0, "rent=0: billed nothing");
                assert_eq!(
                    remaining, drained,
                    "rent=0 + no floor: nothing moved the balance; it idled below the floor"
                );
                assert!(
                    ticks >= ceiling_ticks - 1,
                    "without the floor the run idled to the ceiling ({ticks} ~ {ceiling_ticks} \
                     ticks) — the zombie the floor kills"
                );
            }
            MeterOutcome::BudgetExhausted { .. } => panic!(
                "the negative control is broken: a rent=0 run with NO floor must idle to the \
                 ceiling (Stopped), not halt on a budget/floor"
            ),
        }
    }
}
