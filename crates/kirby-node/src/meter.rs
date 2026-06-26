//! Host-authoritative metering of the booted microVM (spec 3.3, 4.1, gate G2).
//!
//! The meter is the daemon-side, host-authoritative accounting the genome
//! cannot forge (D-9). It reads the backend's host-authoritative sample source
//! on a fixed tick (Linux cgroup v2 `cpu.stat`/`memory.current`, macOS VZ
//! host-process CPU plus boot-time memory cap), converts per-tick consumption to
//! a synthetic sat burn, and debits the SAME daemon-owned treasury counter every
//! capability spend debits (D-9). When cumulative metered burn reaches the
//! genome's budget the treasury refuses the tick (`DebitOutcome::Insufficient`),
//! and that refusal is the budget-death HALT trigger: the daemon pauses then
//! kills the VM and records `terminated:budget_exhausted` (spec 3.3 / 4.1). This
//! is Kirby's death by exhaustion proven at spike scale.
//!
//! GRANULARITY (spec section 11): cgroup counters are sampled on a tick, so the
//! halt is accurate to ONE TICK, not one instruction (a WASM-fuel meter would be
//! per-instruction; Firecracker was chosen for isolation and checkpoint, not
//! instruction-exact billing). G2 therefore asserts the halt lands within one
//! tick of the budget, not exact-to-the-sat.
//!
//! AUTHORITY: only this host-side meter and the capability path move the
//! counter. The genome's `ReportEvent` numbers are advisory and are NEVER billed
//! (gate G3c): a genome under-reporting CPU (or reporting cpu=0) is still billed
//! by what the host actually consumed, because the meter reads the host source,
//! not the genome's claims.
//!
//! EGRESS BYTES (spec 3.3, C-5): the aya/eBPF TC classifier on the VM's TAP
//! counts the bytes the VM emits, and this meter bills them per-byte on the same
//! tick it bills CPU and memory, against the same treasury counter (D-9). The
//! classifier and the TAP plus its nftables default-deny lockdown live in
//! [`crate::meter_egress`] and [`crate::network`]; this module takes the
//! cumulative egress-byte count per tick (an optional input, since a vsock-only
//! VM has no TAP) and adds an egress term to `BurnRates::burn_for_tick`. With the
//! default-deny lockdown the egress bytes are ~0 (the VM has no route out, gate
//! G4), so the egress term is normally a no-op; it exists so that any bytes that
//! DO leave the TAP are metered, and so the meter shape is complete (spec 3.3).

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
use cgroups_rs::fs::cpu::CpuController;
#[cfg(target_os = "linux")]
use cgroups_rs::fs::hierarchies::V2;
#[cfg(target_os = "linux")]
use cgroups_rs::fs::memory::MemController;
#[cfg(target_os = "linux")]
use cgroups_rs::fs::Cgroup;

use crate::treasury::{DebitOutcome, Treasury, TreasuryError};

/// The cgroup v2 unified mount root. The VM's cgroup is addressed relative to
/// this (cgroups-rs takes the path relative to the mount).
#[cfg(target_os = "linux")]
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// How a metered run ended. The daemon drives the VM to one of these terminal
/// states; the genome cannot drive the transition (it only makes gateway calls).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeterOutcome {
    /// Cumulative metered burn reached the budget: the treasury refused a tick.
    /// The daemon HALTS the VM (pause then kill) and records this as
    /// `terminated:budget_exhausted` (spec 4.1, gate G2). `burned_sats` is the
    /// total debited before the refusal (it is `~= budget`, proving the meter
    /// read non-zero usage), and `remaining_at_halt` is the balance the refused
    /// tick reported (the leftover smaller than one tick's burn).
    BudgetExhausted {
        burned_sats: u64,
        remaining_at_halt: u64,
        ticks: u64,
    },
    /// The meter loop was asked to stop (the VM ended for another reason, e.g. a
    /// failover kill in a later chunk) before the budget was exhausted.
    Stopped {
        burned_sats: u64,
        remaining: u64,
        ticks: u64,
    },
}

/// The synthetic burn rates: how cgroup consumption converts to sats per tick.
/// Stub economics for the spike (real pricing is later); the rates exist so a
/// short, measurable workload trips a small budget in a few ticks, exercising
/// the meter and the halt without a long run.
#[derive(Clone, Copy)]
pub struct BurnRates {
    /// Sats charged per microsecond of cgroup CPU time (`cpu.stat usage_usec`
    /// delta). Default bills 1 sat per millisecond of CPU.
    pub cpu_sats_per_usec_num: u64,
    pub cpu_sats_per_usec_den: u64,
    /// Sats charged per MiB of resident memory (`memory.current`) per second,
    /// integrated over the tick (mem-time, spec 3.3). Default bills 1 sat per
    /// MiB-second.
    pub mem_sats_per_mib_sec: u64,
    /// Sats charged per egress byte the eBPF TC classifier counted on the VM's
    /// TAP this tick (spec 3.3, C-5). Numerator/denominator so a sub-1-sat
    /// per-byte rate is expressible (e.g. 1 sat per KiB = 1/1024). Default bills
    /// 1 sat per egress byte: with the default-deny lockdown egress is ~0 so this
    /// is normally a no-op, but a high rate makes any leaked byte costly and
    /// visible (the unforgeable network bill, D-9).
    pub egress_sats_per_byte_num: u64,
    pub egress_sats_per_byte_den: u64,
}

impl Default for BurnRates {
    fn default() -> Self {
        // 1 sat / ms CPU, 1 sat / MiB-second memory, 1 sat / egress byte. With a
        // 100 ms tick and a genome that pins a vCPU and holds a few tens of MiB,
        // cumulative burn climbs fast enough to exhaust a small budget (a few
        // thousand sats) in a couple of seconds, so G2 is a quick test. Egress is
        // ~0 under the default-deny lockdown (G4), so the egress term does not
        // perturb the G2 figures.
        BurnRates {
            cpu_sats_per_usec_num: 1,
            cpu_sats_per_usec_den: 1000,
            mem_sats_per_mib_sec: 1,
            egress_sats_per_byte_num: 1,
            egress_sats_per_byte_den: 1,
        }
    }
}

impl From<&crate::config::MeterRatesConfig> for BurnRates {
    /// Build the runtime burn rates from the `[meter]` config block (F4): a deploy LOWERS
    /// `mem_sats_per_mib_sec` so an always-on VM does not rent-death before it can think
    /// or journal. A field-for-field copy — `MeterRatesConfig`'s defaults are byte-
    /// identical to [`BurnRates::default`], so an absent `[meter]` block is a no-op.
    fn from(c: &crate::config::MeterRatesConfig) -> Self {
        BurnRates {
            cpu_sats_per_usec_num: c.cpu_sats_per_usec_num,
            cpu_sats_per_usec_den: c.cpu_sats_per_usec_den,
            mem_sats_per_mib_sec: c.mem_sats_per_mib_sec,
            egress_sats_per_byte_num: c.egress_sats_per_byte_num,
            egress_sats_per_byte_den: c.egress_sats_per_byte_den,
        }
    }
}

/// The FLOOR-HALT decision (the diarist's death mechanism). Halt when the floor is enabled
/// (`> 0`) and the treasury can no longer GUARANTEE a think — `remaining < halt_floor_sats`.
/// The floor is the per-think D-20 cap (`brain.max_cost_sats`): at or above it ANY think is
/// affordable (so no premature death); strictly below it the next think is not guaranteed, so
/// the genome will park (DENIED_INSUFFICIENT) and must be halted rather than left a zombie. A
/// floor of 0 disables it entirely (every non-diarist workload). Pure, so it is unit-testable
/// without a live meter source.
fn floor_halt_reached(remaining: u64, halt_floor_sats: u64) -> bool {
    halt_floor_sats > 0 && remaining < halt_floor_sats
}

/// Configuration for one metered run.
#[derive(Clone)]
#[cfg(target_os = "linux")]
pub struct MeterConfig {
    /// The VM's cgroup path RELATIVE to the cgroup v2 mount root, e.g.
    /// `user.slice/user-1001.slice/user@1001.service/kirby/<jail_id>`. The jailer
    /// created it under the daemon's delegated slice, so the daemon reads it
    /// rootlessly (the cgroup files are world-readable within the daemon's own
    /// delegated subtree, confirmed live).
    pub cgroup_rel_path: PathBuf,
    /// The sampling tick. The halt is accurate to one of these (spec section 11).
    pub tick: Duration,
    /// The synthetic burn rates.
    pub rates: BurnRates,
}

#[cfg(target_os = "linux")]
impl MeterConfig {
    /// A meter for `cgroup_rel_path` with a 100 ms tick and the default rates.
    pub fn new(cgroup_rel_path: impl Into<PathBuf>) -> Self {
        MeterConfig {
            cgroup_rel_path: cgroup_rel_path.into(),
            tick: Duration::from_millis(100),
            rates: BurnRates::default(),
        }
    }
}

/// Configuration for macOS VZ host-process metering. CPU is sampled from
/// `proc_pid_rusage` for the helper process plus discovered VZ VM service pids;
/// memory is billed against the configured VZ memory cap.
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub struct HostProcessMeterConfig {
    pub root_pid: u32,
    pub service_pids: Vec<u32>,
    pub memory_mib: usize,
    /// The sampling tick. The halt is accurate to one of these (spec section 11).
    pub tick: Duration,
    /// The synthetic burn rates.
    pub rates: BurnRates,
}

/// Configuration for ALLOCATION-based metering (chunk D pt.2). Bills the vCPU/memory
/// RESERVATION as if fully utilized: CPU = `vcpu_count × elapsed`, memory = `mem_mib`
/// cap. Used by the VZ backend, where the guest's real vCPU time is unmeterable.
#[derive(Clone)]
pub struct AllocationMeterConfig {
    pub vcpu_count: u32,
    pub mem_mib: usize,
    /// Boot-time instant; `elapsed()` from here is the allocated-CPU-seconds clock.
    pub start: std::time::Instant,
    /// The sampling tick. The halt is accurate to one of these (spec section 11).
    pub tick: Duration,
    /// The synthetic burn rates (the SAME per-cpu-second rate as every source).
    pub rates: BurnRates,
}

/// A handle the daemon polls each tick: it reads the host meter source, computes the
/// per-tick burn, and debits the treasury. Held by the metered-run loop, which
/// owns the VM-lifecycle transition to the terminal state on exhaustion.
pub struct Meter {
    source: MeterSampleSource,
    treasury: Treasury,
    rates: BurnRates,
    tick: Duration,
    /// The FLOOR-HALT threshold (the diarist's death mechanism). When `> 0`, a tick halts
    /// the VM (returns `DebitOutcome::Insufficient`, the same path a budget exhaustion takes)
    /// as soon as `treasury.remaining() < halt_floor_sats` — even with ZERO synthetic rent.
    /// Set to the per-think D-20 cap (`brain.max_cost_sats`) for the diarist: below it the
    /// next think is not GUARANTEED affordable, so the genome parks (DENIED_INSUFFICIENT) and
    /// would otherwise be a ZOMBIE (rent=0 ⇒ the meter never exhausts and never halts). `0`
    /// (every non-diarist workload) disables it, so all existing metered runs are unchanged.
    halt_floor_sats: u64,
    /// Last observed cumulative CPU usec. The CPU bill is the delta; every host
    /// source is cumulative, so we bill the increment.
    last_cpu_usec: u64,
    /// The optional eBPF egress-byte meter on the VM's TAP (C-5, spec 3.3). A
    /// vsock-only VM (no TAP) has none, so this is `None` and egress bills 0. When
    /// present, the cumulative byte counter is read each tick and the delta is
    /// billed per-byte (the egress term in `BurnRates::burn_for_tick`).
    #[cfg(target_os = "linux")]
    egress: Option<crate::meter_egress::EgressMeter>,
    /// Last observed cumulative egress bytes (the egress bill is the delta).
    #[cfg(target_os = "linux")]
    last_egress_bytes: u64,
    /// Running totals (diagnostics and the G2 evidence).
    burned_sats: u64,
    cpu_usec: u64,
    ticks: u64,
}

enum MeterSampleSource {
    #[cfg(target_os = "linux")]
    Cgroup(CgroupMeterSource),
    #[cfg(target_os = "macos")]
    HostProcess(HostProcessMeterSource),
    /// ALLOCATION-based source (chunk D pt.2): bills the vCPU/memory RESERVATION as
    /// if 100% utilized. Pure arithmetic, no syscalls, so not platform-gated.
    Allocation(AllocationMeterSource),
    /// TEST-ONLY: a fixed in-memory sample source (no cgroup, no VZ host process), so the
    /// metered-run loop — and the diarist's rent=0 FLOOR-HALT — are exercisable in CI without
    /// a live VM. Never constructed in production (the variant is `cfg(test)`).
    #[cfg(test)]
    Mock(MockMeterSource),
}

#[cfg(target_os = "linux")]
struct CgroupMeterSource {
    cgroup: Cgroup,
    abs_path: PathBuf,
}

#[cfg(target_os = "macos")]
struct HostProcessMeterSource {
    root_pid: u32,
    service_pids: Vec<u32>,
    memory_cap_bytes: u64,
    /// Last successfully-sampled cumulative CPU nsec per pid. When a pid vanishes
    /// (ESRCH) mid-run we substitute its FROZEN last-known value into the summed
    /// total instead of dropping it to zero — otherwise the summed cumulative
    /// total would DROP, `tick_once`'s `total_now - total_prev` delta would clamp
    /// to 0, and the new (lower) sum would become the baseline: a persistent
    /// undercount in the agent's favor (free compute => die-when-broke fails). The
    /// frozen value contributes the exited pid's accumulated compute exactly once
    /// more and then never increases, so the total is monotonic across an exit.
    last_cpu_nsec_by_pid: std::collections::HashMap<u32, u64>,
}

/// ALLOCATION-based sample source (chunk D pt.2). Reports the guest's RESERVATION as
/// cumulative consumption: CPU = `vcpu_count × elapsed-since-boot` (so the meter's
/// delta-billing turns it into `vcpu_count × dt × rate` automatically — usage billing
/// at 100% utilization), memory = the fixed `mem_mib` cap. Both are monotonic (CPU
/// grows with wall-time, memory is constant), exactly what `tick_once`'s delta math
/// expects. No syscalls: this is why a busy guest and an idle guest bill identically
/// under VZ, where the guest's real vCPU time is invisible at the host.
struct AllocationMeterSource {
    vcpu_count: u32,
    mem_bytes: u64,
    start: std::time::Instant,
}

impl AllocationMeterSource {
    /// The pure sample math, parameterized by elapsed time so it is deterministically
    /// testable without a clock: cumulative CPU = `vcpu_count × elapsed_usec`,
    /// memory = the fixed cap. Both monotonic in `elapsed`.
    fn sample_at(&self, elapsed: Duration) -> MeterSample {
        let cpu_usec = (self.vcpu_count as u64).saturating_mul(elapsed.as_micros() as u64);
        MeterSample {
            cpu_usec,
            mem_bytes: self.mem_bytes,
        }
    }

    fn sample(&self) -> MeterSample {
        self.sample_at(self.start.elapsed())
    }
}

struct MeterSample {
    cpu_usec: u64,
    mem_bytes: u64,
}

/// TEST-ONLY sample source: reports a fixed cumulative CPU/mem every tick. With zero
/// [`BurnRates`] the per-tick burn is 0, so the metered run moves ONLY as the treasury is
/// drained elsewhere (the THINK/REMEMBER capability path) — exactly the diarist's rent=0
/// economics, where the FLOOR-HALT is the death mechanism rather than synthetic rent.
#[cfg(test)]
struct MockMeterSource {
    cpu_usec: u64,
    mem_bytes: u64,
}

#[cfg(test)]
impl MockMeterSource {
    fn sample(&self) -> MeterSample {
        MeterSample {
            cpu_usec: self.cpu_usec,
            mem_bytes: self.mem_bytes,
        }
    }
}

impl Meter {
    /// Load the VM's cgroup (v2, under the unified mount) and seed the CPU
    /// baseline so the first tick bills only what was consumed after attach.
    /// Returns an error if the cgroup is absent or its cpu/memory controllers are
    /// not readable (a misconfigured placement: the daemon must meter a real
    /// cgroup, never silently bill zero).
    #[cfg(target_os = "linux")]
    pub fn attach(config: &MeterConfig, treasury: Treasury) -> Result<Self, MeterError> {
        Self::attach_with_egress(config, treasury, None)
    }

    /// Attach the meter, optionally with the eBPF egress-byte meter on the VM's
    /// TAP (C-5, spec 3.3). The egress meter's cumulative byte counter is read
    /// each tick and the delta is billed per-byte against the same treasury (the
    /// egress term in `BurnRates::burn_for_tick`). Pass `None` for a vsock-only VM
    /// (no TAP, egress bills 0).
    #[cfg(target_os = "linux")]
    pub fn attach_with_egress(
        config: &MeterConfig,
        treasury: Treasury,
        egress: Option<crate::meter_egress::EgressMeter>,
    ) -> Result<Self, MeterError> {
        let hier = Box::new(V2::new());
        // `Cgroup::load` does not fail on a missing path; it returns a handle
        // whose reads then fail. Verify the cgroup directory exists up front so a
        // bad placement is a hard error, not a silent zero-bill (the C-2-verifier
        // flag: metering must have a real, dedicated cgroup to read).
        let abs = Path::new(CGROUP_V2_ROOT).join(&config.cgroup_rel_path);
        if !abs.is_dir() {
            return Err(MeterError::CgroupMissing(abs));
        }
        let cgroup = Cgroup::load(hier, &config.cgroup_rel_path);

        // Confirm both interface files are actually readable up front, by a
        // direct open. cgroups-rs swallows a per-tick read failure to 0
        // (`unwrap_or(0)`), which would silently bill zero on a bad placement;
        // probing the raw files here makes attach fail LOUDLY instead (the
        // C-2-verifier flag: metering must read a real, dedicated cgroup).
        if std::fs::read_to_string(abs.join("cpu.stat")).is_err() {
            return Err(MeterError::CpuUnreadable(
                abs.clone(),
                "cpu.stat not readable".into(),
            ));
        }
        if std::fs::read_to_string(abs.join("memory.current")).is_err() {
            return Err(MeterError::MemUnreadable(
                abs.clone(),
                "memory.current not readable (is the memory controller enabled in the parent's subtree_control?)".into(),
            ));
        }

        // Seed the CPU baseline so the first tick bills only post-attach usage.
        let last_cpu_usec =
            read_cpu_usec(&cgroup).map_err(|e| MeterError::CpuUnreadable(abs.clone(), e))?;

        // Seed the egress baseline so the first tick bills only post-attach bytes.
        let last_egress_bytes = egress.as_ref().map(|e| e.egress_bytes()).unwrap_or(0);

        Ok(Meter {
            source: MeterSampleSource::Cgroup(CgroupMeterSource {
                cgroup,
                abs_path: abs,
            }),
            treasury,
            rates: config.rates,
            tick: config.tick,
            // Disabled by default; the metered run sets it for the diarist (set_halt_floor).
            halt_floor_sats: 0,
            last_cpu_usec,
            #[cfg(target_os = "linux")]
            egress,
            #[cfg(target_os = "linux")]
            last_egress_bytes,
            burned_sats: 0,
            cpu_usec: 0,
            ticks: 0,
        })
    }

    /// Attach a macOS host-process meter. CPU comes from the VZ helper plus the
    /// launchd-owned VZ service pids discovered at boot; memory is billed as
    /// cap-time using the memory size VZ was configured with.
    #[cfg(target_os = "macos")]
    pub fn attach_host_process(
        config: &HostProcessMeterConfig,
        treasury: Treasury,
    ) -> Result<Self, MeterError> {
        if config.service_pids.is_empty() {
            return Err(MeterError::HostProcessUnreadable {
                root_pid: config.root_pid,
                reason:
                    "no VZ VirtualMachine service pid discovered; refusing helper-only CPU metering"
                        .to_string(),
            });
        }
        let memory_cap_bytes = (config.memory_mib as u64)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| MeterError::HostProcessUnreadable {
                root_pid: config.root_pid,
                reason: format!("memory cap {} MiB overflows bytes", config.memory_mib),
            })?;
        let mut source = HostProcessMeterSource {
            root_pid: config.root_pid,
            service_pids: config.service_pids.clone(),
            memory_cap_bytes,
            last_cpu_nsec_by_pid: std::collections::HashMap::new(),
        };
        let baseline = source.sample()?;

        Ok(Meter {
            source: MeterSampleSource::HostProcess(source),
            treasury,
            rates: config.rates,
            tick: config.tick,
            // Disabled by default; the metered run sets it for the diarist (set_halt_floor).
            halt_floor_sats: 0,
            last_cpu_usec: baseline.cpu_usec,
            burned_sats: 0,
            cpu_usec: 0,
            ticks: 0,
        })
    }

    /// Attach an ALLOCATION-based meter (chunk D pt.2). Bills the vCPU/memory
    /// RESERVATION as if 100% utilized: CPU accrues as `vcpu_count × elapsed-since-
    /// boot` fed into the SAME per-cpu-second [`BurnRates`], memory is the fixed cap.
    /// Used by the VZ backend, where the guest's real vCPU time is structurally
    /// invisible at the host. Pure arithmetic; available on every platform.
    pub fn attach_allocation(
        config: &AllocationMeterConfig,
        treasury: Treasury,
    ) -> Result<Self, MeterError> {
        let mem_bytes = (config.mem_mib as u64).checked_mul(1024 * 1024).ok_or_else(|| {
            MeterError::AllocationInvalid {
                reason: format!("memory cap {} MiB overflows bytes", config.mem_mib),
            }
        })?;
        let source = AllocationMeterSource {
            vcpu_count: config.vcpu_count,
            mem_bytes,
            start: config.start,
        };
        // Seed the CPU baseline from the current elapsed so the first tick bills only
        // post-attach allocated time (matches the cgroup/host-process attach semantics).
        let baseline = source.sample();

        Ok(Meter {
            source: MeterSampleSource::Allocation(source),
            treasury,
            rates: config.rates,
            tick: config.tick,
            halt_floor_sats: 0,
            last_cpu_usec: baseline.cpu_usec,
            #[cfg(target_os = "linux")]
            egress: None,
            #[cfg(target_os = "linux")]
            last_egress_bytes: 0,
            burned_sats: 0,
            cpu_usec: 0,
            ticks: 0,
        })
    }

    /// TEST-ONLY: build a [`Meter`] over a fixed mock sample source, bypassing the real
    /// cgroup/VZ attach (which need a live VM). The mock reports `mock_cpu_usec` /
    /// `mock_mem_bytes` each tick; pass zeros with zero `rates` for the diarist's rent=0 path,
    /// where the treasury falls ONLY via THINK/REMEMBER spends and the FLOOR-HALT is the death
    /// mechanism. This is what lets the rent=0 zombie-gone regression run in CI; the production
    /// attach paths ([`Meter::attach`] / [`Meter::attach_host_process`]) are untouched.
    #[cfg(test)]
    pub(crate) fn attach_mock(
        treasury: Treasury,
        rates: BurnRates,
        tick: Duration,
        mock_cpu_usec: u64,
        mock_mem_bytes: u64,
    ) -> Self {
        Meter {
            source: MeterSampleSource::Mock(MockMeterSource {
                cpu_usec: mock_cpu_usec,
                mem_bytes: mock_mem_bytes,
            }),
            treasury,
            rates,
            tick,
            // Disabled by default; the test arms it via set_halt_floor, exactly like the run.
            halt_floor_sats: 0,
            last_cpu_usec: 0,
            #[cfg(target_os = "linux")]
            egress: None,
            #[cfg(target_os = "linux")]
            last_egress_bytes: 0,
            burned_sats: 0,
            cpu_usec: 0,
            ticks: 0,
        }
    }

    /// Set the FLOOR-HALT threshold (the diarist's death mechanism — see the field doc). The
    /// metered run sets this to the per-think D-20 cap (`brain.max_cost_sats`) for the diarist
    /// workload and leaves it `0` (disabled) for every other workload, so all existing metered
    /// runs are byte-identical.
    pub fn set_halt_floor(&mut self, halt_floor_sats: u64) {
        self.halt_floor_sats = halt_floor_sats;
    }

    /// Read the host meter source once, compute this tick's synthetic burn, and debit the
    /// treasury. Returns the debit outcome so the caller halts on `Insufficient`.
    /// INVARIANT: every sat billed here comes from the host-side meter source,
    /// never from the genome's self-reported numbers (G3c).
    pub fn tick_once(&mut self) -> Result<DebitOutcome, MeterError> {
        self.ticks += 1;

        // CPU: bill the increment of cumulative usage since the last read.
        let sample = self.source.sample()?;
        let cpu_delta_usec = sample.cpu_usec.saturating_sub(self.last_cpu_usec);
        self.last_cpu_usec = sample.cpu_usec;
        self.cpu_usec = self.cpu_usec.saturating_add(cpu_delta_usec);

        // Egress: bill the bytes that left the VM TAP since the last read (the
        // eBPF TC classifier's cumulative counter, C-5). With the default-deny
        // lockdown this delta is ~0 (gate G4). No TAP => no egress meter => 0.
        let egress_delta = self.next_egress_delta();

        let burn =
            self.rates
                .burn_for_tick(cpu_delta_usec, sample.mem_bytes, egress_delta, self.tick);

        // A tick that consumed nothing measurable (and the workload is idle)
        // still advances the loop; debiting 0 is a no-op debit that keeps the
        // remaining balance reported for diagnostics.
        let outcome = self.treasury.debit_metered(burn)?;
        if let DebitOutcome::Debited { cost_sats, remaining } = &outcome {
            self.burned_sats = self.burned_sats.saturating_add(*cost_sats);
            // FLOOR-HALT (the diarist's death, the scope-add): with zero synthetic rent the
            // treasury only falls as the genome THINKs/REMEMBERs through the gateway. When it
            // can no longer GUARANTEE a think, halt the VM via the SAME `Insufficient` path a
            // budget exhaustion takes — so the genome's park becomes a real daemon-initiated
            // death (no zombie). It fires ONCE: the run loop breaks on `Insufficient`. A 0
            // floor (every non-diarist run) skips this, so existing behavior is unchanged.
            if floor_halt_reached(*remaining, self.halt_floor_sats) {
                return Ok(DebitOutcome::Insufficient {
                    remaining: *remaining,
                });
            }
        }
        Ok(outcome)
    }

    /// Total sats debited so far (the G2 metered-burn evidence: it is `~= budget`
    /// at halt, NOT zero, proving the meter read real cgroup usage).
    pub fn burned_sats(&self) -> u64 {
        self.burned_sats
    }

    /// Cumulative CPU microseconds sampled and billed by the host meter.
    pub fn cpu_usec(&self) -> u64 {
        self.cpu_usec
    }

    /// Cumulative egress bytes the eBPF classifier counted on the VM TAP (the G4
    /// evidence: ~0 IP bytes left the TAP under the default-deny lockdown). 0 when
    /// there is no TAP/egress meter.
    #[cfg(target_os = "linux")]
    pub fn egress_bytes(&self) -> u64 {
        self.egress.as_ref().map(|e| e.egress_bytes()).unwrap_or(0)
    }

    /// Take the egress meter out of the meter (so the caller can `shutdown()` it,
    /// which detaches the eBPF classifier via the privileged child). Leaves the
    /// meter with no egress meter (subsequent ticks bill 0 egress).
    #[cfg(target_os = "linux")]
    pub fn take_egress(&mut self) -> Option<crate::meter_egress::EgressMeter> {
        self.egress.take()
    }

    #[cfg(target_os = "linux")]
    fn next_egress_delta(&mut self) -> u64 {
        let egress_bytes = self.egress.as_ref().map(|e| e.egress_bytes()).unwrap_or(0);
        let egress_delta = egress_bytes.saturating_sub(self.last_egress_bytes);
        self.last_egress_bytes = egress_bytes;
        egress_delta
    }

    #[cfg(not(target_os = "linux"))]
    fn next_egress_delta(&mut self) -> u64 {
        0
    }

    /// Ticks elapsed (the halt is accurate to one of these).
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// The sampling tick interval.
    pub fn tick_interval(&self) -> Duration {
        self.tick
    }

    /// The treasury balance, best-effort (0 on a read fault). Diagnostics only,
    /// for the safety-ceiling path; the authoritative balance lives in the
    /// treasury.
    pub fn treasury_remaining_best_effort(&self) -> u64 {
        self.treasury.remaining().unwrap_or(0)
    }
}

impl MeterSampleSource {
    fn sample(&mut self) -> Result<MeterSample, MeterError> {
        match self {
            #[cfg(target_os = "linux")]
            MeterSampleSource::Cgroup(source) => source.sample(),
            #[cfg(target_os = "macos")]
            MeterSampleSource::HostProcess(source) => source.sample(),
            MeterSampleSource::Allocation(source) => Ok(source.sample()),
            #[cfg(test)]
            MeterSampleSource::Mock(source) => Ok(source.sample()),
        }
    }
}

#[cfg(target_os = "linux")]
impl CgroupMeterSource {
    fn sample(&self) -> Result<MeterSample, MeterError> {
        let cpu_usec = read_cpu_usec(&self.cgroup)
            .map_err(|e| MeterError::CpuUnreadable(self.abs_path.clone(), e))?;
        let mem_bytes = read_mem_current(&self.cgroup)
            .map_err(|e| MeterError::MemUnreadable(self.abs_path.clone(), e))?;
        Ok(MeterSample {
            cpu_usec,
            mem_bytes,
        })
    }
}

#[cfg(target_os = "macos")]
impl HostProcessMeterSource {
    fn sample(&mut self) -> Result<MeterSample, MeterError> {
        let mut pids = macos_process_tree_pids(self.root_pid).map_err(|e| {
            MeterError::HostProcessUnreadable {
                root_pid: self.root_pid,
                reason: e,
            }
        })?;
        for service_pid in &self.service_pids {
            let service_tree = macos_process_tree_pids(*service_pid).map_err(|e| {
                MeterError::HostProcessUnreadable {
                    root_pid: self.root_pid,
                    reason: format!("VZ service pid {service_pid} unreadable: {e}"),
                }
            })?;
            for pid in service_tree {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }

        let mut cpu_nsec = 0u64;
        let mut sampled = 0usize;
        for pid in pids {
            let (contribution, was_live) =
                self.accumulate_pid(pid, macos_process_cpu_nsec(pid))?;
            cpu_nsec = cpu_nsec.saturating_add(contribution);
            if was_live {
                sampled += 1;
            }
        }

        if sampled == 0 {
            return Err(MeterError::HostProcessUnreadable {
                root_pid: self.root_pid,
                reason: "no live process in VZ helper/service pid set".to_string(),
            });
        }

        Ok(MeterSample {
            cpu_usec: cpu_nsec / 1000,
            mem_bytes: self.memory_cap_bytes,
        })
    }

    /// Decide one pid's contribution to this tick's cumulative CPU sum and update the
    /// per-pid frozen-value map. Pure w.r.t. the syscall — it takes the already-fetched
    /// `proc_pid_rusage` result — so the undercount-safety invariant is unit-testable with
    /// injected samples (no live VM). Returns `(cpu_nsec_contribution, was_live)`:
    ///   - live sample: contribute the fresh cumulative value, remember it, count it live;
    ///   - root pid gone: hard-fail (losing the helper means we cannot meter at all);
    ///   - service/tree pid gone (ESRCH): contribute its FROZEN last-sampled value (not 0)
    ///     so the summed cumulative total does NOT drop across the exit — preventing the
    ///     persistent undercount (free compute => die-when-broke fails) the keeper flagged;
    ///   - service pid non-ESRCH fault: hard-fail (a real accounting/permission fault);
    ///   - non-root tree pid non-ESRCH fault: skip (contribute 0, not live).
    fn accumulate_pid(
        &mut self,
        pid: u32,
        sample: Result<u64, CpuSampleError>,
    ) -> Result<(u64, bool), MeterError> {
        match sample {
            Ok(pid_cpu_nsec) => {
                self.last_cpu_nsec_by_pid.insert(pid, pid_cpu_nsec);
                Ok((pid_cpu_nsec, true))
            }
            // The ROOT pid (the VZ helper) vanishing is a real failure: losing the
            // helper means we can no longer meter the run at all, so fail loudly.
            Err(e) if pid == self.root_pid => Err(MeterError::HostProcessUnreadable {
                root_pid: self.root_pid,
                reason: e.reason,
            }),
            // A SERVICE pid (or a non-root tree pid) that is genuinely GONE (ESRCH)
            // exited between discovery and this sample — benign for the RUN, but its
            // accumulated CPU must NOT silently leave the summed total: that would
            // make `total_now < total_prev`, the per-tick delta would clamp to 0, and
            // the lower sum would become the baseline forever (a persistent undercount
            // in the agent's favor => free compute => die-when-broke fails). RETAIN the
            // pid's last-sampled cumulative value (frozen), so it contributes its
            // accumulated compute one last time and the total stays monotonic across
            // the exit. A non-ESRCH failure on a service pid (e.g. a permission/
            // accounting fault) is NOT benign and still hard-fails below.
            Err(e) if e.is_no_such_process() => {
                let frozen = self.last_cpu_nsec_by_pid.get(&pid).copied().unwrap_or(0);
                tracing::debug!(
                    pid,
                    root_pid = self.root_pid,
                    is_service = self.service_pids.contains(&pid),
                    frozen_cpu_nsec = frozen,
                    error = %e.reason,
                    "retaining last-sampled CPU for disappeared process (ESRCH) during macOS VZ meter sample"
                );
                Ok((frozen, false))
            }
            // A service pid that failed for a reason OTHER than having exited is a
            // real fault: surface it.
            Err(e) if self.service_pids.contains(&pid) => {
                Err(MeterError::HostProcessUnreadable {
                    root_pid: self.root_pid,
                    reason: e.reason,
                })
            }
            Err(e) => {
                tracing::debug!(
                    pid,
                    root_pid = self.root_pid,
                    error = %e.reason,
                    "skipping disappeared non-root process during macOS VZ meter sample"
                );
                Ok((0, false))
            }
        }
    }
}

impl BurnRates {
    /// Convert one tick's CPU delta (usec), current memory (bytes), and egress
    /// bytes seen this tick to a sat burn. Integer math throughout (no float
    /// drift across ticks): CPU is `delta_usec * num / den`; memory is
    /// `bytes/MiB * tick_ms / 1000 * rate`, arranged to avoid truncating small
    /// per-tick contributions to zero; egress is `bytes * num / den` (the C-5
    /// term, spec 3.3). The egress argument is the DELTA of bytes the eBPF TC
    /// classifier counted on the VM TAP this tick (0 when there is no TAP, or ~0
    /// under the default-deny lockdown, gate G4).
    fn burn_for_tick(
        &self,
        cpu_delta_usec: u64,
        mem_bytes: u64,
        egress_delta_bytes: u64,
        tick: Duration,
    ) -> u64 {
        let cpu_sats = cpu_delta_usec.saturating_mul(self.cpu_sats_per_usec_num)
            / self.cpu_sats_per_usec_den.max(1);

        // mem-time: MiB-seconds this tick = (bytes / 2^20) * (tick_ms / 1000).
        // Compute as bytes * tick_ms * rate / (2^20 * 1000) so a small tick does
        // not floor an in-range memory hold to zero before the multiply.
        let mib = 1024u64 * 1024;
        let tick_ms = tick.as_millis() as u64;
        let mem_sats = mem_bytes
            .saturating_mul(tick_ms)
            .saturating_mul(self.mem_sats_per_mib_sec)
            / (mib.saturating_mul(1000)).max(1);

        // egress: bill the bytes that left the TAP this tick (spec 3.3, C-5).
        let egress_sats = egress_delta_bytes.saturating_mul(self.egress_sats_per_byte_num)
            / self.egress_sats_per_byte_den.max(1);

        cpu_sats
            .saturating_add(mem_sats)
            .saturating_add(egress_sats)
    }
}

/// Read cumulative CPU usage (`cpu.stat usage_usec`) from the cgroup (v2). The
/// cgroups-rs `CpuController::cpu()` parses `cpu.stat`; in v2 the usage line is
/// `usage_usec`. cgroups-rs exposes it as `usage_usec` on the parsed struct.
#[cfg(target_os = "linux")]
fn read_cpu_usec(cgroup: &Cgroup) -> Result<u64, String> {
    let cpu: &CpuController = cgroup
        .controller_of()
        .ok_or_else(|| "cpu controller not attached to this cgroup".to_string())?;
    let stat = cpu.cpu().stat;
    // The v2 `cpu.stat` carries `usage_usec` (total CPU time). cgroups-rs returns
    // the raw `cpu.stat` text in `stat`; parse the usage_usec line.
    parse_flat_keyed(&stat, "usage_usec")
        .ok_or_else(|| "cpu.stat has no usage_usec line (is this a v2 cpu cgroup?)".to_string())
}

/// Read current resident memory (`memory.current`) in bytes from the cgroup
/// (v2). cgroups-rs `MemController::memory_stat().usage_in_bytes` reads
/// `memory.current` on the v2 hierarchy.
#[cfg(target_os = "linux")]
fn read_mem_current(cgroup: &Cgroup) -> Result<u64, String> {
    let mem: &MemController = cgroup
        .controller_of()
        .ok_or_else(|| "memory controller not attached to this cgroup".to_string())?;
    let usage = mem.memory_stat().usage_in_bytes;
    Ok(usage)
}

/// Parse a value from flat-keyed cgroup text (`key value` per line).
#[cfg(target_os = "linux")]
fn parse_flat_keyed(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some(key) {
            return it.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn macos_process_tree_pids(root_pid: u32) -> Result<Vec<u32>, String> {
    let mut out = vec![root_pid];
    let mut stack = vec![root_pid];

    while let Some(pid) = stack.pop() {
        for child in macos_child_pids(pid)? {
            if !out.contains(&child) {
                out.push(child);
                stack.push(child);
            }
        }
    }

    Ok(out)
}

#[cfg(target_os = "macos")]
fn macos_child_pids(pid: u32) -> Result<Vec<u32>, String> {
    let pid = macos_pid_to_c_int(pid)?;
    let count = unsafe { libc::proc_listchildpids(pid, std::ptr::null_mut(), 0) };
    if count < 0 {
        return Err(format!(
            "proc_listchildpids({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut pids = vec![0 as libc::pid_t; count as usize];
    let bytes = pids
        .len()
        .checked_mul(std::mem::size_of::<libc::pid_t>())
        .and_then(|n| i32::try_from(n).ok())
        .ok_or_else(|| format!("proc_listchildpids({pid}) buffer size overflow"))?;
    let found =
        unsafe { libc::proc_listchildpids(pid, pids.as_mut_ptr().cast::<libc::c_void>(), bytes) };
    if found < 0 {
        return Err(format!(
            "proc_listchildpids({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let found = (found as usize).min(pids.len());
    pids.truncate(found);
    Ok(pids
        .into_iter()
        .filter_map(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .collect())
}

/// A `proc_pid_rusage` sampling failure: the human-readable `reason` (surfaced in
/// `MeterError`) plus the raw OS errno so the caller can distinguish a genuinely
/// gone pid (`ESRCH` / "no such process") from other faults without string-matching.
#[cfg(target_os = "macos")]
struct CpuSampleError {
    reason: String,
    raw_os_error: Option<i32>,
}

#[cfg(target_os = "macos")]
impl CpuSampleError {
    /// True when the pid is genuinely gone (`ESRCH`): the process exited between
    /// discovery and sampling — benign for a secondary/service pid.
    fn is_no_such_process(&self) -> bool {
        self.raw_os_error == Some(libc::ESRCH)
    }
}

#[cfg(target_os = "macos")]
fn macos_process_cpu_nsec(pid: u32) -> Result<u64, CpuSampleError> {
    let pid = macos_pid_to_c_int(pid).map_err(|reason| CpuSampleError {
        reason,
        raw_os_error: None,
    })?;
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v4>::uninit();
    let rc = unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V4, usage.as_mut_ptr().cast()) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(CpuSampleError {
            reason: format!("proc_pid_rusage({pid}) failed: {err}"),
            raw_os_error: err.raw_os_error(),
        });
    }
    let usage = unsafe { usage.assume_init() };
    Ok(usage.ri_user_time.saturating_add(usage.ri_system_time))
}

#[cfg(target_os = "macos")]
fn macos_pid_to_c_int(pid: u32) -> Result<libc::c_int, String> {
    libc::c_int::try_from(pid).map_err(|_| format!("pid {pid} does not fit c_int"))
}

/// Errors the meter surfaces. These are host-side faults (a missing or
/// unreadable meter source, a treasury storage fault), never genome-driven: the
/// meter must fail loudly rather than silently bill zero on a bad placement.
#[derive(Debug, thiserror::Error)]
pub enum MeterError {
    #[cfg(target_os = "linux")]
    #[error("the VM cgroup directory is missing at {0} (placement failed: nothing to meter)")]
    CgroupMissing(PathBuf),
    #[cfg(target_os = "linux")]
    #[error("cpu.stat unreadable for cgroup {0}: {1}")]
    CpuUnreadable(PathBuf, String),
    #[cfg(target_os = "linux")]
    #[error("memory.current unreadable for cgroup {0}: {1}")]
    MemUnreadable(PathBuf, String),
    #[cfg(target_os = "macos")]
    #[error("host-process meter source rooted at pid {root_pid} is unreadable: {reason}")]
    HostProcessUnreadable { root_pid: u32, reason: String },
    #[error("allocation meter config invalid: {reason}")]
    AllocationInvalid { reason: String },
    #[error(transparent)]
    Treasury(#[from] TreasuryError),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `[meter]` config block maps field-for-field into the runtime `BurnRates`, and
    /// its defaults are byte-identical to `BurnRates::default` (so an absent block is a
    /// no-op). BurnRates is `Copy` (no `PartialEq`), so the defaults are checked per field.
    #[test]
    fn burn_rates_from_meter_config_round_trips() {
        let def: BurnRates = (&crate::config::MeterRatesConfig::default()).into();
        let std = BurnRates::default();
        assert_eq!(def.cpu_sats_per_usec_num, std.cpu_sats_per_usec_num);
        assert_eq!(def.cpu_sats_per_usec_den, std.cpu_sats_per_usec_den);
        assert_eq!(def.mem_sats_per_mib_sec, std.mem_sats_per_mib_sec);
        assert_eq!(def.egress_sats_per_byte_num, std.egress_sats_per_byte_num);
        assert_eq!(def.egress_sats_per_byte_den, std.egress_sats_per_byte_den);

        // A tuned block (the F4 deploy lever: drop the memory rent) flows through verbatim.
        let tuned = crate::config::MeterRatesConfig {
            mem_sats_per_mib_sec: 0,
            ..crate::config::MeterRatesConfig::default()
        };
        let rates: BurnRates = (&tuned).into();
        assert_eq!(rates.mem_sats_per_mib_sec, 0, "the deploy can zero the memory rent");
        assert_eq!(rates.cpu_sats_per_usec_den, 1000, "untouched fields keep defaults");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn parse_flat_keyed_reads_usage_usec() {
        let stat = "usage_usec 1003338\nuser_usec 900000\nsystem_usec 103338\n";
        assert_eq!(parse_flat_keyed(stat, "usage_usec"), Some(1003338));
        assert_eq!(parse_flat_keyed(stat, "system_usec"), Some(103338));
        assert_eq!(parse_flat_keyed(stat, "absent"), None);
    }

    /// FLOOR-HALT (the diarist's death): with a floor enabled the meter halts strictly BELOW
    /// the per-think cap (zombie-free — at/above the cap any think is affordable); a 0 floor
    /// (every non-diarist run) never floor-halts, whatever the balance.
    #[test]
    fn floor_halt_fires_below_the_cap_and_is_disabled_at_zero() {
        // floor = 0 (disabled): NEVER halts on the floor, even at a drained treasury.
        assert!(!floor_halt_reached(0, 0));
        assert!(!floor_halt_reached(1_000, 0));
        // floor = the per-think cap (the diarist): halt strictly below it.
        let floor = 64;
        assert!(!floor_halt_reached(65, floor));
        assert!(!floor_halt_reached(64, floor), "exactly the cap: a think is still guaranteed, no halt");
        assert!(floor_halt_reached(63, floor), "below the cap: the next think is not guaranteed -> death");
        assert!(floor_halt_reached(0, floor), "drained: death");
    }

    #[test]
    fn burn_bills_cpu_and_memory_nonzero() {
        let rates = BurnRates::default();
        // 100 ms of CPU (100_000 usec) at 1 sat/ms = 100 sats. No egress.
        let cpu_only = rates.burn_for_tick(100_000, 0, 0, Duration::from_millis(100));
        assert_eq!(cpu_only, 100, "100ms CPU at 1 sat/ms");

        // 64 MiB held for a 1000 ms tick at 1 sat/MiB-second = 64 sats.
        let mem_only = rates.burn_for_tick(0, 64 * 1024 * 1024, 0, Duration::from_millis(1000));
        assert_eq!(mem_only, 64, "64 MiB for 1s at 1 sat/MiB-s");

        // Both contribute; the total is their sum (100 sats CPU + 64 sats
        // mem-time), and it is non-zero (the meter reads real usage, the G2
        // burn-not-zero property at the unit level).
        let both = rates.burn_for_tick(100_000, 64 * 1024 * 1024, 0, Duration::from_millis(1000));
        assert_eq!(both, 100 + 64);
        assert!(both > 0);
    }

    #[test]
    fn burn_does_not_floor_small_memory_tick_to_zero() {
        // A 32 MiB hold for a 100 ms tick: 32 * 0.1 = 3.2 MiB-seconds -> 3 sats
        // (integer floor, but NOT zero: the arrange-before-divide keeps it).
        let rates = BurnRates::default();
        let mem = rates.burn_for_tick(0, 32 * 1024 * 1024, 0, Duration::from_millis(100));
        assert_eq!(mem, 3, "32 MiB for 100ms = 3.2 MiB-s floored to 3, not 0");
    }

    #[test]
    fn burn_bills_egress_bytes_per_byte() {
        // The C-5 egress term: at 1 sat/byte, 1500 egress bytes this tick bill
        // 1500 sats. With the default-deny lockdown this delta is ~0 (G4), but
        // any byte that DID leave the TAP is metered (the unforgeable network
        // bill, D-9). CPU and memory zero here so only egress contributes.
        let rates = BurnRates::default();
        let egress_only = rates.burn_for_tick(0, 0, 1500, Duration::from_millis(100));
        assert_eq!(egress_only, 1500, "1500 egress bytes at 1 sat/byte");

        // A sub-1-sat-per-byte rate (1 sat per KiB) floors small deltas but is
        // expressible via the num/den.
        let per_kib = BurnRates {
            egress_sats_per_byte_num: 1,
            egress_sats_per_byte_den: 1024,
            ..rates
        };
        assert_eq!(
            per_kib.burn_for_tick(0, 0, 4096, Duration::from_millis(100)),
            4,
            "4096 bytes at 1 sat/KiB = 4"
        );

        // CPU + mem + egress all contribute and sum.
        let all = rates.burn_for_tick(100_000, 64 * 1024 * 1024, 200, Duration::from_millis(1000));
        assert_eq!(all, 100 + 64 + 200);
    }

    /// UNDERCOUNT SAFETY (the keeper's correctness nuance): each pid's `proc_pid_rusage`
    /// value is CUMULATIVE (monotonic since process start), the meter sums the live pids'
    /// cumulative values each tick, and `tick_once` bills the DELTA of that summed total
    /// (`total_now - total_prev`, `saturating_sub` => clamped to 0 when it would go
    /// negative). So if an exited service pid's accumulated CPU silently LEFT the sum, the
    /// summed total would DROP, the delta would clamp to 0, and the lower sum would become
    /// the baseline forever — a persistent undercount in the agent's favor (free compute,
    /// die-when-broke fails). This drives the pure `accumulate_pid` (no live VM) with
    /// injected samples to assert that an ESRCH-exited pid RETAINS its last-sampled value
    /// so the summed total does NOT decrease across the exit.
    #[test]
    #[cfg(target_os = "macos")]
    fn esrch_pid_retains_last_sample_so_total_does_not_drop() {
        use std::collections::HashMap;

        let mut source = HostProcessMeterSource {
            root_pid: 1,
            service_pids: vec![2],
            memory_cap_bytes: 0,
            last_cpu_nsec_by_pid: HashMap::new(),
        };

        let esrch = || CpuSampleError {
            reason: "proc_pid_rusage(2) failed: No such process".to_string(),
            raw_os_error: Some(libc::ESRCH),
        };

        // Tick 1: root pid (1) and service pid (2) both live with cumulative values.
        let (root_c1, root_live1) = source.accumulate_pid(1, Ok(5_000)).expect("root live");
        let (svc_c1, svc_live1) = source.accumulate_pid(2, Ok(3_000)).expect("service live");
        let total1 = root_c1 + svc_c1;
        assert_eq!(total1, 8_000);
        assert!(root_live1 && svc_live1, "both pids counted live");

        // Tick 2: root pid (1) advanced (cumulative grew); service pid (2) EXITED (ESRCH).
        // Its frozen last-sampled 3_000 must still be contributed, so the summed total is
        // monotonic — it does NOT drop below tick 1 even though pid 2 is gone.
        let (root_c2, root_live2) = source.accumulate_pid(1, Ok(6_000)).expect("root live");
        let (svc_c2, svc_live2) = source.accumulate_pid(2, Err(esrch())).expect("esrch is benign");
        let total2 = root_c2 + svc_c2;
        assert_eq!(svc_c2, 3_000, "exited pid contributes its FROZEN last value, not 0");
        assert!(root_live2, "root still live");
        assert!(!svc_live2, "exited pid is not counted live");
        assert!(
            total2 >= total1,
            "cumulative summed total must not decrease when a pid vanishes (no undercount): {total2} < {total1}"
        );
        assert_eq!(total2, 9_000, "6_000 (root) + 3_000 (frozen service) = 9_000");

        // CONTRAST: the OLD skip-to-zero behavior would have dropped the service term to 0,
        // giving total2' = 6_000 < total1 = 8_000 — the negative delta that clamps and
        // re-baselines low. The retained-frozen value is exactly what prevents that.
        let dropped_to_zero = root_c2; // service term == 0 under the old skip
        assert!(dropped_to_zero < total1, "demonstrates the undercount the fix prevents");
    }

    /// A first-seen pid that is ALREADY gone (ESRCH) with no prior sample contributes 0
    /// (there is nothing accumulated to retain) — no phantom compute, matching the prior
    /// behavior for a never-sampled pid.
    #[test]
    #[cfg(target_os = "macos")]
    fn esrch_pid_never_sampled_contributes_zero() {
        use std::collections::HashMap;

        let mut source = HostProcessMeterSource {
            root_pid: 1,
            service_pids: vec![7],
            memory_cap_bytes: 0,
            last_cpu_nsec_by_pid: HashMap::new(),
        };
        let (c, live) = source
            .accumulate_pid(
                7,
                Err(CpuSampleError {
                    reason: "gone".to_string(),
                    raw_os_error: Some(libc::ESRCH),
                }),
            )
            .expect("esrch benign");
        assert_eq!(c, 0, "never-sampled exited pid contributes 0 (no phantom compute)");
        assert!(!live);
    }

    /// A SERVICE pid failing for a reason OTHER than ESRCH is a real accounting/permission
    /// fault and still HARD-FAILS (unchanged): we never silently freeze a non-exit fault.
    #[test]
    #[cfg(target_os = "macos")]
    fn service_pid_non_esrch_fault_hard_fails() {
        use std::collections::HashMap;

        let mut source = HostProcessMeterSource {
            root_pid: 1,
            service_pids: vec![2],
            memory_cap_bytes: 0,
            last_cpu_nsec_by_pid: HashMap::new(),
        };
        let err = source.accumulate_pid(
            2,
            Err(CpuSampleError {
                reason: "permission denied".to_string(),
                raw_os_error: Some(libc::EPERM),
            }),
        );
        assert!(
            matches!(err, Err(MeterError::HostProcessUnreadable { .. })),
            "a non-ESRCH service-pid fault must still hard-fail"
        );
    }

    /// The ROOT pid vanishing (even via ESRCH) is a hard failure (unchanged): losing the
    /// VZ helper means we can no longer meter the run at all.
    #[test]
    #[cfg(target_os = "macos")]
    fn root_pid_loss_hard_fails() {
        use std::collections::HashMap;

        let mut source = HostProcessMeterSource {
            root_pid: 1,
            service_pids: vec![2],
            memory_cap_bytes: 0,
            last_cpu_nsec_by_pid: HashMap::new(),
        };
        let err = source.accumulate_pid(
            1,
            Err(CpuSampleError {
                reason: "gone".to_string(),
                raw_os_error: Some(libc::ESRCH),
            }),
        );
        assert!(
            matches!(err, Err(MeterError::HostProcessUnreadable { .. })),
            "root pid loss must hard-fail even on ESRCH"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn host_process_attach_requires_vz_service_pid() {
        let treasury = crate::treasury::Treasury::open_temporary(1_000).expect("treasury opens");
        let config = HostProcessMeterConfig {
            root_pid: std::process::id(),
            service_pids: Vec::new(),
            memory_mib: 128,
            tick: Duration::from_millis(100),
            rates: BurnRates::default(),
        };

        let err = match Meter::attach_host_process(&config, treasury) {
            Ok(_) => panic!("empty VZ service pid set must not attach"),
            Err(err) => err,
        };
        match err {
            MeterError::HostProcessUnreadable { root_pid, reason } => {
                assert_eq!(root_pid, config.root_pid);
                assert!(reason.contains("no VZ VirtualMachine service pid discovered"));
                assert!(reason.contains("refusing helper-only CPU metering"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // ---- ALLOCATION-based metering teeth (chunk D pt.2) ----
    //
    // These replace the now-dead `g2_vz_busy_burns_more_than_idle` precision test
    // (which asserted busy > idle — a now-impossible invariant, since allocation
    // billing is utilization-blind BY DESIGN). They are DETERMINISTIC unit tests on
    // `AllocationMeterSource::sample_at(elapsed)`: no VM, no clock, no flakiness.

    /// (a) Same vcpu_count: cumulative CPU scales LINEARLY with elapsed, and equal
    /// elapsed yields equal CPU — the "busy == idle by design" property (allocation
    /// billing does not depend on what the guest actually did, only on wall-time).
    #[test]
    fn allocation_cpu_scales_linearly_with_elapsed() {
        let source = AllocationMeterSource {
            vcpu_count: 1,
            mem_bytes: 128 * 1024 * 1024,
            start: std::time::Instant::now(),
        };

        let s1 = source.sample_at(Duration::from_secs(1));
        let s2 = source.sample_at(Duration::from_secs(2));
        let s4 = source.sample_at(Duration::from_secs(4));

        // 1 vCPU × elapsed_usec.
        assert_eq!(s1.cpu_usec, 1_000_000);
        assert_eq!(s2.cpu_usec, 2_000_000);
        assert_eq!(s4.cpu_usec, 4_000_000);
        // Linear: doubling elapsed doubles cumulative CPU.
        assert_eq!(s2.cpu_usec, s1.cpu_usec * 2);
        assert_eq!(s4.cpu_usec, s2.cpu_usec * 2);

        // Equal elapsed → equal CPU regardless of anything else: busy == idle by design.
        let again = source.sample_at(Duration::from_secs(2));
        assert_eq!(
            again.cpu_usec, s2.cpu_usec,
            "allocation billing is utilization-blind: equal elapsed bills equal CPU"
        );

        // Memory is the fixed cap (allocation, not RSS), independent of elapsed.
        assert_eq!(s1.mem_bytes, 128 * 1024 * 1024);
        assert_eq!(s4.mem_bytes, 128 * 1024 * 1024);
    }

    /// (b) 2 vCPU samples ~2× the cpu_usec of 1 vCPU for the SAME elapsed: the bill
    /// scales with the ALLOCATION (vcpu_count), not utilization.
    #[test]
    fn allocation_cpu_scales_with_vcpu_count() {
        let one = AllocationMeterSource {
            vcpu_count: 1,
            mem_bytes: 0,
            start: std::time::Instant::now(),
        };
        let two = AllocationMeterSource {
            vcpu_count: 2,
            mem_bytes: 0,
            start: std::time::Instant::now(),
        };

        let elapsed = Duration::from_secs(3);
        let c1 = one.sample_at(elapsed).cpu_usec;
        let c2 = two.sample_at(elapsed).cpu_usec;

        assert_eq!(c1, 3_000_000, "1 vCPU × 3s");
        assert_eq!(c2, 6_000_000, "2 vCPU × 3s");
        // The teeth: the 2-vCPU reservation bills EXACTLY 2× the 1-vCPU reservation
        // for the same wall-time. Scaling factor = 2.
        assert_eq!(
            c2,
            c1 * 2,
            "2 vCPU must bill 2x a 1 vCPU allocation for the same elapsed (scales with ALLOCATION not utilization)"
        );
    }

    /// The cumulative CPU fed to the meter is MONOTONIC in elapsed (never decreases),
    /// so `tick_once`'s delta-billing (`saturating_sub`) yields a non-negative per-tick
    /// burn — the same monotonicity contract every source upholds.
    #[test]
    fn allocation_cpu_is_monotonic_in_elapsed() {
        let source = AllocationMeterSource {
            vcpu_count: 2,
            mem_bytes: 0,
            start: std::time::Instant::now(),
        };
        let mut prev = 0u64;
        for ms in [0u64, 50, 100, 250, 1000, 5000] {
            let cur = source.sample_at(Duration::from_millis(ms)).cpu_usec;
            assert!(cur >= prev, "cumulative CPU must not decrease: {cur} < {prev} at {ms}ms");
            prev = cur;
        }
    }

    /// End-to-end through the real per-tick burn math: a 1-vCPU allocation over one
    /// tick's worth of elapsed produces the SAME per-tick burn as feeding the equivalent
    /// cpu_delta to `burn_for_tick` directly — i.e. the allocation source plugs into the
    /// existing delta-billing with NO new coefficient (it reuses cpu_sats_per_usec).
    #[test]
    fn allocation_feeds_existing_burn_math_no_new_coefficient() {
        let rates = BurnRates {
            cpu_sats_per_usec_num: 1,
            cpu_sats_per_usec_den: 1,
            mem_sats_per_mib_sec: 0,
            egress_sats_per_byte_num: 0,
            egress_sats_per_byte_den: 1,
        };
        // 2 vCPU over a 100ms tick = a cpu delta of 2 × 100_000 usec = 200_000 usec.
        let source = AllocationMeterSource {
            vcpu_count: 2,
            mem_bytes: 0,
            start: std::time::Instant::now(),
        };
        let t0 = source.sample_at(Duration::from_millis(0)).cpu_usec;
        let t1 = source.sample_at(Duration::from_millis(100)).cpu_usec;
        let cpu_delta = t1 - t0;
        assert_eq!(cpu_delta, 200_000, "2 vCPU × 100ms = 200_000 usec");

        let burn = rates.burn_for_tick(cpu_delta, 0, 0, Duration::from_millis(100));
        assert_eq!(burn, 200_000, "reuses cpu_sats_per_usec (1/1); no new coefficient");
    }
}
