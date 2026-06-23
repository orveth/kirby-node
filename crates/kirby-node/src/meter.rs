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
}

struct MeterSample {
    cpu_usec: u64,
    mem_bytes: u64,
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
        let source = HostProcessMeterSource {
            root_pid: config.root_pid,
            service_pids: config.service_pids.clone(),
            memory_cap_bytes,
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
    fn sample(&self) -> Result<MeterSample, MeterError> {
        match self {
            #[cfg(target_os = "linux")]
            MeterSampleSource::Cgroup(source) => source.sample(),
            #[cfg(target_os = "macos")]
            MeterSampleSource::HostProcess(source) => source.sample(),
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
    fn sample(&self) -> Result<MeterSample, MeterError> {
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
            match macos_process_cpu_nsec(pid) {
                Ok(pid_cpu_nsec) => {
                    cpu_nsec = cpu_nsec.saturating_add(pid_cpu_nsec);
                    sampled += 1;
                }
                Err(e) if pid == self.root_pid || self.service_pids.contains(&pid) => {
                    return Err(MeterError::HostProcessUnreadable {
                        root_pid: self.root_pid,
                        reason: e,
                    });
                }
                Err(e) => {
                    tracing::debug!(
                        pid,
                        root_pid = self.root_pid,
                        error = %e,
                        "skipping disappeared non-root process during macOS VZ meter sample"
                    );
                }
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

#[cfg(target_os = "macos")]
fn macos_process_cpu_nsec(pid: u32) -> Result<u64, String> {
    let pid = macos_pid_to_c_int(pid)?;
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v4>::uninit();
    let rc = unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V4, usage.as_mut_ptr().cast()) };
    if rc != 0 {
        return Err(format!(
            "proc_pid_rusage({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
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
}
