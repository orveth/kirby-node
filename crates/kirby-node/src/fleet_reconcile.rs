//! RE-ADOPT / REAP on supervisor restart (closes resilience finding G-3, the ORPHAN-ZOMBIE).
//!
//! ## The problem
//! When a `kirby fleet` supervisor is killed, its tenant VMs do NOT die with it. Each tenant is
//! a CHILD `kirby agent` process (which owns a firecracker VM under the jailer); on the
//! supervisor's death those children are REPARENTED to init and keep running, still burning
//! compute, but their presence/lease heartbeats stop — so they go STALE on the relay (they look
//! dead in the UI) while alive. A restarted supervisor has NO `Child` handle to them (a
//! reparented process cannot be `waitpid`-ed; a fresh `Child` is unrecoverable). It must
//! RECONCILE its persisted state with reality: RE-ADOPT the healthy orphans it still owns, REAP
//! the rest.
//!
//! ## The crux: orphan liveness + PID-reuse-safe identification
//! A restarted supervisor reloads the [`crate::fleet::Allocator`] (so it knows `agent_id ->
//! instance_id / CID / port` it was hosting) but holds no process handle. We must answer, per
//! persisted agent: **is its VM still alive, and is it actually OUR agent?** A bare PID check is
//! NOT enough — PIDs get reused, so a live PID might be an unrelated process that inherited the
//! number. So at launch we persist the child's PID in a sidecar keyed by `instance_id`
//! ([`LaunchRegistry`]), and on restart we probe PID-REUSE-SAFE ([`ProcLivenessProbe`]): the
//! process exists (`kill(pid, 0)`) AND `/proc/<pid>/cmdline` still names THIS tenant (the
//! per-tenant config file `tenant-<agent_id>.toml` the launcher spawned it against). A live PID
//! whose cmdline does NOT match is treated as NOT ours (so it is never falsely re-adopted; the
//! agent it stood for is reaped).
//!
//! ## The reconcile decision (pure + unit-testable)
//! [`reconcile`] is a PURE function over (the persisted launch records, an injected liveness
//! [`OrphanLivenessProbe`], an injected [`ReconcileLeaseView`], this node's id) returning a
//! per-agent [`ReconcileVerdict`] of `{ReAdopt | Reap{reason}}`. No VM, no relay, no real
//! process — the load-bearing teeth run in-process (mirroring the fence-test style in
//! `spawn.rs`). The async I/O (probing `/proc`, draining retained relay leases into a snapshot)
//! lives in the wiring (`main.rs::reconcile_fleet_on_startup`), which resolves the lease view to
//! a sync [`LeaseSnapshot`] and then calls this pure fn.
//!
//! Per persisted agent:
//!  - **alive + lease still ours + fresh => RE-ADOPT**: re-track it as a supervise-by-PID
//!    [`PidTenant`] (no relaunch), so the existing `heartbeat_leases` tick resumes refreshing its
//!    lease + presence. A supervisor bounce becomes invisible to the fleet.
//!  - **otherwise => REAP**: kill the orphaned VM/process (signal the PID), release the
//!    allocation, clean the abandoned keystore (this also closes task #15), and clear the ledger
//!    entry. Covers a DEAD/MISSING process, a STALE lease (it died, the TTL elapsed), and a lease
//!    now held by ANOTHER node (we lost the claim — don't fight; reap our local remnant).
//!
//! ## Residuals (documented, not silently assumed)
//!  - A true double-host across a race (two supervisors both think they own an agent mid-handoff)
//!    is bounded by the relay-lease term fence already merged (`relay_lease.rs`); it is not
//!    re-solved here.
//!  - RE-ADOPT resumes presence/lease but CANNOT recover the original child's stdout/console
//!    stream — the reparented child's serial log is no longer wired to this supervisor. The agent
//!    runs and is observable over the relay; only the local console tail is lost until it dies +
//!    respawns.
//!
//! G-CLEAN: this module is only reached by a fleet supervisor on `kirby fleet` startup. A bare
//! `kirby run` / `kirby agent` never constructs a [`LaunchRegistry`] and never reconciles.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::fleet::AgentId;
use crate::fleet_supervisor::TenantProcess;
use crate::lease::{ActiveLease, LeaseNodeId};

/// One launched tenant's durable identification record, persisted at launch in the
/// [`LaunchRegistry`] sidecar keyed by `instance_id`. Carries exactly what a restarted
/// supervisor needs to find the orphan and prove it is OURS: the agent id, the instance id, and
/// the OS PID of the child `kirby agent` process the supervisor spawned. The allocator persists
/// the resource triple; this persists the PID alongside it (the allocator's `TenantAllocation`
/// is a clean wire type shared with the lease/spawn paths, so the volatile PID lives in this
/// sidecar instead of polluting it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRecord {
    /// The tenant's agent id (the lease/treasury key, and the token embedded in the child's
    /// per-tenant config filename `tenant-<agent_id>.toml` the liveness probe matches on).
    pub agent_id: AgentId,
    /// The host instance id `kirby-<agent_id>` (keys the keystore + treasury dirs).
    pub instance_id: String,
    /// The OS PID of the child `kirby agent` process the supervisor spawned for this tenant.
    /// The liveness probe checks `kill(pid, 0)` AND that `/proc/<pid>/cmdline` still names this
    /// tenant (PID-reuse-safe — a recycled PID running something else is not re-adopted).
    pub pid: u32,
}

/// The durable sidecar that records every tenant's launch identity (PID + instance id) so a
/// restarted supervisor can probe its orphans. Persisted as JSON next to the allocator state,
/// written atomically (temp file + rename) on every mutation so a crash mid-write never leaves a
/// truncated file. Keyed by `instance_id` (the same key the keystore/treasury use), so a record
/// sits logically beside the agent's other per-instance state.
///
/// This is the PID half of the persisted state the design calls for; the allocator
/// ([`crate::fleet::Allocator`]) is the resource-triple half. The two are reconciled together on
/// startup: the allocator says WHICH agents this node was hosting (+ their CID/port), this says
/// WHICH PID each was, so liveness can be checked.
#[derive(Debug, Default)]
pub struct LaunchRegistry {
    /// Where the records are persisted (JSON). `None` for an in-memory registry (tests); `Some`
    /// persists every mutation atomically.
    persist_path: Option<PathBuf>,
    /// The launch records, keyed by `instance_id`.
    records: BTreeMap<String, LaunchRecord>,
}

impl LaunchRegistry {
    /// Load the registry from a persisted file at `path`, or start empty if absent. A
    /// corrupt/unreadable file is an error rather than a silent reset: losing the PID records
    /// would blind the reconcile (every orphan would look un-probable and be reaped, killing
    /// healthy agents on a transient read fault) — better to refuse and let the operator look.
    pub fn load_or_new(path: &Path) -> anyhow::Result<Self> {
        let records = if path.exists() {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("read fleet launch registry {}: {e}", path.display()))?;
            serde_json::from_slice::<BTreeMap<String, LaunchRecord>>(&bytes).map_err(|e| {
                anyhow::anyhow!("parse fleet launch registry {}: {e}", path.display())
            })?
        } else {
            BTreeMap::new()
        };
        Ok(LaunchRegistry { persist_path: Some(path.to_path_buf()), records })
    }

    /// A fresh in-memory registry (no persistence) — for tests and a supervisor that never
    /// restarts.
    pub fn in_memory() -> Self {
        LaunchRegistry { persist_path: None, records: BTreeMap::new() }
    }

    /// Record (or overwrite) a tenant's launch identity, keyed by `instance_id`, and persist.
    /// Overwrite is correct: a re-launch of the same instance (after a reap) records the NEW
    /// PID over the stale one.
    pub fn record(&mut self, record: LaunchRecord) -> anyhow::Result<()> {
        self.records.insert(record.instance_id.clone(), record);
        self.persist()
    }

    /// Forget a tenant's launch identity (after a reap), keyed by `instance_id`, and persist.
    /// Idempotent: removing an absent record is a no-op (it still persists the unchanged set,
    /// cheaply).
    pub fn forget(&mut self, instance_id: &str) -> anyhow::Result<()> {
        self.records.remove(instance_id);
        self.persist()
    }

    /// The launch record for an instance id, if any.
    pub fn get(&self, instance_id: &str) -> Option<&LaunchRecord> {
        self.records.get(instance_id)
    }

    /// All persisted launch records (the set the reconcile iterates). Cloned so the caller can
    /// mutate the registry (forget reaped records) while iterating the snapshot.
    pub fn all(&self) -> Vec<LaunchRecord> {
        self.records.values().cloned().collect()
    }

    /// Persist the records to disk if a path is configured, atomically (temp file + rename).
    fn persist(&self) -> anyhow::Result<()> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec_pretty(&self.records)
            .map_err(|e| anyhow::anyhow!("encode fleet launch registry: {e}"))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| anyhow::anyhow!("write fleet launch registry {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| anyhow::anyhow!("rename fleet launch registry into {}: {e}", path.display()))?;
        Ok(())
    }
}

// ----------------------------------------------------------------------------------------
// The liveness probe seam (PID-reuse-safe orphan identification)
// ----------------------------------------------------------------------------------------

/// The orphan-liveness check, behind a trait so the reconcile decision is unit-testable with a
/// mock (no real `/proc`, no real process). Answers the crux question PID-REUSE-SAFE: is the
/// process at `pid` BOTH alive AND still OUR tenant for `agent_id`?
///
/// `Send + Sync` so a [`PidTenant`] (which holds one) crosses the supervisor's tasks.
pub trait OrphanLivenessProbe: Send + Sync {
    /// `true` only if a process exists at `pid` AND it is the `kirby agent` child for
    /// `agent_id` (its cmdline still names this tenant). A dead/missing PID, or a LIVE PID whose
    /// cmdline does not match (PID reuse — the number was recycled by an unrelated process),
    /// returns `false`. Never falsely claims a recycled PID as ours.
    fn alive_and_ours(&self, pid: u32, agent_id: &str) -> bool;
}

/// The per-tenant token the launcher embeds in the child's command line (the config filename
/// `tenant-<agent_id>.toml`). The PID-reuse-safe probe requires this exact token to appear in
/// `/proc/<pid>/cmdline` before it will claim the PID as ours — it is unique per tenant (so
/// `alice` never matches the `alice2` child) and is exactly what `ProcessTenantLauncher` spawns
/// against (`--config <dir>/tenant-<agent_id>.toml`). Kept here as the single source of truth
/// shared by the launcher (which writes it) and the probe (which matches it).
pub fn cmdline_match_token(agent_id: &str) -> String {
    format!("tenant-{agent_id}.toml")
}

/// The real Linux liveness probe: `kill(pid, 0)` (does the process exist + can we signal it?)
/// AND `/proc/<pid>/cmdline` contains the per-tenant [`cmdline_match_token`]. The cmdline read
/// is what makes it PID-REUSE-SAFE: a recycled PID running something else has a different
/// cmdline and is rejected. A `kirby agent` child reparented to init keeps the SAME cmdline, so
/// a genuinely-surviving orphan is correctly recognized.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcLivenessProbe;

impl ProcLivenessProbe {
    /// Read `/proc/<pid>/cmdline` (NUL-separated argv) as a single space-joined string, or
    /// `None` if the process is gone / unreadable. Bounded read (a cmdline is small); a missing
    /// file means the process exited.
    fn read_cmdline(pid: u32) -> Option<String> {
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        // argv entries are NUL-separated; join on spaces so a token match is simple. An empty
        // cmdline (a kernel thread / zombie) yields an empty string (no token => not ours).
        Some(
            raw.split(|b| *b == 0)
                .map(|seg| String::from_utf8_lossy(seg).into_owned())
                .collect::<Vec<_>>()
                .join(" "),
        )
    }
}

impl OrphanLivenessProbe for ProcLivenessProbe {
    fn alive_and_ours(&self, pid: u32, agent_id: &str) -> bool {
        // 1. Does the process exist? `kill(pid, 0)` sends no signal but errors (ESRCH) if no
        //    such process. SAFETY: signal 0 to a pid; it never affects the target, only probes
        //    existence/permission. A return of 0 means the process exists and we may signal it.
        let exists = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if !exists {
            return false;
        }
        // 2. PID-REUSE-SAFE identity: the live PID must still be OUR tenant. Match the unique
        //    per-tenant token in its cmdline; a recycled PID running anything else fails here.
        match Self::read_cmdline(pid) {
            Some(cmdline) => cmdline.contains(&cmdline_match_token(agent_id)),
            None => false,
        }
    }
}

/// A SUPERVISE-BY-PID tenant: a [`TenantProcess`] for a re-adopted orphan the supervisor did NOT
/// spawn in this lifetime (so it has no `Child` to `waitpid`). Liveness is the PID-reuse-safe
/// probe; `kill` signals the PID directly (SIGTERM then SIGKILL).
///
/// This is the handle a RE-ADOPT inserts into the supervisor's live set, so the existing
/// `heartbeat_leases` tick refreshes the orphan's lease and `reap_dead` later collects it if it
/// dies — the orphan becomes a first-class tracked tenant again, indistinguishable to the rest
/// of the supervisor from a freshly-launched one.
pub struct PidTenant {
    pid: u32,
    agent_id: AgentId,
    probe: Arc<dyn OrphanLivenessProbe>,
}

impl PidTenant {
    /// Build a supervise-by-PID handle for a re-adopted orphan. `probe` is the SAME probe the
    /// reconcile used to decide it was alive + ours; `is_running` re-uses it so the supervisor's
    /// dead-tenant detector stays PID-reuse-safe for the orphan's whole re-adopted life.
    pub fn new(pid: u32, agent_id: AgentId, probe: Arc<dyn OrphanLivenessProbe>) -> Self {
        PidTenant { pid, agent_id, probe }
    }
}

impl TenantProcess for PidTenant {
    fn is_running(&self) -> bool {
        // PID-reuse-safe: alive AND still our tenant. If the PID was recycled by an unrelated
        // process after the orphan died, this reads false (the orphan is gone), so the
        // supervisor reaps the slot rather than heartbeating a stranger's PID.
        self.probe.alive_and_ours(self.pid, &self.agent_id)
    }

    fn kill(&self) {
        // We did not spawn this process (it is reparented to init), so there is no `Child` to
        // `.kill()`; signal the PID directly. SIGTERM for a graceful stop, then SIGKILL as the
        // backstop. Best-effort + idempotent: a PID that is already gone returns ESRCH, which we
        // ignore. PID-REUSE-SAFE: only signal if it is STILL our tenant — never SIGKILL a
        // recycled PID that now belongs to an unrelated process.
        if !self.probe.alive_and_ours(self.pid, &self.agent_id) {
            return;
        }
        // SAFETY: kill(2) delivering SIGTERM/SIGKILL to a pid we just confirmed is our tenant; an
        // already-dead pid returns ESRCH (ignored). There is a vanishingly small TOCTOU window
        // between the check and the signal (the PID could exit + be reused), bounded the same way
        // the cgroup-kill path in firecracker.rs is — acceptable for a best-effort reap.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGTERM);
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
        }
    }

    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }
}

// ----------------------------------------------------------------------------------------
// The lease view seam (injected, sync — the async observer pre-resolves into a snapshot)
// ----------------------------------------------------------------------------------------

/// The lease read-side the reconcile needs: "what is the FRESH active lease for this agent, if
/// any?" — answering "is the lease still ours + fresh?" per agent. A SYNC trait so the pure
/// [`reconcile`] decision needs no `await`; the live async observer
/// (`crate::relay_lease::FleetLeaseObserver`, which drains retained relay leases) is pre-resolved
/// into a [`LeaseSnapshot`] by the wiring before the decision runs. Tests inject a mock directly.
pub trait ReconcileLeaseView {
    /// The fresh active lease for `agent_id` (`None` if none is held, or the latest has gone
    /// stale past the TTL). A `Some` whose `node_id` equals THIS node means the lease is still
    /// ours; a different `node_id` means another node took it; `None` means it went stale (the
    /// agent stopped heartbeating — it died).
    fn fresh_lease_for(&self, agent_id: &str) -> Option<ActiveLease>;
}

/// A resolved, point-in-time snapshot of the fleet's fresh leases per agent — the sync
/// [`ReconcileLeaseView`] the wiring builds by awaiting the async occupancy observer once per
/// agent (after draining the relay's retained leases) and the tests build directly. Decouples
/// the pure decision from the async relay I/O.
#[derive(Debug, Default, Clone)]
pub struct LeaseSnapshot {
    leases: BTreeMap<AgentId, ActiveLease>,
}

impl LeaseSnapshot {
    /// An empty snapshot (no agent has a fresh lease).
    pub fn new() -> Self {
        LeaseSnapshot { leases: BTreeMap::new() }
    }

    /// Record a fresh lease for an agent in the snapshot (builder-style).
    pub fn with(mut self, agent_id: &str, lease: ActiveLease) -> Self {
        self.leases.insert(agent_id.to_string(), lease);
        self
    }

    /// Insert a fresh lease for an agent (the wiring folds each resolved lease in).
    pub fn insert(&mut self, agent_id: &str, lease: ActiveLease) {
        self.leases.insert(agent_id.to_string(), lease);
    }
}

impl ReconcileLeaseView for LeaseSnapshot {
    fn fresh_lease_for(&self, agent_id: &str) -> Option<ActiveLease> {
        self.leases.get(agent_id).copied()
    }
}

// ----------------------------------------------------------------------------------------
// The reconcile decision (pure)
// ----------------------------------------------------------------------------------------

/// Why a persisted tenant is being REAPED (logged + drives the cleanup). Each variant names the
/// exact reason the orphan is not being re-adopted, so a reap is never silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReapReason {
    /// The process is gone (dead/missing), OR a live PID whose cmdline no longer names this
    /// tenant (PID reuse — the number was recycled). Either way the orphan's VM is not running
    /// as our agent.
    NotAlive,
    /// The process is alive + ours, but its lease has gone STALE (TTL elapsed — it stopped
    /// heartbeating long enough that it is dead-enough to respawn). Reaped so the slot frees and
    /// the agent can be re-spawned cleanly.
    LeaseStale,
    /// The process is alive + ours, but a FRESH lease now names ANOTHER node — we lost the claim
    /// (a failover, or a manual move). Don't fight: reap our local remnant so we do not
    /// double-host.
    LeaseLostToNode(LeaseNodeId),
}

impl std::fmt::Display for ReapReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReapReason::NotAlive => {
                write!(f, "the process is gone or a recycled PID no longer names this tenant")
            }
            ReapReason::LeaseStale => write!(f, "the lease went stale (TTL elapsed; dead-enough to respawn)"),
            ReapReason::LeaseLostToNode(n) => {
                write!(f, "a fresh lease now names another node ({n}); we lost the claim")
            }
        }
    }
}

/// The reconcile verdict for one persisted tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileVerdict {
    /// Alive + the lease is still ours + fresh: RE-ADOPT (re-track as a supervise-by-PID tenant,
    /// no relaunch; the heartbeat tick resumes refreshing its lease + presence).
    ReAdopt,
    /// REAP (kill the orphan + release the allocation + clean the keystore + clear the ledger).
    Reap(ReapReason),
}

/// One agent's reconcile outcome: which agent, its launch record (so the executor has the PID +
/// instance id to act on), and the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileItem {
    pub record: LaunchRecord,
    pub verdict: ReconcileVerdict,
}

/// THE PURE RECONCILE DECISION (the unit-tested core). For each persisted launch `record`,
/// decide RE-ADOPT vs REAP from (the injected liveness `probe`, the injected `lease_view`, this
/// node's id `this_node`). No VM, no relay, no real process — fully deterministic over its
/// inputs, so the load-bearing teeth run in-process (mirroring the fence-test style in
/// `spawn.rs`).
///
/// The decision per agent:
///  1. NOT alive (dead/missing PID, or a recycled PID whose cmdline no longer names us) =>
///     `Reap(NotAlive)`. Checked FIRST: a dead process needs no lease reasoning.
///  2. Alive + ours, but NO fresh lease (stale / TTL elapsed) => `Reap(LeaseStale)`.
///  3. Alive + ours + a fresh lease naming ANOTHER node => `Reap(LeaseLostToNode)`.
///  4. Alive + ours + a fresh lease naming THIS node => `ReAdopt`.
pub fn reconcile(
    records: &[LaunchRecord],
    probe: &dyn OrphanLivenessProbe,
    lease_view: &dyn ReconcileLeaseView,
    this_node: LeaseNodeId,
) -> Vec<ReconcileItem> {
    records
        .iter()
        .map(|record| {
            let verdict = decide_one(record, probe, lease_view, this_node);
            ReconcileItem { record: record.clone(), verdict }
        })
        .collect()
}

/// The per-agent decision (factored out so it reads as the 4-case table above).
fn decide_one(
    record: &LaunchRecord,
    probe: &dyn OrphanLivenessProbe,
    lease_view: &dyn ReconcileLeaseView,
    this_node: LeaseNodeId,
) -> ReconcileVerdict {
    // (1) Liveness FIRST (PID-reuse-safe). A dead/missing process — or a live PID whose cmdline
    //     no longer names this tenant — is reaped without any lease reasoning.
    if !probe.alive_and_ours(record.pid, &record.agent_id) {
        return ReconcileVerdict::Reap(ReapReason::NotAlive);
    }
    // The process is genuinely OUR live agent. Now the lease decides ownership.
    match lease_view.fresh_lease_for(&record.agent_id) {
        // (4) A fresh lease still names THIS node: it is ours — RE-ADOPT.
        Some(lease) if lease.node_id == this_node => ReconcileVerdict::ReAdopt,
        // (3) A fresh lease names ANOTHER node: we lost the claim — reap our remnant.
        Some(lease) => ReconcileVerdict::Reap(ReapReason::LeaseLostToNode(lease.node_id)),
        // (2) No fresh lease (none / stale / TTL elapsed): dead-enough to respawn — reap.
        None => ReconcileVerdict::Reap(ReapReason::LeaseStale),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// A mock liveness probe: a set of (pid, agent_id) pairs that are "alive + ours". Anything
    /// not in the set is NOT alive (covers dead/missing AND the PID-reuse mismatch — a live PID
    /// whose agent_id does not match is simply absent from the set). Mirrors the stub style in
    /// `spawn.rs` / `fleet_supervisor.rs`.
    #[derive(Default)]
    struct MockProbe {
        alive: HashSet<(u32, String)>,
    }
    impl MockProbe {
        fn with_alive(pairs: &[(u32, &str)]) -> Self {
            MockProbe {
                alive: pairs.iter().map(|(p, a)| (*p, a.to_string())).collect(),
            }
        }
    }
    impl OrphanLivenessProbe for MockProbe {
        fn alive_and_ours(&self, pid: u32, agent_id: &str) -> bool {
            self.alive.contains(&(pid, agent_id.to_string()))
        }
    }

    fn rec(agent_id: &str, pid: u32) -> LaunchRecord {
        LaunchRecord {
            agent_id: agent_id.to_string(),
            instance_id: format!("kirby-{agent_id}"),
            pid,
        }
    }

    fn lease(node_id: LeaseNodeId, term: u64) -> ActiveLease {
        ActiveLease { node_id, term }
    }

    /// TEETH 1: alive + ours + a fresh lease naming THIS node => RE-ADOPT. The healthy orphan
    /// this node still owns is re-adopted (the heartbeat will then cover it).
    #[test]
    fn alive_ours_fresh_lease_readopts() {
        let records = [rec("alice", 1000)];
        let probe = MockProbe::with_alive(&[(1000, "alice")]);
        let view = LeaseSnapshot::new().with("alice", lease(7, 3)); // held by node 7
        let items = reconcile(&records, &probe, &view, 7); // this node IS 7
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].verdict, ReconcileVerdict::ReAdopt, "alive+ours+ours-fresh-lease must re-adopt");
        assert_eq!(items[0].record.agent_id, "alice");
    }

    /// TEETH 2: a DEAD / missing process => REAP(NotAlive). The orphan already exited (or was
    /// never alive); reap releases its allocation + cleans its keystore + clears its ledger.
    #[test]
    fn dead_process_reaps_not_alive() {
        let records = [rec("alice", 1000)];
        let probe = MockProbe::default(); // nothing alive
        // Even with a fresh lease naming us, a dead process is reaped (liveness is checked first).
        let view = LeaseSnapshot::new().with("alice", lease(7, 3));
        let items = reconcile(&records, &probe, &view, 7);
        assert_eq!(items[0].verdict, ReconcileVerdict::Reap(ReapReason::NotAlive));
    }

    /// TEETH 3: alive but the lease is STALE (TTL elapsed; no fresh lease) => REAP(LeaseStale).
    /// It is dead-enough — it stopped heartbeating long enough to be respawnable; reap the slot.
    #[test]
    fn alive_but_stale_lease_reaps() {
        let records = [rec("alice", 1000)];
        let probe = MockProbe::with_alive(&[(1000, "alice")]);
        let view = LeaseSnapshot::new(); // no fresh lease for alice => stale/elapsed
        let items = reconcile(&records, &probe, &view, 7);
        assert_eq!(items[0].verdict, ReconcileVerdict::Reap(ReapReason::LeaseStale));
    }

    /// TEETH 4: alive but a fresh lease now names ANOTHER node => REAP(LeaseLostToNode). We lost
    /// the claim (failover/move); reap our local remnant so we do not double-host.
    #[test]
    fn alive_but_lease_now_another_node_reaps_remnant() {
        let records = [rec("alice", 1000)];
        let probe = MockProbe::with_alive(&[(1000, "alice")]);
        let view = LeaseSnapshot::new().with("alice", lease(9, 5)); // node 9 holds it now
        let items = reconcile(&records, &probe, &view, 7); // we are node 7
        assert_eq!(items[0].verdict, ReconcileVerdict::Reap(ReapReason::LeaseLostToNode(9)));
    }

    /// TEETH 5 (PID REUSE): a LIVE PID whose cmdline does NOT match the expected agent is treated
    /// as NOT alive (the probe returns false), so it is REAPED — never falsely re-adopted as the
    /// agent. Modeled by the mock holding the pid under a DIFFERENT agent_id than the record's.
    #[test]
    fn pid_reuse_mismatch_is_not_alive_and_reaps() {
        let records = [rec("alice", 1000)];
        // PID 1000 is alive but belongs to "somebody-else" (a recycled PID), NOT to "alice".
        let probe = MockProbe::with_alive(&[(1000, "somebody-else")]);
        // A fresh lease naming us would tempt a re-adopt, but the PID is not OUR alice => reap.
        let view = LeaseSnapshot::new().with("alice", lease(7, 3));
        let items = reconcile(&records, &probe, &view, 7);
        assert_eq!(
            items[0].verdict,
            ReconcileVerdict::Reap(ReapReason::NotAlive),
            "a recycled PID under a different agent must be NOT-alive => reap, never a false re-adopt"
        );
    }

    /// A mixed fleet reconciles each agent INDEPENDENTLY: one healthy (re-adopt), one dead
    /// (reap), one alive-but-lost-to-another-node (reap). Proves the decision is per-agent, like
    /// the per-agent lease isolation everywhere else.
    #[test]
    fn mixed_fleet_reconciles_each_agent_independently() {
        let records = [rec("alice", 1000), rec("bob", 1001), rec("carol", 1002)];
        // alice alive+ours; bob dead; carol alive but its lease moved to node 9.
        let probe = MockProbe::with_alive(&[(1000, "alice"), (1002, "carol")]);
        let view = LeaseSnapshot::new()
            .with("alice", lease(7, 1)) // ours
            .with("carol", lease(9, 4)); // another node's now
        let items = reconcile(&records, &probe, &view, 7);
        let by_agent: BTreeMap<_, _> =
            items.into_iter().map(|i| (i.record.agent_id.clone(), i.verdict)).collect();
        assert_eq!(by_agent["alice"], ReconcileVerdict::ReAdopt);
        assert_eq!(by_agent["bob"], ReconcileVerdict::Reap(ReapReason::NotAlive));
        assert_eq!(by_agent["carol"], ReconcileVerdict::Reap(ReapReason::LeaseLostToNode(9)));
    }

    // ---- LaunchRegistry: record / forget / persist round-trip ----

    /// The registry persists launch records and reloads them across a "restart" (drop + reload),
    /// so a restarted supervisor recovers the PIDs it must probe. A forgotten (reaped) record
    /// does not survive.
    #[test]
    fn launch_registry_persists_and_reloads_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "kirby-launch-registry-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("launch-registry.json");

        {
            let mut reg = LaunchRegistry::load_or_new(&path).expect("fresh load");
            reg.record(rec("alice", 1000)).expect("record alice");
            reg.record(rec("bob", 1001)).expect("record bob");
            // bob is reaped before the restart.
            reg.forget("kirby-bob").expect("forget bob");
            // reg dropped here => "supervisor restart"
        }

        let reloaded = LaunchRegistry::load_or_new(&path).expect("reload");
        let all = reloaded.all();
        assert_eq!(all.len(), 1, "only the un-forgotten record survives the restart");
        assert_eq!(all[0].agent_id, "alice");
        assert_eq!(all[0].pid, 1000);
        assert_eq!(reloaded.get("kirby-alice").map(|r| r.pid), Some(1000));
        assert!(reloaded.get("kirby-bob").is_none(), "a forgotten record must not survive");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt registry file is a LOUD error (not a silent empty reset): losing the PID records
    /// would make every orphan look un-probable and get reaped (killing healthy agents), so we
    /// refuse rather than reconcile blind.
    #[test]
    fn corrupt_launch_registry_is_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "kirby-launch-registry-corrupt-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("launch-registry.json");
        std::fs::write(&path, b"{not valid json").unwrap();
        assert!(
            LaunchRegistry::load_or_new(&path).is_err(),
            "a corrupt registry must error, never silently reset to empty (which would reap healthy agents)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- PidTenant: supervise-by-PID liveness + kill use the probe (PID-reuse-safe) ----

    /// A `PidTenant`'s `is_running` reflects the injected probe (alive+ours => running; not =>
    /// exited), so a re-adopted orphan is a first-class tracked tenant whose death the
    /// supervisor's existing dead-detector picks up. A flippable mock proves both states.
    #[test]
    fn pid_tenant_is_running_tracks_the_probe() {
        /// A probe whose liveness is a flippable flag (so the test can simulate the orphan dying).
        struct FlipProbe {
            alive: Mutex<bool>,
        }
        impl OrphanLivenessProbe for FlipProbe {
            fn alive_and_ours(&self, _pid: u32, _agent_id: &str) -> bool {
                *self.alive.lock().unwrap()
            }
        }
        let probe = Arc::new(FlipProbe { alive: Mutex::new(true) });
        let tenant = PidTenant::new(4242, "alice".to_string(), probe.clone());
        assert!(tenant.is_running(), "a re-adopted orphan reads RUNNING while alive+ours");
        // The orphan dies (or its PID is recycled): the probe flips, and the tenant reads EXITED,
        // so the supervisor's reap_dead/dead_tenants picks it up.
        *probe.alive.lock().unwrap() = false;
        assert!(!tenant.is_running(), "once the probe says not-alive, the tenant reads EXITED");
    }

    /// `PidTenant::kill` only signals when the PID is STILL ours (PID-reuse-safe): a probe that
    /// says not-ours makes kill a no-op (never SIGKILL a recycled PID). We assert the guard by
    /// using PID 0-style is not needed — we just prove kill does not panic and respects the
    /// not-ours short-circuit via a probe that reports false (so no real signal is sent).
    #[test]
    fn pid_tenant_kill_is_a_noop_when_not_ours() {
        struct NeverOurs;
        impl OrphanLivenessProbe for NeverOurs {
            fn alive_and_ours(&self, _pid: u32, _agent_id: &str) -> bool {
                false
            }
        }
        // PID 1 (init) — if kill did NOT short-circuit on not-ours it would attempt to signal
        // init (which we could not anyway as non-root, but the point is the guard prevents even
        // trying). With the not-ours probe, kill returns immediately without calling libc::kill.
        let tenant = PidTenant::new(1, "alice".to_string(), Arc::new(NeverOurs));
        tenant.kill(); // must be a clean no-op (no panic, no signal to the recycled/foreign PID)
    }
}
