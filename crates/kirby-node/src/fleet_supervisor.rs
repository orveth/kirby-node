//! The fleet supervisor (fleet-host S2, spec 2.1 / 3 / slice S2): the long-running
//! control process that hosts N tenants on one node, PROCESS-PER-TENANT (the locked
//! Q-process decision). It is OFF by default: nothing constructs a supervisor unless
//! `kirby fleet` is explicitly run, so `kirby run` / `kirby agent` are byte-identical
//! (G-CLEAN).
//!
//! WHAT IT DOES, per tenant, from a STATIC operator-declared `[fleet]` config:
//!  1. allocates a distinct CID / instance_id / gateway_port via the S0 [`crate::fleet::Allocator`];
//!  2. derives a per-agent treasury PATH (DB-per-agent, spec 2.1) so each tenant takes its
//!     OWN sled exclusive dir lock and there is zero cross-tenant contention;
//!  3. forms/joins the agent's per-agent lease and grants `{agent_id, self_node}` at the
//!     current term -- the lease-cluster SUBSTRATE the failover supervisor (S5/S6) needs
//!     (the child does NOT yet enforce this; see KNOWN DEFERRAL below);
//!  4. LAUNCHES the tenant as a CHILD process running the existing single-agent path
//!     (`kirby agent --config <derived tenant config>`) with the allocated resources;
//!  5. MONITORS child lifecycle (running / exited). The dead-tenant detection is the hook
//!     the failover supervisor (S5/S6) will act on; S2 only TRACKS it.
//!
//! THE TESTABILITY SEAM ([`TenantLauncher`]): the child launch sits behind a trait so the
//! supervisor's allocation + lifecycle + lease-grant logic is testable WITHOUT real VMs or
//! processes (non-gated). [`ProcessTenantLauncher`] is the real impl (spawns `kirby agent`);
//! a test supplies a stub launcher. The real-VM end-to-end path is `KIRBY_GENOME_IMAGE`-gated.
//!
//! THE LEASE SEAM: the supervisor grants per-agent leases through a [`LeaseGrantor`] (a
//! tiny trait over the Raft [`crate::raft_lease::LeaseNode`]); the gateway debit fence is
//! read through the [`crate::raft_lease::LeaseAuthority`] trait (commit 1), so a future
//! per-agent FROST-quorum lease drops in behind both without touching the supervisor.
//!
//! KNOWN DEFERRAL (S2, deliberate, in line with the roadmap): the supervisor GRANTS each
//! tenant its per-agent lease, but the tenant CHILD PROCESS does NOT yet enforce it -- the
//! child boots with no lease fence (`BootConfig.lease_fence = None`), because the lease
//! lives in THIS supervisor process and the child is a separate process. Enforcing it would
//! need a RemoteLeaseAuthority (the child querying this supervisor over IPC before each
//! debit). That is intentionally NOT built here: the lease only becomes load-bearing when a
//! SECOND node can contend for a tenant's agent (failover, S5/S6), and in S2 (single host,
//! static config, no failover) nothing else runs a tenant's agent, so the unfenced child is
//! not exploitable. Moreover the interim Raft lease is slated to be SUBSUMED by per-agent
//! FROST quorum co-signing (S3) plus the per-agent-quorum-as-lease scaling model, where an
//! agent's acts are gated at the SIGNING layer (a quorum co-sign), not a Raft fence in the
//! child. So child-side lease enforcement is deferred to S5/S6 rather than invested in the
//! interim mechanism now. S2 delivers multi-tenant RESOURCE isolation (own VM / CID /
//! treasury per tenant), which IS enforced and tested.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{KirbyConfig, TenantConfig};
use crate::fleet::{AgentId, AllocError, Allocator, TenantAllocation};
use crate::raft_lease::{LeaseNodeId, LeaseResponse};

/// What a launched tenant's resources + grant came out to (the supervisor's record of
/// one live tenant). Returned per tenant from [`FleetSupervisor::launch_all`] so a test
/// (and the operator) can inspect the allocation + the lease term it was granted at.
#[derive(Debug, Clone)]
pub struct TenantRecord {
    /// The tenant's agent id.
    pub agent_id: AgentId,
    /// The allocated resource triple (distinct CID / instance_id / gateway_port).
    pub allocation: TenantAllocation,
    /// The per-agent treasury path (DB-per-agent, spec 2.1): this tenant's OWN sled dir.
    pub treasury_path: PathBuf,
    /// The lease term the supervisor granted `{agent_id, self_node}` at.
    pub lease_term: u64,
}

/// The launch description the supervisor hands a [`TenantLauncher`]: everything the child
/// `kirby agent` needs that is NOT already in the base config. The launcher turns this into
/// a running child (real impl) or an in-memory tracked process (stub impl). The base config
/// + these per-tenant overrides fully determine the child.
#[derive(Debug, Clone)]
pub struct TenantLaunchSpec {
    /// The tenant's agent id (the lease key, the treasury/instance label).
    pub agent_id: AgentId,
    /// The allocated CID / instance_id / gateway_port for this tenant.
    pub allocation: TenantAllocation,
    /// The per-agent treasury path (the child's `node_id`-derived sled dir).
    pub treasury_path: PathBuf,
    /// This tenant's initial treasury balance (play-money, seeded on first create).
    pub initial_sats: u64,
}

/// A handle to a launched tenant, the lifecycle the supervisor monitors. Object-safe so the
/// real (child-process) and stub (in-memory) impls share one supervisor. The supervisor only
/// ever observes RUNNING vs EXITED and can KILL; the dead-detection is the failover hook.
pub trait TenantProcess: Send + Sync {
    /// Whether the tenant is still running. The real impl polls the child's exit status
    /// without blocking; the stub returns its tracked state. A tenant that has exited
    /// (crashed or finished) reports false, which is exactly the death the supervisor must
    /// detect for failover (S5/S6) to later act on.
    fn is_running(&self) -> bool;

    /// Kill the tenant (the supervisor reaping it, or a test forcing a death). Idempotent:
    /// killing an already-dead tenant is a no-op. After this, `is_running` reports false.
    fn kill(&self);
}

/// The child-launch seam (the testability boundary): given a [`TenantLaunchSpec`], produce a
/// running [`TenantProcess`]. The real impl spawns `kirby agent`; a test supplies a stub so
/// the supervisor's allocation / lifecycle / lease-grant logic is exercised with NO VM or
/// process (non-gated). `Send + Sync` so the supervisor can hold it across tasks.
pub trait TenantLauncher: Send + Sync {
    /// Launch one tenant. On success the tenant is RUNNING under the returned handle. An
    /// error (e.g. the binary is missing) aborts THIS tenant's launch; the supervisor
    /// releases the tenant's allocation so a failed launch leaks no slot.
    fn launch(&self, spec: &TenantLaunchSpec) -> anyhow::Result<Box<dyn TenantProcess>>;
}

/// The lease-grant seam: grant `{agent_id, self_node}` for a tenant and return the committed
/// term. Implemented over the Raft [`crate::raft_lease::LeaseNode`] (the supervisor is a
/// voter/leader in the agents' cluster); a per-agent FROST-quorum lease impl drops in here
/// later. Async because a real grant awaits a Raft commit. Kept SEPARATE from
/// [`crate::raft_lease::LeaseAuthority`] (the read-only fence seam) because granting is
/// impl-specific and write-side, while the fence is read-only.
#[async_trait::async_trait]
pub trait LeaseGrantor: Send + Sync {
    /// Grant `agent_id`'s lease to this node and return the committed lease (node + term).
    /// Only touches this agent's lease entry (per-agent isolation, S1).
    async fn grant_for(&self, agent_id: &str, node_id: LeaseNodeId) -> anyhow::Result<LeaseResponse>;
}

#[async_trait::async_trait]
impl LeaseGrantor for crate::raft_lease::LeaseNode {
    async fn grant_for(&self, agent_id: &str, node_id: LeaseNodeId) -> anyhow::Result<LeaseResponse> {
        self.grant_lease_for(agent_id, node_id).await
    }
}

/// The fleet supervisor itself (fleet-host S2). Owns the resource allocator, the base config
/// (each tenant's child is the base config with per-tenant overrides), this node's lease id,
/// the lease grantor, the tenant launcher, and the live tenant set it monitors.
pub struct FleetSupervisor {
    /// This node's lease id (the supervisor grants tenants' leases to itself).
    node_id: LeaseNodeId,
    /// The base config every tenant child inherits (relay, brain, image, etc.).
    base_config: KirbyConfig,
    /// The S0 resource allocator (distinct CID / instance_id / gateway_port per tenant).
    allocator: Allocator,
    /// The per-agent lease grantor (Raft node, or a swapped impl).
    grantor: Arc<dyn LeaseGrantor>,
    /// The child-launch seam (real process launcher, or a test stub).
    launcher: Arc<dyn TenantLauncher>,
    /// The live tenant set, keyed by agent id: the running handle + its record. The
    /// supervisor monitors these for death (the failover hook, S5/S6).
    tenants: BTreeMap<AgentId, LiveTenant>,
}

/// One live tenant the supervisor monitors: the lifecycle handle + the record of how it was
/// allocated/granted (so a test and the operator can inspect it, and so a reap releases the
/// right allocation).
struct LiveTenant {
    process: Box<dyn TenantProcess>,
    record: TenantRecord,
}

/// The status of a tenant the supervisor tracks: RUNNING, or EXITED (the dead-tenant
/// detection the failover supervisor S5/S6 acts on; S2 only reports it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// The tenant child is alive.
    Running,
    /// The tenant child has exited (crashed or finished). This is the failover trigger.
    Exited,
}

impl FleetSupervisor {
    /// Build a supervisor over a base config, this node's lease id, a lease grantor, and a
    /// tenant launcher. The allocator is in-memory (a long-lived supervisor uses
    /// [`Allocator::load_or_new`] for restart-safe CIDs; this constructor takes the
    /// allocator so the caller chooses persistence). No tenant is launched yet.
    pub fn new(
        node_id: LeaseNodeId,
        base_config: KirbyConfig,
        allocator: Allocator,
        grantor: Arc<dyn LeaseGrantor>,
        launcher: Arc<dyn TenantLauncher>,
    ) -> Self {
        FleetSupervisor {
            node_id,
            base_config,
            allocator,
            grantor,
            launcher,
            tenants: BTreeMap::new(),
        }
    }

    /// Launch every STATIC tenant declared in `[fleet]` (spec slice S2). For each tenant, in
    /// declaration order: allocate the resource triple, derive the per-agent treasury path,
    /// grant the per-agent lease at the current term, and launch the child.
    ///
    /// ALL-OR-NOTHING: on ANY per-tenant failure (allocation exhausted, grant fails, launch
    /// fails) every tenant ALREADY launched in this batch is KILLED and REAPED (its OS child
    /// process is signalled + reaped and its allocator slot released) before the error is
    /// returned. Dropping a `std::process::Child` does NOT kill the OS process, so an explicit
    /// kill is required; without it a partial batch would leak orphaned children AND leak
    /// allocator slots. The supervisor never silently hosts a partial fleet, and a failed batch
    /// leaves it with no tracked tenants. Returns the records of the launched tenants on full
    /// success.
    pub async fn launch_all(&mut self) -> anyhow::Result<Vec<TenantRecord>> {
        let tenants = self.base_config.fleet.tenants.clone();
        let mut records = Vec::with_capacity(tenants.len());
        for tenant in &tenants {
            match self.launch_one(tenant).await {
                Ok(record) => records.push(record),
                Err(e) => {
                    // A mid-batch failure must not leak the tenants already launched in this
                    // batch: kill their OS children (a dropped `Child` keeps running) and
                    // release their allocator slots before surfacing the error.
                    self.kill_and_reap_all();
                    return Err(e);
                }
            }
        }
        Ok(records)
    }

    /// Kill + reap EVERY tracked tenant: signal each child dead, reap it (release its allocator
    /// slot), and clear the live set. Used to roll back a partially-launched batch in
    /// `launch_all` so a failed batch leaves no orphaned child process and no leaked allocator
    /// slot. Idempotent on an empty set.
    fn kill_and_reap_all(&mut self) {
        let ids: Vec<AgentId> = self.tenants.keys().cloned().collect();
        for id in ids {
            if let Some(live) = self.tenants.remove(&id) {
                // Kill the OS child first (a dropped `Child` does NOT terminate the process),
                // then release the allocator slot so no CID/port is leaked.
                live.process.kill();
                self.allocator.release(&id);
            }
        }
    }

    /// Launch ONE tenant: allocate -> derive treasury path -> grant lease -> launch child ->
    /// track. Releases the allocation on any later failure so no slot leaks. Public so a test
    /// (and a later spawn control-plane) can launch a single tenant; `launch_all` calls it.
    pub async fn launch_one(&mut self, tenant: &TenantConfig) -> anyhow::Result<TenantRecord> {
        // (1) Allocate the distinct resource triple (S0). At-most-once per agent; the
        // allocator rejects a duplicate or an over-cap request without consuming a slot.
        let allocation = match self.allocator.allocate(&tenant.agent_id) {
            Ok(a) => a,
            Err(AllocError::AlreadyAllocated { agent_id }) => {
                anyhow::bail!(
                    "fleet supervisor: tenant {agent_id:?} is already allocated (a tenant is launched at most once)"
                );
            }
            Err(e) => return Err(e.into()),
        };

        // From here on, a failure must RELEASE the allocation so no CID/port slot leaks.
        let result = self.provision_and_launch(tenant, &allocation).await;
        match result {
            Ok(record) => Ok(record),
            Err(e) => {
                self.allocator.release(&tenant.agent_id);
                Err(e)
            }
        }
    }

    /// The fallible middle of a launch (split out so `launch_one` can release the allocation
    /// on failure): derive the treasury path, grant the lease, launch the child, and record
    /// the live tenant.
    async fn provision_and_launch(
        &mut self,
        tenant: &TenantConfig,
        allocation: &TenantAllocation,
    ) -> anyhow::Result<TenantRecord> {
        // (2) Per-agent treasury path (DB-per-agent, spec 2.1): each tenant takes its OWN
        // sled exclusive dir lock, so opening tenant A's treasury never blocks on B's
        // (G-TENANT-ISOLATION). The child's `kirby agent` keys its treasury off node_id, and
        // the derived child config sets node_id = instance_id (distinct per tenant). The
        // recorded path MUST be the path the child actually opens, so derive it from the
        // child's node_id (= instance_id) via `treasury_path_for`, NOT from the agent_id via
        // `treasury_path_for_agent` (a path the child never opens). Isolation still holds: the
        // instance_id is distinct per tenant, so the per-tenant paths are distinct.
        let treasury_path = crate::boot::treasury_path_for(&allocation.instance_id);

        // (3) Grant the per-agent lease to THIS node at the current term (S1). Touches only
        // this agent's entry, so granting tenant A never perturbs tenant B's lease.
        let granted = self
            .grantor
            .grant_for(&tenant.agent_id, self.node_id)
            .await
            .map_err(|e| anyhow::anyhow!("fleet supervisor: grant lease for tenant {:?}: {e}", tenant.agent_id))?;

        // (4) Launch the child running the existing single-agent path with the allocated
        // resources. Behind the TenantLauncher seam: the real impl spawns `kirby agent`; a
        // test supplies a stub. The launch carries the CID/port the child must bind.
        let spec = TenantLaunchSpec {
            agent_id: tenant.agent_id.clone(),
            allocation: allocation.clone(),
            treasury_path: treasury_path.clone(),
            initial_sats: tenant.initial_sats,
        };
        let process = self
            .launcher
            .launch(&spec)
            .map_err(|e| anyhow::anyhow!("fleet supervisor: launch tenant {:?}: {e}", tenant.agent_id))?;

        // (5) Track the live tenant for lifecycle monitoring (the failover hook, S5/S6).
        let record = TenantRecord {
            agent_id: tenant.agent_id.clone(),
            allocation: allocation.clone(),
            treasury_path,
            lease_term: granted.term,
        };
        self.tenants.insert(
            tenant.agent_id.clone(),
            LiveTenant { process, record: record.clone() },
        );
        Ok(record)
    }

    /// The number of tenants the supervisor is currently tracking (launched, not yet reaped).
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// The status of a tracked tenant (RUNNING vs EXITED), or `None` if not tracked. This is
    /// the dead-tenant detector: a tenant whose child has exited reports `Exited`, which the
    /// failover supervisor (S5/S6) will act on. S2 only TRACKS it.
    pub fn tenant_status(&self, agent_id: &str) -> Option<TenantStatus> {
        self.tenants.get(agent_id).map(|t| {
            if t.process.is_running() {
                TenantStatus::Running
            } else {
                TenantStatus::Exited
            }
        })
    }

    /// The record for a tracked tenant (its allocation + treasury path + lease term), or
    /// `None` if not tracked.
    pub fn tenant_record(&self, agent_id: &str) -> Option<&TenantRecord> {
        self.tenants.get(agent_id).map(|t| &t.record)
    }

    /// The agent ids of every EXITED tenant (the dead set the failover supervisor S5/S6 acts
    /// on). S2 surfaces it; it does not yet re-grant or restart.
    pub fn dead_tenants(&self) -> Vec<AgentId> {
        self.tenants
            .iter()
            .filter(|(_, t)| !t.process.is_running())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Reap a dead tenant: drop its lifecycle handle and RELEASE its allocation so the CID/
    /// port slot is reusable. Refuses to reap a still-running tenant (the caller must kill it
    /// first). Returns the reaped record. This is the cleanup half of lifecycle monitoring;
    /// failover (re-grant + relaunch elsewhere) is S5/S6.
    pub fn reap(&mut self, agent_id: &str) -> anyhow::Result<TenantRecord> {
        let Some(live) = self.tenants.get(agent_id) else {
            anyhow::bail!("fleet supervisor: cannot reap unknown tenant {agent_id:?}");
        };
        if live.process.is_running() {
            anyhow::bail!(
                "fleet supervisor: refusing to reap tenant {agent_id:?} while it is still RUNNING (kill it first)"
            );
        }
        let live = self.tenants.remove(agent_id).expect("checked present");
        self.allocator.release(agent_id);
        Ok(live.record)
    }

    /// Reap EVERY exited tenant: for each tracked tenant whose child has died, drop its handle
    /// and RELEASE its allocator slot, returning the reaped records. This is the supervisor's
    /// shutdown/restart-safety cleanup: without it, the persisted allocator keeps a slot marked
    /// LIVE for a dead CID/port, which would survive a supervisor restart and never be re-handed
    /// (a leaked slot). Still-running tenants are left untouched. Idempotent (no dead tenants =>
    /// empty result).
    pub fn reap_dead(&mut self) -> Vec<TenantRecord> {
        let dead: Vec<AgentId> = self
            .tenants
            .iter()
            .filter(|(_, t)| !t.process.is_running())
            .map(|(id, _)| id.clone())
            .collect();
        let mut reaped = Vec::with_capacity(dead.len());
        for id in dead {
            if let Some(live) = self.tenants.remove(&id) {
                self.allocator.release(&id);
                reaped.push(live.record);
            }
        }
        reaped
    }

    /// Kill a tracked tenant (force a death), for an operator stop or a test. Idempotent on
    /// an already-dead tenant. Does NOT reap (the slot stays held until `reap`), so the
    /// dead-tenant detector still reports it as `Exited` for the failover hook.
    pub fn kill(&self, agent_id: &str) {
        if let Some(live) = self.tenants.get(agent_id) {
            live.process.kill();
        }
    }
}

/// The REAL tenant launcher (fleet-host S2): spawns each tenant as a child `kirby agent`
/// process running the existing single-agent path, with the allocated CID/port handed in via
/// the `KIRBY_GUEST_CID` / `KIRBY_GATEWAY_PORT` env vars (honored by
/// `RunAgentConfig::from_config`; absent for every non-fleet run, so the single-agent path is
/// unchanged). It writes a DERIVED per-tenant `kirby.toml` (the base config with the tenant's
/// agent_id, a per-tenant node_id = instance_id so the child's treasury is DB-per-agent, and
/// the tenant's initial_sats) to a per-tenant config dir, then spawns the binary against it.
///
/// This path boots a REAL VM (via the child's `kirby agent`), so it is exercised only by the
/// `KIRBY_GENOME_IMAGE`-gated G-N-TENANTS gate; the non-gated gates use a stub launcher.
pub struct ProcessTenantLauncher {
    /// The base config each tenant child inherits (serialized + per-tenant overrides applied).
    base_config: KirbyConfig,
    /// The `kirby` binary to spawn (the current exe by default).
    binary: PathBuf,
    /// The dir derived per-tenant config files are written under.
    config_dir: PathBuf,
}

impl ProcessTenantLauncher {
    /// Build the real launcher. `binary` is the `kirby` executable to spawn (typically
    /// `std::env::current_exe()`); `config_dir` is where derived per-tenant configs are
    /// written.
    pub fn new(base_config: KirbyConfig, binary: PathBuf, config_dir: PathBuf) -> Self {
        ProcessTenantLauncher { base_config, binary, config_dir }
    }

    /// Derive the per-tenant config TOML: the base config with the tenant's `agent_id`, a
    /// per-tenant `node_id` set to the instance id (so the child's per-node treasury path is
    /// DB-per-agent, distinct from every other tenant), and the tenant's initial funding. The
    /// `[fleet]` block is cleared on the child so a tenant child never recursively starts its
    /// own supervisor.
    fn derive_tenant_config(&self, spec: &TenantLaunchSpec) -> KirbyConfig {
        let mut cfg = self.base_config.clone();
        cfg.agent_id = spec.agent_id.clone();
        // The child keys its treasury off node_id; set it to the unique instance id so each
        // tenant takes its OWN sled lock (DB-per-agent isolation, spec 2.1).
        cfg.node_id = spec.allocation.instance_id.clone();
        cfg.funding.initial_sats = spec.initial_sats;
        // A tenant child is a plain single-agent `kirby agent`; it must NOT inherit the fleet
        // tenant list (no recursive fleets).
        cfg.fleet = crate::config::FleetConfig::default();
        cfg
    }
}

impl TenantLauncher for ProcessTenantLauncher {
    fn launch(&self, spec: &TenantLaunchSpec) -> anyhow::Result<Box<dyn TenantProcess>> {
        use std::process::Command;

        let cfg = self.derive_tenant_config(spec);
        let toml = toml::to_string_pretty(&cfg)
            .map_err(|e| anyhow::anyhow!("serialize tenant {:?} config: {e}", spec.agent_id))?;
        std::fs::create_dir_all(&self.config_dir).map_err(|e| {
            anyhow::anyhow!("create tenant config dir {}: {e}", self.config_dir.display())
        })?;
        let config_path = self.config_dir.join(format!("tenant-{}.toml", spec.agent_id));
        std::fs::write(&config_path, toml)
            .map_err(|e| anyhow::anyhow!("write tenant config {}: {e}", config_path.display()))?;

        // Spawn `kirby agent --config <derived>` with the allocated CID/port in the env. The
        // child runs the EXISTING single-agent path verbatim; the supervisor adds nothing to
        // the hot path (spec 2.1: a tenant IS a `kirby run` with allocated resources).
        let child = Command::new(&self.binary)
            .arg("agent")
            .arg("--config")
            .arg(&config_path)
            .env("KIRBY_GUEST_CID", spec.allocation.guest_cid.to_string())
            .env("KIRBY_GATEWAY_PORT", spec.allocation.gateway_port.to_string())
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!("spawn `kirby agent` for tenant {:?}: {e}", spec.agent_id)
            })?;
        Ok(Box::new(ChildTenant { child: std::sync::Mutex::new(child) }))
    }
}

/// A real child-process tenant (the [`ProcessTenantLauncher`] output). Wraps the spawned
/// `kirby agent` child; `is_running` polls its exit status without blocking, `kill` signals
/// it. The `Mutex` makes it `Send + Sync` for the supervisor to hold across tasks.
struct ChildTenant {
    child: std::sync::Mutex<std::process::Child>,
}

impl TenantProcess for ChildTenant {
    fn is_running(&self) -> bool {
        let mut guard = self.child.lock().expect("child mutex");
        // `try_wait` returns Ok(None) while the child is still running, Ok(Some(_)) once it
        // has exited (the death the supervisor detects), Err on a wait fault (treat as dead).
        matches!(guard.try_wait(), Ok(None))
    }

    fn kill(&self) {
        let mut guard = self.child.lock().expect("child mutex");
        // Best-effort: a child that already exited returns an error from kill, which we
        // ignore (kill is idempotent from the supervisor's view).
        let _ = guard.kill();
        let _ = guard.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A stub tenant process: in-memory RUNNING/EXITED state, no real process. Lets the
    /// supervisor's allocation / lifecycle / lease-grant logic run with NO VM (non-gated).
    struct StubTenant {
        running: Arc<AtomicBool>,
    }

    impl TenantProcess for StubTenant {
        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
        fn kill(&self) {
            self.running.store(false, Ordering::SeqCst);
        }
    }

    /// A stub launcher: records every launch spec and hands back a controllable StubTenant.
    /// A shared `kill_switch` per agent lets a test force a tenant death deterministically.
    /// `fail_on` names a tenant whose launch returns an error, modeling a mid-batch failure.
    #[derive(Default)]
    struct StubLauncher {
        launched: std::sync::Mutex<Vec<TenantLaunchSpec>>,
        switches: std::sync::Mutex<BTreeMap<AgentId, Arc<AtomicBool>>>,
        fail_on: std::sync::Mutex<Option<AgentId>>,
    }

    impl StubLauncher {
        fn running_flag(&self, agent_id: &str) -> Arc<AtomicBool> {
            self.switches.lock().unwrap().get(agent_id).cloned().expect("agent launched")
        }

        /// The running flag for an agent IF it was ever launched (so a test can prove a
        /// rolled-back tenant's child was killed). `None` if it was never launched.
        fn maybe_running_flag(&self, agent_id: &str) -> Option<Arc<AtomicBool>> {
            self.switches.lock().unwrap().get(agent_id).cloned()
        }

        fn set_fail_on(&self, agent_id: &str) {
            *self.fail_on.lock().unwrap() = Some(agent_id.to_string());
        }
    }

    impl TenantLauncher for StubLauncher {
        fn launch(&self, spec: &TenantLaunchSpec) -> anyhow::Result<Box<dyn TenantProcess>> {
            if self.fail_on.lock().unwrap().as_deref() == Some(spec.agent_id.as_str()) {
                anyhow::bail!("stub launcher: forced launch failure for {:?}", spec.agent_id);
            }
            let running = Arc::new(AtomicBool::new(true));
            self.switches.lock().unwrap().insert(spec.agent_id.clone(), running.clone());
            self.launched.lock().unwrap().push(spec.clone());
            Ok(Box::new(StubTenant { running }))
        }
    }

    /// A stub grantor: records every (agent_id, node_id) grant and stamps an increasing term
    /// PER agent, so a test can assert per-agent independence without a live Raft cluster.
    #[derive(Default)]
    struct StubGrantor {
        grants: std::sync::Mutex<Vec<(AgentId, LeaseNodeId)>>,
        next_term: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl LeaseGrantor for StubGrantor {
        async fn grant_for(&self, agent_id: &str, node_id: LeaseNodeId) -> anyhow::Result<LeaseResponse> {
            self.grants.lock().unwrap().push((agent_id.to_string(), node_id));
            let term = self.next_term.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(LeaseResponse { node_id, term })
        }
    }

    fn base_config_with_tenants(tenants: Vec<TenantConfig>) -> KirbyConfig {
        let toml = r#"
            genome_image = { path = "/tmp/kirby/genome-image" }
            [identity]
            key_path = "/tmp/kirby/node.nostr.key"
            [relay]
            url = "ws://127.0.0.1:7777"
        "#;
        let mut cfg = KirbyConfig::from_toml_str(toml).expect("base config");
        cfg.fleet.tenants = tenants;
        cfg
    }

    fn tenant(agent_id: &str, sats: u64) -> TenantConfig {
        TenantConfig { agent_id: agent_id.to_string(), initial_sats: sats }
    }

    /// The supervisor allocates a DISTINCT resource triple per tenant, grants each its OWN
    /// per-agent lease, and launches each child with the allocated CID/port. TEETH: no two
    /// tenants share a CID/port; each gets its own treasury path; each gets a distinct lease
    /// grant (per-agent independence).
    #[tokio::test]
    async fn launches_n_tenants_with_distinct_resources_and_per_agent_grants() {
        let cfg = base_config_with_tenants(vec![
            tenant("alice", 500_000),
            tenant("bob", 700_000),
            tenant("carol", 900_000),
        ]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());
        let mut sup = FleetSupervisor::new(1, cfg, allocator, grantor.clone(), launcher.clone());

        let records = sup.launch_all().await.expect("launch all tenants");
        assert_eq!(records.len(), 3);
        assert_eq!(sup.tenant_count(), 3);

        // Distinct CID / port / instance_id / treasury path across tenants.
        let mut cids = std::collections::BTreeSet::new();
        let mut ports = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for r in &records {
            assert!(r.allocation.guest_cid > 2, "CID must clear the vsock-reserved range");
            assert!(cids.insert(r.allocation.guest_cid), "duplicate CID across tenants");
            assert!(ports.insert(r.allocation.gateway_port), "duplicate port across tenants");
            assert!(paths.insert(r.treasury_path.clone()), "two tenants share a treasury path");
            assert_eq!(r.allocation.instance_id, format!("kirby-{}", r.agent_id));
            // G-TENANT-ISOLATION: the recorded treasury path MUST be the path the child
            // actually opens. The child sets node_id = instance_id and opens
            // `treasury_path_for(node_id)`, so the record must match that, NOT
            // `treasury_path_for_agent(agent_id)` (a path no child ever opens).
            assert_eq!(
                r.treasury_path,
                crate::boot::treasury_path_for(&r.allocation.instance_id),
                "recorded treasury path must be the child's real (instance_id-derived) path"
            );
        }

        // Each tenant got its OWN per-agent lease grant to this node (per-agent, S1).
        let grants = grantor.grants.lock().unwrap().clone();
        assert_eq!(grants.len(), 3, "one grant per tenant");
        for (agent_id, node_id) in &grants {
            assert_eq!(*node_id, 1, "the supervisor grants each tenant's lease to itself");
            assert!(["alice", "bob", "carol"].contains(&agent_id.as_str()));
        }

        // The launcher saw each tenant's allocated CID/port + initial_sats.
        let launched = launcher.launched.lock().unwrap().clone();
        assert_eq!(launched.len(), 3);
        let alice = launched.iter().find(|s| s.agent_id == "alice").unwrap();
        assert_eq!(alice.initial_sats, 500_000);

        // All three report RUNNING; none dead yet.
        for id in ["alice", "bob", "carol"] {
            assert_eq!(sup.tenant_status(id), Some(TenantStatus::Running));
        }
        assert!(sup.dead_tenants().is_empty());
    }

    /// Killing ONE tenant does not disturb another: the killed tenant reports EXITED and is
    /// the only dead one; the others stay RUNNING. This is the crash-isolation property
    /// (process-per-tenant) at the supervisor-tracking level (the VM-level isolation is the
    /// gated G-N-TENANTS gate).
    #[tokio::test]
    async fn killing_one_tenant_does_not_disturb_another() {
        let cfg = base_config_with_tenants(vec![tenant("alice", 1_000_000), tenant("bob", 1_000_000)]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());
        let mut sup = FleetSupervisor::new(1, cfg, allocator, grantor, launcher.clone());
        sup.launch_all().await.expect("launch all");

        // Kill alice via the launcher's switch (modeling a child crash).
        launcher.running_flag("alice").store(false, Ordering::SeqCst);

        assert_eq!(sup.tenant_status("alice"), Some(TenantStatus::Exited), "alice must read EXITED");
        assert_eq!(sup.tenant_status("bob"), Some(TenantStatus::Running), "bob must be undisturbed by alice's death");
        assert_eq!(sup.dead_tenants(), vec!["alice".to_string()], "only alice is dead");

        // Reaping the dead tenant frees its slot (and only its slot); bob is untouched.
        let reaped = sup.reap("alice").expect("reap dead alice");
        assert_eq!(reaped.agent_id, "alice");
        assert_eq!(sup.tenant_count(), 1);
        assert_eq!(sup.tenant_status("bob"), Some(TenantStatus::Running));
        // Refusing to reap a live tenant.
        let err = sup.reap("bob").unwrap_err();
        assert!(err.to_string().contains("still RUNNING"));
    }

    /// A launch that fails partway (the grantor errors) RELEASES the tenant's allocation, so
    /// a failed launch leaks no CID/port slot. TEETH: after the failure the freed slot is
    /// reusable and the tenant is not tracked.
    #[tokio::test]
    async fn failed_launch_releases_the_allocation() {
        struct FailingGrantor;
        #[async_trait::async_trait]
        impl LeaseGrantor for FailingGrantor {
            async fn grant_for(&self, _agent_id: &str, _node_id: LeaseNodeId) -> anyhow::Result<LeaseResponse> {
                anyhow::bail!("grant refused (not leader)")
            }
        }
        let cfg = base_config_with_tenants(vec![tenant("alice", 1_000_000)]);
        let allocator = Allocator::new(&cfg.fleet);
        let launcher = Arc::new(StubLauncher::default());
        let mut sup = FleetSupervisor::new(1, cfg, allocator, Arc::new(FailingGrantor), launcher.clone());

        let err = sup.launch_one(&tenant("alice", 1_000_000)).await.unwrap_err();
        assert!(err.to_string().contains("grant lease"), "the grant failure surfaces: {err}");
        // The allocation was released: nothing is tracked, and nothing was launched.
        assert_eq!(sup.tenant_count(), 0);
        assert!(launcher.launched.lock().unwrap().is_empty(), "a failed grant must not launch a child");
        // The freed slot is reusable: a fresh launch (with a working grantor) succeeds.
        let mut sup2 = {
            let cfg = base_config_with_tenants(vec![]);
            let allocator = Allocator::new(&cfg.fleet);
            FleetSupervisor::new(1, cfg, allocator, Arc::new(StubGrantor::default()), launcher.clone())
        };
        sup2.launch_one(&tenant("alice", 1_000_000)).await.expect("relaunch after release");
        assert_eq!(sup2.tenant_count(), 1);
    }

    /// A MID-BATCH launch failure rolls back the WHOLE batch: every tenant already launched is
    /// KILLED (its child terminated, not merely dropped) and REAPED (its allocator slot freed),
    /// so the failed batch leaves no orphaned child and no leaked slot. TEETH: after the
    /// failure the already-launched tenants' kill-switches read false (killed), nothing is
    /// tracked, the allocator is empty, and every freed CID is reusable by a fresh batch.
    #[tokio::test]
    async fn mid_batch_launch_failure_kills_and_releases_already_launched_tenants() {
        let cfg = base_config_with_tenants(vec![
            tenant("alice", 1_000_000),
            tenant("bob", 1_000_000),
            tenant("carol", 1_000_000), // carol's launch fails, after alice + bob are up
        ]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());
        launcher.set_fail_on("carol");
        let mut sup = FleetSupervisor::new(1, cfg, allocator, grantor, launcher.clone());

        let err = sup.launch_all().await.unwrap_err();
        assert!(
            err.to_string().contains("forced launch failure"),
            "the mid-batch failure surfaces: {err}"
        );

        // The whole batch was rolled back: nothing is tracked.
        assert_eq!(sup.tenant_count(), 0, "a failed batch must track no tenants");

        // The already-launched tenants' OS children were KILLED (a dropped Child keeps
        // running; the supervisor must signal them). Their kill-switches read false.
        for id in ["alice", "bob"] {
            let flag = launcher.maybe_running_flag(id).expect("alice/bob were launched");
            assert!(
                !flag.load(Ordering::SeqCst),
                "{id}'s child must be killed on a rolled-back batch (no orphan)"
            );
        }
        // carol's launch failed, so carol was never launched.
        assert!(launcher.maybe_running_flag("carol").is_none(), "carol never launched");

        // Their allocator slots were RELEASED: a fresh full batch succeeds (no leaked slot,
        // and the freed CIDs are reusable).
        let cfg2 = base_config_with_tenants(vec![tenant("alice", 1), tenant("bob", 1)]);
        let allocator2 = Allocator::new(&cfg2.fleet);
        let mut sup2 = FleetSupervisor::new(
            1,
            cfg2,
            allocator2,
            Arc::new(StubGrantor::default()),
            Arc::new(StubLauncher::default()),
        );
        let records = sup2.launch_all().await.expect("a clean batch after a failed one");
        assert_eq!(records.len(), 2);
    }

    /// `reap_dead` releases the allocator slot for EVERY exited tenant (the supervisor's
    /// shutdown/restart-safety cleanup) and leaves running tenants alone. TEETH: after a
    /// tenant dies and is reaped, its slot is reusable; a still-running tenant is untouched.
    #[tokio::test]
    async fn reap_dead_releases_exited_tenant_slots_only() {
        let cfg = base_config_with_tenants(vec![tenant("alice", 1), tenant("bob", 1)]);
        let allocator = Allocator::new(&cfg.fleet);
        let launcher = Arc::new(StubLauncher::default());
        let mut sup = FleetSupervisor::new(
            1,
            cfg,
            allocator,
            Arc::new(StubGrantor::default()),
            launcher.clone(),
        );
        sup.launch_all().await.expect("launch all");

        // alice dies; bob stays up.
        launcher.running_flag("alice").store(false, Ordering::SeqCst);

        let reaped = sup.reap_dead();
        assert_eq!(reaped.len(), 1, "exactly the one dead tenant is reaped");
        assert_eq!(reaped[0].agent_id, "alice");
        assert_eq!(sup.tenant_count(), 1, "bob is still tracked");
        assert_eq!(sup.tenant_status("bob"), Some(TenantStatus::Running), "bob untouched");
        assert!(sup.tenant_status("alice").is_none(), "alice was reaped");

        // A second reap with no dead tenants is a no-op.
        assert!(sup.reap_dead().is_empty(), "no dead tenants => empty reap");
    }

    /// The real launcher derives a per-tenant child config that is DB-per-agent isolated: the
    /// child's node_id is the unique instance id (so its treasury path differs per tenant),
    /// its agent_id + funding are the tenant's, and the `[fleet]` block is cleared (no
    /// recursive fleets). This pins the derivation without spawning a real process.
    #[test]
    fn real_launcher_derives_isolated_per_tenant_config() {
        let base = base_config_with_tenants(vec![]);
        let launcher = ProcessTenantLauncher::new(
            base,
            PathBuf::from("/nonexistent/kirby"),
            std::env::temp_dir().join("kirby-fleet-test-cfgs"),
        );
        let alloc_a = TenantAllocation {
            agent_id: "alice".into(),
            guest_cid: 100,
            instance_id: "kirby-alice".into(),
            gateway_port: 9000,
        };
        let alloc_b = TenantAllocation {
            agent_id: "bob".into(),
            guest_cid: 101,
            instance_id: "kirby-bob".into(),
            gateway_port: 9001,
        };
        let spec_a = TenantLaunchSpec {
            agent_id: "alice".into(),
            allocation: alloc_a,
            treasury_path: crate::boot::treasury_path_for_agent("alice"),
            initial_sats: 333_000,
        };
        let cfg_a = launcher.derive_tenant_config(&spec_a);
        assert_eq!(cfg_a.agent_id, "alice");
        assert_eq!(cfg_a.node_id, "kirby-alice", "child node_id = instance id (DB-per-agent treasury)");
        assert_eq!(cfg_a.funding.initial_sats, 333_000);
        assert!(cfg_a.fleet.tenants.is_empty(), "the child must not inherit the tenant list");

        // Two tenants derive DISTINCT node_ids => distinct treasury paths (the isolation
        // property the DB-per-agent design guarantees, G-TENANT-ISOLATION).
        let spec_b = TenantLaunchSpec {
            agent_id: "bob".into(),
            allocation: alloc_b,
            treasury_path: crate::boot::treasury_path_for_agent("bob"),
            initial_sats: 333_000,
        };
        let cfg_b = launcher.derive_tenant_config(&spec_b);
        assert_ne!(cfg_a.node_id, cfg_b.node_id, "two tenants must derive distinct node_ids");
        assert_ne!(
            crate::boot::treasury_path_for(&cfg_a.node_id),
            crate::boot::treasury_path_for(&cfg_b.node_id),
            "two tenants must get distinct treasury paths"
        );
    }
}
