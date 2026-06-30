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
//! THE LEASE SEAM: the supervisor CLAIMS per-agent leases through a [`LeaseGrantor`] (a tiny
//! write-side trait; the relay-native impl FROST-signs a lease and publishes it to the relay,
//! [`crate::relay_lease::RelayLeaseGrantor`]); the gateway debit fence is read through the
//! [`crate::lease::LeaseAuthority`] trait, so the relay-native lease drops in behind both
//! without touching the supervisor.
//!
//! KNOWN DEFERRAL (S2, deliberate, in line with the roadmap): the supervisor CLAIMS each
//! tenant its per-agent lease (term 1 on launch), but the tenant CHILD PROCESS does NOT yet
//! enforce it -- the child boots with no lease fence (`BootConfig.lease_fence = None`),
//! because the lease lives in THIS supervisor process and the child is a separate process.
//! Enforcing it would need a RemoteLeaseAuthority (the child querying this supervisor over IPC
//! before each debit). That is intentionally NOT built here: the lease only becomes
//! load-bearing when a SECOND node can contend for a tenant's agent (failover, S5/S6), and in
//! S2 (single host, static config, no failover) nothing else runs a tenant's agent, so the
//! unfenced child is not exploitable. The failover-detection loop that claims `term + 1` on a
//! takeover is a later chunk. S2 delivers multi-tenant RESOURCE isolation (own VM / CID /
//! treasury per tenant), which IS enforced and tested.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{KirbyConfig, TenantConfig};
use crate::fleet::{AgentId, AllocError, Allocator, TenantAllocation};
use crate::lease::{LeaseNodeId, LeaseResponse};

/// Default settle window for the READ-AFTER-WRITE LAUNCH FENCE (failover finding G-1): how long
/// to let a competing peer's claim PROPAGATE to the relay after our own claim publishes, before
/// the re-read that confirms which survivor won. ~2s is comfortably above a single relay round-trip
/// yet far inside the 30s lease TTL, so a takeover that pauses here to confirm never re-stales the
/// lease it just claimed. Applied only when a [`crate::relay_lease::LeaseReader`] is attached.
pub const DEFAULT_LAUNCH_CONFIRM_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

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
    /// The tenant's per-agent FROST keystore dir (S3d): where its 3 holder shares +
    /// group pubkeys live (0600), beside its treasury. Keyed by `instance_id`.
    pub keystore_dir: PathBuf,
    /// The tenant's SOVEREIGN identity (S3d): the npub of its per-agent FROST group key Q.
    /// Durable across restarts (idempotent provisioning yields the same Q). For a FROST
    /// tenant, Q signs everything; this is the followable public identity.
    pub frost_npub: String,
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
    /// FIX 3 (FROST-tenant wiring): the per-agent FROST keystore dir the supervisor
    /// provisioned for this tenant (its sovereign 2-of-3 Q). Threaded into the child via
    /// `derive_tenant_config` -> `identity.frost_keystore_dir`, so the launched tenant's voice
    /// signs with its OWN Q (the FROST branch in `build_nostr_actuator`), not the node key.
    pub frost_keystore_dir: PathBuf,
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

    /// The OS PID of the tenant's process, if known. The real child-process tenant
    /// ([`ChildTenant`]) returns its spawned child's PID so the supervisor can PERSIST it (the
    /// re-adopt/reap sidecar, [`crate::fleet_reconcile::LaunchRegistry`]) and find the orphan
    /// PID-reuse-safe after a supervisor restart. A re-adopted supervise-by-PID tenant
    /// ([`crate::fleet_reconcile::PidTenant`]) returns the PID it tracks. A pure in-memory stub
    /// returns `None` (it has no OS process). Default `None` so impls that have no PID need not
    /// override it.
    fn pid(&self) -> Option<u32> {
        None
    }
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

/// The lease-grant (CLAIM) seam: claim `{agent_id, self_node}` for a tenant and return the
/// claimed lease (node + term). Implemented over the relay-native FROST-signed lease
/// ([`crate::relay_lease::RelayLeaseGrantor`]): the supervisor holds the tenant's quorum, so a
/// claim FROST-signs a lease and publishes it to the relay. Async because a real claim awaits
/// the publish. Kept SEPARATE from [`crate::lease::LeaseAuthority`] (the read-only fence seam)
/// because claiming is impl-specific and write-side, while the fence is read-only.
#[async_trait::async_trait]
pub trait LeaseGrantor: Send + Sync {
    /// Claim `agent_id`'s lease for this node AT an explicit `term` and return the claimed lease
    /// (node + term). Only touches this agent's lease entry (per-agent isolation, S1). Three
    /// callers, three terms: first launch claims term 1 (via the default [`grant_for`]); a
    /// HEARTBEAT re-claims at the CURRENT term (re-publishing refreshes the lease's `issued_at`
    /// so it stays within the TTL and the agent is not falsely seen as dead); a FAILOVER takeover
    /// claims `term + 1` (the monotonic fencing token that fences out the dead holder if it
    /// revives).
    ///
    /// `keystore_dir` is the tenant's per-agent FROST keystore: the relay-native grantor loads
    /// the agent's quorum Q from it to FROST-SIGN the lease (F9-2 -- a node can only claim a
    /// lease for an agent whose quorum it holds). A stub grantor (the tests) ignores it.
    async fn claim_at(
        &self,
        agent_id: &str,
        node_id: LeaseNodeId,
        term: u64,
        keystore_dir: &std::path::Path,
    ) -> anyhow::Result<LeaseResponse>;

    /// Claim `agent_id`'s lease at term 1 -- the first-launch claim (the common case). Defined
    /// in terms of [`Self::claim_at`]; an impl only needs to provide `claim_at`.
    async fn grant_for(
        &self,
        agent_id: &str,
        node_id: LeaseNodeId,
        keystore_dir: &std::path::Path,
    ) -> anyhow::Result<LeaseResponse> {
        self.claim_at(agent_id, node_id, 1, keystore_dir).await
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
    /// The durable PID sidecar (re-adopt/reap, G-3): records each launched tenant's child PID
    /// (keyed by instance_id) alongside the allocator's resource triple, so a RESTARTED
    /// supervisor can probe its orphans PID-reuse-safe. Defaults to in-memory (a supervisor that
    /// never restarts, and the tests); the real `kirby fleet` wiring swaps in a persisted one via
    /// [`Self::with_launch_registry`]. Recorded on a successful launch, forgotten on a reap.
    launch_registry: crate::fleet_reconcile::LaunchRegistry,
    /// THE READ-AFTER-WRITE LAUNCH FENCE (failover finding G-1, the double-LAUNCH): a relay
    /// re-reader consulted in [`Self::provision_and_launch`] AFTER the lease claim publishes and
    /// BEFORE the VM launches. Two survivors that both pass the failover decision both
    /// `claim_at(term+1)` under the agent's SAME quorum Q; the relay collapses both addressable
    /// (kind 31002) claims to ONE surviving event naming ONE holder. Re-reading that survivor
    /// confirms whether THIS node won — only the winner launches; the loser aborts (releasing its
    /// allocation) and lets a later tick re-settle. `None` (the default, and every in-process test)
    /// SKIPS the confirm, so the supervisor's allocation/lifecycle logic is exercised with no relay;
    /// the live `kirby fleet` control-plane wiring attaches a real reader via
    /// [`Self::with_lease_confirmer`]. See [`crate::relay_lease::confirm_takeover_win`].
    lease_confirmer: Option<Arc<dyn crate::relay_lease::LeaseReader>>,
    /// How long to let a competing peer's claim PROPAGATE to the relay before the read-after-write
    /// re-read, so a simultaneous racer's claim can arrive and be arbitrated (the launch fence is
    /// only as good as this settle window). Applied only when `lease_confirmer` is set.
    confirm_settle: std::time::Duration,
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
            // In-memory by default (tests / a supervisor that never restarts). The real
            // `kirby fleet` wiring swaps in a persisted registry via `with_launch_registry`.
            launch_registry: crate::fleet_reconcile::LaunchRegistry::in_memory(),
            // No read-after-write launch fence by default (in-process tests run with no relay);
            // the live control-plane attaches one via `with_lease_confirmer`.
            lease_confirmer: None,
            confirm_settle: DEFAULT_LAUNCH_CONFIRM_SETTLE,
        }
    }

    /// Attach a DURABLE PID sidecar so launches persist their child PID (keyed by instance_id)
    /// for the re-adopt/reap reconcile after a restart (G-3). Builder-style: the real
    /// `kirby fleet` wiring calls this with a [`crate::fleet_reconcile::LaunchRegistry::load_or_new`]
    /// over a path beside the allocator state; the in-memory default is left in place otherwise.
    pub fn with_launch_registry(
        mut self,
        registry: crate::fleet_reconcile::LaunchRegistry,
    ) -> Self {
        self.launch_registry = registry;
        self
    }

    /// Attach the READ-AFTER-WRITE LAUNCH FENCE (failover finding G-1): a relay re-reader that
    /// [`Self::provision_and_launch`] consults AFTER the lease claim publishes and BEFORE the VM
    /// launches, so a takeover launches ONLY if THIS node is confirmed to hold the surviving
    /// latest-term lease (the loser of a two-survivor race aborts and releases its allocation).
    /// Builder-style: the live `kirby fleet` control-plane attaches a [`crate::relay_lease::RelayLeaseReader`]
    /// over its connected relay client; the in-memory default leaves the confirm OFF (tests). The
    /// `settle` window lets a simultaneous peer's claim propagate to the relay before the re-read.
    pub fn with_lease_confirmer(
        mut self,
        confirmer: Arc<dyn crate::relay_lease::LeaseReader>,
        settle: std::time::Duration,
    ) -> Self {
        self.lease_confirmer = Some(confirmer);
        self.confirm_settle = settle;
        self
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
                // Forget its PID sidecar record too, so a reaped/rolled-back tenant is not
                // probed as an orphan after a restart.
                self.forget_launch_record(&live.record.allocation.instance_id);
            }
        }
    }

    /// Forget a tenant's PID sidecar record (re-adopt/reap, G-3) after it is reaped, keyed by
    /// instance_id. Best-effort: a persist failure is logged, not fatal (a stale record would at
    /// worst be reconciled to a dead process on the next restart and reaped again — never a
    /// double-host).
    fn forget_launch_record(&mut self, instance_id: &str) {
        if let Err(e) = self.launch_registry.forget(instance_id) {
            tracing::warn!(
                instance_id, error = %e,
                "fleet supervisor: failed to forget launch PID record on reap (will be reconciled dead on next restart)"
            );
        }
    }

    /// Launch ONE tenant for the FIRST time (claims the lease at term 1, via
    /// [`Self::launch_one_at_term`]). Public so a test (and the spawn control-plane) can launch a
    /// single tenant; `launch_all` calls it.
    pub async fn launch_one(&mut self, tenant: &TenantConfig) -> anyhow::Result<TenantRecord> {
        // A first launch claims term 1 (the lease's opening epoch). A FAILOVER takeover instead
        // calls `launch_one_at_term` with the verdict's `beat_term` (the monotonic fencing token
        // that beats the dead holder's stale lease) so the tenant is RECORDED at the right term and
        // its heartbeat re-publishes at THAT term, never silently dropping back to term 1.
        self.launch_one_at_term(tenant, 1).await
    }

    /// Launch ONE tenant CLAIMING ITS LEASE AT AN EXPLICIT `term`: the SAME allocate -> provision
    /// keyset -> claim -> launch -> track path as [`Self::launch_one`], but the lease is claimed at
    /// `term` (term 1 for a first launch; the verdict's `beat_term` for a G-4 failover TAKEOVER —
    /// the monotonic fencing token that fences out the dead holder if it revives). Recording the
    /// tenant at `term` is what makes the subsequent [`Self::heartbeat_leases`] re-publish at the
    /// takeover term rather than reverting to term 1 (which observers would ignore as stale, slowly
    /// re-staling the lease). Releases the allocation on any later failure so no slot leaks.
    pub async fn launch_one_at_term(
        &mut self,
        tenant: &TenantConfig,
        term: u64,
    ) -> anyhow::Result<TenantRecord> {
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
        let result = self.provision_and_launch(tenant, &allocation, term).await;
        match result {
            Ok(record) => Ok(record),
            Err(e) => {
                self.allocator.release(&tenant.agent_id);
                Err(e)
            }
        }
    }

    /// The fallible middle of a launch (split out so `launch_one_at_term` can release the
    /// allocation on failure): derive the treasury path, claim the lease AT `term`, launch the
    /// child, and record the live tenant.
    async fn provision_and_launch(
        &mut self,
        tenant: &TenantConfig,
        allocation: &TenantAllocation,
        term: u64,
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

        // (2b) PROVISION THE PER-AGENT FROST KEYSET (S3d). The supervisor is the trusted
        // dealer: on FIRST spawn it generates the tenant's OWN 2-of-3 group key Q, splits it,
        // writes all 3 holder shares (0600) + the group pubkeys beside the treasury (keyed by
        // the SAME instance_id), and the transient share material is zeroized after persisting.
        // IDEMPOTENT: on a restart (the keystore already exists) it RELOADS the SAME Q -- the
        // agent's sovereign identity is durable across restarts (it dies and comes back as
        // itself). Q SIGNS EVERYTHING for a FROST tenant. Keyed by instance_id so each tenant's
        // keystore is distinct (the same isolation the treasury path has). This runs AFTER
        // allocation (so instance_id exists) and BEFORE launch (so the agent is born with Q).
        let keystore_dir = crate::keyset_provisioning::keystore_dir_for(&allocation.instance_id);
        let frost_identity = crate::keyset_provisioning::provision_keyset_at(&keystore_dir)
            .map_err(|e| {
                anyhow::anyhow!(
                    "fleet supervisor: provision FROST keyset for tenant {:?}: {e}",
                    tenant.agent_id
                )
            })?;
        let frost_npub = frost_identity.npub();

        // (3) Claim the per-agent lease for THIS node at `term` (S1): term 1 for a first launch,
        // the verdict's `beat_term` for a failover takeover. Touches only this agent's entry, so
        // claiming tenant A never perturbs tenant B's lease.
        let granted = self
            .grantor
            .claim_at(&tenant.agent_id, self.node_id, term, &keystore_dir)
            .await
            .map_err(|e| anyhow::anyhow!("fleet supervisor: claim lease (term {term}) for tenant {:?}: {e}", tenant.agent_id))?;

        // (3b) READ-AFTER-WRITE LAUNCH FENCE (failover finding G-1, the double-LAUNCH). The claim
        // above FROST-signs + publishes our lease and returns Ok IMMEDIATELY — it does NOT prove we
        // WON. Two survivors that both pass `detect_takeovers` would both reach here and both claim
        // `term` under the agent's SAME quorum Q; the monotonic-term lease alone does NOT stop them
        // both LAUNCHING (it only fences the dead holder if it revives). So, when a confirmer is
        // attached (the live control-plane), let a competing peer's claim PROPAGATE, then RE-READ the
        // agent's surviving latest lease from the relay (a real round-trip, not the local cache):
        // the relay collapses the racing addressable (kind 31002) claims to ONE event naming ONE
        // holder, so we launch ONLY if that survivor is THIS node at the claimed term. A peer that
        // won (equal-or-higher term from a different holder), an unconfirmable claim, or a read
        // failure all FAIL CLOSED — we `bail!`, which releases this allocation in `launch_one_at_term`
        // and lets a later tick re-settle (the winner keeps the agent; we never double-run it). This
        // is skipped (confirmer = None) for a first-launch supervisor with no relay (the tests).
        if let Some(confirmer) = self.lease_confirmer.clone() {
            // Let a simultaneous racer's claim arrive at the relay before we judge the winner.
            tokio::time::sleep(self.confirm_settle).await;
            let surviving = confirmer
                .latest_lease(&tenant.agent_id)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "fleet supervisor: read-after-write confirm for tenant {:?} at term {term} could not re-read the lease ({e}); aborting the launch (fail closed)",
                        tenant.agent_id
                    )
                })?;
            if !crate::relay_lease::confirm_takeover_win(surviving, term, self.node_id) {
                anyhow::bail!(
                    "fleet supervisor: read-after-write confirm DENIED the launch of tenant {:?} at term {term} — a peer won the term race (surviving latest lease = {surviving:?}); releasing the allocation and standing down (a later tick re-settles)",
                    tenant.agent_id
                );
            }
            tracing::info!(
                agent_id = %tenant.agent_id, term,
                "fleet supervisor: read-after-write confirm — THIS node holds the surviving lease at the claimed term; proceeding to launch"
            );
        }

        // (4) Launch the child running the existing single-agent path with the allocated
        // resources. Behind the TenantLauncher seam: the real impl spawns `kirby agent`; a
        // test supplies a stub. The launch carries the CID/port the child must bind.
        let spec = TenantLaunchSpec {
            agent_id: tenant.agent_id.clone(),
            allocation: allocation.clone(),
            treasury_path: treasury_path.clone(),
            initial_sats: tenant.initial_sats,
            // FIX 3: carry the provisioned keystore into the child so its voice signs via its
            // sovereign Q (threaded into `identity.frost_keystore_dir` in derive_tenant_config).
            frost_keystore_dir: keystore_dir.clone(),
        };
        let process = self
            .launcher
            .launch(&spec)
            .map_err(|e| anyhow::anyhow!("fleet supervisor: launch tenant {:?}: {e}", tenant.agent_id))?;

        // (4b) PERSIST the launched child PID in the durable sidecar (re-adopt/reap, G-3), keyed
        // by instance_id, so a RESTARTED supervisor can probe this orphan PID-reuse-safe (the
        // allocator persists the resource triple; this persists the PID beside it). Only the real
        // child-process launcher exposes a PID; a pure in-memory stub returns `None` and records
        // nothing (it has no orphan to reconcile). A persist failure is logged but NOT fatal to
        // the launch — the agent is up and lease-claimed; the worst case is that a subsequent
        // crash before the next persist leaves this one orphan un-probable (it would then be
        // conservatively reaped on restart, never double-hosted).
        if let Some(pid) = process.pid() {
            let record = crate::fleet_reconcile::LaunchRecord {
                agent_id: tenant.agent_id.clone(),
                instance_id: allocation.instance_id.clone(),
                pid,
            };
            if let Err(e) = self.launch_registry.record(record) {
                tracing::warn!(
                    agent_id = %tenant.agent_id, pid, error = %e,
                    "fleet supervisor: failed to persist launch PID (re-adopt sidecar); the agent is up but this orphan may not be re-adoptable after a restart"
                );
            }
        }

        // (5) Track the live tenant for lifecycle monitoring (the failover hook, S5/S6).
        let record = TenantRecord {
            agent_id: tenant.agent_id.clone(),
            allocation: allocation.clone(),
            treasury_path,
            lease_term: granted.term,
            keystore_dir,
            frost_npub,
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

    /// The agent ids of the tenants this node currently hosts (launched, not yet reaped).
    pub fn live_agent_ids(&self) -> Vec<AgentId> {
        self.tenants.keys().cloned().collect()
    }

    /// HEARTBEAT every live tenant's lease: re-claim it at its CURRENT term so the lease's signed
    /// `issued_at` is refreshed and stays within [`crate::relay_lease::LEASE_TTL_SECS`]. This is
    /// the keystone the whole lease lifecycle rests on. Without it every lease would go stale
    /// ~one TTL after launch and (a) the claim-before-launch fence would go blind, letting a
    /// re-delivered spawn request double-spawn, and (b) a failover detector would see a HEALTHY
    /// agent as dead and wrongly take it over. Re-claiming at the SAME term refreshes freshness
    /// WITHOUT bumping the fencing token (only a failover bumps the term, so a heartbeat can never
    /// fence out a healthy sibling).
    ///
    /// Best-effort per tenant: a transient publish failure is logged and retried on the next
    /// tick — the TTL tolerates several missed heartbeats, so one bad heartbeat never kills a
    /// lease. Read-only on the supervisor (`&self`): it re-publishes existing leases, it does not
    /// mutate the tenant set.
    ///
    /// SKIPS an EXITED tenant (G-4 failover bug 1): a tenant whose child has died is still tracked
    /// until the next [`Self::reap_dead`] tick, but its lease MUST NOT be refreshed — heartbeating
    /// a dead agent's lease keeps it fresh forever, so it never goes stale and no peer ever fails
    /// it over (a crashed agent would be heartbeat-resurrected indefinitely). Letting the dead
    /// tenant's lease lapse is what unblocks failover; the imminent reap then frees its slot. (A
    /// LIVE agent keeps heartbeating, so this only ever silences a genuinely dead one.)
    pub async fn heartbeat_leases(&self) {
        for (agent_id, live) in &self.tenants {
            // Do not refresh a dead tenant's lease — it must be allowed to go stale so a peer can
            // take the agent over. `reap_dead` (a faster tick) removes it shortly after.
            if !live.process.is_running() {
                tracing::debug!(
                    agent_id = %agent_id,
                    "FLEET: skipping lease heartbeat for an EXITED tenant (letting its lease go stale so failover can act; it will be reaped)"
                );
                continue;
            }
            let term = live.record.lease_term;
            match self
                .grantor
                .claim_at(agent_id, self.node_id, term, &live.record.keystore_dir)
                .await
            {
                Ok(_) => {
                    tracing::debug!(agent_id = %agent_id, term, "FLEET: lease heartbeat re-published")
                }
                Err(e) => tracing::warn!(
                    agent_id = %agent_id, term, error = %e,
                    "FLEET: lease heartbeat failed (will retry next tick)"
                ),
            }
        }
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
        // Forget the PID sidecar record too (re-adopt/reap, G-3): a reaped tenant is no longer an
        // orphan to probe on the next restart.
        self.forget_launch_record(&live.record.allocation.instance_id);
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
                // Forget the PID sidecar record too (re-adopt/reap, G-3).
                self.forget_launch_record(&live.record.allocation.instance_id);
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

    /// RE-ADOPT a healthy orphan after a supervisor restart (re-adopt/reap, G-3): re-track an
    /// already-running tenant this node still owns as a supervise-by-PID
    /// [`crate::fleet_reconcile::PidTenant`], WITHOUT relaunching it. The allocation already
    /// lives in the reloaded [`crate::fleet::Allocator`] (so we do NOT re-allocate — that would
    /// reject as `AlreadyAllocated` or hand a new CID), and its PID sidecar record already
    /// survived (so we do NOT re-record). We only insert it into the live set, so the existing
    /// [`Self::heartbeat_leases`] tick resumes refreshing its lease + presence and
    /// [`Self::reap_dead`] later collects it if it dies — a supervisor bounce becomes invisible
    /// to the fleet. `record.lease_term` is the term the heartbeat will re-claim at (the lease is
    /// still ours + fresh, which is exactly why the reconcile chose re-adopt).
    pub fn re_adopt(&mut self, record: TenantRecord, process: Box<dyn TenantProcess>) {
        let agent_id = record.agent_id.clone();
        self.tenants.insert(agent_id, LiveTenant { process, record });
    }

    /// REAP an orphan the reconcile rejected (re-adopt/reap, G-3): kill the orphaned VM/process
    /// (signal its PID via the supervise-by-PID `process`), RELEASE its allocator slot, CLEAN its
    /// abandoned FROST keystore (this also closes task #15 — the abandoned-keystore cleanup), and
    /// FORGET its PID sidecar record. The orphan was NOT tracked in the live set (it is a
    /// reparented process from a previous supervisor lifetime), so this does not touch `tenants`.
    ///
    /// Best-effort + idempotent on each step: the kill ignores an already-dead PID; the release
    /// is a no-op if the slot was already freed; the keystore removal ignores a missing dir; the
    /// forget ignores an absent record. Cleaning the keystore is safe because the agent is being
    /// reaped/forgotten — a future spawn of the same agent_id mints a fresh sovereign Q (the
    /// reaped identity is intentionally not preserved; this is the abandoned-allocation cleanup,
    /// not a hibernation handoff).
    pub fn reap_orphan(
        &mut self,
        process: Box<dyn TenantProcess>,
        agent_id: &str,
        instance_id: &str,
        keystore_dir: &std::path::Path,
    ) {
        // Kill the orphaned VM/process first (it is reparented to init and still burning compute).
        process.kill();
        // Release the allocator slot so its CID/port is reusable.
        self.allocator.release(agent_id);
        // Clean the abandoned keystore (closes #15). Best-effort: a missing dir is fine.
        if keystore_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(keystore_dir) {
                tracing::warn!(
                    agent_id, keystore = %keystore_dir.display(), error = %e,
                    "fleet supervisor: failed to clean abandoned keystore on reap (slot freed; keystore left for the operator)"
                );
            }
        }
        // Forget the PID sidecar record so the orphan is not probed again on the next restart.
        self.forget_launch_record(instance_id);
    }

    /// RECONCILE persisted state with reality on supervisor restart (re-adopt/reap, G-3) — the
    /// EXECUTOR that turns the pure [`crate::fleet_reconcile::reconcile`] decision into action.
    /// Runs over THIS supervisor's own persisted launch registry (the PIDs it recorded before the
    /// restart), the injected liveness `probe`, and the resolved `lease_view` snapshot (the wiring
    /// drains the relay's retained leases into it). For each persisted orphan:
    ///  - RE-ADOPT: reconstruct its [`TenantRecord`] from the reloaded allocator + deterministic
    ///    path helpers + the observed lease term, build a supervise-by-PID
    ///    [`crate::fleet_reconcile::PidTenant`] from its persisted PID, and re-track it (the
    ///    heartbeat then covers it).
    ///  - REAP: kill the orphan + release its slot + clean its keystore (#15) + forget its sidecar
    ///    record (via [`Self::reap_orphan`]), and clear its durable spawn-ledger entry (if a
    ///    `ledger` is wired) so a future spawn request for the same agent_id can re-spawn it.
    ///
    /// The PURE decision is kept in `fleet_reconcile` (unit-tested); this is the thin glue that
    /// supplies the supervisor's real state (registry PIDs, allocator, path helpers) and performs
    /// the side effects. Returns a [`ReconcileSummary`] for logging. MUST be called BEFORE
    /// `launch_all` / the listen loop, so a static tenant that is also a healthy orphan is
    /// re-adopted rather than double-launched.
    ///
    /// THE FALSE-REAP FENCE: `obs` reports whether the lease snapshot is COMPLETE (the relay sent
    /// an EOSE — every retained lease is in) or INCOMPLETE (no EOSE within the wiring's backstop).
    /// A reap is DESTRUCTIVE (kills the VM + releases the slot + DELETES the keystore = the agent's
    /// FROST identity + clears the ledger), so we route through
    /// [`crate::fleet_reconcile::reconcile_plan`]: on an INCOMPLETE observation it returns
    /// `SkipUnconfirmedObservation` and this fn performs NO side effects (an alive orphan whose
    /// retained lease simply had not arrived is left running for a later restart to reconcile) —
    /// an alive agent is NEVER reaped on unconfirmed lease data.
    pub fn apply_reconcile(
        &mut self,
        probe: Arc<dyn crate::fleet_reconcile::OrphanLivenessProbe>,
        lease_view: &dyn crate::fleet_reconcile::ReconcileLeaseView,
        obs: crate::fleet_reconcile::LeaseObservation,
        ledger: Option<&dyn crate::spawn::SpawnLedger>,
    ) -> ReconcileSummary {
        use crate::fleet_reconcile::{reconcile_plan, PidTenant, ReconcilePlan, ReconcileVerdict};

        let records = self.launch_registry.all();
        let mut summary = ReconcileSummary::default();
        // THE FENCE: only act on a CONFIRMED-COMPLETE lease observation. An incomplete one
        // (relay slow / no EOSE) yields a fail-SAFE skip — no destructive reap on absence.
        let items = match reconcile_plan(obs, &records, probe.as_ref(), lease_view, self.node_id) {
            ReconcilePlan::Apply(items) => items,
            ReconcilePlan::SkipUnconfirmedObservation => {
                tracing::warn!(
                    agents = records.len(),
                    "FLEET reconcile: SKIPPED — the lease observation was INCOMPLETE (no EOSE from \
                     the relay within the backstop), so a lease-absence cannot be trusted as a dead \
                     agent. Failing SAFE: orphans keep running; a later restart against a healthy \
                     relay will reconcile them. (Never reap an alive agent on unconfirmed lease data.)"
                );
                summary.skipped_unconfirmed = true;
                return summary;
            }
        };

        for item in items {
            let rec = &item.record;
            match item.verdict {
                ReconcileVerdict::ReAdopt => {
                    // Reconstruct the live tenant's record from durable + deterministic sources.
                    // The allocation survived in the reloaded allocator (load_or_new); the lease
                    // term is the one we just observed as fresh + ours; the keystore + treasury
                    // paths are deterministic from the instance_id. The npub is best-effort
                    // (informational; a load failure does not block re-adopting a live agent).
                    let allocation = match self.allocator.allocation_for(&rec.agent_id) {
                        Some(a) => a.clone(),
                        None => {
                            // The PID record outlived its allocation (a torn persist). Treat it as
                            // un-re-adoptable: reap the orphan so it is not left un-tracked.
                            tracing::warn!(
                                agent_id = %rec.agent_id,
                                "FLEET reconcile: re-adopt wanted but no allocation survived; reaping the orphan instead"
                            );
                            let keystore_dir =
                                crate::keyset_provisioning::keystore_dir_for(&rec.instance_id);
                            let pid_tenant = Box::new(PidTenant::new(
                                rec.pid,
                                rec.agent_id.clone(),
                                probe.clone(),
                            ));
                            self.reap_orphan(pid_tenant, &rec.agent_id, &rec.instance_id, &keystore_dir);
                            if let Some(l) = ledger {
                                let _ = l.release(&rec.agent_id);
                            }
                            summary.reaped.push((rec.agent_id.clone(), "no allocation survived".to_string()));
                            continue;
                        }
                    };
                    let keystore_dir =
                        crate::keyset_provisioning::keystore_dir_for(&rec.instance_id);
                    let lease_term =
                        lease_view.fresh_lease_for(&rec.agent_id).map(|l| l.term).unwrap_or(1);
                    let frost_npub = crate::frost_identity::FrostIdentity::load(
                        &keystore_dir.join("group_pubkeys.json"),
                    )
                    .map(|id| id.npub())
                    .unwrap_or_default();
                    let record = TenantRecord {
                        agent_id: rec.agent_id.clone(),
                        treasury_path: crate::boot::treasury_path_for(&allocation.instance_id),
                        allocation,
                        lease_term,
                        keystore_dir,
                        frost_npub,
                    };
                    let pid_tenant =
                        Box::new(PidTenant::new(rec.pid, rec.agent_id.clone(), probe.clone()));
                    self.re_adopt(record, pid_tenant);
                    tracing::info!(
                        agent_id = %rec.agent_id, pid = rec.pid, term = lease_term,
                        "FLEET reconcile: RE-ADOPTED a healthy orphan (heartbeat resumes its lease + presence)"
                    );
                    summary.readopted.push(rec.agent_id.clone());
                }
                ReconcileVerdict::Reap(reason) => {
                    let keystore_dir =
                        crate::keyset_provisioning::keystore_dir_for(&rec.instance_id);
                    let pid_tenant =
                        Box::new(PidTenant::new(rec.pid, rec.agent_id.clone(), probe.clone()));
                    self.reap_orphan(pid_tenant, &rec.agent_id, &rec.instance_id, &keystore_dir);
                    // Clear the durable spawn-ledger entry so the reaped agent_id can be re-spawned
                    // (the reaped agent is forgotten; a fresh request mints a new sovereign Q).
                    if let Some(l) = ledger {
                        if let Err(e) = l.release(&rec.agent_id) {
                            tracing::warn!(
                                agent_id = %rec.agent_id, error = %e,
                                "FLEET reconcile: failed to clear the spawn-ledger entry for a reaped orphan"
                            );
                        }
                    }
                    tracing::info!(
                        agent_id = %rec.agent_id, pid = rec.pid, reason = %reason,
                        "FLEET reconcile: REAPED an orphan (killed + slot released + keystore cleaned + ledger cleared)"
                    );
                    summary.reaped.push((rec.agent_id.clone(), reason.to_string()));
                }
            }
        }
        summary
    }

    /// The allocation a tenant currently holds in the (possibly reloaded) allocator, if any. A
    /// passthrough so the reconcile executor can reconstruct a re-adopted orphan's record from the
    /// allocation that survived the restart.
    pub fn allocation_for(&self, agent_id: &str) -> Option<TenantAllocation> {
        self.allocator.allocation_for(agent_id).cloned()
    }
}

/// What a startup reconcile (re-adopt/reap, G-3) did, for logging + the operator evidence line.
#[derive(Debug, Default, Clone)]
pub struct ReconcileSummary {
    /// Agent ids of healthy orphans RE-ADOPTED (re-tracked, no relaunch).
    pub readopted: Vec<AgentId>,
    /// `(agent_id, reason)` of orphans REAPED (killed + slot released + keystore cleaned).
    pub reaped: Vec<(AgentId, String)>,
    /// THE FALSE-REAP FENCE: `true` if the whole reconcile was SKIPPED because the lease
    /// observation was incomplete (no EOSE) — NOTHING was reaped or re-adopted, the orphans were
    /// left running, and a later restart will reconcile them. Distinguishes a fail-safe skip from
    /// a genuine "nothing to do".
    pub skipped_unconfirmed: bool,
}

impl ReconcileSummary {
    /// Whether the reconcile touched anything (so the wiring can log a tidy "nothing to do"). A
    /// fail-safe skip on an incomplete observation also reads empty (it touched nothing), but the
    /// wiring inspects [`Self::skipped_unconfirmed`] to log it distinctly.
    pub fn is_empty(&self) -> bool {
        self.readopted.is_empty() && self.reaped.is_empty()
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
        // Give each tenant its OWN Nostr identity key dir (keyed off the unique instance id),
        // mirroring the DB-per-agent treasury isolation above. Without this every tenant child
        // inherits the base config's `identity.key_path` verbatim and resolves to the SAME
        // `node.nostr.key`; since key creation is exclusive (`create_new`, nerve.rs), all but
        // the first tenant fail with EEXIST and exit. A per-instance dir resolves to its own
        // `<dir>/node.nostr.key`, so each tenant gets a distinct npub (and, via the §F3 one-key
        // invariant, its own memory key too).
        cfg.identity.key_path = self.config_dir.join(format!("keys-{}", spec.allocation.instance_id));
        // FIX 3 (FROST-tenant wiring) — RIGHT ALONGSIDE PR #36's per-tenant `key_path` above:
        // both are per-tenant isolations keyed by instance_id and they COEXIST. The node key_path
        // (above) roots presence/memory; the FROST keystore (here) roots the OUTWARD VOICE. Set
        // the child's `identity.frost_keystore_dir` to the supervisor-provisioned keystore so the
        // launched tenant signs published notes via its sovereign 2-of-3 Q (the FROST branch in
        // `build_nostr_actuator`), NOT the node key. Without this the child hardcoded `None` and
        // signed with the node key — the FROST branch was dead in the real flow (the gap three
        // reviews flagged). This survives serialization into the child's `kirby.toml`.
        cfg.identity.frost_keystore_dir = Some(spec.frost_keystore_dir.clone());
        // PER-AGENT MONEY ISOLATION (#74) + the latent dm-key-collision fix, alongside the
        // per-tenant key_path/frost_keystore_dir rewrites above. Point the child's
        // `identity.treasury_dir` at its OWN durable per-instance dir (keyed by the same
        // instance_id). Two coupled effects:
        //   1. dm-key collision: `treasury_dir()` (config.rs) otherwise falls back to
        //      `key_path.parent()` = the SHARED per-node config dir, so the child's DM key
        //      (`treasury_dir()/social.dm.key`, run_agent.rs) resolved to the SAME path for
        //      EVERY tenant on this host — a cross-tenant key collision (latent: multi-capable
        //      DM on one host isn't exercised yet). Per-instance gives each its own key home.
        //   2. it homes the per-agent SOVEREIGN Cashu wallet store (below) + the wallet spend
        //      key (the P1-b seam), under the durable state root so they survive reap + reboot
        //      (`reap_orphan` deletes only `keystore-{id}`, never this `agent-{id}` dir).
        // Supervisor-path-scoped, so a bare `kirby run` is byte-identical (G-CLEAN).
        let agent_dir = crate::boot::agent_state_dir_for(&spec.allocation.instance_id);
        // The per-agent SOVEREIGN Cashu wallet store (#74): each tenant opens its OWN
        // cdk-sqlite wallet (+ its sibling `.seed` spend key) under its per-instance dir, so
        // two tenants never share one wallet DB. Only the `routstr` (Cashu) backend reads it.
        // The `routstr_key` backend's `api_key_path` is deliberately NOT rewritten here: it is
        // a node-shared CUSTODIAL credential (one funded prepaid key), and a path-rewrite would
        // point each tenant at a key file that does not exist (boot refuses). Per-agent
        // custodial keys are key PROVISIONING (a later chunk), not a path rewrite.
        cfg.brain.wallet_db_path = agent_dir
            .join("wallet.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.identity.treasury_dir = Some(agent_dir);
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
        // Capture the OS PID before the child moves into the mutex, so the supervisor can persist
        // it (the re-adopt/reap sidecar) without locking. The child was spawned `--config
        // <dir>/tenant-<agent_id>.toml`, so its `/proc/<pid>/cmdline` carries the unique
        // `tenant-<agent_id>.toml` token the PID-reuse-safe liveness probe matches on.
        let pid = child.id();
        Ok(Box::new(ChildTenant { child: std::sync::Mutex::new(child), pid }))
    }
}

/// A real child-process tenant (the [`ProcessTenantLauncher`] output). Wraps the spawned
/// `kirby agent` child; `is_running` polls its exit status without blocking, `kill` signals
/// it. The `Mutex` makes it `Send + Sync` for the supervisor to hold across tasks.
struct ChildTenant {
    child: std::sync::Mutex<std::process::Child>,
    /// The spawned child's OS PID, captured at launch (so the supervisor persists it for the
    /// re-adopt/reap sidecar without locking the mutex).
    pid: u32,
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

    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A stub tenant process: in-memory RUNNING/EXITED state, no real process. Lets the
    /// supervisor's allocation / lifecycle / lease-grant logic run with NO VM (non-gated).
    /// Carries a synthetic `pid` so the launch path's PID-sidecar persistence (re-adopt/reap) is
    /// exercised non-gated (a real PID comes from a spawned child; this models it).
    struct StubTenant {
        running: Arc<AtomicBool>,
        pid: Option<u32>,
    }

    impl TenantProcess for StubTenant {
        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
        fn kill(&self) {
            self.running.store(false, Ordering::SeqCst);
        }
        fn pid(&self) -> Option<u32> {
            self.pid
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
        /// A monotonic synthetic-PID counter so each launched stub tenant gets a distinct pid the
        /// supervisor persists to the sidecar (the re-adopt/reap PID-persistence path).
        next_pid: std::sync::atomic::AtomicU32,
        /// The synthetic pid handed to each agent's launch (so a test can assert the supervisor
        /// recorded the right PID for it).
        pids: std::sync::Mutex<BTreeMap<AgentId, u32>>,
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

        /// The synthetic pid this launcher assigned to an agent at launch (for asserting the
        /// supervisor persisted it).
        fn pid_for(&self, agent_id: &str) -> Option<u32> {
            self.pids.lock().unwrap().get(agent_id).copied()
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
            // Hand out a distinct synthetic pid (>= 100_000 to avoid clashing with a real low pid)
            // so the supervisor persists it to the re-adopt/reap sidecar.
            let pid = 100_000 + self.next_pid.fetch_add(1, Ordering::SeqCst);
            self.pids.lock().unwrap().insert(spec.agent_id.clone(), pid);
            Ok(Box::new(StubTenant { running, pid: Some(pid) }))
        }
    }

    /// A stub grantor: records every (agent_id, node_id) claim so a test can assert per-agent
    /// independence without a live relay, and ECHOES the term it was claimed at (so a heartbeat
    /// re-claims at the same term, a failover at term + 1, and a test can read it back).
    #[derive(Default)]
    struct StubGrantor {
        grants: std::sync::Mutex<Vec<(AgentId, LeaseNodeId)>>,
    }

    #[async_trait::async_trait]
    impl LeaseGrantor for StubGrantor {
        async fn claim_at(
            &self,
            agent_id: &str,
            node_id: LeaseNodeId,
            term: u64,
            _keystore_dir: &std::path::Path,
        ) -> anyhow::Result<LeaseResponse> {
            self.grants.lock().unwrap().push((agent_id.to_string(), node_id));
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
        // FIX 2: pin the DURABLE state root (treasury + keystore) to a STABLE per-binary temp
        // dir for the fleet tests, set ONCE here (not mid-test), so a test that provisions real
        // keystores via `launch_all` never pollutes the operator's real data dir AND no test
        // mutates `$KIRBY_STATE_ROOT` mid-run (which would race a sibling test's path recompute).
        // The per-instance subdirs are unique, so one shared root is safe across these tests.
        let root = std::env::temp_dir().join("kirby-fleet-test-state");
        cfg.state_root = Some(root.clone());
        cfg.apply_state_root_env();
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
        // Unique-per-run ids: launch_all provisions REAL FROST keystores keyed by instance_id
        // under the SHARED test state_root, so FIXED ids would collide/race with sibling fleet
        // tests that also launch "alice"/"bob"/"carol" in parallel (the rug-proof anchor guard
        // then sees a half-written keystore and fails). Unique ids isolate this run's keystores.
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a = format!("ln-alice-{suffix}");
        let b = format!("ln-bob-{suffix}");
        let c = format!("ln-carol-{suffix}");
        let cfg = base_config_with_tenants(vec![
            tenant(&a, 500_000),
            tenant(&b, 700_000),
            tenant(&c, 900_000),
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
            assert!([a.as_str(), b.as_str(), c.as_str()].contains(&agent_id.as_str()));
        }

        // The launcher saw each tenant's allocated CID/port + initial_sats.
        let launched = launcher.launched.lock().unwrap().clone();
        assert_eq!(launched.len(), 3);
        let alice = launched.iter().find(|s| s.agent_id == a).unwrap();
        assert_eq!(alice.initial_sats, 500_000);

        // All three report RUNNING; none dead yet.
        for id in [&a, &b, &c] {
            assert_eq!(sup.tenant_status(id), Some(TenantStatus::Running));
        }
        assert!(sup.dead_tenants().is_empty());

        // Tidy the real keystores this test provisioned.
        for r in &records {
            let _ = std::fs::remove_dir_all(&r.keystore_dir);
        }
    }

    /// S3d at the SUPERVISOR level: launching a tenant PROVISIONS its per-agent FROST keystore
    /// (the supervisor is the dealer) and records its sovereign Q-npub. TEETH: after launch the
    /// keystore dir holds the group pubkeys + 3 holder shares (so the agent is born with Q), the
    /// record carries a real npub, and re-provisioning the SAME instance_id (a restart) yields
    /// the SAME npub (idempotent, no regeneration). Distinct tenants get DISTINCT keystores +
    /// distinct sovereign Qs.
    #[tokio::test]
    async fn supervisor_provisions_per_agent_frost_keyset_at_spawn() {
        // FIX 2: the DURABLE state root is pinned to a stable per-binary temp dir by
        // `base_config_with_tenants` (set ONCE, not mid-test), so this test's real keystores
        // never pollute the operator's data dir and no env race with sibling tests occurs.
        // Unique agent ids per test run so the instance-keyed keystore dirs do not collide with
        // other tests/runs sharing the temp dir.
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a_id = format!("s3d-alice-{suffix}");
        let b_id = format!("s3d-bob-{suffix}");
        let cfg = base_config_with_tenants(vec![tenant(&a_id, 500_000), tenant(&b_id, 700_000)]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());
        let mut sup = FleetSupervisor::new(1, cfg, allocator, grantor, launcher);

        let records = sup.launch_all().await.expect("launch all");
        assert_eq!(records.len(), 2);

        let mut npubs = std::collections::BTreeSet::new();
        let mut keystores = std::collections::BTreeSet::new();
        for r in &records {
            // Each tenant was born with a real FROST identity (Q-npub).
            assert!(r.frost_npub.starts_with("npub1"), "tenant must have a sovereign npub, got {}", r.frost_npub);
            assert!(npubs.insert(r.frost_npub.clone()), "two tenants share a sovereign Q (must be distinct)");
            assert!(keystores.insert(r.keystore_dir.clone()), "two tenants share a keystore dir");

            // The keystore is provisioned: group pubkeys + 3 holder shares exist beside the treasury.
            assert!(r.keystore_dir.join("group_pubkeys.json").is_file(), "group pubkeys must be written at spawn");
            for idx in 1..=3 {
                assert!(
                    r.keystore_dir.join(format!("share_{idx}.json")).is_file(),
                    "holder share_{idx} must be written at spawn"
                );
            }
            // The keystore sits beside the treasury (same instance_id key).
            assert_eq!(
                r.keystore_dir,
                crate::keyset_provisioning::keystore_dir_for(&r.allocation.instance_id),
                "keystore dir must be keyed by instance_id (beside the treasury)"
            );
        }

        // IDEMPOTENT across restart: re-provisioning the SAME instance_id yields the SAME npub
        // (the supervisor's restart path reloads, never regenerates).
        for r in &records {
            let reload = crate::keyset_provisioning::provision_keyset_at(&r.keystore_dir)
                .expect("reload existing keystore (restart)");
            assert_eq!(reload.npub(), r.frost_npub, "restart must reload the SAME sovereign Q (no regen)");
        }

        // Cleanup the temp keystores.
        for r in &records {
            let _ = std::fs::remove_dir_all(&r.keystore_dir);
        }
    }

    /// Killing ONE tenant does not disturb another: the killed tenant reports EXITED and is
    /// the only dead one; the others stay RUNNING. This is the crash-isolation property
    /// (process-per-tenant) at the supervisor-tracking level (the VM-level isolation is the
    /// gated G-N-TENANTS gate).
    #[tokio::test]
    async fn killing_one_tenant_does_not_disturb_another() {
        // Unique-per-run ids: launch_all provisions REAL keystores under the SHARED test
        // state_root, so fixed ids race sibling fleet tests (see launches_n_tenants).
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a = format!("ko-alice-{suffix}");
        let b = format!("ko-bob-{suffix}");
        let cfg = base_config_with_tenants(vec![tenant(&a, 1_000_000), tenant(&b, 1_000_000)]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());
        let mut sup = FleetSupervisor::new(1, cfg, allocator, grantor, launcher.clone());
        sup.launch_all().await.expect("launch all");

        // Kill alice via the launcher's switch (modeling a child crash).
        launcher.running_flag(&a).store(false, Ordering::SeqCst);

        assert_eq!(sup.tenant_status(&a), Some(TenantStatus::Exited), "alice must read EXITED");
        assert_eq!(sup.tenant_status(&b), Some(TenantStatus::Running), "bob must be undisturbed by alice's death");
        assert_eq!(sup.dead_tenants(), vec![a.clone()], "only alice is dead");

        // Reaping the dead tenant frees its slot (and only its slot); bob is untouched.
        let reaped = sup.reap(&a).expect("reap dead alice");
        assert_eq!(reaped.agent_id, a);
        assert_eq!(sup.tenant_count(), 1);
        assert_eq!(sup.tenant_status(&b), Some(TenantStatus::Running));
        // Refusing to reap a live tenant.
        let err = sup.reap(&b).unwrap_err();
        assert!(err.to_string().contains("still RUNNING"));

        // Tidy the real keystores this test provisioned.
        for id in [&a, &b] {
            let _ = std::fs::remove_dir_all(crate::keyset_provisioning::keystore_dir_for(&format!("kirby-{id}")));
        }
    }

    /// A launch that fails partway (the grantor errors) RELEASES the tenant's allocation, so
    /// a failed launch leaks no CID/port slot. TEETH: after the failure the freed slot is
    /// reusable and the tenant is not tracked.
    #[tokio::test]
    async fn failed_launch_releases_the_allocation() {
        struct FailingGrantor;
        #[async_trait::async_trait]
        impl LeaseGrantor for FailingGrantor {
            async fn claim_at(
                &self,
                _agent_id: &str,
                _node_id: LeaseNodeId,
                _term: u64,
                _keystore_dir: &std::path::Path,
            ) -> anyhow::Result<LeaseResponse> {
                anyhow::bail!("grant refused (not leader)")
            }
        }
        // Unique-per-run id: launch_one provisions a REAL keystore for the tenant under the
        // SHARED test state_root BEFORE the grant step. A FIXED id ("alice") collides with the
        // sibling fleet tests that also launch "alice" in parallel — the rug-proof anchor guard
        // then sees a half-written keystore and the relaunch fails ("missing/corrupt holder
        // share"). A unique id isolates this run's keystore. (This was the recurring CI flake.)
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a = format!("fl-alice-{suffix}");
        let cfg = base_config_with_tenants(vec![tenant(&a, 1_000_000)]);
        let allocator = Allocator::new(&cfg.fleet);
        let launcher = Arc::new(StubLauncher::default());
        let mut sup = FleetSupervisor::new(1, cfg, allocator, Arc::new(FailingGrantor), launcher.clone());

        let err = sup.launch_one(&tenant(&a, 1_000_000)).await.unwrap_err();
        assert!(err.to_string().contains("claim lease"), "the claim/grant failure surfaces: {err}");
        // The allocation was released: nothing is tracked, and nothing was launched.
        assert_eq!(sup.tenant_count(), 0);
        assert!(launcher.launched.lock().unwrap().is_empty(), "a failed grant must not launch a child");
        // The freed slot is reusable: a fresh launch (with a working grantor) succeeds.
        let mut sup2 = {
            let cfg = base_config_with_tenants(vec![]);
            let allocator = Allocator::new(&cfg.fleet);
            FleetSupervisor::new(1, cfg, allocator, Arc::new(StubGrantor::default()), launcher.clone())
        };
        sup2.launch_one(&tenant(&a, 1_000_000)).await.expect("relaunch after release");
        assert_eq!(sup2.tenant_count(), 1);

        // Tidy the real keystore this test provisioned.
        let _ = std::fs::remove_dir_all(crate::keyset_provisioning::keystore_dir_for(&format!("kirby-{a}")));
    }

    /// A MID-BATCH launch failure rolls back the WHOLE batch: every tenant already launched is
    /// KILLED (its child terminated, not merely dropped) and REAPED (its allocator slot freed),
    /// so the failed batch leaves no orphaned child and no leaked slot. TEETH: after the
    /// failure the already-launched tenants' kill-switches read false (killed), nothing is
    /// tracked, the allocator is empty, and every freed CID is reusable by a fresh batch.
    #[tokio::test]
    async fn mid_batch_launch_failure_kills_and_releases_already_launched_tenants() {
        // Unique-per-run agent ids: launch_all provisions REAL FROST keystores keyed by
        // instance_id (= kirby-<agent_id>), and the rug-proof anchor guard (S3d) refuses to
        // regenerate an existing group_pubkeys.json. Reusing FIXED ids leaks those keystores
        // across runs into the guard -> a flaky failure (the shared state_root is intentionally
        // fixed to avoid a $KIRBY_STATE_ROOT env race between parallel tests, so the isolation
        // lever is the agent_id, not the root). Unique ids keep each run's keystores isolated.
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a = format!("mb-alice-{suffix}");
        let b = format!("mb-bob-{suffix}");
        let c = format!("mb-carol-{suffix}");
        let cfg = base_config_with_tenants(vec![
            tenant(&a, 1_000_000),
            tenant(&b, 1_000_000),
            tenant(&c, 1_000_000), // carol's launch fails, after alice + bob are up
        ]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());
        launcher.set_fail_on(&c);
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
        for id in [&a, &b] {
            let flag = launcher.maybe_running_flag(id).expect("alice/bob were launched");
            assert!(
                !flag.load(Ordering::SeqCst),
                "{id}'s child must be killed on a rolled-back batch (no orphan)"
            );
        }
        // carol's launch failed, so carol was never launched.
        assert!(launcher.maybe_running_flag(&c).is_none(), "carol never launched");

        // Their allocator slots were RELEASED: a fresh full batch succeeds (no leaked slot,
        // and the freed CIDs are reusable).
        let cfg2 = base_config_with_tenants(vec![tenant(&a, 1), tenant(&b, 1)]);
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

        // Tidy: remove the real keystores this test provisioned (both batches, all ids).
        for id in [&a, &b, &c] {
            let inst = format!("kirby-{id}");
            let _ = std::fs::remove_dir_all(crate::keyset_provisioning::keystore_dir_for(&inst));
        }
    }

    /// `reap_dead` releases the allocator slot for EVERY exited tenant (the supervisor's
    /// shutdown/restart-safety cleanup) and leaves running tenants alone. TEETH: after a
    /// tenant dies and is reaped, its slot is reusable; a still-running tenant is untouched.
    #[tokio::test]
    async fn reap_dead_releases_exited_tenant_slots_only() {
        // Unique-per-run ids: launch_all provisions REAL keystores under the SHARED test
        // state_root, so fixed ids race sibling fleet tests (see launches_n_tenants).
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a = format!("rd-alice-{suffix}");
        let b = format!("rd-bob-{suffix}");
        let cfg = base_config_with_tenants(vec![tenant(&a, 1), tenant(&b, 1)]);
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
        launcher.running_flag(&a).store(false, Ordering::SeqCst);

        let reaped = sup.reap_dead();
        assert_eq!(reaped.len(), 1, "exactly the one dead tenant is reaped");
        assert_eq!(reaped[0].agent_id, a);
        assert_eq!(sup.tenant_count(), 1, "bob is still tracked");
        assert_eq!(sup.tenant_status(&b), Some(TenantStatus::Running), "bob untouched");
        assert!(sup.tenant_status(&a).is_none(), "alice was reaped");

        // A second reap with no dead tenants is a no-op.
        assert!(sup.reap_dead().is_empty(), "no dead tenants => empty reap");

        // Tidy the real keystores this test provisioned.
        for id in [&a, &b] {
            let _ = std::fs::remove_dir_all(crate::keyset_provisioning::keystore_dir_for(&format!("kirby-{id}")));
        }
    }

    /// G-4 FAILOVER BUG 1 (the regression guard): a DEAD tenant's lease MUST NOT be heartbeated —
    /// `heartbeat_leases` skips an EXITED tenant so its lease goes stale and a peer can fail it
    /// over, while a still-running sibling keeps heartbeating. TEETH: after one tenant dies, a
    /// heartbeat tick re-claims ONLY the live tenant's lease; the dead tenant's lease is left to
    /// lapse (the bug was that the supervisor heartbeat-resurrected a crashed agent's lease
    /// forever, so it never went stale and failover never triggered). The companion `reap_dead`
    /// then removes the dead tenant.
    #[tokio::test]
    async fn heartbeat_skips_a_dead_tenant_so_its_lease_goes_stale() {
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a = format!("hb-alice-{suffix}");
        let b = format!("hb-bob-{suffix}");
        let cfg = base_config_with_tenants(vec![tenant(&a, 1), tenant(&b, 1)]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());
        let mut sup =
            FleetSupervisor::new(1, cfg, allocator, grantor.clone(), launcher.clone());
        sup.launch_all().await.expect("launch all");

        // The launch claimed each tenant's lease once (term 1). Record where the launch grants end
        // so we can inspect ONLY the grants the heartbeat adds.
        let grants_after_launch = grantor.grants.lock().unwrap().len();
        assert_eq!(grants_after_launch, 2, "one launch grant per tenant");

        // alice dies (its child exits); bob stays up.
        launcher.running_flag(&a).store(false, Ordering::SeqCst);

        // A heartbeat tick: it must refresh ONLY bob's lease (alice is dead → its lease must be
        // allowed to go stale so a peer fails it over).
        sup.heartbeat_leases().await;

        let all_grants = grantor.grants.lock().unwrap().clone();
        let heartbeat_grants: Vec<&AgentId> =
            all_grants[grants_after_launch..].iter().map(|(id, _)| id).collect();
        assert!(
            heartbeat_grants.iter().all(|id| **id == b),
            "the heartbeat must NOT re-claim the DEAD tenant's lease (got {heartbeat_grants:?})"
        );
        assert!(
            heartbeat_grants.iter().any(|id| **id == b),
            "the heartbeat MUST still refresh the LIVE tenant's lease"
        );

        // And the dead tenant is reaped by the companion tick, freeing its slot.
        let reaped = sup.reap_dead();
        assert_eq!(reaped.len(), 1, "the dead tenant is reaped");
        assert_eq!(reaped[0].agent_id, a);

        // Tidy the real keystores this test provisioned.
        for id in [&a, &b] {
            let _ = std::fs::remove_dir_all(crate::keyset_provisioning::keystore_dir_for(&format!("kirby-{id}")));
        }
    }

    /// A tiny shared addressable "relay" for the read-after-write LAUNCH-FENCE test: it keeps the
    /// SURVIVING lease per agent the way a real relay keeps the latest addressable (kind 31002)
    /// replaceable event keyed by `(Q, kind, d=agent_id)`. Two survivors racing the SAME agent
    /// sign under the SAME Q, so the relay holds exactly ONE event: a strictly-HIGHER term
    /// overwrites; an EQUAL term keeps the FIRST claimant (the deterministic equal-term tiebreak —
    /// a real relay breaks an equal-`created_at` addressable tie by lowest event id; "first wins"
    /// is a faithful deterministic stand-in). The point: after both racers claim, the relay names
    /// exactly ONE holder, and the read-after-write fence must let only THAT node launch.
    #[derive(Clone, Default)]
    struct RaceRelay {
        // agent_id -> (holder_node_id, term)
        latest: Arc<std::sync::Mutex<std::collections::HashMap<String, (LeaseNodeId, u64)>>>,
    }
    impl RaceRelay {
        fn publish(&self, agent_id: &str, holder: LeaseNodeId, term: u64) {
            let mut m = self.latest.lock().unwrap();
            match m.get(agent_id).copied() {
                // Strictly higher term replaces; equal term keeps the FIRST holder (tiebreak);
                // a lower term never moves it backward.
                Some((_, t)) if term > t => {
                    m.insert(agent_id.to_string(), (holder, term));
                }
                None => {
                    m.insert(agent_id.to_string(), (holder, term));
                }
                Some(_) => {} // equal-or-lower term: the surviving (first/higher) holder stands.
            }
        }
        fn surviving(&self, agent_id: &str) -> Option<(LeaseNodeId, u64)> {
            self.latest.lock().unwrap().get(agent_id).copied()
        }
    }

    /// A grantor that PUBLISHES each claim into the shared `RaceRelay` (modeling the real
    /// grantor's FROST-sign-and-publish), so the read-after-write re-read sees the LWW survivor.
    struct RaceGrantor {
        node_id: LeaseNodeId,
        relay: RaceRelay,
    }
    #[async_trait::async_trait]
    impl LeaseGrantor for RaceGrantor {
        async fn claim_at(
            &self,
            agent_id: &str,
            node_id: LeaseNodeId,
            term: u64,
            _keystore_dir: &std::path::Path,
        ) -> anyhow::Result<LeaseResponse> {
            // A node only claims a lease naming itself (mirrors the real grantor's invariant).
            assert_eq!(node_id, self.node_id, "a node claims only its own holder id");
            self.relay.publish(agent_id, node_id, term);
            Ok(LeaseResponse { node_id, term })
        }
    }

    /// The read-after-write CONFIRMER over the shared `RaceRelay`: it returns the surviving
    /// holder/term the relay kept, exactly as `RelayLeaseReader` returns the surviving relay event.
    struct RaceConfirmer {
        relay: RaceRelay,
    }
    #[async_trait::async_trait]
    impl crate::relay_lease::LeaseReader for RaceConfirmer {
        async fn latest_lease(
            &self,
            agent_id: &str,
        ) -> anyhow::Result<Option<crate::relay_lease::ObservedLeaseRecord>> {
            Ok(self.relay.surviving(agent_id).map(|(holder, term)| {
                crate::relay_lease::ObservedLeaseRecord {
                    holder_node_id: holder,
                    term,
                    issued_at: 0,
                }
            }))
        }
    }

    /// A launcher whose launches all increment ONE shared counter (so a test spanning TWO
    /// supervisors can assert the TOTAL number of VMs that would be launched across the fleet).
    #[derive(Clone)]
    struct CountingLauncher {
        launches: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl TenantLauncher for CountingLauncher {
        fn launch(&self, _spec: &TenantLaunchSpec) -> anyhow::Result<Box<dyn TenantProcess>> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(StubTenant { running: Arc::new(AtomicBool::new(true)), pid: None }))
        }
    }

    /// THE READ-AFTER-WRITE LAUNCH FENCE, end to end at the SUPERVISOR (failover finding G-1, the
    /// double-LAUNCH). Two SURVIVORS race the SAME stale agent at the SAME takeover term (`term+1`)
    /// — the exact case `detect_takeovers` alone CANNOT contain (both can pass the decision before
    /// either's claim has propagated). Each supervisor claims `term+1` (both publish into the shared
    /// relay, which keeps ONE surviving holder), then runs the read-after-write confirm and launches
    /// ONLY if it is that survivor. TEETH: EXACTLY ONE of the two supervisors launches a VM; the
    /// loser's `launch_one_at_term` returns an error AND releases its allocation (no leaked slot).
    /// This is the assertion the lease-layer race test (`full_loop_run::single_winner_when_two_...`)
    /// could not make — it had no VM, so it could not catch a double-LAUNCH. Goes RED if the
    /// read-after-write fence in `provision_and_launch` is removed (both would then launch).
    #[tokio::test]
    async fn read_after_write_fence_lets_only_one_of_two_racing_survivors_launch() {
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let agent = format!("raw-fence-{suffix}");
        let beat_term = 5u64; // both survivors take over the dead holder's lease at the same term.

        let relay = RaceRelay::default();
        let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let zero_settle = std::time::Duration::ZERO; // deterministic test: no real propagation wait.

        // Build TWO survivor supervisors (node 2 and node 3) over the SAME shared relay + launch
        // counter, each with the read-after-write confirmer attached. Distinct node ids, distinct
        // (in-memory) allocators — they are different machines that both decided to take over.
        let mut sups = Vec::new();
        for node_id in [2u64, 3u64] {
            let cfg = base_config_with_tenants(vec![]);
            let allocator = Allocator::new(&cfg.fleet);
            let grantor = Arc::new(RaceGrantor { node_id, relay: relay.clone() });
            let launcher = Arc::new(CountingLauncher { launches: launches.clone() });
            let confirmer = Arc::new(RaceConfirmer { relay: relay.clone() });
            let sup = FleetSupervisor::new(node_id, cfg, allocator, grantor, launcher)
                .with_lease_confirmer(confirmer, zero_settle);
            sups.push((node_id, sup));
        }

        // Both survivors take over the SAME agent at the SAME term, in sequence (node 2 first). The
        // shared relay keeps node 2 as the surviving holder at `beat_term`; node 3's later claim at
        // the SAME term does not displace it (the equal-term tiebreak).
        let t = tenant(&agent, 1);
        let r2 = sups[0].1.launch_one_at_term(&t, beat_term).await;
        let r3 = sups[1].1.launch_one_at_term(&t, beat_term).await;

        // The relay's single surviving holder is node 2 (claimed first at this term).
        assert_eq!(
            relay.surviving(&agent),
            Some((2, beat_term)),
            "the relay keeps ONE surviving holder for the raced agent (the first claimant at the term)"
        );

        // EXACTLY ONE VM launched across the fleet — the single-winner property on the LAUNCH path.
        assert_eq!(
            launches.load(Ordering::SeqCst),
            1,
            "exactly ONE of the two racing survivors may launch the agent (read-after-write single-winner)"
        );

        // The winner (node 2, the surviving holder) launched and is tracking the tenant; the loser
        // (node 3) aborted with an error and is tracking NOTHING (its allocation was released).
        assert!(r2.is_ok(), "the surviving-holder node launches (got {r2:?})");
        assert!(
            r3.is_err(),
            "the LOSER's launch must be DENIED by the read-after-write confirm (got {r3:?})"
        );
        assert_eq!(sups[0].1.tenant_count(), 1, "the winner tracks the launched tenant");
        assert_eq!(
            sups[1].1.tenant_count(),
            0,
            "the loser tracks no tenant (it never launched)"
        );

        // The loser RELEASED its allocation (no leaked CID/port slot): a fresh allocate for the
        // same agent on the loser succeeds, proving the slot was freed by the aborted takeover.
        assert!(
            sups[1].1.allocator.allocate(&agent).is_ok(),
            "the loser must have RELEASED its allocation on the aborted takeover (no leaked slot)"
        );

        // Tidy the real keystore this test provisioned (idempotently, by whichever survivor first).
        let _ = std::fs::remove_dir_all(crate::keyset_provisioning::keystore_dir_for(&format!("kirby-{agent}")));
    }

    /// RE-ADOPT/REAP at the SUPERVISOR level (G-3): launching a tenant PERSISTS its child PID to
    /// the durable sidecar (so a restart can probe it), `re_adopt` re-tracks a healthy orphan as a
    /// supervise-by-PID tenant WITHOUT re-allocating (the heartbeat then covers it), and
    /// `reap_orphan` kills the orphan + releases its slot + cleans its keystore (#15) + forgets
    /// its sidecar record. Exercised with the stub launcher + a mock probe (no VM, non-gated).
    #[tokio::test]
    async fn launch_persists_pid_and_readopt_reap_orphan_round_trip() {
        use crate::fleet_reconcile::{LaunchRegistry, OrphanLivenessProbe, PidTenant};

        // A mock probe whose liveness is a flippable flag (no real /proc).
        struct AlwaysAlive;
        impl OrphanLivenessProbe for AlwaysAlive {
            fn alive_and_ours(&self, _pid: u32, _agent_id: &str) -> bool {
                true
            }
        }

        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let a = format!("ra-alice-{suffix}");
        let cfg = base_config_with_tenants(vec![tenant(&a, 500_000)]);
        let allocator = Allocator::new(&cfg.fleet);
        let grantor = Arc::new(StubGrantor::default());
        let launcher = Arc::new(StubLauncher::default());

        // A persisted launch registry over a temp file so we can prove the PID survives.
        let reg_dir = std::env::temp_dir().join(format!("kirby-ra-reg-{suffix}"));
        std::fs::create_dir_all(&reg_dir).unwrap();
        let reg_path = reg_dir.join("launch-registry.json");
        let registry = LaunchRegistry::load_or_new(&reg_path).expect("fresh registry");

        let mut sup = FleetSupervisor::new(1, cfg, allocator, grantor, launcher.clone())
            .with_launch_registry(registry);

        // (1) LAUNCH persists the child PID to the sidecar, keyed by instance_id.
        let record = sup.launch_one(&tenant(&a, 500_000)).await.expect("launch alice");
        let expected_pid = launcher.pid_for(&a).expect("launcher assigned a pid");
        let persisted = LaunchRegistry::load_or_new(&reg_path).expect("reload registry");
        let inst = format!("kirby-{a}");
        assert_eq!(
            persisted.get(&inst).map(|r| r.pid),
            Some(expected_pid),
            "the launch must persist the child PID to the sidecar (keyed by instance_id)"
        );
        assert_eq!(persisted.get(&inst).map(|r| r.agent_id.as_str()), Some(a.as_str()));

        // Simulate a RESTART: the orphan keeps running, but the supervisor drops its in-memory
        // tracking. Build a fresh supervisor reloading the SAME allocator state + registry would
        // be the full path; here we exercise the two supervisor primitives directly.

        // (2) RE-ADOPT: re-track the healthy orphan as a supervise-by-PID tenant (no relaunch).
        let probe: Arc<dyn OrphanLivenessProbe> = Arc::new(AlwaysAlive);
        let pid_tenant = Box::new(PidTenant::new(expected_pid, a.clone(), probe.clone()));
        sup.re_adopt(record.clone(), pid_tenant);
        // It is tracked, RUNNING (the probe says alive+ours), and the heartbeat would cover it.
        assert_eq!(sup.tenant_status(&a), Some(TenantStatus::Running), "re-adopted orphan reads RUNNING");
        assert!(sup.tenant_record(&a).is_some(), "re-adopted orphan is tracked again");
        // Heartbeat covers the re-adopted tenant without panicking (it re-claims at its term).
        sup.heartbeat_leases().await;

        // (3) REAP an orphan: a keystore dir present is cleaned, the slot released, record forgotten.
        let keystore_dir = reg_dir.join(format!("keystore-{inst}"));
        std::fs::create_dir_all(&keystore_dir).unwrap();
        std::fs::write(keystore_dir.join("group_pubkeys.json"), b"{}").unwrap();
        let orphan_kill = Box::new(PidTenant::new(expected_pid, a.clone(), probe));
        sup.reap_orphan(orphan_kill, &a, &inst, &keystore_dir);
        // The abandoned keystore was cleaned (closes #15).
        assert!(!keystore_dir.exists(), "reap_orphan must clean the abandoned keystore (#15)");
        // The sidecar record was forgotten (the orphan is no longer probed on the next restart).
        let after = LaunchRegistry::load_or_new(&reg_path).expect("reload after reap");
        assert!(after.get(&inst).is_none(), "reap_orphan must forget the PID sidecar record");

        let _ = std::fs::remove_dir_all(&reg_dir);
        let _ = std::fs::remove_dir_all(crate::keyset_provisioning::keystore_dir_for(&inst));
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
        let keystore_a = std::env::temp_dir().join("kirby-keystore-kirby-alice");
        let spec_a = TenantLaunchSpec {
            agent_id: "alice".into(),
            allocation: alloc_a,
            treasury_path: crate::boot::treasury_path_for_agent("alice"),
            initial_sats: 333_000,
            frost_keystore_dir: keystore_a.clone(),
        };
        let cfg_a = launcher.derive_tenant_config(&spec_a);
        assert_eq!(cfg_a.agent_id, "alice");
        assert_eq!(cfg_a.node_id, "kirby-alice", "child node_id = instance id (DB-per-agent treasury)");
        assert_eq!(cfg_a.funding.initial_sats, 333_000);
        assert!(cfg_a.fleet.tenants.is_empty(), "the child must not inherit the tenant list");

        // FIX 3 (the gap-catching assertion): a derived FROST-tenant child config MUST carry
        // `identity.frost_keystore_dir = Some(<keystore>)` so that `agent_boot_config` builds a
        // `SocialConfig` with `frost_keystore_dir = Some(...)`, which makes `build_nostr_actuator`
        // take the FROST branch (the voice signs via the sovereign 2-of-3 Q, not the node key).
        // Before FIX 3 the child hardcoded `None` and this wiring was absent — the FROST branch
        // was dead in the real flow. This unit assertion on derive_tenant_config catches a
        // regression of that gap without a VM.
        assert_eq!(
            cfg_a.identity.frost_keystore_dir.as_deref(),
            Some(keystore_a.as_path()),
            "the FROST-tenant child must carry its provisioned keystore dir (else its voice signs \
             with the node key, not its sovereign Q — the FROST branch would be dead)"
        );

        // Two tenants derive DISTINCT node_ids => distinct treasury paths (the isolation
        // property the DB-per-agent design guarantees, G-TENANT-ISOLATION).
        let keystore_b = std::env::temp_dir().join("kirby-keystore-kirby-bob");
        let spec_b = TenantLaunchSpec {
            agent_id: "bob".into(),
            allocation: alloc_b,
            treasury_path: crate::boot::treasury_path_for_agent("bob"),
            initial_sats: 333_000,
            frost_keystore_dir: keystore_b.clone(),
        };
        let cfg_b = launcher.derive_tenant_config(&spec_b);
        // FIX 3: distinct tenants thread DISTINCT keystores (each its own sovereign Q).
        assert_eq!(cfg_b.identity.frost_keystore_dir.as_deref(), Some(keystore_b.as_path()));
        assert_ne!(
            cfg_a.identity.frost_keystore_dir, cfg_b.identity.frost_keystore_dir,
            "two FROST tenants must thread DISTINCT keystores (distinct sovereign Qs)"
        );
        assert_ne!(cfg_a.node_id, cfg_b.node_id, "two tenants must derive distinct node_ids");
        assert_ne!(
            crate::boot::treasury_path_for(&cfg_a.node_id),
            crate::boot::treasury_path_for(&cfg_b.node_id),
            "two tenants must get distinct treasury paths"
        );

        // Two tenants must also derive DISTINCT identity key paths. Without this they inherit
        // the base config's `identity.key_path` verbatim and race to create the SAME
        // `node.nostr.key` (exclusive `create_new` in nerve.rs) -- every tenant but the first
        // exits with EEXIST. This regresses the multi-tenant fleet to a single live tenant.
        assert_ne!(
            cfg_a.identity.key_path, cfg_b.identity.key_path,
            "two tenants must derive distinct identity key paths (else they collide on one npub)"
        );

        // P1-a (#74) + the dm-key-collision fix. Each tenant's `identity.treasury_dir` is its
        // OWN per-instance durable dir (`agent-<instance_id>`); WITHOUT this it falls back to
        // the SHARED config_dir and the dm/wallet keys collide across tenants on one host.
        assert!(
            cfg_a.identity.treasury_dir.as_ref().unwrap().ends_with("agent-kirby-alice"),
            "the child's treasury_dir must be its per-instance durable dir agent-<instance_id>"
        );
        assert_ne!(
            cfg_a.identity.treasury_dir, cfg_b.identity.treasury_dir,
            "two tenants must derive distinct treasury_dirs (the unified per-tenant fix)"
        );
        // RED-on-revert for the dm-key collision: the shipped DM key path is
        // `treasury_dir()/social.dm.key`; reverting the treasury_dir rewrite makes both fall
        // back to the shared config_dir => identical => this fails.
        assert_ne!(
            cfg_a.identity.treasury_dir().join("social.dm.key"),
            cfg_b.identity.treasury_dir().join("social.dm.key"),
            "the shipped per-agent DM key path must differ per tenant (no shared-config_dir collision)"
        );
        // The per-agent SOVEREIGN wallet store is per-tenant and lives under the tenant's
        // durable per-instance dir (#74: two tenants never share one wallet sled).
        assert_ne!(
            cfg_a.brain.wallet_db_path, cfg_b.brain.wallet_db_path,
            "two tenants must derive distinct per-agent wallet stores (#74)"
        );
        assert!(
            cfg_a.brain.wallet_db_path.contains("agent-kirby-alice")
                && cfg_a.brain.wallet_db_path.ends_with("wallet.sqlite"),
            "the per-agent wallet store lives under the tenant's per-instance durable dir"
        );
        // The api_key is a node-SHARED CUSTODIAL credential — NOT rewritten per-tenant (a
        // path-rewrite would point each tenant at a missing key file and refuse to boot;
        // per-agent custodial keys are key provisioning, a later chunk). Both inherit the
        // base verbatim => equal.
        assert_eq!(
            cfg_a.brain.api_key_path, cfg_b.brain.api_key_path,
            "api_key_path is node-shared custodial and must NOT be rewritten per-tenant"
        );
        assert_ne!(
            crate::nerve::NodeIdentity::resolve_key_path(
                Some(&cfg_a.identity.key_path),
                &cfg_a.identity.treasury_dir(),
            ),
            crate::nerve::NodeIdentity::resolve_key_path(
                Some(&cfg_b.identity.key_path),
                &cfg_b.identity.treasury_dir(),
            ),
            "two tenants must resolve to distinct node.nostr.key files"
        );
    }
}
