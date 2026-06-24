//! The fleet-host allocator (fleet-host S0, spec 2.1): the resource bookkeeping a
//! fleet supervisor owns so it can host many tenants on one node.
//!
//! Each tenant is an isolated genome with its OWN `guest_cid`, `instance_id`, and
//! `gateway_port` (the VM-isolation seam is already per-instance, sandbox.rs:359-368;
//! this is the allocation problem that sits in front of it, not a boundary redesign).
//! This module is PURE bookkeeping: it hands out distinct, non-colliding resource
//! triples, persists the live set so a supervisor restart never reuses a CID still
//! held by a live tenant, and rejects on exhaustion. It boots no VM, opens no
//! treasury, and signs nothing; the later slices wire it into the run path.
//!
//! INVARIANTS (gate G-ALLOC):
//!  - two LIVE tenants never share a CID or a gateway port;
//!  - allocation is rejected once `max_tenants` distinct slots are live (exhaustion);
//!  - a supervisor restart, reloading the persisted live set, never re-hands a CID
//!    that a still-live tenant holds.
//!
//! CID base: vsock reserves CIDs 0, 1, and 2, so the pool starts HIGH (config
//! `fleet.base_cid`, default 100). The allocator is additive and INERT for a
//! single-agent `kirby run`: nothing constructs it unless a fleet supervisor does.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::FleetConfig;

/// A tenant agent id (the `agent_id` label, config.rs). A `String` for now, matching
/// the rest of the codebase; the per-agent lease uses the same alias (raft_lease.rs).
pub type AgentId = String;

/// One tenant's allocated resource triple: its guest CID, its host-side instance id
/// (jail/cgroup/TAP derive from it, sandbox.rs:359-362), and its gateway vsock port.
/// Distinct per live tenant, by construction of [`Allocator`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantAllocation {
    /// The agent this slot belongs to.
    pub agent_id: AgentId,
    /// The guest CID for this tenant's vsock (one genome per CID, sandbox.rs:363-366).
    pub guest_cid: u32,
    /// The host instance id `kirby-<agent_id>` (host state namespaces off it).
    pub instance_id: String,
    /// The gateway vsock port the daemon serves this tenant on (sandbox.rs:367-368).
    pub gateway_port: u32,
}

/// The derived host instance id for an agent: `kirby-<agent_id>`. Deterministic, so a
/// supervisor restart reconstitutes the SAME jail/cgroup/TAP names for the agent
/// (sandbox.rs:359-362). Public so callers outside the allocator (e.g. a restore path)
/// can derive the same id without re-allocating.
pub fn instance_id_for(agent_id: &str) -> String {
    format!("kirby-{agent_id}")
}

/// What went wrong when the allocator could not satisfy a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocError {
    /// The per-host tenant ceiling (`max_tenants`) is reached: no free slot remains.
    Exhausted { max_tenants: u32, live: u32 },
    /// This agent already holds a live allocation (allocation is at-most-once per
    /// agent; the caller should reuse the existing slot, not re-allocate).
    AlreadyAllocated { agent_id: AgentId },
    /// The CID space wrapped (a pathological `base_cid` near `u32::MAX`); refuse
    /// rather than overflow into a reserved/colliding CID.
    CidSpaceOverflow,
}

impl std::fmt::Display for AllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllocError::Exhausted { max_tenants, live } => write!(
                f,
                "fleet allocator exhausted: {live} live tenant(s) at the max_tenants={max_tenants} ceiling"
            ),
            AllocError::AlreadyAllocated { agent_id } => {
                write!(f, "fleet allocator: agent {agent_id:?} already holds a live allocation")
            }
            AllocError::CidSpaceOverflow => {
                write!(f, "fleet allocator: CID space overflowed (base_cid too high for max_tenants)")
            }
        }
    }
}

impl std::error::Error for AllocError {}

/// The persisted allocator state: the set of LIVE tenant allocations, keyed by agent.
/// Persisted as JSON so a supervisor restart reloads exactly which CIDs/ports are held
/// and never re-hands a live one. The map is the single source of truth; the next free
/// CID/port is derived from it on every allocate (no separate counter to desync).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AllocatorState {
    live: BTreeMap<AgentId, TenantAllocation>,
}

/// The fleet resource allocator (spec 2.1). Owns the live tenant set and the policy
/// (base CID, base port, max tenants) from `[fleet]` config. Hands out distinct
/// CID/instance_id/gateway_port triples, persists the live set, and rejects on
/// exhaustion. Additive + inert: only a fleet supervisor constructs one.
pub struct Allocator {
    base_cid: u32,
    gateway_port_base: u32,
    max_tenants: u32,
    /// Where the live set is persisted (JSON). `None` for an in-memory allocator
    /// (tests / a supervisor that never restarts); `Some` persists every mutation.
    persist_path: Option<PathBuf>,
    state: AllocatorState,
}

impl Allocator {
    /// A fresh in-memory allocator from `[fleet]` config (no persistence). Suitable
    /// for a single supervisor lifetime or tests; a restart loses the live set, so a
    /// long-lived supervisor uses [`Allocator::load_or_new`] with a persist path.
    pub fn new(fleet: &FleetConfig) -> Self {
        Allocator {
            base_cid: fleet.base_cid,
            gateway_port_base: fleet.gateway_port_base,
            max_tenants: fleet.max_tenants,
            persist_path: None,
            state: AllocatorState::default(),
        }
    }

    /// Load the allocator from a persisted live set at `path`, or start empty if the
    /// file is absent. The reloaded live set is authoritative: a CID/port a live
    /// tenant holds is honored and never re-handed (the restart-no-reuse invariant,
    /// gate G-ALLOC). A corrupt/unreadable file is an error (better to refuse than to
    /// silently lose track of live tenants and double-allocate a CID).
    pub fn load_or_new(fleet: &FleetConfig, path: &Path) -> anyhow::Result<Self> {
        let state = if path.exists() {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("read fleet allocator state {}: {e}", path.display()))?;
            serde_json::from_slice::<AllocatorState>(&bytes).map_err(|e| {
                anyhow::anyhow!("parse fleet allocator state {}: {e}", path.display())
            })?
        } else {
            AllocatorState::default()
        };
        Ok(Allocator {
            base_cid: fleet.base_cid,
            gateway_port_base: fleet.gateway_port_base,
            max_tenants: fleet.max_tenants,
            persist_path: Some(path.to_path_buf()),
            state,
        })
    }

    /// The number of LIVE tenants currently allocated.
    pub fn live_count(&self) -> u32 {
        self.state.live.len() as u32
    }

    /// The live allocation for an agent, if any.
    pub fn allocation_for(&self, agent_id: &str) -> Option<&TenantAllocation> {
        self.state.live.get(agent_id)
    }

    /// Allocate a fresh resource triple for `agent_id`. Picks the LOWEST free CID at or
    /// above `base_cid` not held by a live tenant (so a released slot is reused, but a
    /// LIVE slot never is), the matching gateway port at the same offset, and the
    /// deterministic instance id. Persists the new live set before returning.
    ///
    /// Rejects (debits no slot) when: the agent already holds a live allocation
    /// (at-most-once per agent); the live count is at the `max_tenants` ceiling
    /// (exhaustion); or the CID space would overflow. On any rejection the live set is
    /// unchanged and nothing is persisted.
    pub fn allocate(&mut self, agent_id: &str) -> Result<TenantAllocation, AllocError> {
        if self.state.live.contains_key(agent_id) {
            return Err(AllocError::AlreadyAllocated { agent_id: agent_id.to_string() });
        }
        if self.live_count() >= self.max_tenants {
            return Err(AllocError::Exhausted {
                max_tenants: self.max_tenants,
                live: self.live_count(),
            });
        }
        // Pick the lowest CID offset whose CID is not held by a live tenant. Bounded
        // by max_tenants live tenants, so at most max_tenants offsets are occupied;
        // the search terminates at the first free offset within [0, max_tenants].
        let occupied_cids: std::collections::BTreeSet<u32> =
            self.state.live.values().map(|a| a.guest_cid).collect();
        let mut offset: u32 = 0;
        let guest_cid = loop {
            let cid = self
                .base_cid
                .checked_add(offset)
                .ok_or(AllocError::CidSpaceOverflow)?;
            if !occupied_cids.contains(&cid) {
                break cid;
            }
            offset = offset.checked_add(1).ok_or(AllocError::CidSpaceOverflow)?;
        };
        let gateway_port = self
            .gateway_port_base
            .checked_add(offset)
            .ok_or(AllocError::CidSpaceOverflow)?;
        let allocation = TenantAllocation {
            agent_id: agent_id.to_string(),
            guest_cid,
            instance_id: instance_id_for(agent_id),
            gateway_port,
        };
        self.state.live.insert(agent_id.to_string(), allocation.clone());
        self.persist()
            .map_err(|_| {
                // Roll back the in-memory insert so a failed persist never leaves the
                // allocator believing a slot is live that did not durably commit.
                self.state.live.remove(agent_id);
                AllocError::Exhausted { max_tenants: self.max_tenants, live: self.live_count() }
            })?;
        Ok(allocation)
    }

    /// Release a live tenant's slot (the tenant died / was reaped), freeing its CID and
    /// port for reuse. Returns the freed allocation, or `None` if the agent held none.
    /// Persists the shrunk live set.
    pub fn release(&mut self, agent_id: &str) -> Option<TenantAllocation> {
        let freed = self.state.live.remove(agent_id);
        if freed.is_some() {
            // A persist failure on release is logged but not fatal: the worst case is a
            // CID stays marked live (conservative, never a double-allocation).
            if let Err(e) = self.persist() {
                tracing::error!(error = %e, agent_id, "fleet allocator: persist after release failed");
            }
        }
        freed
    }

    /// Persist the live set to disk if a persist path is configured. Writes atomically
    /// via a temp file + rename so a crash mid-write never leaves a truncated state file
    /// that would lose track of live tenants.
    fn persist(&self) -> anyhow::Result<()> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| anyhow::anyhow!("encode fleet allocator state: {e}"))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| anyhow::anyhow!("write fleet allocator state {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| anyhow::anyhow!("rename fleet allocator state into {}: {e}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet(base_cid: u32, max_tenants: u32, port_base: u32) -> FleetConfig {
        FleetConfig { base_cid, max_tenants, gateway_port_base: port_base, tenants: Vec::new() }
    }

    /// G-ALLOC core: N tenants get DISTINCT CID/instance_id/gateway_port, and the CID
    /// stays above the vsock-reserved range. Also pins the deterministic instance id.
    #[test]
    fn hands_distinct_triples_to_n_tenants() {
        let mut alloc = Allocator::new(&fleet(100, 8, 9000));
        let mut cids = std::collections::BTreeSet::new();
        let mut ports = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for n in 0..5 {
            let a = alloc.allocate(&format!("agent-{n}")).expect("allocate");
            assert!(a.guest_cid > 2, "CID must avoid the vsock-reserved 0..=2, got {}", a.guest_cid);
            assert_eq!(a.instance_id, format!("kirby-agent-{n}"));
            assert!(cids.insert(a.guest_cid), "duplicate CID {}", a.guest_cid);
            assert!(ports.insert(a.gateway_port), "duplicate port {}", a.gateway_port);
            assert!(ids.insert(a.instance_id.clone()), "duplicate instance id {}", a.instance_id);
        }
        assert_eq!(alloc.live_count(), 5);
    }

    /// G-ALLOC TEETH: never hand the same CID/port to two LIVE tenants. Allocating for
    /// the same agent twice is rejected (at-most-once), and across distinct agents the
    /// CID/port sets are disjoint.
    #[test]
    fn never_two_live_tenants_on_one_cid_or_port() {
        let mut alloc = Allocator::new(&fleet(100, 8, 9000));
        let a = alloc.allocate("agent-a").expect("allocate a");
        // Re-allocating the SAME live agent is refused (no second slot, no CID reuse).
        let err = alloc.allocate("agent-a").unwrap_err();
        assert_eq!(err, AllocError::AlreadyAllocated { agent_id: "agent-a".into() });
        let b = alloc.allocate("agent-b").expect("allocate b");
        assert_ne!(a.guest_cid, b.guest_cid, "two live tenants share a CID");
        assert_ne!(a.gateway_port, b.gateway_port, "two live tenants share a port");
    }

    /// G-ALLOC TEETH: reject on exhaustion. Once `max_tenants` slots are live, the next
    /// allocate is `Exhausted` and allocates nothing.
    #[test]
    fn rejects_on_exhaustion() {
        let mut alloc = Allocator::new(&fleet(100, 3, 9000));
        for n in 0..3 {
            alloc.allocate(&format!("agent-{n}")).expect("allocate within cap");
        }
        let err = alloc.allocate("agent-overflow").unwrap_err();
        assert_eq!(err, AllocError::Exhausted { max_tenants: 3, live: 3 });
        assert_eq!(alloc.live_count(), 3, "a rejected allocate must not consume a slot");
        // Releasing one frees exactly one slot, and the freed CID is then reusable.
        let freed = alloc.release("agent-0").expect("release a live tenant");
        let reused = alloc.allocate("agent-3").expect("allocate after a release");
        assert_eq!(reused.guest_cid, freed.guest_cid, "the freed CID is reused, not grown");
    }

    /// G-ALLOC TEETH (the load-bearing one): a supervisor restart, reloading the
    /// persisted live set, NEVER re-hands a CID still held by a live tenant. We persist
    /// two live tenants, drop the allocator (a restart), reload from disk, and allocate
    /// a third: its CID must differ from BOTH live CIDs.
    #[test]
    fn restart_never_reuses_a_live_cid() {
        let dir = std::env::temp_dir().join(format!(
            "kirby-fleet-alloc-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alloc.json");
        let cfg = fleet(100, 8, 9000);

        let (cid_a, cid_b);
        {
            let mut alloc = Allocator::load_or_new(&cfg, &path).expect("fresh load");
            cid_a = alloc.allocate("agent-a").expect("alloc a").guest_cid;
            cid_b = alloc.allocate("agent-b").expect("alloc b").guest_cid;
            // alloc dropped here => "supervisor restart"
        }
        // Reload from the persisted live set and allocate a third tenant.
        let mut reloaded = Allocator::load_or_new(&cfg, &path).expect("reload");
        assert_eq!(reloaded.live_count(), 2, "the live set survived the restart");
        let cid_c = reloaded.allocate("agent-c").expect("alloc c after restart").guest_cid;
        assert_ne!(cid_c, cid_a, "restart re-handed a live CID (agent-a)");
        assert_ne!(cid_c, cid_b, "restart re-handed a live CID (agent-b)");

        // And a tenant released BEFORE the restart frees its CID for post-restart reuse.
        reloaded.release("agent-a");
        let mut reloaded2 = Allocator::load_or_new(&cfg, &path).expect("reload 2");
        let cid_d = reloaded2.allocate("agent-d").expect("alloc d").guest_cid;
        assert_eq!(cid_d, cid_a, "a released CID should be reusable after a restart");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
