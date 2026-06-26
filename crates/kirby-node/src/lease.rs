//! The lease SEAM + its shared value types (the no-split-brain fence the gateway money-path
//! and the fleet supervisor read through). This module is TRANSPORT-FREE: it defines only the
//! trait and the small value types every lease implementation shares, so the concrete
//! mechanism (today the relay-native FROST-signed [`crate::relay_lease::RelayLeaseAuthority`],
//! tomorrow an iroh-QUIC partition-safe Raft) can be swapped WITHOUT touching the gateway or
//! the supervisor.
//!
//! THE INVARIANT (build-spec `build-spec-kirby-failover-relay-lease-20260625.md` 2-4): for
//! each agent, at most one node holds the active lease at the latest term. A node ACTS for an
//! agent only while it holds that latest term; a failover node claims `term + 1` (a monotonic
//! fencing token); a node that cannot confirm it is the latest term stands down. The gateway
//! money-path gates every debit on [`LeaseAuthority::fence_for`], so a fenced node debits 0
//! (no double-burn) -- the single-writer fence that, with the mint's global serialization,
//! keeps money safe across a failover.
//!
//! WHY this was cut out of the loopback-Raft cluster (build-spec 1, 3): the loopback Raft lease
//! was SAME-HOST only (plain-TCP Raft cannot form across NAT). Cross-machine failover is now
//! the goal, so the lease rides the SAME Nostr relay that already does NAT traversal for
//! presence / FROST cosign. The `LeaseAuthority` SEAM survives the cut intact; only the
//! mechanism behind it changed.

use serde::{Deserialize, Serialize};

/// A node id in the lease fabric. A small integer label for a node; stable for the node's
/// life. Carried in a lease so the fence can name the holder.
pub type LeaseNodeId = u64;

/// A tenant agent id, the key of the per-agent lease (fleet-host S1). A `String`, matching
/// the rest of the codebase (`agent_id` is a plain label, config.rs) and the allocator's
/// [`crate::fleet::AgentId`]. A host runs N agents, each fenced independently, so the lease is
/// keyed by agent, not global.
pub type AgentId = String;

/// The default agent slot for the SINGLE-AGENT path (fleet off). A bare `kirby run`
/// claims/observes/fences against this one reserved slot, so the per-agent behavior degrades
/// to exactly the old single-value behavior. Real fleet `agent_id` labels are non-empty, so
/// they never collide with this sentinel.
pub const DEFAULT_AGENT: &str = "";

/// The active lease value: who holds the agent, at what monotonic term. The whole
/// no-split-brain invariant is a property of, for a given agent, exactly one `{node_id, term}`
/// being the latest authoritative lease.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveLease {
    pub node_id: LeaseNodeId,
    pub term: u64,
}

/// The reply to a lease GRANT/claim: the lease as it stands after the claim (the granted node
/// and the term stamped). Returned to the caller so it learns the term it now holds. Kept as a
/// shared type so the write-side seam ([`crate::fleet_supervisor::LeaseGrantor`]) is
/// mechanism-neutral.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseResponse {
    /// The node that holds the active lease after the claim (the grantee).
    pub node_id: LeaseNodeId,
    /// The term stamped on the lease.
    pub term: u64,
}

/// THE LEASE SEAM: exactly what the gateway money-fence and the fleet supervisor need from the
/// lease, behind a trait so the concrete lease implementation can be swapped WITHOUT touching
/// the gateway. The gateway holds it as `Arc<dyn LeaseAuthority>` (like the `Rail` /
/// `MemoryBackend` seams).
///
/// The trait is deliberately MINIMAL: it is the read-side the fence + supervisor use to answer
/// "may THIS node act for `agent_id` right now?" and "what term is it active at?" It does NOT
/// expose granting (that is impl-specific: a Raft `client_write` vs a FROST ceremony), so a
/// caller behind the trait cannot mutate the lease, only read it. This keeps the seam
/// read-only and the no-split-brain guarantee owned by the concrete impl.
///
/// Object-safe via `async_trait`, and `Send + Sync` so it crosses the serve tasks.
#[async_trait::async_trait]
pub trait LeaseAuthority: Send + Sync {
    /// This node's id (for evidence/logging on a fence-deny). Stable for the impl's life.
    fn node_id(&self) -> LeaseNodeId;

    /// The active lease for `agent_id`, or `None` if none is active for it (none observed, or
    /// the latest has gone stale). Reads ONLY this agent's entry, so it never reports another
    /// agent's holder.
    async fn active_lease_for(&self, agent_id: &str) -> Option<ActiveLease>;

    /// THE ACTIVE-NODE CHECK for `agent_id`: the term THIS node is active at for the agent
    /// (it holds the agent's latest non-stale lease), or `None` (not active for this agent).
    /// The supervisor uses this to confirm a tenant it launched genuinely holds its agent's
    /// lease.
    async fn active_term_for(&self, agent_id: &str) -> Option<u64>;

    /// THE TERM-FENCE for `agent_id` for a node that BELIEVES it is active at `believed_term`:
    /// `Active` only if the current lease for the agent still names this node at a term >=
    /// `believed_term`; otherwise `Fenced`. This is the single check the gateway money-path
    /// gates every debit on.
    async fn fence_for(&self, agent_id: &str, believed_term: u64) -> FenceVerdict;
}

/// The outcome of a term-fence check. `Active` means the node still holds the lease at a
/// current-enough term and may run/debit; `Fenced` means a higher term superseded it (the
/// lease moved, or it went stale), so it must NOT run or debit (no double-execute / no
/// double-burn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceVerdict {
    /// The node holds the lease at `term` (>= what it believed); proceed.
    Active { term: u64 },
    /// The node is fenced: the latest lease is at `committed_term` held by `committed_holder`,
    /// which superseded this node's `believed_term`. Do NOT run or debit.
    Fenced {
        committed_term: u64,
        committed_holder: LeaseNodeId,
        believed_term: u64,
    },
}

impl FenceVerdict {
    /// Whether the node may run/debit (true only for `Active`). The run/restore path and the
    /// debit path both gate on this.
    pub fn may_act(&self) -> bool {
        matches!(self, FenceVerdict::Active { .. })
    }
}

/// THE SPAWN FENCE READ-SIDE: exactly what the spawn consumer needs to answer "is `agent_id`
/// already held by a FRESH lease, and by which node?" before it launches — the claim-before-
/// launch fence that closes the cross-node DOUBLE-SPAWN (resilience finding G-1: a retained
/// spawn request re-delivered to a second node would otherwise launch a duplicate).
///
/// Deliberately NARROWER than [`LeaseAuthority`]: it exposes only `node_id` + `active_lease_for`,
/// and NONE of the money-fence methods (`fence_for` / `active_term_for`). This is on purpose —
/// the double-spawn guard must NEVER be mistaken for, or wired as, the gateway's money
/// safety-fence. The blanket impl below lets a fully Q-VERIFIED [`LeaseAuthority`] satisfy this
/// seam directly (so once cross-machine keyset sharing lands — G-2 — the spawn fence can verify
/// the peer lease under the agent's quorum), while a cooperative occupancy view
/// (`crate::relay_lease::FleetLeaseObserver`) satisfies it today without that key.
#[async_trait::async_trait]
pub trait SpawnFenceView: Send + Sync {
    /// This node's id. The consumer backs off ONLY when a fresh lease names a node OTHER than
    /// this one (a same-node lease, or none, lets the spawn proceed — same-node idempotency is
    /// the durable spawned-set's job).
    fn node_id(&self) -> LeaseNodeId;

    /// The fresh active lease for `agent_id`, or `None` if none is held (none observed, or the
    /// latest has gone stale). A `Some` whose `node_id` differs from [`Self::node_id`] means
    /// another node already hosts the agent → the consumer must NOT launch a duplicate.
    async fn active_lease_for(&self, agent_id: &str) -> Option<ActiveLease>;
}

/// A fully Q-VERIFIED [`LeaseAuthority`] is a strictly stronger fence than the cooperative
/// occupancy view, so it satisfies [`SpawnFenceView`] directly. This is the path the spawn
/// fence upgrades to once an agent's keyset is shared across nodes (G-2): the consumer then
/// backs off only on a lease it has cryptographically verified under the agent's quorum Q.
#[async_trait::async_trait]
impl SpawnFenceView for std::sync::Arc<dyn LeaseAuthority> {
    // UFCS (`LeaseAuthority::method(&**self, ..)`) is deliberate: `Arc<dyn LeaseAuthority>` now
    // ALSO implements `SpawnFenceView`, so a bare `self.node_id()` would re-resolve to THIS impl
    // (infinite recursion). Forcing the call onto `&dyn LeaseAuthority` selects the inner method.
    fn node_id(&self) -> LeaseNodeId {
        LeaseAuthority::node_id(&**self)
    }
    async fn active_lease_for(&self, agent_id: &str) -> Option<ActiveLease> {
        LeaseAuthority::active_lease_for(&**self, agent_id).await
    }
}
