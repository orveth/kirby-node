//! The genome to daemon gateway contract (spec 3.1 and 3.2).
//!
//! Both the daemon (gRPC server) and the genome (gRPC client) depend on this
//! crate, so the wire shape and the schema_version have a single source of
//! truth. The service logic (the spec 3.2 authorize order) lives in the daemon,
//! not here; this crate is types only.

/// The current additive-only schema version for every gateway message.
pub const SCHEMA_VERSION: u32 = 1;

/// The Nostr event kind for a Kirby node's presence beacon (the "nerve" slice 1).
///
/// This is the cross-node agreed constant: every node publishes its presence as a
/// REPLACEABLE Nostr event of this kind, and subscribes to `{kinds:[this]}` (all
/// authors) to discover the live fleet. It lives here, in the shared contract
/// crate, so all nodes agree on one value with no central registry.
///
/// The value `10100` is in the Nostr REPLACEABLE range (10000..20000, per NIP-01),
/// so a relay keeps only the LATEST event per node pubkey: re-publishing on an
/// interval bumps `created_at` and replaces the prior beacon, and a node that stops
/// publishing leaves a beacon whose `created_at` goes stale (the death signal).
///
/// It is a plain `u16` so the musl genome (which also depends on this crate) pays
/// no weight for it; only the daemon (host-side) maps it to a `nostr` `Kind`.
pub const KIND_KIRBY_PRESENCE: u16 = 10100;

/// The Nostr event kind for a Kirby agent's lifecycle milestone (born / died).
///
/// Unlike the replaceable presence beacon, this is a REGULAR (stored) event kind
/// (1000..10000, per NIP-01), so the relay KEEPS every one: it is the signed,
/// append-only birth/death log of an agent. A sovereign node emits exactly one
/// `born` when its agent boots (content reason "funded") and exactly one `died`
/// when its agent's budget is exhausted or it shuts down (content reason "broke").
///
/// The content JSON is `{ agent_id, event, treasury_sats, reason }` and the tags
/// are `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`, per the unified
/// event-kinds contract (`plans/kirby-cluster-event-kinds-20260619.md`). It lives
/// here in the shared contract crate so every node and the UI agree on one value.
pub const KIND_KIRBY_LIFECYCLE: u16 = 9100;

pub mod gateway {
    //! Generated tonic types for `kirby.gateway.v1`.
    tonic::include_proto!("kirby.gateway.v1");
}

pub use gateway::*;
