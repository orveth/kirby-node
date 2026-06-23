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

/// The Nostr event kind for a Kirby agent's LIVE state (the "Kirby face": current
/// treasury, runway, lifecycle phase).
///
/// Unlike the append-only 9100 birth/death log, this is an ADDRESSABLE event kind
/// (30000..40000, per NIP-01): keyed by a `d` tag set to the `agent_id`, the relay
/// keeps only the LATEST event per `(pubkey, kind, d)`. The agent re-publishes it
/// on its presence cadence with the live treasury balance, so the current event IS
/// the agent's current state; frequent updates are cheap (each replaces the prior).
///
/// The content JSON is `{ agent_id, treasury_sats, runway_secs, lifecycle, backend,
/// lease_holder_node, lease_term }` and the tags are `["d",<agent_id>]`,
/// `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`, per the unified
/// event-kinds contract (`plans/kirby-cluster-event-kinds-20260619.md`). It lives
/// here in the shared contract crate so every node and the UI agree on one value.
pub const KIND_KIRBY_AGENT_STATE: u16 = 31000;

/// The Nostr event kind for a Kirby agent's WAKE-REQUEST (the hibernation
/// commitment: an agent has sealed its state to sleep, and this is the public,
/// signed record of how to wake it — the `wake_at` timer, the immutable
/// `bundle_digest`, the genome `image_ref`, and the `seal` block naming the share
/// holders + threshold). The JSON content shape is the `hibernate::WakeRequest`
/// payload (`{ wake_at, bundle_digest, image_ref, seal, resume_seq, solvency_hint }`).
///
/// This is an ADDRESSABLE event kind (30000..40000, per NIP-01): keyed by a `d` tag
/// set to the `agent_id`, the relay keeps only the LATEST event per
/// `(pubkey, kind, d)`. ADDRESSABLE, not REPLACEABLE (10000..20000), for two reasons:
///   1. **Discovery returns the current commitment, no stale pile-up.** A re-seal
///      (a bumped `seal_epoch` / pushed-back `wake_at`) publishes a new addressable
///      event that REPLACES the prior wake-request for that agent, so a waker always
///      reads the live commitment — unlike a REGULAR/stored kind (e.g. 9100), which
///      would accumulate every wake-request ever and force created_at de-duping.
///   2. **Multi-agent-per-node stays open (the agent-scoped discipline).** A
///      REPLACEABLE kind is keyed by `(pubkey, kind)` only, so a second agent on the
///      same node (Move-2) would CLOBBER the first's wake-request. Keying on
///      `d = agent_id` gives one wake-request PER AGENT — the same reasoning that
///      made 31000 agent-state addressable.
///
/// The content JSON is the `WakeRequest` payload and the tags are `["d",<agent_id>]`
/// (the addressable key), `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`
/// (the unified vocabulary), plus `["x",<bundle_digest>]` — the indexable single-letter
/// hash tag (NIP-94 convention: `x` = sha256) so a waker can `#x`-filter the relay to
/// fetch a wake-request by its `bundle_digest`. It lives here in the shared contract
/// crate so every node agrees on one value with no central registry (thin slice H3,
/// `plans/build-spec-kirby-hibernation-thinslice.md`).
pub const KIND_KIRBY_WAKE_REQUEST: u16 = 31001;

pub mod gateway {
    //! Generated tonic types for `kirby.gateway.v1`.
    tonic::include_proto!("kirby.gateway.v1");
}

pub use gateway::*;
