//! The genome to daemon gateway contract (spec 3.1 and 3.2).
//!
//! Both the daemon (gRPC server) and the genome (gRPC client) depend on this
//! crate, so the wire shape and the schema_version have a single source of
//! truth. The service logic (the spec 3.2 authorize order) lives in the daemon,
//! not here; this crate is types only.

/// The current additive-only schema version for every gateway message.
pub const SCHEMA_VERSION: u32 = 1;

/// The actuator kind (and per-kind allowlist token) for a Nostr publish: the FIRST
/// outward actuator (the agent's first voice to the world). The genome sets
/// `Actuate.kind` to this; the daemon's `destination` returns it (so a workload whose
/// allowlist lacks this token issues ZERO publishes at the gateway allowlist step); and
/// the daemon's actuator handler dispatches on it. It lives here, in the shared contract
/// crate, so the genome (which builds the request) and the daemon (which gates + performs
/// it) agree on ONE value with no central registry.
pub const ACTUATE_KIND_NOSTR_PUBLISH: &str = "nostr.publish";

/// The only Nostr event kind the `nostr.publish` actuator may emit in the MVP: 1, a public
/// text note (NIP-01). The daemon RESTRICTS the publishable kind to this (defense in depth,
/// the handler is a new entry point); a payload naming any other kind is refused. A `u16`
/// so the musl genome pays no weight; the daemon maps it to a `nostr` `Kind`.
pub const NOSTR_KIND_TEXT_NOTE: u16 = 1;

/// The hard byte cap on a single published note's text (the agent's public voice is one
/// sane `kind:1` line). The GENOME sanitizes + caps to this before requesting a publish,
/// and the DAEMON independently RE-CAPS to it (it never trusts the genome's cap; the
/// handler is a new entry point). Shared here so the two bounds cannot drift. An over-cap
/// note is REFUSED (a wasted think + feedback), never truncated (truncation could sever a
/// multibyte char or silently post a half-thought).
pub const MAX_NOTE_BYTES: usize = 512;

/// Sanitize + validate model-generated note text into ONE safe public line: the SHARED
/// publish-note guard. Both the GENOME (before it requests a publish) and the DAEMON (before it
/// signs + sends, defense in depth as a NEW entry point) call this INDEPENDENTLY, so the two
/// sides enforce the SAME rule with no drift while neither trusts the other did it. The rule:
/// every control character AND the Unicode line/paragraph separators (U+2028 / U+2029, which
/// render as line breaks but are NOT `char::is_control`) are mapped to a space, then whitespace
/// runs are collapsed and the ends trimmed; the result must be non-empty and within
/// [`MAX_NOTE_BYTES`]. An over-cap note is REFUSED (`Err`), never truncated (truncation could
/// sever a multibyte char or post a half-thought). Returns the clean single-line note, or a
/// human-readable reason. Total: any input either yields a clean line or a reason, never panics.
pub fn sanitize_note_for_publish(raw: &str) -> Result<String, String> {
    let spaced: String = raw
        .chars()
        .map(|c| {
            if c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
                ' '
            } else {
                c
            }
        })
        .collect();
    // `split_whitespace` drops the (now whitespace-only) runs and trims the ends; `join(" ")`
    // re-joins with exactly one space. Non-whitespace content is preserved verbatim.
    let clean = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        return Err("note text is empty after stripping control characters and whitespace".into());
    }
    if clean.len() > MAX_NOTE_BYTES {
        return Err(format!(
            "note text exceeds the {MAX_NOTE_BYTES}-byte cap ({} bytes after sanitizing)",
            clean.len()
        ));
    }
    Ok(clean)
}

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

/// NIP-90 (Data Vending Machine) JOB REQUEST kind range, inclusive: a relay event whose
/// kind falls in `[5000, 5999]` is a DVM job request -- the earn trigger (earn-loop
/// Component 1, the inbound surface). The daemon maps any kind in this range to
/// [`InboundKind::JobRequest`] in its fixed host-side allowlist table (`nerve.rs`); a
/// kind OUTSIDE this range (and not another allowlisted kind) is dropped (default-deny).
/// Job RESULTS are 6000-6999 and FEEDBACK is 7000 (the agent EMITS those via the
/// actuator; it does not receive them), so only the request range maps inbound here.
/// Shared in the contract crate so the host allowlist and any future genome-side
/// classification agree on one range with no central registry.
pub const NIP90_JOB_REQUEST_KIND_MIN: u16 = 5000;
pub const NIP90_JOB_REQUEST_KIND_MAX: u16 = 5999;

/// The Nostr event kind for a Kirby agent's CROSS-MACHINE LEASE (the NAT-friendly,
/// relay-native failover claim that supersedes the loopback Raft lease for
/// cross-machine fleets).
///
/// A lease names which node is the active holder of an agent at a given monotonic
/// `term`. A node ACTS for the agent only if it holds the LATEST observed `term`;
/// failover claims `term + 1` (a monotonic fencing token). The lease is FROST-signed
/// by the agent's OWN quorum key Q -- a node cannot forge a claim for an agent whose
/// shares it does not hold, so failover authority is tied to the agent's own quorum,
/// NOT to node identity.
///
/// This is an ADDRESSABLE event kind (30000..40000, per NIP-01): keyed by a `d` tag
/// set to the `agent_id`, the relay keeps only the LATEST event per `(pubkey, kind, d)`.
/// ADDRESSABLE for the same reasons 31000/31001 are: a re-publish (a heartbeat refresh,
/// or a failover `term + 1`) REPLACES the prior lease for that agent rather than piling
/// up, and keying on `d = agent_id` keeps multi-agent-per-node open (a second agent's
/// lease cannot clobber the first's). Latest-wins is by the monotonic `term` in the
/// content, NOT by `created_at`, so an observer never moves a term backward.
///
/// The content JSON is `{ agent_id, holder_node_id, term, issued_at }` and the tags are
/// `["d",<agent_id>]`, `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`, per the
/// unified event-kinds vocabulary. It lives here, in the shared contract crate, so every
/// node agrees on one value with no central registry. A `u16` so the musl genome pays no
/// weight; only the daemon (host-side) maps it to a `nostr` `Kind`.
pub const KIND_KIRBY_LEASE: u16 = 31002;

/// The Nostr event kind for a Kirby SPAWN REQUEST — the signed relay event that asks
/// any node in the fleet to create (spawn) an agent. This is the control-plane trigger
/// that lets a user/operator create an agent on a node they do not run, INCLUDING a node
/// behind a LAN/NAT (the node makes only OUTBOUND relay connections: it subscribes to see
/// the request, claims the agent via the relay-lease, and launches — no inbound port).
///
/// Unlike the other KIND_KIRBY_* events, a spawn request is NOT signed by the agent's
/// quorum key Q — the agent does not exist yet. It is signed by the REQUESTER (the
/// operator/creator key in the three-keys model); a node verifies that signature
/// (the inbound trust boundary) and then runs the spawn through the authorization SEAM
/// (the anti-spam / network-join gate, pops-ready) before it ever claims or launches.
///
/// This is an ADDRESSABLE event kind (30000..40000, per NIP-01): keyed by a `d` tag set
/// to the `agent_id`, the relay keeps only the LATEST request per `(pubkey, kind, d)` —
/// a re-issued request (bumped funding/config) REPLACES the prior one rather than piling
/// up, and keying on `d = agent_id` keeps the per-agent discipline (one pending request
/// per agent identity). Idempotency of the LAUNCH is enforced downstream by the
/// relay-lease CLAIM (exactly one node launches a given agent_id), not by the relay's
/// addressable de-dup.
///
/// The content JSON is `{ agent_id, genome_config, image_ref, funding, requester_pubkey }`,
/// bounded + validated host-side (a NEW attacker-controlled entry point), and the tags are
/// `["d",<agent_id>]`, `["t","kirby"]`, `["a",<agent_id>]`. It lives here in the shared
/// contract crate so every node and the UI agree on one value with no central registry.
pub const KIND_KIRBY_SPAWN_REQUEST: u16 = 31003;

pub mod gateway {
    //! Generated tonic types for `kirby.gateway.v1`.
    tonic::include_proto!("kirby.gateway.v1");
}

pub use gateway::*;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the SHARED publish-note guard (P3-sanitize teeth, enforced by genome AND daemon) ----

    #[test]
    fn clean_note_passes_through_unchanged() {
        assert_eq!(
            sanitize_note_for_publish("the relay has been quiet for three ticks").unwrap(),
            "the relay has been quiet for three ticks"
        );
    }

    #[test]
    fn control_chars_are_stripped() {
        // NUL, bell, ESC, DEL: not whitespace, so they would survive a naive split_whitespace;
        // the explicit is_control mapping turns them into spaces, then they collapse away.
        let dirty = "hi\u{0}\u{7}there\u{1b}\u{7f}friend";
        assert_eq!(sanitize_note_for_publish(dirty).unwrap(), "hi there friend");
    }

    #[test]
    fn newlines_collapse_to_a_single_line() {
        assert_eq!(
            sanitize_note_for_publish("line one\nline two\r\nline three").unwrap(),
            "line one line two line three"
        );
        assert!(!sanitize_note_for_publish("a\nb").unwrap().contains('\n'));
    }

    #[test]
    fn unicode_line_separators_are_stripped() {
        // FIX-6: U+2028 (LS) / U+2029 (PS) render as breaks but are NOT char::is_control. A note
        // must not be able to smuggle a multi-line payload onto a relay through them.
        let smuggle = "first\u{2028}second\u{2029}third";
        let clean = sanitize_note_for_publish(smuggle).unwrap();
        assert!(!clean.contains('\u{2028}') && !clean.contains('\u{2029}'));
        assert_eq!(clean, "first second third");
    }

    #[test]
    fn whitespace_runs_collapse_and_ends_trim() {
        assert_eq!(
            sanitize_note_for_publish("  hello\t\t  world   ").unwrap(),
            "hello world"
        );
    }

    #[test]
    fn empty_or_blank_is_rejected() {
        assert!(sanitize_note_for_publish("").is_err());
        assert!(sanitize_note_for_publish("    \t\n  ").is_err());
        assert!(sanitize_note_for_publish("\u{0}\u{2028}\r\n").is_err());
    }

    #[test]
    fn over_cap_is_refused_and_the_boundary_is_accepted() {
        let over = "x".repeat(MAX_NOTE_BYTES + 1);
        assert!(sanitize_note_for_publish(&over).is_err());
        // Exactly the cap is accepted (refused means strictly greater).
        let at = "x".repeat(MAX_NOTE_BYTES);
        assert_eq!(
            sanitize_note_for_publish(&at).unwrap().len(),
            MAX_NOTE_BYTES
        );
    }

    #[test]
    fn multibyte_content_is_preserved_not_severed() {
        // Non-ASCII letters + emoji are NOT control/whitespace, so they pass through intact; the
        // cap is REFUSED not truncated, so a multibyte char is never sliced mid-sequence.
        let note = "café ünïcode 🜂 sovereign";
        assert_eq!(sanitize_note_for_publish(note).unwrap(), note);
    }
}
