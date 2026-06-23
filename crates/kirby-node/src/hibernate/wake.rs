//! Kirby hibernation, thin slice (Move 1): the wake-request Nostr event (chunk H3).
//!
//! The wake-request is the signed, public commitment that an agent has hibernated:
//! its [`WakeRequest`] payload (the `wake_at` timer, the immutable `bundle_digest`,
//! the genome `image_ref`, the `seal` block naming the share holders + threshold, the
//! `resume_seq`, the `solvency_hint`) wrapped as the content of a Nostr event of kind
//! [`KIND_KIRBY_WAKE_REQUEST`], signed by the node/agent key and published to a relay.
//! A waker (the unseal path, H5) fetches it back, agent-scoped — by `(npub, agent_id)`
//! or by `(npub, bundle_digest)`.
//!
//! It mirrors the `nerve` module's `*Content` + `build_*`/`publish_*`/`fetch_*` shape
//! and REUSES the nerve relay client ([`connect_client`](crate::nerve) /
//! [`connect_reader`](crate::nerve)) rather than duplicating any relay/publish
//! machinery. Like the slice-1 presence beacon it is entirely HOST-SIDE and
//! UNPRIVILEGED — an outbound relay websocket; it never crosses vsock or touches the
//! genome / the `SandboxBackend` trait.
//!
//! ## Event shape
//! - **Kind:** [`KIND_KIRBY_WAKE_REQUEST`] = 31001, ADDRESSABLE (one per
//!   `(pubkey, kind, d)`): the `d` tag = `agent_id`, so a re-seal REPLACES the prior
//!   wake-request and multi-agent-per-node stays open (full rationale on the const).
//! - **Content:** the [`WakeRequest`] JSON.
//! - **Tags:** `["d",agent_id]` (the addressable key), `["t","kirby"]`,
//!   `["a",agent_id]`, `["node",node_id]` (the unified vocabulary), plus
//!   `["x",bundle_digest]` — the indexable single-letter hash tag (NIP-94 convention:
//!   `x` = sha256) so a waker can `#x`-filter the relay to fetch by `bundle_digest`.

use std::time::Duration;

use anyhow::Context as _;
use futures::StreamExt as _;
use nostr_sdk::prelude::*;

use kirby_proto::KIND_KIRBY_WAKE_REQUEST;

use crate::hibernate::WakeRequest;
use crate::nerve::{connect_client, connect_reader, NodeIdentity};

// The unified Kirby tag vocabulary. These mirror the module-private consts in `nerve`
// and are re-declared here as inert string literals: only the relay CLIENT is shared
// (per the H3 charter — "do NOT duplicate relay/publish logic"), so re-stating a few
// one-character tag names costs nothing and avoids widening the nerve surface further.
const TAG_T: &str = "t";
const TAG_T_KIRBY: &str = "kirby";
const TAG_A: &str = "a";
const TAG_D: &str = "d";
const TAG_NODE: &str = "node";
/// The indexable single-letter hash tag carrying the `bundle_digest` (NIP-94
/// convention: `x` = sha256), so a relay `#x` filter fetches a wake-request by digest.
const TAG_X: &str = "x";

/// A wake-request fetched back from a relay: the decoded [`WakeRequest`] content plus
/// the author npub and relay metadata (mirrors `nerve::PresenceRecord`). The signature
/// was verified by the SDK on delivery and re-checked in [`record_from_event`].
#[derive(Debug, Clone)]
pub struct WakeRecord {
    /// The publishing agent/node npub (its stable identity).
    pub npub: String,
    /// The decoded wake-request payload.
    pub request: WakeRequest,
    /// The event's `created_at` (unix seconds): when this wake-request was published.
    pub published_at: u64,
    /// The Nostr event id (hex).
    pub event_id: String,
}

/// Build the wake-request [`EventBuilder`]: an ADDRESSABLE [`KIND_KIRBY_WAKE_REQUEST`]
/// event whose content is `request` as JSON, tagged per the unified vocabulary plus the
/// `x` = `bundle_digest` hash tag. The caller's client signs it (with the node/agent
/// key) and stamps `created_at` at publish time.
fn build_wake_request(
    request: &WakeRequest,
    agent_id: &str,
    node_id: &str,
) -> anyhow::Result<EventBuilder> {
    let json = serde_json::to_string(request).context("serialize wake-request content")?;
    let tags: Vec<Tag> = vec![
        Tag::parse([TAG_D, agent_id])?,
        Tag::parse([TAG_T, TAG_T_KIRBY])?,
        Tag::parse([TAG_A, agent_id])?,
        Tag::parse([TAG_NODE, node_id])?,
        Tag::parse([TAG_X, &request.bundle_digest])?,
    ];
    Ok(EventBuilder::new(Kind::from(KIND_KIRBY_WAKE_REQUEST), json).tags(tags))
}

/// Publish ONE wake-request to the relay, signed by `identity` (the node/agent key),
/// then disconnect — a one-shot connect-publish-disconnect mirroring
/// `nerve::publish_agent_state` and reusing the nerve relay client. The event is
/// addressable (keyed by the `agent_id` `d` tag), so each publish REPLACES the prior
/// wake-request for the agent. Returns the published event id (hex) on success.
pub async fn publish_wake_request(
    identity: &NodeIdentity,
    relay_url: &str,
    agent_id: &str,
    node_id: &str,
    request: &WakeRequest,
) -> anyhow::Result<String> {
    let builder = build_wake_request(request, agent_id, node_id)?;
    let client = connect_client(identity, relay_url).await?;
    let result = client
        .send_event_builder(builder)
        .await
        .context("publish wake-request event");
    // Best-effort clean disconnect regardless of the send outcome.
    client.disconnect().await;
    let output = result?;
    let id = output.val.to_hex();
    tracing::info!(
        agent_id,
        node_id,
        wake_at = request.wake_at,
        bundle_digest = %request.bundle_digest,
        resume_seq = request.resume_seq,
        seal_epoch = request.seal.seal_epoch,
        event_id = %id,
        "published wake-request event (the hibernation commitment)"
    );
    Ok(id)
}

/// Parse a `npub...` (bech32) or a hex pubkey into a [`PublicKey`].
fn parse_pubkey(npub: &str) -> anyhow::Result<PublicKey> {
    PublicKey::from_bech32(npub)
        .or_else(|_| PublicKey::from_hex(npub))
        .with_context(|| format!("parse npub/pubkey {npub}"))
}

/// Fetch a specific agent's current wake-request. The agent is identified by BOTH its
/// `npub` (bech32 `npub...` or hex pubkey) AND its `agent_id` (the addressable `d`
/// tag), so the query `{kinds:[KIND_KIRBY_WAKE_REQUEST], authors:[npub], #d:[agent_id]}`
/// resolves to exactly THAT agent's latest wake-request — never another agent's on the
/// same node. Returns `None` if the agent has no live wake-request on the relay.
/// `timeout` bounds the relay query (the stream auto-closes on EOSE).
///
/// Agent-scoped by construction: keying on `(npub, d=agent_id)` keeps the primitive
/// correct under multi-agent-per-node (Move-2), not only the thin slice's agent==node
/// — a node hosting two agents must not have one agent's fetch return the other's.
pub async fn fetch_wake_request_by_agent(
    relay_url: &str,
    npub: &str,
    agent_id: &str,
    timeout: Duration,
) -> anyhow::Result<Option<WakeRecord>> {
    let filter = Filter::new()
        .kind(Kind::from(KIND_KIRBY_WAKE_REQUEST))
        .author(parse_pubkey(npub)?)
        .identifier(agent_id);
    fetch_newest(relay_url, filter, timeout).await
}

/// Fetch a wake-request by its author + `bundle_digest`: query
/// `{kinds:[KIND_KIRBY_WAKE_REQUEST], authors:[npub], #x:[bundle_digest]}` (the
/// indexable hash tag) and return the newest match decoded, or `None`.
///
/// The `bundle_digest` is a CONTENT COMMITMENT, not an identity — two agents could in
/// principle commit to the same bundle — so the author `npub` is part of the filter to
/// make `(npub, bundle_digest)` unambiguous. Use this to confirm a known agent's
/// current wake-request commits to an EXPECTED digest (e.g. validating an on-relay
/// wake-request against the `bundle_digest` carried by a [`Lease`](crate::hibernate::Lease)
/// or [`WatcherRecord`](crate::hibernate::WatcherRecord)). Because the kind is
/// addressable (one per agent, latest wins), a superseded digest's event is gone — so a
/// match means `bundle_digest` is that agent's CURRENT commitment.
pub async fn fetch_wake_request_by_digest(
    relay_url: &str,
    npub: &str,
    bundle_digest: &str,
    timeout: Duration,
) -> anyhow::Result<Option<WakeRecord>> {
    let filter = Filter::new()
        .kind(Kind::from(KIND_KIRBY_WAKE_REQUEST))
        .author(parse_pubkey(npub)?)
        .custom_tag(SingleLetterTag::lowercase(Alphabet::X), bundle_digest);
    fetch_newest(relay_url, filter, timeout).await
}

/// Stream `filter` over a read-only nerve client and return the newest decodable
/// wake-request as a [`WakeRecord`] (or `None`). Foreign / undecodable events of the
/// same kind are skipped (mirroring `nerve::fetch_fleet`); de-dups defensively to the
/// newest `created_at` even though the relay should hold only the latest addressable.
async fn fetch_newest(
    relay_url: &str,
    filter: Filter,
    timeout: Duration,
) -> anyhow::Result<Option<WakeRecord>> {
    let client = connect_reader(relay_url).await?;
    let mut stream = client
        .stream_events(filter, timeout)
        .await
        .context("stream wake-requests")?;

    let mut newest: Option<WakeRecord> = None;
    while let Some(event) = stream.next().await {
        if event.kind != Kind::from(KIND_KIRBY_WAKE_REQUEST) {
            continue;
        }
        let Some(record) = record_from_event(&event) else {
            continue;
        };
        match &newest {
            Some(prev) if prev.published_at >= record.published_at => {}
            _ => newest = Some(record),
        }
    }

    client.disconnect().await;
    Ok(newest)
}

/// Decode a received wake-request [`Event`] into a [`WakeRecord`]: re-verify the
/// signature (the SDK already verifies relay-sourced events; this is a cheap,
/// defensive re-check that also makes the tamper-rejection property hold at the decode
/// layer), then decode the content JSON. Returns `None` if the signature is invalid or
/// the content is not a well-formed [`WakeRequest`] (a foreign event of the same kind).
fn record_from_event(event: &Event) -> Option<WakeRecord> {
    if event.verify().is_err() {
        return None;
    }
    let request: WakeRequest = serde_json::from_str(&event.content).ok()?;
    Some(WakeRecord {
        npub: event.pubkey.to_bech32().unwrap_or_default(),
        request,
        published_at: event.created_at.as_secs(),
        event_id: event.id.to_hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibernate::{Seal, SEAL_SHARES, SEAL_THRESHOLD};

    /// A fully-populated sample wake-request for the round-trip / shape assertions.
    /// `bundle_digest` is a parameter so a live-relay test can make it unique per run.
    fn sample_request(bundle_digest: &str) -> WakeRequest {
        WakeRequest {
            wake_at: 1_900_000_000,
            bundle_digest: bundle_digest.to_string(),
            image_ref: "sha256:0123456789abcdef".to_string(),
            seal: Seal {
                holder_pubkeys: vec![
                    "holder-a".to_string(),
                    "holder-b".to_string(),
                    "holder-c".to_string(),
                ],
                threshold: SEAL_THRESHOLD,
                commitments: vec![
                    "commit-a".to_string(),
                    "commit-b".to_string(),
                    "commit-c".to_string(),
                ],
                seal_epoch: 7,
            },
            resume_seq: 42,
            solvency_hint: 3_899,
        }
    }

    #[test]
    fn wake_request_event_shape_matches_the_contract() {
        let keys = Keys::generate();
        let request = sample_request("deadbeefdigest");
        let event = build_wake_request(&request, "agent-0", "node-1")
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();

        // Kind = 31001, ADDRESSABLE (one per (pubkey, kind, d), latest wins).
        assert_eq!(event.kind, Kind::from(KIND_KIRBY_WAKE_REQUEST));
        assert_eq!(event.kind.as_u16(), 31001);
        assert!(
            event.kind.is_addressable(),
            "wake-request must be addressable: a re-seal replaces the prior, and \
             multi-agent-per-node stays open"
        );

        // Tags: the unified d/a/t/node vocabulary + the x=bundle_digest hash tag.
        let has_tag = |name: &str, val: &str| {
            event.tags.iter().any(|t| {
                let s = t.as_slice();
                s.first().map(String::as_str) == Some(name)
                    && s.get(1).map(String::as_str) == Some(val)
            })
        };
        assert!(has_tag("d", "agent-0"), "the addressable d tag is the agent_id");
        assert!(has_tag("t", "kirby"));
        assert!(has_tag("a", "agent-0"));
        assert!(has_tag("node", "node-1"));
        assert!(
            has_tag("x", "deadbeefdigest"),
            "the x hash tag carries the bundle_digest for #x-fetch"
        );

        // Content round-trips back to the exact WakeRequest (all fields carried).
        let decoded: WakeRequest = serde_json::from_str(&event.content).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.seal.threshold, SEAL_THRESHOLD);
        assert_eq!(decoded.seal.holder_pubkeys.len(), SEAL_SHARES as usize);
    }

    #[test]
    fn signature_verifies_and_a_tampered_event_is_rejected() {
        let keys = Keys::generate();
        let request = sample_request("digest-sig");
        let event = build_wake_request(&request, "agent-0", "node-1")
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();

        // A well-formed signed event verifies and decodes to a full record.
        assert!(event.verify().is_ok(), "the node-key signature must verify");
        let record = record_from_event(&event).expect("decode a valid wake-request");
        assert_eq!(record.request, request, "all fields carried through the event");
        assert_eq!(record.npub, keys.public_key().to_bech32().unwrap());
        assert_eq!(record.event_id, event.id.to_hex());
        assert_eq!(record.published_at, event.created_at.as_secs());

        // Tamper the content AFTER signing (valid JSON, but a different request): the
        // event id no longer matches the content, so verification fails and the decode
        // path rejects it. A waker can never be fooled by a re-written wake-request.
        let mut forged = event.clone();
        forged.content = serde_json::to_string(&sample_request("forged-digest")).unwrap();
        assert!(
            forged.verify().is_err(),
            "a content-tampered event must fail signature verification"
        );
        assert!(
            record_from_event(&forged).is_none(),
            "record_from_event rejects an event whose signature does not verify"
        );
    }

    #[test]
    fn record_from_event_rejects_foreign_content() {
        // Same kind, but the content is not a WakeRequest -> None (sig is valid; the
        // content decode fails).
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::from(KIND_KIRBY_WAKE_REQUEST), "not a wake-request")
            .sign_with_keys(&keys)
            .unwrap();
        assert!(event.verify().is_ok());
        assert!(
            record_from_event(&event).is_none(),
            "non-WakeRequest content of the same kind decodes to None"
        );
    }

    // Live round-trip against a running relay (publish -> fetch-by-agent +
    // fetch-by-digest), proving the fetch primitives are AGENT-SCOPED: two agents under
    // ONE npub, each fetch returns its own wake-request, never the other's. #[ignore]d
    // like the other relay tests in this crate (e.g. memory_engram's live test): it
    // defaults to ws://127.0.0.1:7777, or set KIRBY_TEST_RELAY. Run with:
    // `cargo test -p kirby-node wake:: -- --ignored`.
    #[tokio::test]
    #[ignore = "needs a running relay; defaults to ws://127.0.0.1:7777 or set KIRBY_TEST_RELAY"]
    async fn wake_request_round_trips_through_a_relay() {
        let relay =
            std::env::var("KIRBY_TEST_RELAY").unwrap_or_else(|_| "ws://127.0.0.1:7777".to_string());
        let timeout = Duration::from_secs(8);

        // A fresh random identity per run -> a unique npub, so this test never collides
        // with another agent's addressable wake-request on the shared relay.
        let dir = tempdir();
        let identity = NodeIdentity::load_or_create(&dir.join("node.nostr.key")).unwrap();
        let npub = identity.npub();
        let node_id = "h3-roundtrip-node";

        // TWO agents under the SAME npub (the multi-agent-per-node shape): distinct
        // agent_id (the `d` tag) + distinct bundle, so we can prove the fetch primitives
        // are agent-scoped, not "newest across the pubkey". Addressable keying is
        // `(pubkey, kind, d)`, so both coexist on the relay.
        let agent_a = "h3-roundtrip-agent-a";
        let agent_b = "h3-roundtrip-agent-b";
        let req_a = sample_request(&format!("{npub}-bundle-a"));
        let req_b = {
            let mut r = sample_request(&format!("{npub}-bundle-b"));
            r.resume_seq = 99; // distinct from A beyond the digest
            r
        };

        let id_a = publish_wake_request(&identity, &relay, agent_a, node_id, &req_a)
            .await
            .expect("publish A");
        let id_b = publish_wake_request(&identity, &relay, agent_b, node_id, &req_b)
            .await
            .expect("publish B");
        assert!(!id_a.is_empty() && !id_b.is_empty(), "published events have ids");

        // fetch-by-agent is agent-scoped: each agent_id returns ITS OWN wake-request,
        // never the other agent's on the same npub (the multi-agent-correctness guard).
        let got_a = fetch_wake_request_by_agent(&relay, &npub, agent_a, timeout)
            .await
            .expect("fetch A")
            .expect("agent A's wake-request is on the relay");
        assert_eq!(got_a.request, req_a, "all of agent A's fields carried");
        assert_eq!(got_a.npub, npub);
        assert_eq!(got_a.event_id, id_a);

        let got_b = fetch_wake_request_by_agent(&relay, &npub, agent_b, timeout)
            .await
            .expect("fetch B")
            .expect("agent B's wake-request is on the relay");
        assert_eq!(got_b.request, req_b, "all of agent B's fields carried");
        assert_ne!(got_b.request, req_a, "B's fetch is NOT A — the d tag scopes the fetch");

        // fetch-by-digest is (npub, digest)-scoped: each digest resolves to its own request.
        let by_digest_a = fetch_wake_request_by_digest(&relay, &npub, &req_a.bundle_digest, timeout)
            .await
            .expect("fetch digest A")
            .expect("digest A present");
        assert_eq!(by_digest_a.request, req_a, "all fields carried by digest-fetch");
        let by_digest_b = fetch_wake_request_by_digest(&relay, &npub, &req_b.bundle_digest, timeout)
            .await
            .expect("fetch digest B")
            .expect("digest B present");
        assert_eq!(by_digest_b.request, req_b);

        // A digest this npub never sealed resolves to nothing.
        let missing = fetch_wake_request_by_digest(&relay, &npub, "no-such-digest-xyz", timeout)
            .await
            .expect("fetch by absent digest");
        assert!(missing.is_none(), "an unknown digest has no wake-request");

        cleanup(&dir);
    }

    // Minimal temp-dir helpers (mirrors nerve's test helpers; no extra dev-dep): the
    // OS temp dir + pid + a counter so parallel tests do not collide.
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("kirby-wake-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn cleanup(p: &std::path::Path) {
        let _ = std::fs::remove_dir_all(p);
    }
}
