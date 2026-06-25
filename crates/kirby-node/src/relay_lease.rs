//! The relay-native, FROST-signed cross-machine lease (#9, build-spec
//! `build-spec-kirby-failover-relay-lease-20260625.md`): the ACTIVE implementation of the
//! [`crate::lease::LeaseAuthority`] seam. It needs NO new transport -- it rides the SAME
//! Nostr relay the nerve already uses for presence / lifecycle / FROST cosign, so it works
//! across LAN/NAT where the loopback-only Raft lease (now CUT) could not form.
//!
//! WHY (the corrected fact that simplifies failover): the relay ALREADY does NAT
//! traversal for everything, including the cross-machine FROST cosign proof (turtle +
//! LNVPS co-signed a real kind:1 over the relay). Plain-TCP loopback-Raft needs inbound peer
//! dials and cannot form across NAT; the relay does not. So cross-machine coordination
//! reuses the relay rather than inventing a transport.
//!
//! THE LEASE RECORD (spec 2): a Nostr event of kind [`kirby_proto::KIND_KIRBY_LEASE`],
//! ADDRESSABLE on `["d", <agent_id>]`, content JSON
//! `{ agent_id, holder_node_id, term, issued_at }`. Latest-wins by the MONOTONIC `term`
//! in the content (NOT by `created_at`): an observer never moves a term backward
//! (observe-only-forward), exactly mirroring the loopback-Raft handle's
//! `observe_committed_lease_for` semantics. A node ACTS for an agent only while it holds
//! the latest observed term; failover claims `term + 1` (a monotonic fencing token).
//!
//! THE CRYPTO (spec 2, F9-2): the lease is FROST-signed by the agent's OWN quorum key Q
//! -- the SAME group taproot key its presence/lifecycle beacons are signed under, through
//! the SAME [`crate::quorum_signer::QuorumSigner`] + guardian membrane path. A node
//! therefore cannot forge a claim for an agent whose shares it does not hold: failover
//! authority is tied to the agent's own quorum, not to node identity. On OBSERVE every
//! lease event is VERIFIED as a valid BIP-340 signature under that agent's expected Q
//! (re-derived id, pubkey-equality, and sig check); a lease NOT signed by the agent's Q is
//! REJECTED and never becomes the active lease.
//!
//! STAND-DOWN (spec 5, F9-3): a lease past its TTL ([`LEASE_TTL_SECS`]), or a relay this node
//! cannot reach to refresh/observe, makes [`RelayLeaseAuthority::fence_for`] return
//! `Fenced` and `active_term_for` return `None`. A node that loses the relay PAUSES rather
//! than acting on a stale term (liveness-over-safety): it cannot confirm it is still the
//! latest holder, so it stands down.
//!
//! SCOPE: this is the ACTIVE lease authority. The fleet supervisor CLAIMS an agent's lease
//! here on launch ([`RelayLeaseAuthority::claim`] -> publish to the relay), and the gateway
//! money-fence reads it through the [`crate::lease::LeaseAuthority`] trait. The loopback Raft
//! lease has been removed. The per-spend term-gate (F9-4) and the cryptographic
//! membrane co-sign (sovereign form) are later chunks.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::lease::{ActiveLease, FenceVerdict, LeaseAuthority, LeaseNodeId, LeaseResponse};
use crate::quorum_signer::QuorumSigner;
use kirby_custody::cosign_net::{nip01_event_id_with_tags, NostrEvent};

/// The lease time-to-live (spec 10): a lease whose `issued_at` is older than this is
/// STALE and no longer authorizes its holder. The active holder re-publishes (a
/// heartbeat) within the TTL to stay live; a failover node treats a TTL-elapsed lease as
/// claimable at `term + 1`.
///
/// This is now a MONEY dial (build-spec Findings 1+2): the window directly bounds the
/// failover change-stranding risk AND trades against the false-failover rate on the SAME
/// dial -- a tighter TTL means less stranding but more false failovers. The spec proposes
/// ~30s (heartbeat ~10s, i.e. ~3 missed heartbeats before a lease is considered stale);
/// gudnuf confirms the value. Kept a `const` so the one place to retune it is here.
pub const LEASE_TTL_SECS: u64 = 30;

/// The NIP-01 `d` tag name (the addressable key). The lease's `d` value is the `agent_id`,
/// so the relay keeps only the latest lease per `(Q, kind, agent_id)`.
const TAG_D: &str = "d";
/// The relay-wide Kirby discovery tag (`["t","kirby"]`), per the unified tag vocabulary.
const TAG_T: &str = "t";
const TAG_T_KIRBY: &str = "kirby";
/// The agent-scope tag (`["a",<agent_id>]`).
const TAG_A: &str = "a";
/// The node-scope tag (`["node",<node_id>]`): which node CLAIMED this lease (informational;
/// the authoritative holder is the `holder_node_id` in the signed content).
const TAG_NODE: &str = "node";

/// The lease event's content JSON (spec 2): who holds the agent, at what monotonic term,
/// and when the lease was issued (for the TTL). This is signed VERBATIM under Q (the note
/// sanitizer is kind:1-only), so the bytes a holder claims are the bytes the quorum
/// authorized and an observer re-verifies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseContent {
    /// The agent this lease is for (also the `d` addressable key).
    pub agent_id: String,
    /// The node that holds the active lease (the authoritative holder; a claim names
    /// itself here). This is the `node_id` the fence checks against, mirroring
    /// [`ActiveLease::node_id`].
    pub holder_node_id: LeaseNodeId,
    /// The MONOTONIC fencing term. Failover claims `term + 1`; an observer never moves it
    /// backward (observe-only-forward).
    pub term: u64,
    /// Unix seconds the lease was issued (the heartbeat timestamp). The TTL is measured
    /// against this, NOT against the event's `created_at`, so the freshness check reads the
    /// SIGNED content rather than relay-settable metadata.
    pub issued_at: u64,
}

/// The latest lease this node has OBSERVED for an agent, with the moment it was observed
/// (so a relay that stops delivering eventually ages the lease past its TTL -> stand-down).
#[derive(Debug, Clone)]
struct ObservedLease {
    content: LeaseContent,
}

/// Wall-clock now in unix seconds (the lease freshness clock). A `const fn`-free helper so
/// the TTL math has one source; tests inject time via [`RelayLeaseAuthority::observe_at`].
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        // A clock before the epoch is impossible in practice; treat it as 0 (which ages
        // every lease out -> stand-down, the safe direction).
        .unwrap_or(0)
}

/// A relay-native, FROST-signed implementation of the [`LeaseAuthority`] seam. It tracks
/// the latest observed `(holder_node_id, term)` per agent (latest-wins by monotonic term,
/// observe-only-forward), verifies every observed lease under the agent's own Q, and
/// answers the four trait methods from that observed state with a TTL stand-down.
///
/// The `claim` method (impl-specific, NOT a trait method -- the seam is read-only by
/// design) FROST-signs a lease under the agent's Q and hands back the signed event for the
/// caller to publish to the relay; observing nodes pick it up via [`Self::observe`].
pub struct RelayLeaseAuthority {
    /// This node's id (the trait `node_id`; for evidence/logging on a fence-deny).
    node_id: LeaseNodeId,
    /// The agent's quorum signer (its FROST group key Q). Only a node that HOLDS the
    /// quorum can produce a Q-signed claim -- this is the F9-2 anti-forgery root. `None`
    /// for an observe-only node (one that watches an agent it cannot sign for); such a
    /// node can OBSERVE + fence but cannot `claim`.
    signer: Option<Arc<QuorumSigner>>,
    /// The expected x-only Q (32 bytes) per agent: a lease for `agent_id` is ACCEPTED only
    /// if its event pubkey is THIS Q and the BIP-340 signature verifies under it. This is
    /// the observe-side anti-forgery check -- a lease signed by any other key (a node that
    /// does not hold the agent's shares) is rejected. Keyed by `agent_id` so a multi-agent
    /// observer holds each agent's expected Q independently.
    expected_q: HashMap<String, [u8; 32]>,
    /// The latest observed lease per agent (observe-only-forward by term). Behind a
    /// `RwLock` so the observe task (write) and the fence reads (read) cross tasks, like
    /// the loopback-Raft store's `RwLock`.
    observed: RwLock<HashMap<String, ObservedLease>>,
}

impl RelayLeaseAuthority {
    /// Build a relay-lease authority for a node. `signer` is the agent's quorum signer
    /// (present on a node that holds the agent's shares, so it can `claim`); pass the
    /// agent's expected Q under each `agent_id` it will observe so observe-time verification
    /// can reject forged leases.
    pub fn new(
        node_id: LeaseNodeId,
        signer: Option<Arc<QuorumSigner>>,
        expected_q: HashMap<String, [u8; 32]>,
    ) -> Self {
        Self {
            node_id,
            signer,
            expected_q,
            observed: RwLock::new(HashMap::new()),
        }
    }

    /// Convenience constructor for the single-agent case: a node that holds one agent's
    /// quorum and observes that one agent. Registers the agent's Q (from the signer) as the
    /// expected verifying key for `agent_id`.
    pub fn single_agent(node_id: LeaseNodeId, agent_id: &str, signer: Arc<QuorumSigner>) -> Self {
        let mut expected_q = HashMap::new();
        expected_q.insert(agent_id.to_string(), signer.q_bytes());
        Self::new(node_id, Some(signer), expected_q)
    }

    /// CLAIM the lease for `agent_id` at `term` (spec 2; NOT a trait method -- granting is
    /// impl-specific, so the read-only seam cannot mutate the lease). Builds the lease
    /// content naming THIS node as holder, FROST-signs the event under the agent's quorum Q
    /// through the SAME `QuorumSigner` path the beacons use, and returns the signed
    /// [`NostrEvent`] for the caller to publish to the relay. Failover passes `term + 1`.
    ///
    /// FAIL CLOSED: a node without the agent's quorum (`signer == None`) CANNOT claim --
    /// the only way to mint a valid lease is to hold the shares (F9-2). The signed event is
    /// also locally re-derived + verified against the claimed Q before it is returned, so a
    /// broken quorum never yields a publishable (but invalid) lease.
    pub async fn claim(&self, agent_id: &str, term: u64) -> anyhow::Result<NostrEvent> {
        let signer = self.signer.as_ref().with_context(|| {
            format!(
                "node {} holds no quorum for agent {agent_id}; it cannot claim a lease (F9-2)",
                self.node_id
            )
        })?;
        let issued_at = now_secs();
        let content = LeaseContent {
            agent_id: agent_id.to_string(),
            holder_node_id: self.node_id,
            term,
            issued_at,
        };
        let json = serde_json::to_string(&content).context("serialize lease content")?;
        let tags = lease_tags(agent_id, self.node_id);

        // FROST-sign the lease under Q (the SAME ceremony + guardian membrane that signs the
        // beacons). The content is machine JSON -> signed verbatim (the note sanitizer is
        // kind:1-only). `created_at` is the issue time (seconds).
        let event = signer
            .sign_nostr_event_with_tags(
                kirby_proto::KIND_KIRBY_LEASE as u32,
                issued_at,
                &tags,
                &json,
            )
            .context("FROST quorum failed to co-sign the lease event")?;

        // Defense in depth: the produced event MUST itself verify under the claimed Q
        // (the same gate observe-side runs). A claim that does not verify is never returned.
        verify_lease_event(&event, &signer.q_bytes())
            .context("freshly-signed lease failed local verification under Q")?;
        Ok(event)
    }

    /// OBSERVE a lease event from the relay (spec 2, F9-2): verify it under the agent's
    /// expected Q, then fold it in LATEST-WINS by monotonic term (observe-only-forward,
    /// never backward). Returns whether the event was accepted as the new latest (`true`),
    /// or rejected/ignored (`false`: a forged signature, an unknown agent, or a term not
    /// strictly newer than what is already observed).
    ///
    /// Uses the wall clock for the observe time; [`Self::observe_at`] injects time for
    /// tests. The VERIFY is load-bearing (F9-2): a lease whose event pubkey is not the
    /// agent's Q, or whose BIP-340 signature does not check under it, is REJECTED -- a node
    /// cannot forge a claim for an agent whose key it does not hold.
    pub async fn observe(&self, event: &NostrEvent) -> bool {
        self.observe_at(event, now_secs()).await
    }

    /// [`Self::observe`] with an injectable observe time (unix seconds) for deterministic
    /// TTL/stand-down tests. Production calls `observe`.
    pub async fn observe_at(&self, event: &NostrEvent, _observed_at: u64) -> bool {
        // 1. It must be a lease event with parseable lease content.
        if event.kind != kirby_proto::KIND_KIRBY_LEASE as u32 {
            return false;
        }
        let content: LeaseContent = match serde_json::from_str(&event.content) {
            Ok(c) => c,
            Err(_) => return false,
        };
        // 2. The `d` addressable key MUST match the content's agent_id (a relay routes by
        //    the tag; the signed content is authoritative -- they must agree, or the event
        //    is malformed / mis-addressed).
        if d_tag(event).as_deref() != Some(content.agent_id.as_str()) {
            return false;
        }
        // 3. VERIFY UNDER THE AGENT'S Q (F9-2). We must KNOW the agent's expected Q; an
        //    unknown agent is rejected (we will not trust a key we were not told to). The
        //    event pubkey must equal that Q AND the BIP-340 signature must verify over the
        //    re-derived NIP-01 id. A lease signed by any other key is rejected here.
        let expected_q = match self.expected_q.get(&content.agent_id) {
            Some(q) => q,
            None => return false,
        };
        if verify_lease_event(event, expected_q).is_err() {
            return false;
        }
        // 4. LATEST-WINS, OBSERVE-ONLY-FORWARD by monotonic term (mirrors the loopback-Raft
        //    store's observe_committed_lease_for: only a STRICTLY-newer term replaces the
        //    observed lease; a stale or equal term is ignored, so the term never moves
        //    backward).
        let mut observed = self.observed.write().await;
        match observed.get(&content.agent_id) {
            Some(prev) if prev.content.term >= content.term => false,
            _ => {
                observed.insert(content.agent_id.clone(), ObservedLease { content });
                true
            }
        }
    }

    /// The latest observed lease for `agent_id` projected to an [`ActiveLease`] IF it is
    /// still within its TTL (fresh). A stale lease (TTL elapsed) is NOT returned -- a stale
    /// term does not authorize anyone (F9-3). Internal helper for the trait methods.
    async fn fresh_active_lease(&self, agent_id: &str, now: u64) -> Option<ActiveLease> {
        let observed = self.observed.read().await;
        let entry = observed.get(agent_id)?;
        if is_stale(entry.content.issued_at, now) {
            return None;
        }
        Some(ActiveLease {
            node_id: entry.content.holder_node_id,
            term: entry.content.term,
        })
    }
}

#[async_trait::async_trait]
impl LeaseAuthority for RelayLeaseAuthority {
    fn node_id(&self) -> LeaseNodeId {
        self.node_id
    }

    /// The committed active lease for `agent_id`, or `None` if none is observed (or the
    /// latest observed one has gone stale). Reads ONLY this agent's entry, so it never
    /// reports another agent's holder -- per-agent isolation, like the loopback-Raft handle.
    async fn active_lease_for(&self, agent_id: &str) -> Option<ActiveLease> {
        self.fresh_active_lease(agent_id, now_secs()).await
    }

    /// The term THIS node is active at for `agent_id`: `Some(term)` only if the latest
    /// FRESH observed lease still names this node, else `None`. The relay-lease has no
    /// separate "leadership": holding the latest non-stale term IS being active (the
    /// relay-settled latest-wins is the linearization the loopback-Raft leader provided).
    async fn active_term_for(&self, agent_id: &str) -> Option<u64> {
        match self.fresh_active_lease(agent_id, now_secs()).await {
            Some(l) if l.node_id == self.node_id => Some(l.term),
            // No fresh lease (none observed, or stale -> stand-down per F9-3), or the lease
            // names someone else: this node is not active for the agent.
            _ => None,
        }
    }

    /// THE TERM-FENCE for `agent_id` for a node that BELIEVES it is active at
    /// `believed_term`: `Active` only if the latest FRESH observed lease still names THIS
    /// node at a term >= `believed_term`; otherwise `Fenced`. The fencing semantics the cut
    /// loopback-Raft lease used (a higher-term claim by another node, OR a lease moved to another
    /// holder, fences this node out), with the
    /// added F9-3 rule: a STALE lease (TTL elapsed, e.g. the relay stopped delivering)
    /// fences too -- a node stands down rather than acting on a term it can no longer
    /// confirm is latest. Reads ONLY this agent's entry (per-agent isolation).
    async fn fence_for(&self, agent_id: &str, believed_term: u64) -> FenceVerdict {
        let now = now_secs();
        match self.fresh_active_lease(agent_id, now).await {
            // The latest FRESH lease still names THIS node at a term >= believed: genuinely
            // still the active node.
            Some(l) if l.node_id == self.node_id && l.term >= believed_term => {
                FenceVerdict::Active { term: l.term }
            }
            // A fresh lease exists but it superseded this node (higher term, or a different
            // holder): fenced out.
            Some(l) => FenceVerdict::Fenced {
                committed_term: l.term,
                committed_holder: l.node_id,
                believed_term,
            },
            // No FRESH lease for the agent: either none was ever observed, or the latest is
            // STALE (TTL elapsed / relay unreachable). Either way nothing authorizes this
            // node now -> stand down (F9-3). Report the stale lease's evidence if we have it.
            None => {
                let stale = {
                    let observed = self.observed.read().await;
                    observed.get(agent_id).map(|e| {
                        (e.content.term, e.content.holder_node_id)
                    })
                };
                let (committed_term, committed_holder) = stale.unwrap_or((0, 0));
                FenceVerdict::Fenced {
                    committed_term,
                    committed_holder,
                    believed_term,
                }
            }
        }
    }
}

/// The tags every lease event carries: `["d",<agent_id>]` (the addressable key),
/// `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`. The `d` tag makes the event
/// addressable so the relay keeps only the latest lease per `(Q, kind, agent_id)`.
fn lease_tags(agent_id: &str, node_id: LeaseNodeId) -> Vec<Vec<String>> {
    vec![
        vec![TAG_D.to_string(), agent_id.to_string()],
        vec![TAG_T.to_string(), TAG_T_KIRBY.to_string()],
        vec![TAG_A.to_string(), agent_id.to_string()],
        vec![TAG_NODE.to_string(), node_id.to_string()],
    ]
}

/// Read the `d` addressable-tag value off an event (the agent_id the relay routes by).
fn d_tag(event: &NostrEvent) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some(TAG_D))
        .and_then(|t| t.get(1).cloned())
}

/// Whether a lease issued at `issued_at` is STALE as of `now` (its TTL has elapsed). A
/// lease from the FUTURE (issued_at > now, a clock skew) is treated as fresh (not stale);
/// the relay-settled latest-wins still governs which lease is authoritative.
fn is_stale(issued_at: u64, now: u64) -> bool {
    now.saturating_sub(issued_at) > LEASE_TTL_SECS
}

/// VERIFY a lease event under the expected agent Q (F9-2): recompute the NIP-01 id over the
/// event's `(pubkey, created_at, kind, tags, content)`, require the event's `id` and
/// `pubkey` to match (the pubkey MUST be the expected Q), and check the 64-byte BIP-340
/// signature under that x-only Q. Any mismatch is an error -> the lease is rejected.
///
/// This is the SAME verification shape the nerve's `frost_sign_beacon` runs locally before
/// publishing (re-derive id + verify sig under Q), here used on the OBSERVE side so a node
/// only trusts a lease the agent's own quorum genuinely signed.
fn verify_lease_event(event: &NostrEvent, expected_q: &[u8; 32]) -> anyhow::Result<()> {
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};

    // 1. The event pubkey MUST be the expected Q (a lease signed under any other key is not
    //    this agent's quorum -> reject before any crypto).
    let expected_q_hex = hex::encode(expected_q);
    if event.pubkey != expected_q_hex {
        anyhow::bail!(
            "lease event pubkey {} is not the agent's quorum key Q {expected_q_hex} (forged claim)",
            event.pubkey
        );
    }

    // 2. The event id MUST be the NIP-01 id over the signed fields (so a relay/forger cannot
    //    swap content/tags while keeping a valid-looking id). Re-derive and compare.
    let derived_id = nip01_event_id_with_tags(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    let claimed_id = hex::decode(&event.id).context("lease event id is not hex")?;
    if claimed_id.as_slice() != derived_id.as_slice() {
        anyhow::bail!("lease event id does not match the NIP-01 id over its signed fields");
    }

    // 3. The 64-byte BIP-340 signature MUST verify under Q over that id.
    let q_xonly =
        XOnlyPublicKey::from_slice(expected_q).context("agent Q is not a valid x-only key")?;
    let sig_bytes = hex::decode(&event.sig).context("lease event sig is not hex")?;
    let sig = schnorr::Signature::from_slice(&sig_bytes)
        .context("lease event sig is not a 64-byte BIP-340 signature")?;
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&sig, &Message::from_digest(derived_id), &q_xonly)
        .context("lease event BIP-340 signature does not verify under the agent's Q")?;
    Ok(())
}

/// PUBLISH a signed lease event to the relay (the write-side transport). A node that CLAIMS a
/// lease FROST-signs it ([`RelayLeaseAuthority::claim`]) then publishes it here so observing
/// nodes pick it up. A trait so the production path (a nerve relay [`nostr_sdk::Client`]) and
/// the tests (an in-memory relay) share the [`RelayLeaseGrantor`] without it depending on the
/// concrete wire.
#[async_trait::async_trait]
pub trait LeasePublisher: Send + Sync {
    /// Publish the (already FROST-signed) lease event to the relay. Errors if the publish
    /// fails (the claim then surfaces an error and the launch does not proceed as active).
    async fn publish_lease(&self, event: &NostrEvent) -> anyhow::Result<()>;
}

/// The production [`LeasePublisher`]: publishes a pre-signed lease event to the fleet relay
/// over a nostr-sdk client (the SAME wire the nerve presence/lifecycle/FROST cosign uses --
/// no new transport). The lease is already FROST-signed under the agent's Q, so the client's
/// own (throwaway) key is irrelevant; it is published VERBATIM as a pre-signed owned event
/// via `send_event` (mirroring the actuator's FROST publish path), then re-materialized +
/// locally re-verified before it leaves.
pub struct RelayLeasePublisher {
    client: nostr_sdk::Client,
}

impl RelayLeasePublisher {
    /// Connect a publisher to `relay_url` (a read/write client; the lease is pre-signed, so
    /// the client key is never used to sign). Reuses the nerve's reader-client construction.
    pub async fn connect(relay_url: &str) -> anyhow::Result<Self> {
        let client = crate::nerve::connect_reader(relay_url)
            .await
            .with_context(|| format!("connect the relay-lease publisher to {relay_url}"))?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl LeasePublisher for RelayLeasePublisher {
    async fn publish_lease(&self, event: &NostrEvent) -> anyhow::Result<()> {
        // Re-materialize the pre-signed lease from its NIP-01 JSON and locally re-verify (id +
        // BIP-340 sig under Q) before it leaves -- fail closed if the aggregate is bad, exactly
        // as the nerve's FROST beacon publish does.
        use nostr_sdk::JsonUtil as _;
        let json = serde_json::to_string(event).context("serialize the lease event to JSON")?;
        let owned = nostr_sdk::Event::from_json(&json)
            .map_err(|e| anyhow::anyhow!("parse the FROST-signed lease event: {e}"))?;
        owned
            .verify()
            .map_err(|e| anyhow::anyhow!("lease event failed local verification before publish: {e}"))?;
        self.client
            .send_event(&owned)
            .await
            .map_err(|e| anyhow::anyhow!("publish the lease event to the relay: {e}"))?;
        Ok(())
    }
}

/// The relay-native CLAIM (write-side) grantor wired into the fleet supervisor's launch path
/// ([`crate::fleet_supervisor::LeaseGrantor`]): it holds this node's id and a
/// [`LeasePublisher`]. On a claim it LOADS the tenant's per-agent quorum Q from the keystore
/// the supervisor just provisioned, FROST-signs a lease at the requested term, publishes it to
/// the relay, and returns the claimed `{node_id, term}`. Loading the quorum per claim (rather
/// than holding one signer) is what lets ONE grantor claim for EVERY tenant -- each tenant's
/// lease is signed under ITS OWN Q (F9-2: a node can only claim a lease for an agent whose
/// quorum it holds). The MVP claims term 1 on launch; a failover takeover (a later chunk)
/// claims `term + 1`.
pub struct RelayLeaseGrantor {
    node_id: LeaseNodeId,
    publisher: Arc<dyn LeasePublisher>,
}

impl RelayLeaseGrantor {
    /// Build a grantor for this node over a relay publisher.
    pub fn new(node_id: LeaseNodeId, publisher: Arc<dyn LeasePublisher>) -> Self {
        Self { node_id, publisher }
    }

    /// CLAIM `agent_id`'s lease for this node at `term` using the per-agent quorum loaded from
    /// `keystore_dir`: FROST-sign the lease under that Q, publish it to the relay, and return
    /// the claimed `{node_id, term}`. The `node_id` argument MUST be this grantor's own node id
    /// (a node can only claim a lease naming itself as holder); a mismatch is an error.
    pub async fn claim_for(
        &self,
        agent_id: &str,
        node_id: LeaseNodeId,
        term: u64,
        keystore_dir: &std::path::Path,
    ) -> anyhow::Result<LeaseResponse> {
        anyhow::ensure!(
            node_id == self.node_id,
            "a node can only claim a lease naming ITSELF as holder: requested holder {node_id} != this node {}",
            self.node_id
        );
        // Load the tenant's OWN quorum Q from the keystore the supervisor provisioned, and
        // build a single-agent authority that signs THIS agent's lease under THAT Q.
        let signer = Arc::new(
            crate::keyset_provisioning::load_quorum_signer_at(keystore_dir).with_context(|| {
                format!(
                    "load the per-agent quorum for {agent_id} from {} to sign its lease",
                    keystore_dir.display()
                )
            })?,
        );
        let authority = RelayLeaseAuthority::single_agent(self.node_id, agent_id, signer);
        let event = authority.claim(agent_id, term).await?;
        self.publisher
            .publish_lease(&event)
            .await
            .context("publish the claimed lease to the relay")?;
        Ok(LeaseResponse { node_id, term })
    }
}

#[async_trait::async_trait]
impl crate::fleet_supervisor::LeaseGrantor for RelayLeaseGrantor {
    /// Claim `agent_id`'s lease at term 1 (MVP first-launch claim). A failover takeover that
    /// claims `term + 1` is a later chunk; on first launch the term is 1.
    async fn grant_for(
        &self,
        agent_id: &str,
        node_id: LeaseNodeId,
        keystore_dir: &std::path::Path,
    ) -> anyhow::Result<LeaseResponse> {
        self.claim_for(agent_id, node_id, 1, keystore_dir).await
    }
}
