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

use crate::lease::{ActiveLease, FenceVerdict, LeaseAuthority, LeaseNodeId, LeaseResponse, SpawnFenceView};
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

/// How many TTLs into the future a freshly-claimed lease's NIP-40 `expiration` is set (G-4
/// failover bug 2, ghost accumulation). The lease event carries `["expiration", issued_at +
/// LEASE_EXPIRATION_TTL_MULTIPLE * LEASE_TTL_SECS]`; a NIP-40-aware relay (nostr-rs-relay) DROPS
/// the addressable lease once that time passes. A LIVE agent heartbeats every ~TTL/3, each
/// heartbeat re-issuing the lease with a fresh, further-out expiration, so its lease never
/// expires while it is alive; a DEAD agent's final lease expires `MULTIPLE * TTL` after its last
/// heartbeat and the relay garbage-collects it — so ancient ghost leases stop accumulating. The
/// multiple is > 1 (a live agent must survive a few missed heartbeats without its lease being
/// dropped, exactly as the TTL tolerates them). The client-side age bound in
/// [`crate::failover_detect::detect_takeovers`] is the backstop for a relay that does NOT honor
/// NIP-40, so correctness does not depend on relay support.
pub const LEASE_EXPIRATION_TTL_MULTIPLE: u64 = 4;

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
/// The NIP-40 expiration tag (`["expiration",<unix-seconds>]`): a NIP-40-aware relay drops the
/// event once this passes, so a dead agent's last lease is garbage-collected (failover bug 2).
const TAG_EXPIRATION: &str = "expiration";

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

/// The LATEST observed lease for an agent, IGNORING the TTL — the read shape the failover
/// detector needs to distinguish "STALE (we saw a lease, then it went quiet past the TTL)" from
/// "ABSENT (we never saw a lease at all)". Unlike [`ActiveLease`] (which is only ever produced
/// from a FRESH, TTL-filtered projection), this carries the SIGNED `issued_at` so the detector
/// can judge staleness itself at an explicit `now` and beat the OBSERVED `term`.
///
/// This is a read-only projection of the observer's internal state. It is NOT a money/security
/// authority (the occupancy observer does not verify the FROST signature — see
/// [`FleetLeaseObserver`]); it is the cooperative-fleet hint the steady-state failover
/// detector reasons over, the same trust level the spawn fence already uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedLeaseRecord {
    /// The node that holds the latest observed lease (the authoritative holder named in the
    /// signed content). On a takeover the detector beats `term`, not this node's own term.
    pub holder_node_id: LeaseNodeId,
    /// The MONOTONIC fencing term of the latest observed lease. A takeover claims `term + 1`.
    pub term: u64,
    /// Unix seconds the lease was issued (the heartbeat timestamp). Staleness is judged against
    /// this, exactly as [`is_stale`] does for the fresh projection.
    pub issued_at: u64,
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
        // NIP-40 expiration (failover bug 2): the relay drops this addressable lease once the
        // expiration passes, so a DEAD agent's last lease is garbage-collected instead of
        // lingering as a permanent ghost. A live agent's heartbeat re-issues with a fresh
        // expiration before this elapses (the same way the TTL is kept fresh).
        let expiration = issued_at + LEASE_EXPIRATION_TTL_MULTIPLE * LEASE_TTL_SECS;
        let tags = lease_tags(agent_id, self.node_id, expiration);

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
/// `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`, and the NIP-40
/// `["expiration",<unix-seconds>]` (failover bug 2: a NIP-40-aware relay drops the lease once
/// `expiration` passes, so a dead agent's last lease does not linger as a permanent ghost). The
/// `d` tag makes the event addressable so the relay keeps only the latest lease per
/// `(Q, kind, agent_id)`. All tags are part of the FROST-signed NIP-01 id, so the expiration is
/// authentic (an observer re-derives the id over the SAME tags it verifies under Q).
fn lease_tags(agent_id: &str, node_id: LeaseNodeId, expiration: u64) -> Vec<Vec<String>> {
    vec![
        vec![TAG_D.to_string(), agent_id.to_string()],
        vec![TAG_T.to_string(), TAG_T_KIRBY.to_string()],
        vec![TAG_A.to_string(), agent_id.to_string()],
        vec![TAG_NODE.to_string(), node_id.to_string()],
        vec![TAG_EXPIRATION.to_string(), expiration.to_string()],
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
    /// Claim `agent_id`'s lease at an EXPLICIT `term`: term 1 on first launch (via the default
    /// `grant_for`), the CURRENT term on a heartbeat re-publish (refresh `issued_at`), or
    /// `term + 1` on a failover takeover. Loads the agent's quorum Q from `keystore_dir` and
    /// FROST-signs the lease under it (F9-2), then publishes it to the relay.
    async fn claim_at(
        &self,
        agent_id: &str,
        node_id: LeaseNodeId,
        term: u64,
        keystore_dir: &std::path::Path,
    ) -> anyhow::Result<LeaseResponse> {
        self.claim_for(agent_id, node_id, term, keystore_dir).await
    }
}

/// THE READ-AFTER-WRITE CONFIRM seam (failover launch fence, finding G-1 on the LAUNCH path):
/// re-read an agent's CURRENT latest lease from the relay with a REAL round-trip (NOT a local
/// cache), so the takeover path can confirm THIS node actually WON the term race before it
/// launches a VM. Two survivors that both pass `detect_takeovers` would both `claim_at(term+1)`
/// under the agent's SAME quorum Q; because the lease is an addressable (kind 31002) replaceable
/// event keyed by `(Q, kind, d=agent_id)`, the relay collapses both claims to exactly ONE
/// surviving event — and that one event names exactly one `holder_node_id`. Re-reading it after
/// our own publish settles is therefore both the win-confirmation AND the deterministic equal-term
/// tiebreak (the relay's latest-wins picks the single winner; the loser sees a holder that is not
/// itself and stands down). A trait so the production path (a nerve [`nostr_sdk::Client`]) and the
/// tests (an in-memory relay) share the launch fence without it depending on the concrete wire.
///
/// This is a COOPERATIVE-FLEET read at the SAME trust level as [`FleetLeaseObserver`] (structural,
/// NOT Q-verified — cross-machine the peer's Q is not yet known, finding G-2); it is a launch
/// SAFETY gate (do not double-run an agent), never a money authority.
#[async_trait::async_trait]
pub trait LeaseReader: Send + Sync {
    /// Re-read `agent_id`'s LATEST lease from the relay with a real round-trip, TTL-ignored
    /// (the caller judges the win by holder+term, not freshness). `Ok(None)` means the relay
    /// returned no lease for the agent within the read window; `Err` means the read itself failed
    /// (the relay was unreachable) — the caller treats BOTH as "could not confirm the win" and
    /// aborts the launch (fail closed: never launch on an unconfirmed claim).
    async fn latest_lease(&self, agent_id: &str) -> anyhow::Result<Option<ObservedLeaseRecord>>;
}

/// The pure read-after-write DECISION (no I/O, exhaustively testable): given the lease that
/// SURVIVED at the relay after our claim published, did THIS node win the right to launch
/// `agent_id` at `claimed_term`?
///
/// - A survivor at a STRICTLY HIGHER term than we claimed → a peer raced us and bumped the
///   fencing token past ours; THEY won — stand down.
/// - A survivor at EXACTLY our term naming THIS node → our claim is the one the relay kept (we
///   won the latest-wins collapse) → launch.
/// - A survivor at our term naming a DIFFERENT node → an equal-term race the relay's latest-wins
///   resolved in the peer's favour; THEY won — stand down. (This is the deterministic equal-term
///   tiebreak the observer doc flagged as unresolved: the relay arbitrates, the loser self-fences.)
/// - A survivor at a LOWER term, or NO survivor at all → we cannot confirm our own claim is live
///   (our publish should have produced a ≥ `claimed_term` lease naming us); FAIL CLOSED and stand
///   down rather than launch on an unconfirmed claim.
pub fn confirm_takeover_win(
    surviving: Option<ObservedLeaseRecord>,
    claimed_term: u64,
    this_node: LeaseNodeId,
) -> bool {
    match surviving {
        Some(lease) if lease.term == claimed_term && lease.holder_node_id == this_node => true,
        // Higher term, equal-term-other-holder, lower term, or absent: not our confirmed win.
        _ => false,
    }
}

/// Resolve the agent's expected group key Q (32 x-only bytes) from THIS node's LOCAL keystore,
/// using only the PUBLIC pubkeys (no secret shares -- distribution-agnostic). `None` when this
/// node holds no keystore for the agent (the cross-machine pure-observer case, finding G-2): the
/// fence then cannot verify a surviving lease and must fail closed. The keystore is keyed by the
/// agent's instance id via the SAME `instance_id_for(agent_id) -> keystore_dir_for` derivation the
/// failover admission gate uses, so Q is resolvable from the `agent_id` alone (no new wiring).
fn local_expected_q(agent_id: &str) -> Option<[u8; 32]> {
    let instance_id = crate::fleet::instance_id_for(agent_id);
    let keystore_dir = crate::keyset_provisioning::keystore_dir_for(&instance_id);
    crate::keyset_provisioning::load_group_q_at(&keystore_dir).ok()
}

/// The PURE read-after-write SELECTION over a set of fetched lease events (no I/O, exhaustively
/// testable -- the verification counterpart of [`confirm_takeover_win`]): keep ONLY the events
/// whose `d` tag agrees with the signed `agent_id` AND that are validly FROST-signed under the
/// agent's expected quorum key Q (`event.pubkey == hex(Q)`, the NIP-01 id re-derives, and the
/// 64-byte BIP-340 signature verifies -- the canonical [`verify_lease_event`]); then return the
/// highest `(term, issued_at)` among the survivors.
///
/// THE FENCE-HARDENING INVARIANT (finding G-2): a forged or relay-injected lease -- signed by any
/// key that is not the agent's Q, or a genuine lease whose content/tags were tampered -- is
/// DROPPED here, BEFORE it can reach the `(term, issued_at)` max. This closes BOTH failure modes
/// of the unverified read:
///   * a forged lease naming ANOTHER holder at a higher term can no longer make the rightful
///     winner stand down (liveness / DoS), and
///   * a forged lease naming THIS node at the claimed term can no longer FALSELY confirm a win
///     and cause a DOUBLE-LAUNCH (the double-spend the fence exists to prevent).
///
/// Returns `None` when no verified lease survives (all forged, or none present) -> the caller
/// fails closed (does not launch on an unconfirmable claim).
fn select_verified_latest_lease(
    events: &[NostrEvent],
    agent_id: &str,
    expected_q: &[u8; 32],
) -> Option<ObservedLeaseRecord> {
    let mut best: Option<ObservedLeaseRecord> = None;
    for event in events {
        // Structural: the content decodes AND the `d` tag agrees with the signed agent_id (drop a
        // mis-addressed event), matching the existing occupancy read.
        let content: LeaseContent = match serde_json::from_str(&event.content) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if d_tag(event).as_deref() != Some(content.agent_id.as_str()) || content.agent_id != agent_id
        {
            continue;
        }
        // Q-VERIFY (the hardening): the lease MUST be validly FROST-signed under the agent's
        // expected Q. A lease under any other key (a forger / malicious relay) or a tampered one
        // fails here and is DROPPED -- it never influences the `(term, issued_at)` max below.
        if verify_lease_event(event, expected_q).is_err() {
            continue;
        }
        let rec = ObservedLeaseRecord {
            holder_node_id: content.holder_node_id,
            term: content.term,
            issued_at: content.issued_at,
        };
        // Highest term wins; tie broken by the fresher issued_at (the relay's latest-wins for an
        // addressable replaceable event) -- now over VERIFIED events only.
        let take = match best {
            None => true,
            Some(b) => (rec.term, rec.issued_at) > (b.term, b.issued_at),
        };
        if take {
            best = Some(rec);
        }
    }
    best
}

/// The production [`LeaseReader`]: re-reads an agent's latest addressable lease (kind 31002,
/// `#d`=agent_id) from the fleet relay over a [`nostr_sdk::Client`] via a real `fetch_events`
/// round-trip (the SAME read mechanism the engram rail uses for its addressable head — REQ →
/// EOSE, never the subscription cache). Shares the control-plane's already-connected client (it
/// is `Clone`/`Arc`-backed), so the fence reads the same relay the claim published to with no new
/// connection. The read is STRUCTURAL (decode `LeaseContent`, check the `d` tag agrees with the
/// signed `agent_id`), matching the cooperative-fleet trust level of [`FleetLeaseObserver`].
pub struct RelayLeaseReader {
    client: nostr_sdk::Client,
    /// How long to wait for the relay to answer the re-read REQ (a fetch that times out yields
    /// `Ok(empty)` → the caller fails closed). Bounded so the single-takeover-per-tick slot is
    /// never held hostage by a slow relay.
    read_timeout: std::time::Duration,
}

impl RelayLeaseReader {
    /// Build a reader over a (cloned, already-connected) fleet relay client.
    pub fn new(client: nostr_sdk::Client, read_timeout: std::time::Duration) -> Self {
        Self { client, read_timeout }
    }
}

#[async_trait::async_trait]
impl LeaseReader for RelayLeaseReader {
    async fn latest_lease(&self, agent_id: &str) -> anyhow::Result<Option<ObservedLeaseRecord>> {
        use nostr_sdk::prelude::*;
        // Addressable filter: kind 31002 + the `#d` identifier = agent_id. The relay holds at most
        // one replaceable event per (author Q, kind, d); we defensively reduce by highest
        // (term, issued_at) in case more than one author key ever appears under the same d.
        let filter = Filter::new()
            .kind(Kind::from(kirby_proto::KIND_KIRBY_LEASE))
            .identifier(agent_id);
        let events = self
            .client
            .fetch_events(filter, self.read_timeout)
            .await
            .map_err(|e| anyhow::anyhow!("re-read latest lease for {agent_id}: {e}"))?;
        // Q-VERIFY THE FENCE RE-READ (finding G-2 hardening): resolve the agent's expected quorum
        // key Q from THIS node's LOCAL keystore (PUBLIC pubkeys only -- distribution-agnostic, so a
        // node holding only its own share can still verify). If this node holds no keystore for the
        // agent it CANNOT verify the lease (the cross-machine pure-observer case) -> report NO
        // confirmable lease so the caller FAILS CLOSED (never launch on an unverifiable claim).
        let expected_q = match local_expected_q(agent_id) {
            Some(q) => q,
            None => {
                tracing::warn!(
                    agent_id,
                    "fence re-read: no local keystore to resolve the agent's Q; cannot verify the \
                     surviving lease -> reporting none (fail closed)"
                );
                return Ok(None);
            }
        };

        // Re-materialize each live relay event as the transport-free `NostrEvent` the canonical
        // `verify_lease_event` checks (the SAME NIP-01 JSON shape the publish path round-trips), then
        // keep ONLY the leases validly FROST-signed under Q and take the latest (see
        // `select_verified_latest_lease`). A forged / relay-injected lease (any other signing key,
        // or a tampered one) is dropped before it can sway the takeover decision -- closing BOTH the
        // false-stand-down and the double-launch holes.
        let candidates: Vec<NostrEvent> = events
            .into_iter()
            .filter_map(|e| serde_json::from_str::<NostrEvent>(&nostr_sdk::JsonUtil::as_json(&e)).ok())
            .collect();
        Ok(select_verified_latest_lease(&candidates, agent_id, &expected_q))
    }
}

/// Read the `d` addressable-tag value off a nostr-sdk event (the agent_id the relay routes by).
/// The fleet occupancy observer reads live relay events (`nostr_sdk::Event`), distinct from the
/// transport-free [`NostrEvent`] the verified [`RelayLeaseAuthority`] path uses.
fn sdk_d_tag(event: &nostr_sdk::Event) -> Option<String> {
    event.tags.iter().find_map(|t| {
        let s = t.as_slice();
        if s.first().map(String::as_str) == Some(TAG_D) {
            s.get(1).cloned()
        } else {
            None
        }
    })
}

/// THE CLAIM-BEFORE-LAUNCH FENCE read-side (closes resilience finding G-1, the cross-node
/// DOUBLE-SPAWN): a COOPERATIVE-FLEET occupancy view of which node currently holds which agent,
/// folded from the lease events ([`kirby_proto::KIND_KIRBY_LEASE`]) the fleet publishes to the
/// relay. A node about to spawn `agent_id` consults [`SpawnFenceView::active_lease_for`]; if a
/// FRESH lease names ANOTHER node, it backs off (no duplicate launch).
///
/// **NOT a security boundary, and NOT a money authority — read this before reusing it.** Unlike
/// [`RelayLeaseAuthority`] (which VERIFIES every observed lease under the agent's quorum Q before
/// trusting it, F9-2), this observer does NOT verify the FROST signature. The reason is finding
/// G-2: today each node provisions its OWN per-agent keyset, so a node about to spawn `agent_id`
/// does not yet hold or even KNOW that agent's Q and cannot verify a peer's lease under it. So
/// the fence trusts a lease STRUCTURALLY (right kind + the `d` tag agreeing with the signed
/// `agent_id` + still within the TTL) as a cooperative-fleet hint.
///
/// The bounded residual this accepts: a forged 31002 (any key) can BLOCK a spawn of one specific
/// `agent_id` — a targeted denial. That is strictly LESS harmful than the double-spawn it prevents
/// (which burns real money on two VMs and forks the agent's identity), it is bounded to one label,
/// and it is CLOSED once cross-machine keyset sharing (G-2) lets the fence verify under Q — at
/// which point a Q-verified [`RelayLeaseAuthority`] is swapped in via the blanket
/// `SpawnFenceView for Arc<dyn LeaseAuthority>` impl with NO change to the consumer. It
/// deliberately does NOT implement [`LeaseAuthority`], so it can never be wired as the gateway
/// money-fence. The other residual (a true simultaneous claim race between two nodes that have
/// not yet observed each other) still needs the monotonic-term tiebreak the spec calls out and is
/// not closed here.
pub struct FleetLeaseObserver {
    /// This node's id (so the fence skips only a lease held by ANOTHER node).
    node_id: LeaseNodeId,
    /// The latest lease OBSERVED per agent (latest-wins by monotonic term, observe-only-forward).
    /// Stores the raw [`LeaseContent`] so freshness is judged against the SIGNED `issued_at`.
    observed: RwLock<HashMap<String, LeaseContent>>,
}

impl FleetLeaseObserver {
    /// Build an occupancy observer for `node_id` (the node that will consult it before spawning).
    pub fn new(node_id: LeaseNodeId) -> Self {
        Self { node_id, observed: RwLock::new(HashMap::new()) }
    }

    /// OBSERVE a lease event from the relay and fold it into the occupancy view. Accepts a
    /// strictly-NEWER term (a new claim or a failover takeover) AND a SAME-term re-publish by the
    /// SAME holder with a fresher `issued_at` (a HEARTBEAT — it refreshes freshness so a live,
    /// heartbeating agent does not look dead to a peer's fence after one TTL, WITHOUT bumping the
    /// fencing token). STRUCTURAL ONLY — no Q verification (see the type doc). Returns whether the
    /// event was folded in (`true`), or ignored (`false`: wrong kind, malformed content, a `d` tag
    /// that disagrees with the signed `agent_id`, an older term, a same-term event from a DIFFERENT
    /// holder, or a non-fresher replay).
    pub async fn observe_occupancy(&self, event: &nostr_sdk::Event) -> bool {
        if event.kind.as_u16() != kirby_proto::KIND_KIRBY_LEASE {
            return false;
        }
        let content: LeaseContent = match serde_json::from_str(&event.content) {
            Ok(c) => c,
            Err(_) => return false,
        };
        // The addressable `d` tag MUST agree with the signed content's agent_id (a mis-addressed
        // or malformed event is dropped), mirroring the verified observe path's check.
        if sdk_d_tag(event).as_deref() != Some(content.agent_id.as_str()) {
            return false;
        }
        let mut observed = self.observed.write().await;
        let accept = match observed.get(&content.agent_id) {
            None => true,
            // A strictly-NEWER term is a new epoch (first claim, or a failover takeover that bumped
            // the fencing token) -- always fold it in.
            Some(prev) if content.term > prev.term => true,
            // A SAME-term re-publish by the SAME holder with a fresher `issued_at` is a HEARTBEAT
            // (heartbeat_leases re-claims at the current term to refresh freshness WITHOUT bumping
            // the token) -- fold it in so the lease stays fresh for peers' fences. A same-term
            // event from a DIFFERENT holder is the simultaneous-claim race (a documented residual
            // the term tiebreak resolves, not here) and a non-fresher one is a replay/dup; both are
            // ignored so the observed holder never flaps within a term.
            Some(prev) => content.holder_node_id == prev.holder_node_id && content.issued_at > prev.issued_at,
        };
        if accept {
            observed.insert(content.agent_id.clone(), content);
        }
        accept
    }

    /// Test/diagnostic seam: observe with an injectable observe time is not needed here (freshness
    /// is read at query time via [`SpawnFenceView::active_lease_for`]); this exposes the freshness
    /// projection at an explicit `now` for deterministic TTL tests.
    async fn fresh_active_lease_at(&self, agent_id: &str, now: u64) -> Option<ActiveLease> {
        let observed = self.observed.read().await;
        let c = observed.get(agent_id)?;
        if is_stale(c.issued_at, now) {
            return None;
        }
        Some(ActiveLease { node_id: c.holder_node_id, term: c.term })
    }

    /// The LATEST observed lease for `agent_id` IGNORING the TTL — its holder, term, and signed
    /// `issued_at` — or `None` if NO lease has EVER been observed for the agent. This is the
    /// failover detector's "stale vs absent" distinguisher: [`SpawnFenceView::active_lease_for`]
    /// already collapses both "never seen" and "seen but stale" to `None`, but a takeover decision
    /// MUST treat them differently — a stale lease (seen, went quiet) is a takeover candidate,
    /// while an absent one (never seen) is NOT (we have no evidence the agent exists, so claiming
    /// it would be inventing an agent, not failing one over). The caller judges staleness itself
    /// via [`is_stale`] / its own TTL at an explicit `now`.
    ///
    /// ADDITIVE + read-only: it does NOT change the existing fresh projection or any other method;
    /// it just exposes the raw stored `(holder, term, issued_at)` the TTL filter would otherwise
    /// hide.
    pub async fn latest_observed_lease(&self, agent_id: &str) -> Option<ObservedLeaseRecord> {
        let observed = self.observed.read().await;
        observed.get(agent_id).map(|c| ObservedLeaseRecord {
            holder_node_id: c.holder_node_id,
            term: c.term,
            issued_at: c.issued_at,
        })
    }

    /// A point-in-time snapshot of EVERY observed lease (latest-wins, TTL-IGNORED), keyed by
    /// agent_id — the sync read shape the pure failover-detection decision consumes (mirroring how
    /// [`crate::fleet_reconcile::LeaseSnapshot`] pre-resolves the async observer into a sync view so
    /// the pure decision needs no `await`). The detector judges staleness per entry against an
    /// injected `now` + TTL, and derives the observer-blind fail-safe ("have I seen ANY fresh lease
    /// within the TTL?") from the SAME snapshot, so the decision is taken over one consistent view.
    pub async fn observed_snapshot(&self) -> std::collections::BTreeMap<String, ObservedLeaseRecord> {
        let observed = self.observed.read().await;
        observed
            .iter()
            .map(|(agent_id, c)| {
                (
                    agent_id.clone(),
                    ObservedLeaseRecord {
                        holder_node_id: c.holder_node_id,
                        term: c.term,
                        issued_at: c.issued_at,
                    },
                )
            })
            .collect()
    }

    /// Whether this node has observed AT LEAST ONE lease (for ANY agent) that is still FRESH (its
    /// `issued_at` is within the TTL) as of `now`. This is the observer-blind FAIL-SAFE signal the
    /// steady-state failover detector stands down on: a node whose relay link is down (e.g. the
    /// 55s keepalive-ping self-kill the reconcile wiring disables, main.rs) stops receiving ALL
    /// lease events, so EVERY observed lease ages past the TTL together — which is
    /// indistinguishable, per-agent, from real peer deaths. If NOTHING is fresh, the silence is far
    /// more likely OUR blindness than a simultaneous fleet-wide death, so the detector emits ZERO
    /// takeovers (see [`crate::failover_detect::detect_takeovers`]). Conversely, even one fresh
    /// lease proves the relay link is delivering, so a stale peer beside it is a genuine candidate.
    pub async fn has_fresh_lease_within_ttl(&self, now: u64) -> bool {
        let observed = self.observed.read().await;
        observed.values().any(|c| !is_stale(c.issued_at, now))
    }
}

#[async_trait::async_trait]
impl SpawnFenceView for FleetLeaseObserver {
    fn node_id(&self) -> LeaseNodeId {
        self.node_id
    }
    /// The latest observed lease for `agent_id` IF still within its TTL (a stale lease — the
    /// holder stopped heartbeating, e.g. it died — does NOT count as occupancy, so the agent can
    /// be (re)spawned). Freshness is judged at the moment of the query.
    async fn active_lease_for(&self, agent_id: &str) -> Option<ActiveLease> {
        self.fresh_active_lease_at(agent_id, now_secs()).await
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    use nostr_sdk::prelude::*;

    /// Build a lease event signed by a THROWAWAY key — the occupancy observer does NOT verify the
    /// signature (the whole point: cross-node the agent's Q is not yet known, finding G-2). The
    /// `d_tag` is separate from `agent_id` so a test can force a mis-addressed event.
    fn lease_event(agent_id: &str, holder: LeaseNodeId, term: u64, issued_at: u64, d_tag: &str) -> nostr_sdk::Event {
        let content = serde_json::to_string(&LeaseContent {
            agent_id: agent_id.to_string(),
            holder_node_id: holder,
            term,
            issued_at,
        })
        .unwrap();
        EventBuilder::new(Kind::from(kirby_proto::KIND_KIRBY_LEASE), content)
            .tags([Tag::parse(["d", d_tag]).unwrap()])
            .sign_with_keys(&Keys::generate())
            .unwrap()
    }

    #[tokio::test]
    async fn observe_latest_wins_by_monotonic_term() {
        let obs = FleetLeaseObserver::new(1);
        assert!(obs.observe_occupancy(&lease_event("a", 2, 1, 1000, "a")).await);
        // A strictly-newer term replaces it.
        assert!(obs.observe_occupancy(&lease_event("a", 3, 2, 1000, "a")).await);
        let l = obs.fresh_active_lease_at("a", 1000).await.unwrap();
        assert_eq!((l.node_id, l.term), (3, 2), "latest-wins by term");
        // An equal or older term is ignored (observe-only-forward — the term never moves backward).
        assert!(!obs.observe_occupancy(&lease_event("a", 9, 2, 1000, "a")).await, "equal term ignored");
        assert!(!obs.observe_occupancy(&lease_event("a", 9, 1, 1000, "a")).await, "older term ignored");
        let l = obs.fresh_active_lease_at("a", 1000).await.unwrap();
        assert_eq!((l.node_id, l.term), (3, 2), "term never moves backward");
    }

    #[tokio::test]
    async fn stale_lease_is_not_occupancy() {
        let obs = FleetLeaseObserver::new(1);
        assert!(obs.observe_occupancy(&lease_event("a", 2, 1, 1000, "a")).await);
        // Within the TTL the agent is occupied (a fence would back off).
        assert!(obs.fresh_active_lease_at("a", 1000 + LEASE_TTL_SECS).await.is_some(), "within TTL = occupied");
        // Past the TTL it is NOT occupancy: the holder stopped heartbeating (it died), so the
        // agent is free to (re)spawn. This is exactly what makes the heartbeat load-bearing.
        assert!(obs.fresh_active_lease_at("a", 1000 + LEASE_TTL_SECS + 1).await.is_none(), "past TTL = free");
    }

    /// HEARTBEAT REFRESH (the keystone the whole lifecycle rests on): a SAME-term re-publish with
    /// a fresher `issued_at` -- exactly what `FleetSupervisor::heartbeat_leases` emits every 10s
    /// WITHOUT bumping the term -- MUST refresh the observed lease's freshness. Otherwise a peer's
    /// occupancy fence sees a live, heartbeating agent go stale ~one TTL after launch and
    /// double-spawns it (the bug strict latest-wins-by-term hid: it dropped every same-term
    /// heartbeat, so the stored `issued_at` froze at first observation).
    #[tokio::test]
    async fn heartbeat_same_term_refreshes_freshness() {
        let obs = FleetLeaseObserver::new(1);
        // Node 2 claims agent "a" at term 1, issued_at = 1000.
        assert!(obs.observe_occupancy(&lease_event("a", 2, 1, 1000, "a")).await);
        // 20s later node 2 HEARTBEATS: SAME term 1, fresher issued_at = 1020 (no term bump).
        assert!(
            obs.observe_occupancy(&lease_event("a", 2, 1, 1020, "a")).await,
            "a same-term heartbeat with a fresher issued_at must be folded in (it refreshes the lease)"
        );
        // At 1035 the ORIGINAL issue (1000) is 35s old (> TTL) but the heartbeat (1020) is 15s old:
        // a live, heartbeating agent must still read as occupied (so a peer fence keeps backing off).
        let l = obs.fresh_active_lease_at("a", 1035).await;
        assert!(
            l.is_some_and(|l| l.node_id == 2 && l.term == 1),
            "heartbeat must keep the lease fresh for the fence (got {l:?})"
        );
        // Sanity: a same-term re-publish that is NOT fresher (a true replay/dup) is still ignored.
        assert!(
            !obs.observe_occupancy(&lease_event("a", 2, 1, 1020, "a")).await,
            "a same-term, non-fresher re-publish (replay) must be ignored"
        );
    }

    #[tokio::test]
    async fn d_tag_disagreement_and_wrong_kind_are_dropped() {
        let obs = FleetLeaseObserver::new(1);
        // A `d` tag ("x") that disagrees with the signed content's agent_id ("y") is dropped.
        assert!(!obs.observe_occupancy(&lease_event("y", 2, 1, 1000, "x")).await);
        assert!(obs.fresh_active_lease_at("y", 1000).await.is_none());
        assert!(obs.fresh_active_lease_at("x", 1000).await.is_none());
        // A non-lease kind is dropped.
        let wrong = EventBuilder::new(Kind::from(1u16), "{}").sign_with_keys(&Keys::generate()).unwrap();
        assert!(!obs.observe_occupancy(&wrong).await);
    }

    /// The ADDITIVE accessor `latest_observed_lease` exposes the raw stored lease IGNORING the TTL,
    /// so a caller can tell STALE (seen, went quiet) apart from ABSENT (never seen) — the
    /// distinction the failover detector needs but the TTL-filtered fresh projection collapses.
    #[tokio::test]
    async fn latest_observed_lease_distinguishes_stale_from_absent() {
        let obs = FleetLeaseObserver::new(1);
        // A NEVER-seen agent is None on BOTH the fresh projection and the raw accessor.
        assert!(obs.latest_observed_lease("ghost").await.is_none(), "never-observed => absent (None)");
        // Observe a lease for "a" at term 4, issued_at 1000.
        assert!(obs.observe_occupancy(&lease_event("a", 2, 4, 1000, "a")).await);
        // FAR past the TTL, the FRESH projection collapses to None (looks the same as absent)...
        assert!(obs.fresh_active_lease_at("a", 1000 + LEASE_TTL_SECS + 100).await.is_none());
        // ...but the raw accessor STILL returns the observed lease (holder/term/issued_at intact),
        // so the detector can see it is STALE (seen) rather than ABSENT (never seen).
        let raw = obs.latest_observed_lease("a").await.expect("a stale lease is still observed");
        assert_eq!(
            raw,
            ObservedLeaseRecord { holder_node_id: 2, term: 4, issued_at: 1000 },
            "the raw accessor must carry holder + the OBSERVED term + the signed issued_at, TTL-ignored"
        );
    }

    /// The observer-blind FAIL-SAFE signal `has_fresh_lease_within_ttl`: true only while AT LEAST
    /// one observed lease is still fresh at `now`. When the relay link drops, all observed leases
    /// age past the TTL together and this goes false — the detector's stand-down trigger.
    #[tokio::test]
    async fn has_fresh_lease_within_ttl_tracks_freshness() {
        let obs = FleetLeaseObserver::new(1);
        // No observations yet => nothing fresh (a brand-new, not-yet-synced observer is "blind").
        assert!(!obs.has_fresh_lease_within_ttl(1000).await, "no observations => not fresh");
        // Two leases observed at issued_at 1000.
        assert!(obs.observe_occupancy(&lease_event("a", 2, 1, 1000, "a")).await);
        assert!(obs.observe_occupancy(&lease_event("b", 3, 1, 1000, "b")).await);
        // Within the TTL at least one is fresh => the link is delivering.
        assert!(obs.has_fresh_lease_within_ttl(1000 + LEASE_TTL_SECS).await, "within TTL => a fresh lease exists");
        // Past the TTL for BOTH (the signature of a dropped link): nothing fresh => stand-down signal.
        assert!(
            !obs.has_fresh_lease_within_ttl(1000 + LEASE_TTL_SECS + 1).await,
            "all leases aged past TTL => no fresh lease => observer-blind"
        );
    }

    /// `observed_snapshot` drains EVERY observed lease (TTL-ignored, latest-wins) into the sync view
    /// the pure detector consumes — so the decision is taken over one consistent point-in-time
    /// snapshot rather than racing per-agent reads against the live map.
    #[tokio::test]
    async fn observed_snapshot_drains_all_latest_observed_leases() {
        let obs = FleetLeaseObserver::new(1);
        assert!(obs.observe_occupancy(&lease_event("a", 2, 1, 1000, "a")).await);
        assert!(obs.observe_occupancy(&lease_event("b", 3, 5, 2000, "b")).await);
        // A later takeover of "a" at term 2 by node 9 (latest-wins by term) is what the snapshot shows.
        assert!(obs.observe_occupancy(&lease_event("a", 9, 2, 1500, "a")).await);
        let snap = obs.observed_snapshot().await;
        assert_eq!(snap.len(), 2);
        assert_eq!(snap["a"], ObservedLeaseRecord { holder_node_id: 9, term: 2, issued_at: 1500 });
        assert_eq!(snap["b"], ObservedLeaseRecord { holder_node_id: 3, term: 5, issued_at: 2000 });
    }

    /// THE READ-AFTER-WRITE LAUNCH FENCE decision (failover bug G-1 on the launch path). Given the
    /// lease that SURVIVED at the relay after our `claim_at(term+1)` published, `confirm_takeover_win`
    /// admits a launch ONLY when this node is the surviving holder at exactly the claimed term —
    /// every other shape (a peer won at our term, a higher term beat us, a lower term, or no lease
    /// at all) FAILS CLOSED. This is the predicate that turns two racing survivors into one launcher.
    #[test]
    fn confirm_takeover_win_admits_only_the_surviving_holder_at_the_claimed_term() {
        const ME: LeaseNodeId = 2;
        let claimed = 5u64;
        let rec = |holder, term| ObservedLeaseRecord { holder_node_id: holder, term, issued_at: 1000 };

        // WIN: we are the surviving holder at exactly our claimed term -> launch.
        assert!(
            confirm_takeover_win(Some(rec(ME, claimed)), claimed, ME),
            "this node holds the surviving lease at the claimed term => it won the race => launch"
        );

        // LOSE (equal-term race, the relay's latest-wins kept the PEER): a DIFFERENT holder at our
        // exact term is the deterministic equal-term tiebreak resolving against us -> stand down.
        assert!(
            !confirm_takeover_win(Some(rec(3, claimed)), claimed, ME),
            "a peer holds the surviving lease at the SAME term (relay latest-wins resolved against us) => abort"
        );

        // LOSE (a peer bumped the fencing token past ours): a strictly higher term -> stand down.
        assert!(
            !confirm_takeover_win(Some(rec(3, claimed + 1)), claimed, ME),
            "a peer's higher-term lease survived => they won => abort"
        );
        // Even if the higher-term holder were somehow US, it is not the term we claimed -> fail closed.
        assert!(
            !confirm_takeover_win(Some(rec(ME, claimed + 1)), claimed, ME),
            "a surviving term that is not the one we claimed cannot confirm THIS claim => abort"
        );

        // FAIL CLOSED: a lower term, or no lease at all, cannot confirm our own claim is live.
        assert!(
            !confirm_takeover_win(Some(rec(ME, claimed - 1)), claimed, ME),
            "a lower surviving term means our claim is not the latest we can see => abort"
        );
        assert!(
            !confirm_takeover_win(None, claimed, ME),
            "no surviving lease => the relay could not confirm our claim => fail closed, do not launch"
        );
    }
}

/// Q-VERIFICATION of the read-after-write fence (finding G-2 hardening). The fence's surviving-lease
/// selection must trust ONLY a lease validly FROST-signed under the agent's expected quorum key Q;
/// a forged / relay-injected lease (any other signing key, or a tampered one) must be DROPPED before
/// it can sway `confirm_takeover_win`. These teeth exercise the PURE selection
/// (`select_verified_latest_lease`) so they need no relay -- the verification counterpart of the
/// pure `confirm_takeover_win` test above. Each is RED on revert (remove the Q-verify and the
/// forged event wins the `(term, issued_at)` max).
#[cfg(test)]
mod fence_qverify_tests {
    use super::*;
    use crate::quorum_signer::local_quorum_from_keyset;
    use kirby_custody::generate_dealer_keyset;

    /// Sign a lease event under `signer`'s quorum key Q with FULLY CONTROLLED fields (holder, term,
    /// issued_at) -- a GENUINE lease iff `signer`'s Q is the one the verifier expects, a FORGERY when
    /// `signer` is some OTHER keyset's quorum. Lets a test pin holder/term/issued_at deterministically
    /// (unlike `RelayLeaseAuthority::claim`, which stamps issued_at = wall clock).
    fn sign_lease(
        signer: &QuorumSigner,
        agent_id: &str,
        holder: LeaseNodeId,
        term: u64,
        issued_at: u64,
    ) -> NostrEvent {
        let content = serde_json::to_string(&LeaseContent {
            agent_id: agent_id.to_string(),
            holder_node_id: holder,
            term,
            issued_at,
        })
        .unwrap();
        let tags = vec![vec![TAG_D.to_string(), agent_id.to_string()]];
        signer
            .sign_nostr_event_with_tags(kirby_proto::KIND_KIRBY_LEASE as u32, issued_at, &tags, &content)
            .expect("sign a lease event under the quorum key Q")
    }

    /// A fresh 2-of-3 quorum signer over a new dealer keyset (its own Q).
    fn signer() -> QuorumSigner {
        local_quorum_from_keyset(&generate_dealer_keyset(2, 3).expect("dealer keyset"))
            .expect("build quorum signer")
    }

    /// BASELINE: a genuine Q-signed lease verifies and is selected (the verifier does not reject a
    /// real lease). Stays GREEN on revert -- it does not depend on the dropping behavior.
    #[test]
    fn genuine_q_lease_is_selected() {
        let s = signer();
        let q = s.q_bytes();
        let ev = sign_lease(&s, "agentA", 2, 5, 1000);
        assert_eq!(
            select_verified_latest_lease(&[ev], "agentA", &q),
            Some(ObservedLeaseRecord { holder_node_id: 2, term: 5, issued_at: 1000 }),
            "a genuine Q-signed lease must verify and be selected"
        );
    }

    /// DIRECTION A (liveness / no wrongful stand-down): a forged lease naming ANOTHER holder at a
    /// HIGHER term must be dropped, so the surviving record still names THIS node (ME) at the claimed
    /// term and `confirm_takeover_win` lets ME launch. RED on revert: the forged higher-term event
    /// wins the max -> surviving names OTHER -> confirm == false -> ME wrongly stands down.
    #[test]
    fn forged_other_holder_higher_term_dropped_no_wrongful_standdown() {
        const ME: LeaseNodeId = 2;
        const OTHER: LeaseNodeId = 9;
        let claimed = 5u64;
        let agent = signer(); // holds the real Q
        let q = agent.q_bytes();
        let forger = signer(); // a DIFFERENT keyset -> a different Q (the attacker)

        let genuine = sign_lease(&agent, "agentA", ME, claimed, 1000);
        let forged = sign_lease(&forger, "agentA", OTHER, claimed + 1, 2000); // higher term + fresher

        let got = select_verified_latest_lease(&[genuine, forged], "agentA", &q);
        assert_eq!(
            got,
            Some(ObservedLeaseRecord { holder_node_id: ME, term: claimed, issued_at: 1000 }),
            "the forged higher-term lease (wrong Q) must be DROPPED; the genuine ME-lease survives"
        );
        assert!(
            confirm_takeover_win(got, claimed, ME),
            "forgery dropped => ME is the surviving holder at the claimed term => launch (no wrongful stand-down)"
        );
    }

    /// DIRECTION B (THE MONEY TEETH -- double-spend): a forged lease naming THIS node (ME) at the
    /// claimed term, with a FRESHER issued_at, must be dropped when a PEER legitimately holds the
    /// lease -- so `confirm_takeover_win` keeps ME standing down (the peer keeps the agent; no
    /// double-launch). RED on revert: the forged ME-lease wins the tie on issued_at -> confirm ==
    /// true -> ME ALSO launches -> DOUBLE-LAUNCH (the exact double-spend the fence exists to stop).
    #[test]
    fn forged_self_named_lease_dropped_no_double_launch() {
        const ME: LeaseNodeId = 2;
        const PEER: LeaseNodeId = 9;
        let claimed = 5u64;
        let agent = signer();
        let q = agent.q_bytes();
        let forger = signer(); // attacker's keyset (not the agent's Q)

        let genuine_peer = sign_lease(&agent, "agentA", PEER, claimed, 1000); // the peer legitimately won
        let forged_me = sign_lease(&forger, "agentA", ME, claimed, 2000); // attacker: "ME won", fresher

        let got = select_verified_latest_lease(&[genuine_peer, forged_me], "agentA", &q);
        assert_eq!(
            got,
            Some(ObservedLeaseRecord { holder_node_id: PEER, term: claimed, issued_at: 1000 }),
            "the forged self-named lease (wrong Q) must be DROPPED; the genuine PEER-lease survives"
        );
        assert!(
            !confirm_takeover_win(got, claimed, ME),
            "forgery dropped => the surviving holder is the PEER => ME stands down (NO double-launch)"
        );
    }

    /// A genuine Q-lease that is later TAMPERED (content mutated, original id + sig kept) fails the
    /// NIP-01 id re-derivation under Q and is dropped -- both alongside a genuine lease and alone.
    #[test]
    fn tampered_lease_content_is_dropped() {
        let s = signer();
        let q = s.q_bytes();
        let genuine = sign_lease(&s, "agentA", 2, 5, 1000);
        let tampered_content = serde_json::to_string(&LeaseContent {
            agent_id: "agentA".to_string(),
            holder_node_id: 9,
            term: 99,
            issued_at: 9000,
        })
        .unwrap();
        // Tampered ALONGSIDE the genuine: only the genuine (lower term) survives -- the tampered one
        // claims a far higher term but its id no longer matches its content under Q, so it is dropped.
        let mut tampered = genuine.clone();
        tampered.content = tampered_content.clone();
        assert_eq!(
            select_verified_latest_lease(&[tampered, genuine.clone()], "agentA", &q),
            Some(ObservedLeaseRecord { holder_node_id: 2, term: 5, issued_at: 1000 }),
            "a tampered lease (id != content under Q) must be dropped; the genuine one survives"
        );
        // Tampered ALONE: nothing verifies -> None -> the caller fails closed.
        let mut tampered_only = genuine;
        tampered_only.content = tampered_content;
        assert_eq!(
            select_verified_latest_lease(&[tampered_only], "agentA", &q),
            None,
            "a tampered lease alone leaves no verified survivor"
        );
    }

    /// ALL-FORGED -> None: when every fetched event is signed under a non-Q key, no verified lease
    /// survives, so the fence reports None and the launch fails closed (stands down). RED on revert:
    /// a forged event would be selected -> Some -> a launch on an unverifiable claim.
    #[test]
    fn all_forged_yields_none_fail_closed() {
        let q = signer().q_bytes();
        let forged1 = sign_lease(&signer(), "agentA", 9, 7, 3000);
        let forged2 = sign_lease(&signer(), "agentA", 8, 6, 2000);
        assert_eq!(
            select_verified_latest_lease(&[forged1, forged2], "agentA", &q),
            None,
            "no lease signed under the expected Q => None => the caller fails closed"
        );
        assert!(!confirm_takeover_win(None, 7, 2), "None => stand down (no launch)");
    }
}
