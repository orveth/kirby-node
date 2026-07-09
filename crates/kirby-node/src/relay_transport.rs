//! S5/S6 (the keystone): the RELAY-NATIVE [`HolderTransport`] + the holder-side server loop.
//!
//! [`crate::remote_holder`] built the `RemoteHolder` proxy + the `RemoteHolderServer` and an
//! IN-PROCESS mock link ([`crate::remote_holder::InProcessHolderLink`]) for fast ungated
//! teeth. This module is the REAL transport that link's doc-comment promised "drops in
//! unchanged": it carries the SAME opaque [`CoSignEvent`]s over the shared Nostr fleet relay,
//! so a coordinator on one machine reaches a share-holder's `RemoteHolderServer` on ANOTHER
//! machine. It is the network layer of cross-machine FROST; the crypto + the membrane are
//! already proven (and unchanged).
//!
//! THE OPACITY CONTRACT (preserved, and the whole reason a relay drops in): the carrier (the
//! relay + this transport's routing) reads ONLY the routing surface -- the recipient (`#p`
//! tag), the kind, and, after decode, `(session_id, round, from)` -- and treats the FROST
//! `payload` as OPAQUE bytes it NEVER deserializes as a FROST type. This is exactly what
//! custody `seam.rs`'s `InMemoryRelay` and `remote_holder`'s `InProcessHolderLink` prove; the
//! `nonce_never_crosses` invariant therefore holds over the wire too (only public
//! commitments + partial signature shares + the public `SigningPackage` ever cross; see the
//! byte-level test below).
//!
//! WIRE FORMAT: one [`CoSignEvent`] becomes one [`kirby_proto::KIND_KIRBY_COSIGN`] (ephemeral)
//! Nostr event. The event is SIGNED BY THE SENDER NODE'S TRANSPORT KEY (sender-auth +
//! integrity for free via `event.verify()`) and `#p`-ADDRESSED to the recipient node's
//! transport key (the relay's routing primitive). The opaque `CoSignEvent` rides in the
//! content as a [`CoSignWire`] (its fields mirrored, the `payload` hex-encoded -- `CoSignEvent`
//! itself is not `Serialize`). NO secret crosses: signing frames are PUBLIC material, so they
//! are authenticated but NOT encrypted (gudnuf-confirmed: the turtle+LNVPS proof published
//! commitments + shares on a plain relay and it verified). The SECRET share-ship path (a
//! holder's `KeyPackage`) is a SEPARATE, NIP-44-ENCRYPTED kind -- it lives with the remote
//! `ShareSink`, not here.
//!
//! THE SYNC SEAM (why the `Holder` trait stays sync): [`HolderTransport`] is deliberately
//! synchronous so a `RemoteHolder` satisfies the sync `Holder` trait WITHOUT changing the
//! `QuorumSigner` ceremony body. A real relay client is async, so [`CoordinatorRelayHub`]
//! runs a BACKGROUND ACTOR (its own thread + current-thread runtime) that owns the relay
//! connection; the sync [`RelayHolderTransport::send`]/`recv` bridge to it over channels:
//!   * `send` enqueues an outbound frame on an UNBOUNDED channel (NON-blocking, safe from any
//!     context -- it never blocks a runtime worker).
//!   * `recv` BLOCKS the calling thread on a `std::sync::mpsc` channel up to a per-wire
//!     TIMEOUT, returning `Err` on timeout -- exactly the "the timeout lives INSIDE the
//!     transport" the `QuorumSigner` doc anticipates, which the any-available-2-of-3 fallback
//!     turns into "abandon this subset, try another reachable one".
//!
//! Because `recv` blocks the caller, the LIVE sign path must drive the ceremony OFF the async
//! runtime (a `spawn_blocking`); the boot-wiring lane handles that. The in-file tests are
//! plain sync `#[test]`s (like `remote_holder`'s), which is the natural fit.
//!
//! DEMUX (one connection, N holders): a coordinator runs N `RemoteHolder`s for an agent's N
//! shares but holds ONE relay connection (subscription `#p = my transport pubkey`). The actor
//! routes each inbound reply to the right holder's `recv` by the reply's SENDER transport
//! pubkey (the holder's key). Routing by the network identity -- not by the FROST `from` u16
//! -- is what the endpoint-auth slice tightens (only the expected holder pubkey for a share);
//! `RemoteHolder`'s own `from`-u16 + `session_id` checks stay on top.
//!
//! ENDPOINT AUTH (this lane's deliverable, layered on top, NOT a post-merge TODO): the holder
//! consults a [`CoordinatorAuthorizer`] BEFORE it handles a solicit, so a rogue/un-entitled
//! node cannot drive a holder through ceremonies (nonce-burn / grief). The MVP authorizer
//! (added in the auth slice) accepts a solicit ONLY from the node holding the agent's current
//! FROST relay lease ([`crate::relay_lease`]) whose transport pubkey is the one
//! `distributed-spawn` provisioned (placement.json). This module ships the SEAM
//! ([`CoordinatorAuthorizer`]) + an [`allow_all_coordinators`] stub for the auth-independent
//! core; the lease+placement authorizer drops in without touching the transport.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver as StdReceiver, RecvTimeoutError, Sender as StdSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use nostr_sdk::nips::nip44::{self, Version};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use kirby_custody::seam::{CoSignEvent, GuardianId};

use crate::keyset_provisioning::{LocalSealedSink, ShareSink};
use crate::quorum_signer::CeremonyGate;
use crate::remote_holder::{HolderTransport, HolderTransportFactory, RemoteHolderServer};

/// The default per-wire timeout a [`RelayHolderTransport::recv`] waits for a reply before
/// returning `Err` (which the any-available-2-of-3 fallback treats as "this holder is
/// unreachable; try another subset"). A real cross-machine round-trip over a relay is well
/// under a second; this generous bound tolerates a slow relay without hanging a ceremony.
pub const DEFAULT_WIRE_TIMEOUT: Duration = Duration::from_secs(10);

/// Session-scoped inbound PROBE-reply routing: (holder transport pubkey, probe session id) -> that
/// probe's reply channel. Held separately from the signer's per-holder `routes` so a probe and a
/// live ceremony can never clobber each other (the F2 non-mutating routing fix); see
/// [`CoordinatorRelayHub::connect_probe`].
type ProbeRoutes = Arc<Mutex<HashMap<(PublicKey, u64), StdSender<CoSignEvent>>>>;

/// Session-scoped inbound THRESHOLD-ECDH-reply routing: (holder transport pubkey, ECDH session id)
/// -> that ceremony's reply channel. Held SEPARATELY from the signer's per-holder `routes` (exactly
/// like [`ProbeRoutes`]) so a single-round ECDH ceremony can never clobber the memoized signer's
/// route for the same holder; see [`CoordinatorRelayHub::connect_ecdh`]. Same shape as `ProbeRoutes`
/// but a DISTINCT map (a probe session id and an ECDH session id come from different counters, so
/// they must not share a keyspace).
type EcdhRoutes = Arc<Mutex<HashMap<(PublicKey, u64), StdSender<CoSignEvent>>>>;

/// A holder-side gate: may this coordinator (its transport pubkey) solicit a co-sign for this
/// agent right now? Consulted by [`run_holder_server`] BEFORE it lets a frame reach the
/// `RemoteHolderServer`, so an un-entitled node cannot burn a holder's nonces or grief it.
///
/// The auth-independent core uses [`allow_all_coordinators`]; the endpoint-auth slice supplies
/// the real MVP authorizer (accept ONLY the current relay-lease holder whose transport pubkey
/// matches the provisioned placement), WITHOUT changing this transport.
pub type CoordinatorAuthorizer =
    Arc<dyn Fn(&str, &PublicKey) -> bool + Send + Sync + 'static>;

/// The auth-independent STUB authorizer: accept every coordinator. Used by the transport core
/// and its tests. PRODUCTION MUST NOT ship with this -- the lease+placement authorizer
/// replaces it before any live cross-machine use (this lane's merged deliverable).
pub fn allow_all_coordinators() -> CoordinatorAuthorizer {
    Arc::new(|_agent_id: &str, _coordinator: &PublicKey| true)
}

/// The on-the-wire form of an opaque [`CoSignEvent`]. `CoSignEvent` derives only `Debug +
/// Clone` (custody `seam.rs`), so we mirror its fields for serde. `from` is the FROST
/// [`GuardianId`] (serde via the frost `serde` feature). `payload` is the OPAQUE FROST bytes
/// (a serialized public `SigningCommitments` / `SignatureShare` / `SigningPackage`), carried
/// hex-encoded -- this codec NEVER deserializes it as a FROST type, preserving the opacity
/// contract (the byte-level test asserts no `SigningNonces` is recoverable from it).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoSignWire {
    /// The agent whose quorum this frame belongs to (binds a frame to one agent on a shared
    /// relay; the hub/holder drop a frame whose `agent_id` is not theirs).
    agent_id: String,
    session_id: u64,
    from: GuardianId,
    round: u8,
    /// The opaque FROST payload, hex-encoded. NEVER interpreted here.
    payload_hex: String,
}

impl CoSignWire {
    fn from_cosign(agent_id: &str, ev: &CoSignEvent) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            session_id: ev.session_id,
            from: ev.from,
            round: ev.round,
            payload_hex: hex::encode(&ev.payload),
        }
    }

    fn into_cosign(self) -> anyhow::Result<CoSignEvent> {
        let payload = hex::decode(&self.payload_hex)
            .context("decode the opaque CoSignEvent payload hex")?;
        Ok(CoSignEvent {
            session_id: self.session_id,
            from: self.from,
            round: self.round,
            payload,
        })
    }
}

/// Wrap an opaque [`CoSignEvent`] in a signed, `#p`-addressed [`kirby_proto::KIND_KIRBY_COSIGN`]
/// Nostr event. Signed by `signer` (the sender node's transport key -> sender-auth) and
/// addressed to `recipient` (the relay's routing primitive). The `["t","kirby"]` + `["a",agent]`
/// tags are discovery/observability only; routing is by `#p` + kind, and decode reads the
/// content -- never these tags -- so the relay never needs to parse the FROST payload.
pub(crate) fn encode_cosign_frame(
    agent_id: &str,
    event: &CoSignEvent,
    recipient: PublicKey,
    signer: &Keys,
) -> anyhow::Result<Event> {
    let wire = CoSignWire::from_cosign(agent_id, event);
    let content = serde_json::to_string(&wire).context("serialize CoSignWire")?;
    let tags = vec![
        Tag::public_key(recipient),
        Tag::parse(["t", "kirby"]).context("t tag")?,
        Tag::parse(["a", agent_id]).context("a tag")?,
    ];
    EventBuilder::new(Kind::from(kirby_proto::KIND_KIRBY_COSIGN), content)
        .tags(tags)
        .sign_with_keys(signer)
        .map_err(|e| anyhow::anyhow!("sign co-sign frame: {e}"))
}

/// Verify + decode a [`kirby_proto::KIND_KIRBY_COSIGN`] Nostr event back into its opaque
/// [`CoSignEvent`] and the SENDER's transport pubkey (`event.pubkey`). The signature/id are
/// verified (the trust boundary, same wall as `verify_and_enqueue`); the kind is re-checked
/// (never trust the relay filter). Returns `(agent_id, CoSignEvent, sender)`.
pub(crate) fn decode_cosign_frame(
    event: &Event,
) -> anyhow::Result<(String, CoSignEvent, PublicKey)> {
    event
        .verify()
        .map_err(|e| anyhow::anyhow!("co-sign frame failed signature/id verification: {e}"))?;
    if event.kind != Kind::from(kirby_proto::KIND_KIRBY_COSIGN) {
        anyhow::bail!(
            "not a co-sign frame (kind {}, expected {})",
            event.kind.as_u16(),
            kirby_proto::KIND_KIRBY_COSIGN
        );
    }
    let wire: CoSignWire =
        serde_json::from_str(&event.content).context("deserialize CoSignWire from frame content")?;
    let agent_id = wire.agent_id.clone();
    let cosign = wire.into_cosign()?;
    Ok((agent_id, cosign, event.pubkey))
}

/// Read the FIRST `#p` recipient pubkey off an event (the relay's routing primitive). Used by
/// the in-memory relay double to route exactly as a real relay's `#p` index does (it never
/// reads content). TEST-ONLY: the production `RelayConn` relies on the relay's own `#p`
/// subscription filter for routing and the actor demuxes by `event.pubkey` (the sender), so no
/// production path reads the recipient tag back.
#[cfg(test)]
fn recipient_pubkey(event: &Event) -> Option<PublicKey> {
    event.tags.iter().find_map(|t| {
        let s = t.as_slice();
        if s.first().map(|k| k.as_str() == "p").unwrap_or(false) {
            s.get(1).and_then(|hex| PublicKey::from_hex(hex.as_str()).ok())
        } else {
            None
        }
    })
}

/// The minimal async relay capability the transport needs. The production impl wraps a
/// nostr-sdk `Client` (subscribed to `#p = me` + [`kirby_proto::KIND_KIRBY_COSIGN`]); the test
/// impl ([`InMemoryRelay`]) is an in-memory double that routes by `#p` + kind and NEVER reads
/// content (the opacity contract). Kept generic (not `dyn`) so the actor's current-thread
/// runtime needs no `Send` futures.
#[allow(async_fn_in_trait)]
pub trait RelayConn: Send + 'static {
    /// Publish one (already-signed) event to the relay.
    async fn publish(&self, event: Event) -> anyhow::Result<()>;
    /// Receive the next event matching this connection's subscription.
    async fn next_event(&self) -> anyhow::Result<Event>;
}

/// The coordinator-side relay hub: ONE relay connection shared by all of an agent's
/// `RemoteHolder`s, driven by a background actor thread. [`Self::connect`] returns a sync
/// [`RelayHolderTransport`] per holder; the actor demuxes inbound replies to the right one by
/// the reply's sender transport pubkey.
pub struct CoordinatorRelayHub {
    /// This coordinator's transport key (signs outbound frames). Cloned into each transport.
    coordinator_keys: Keys,
    /// The agent whose quorum this hub coordinates (binds frames + the `#a` tag).
    agent_id: String,
    /// Outbound frames -> the actor (unbounded so `send` is non-blocking + context-safe).
    outbound_tx: UnboundedSender<Event>,
    /// Inbound-reply routing: holder transport pubkey -> that holder's reply channel. The
    /// actor reads it on every inbound frame; [`Self::connect`] registers a route.
    routes: Arc<Mutex<HashMap<PublicKey, StdSender<CoSignEvent>>>>,
    /// Inbound PROBE-reply routing, held SEPARATELY from `routes` (keyed by (holder pubkey, probe
    /// session id)) so a takeover-admission liveness probe ([`crate::quorum_probe`]) and a live
    /// signing ceremony over the SAME holder can never clobber each other's reply route. A probe
    /// registers a SESSION-SCOPED route via [`Self::connect_probe`]; the actor demuxes a
    /// `ROUND_PROBE_ACK` reply here and EVERY other reply (commitment / share / refusal) through
    /// `routes` (unchanged). A probe route is removed when its transport drops, so the map holds
    /// only in-flight probes (bounded over a long-lived node's periodic failover probes).
    probe_routes: ProbeRoutes,
    /// Session-scoped ECDH-reply routing (see [`EcdhRoutes`]): the single-round threshold-ECDH
    /// ceremony ([`crate::quorum_ecdh`]) registers a route here via [`Self::connect_ecdh`], so its
    /// contribution/refusal reply demuxes SEPARATELY from the memoized signer's per-holder `routes`.
    /// A route is removed when its transport drops, so the map holds only in-flight ECDH ceremonies.
    ecdh_routes: EcdhRoutes,
    /// The per-wire `recv` timeout handed to each transport.
    timeout: Duration,
    /// The PER-AGENT ceremony serializer (see [`CeremonyGate`]). The hub is the agent's ONE
    /// transport authority, so it owns the ONE gate every ceremony over these holders holds. Handed
    /// to the distributed [`crate::quorum_signer::QuorumSigner`] (and the future ECDH path) so all
    /// of an agent's ceremonies serialize; a distributed signer cannot be built without it.
    ceremony_gate: CeremonyGate,
    /// The actor thread handle (joined on drop so the thread does not outlive the hub).
    actor: Option<std::thread::JoinHandle<()>>,
}

impl CoordinatorRelayHub {
    /// Start a hub over `conn` (already connected + subscribed to `#p = coordinator pubkey` +
    /// the co-sign kind). Spawns the background actor thread (its own current-thread runtime).
    ///
    /// pub(crate), NOT pub: starting a coordinator hub is HALF of engaging distributed signing
    /// (the other half is [`crate::keyset_provisioning::load_quorum_signer_distributed`]). The only
    /// pub engager is [`AgentCosign::build`], which starts the hub IFF the ON-flip flag is set --
    /// so there is no flag-blind route to distributed signing. In-crate callers are `AgentCosign` +
    /// the tests; no downstream/integration-crate caller exists.
    pub(crate) fn start<C: RelayConn>(
        conn: C,
        coordinator_keys: Keys,
        agent_id: impl Into<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let agent_id = agent_id.into();
        let (outbound_tx, outbound_rx) = unbounded_channel::<Event>();
        let routes: Arc<Mutex<HashMap<PublicKey, StdSender<CoSignEvent>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let probe_routes: ProbeRoutes =
            Arc::new(Mutex::new(HashMap::new()));
        let ecdh_routes: EcdhRoutes = Arc::new(Mutex::new(HashMap::new()));
        let actor_routes = Arc::clone(&routes);
        let actor_probe_routes = Arc::clone(&probe_routes);
        let actor_ecdh_routes = Arc::clone(&ecdh_routes);
        let actor_agent = agent_id.clone();
        let actor = std::thread::Builder::new()
            .name("kirby-cosign-coordinator".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "co-sign coordinator actor: failed to build runtime");
                        return;
                    }
                };
                rt.block_on(coordinator_actor(
                    conn,
                    outbound_rx,
                    actor_routes,
                    actor_probe_routes,
                    actor_ecdh_routes,
                    actor_agent,
                ));
            })
            .context("spawn the co-sign coordinator actor thread")?;
        Ok(Self {
            coordinator_keys,
            agent_id,
            outbound_tx,
            routes,
            probe_routes,
            ecdh_routes,
            timeout,
            // ONE gate per hub = one per agent; every sign site loads the memoized distributed
            // signer built from this hub, so they all share this gate and serialize.
            ceremony_gate: CeremonyGate::new(),
            actor: Some(actor),
        })
    }

    /// Connect a [`RelayHolderTransport`] to the holder named by `address`
    /// (`<holder_transport_pubkey_hex>@<relay_csv>`; the relay part is the holder's reach and
    /// is honored by the production `RelayConn`, ignored by the in-memory double). Registers a
    /// reply route keyed by the holder's transport pubkey and returns the sync transport.
    ///
    /// Returns the CONCRETE transport. The cross-lane `HolderTransportFactory::connect(&str)`
    /// (landed on main by `distributed-spawn`) boxes this -- the `impl HolderTransportFactory
    /// for CoordinatorRelayHub` is added when this branch rebases onto that merged trait. The
    /// `address` is the SAME opaque token `distributed-spawn` persists in `placement.json` for
    /// both provisioning (the remote `ShareSink`) and signing (here).
    pub fn connect(&self, address: &str) -> anyhow::Result<RelayHolderTransport> {
        let (holder_pubkey, _relays) = parse_holder_address(address)?;
        let (reply_tx, reply_rx) = std::sync::mpsc::channel::<CoSignEvent>();
        self.routes
            .lock()
            .map_err(|_| anyhow::anyhow!("co-sign hub routes poisoned"))?
            .insert(holder_pubkey, reply_tx);
        Ok(RelayHolderTransport {
            agent_id: self.agent_id.clone(),
            holder_pubkey,
            coordinator_keys: self.coordinator_keys.clone(),
            outbound_tx: self.outbound_tx.clone(),
            // `std::sync::mpsc::Receiver` is `!Sync`; a `RemoteHolder<T>` requires `T: Send +
            // Sync` (the `Holder: Send + Sync` bound). Wrap the receiver in a `Mutex` (it is
            // `Send`, so `Mutex<Receiver>` is `Send + Sync`). `recv` is called by one ceremony
            // thread at a time per transport, so the lock is uncontended.
            reply_rx: Mutex::new(reply_rx),
            timeout: self.timeout,
            // A signing transport uses the session-AGNOSTIC `routes` map; no per-transport
            // cleanup (its route is bounded -- one per holder -- and lives for the hub). Byte
            // identical to before `probe_routes` existed.
            probe_route: None,
            ecdh_route: None,
        })
    }

    /// Connect a SESSION-SCOPED transport for a takeover-admission liveness probe
    /// ([`crate::quorum_probe`]). Unlike [`Self::connect`], its reply route lands in `probe_routes`
    /// keyed by (holder pubkey, `session_id`), so registering it can NEVER overwrite the memoized
    /// signer's session-agnostic `routes` entry for the same holder (the pre-#49 clobber: a bare
    /// `routes.insert(pubkey, ..)` shared one channel per holder, so a probe's connect stole the
    /// live signer's reply route). The returned transport removes its own probe route on drop, so a
    /// per-probe route never outlives its one round-trip. Its `send` carries `ROUND_PROBE`, and the
    /// holder answers `ROUND_PROBE_ACK` echoing `session_id` -- which the actor demuxes back here.
    pub fn connect_probe(
        &self,
        address: &str,
        session_id: u64,
    ) -> anyhow::Result<RelayHolderTransport> {
        let (holder_pubkey, _relays) = parse_holder_address(address)?;
        let (reply_tx, reply_rx) = std::sync::mpsc::channel::<CoSignEvent>();
        self.probe_routes
            .lock()
            .map_err(|_| anyhow::anyhow!("co-sign hub probe routes poisoned"))?
            .insert((holder_pubkey, session_id), reply_tx);
        Ok(RelayHolderTransport {
            agent_id: self.agent_id.clone(),
            holder_pubkey,
            coordinator_keys: self.coordinator_keys.clone(),
            outbound_tx: self.outbound_tx.clone(),
            reply_rx: Mutex::new(reply_rx),
            timeout: self.timeout,
            // Remove THIS probe's (pubkey, session) route when the transport drops (probe done,
            // whether it got an ack or timed out) so `probe_routes` tracks only live probes.
            probe_route: Some(ProbeRouteHandle {
                probe_routes: Arc::clone(&self.probe_routes),
                key: (holder_pubkey, session_id),
            }),
            ecdh_route: None,
        })
    }

    /// Connect a SESSION-SCOPED transport for a single-round THRESHOLD-ECDH ceremony
    /// ([`crate::quorum_ecdh::QuorumEcdh`] distributed mode). Mirrors [`Self::connect_probe`]: its
    /// reply route lands in `ecdh_routes` keyed by (holder pubkey, `session_id`), so registering it
    /// can NEVER overwrite the memoized signer's session-agnostic `routes` entry for the same holder
    /// (the same clobber `connect_probe` was built to avoid). The returned transport removes its own
    /// ECDH route on drop. Its `send` carries [`crate::remote_holder::ROUND_ECDH_REQUEST`]; the holder
    /// answers `ROUND_ECDH_CONTRIBUTION` (or `ROUND_ECDH_REFUSAL`) echoing `session_id`, which the
    /// actor demuxes back here.
    pub fn connect_ecdh(
        &self,
        address: &str,
        session_id: u64,
    ) -> anyhow::Result<RelayHolderTransport> {
        let (holder_pubkey, _relays) = parse_holder_address(address)?;
        let (reply_tx, reply_rx) = std::sync::mpsc::channel::<CoSignEvent>();
        self.ecdh_routes
            .lock()
            .map_err(|_| anyhow::anyhow!("co-sign hub ecdh routes poisoned"))?
            .insert((holder_pubkey, session_id), reply_tx);
        Ok(RelayHolderTransport {
            agent_id: self.agent_id.clone(),
            holder_pubkey,
            coordinator_keys: self.coordinator_keys.clone(),
            outbound_tx: self.outbound_tx.clone(),
            reply_rx: Mutex::new(reply_rx),
            timeout: self.timeout,
            probe_route: None,
            // Remove THIS ceremony's (pubkey, session) route when the transport drops.
            ecdh_route: Some(EcdhRouteHandle {
                ecdh_routes: Arc::clone(&self.ecdh_routes),
                key: (holder_pubkey, session_id),
            }),
        })
    }
}

/// Box the concrete [`CoordinatorRelayHub::connect`] so the distributed sign path builds
/// `RemoteHolder`s from a `placement.json` address without naming the relay transport's concrete
/// type. [`crate::remote_holder`] owns the trait + the blanket `impl HolderTransport for Box<dyn
/// HolderTransport + Send + Sync>`; this is the single place the relay transport satisfies it.
impl HolderTransportFactory for CoordinatorRelayHub {
    fn connect(&self, address: &str) -> anyhow::Result<Box<dyn HolderTransport + Send + Sync>> {
        Ok(Box::new(CoordinatorRelayHub::connect(self, address)?))
    }

    fn connect_probe(
        &self,
        address: &str,
        session_id: u64,
    ) -> anyhow::Result<Box<dyn HolderTransport + Send + Sync>> {
        Ok(Box::new(CoordinatorRelayHub::connect_probe(self, address, session_id)?))
    }

    fn connect_ecdh(
        &self,
        address: &str,
        session_id: u64,
    ) -> anyhow::Result<Box<dyn HolderTransport + Send + Sync>> {
        Ok(Box::new(CoordinatorRelayHub::connect_ecdh(self, address, session_id)?))
    }

    fn ceremony_gate(&self) -> CeremonyGate {
        self.ceremony_gate.clone()
    }
}

impl Drop for CoordinatorRelayHub {
    fn drop(&mut self) {
        // The actor thread ends on its own when the outbound channel closes (this hub + every
        // transport dropped) or the connection errors. Detach it (a daemon) rather than block on
        // join, since a transport may briefly outlive the hub: taking the handle and dropping it
        // detaches the thread.
        let _ = self.actor.take();
    }
}

/// The agent's co-sign COORDINATOR: the ONE shared [`CoordinatorRelayHub`] for a DISTRIBUTED FROST
/// keystore (`None` for a co-located or non-FROST agent), plus the memoized distributed
/// [`QuorumSigner`]. Built ONCE at agent boot ([`crate::run_agent`]) and threaded to EVERY sign site
/// (the beacon signer + the voice actuator), so all of them load their signer through this ONE seam.
///
/// WHY IT IS STRUCTURAL (not merely a tooth): the hub demuxes inbound replies by holder pubkey in a
/// single routes map, and [`CoordinatorRelayHub::connect`] OVERWRITES a holder's route. Two
/// INDEPENDENT distributed `QuorumSigner`s (a beacon one + a voice one) connecting the SAME holders
/// over the SAME coordinator key would clobber each other's reply routes AND collide on the shared
/// `#p = coordinator` inbound subscription. Memoizing ONE hub-backed signer here means both sign
/// sites share ONE hub + ONE routes map + ONE holder set -- the cross-talk cannot happen BY
/// CONSTRUCTION.
///
/// DISPATCH: distributed FROST signing is ENGAGED IFF BOTH hold -- `placement.json` present AND the
/// explicit ON-flip gate `identity.distributed_signing_enabled == true`. The ONE flag-aware dispatch
/// point is [`crate::keyset_provisioning::load_agent_quorum_signer`] (it takes the flag, so there is
/// NO flag-blind route to distributed). `AgentCosign` decides engagement ONCE at
/// [`Self::build`] -- it starts the shared hub IFF engaged -- and every [`Self::load_signer`] loads
/// through that dispatcher, passing `distributed_signing_enabled = self.hub.is_some()` (hub present
/// == engaged) and the hub as the factory:
///   * ENGAGED (hub present) => the hub-backed signer ([`crate::keyset_provisioning::load_quorum_signer_distributed`]),
///     MEMOIZED (sharing is mandatory, see above).
///   * NOT ENGAGED (co-located, OR placement present but the flag is FALSE => INERT) => a FRESH
///     per-call signer ([`crate::keyset_provisioning::load_quorum_signer_at`]), byte-identical to the
///     pre-Inc2 path -- NO memoization, so no shared state is introduced where there was none.
///
/// WHY THE FLAG (the ON-flip gate, decoupled from file presence): a future distributed-provision-at-
/// spawn WRITES `placement.json`, so presence-alone would silently auto-engage distributed signing --
/// and with it the concurrent-ceremony clobber below -- before the serializer lands. The flag defaults
/// FALSE, so `placement.json` alone is INERT until an operator flips it (only after #48 + #49 close).
///
/// CARRIED CONSTRAINT (why the flag must stay FALSE until #49): a shared distributed signer assumes
/// ceremonies are SERIALIZED per agent -- [`RelayHolderTransport::recv`] is one-ceremony-at-a-time per
/// transport (a single reply channel per holder). Enabling distributed signing without per-agent
/// ceremony serialization lets concurrent beacon/voice/DM ceremonies clobber each other's reply
/// routes -- a money-safety violation. Inc2a ships the wiring default-OFF; the ON-flip (co-gated with
/// cross-machine ECDH, Inc3) MUST add serialization before flipping the flag on for real money.
pub struct AgentCosign {
    /// The agent's FROST keystore dir (`None` for a non-FROST / no-keystore boot).
    keystore_dir: Option<PathBuf>,
    /// The ONE shared coordinator hub for a DISTRIBUTED keystore; `None` when co-located / no-frost.
    hub: Option<Arc<CoordinatorRelayHub>>,
    /// The memoized distributed `QuorumSigner` (built on first [`Self::load_signer`], reused after).
    /// Only populated on the distributed (hub) path; co-located loads are fresh per call.
    signer: Mutex<Option<Arc<crate::quorum_signer::QuorumSigner>>>,
}

impl AgentCosign {
    /// Build the agent's co-sign coordinator from its config-derived inputs. When `keystore_dir` is
    /// a DISTRIBUTED keystore (placement.json present) start the ONE shared hub over a
    /// [`NostrRelayConn`]: `coordinator_keys` is the coordinator's transport identity (the agent's
    /// node key), `relays` the co-sign relay set, `agent_id` binds every frame. The subscription is
    /// warmed up front ([`NostrRelayConn::ensure_connected`]) BEFORE the conn moves into the hub's
    /// actor thread, so a solicit published right after boot has a live subscriber. Co-located /
    /// absent / non-FROST => no hub (the byte-identical single-box path).
    ///
    /// RUNTIME REQUIREMENT: `ensure_connected` warms the relay-pool tasks on the CALLER's tokio
    /// runtime (the one awaiting this fn), then the conn moves into the hub actor's own thread +
    /// runtime; the pool tasks keep living on the caller runtime. So this MUST be awaited on a
    /// LONG-LIVED runtime that outlives the agent (the `run_agent` agent runtime satisfies this) --
    /// building it on a short-lived/setup runtime would strand the pool tasks and later ceremonies
    /// would time out. (Hardening this into a self-contained connect-inside-the-actor-runtime is a
    /// transport-layer follow-up; the single-agent boot path meets the requirement today.)
    pub async fn build(
        keystore_dir: Option<PathBuf>,
        coordinator_keys: Keys,
        agent_id: &str,
        relays: &[String],
        distributed_signing_enabled: bool,
    ) -> anyhow::Result<Self> {
        let hub = match keystore_dir.as_deref() {
            // ENGAGE distributed IFF the ON-flip gate is set AND the keystore is distributed-shaped.
            Some(dir) if distributed_signing_enabled && crate::keyset_provisioning::is_distributed_keystore(dir) => {
                if relays.is_empty() {
                    anyhow::bail!(
                        "distributed FROST keystore {} needs at least one co-sign relay to reach \
                         the remote holders, but the relay set is empty (fail closed)",
                        dir.display()
                    );
                }
                let conn = NostrRelayConn::new(coordinator_keys.public_key(), relays.to_vec())
                    .context("build the coordinator NostrRelayConn for distributed co-signing")?;
                conn.ensure_connected()
                    .await
                    .context("connect + subscribe the coordinator co-sign relay before signing")?;
                let hub = CoordinatorRelayHub::start(
                    conn,
                    coordinator_keys,
                    agent_id.to_string(),
                    DEFAULT_WIRE_TIMEOUT,
                )
                .context("start the shared co-sign coordinator hub")?;
                tracing::info!(
                    keystore = %dir.display(),
                    relays = relays.len(),
                    "distributed FROST keystore + distributed_signing_enabled: started the ONE shared co-sign coordinator hub (Q signs across machines)"
                );
                Some(Arc::new(hub))
            }
            // INERT: a distributed-shaped keystore whose ON-flip gate is OFF -- build NO hub, stay
            // co-located. (Loud, so an operator sees the manifest present but signing not engaged.)
            Some(dir)
                if !distributed_signing_enabled
                    && crate::keyset_provisioning::is_distributed_keystore(dir) =>
            {
                tracing::warn!(
                    keystore = %dir.display(),
                    "FROST keystore has a placement.json but identity.distributed_signing_enabled=false: \
                     distributed signing is INERT (co-located path, NO co-sign hub built). Enable only \
                     after #48 (reconnect proof) + #49 (ceremony serialization) close."
                );
                None
            }
            _ => None,
        };
        Ok(Self { keystore_dir, hub, signer: Mutex::new(None) })
    }

    /// A coordinator for a NON-FROST / no-keystore boot (the boot demo, app-checkpoint, tests that
    /// never sign under Q): no hub, no keystore. [`Self::load_signer`] / [`Self::load_ecdh`] error
    /// if called (there is nothing to load) -- those paths only run when a FROST keystore is set.
    pub fn none() -> Self {
        Self { keystore_dir: None, hub: None, signer: Mutex::new(None) }
    }

    /// Whether this agent's keystore is DISTRIBUTED (a shared hub was started).
    pub fn is_distributed(&self) -> bool {
        self.hub.is_some()
    }

    /// The [`QuorumSigner`](crate::quorum_signer::QuorumSigner) for this agent's keystore, dispatched
    /// by the keystore shape. DISTRIBUTED => the MEMOIZED one hub-backed signer (shared across all
    /// sign sites: one routes map / one holder set). CO-LOCATED => a FRESH per-call signer
    /// (byte-identical to the pre-Inc2 path; no shared state).
    pub fn load_signer(&self) -> anyhow::Result<Arc<crate::quorum_signer::QuorumSigner>> {
        let dir = self.keystore_dir.as_deref().ok_or_else(|| {
            anyhow::anyhow!("AgentCosign::load_signer called with no FROST keystore configured")
        })?;
        match &self.hub {
            // DISTRIBUTED: memoize the ONE shared signer (sharing is mandatory -- one routes map).
            Some(hub) => {
                let mut cached = self
                    .signer
                    .lock()
                    .map_err(|_| anyhow::anyhow!("AgentCosign signer cache mutex poisoned"))?;
                if let Some(existing) = cached.as_ref() {
                    return Ok(Arc::clone(existing));
                }
                // Engaged: dispatch with the flag TRUE + the hub as factory (the single flag-aware
                // dispatch point). hub.is_some() == engaged, so this is consistent by construction.
                let signer = crate::keyset_provisioning::load_agent_quorum_signer(
                    dir,
                    Some(hub.as_ref() as &dyn HolderTransportFactory),
                    true,
                )
                .context("load the distributed QuorumSigner via the shared co-sign hub")?;
                let arc = Arc::new(signer);
                *cached = Some(Arc::clone(&arc));
                Ok(arc)
            }
            // NOT ENGAGED (co-located, OR placement present but flag off => INERT): a fresh signer
            // per call. The dispatcher, with the flag FALSE, takes the co-located loader even if a
            // placement.json exists -- byte-identical to today's two-independent-signers path.
            None => {
                let signer = crate::keyset_provisioning::load_agent_quorum_signer(dir, None, false)
                    .context("load the co-located QuorumSigner")?;
                Ok(Arc::new(signer))
            }
        }
    }

    /// The [`QuorumEcdh`](crate::quorum_ecdh::QuorumEcdh) for the DM / wallet-read / memory (NIP-44)
    /// path, dispatched by the SAME engagement decision as [`Self::load_signer`]:
    ///   * DISTRIBUTED (`self.hub.is_some()` -- placement present AND the ON-flip gate set): the
    ///     cross-machine threshold-ECDH self-decrypt round over the shared hub (Inc3, now WIRED). An
    ///     engaged distributed agent holds fewer than the quorum of shares locally, so ECDH runs over
    ///     the SAME remote holders + relay transport as signing, serialized by the shared ceremony
    ///     gate. (This deletes the pre-Inc3 fail-closed bail.)
    ///   * CO-LOCATED (or placement-present-but-INERT, flag off): the in-process combine
    ///     ([`crate::keyset_provisioning::load_quorum_ecdh_at`]), byte-identical to before.
    pub fn load_ecdh(&self) -> anyhow::Result<crate::quorum_ecdh::QuorumEcdh> {
        let dir = self.keystore_dir.as_deref().ok_or_else(|| {
            anyhow::anyhow!("AgentCosign::load_ecdh called with no FROST keystore configured")
        })?;
        match &self.hub {
            Some(hub) => crate::keyset_provisioning::load_quorum_ecdh_distributed(
                dir,
                Arc::clone(hub) as Arc<dyn HolderTransportFactory + Send + Sync>,
            )
            .with_context(|| {
                format!(
                    "load the distributed QuorumEcdh via the shared co-sign hub (keystore {})",
                    dir.display()
                )
            }),
            None => crate::keyset_provisioning::load_quorum_ecdh_at(dir).with_context(|| {
                format!("load co-located QuorumEcdh from keystore {}", dir.display())
            }),
        }
    }
}

/// The background actor: own the connection, publish outbound frames, demux inbound replies to
/// the registered per-holder reply channel by the reply's SENDER transport pubkey. Ends when
/// the outbound channel closes (hub + all transports dropped) or the connection errors.
async fn coordinator_actor<C: RelayConn>(
    conn: C,
    mut outbound_rx: UnboundedReceiver<Event>,
    routes: Arc<Mutex<HashMap<PublicKey, StdSender<CoSignEvent>>>>,
    probe_routes: ProbeRoutes,
    ecdh_routes: EcdhRoutes,
    agent_id: String,
) {
    loop {
        tokio::select! {
            maybe = outbound_rx.recv() => match maybe {
                Some(event) => {
                    if let Err(e) = conn.publish(event).await {
                        tracing::warn!(error = %e, "co-sign coordinator: failed to publish a request frame");
                    }
                }
                None => break, // hub + all transports dropped
            },
            res = conn.next_event() => match res {
                Ok(event) => {
                    match decode_cosign_frame(&event) {
                        Ok((frame_agent, cosign, sender)) => {
                            if frame_agent != agent_id {
                                continue; // a frame for another agent on the shared relay
                            }
                            // A ROUND_PROBE_ACK is a takeover-admission liveness reply: demux it to
                            // its SESSION-SCOPED probe route (keyed by (sender, session_id)) so it can
                            // neither clobber nor be clobbered by the memoized signer's per-holder
                            // route. Every other reply (commitment / share / refusal) is a signing
                            // ceremony reply and routes through `routes` by the sender alone -- the
                            // pre-#49 path, unchanged.
                            let route = match cosign.round {
                                crate::remote_holder::ROUND_PROBE_ACK => probe_routes
                                    .lock()
                                    .ok()
                                    .and_then(|m| m.get(&(sender, cosign.session_id)).cloned()),
                                // A single-round ECDH reply (contribution or refusal) demuxes to its
                                // SESSION-SCOPED route, so it never clobbers / is clobbered by the
                                // memoized signer's per-holder route.
                                crate::remote_holder::ROUND_ECDH_CONTRIBUTION
                                | crate::remote_holder::ROUND_ECDH_REFUSAL => ecdh_routes
                                    .lock()
                                    .ok()
                                    .and_then(|m| m.get(&(sender, cosign.session_id)).cloned()),
                                _ => routes.lock().ok().and_then(|m| m.get(&sender).cloned()),
                            };
                            match route {
                                Some(tx) => {
                                    // A closed receiver (its RemoteHolder gave up) is harmless.
                                    let _ = tx.send(cosign);
                                }
                                None => tracing::debug!(
                                    sender = %sender.to_hex(),
                                    "co-sign coordinator: reply from an unrouted sender, dropped"
                                ),
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "co-sign coordinator: dropped an undecodable reply frame"),
                    }
                }
                Err(_) => break, // connection closed
            },
        }
    }
}

/// The per-holder sync [`HolderTransport`] handle into a [`CoordinatorRelayHub`]. `send`
/// enqueues a `#p`-addressed, signed request frame (non-blocking); `recv` blocks the caller on
/// the demuxed reply channel up to `timeout`, returning `Err` on timeout (the
/// any-available-2-of-3 fallback's "unreachable holder" signal).
pub struct RelayHolderTransport {
    agent_id: String,
    holder_pubkey: PublicKey,
    coordinator_keys: Keys,
    outbound_tx: UnboundedSender<Event>,
    /// The demuxed replies for THIS holder. A `std::sync::mpsc::Receiver` is `!Sync`, but a
    /// `RemoteHolder<T>` requires `T: Send + Sync` (the `Holder: Send + Sync` bound), so wrap
    /// it in a `Mutex` (the receiver is `Send`, making `Mutex<Receiver>` `Send + Sync`). Only
    /// one ceremony thread calls `recv` per transport, so the lock is uncontended.
    reply_rx: Mutex<StdReceiver<CoSignEvent>>,
    timeout: Duration,
    /// Set ONLY for a probe transport ([`CoordinatorRelayHub::connect_probe`]): removes this
    /// probe's session-scoped route from `probe_routes` on drop. `None` for a signing transport
    /// ([`CoordinatorRelayHub::connect`]) -- its session-agnostic route is bounded and lives for
    /// the hub, so the signer path is unchanged.
    probe_route: Option<ProbeRouteHandle>,
    /// Set ONLY for an ECDH transport ([`CoordinatorRelayHub::connect_ecdh`]): removes this ceremony's
    /// session-scoped route from `ecdh_routes` on drop. `None` for signing / probe transports.
    ecdh_route: Option<EcdhRouteHandle>,
}

/// Removes a probe's `(holder pubkey, session id)` route from the hub's `probe_routes` when the
/// probe transport drops, so a per-probe route never outlives its one round-trip.
struct ProbeRouteHandle {
    probe_routes: ProbeRoutes,
    key: (PublicKey, u64),
}

/// Removes an ECDH ceremony's `(holder pubkey, session id)` route from the hub's `ecdh_routes` when
/// the ECDH transport drops, so a per-ceremony route never outlives its one round-trip (mirrors
/// [`ProbeRouteHandle`]).
struct EcdhRouteHandle {
    ecdh_routes: EcdhRoutes,
    key: (PublicKey, u64),
}

impl Drop for RelayHolderTransport {
    fn drop(&mut self) {
        if let Some(handle) = self.probe_route.take() {
            if let Ok(mut routes) = handle.probe_routes.lock() {
                routes.remove(&handle.key);
            }
        }
        if let Some(handle) = self.ecdh_route.take() {
            if let Ok(mut routes) = handle.ecdh_routes.lock() {
                routes.remove(&handle.key);
            }
        }
    }
}

impl HolderTransport for RelayHolderTransport {
    fn send(&self, event: CoSignEvent) -> anyhow::Result<()> {
        let frame = encode_cosign_frame(
            &self.agent_id,
            &event,
            self.holder_pubkey,
            &self.coordinator_keys,
        )?;
        // Unbounded send: non-blocking + safe from any context (never blocks a runtime worker).
        self.outbound_tx
            .send(frame)
            .map_err(|_| anyhow::anyhow!("co-sign coordinator actor is gone (relay hub dropped)"))
    }

    fn recv(&self) -> anyhow::Result<CoSignEvent> {
        let rx = self
            .reply_rx
            .lock()
            .map_err(|_| anyhow::anyhow!("relay holder transport reply channel poisoned"))?;
        match rx.recv_timeout(self.timeout) {
            Ok(event) => Ok(event),
            Err(RecvTimeoutError::Timeout) => anyhow::bail!(
                "timed out after {:?} waiting for a reply from holder {}",
                self.timeout,
                self.holder_pubkey.to_hex()
            ),
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("co-sign coordinator actor closed the reply channel for holder {}", self.holder_pubkey.to_hex())
            }
        }
    }
}

/// Run a holder-side server loop: subscribe (via `conn`) to co-sign frames `#p`-addressed to
/// this holder, and for each one consult the [`CoordinatorAuthorizer`], run the
/// `RemoteHolderServer` (the membrane + the share, on THIS machine), and publish the reply
/// `#p`-addressed back to the soliciting coordinator. The SIBLING of [`crate::nerve::run_inbound`]
/// for the co-sign surface. Runs until `shutdown` fires or the connection errors.
///
/// `agent_id` is the agent this holder backs; a frame for any other agent is dropped (defense
/// on a shared relay). `holder_keys` is the holder's transport identity (signs every reply).
pub async fn run_holder_server<C: RelayConn>(
    holder_keys: &Keys,
    agent_id: &str,
    server: Arc<RemoteHolderServer>,
    conn: C,
    authorize: CoordinatorAuthorizer,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(
        holder_npub = %holder_keys.public_key().to_bech32().unwrap_or_default(),
        agent_id,
        "co-sign holder server starting (the cross-machine FROST holder endpoint)"
    );
    // Per-holder anti-replay guard for inbound solicits (PIECE 3): freshness window + dedup.
    let guard = ReplayGuard::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!(agent_id, "co-sign holder server shutting down");
                break;
            }
            res = conn.next_event() => match res {
                Ok(event) => {
                    if let Err(e) = handle_holder_frame(holder_keys, agent_id, &server, &conn, &authorize, &guard, &event).await {
                        tracing::warn!(error = %e, "co-sign holder server: dropped a frame");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "co-sign holder server: connection closed, stopping");
                    break;
                }
            },
        }
    }
    Ok(())
}

/// Screen + handle ONE inbound co-sign request frame on the holder side: verify/decode,
/// agent-bind, authorize the coordinator, run the `RemoteHolderServer`, publish the reply. Any
/// failure is a DROP (logged, never a panic) -- a hostile/misrouted frame must not crash a
/// holder.
async fn handle_holder_frame<C: RelayConn>(
    holder_keys: &Keys,
    agent_id: &str,
    server: &RemoteHolderServer,
    conn: &C,
    authorize: &CoordinatorAuthorizer,
    guard: &ReplayGuard,
    event: &Event,
) -> anyhow::Result<()> {
    let (frame_agent, cosign, coordinator) = decode_cosign_frame(event)?;
    if frame_agent != agent_id {
        anyhow::bail!(
            "co-sign frame for agent {frame_agent}, this holder backs {agent_id} -- dropped"
        );
    }
    // ENDPOINT AUTH: only an entitled coordinator may drive this holder (the stub allows all;
    // the lease+placement authorizer drops in here). Reject BEFORE the server burns a nonce.
    if !authorize(&frame_agent, &coordinator) {
        anyhow::bail!(
            "co-sign solicit from un-entitled coordinator {} for agent {frame_agent} -- refused",
            coordinator.to_hex()
        );
    }
    // ANTI-REPLAY (PIECE 3): refuse a stale or duplicate solicit BEFORE the server burns a nonce.
    // (session_id + round are Copy, read before `cosign` is moved into `server.handle` below.)
    guard
        .admit(
            &coordinator,
            cosign.session_id,
            cosign.round,
            event.created_at.as_secs(),
            now_unix(),
        )
        .context("anti-replay guard refused the solicit")?;
    // Run the membrane + the share on THIS machine. The reply is itself an opaque CoSignEvent
    // (a commitment, a share, or a refusal); publish it back to the soliciting coordinator.
    let reply = server.handle(cosign);
    let reply_frame = encode_cosign_frame(agent_id, &reply, coordinator, holder_keys)?;
    conn.publish(reply_frame)
        .await
        .context("publish the holder's reply frame")
}

/// Parse a holder `address` token (`<holder_transport_pubkey_hex>@<relay_csv>`). The pubkey is
/// the holder's transport identity (`#p` target + reply-sender to verify + share-encrypt-to);
/// the relays are where to reach it. The relay part may be empty / `inmem` for the in-memory
/// double. The SAME token is used by the remote `ShareSink` (provision) and `connect` (sign),
/// so a holder is named identically on both sides.
fn parse_holder_address(address: &str) -> anyhow::Result<(PublicKey, Vec<String>)> {
    let (pubkey_hex, relay_part) = match address.split_once('@') {
        Some((pk, relays)) => (pk, relays),
        None => (address, ""),
    };
    let holder_pubkey = PublicKey::from_hex(pubkey_hex.trim()).map_err(|e| {
        anyhow::anyhow!("holder address has an invalid transport pubkey {pubkey_hex:?}: {e}")
    })?;
    let relays: Vec<String> = relay_part
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "inmem")
        .map(|s| s.to_string())
        .collect();
    Ok((holder_pubkey, relays))
}

// ================================================================================================
// PART (b): the REMOTE ShareSink -- distributed provisioning ships a SECRET share to a holder host.
//
// The co-located `LocalSealedSink` seals share `i` to a local dir. The REMOTE sink ships share `i`
// to a holder on ANOTHER machine, NIP-44-ENCRYPTED to that holder's transport pubkey (the share
// KeyPackage is the secret -- unlike the co-sign frames, this MUST be confidential), and the holder
// SEALS it at rest (reusing the proven `LocalSealedSink`). It impls the EXISTING `ShareSink` trait
// UNCHANGED (no widening), so `provision_keyset_with_sinks` drives it identically:
//   * `put_share(idx, plaintext)` -- NIP-44-encrypt the KeyPackage to the holder pubkey, publish a
//     KIND_KIRBY_SHARE Ship frame (signed by the DEALER's transport key = sender-auth), AWAIT the
//     holder's durable-seal ACK. Returns Ok only once the holder has sealed it at rest.
//   * `has_share(idx)` -- a ROUND-TRIP loadability ATTESTATION: the holder unseals + parses its own
//     share locally and replies present/absent. The secret NEVER crosses back.
//   * `get_share(idx)` -- ERRS BY DESIGN. A remote holder must NEVER return its plaintext share to
//     the dealer; that would re-centralize all 3 shares in dealer RAM and break the TEE-substitute
//     invariant. (worker:distributed-spawn's distributed reload gates on `has_share` only and its
//     sign path builds RemoteHolders via the factory, so `get_share` is never hit on its paths.)
//
// The HOLDER never needs the group `PublicKeyPackage` shipped to it: the membrane only derives Q,
// and Q comes from the group verifying key, which is present in the holder's OWN `KeyPackage`
// (`taproot_address`/`group_xonly_q` read `verifying_key()` only). So a holder self-constructs its
// `own_pubkeys` from its shipped share alone (see `own_pubkeys_from_key_package`).
// ================================================================================================

/// A holder-side gate: may this dealer (its transport pubkey) provision share `idx` for this
/// agent? Consulted by [`run_share_sink_server`] BEFORE it seals a shipped share. The
/// auth-independent core uses [`allow_all_dealers`]; the endpoint-auth slice supplies the real
/// authorizer (accept only the provisioned dealer), WITHOUT changing the sink/server.
pub type DealerAuthorizer = Arc<dyn Fn(&str, &PublicKey) -> bool + Send + Sync + 'static>;

/// The auth-independent STUB dealer authorizer: accept every dealer. PRODUCTION MUST NOT ship with
/// this -- the real authorizer replaces it before any live cross-machine provisioning.
pub fn allow_all_dealers() -> DealerAuthorizer {
    Arc::new(|_agent_id: &str, _dealer: &PublicKey| true)
}

/// A typed control frame on the [`kirby_proto::KIND_KIRBY_SHARE`] surface. `Ship` carries the share
/// KeyPackage as NIP-44 ciphertext (encrypted dealer -> holder); the others are plaintext control.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ShareFrame {
    /// dealer -> holder: deliver share `idx` for `agent_id`. `ciphertext` is the share KeyPackage
    /// JSON, NIP-44-encrypted to the holder's transport pubkey (only the holder decrypts).
    Ship { agent_id: String, idx: u16, ciphertext: String },
    /// holder -> dealer: durable-seal ACK. `ok` is true once the share is sealed at rest.
    ShipAck { agent_id: String, idx: u16, ok: bool, detail: Option<String> },
    /// dealer -> holder: "do you hold a loadable share `idx` for `agent_id`?"
    HasQuery { agent_id: String, idx: u16 },
    /// holder -> dealer: the loadability attestation (true iff the holder unsealed + parsed it).
    HasReply { agent_id: String, idx: u16, present: bool },
}

impl ShareFrame {
    /// The agent this frame is about (for the `#a` tag + agent-binding).
    fn agent_id(&self) -> &str {
        match self {
            ShareFrame::Ship { agent_id, .. }
            | ShareFrame::ShipAck { agent_id, .. }
            | ShareFrame::HasQuery { agent_id, .. }
            | ShareFrame::HasReply { agent_id, .. } => agent_id,
        }
    }
}

/// Wrap a [`ShareFrame`] in a signed, `#p`-addressed [`kirby_proto::KIND_KIRBY_SHARE`] event. Signed
/// by `signer` (sender-auth) and addressed to `recipient`. The `Ship` variant already carries the
/// SECRET as NIP-44 ciphertext in its `ciphertext` field, so the event content itself is safe.
fn encode_share_frame(
    frame: &ShareFrame,
    recipient: PublicKey,
    signer: &Keys,
) -> anyhow::Result<Event> {
    let content = serde_json::to_string(frame).context("serialize ShareFrame")?;
    let tags = vec![
        Tag::public_key(recipient),
        Tag::parse(["t", "kirby"]).context("t tag")?,
        Tag::parse(["a", frame.agent_id()]).context("a tag")?,
    ];
    EventBuilder::new(Kind::from(kirby_proto::KIND_KIRBY_SHARE), content)
        .tags(tags)
        .sign_with_keys(signer)
        .map_err(|e| anyhow::anyhow!("sign share frame: {e}"))
}

/// Verify + decode a [`kirby_proto::KIND_KIRBY_SHARE`] event into its [`ShareFrame`] and the SENDER's
/// transport pubkey. Signature/id + kind are checked (the trust boundary).
fn decode_share_frame(event: &Event) -> anyhow::Result<(ShareFrame, PublicKey)> {
    event
        .verify()
        .map_err(|e| anyhow::anyhow!("share frame failed signature/id verification: {e}"))?;
    if event.kind != Kind::from(kirby_proto::KIND_KIRBY_SHARE) {
        anyhow::bail!(
            "not a share frame (kind {}, expected {})",
            event.kind.as_u16(),
            kirby_proto::KIND_KIRBY_SHARE
        );
    }
    let frame: ShareFrame =
        serde_json::from_str(&event.content).context("deserialize ShareFrame from content")?;
    Ok((frame, event.pubkey))
}

/// Build a holder's `own_pubkeys` from its share `KeyPackage` ALONE. The guardian membrane only
/// derives Q, and Q comes from the group verifying key (`taproot_address`/`group_xonly_q` read
/// `verifying_key()` only -- NOT the verifying-shares map), which the holder's own `KeyPackage`
/// already carries. So a `PublicKeyPackage` holding just this holder's own verifying share plus the
/// (correct) group verifying key derives the SAME Q -- the holder needs nothing shipped beyond its
/// share. (If the membrane ever consulted the full verifying-shares map, this would need the real
/// package; it does not, and the ship -> seal -> load -> sign round-trip test proves Q is correct.)
fn own_pubkeys_from_key_package(kp: &KeyPackage) -> PublicKeyPackage {
    let mut verifying_shares = BTreeMap::new();
    verifying_shares.insert(*kp.identifier(), *kp.verifying_share());
    // frost-core 3.0 `PublicKeyPackage::new(verifying_shares, verifying_key, min_signers)`. The
    // membrane reads only `verifying_key()` (for Q), never the threshold field, so this value is
    // not load-bearing for validation; set it to the true 2-of-3 threshold for honesty.
    PublicKeyPackage::new(
        verifying_shares,
        *kp.verifying_key(),
        Some(crate::quorum_signer::MIN_SIGNERS),
    )
}

/// The holder-local directory that stores share(s) for one agent (sealed at rest). `<base>/agent-
/// <agent_id>/`; the `LocalSealedSink` there seals `share_<idx>.sealed` under the holder's machine
/// binding. One holder backs one agent share, but the dir is per-agent so a holder pool node can
/// back several agents.
fn holder_share_dir(base: &Path, agent_id: &str) -> PathBuf {
    base.join(format!("agent-{agent_id}"))
}

/// The dealer-side actor bridging the SYNC [`ShareSink`] methods to the async relay: it owns the
/// connection, publishes outbound Ship/HasQuery frames on demand, and pushes inbound holder replies
/// to a single reply channel (one request outstanding at a time per sink, since
/// `provision_keyset_with_sinks` drives a sink sequentially).
struct ShareSinkActor;

/// The dealer-side client a [`RemoteShareSink`] uses: a background actor + sync ship/query bridges.
struct ShareSinkClient {
    agent_id: String,
    holder_pubkey: PublicKey,
    dealer_keys: Keys,
    outbound_tx: UnboundedSender<Event>,
    reply_rx: Mutex<StdReceiver<ShareFrame>>,
    timeout: Duration,
    _actor: Option<std::thread::JoinHandle<()>>,
}

impl ShareSinkClient {
    fn start<C: RelayConn>(
        conn: C,
        dealer_keys: Keys,
        holder_pubkey: PublicKey,
        agent_id: String,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let (outbound_tx, outbound_rx) = unbounded_channel::<Event>();
        let (reply_tx, reply_rx) = std::sync::mpsc::channel::<ShareFrame>();
        let actor_agent = agent_id.clone();
        let actor = std::thread::Builder::new()
            .name("kirby-share-sink".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "share sink actor: failed to build runtime");
                        return;
                    }
                };
                rt.block_on(ShareSinkActor::run(conn, outbound_rx, reply_tx, actor_agent));
            })
            .context("spawn the share-sink actor thread")?;
        Ok(Self {
            agent_id,
            holder_pubkey,
            dealer_keys,
            outbound_tx,
            reply_rx: Mutex::new(reply_rx),
            timeout,
            _actor: Some(actor),
        })
    }

    /// Publish `frame` to the holder and block for the next inbound reply matching `accept`, up to
    /// the timeout. Non-matching replies are skipped (drained) until one matches or time runs out.
    fn round_trip(
        &self,
        frame: &ShareFrame,
        accept: impl Fn(&ShareFrame) -> Option<anyhow::Result<bool>>,
    ) -> anyhow::Result<bool> {
        let event = encode_share_frame(frame, self.holder_pubkey, &self.dealer_keys)?;
        self.outbound_tx
            .send(event)
            .map_err(|_| anyhow::anyhow!("share-sink actor is gone"))?;
        let rx = self
            .reply_rx
            .lock()
            .map_err(|_| anyhow::anyhow!("share-sink reply channel poisoned"))?;
        let deadline = self.timeout;
        loop {
            match rx.recv_timeout(deadline) {
                Ok(reply) => {
                    if let Some(result) = accept(&reply) {
                        return result;
                    }
                    // Not the reply we are waiting for; keep draining within the same budget.
                }
                Err(RecvTimeoutError::Timeout) => {
                    anyhow::bail!("timed out after {:?} awaiting holder reply", self.timeout)
                }
                Err(RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("share-sink actor closed the reply channel")
                }
            }
        }
    }

    /// Ship share `idx` (NIP-44-encrypted to the holder) and await the durable-seal ACK.
    fn ship(&self, idx: u16, plaintext: &[u8]) -> anyhow::Result<()> {
        let ciphertext = nip44::encrypt(
            self.dealer_keys.secret_key(),
            &self.holder_pubkey,
            plaintext,
            Version::V2,
        )
        .map_err(|e| anyhow::anyhow!("NIP-44 encrypt share {idx}: {e}"))?;
        let frame = ShareFrame::Ship {
            agent_id: self.agent_id.clone(),
            idx,
            ciphertext,
        };
        let ok = self.round_trip(&frame, |reply| match reply {
            ShareFrame::ShipAck { idx: r_idx, ok, detail, .. } if *r_idx == idx => Some(if *ok {
                Ok(true)
            } else {
                Err(anyhow::anyhow!(
                    "holder refused to seal share {idx}: {}",
                    detail.clone().unwrap_or_default()
                ))
            }),
            _ => None,
        })?;
        if ok {
            Ok(())
        } else {
            anyhow::bail!("holder did not ACK share {idx}")
        }
    }

    /// Query whether the holder holds a loadable share `idx`.
    fn query(&self, idx: u16) -> anyhow::Result<bool> {
        let frame = ShareFrame::HasQuery {
            agent_id: self.agent_id.clone(),
            idx,
        };
        self.round_trip(&frame, |reply| match reply {
            ShareFrame::HasReply { idx: r_idx, present, .. } if *r_idx == idx => {
                Some(Ok(*present))
            }
            _ => None,
        })
    }
}

impl ShareSinkActor {
    async fn run<C: RelayConn>(
        conn: C,
        mut outbound_rx: UnboundedReceiver<Event>,
        reply_tx: StdSender<ShareFrame>,
        agent_id: String,
    ) {
        loop {
            tokio::select! {
                maybe = outbound_rx.recv() => match maybe {
                    Some(event) => {
                        if let Err(e) = conn.publish(event).await {
                            tracing::warn!(error = %e, "share sink: failed to publish a frame");
                        }
                    }
                    None => break,
                },
                res = conn.next_event() => match res {
                    Ok(event) => {
                        if let Ok((frame, _sender)) = decode_share_frame(&event) {
                            if frame.agent_id() == agent_id {
                                let _ = reply_tx.send(frame);
                            }
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    }
}

/// A remote [`ShareSink`]: ships its one holder's share to that holder's machine (NIP-44-encrypted),
/// where it is sealed at rest, and attests possession on reload. Impls the EXISTING `ShareSink`
/// trait unchanged so `provision_keyset_with_sinks` drives it like a `LocalSealedSink`.
pub struct RemoteShareSink {
    /// The seal-domain label (holder-1/2/3), distinct per sink (distributed-spawn uses it).
    label: String,
    client: ShareSinkClient,
}

impl RemoteShareSink {
    /// Build a remote sink over `conn` (connected + subscribed to `#p = dealer pubkey` + the share
    /// kind) targeting the holder named by `address` (`<holder_transport_pubkey_hex>@<relay_csv>` --
    /// the SAME placement token the sign-side `connect` uses), labelled `label`, signing ships with
    /// `dealer_keys`.
    pub fn start<C: RelayConn>(
        conn: C,
        dealer_keys: Keys,
        agent_id: impl Into<String>,
        address: &str,
        label: impl Into<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let (holder_pubkey, _relays) = parse_holder_address(address)?;
        let agent_id = agent_id.into();
        let client = ShareSinkClient::start(conn, dealer_keys, holder_pubkey, agent_id, timeout)?;
        Ok(Self {
            label: label.into(),
            client,
        })
    }
}

impl ShareSink for RemoteShareSink {
    fn label(&self) -> &str {
        &self.label
    }

    fn put_share(&self, idx: u16, plaintext: &[u8]) -> anyhow::Result<()> {
        self.client.ship(idx, plaintext)
    }

    fn has_share(&self, idx: u16) -> bool {
        // A round-trip attestation; any transport error is "not present" (the fail-closed reload
        // turns a missing/unreachable share into a loud error, never a silent new Q).
        self.client.query(idx).unwrap_or(false)
    }

    fn get_share(&self, _idx: u16) -> anyhow::Result<Vec<u8>> {
        // BY DESIGN: a remote holder NEVER returns its plaintext share to the dealer (the
        // TEE-substitute invariant). The distributed reload gates on `has_share`; the distributed
        // sign path builds RemoteHolders via the factory and touches no sink. So this is never a
        // legitimate call -- it is a loud refusal, not a re-centralization.
        anyhow::bail!(
            "RemoteShareSink::get_share is unsupported by design: a remote holder must never return \
             its plaintext share to the dealer (use has_share for reload validation + the sign-side \
             factory for signing)"
        )
    }
}

/// Run a holder-side share-sink server loop: subscribe (via `conn`) to share frames `#p`-addressed
/// to this holder, and for each `Ship` decrypt + seal it at rest under `keystore_base` (reusing
/// `LocalSealedSink`) and ACK; for each `HasQuery` reply with a loadability attestation. The SIBLING
/// of [`run_holder_server`] for the provisioning surface. Runs until `shutdown` fires.
///
/// `holder_keys` is the holder's transport identity (decrypts ships + signs replies). `authorize` is
/// consulted before a share is sealed (stub = [`allow_all_dealers`]).
pub async fn run_share_sink_server<C: RelayConn>(
    holder_keys: &Keys,
    keystore_base: &Path,
    conn: C,
    authorize: DealerAuthorizer,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(
        holder_npub = %holder_keys.public_key().to_bech32().unwrap_or_default(),
        keystore = %keystore_base.display(),
        "share-sink holder server starting (the cross-machine provisioning endpoint)"
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("share-sink holder server shutting down");
                break;
            }
            res = conn.next_event() => match res {
                Ok(event) => {
                    if let Err(e) = handle_share_frame(holder_keys, keystore_base, &conn, &authorize, &event).await {
                        tracing::warn!(error = %e, "share-sink holder server: dropped a frame");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "share-sink holder server: connection closed, stopping");
                    break;
                }
            },
        }
    }
    Ok(())
}

/// Handle ONE inbound share frame on the holder side: decrypt + seal a `Ship` (then ACK), or answer
/// a `HasQuery`. Any failure is a DROP / a `ShipAck{ok:false}` (logged, never a panic).
async fn handle_share_frame<C: RelayConn>(
    holder_keys: &Keys,
    keystore_base: &Path,
    conn: &C,
    authorize: &DealerAuthorizer,
    event: &Event,
) -> anyhow::Result<()> {
    let (frame, dealer) = decode_share_frame(event)?;
    match frame {
        ShareFrame::Ship { agent_id, idx, ciphertext } => {
            let reply = seal_shipped_share(holder_keys, keystore_base, authorize, &dealer, &agent_id, idx, &ciphertext);
            let ack = match reply {
                Ok(()) => ShareFrame::ShipAck { agent_id, idx, ok: true, detail: None },
                Err(e) => ShareFrame::ShipAck {
                    agent_id,
                    idx,
                    ok: false,
                    detail: Some(format!("{e}")),
                },
            };
            let frame = encode_share_frame(&ack, dealer, holder_keys)?;
            conn.publish(frame).await.context("publish ship ACK")
        }
        ShareFrame::HasQuery { agent_id, idx } => {
            let present = share_is_loadable(keystore_base, &agent_id, idx);
            let reply = ShareFrame::HasReply { agent_id, idx, present };
            let frame = encode_share_frame(&reply, dealer, holder_keys)?;
            conn.publish(frame).await.context("publish has-share reply")
        }
        // A holder server should not receive ACK/reply frames; ignore them.
        ShareFrame::ShipAck { .. } | ShareFrame::HasReply { .. } => Ok(()),
    }
}

/// Decrypt a shipped share (NIP-44, dealer -> holder) and SEAL it at rest via `LocalSealedSink`.
/// Authorizes the dealer first; refuses to clobber an already-sealed share for this (agent, idx).
fn seal_shipped_share(
    holder_keys: &Keys,
    keystore_base: &Path,
    authorize: &DealerAuthorizer,
    dealer: &PublicKey,
    agent_id: &str,
    idx: u16,
    ciphertext: &str,
) -> anyhow::Result<()> {
    if !authorize(agent_id, dealer) {
        anyhow::bail!("share ship from un-authorized dealer {} for agent {agent_id}", dealer.to_hex());
    }
    let dir = holder_share_dir(keystore_base, agent_id);
    let sink = LocalSealedSink::open(&dir, agent_id.to_string())
        .with_context(|| format!("open holder sealed store {}", dir.display()))?;
    // Refuse to overwrite an established share (a re-key is membership rotation, out of MVP scope).
    if sink.has_share(idx) {
        anyhow::bail!("holder already holds share {idx} for agent {agent_id} (refusing to clobber)");
    }
    // NIP-44-decrypt with THIS holder's key against the DEALER's pubkey (the signed event's author).
    let plaintext = nip44::decrypt_to_bytes(holder_keys.secret_key(), dealer, ciphertext)
        .map_err(|e| anyhow::anyhow!("NIP-44 decrypt share {idx}: {e}"))?;
    // Sanity: it must parse as a KeyPackage before we seal it (reject garbage early).
    let _kp: KeyPackage = serde_json::from_slice(&plaintext)
        .with_context(|| format!("shipped share {idx} is not a valid KeyPackage"))?;
    // Seal at rest (LocalSealedSink seals under the holder's machine binding + per-dir salt).
    sink.put_share(idx, &plaintext)
        .with_context(|| format!("seal shipped share {idx} at rest"))?;
    // Establish the authorized COORDINATOR for this agent = the dealer that shipped the share
    // (single-coordinator MVP: the spawning node provisions AND coordinates). This is the holder's
    // provision-time root of trust for `coordinator_authorizer`.
    persist_authorized_coordinator(keystore_base, agent_id, dealer)
        .context("persist the authorized coordinator at provision")?;
    tracing::info!(agent_id, idx, dealer = %dealer.to_hex(), "holder sealed a shipped FROST share + recorded its authorized coordinator");
    Ok(())
}

/// Whether the holder holds a LOADABLE share `idx` for `agent_id`: the sealed share exists AND
/// unseals + parses as a `KeyPackage`. The loadability attestation `has_share` reports.
fn share_is_loadable(keystore_base: &Path, agent_id: &str, idx: u16) -> bool {
    let dir = holder_share_dir(keystore_base, agent_id);
    let Ok(sink) = LocalSealedSink::open(&dir, agent_id.to_string()) else {
        return false;
    };
    if !sink.has_share(idx) {
        return false;
    }
    match sink.get_share(idx) {
        Ok(bytes) => serde_json::from_slice::<KeyPackage>(&bytes).is_ok(),
        Err(_) => false,
    }
}

/// Build a holder's [`RemoteHolderServer`] from its SEALED share at rest (the holder-boot loader,
/// counterpart of [`run_share_sink_server`]). Unseals share `idx` for `agent_id` via
/// `LocalSealedSink`, self-derives `own_pubkeys` from the share's group verifying key (see
/// [`own_pubkeys_from_key_package`]), and constructs the server -- so the holder can co-sign as
/// itself without the group `PublicKeyPackage` ever being shipped to it.
pub fn load_remote_holder_server(
    keystore_base: &Path,
    agent_id: &str,
    idx: u16,
) -> anyhow::Result<RemoteHolderServer> {
    let dir = holder_share_dir(keystore_base, agent_id);
    let sink = LocalSealedSink::open(&dir, agent_id.to_string())
        .with_context(|| format!("open holder sealed store {}", dir.display()))?;
    let bytes = sink
        .get_share(idx)
        .with_context(|| format!("unseal holder share {idx} for agent {agent_id}"))?;
    let kp: KeyPackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("deserialize holder KeyPackage {idx}"))?;
    let own_pubkeys = own_pubkeys_from_key_package(&kp);
    Ok(RemoteHolderServer::new(kp, own_pubkeys))
}

// ================================================================================================
// PART (c) PIECE 1: ENDPOINT AUTH -- the holder binds co-sign solicits to its AUTHORIZED COORDINATOR.
//
// keeper's resolved MVP (the implementation of gudnuf's already-✓'d lease-as-token + config model):
// the holder accepts a co-sign solicit ONLY from the agent's AUTHORIZED COORDINATOR transport pubkey,
// established at PROVISION time. In single-coordinator MVP the spawning node provisions AND
// coordinates, so the authorized coordinator = the DEALER that shipped the share (which signs the
// share-ship). The holder persists that pubkey when it seals the first share -- no placement field,
// no ship-frame change; provision-time is the root of trust. PIECE 2 (a fresh-lease LIVENESS check)
// folds into `coordinator_authorizer` next; the lease-carries-the-claiming-node's-pubkey shape is
// the cross-machine FAILOVER lane's (not this one). This replaces the `allow_all_coordinators` stub.
// ================================================================================================

/// The file (in a holder's per-agent dir) naming the AUTHORIZED COORDINATOR for that agent: the
/// transport pubkey the holder will co-sign solicits from. Established at PROVISION time.
const COORDINATOR_FILE: &str = "coordinator.pubkey";

fn coordinator_path(keystore_base: &Path, agent_id: &str) -> PathBuf {
    holder_share_dir(keystore_base, agent_id).join(COORDINATOR_FILE)
}

/// Persist (at provision) the agent's authorized COORDINATOR transport pubkey on the holder. The
/// coordinator is the DEALER that shipped the share (single-coordinator MVP: the spawning node
/// provisions AND coordinates). Idempotent; REFUSES to overwrite with a DIFFERENT coordinator (a
/// conflicting re-provision is rejected loudly, never silently re-rooted).
fn persist_authorized_coordinator(
    keystore_base: &Path,
    agent_id: &str,
    coordinator: &PublicKey,
) -> anyhow::Result<()> {
    let path = coordinator_path(keystore_base, agent_id);
    if path.is_file() {
        let existing = load_authorized_coordinator(keystore_base, agent_id)?;
        if &existing != coordinator {
            anyhow::bail!(
                "agent {agent_id} already has authorized coordinator {} on this holder; refusing to \
                 re-root to {}",
                existing.to_hex(),
                coordinator.to_hex()
            );
        }
        return Ok(());
    }
    std::fs::write(&path, coordinator.to_hex())
        .with_context(|| format!("persist authorized coordinator {}", path.display()))?;
    Ok(())
}

/// Load the agent's authorized COORDINATOR transport pubkey on this holder (set at provision).
pub fn load_authorized_coordinator(
    keystore_base: &Path,
    agent_id: &str,
) -> anyhow::Result<PublicKey> {
    let path = coordinator_path(keystore_base, agent_id);
    let hex = std::fs::read_to_string(&path)
        .with_context(|| format!("read authorized coordinator {}", path.display()))?;
    PublicKey::from_hex(hex.trim())
        .map_err(|e| anyhow::anyhow!("authorized coordinator {} is not a valid pubkey: {e}", path.display()))
}

/// The MVP [`CoordinatorAuthorizer`]: accept a co-sign solicit ONLY from the agent's authorized
/// coordinator transport pubkey (the provision-time root of trust). This is the SENDER-BINDING gate
/// that replaces [`allow_all_coordinators`] -- a rogue/un-entitled node's solicit is refused before
/// the holder ever burns a nonce. (PIECE 2 will compose this with a fresh-lease LIVENESS check:
/// `sender == coordinator AND the agent has a current Q-signed lease`.)
pub fn coordinator_authorizer(coordinator: PublicKey) -> CoordinatorAuthorizer {
    Arc::new(move |_agent_id: &str, sender: &PublicKey| sender == &coordinator)
}

// ================================================================================================
// PART (c) PIECE 2: the FRESH-LEASE LIVENESS check (folds into the coordinator authorizer).
//
// Sender-binding (PIECE 1) says WHO may solicit; the lease says WHETHER that coordinator is
// currently entitled to run the agent. keeper's MVP: the holder co-signs iff (sender == authorized
// coordinator) AND a FRESH lease exists for the agent. The holder learns the lease by WATCHING the
// relay: a [`kirby_proto::KIND_KIRBY_LEASE`] event, FROST-signed under the agent's OWN Q (the holder
// derives that Q from its share's group verifying key -- so it trusts ONLY its own agent's quorum,
// never a coordinator-asserted lease), latest-wins by the monotonic `term`, fresh while `issued_at`
// is within [`LEASE_TTL_SECS`]. A coordinator whose lease lapsed (the agent moved/died) is refused
// even though it is still the provisioned coordinator -- liveness, not just identity.
//
// (The lease-CARRIES-the-claiming-node's-pubkey shape, which lets a NEW failover coordinator be
// authorized without re-provisioning, is the cross-machine FAILOVER lane's; this lane reads the
// lease purely as the agent's liveness signal.)
// ================================================================================================

/// Current unix seconds (the freshness clock).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The fields the holder reads from a lease's signed content to judge liveness. A minimal local
/// shape (serde ignores the other lease fields, e.g. `holder_node_id`), so this does not couple to
/// `relay_lease::LeaseContent`'s full type -- only to the stable wire contract (spec 2:
/// `{ agent_id, holder_node_id, term, issued_at }`).
#[derive(serde::Deserialize)]
struct LeaseFreshness {
    agent_id: String,
    term: u64,
    issued_at: u64,
}

/// A holder-side view of the latest observed lease per agent (term + issued_at), populated by
/// [`run_lease_watcher`] and read by [`coordinator_authorizer_with_lease`]. Cloneable (shares the
/// inner map) so the watcher task and the authorizer closure see the same observations.
#[derive(Clone, Default)]
pub struct LeaseView {
    inner: Arc<Mutex<HashMap<String, (u64, u64)>>>, // agent_id -> (term, issued_at)
}

impl LeaseView {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold in an observed lease, OBSERVE-ONLY-FORWARD by monotonic term (a stale/equal term is
    /// ignored, mirroring the relay-lease store -- so an old replayed lease never moves the view
    /// backward). Records `issued_at` for the freshness check.
    fn observe(&self, agent_id: &str, term: u64, issued_at: u64) {
        let mut m = match self.inner.lock() {
            Ok(m) => m,
            Err(_) => return, // poisoned: skip (fail-safe; the authorizer fails closed)
        };
        match m.get(agent_id) {
            Some((prev_term, _)) if *prev_term >= term => {} // observe-only-forward
            _ => {
                m.insert(agent_id.to_string(), (term, issued_at));
            }
        }
    }

    /// Whether a FRESH lease exists for `agent_id` at `now`: an observed lease whose `issued_at` is
    /// within [`crate::relay_lease::LEASE_TTL_SECS`] (the canonical lease TTL). Fails closed (false)
    /// on a poisoned lock or no observation.
    fn is_fresh_at(&self, agent_id: &str, now: u64) -> bool {
        match self.inner.lock() {
            Ok(m) => m
                .get(agent_id)
                .map(|(_, issued_at)| now <= issued_at.saturating_add(crate::relay_lease::LEASE_TTL_SECS))
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// [`Self::is_fresh_at`] at the current time.
    pub fn is_fresh(&self, agent_id: &str) -> bool {
        self.is_fresh_at(agent_id, now_unix())
    }
}

/// Read a lease event's `d` tag (the addressable key; the lease's value is the `agent_id`).
fn lease_d_tag(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|t| {
        let s = t.as_slice();
        if s.first().map(|k| k.as_str() == "d").unwrap_or(false) {
            s.get(1).cloned()
        } else {
            None
        }
    })
}

/// Verify + fold ONE lease event into the [`LeaseView`]. The trust wall: the event MUST verify
/// (sig/id), be signed by the AGENT's OWN Q (`event.pubkey == agent_q` -- never a coordinator-
/// asserted lease), be a [`kirby_proto::KIND_KIRBY_LEASE`] whose content + `d` tag name THIS agent.
/// Returns whether it was accepted (observed). A forged/foreign/wrong-kind lease is dropped.
fn observe_lease_frame(
    view: &LeaseView,
    agent_q: &PublicKey,
    agent_id: &str,
    event: &Event,
) -> bool {
    if event.verify().is_err() {
        return false;
    }
    if &event.pubkey != agent_q {
        return false; // not signed by THIS agent's quorum key Q
    }
    if event.kind != Kind::from(kirby_proto::KIND_KIRBY_LEASE) {
        return false;
    }
    let content: LeaseFreshness = match serde_json::from_str(&event.content) {
        Ok(c) => c,
        Err(_) => return false,
    };
    if content.agent_id != agent_id || lease_d_tag(event).as_deref() != Some(agent_id) {
        return false; // the content + addressable key must both name this agent
    }
    view.observe(agent_id, content.term, content.issued_at);
    true
}

/// Run a holder-side lease-watcher: subscribe (via `conn`) to [`kirby_proto::KIND_KIRBY_LEASE`]
/// events and fold each Q-verified lease for `agent_id` into `view` (which the authorizer reads for
/// the freshness check). `agent_q` is the agent's group key (the holder derives it from its share
/// via [`holder_agent_q`]); only leases signed by it are trusted. Runs until `shutdown` fires.
pub async fn run_lease_watcher<C: RelayConn>(
    agent_q: PublicKey,
    agent_id: &str,
    view: LeaseView,
    conn: C,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(agent_id, agent_q = %agent_q.to_hex(), "holder lease-watcher starting (liveness gate)");
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            res = conn.next_event() => match res {
                Ok(event) => {
                    let _ = observe_lease_frame(&view, &agent_q, agent_id, &event);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "holder lease-watcher: connection closed, stopping");
                    break;
                }
            },
        }
    }
    Ok(())
}

/// The SHIPPABLE MVP [`CoordinatorAuthorizer`]: accept a co-sign solicit iff (sender == the agent's
/// authorized coordinator) AND (a FRESH lease exists for the agent in `view`). This composes PIECE 1
/// (sender-binding, the provision-time root of trust) with PIECE 2 (lease liveness). This is what
/// the holder boot wires into [`run_holder_server`] -- NOT the `allow_all_coordinators` stub.
pub fn coordinator_authorizer_with_lease(
    coordinator: PublicKey,
    view: LeaseView,
) -> CoordinatorAuthorizer {
    Arc::new(move |agent_id: &str, sender: &PublicKey| {
        sender == &coordinator && view.is_fresh(agent_id)
    })
}

/// Derive the agent's group key Q from a holder's SEALED share (so the holder can verify the agent's
/// own Q-signed leases without any pubkeys shipped to it -- the same self-derivation
/// [`own_pubkeys_from_key_package`] uses). The holder boot calls this to seed [`run_lease_watcher`].
pub fn holder_agent_q(keystore_base: &Path, agent_id: &str, idx: u16) -> anyhow::Result<PublicKey> {
    let dir = holder_share_dir(keystore_base, agent_id);
    let sink = LocalSealedSink::open(&dir, agent_id.to_string())
        .with_context(|| format!("open holder sealed store {}", dir.display()))?;
    let bytes = sink
        .get_share(idx)
        .with_context(|| format!("unseal holder share {idx} for agent {agent_id}"))?;
    let kp: KeyPackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("deserialize holder KeyPackage {idx}"))?;
    let own = own_pubkeys_from_key_package(&kp);
    let q = kirby_custody::group_xonly_q(&own).map_err(|e| anyhow::anyhow!("derive agent Q: {e}"))?;
    PublicKey::from_slice(&q).map_err(|e| anyhow::anyhow!("agent Q is not a valid x-only key: {e}"))
}

// ================================================================================================
// PART (c) PIECE 3: ANTI-REPLAY (a freshness window + per-frame dedup on the solicit path).
//
// A captured cosign solicit replayed off the relay must not drive a holder. Two guards, on TOP of
// the RemoteHolderServer's own single-use-nonce discipline: (1) a FRESHNESS window on the frame's
// signed `created_at` (a stale replay is refused; ephemeral kinds already shrink the window a relay
// would even deliver), and (2) per-(coordinator, session, round) DEDUP within the window (a frame
// replayed in-window is refused before the server sees it). A FRESH forgery cannot pass sender-auth
// (it is not signed by the coordinator), so freshness + sender-binding + dedup together close the
// replay surface for the solicit path.
// ================================================================================================

/// How far a cosign frame's signed `created_at` may diverge from now (clock-skew + relay-latency
/// tolerance) before it is treated as a replay and refused.
const FRESHNESS_WINDOW_SECS: u64 = 120;

/// Per-holder anti-replay guard for inbound cosign solicits: a freshness window on `created_at`
/// plus dedup of (coordinator, session, round) seen within the window. Bounded -- stale entries are
/// evicted on each admit, so it cannot grow without bound.
#[derive(Default)]
struct ReplayGuard {
    seen: Mutex<HashMap<(PublicKey, u64, u8), u64>>,
}

impl ReplayGuard {
    fn new() -> Self {
        Self::default()
    }

    /// Admit a frame for processing, or `Err` if it is STALE (its `created_at` is outside the
    /// freshness window) or a REPLAY (this (coordinator, session, round) was already seen in-window).
    /// Records the frame on admit. `now` is injected so the logic is deterministically testable.
    fn admit(
        &self,
        coordinator: &PublicKey,
        session: u64,
        round: u8,
        created_at: u64,
        now: u64,
    ) -> anyhow::Result<()> {
        // FRESHNESS: reject a frame whose signed created_at is too far from now (a stale replay, or
        // a wildly-skewed clock). Symmetric window (tolerate a little future skew + past latency).
        if created_at.saturating_add(FRESHNESS_WINDOW_SECS) < now
            || created_at > now.saturating_add(FRESHNESS_WINDOW_SECS)
        {
            anyhow::bail!(
                "cosign frame created_at {created_at} is outside the ±{FRESHNESS_WINDOW_SECS}s \
                 freshness window (now {now}) -- refused as a replay"
            );
        }
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| anyhow::anyhow!("replay guard poisoned"))?;
        // Bound memory: drop entries older than the window (they can never be a valid replay now).
        seen.retain(|_, seen_at| seen_at.saturating_add(FRESHNESS_WINDOW_SECS) >= now);
        let key = (*coordinator, session, round);
        if seen.contains_key(&key) {
            anyhow::bail!(
                "replayed cosign frame (coordinator/session/round {session}/{round} already seen \
                 in-window) -- refused"
            );
        }
        seen.insert(key, now);
        Ok(())
    }
}

// ================================================================================================
// THE PRODUCTION `RelayConn`: `NostrRelayConn` -- the wire the cross-machine ceremony rides.
//
// Everything above is generic over `<C: RelayConn>` and, until now, only the in-memory
// `InMemoryConn` (tests) satisfied it. `NostrRelayConn` is the real transport: a `nostr_sdk`
// `Client` subscribed to `#p = me` + the kirby transport kinds, reaching one or more real relays.
// It is the ONE keystone that turns the whole (already-proven) ceremony into a cross-machine one.
// ================================================================================================

/// How many recently-seen event ids [`NostrRelayConn`] remembers to suppress the SAME frame
/// arriving from multiple relays (multi-relay dedup). Bounded so a long-lived ceremony
/// subscription never grows without limit; a ceremony's frame rate is low, so this spans far
/// more than any in-flight window.
const SEEN_EVENT_CAP: usize = 4096;

/// A bounded recently-seen-event-id set with FIFO eviction, for cross-relay dedup: the SAME
/// signed frame is delivered once per relay it reaches, but the transport must yield it ONCE.
#[derive(Default)]
struct SeenEvents {
    set: std::collections::HashSet<EventId>,
    order: std::collections::VecDeque<EventId>,
}

impl SeenEvents {
    /// Record `id`; return `true` the FIRST time it is seen, `false` on a duplicate.
    fn first_sight(&mut self, id: EventId) -> bool {
        if self.set.contains(&id) {
            return false;
        }
        self.set.insert(id);
        self.order.push_back(id);
        if self.order.len() > SEEN_EVENT_CAP {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

/// The production [`RelayConn`]: a `nostr_sdk::Client` subscribed to `#p = me` + the kirby
/// transport kinds ([`kirby_proto::KIND_KIRBY_COSIGN`] + [`kirby_proto::KIND_KIRBY_SHARE`]),
/// reaching one or more real relays. Drops into the SAME `RelayConn` seam the in-memory double
/// fills, so the [`CoordinatorRelayHub`] / [`run_holder_server`] / framing are all unchanged.
///
/// OPACITY (the whole reason a relay drops in): a DUMB carrier. It moves whole signed [`Event`]s
/// and NEVER deserializes the ceremony `payload`; routing is the relay's `#p` + kind index alone,
/// exactly as the in-memory double. So the `nonce_never_crosses` invariant holds over the wire.
///
/// FAIL-CLOSED: `publish`/`next_event` surface every failure as `Err` (the any-available-2-of-3
/// fallback + the per-wire timeout turn that into "abandon this subset / defer"); a frame is never
/// silently dropped or fabricated. In particular `publish` treats "reached zero relays" as `Err`
/// even though nostr-sdk's `send_event` returns `Ok` with an empty success set in that case.
///
/// RECONNECT (the #103 lesson, load-bearing): the persistent subscription is NON-auto-closing and
/// the relays keep nostr-relay-pool's DEFAULT options -- `reconnect = true` AND the keepalive PING
/// ON. This is the deliberate OPPOSITE of the nerve presence lane (which disables ping because it
/// re-beacons every <=15s): here the keepalive is what surfaces a half-open socket so the pool's
/// reconnect loop fires, and on every (re)connect the pool AUTO-RE-SENDS the active REQ
/// (nostr-relay-pool `InnerRelay::resubscribe`, verified in-source). So a dropped / half-open relay
/// self-heals for the next ceremony with NO manual re-subscribe; a ceremony in flight during the
/// outage just times out per wire and the fallback abandons that subset. Multi-relay reach is the
/// other half: a frame fans out to every relay, so one relay dying still lands it via another.
///
/// LAZY CONNECT (runtime affinity): nostr-relay-pool spawns each relay's connection task on the
/// runtime that drives `connect().await` (`async_utility::task::spawn` -> `Handle::current`). The
/// hub / holder-server move a `RelayConn` into a background thread with ITS OWN runtime and drive
/// it there, so connect+subscribe is DEFERRED to the first `publish` / `next_event` (guarded by a
/// once-cell) -- that runs on the long-lived actor runtime, so the relay tasks live exactly as
/// long as the actor that owns them. Connecting eagerly on a throwaway runtime would strand them.
/// A caller that wants the subscription live up front (e.g. so a holder is subscribed BEFORE any
/// ephemeral solicit is published) calls [`Self::ensure_connected`] on its own long-lived runtime.
pub struct NostrRelayConn {
    /// This connection's own transport pubkey; the subscription is `#p = me`.
    me: PublicKey,
    /// The relays this connection publishes to (all of them) and reads from (deduped).
    relays: Vec<String>,
    /// The nostr-sdk client, built signer-LESS: frames are pre-signed before `publish`, so the
    /// client only carries bytes (it never signs, preserving opacity + the sender-auth model).
    client: Client,
    /// The pool notification stream, taken at construction (before connect) so nothing is missed
    /// once the relays come up. A `tokio::sync::Mutex` (matching the in-memory double) gives
    /// `next_event` `&self` access; it is driven by ONE actor loop, so the lock is uncontended.
    notifications: tokio::sync::Mutex<tokio::sync::broadcast::Receiver<RelayPoolNotification>>,
    /// Connect + subscribe exactly once, on the runtime of the first `publish` / `next_event`
    /// (or [`Self::ensure_connected`]). Cancel-safe: a cancelled init just retries next call.
    ready: tokio::sync::OnceCell<()>,
    /// Recently-seen event ids for cross-relay dedup.
    seen: Mutex<SeenEvents>,
}

impl NostrRelayConn {
    /// Bind a connection to `me` over `relays` WITHOUT connecting yet (connect is deferred to the
    /// first use; see the type doc's runtime-affinity note). Errs on an empty relay set
    /// (fail-closed: a carrier with nowhere to go is a configuration error, not a silent no-op).
    pub fn new(me: PublicKey, relays: Vec<String>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !relays.is_empty(),
            "NostrRelayConn requires at least one relay URL (got none)"
        );
        let client = Client::builder().build();
        let notifications = client.notifications();
        Ok(Self {
            me,
            relays,
            client,
            notifications: tokio::sync::Mutex::new(notifications),
            ready: tokio::sync::OnceCell::new(),
            seen: Mutex::new(SeenEvents::default()),
        })
    }

    /// Bind a connection from a holder-address token (`<pubkey_hex>@<relay_csv>`): subscribe
    /// `#p = <pubkey>` over `<relay_csv>`. Symmetric -- the coordinator and each holder each stand
    /// up their own `NostrRelayConn` from their own address (the SAME token `placement.json` holds).
    pub fn from_address(address: &str) -> anyhow::Result<Self> {
        let (me, relays) = parse_holder_address(address)?;
        Self::new(me, relays)
    }

    /// Force connect + subscribe now (idempotent). Production connects lazily on first use; this
    /// lets a caller warm the persistent subscription up front on its OWN long-lived runtime --
    /// e.g. so a holder's `#p = me` subscription is live BEFORE any (ephemeral, un-stored)
    /// KIND_KIRBY_COSIGN solicit is published at it.
    pub async fn ensure_connected(&self) -> anyhow::Result<()> {
        self.ensure_ready().await
    }

    /// Connect every relay (DEFAULT options: reconnect + keepalive ping ON) and subscribe the
    /// persistent `#p = me` + transport-kinds filter, exactly once. Uses `connect()` -- which spawns
    /// each relay's reconnect-looping task, so a relay down at init keeps retrying -- plus
    /// `wait_for_connection` (bounded, so the first publish rides a live socket where one is
    /// reachable); `verify_subscriptions(true)` per relay so a hostile relay cannot inject
    /// off-`#p` / wrong-kind frames; and a STABLE subscription id so a cancelled-retry or a reconnect
    /// re-REQs the SAME id rather than stacking a second subscription. A relay still down here is NOT
    /// fatal (reconnect keeps trying); the per-publish empty-success check is the real fail-closed gate.
    async fn ensure_ready(&self) -> anyhow::Result<()> {
        self.ready
            .get_or_try_init(|| async {
                for url in &self.relays {
                    // verify_subscriptions(true): the pool LOCALLY drops any relay-pushed event that
                    // does not match our active subscription, so a buggy / hostile relay cannot inject
                    // an off-`#p` or wrong-kind frame into next_event. Defense-in-depth for the routing
                    // + opacity contract -- WITHOUT this carrier ever parsing a tag itself.
                    self.client
                        .pool()
                        .add_relay(url, RelayOptions::new().verify_subscriptions(true))
                        .await
                        .with_context(|| format!("NostrRelayConn: add relay {url}"))?;
                }
                // connect() -- NOT try_connect -- spawns each relay's PERSISTENT connection task, so a
                // relay that is DOWN at init keeps retrying via the reconnect loop instead of being
                // abandoned (try_connect schedules NO retry after an initial-connection failure:
                // pool/mod.rs "without spawning the connection task if it fails"). wait_for_connection
                // then bounds the wait so the first publish rides a live socket where one is reachable.
                self.client.connect().await;
                self.client.wait_for_connection(Duration::from_secs(10)).await;
                let filter = Filter::new()
                    .kinds([
                        Kind::from(kirby_proto::KIND_KIRBY_COSIGN),
                        Kind::from(kirby_proto::KIND_KIRBY_SHARE),
                    ])
                    .pubkey(self.me);
                // A STABLE subscription id (derived from `me`): re-subscribing -- whether from a
                // cancelled-then-retried init or the pool's auto-resubscribe on reconnect -- reuses the
                // SAME id (an idempotent re-REQ), so it never stacks a second long-lived subscription.
                let sub_id = SubscriptionId::new(format!("kirby-frost-cosign-{}", self.me.to_hex()));
                self.client
                    .subscribe_with_id(sub_id, filter, None)
                    .await
                    .context("NostrRelayConn: subscribe #p=me + transport kinds")?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .map(|_| ())
    }
}

impl RelayConn for NostrRelayConn {
    async fn publish(&self, event: Event) -> anyhow::Result<()> {
        self.ensure_ready().await?;
        // send_event returns Ok even when EVERY relay rejected (the per-relay results live in the
        // Output); it Errs only on a structural miss (no relays configured). Fail-closed: an empty
        // success set means the frame reached NO relay -- surface it as Err so the wire times out
        // cleanly instead of pretending the frame was delivered.
        let output = self
            .client
            .send_event(&event)
            .await
            .map_err(|e| anyhow::anyhow!("NostrRelayConn publish: {e}"))?;
        if output.success.is_empty() {
            anyhow::bail!(
                "NostrRelayConn publish: reached zero relays ({} failed)",
                output.failed.len()
            );
        }
        Ok(())
    }

    async fn next_event(&self) -> anyhow::Result<Event> {
        self.ensure_ready().await?;
        let mut rx = self.notifications.lock().await;
        loop {
            match rx.recv().await {
                Ok(RelayPoolNotification::Event { event, .. }) => {
                    // Cross-relay dedup by id (the SAME frame arrives once per relay). NEVER
                    // inspect the payload -- the carrier stays opaque. There is NO await between
                    // matching and returning, so a `select!` cancellation cannot drop a frame
                    // already taken off the stream.
                    let id = event.id;
                    if self
                        .seen
                        .lock()
                        .map_err(|_| anyhow::anyhow!("NostrRelayConn seen-set poisoned"))?
                        .first_sight(id)
                    {
                        return Ok(*event);
                    }
                }
                Ok(RelayPoolNotification::Shutdown) => {
                    anyhow::bail!("NostrRelayConn: relay pool shut down");
                }
                // EOSE / OK / other relay messages are not a delivery -- keep waiting.
                Ok(RelayPoolNotification::Message { .. }) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // The stream overflowed and dropped `n` notifications for THIS receiver. We do NOT
                    // surface this as Err: an Err from next_event makes the actor loop `break`, which
                    // would tear down the whole long-lived hub / holder-server on a transient overflow.
                    // Fail-closed is preserved at the CEREMONY boundary instead -- a dropped frame means
                    // a reply the peer awaits never arrives, so that wire hits its timeout and the
                    // any-available-2-of-3 fallback abandons the subset. An incomplete aggregate can
                    // never verify under Q, so a lag can only cost a clean retry, never a partial /
                    // wrong signature. Logged loudly so overload stays visible.
                    tracing::warn!(
                        skipped = n,
                        "NostrRelayConn: notification stream lagged (dropped frames surface as a per-wire timeout + fallback)"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    anyhow::bail!("NostrRelayConn: notification stream closed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quorum_signer::{Holder, LocalHolder, QuorumSigner};
    use crate::remote_holder::{InProcessHolderLink, RemoteHolder};
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
    use bitcoin::KnownHrp;
    use kirby_custody::cosign_net::nip01_event_id;
    use kirby_custody::{generate_dealer_keyset, key_packages, taproot_address};

    const CREATED_AT: u64 = 1750000000;
    const CONTENT: &str = "Kirby co-signs across machines over the relay, by choice.";
    const AGENT: &str = "agent-relay-test";

    fn keyset() -> kirby_custody::DealerKeyset {
        generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen")
    }

    fn three_kps(ks: &kirby_custody::DealerKeyset) -> Vec<KeyPackage> {
        key_packages(ks).expect("key packages").into_values().collect()
    }

    fn verifies_under_q(sig_hex: &str, message: &[u8; 32], pubkeys: &PublicKeyPackage) -> bool {
        let (_addr, internal_p) = taproot_address(pubkeys, KnownHrp::Testnets).expect("addr");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let Ok(bytes) = hex::decode(sig_hex) else { return false };
        let Ok(sig) = schnorr::Signature::from_slice(&bytes) else { return false };
        secp.verify_schnorr(&sig, &Message::from_digest(*message), &q_xonly)
            .is_ok()
    }

    // ----- An in-memory relay double: routes by `#p` + carries content opaque (the contract) ---

    /// A shared in-memory relay: per-subscriber inbox keyed by the subscriber's pubkey. A
    /// published event is delivered to the inbox of its `#p` recipient. It reads ONLY the `#p`
    /// tag (a real relay's routing index) and NEVER the content -- the opacity contract that
    /// lets a real relay drop into the `RelayConn` seam unchanged.
    #[derive(Clone)]
    struct InMemoryRelay {
        inboxes: Arc<Mutex<HashMap<PublicKey, UnboundedSender<Event>>>>,
    }

    impl InMemoryRelay {
        fn new() -> Self {
            Self { inboxes: Arc::new(Mutex::new(HashMap::new())) }
        }

        /// A connection bound to `me` (registers its inbox; events `#p`-addressed to `me` land here).
        fn endpoint(&self, me: PublicKey) -> InMemoryConn {
            let (tx, rx) = unbounded_channel();
            self.inboxes.lock().unwrap().insert(me, tx);
            InMemoryConn {
                inboxes: Arc::clone(&self.inboxes),
                rx: tokio::sync::Mutex::new(rx),
                wire_log: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    /// One in-memory `RelayConn` endpoint. `publish` routes by `#p`; `next_event` pops this
    /// endpoint's inbox. Every published event is also appended to a shared `wire_log` for the
    /// opacity byte-check.
    struct InMemoryConn {
        inboxes: Arc<Mutex<HashMap<PublicKey, UnboundedSender<Event>>>>,
        rx: tokio::sync::Mutex<UnboundedReceiver<Event>>,
        wire_log: Arc<Mutex<Vec<Event>>>,
    }

    impl RelayConn for InMemoryConn {
        async fn publish(&self, event: Event) -> anyhow::Result<()> {
            self.wire_log.lock().unwrap().push(event.clone());
            let to = recipient_pubkey(&event)
                .ok_or_else(|| anyhow::anyhow!("in-memory relay: frame has no #p recipient"))?;
            let inboxes = self.inboxes.lock().unwrap();
            match inboxes.get(&to) {
                Some(tx) => {
                    let _ = tx.send(event);
                    Ok(())
                }
                None => anyhow::bail!("in-memory relay: no subscriber for {}", to.to_hex()),
            }
        }

        async fn next_event(&self) -> anyhow::Result<Event> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("in-memory relay: closed"))
        }
    }

    /// THE CODEC ROUND-TRIPS: a CoSignEvent -> signed Nostr frame -> back to the SAME
    /// CoSignEvent, with the sender = the signer's transport pubkey, and a tampered frame is
    /// rejected at verify.
    #[test]
    fn codec_round_trips_and_rejects_tampering() {
        let coordinator = Keys::generate();
        let holder = Keys::generate();
        let cse = CoSignEvent {
            session_id: 42,
            from: GuardianId::try_from(2u16).unwrap(),
            round: kirby_custody::seam::ROUND_SHARE,
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let frame =
            encode_cosign_frame(AGENT, &cse, holder.public_key(), &coordinator).expect("encode");
        let (agent, decoded, sender) = decode_cosign_frame(&frame).expect("decode");
        assert_eq!(agent, AGENT);
        assert_eq!(sender, coordinator.public_key(), "sender is the signer's transport key");
        assert_eq!(decoded.session_id, cse.session_id);
        assert_eq!(decoded.from, cse.from);
        assert_eq!(decoded.round, cse.round);
        assert_eq!(decoded.payload, cse.payload, "opaque payload round-trips byte-for-byte");

        // Tamper the content after signing -> verify must fail (the id no longer matches).
        let json = serde_json::to_string(&frame).expect("serialize frame to json");
        let tampered = json.replace("cafebabe", "deadbeef");
        assert_ne!(json, tampered, "the tamper must actually change the frame json");
        let bad = Event::from_json(&tampered).expect("parse the tampered json back to an Event");
        assert!(
            decode_cosign_frame(&bad).is_err(),
            "a tampered frame must be rejected at verify (id/content mismatch)"
        );
        println!("CODEC PASS: CoSignEvent <-> signed frame round-trips; tampering rejected at verify");
    }

    /// THE KEYSTONE TEETH: a 2-of-3 quorum where ONE holder is a `RemoteHolder` over the REAL
    /// relay transport (the in-memory relay double + the holder server loop running on its own
    /// thread) and the other is co-located produces a Q-valid BIP-340 signature -- WITHOUT
    /// changing the QuorumSigner ceremony body. This is the cross-machine round-trip, sync
    /// bridge + actor + holder server included.
    #[test]
    fn remote_relay_holder_in_a_2of3_quorum_produces_a_q_valid_signature() {
        let ks = keyset();
        let kps = three_kps(&ks);

        let relay = InMemoryRelay::new();
        let coordinator_keys = Keys::generate();
        let holder_keys = Keys::generate();

        // Holder 2 lives "on another machine": start its server loop on its own thread.
        let server2 = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let holder_conn = relay.endpoint(holder_keys.public_key());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let holder_keys_thread = holder_keys.clone();
        let server2_thread = Arc::clone(&server2);
        let holder_thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("holder rt");
            rt.block_on(async {
                let _ = run_holder_server(
                    &holder_keys_thread,
                    AGENT,
                    server2_thread,
                    holder_conn,
                    allow_all_coordinators(),
                    shutdown_rx,
                )
                .await;
            });
        });

        // The coordinator hub over its own relay endpoint.
        let coord_conn = relay.endpoint(coordinator_keys.public_key());
        let hub = CoordinatorRelayHub::start(
            coord_conn,
            coordinator_keys.clone(),
            AGENT,
            DEFAULT_WIRE_TIMEOUT,
        )
        .expect("start hub");

        // Holder 1 co-located; holder 2 remote over the relay transport.
        let local = LocalHolder::new(kps[0].clone(), ks.pubkeys.clone());
        let remote_addr = format!("{}@inmem", holder_keys.public_key().to_hex());
        let remote_transport = hub.connect(&remote_addr).expect("connect remote holder");
        let remote = RemoteHolder::new(
            crate::quorum_signer::identifier_to_u16(kps[1].identifier()),
            remote_transport,
        );

        let holders: Vec<Box<dyn Holder>> = vec![Box::new(local), Box::new(remote)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build mixed signer");

        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("2-of-3 with a relay RemoteHolder signs");

        let expect_id = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, CONTENT);
        assert_eq!(event.id, hex::encode(expect_id), "id is the NIP-01 id under Q");
        assert_eq!(event.pubkey, hex::encode(qs.q_bytes()));
        assert!(
            verifies_under_q(&event.sig, &expect_id, &ks.pubkeys),
            "the mixed local+relay-remote 2-of-3 aggregate must verify under Q"
        );

        let _ = shutdown_tx.send(());
        drop(hub);
        let _ = holder_thread.join();
        println!("RELAY-REMOTE-HOLDER PASS: a 2-of-3 quorum with one RemoteHolder over the relay produced a Q-valid signature");
    }

    /// F2 TOOTH (non-mutating probe routing): a takeover-admission PROBE and a live signing ceremony
    /// share ONE hub + ONE holder, concurrently -- and NEITHER loses its reply route. The signer's
    /// transport ([`CoordinatorRelayHub::connect`]) takes a session-agnostic route; the probe's
    /// ([`CoordinatorRelayHub::connect_probe`]) a session-scoped one. The holder then emits BOTH a
    /// ceremony reply (`ROUND_COMMITMENT`) and a probe ack (`ROUND_PROBE_ACK`), and each is demuxed to
    /// its OWN transport. Before #49 the probe's connect did a bare `routes.insert(pubkey, ..)` that
    /// OVERWROTE the memoized signer's per-holder reply route -- so the ceremony reply would land in
    /// the probe's channel and the live signer would hang. RED-on-revert: route `connect_probe` back
    /// into `routes` (the pre-fix clobber) and the signer's `recv` below times out (route stolen).
    #[test]
    fn probe_and_live_ceremony_over_one_hub_keep_their_reply_routes() {
        let relay = InMemoryRelay::new();
        let coordinator_keys = Keys::generate();
        let holder_keys = Keys::generate();

        let coord_conn = relay.endpoint(coordinator_keys.public_key());
        let hub = CoordinatorRelayHub::start(
            coord_conn,
            coordinator_keys.clone(),
            AGENT,
            DEFAULT_WIRE_TIMEOUT,
        )
        .expect("start hub");

        let holder_addr = format!("{}@inmem", holder_keys.public_key().to_hex());
        // The memoized SIGNER's transport for this holder (session-agnostic route in `routes`).
        let signer_transport = hub.connect(&holder_addr).expect("signer connect");
        // A PROBE's transport for the SAME holder, session-scoped in `probe_routes`.
        const PROBE_SESSION: u64 = 7;
        let probe_transport =
            hub.connect_probe(&holder_addr, PROBE_SESSION).expect("probe connect");

        // The holder emits BOTH replies (signed by its transport key, #p-addressed to the
        // coordinator): the probe ack FIRST, so a clobbered signer route would drop the ceremony
        // reply that follows. The ceremony reply carries the signer's first session id (0).
        let probe_ack = CoSignEvent {
            session_id: PROBE_SESSION,
            from: GuardianId::try_from(2u16).unwrap(),
            round: crate::remote_holder::ROUND_PROBE_ACK,
            payload: Vec::new(),
        };
        let ceremony_reply = CoSignEvent {
            session_id: 0,
            from: GuardianId::try_from(2u16).unwrap(),
            round: kirby_custody::seam::ROUND_COMMITMENT,
            payload: vec![0xAB, 0xCD],
        };
        let ack_frame =
            encode_cosign_frame(AGENT, &probe_ack, coordinator_keys.public_key(), &holder_keys)
                .expect("encode probe ack");
        let reply_frame = encode_cosign_frame(
            AGENT,
            &ceremony_reply,
            coordinator_keys.public_key(),
            &holder_keys,
        )
        .expect("encode ceremony reply");

        let holder_conn = relay.endpoint(holder_keys.public_key());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("publish rt");
        rt.block_on(async {
            holder_conn.publish(ack_frame).await.expect("publish probe ack");
            holder_conn.publish(reply_frame).await.expect("publish ceremony reply");
        });

        // The signer's route must still receive the CEREMONY reply, and the probe's route the PROBE
        // ACK -- neither clobbered by the other's connect over the shared hub.
        let got_signer = signer_transport
            .recv()
            .expect("signer route intact: the ceremony reply must reach the signer transport");
        assert_eq!(
            got_signer.round,
            kirby_custody::seam::ROUND_COMMITMENT,
            "the signer transport got the ceremony reply, not the probe ack"
        );
        assert_eq!(got_signer.payload, vec![0xAB, 0xCD]);

        let got_probe = probe_transport
            .recv()
            .expect("probe route intact: the probe ack must reach the probe transport");
        assert_eq!(got_probe.round, crate::remote_holder::ROUND_PROBE_ACK);
        assert_eq!(
            got_probe.session_id, PROBE_SESSION,
            "the probe transport got its own session-scoped ack"
        );

        drop(hub);
        println!(
            "F2 PASS: a probe + a live ceremony over one hub keep distinct reply routes (no clobber)"
        );
    }

    /// THE ECDH-DEMUX TOOTH: a live SIGNER ceremony and a single-round ECDH ceremony over the SAME
    /// hub for the SAME holder keep DISTINCT reply routes. The holder emits BOTH an ECDH contribution
    /// (`ROUND_ECDH_CONTRIBUTION`, session-scoped) and a signing reply (`ROUND_COMMITMENT`,
    /// per-holder); each demuxes to its OWN transport. If `connect_ecdh` had registered in the
    /// signer's per-holder `routes` (the clobber), the ceremony reply would land in the ECDH channel
    /// and the live signer would hang — this proves the session-scoped ECDH route avoids that.
    #[test]
    fn ecdh_and_live_ceremony_over_one_hub_keep_their_reply_routes() {
        let relay = InMemoryRelay::new();
        let coordinator_keys = Keys::generate();
        let holder_keys = Keys::generate();

        let coord_conn = relay.endpoint(coordinator_keys.public_key());
        let hub = CoordinatorRelayHub::start(
            coord_conn,
            coordinator_keys.clone(),
            AGENT,
            DEFAULT_WIRE_TIMEOUT,
        )
        .expect("start hub");

        let holder_addr = format!("{}@inmem", holder_keys.public_key().to_hex());
        // The memoized SIGNER's transport (session-agnostic route in `routes`).
        let signer_transport = hub.connect(&holder_addr).expect("signer connect");
        // An ECDH ceremony's transport for the SAME holder, session-scoped in `ecdh_routes`.
        const ECDH_SESSION: u64 = 5;
        let ecdh_transport = hub.connect_ecdh(&holder_addr, ECDH_SESSION).expect("ecdh connect");

        // The holder emits the ECDH contribution FIRST (a clobbered signer route would then drop the
        // ceremony reply that follows). The ceremony reply carries the signer's first session id (0).
        let ecdh_reply = CoSignEvent {
            session_id: ECDH_SESSION,
            from: GuardianId::try_from(2u16).unwrap(),
            round: crate::remote_holder::ROUND_ECDH_CONTRIBUTION,
            payload: vec![0x01, 0x02, 0x03],
        };
        let ceremony_reply = CoSignEvent {
            session_id: 0,
            from: GuardianId::try_from(2u16).unwrap(),
            round: kirby_custody::seam::ROUND_COMMITMENT,
            payload: vec![0xAB, 0xCD],
        };
        let ecdh_frame =
            encode_cosign_frame(AGENT, &ecdh_reply, coordinator_keys.public_key(), &holder_keys)
                .expect("encode ecdh reply");
        let reply_frame = encode_cosign_frame(
            AGENT,
            &ceremony_reply,
            coordinator_keys.public_key(),
            &holder_keys,
        )
        .expect("encode ceremony reply");

        let holder_conn = relay.endpoint(holder_keys.public_key());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("publish rt");
        rt.block_on(async {
            holder_conn.publish(ecdh_frame).await.expect("publish ecdh reply");
            holder_conn.publish(reply_frame).await.expect("publish ceremony reply");
        });

        // The signer's route must still receive the CEREMONY reply, and the ECDH route the ECDH
        // contribution -- neither clobbered by the other's connect over the shared hub.
        let got_signer = signer_transport
            .recv()
            .expect("signer route intact: the ceremony reply must reach the signer transport");
        assert_eq!(
            got_signer.round,
            kirby_custody::seam::ROUND_COMMITMENT,
            "the signer transport got the ceremony reply, not the ECDH contribution"
        );
        assert_eq!(got_signer.payload, vec![0xAB, 0xCD]);

        let got_ecdh = ecdh_transport
            .recv()
            .expect("ecdh route intact: the contribution must reach the ecdh transport");
        assert_eq!(got_ecdh.round, crate::remote_holder::ROUND_ECDH_CONTRIBUTION);
        assert_eq!(
            got_ecdh.session_id, ECDH_SESSION,
            "the ECDH transport got its own session-scoped contribution"
        );
        assert_eq!(got_ecdh.payload, vec![0x01, 0x02, 0x03]);

        drop(hub);
        println!(
            "ECDH-DEMUX PASS: an ECDH ceremony + a live signer over one hub keep distinct reply routes (no clobber)"
        );
    }

    /// A fresh temp keystore base unique to this test + process (the holder's sealed store).
    fn temp_keystore_base(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kirby-ht-sink-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Spawn a holder-side share-sink server on its own thread (own runtime), returning its
    /// shutdown sender + join handle. The server seals shipped shares under `base`.
    fn spawn_share_sink_server(
        relay: &InMemoryRelay,
        holder: &Keys,
        base: &Path,
    ) -> (tokio::sync::oneshot::Sender<()>, std::thread::JoinHandle<()>) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let conn = relay.endpoint(holder.public_key());
        let holder_keys = holder.clone();
        let base = base.to_path_buf();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("share-sink rt");
            rt.block_on(async {
                let _ = run_share_sink_server(
                    &holder_keys,
                    &base,
                    conn,
                    allow_all_dealers(),
                    shutdown_rx,
                )
                .await;
            });
        });
        (shutdown_tx, handle)
    }

    /// REMOTE ShareSink ROUND-TRIP: ship a share (NIP-44-encrypted) -> the holder seals it at rest
    /// -> ACK; `has_share` attests it present (and a different idx absent = fail-closed); `get_share`
    /// Errs by design; and the holder LOADS its sealed share back into a RemoteHolderServer.
    #[test]
    fn remote_share_sink_ships_seals_loads_and_attests() {
        let ks = keyset();
        let kps = three_kps(&ks);
        let idx = crate::quorum_signer::identifier_to_u16(kps[1].identifier());
        let kp_json = serde_json::to_vec(&kps[1]).expect("serialize the share KeyPackage");

        let relay = InMemoryRelay::new();
        let dealer = Keys::generate();
        let holder = Keys::generate();
        let base = temp_keystore_base("attest");
        let (shutdown_tx, server_thread) = spawn_share_sink_server(&relay, &holder, &base);

        let dealer_conn = relay.endpoint(dealer.public_key());
        let addr = format!("{}@inmem", holder.public_key().to_hex());
        let sink = RemoteShareSink::start(
            dealer_conn,
            dealer.clone(),
            AGENT,
            &addr,
            "holder-2",
            DEFAULT_WIRE_TIMEOUT,
        )
        .expect("start the remote share sink");

        // Ship -> holder NIP-44-decrypts -> seals at rest -> ACK.
        sink.put_share(idx, &kp_json).expect("ship + seal + ACK");
        // The holder recorded the shipping dealer as its authorized coordinator (provision-time
        // root of trust for the endpoint authorizer).
        assert_eq!(
            load_authorized_coordinator(&base, AGENT).expect("authorized coordinator persisted"),
            dealer.public_key(),
            "the holder must record the shipping dealer as the authorized coordinator"
        );
        // Attestation: present for the shipped idx, absent for any other (fail-closed).
        assert!(sink.has_share(idx), "the holder must attest the sealed share present");
        let other = if idx == 1 { 2 } else { 1 };
        assert!(!sink.has_share(other), "an unshipped idx must attest ABSENT (fail-closed reload)");
        // get_share Errs by design (never re-centralize the secret).
        assert!(sink.get_share(idx).is_err(), "RemoteShareSink::get_share must Err by design");

        // The holder loads its sealed share into a RemoteHolderServer (self-derived pubkeys).
        let loaded = load_remote_holder_server(&base, AGENT, idx).expect("load the sealed share");
        assert_eq!(loaded.id(), idx, "the loaded server holds the shipped share's identifier");

        let _ = shutdown_tx.send(());
        drop(sink);
        let _ = server_thread.join();
        let _ = std::fs::remove_dir_all(&base);
        println!("REMOTE-SHARESINK PASS: ship -> NIP-44 -> holder seal-at-rest -> ACK; has_share attests; get_share Errs; load unseals to the right server");
    }

    /// THE PART-(b) KEYSTONE: a share that was NIP-44-shipped to a holder, SEALED at rest, then
    /// RELOADED, co-signs a Q-valid 2-of-3 -- proving the holder's self-derived `own_pubkeys`
    /// (from the share's group verifying key alone) yields the CORRECT Q. Uses the in-process link
    /// for the sign step (the relay sign path is covered separately) to focus on ship->seal->load.
    #[test]
    fn shipped_share_loads_and_signs_q_valid() {
        let ks = keyset();
        let kps = three_kps(&ks);
        let idx = crate::quorum_signer::identifier_to_u16(kps[1].identifier());
        let kp_json = serde_json::to_vec(&kps[1]).expect("serialize the share KeyPackage");

        let relay = InMemoryRelay::new();
        let dealer = Keys::generate();
        let holder = Keys::generate();
        let base = temp_keystore_base("sign");
        let (shutdown_tx, server_thread) = spawn_share_sink_server(&relay, &holder, &base);

        let dealer_conn = relay.endpoint(dealer.public_key());
        let addr = format!("{}@inmem", holder.public_key().to_hex());
        let sink = RemoteShareSink::start(
            dealer_conn,
            dealer.clone(),
            AGENT,
            &addr,
            "holder-2",
            DEFAULT_WIRE_TIMEOUT,
        )
        .expect("start the remote share sink");
        sink.put_share(idx, &kp_json).expect("ship + seal");
        let _ = shutdown_tx.send(());
        drop(sink);
        let _ = server_thread.join();

        // Reload the sealed share into a RemoteHolderServer and co-sign a 2-of-3 with a co-located
        // holder (via the in-process link).
        let loaded = Arc::new(load_remote_holder_server(&base, AGENT, idx).expect("load sealed share"));
        let link = InProcessHolderLink::new(Arc::clone(&loaded));
        let remote = RemoteHolder::new(loaded.id(), link);
        let local = LocalHolder::new(kps[0].clone(), ks.pubkeys.clone());
        let holders: Vec<Box<dyn Holder>> = vec![Box::new(local), Box::new(remote)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build signer");

        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("a shipped+sealed+reloaded share co-signs");
        let expect_id = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, CONTENT);
        assert!(
            verifies_under_q(&event.sig, &expect_id, &ks.pubkeys),
            "a shipped+sealed+reloaded share must co-sign Q-valid (self-derived own_pubkeys gives the correct Q)"
        );

        let _ = std::fs::remove_dir_all(&base);
        println!("SHIPPED-SHARE-SIGNS PASS: a NIP-44-shipped, sealed-at-rest, reloaded share co-signs a Q-valid 2-of-3 (self-derived holder pubkeys)");
    }

    /// ENDPOINT AUTH (PIECE 1): a holder gated by [`coordinator_authorizer`] ACCEPTS a co-sign
    /// solicit from its authorized coordinator and REFUSES one from any other (rogue) node -- the
    /// rogue's `commit` gets no reply (the holder dropped it before burning a nonce) and times out,
    /// while the authorized coordinator's `commit` returns a real commitment.
    #[test]
    fn holder_binds_solicits_to_its_authorized_coordinator() {
        let ks = keyset();
        let kps = three_kps(&ks);
        let id = crate::quorum_signer::identifier_to_u16(kps[1].identifier());

        let relay = InMemoryRelay::new();
        let authorized = Keys::generate(); // the provision-time coordinator
        let rogue = Keys::generate(); // an un-entitled node
        let holder_keys = Keys::generate();

        // The cosign holder server, gated to ONLY the authorized coordinator's pubkey.
        let server = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let holder_conn = relay.endpoint(holder_keys.public_key());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let hk = holder_keys.clone();
        let srv = Arc::clone(&server);
        let authz = coordinator_authorizer(authorized.public_key());
        let holder_thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("holder rt");
            rt.block_on(async {
                let _ = run_holder_server(&hk, AGENT, srv, holder_conn, authz, shutdown_rx).await;
            });
        });

        let holder_addr = format!("{}@inmem", holder_keys.public_key().to_hex());

        // ROGUE coordinator: a SHORT timeout so the refusal is fast. `commit` must Err (the holder
        // drops the solicit before any nonce is generated -> no reply -> timeout).
        let rogue_conn = relay.endpoint(rogue.public_key());
        let rogue_hub = CoordinatorRelayHub::start(
            rogue_conn,
            rogue.clone(),
            AGENT,
            Duration::from_millis(800),
        )
        .expect("rogue hub");
        let rogue_remote = RemoteHolder::new(id, rogue_hub.connect(&holder_addr).expect("connect"));
        assert!(
            rogue_remote.commit(1).is_err(),
            "the holder MUST refuse a solicit from an unauthorized coordinator (no reply, no nonce burned)"
        );

        // AUTHORIZED coordinator: `commit` succeeds (the holder replies with a real commitment).
        let auth_conn = relay.endpoint(authorized.public_key());
        let auth_hub = CoordinatorRelayHub::start(
            auth_conn,
            authorized.clone(),
            AGENT,
            DEFAULT_WIRE_TIMEOUT,
        )
        .expect("authorized hub");
        let auth_remote = RemoteHolder::new(id, auth_hub.connect(&holder_addr).expect("connect"));
        assert!(
            auth_remote.commit(2).is_ok(),
            "the holder MUST accept a solicit from its authorized coordinator"
        );

        let _ = shutdown_tx.send(());
        drop(rogue_hub);
        drop(auth_hub);
        let _ = holder_thread.join();
        println!("COORDINATOR-AUTH PASS: holder accepts its authorized coordinator's solicit, refuses a rogue's (no nonce burned)");
    }

    /// Sign a KIND_KIRBY_LEASE event under `qs` (the agent's Q) for the lease-liveness tests. The
    /// content names the agent + term + issued_at (holder_node_id is ignored by the reader).
    fn sign_test_lease(qs: &QuorumSigner, agent: &str, term: u64, issued_at: u64) -> Event {
        let json = format!(
            r#"{{"agent_id":"{agent}","holder_node_id":"node-test","term":{term},"issued_at":{issued_at}}}"#
        );
        let signed = qs
            .sign_nostr_event_with_tags(
                kirby_proto::KIND_KIRBY_LEASE as u32,
                issued_at,
                &[vec!["d".to_string(), agent.to_string()]],
                &json,
            )
            .expect("sign test lease under Q");
        Event::from_json(serde_json::to_string(&signed).expect("serialize lease event"))
            .expect("parse lease event")
    }

    /// PIECE 2: the lease-composed authorizer requires BOTH (sender == coordinator) AND a FRESH,
    /// agent-Q-signed lease. A lease signed by a non-agent Q is rejected; a stale lease (or none)
    /// refuses even the authorized coordinator (liveness lapsed, not just identity).
    #[test]
    fn fresh_lease_gates_the_authorizer() {
        let ks = keyset();
        let qs = crate::quorum_signer::local_quorum_from_keyset(&ks).expect("build quorum signer");
        let agent_q = PublicKey::from_slice(&qs.q_bytes()).expect("agent Q");
        let coordinator = Keys::generate().public_key();
        let view = LeaseView::new();
        let authz = coordinator_authorizer_with_lease(coordinator, view.clone());

        // (a) No lease yet -> reject even the authorized coordinator (the liveness gate).
        assert!(!authz(AGENT, &coordinator), "no lease => reject (liveness gate)");

        // (b) A FRESH lease signed by the AGENT's Q -> observed -> the coordinator is accepted.
        let now = now_unix();
        assert!(
            observe_lease_frame(&view, &agent_q, AGENT, &sign_test_lease(&qs, AGENT, 1, now)),
            "a fresh Q-signed lease must be observed"
        );
        assert!(authz(AGENT, &coordinator), "coordinator + fresh lease => accept");
        assert!(
            !authz(AGENT, &Keys::generate().public_key()),
            "wrong sender => reject even with a fresh lease"
        );

        // (c) A lease signed by a DIFFERENT (non-agent) Q -> rejected, never observed.
        let ks2 = keyset();
        let qs2 = crate::quorum_signer::local_quorum_from_keyset(&ks2).expect("other signer");
        assert!(
            !observe_lease_frame(&view, &agent_q, AGENT, &sign_test_lease(&qs2, AGENT, 9, now)),
            "a lease signed by a non-agent Q must be rejected"
        );

        // (d) A STALE lease (newer term, issued_at far past) -> observed-forward but is_fresh false.
        let stale_at = now.saturating_sub(crate::relay_lease::LEASE_TTL_SECS * 5);
        assert!(
            observe_lease_frame(&view, &agent_q, AGENT, &sign_test_lease(&qs, AGENT, 2, stale_at)),
            "the stale lease (newer term) is still observed (term moves forward)"
        );
        assert!(!authz(AGENT, &coordinator), "a stale lease => reject (liveness lapsed)");
        println!("FRESH-LEASE-GATE PASS: authorizer = sender==coordinator AND a fresh agent-Q lease; wrong-Q + stale + none all refuse");
    }

    /// PIECE 3: the replay guard refuses a STALE-created_at frame and a DUPLICATE
    /// (coordinator, session, round) within the window, while admitting fresh, distinct frames.
    #[test]
    fn replay_guard_rejects_stale_and_duplicate_frames() {
        let guard = ReplayGuard::new();
        let coord = Keys::generate().public_key();
        let now = now_unix();

        // Fresh + first-seen -> admit.
        assert!(guard.admit(&coord, 5, 10, now, now).is_ok(), "a fresh first-seen frame is admitted");
        // The SAME (coord, session, round) -> replay, refused.
        assert!(
            guard.admit(&coord, 5, 10, now, now).is_err(),
            "a duplicate (coord,session,round) is refused"
        );
        // A different ROUND of the same session is a distinct frame -> admitted.
        assert!(
            guard.admit(&coord, 5, 3, now, now).is_ok(),
            "a different round of the same session is admitted (distinct frame)"
        );
        // A STALE created_at (far in the past) -> refused (outside the freshness window).
        assert!(
            guard
                .admit(&coord, 6, 10, now.saturating_sub(FRESHNESS_WINDOW_SECS * 3), now)
                .is_err(),
            "a stale-created_at frame is refused"
        );
        // A DIFFERENT coordinator with the same session/round is a distinct frame -> admitted.
        let other = Keys::generate().public_key();
        assert!(
            guard.admit(&other, 5, 10, now, now).is_ok(),
            "a different coordinator is a distinct frame"
        );
        println!("REPLAY-GUARD PASS: fresh admitted; duplicate (coord,session,round) refused; stale created_at refused");
    }

    // ---- NostrRelayConn: the production transport, proven over a REAL (hermetic, in-process) ----
    // ---- nostr relay. These are ADDITIVE: the InMemoryConn tests above stay the fast golden.  ----

    use nostr_relay_builder::{LocalRelay, MockRelay, RelayBuilder};

    /// FRAME ROUND-TRIP over a REAL relay: a `#p`-addressed CoSignEvent frame published by the
    /// coordinator's [`NostrRelayConn`] arrives at the holder's [`NostrRelayConn`] over a hermetic
    /// in-process nostr relay, decodes to the SAME CoSignEvent (opaque payload byte-identical),
    /// and a tampered copy is rejected at verify (integrity is the frame's; the carrier only moved
    /// bytes). Mirrors [`codec_round_trips_and_rejects_tampering`] but over the real wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relayconn_frame_round_trips_over_real_relay() {
        let relay = MockRelay::run().await.expect("boot the in-process relay");
        let url = relay.url().await.to_string();

        let coordinator = Keys::generate();
        let holder = Keys::generate();

        let coord_conn =
            NostrRelayConn::new(coordinator.public_key(), vec![url.clone()]).expect("coord conn");
        let holder_conn =
            NostrRelayConn::new(holder.public_key(), vec![url.clone()]).expect("holder conn");
        // Warm BOTH persistent subscriptions before publishing: KIND_KIRBY_COSIGN is ephemeral,
        // so a subscriber must be live at publish time (a real relay does not store it).
        coord_conn.ensure_connected().await.expect("coordinator subscribes");
        holder_conn.ensure_connected().await.expect("holder subscribes");

        let cse = CoSignEvent {
            session_id: 42,
            from: GuardianId::try_from(2u16).unwrap(),
            round: kirby_custody::seam::ROUND_SHARE,
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let frame =
            encode_cosign_frame(AGENT, &cse, holder.public_key(), &coordinator).expect("encode");

        // KIND_KIRBY_COSIGN is ephemeral (a real relay does not store it), so it lands ONLY if the
        // holder's subscribe REQ is already live at publish time. Under parallel test load that REQ
        // can still be settling, so we publish-then-await in a SERIALIZED bounded retry rather than
        // racing a single send. A lost ephemeral publish queues nothing (no matching subscriber), and
        // we break on the first delivery -- so exactly one frame is received (routing/opacity proof
        // unchanged; a broken `#p=me` binding still routes NOTHING => every retry times out => red).
        let mut got = None;
        for _ in 0..20 {
            coord_conn
                .publish(frame.clone())
                .await
                .expect("publish the frame over the real relay");
            if let Ok(ev) = tokio::time::timeout(Duration::from_secs(2), holder_conn.next_event()).await
            {
                got = Some(ev.expect("next_event ok"));
                break;
            }
        }
        let got = got.expect("the frame must arrive at the #p-addressed holder within the retry budget");

        let (agent, decoded, sender) =
            decode_cosign_frame(&got).expect("decode the delivered frame");
        assert_eq!(agent, AGENT);
        assert_eq!(sender, coordinator.public_key(), "sender is the publisher's transport key");
        assert_eq!(decoded.session_id, cse.session_id);
        assert_eq!(decoded.from, cse.from);
        assert_eq!(decoded.round, cse.round);
        assert_eq!(
            decoded.payload, cse.payload,
            "opaque payload round-trips byte-for-byte over the wire"
        );

        // Tamper the DELIVERED frame -> verify must fail (the id no longer matches the content).
        let json = serde_json::to_string(&got).expect("serialize the delivered frame to json");
        let tampered = json.replace("cafebabe", "deadbeef");
        assert_ne!(json, tampered, "the tamper must actually change the frame json");
        let bad = Event::from_json(&tampered).expect("parse the tampered json back to an Event");
        assert!(
            decode_cosign_frame(&bad).is_err(),
            "a tampered frame must be rejected at verify (id/content mismatch)"
        );
        println!("RELAYCONN-ROUNDTRIP PASS: #p-addressed CoSignEvent frame round-trips over a real relay; opaque payload byte-identical; tamper rejected");
    }

    /// ★ TRANSPARENCY TOOTH: the SAME 2-of-3 ceremony the in-memory keystone proves
    /// ([`remote_relay_holder_in_a_2of3_quorum_produces_a_q_valid_signature`]), but with the one
    /// remote holder reached over `NostrRelayConn` + a REAL (in-process) nostr relay, produces a
    /// signature that verifies under Q -- byte-identical-VERIFYING to the in-process golden. Proves
    /// the production wire carries the ceremony faithfully: nostr-sdk really moves our opaque
    /// frames over a real relay, sync bridge + actor + holder-server included.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relay_remote_holder_2of3_over_real_relay_is_q_valid() {
        let ks = keyset();
        let kps = three_kps(&ks);

        let relay = MockRelay::run().await.expect("boot the in-process relay");
        let url = relay.url().await.to_string();

        let coordinator_keys = Keys::generate();
        let holder_keys = Keys::generate();

        // Warm both persistent subscriptions on THIS long-lived runtime BEFORE the ceremony
        // solicits (ephemeral cosign frames need a live subscriber at publish time). The relay-pool
        // tasks then live on this runtime, which outlives the whole ceremony.
        let holder_conn =
            NostrRelayConn::new(holder_keys.public_key(), vec![url.clone()]).expect("holder conn");
        holder_conn.ensure_connected().await.expect("holder subscribes");
        let coord_conn = NostrRelayConn::new(coordinator_keys.public_key(), vec![url.clone()])
            .expect("coord conn");
        coord_conn.ensure_connected().await.expect("coordinator subscribes");

        // Holder 2 "on another machine": its server loop on its own thread + runtime, driving the
        // (already-connected) holder_conn.
        let server2 = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let holder_keys_thread = holder_keys.clone();
        let server2_thread = Arc::clone(&server2);
        let holder_thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("holder rt");
            rt.block_on(async {
                let _ = run_holder_server(
                    &holder_keys_thread,
                    AGENT,
                    server2_thread,
                    holder_conn,
                    allow_all_coordinators(),
                    shutdown_rx,
                )
                .await;
            });
        });

        // The coordinator hub over its (already-connected) relay endpoint.
        let hub = CoordinatorRelayHub::start(
            coord_conn,
            coordinator_keys.clone(),
            AGENT,
            DEFAULT_WIRE_TIMEOUT,
        )
        .expect("start hub");

        // Holder 1 co-located; holder 2 remote over the REAL relay transport.
        let local = LocalHolder::new(kps[0].clone(), ks.pubkeys.clone());
        let remote_addr = format!("{}@{}", holder_keys.public_key().to_hex(), url);
        let remote_transport = hub.connect(&remote_addr).expect("connect remote holder");
        let remote = RemoteHolder::new(
            crate::quorum_signer::identifier_to_u16(kps[1].identifier()),
            remote_transport,
        );

        let holders: Vec<Box<dyn Holder>> = vec![Box::new(local), Box::new(remote)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build mixed signer");
        let q_bytes = qs.q_bytes().to_vec();

        // The ceremony is SYNC (RemoteHolder.recv blocks on the wire); drive it off the async
        // workers so the relay-pool tasks keep progressing on this runtime.
        let event =
            tokio::task::spawn_blocking(move || qs.sign_nostr_event(1, CREATED_AT, CONTENT))
                .await
                .expect("join the ceremony task")
                .expect("2-of-3 with a relay RemoteHolder over a real relay signs");

        let expect_id = nip01_event_id(&hex::encode(&q_bytes), CREATED_AT, 1, CONTENT);
        assert_eq!(event.id, hex::encode(expect_id), "id is the NIP-01 id under Q");
        assert_eq!(event.pubkey, hex::encode(&q_bytes));
        assert!(
            verifies_under_q(&event.sig, &expect_id, &ks.pubkeys),
            "the mixed local + relay-remote 2-of-3 aggregate must verify under Q (== in-process golden)"
        );

        let _ = shutdown_tx.send(());
        drop(hub);
        let _ = holder_thread.join();
        println!("RELAY-TRANSPARENCY PASS: a 2-of-3 with one RemoteHolder over NostrRelayConn + a real relay produced a Q-valid signature (== in-process golden)");
    }

    /// MULTI-RELAY FAILOVER: both sides reach TWO relays; kill one mid-run, and a `#p`-addressed
    /// frame still lands via the other. Proves the publish fan-out + inbound dedup give real
    /// redundancy -- the resilience half of the #103 lesson: a dead / half-open relay does not
    /// strand a frame when another relay carries it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relayconn_multi_relay_survives_one_relay_dying() {
        let relay1 = MockRelay::run().await.expect("relay 1");
        let relay2 = MockRelay::run().await.expect("relay 2");
        let url1 = relay1.url().await.to_string();
        let url2 = relay2.url().await.to_string();

        let coordinator = Keys::generate();
        let holder = Keys::generate();

        let coord_conn =
            NostrRelayConn::new(coordinator.public_key(), vec![url1.clone(), url2.clone()])
                .expect("coord conn");
        let holder_conn =
            NostrRelayConn::new(holder.public_key(), vec![url1.clone(), url2.clone()])
                .expect("holder conn");
        coord_conn.ensure_connected().await.expect("coordinator subscribes to both");
        holder_conn.ensure_connected().await.expect("holder subscribes to both");

        // Kill relay 1 mid-run. The connections stay reachable via relay 2 (fan-out publish +
        // dedup inbound), so the frame must still land.
        relay1.shutdown();

        let cse = CoSignEvent {
            session_id: 7,
            from: GuardianId::try_from(1u16).unwrap(),
            round: kirby_custody::seam::ROUND_SHARE,
            payload: vec![0xF0, 0x0D],
        };
        let frame =
            encode_cosign_frame(AGENT, &cse, holder.public_key(), &coordinator).expect("encode");
        // Fan-out: relay 1 is dead, but relay 2 accepts -> publish succeeds (non-empty success).
        // The frame is ephemeral, so it lands only if the holder's REQ is live on relay 2 at publish
        // time; under parallel test load that can still be settling, so serialized bounded
        // publish-then-await retry (pollution-free: a lost ephemeral queues nothing; break on land).
        // Honest-red-safe: `publish().expect` still bails if NO relay accepts (both dead => failover
        // truly broken => panic on the first iteration), and if delivery never lands the retry budget
        // is exhausted => panic -- neither masks a real failover break.
        let mut got = None;
        for _ in 0..20 {
            coord_conn
                .publish(frame.clone())
                .await
                .expect("publish still reaches a live relay after one died");
            if let Ok(ev) = tokio::time::timeout(Duration::from_secs(2), holder_conn.next_event()).await
            {
                got = Some(ev.expect("next_event ok"));
                break;
            }
        }
        let got = got.expect("the frame must arrive via the surviving relay within the retry budget");
        let (_agent, decoded, sender) = decode_cosign_frame(&got).expect("decode");
        assert_eq!(sender, coordinator.public_key());
        assert_eq!(
            decoded.payload, cse.payload,
            "the frame survived one relay dying, delivered via the other"
        );
        println!("RELAYCONN-FAILOVER PASS: with 2 relays and one killed mid-run, the #p-addressed frame still landed via the survivor");
    }

    // ---- #48: half-open RECONNECT proof. The failover tooth above proves multi-relay REDUNDANCY --
    // ---- (kill 1 of 2). These two prove the SINGLE-relay self-heal the #103 lesson demands: a  ----
    // ---- socket dies, the pool detects it, reconnects to the SAME url, and AUTO-RESUBSCRIBES    ----
    // ---- (InnerRelay::resubscribe) the stable-id REQ, so a frame published AFTER the drop still ----
    // ---- lands -- with NO manual re-subscribe. Tooth A is the clean-close case (fast, CI); B is ----
    // ---- the TRUE half-open (silently-dead socket, only the keepalive ping can surface it).     ----
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Parse the port out of a relay url like `ws://127.0.0.1:54321` (a trailing `/` is tolerated).
    /// We take the port from a live `MockRelay`'s own url rather than reserving one ourselves --
    /// `MockRelay::run` binds a guaranteed-free port (no bind-then-rebind TOCTOU race).
    fn port_of(relay_url: &str) -> u16 {
        relay_url
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("could not parse a port out of relay url {relay_url}"))
    }

    /// Run an in-process nostr relay on a FIXED port (so a shutdown+restart reuses the SAME url and
    /// a same-url reconnect can succeed). `MockRelay::run` picks a random port; it is a thin `Deref`
    /// over `LocalRelay`, so we build the `LocalRelay` directly with `RelayBuilder::port`. Retries
    /// the bind: a just-shutdown relay can hold the port briefly (listener teardown / lingering
    /// client sockets), so a fixed-port restart may need a few attempts.
    async fn run_fixed_port_relay(port: u16) -> LocalRelay {
        let mut last_err = None;
        for _ in 0..25 {
            let relay = LocalRelay::new(RelayBuilder::default().port(port));
            match relay.run().await {
                Ok(()) => return relay,
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        panic!("could not bind a fixed-port relay on {port}: {last_err:?}");
    }

    /// A tiny in-process TCP forwarder for the TRUE half-open test (Tooth B). It listens on a
    /// localhost port and, per accepted client connection, dials `upstream` and copies bytes both
    /// directions. `blackhole()` FREEZES every connection open AT THAT MOMENT -- the copy loop stops
    /// moving bytes but HOLDS all four socket halves open (never drops them), so the client still
    /// believes its socket is live: a genuine half-open (NOT a close -- a close is Tooth A's case).
    /// Connections accepted AFTER `blackhole()` (i.e. the pool's reconnect) forward normally, so the
    /// client can recover by reconnecting to the SAME url. This works because a `broadcast` send
    /// reaches only receivers that were subscribed at send time; a post-freeze connection subscribes
    /// later and so never receives the freeze signal.
    struct TcpBlackholeForwarder {
        local_port: u16,
        freeze_tx: tokio::sync::broadcast::Sender<()>,
        accept_task: tokio::task::JoinHandle<()>,
    }

    impl TcpBlackholeForwarder {
        async fn start(upstream_port: u16) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the forwarder listener");
            let local_port =
                listener.local_addr().expect("forwarder local addr").port();
            let (freeze_tx, _rx0) = tokio::sync::broadcast::channel::<()>(8);
            let accept_freeze = freeze_tx.clone();
            let accept_task = tokio::spawn(async move {
                loop {
                    let client = match listener.accept().await {
                        Ok((sock, _peer)) => sock,
                        Err(_) => break,
                    };
                    // Subscribe at ACCEPT time: a freeze sent before this connection existed is not
                    // delivered to it, so a reconnect (a fresh accept post-freeze) forwards normally.
                    let freeze_rx = accept_freeze.subscribe();
                    tokio::spawn(async move {
                        if let Ok(server) =
                            tokio::net::TcpStream::connect(("127.0.0.1", upstream_port)).await
                        {
                            pump_until_frozen(client, server, freeze_rx).await;
                        }
                    });
                }
            });
            Self { local_port, freeze_tx, accept_task }
        }

        fn url(&self) -> String {
            format!("ws://127.0.0.1:{}", self.local_port)
        }

        /// Freeze every currently-open connection into a half-open state: bytes stop, but the
        /// sockets stay OPEN so the client still sees a live socket.
        fn blackhole(&self) {
            let _ = self.freeze_tx.send(());
        }
    }

    impl Drop for TcpBlackholeForwarder {
        fn drop(&mut self) {
            self.accept_task.abort();
        }
    }

    /// Copy bytes both ways between `client` and `server` until either side closes OR a freeze
    /// signal arrives. On freeze we PARK holding all four socket halves (they stay owned by this
    /// frame and are never dropped) -- that is the true half-open: the sockets remain OPEN but no
    /// byte moves, so only the peer's keepalive ping can ever surface the death.
    async fn pump_until_frozen(
        client: tokio::net::TcpStream,
        server: tokio::net::TcpStream,
        mut freeze_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let (mut cr, mut cw) = client.into_split();
        let (mut sr, mut sw) = server.into_split();
        let mut cbuf = vec![0u8; 8192];
        let mut sbuf = vec![0u8; 8192];
        loop {
            tokio::select! {
                _ = freeze_rx.recv() => {
                    // HALF-OPEN: hold cr/cw/sr/sw open, move no bytes, park until the forwarder is
                    // torn down at test end. The peer's socket stays ESTABLISHED but silent.
                    std::future::pending::<()>().await;
                    return;
                }
                r = cr.read(&mut cbuf) => match r {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if sw.write_all(&cbuf[..n]).await.is_err() {
                            return;
                        }
                    }
                },
                r = sr.read(&mut sbuf) => match r {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if cw.write_all(&sbuf[..n]).await.is_err() {
                            return;
                        }
                    }
                },
            }
        }
    }

    /// TOOTH A (fast, CI-default): CLEAN-DROP + SAME-PORT RESTART -> reconnect + auto-resubscribe.
    /// A frame round-trips over a fixed-port relay; the relay is cleanly shut down and a NEW relay
    /// is started on the SAME port; a frame published AFTER the drop still lands at the holder. It
    /// lands ONLY because the pool reconnected to the same url AND auto-re-REQ'd the stable-id
    /// subscription (we never manually re-subscribe). This is the committed regression guard for
    /// the reconnect + resubscribe path; if either breaks, this test times out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relayconn_reconnects_and_resubscribes_after_clean_drop_same_port() {
        let relay = MockRelay::run().await.expect("boot the in-process relay");
        let url = relay.url().await.to_string();
        let port = port_of(&url);

        let coordinator = Keys::generate();
        let holder = Keys::generate();
        let coord_conn = Arc::new(
            NostrRelayConn::new(coordinator.public_key(), vec![url.clone()]).expect("coord conn"),
        );
        let holder_conn =
            NostrRelayConn::new(holder.public_key(), vec![url.clone()]).expect("holder conn");
        coord_conn.ensure_connected().await.expect("coordinator subscribes");
        holder_conn.ensure_connected().await.expect("holder subscribes");

        // Baseline: one frame round-trips over the live relay (the setup carries frames).
        let baseline = CoSignEvent {
            session_id: 1,
            from: GuardianId::try_from(1u16).unwrap(),
            round: kirby_custody::seam::ROUND_SHARE,
            payload: vec![0x01],
        };
        let bframe =
            encode_cosign_frame(AGENT, &baseline, holder.public_key(), &coordinator).expect("encode");
        // The frame is ephemeral (KIND_KIRBY_COSIGN, not stored), so it lands ONLY if the holder's
        // subscribe REQ is already live at the relay when the coordinator publishes. Under parallel
        // test load that REQ can still be settling, so we publish-then-await in a SERIALIZED bounded
        // retry (publish one frame, wait briefly, break on delivery) rather than racing a single send.
        // Serialized -- NOT a background publisher -- so we never over-publish: a lost ephemeral frame
        // queues nothing at the holder (the relay drops it with no matching subscriber), and once the
        // REQ is live exactly one frame lands and we break, so no duplicate baseline frame can leak
        // into the post-drop receive below.
        let mut got = None;
        for _ in 0..20 {
            coord_conn
                .publish(bframe.clone())
                .await
                .expect("publish the baseline frame");
            if let Ok(ev) = tokio::time::timeout(Duration::from_secs(2), holder_conn.next_event()).await
            {
                got = Some(ev.expect("next_event ok"));
                break;
            }
        }
        let got = got.expect("the baseline frame must arrive over the live relay within the retry budget");
        assert_eq!(
            decode_cosign_frame(&got).expect("decode baseline").1.payload,
            baseline.payload,
            "baseline frame round-trips before the drop"
        );

        // DROP: clean-close the relay (the client detects the close at once), then restart a NEW
        // relay on the SAME port so the same-url reconnect has a live socket to reach.
        relay.shutdown();
        let relay2 = run_fixed_port_relay(port).await;
        assert_eq!(
            relay2.url().await.to_string(),
            url,
            "the restarted relay must reuse the same url so reconnect targets it"
        );

        // POST-DROP frame. KIND_KIRBY_COSIGN is ephemeral (not stored), so it lands only if the
        // holder is subscribed at publish time -- i.e. AFTER it has reconnected + auto-resubscribed.
        // The publisher retries in the background (each attempt rides the current socket; publishes
        // before the holder resubscribes are simply lost) while we await the delivery once. The
        // default retry_interval is 10s, so allow several reconnect cycles under a 60s ceiling.
        let after = CoSignEvent {
            session_id: 2,
            from: GuardianId::try_from(2u16).unwrap(),
            round: kirby_custody::seam::ROUND_SHARE,
            payload: vec![0x02, 0x03],
        };
        let aframe =
            encode_cosign_frame(AGENT, &after, holder.public_key(), &coordinator).expect("encode");
        let pub_conn = Arc::clone(&coord_conn);
        let publisher = tokio::spawn(async move {
            loop {
                let _ = pub_conn.publish(aframe.clone()).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        let got2 = tokio::time::timeout(Duration::from_secs(60), holder_conn.next_event())
            .await
            .expect(
                "the post-drop frame must land after the pool reconnects + auto-resubscribes within 60s",
            )
            .expect("next_event ok");
        publisher.abort();
        assert_eq!(
            decode_cosign_frame(&got2).expect("decode post-drop").1.payload,
            after.payload,
            "the post-drop frame arrived only via reconnect + auto-resubscribe (no manual re-sub)"
        );
        // Keep the restarted relay alive until the assertion completes.
        drop(relay2);
        println!("RELAYCONN-RECONNECT PASS: after a clean drop + same-port restart, a post-drop #p-addressed frame landed via reconnect + auto-resubscribe (no manual re-subscribe)");
    }

    /// TOOTH B (the TRUE half-open, `#[ignore]`d -- ~110s wall floor, not fast CI). An in-process
    /// TCP forwarder sits between the clients and a fixed-port relay. Mid-run we BLACKHOLE it: both
    /// live connections freeze with their sockets held OPEN (a genuine half-open -- the client still
    /// thinks the socket is live). A clean close would be detected at once (that is Tooth A); a
    /// silently-dead socket is surfaced ONLY by the keepalive ping. So the post-blackhole frame
    /// lands ONLY because: the 55s ping went unanswered -> the NEXT ping tick returned
    /// `NotRepliedToPing` (hence a ~2x55s ~= 110s detection floor) -> the pool reconnected (a fresh
    /// TCP conn the forwarder forwards normally) -> it auto-re-REQ'd the stable-id subscription.
    /// This is the ONLY tooth that bites the keepalive-ping flag specifically.
    ///
    /// Run it explicitly (it is not in fast CI):
    ///   nix develop -c cargo test -p kirby-node relay_transport -- --ignored
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "true half-open detection has a ~110s wall floor (2x the hard-coded 55s PING_INTERVAL); run with -- --ignored"]
    async fn relayconn_half_open_surfaced_by_keepalive_ping_reconnects_and_resubscribes() {
        let relay = MockRelay::run().await.expect("boot the in-process relay");
        let relay_port = port_of(&relay.url().await.to_string());
        let forwarder = TcpBlackholeForwarder::start(relay_port).await;
        let url = forwarder.url();

        let coordinator = Keys::generate();
        let holder = Keys::generate();
        let coord_conn = Arc::new(
            NostrRelayConn::new(coordinator.public_key(), vec![url.clone()]).expect("coord conn"),
        );
        let holder_conn =
            NostrRelayConn::new(holder.public_key(), vec![url.clone()]).expect("holder conn");
        coord_conn.ensure_connected().await.expect("coordinator subscribes via the forwarder");
        holder_conn.ensure_connected().await.expect("holder subscribes via the forwarder");

        // Baseline: a frame round-trips THROUGH the forwarder (the forwarder path carries frames).
        let baseline = CoSignEvent {
            session_id: 10,
            from: GuardianId::try_from(1u16).unwrap(),
            round: kirby_custody::seam::ROUND_SHARE,
            payload: vec![0x10],
        };
        let bframe =
            encode_cosign_frame(AGENT, &baseline, holder.public_key(), &coordinator).expect("encode");
        // Same ephemeral publish-race as the other real-relay teeth: serialized bounded retry so a
        // publish before the holder's REQ is live at the relay doesn't strand the baseline (pollution-
        // free -- a lost ephemeral frame queues nothing, and we break on the first delivery).
        let mut got = None;
        for _ in 0..20 {
            coord_conn
                .publish(bframe.clone())
                .await
                .expect("publish the baseline frame via the forwarder");
            if let Ok(ev) = tokio::time::timeout(Duration::from_secs(2), holder_conn.next_event()).await
            {
                got = Some(ev.expect("next_event ok"));
                break;
            }
        }
        let got = got.expect("the baseline frame must arrive through the forwarder within the retry budget");
        assert_eq!(
            decode_cosign_frame(&got).expect("decode baseline").1.payload,
            baseline.payload,
            "baseline frame round-trips through the forwarder before the blackhole"
        );

        // BLACKHOLE: freeze both live connections into a half-open (sockets held OPEN, bytes stopped).
        // The client cannot tell the socket died; only the 55s keepalive ping will surface it.
        forwarder.blackhole();

        // POST-BLACKHOLE frame. It lands ONLY if the ping surfaced the half-open (~110s), the pool
        // reconnected (a fresh conn the forwarder forwards), and it auto-resubscribed. Retry publish
        // in the background; await the delivery once under a 180s ceiling (< the 300s idle_timeout).
        let after = CoSignEvent {
            session_id: 11,
            from: GuardianId::try_from(2u16).unwrap(),
            round: kirby_custody::seam::ROUND_SHARE,
            payload: vec![0x11, 0x12],
        };
        let aframe =
            encode_cosign_frame(AGENT, &after, holder.public_key(), &coordinator).expect("encode");
        let pub_conn = Arc::clone(&coord_conn);
        let publisher = tokio::spawn(async move {
            loop {
                let _ = pub_conn.publish(aframe.clone()).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
        let got2 = tokio::time::timeout(Duration::from_secs(180), holder_conn.next_event())
            .await
            .expect(
                "the post-blackhole frame must land after the keepalive ping surfaces the half-open (~110s) + reconnect + resubscribe within 180s",
            )
            .expect("next_event ok");
        publisher.abort();
        assert_eq!(
            decode_cosign_frame(&got2).expect("decode post-blackhole").1.payload,
            after.payload,
            "the post-blackhole frame arrived only via ping-driven reconnect + auto-resubscribe"
        );
        // Keep the relay + forwarder alive until the assertion completes.
        drop(forwarder);
        drop(relay);
        println!("RELAYCONN-HALFOPEN PASS: a blackholed (sockets-held-open) half-open socket was surfaced by the 55s keepalive ping; the pool reconnected + auto-resubscribed and a post-blackhole frame landed");
    }
}
