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
use crate::remote_holder::{HolderTransport, HolderTransportFactory, RemoteHolderServer};

/// The default per-wire timeout a [`RelayHolderTransport::recv`] waits for a reply before
/// returning `Err` (which the any-available-2-of-3 fallback treats as "this holder is
/// unreachable; try another subset"). A real cross-machine round-trip over a relay is well
/// under a second; this generous bound tolerates a slow relay without hanging a ceremony.
pub const DEFAULT_WIRE_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// The per-wire `recv` timeout handed to each transport.
    timeout: Duration,
    /// The actor thread handle (joined on drop so the thread does not outlive the hub).
    actor: Option<std::thread::JoinHandle<()>>,
}

impl CoordinatorRelayHub {
    /// Start a hub over `conn` (already connected + subscribed to `#p = coordinator pubkey` +
    /// the co-sign kind). Spawns the background actor thread (its own current-thread runtime).
    pub fn start<C: RelayConn>(
        conn: C,
        coordinator_keys: Keys,
        agent_id: impl Into<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let agent_id = agent_id.into();
        let (outbound_tx, outbound_rx) = unbounded_channel::<Event>();
        let routes: Arc<Mutex<HashMap<PublicKey, StdSender<CoSignEvent>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let actor_routes = Arc::clone(&routes);
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
                rt.block_on(coordinator_actor(conn, outbound_rx, actor_routes, actor_agent));
            })
            .context("spawn the co-sign coordinator actor thread")?;
        Ok(Self {
            coordinator_keys,
            agent_id,
            outbound_tx,
            routes,
            timeout,
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

/// The background actor: own the connection, publish outbound frames, demux inbound replies to
/// the registered per-holder reply channel by the reply's SENDER transport pubkey. Ends when
/// the outbound channel closes (hub + all transports dropped) or the connection errors.
async fn coordinator_actor<C: RelayConn>(
    conn: C,
    mut outbound_rx: UnboundedReceiver<Event>,
    routes: Arc<Mutex<HashMap<PublicKey, StdSender<CoSignEvent>>>>,
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
                            let route = routes
                                .lock()
                                .ok()
                                .and_then(|m| m.get(&sender).cloned());
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
}
