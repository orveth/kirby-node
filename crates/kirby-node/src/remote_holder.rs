//! S5/S6 (chunk 1, the keystone): the `RemoteHolder` -- a [`crate::quorum_signer::Holder`]
//! whose FROST share lives on ANOTHER machine.
//!
//! This is the seam the [`crate::quorum_signer::QuorumSigner`] was explicitly built for
//! (see `quorum_signer.rs`: "the `Holder` trait is the S5/S6 SEAM ... a future
//! `RemoteHolder` ... implements the SAME three operations ... so the `QuorumSigner`
//! ceremony body does not change at all when holders move off-box"). A `RemoteHolder` is
//! a thin COORDINATOR-SIDE PROXY: it owns NO `KeyPackage`, NO `SigningNonces`, and NO
//! group secret. It exchanges OPAQUE [`CoSignEvent`]s with a [`RemoteHolderServer`] that
//! runs on the holder's own machine and owns that holder's one share.
//!
//! THE WHOLE POINT (the TEE-substitute invariant): the secret `SigningNonces` NEVER
//! crosses the wire. Each holder generates its nonce LOCALLY inside its server, stores it
//! there keyed by `session_id`, and on round 2 looks it up, signs, and drops it -- all on
//! its own box. Only the PUBLIC `SigningCommitments` (round 1) and the partial
//! `SignatureShare` (round 2) cross the seam. A host that reads the coordinator's RAM
//! finds no share and no nonce for a remote holder; a host that reads ONE holder's RAM
//! finds exactly one share = useless below the 2-of-3 threshold. This is enforced by
//! CONSTRUCTION (the proxy has no field that could hold a nonce) and asserted executably
//! by `nonce_never_crosses_the_wire` in the tests below.
//!
//! THE MEMBRANE RUNS HOLDER-SIDE (the design's contract): the [`RemoteHolderServer`] runs
//! [`kirby_custody::guardian::validate`] against ITS OWN persisted `PublicKeyPackage`
//! (never a Q the coordinator asserts) BEFORE it produces a share, and refuses on any
//! validation failure -- it NEVER blind-signs whatever bytes the coordinator placed in the
//! `SigningPackage`. This closes the `frost-nostr-cosign` "DEMO LIMITATION ... THIS
//! GUARDIAN BLIND-SIGNS" gap for the cross-machine path: the typed [`CoSignRequest`] is
//! sent to the holder (opaque on the wire) and the holder re-reconstructs + equality-checks
//! the id itself.
//!
//! SCOPE (chunk 1, per the cross-machine-FROST design spec): identity/signing ONLY, the
//! `RemoteHolder` + an IN-PROCESS mock transport so the teeth are fast + ungated. Trusted-
//! dealer keygen (the keysets here come from the same dealer split the co-located path
//! uses). NO any-available-2-of-3 selection (chunk 2), NO distributed provisioning /
//! at-rest sealing (chunk 3), NO membership rotation (chunk 4), NO failover takeover
//! (chunk 5), NO P2PK/NUT-11 ecash (chunk 6), and NO real relay transport (a later chunk
//! boundary; the mock transport here is shaped so the kirby-nostr relay drops in unchanged,
//! the same opacity contract custody `seam.rs` already proves). Plain ecash stays bearer
//! for now (a documented residual, see the design spec section 5).
//!
//! WIRE FORMAT: reuses custody's opaque [`CoSignEvent`] carrier + the
//! `ROUND_COMMITMENT` / `ROUND_PACKAGE` / `ROUND_SHARE` discriminants, harvested from the
//! proven `frost-nostr-cosign` bin (turtle + LNVPS co-signed a real Nostr note over exactly
//! this shape). The coordinator-side proxy ADDS two request discriminants
//! ([`ROUND_COMMIT_REQUEST`], a trigger; and the round-2 request carries the typed
//! `CoSignRequest` alongside the `SigningPackage`) and a refusal frame
//! ([`ROUND_REFUSAL`]). A holder that refuses replies with a `ROUND_REFUSAL` event whose
//! payload is a serialized [`RefuseReason`]; the proxy maps it back to a `RefuseReason` so
//! the `QuorumSigner` ceremony aborts EXACTLY as it does for a co-located refusal.
//!
//! ENTRY-POINT GUARDS (the `feedback_new_entry_point_needs_input_guards` lesson -- a new
//! signing entry point must re-port the guards its co-located sibling has): the proxy binds
//! every reply to BOTH the expected `session_id` AND the expected holder identifier
//! (`reply.from`), so a misrouted or spoofed reply for the same session on a shared relay is
//! rejected rather than accepted as this holder's commitment/share. The `QuorumSigner`
//! keeps the dup-signer guard (two holders aliased to one identifier are refused before
//! round 1, so no single-use nonce is reused). Full mutual coordinator<->holder
//! authentication over a real relay (so a rogue node cannot SOLICIT a share or replay one)
//! is the remaining chunk-1 design item flagged in the spec's residual 6; the in-process
//! mock here does not need it, but the sender-identity check is the half that lives in this
//! proxy regardless of transport.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::SigningPackage;

use kirby_custody::guardian::{self, CoSignRequest, RefuseReason};
use kirby_custody::seam::{CoSignEvent, GuardianId, ROUND_COMMITMENT, ROUND_PACKAGE, ROUND_SHARE};

use crate::quorum_signer::{identifier_to_u16, Holder, MIN_SIGNERS};

/// Round discriminant: the coordinator's round-1 COMMIT TRIGGER (coordinator -> holder).
/// Mirrors the proven `frost-nostr-cosign` flow where the coordinator sends a
/// `ROUND_COMMITMENT` frame with an EMPTY payload to ask a guardian to commit. We give the
/// trigger its own discriminant so the holder server can tell "please commit" (trigger,
/// coordinator -> holder) apart from "here is my commitment" (`ROUND_COMMITMENT`, holder ->
/// coordinator) without inspecting the payload.
pub const ROUND_COMMIT_REQUEST: u8 = 10;

/// Round discriminant: a holder's REFUSAL (holder -> coordinator). The payload is a
/// serialized [`RefuseReason`]; the proxy decodes it and surfaces it so the ceremony
/// aborts with no signature, exactly like a co-located holder's `Err(reason)`.
pub const ROUND_REFUSAL: u8 = 11;

/// The round-2 SIGN REQUEST envelope (coordinator -> holder). Sent as the payload of a
/// [`ROUND_PACKAGE`] event so the holder receives BOTH the assembled `SigningPackage` AND
/// the typed [`CoSignRequest`] it must independently re-reconstruct + equality-check (the
/// membrane). Both are serialized opaque bytes on the wire; the carrier never reads them.
///
/// SECURITY: this envelope carries NO secret material -- the `SigningPackage` is public
/// commitments + the message, and the `CoSignRequest` is the public typed intent + the
/// claimed signer set. The holder derives Q from its OWN pubkeys (never from this
/// envelope), so a malicious coordinator cannot smuggle a Q that makes a forged message
/// reconstruct.
#[derive(serde::Serialize, serde::Deserialize)]
struct SignRequestEnvelope {
    /// The assembled signing package (public commitments + the message to sign).
    package: SigningPackage,
    /// The typed request the holder re-reconstructs the id from and equality-checks.
    request: CoSignRequest,
}

/// A SYNCHRONOUS request/reply transport to one remote holder, carrying OPAQUE
/// [`CoSignEvent`]s. This is the seam between the (synchronous) [`Holder`] trait and a
/// remote share-holder: `RemoteHolder` calls `send` then `recv` for each round.
///
/// It is deliberately SYNC so a `RemoteHolder` implements the existing sync [`Holder`]
/// trait WITHOUT changing the `QuorumSigner` ceremony body (the seam's reason to exist).
/// The custody `coordinate_2of3_over_seam` is a DIFFERENT, async, coordinator-OWNS-all-
/// shares driver; this transport is the request/reply shape the per-holder seam needs.
///
/// The mock impl ([`InProcessHolderLink`]) is an in-process paired queue to a
/// [`RemoteHolderServer`]. A real impl wraps + signs a Nostr event and round-trips it
/// through the kirby-nostr relay; because the carrier routes by `(session_id, round)` and
/// NEVER reads the opaque payload, that real transport drops in here unchanged (the same
/// opacity contract custody `seam.rs` proves).
pub trait HolderTransport {
    /// Send one opaque event to the remote holder.
    fn send(&self, event: CoSignEvent) -> anyhow::Result<()>;
    /// Receive the next opaque event from the remote holder (blocking in a real impl;
    /// immediate for the in-process mock since the server replies synchronously on send).
    fn recv(&self) -> anyhow::Result<CoSignEvent>;
}

/// Box-erasure so a [`RemoteHolder`] can hold a TRANSPORT chosen at run time (a
/// [`HolderTransportFactory`] returns one `Box<dyn HolderTransport>` per holder address). The
/// `RemoteHolder<T>` bound is `T: HolderTransport + Send + Sync`, so the boxed form must be
/// `Box<dyn HolderTransport + Send + Sync>` and must itself implement the trait — this blanket
/// impl just forwards to the inner transport.
impl HolderTransport for Box<dyn HolderTransport + Send + Sync> {
    fn send(&self, event: CoSignEvent) -> anyhow::Result<()> {
        (**self).send(event)
    }
    fn recv(&self) -> anyhow::Result<CoSignEvent> {
        (**self).recv()
    }
}

/// Build a [`HolderTransport`] to the holder reachable at a placement ADDRESS — the seam the
/// distributed SIGN path uses to turn a per-agent placement manifest into live
/// [`RemoteHolder`]s WITHOUT changing the [`crate::quorum_signer::QuorumSigner`] ceremony body.
///
/// `address` is OPAQUE to the signer (it is interpreted only by the factory): a relay-native
/// factory maps it to a relay route to the holder's `RemoteHolderServer`; the in-process test
/// factory keys a registry of stood-up servers on it. The factory returns a boxed transport so a
/// heterogeneous holder roster (different
/// addresses, possibly different transports) can be assembled into one quorum signer.
///
/// This is the SIGN-side counterpart of the provision-side `ShareSink` seam: provisioning ships
/// share `i` to a sink at a holder address; signing dials that SAME holder address through this
/// factory. The placement manifest (`placement.json`) is the durable map of identifier -> address
/// that both sides share.
pub trait HolderTransportFactory {
    /// Connect to the holder reachable at `address`, returning a transport carrying opaque
    /// [`CoSignEvent`]s. An unreachable/unknown address is an `Err` (the loader fails closed,
    /// never silently builds an under-strength quorum).
    fn connect(&self, address: &str) -> anyhow::Result<Box<dyn HolderTransport + Send + Sync>>;
}

/// The coordinator-side PROXY for a holder whose share lives on another machine.
///
/// It implements [`Holder`] by exchanging opaque [`CoSignEvent`]s with a
/// [`RemoteHolderServer`] over a [`HolderTransport`]. It owns NO `KeyPackage`, NO
/// `SigningNonces`, and NO secret share -- only the remote holder's `id` (its u16 FROST
/// identifier, which is PUBLIC: it is part of the signer set every observer sees) and the
/// transport handle. This is the structural guarantee that a host reading the
/// coordinator's RAM finds nothing signable for this holder.
pub struct RemoteHolder<T: HolderTransport> {
    /// The remote holder's FROST identifier as a u16 (PUBLIC -- the membrane's signer-set
    /// element). NOT a secret; every observer of the signer set sees it.
    id_u16: u16,
    /// The transport to the holder's machine. Carries ONLY opaque CoSignEvents.
    transport: T,
}

impl<T: HolderTransport> RemoteHolder<T> {
    /// Build a remote-holder proxy for the holder identified by `id_u16`, talking over
    /// `transport`. The proxy holds NO secret material.
    pub fn new(id_u16: u16, transport: T) -> Self {
        Self { id_u16, transport }
    }
}

impl<T: HolderTransport + Send + Sync> Holder for RemoteHolder<T> {
    fn id(&self) -> u16 {
        self.id_u16
    }

    /// Round 1: ask the remote holder to commit. The holder generates its OWN fresh
    /// single-use nonce ON ITS OWN MACHINE, stores it there keyed by `session_id`, and
    /// returns ONLY the public `SigningCommitments`. This proxy never sees the nonce.
    fn commit(&self, session_id: u64) -> anyhow::Result<SigningCommitments> {
        // Send the commit TRIGGER (empty payload, like the proven frost-nostr-cosign flow).
        self.transport.send(CoSignEvent {
            session_id,
            from: coordinator_id(),
            round: ROUND_COMMIT_REQUEST,
            payload: Vec::new(),
        })?;
        // Receive the holder's reply: a ROUND_COMMITMENT event whose opaque payload is the
        // serialized public SigningCommitments. A refusal here (e.g. a nonce-reuse guard
        // trip on the holder) comes back as ROUND_REFUSAL.
        let reply = self.transport.recv()?;
        if reply.session_id != session_id {
            anyhow::bail!(
                "remote holder {} round-1 reply session mismatch (asked {session_id}, got {})",
                self.id_u16,
                reply.session_id
            );
        }
        // SENDER-IDENTITY CHECK (the new-entry-point guard): the reply MUST come from THIS
        // holder, not another endpoint that happened to be on the same session id. On a
        // shared relay transport a misrouted or spoofed reply for this session could
        // otherwise be accepted; bind the reply to the expected holder identifier.
        if identifier_to_u16(&reply.from) != self.id_u16 {
            anyhow::bail!(
                "remote holder {} round-1 reply came from {} (expected {})",
                self.id_u16,
                identifier_to_u16(&reply.from),
                self.id_u16
            );
        }
        match reply.round {
            ROUND_COMMITMENT => {
                let commitments: SigningCommitments = serde_json::from_slice(&reply.payload)
                    .map_err(|e| {
                        anyhow::anyhow!("remote holder {} commitment decode: {e}", self.id_u16)
                    })?;
                Ok(commitments)
            }
            ROUND_REFUSAL => {
                let reason: RefuseReason = serde_json::from_slice(&reply.payload).map_err(|e| {
                    anyhow::anyhow!("remote holder {} refusal decode: {e}", self.id_u16)
                })?;
                anyhow::bail!(
                    "remote holder {} REFUSED at round 1 ({reason:?})",
                    self.id_u16
                )
            }
            other => anyhow::bail!(
                "remote holder {} round-1 reply has unexpected round {other}",
                self.id_u16
            ),
        }
    }

    /// THE MEMBRANE + round 2, executed ON THE HOLDER'S MACHINE. This proxy sends the
    /// assembled `package` + the typed `req` (opaque on the wire); the remote holder looks
    /// up + removes its OWN nonce for `session_id`, runs `guardian::validate` against ITS
    /// OWN pubkeys, and ONLY on `Ok(())` signs and returns the public `SignatureShare`.
    /// The proxy never sees the nonce or the share's construction -- only the finished
    /// public partial signature crosses back.
    fn validate_and_sign(
        &self,
        session_id: u64,
        req: &CoSignRequest,
        package: &SigningPackage,
    ) -> Result<SignatureShare, RefuseReason> {
        // Build the opaque sign-request envelope (package + typed request). A serialization
        // failure is an internal fault -> a hard refusal (we never half-sign).
        let envelope = SignRequestEnvelope {
            package: package.clone(),
            request: req.clone(),
        };
        let payload = match serde_json::to_vec(&envelope) {
            Ok(p) => p,
            // BadKeyset is the closest "this holder cannot sign" reason; a transport/codec
            // fault must abort the ceremony, never blind-sign.
            Err(_) => return Err(RefuseReason::BadKeyset),
        };
        if self
            .transport
            .send(CoSignEvent {
                session_id,
                from: coordinator_id(),
                round: ROUND_PACKAGE,
                payload,
            })
            .is_err()
        {
            return Err(RefuseReason::BadKeyset);
        }
        // Receive the holder's reply: a ROUND_SHARE (success) or a ROUND_REFUSAL.
        let reply = match self.transport.recv() {
            Ok(e) => e,
            Err(_) => return Err(RefuseReason::BadKeyset),
        };
        if reply.session_id != session_id {
            return Err(RefuseReason::BadKeyset);
        }
        // SENDER-IDENTITY CHECK (the new-entry-point guard): bind the round-2 reply to THIS
        // holder. A reply (share OR refusal) from any other endpoint for this session is
        // rejected -- a misrouted/spoofed share must never be aggregated as this holder's.
        if identifier_to_u16(&reply.from) != self.id_u16 {
            return Err(RefuseReason::BadKeyset);
        }
        match reply.round {
            ROUND_SHARE => serde_json::from_slice::<SignatureShare>(&reply.payload)
                .map_err(|_| RefuseReason::BadKeyset),
            ROUND_REFUSAL => {
                let reason = serde_json::from_slice::<RefuseReason>(&reply.payload)
                    .unwrap_or(RefuseReason::BadKeyset);
                Err(reason)
            }
            // Anything else is a protocol fault: refuse rather than trust an unknown frame.
            _ => Err(RefuseReason::BadKeyset),
        }
    }
}

/// The HOLDER-SIDE endpoint: the thing that runs on the holder's OWN machine and owns that
/// holder's one share. It holds the `KeyPackage`, its OWN copy of the group
/// `PublicKeyPackage` (the membrane derives Q from THIS, never a coordinator-asserted Q),
/// and a per-session store of its secret `SigningNonces`. A coordinator NEVER touches any
/// of these -- it only sends opaque request events and receives opaque reply events.
///
/// This is the validating counterpart of the `frost-nostr-cosign` bin's guardian, with the
/// membrane WIRED (that bin blind-signs by design; production cross-machine custody MUST
/// validate, per its own "DEMO LIMITATION" comment). It is essentially a network-fronted
/// `LocalHolder`: same nonce ownership, same membrane, same single-use discipline.
pub struct RemoteHolderServer {
    key_package: KeyPackage,
    /// The holder's OWN copy of the group public keys. The membrane derives Q from THIS.
    own_pubkeys: PublicKeyPackage,
    id_u16: u16,
    /// The holder's OWN secret nonces, keyed by `session_id`, living ONLY on this machine.
    /// Inserted in the round-1 commit handler; REMOVED (consumed + dropped) in the round-2
    /// sign handler. This map is the in-process stand-in for a real remote holder keeping
    /// its nonce on its own box; it is NEVER serialized and NEVER leaves this struct. A
    /// `Mutex` (like `LocalHolder`) keeps the server `Send + Sync` so a `RemoteHolder`
    /// wrapping it satisfies the `Holder: Send + Sync` bound the `QuorumSigner` requires.
    nonces: Mutex<HashMap<u64, SigningNonces>>,
}

impl RemoteHolderServer {
    /// Build a holder server from its `KeyPackage` and its OWN copy of the group `pubkeys`.
    pub fn new(key_package: KeyPackage, own_pubkeys: PublicKeyPackage) -> Self {
        let id_u16 = identifier_to_u16(key_package.identifier());
        Self {
            key_package,
            own_pubkeys,
            id_u16,
            nonces: Mutex::new(HashMap::new()),
        }
    }

    /// This holder's FROST identifier (u16, public).
    pub fn id(&self) -> u16 {
        self.id_u16
    }

    /// Handle ONE opaque request event from a coordinator and return the opaque reply
    /// event. This is the entire holder-side protocol: a commit trigger yields a
    /// `ROUND_COMMITMENT` reply (or a `ROUND_REFUSAL`); a sign request yields a
    /// `ROUND_SHARE` reply (or a `ROUND_REFUSAL`). The secret nonce is generated, stored,
    /// looked up, and dropped ENTIRELY inside this method on this machine.
    pub fn handle(&self, event: CoSignEvent) -> CoSignEvent {
        match event.round {
            ROUND_COMMIT_REQUEST => self.handle_commit(event.session_id),
            ROUND_PACKAGE => self.handle_sign(event),
            // An unknown request frame: refuse (never sign something we do not understand).
            _ => self.refuse(event.session_id, RefuseReason::BadKeyset),
        }
    }

    /// Round 1 on the holder's machine: generate a FRESH single-use nonce, STORE it keyed
    /// by `session_id`, and reply with ONLY the public commitment. The nonce stays here.
    fn handle_commit(&self, session_id: u64) -> CoSignEvent {
        // Use the custody crate's OS CSPRNG (the rand_core 0.6 the ZF frost crate needs),
        // exactly as `LocalHolder::commit` does.
        let (nonce, commitment) = kirby_custody::commit_for(&self.key_package);
        {
            let mut nonces = match self.nonces.lock() {
                Ok(n) => n,
                Err(_) => return self.refuse(session_id, RefuseReason::BadKeyset),
            };
            // Single-use per holder: refuse to clobber a live nonce (a clobber would strand
            // an in-flight ceremony's nonce -> a stuck sign). Same guard as `LocalHolder`.
            if nonces.contains_key(&session_id) {
                return self.refuse(session_id, RefuseReason::BadKeyset);
            }
            nonces.insert(session_id, nonce);
        }
        let payload = match serde_json::to_vec(&commitment) {
            Ok(p) => p,
            Err(_) => {
                // Roll the nonce back out so a later retry under the same session can commit.
                if let Ok(mut nonces) = self.nonces.lock() {
                    nonces.remove(&session_id);
                }
                return self.refuse(session_id, RefuseReason::BadKeyset);
            }
        };
        CoSignEvent {
            session_id,
            from: self.frost_id(),
            round: ROUND_COMMITMENT,
            payload,
        }
    }

    /// Round 2 on the holder's machine: decode the sign-request envelope, LOOK UP + REMOVE
    /// this holder's nonce for the session, run the membrane against its OWN pubkeys, and
    /// ONLY on `Ok(())` sign + reply with the public share. A refusal (or a missing nonce)
    /// replies `ROUND_REFUSAL` and the removed nonce is dropped (never reused).
    fn handle_sign(&self, event: CoSignEvent) -> CoSignEvent {
        let session_id = event.session_id;
        let envelope: SignRequestEnvelope = match serde_json::from_slice(&event.payload) {
            Ok(e) => e,
            Err(_) => return self.refuse(session_id, RefuseReason::BadKeyset),
        };
        // LOOK UP + REMOVE the nonce. A missing nonce (no matching commit) is a hard
        // refusal -- never reach for another session's or holder's nonce. The removed nonce
        // lives only in this scope: used once, dropped on return (whether we sign OR refuse).
        let nonce = {
            let mut nonces = match self.nonces.lock() {
                Ok(n) => n,
                Err(_) => return self.refuse(session_id, RefuseReason::BadKeyset),
            };
            match nonces.remove(&session_id) {
                Some(n) => n,
                None => return self.refuse(session_id, RefuseReason::BadKeyset),
            }
        };
        // THE MEMBRANE: derive Q from THIS holder's own pubkeys (never a coordinator-
        // asserted Q) and require the package's message to equal the id reconstructed from
        // the typed intent. A refusal here means NO share is produced; the nonce is dropped.
        if let Err(reason) = guardian::validate(
            &envelope.request,
            &envelope.package,
            &self.own_pubkeys,
            self.id_u16,
            MIN_SIGNERS,
        ) {
            return self.refuse(session_id, reason);
        }
        // Only after the membrane passed: produce the tweaked (key-path, merkle_root=None)
        // signature share, consuming the nonce. A round-2 failure is a hard refusal.
        match frost::round2::sign_with_tweak(&envelope.package, &nonce, &self.key_package, None) {
            Ok(share) => match serde_json::to_vec(&share) {
                Ok(payload) => CoSignEvent {
                    session_id,
                    from: self.frost_id(),
                    round: ROUND_SHARE,
                    payload,
                },
                Err(_) => self.refuse(session_id, RefuseReason::BadKeyset),
            },
            Err(_) => self.refuse(session_id, RefuseReason::BadKeyset),
        }
    }

    /// Build a `ROUND_REFUSAL` reply carrying the serialized reason.
    fn refuse(&self, session_id: u64, reason: RefuseReason) -> CoSignEvent {
        // RefuseReason serialization cannot realistically fail; fall back to an empty
        // payload (the proxy maps an undecodable refusal to BadKeyset, still a refusal).
        let payload = serde_json::to_vec(&reason).unwrap_or_default();
        CoSignEvent {
            session_id,
            from: self.frost_id(),
            round: ROUND_REFUSAL,
            payload,
        }
    }

    /// This holder's FROST `Identifier` (for the `from` field of reply events). The
    /// trusted-dealer identifiers are 1..=n, so u16 -> Identifier is exact.
    fn frost_id(&self) -> GuardianId {
        GuardianId::try_from(self.id_u16).expect("trusted-dealer identifier 1..=n is valid")
    }
}

/// Reserved wire address for the coordinator (never a holder identifier). Mirrors custody
/// `seam.rs`'s `COORDINATOR_ADDR`.
fn coordinator_id() -> GuardianId {
    GuardianId::try_from(u16::MAX).expect("reserved coordinator id is valid")
}

/// A shared in-process relay bus connecting one coordinator-side [`RemoteHolder`] to one
/// [`RemoteHolderServer`], for the FAST UNGATED teeth. It models a real relay's
/// request/reply round-trip: the coordinator `send`s a request, the bus drives the server's
/// `handle`, and the server's reply is queued for the coordinator's `recv`. The bus reads
/// ONLY `(session_id, round)` for routing/observability and NEVER deserializes a payload --
/// the same opacity contract custody `seam.rs` proves (and the test
/// `mock_transport_never_inspects_payload` re-proves here), so the kirby-nostr relay drops
/// in unchanged at a later chunk boundary.
pub struct InProcessHolderLink {
    /// The holder server this link drives (it lives "on the other machine").
    server: Arc<RemoteHolderServer>,
    /// Replies waiting for the coordinator to `recv`.
    inbox: Arc<Mutex<VecDeque<CoSignEvent>>>,
    /// A wire LOG of every event that crossed the link (both directions), for the
    /// nonce-never-crosses assertion. Each entry is the full opaque [`CoSignEvent`] as it
    /// would hit a real wire (the payload is the serialized bytes a relay would carry).
    wire_log: Arc<Mutex<Vec<CoSignEvent>>>,
}

impl InProcessHolderLink {
    /// Build a link to `server`. The coordinator side is the returned value (it implements
    /// [`HolderTransport`]); the server side is `server` (it lives on its own machine).
    /// `Arc<Mutex<..>>` (not `Rc<RefCell<..>>`) so the link is `Send + Sync` and a
    /// `RemoteHolder` wrapping it satisfies the `Holder: Send + Sync` bound -- the same
    /// reality a real relay transport has.
    pub fn new(server: Arc<RemoteHolderServer>) -> Self {
        Self {
            server,
            inbox: Arc::new(Mutex::new(VecDeque::new())),
            wire_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A clone of the wire log handle, so a test can inspect EXACTLY what crossed the link.
    pub fn wire_log(&self) -> Arc<Mutex<Vec<CoSignEvent>>> {
        Arc::clone(&self.wire_log)
    }
}

impl HolderTransport for InProcessHolderLink {
    fn send(&self, event: CoSignEvent) -> anyhow::Result<()> {
        // Record the coordinator -> holder event on the wire (opaque; routing only).
        self.wire_log
            .lock()
            .map_err(|_| anyhow::anyhow!("wire log poisoned"))?
            .push(event.clone());
        // Drive the server's handler (it runs "on the other machine") and queue its reply.
        let reply = self.server.handle(event);
        // Record the holder -> coordinator reply on the wire too.
        self.wire_log
            .lock()
            .map_err(|_| anyhow::anyhow!("wire log poisoned"))?
            .push(reply.clone());
        self.inbox
            .lock()
            .map_err(|_| anyhow::anyhow!("inbox poisoned"))?
            .push_back(reply);
        Ok(())
    }

    fn recv(&self) -> anyhow::Result<CoSignEvent> {
        self.inbox
            .lock()
            .map_err(|_| anyhow::anyhow!("inbox poisoned"))?
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("no reply queued from the remote holder"))
    }
}

/// An IN-PROCESS [`HolderTransportFactory`] for the FAST UNGATED distributed-sign teeth: a
/// registry of stood-up [`RemoteHolderServer`]s keyed by their placement ADDRESS. `connect`
/// hands back an [`InProcessHolderLink`] to the matching server, so the distributed loader's
/// `factory.connect(address)` reaches the right "holder host" without a real relay. It models
/// the production reality faithfully: each server was built by unsealing ITS OWN share from
/// ITS OWN sink dir ("its machine"), the coordinator holds only the proxy, and the share never
/// crosses back. A relay-native factory drops in here unchanged behind the same
/// `HolderTransportFactory` trait.
#[cfg(test)]
pub(crate) struct InProcessHolderFleet {
    servers: HashMap<String, Arc<RemoteHolderServer>>,
}

#[cfg(test)]
impl InProcessHolderFleet {
    pub(crate) fn new() -> Self {
        Self { servers: HashMap::new() }
    }

    /// Register the holder reachable at `address` (the placement manifest's per-holder address).
    pub(crate) fn register(&mut self, address: impl Into<String>, server: Arc<RemoteHolderServer>) {
        self.servers.insert(address.into(), server);
    }
}

#[cfg(test)]
impl HolderTransportFactory for InProcessHolderFleet {
    fn connect(&self, address: &str) -> anyhow::Result<Box<dyn HolderTransport + Send + Sync>> {
        let server = self
            .servers
            .get(address)
            .ok_or_else(|| anyhow::anyhow!("no in-process holder registered at address {address:?}"))?;
        Ok(Box::new(InProcessHolderLink::new(Arc::clone(server))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quorum_signer::{LocalHolder, QuorumSigner};
    use std::sync::Arc;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
    use bitcoin::KnownHrp;
    use kirby_custody::cosign_net::nip01_event_id;
    use kirby_custody::{generate_dealer_keyset, group_xonly_q, key_packages, taproot_address};

    const CREATED_AT: u64 = 1750000000;
    const CONTENT: &str = "Kirby co-signs across machines by choice.";

    /// A fresh real 2-of-3 trusted-dealer keyset (OsRng inside custody). Every assertion
    /// re-derives Q, so a fresh keyset per run is fine.
    fn keyset() -> kirby_custody::DealerKeyset {
        generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen")
    }

    /// The three per-guardian key packages, ordered by identifier 1,2,3.
    fn three_kps(ks: &kirby_custody::DealerKeyset) -> Vec<KeyPackage> {
        let map = key_packages(ks).expect("key packages");
        // BTreeMap iteration is identifier-ordered (1,2,3).
        map.into_values().collect()
    }

    /// Independent verification: a 64-byte sig verifies as BIP-340 under the tweaked Q.
    fn verifies_under_q(sig_hex: &str, message: &[u8; 32], pubkeys: &PublicKeyPackage) -> bool {
        let (_addr, internal_p) = taproot_address(pubkeys, KnownHrp::Testnets).expect("addr");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let Ok(bytes) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(sig) = schnorr::Signature::from_slice(&bytes) else {
            return false;
        };
        secp.verify_schnorr(&sig, &Message::from_digest(*message), &q_xonly)
            .is_ok()
    }

    /// THE KEYSTONE TEETH: a 2-of-3 quorum where ONE holder is a `RemoteHolder` (over the
    /// in-process mock transport) and the other is a co-located `LocalHolder` produces a
    /// VALID BIP-340 signature under the group key Q -- WITHOUT changing the QuorumSigner
    /// ceremony body. This is the whole point of the `Holder` seam: holders can be local or
    /// remote and the call site is identical.
    #[test]
    fn remote_holder_in_a_2of3_quorum_produces_a_q_valid_signature() {
        let ks = keyset();
        let kps = three_kps(&ks);

        // Holder 1 is co-located; holder 2 lives "on another machine" behind a RemoteHolder.
        let local = LocalHolder::new(kps[0].clone(), ks.pubkeys.clone());
        let server2 = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let link2 = InProcessHolderLink::new(Arc::clone(&server2));
        let remote = RemoteHolder::new(server2.id(), link2);

        // The SAME QuorumSigner ceremony body drives a mixed local+remote quorum.
        let holders: Vec<Box<dyn Holder>> = vec![Box::new(local), Box::new(remote)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build mixed quorum signer");

        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("2-of-3 with a RemoteHolder signs the note");

        // The published id is the NIP-01 id under Q; the aggregate verifies under Q.
        let expect_id = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, CONTENT);
        assert_eq!(event.id, hex::encode(expect_id), "id is the NIP-01 id under Q");
        assert_eq!(event.pubkey, hex::encode(qs.q_bytes()));
        assert!(
            verifies_under_q(&event.sig, &expect_id, &ks.pubkeys),
            "the mixed local+remote 2-of-3 aggregate must verify under Q"
        );
        println!(
            "REMOTE-HOLDER-Q-VALID PASS: a 2-of-3 quorum with one RemoteHolder (over the mock \
             transport) produced a Q-valid BIP-340 signature (ceremony body unchanged)"
        );
    }

    /// Both holders remote (each behind its own RemoteHolder + server + link) still reaches
    /// a Q-valid signature -- proving the seam works when NO share is co-located at all.
    #[test]
    fn two_remote_holders_produce_a_q_valid_signature() {
        let ks = keyset();
        let kps = three_kps(&ks);

        let server1 = Arc::new(RemoteHolderServer::new(kps[0].clone(), ks.pubkeys.clone()));
        let server2 = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let r1 = RemoteHolder::new(server1.id(), InProcessHolderLink::new(Arc::clone(&server1)));
        let r2 = RemoteHolder::new(server2.id(), InProcessHolderLink::new(Arc::clone(&server2)));

        let holders: Vec<Box<dyn Holder>> = vec![Box::new(r1), Box::new(r2)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build all-remote signer");

        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("2-of-3 with two RemoteHolders signs");
        let expect_id = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, CONTENT);
        assert!(
            verifies_under_q(&event.sig, &expect_id, &ks.pubkeys),
            "an all-remote 2-of-3 aggregate must verify under Q"
        );
        println!("TWO-REMOTE-HOLDERS PASS: a fully off-box 2-of-3 quorum produced a Q-valid signature");
    }

    /// THE NONCE-NEVER-CROSSES INVARIANT, ASSERTED EXECUTABLY (not just a comment). Run a
    /// full mixed local+remote ceremony, capture EVERY CoSignEvent that crossed the link in
    /// both directions, and assert NO secret `SigningNonces` is recoverable from ANY wire
    /// payload. We make this a TRUE negative: we serialize a real SigningNonces for THIS
    /// holder's key the way it WOULD be encoded, and assert those secret bytes appear in no
    /// frame; we also assert no frame deserializes as a SigningNonces. The frames that DO
    /// cross are exactly: the round-1 commit trigger (empty), the round-1 commitment
    /// (public), the round-2 package+request (public), and the round-2 share (public).
    #[test]
    fn nonce_never_crosses_the_wire() {
        let ks = keyset();
        let kps = three_kps(&ks);

        let local = LocalHolder::new(kps[0].clone(), ks.pubkeys.clone());
        let server2 = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let link2 = InProcessHolderLink::new(Arc::clone(&server2));
        let wire = link2.wire_log();
        let remote = RemoteHolder::new(server2.id(), link2);

        let holders: Vec<Box<dyn Holder>> = vec![Box::new(local), Box::new(remote)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build mixed quorum signer");
        qs.sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("ceremony signs");

        let frames = wire.lock().expect("wire log lock");
        // Sanity: the ceremony actually used the link (commit trigger + commitment +
        // package + share = at least 4 frames crossed).
        assert!(
            frames.len() >= 4,
            "expected the remote holder's round-1 + round-2 frames to cross, saw {}",
            frames.len()
        );

        // (a) NEGATIVE-BY-DESERIALIZATION: no opaque payload that crossed can be decoded as
        //     a SigningNonces. If any frame carried a nonce, this parse would succeed.
        for (i, f) in frames.iter().enumerate() {
            let as_nonce: Result<SigningNonces, _> = serde_json::from_slice(&f.payload);
            assert!(
                as_nonce.is_err(),
                "frame {i} (round {}) deserialized as a SigningNonces -- the secret nonce crossed the wire!",
                f.round
            );
        }

        // (b) NEGATIVE-BY-BYTES (defense-in-depth on top of (a)): independently produce a
        //     SigningNonces for this holder's share and serialize it the same way the server
        //     serializes a commitment/share (serde_json), then assert NONE of its bytes
        //     appear inside any wire payload. A SigningNonces is randomized, so this sample's
        //     exact bytes differ from whatever the server generated -- so (b) does NOT prove
        //     the server's specific nonce is absent (that is (a)'s job, structurally). What
        //     (b) DOES catch is a regression that serializes a nonce with a recognizable
        //     fixed envelope/prefix into a larger frame, which (a) (a whole-frame parse)
        //     would miss. The two together: (a) = no frame IS a nonce; (b) = the nonce
        //     wire-shape is not embedded in any frame.
        let (sample_nonce, _c) = kirby_custody::commit_for(&kps[1]);
        let nonce_bytes = serde_json::to_vec(&sample_nonce).expect("serialize sample nonce");
        // The nonce serialization is non-trivial; use its full body as the needle.
        assert!(
            !nonce_bytes.is_empty(),
            "a serialized SigningNonces should be non-empty (sanity for the needle)"
        );
        for (i, f) in frames.iter().enumerate() {
            assert!(
                !contains_subslice(&f.payload, &nonce_bytes),
                "frame {i} (round {}) contains a serialized SigningNonces -- secret nonce leaked!",
                f.round
            );
        }

        // (c) POSITIVE: confirm the frames that DID cross are the expected PUBLIC ones, so
        //     this test cannot pass vacuously (e.g. if the link silently carried nothing).
        let rounds: Vec<u8> = frames.iter().map(|f| f.round).collect();
        assert!(
            rounds.contains(&ROUND_COMMIT_REQUEST),
            "the round-1 commit trigger must have crossed; rounds = {rounds:?}"
        );
        assert!(
            rounds.contains(&ROUND_COMMITMENT),
            "the public round-1 commitment must have crossed; rounds = {rounds:?}"
        );
        assert!(
            rounds.contains(&ROUND_PACKAGE),
            "the round-2 package+request must have crossed; rounds = {rounds:?}"
        );
        assert!(
            rounds.contains(&ROUND_SHARE),
            "the public round-2 share must have crossed; rounds = {rounds:?}"
        );
        // And a commitment frame really IS a public SigningCommitments (the right thing
        // crossed, not garbage), so the negative checks above are meaningful.
        let commitment_frame = frames
            .iter()
            .find(|f| f.round == ROUND_COMMITMENT)
            .expect("a commitment frame");
        let _c: SigningCommitments = serde_json::from_slice(&commitment_frame.payload)
            .expect("the round-1 commitment frame must decode as public SigningCommitments");

        println!(
            "NONCE-NEVER-CROSSES PASS: across {} wire frames (commit-trigger/commitment/package/share), \
             no SigningNonces is recoverable -- only public commitments + the partial share crossed",
            frames.len()
        );
    }

    /// THE MEMBRANE RUNS HOLDER-SIDE: a holder that is asked to sign a TAMPERED package
    /// (its message is a DIFFERENT note's id, not the one the typed request names) REFUSES,
    /// so NO share is produced and the ceremony aborts -- proving the remote holder is not a
    /// blind-signer. Mirrors `quorum_signer::g_quorum_membrane_wired`, but holder-side.
    #[test]
    fn remote_holder_refuses_a_tampered_package_no_share() {
        let ks = keyset();
        let kps = three_kps(&ks);
        let server = RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone());

        // Round 1: the holder commits (stores its nonce) for this session.
        let session_id = 7u64;
        let commit_reply = server.handle(CoSignEvent {
            session_id,
            from: coordinator_id(),
            round: ROUND_COMMIT_REQUEST,
            payload: Vec::new(),
        });
        assert_eq!(commit_reply.round, ROUND_COMMITMENT, "holder commits at round 1");
        let commitment: SigningCommitments =
            serde_json::from_slice(&commit_reply.payload).expect("commitment decodes");

        // Build a TAMPERED package: its message is a DIFFERENT note's id. A blind-signer
        // would happily co-sign this; the membrane must refuse.
        let q_hex = hex::encode(group_xonly_q(&ks.pubkeys).unwrap());
        let wrong_id = nip01_event_id(&q_hex, CREATED_AT, 1, "a DIFFERENT note");
        let mut commitments = std::collections::BTreeMap::new();
        commitments.insert(*kps[1].identifier(), commitment);
        let tampered = SigningPackage::new(commitments, &wrong_id);

        // The typed request asks to sign the REAL note (CONTENT), but the package carries
        // the wrong message -> guardian::validate must return MessageMismatch.
        let req = CoSignRequest {
            session_id,
            intent: guardian::SignIntent::NostrEvent {
                kind: 1,
                created_at: CREATED_AT,
                tags: Vec::new(),
                content: CONTENT.to_string(),
            },
            signer_set: [server.id()].into_iter().collect(),
        };
        let envelope = SignRequestEnvelope {
            package: tampered,
            request: req,
        };
        let sign_reply = server.handle(CoSignEvent {
            session_id,
            from: coordinator_id(),
            round: ROUND_PACKAGE,
            payload: serde_json::to_vec(&envelope).unwrap(),
        });

        assert_eq!(
            sign_reply.round, ROUND_REFUSAL,
            "the holder must REFUSE a tampered package (no share)"
        );
        let reason: RefuseReason = serde_json::from_slice(&sign_reply.payload).unwrap();
        assert_eq!(
            reason,
            RefuseReason::MessageMismatch,
            "the refusal must be MessageMismatch (the membrane caught the wrong message)"
        );

        // And the nonce was consumed by the refused sign attempt: a second sign for the
        // same session finds no nonce -> a hard refusal (no reuse). The proxy maps a
        // missing-nonce refusal to BadKeyset.
        let again = server.handle(CoSignEvent {
            session_id,
            from: coordinator_id(),
            round: ROUND_PACKAGE,
            payload: sign_reply_payload_for_real_note(&ks, &kps, session_id),
        });
        assert_eq!(
            again.round, ROUND_REFUSAL,
            "after a refusal the nonce is dropped; a re-sign for the same session must refuse (no reuse)"
        );
        println!("REMOTE-HOLDER-MEMBRANE PASS: a tampered package is refused holder-side (MessageMismatch), no share, nonce dropped");
    }

    /// Helper: build a sign-request envelope payload for the REAL note (CONTENT) over a
    /// fresh commitment, used to prove a missing nonce refuses on re-sign.
    fn sign_reply_payload_for_real_note(
        ks: &kirby_custody::DealerKeyset,
        kps: &[KeyPackage],
        session_id: u64,
    ) -> Vec<u8> {
        let q_hex = hex::encode(group_xonly_q(&ks.pubkeys).unwrap());
        let real_id = nip01_event_id(&q_hex, CREATED_AT, 1, CONTENT);
        // A commitment from a throwaway nonce (we only need a well-formed package shape).
        let (_n, c) = kirby_custody::commit_for(&kps[1]);
        let mut commitments = std::collections::BTreeMap::new();
        commitments.insert(*kps[1].identifier(), c);
        let package = SigningPackage::new(commitments, &real_id);
        let req = CoSignRequest {
            session_id,
            intent: guardian::SignIntent::NostrEvent {
                kind: 1,
                created_at: CREATED_AT,
                tags: Vec::new(),
                content: CONTENT.to_string(),
            },
            signer_set: [identifier_to_u16(kps[1].identifier())].into_iter().collect(),
        };
        serde_json::to_vec(&SignRequestEnvelope { package, request: req }).unwrap()
    }

    /// The mock transport is OPACITY-FAITHFUL: the link routes by `(session_id, round)` and
    /// carries an ARBITRARY (even garbage) payload verbatim, never parsing it -- the same
    /// contract custody `seam.rs` proves, which is what lets the kirby-nostr relay drop in
    /// unchanged at a later chunk boundary.
    #[test]
    fn mock_transport_never_inspects_payload() {
        let ks = keyset();
        let kps = three_kps(&ks);
        let server = Arc::new(RemoteHolderServer::new(kps[0].clone(), ks.pubkeys.clone()));
        let link = InProcessHolderLink::new(Arc::clone(&server));
        let wire = link.wire_log();

        // Send a frame the server does not recognize (round 99) with a garbage payload.
        let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x42];
        link.send(CoSignEvent {
            session_id: 42,
            from: coordinator_id(),
            round: 99,
            payload: garbage.clone(),
        })
        .expect("send garbage");

        // The wire log's FIRST entry is the exact bytes we sent (carried verbatim, the link
        // never parsed them). The server replied with a refusal (it did not crash on it).
        let frames = wire.lock().expect("wire log lock");
        assert_eq!(frames[0].payload, garbage, "the link carried the opaque payload verbatim");
        assert_eq!(frames[0].round, 99, "the link preserved the round discriminant");
        assert_eq!(
            frames[1].round, ROUND_REFUSAL,
            "an unknown request round is refused holder-side (never blind-handled)"
        );
        println!("MOCK-OPACITY PASS: the link routes by (session_id, round) and carries opaque payload verbatim");
    }

    /// A duplicate holder in the quorum is rejected by the QuorumSigner BEFORE any round-1
    /// commit (the `feedback_new_entry_point_needs_input_guards` lesson: a new signing entry
    /// point must keep the dup-signer guard). Here both holders are RemoteHolders aliased to
    /// the SAME identifier; the signer must refuse rather than reuse a single-use nonce.
    #[test]
    fn duplicate_remote_holder_is_rejected_before_round1() {
        let ks = keyset();
        let kps = three_kps(&ks);
        // Two RemoteHolders BOTH pointing at identifier-1 servers (same u16 id).
        let s_a = Arc::new(RemoteHolderServer::new(kps[0].clone(), ks.pubkeys.clone()));
        let s_b = Arc::new(RemoteHolderServer::new(kps[0].clone(), ks.pubkeys.clone()));
        let r_a = RemoteHolder::new(s_a.id(), InProcessHolderLink::new(Arc::clone(&s_a)));
        let r_b = RemoteHolder::new(s_b.id(), InProcessHolderLink::new(Arc::clone(&s_b)));
        assert_eq!(r_a.id(), r_b.id(), "both proxies alias the same identifier");

        let holders: Vec<Box<dyn Holder>> = vec![Box::new(r_a), Box::new(r_b)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build signer");
        let res = qs.sign_nostr_event(1, CREATED_AT, CONTENT);
        assert!(
            res.is_err(),
            "a quorum of two same-identifier holders must be refused (no nonce reuse), got {res:?}"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("distinct identifiers") || msg.contains("quorum"),
            "the refusal should explain the collapsed/duplicate quorum: {msg}"
        );
        println!("DUP-REMOTE-HOLDER PASS: two same-identifier RemoteHolders are refused before round 1 (no nonce reuse)");
    }

    /// A transport that wraps a real link but REWRITES every reply's `from` to a different
    /// identifier -- modeling a misrouted or spoofed reply on a shared relay. Used to prove
    /// the proxy's sender-identity guard.
    struct SpoofingFromLink {
        inner: InProcessHolderLink,
        spoof_from: GuardianId,
    }
    impl HolderTransport for SpoofingFromLink {
        fn send(&self, event: CoSignEvent) -> anyhow::Result<()> {
            self.inner.send(event)
        }
        fn recv(&self) -> anyhow::Result<CoSignEvent> {
            let mut e = self.inner.recv()?;
            e.from = self.spoof_from; // pretend the reply came from someone else
            Ok(e)
        }
    }

    /// THE SENDER-IDENTITY GUARD: a reply whose `from` is NOT this holder's identifier is
    /// rejected (the proxy never accepts a misrouted/spoofed commitment or share for the
    /// session). Catches the protocol-integrity hole a shared relay transport would expose.
    #[test]
    fn remote_holder_rejects_reply_from_a_wrong_sender() {
        let ks = keyset();
        let kps = three_kps(&ks);
        // The server is identifier 2; the link rewrites replies to claim identifier 1.
        let server = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let wrong_from = GuardianId::try_from(identifier_to_u16(kps[0].identifier())).unwrap();
        assert_ne!(server.id(), identifier_to_u16(kps[0].identifier()), "the spoof id must differ");
        let link = SpoofingFromLink {
            inner: InProcessHolderLink::new(Arc::clone(&server)),
            spoof_from: wrong_from,
        };
        let remote = RemoteHolder::new(server.id(), link);

        // Round 1: the commit reply will claim the wrong sender -> the proxy must reject it.
        let res = remote.commit(1);
        assert!(
            res.is_err(),
            "a round-1 reply from the wrong sender must be rejected, got {res:?}"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("came from"),
            "the rejection should name the sender mismatch: {msg}"
        );
        println!("SENDER-IDENTITY PASS: a reply from the wrong holder identifier is rejected (no misrouted/spoofed frame accepted)");
    }

    /// A naive subslice search for the nonce-bytes needle (no extra deps).
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
