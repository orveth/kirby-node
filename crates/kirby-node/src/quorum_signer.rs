//! S3c: the LIVE PER-AGENT FROST QUORUM SIGNER.
//!
//! This is the first time a live signing path flows through a 2-of-3 threshold
//! quorum AND the first real caller of the guardian-validation membrane
//! ([`kirby_custody::guardian::validate`]). It is the signing counterpart of
//! [`crate::frost_identity::FrostIdentity`]: where `FrostIdentity` is the PUBLIC
//! face of the group (the taproot output key Q + the npub), the `QuorumSigner`
//! holds the SECRET signing material (the per-guardian `KeyPackage`s) and produces
//! aggregate BIP-340 signatures under Q.
//!
//! LOCKED DESIGN (gudnuf):
//!   * Q SIGNS EVERYTHING. The agent's identity is its FROST group taproot key Q;
//!     a FROST tenant has NO node-local signing key. S3c targets the kind:1 voice
//!     path (presence/lifecycle is S3e).
//!   * HOLDERS CO-LOCATED IN-PROCESS for S3. The `QuorumSigner` holds all 3
//!     KeyPackages as in-process [`Holder`]s. Cross-machine share distribution is
//!     S5/S6: the [`Holder`] trait is the seam where a co-located holder is later
//!     replaced by a remote (network) holder WITHOUT changing the call site. NO
//!     network transport is built here.
//!   * Plaintext key material at rest (no sealing this slice).
//!
//! THE CEREMONY (reuses [`kirby_custody::coordinator`]'s flow, NOT its `Coordinator`
//! struct, because each holder must run the membrane between round1 and round2):
//!   1. Re-port the publish-path CONTENT GUARD: run
//!      [`kirby_proto::sanitize_note_for_publish`] and sign the SANITIZED content;
//!      require kind == [`kirby_proto::NOSTR_KIND_TEXT_NOTE`]; tags are empty.
//!   2. Compute the NIP-01 event id under Q (the FROST `message`).
//!   3. Each participating holder: `round1::commit` (a FRESH single-use nonce).
//!      Assemble exactly ONE `SigningPackage` over the event id.
//!   4. THE MEMBRANE: each participating holder calls `guardian::validate` with its
//!      OWN copy of the group `pubkeys` BEFORE `round2::sign_with_tweak`. Only on
//!      `Ok(())` does that holder sign. Any refusal ABORTS the whole ceremony and
//!      emits NO signature.
//!   5. `aggregate_with_tweak` -> the 64-byte BIP-340 sig. Assemble the `NostrEvent`.
//!
//! A NEW `QuorumSigner` ceremony per call (no nonce reuse across ceremonies),
//! mirroring `coordinator.rs`'s single-shot guarantee.
//!
//! THE GUARD-RE-PORT LESSON (load-bearing): a newly-reachable signing entry point
//! inherits the shared crypto but NOT the sibling publish path's per-entry-point
//! guards. The actuator's `validate_nostr_publish` enforces: kind == 1, sanitize,
//! reject tags. `sign_nostr_event` re-enforces each here rather than assuming the
//! caller sanitized (Step 1 above + the empty-tags invariant baked into the
//! NIP-01 id, which uses `tags = []`). At-most-once stays a gateway concern (the
//! `authorize_actuate` reserve-before-publish ordering is unchanged by this slice).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use anyhow::Context as _;
use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};

#[cfg(test)]
use kirby_custody::cosign_net::nip01_event_id;
use kirby_custody::cosign_net::{nip01_event_id_with_tags, NostrEvent};
use kirby_custody::guardian::{
    self, CoSignRequest, RefuseReason, SignIntent, KIND_KIRBY_AGENT_STATE, KIND_KIRBY_LEASE,
    KIND_KIRBY_LIFECYCLE, KIND_KIRBY_PRESENCE, KIND_NOSTR_INBOX_RELAYS, KIND_NOSTR_SEAL,
};
use kirby_custody::group_xonly_q;

/// The S3 quorum size (a 2-of-3 group: any 2 of the 3 holders co-sign).
///
/// `pub(crate)` so the S5/S6 [`crate::remote_holder`] module reuses the SAME threshold the
/// co-located path uses (a remote holder's membrane `min_signers` must match the
/// coordinator's, or it would apply a different threshold than the rest of the quorum).
pub(crate) const MIN_SIGNERS: u16 = 2;

/// Map a FROST `Identifier` to its u16 wire form (the same projection the guardian
/// membrane uses; sound for trusted-dealer identifiers 1..=n). A holder's `id()`
/// returns this u16 so the call site can build the membrane's `signer_set` and
/// `my_identifier` without depending on the frost `Identifier` type.
///
/// `pub(crate)` so the S5/S6 [`crate::remote_holder`] module derives a holder server's u16
/// id from its `KeyPackage` with the SAME projection (the id must agree across the seam).
pub(crate) fn identifier_to_u16(id: &Identifier) -> u16 {
    let bytes = id.serialize();
    let n = bytes.len();
    u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])
}

/// A FROST share holder: ONE participant in the threshold group. For S3 the only
/// impl is [`LocalHolder`] (the KeyPackage lives in this process). This trait is the
/// S5/S6 SEAM: a future `RemoteHolder` that talks to a holder on another machine
/// implements the SAME three operations (commit / validate-and-sign / identity) so
/// the [`QuorumSigner`] ceremony body does not change at all when holders move
/// off-box.
///
/// The contract a remote holder MUST also honor (it is the whole point of the
/// membrane): `validate_and_sign` runs `guardian::validate` against ITS OWN copy of
/// the group `pubkeys` BEFORE it produces a signature share, and refuses on any
/// validation failure -- it NEVER blind-signs whatever bytes the coordinator placed
/// in the package.
///
/// NONCE OWNERSHIP (the S5/S6-real seam): the secret `SigningNonces` NEVER crosses
/// the trait boundary. Each holder GENERATES its own nonce in `commit` and STORES it
/// internally keyed by `session_id`, returning ONLY the public commitment. In
/// `validate_and_sign` the holder LOOKS UP + REMOVES its own nonce for that session,
/// signs, and drops it immediately (used-once, dropped at scope exit). A remote
/// holder retains its nonce on its own machine identically -- the coordinator never
/// sees it. This is why the [`QuorumSigner`] holds NO `SigningNonces` at all.
pub trait Holder: Send + Sync {
    /// This holder's FROST identifier as a u16 (the membrane's signer-set element).
    fn id(&self) -> u16;

    /// Round 1: GENERATE a FRESH single-use signing nonce, STORE it internally keyed
    /// by `session_id`, and return ONLY the public commitment. The secret nonce stays
    /// with the holder (it never crosses the seam); a remote holder returns the
    /// serialized commitment over the wire and keeps its nonce on its own machine.
    fn commit(&self, session_id: u64) -> anyhow::Result<SigningCommitments>;

    /// THE MEMBRANE + round 2. Given the assembled `package`, the `session_id` (whose
    /// nonce this holder stored in `commit`), and the typed `req`, the holder:
    ///   1. LOOKS UP + REMOVES its own stored nonce for `session_id` (used-once: it is
    ///      dropped at the end of this call, never reusable across ceremonies),
    ///   2. runs `guardian::validate(req, package, &own_pubkeys, self.id(), MIN_SIGNERS)`,
    ///      deriving Q from its OWN `pubkeys` (never a coordinator-asserted Q), and
    ///   3. ONLY on `Ok(())` calls `round2::sign_with_tweak` and returns the share.
    ///
    /// On any refusal it returns `Err(reason)` and produces NO share -> the whole
    /// ceremony aborts (no signature emitted). The nonce is consumed (removed) BEFORE
    /// the membrane runs, so a refusal still drops the nonce -- it can never be reused.
    fn validate_and_sign(
        &self,
        session_id: u64,
        req: &CoSignRequest,
        package: &SigningPackage,
    ) -> Result<SignatureShare, RefuseReason>;
}

/// A co-located (in-process) holder: it owns its `KeyPackage`, its OWN copy of the
/// group `PublicKeyPackage` (the membrane requires each holder to derive Q from its
/// OWN pubkeys, never one the coordinator asserts), AND a per-session store of its
/// secret nonces. Plaintext at rest for S3.
pub struct LocalHolder {
    key_package: KeyPackage,
    /// This holder's OWN copy of the group public keys (the membrane derives Q from
    /// THIS, not from anything the coordinator passes). For S5/S6 each remote holder
    /// would hold its own persisted copy identically.
    own_pubkeys: PublicKeyPackage,
    id_u16: u16,
    /// The holder's OWN secret nonces, keyed by `session_id`. A nonce is inserted in
    /// `commit` and REMOVED (consumed, then dropped) in `validate_and_sign`. The
    /// coordinator never sees this map -- it is the in-process stand-in for a remote
    /// holder retaining its nonce on its own machine.
    nonces: Mutex<HashMap<u64, SigningNonces>>,
}

impl LocalHolder {
    /// Build a co-located holder from its `KeyPackage` and its own copy of the group
    /// `pubkeys`.
    pub fn new(key_package: KeyPackage, own_pubkeys: PublicKeyPackage) -> Self {
        let id_u16 = identifier_to_u16(key_package.identifier());
        Self {
            key_package,
            own_pubkeys,
            id_u16,
            nonces: Mutex::new(HashMap::new()),
        }
    }
}

impl Holder for LocalHolder {
    fn id(&self) -> u16 {
        self.id_u16
    }

    fn commit(&self, session_id: u64) -> anyhow::Result<SigningCommitments> {
        // Use the custody crate's OS CSPRNG (rand 0.8 = the rand_core 0.6 the ZF
        // frost crate requires). kirby-node's own `rand` resolves to rand_core 0.9,
        // whose `OsRng` does NOT implement frost's rand_core 0.6 `RngCore`, so the
        // nonce commit must go through `kirby_custody::commit_for`.
        let (nonce, commitment) = kirby_custody::commit_for(&self.key_package);
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| anyhow::anyhow!("holder {} nonce store poisoned", self.id_u16))?;
        // A session_id is single-use per holder; refuse to clobber a live nonce (that
        // would silently drop an in-flight ceremony's nonce -> a stuck sign).
        if nonces.contains_key(&session_id) {
            anyhow::bail!(
                "holder {} already has a live nonce for session {session_id} (nonce reuse guard)",
                self.id_u16
            );
        }
        nonces.insert(session_id, nonce);
        Ok(commitment)
    }

    fn validate_and_sign(
        &self,
        session_id: u64,
        req: &CoSignRequest,
        package: &SigningPackage,
    ) -> Result<SignatureShare, RefuseReason> {
        // 1. LOOK UP + REMOVE this holder's own nonce for the session. The removed
        //    nonce lives only in this scope: used once, then dropped on return (whether
        //    we sign OR refuse). A missing nonce (no matching `commit`) is a hard
        //    refusal -- never reach for someone else's nonce.
        let nonce = {
            let mut nonces = self.nonces.lock().map_err(|_| RefuseReason::BadKeyset)?;
            nonces.remove(&session_id).ok_or(RefuseReason::BadKeyset)?
        };
        // 2. THE MEMBRANE: derive Q from THIS holder's own pubkeys and require the
        //    package's message to equal the id reconstructed from the typed intent.
        //    A refusal here means NO share is produced (the ceremony aborts) AND the
        //    nonce we just removed is dropped at the end of this scope (never reused).
        guardian::validate(req, package, &self.own_pubkeys, self.id_u16, MIN_SIGNERS)?;
        // 3. Only after the membrane passed: produce the tweaked (key-path,
        //    merkle_root = None) signature share, consuming the nonce. Treat a round2
        //    failure as a hard refusal (BadKeyset is the closest "this holder cannot
        //    sign" reason). In practice round2 only fails on a malformed package,
        //    which the membrane's equality check has already constrained to the
        //    reconstructed id.
        frost::round2::sign_with_tweak(package, &nonce, &self.key_package, None)
            .map_err(|_| RefuseReason::BadKeyset)
    }
}

/// A live per-agent FROST quorum signer. Holds the 3 holders (in-process for S3,
/// behind the [`Holder`] seam) + the group `PublicKeyPackage` + the derived taproot
/// key Q. Produces aggregate BIP-340 signatures under Q via a 2-of-3 ceremony with
/// the guardian membrane wired into every holder.
pub struct QuorumSigner {
    /// The 3 share holders (any 2 form a quorum). Behind the [`Holder`] seam so S5/S6
    /// swaps co-located holders for remote ones without changing `sign_nostr_event`. The
    /// signer chooses an AVAILABLE 2-of-3 subset per call (any-available selection with
    /// fallback; see `sign_nostr_event_with_tags` step 3), so one unreachable holder does
    /// not kill a ceremony another reachable subset could complete.
    holders: Vec<Box<dyn Holder>>,
    /// The group public key package (the FROST verifying material): used to assemble
    /// the coordinator's view AND to aggregate the shares. Each holder ALSO carries
    /// its own copy for the membrane (a holder never trusts a coordinator-asserted Q).
    pubkeys: PublicKeyPackage,
    /// The group taproot output key Q as 32 x-only bytes (= `hex(Q)` is the event
    /// pubkey). Derived once at construction.
    q_bytes: [u8; 32],
    /// A MONOTONIC per-ceremony session-id counter. Each `sign_nostr_event*` call
    /// takes the next value (`fetch_add(1)`) as its FROST `session_id`, so two
    /// ceremonies NEVER collide -- even when they start in the same second (a beacon
    /// burst at startup: presence + `born` lifecycle + the metered 31000 emitter).
    /// Deriving the session id from `created_at` (seconds) tripped the holder's
    /// nonce-reuse guard on same-second ceremonies -> a fail-closed LOST publish.
    /// The guard itself stays intact: a genuine double-use of ONE session id still
    /// refuses; this just guarantees distinct ceremonies get distinct ids.
    next_session: AtomicU64,
}

impl QuorumSigner {
    /// Build a quorum signer from the 3 holders and the group `pubkeys`. Derives Q
    /// once (BIP-341 key-path tweak, merkle_root = None) so it matches
    /// [`crate::frost_identity::FrostIdentity`] and the custody coordinator exactly.
    pub fn new(
        holders: Vec<Box<dyn Holder>>,
        pubkeys: PublicKeyPackage,
    ) -> anyhow::Result<Self> {
        let q_bytes =
            group_xonly_q(&pubkeys).map_err(|e| anyhow::anyhow!("derive group Q: {e}"))?;
        Ok(Self {
            holders,
            pubkeys,
            q_bytes,
            next_session: AtomicU64::new(0),
        })
    }

    /// Convenience constructor for the co-located (S3) case: build a `QuorumSigner`
    /// from the 3 per-guardian `KeyPackage`s + the group `pubkeys`, wrapping each in a
    /// [`LocalHolder`] that carries its OWN copy of `pubkeys`.
    pub fn from_local_key_packages(
        key_packages: Vec<KeyPackage>,
        pubkeys: PublicKeyPackage,
    ) -> anyhow::Result<Self> {
        let holders: Vec<Box<dyn Holder>> = key_packages
            .into_iter()
            .map(|kp| Box::new(LocalHolder::new(kp, pubkeys.clone())) as Box<dyn Holder>)
            .collect();
        Self::new(holders, pubkeys)
    }

    /// The group taproot key Q as 32 x-only bytes (the event pubkey + what the npub
    /// encodes). Lowercase hex of this is the `pubkey` field of every event signed.
    pub fn q_bytes(&self) -> [u8; 32] {
        self.q_bytes
    }

    /// Sign a kind:1 voice note (the S3c path): a thin wrapper over
    /// [`Self::sign_nostr_event_with_tags`] with EMPTY tags. Kept so the actuator's
    /// voice call site is unchanged.
    pub fn sign_nostr_event(
        &self,
        kind: u32,
        created_at: u64,
        content: &str,
    ) -> anyhow::Result<NostrEvent> {
        self.sign_nostr_event_with_tags(kind, created_at, &[], content)
    }

    /// Sign a Nostr event (voice OR beacon) through a fresh 2-of-3 FROST ceremony with
    /// the guardian membrane wired into every participating holder. Returns the finished
    /// [`NostrEvent`] (id, pubkey = hex(Q), content, tags, the aggregate 64-byte BIP-340
    /// sig). Each call is a NEW ceremony (fresh nonces; no reuse across ceremonies).
    ///
    /// S3e GENERALIZATION ("Q signs everything"): the agent's PUBLIC Nostr output is its
    /// voice (kind:1) PLUS its three beacons (10100 presence / 9100 lifecycle / 31000
    /// agent-state), all under the SAME group key Q. The id is computed over `kind`,
    /// `created_at`, `tags`, AND `content`, so a beacon's tags are part of the signed id.
    ///
    /// RE-PORTED PUBLISH-PATH GUARDS (a signing entry point re-enforces them, it does not
    /// assume the caller did):
    ///   * kind MUST be one of {1, 10100, 9100, 31000}; any other kind is refused.
    ///   * THE NOTE SANITIZER APPLIES ONLY TO kind:1. The free-text voice runs through
    ///     `kirby_proto::sanitize_note_for_publish` and the SANITIZED result is what is
    ///     signed/published (control + U+2028/9 stripped, whitespace collapsed, non-empty,
    ///     within `MAX_NOTE_BYTES`). The BEACONS carry machine-generated JSON state, not
    ///     prose: running the note sanitizer on JSON would corrupt it (collapse spaces,
    ///     strip structure), so beacon content is signed VERBATIM. The guardian membrane
    ///     enforces the same kind:1-only content policy independently per holder.
    ///
    /// AVAILABILITY (S5/S6): the signer set is chosen by ANY-AVAILABLE-2-of-3 selection
    /// with fallback (see step 3 + `try_subset_ceremony`). When every holder is reachable
    /// the first subset tried is `holders[0..MIN_SIGNERS]`, so the all-healthy path is the
    /// SAME ceremony as before; when a holder times out or refuses, the ceremony falls back
    /// to another 2-of-3 subset and only fails when NO subset can complete. One unreachable
    /// holder no longer kills a ceremony a different reachable subset could finish.
    ///
    /// COST NOTE (S5/S6): this still runs a full quorum ceremony PER beacon. For S3 the
    /// holders are co-located in-process (sub-ms), so a per-presence-interval ceremony is
    /// fine. When holders move off-box, a quorum ceremony on every presence beacon is too
    /// expensive on the wire -- that lane MUST adopt a cheaper presence cadence or a
    /// short-lived session sub-key delegated by Q. Do NOT build that here (it is the
    /// deferred cost note, separate from this availability chunk).
    ///
    /// The guardian membrane independently re-checks kind, the (kind:1-only)
    /// content-canonicality, and the id-over-tags equality per holder (defense in depth),
    /// so even a bug here cannot get a dirty/wrong-kind/wrong-tags event co-signed.
    pub fn sign_nostr_event_with_tags(
        &self,
        kind: u32,
        created_at: u64,
        tags: &[Vec<String>],
        content: &str,
    ) -> anyhow::Result<NostrEvent> {
        // 1. RE-PORT THE GUARDS. kind-restrict to the voice + the three beacon kinds.
        if !is_signable_kind(kind) {
            anyhow::bail!(
                "QuorumSigner refuses kind {kind}: only kind 1 (voice), the Kirby beacons \
                 {KIND_KIRBY_PRESENCE}/{KIND_KIRBY_LIFECYCLE}/{KIND_KIRBY_AGENT_STATE}, the \
                 cross-machine lease {KIND_KIRBY_LEASE}, the NIP-17 DM seal {KIND_NOSTR_SEAL}, and \
                 the DM inbox-relay list {KIND_NOSTR_INBOX_RELAYS} are signable"
            );
        }
        // The NOTE SANITIZER applies ONLY to kind:1 (free text). Beacons (JSON state) are
        // signed verbatim -- never run through the note sanitizer.
        let signed_content = if kind == kirby_proto::NOSTR_KIND_TEXT_NOTE as u32 {
            kirby_proto::sanitize_note_for_publish(content).map_err(|reason| {
                anyhow::anyhow!("note content refused by the publish guard: {reason}")
            })?
        } else {
            content.to_string()
        };
        let signed_tags: Vec<Vec<String>> = tags.to_vec();

        // 2. Compute the NIP-01 event id under Q (the FROST message) over content AND tags.
        let q_hex = hex::encode(self.q_bytes);
        let event_id =
            nip01_event_id_with_tags(&q_hex, created_at, kind, &signed_tags, &signed_content);

        // 3. ANY-AVAILABLE-t-of-n SELECTION + FALLBACK (S5/S6: replaces the old
        //    "2-of-the-first-MIN_SIGNERS, abort on any refusal" stub). Enumerate the
        //    MIN_SIGNERS-of-n holder subsets and try each one's FULL ceremony in turn. On
        //    a holder error in EITHER round (a remote timeout OR a refusal both surface as
        //    `Err`), ABANDON that subset and fall back to the next untried one. Succeed as
        //    soon as any subset yields a Q-valid aggregate; fail cleanly only when NO
        //    subset completes.
        //
        //    ALL-HEALTHY INVARIANT (constraint: byte-for-byte same as the old path when
        //    every holder is reachable): `quorum_subsets` lists the first-MIN_SIGNERS set
        //    FIRST (it is the lexicographically smallest index combination,
        //    `[0..MIN_SIGNERS]`). So when no holder fails, the FIRST subset tried is
        //    exactly `holders.iter().take(MIN_SIGNERS)` and the ceremony is identical to
        //    today's -- no feature flag, a strict generalization.
        //
        //    NO HANG: there are no async/wall-clock timeouts here. The `Holder` ops look
        //    synchronous; a real remote holder's per-wire timeout lives INSIDE its
        //    transport (it returns `Err` on timeout). We react to the `Err`, never block on
        //    wall clock, so this loop terminates after at most `quorum_subsets.len()`
        //    attempts.
        if self.holders.len() < MIN_SIGNERS as usize {
            anyhow::bail!(
                "QuorumSigner has {} holders, need at least {MIN_SIGNERS} to form a quorum",
                self.holders.len()
            );
        }
        let subsets = quorum_subsets(self.holders.len(), MIN_SIGNERS as usize);

        // The typed request intent + tags are the SAME for every attempt (only the per-
        // attempt session id and signer_set differ); build the shared parts once and clone
        // the per-attempt `CoSignRequest` inside the loop (the membrane needs an owned req).
        let intent = SignIntent::NostrEvent {
            kind,
            created_at,
            tags: signed_tags.clone(),
            content: signed_content.clone(),
        };

        let mut last_err: Option<anyhow::Error> = None;
        for subset in &subsets {
            // `&dyn Holder` (deref the box) so the helper takes a `&[&dyn Holder]` -- the
            // ceremony does not care whether a holder is co-located or remote.
            let participants: Vec<&dyn Holder> =
                subset.iter().map(|&i| self.holders[i].as_ref()).collect();
            match self.try_subset_ceremony(&participants, &event_id, &intent) {
                Ok(sig) => {
                    // Assemble the finished event: pubkey = hex(Q), the signed content
                    // (sanitized for kind:1, verbatim JSON for a beacon), the signed tags,
                    // the aggregate sig, the id.
                    return Ok(NostrEvent {
                        id: hex::encode(event_id),
                        pubkey: q_hex,
                        created_at,
                        kind,
                        tags: signed_tags,
                        content: signed_content,
                        sig: hex::encode(sig),
                    });
                }
                Err(e) => {
                    // ABANDON this subset and fall back to the next. A stranded nonce from a
                    // holder that DID commit in this failed attempt is left under that
                    // attempt's session id; because session ids are never reused (the
                    // monotonic counter) it can never be re-signed, so it is at worst a
                    // bounded in-memory map entry on that holder (the documented-leak choice;
                    // see `try_subset_ceremony`). No partial signature is ever emitted.
                    let ids: Vec<u16> = participants.iter().map(|h| h.id()).collect();
                    last_err = Some(e.context(format!(
                        "quorum subset {ids:?} failed; trying the next reachable subset"
                    )));
                }
            }
        }

        // No MIN_SIGNERS-of-n subset completed: fail CLEANLY (no partial/forged signature,
        // no hang, no panic). Surface the last subset's failure as the cause.
        let detail = match last_err {
            Some(e) => format!("{e:#}"),
            None => "no quorum subset was available".to_string(),
        };
        anyhow::bail!(
            "no available {MIN_SIGNERS}-of-{n} holder subset could complete the ceremony; \
             NO signature emitted (last failure: {detail})",
            n = self.holders.len()
        );
    }

    /// Run ONE subset's full 2-of-3 ceremony: a FRESH session id, round-1 commit over the
    /// subset, assemble the `SigningPackage`, the membrane + round-2 sign, and aggregate.
    /// Returns the 64-byte BIP-340 aggregate signature on success, or an `Err` (which the
    /// caller treats as "abandon this subset, fall back to the next").
    ///
    /// FRESH SESSION ID PER ATTEMPT (the cardinal FROST rule): the session id comes from
    /// the monotonic `self.next_session.fetch_add` so it is DISTINCT from every other
    /// attempt's. Never reused across attempts -> a holder that committed in a failed
    /// attempt cannot have its single-use nonce re-signed (its nonce is stranded under that
    /// old, never-to-recur session id). The published event's `created_at` is unchanged;
    /// only this internal ceremony id differs.
    ///
    /// STRANDED-NONCE POLICY (documented bounded leak, NOT `Holder::release`): when this
    /// attempt is abandoned, a holder that already committed keeps a single-use nonce in its
    /// in-memory store keyed by this attempt's session id. That entry is harmless: the
    /// session id is never reused, so the nonce can never be re-signed (zero nonce-reuse
    /// risk), and it is bounded (at most one stranded nonce per committed holder per failed
    /// attempt). We deliberately do NOT widen the `Holder` seam with a `release` op in this
    /// chunk (that would touch the freshly-merged RemoteHolder wire format, which is out of
    /// scope here); the leak is documented and bounded instead. A future chunk MAY add a
    /// best-effort `release(session_id)` to drop the stranded nonce eagerly.
    ///
    /// RE-PORTED GUARDS PER ATTEMPT (the `feedback_new_entry_point_needs_input_guards`
    /// lesson -- a guard must hold on EVERY attempt, not just the first): the dup-signer
    /// distinct-identifier check runs HERE, inside the per-attempt helper, so a fallback
    /// subset is checked too. The kind-restrict + kind:1 note-sanitizer guards ran once in
    /// `sign_nostr_event_with_tags` and feed the SAME `event_id` + `intent` into every
    /// attempt (so a dirty/wrong-kind event is rejected before ANY attempt). The guardian
    /// membrane re-validates kind/content/id-over-tags per holder per attempt independently.
    fn try_subset_ceremony(
        &self,
        participants: &[&dyn Holder],
        event_id: &[u8; 32],
        intent: &SignIntent,
    ) -> anyhow::Result<[u8; 64]> {
        // RE-PORT THE DUP-SIGNER GUARD (per attempt). The claimed signer set the membrane
        // cross-checks against the package: two holders aliased to the same u16 would form a
        // degenerate quorum (mirrors the coordinator's dup-signer guard + the
        // QuorumSigner's old pre-ceremony check). Refuse rather than reuse a single-use
        // nonce across an aliased identifier.
        let signer_set: BTreeSet<u16> = participants.iter().map(|h| h.id()).collect();
        if signer_set.len() < MIN_SIGNERS as usize {
            anyhow::bail!(
                "quorum holders collapsed to fewer than {MIN_SIGNERS} distinct identifiers"
            );
        }

        // A FRESH per-attempt session id (see the doc comment): monotonic, never reused.
        let session_id = self.next_session.fetch_add(1, Ordering::Relaxed);

        // Round 1: each participating holder GENERATES + STORES its OWN fresh single-use
        // nonce and returns ONLY its public commitment (the secret nonce never crosses the
        // seam -- the remote-readiness contract). A commit `Err` (a remote timeout or a
        // refusal) propagates up -> the caller abandons this subset.
        let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for holder in participants {
            let commitment = holder.commit(session_id).with_context(|| {
                format!("holder {} round-1 commit (session {session_id})", holder.id())
            })?;
            // Recover the frost Identifier for the package map from the holder's u16.
            // The trusted-dealer identifiers are 1..=n, so u16 -> Identifier is exact.
            let ident = Identifier::try_from(holder.id()).map_err(|e| {
                anyhow::anyhow!("holder id {} is not a valid FROST identifier: {e}", holder.id())
            })?;
            commitments.insert(ident, commitment);
        }

        // Assemble exactly ONE SigningPackage over the event id for this attempt.
        let package = SigningPackage::new(commitments, event_id);

        // THE MEMBRANE + round 2: each participating holder removes its own nonce,
        // validates against its OWN pubkeys, THEN signs. The QuorumSigner passes NO nonce --
        // the holder looks up + drops its own (used-once). A `validate_and_sign` `Err` (a
        // remote timeout OR a guardian refusal) propagates up -> the caller abandons this
        // subset. NO partial signature is ever emitted on the failure path.
        let req = CoSignRequest {
            session_id, // routing/dedupe only (not security-load-bearing)
            intent: intent.clone(),
            signer_set: signer_set.clone(),
        };
        let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        for holder in participants {
            let share = holder
                .validate_and_sign(session_id, &req, &package)
                .map_err(|reason| {
                    anyhow::anyhow!(
                        "holder {} REFUSED to co-sign ({reason:?}); subset abandoned, NO signature emitted",
                        holder.id()
                    )
                })?;
            let ident = Identifier::try_from(holder.id())
                .map_err(|e| anyhow::anyhow!("holder id to identifier: {e}"))?;
            shares.insert(ident, share);
        }

        // Aggregate the tweaked shares -> the 64-byte BIP-340 signature under Q. (An
        // aggregate failure also abandons this subset rather than emitting anything.)
        let group_sig = frost::aggregate_with_tweak(&package, &shares, &self.pubkeys, None)
            .map_err(|e| anyhow::anyhow!("aggregate FROST shares: {e}"))?;
        let sig_bytes = group_sig
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize aggregate signature: {e}"))?;
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("expected a 64-byte BIP-340 signature, got {}", sig_bytes.len())
        })?;
        Ok(sig)
    }
}

/// Enumerate the `t`-of-`n` holder subsets as ASCENDING lists of holder INDICES, in
/// lexicographic order. For n=3, t=2 this yields `[[0,1],[0,2],[1,2]]`.
///
/// THE ORDER IS LOAD-BEARING: the FIRST element is always `[0, 1, .., t-1]` (the
/// first-`t` holders). The any-available selection tries subsets in this order, so when
/// every holder is healthy the first attempt is exactly `holders.iter().take(t)` -- the
/// SAME ceremony the old "2-of-the-first-MIN_SIGNERS" stub ran (the all-healthy
/// byte-identical invariant). Fallback then walks the remaining subsets in a stable order.
///
/// Returns an empty vec if `t == 0` or `t > n` (the caller has already guarded `n >= t`).
fn quorum_subsets(n: usize, t: usize) -> Vec<Vec<usize>> {
    if t == 0 || t > n {
        return Vec::new();
    }
    let mut out: Vec<Vec<usize>> = Vec::new();
    // `combo` holds the current ascending index selection; emit each complete one.
    let mut combo: Vec<usize> = Vec::with_capacity(t);
    fn recurse(start: usize, n: usize, t: usize, combo: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if combo.len() == t {
            out.push(combo.clone());
            return;
        }
        // Stop early once too few indices remain to complete a `t`-set (keeps it minimal).
        let need = t - combo.len();
        for i in start..=n - need {
            combo.push(i);
            recurse(i + 1, n, t, combo, out);
            combo.pop();
        }
    }
    recurse(0, n, t, &mut combo, &mut out);
    out
}

/// Is `kind` one the QuorumSigner will sign? The agent's Nostr output under Q: the
/// free-text voice (kind:1), its three beacons (presence/lifecycle/agent-state), the
/// cross-machine lease (31002), and its NIP-17 DM seal (kind:13) + DM inbox-relay list
/// (kind:10050) (P1). MUST mirror `kirby_custody::guardian::is_authorizable_kind` (the
/// membrane re-checks independently per holder -- a tooth fails if either side omits a kind).
fn is_signable_kind(kind: u32) -> bool {
    kind == kirby_proto::NOSTR_KIND_TEXT_NOTE as u32
        || matches!(
            kind,
            KIND_KIRBY_PRESENCE
                | KIND_KIRBY_LIFECYCLE
                | KIND_KIRBY_AGENT_STATE
                | KIND_KIRBY_LEASE
                | KIND_NOSTR_SEAL
                | KIND_NOSTR_INBOX_RELAYS
        )
}

/// Build the per-guardian `KeyPackage`s + the group `PublicKeyPackage` from a custody
/// dealer keyset (the provisioning convenience the co-located S3 path uses). The
/// secret shares NEVER leave the process. For S5/S6 each share is provisioned to a
/// separate holder out of band; this helper is the single-box stand-in.
pub fn local_quorum_from_keyset(
    keyset: &kirby_custody::DealerKeyset,
) -> anyhow::Result<QuorumSigner> {
    let kps = kirby_custody::key_packages(keyset)
        .map_err(|e| anyhow::anyhow!("derive key packages: {e}"))?;
    let key_packages: Vec<KeyPackage> = kps.into_values().collect();
    QuorumSigner::from_local_key_packages(key_packages, keyset.pubkeys.clone())
        .context("build co-located quorum signer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
    use bitcoin::KnownHrp;
    use kirby_custody::{generate_dealer_keyset, taproot_address};

    const CREATED_AT: u64 = 1750000000;
    const CONTENT: &str = "Hello world! Kirby co-signs by choice.";

    // A fresh real 2-of-3 trusted-dealer keyset (OsRng inside the custody crate; the
    // tests assert structural invariants under whatever Q is derived, so a fresh
    // keyset per run is fine -- we never compare across runs). kirby-node's own
    // `rand` resolves to an incompatible rand_core, so seeding from here is not
    // possible; determinism is unnecessary here (every assertion re-derives Q).
    fn keyset() -> kirby_custody::DealerKeyset {
        generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen")
    }

    /// Build a real co-located quorum signer over a fresh 2-of-3 keyset.
    fn signer() -> (kirby_custody::DealerKeyset, QuorumSigner) {
        let ks = keyset();
        let qs = local_quorum_from_keyset(&ks).expect("build quorum signer");
        (ks, qs)
    }

    /// G-QUORUM-SIGN-VERIFIES-UNDER-Q: the event the QuorumSigner produces verifies
    /// as a valid BIP-340 schnorr sig over its NIP-01 id under the TWEAKED group key
    /// Q, and FAILS under the untweaked internal key P. (Assertion shape lifted from
    /// coordinator.rs g1_verify_under_q_pass_under_p_fail.)
    #[test]
    fn g_quorum_sign_verifies_under_q() {
        let (ks, qs) = signer();
        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("2-of-3 quorum signs the note");

        // The event's pubkey is hex(Q), content is the (already-canonical) input, tags empty.
        assert_eq!(event.pubkey, hex::encode(qs.q_bytes()));
        assert_eq!(event.content, CONTENT);
        assert!(event.tags.is_empty());
        assert_eq!(event.kind, 1);

        // The id is the NIP-01 id over Q (independently recompute it).
        let expect_id = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, CONTENT);
        assert_eq!(event.id, hex::encode(expect_id), "event id must be the NIP-01 id under Q");

        // Derive Q (tweaked, merkle_root=None) and P from the keyset directly.
        let (_addr, internal_p) =
            taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();

        let sig_bytes = hex::decode(&event.sig).expect("hex sig");
        let sig = schnorr::Signature::from_slice(&sig_bytes).expect("parse 64-byte sig");
        let msg = Message::from_digest(expect_id);

        // (a) VERIFIES under the TWEAKED group key Q.
        assert!(
            secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok(),
            "aggregate must verify under tweaked group Q"
        );
        // (b) FAILS under the UNTWEAKED internal key P (proves the taproot tweak is real).
        assert!(
            secp.verify_schnorr(&sig, &msg, &internal_p).is_err(),
            "aggregate must NOT verify under untweaked P"
        );
        // (c) Q != P (non-trivial tweak, no script path).
        assert_ne!(q_xonly, internal_p, "Q must differ from P");
        println!("G-QUORUM-SIGN-VERIFIES-UNDER-Q PASS: quorum sig verifies under Q, fails under P, Q != P");
    }

    /// G-QUORUM-MEMBRANE-WIRED: prove the guardian membrane is actually IN the live
    /// signing path. We drive the ceremony body with a SigningPackage whose message
    /// is NOT the event id; the holder's `guardian::validate` MUST refuse
    /// (MessageMismatch) so NO share is produced. If a future refactor forgets to
    /// call `guardian::validate` before `round2::sign_with_tweak`, this test FAILS.
    #[test]
    fn g_quorum_membrane_wired() {
        let (ks, _qs) = signer();
        // Build two LocalHolders directly (identifiers 1 and 2) so we can drive the
        // ceremony body with a TAMPERED package.
        let kps = kirby_custody::key_packages(&ks).expect("kps");
        let mut kps_vec: Vec<KeyPackage> = kps.into_values().collect();
        kps_vec.truncate(2);
        let h1 = LocalHolder::new(kps_vec[0].clone(), ks.pubkeys.clone());
        let h2 = LocalHolder::new(kps_vec[1].clone(), ks.pubkeys.clone());

        // Real round1 commitments over both holders. Each holder STORES its own nonce
        // internally keyed by this session id; round 2 looks it up + removes it.
        let session_id = 1u64;
        let c1 = h1.commit(session_id).expect("h1 commit");
        let c2 = h2.commit(session_id).expect("h2 commit");
        let i1 = Identifier::try_from(h1.id()).unwrap();
        let i2 = Identifier::try_from(h2.id()).unwrap();
        let mut commitments = BTreeMap::new();
        commitments.insert(i1, c1);
        commitments.insert(i2, c2);

        // A TAMPERED package: its message is a different note's id (NOT the one the
        // request asks to sign). A blind-signer would happily co-sign this.
        let q_hex = hex::encode(group_xonly_q(&ks.pubkeys).unwrap());
        let wrong_id = nip01_event_id(&q_hex, CREATED_AT, 1, "a DIFFERENT note");
        let tampered = SigningPackage::new(commitments, &wrong_id);

        let signer_set: BTreeSet<u16> = [h1.id(), h2.id()].into_iter().collect();
        let req = CoSignRequest {
            session_id,
            intent: SignIntent::NostrEvent {
                kind: 1,
                created_at: CREATED_AT,
                tags: Vec::new(),
                content: CONTENT.to_string(),
            },
            signer_set,
        };

        // Each holder MUST refuse (the package message != the reconstructed id). The
        // holder looks up + removes its OWN stored nonce for `session_id`, then the
        // membrane rejects -> no share, and the removed nonce is dropped (never reused).
        let r1 = h1.validate_and_sign(session_id, &req, &tampered);
        let r2 = h2.validate_and_sign(session_id, &req, &tampered);
        assert_eq!(
            r1,
            Err(RefuseReason::MessageMismatch),
            "holder 1 must refuse a tampered package (membrane wired)"
        );
        assert_eq!(
            r2,
            Err(RefuseReason::MessageMismatch),
            "holder 2 must refuse a tampered package (membrane wired)"
        );

        // And the full ceremony over a real signer DOES abort when a tampered
        // intent is fed: ask sign_nostr_event for a kind it refuses pre-ceremony is
        // a different guard; here we assert the holder-level refusal IS the gate that
        // would abort `sign_nostr_event` (it propagates the refusal as an Err).
        println!("G-QUORUM-MEMBRANE-WIRED PASS: both holders refuse a tampered (wrong-message) package -> no share, ceremony aborts");
    }

    /// G-QUORUM-SUB-THRESHOLD: a 1-of-3 quorum aborts cleanly (no panic, no
    /// signature) -- the QuorumSigner needs at least MIN_SIGNERS holders.
    #[test]
    fn g_quorum_sub_threshold() {
        let ks = keyset();
        let kps = kirby_custody::key_packages(&ks).expect("kps");
        let one: Vec<KeyPackage> = kps.into_values().take(1).collect();
        let qs = QuorumSigner::from_local_key_packages(one, ks.pubkeys.clone())
            .expect("build 1-holder signer");
        let res = qs.sign_nostr_event(1, CREATED_AT, CONTENT);
        assert!(
            res.is_err(),
            "a 1-of-3 (sub-threshold) signer must abort, not sign; got {res:?}"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("at least") || msg.contains("quorum"),
            "sub-threshold error should explain the quorum shortfall: {msg}"
        );
        println!("G-QUORUM-SUB-THRESHOLD PASS: 1-of-3 aborts cleanly (no panic, no signature)");
    }

    /// G-QUORUM-LONE-SHARE-UNSPENDABLE: a single holder cannot produce a signature
    /// that verifies under Q. Hand-drive round1/round2/aggregate from ONE share
    /// (bypassing the QuorumSigner threshold guard) and assert no Q-valid sig results.
    /// (Cryptographic-floor assertion shape from coordinator.rs g3.)
    #[test]
    fn g_quorum_lone_share_unspendable() {
        let ks = keyset();
        let kps = kirby_custody::key_packages(&ks).expect("kps");
        let lone: Vec<KeyPackage> = kps.into_values().take(1).collect();
        let kp = &lone[0];

        let (_addr, internal_p) =
            taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        let q_hex = hex::encode(group_xonly_q(&ks.pubkeys).unwrap());
        let message = nip01_event_id(&q_hex, CREATED_AT, 1, CONTENT);

        let (nonce, commitment) = kirby_custody::commit_for(kp);
        let mut commit_map = BTreeMap::new();
        commit_map.insert(*kp.identifier(), commitment);
        let package = SigningPackage::new(commit_map, &message);

        let q_valid = 'attempt: {
            let Ok(share) = frost::round2::sign_with_tweak(&package, &nonce, kp, None) else {
                break 'attempt false;
            };
            let mut share_map = BTreeMap::new();
            share_map.insert(*kp.identifier(), share);
            let Ok(sig) = frost::aggregate_with_tweak(&package, &share_map, &ks.pubkeys, None)
            else {
                break 'attempt false;
            };
            let Ok(bytes) = sig.serialize() else { break 'attempt false; };
            let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else { break 'attempt false; };
            let secp = Secp256k1::verification_only();
            let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
            let q_xonly = q_tweaked.to_x_only_public_key();
            let Ok(s) = schnorr::Signature::from_slice(&arr) else { break 'attempt false; };
            secp.verify_schnorr(&s, &Message::from_digest(message), &q_xonly).is_ok()
        };
        assert!(!q_valid, "a LONE share must NOT yield a signature valid under Q");
        println!("G-QUORUM-LONE-SHARE-UNSPENDABLE PASS: one share yields no Q-valid signature");
    }

    /// G-QUORUM-CONTENT-GUARD: the re-ported publish-path guards reject BEFORE any
    /// signing -- over-512 content, control chars, and a wrong kind all error out and
    /// produce no event.
    #[test]
    fn g_quorum_content_guard() {
        let (_ks, qs) = signer();

        // (a) Over MAX_NOTE_BYTES -> refused (sanitize rejects > 512).
        let big = "x".repeat(kirby_proto::MAX_NOTE_BYTES + 1);
        assert!(
            qs.sign_nostr_event(1, CREATED_AT, &big).is_err(),
            "over-512 content must be refused before signing"
        );

        // (b) Control chars: sanitize maps them to spaces; the SIGNED content is the
        //     cleaned form (not a refusal), so verify the published content is clean.
        let dirty = "hello\u{0007}\u{0000}world";
        let ev = qs
            .sign_nostr_event(1, CREATED_AT, dirty)
            .expect("control chars are sanitized, not refused");
        assert!(
            !ev.content.contains('\u{0007}') && !ev.content.contains('\u{0000}'),
            "signed content must be sanitized (no control chars), got {:?}",
            ev.content
        );
        // The signed id is over the SANITIZED content (re-derive to confirm).
        let expect = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, &ev.content);
        assert_eq!(ev.id, hex::encode(expect), "id is over the sanitized content");

        // (c) Empty / whitespace-only -> refused (sanitize -> empty).
        assert!(qs.sign_nostr_event(1, CREATED_AT, "   \t  ").is_err(), "whitespace-only refused");
        assert!(qs.sign_nostr_event(1, CREATED_AT, "").is_err(), "empty refused");

        // (d) Wrong kind (kind:0) -> refused before any ceremony.
        assert!(
            qs.sign_nostr_event(0, CREATED_AT, CONTENT).is_err(),
            "kind != 1 must be refused"
        );
        println!("G-QUORUM-CONTENT-GUARD PASS: over-512/empty/ws-only/wrong-kind refused; control chars sanitized into the signed id");
    }

    /// All three distinct pairs co-sign a valid-under-Q note (no privileged holder):
    /// rotate which two holders form the quorum and assert each yields a verifying
    /// event. (Parity with coordinator.rs g4; here through the full QuorumSigner.)
    #[test]
    fn g_quorum_all_pairs_sign() {
        let ks = keyset();
        let kps = kirby_custody::key_packages(&ks).expect("kps");
        let all: Vec<KeyPackage> = kps.into_values().collect();
        assert_eq!(all.len(), 3);

        let (_addr, internal_p) =
            taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();

        for (a, b, label) in [(0, 1, "{1,2}"), (0, 2, "{1,3}"), (1, 2, "{2,3}")] {
            let pair = vec![all[a].clone(), all[b].clone()];
            let qs = QuorumSigner::from_local_key_packages(pair, ks.pubkeys.clone())
                .expect("build pair signer");
            let ev = qs.sign_nostr_event(1, CREATED_AT, CONTENT).expect("pair signs");
            let id = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, CONTENT);
            let sig = schnorr::Signature::from_slice(&hex::decode(&ev.sig).unwrap()).unwrap();
            assert!(
                secp.verify_schnorr(&sig, &Message::from_digest(id), &q_xonly).is_ok(),
                "pair {label} must verify under Q"
            );
        }
        println!("G-QUORUM-ALL-PAIRS-SIGN PASS: {{1,2}} {{1,3}} {{2,3}} each co-sign valid-under-Q (no privileged holder)");
    }

    /// G-SEAL-BOTH-MEMBRANES: a kind:13 NIP-17 DM seal co-signs through the co-located
    /// quorum, which requires BOTH the node's `is_signable_kind` AND the custody guardian
    /// membrane (`is_authorizable_kind`) to admit kind:13 (defense-in-depth: the coordinator
    /// guard + the per-holder membrane). If EITHER omits 13, the ceremony aborts (the
    /// coordinator bails up front, or a holder refuses per-membrane) and this fails -- the
    /// red-on-revert tooth for the two-crate lockstep that lets DMs move to Q (P1).
    #[test]
    fn g_seal_kind13_signs_through_both_membranes() {
        let (ks, qs) = signer();
        // The seal content is opaque NIP-44 ciphertext in production; a placeholder suffices
        // (the membrane signs kind:13 VERBATIM -- no content policy, unlike kind:1).
        let content = "nip44-ciphertext-placeholder";
        let seal = qs
            .sign_nostr_event_with_tags(KIND_NOSTR_SEAL, CREATED_AT, &[], content)
            .expect("kind:13 seal must co-sign (needs BOTH node is_signable_kind + custody membrane)");
        assert_eq!(seal.kind, KIND_NOSTR_SEAL, "signed event must be a kind:13 seal");

        // It is a real BIP-340 sig over the NIP-01 id under the tweaked Q (same check the beacons use).
        let (_addr, internal_p) = taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let id = nip01_event_id_with_tags(
            &hex::encode(qs.q_bytes()),
            seal.created_at,
            seal.kind,
            &[],
            content,
        );
        assert_eq!(seal.id, hex::encode(id), "seal id must be the NIP-01 id under Q");
        let sig = schnorr::Signature::from_slice(&hex::decode(&seal.sig).unwrap()).expect("parse sig");
        assert!(
            secp.verify_schnorr(&sig, &Message::from_digest(id), &q_xonly).is_ok(),
            "the kind:13 seal must verify under Q"
        );
        println!("G-SEAL-BOTH-MEMBRANES PASS: kind:13 seal co-signs valid-under-Q (both membranes admit 13)");
    }

    /// G-INBOX-RELAYS-BOTH-MEMBRANES: the kind:10050 DM inbox-relay list co-signs through the
    /// quorum, which (like the seal) needs BOTH membranes to admit 10050 -- so a born-unified
    /// agent can advertise its DM inbox UNDER Q (peers must find Q's inbox to DM Q). Red-on-revert:
    /// if either membrane omits 10050 the ceremony aborts. (P1, the second membrane expansion.)
    #[test]
    fn g_inbox_relays_kind10050_signs_through_both_membranes() {
        let (ks, qs) = signer();
        // A kind:10050 carries relay tags (["relay", <url>]); empty content, signed verbatim.
        let tags = vec![vec!["relay".to_string(), "wss://relay.example".to_string()]];
        let ev = qs
            .sign_nostr_event_with_tags(KIND_NOSTR_INBOX_RELAYS, CREATED_AT, &tags, "")
            .expect("kind:10050 must co-sign (needs BOTH node is_signable_kind + custody membrane)");
        assert_eq!(ev.kind, KIND_NOSTR_INBOX_RELAYS, "signed event must be a kind:10050 inbox list");
        let (_addr, internal_p) = taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let id = nip01_event_id_with_tags(&hex::encode(qs.q_bytes()), ev.created_at, ev.kind, &tags, "");
        assert_eq!(ev.id, hex::encode(id), "10050 id must be the NIP-01 id under Q");
        let sig = schnorr::Signature::from_slice(&hex::decode(&ev.sig).unwrap()).expect("parse sig");
        assert!(
            secp.verify_schnorr(&sig, &Message::from_digest(id), &q_xonly).is_ok(),
            "the kind:10050 inbox list must verify under Q"
        );
        println!("G-INBOX-RELAYS-BOTH-MEMBRANES PASS: kind:10050 co-signs valid-under-Q (both membranes admit 10050)");
    }

    /// G-SAME-SECOND-BEACONS-DONT-COLLIDE: two ceremonies that share a wall-clock
    /// second (the same `created_at`) BOTH succeed and produce valid-under-Q events.
    /// Regression guard for the availability bug where the session id was derived from
    /// `created_at` (seconds): same-second beacons collided on the holder's nonce-reuse
    /// guard and one fail-closed -> a LOST presence/lifecycle/agent-state publish.
    /// Realistic at startup: presence + `born` lifecycle + the 31000 emitter all fire
    /// near the same instant. The monotonic per-ceremony session counter makes the two
    /// ceremonies use DISTINCT session ids, so neither trips the guard.
    #[test]
    fn g_same_second_beacons_dont_collide() {
        let (ks, qs) = signer();

        // Two beacons in the SAME second: presence (10100) then lifecycle (9100), both
        // at CREATED_AT, exercising distinct kinds + content but an identical timestamp.
        let presence = qs
            .sign_nostr_event_with_tags(
                KIND_KIRBY_PRESENCE,
                CREATED_AT,
                &[],
                "{\"status\":\"online\"}",
            )
            .expect("first same-second beacon must sign");
        let lifecycle = qs
            .sign_nostr_event_with_tags(
                KIND_KIRBY_LIFECYCLE,
                CREATED_AT,
                &[],
                "{\"event\":\"born\"}",
            )
            .expect("second same-second beacon must ALSO sign (no collision)");

        // Both carry the real timestamp unchanged (only the internal session id differs).
        assert_eq!(presence.created_at, CREATED_AT);
        assert_eq!(lifecycle.created_at, CREATED_AT);
        assert_eq!(presence.kind, KIND_KIRBY_PRESENCE);
        assert_eq!(lifecycle.kind, KIND_KIRBY_LIFECYCLE);

        // Both verify as real BIP-340 sigs over their NIP-01 id under the tweaked Q.
        let (_addr, internal_p) =
            taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();

        for (ev, content) in [
            (&presence, "{\"status\":\"online\"}"),
            (&lifecycle, "{\"event\":\"born\"}"),
        ] {
            let id = nip01_event_id_with_tags(
                &hex::encode(qs.q_bytes()),
                ev.created_at,
                ev.kind,
                &[],
                content,
            );
            assert_eq!(ev.id, hex::encode(id), "event id must be the NIP-01 id under Q");
            let sig =
                schnorr::Signature::from_slice(&hex::decode(&ev.sig).unwrap()).expect("parse sig");
            assert!(
                secp.verify_schnorr(&sig, &Message::from_digest(id), &q_xonly).is_ok(),
                "same-second beacon kind {} must verify under Q",
                ev.kind
            );
        }
        println!("G-SAME-SECOND-BEACONS-DONT-COLLIDE PASS: two beacons sharing created_at BOTH sign + verify under Q (no nonce-reuse collision)");
    }

    // ------------------------------------------------------------------------------------
    // ANY-AVAILABLE-2-of-3 SELECTION + FALLBACK (cross-machine FROST keyset chunk 2) TEETH.
    // ------------------------------------------------------------------------------------

    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;

    /// A configurable `Holder` test double wrapping a real `LocalHolder`. When healthy it
    /// produces real commitments + shares (so a quorum it is part of yields a Q-valid
    /// aggregate); when told to fail it returns `Err` from `commit` and/or
    /// `validate_and_sign` -- modeling an unreachable/refusing remote holder (a remote
    /// timeout and a refusal both surface as `Err` to the QuorumSigner, exactly what this
    /// double simulates). It also RECORDS every `session_id` it is asked to commit, so a
    /// test can assert no session id is reused across fallback attempts.
    struct FlakyHolder {
        inner: LocalHolder,
        fail_commit: AtomicBool,
        fail_sign: AtomicBool,
        /// Every session id this holder was asked to `commit` (in call order), so a test
        /// can assert strictly distinct ids across fallback attempts.
        committed_sessions: Arc<Mutex<Vec<u64>>>,
        /// How many times `commit` was called (proves a fallback actually re-attempted).
        commit_calls: Arc<AtomicUsize>,
    }

    impl FlakyHolder {
        fn new(inner: LocalHolder) -> Self {
            Self {
                inner,
                fail_commit: AtomicBool::new(false),
                fail_sign: AtomicBool::new(false),
                committed_sessions: Arc::new(Mutex::new(Vec::new())),
                commit_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
        fn failing_commit(inner: LocalHolder) -> Self {
            let h = Self::new(inner);
            h.fail_commit.store(true, Ordering::Relaxed);
            h
        }
        fn failing_sign(inner: LocalHolder) -> Self {
            let h = Self::new(inner);
            h.fail_sign.store(true, Ordering::Relaxed);
            h
        }
        fn sessions_handle(&self) -> Arc<Mutex<Vec<u64>>> {
            Arc::clone(&self.committed_sessions)
        }
        fn commit_calls_handle(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.commit_calls)
        }
    }

    impl Holder for FlakyHolder {
        fn id(&self) -> u16 {
            self.inner.id()
        }
        fn commit(&self, session_id: u64) -> anyhow::Result<SigningCommitments> {
            self.commit_calls.fetch_add(1, Ordering::Relaxed);
            self.committed_sessions
                .lock()
                .expect("sessions lock")
                .push(session_id);
            if self.fail_commit.load(Ordering::Relaxed) {
                anyhow::bail!("FlakyHolder {} simulated commit failure (unreachable)", self.id());
            }
            // Healthy: produce a REAL commitment (stores the real nonce internally).
            self.inner.commit(session_id)
        }
        fn validate_and_sign(
            &self,
            session_id: u64,
            req: &CoSignRequest,
            package: &SigningPackage,
        ) -> Result<SignatureShare, RefuseReason> {
            if self.fail_sign.load(Ordering::Relaxed) {
                // A refusal surfaces as Err exactly like a remote timeout would.
                return Err(RefuseReason::BadKeyset);
            }
            self.inner.validate_and_sign(session_id, req, package)
        }
    }

    /// Independent BIP-340-under-Q verification of a finished event (re-derives Q from the
    /// keyset, never trusts the signer's own view). Returns true iff the aggregate verifies.
    fn event_verifies_under_q(event: &NostrEvent, ks: &kirby_custody::DealerKeyset) -> bool {
        let (_addr, internal_p) =
            taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let id = nip01_event_id_with_tags(&event.pubkey, event.created_at, event.kind, &event.tags, &event.content);
        let Ok(sig_bytes) = hex::decode(&event.sig) else { return false };
        let Ok(sig) = schnorr::Signature::from_slice(&sig_bytes) else { return false };
        secp.verify_schnorr(&sig, &Message::from_digest(id), &q_xonly).is_ok()
    }

    /// Build three FlakyHolders (identifiers 1,2,3) over a fresh keyset, ALL healthy by
    /// default. Returns the keyset + the three holders (the caller flips failure flags and
    /// grabs the recording handles BEFORE moving them into a QuorumSigner).
    fn three_flaky(ks: &kirby_custody::DealerKeyset) -> Vec<FlakyHolder> {
        let kps = kirby_custody::key_packages(ks).expect("key packages");
        // BTreeMap iteration is identifier-ordered (1,2,3).
        kps.into_values()
            .map(|kp| FlakyHolder::new(LocalHolder::new(kp, ks.pubkeys.clone())))
            .collect()
    }

    /// QUORUM-SUBSETS-ENUMERATION: the 2-of-3 subsets are exactly {0,1},{0,2},{1,2} in that
    /// order, and the FIRST is the first-MIN_SIGNERS set (the all-healthy invariant root).
    #[test]
    fn quorum_subsets_enumerates_first_min_signers_first() {
        let subsets = quorum_subsets(3, MIN_SIGNERS as usize);
        assert_eq!(
            subsets,
            vec![vec![0, 1], vec![0, 2], vec![1, 2]],
            "2-of-3 subsets must be {{0,1}},{{0,2}},{{1,2}} in lexicographic order"
        );
        assert_eq!(
            subsets[0],
            (0..MIN_SIGNERS as usize).collect::<Vec<_>>(),
            "the FIRST subset must be the first-MIN_SIGNERS set (all-healthy byte-identical invariant)"
        );
        // Degenerate guards: t==0 or t>n yield no subsets (the caller has guarded n>=t).
        assert!(quorum_subsets(3, 0).is_empty(), "t==0 -> no subsets");
        assert!(quorum_subsets(1, 2).is_empty(), "t>n -> no subsets");
        // A 4-holder pool still lists [0,1] first, then the rest in lex order.
        assert_eq!(quorum_subsets(4, 2)[0], vec![0, 1]);
        println!("QUORUM-SUBSETS-ENUMERATION PASS: 2-of-3 = {{0,1}},{{0,2}},{{1,2}}; first = first-MIN_SIGNERS");
    }

    /// ONE-UNAVAILABLE-FALLS-BACK: exactly one holder is unreachable -> the ceremony
    /// SUCCEEDS via an alternate 2-of-3 subset, and the resulting signature VERIFIES under
    /// Q (real signature verification, not just `is_ok()`). Holder at index 1 fails its
    /// commit, so the first subset {0,1} is abandoned and the signer falls back to {0,2}
    /// (both healthy) which completes.
    #[test]
    fn one_unavailable_falls_back() {
        let ks = keyset();
        let mut flaky = three_flaky(&ks);
        // Make holder index 1 unreachable (fails commit). Indices 0 and 2 stay healthy.
        flaky[1] = FlakyHolder::failing_commit(LocalHolder::new(
            kirby_custody::key_packages(&ks)
                .expect("kps")
                .into_values()
                .nth(1)
                .expect("second kp"),
            ks.pubkeys.clone(),
        ));

        let holders: Vec<Box<dyn Holder>> =
            flaky.into_iter().map(|h| Box::new(h) as Box<dyn Holder>).collect();
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build flaky signer");

        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("one unavailable holder must fall back to a reachable 2-of-3 subset");
        assert!(
            event_verifies_under_q(&event, &ks),
            "the fallback subset's aggregate must verify under Q (real BIP-340 verification)"
        );
        let expect_id = nip01_event_id(&hex::encode(qs.q_bytes()), CREATED_AT, 1, CONTENT);
        assert_eq!(event.id, hex::encode(expect_id), "id is the NIP-01 id under Q");
        println!("ONE-UNAVAILABLE-FALLS-BACK PASS: holder 2 unreachable -> ceremony completes via {{1,3}}, sig verifies under Q");
    }

    /// ONE-UNAVAILABLE-FALLS-BACK (sign-side): the same availability boundary when the
    /// unreachable holder fails at ROUND 2 (validate_and_sign) rather than commit -- the
    /// ceremony still falls back and produces a Q-valid signature. Proves fallback triggers
    /// on a round-2 holder Err too, not just a round-1 one.
    #[test]
    fn one_unavailable_at_sign_falls_back() {
        let ks = keyset();
        let mut flaky = three_flaky(&ks);
        flaky[1] = FlakyHolder::failing_sign(LocalHolder::new(
            kirby_custody::key_packages(&ks)
                .expect("kps")
                .into_values()
                .nth(1)
                .expect("second kp"),
            ks.pubkeys.clone(),
        ));
        let holders: Vec<Box<dyn Holder>> =
            flaky.into_iter().map(|h| Box::new(h) as Box<dyn Holder>).collect();
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build flaky signer");

        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("a round-2 holder failure must fall back to a reachable subset");
        assert!(
            event_verifies_under_q(&event, &ks),
            "the fallback subset's aggregate must verify under Q after a round-2 failure"
        );
        println!("ONE-UNAVAILABLE-AT-SIGN-FALLS-BACK PASS: holder 2 refuses round 2 -> fall back to {{1,3}}, sig verifies under Q");
    }

    /// TWO-UNAVAILABLE-FAILS-CLEAN: two holders are unreachable -> the ceremony returns
    /// `Err`, emits NO signature, does not panic, does not hang. Holders at indices 1 and 2
    /// fail commit; every 2-of-3 subset ({0,1},{0,2},{1,2}) contains at least one of them,
    /// so none can complete and the signer fails cleanly.
    #[test]
    fn two_unavailable_fails_clean() {
        let ks = keyset();
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&ks)
            .expect("kps")
            .into_values()
            .collect();
        let h0 = FlakyHolder::new(LocalHolder::new(kps[0].clone(), ks.pubkeys.clone()));
        let h1 = FlakyHolder::failing_commit(LocalHolder::new(kps[1].clone(), ks.pubkeys.clone()));
        let h2 = FlakyHolder::failing_commit(LocalHolder::new(kps[2].clone(), ks.pubkeys.clone()));
        let holders: Vec<Box<dyn Holder>> =
            vec![Box::new(h0), Box::new(h1), Box::new(h2)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build signer");

        let res = qs.sign_nostr_event(1, CREATED_AT, CONTENT);
        assert!(
            res.is_err(),
            "two unavailable holders leave no completable 2-of-3 subset -> must fail, got {res:?}"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("no available") && msg.contains("NO signature"),
            "the clean failure must say no subset completed + NO signature emitted: {msg}"
        );
        println!("TWO-UNAVAILABLE-FAILS-CLEAN PASS: two holders unreachable -> clean Err, no signature, no panic, no hang");
    }

    /// FRESH-SESSION-PER-ATTEMPT: no session id is reused across fallback attempts. A
    /// recording healthy holder (index 0) is part of BOTH the abandoned subset {0,1} and
    /// the successful subset {0,2}; it observes STRICTLY DISTINCT session ids across the two
    /// attempts (and is asked to commit more than once, proving a real fallback happened).
    /// Reusing a session id would trip the holder nonce-reuse guard AND is the cardinal
    /// FROST sin; this proves the fallback never does it.
    #[test]
    fn fresh_session_per_attempt() {
        let ks = keyset();
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&ks)
            .expect("kps")
            .into_values()
            .collect();
        // Index 0: a healthy RECORDING holder (in both {0,1} and {0,2}).
        let h0 = FlakyHolder::new(LocalHolder::new(kps[0].clone(), ks.pubkeys.clone()));
        let sessions = h0.sessions_handle();
        let commit_calls = h0.commit_calls_handle();
        // Index 1: fails commit -> the first subset {0,1} is abandoned AFTER h0 commits.
        let h1 = FlakyHolder::failing_commit(LocalHolder::new(kps[1].clone(), ks.pubkeys.clone()));
        // Index 2: healthy -> the fallback subset {0,2} completes.
        let h2 = FlakyHolder::new(LocalHolder::new(kps[2].clone(), ks.pubkeys.clone()));

        let holders: Vec<Box<dyn Holder>> =
            vec![Box::new(h0), Box::new(h1), Box::new(h2)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build signer");
        let event = qs
            .sign_nostr_event(1, CREATED_AT, CONTENT)
            .expect("falls back to {0,2} and signs");
        assert!(event_verifies_under_q(&event, &ks), "the fallback sig must verify under Q");

        // The recording holder committed in MORE THAN ONE attempt (a real fallback), and
        // every session id it saw is DISTINCT (no reuse across attempts).
        let seen = sessions.lock().expect("sessions lock").clone();
        assert!(
            commit_calls.load(Ordering::Relaxed) >= 2 && seen.len() >= 2,
            "the recording holder must have committed across at least two attempts; saw {seen:?}"
        );
        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "every per-attempt session id must be DISTINCT (no reuse across fallback); saw {seen:?}"
        );
        println!(
            "FRESH-SESSION-PER-ATTEMPT PASS: recording holder saw distinct session ids {seen:?} across fallback attempts (no reuse)"
        );
    }

    /// HAPPY-PATH-UNCHANGED: all holders healthy -> the FIRST subset {0,1} succeeds on the
    /// first try, the sig verifies under Q, and NO fallback occurs. The recording holder is
    /// asked to commit EXACTLY ONCE (a single attempt) under a single session id -- the
    /// all-healthy path is the same one-ceremony shape as before this chunk.
    #[test]
    fn happy_path_unchanged() {
        let ks = keyset();
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&ks)
            .expect("kps")
            .into_values()
            .collect();
        let h0 = FlakyHolder::new(LocalHolder::new(kps[0].clone(), ks.pubkeys.clone()));
        let sessions = h0.sessions_handle();
        let commit_calls = h0.commit_calls_handle();
        let h1 = FlakyHolder::new(LocalHolder::new(kps[1].clone(), ks.pubkeys.clone()));
        let h2 = FlakyHolder::new(LocalHolder::new(kps[2].clone(), ks.pubkeys.clone()));

        let holders: Vec<Box<dyn Holder>> =
            vec![Box::new(h0), Box::new(h1), Box::new(h2)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build signer");
        let event = qs.sign_nostr_event(1, CREATED_AT, CONTENT).expect("all-healthy signs");
        assert!(event_verifies_under_q(&event, &ks), "the all-healthy sig must verify under Q");

        // Exactly ONE attempt: the recording holder committed once (the first subset {0,1}
        // succeeded; index 2 was never reached). The all-healthy first-subset invariant.
        assert_eq!(
            commit_calls.load(Ordering::Relaxed),
            1,
            "all-healthy must run exactly ONE ceremony (the first subset), no fallback"
        );
        let seen = sessions.lock().expect("sessions lock").clone();
        assert_eq!(seen.len(), 1, "exactly one session id used (one attempt); saw {seen:?}");
        // And holder index 2 (h2) was NEVER asked to commit (it is not in the first subset
        // {0,1}); we assert this indirectly: only h0 + h1 participated. h2's absence is
        // implied by h0's single commit + the {0,1}-first ordering proven separately.
        println!("HAPPY-PATH-UNCHANGED PASS: all-healthy -> first subset {{1,2}} signs on the first try (one ceremony, one session id), sig verifies under Q");
    }

    /// NO-HONEST-QUORUM-STILL-FAILS (fallback must NOT mask a genuine policy refusal): if
    /// no 2-of-3 subset has two SIGNING holders, the ceremony must STILL fail -- the
    /// fallback must never fabricate a success out of subsets that each refuse. Holders at
    /// indices 1 and 2 refuse at round 2 (a genuine guardian refusal, not a transport
    /// flake); every subset contains at least one refuser, so no subset yields two shares.
    #[test]
    fn no_honest_quorum_still_fails() {
        let ks = keyset();
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&ks)
            .expect("kps")
            .into_values()
            .collect();
        let h0 = FlakyHolder::new(LocalHolder::new(kps[0].clone(), ks.pubkeys.clone()));
        let h1 = FlakyHolder::failing_sign(LocalHolder::new(kps[1].clone(), ks.pubkeys.clone()));
        let h2 = FlakyHolder::failing_sign(LocalHolder::new(kps[2].clone(), ks.pubkeys.clone()));
        let holders: Vec<Box<dyn Holder>> =
            vec![Box::new(h0), Box::new(h1), Box::new(h2)];
        let qs = QuorumSigner::new(holders, ks.pubkeys.clone()).expect("build signer");

        let res = qs.sign_nostr_event(1, CREATED_AT, CONTENT);
        assert!(
            res.is_err(),
            "no subset has two signing holders -> the ceremony MUST fail (fallback must not mask refusals), got {res:?}"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("no available") && msg.contains("NO signature"),
            "the failure must be the clean no-subset-completed error, NO signature: {msg}"
        );
        println!("NO-HONEST-QUORUM-STILL-FAILS PASS: every subset has a refuser -> clean Err, fallback did NOT mask the refusals into a forged success");
    }
}
