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
    KIND_KIRBY_LIFECYCLE, KIND_KIRBY_PRESENCE,
};
use kirby_custody::group_xonly_q;

/// The S3 quorum size (a 2-of-3 group: any 2 of the 3 holders co-sign).
const MIN_SIGNERS: u16 = 2;

/// Map a FROST `Identifier` to its u16 wire form (the same projection the guardian
/// membrane uses; sound for trusted-dealer identifiers 1..=n). A holder's `id()`
/// returns this u16 so the call site can build the membrane's `signer_set` and
/// `my_identifier` without depending on the frost `Identifier` type.
fn identifier_to_u16(id: &Identifier) -> u16 {
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
    /// swaps co-located holders for remote ones without changing `sign_nostr_event`.
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
    /// COST NOTE (S5/S6): this runs a full quorum ceremony PER beacon. For S3 the holders
    /// are co-located in-process (sub-ms), so a per-presence-interval ceremony is fine.
    /// When holders move off-box (S5/S6), a quorum ceremony on every presence beacon is
    /// too expensive on the wire -- that lane MUST adopt a cheaper presence cadence or a
    /// short-lived session sub-key delegated by Q. Do NOT build that here.
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
                 {KIND_KIRBY_PRESENCE}/{KIND_KIRBY_LIFECYCLE}/{KIND_KIRBY_AGENT_STATE}, and the \
                 cross-machine lease {KIND_KIRBY_LEASE} are signable"
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

        // 3. Pick the signer set: the FIRST `MIN_SIGNERS` holders.
        //
        //    S3 SIMPLIFICATION (known): this is "2-of-the-first-2", NOT "any available
        //    2-of-3". The ceremony always uses `holders[0..MIN_SIGNERS]` and ABORTS on
        //    any refusal or commit failure -- it does not fall back to a different
        //    holder. That is fine for S3, where all 3 holders are co-located in this
        //    process and always healthy. S5/S6 (remote holders that CAN be unavailable
        //    or slow) MUST replace this with any-available-2-of-3 selection: try a
        //    quorum, and on a holder timeout/refusal fall back to another subset +
        //    retry, only failing when no 2-of-3 subset is reachable. Do NOT assume the
        //    first MIN_SIGNERS are alive once holders are off-box.
        if self.holders.len() < MIN_SIGNERS as usize {
            anyhow::bail!(
                "QuorumSigner has {} holders, need at least {MIN_SIGNERS} to form a quorum",
                self.holders.len()
            );
        }
        let participants: Vec<&Box<dyn Holder>> =
            self.holders.iter().take(MIN_SIGNERS as usize).collect();

        // The claimed signer set the membrane cross-checks against the package.
        let signer_set: BTreeSet<u16> = participants.iter().map(|h| h.id()).collect();
        if signer_set.len() < MIN_SIGNERS as usize {
            // Two holders aliased to the same u16: refuse rather than form a
            // degenerate quorum (mirrors the coordinator's dup-signer guard).
            anyhow::bail!("quorum holders collapsed to fewer than {MIN_SIGNERS} distinct identifiers");
        }

        // A per-ceremony session id: each participating holder stores its own nonce
        // under this id in `commit` and removes+drops it in `validate_and_sign`. It is
        // a MONOTONIC counter (NOT `created_at`): two ceremonies that start in the same
        // second would otherwise share a session id and the holder's nonce-reuse guard
        // would fail-close the second one (a clobber would strand a live nonce) -> a
        // LOST publish. Same-second concurrent beacons are realistic at startup
        // (presence + `born` + the 31000 emitter), so distinct ceremonies MUST get
        // distinct session ids while the guard stays meaningful (a genuine double-use
        // of one id still refuses). The published event's `created_at` is unchanged --
        // only this internal ceremony id differs. No `SigningNonces` is ever held by
        // the QuorumSigner.
        let session_id = self.next_session.fetch_add(1, Ordering::Relaxed);

        // 4a. Round 1: each participating holder GENERATES + STORES its OWN fresh
        //     single-use nonce and returns ONLY its public commitment (the secret nonce
        //     never crosses the seam -- the remote-readiness contract).
        let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for holder in &participants {
            let commitment = holder.commit(session_id).with_context(|| {
                format!("holder {} round-1 commit (session {session_id})", holder.id())
            })?;
            // Recover the frost Identifier for the package map from the holder's u16.
            // The trusted-dealer identifiers are 1..=n, so u16 -> Identifier is exact.
            let ident = Identifier::try_from(holder.id())
                .map_err(|e| anyhow::anyhow!("holder id {} is not a valid FROST identifier: {e}", holder.id()))?;
            commitments.insert(ident, commitment);
        }

        // 4b. Assemble exactly ONE SigningPackage over the event id.
        let package = SigningPackage::new(commitments, &event_id);

        // 4c. THE MEMBRANE + round 2: each participating holder removes its own nonce,
        //     validates, THEN signs. The QuorumSigner passes NO nonce -- the holder
        //     looks up + drops its own (used-once). The typed request the membrane
        //     re-reconstructs and equality-checks.
        let req = CoSignRequest {
            session_id, // routing/dedupe only (not security-load-bearing)
            intent: SignIntent::NostrEvent {
                kind,
                created_at,
                tags: signed_tags.clone(),
                content: signed_content.clone(),
            },
            signer_set: signer_set.clone(),
        };
        let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        for holder in &participants {
            let share = holder
                .validate_and_sign(session_id, &req, &package)
                .map_err(|reason| {
                    anyhow::anyhow!(
                        "holder {} REFUSED to co-sign ({reason:?}); ceremony aborted, NO signature emitted",
                        holder.id()
                    )
                })?;
            let ident = Identifier::try_from(holder.id())
                .map_err(|e| anyhow::anyhow!("holder id to identifier: {e}"))?;
            shares.insert(ident, share);
        }

        // 5. Aggregate the tweaked shares -> the 64-byte BIP-340 signature under Q.
        let group_sig = frost::aggregate_with_tweak(&package, &shares, &self.pubkeys, None)
            .map_err(|e| anyhow::anyhow!("aggregate FROST shares: {e}"))?;
        let sig_bytes = group_sig
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize aggregate signature: {e}"))?;
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a 64-byte BIP-340 signature, got {}", sig_bytes.len()))?;

        // Assemble the finished event: pubkey = hex(Q), the signed content (sanitized for
        // kind:1, verbatim JSON for a beacon), the signed tags, the aggregate sig, the id.
        Ok(NostrEvent {
            id: hex::encode(event_id),
            pubkey: q_hex,
            created_at,
            kind,
            tags: signed_tags,
            content: signed_content,
            sig: hex::encode(sig),
        })
    }
}

/// Is `kind` one the QuorumSigner will sign? The agent's PUBLIC Nostr output: the
/// free-text voice (kind:1) PLUS its three beacons (presence/lifecycle/agent-state),
/// all under Q. Mirrors `kirby_custody::guardian`'s authorizable-kind set (the membrane
/// re-checks independently per holder).
fn is_signable_kind(kind: u32) -> bool {
    kind == kirby_proto::NOSTR_KIND_TEXT_NOTE as u32
        || matches!(
            kind,
            KIND_KIRBY_PRESENCE | KIND_KIRBY_LIFECYCLE | KIND_KIRBY_AGENT_STATE | KIND_KIRBY_LEASE
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
}
