//! S3b: the GUARDIAN-VALIDATION MEMBRANE — a pure, no-network validation gate a
//! FROST guardian runs BEFORE `round2::sign_with_tweak`, so it NEVER blind-signs.
//!
//! The harness binary `frost-nostr-cosign` (and the C-6 seam) currently contribute a
//! signature share for WHATEVER message the coordinator put into the `SigningPackage`
//! (see the "DEMO LIMITATION ... THIS GUARDIAN BLIND-SIGNS" comment in
//! `src/bin/frost-nostr-cosign.rs`). That is the single most dangerous gap in a
//! per-agent FROST live signer: a malicious or buggy coordinator can get an honest
//! quorum to sign a DIFFERENT note, or a Bitcoin sighash disguised as a Nostr event.
//!
//! `validate` closes that gap. It is ADDITIVE: it does not touch the C-1..C-6 crypto
//! paths (seam.rs / coordinator.rs / spend.rs). It is PURE and NO-NETWORK so it is
//! fast and unit-testable. The contract is simple and absolute:
//!
//!   A guardian refuses to sign anything it cannot INDEPENDENTLY RECONSTRUCT from
//!   its OWN PublicKeyPackage plus a typed intent.
//!
//! The load-bearing line is the message-equality check (step 3): the guardian derives
//! Q from its own `PublicKeyPackage` (NEVER a Q the coordinator asserts), reconstructs
//! the NIP-01 event id from the typed intent under that Q, and requires
//! `package.message() == expected_id`. If the coordinator put anything else in the
//! package — a different note, a Bitcoin sighash, arbitrary bytes — the guardian
//! refuses.
//!
//! CALLER PROVENANCE (load-bearing): the caller MUST pass its OWN locally-persisted
//! `pubkeys` (`PublicKeyPackage`) and a `min_signers` derived from its OWN `KeyPackage` —
//! NEVER values supplied by the coordinator / over the wire. `validate` derives Q SOLELY
//! from the passed `pubkeys`; feeding it wire-supplied pubkeys would let a malicious
//! coordinator pick a Q that makes its forged message reconstruct, defeating the entire
//! membrane.
//!
//! INTEGRATION STATUS (S3b): this slice only DEFINES and PROVES the membrane in isolation.
//! It is NOT yet wired into any live signer. The harness binary
//! `src/bin/frost-nostr-cosign.rs` STILL BLIND-SIGNS by design (see its own
//! "DEMO LIMITATION" comment) and is intentionally untouched here. S3c MUST make the
//! kirby-node holder loop call `guardian::validate` and refuse on any `Err` BEFORE it ever
//! calls `round2::sign_with_tweak`. Until that wiring lands, the membrane is dormant.

use std::collections::BTreeSet;

use frost_secp256k1_tr as frost;
use frost::keys::PublicKeyPackage;
use frost::{Identifier, SigningPackage};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::cosign_net::nip01_event_id;
use crate::cosign_net::nip01_event_id_with_tags;
use crate::group_xonly_q;

/// The Nostr "short text note" kind (the agent's free-text voice). The ONLY kind whose
/// content runs through the note content-policy (`content_is_clean`); the beacon kinds
/// carry machine-generated JSON state, not free text, so that policy does not apply.
pub const NOSTR_TEXT_NOTE_KIND: u32 = 1;

/// The Kirby PRESENCE beacon kind (10100): a REPLACEABLE liveness heartbeat.
pub const KIND_KIRBY_PRESENCE: u32 = 10100;
/// The Kirby LIFECYCLE event kind (9100): the signed born/died log.
pub const KIND_KIRBY_LIFECYCLE: u32 = 9100;
/// The Kirby AGENT-STATE kind (31000): the ADDRESSABLE live "Kirby face".
pub const KIND_KIRBY_AGENT_STATE: u32 = 31000;
/// The Kirby cross-machine LEASE kind (31002): the ADDRESSABLE relay-native failover
/// claim. MUST match `kirby_proto::KIND_KIRBY_LEASE` (custody cannot import kirby_proto,
/// so this is a hand-maintained mirror like the beacon kinds above). Like the beacons it
/// carries machine-generated JSON (`{ agent_id, holder_node_id, term, issued_at }`), so it
/// is signed VERBATIM (the note sanitizer is kind:1-only) and the membrane's real gate is
/// the id-over-content-and-tags equality check.
pub const KIND_KIRBY_LEASE: u32 = 31002;

/// The NIP-59 SEAL kind (13): a NIP-17 direct-message seal authored by Q (the DM-under-Q
/// path, P1). Its content is NIP-44-ENCRYPTED (opaque ciphertext), so -- like the beacons
/// and unlike kind:1 -- no content policy applies; the membrane's gate is the
/// id-over-content-and-tags equality. Authorizing it lets Q author DMs, which is within the
/// agent's existing DM capability (a compromised coordinator can at most get Q to author an
/// encrypted DM). MUST stay in lockstep with `kirby-node`'s `quorum_signer::is_signable_kind`
/// (a tooth fails if either membrane omits 13).
pub const KIND_NOSTR_SEAL: u32 = 13;

/// The NIP-17 DM inbox-relay list kind (10050): where peers should send this agent's NIP-17
/// DMs. On the born-unified path (P1) it is published UNDER Q so peers DM Q. Like the seal
/// and the beacons it is a public Q-signed event (JSON, no content policy); the membrane gate
/// is the id-over-content-and-tags equality. Authorized alongside kind:13 so a born-unified
/// agent can advertise its DM inbox under Q. MUST stay in lockstep with `kirby-node`'s
/// `quorum_signer::is_signable_kind` (a tooth fails if either membrane omits it).
pub const KIND_NOSTR_INBOX_RELAYS: u32 = 10050;

/// S3e: is `kind` one a guardian will authorize? The agent's PUBLIC Nostr output is its
/// voice (kind:1) PLUS its three public beacons (presence/lifecycle/agent-state) PLUS its
/// cross-machine lease (31002) PLUS its NIP-17 DM seal (kind:13) and DM inbox-relay list
/// (kind:10050) (P1) -- all signed by the same group key Q ("Q signs everything", gudnuf's
/// decision A). The lease rides the SAME membrane: a node cannot get the quorum to co-sign a
/// lease for an agent whose shares it does not hold. Any other kind (and the future
/// BitcoinSpend intent) needs its own reconstruction + policy and is refused as `BadKind`.
fn is_authorizable_kind(kind: u32) -> bool {
    matches!(
        kind,
        NOSTR_TEXT_NOTE_KIND
            | KIND_KIRBY_PRESENCE
            | KIND_KIRBY_LIFECYCLE
            | KIND_KIRBY_AGENT_STATE
            | KIND_KIRBY_LEASE
            | KIND_NOSTR_SEAL
            | KIND_NOSTR_INBOX_RELAYS
    )
}

/// Maximum content length (bytes, UTF-8) a guardian will co-sign for a kind:1 note.
///
/// MUST match `kirby_proto::MAX_NOTE_BYTES`.
///
/// SYNC REQUIREMENT: kirby-node's publish path uses `kirby_proto::sanitize_note_for_publish`
/// to clamp/sanitize note content before it is published, and `kirby_proto::MAX_NOTE_BYTES`
/// bounds the result. Custody is a separate crate and CANNOT import kirby_proto, so this
/// constant and `sanitize_note` below are a deliberate, hand-maintained REPLICA of that
/// canonical implementation (see `sanitize_note`). These MUST stay byte-for-byte in sync:
/// if kirby_proto's sanitizer changes its cap or its algorithm, this constant and
/// `sanitize_note` must be updated to match. STRONGLY RECOMMENDED FUTURE UNIFICATION: lift
/// the policy into a shared `nostr-note-policy` crate that genome, daemon, and guardian all
/// depend on, so there is exactly ONE implementation of "clean note content".
pub const MAX_NOTE_BYTES: usize = 512;

/// A typed co-sign request a guardian receives. The guardian validates THIS against the
/// coordinator's `SigningPackage`; it never trusts the package's message bytes directly.
///
/// SERDE (S5/S6): this is `Serialize`/`Deserialize` so a coordinator can send the TYPED
/// intent to a `RemoteHolder` over the seam (the holder runs the membrane on its OWN box
/// and re-reconstructs the id from THIS, never trusting a Q the coordinator asserts). The
/// request carries NO secret material -- only the public intent + the claimed signer set --
/// so serializing it leaks nothing a relay observer could not already infer from the event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoSignRequest {
    /// The signing-session id (routing/dedupe; not security-load-bearing here).
    pub session_id: u64,
    /// What the guardian is being asked to authorize, in typed form.
    pub intent: SignIntent,
    /// The claimed quorum: the set of FROST identifiers (as u16) participating.
    pub signer_set: BTreeSet<u16>,
}

/// The typed intent a guardian can independently reconstruct into a signed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignIntent {
    /// A Nostr event. S3e accepts the agent's voice (kind:1) AND its three public
    /// beacons (10100 presence / 9100 lifecycle / 31000 agent-state); the guardian
    /// recomputes the NIP-01 event id under its OWN Q -- over `kind`, `created_at`,
    /// `tags`, and `content` -- and requires the package message to equal it. `tags` is
    /// part of the signed id, so a beacon's tags are reconstructed and equality-checked
    /// exactly like its content. The note content-policy (`content_is_clean`) applies
    /// ONLY to kind:1; beacon JSON is signed verbatim (never run through the note
    /// sanitizer).
    NostrEvent {
        kind: u32,
        created_at: u64,
        /// The event's tag array (each tag a `["name","value",...]`). Empty for a plain
        /// kind:1 note; populated for the beacons.
        tags: Vec<Vec<String>>,
        content: String,
    },
    // FUTURE (not implemented in S3b): a `BitcoinSpend` variant carrying the typed spend
    // (inputs/outputs/amounts) so the guardian can re-derive the BIP-341 sighash itself
    // and require `package.message() == that sighash` — the same membrane shape, a
    // different reconstruction. Deliberately not added yet so there is no half-built
    // money path; until it exists, any non-NostrEvent message simply cannot be matched
    // and is refused.
}

/// Why a guardian refused to sign. Every refusal is a HARD STOP: the guardian must not
/// emit a signature share.
///
/// SERDE (S5/S6): `Serialize`/`Deserialize` so a `RemoteHolder` can carry a holder's
/// refusal back to the coordinator over the seam (an opaque refusal frame) -- the
/// coordinator then aborts the ceremony exactly as it does for a co-located refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefuseReason {
    /// `package.message()` does not equal the id the guardian independently reconstructed
    /// from the typed intent under its OWN Q. The single most important refusal: it stops
    /// a malicious coordinator getting the quorum to sign a different note OR a Bitcoin
    /// sighash disguised as a note.
    MessageMismatch,
    /// This guardian's own identifier is not in the claimed `signer_set`.
    NotInSignerSet,
    /// The claimed `signer_set` (or the package's commitments) has fewer than
    /// `min_signers` participants.
    SubThreshold,
    /// A signer identifier appears more than once across the request/package (would reuse
    /// a single-use nonce), or the claimed set and the package's commitment set disagree.
    DuplicateSigner,
    /// The intent's `kind` is not a kind this membrane will authorize (kind:1 + the three
    /// Kirby beacon kinds 10100/9100/31000; everything else is refused).
    BadKind,
    /// The intent's content is not already in canonical (publish-path) form: it is not
    /// byte-identical to what `kirby_proto::sanitize_note_for_publish` would emit (it
    /// contains a control char / U+2028 / U+2029, has collapsible whitespace, is empty,
    /// or exceeds `MAX_NOTE_BYTES`). A guardian must never co-sign content the publish
    /// path would rewrite — rewriting means signing something different = blind-signing.
    DirtyContent,
    /// Q could not be derived from the guardian's own `PublicKeyPackage` (a malformed
    /// keyset). Refuse rather than sign under an unknown key.
    BadKeyset,
    /// Two DISTINCT FROST `Identifier`s in the package's signing commitments collapse to
    /// the same u16 under `identifier_to_u16`. Sound only for trusted-dealer identifiers
    /// 1..=n; under custom/DKG identifiers an alias would weaken the signer-set
    /// cross-check, so the guardian refuses rather than trust a possibly-collapsed set.
    IdentifierAliasing,
}

/// A deliberate, hand-maintained REPLICA of `kirby_proto::sanitize_note_for_publish`
/// (the SINGLE SOURCE OF TRUTH on the publish path). Custody cannot import kirby_proto,
/// so this reproduces its algorithm exactly:
///
///   1. map every `char` that `is_control()` (C0/C1 control range, incl. `\n`/`\t`) OR
///      is U+2028 / U+2029 to a single ASCII space;
///   2. collapse runs of whitespace via `split_whitespace().join(" ")` (this also trims
///      leading/trailing whitespace);
///   3. reject empty (-> None);
///   4. reject length (UTF-8 bytes) > `MAX_NOTE_BYTES` (-> None).
///
/// Returns the canonical form on success, `None` on rejection. Kept in sync BY HAND with
/// kirby_proto; STRONGLY RECOMMEND a future shared `nostr-note-policy` crate so genome,
/// daemon, and guardian share ONE implementation.
///
/// Codebase philosophy: the genome and the daemon each sanitize independently (neither
/// trusts the other); this guardian is a THIRD independent enforcement point.
fn sanitize_note(raw: &str) -> Option<String> {
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
    let clean = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        return None;
    }
    if clean.len() > MAX_NOTE_BYTES {
        return None;
    }
    Some(clean)
}

/// Content-policy check: returns true iff `content` is safe to co-sign as a kind:1 note.
///
/// REJECT-UNLESS-CANONICAL: content is clean ONLY if it is already byte-identical to its
/// sanitized form (`sanitize_note`). A guardian must NEVER co-sign content that the
/// publish path would rewrite, because the publish path computes the event id over its
/// own sanitized output: if the guardian validated/co-signed the raw string while the
/// publisher emits a rewritten string, the published event id would differ from the
/// validated id and the aggregate signature would not match the published note. Silently
/// "cleaning" and signing a different string than presented is itself a form of
/// blind-signing — so we refuse `DirtyContent` unless the content is already canonical.
pub fn content_is_clean(content: &str) -> bool {
    matches!(sanitize_note(content), Some(c) if c == content)
}

/// Map a FROST `Identifier` to its u16 wire form. ZF serializes an Identifier as a
/// 32-byte big-endian scalar; the default dealer identifiers are 1..=n, so the value
/// lives in the last two bytes. Mirrors `identifier_to_u16` in the harness binary.
///
/// WARNING: this truncation is ONLY sound for trusted-dealer identifiers 1..=n (the
/// default keygen path). Two DISTINCT custom/DKG identifiers can collide in their last
/// two bytes and ALIAS to the same u16, which would weaken the signer-set cross-check. A
/// DKG / custom-identifier upgrade MUST switch the signer-set checks to operate on the
/// full `Identifier` type instead of u16. Until then, `validate` guards against aliasing
/// by refusing whenever the u16 projection collapses two distinct Identifiers.
fn identifier_to_u16(id: &Identifier) -> u16 {
    let bytes = id.serialize();
    let n = bytes.len();
    u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])
}

/// Validate a co-sign request BEFORE `round2::sign_with_tweak`. `Ok(())` is the ONLY
/// value that means "safe to sign". Pure, no network, no secret material touched.
///
/// CALLER PROVENANCE (load-bearing): `pubkeys` and `min_signers` MUST come from the
/// caller's OWN locally-persisted keyset / `KeyPackage`, NEVER from the coordinator or the
/// wire. Q is derived solely from the passed `pubkeys`; passing coordinator-supplied
/// pubkeys would defeat the membrane.
///
/// INTEGRATION (S3b): this function is NOT yet called by any live signer. The harness
/// binary still blind-signs by design; S3c MUST insert a `guardian::validate` call (and
/// refuse on `Err`) into the kirby-node holder loop ahead of `round2::sign_with_tweak`.
///
/// Validation order (each step is a hard gate):
///   1. Derive Q from the guardian's OWN `pubkeys` (never a Q the coordinator asserts).
///   2. For a NostrEvent: require kind == 1; run the content policy; recompute the
///      NIP-01 event id under Q.
///   3. EQUALITY CHECK: require `package.message() == expected_id`.
///   4. Signer-set checks: this guardian in the set; set size >= min_signers; guard u16
///      aliasing; and the claimed set equals the package's committed set exactly.
pub fn validate(
    req: &CoSignRequest,
    package: &SigningPackage,
    pubkeys: &PublicKeyPackage,
    my_identifier: u16,
    min_signers: u16,
) -> Result<(), RefuseReason> {
    // 1. Derive Q from the guardian's OWN PublicKeyPackage. NEVER trust a Q the
    //    coordinator asserts: the whole point of the membrane is independent reconstruction.
    let q = group_xonly_q(pubkeys).map_err(|_| RefuseReason::BadKeyset)?;
    let q_hex = hex::encode(q);

    // 2. Reconstruct the message from the typed intent under Q.
    let expected_id: [u8; 32] = match &req.intent {
        SignIntent::NostrEvent {
            kind,
            created_at,
            tags,
            content,
        } => {
            // kind:1 (voice) + the three Kirby beacon kinds are authorizable; nothing else.
            if !is_authorizable_kind(*kind) {
                return Err(RefuseReason::BadKind);
            }
            // CONTENT POLICY (S3e): the note sanitizer applies ONLY to the free-text
            // voice (kind:1). The beacons (10100/9100/31000) carry machine-generated
            // JSON state, not user prose, so they are NOT run through the note sanitizer
            // -- the JSON is signed verbatim (running `split_whitespace`/collapse on it
            // would corrupt the payload). The guardian still re-derives + equality-checks
            // their id (over content AND tags), which is the real anti-blind-sign gate.
            if *kind == NOSTR_TEXT_NOTE_KIND && !content_is_clean(content) {
                return Err(RefuseReason::DirtyContent);
            }
            // Reconstruct over content AND tags: for a beacon the tags are part of the
            // signed id, so a coordinator that altered a tag would fail the equality check.
            nip01_event_id_with_tags(&q_hex, *created_at, *kind, tags, content)
        }
    };

    // 3. EQUALITY CHECK (the most load-bearing line): the package's message MUST equal
    //    the id the guardian independently reconstructed. This is what stops a malicious
    //    coordinator getting the quorum to sign a different note OR a Bitcoin sighash
    //    disguised as a note.
    if package.message().as_slice() != expected_id.as_slice() {
        return Err(RefuseReason::MessageMismatch);
    }

    // 4. Signer-set checks.
    // 4a. This guardian must actually be in the claimed quorum.
    if !req.signer_set.contains(&my_identifier) {
        return Err(RefuseReason::NotInSignerSet);
    }
    // 4b. The quorum must be at least threshold. (A BTreeSet has already deduped the
    //     claimed set, so this counts DISTINCT signers.)
    if req.signer_set.len() < min_signers as usize {
        return Err(RefuseReason::SubThreshold);
    }
    // 4c. Cross-check against the package's signing_commitments. NOTE: `validate` operates
    //     on ALREADY-deserialized, already-deduped structures — `req.signer_set` is a
    //     `BTreeSet<u16>` and the package's commitments are a `BTreeMap<Identifier, _>`, so
    //     any LITERAL wire-duplicate has already collapsed before we see it. This check
    //     therefore proves "the claimed signer set EQUALS the package's actual committed
    //     set", NOT "no literal duplicate appeared on the wire before deserialization".
    //     Rejecting literal wire-level duplicates is the responsibility of the S3c
    //     transport/deserialization layer (which sees the raw frames).
    //
    //     First, guard against u16 ALIASING: `identifier_to_u16` is only injective for
    //     trusted-dealer identifiers 1..=n. If two DISTINCT package Identifiers collapse to
    //     the same u16, the u16 set would be smaller than the real participant set and the
    //     cross-check would be unsound — refuse `IdentifierAliasing`.
    let pkg_id_count = package.signing_commitments().keys().count();
    let pkg_ids: BTreeSet<u16> = package
        .signing_commitments()
        .keys()
        .map(identifier_to_u16)
        .collect();
    if pkg_ids.len() < pkg_id_count {
        return Err(RefuseReason::IdentifierAliasing);
    }
    if pkg_ids.len() < min_signers as usize {
        return Err(RefuseReason::SubThreshold);
    }
    // A size disagreement (or different membership) between the claimed set and the
    // package's committed quorum means the request lied about who is signing -> refuse
    // `DuplicateSigner`.
    if pkg_ids != req.signer_set {
        return Err(RefuseReason::DuplicateSigner);
    }

    // 5. Only here is it safe to sign.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::key_packages;
    use crate::{generate_dealer_keyset_with_rng, group_xonly_q};
    use frost_secp256k1_tr as frost;
    use frost::keys::KeyPackage;
    use frost::round1::{SigningCommitments, SigningNonces};
    use frost::Identifier;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::BTreeMap;

    // Non-secret, zero-funds reproducible fixture seed for the guardian-membrane tests.
    const SEED: [u8; 32] = *b"kirby-custody-s3b-guardian-seed!";
    const CREATED_AT: u64 = 1750000000;
    const CONTENT: &str = "Hello world! Kirby co-signs by choice.";

    /// Build a 2-of-3 keyset + the two-signer KeyPackages (identifiers 1 and 2).
    fn keyset_and_two() -> (crate::DealerKeyset, Vec<KeyPackage>) {
        let mut rng = StdRng::from_seed(SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let all = key_packages(&keyset).expect("key packages");
        let signers: Vec<KeyPackage> = all.into_values().take(2).collect();
        (keyset, signers)
    }

    /// Run a real round1 over the two signers and build a SigningPackage whose message is
    /// `message`. Returns the package (the coordinator's aggregated package).
    fn package_with_message(signers: &[KeyPackage], message: &[u8]) -> SigningPackage {
        let mut rng = rand::rngs::OsRng;
        let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for kp in signers {
            let (_n, c): (SigningNonces, SigningCommitments) =
                frost::round1::commit(kp.signing_share(), &mut rng);
            commitments.insert(*kp.identifier(), c);
        }
        SigningPackage::new(commitments, message)
    }

    fn nostr_intent(content: &str) -> SignIntent {
        SignIntent::NostrEvent {
            kind: NOSTR_TEXT_NOTE_KIND,
            created_at: CREATED_AT,
            tags: Vec::new(),
            content: content.to_string(),
        }
    }

    /// G-GUARDIAN-ACCEPTS-VALID: a correctly-constructed request over a real keyset, whose
    /// SigningPackage message == the nip01 id reconstructed under the group's own Q, with
    /// the right signer set, validates Ok.
    #[test]
    fn g_guardian_accepts_valid() {
        let (keyset, signers) = keyset_and_two();
        let q = group_xonly_q(&keyset.pubkeys).expect("Q");
        let id = nip01_event_id(&hex::encode(q), CREATED_AT, 1, CONTENT);
        let package = package_with_message(&signers, &id);

        let signer_set: BTreeSet<u16> = [1u16, 2u16].into_iter().collect();
        let req = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(CONTENT),
            signer_set,
        };
        let res = validate(&req, &package, &keyset.pubkeys, 1, 2);
        assert_eq!(res, Ok(()), "a correctly-constructed request must validate");
        println!("G-GUARDIAN-ACCEPTS-VALID PASS: real keyset, message == reconstructed id, set OK -> Ok");
    }

    /// G-GUARDIAN-REJECT-MISMATCH: the package signs a DIFFERENT note's id -> MessageMismatch;
    /// and a 32-byte blob shaped like a Bitcoin sighash -> MessageMismatch.
    #[test]
    fn g_guardian_reject_mismatch() {
        let (keyset, signers) = keyset_and_two();
        let q = group_xonly_q(&keyset.pubkeys).expect("Q");

        // (a) A DIFFERENT note's id (same Q, different content).
        let other_id = nip01_event_id(&hex::encode(q), CREATED_AT, 1, "a DIFFERENT note");
        let package_a = package_with_message(&signers, &other_id);
        let req = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(CONTENT), // asks to sign CONTENT, package holds another id
            signer_set: [1u16, 2u16].into_iter().collect(),
        };
        let res_a = validate(&req, &package_a, &keyset.pubkeys, 1, 2);
        assert_eq!(res_a, Err(RefuseReason::MessageMismatch), "different note -> MessageMismatch");

        // (b) A 32-byte blob shaped like a Bitcoin sighash (definitely not the nip01 id).
        let fake_sighash = [0xABu8; 32];
        let package_b = package_with_message(&signers, &fake_sighash);
        let res_b = validate(&req, &package_b, &keyset.pubkeys, 1, 2);
        assert_eq!(
            res_b,
            Err(RefuseReason::MessageMismatch),
            "a Bitcoin-sighash-shaped blob disguised as a note -> MessageMismatch"
        );
        println!("G-GUARDIAN-REJECT-MISMATCH PASS: different-note id AND fake sighash both refused MessageMismatch");
    }

    /// G-GUARDIAN-REJECT-BLIND: the intent reconstructs to id X but the package holds
    /// unrelated bytes -> MessageMismatch. Proves a guardian NEVER blind-signs whatever the
    /// coordinator put in the package.
    #[test]
    fn g_guardian_reject_blind() {
        let (keyset, signers) = keyset_and_two();
        // Unrelated, non-id-shaped bytes (not even derived from any Q).
        let unrelated = b"this is not any nostr event id at all";
        let package = package_with_message(&signers, unrelated);
        let req = CoSignRequest {
            session_id: 1,
            intent: nostr_intent(CONTENT),
            signer_set: [1u16, 2u16].into_iter().collect(),
        };
        let res = validate(&req, &package, &keyset.pubkeys, 1, 2);
        assert_eq!(
            res,
            Err(RefuseReason::MessageMismatch),
            "unrelated package bytes -> MessageMismatch (no blind-signing)"
        );
        println!("G-GUARDIAN-REJECT-BLIND PASS: guardian refuses to sign unrelated package bytes");
    }

    /// G-GUARDIAN-SIGNER-SET: my_identifier not in the set -> NotInSignerSet;
    /// |set| < min_signers -> SubThreshold; a duplicate-identifier path -> DuplicateSigner.
    #[test]
    fn g_guardian_signer_set() {
        let (keyset, signers) = keyset_and_two();
        let q = group_xonly_q(&keyset.pubkeys).expect("Q");
        let id = nip01_event_id(&hex::encode(q), CREATED_AT, 1, CONTENT);
        let package = package_with_message(&signers, &id); // package commitments = {1,2}

        // (a) my_identifier (3) is not in the claimed set {1,2} -> NotInSignerSet. The
        //     message matches, so this isolates the signer-set check.
        let req_not_in = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(CONTENT),
            signer_set: [1u16, 2u16].into_iter().collect(),
        };
        let res_not_in = validate(&req_not_in, &package, &keyset.pubkeys, 3, 2);
        assert_eq!(res_not_in, Err(RefuseReason::NotInSignerSet), "id not in set -> NotInSignerSet");

        // (b) claimed set is sub-threshold ({1} with min_signers 2) -> SubThreshold.
        let req_sub = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(CONTENT),
            signer_set: [1u16].into_iter().collect(),
        };
        let res_sub = validate(&req_sub, &package, &keyset.pubkeys, 1, 2);
        assert_eq!(res_sub, Err(RefuseReason::SubThreshold), "sub-threshold claimed set -> SubThreshold");

        // (c) DuplicateSigner: the claimed set disagrees with the package's committed
        //     quorum. The package was built over {1,2}; a claimed set {1,3} (3 is not in
        //     the package) means the request lied about who is signing -> DuplicateSigner.
        //     (A literal duplicate u16 collapses in a BTreeSet on the wire; the membrane
        //     catches it at the same place via the package-vs-claimed-set inequality.)
        let req_dup = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(CONTENT),
            signer_set: [1u16, 3u16].into_iter().collect(),
        };
        let res_dup = validate(&req_dup, &package, &keyset.pubkeys, 1, 2);
        assert_eq!(
            res_dup,
            Err(RefuseReason::DuplicateSigner),
            "claimed set inconsistent with the package's committed quorum -> DuplicateSigner"
        );
        println!("G-GUARDIAN-SIGNER-SET PASS: NotInSignerSet, SubThreshold, DuplicateSigner all refused");
    }

    /// G-GUARDIAN-DIRTY-CONTENT: any NON-CANONICAL content (the publish path would rewrite
    /// it) -> DirtyContent; over-MAX content -> DirtyContent; a bad kind -> BadKind.
    /// Aligned with FIX 1: `content_is_clean` is now REJECT-UNLESS-CANONICAL, matching
    /// `kirby_proto::sanitize_note_for_publish` byte-for-byte. `\n` / `\t` now REJECT
    /// (they sanitize to a space, so the raw string != its canonical form).
    #[test]
    fn g_guardian_dirty_content() {
        let (keyset, signers) = keyset_and_two();
        let q = group_xonly_q(&keyset.pubkeys).expect("Q");

        // (a) Content with a forbidden control char (a bell, U+0007). content_is_clean
        //     returns false BEFORE any id is computed -> DirtyContent. The package message
        //     is irrelevant (refusal happens earlier), but build a real one anyway.
        let dirty = "hello\u{0007}world";
        let id_dirty = nip01_event_id(&hex::encode(q), CREATED_AT, 1, dirty);
        let package_dirty = package_with_message(&signers, &id_dirty);
        let req_dirty = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(dirty),
            signer_set: [1u16, 2u16].into_iter().collect(),
        };
        assert_eq!(
            validate(&req_dirty, &package_dirty, &keyset.pubkeys, 1, 2),
            Err(RefuseReason::DirtyContent),
            "control char -> DirtyContent"
        );

        // (b) Content over MAX_NOTE_BYTES (now 512) -> DirtyContent.
        let big = "x".repeat(MAX_NOTE_BYTES + 1);
        let id_big = nip01_event_id(&hex::encode(q), CREATED_AT, 1, &big);
        let package_big = package_with_message(&signers, &id_big);
        let req_big = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(&big),
            signer_set: [1u16, 2u16].into_iter().collect(),
        };
        assert_eq!(
            validate(&req_big, &package_big, &keyset.pubkeys, 1, 2),
            Err(RefuseReason::DirtyContent),
            "over MAX_NOTE_BYTES -> DirtyContent"
        );

        // (c) A bad kind (kind:0, metadata) -> BadKind.
        let id_kind = nip01_event_id(&hex::encode(q), CREATED_AT, 0, CONTENT);
        let package_kind = package_with_message(&signers, &id_kind);
        let req_kind = CoSignRequest {
            session_id: 7,
            intent: SignIntent::NostrEvent {
                kind: 0,
                created_at: CREATED_AT,
                tags: Vec::new(),
                content: CONTENT.to_string(),
            },
            signer_set: [1u16, 2u16].into_iter().collect(),
        };
        assert_eq!(
            validate(&req_kind, &package_kind, &keyset.pubkeys, 1, 2),
            Err(RefuseReason::BadKind),
            "kind != 1 -> BadKind"
        );

        // (d) NON-CANONICAL whitespace now REJECTS (publish path would rewrite it):
        //     `\n` and `\t` sanitize to a space, so the raw string is not its own
        //     canonical form -> not clean.
        assert!(!content_is_clean("line one\nline two"), "embedded \\n is non-canonical -> reject");
        assert!(!content_is_clean("col1\tcol2"), "embedded \\t is non-canonical -> reject");
        // A NostrEvent carrying a `\n` must refuse DirtyContent through `validate` too.
        let nl = "line one\nline two";
        let id_nl = nip01_event_id(&hex::encode(q), CREATED_AT, 1, nl);
        let package_nl = package_with_message(&signers, &id_nl);
        let req_nl = CoSignRequest {
            session_id: 7,
            intent: nostr_intent(nl),
            signer_set: [1u16, 2u16].into_iter().collect(),
        };
        assert_eq!(
            validate(&req_nl, &package_nl, &keyset.pubkeys, 1, 2),
            Err(RefuseReason::DirtyContent),
            "embedded \\n -> DirtyContent (publish path would rewrite it)"
        );

        // (e) Whitespace-only sanitizes to empty -> reject.
        assert!(!content_is_clean("   \t  "), "whitespace-only -> empty after sanitize -> reject");
        assert!(!content_is_clean(""), "empty -> reject");

        // (f) Leading/trailing whitespace and a double-space run are non-canonical
        //     (split_whitespace().join(\" \") would trim/collapse them) -> reject.
        assert!(!content_is_clean(" leading space"), "leading whitespace -> reject");
        assert!(!content_is_clean("trailing space "), "trailing whitespace -> reject");
        assert!(!content_is_clean("double  space"), "double-space run -> reject");

        // (g) U+2028 / U+2029 still reject (mapped to space -> non-canonical).
        assert!(!content_is_clean("sep\u{2028}sep"), "U+2028 -> reject");
        assert!(!content_is_clean("sep\u{2029}sep"), "U+2029 -> reject");
        assert!(!content_is_clean("nul\u{0000}byte"), "NUL -> reject");

        // (h) A clean, canonical single-line string (no controls, single spaces, trimmed)
        //     PASSES the checker. Exactly 512 bytes is also accepted (== MAX, not >).
        assert!(content_is_clean(CONTENT), "canonical single-line content -> clean");
        assert!(content_is_clean(&"x".repeat(MAX_NOTE_BYTES)), "content at exactly MAX -> clean");

        println!("G-GUARDIAN-DIRTY-CONTENT PASS: non-canonical (\\n/\\t/dbl-space/lead/trail/ws-only/empty/U+2028/U+2029/control), over-512 all refused; canonical single-line clean");
    }

    /// G-BEACON-MEMBRANE (custody half): the guardian ACCEPTS a beacon (10100/9100/31000)
    /// whose id (over content AND tags) matches the package, REFUSES a TAMPERED beacon
    /// package (wrong tags or wrong content) with MessageMismatch, and does NOT run the
    /// note-sanitizer on beacon JSON (a beacon whose content would be rewritten by the
    /// note sanitizer -- it has `:` and spaces and is not "canonical note" form -- still
    /// validates, proving the kind:1-only content policy).
    #[test]
    fn g_beacon_membrane() {
        let (keyset, signers) = keyset_and_two();
        let q = group_xonly_q(&keyset.pubkeys).expect("Q");
        let q_hex = hex::encode(q);
        let signer_set: BTreeSet<u16> = [1u16, 2u16].into_iter().collect();

        // A realistic beacon JSON content + tags. The JSON is DELIBERATELY shaped so the
        // note sanitizer WOULD rewrite it (it contains `{`, `:`, multiple spaces around
        // the JSON) -- if the membrane wrongly applied content_is_clean to it, it would
        // refuse DirtyContent. It must NOT, because the policy is kind:1-only.
        let beacon_content = r#"{"agent_id":"agent-0",  "treasury_sats":1234,"lifecycle":"running"}"#;
        assert!(
            !content_is_clean(beacon_content),
            "the beacon JSON is intentionally NON-canonical for the note sanitizer (double space) so this test is meaningful"
        );
        let tags: Vec<Vec<String>> = vec![
            vec!["d".to_string(), "agent-0".to_string()],
            vec!["t".to_string(), "kirby".to_string()],
            vec!["node".to_string(), "node-1".to_string()],
        ];

        for kind in [KIND_KIRBY_PRESENCE, KIND_KIRBY_LIFECYCLE, KIND_KIRBY_AGENT_STATE] {
            // (a) ACCEPT: the package's message == the id reconstructed over content AND tags.
            let id = nip01_event_id_with_tags(&q_hex, CREATED_AT, kind, &tags, beacon_content);
            let package = package_with_message(&signers, &id);
            let req = CoSignRequest {
                session_id: 7,
                intent: SignIntent::NostrEvent {
                    kind,
                    created_at: CREATED_AT,
                    tags: tags.clone(),
                    content: beacon_content.to_string(),
                },
                signer_set: signer_set.clone(),
            };
            assert_eq!(
                validate(&req, &package, &keyset.pubkeys, 1, 2),
                Ok(()),
                "kind {kind} beacon with matching id+tags must validate (JSON NOT sanitized)"
            );

            // (b) REFUSE: a package signing the id with TAMPERED tags (a malicious
            //     coordinator that changed the node tag) -> MessageMismatch. The request
            //     still claims the ORIGINAL tags, so the reconstructed id differs.
            let mut bad_tags = tags.clone();
            bad_tags[2][1] = "evil-node".to_string();
            let tampered_id =
                nip01_event_id_with_tags(&q_hex, CREATED_AT, kind, &bad_tags, beacon_content);
            let tampered_package = package_with_message(&signers, &tampered_id);
            assert_eq!(
                validate(&req, &tampered_package, &keyset.pubkeys, 1, 2),
                Err(RefuseReason::MessageMismatch),
                "kind {kind} beacon with tampered tags must refuse MessageMismatch"
            );

            // (c) REFUSE: a package signing the id over TAMPERED content -> MessageMismatch.
            let tampered_content_id = nip01_event_id_with_tags(
                &q_hex,
                CREATED_AT,
                kind,
                &tags,
                r#"{"agent_id":"agent-0","treasury_sats":999999}"#,
            );
            let tcp = package_with_message(&signers, &tampered_content_id);
            assert_eq!(
                validate(&req, &tcp, &keyset.pubkeys, 1, 2),
                Err(RefuseReason::MessageMismatch),
                "kind {kind} beacon with tampered content must refuse MessageMismatch"
            );
        }

        // (d) An unauthorized kind (kind:0) still -> BadKind even with beacon-shaped tags.
        let id0 = nip01_event_id_with_tags(&q_hex, CREATED_AT, 0, &tags, beacon_content);
        let pkg0 = package_with_message(&signers, &id0);
        let req0 = CoSignRequest {
            session_id: 7,
            intent: SignIntent::NostrEvent {
                kind: 0,
                created_at: CREATED_AT,
                tags: tags.clone(),
                content: beacon_content.to_string(),
            },
            signer_set: signer_set.clone(),
        };
        assert_eq!(
            validate(&req0, &pkg0, &keyset.pubkeys, 1, 2),
            Err(RefuseReason::BadKind),
            "kind:0 is still BadKind"
        );

        println!("G-BEACON-MEMBRANE (custody) PASS: 10100/9100/31000 accept on matching id+tags, refuse tampered tags/content (MessageMismatch), beacon JSON NOT sanitized, kind:0 still BadKind");
    }
}
