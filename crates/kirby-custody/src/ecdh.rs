//! Phase-0 spike: **threshold ECDH** over the existing FROST 2-of-3 keyset.
//!
//! The custody crate signs today (BIP-340 Schnorr under the tweaked taproot key Q,
//! see [`crate::coordinator`]). It does NOT do ECDH — yet NIP-44 (hence NIP-17 DMs
//! and the NIP-60 wallet's self-encryption) needs the ECDH shared secret. This
//! module proves the primitive that closes that gap **without ever reconstructing
//! the group secret scalar on any machine**.
//!
//! # The construction (single round, linearly homomorphic)
//!
//! NIP-44 v2 needs the ECDH shared secret: for our secret scalar `s` (behind our
//! pubkey) and a peer's pubkey `B`, the 32-byte x-coordinate of the point `s·B`,
//! run through `HKDF-Extract(salt = "nip44-v2")` to get the conversation key
//! (<https://nips.nostr.com/44>).
//!
//! `s` is Shamir/FROST-shared as `s = Σ λ_i · s_i` over a signing set (`λ_i` are the
//! Lagrange coefficients at 0). Because point multiplication is linear, each holder
//! can compute its **point contribution** `P_i = λ_i · s_i · B` from its OWN share
//! `s_i` and the PUBLIC peer key `B`, and the coordinator sums:
//!
//! ```text
//!   Σ P_i = Σ (λ_i · s_i) · B = (Σ λ_i · s_i) · B = s · B
//! ```
//!
//! The scalar `s` is never formed; no holder learns another's share; the result is
//! byte-identical to the point vanilla ECDH would produce, so its x-coordinate feeds
//! NIP-44 unchanged. Unlike threshold *ECDSA* (multi-round, MtA), threshold *ECDH*
//! is a single request/response round: it is strictly SIMPLER than the FROST-Schnorr
//! signing this crate already ships (no nonce-commit / challenge rounds).
//!
//! # Two identity keys
//!
//! - [`threshold_ecdh_untweaked`] combines against the **untweaked** FROST group key
//!   `P` (`s·G = P`). This is the pure primitive; it is what the NIP-44 known-answer
//!   vectors validate (their keys are plain, un-tweaked).
//! - [`threshold_ecdh_tweaked_q`] derives against the agent's **actual Nostr identity
//!   `Q`** — the BIP-341 taproot output key ([`crate::group_xonly_q`], the key the node
//!   signs presence under and the key a peer DMs). `Q = lift_even(P) + t·G`, so the
//!   ECDH scalar is `d_tw = d_int + t` where `d_int·G = lift_even(P)`. Holders still
//!   emit UNTWEAKED contributions `λ_i·s_i·B`; the coordinator applies the internal
//!   parity (`±`) and adds the PUBLIC tweak point `t·B`. This is the path a real
//!   NIP-17 DM to the agent will ride.
//!
//! Scope is a spike: prove the primitive (teeth-tested, vector-validated), in-process
//! (co-located shares). Wiring `QuorumEcdh` into the DM / NIP-60 call-sites, the
//! conversation-key cache, and the cross-machine transport are later phases.

use std::collections::BTreeSet;
use std::fmt;

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;

use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// NIP-44 v2 HKDF-Extract salt (<https://nips.nostr.com/44>).
const NIP44_V2_SALT: &[u8] = b"nip44-v2";

/// Errors from the threshold-ECDH primitive. Never panics; mirrors the
/// coordinator's fail-closed posture (a bad ceremony yields an error, not a secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdhError {
    /// A point (peer key or contribution) was not a valid, non-identity secp256k1
    /// point in compressed SEC1 form.
    MalformedPoint(String),
    /// A scalar (share or identifier) did not deserialize to a canonical field element.
    MalformedScalar(String),
    /// The signing set was empty, or fewer than one contribution was aggregated.
    EmptySet,
    /// A signer identifier appeared more than once in the signing set (a duplicate
    /// would double-count a share in the Lagrange combine).
    DuplicateSigner(String),
    /// A holder was asked to contribute for a signing set it is not a member of (its
    /// Lagrange coefficient would be undefined for that set).
    SignerNotInSet(String),
    /// Fewer than `min_signers` participated. A sub-threshold set would Lagrange-combine
    /// to the WRONG scalar (not `s`), silently yielding an unusable secret — reject it.
    SubThreshold(String),
    /// The signers are not one consistent group, or do not match the supplied
    /// `PublicKeyPackage` (shares from a different keyset would fold to a secret for no
    /// real key). Binds the ceremony to exactly one Q.
    MismatchedGroup(String),
}

impl fmt::Display for EcdhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcdhError::MalformedPoint(m) => write!(f, "malformed curve point: {m}"),
            EcdhError::MalformedScalar(m) => write!(f, "malformed scalar: {m}"),
            EcdhError::EmptySet => write!(f, "empty signing set / no contributions"),
            EcdhError::DuplicateSigner(m) => write!(f, "duplicate signer in set: {m}"),
            EcdhError::SignerNotInSet(m) => write!(f, "signer not in its signing set: {m}"),
            EcdhError::SubThreshold(m) => write!(f, "sub-threshold signing set: {m}"),
            EcdhError::MismatchedGroup(m) => write!(f, "mismatched signing group: {m}"),
        }
    }
}

impl std::error::Error for EcdhError {}

/// A curve point as it crosses the ceremony transport: an opaque 33-byte compressed
/// SEC1 point. A holder's ECDH contribution is exactly this — **a point, never a
/// share**. The shared secret point is also carried as this type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WirePoint(pub [u8; 33]);

impl WirePoint {
    fn to_projective(self) -> Result<ProjectivePoint, EcdhError> {
        let encoded = EncodedPoint::from_bytes(self.0.as_slice())
            .map_err(|e| EcdhError::MalformedPoint(e.to_string()))?;
        let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
        let affine =
            affine.ok_or_else(|| EcdhError::MalformedPoint("point not on curve".to_string()))?;
        Ok(ProjectivePoint::from(affine))
    }

    fn from_projective(p: &ProjectivePoint) -> Result<Self, EcdhError> {
        // The identity has no valid 33-byte compressed form and must never appear as
        // a contribution or a shared secret (it would mean a zero scalar or a
        // canceling combine — reject it rather than emit a degenerate secret).
        if p == &ProjectivePoint::IDENTITY {
            return Err(EcdhError::MalformedPoint("point at infinity".to_string()));
        }
        let encoded = p.to_affine().to_encoded_point(true);
        let bytes: [u8; 33] = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| EcdhError::MalformedPoint("not a 33-byte compressed point".to_string()))?;
        Ok(WirePoint(bytes))
    }

    /// The 32-byte big-endian x-coordinate (NIP-44's ECDH shared-secret material).
    fn x_coordinate(self) -> Result<[u8; 32], EcdhError> {
        let p = self.to_projective()?;
        Ok(p.to_affine().x().into())
    }
}

/// Lift a 32-byte Nostr x-only pubkey to its even-Y point (NIP-44 uses the peer key
/// with an implicit `0x02` prefix). Returns the compressed wire point, or an error
/// if the x-coordinate is not on the curve.
pub fn peer_point_from_xonly(xonly: &[u8; 32]) -> Result<WirePoint, EcdhError> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // even-Y lift, per NIP-44 / BIP-340 pubkey convention
    compressed[1..].copy_from_slice(xonly);
    // Validate it decodes to a real curve point (round-trips through the affine form).
    WirePoint(compressed).to_projective()?;
    Ok(WirePoint(compressed))
}

/// Load a 32-byte big-endian scalar (a FROST share or identifier serialization) into
/// a k256 scalar. Rejects a non-canonical (≥ n) encoding.
fn scalar_from_be_bytes(bytes: &[u8]) -> Result<Scalar, EcdhError> {
    let fb: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EcdhError::MalformedScalar(format!("expected 32 bytes, got {}", bytes.len())))?;
    let field_bytes = FieldBytes::from(fb);
    Option::from(Scalar::from_repr(field_bytes))
        .ok_or_else(|| EcdhError::MalformedScalar("scalar >= group order".to_string()))
}

/// The scalar value of a FROST identifier (its x-coordinate on the sharing polynomial).
fn identifier_scalar(id: &Identifier) -> Result<Scalar, EcdhError> {
    scalar_from_be_bytes(&id.serialize())
}

/// The Lagrange coefficient `λ_i(0) = Π_{j≠i} x_j / (x_j − x_i)` for signer `i` over
/// `signing_set`, evaluated at 0 (the point where the shared polynomial equals the
/// group secret). Depends only on the PUBLIC identifiers, so any party can compute it.
fn lagrange_coefficient(i: &Identifier, signing_set: &[Identifier]) -> Result<Scalar, EcdhError> {
    if signing_set.is_empty() {
        return Err(EcdhError::EmptySet);
    }
    let mut seen: BTreeSet<Identifier> = BTreeSet::new();
    for id in signing_set {
        if !seen.insert(*id) {
            return Err(EcdhError::DuplicateSigner(format!("{id:?}")));
        }
    }
    if !signing_set.contains(i) {
        return Err(EcdhError::SignerNotInSet(format!("{i:?}")));
    }

    let x_i = identifier_scalar(i)?;
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for j in signing_set {
        if j == i {
            continue;
        }
        let x_j = identifier_scalar(j)?;
        numerator *= x_j;
        denominator *= x_j - x_i; // distinct identifiers => nonzero factor
    }
    let inv = Option::<Scalar>::from(denominator.invert())
        .ok_or_else(|| EcdhError::MalformedScalar("zero Lagrange denominator".to_string()))?;
    Ok(numerator * inv)
}

/// A single holder's ECDH point contribution `P_i = λ_i · s_i · B`, computed from the
/// holder's OWN share (`kp`), the PUBLIC signing set, and the PUBLIC peer point `B`.
///
/// The output is a compressed curve point; the secret share never leaves the holder.
/// (Recovering `s_i` from `λ_i·s_i·B` is a discrete-log problem.)
pub fn holder_ecdh_contribution(
    kp: &KeyPackage,
    signing_set: &[Identifier],
    peer: &WirePoint,
) -> Result<WirePoint, EcdhError> {
    let lambda = lagrange_coefficient(kp.identifier(), signing_set)?;
    let s_i = scalar_from_be_bytes(&kp.signing_share().serialize())?;
    let b = peer.to_projective()?;
    let contribution = b * (lambda * s_i);
    WirePoint::from_projective(&contribution)
}

/// The coordinator's aggregate: `Σ P_i = s·B`, the ECDH point under the UNTWEAKED
/// group key `P` (`s·G = P`). `s` is never formed.
pub fn aggregate_contributions(contributions: &[WirePoint]) -> Result<WirePoint, EcdhError> {
    if contributions.is_empty() {
        return Err(EcdhError::EmptySet);
    }
    let mut acc = ProjectivePoint::IDENTITY;
    for c in contributions {
        acc += c.to_projective()?;
    }
    WirePoint::from_projective(&acc)
}

/// Derive the NIP-44 v2 conversation key from a shared ECDH point:
/// `HKDF-Extract(salt = "nip44-v2", ikm = x(shared_point))` (SHA-256).
pub fn nip44_conversation_key(shared: &WirePoint) -> Result<[u8; 32], EcdhError> {
    let shared_x = shared.x_coordinate()?;
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(NIP44_V2_SALT), &shared_x);
    Ok(prk.into())
}

/// Validate a signing set for a threshold-ECDH ceremony and return the group's shared
/// verifying-key bytes. Enforces: non-empty, no duplicate identifiers, all key packages
/// from the SAME group (identical verifying key + threshold), and at least `min_signers`
/// participants. A sub-threshold or cross-keyset set would Lagrange-combine to the wrong
/// scalar and silently return an unusable "secret" — this rejects it up front, fail-closed.
fn validate_signers(signers: &[&KeyPackage]) -> Result<Vec<u8>, EcdhError> {
    let first = signers.first().ok_or(EcdhError::EmptySet)?;
    let group_vk = first
        .verifying_key()
        .serialize()
        .map_err(|e| EcdhError::MalformedPoint(e.to_string()))?;
    let min_signers = *first.min_signers();

    let mut seen: BTreeSet<Identifier> = BTreeSet::new();
    for kp in signers {
        if !seen.insert(*kp.identifier()) {
            return Err(EcdhError::DuplicateSigner(format!("{:?}", kp.identifier())));
        }
        let vk = kp
            .verifying_key()
            .serialize()
            .map_err(|e| EcdhError::MalformedPoint(e.to_string()))?;
        if vk != group_vk || *kp.min_signers() != min_signers {
            return Err(EcdhError::MismatchedGroup(
                "signers are not one consistent 2-of-3 group".to_string(),
            ));
        }
    }
    if signers.len() < min_signers as usize {
        return Err(EcdhError::SubThreshold(format!(
            "{} of {} required signers",
            signers.len(),
            min_signers
        )));
    }
    Ok(group_vk)
}

/// In-process threshold ECDH against the **untweaked** FROST group key `P`. Drives the
/// participating `signers` (a ≥-threshold subset of ONE group), aggregates their
/// contributions, and returns the shared point `s·B`. Matches a peer who ECDHs against
/// `P` (plain key) — the form the NIP-44 known-answer vectors exercise.
pub fn threshold_ecdh_untweaked(
    signers: &[&KeyPackage],
    peer_xonly: &[u8; 32],
) -> Result<WirePoint, EcdhError> {
    validate_signers(signers)?;
    let peer = peer_point_from_xonly(peer_xonly)?;
    let signing_set: Vec<Identifier> = signers.iter().map(|kp| *kp.identifier()).collect();
    let contributions = signers
        .iter()
        .map(|kp| holder_ecdh_contribution(kp, &signing_set, &peer))
        .collect::<Result<Vec<_>, _>>()?;
    aggregate_contributions(&contributions)
}

/// Parse a `PublicKeyPackage`'s (untweaked) group verifying key `P` into a k256 point.
fn verifying_key_point(pubkeys: &PublicKeyPackage) -> Result<ProjectivePoint, EcdhError> {
    let vk_bytes = pubkeys
        .verifying_key()
        .serialize()
        .map_err(|e| EcdhError::MalformedPoint(e.to_string()))?;
    let encoded = EncodedPoint::from_bytes(vk_bytes.as_slice())
        .map_err(|e| EcdhError::MalformedPoint(e.to_string()))?;
    let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
    affine
        .map(ProjectivePoint::from)
        .ok_or_else(|| EcdhError::MalformedPoint("verifying key not on curve".to_string()))
}

/// The taproot tweak scalar `t = int(H_TapTweak(x(P)))` with no script tree
/// (`merkle_root = None`), computed EXACTLY as `frost-secp256k1-tr`'s `tweak()` does:
/// tagged hash `TapTweak` over the internal key's x-coordinate, then `Scalar::reduce`
/// (reduce mod n).
///
/// Note: strict BIP-341 treats `t ≥ n` as invalid (abort); frost REDUCES instead. We
/// match frost deliberately — this ECDH must derive against the SAME Q the fleet already
/// signs under (frost's `sign_with_tweak`/`group_xonly_q`), so matching frost's tweak,
/// not strict BIP-341, is the requirement. The two differ only in the ~2⁻¹²⁸ `t ≥ n`
/// case; `tweaked_q_matches_group_xonly_q` proves the derived Q equals the production Q.
fn tap_tweak_none(internal_p: &ProjectivePoint) -> Scalar {
    // tagged_hash(tag) = SHA256( SHA256(tag) || SHA256(tag) || .. )
    let tag_hash = Sha256::digest(b"TapTweak");
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(internal_p.to_affine().x());
    Scalar::reduce(U256::from_be_slice(&hasher.finalize()))
}

/// The agent's taproot output key `Q` as a 32-byte x-only key, derived through THIS
/// module's k256 tweak path (`Q = lift_even(P) + t·G`). It must equal
/// [`crate::group_xonly_q`] (a test asserts this) — that equality is what proves the
/// tweak fold below targets the exact key a peer DMs.
pub fn tweaked_q_xonly(pubkeys: &PublicKeyPackage) -> Result<[u8; 32], EcdhError> {
    let p = verifying_key_point(pubkeys)?;
    let q = lift_even_y(&p) + ProjectivePoint::GENERATOR * tap_tweak_none(&p);
    if q == ProjectivePoint::IDENTITY {
        return Err(EcdhError::MalformedPoint("tweaked Q is the identity".to_string()));
    }
    Ok(q.to_affine().x().into())
}

/// The even-Y lift of a point: `P` if it already has even Y, else `−P` (same x, even
/// Y). This is `frost`'s `into_even_y` at the group level — the effective internal
/// signing key is always the even-Y representative.
fn lift_even_y(p: &ProjectivePoint) -> ProjectivePoint {
    if bool::from(p.to_affine().y_is_odd()) {
        -*p
    } else {
        *p
    }
}

/// In-process threshold ECDH against the agent's **actual taproot Nostr identity `Q`**
/// (`Q = lift_even(P) + t·G`, `merkle_root = None`). This is the key a NIP-17 DM to the
/// agent is encrypted to.
///
/// Holders emit the SAME untweaked contributions `λ_i·s_i·B` as [`threshold_ecdh_untweaked`];
/// the coordinator then folds the tweak using only PUBLIC data:
///
/// ```text
///   d_tw · B = (d_int + t) · B = d_int·B + t·B ,   d_int·B = ± (s·B)
/// ```
///
/// where the sign matches `P`'s parity (frost's even-Y normalization) and `t·B` uses
/// the public tweak scalar and the public peer point. The result's x-coordinate is the
/// NIP-44 shared secret a peer DMing `Q` computes on their side (proven by the
/// peer-symmetry test).
pub fn threshold_ecdh_tweaked_q(
    signers: &[&KeyPackage],
    pubkeys: &PublicKeyPackage,
    peer_xonly: &[u8; 32],
) -> Result<WirePoint, EcdhError> {
    // Bind the signers to THIS group AND to the supplied `pubkeys` (the tweak/parity
    // are derived from `pubkeys`): shares from a different keyset must not be folded
    // with another group's tweak, which would return a secret for no real Q.
    let group_vk = validate_signers(signers)?;
    let pk_vk = pubkeys
        .verifying_key()
        .serialize()
        .map_err(|e| EcdhError::MalformedPoint(e.to_string()))?;
    if group_vk != pk_vk {
        return Err(EcdhError::MismatchedGroup(
            "signers' group key does not match the supplied PublicKeyPackage".to_string(),
        ));
    }
    for kp in signers {
        if !pubkeys.verifying_shares().contains_key(kp.identifier()) {
            return Err(EcdhError::MismatchedGroup(format!(
                "signer {:?} is not a member of the supplied PublicKeyPackage",
                kp.identifier()
            )));
        }
    }

    let peer = peer_point_from_xonly(peer_xonly)?;
    let b = peer.to_projective()?;

    // s·B from the untweaked threshold combine (s never formed).
    let s_b = threshold_ecdh_untweaked(signers, peer_xonly)?.to_projective()?;

    let p = verifying_key_point(pubkeys)?;
    // d_int·B: negate the combine iff P has odd Y (frost's into_even_y on the group).
    let d_int_b = if bool::from(p.to_affine().y_is_odd()) {
        -s_b
    } else {
        s_b
    };
    // + t·B, the public taproot tweak folded on the ECDH side.
    let r = d_int_b + b * tap_tweak_none(&p);
    WirePoint::from_projective(&r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::key_packages;
    use crate::{generate_dealer_keyset_with_rng, group_xonly_q};
    use frost::keys::{IdentifierList, SecretShare};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // Non-secret, zero-funds reproducible fixture seed (mirrors the crate's style).
    const ECDH_SEED: [u8; 32] = *b"kirby-custody-ecdh-p0-seed-mtny!";

    /// paulmillr/nip44 v2 `get_conversation_key` known-answer vectors
    /// (<https://github.com/paulmillr/nip44>): (sec1, pub2, conversation_key), hex.
    /// pub2 is a 32-byte x-only key.
    const NIP44_VECTORS: &[(&str, &str, &str)] = &[
        (
            "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
            "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
            "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1",
        ),
        (
            "a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
            "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
            "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b",
        ),
        (
            "98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311",
            "aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1",
            "9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7",
        ),
    ];

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).expect("hex");
        v.try_into().expect("32 bytes")
    }

    /// Build a 2-of-3 keyset by SPLITTING a known secret scalar (so the group secret
    /// equals `sec1` and the group key `P = sec1·G` — the plain, un-tweaked identity
    /// the NIP-44 vectors assume).
    fn split_known_secret(sec1: &[u8; 32]) -> (Vec<KeyPackage>, PublicKeyPackage) {
        let mut rng = StdRng::from_seed(ECDH_SEED);
        let signing_key = frost::SigningKey::deserialize(sec1).expect("valid sec1 scalar");
        let (shares, pubkeys) =
            frost::keys::split(&signing_key, 3, 2, IdentifierList::Default, &mut rng)
                .expect("split 2-of-3");
        let kps = shares
            .into_values()
            .map(|s: SecretShare| KeyPackage::try_from(s).expect("key package"))
            .collect();
        (kps, pubkeys)
    }

    fn dealer_keyset() -> (Vec<KeyPackage>, PublicKeyPackage) {
        let mut rng = StdRng::from_seed(ECDH_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let kps = key_packages(&keyset)
            .expect("key packages")
            .into_values()
            .collect();
        (kps, keyset.pubkeys)
    }

    /// THE primitive validation (external oracle): split each NIP-44 vector's `sec1`
    /// into 2-of-3, run threshold ECDH (never reconstructing `sec1`) against `pub2`,
    /// and assert the derived conversation key matches the vector byte-for-byte.
    #[test]
    fn nip44_known_answer_vectors_untweaked() {
        for (sec1_hex, pub2_hex, ck_hex) in NIP44_VECTORS {
            let sec1 = hex32(sec1_hex);
            let pub2 = hex32(pub2_hex);
            let expected = hex32(ck_hex);

            let (kps, _pk) = split_known_secret(&sec1);
            // A 2-of-3 quorum {1, 2}.
            let quorum = [&kps[0], &kps[1]];
            let shared = threshold_ecdh_untweaked(&quorum, &pub2).expect("threshold ecdh");
            let ck = nip44_conversation_key(&shared).expect("conversation key");

            assert_eq!(
                ck, expected,
                "threshold ECDH conversation key must match NIP-44 vector (sec1={sec1_hex})"
            );
        }
        println!("NIP44 PASS: threshold-ECDH conversation keys match all paulmillr/nip44 v2 known-answer vectors (key never reconstructed)");
    }

    /// Every valid 2-of-3 quorum {1,2}, {1,3}, {2,3} derives the SAME shared secret
    /// (quorum-agnostic correctness) — and it equals the direct single-scalar ECDH
    /// with the reconstructed secret (self-consistency oracle).
    #[test]
    fn all_quorums_agree_and_match_reconstructed() {
        let (kps, _pk) = split_known_secret(&hex32(NIP44_VECTORS[0].0));
        let pub2 = hex32(NIP44_VECTORS[0].1);

        let s12 = threshold_ecdh_untweaked(&[&kps[0], &kps[1]], &pub2).unwrap();
        let s13 = threshold_ecdh_untweaked(&[&kps[0], &kps[2]], &pub2).unwrap();
        let s23 = threshold_ecdh_untweaked(&[&kps[1], &kps[2]], &pub2).unwrap();
        assert_eq!(s12, s13, "quorum {{1,3}} must agree with {{1,2}}");
        assert_eq!(s12, s23, "quorum {{2,3}} must agree with {{1,2}}");

        // Direct ECDH with the KNOWN secret (the vectors' sec1) as the oracle.
        let s = scalar_from_be_bytes(&hex32(NIP44_VECTORS[0].0)).unwrap();
        let b = peer_point_from_xonly(&pub2).unwrap().to_projective().unwrap();
        let direct = WirePoint::from_projective(&(b * s)).unwrap();
        assert_eq!(s12, direct, "threshold combine must equal direct s·B");
        println!("AGREE PASS: all 3 quorums agree and match the reconstructed-scalar ECDH oracle");
    }

    /// The Lagrange combine reconstructs the group verifying key: `Σ λ_i·s_i·G == P`
    /// for a 2-subset. This validates the Lagrange coefficients + scalar handling
    /// independently of any peer (the load-bearing algebra behind the point-combine).
    #[test]
    fn lagrange_combine_reconstructs_group_key() {
        let (kps, pk) = dealer_keyset();
        let p = verifying_key_point(&pk).unwrap();
        let quorum = [kps[0].identifier(), kps[1].identifier()];
        let mut acc = Scalar::ZERO;
        for kp in [&kps[0], &kps[1]] {
            let lambda = lagrange_coefficient(kp.identifier(), &[*quorum[0], *quorum[1]]).unwrap();
            let s_i = scalar_from_be_bytes(&kp.signing_share().serialize()).unwrap();
            acc += lambda * s_i;
        }
        assert_eq!(
            ProjectivePoint::GENERATOR * acc,
            p,
            "Σ λ_i·s_i·G must equal the group verifying key P"
        );
        println!("LAGRANGE PASS: Σ λ_i·s_i·G == P (Lagrange coefficients + scalar handling correct)");
    }

    /// The module's tweak path derives exactly the key production uses: our
    /// `tweaked_q_xonly` must equal `crate::group_xonly_q`. This anchors the whole
    /// tweaked-Q ECDH to the real Nostr identity a peer DMs.
    #[test]
    fn tweaked_q_matches_group_xonly_q() {
        let (_kps, pk) = dealer_keyset();
        let ours = tweaked_q_xonly(&pk).unwrap();
        let production = group_xonly_q(&pk).expect("group_xonly_q");
        assert_eq!(
            ours, production,
            "our k256 tweak path must reproduce group_xonly_q (the node's real npub)"
        );
        println!("TWEAK-Q PASS: tweaked_q_xonly == group_xonly_q (tweak fold targets the real identity)");
    }

    /// A keyset generated from a varied seed, plus whether its group key `P` has odd Y.
    fn keyset_for_seed(seed_byte: u8) -> (Vec<KeyPackage>, PublicKeyPackage, bool) {
        let mut seed = ECDH_SEED;
        seed[0] = seed_byte;
        let mut rng = StdRng::from_seed(seed);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let p_odd = bool::from(
            verifying_key_point(&keyset.pubkeys)
                .unwrap()
                .to_affine()
                .y_is_odd(),
        );
        let kps = key_packages(&keyset)
            .expect("key packages")
            .into_values()
            .collect();
        (kps, keyset.pubkeys, p_odd)
    }

    /// End-to-end Kirby-identity proof (no external vector needed): a peer who ECDHs
    /// against the agent's real npub `Q` derives the SAME NIP-44 conversation key the
    /// agent derives via tweaked-Q threshold ECDH — for every 2-of-3 quorum, and
    /// deterministically across BOTH parities of the group key `P` (so the internal
    /// even-Y negation branch of the tweak fold is actually exercised, not just the
    /// happy parity of one fixed keyset).
    #[test]
    fn peer_symmetry_tweaked_q_both_parities() {
        // A peer with a fixed, valid secret b; its x-only pubkey is what the agent
        // ECDHs against.
        let b = scalar_from_be_bytes(&hex32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ))
        .unwrap();
        let peer_xonly: [u8; 32] = (ProjectivePoint::GENERATOR * b).to_affine().x().into();

        // Find one even-Y-P keyset and one odd-Y-P keyset (P parity is ~50/50 per seed,
        // so this terminates almost surely well within the bound).
        let mut even = None;
        let mut odd = None;
        for seed_byte in 0u8..64 {
            let (kps, pk, p_odd) = keyset_for_seed(seed_byte);
            if p_odd && odd.is_none() {
                odd = Some((kps, pk));
            } else if !p_odd && even.is_none() {
                even = Some((kps, pk));
            }
            if even.is_some() && odd.is_some() {
                break;
            }
        }
        let even = even.expect("an even-Y P keyset within 64 seeds");
        let odd = odd.expect("an odd-Y P keyset within 64 seeds");

        for (parity, (kps, pk)) in [("even-Y P", even), ("odd-Y P", odd)] {
            // The tweak path targets the real npub for THIS keyset (both parities).
            assert_eq!(
                tweaked_q_xonly(&pk).unwrap(),
                group_xonly_q(&pk).unwrap(),
                "{parity}: tweaked_q_xonly must equal group_xonly_q"
            );

            // Peer side: x( b · lift_even(Q) ) → conversation key.
            let q_xonly = tweaked_q_xonly(&pk).unwrap();
            let q_point = peer_point_from_xonly(&q_xonly).unwrap().to_projective().unwrap();
            let peer_ck =
                nip44_conversation_key(&WirePoint::from_projective(&(q_point * b)).unwrap()).unwrap();

            for (a, c, label) in [(0usize, 1usize, "{1,2}"), (0, 2, "{1,3}"), (1, 2, "{2,3}")] {
                let quorum = [&kps[a], &kps[c]];
                let agent_shared = threshold_ecdh_tweaked_q(&quorum, &pk, &peer_xonly).unwrap();
                assert_eq!(
                    nip44_conversation_key(&agent_shared).unwrap(),
                    peer_ck,
                    "{parity} quorum {label}: agent and peer must derive the same conversation key"
                );
            }
        }
        println!("SYMMETRY PASS: peer↔agent NIP-44 conversation keys match for all quorums across BOTH P parities (even-Y and odd-Y group key)");
    }

    // ---- TEETH (red-on-revert) ----

    /// A sub-threshold set cannot derive the secret: one holder's contribution alone
    /// (using a 2-of-2 Lagrange weight) does NOT equal the true 2-of-3 shared secret.
    /// The quorum is REQUIRED — a lone holder cannot ECDH.
    #[test]
    fn tooth_single_holder_cannot_derive() {
        let (kps, _pk) = split_known_secret(&hex32(NIP44_VECTORS[0].0));
        let pub2 = hex32(NIP44_VECTORS[0].1);
        let peer = peer_point_from_xonly(&pub2).unwrap();

        let full = threshold_ecdh_untweaked(&[&kps[0], &kps[1]], &pub2).unwrap();
        // Only holder 1 contributes (but with the {1,2} Lagrange weight).
        let lone = holder_ecdh_contribution(&kps[0], &[*kps[0].identifier(), *kps[1].identifier()], &peer)
            .unwrap();
        assert_ne!(
            lone, full,
            "a single holder's contribution must NOT equal the true shared secret"
        );
        println!("TOOTH single-holder PASS: one share cannot derive the ECDH secret (quorum required)");
    }

    /// The Lagrange coefficients are load-bearing: contributing under the WRONG signing
    /// set (so the wrong λ) yields the wrong aggregate. A regression that dropped or
    /// hardcoded λ would make this pass silently — here it must diverge.
    #[test]
    fn tooth_wrong_signing_set_diverges() {
        let (kps, _pk) = split_known_secret(&hex32(NIP44_VECTORS[0].0));
        let pub2 = hex32(NIP44_VECTORS[0].1);
        let peer = peer_point_from_xonly(&pub2).unwrap();

        let correct = threshold_ecdh_untweaked(&[&kps[0], &kps[1]], &pub2).unwrap();
        // Holder 1 computes λ for {1,3} while holder 2 uses {1,2}: mismatched sets.
        let c1_wrong =
            holder_ecdh_contribution(&kps[0], &[*kps[0].identifier(), *kps[2].identifier()], &peer)
                .unwrap();
        let c2 =
            holder_ecdh_contribution(&kps[1], &[*kps[0].identifier(), *kps[1].identifier()], &peer)
                .unwrap();
        let mixed = aggregate_contributions(&[c1_wrong, c2]).unwrap();
        assert_ne!(
            mixed, correct,
            "mismatched Lagrange sets must NOT reconstruct the correct secret"
        );
        println!("TOOTH wrong-set PASS: mismatched Lagrange coefficients diverge (λ is load-bearing)");
    }

    /// The taproot tweak is load-bearing: ECDH against the tweaked `Q` differs from
    /// ECDH against the untweaked `P` (because `Q ≠ P`). A wiring that forgot the
    /// tweak would derive a key a real peer never computes — this catches it.
    #[test]
    fn tooth_tweak_changes_the_secret() {
        let (kps, pk) = dealer_keyset();
        let pub2 = hex32(NIP44_VECTORS[0].1);
        let quorum = [&kps[0], &kps[1]];

        let untweaked = threshold_ecdh_untweaked(&quorum, &pub2).unwrap();
        let tweaked = threshold_ecdh_tweaked_q(&quorum, &pk, &pub2).unwrap();
        assert_ne!(
            nip44_conversation_key(&untweaked).unwrap(),
            nip44_conversation_key(&tweaked).unwrap(),
            "tweaked-Q ECDH must differ from untweaked-P ECDH (the tweak is real)"
        );
        println!("TOOTH tweak PASS: threshold-ECDH under Q differs from under P (tweak fold is load-bearing)");
    }

    /// A holder emits a POINT, never its share. The no-leak guarantee is STRUCTURAL: the
    /// wire type is a 33-byte compressed curve point (`WirePoint([u8; 33])`), so it cannot
    /// carry a scalar share by construction, and the emitted value is exactly `λ_i·s_i·B`
    /// — recovering `s_i` from it is a discrete-log problem. This test makes that concrete:
    /// the contribution decodes as an on-curve point, equals the independently recomputed
    /// `λ·s·B`, and varies with the peer (so it is not a static function of the share).
    #[test]
    fn tooth_contribution_is_a_point_valued_function() {
        let (kps, _pk) = split_known_secret(&hex32(NIP44_VECTORS[0].0));
        let set = [*kps[0].identifier(), *kps[1].identifier()];
        let peer_a = peer_point_from_xonly(&hex32(NIP44_VECTORS[0].1)).unwrap();
        let peer_b = peer_point_from_xonly(&hex32(NIP44_VECTORS[2].1)).unwrap();

        let c_a = holder_ecdh_contribution(&kps[0], &set, &peer_a).unwrap();
        let c_b = holder_ecdh_contribution(&kps[0], &set, &peer_b).unwrap();

        // Decodes as a real on-curve point (a point, not a scalar).
        let c_a_pt = c_a.to_projective().expect("on-curve point");
        // Exactly λ·s·B (a point-valued function of the PUBLIC peer key; s is only
        // discrete-log-recoverable from it).
        let lambda = lagrange_coefficient(kps[0].identifier(), &set).unwrap();
        let s_i = scalar_from_be_bytes(&kps[0].signing_share().serialize()).unwrap();
        assert_eq!(
            c_a_pt,
            peer_a.to_projective().unwrap() * (lambda * s_i),
            "contribution must equal λ·s·B"
        );
        // Peer-dependent: not a fixed echo of the share.
        assert_ne!(c_a, c_b, "same share, different peer must give a different wire point");
        assert_ne!(c_a, peer_a, "contribution is not the peer point itself");
        println!("TOOTH wire PASS: a contribution is a peer-dependent curve point (λ·s·B), never the share");
    }

    /// The threshold is enforced at the driver: a sub-threshold set is rejected up front
    /// (SubThreshold), never silently returning a wrong scalar's ECDH. (Finding 1.)
    #[test]
    fn tooth_untweaked_rejects_subthreshold() {
        let (kps, _pk) = split_known_secret(&hex32(NIP44_VECTORS[0].0));
        let pub2 = hex32(NIP44_VECTORS[0].1);
        let lone = threshold_ecdh_untweaked(&[&kps[0]], &pub2);
        assert!(
            matches!(lone, Err(EcdhError::SubThreshold(_))),
            "a lone signer (1 of 2-of-3) must be rejected as SubThreshold, got {lone:?}"
        );
        println!("TOOTH subthreshold PASS: the driver rejects a sub-threshold set (no silent wrong secret)");
    }

    /// Shares must be bound to their group: mixing key packages from two different keysets,
    /// or handing tweaked-Q a mismatched PublicKeyPackage, is rejected (MismatchedGroup).
    /// (Finding 2.)
    #[test]
    fn tooth_rejects_cross_keyset_shares() {
        let (kps_a, pk_a) = split_known_secret(&hex32(NIP44_VECTORS[0].0));
        let (kps_b, _pk_b) = split_known_secret(&hex32(NIP44_VECTORS[1].0));
        let pub2 = hex32(NIP44_VECTORS[0].1);

        // One share from keyset A, one from keyset B: not one group.
        let mixed = threshold_ecdh_untweaked(&[&kps_a[0], &kps_b[1]], &pub2);
        assert!(
            matches!(mixed, Err(EcdhError::MismatchedGroup(_))),
            "cross-keyset signers must be rejected, got {mixed:?}"
        );

        // Valid keyset-A quorum but the WRONG PublicKeyPackage's tweak would be applied.
        let (_kps_b2, pk_b) = split_known_secret(&hex32(NIP44_VECTORS[1].0));
        let wrong_pk = threshold_ecdh_tweaked_q(&[&kps_a[0], &kps_a[1]], &pk_b, &pub2);
        assert!(
            matches!(wrong_pk, Err(EcdhError::MismatchedGroup(_))),
            "tweaked-Q with a mismatched PublicKeyPackage must be rejected, got {wrong_pk:?}"
        );
        // Sanity: the matching pubkeys is accepted.
        assert!(threshold_ecdh_tweaked_q(&[&kps_a[0], &kps_a[1]], &pk_a, &pub2).is_ok());
        println!("TOOTH group-binding PASS: cross-keyset shares and mismatched pubkeys are rejected (MismatchedGroup)");
    }
}
