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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// NIP-44 v2 HKDF-Extract salt (<https://nips.nostr.com/44>).
const NIP44_V2_SALT: &[u8] = b"nip44-v2";

/// Domain-separation tag for the threshold-ECDH DLEQ challenge (a BIP-340-style tagged hash,
/// [`dleq_challenge`]). Versioned so a future construction change is unambiguous. codex flagged
/// transcript binding + a ciphersuite/domain tag as mandatory (protocol hygiene, not algebraic
/// necessity); this is that tag.
const DLEQ_DST: &[u8] = b"kirby/threshold-ecdh/dleq/v1";

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
    /// A holder's DLEQ proof did not verify against its CANONICAL public verifying share:
    /// the raw contribution `D_i` does NOT use the same secret share `s_i` as `V_i = s_i·G`.
    /// The `String` names the holder (identifiable blame) — an ECDH aggregate has no public
    /// verification equation, so an unverified `D_i` MUST be dropped + attributed here rather
    /// than silently folded into a corrupt shared secret. Fail-closed.
    DleqVerifyFailed(String),
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
            EcdhError::DleqVerifyFailed(m) => write!(f, "DLEQ proof failed to verify: {m}"),
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

// A `WirePoint` crosses the ceremony seam (inside an [`EcdhContribution`] / [`DleqProof`]), so it
// serializes. It is a fixed 33-byte compressed SEC1 point; serde has no built-in impl for `[u8; 33]`
// (only arrays up to 32), so encode as lowercase hex (canonical, human-debuggable on the wire). This
// is a pure BYTE container — on-curve validation happens at [`WirePoint::to_projective`] use-sites,
// exactly as for a `WirePoint` built any other way (a malformed hex point is caught there, not here).
impl Serialize for WirePoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for WirePoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 33] = bytes.as_slice().try_into().map_err(|_| {
            serde::de::Error::custom("WirePoint must be exactly 33 bytes (compressed SEC1)")
        })?;
        Ok(WirePoint(arr))
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

// ================================================================================================
// CROSS-MACHINE threshold-ECDH: RAW holder contributions + a Chaum-Pedersen DLEQ integrity proof.
//
// The co-located [`holder_ecdh_contribution`] bakes the Lagrange weight λ_i into the holder's
// output (`λ_i·s_i·B`). The CROSS-MACHINE path instead has each holder emit the RAW point
// `D_i = s_i·B` + a DLEQ proof, and the COORDINATOR applies λ_i over the responding set. This
// (codex-recommended) split makes the DLEQ a DIRECT proof against the holder's PUBLIC verifying
// share `V_i = s_i·G` (`log_G(V_i) == log_B(D_i)`), and the holder no longer needs to know the
// signing set. The final aggregate is identical to the co-located tweaked-Q path (a test locks
// `aggregate_raw_contributions_tweaked_q == threshold_ecdh_tweaked_q`, so the NIP-44 vectors
// validate this path transitively).
//
// WHY THE PROOF (codex Q3): unlike a bad *signature* share (which fails aggregate verification
// against Q for free), a bad *ECDH* share has NO public verification equation — a wrong `D_i`
// silently yields a wrong shared point with no way to attribute the fault. The DLEQ gives
// per-contribution correctness + IDENTIFIABLE BLAME at contribution time, so the coordinator
// drops + names the cheating holder and never folds an unverified `D_i` into the secret.
// ================================================================================================

/// A holder's RAW ECDH contribution `D_i = s_i·B` (NO Lagrange weight — the coordinator applies λ
/// over the responding set) plus a [`DleqProof`] that `D_i` uses the SAME secret share `s_i` as the
/// holder's PUBLIC verifying share `V_i = s_i·G`. Crosses the ceremony seam holder→coordinator:
/// a POINT + a proof, NEVER the share (recovering `s_i` from `s_i·B` is a discrete-log problem).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhContribution {
    /// The raw contribution point `D_i = s_i·B` (compressed SEC1).
    pub d_i: WirePoint,
    /// The DLEQ proof binding `D_i` to the holder's canonical `V_i`.
    pub proof: DleqProof,
}

/// A non-interactive Chaum-Pedersen DLEQ proof that `log_G(V) == log_B(D)` for a secret scalar `s`
/// (`V = s·G` public, `D = s·B`), over secp256k1 with Fiat-Shamir. Carries the `(R1, R2, z)`
/// variant. codex confirmed the exact construction (both verification equations). Without it a
/// byzantine holder's wrong `D` silently corrupts the aggregate with no identifiable blame.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DleqProof {
    /// `R1 = r·G` (the commitment on the `G` base).
    r1: WirePoint,
    /// `R2 = r·B` (the commitment on the `B` base).
    r2: WirePoint,
    /// `z = r + c·s` (mod n), 32-byte big-endian.
    z: [u8; 32],
}

// Hand-written Debug (NOT derived) — REDACT the secret-derived point material so a stray `{:?}` on a
// contribution can never dump it to a log (codex F3). `D_i = s_i·B` is sensitive: a threshold of D_i's
// reconstructs K_self (the NIP-44 conversation key). The DLEQ transcript (R1, R2, z) is derived from
// the holder's secret nonce r (z also folds in the share s); though it crosses the wire alongside D_i,
// we keep raw nonce-derived point/scalar hex out of logs on this money path. Serde (the ACTUAL wire
// form) is untouched — only the human/log rendering is redacted; the struct name stays for diagnostics.
impl fmt::Debug for EcdhContribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdhContribution")
            .field("d_i", &"<redacted D_i>")
            .field("proof", &self.proof)
            .finish()
    }
}

impl fmt::Debug for DleqProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DleqProof")
            .field("r1", &"<redacted>")
            .field("r2", &"<redacted>")
            .field("z", &"<redacted>")
            .finish()
    }
}

/// Serialize a k256 scalar to its 32-byte big-endian form (the wire encoding of `z`).
fn scalar_to_be_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

/// The Fiat-Shamir challenge `c = tagged_hash(DLEQ_DST, G ‖ B ‖ V ‖ D ‖ R1 ‖ R2) mod n`. Binds
/// ALL public points (codex: transcript binding is mandatory) + a domain-separation tag. `G` is
/// fixed by the ciphersuite but included for cleanliness. Points are canonical compressed SEC1.
/// A `tagged_hash` per BIP-340 (`SHA256(SHA256(tag)‖SHA256(tag)‖msg)`), reduced mod n like
/// [`tap_tweak_none`]. The caller REJECTS `c == 0` (a zero challenge makes the proof trivially
/// satisfiable for any `D`); its probability is ~2⁻²⁵⁶.
fn dleq_challenge(
    b: &WirePoint,
    v: &WirePoint,
    d: &WirePoint,
    r1: &WirePoint,
    r2: &WirePoint,
) -> Scalar {
    let g = ProjectivePoint::GENERATOR.to_affine().to_encoded_point(true);
    let tag_hash = Sha256::digest(DLEQ_DST);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(g.as_bytes());
    hasher.update(b.0);
    hasher.update(v.0);
    hasher.update(d.0);
    hasher.update(r1.0);
    hasher.update(r2.0);
    Scalar::reduce(U256::from_be_slice(&hasher.finalize()))
}

/// Holder-side: compute the RAW ECDH contribution `D = s·B` for the PUBLIC peer point `B` (which is
/// the target key, or `Q` itself for self-decrypt), and a DLEQ proof that `D` uses the SAME `s` as
/// the holder's public verifying share `V = s·G`. The secret share never leaves the holder; only a
/// point + a proof cross the seam.
///
/// The proof is built over `V = s·G` recomputed from the holder's own `s`, so the proof is
/// internally consistent; the COORDINATOR verifies it against the CANONICAL `V_i` from the group
/// `PublicKeyPackage` (never a holder-asserted one), so a holder whose `s` does not match its
/// canonical share cannot produce a passing contribution (it is caught + attributed).
pub fn holder_ecdh_raw_contribution(
    kp: &KeyPackage,
    peer: &WirePoint,
) -> Result<EcdhContribution, EcdhError> {
    let s = scalar_from_be_bytes(&kp.signing_share().serialize())?;
    let b = peer.to_projective()?;
    // D = s·B (raw). from_projective rejects the identity (a zero share / canceling combine).
    let d_i = WirePoint::from_projective(&(b * s))?;
    // V = s·G, recomputed from THIS holder's s (binds the proof to the same s that made D).
    let v = WirePoint::from_projective(&(ProjectivePoint::GENERATOR * s))?;
    // Fiat-Shamir: r ← nonzero CSPRNG scalar; R1 = r·G, R2 = r·B; c = H(transcript); z = r + c·s.
    let mut rng = rand::rngs::OsRng;
    let r = *k256::NonZeroScalar::random(&mut rng);
    let r1 = WirePoint::from_projective(&(ProjectivePoint::GENERATOR * r))?;
    let r2 = WirePoint::from_projective(&(b * r))?;
    let c = dleq_challenge(peer, &v, &d_i, &r1, &r2);
    if c == Scalar::ZERO {
        // ~2⁻²⁵⁶; a zero challenge makes the proof trivially satisfiable — refuse to emit one.
        return Err(EcdhError::MalformedScalar("DLEQ challenge reduced to zero".to_string()));
    }
    let z = r + c * s;
    Ok(EcdhContribution {
        d_i,
        proof: DleqProof { r1, r2, z: scalar_to_be_bytes(&z) },
    })
}

/// Verify a [`DleqProof`] that `D = s·B` uses the SAME `s` as the public `V = s·G`
/// (`log_G(V) == log_B(D)`). Recomputes the Fiat-Shamir challenge over the SAME transcript,
/// rejects a zero challenge and a non-canonical `z`, then checks BOTH equations
/// `z·G == R1 + c·V` and `z·B == R2 + c·D`. `Ok(())` iff valid; any failure is a
/// [`EcdhError::DleqVerifyFailed`] (fail-closed). Every point is validated on decode
/// ([`WirePoint::to_projective`]); the identity has no 33-byte compressed form so it cannot appear.
pub fn verify_dleq_share(
    proof: &DleqProof,
    b: &WirePoint,
    v: &WirePoint,
    d: &WirePoint,
) -> Result<(), EcdhError> {
    let b_pt = b.to_projective()?;
    let v_pt = v.to_projective()?;
    let d_pt = d.to_projective()?;
    let r1_pt = proof.r1.to_projective()?;
    let r2_pt = proof.r2.to_projective()?;
    // z must be a canonical (< n) scalar.
    let z = scalar_from_be_bytes(&proof.z)?;
    let c = dleq_challenge(b, v, d, &proof.r1, &proof.r2);
    if c == Scalar::ZERO {
        return Err(EcdhError::DleqVerifyFailed("challenge reduced to zero".to_string()));
    }
    // z·G == R1 + c·V  AND  z·B == R2 + c·D
    let ok_g = ProjectivePoint::GENERATOR * z == r1_pt + v_pt * c;
    let ok_b = b_pt * z == r2_pt + d_pt * c;
    if ok_g && ok_b {
        Ok(())
    } else {
        Err(EcdhError::DleqVerifyFailed("DLEQ equation check failed".to_string()))
    }
}

/// Verify a SINGLE holder's contribution against its CANONICAL verifying share `V_i` (the group's
/// known share for `id`) for the peer `peer_xonly`. This is the per-contribution check a coordinator
/// runs to ACCEPT or REJECT a responder BEFORE counting it toward the threshold: a byzantine holder
/// whose `D_i` fails is then skipped like an unreachable one (the round continues to another holder),
/// rather than a single bad share aborting a round an honest majority could complete. Returns
/// [`EcdhError::DleqVerifyFailed`] (attributed) on a bad proof.
pub fn verify_contribution(
    pubkeys: &PublicKeyPackage,
    id: &Identifier,
    peer_xonly: &[u8; 32],
    contribution: &EcdhContribution,
) -> Result<(), EcdhError> {
    let peer = peer_point_from_xonly(peer_xonly)?;
    let v_i = verifying_share_point(pubkeys, id)?;
    verify_dleq_share(&contribution.proof, &peer, &v_i, &contribution.d_i)
}

/// The CANONICAL public verifying share `V_i = s_i·G` for holder `id`, from the group
/// `PublicKeyPackage`. The coordinator verifies each DLEQ against THIS (never a holder-asserted V):
/// it is what binds a raw contribution to the fleet's known share for that identifier.
fn verifying_share_point(
    pubkeys: &PublicKeyPackage,
    id: &Identifier,
) -> Result<WirePoint, EcdhError> {
    let vs = pubkeys.verifying_shares().get(id).ok_or_else(|| {
        EcdhError::MismatchedGroup(format!("{id:?} is not a member of the PublicKeyPackage"))
    })?;
    let bytes = vs
        .serialize()
        .map_err(|e| EcdhError::MalformedPoint(e.to_string()))?;
    let arr: [u8; 33] = bytes.as_slice().try_into().map_err(|_| {
        EcdhError::MalformedPoint("verifying share is not a 33-byte compressed point".to_string())
    })?;
    Ok(WirePoint(arr))
}

/// The COORDINATOR aggregate over the RESPONDING holders for the tweaked identity `Q`. For each
/// contribution: VERIFY its DLEQ against the CANONICAL `V_i` (fail-closed + attributed — an
/// unverified `D_i` is never folded), then λ-weight `D_i` over the EXACT responding set and sum to
/// `S_B = Σ λ_i·D_i = s·B` (untweaked; `s` never formed). Finally fold parity + the public taproot
/// tweak once — `Q_B = μ·S_B + t·B` — identical to [`threshold_ecdh_tweaked_q`] (the tweak lives
/// entirely in the coordinator's public post-step; the per-holder DLEQ is about `s_i`, not the
/// tweak — codex).
///
/// `contributions` is `(identifier, contribution)` for each responding holder. Requires
/// `>= min_signers` DISTINCT responders that are members of `pubkeys` (a sub-threshold or
/// cross-keyset combine folds to the WRONG scalar and is rejected up front, fail-closed).
pub fn aggregate_raw_contributions_tweaked_q(
    contributions: &[(Identifier, EcdhContribution)],
    pubkeys: &PublicKeyPackage,
    min_signers: u16,
    peer_xonly: &[u8; 32],
) -> Result<WirePoint, EcdhError> {
    if contributions.is_empty() {
        return Err(EcdhError::EmptySet);
    }
    let peer = peer_point_from_xonly(peer_xonly)?;
    let b = peer.to_projective()?;

    // The responding set (drives Lagrange). Reject duplicates — a repeated identifier would
    // double-count a share in the combine.
    let responding: Vec<Identifier> = contributions.iter().map(|(id, _)| *id).collect();
    let mut seen: BTreeSet<Identifier> = BTreeSet::new();
    for id in &responding {
        if !seen.insert(*id) {
            return Err(EcdhError::DuplicateSigner(format!("{id:?}")));
        }
    }
    // Threshold: a sub-threshold responding set Lagrange-combines to the WRONG scalar (not `s`),
    // and an ECDH aggregate has no self-check to catch it — reject it here, fail-closed.
    if responding.len() < min_signers as usize {
        return Err(EcdhError::SubThreshold(format!(
            "{} of {} required responders",
            responding.len(),
            min_signers
        )));
    }

    let mut acc = ProjectivePoint::IDENTITY;
    for (id, contrib) in contributions {
        // VERIFY against the CANONICAL V_i (membership is checked inside). A failure is a hard,
        // attributed drop — never fold an unverified contribution into the secret.
        let v_i = verifying_share_point(pubkeys, id)?;
        verify_dleq_share(&contrib.proof, &peer, &v_i, &contrib.d_i)
            .map_err(|_| EcdhError::DleqVerifyFailed(format!("holder {id:?}")))?;
        let lambda = lagrange_coefficient(id, &responding)?;
        acc += contrib.d_i.to_projective()? * lambda;
    }

    // acc = Σ λ_i·D_i = s·B (untweaked). Fold parity (frost even-Y) + the public tweak t·B once,
    // exactly as `threshold_ecdh_tweaked_q` does.
    let p = verifying_key_point(pubkeys)?;
    let d_int_b = if bool::from(p.to_affine().y_is_odd()) {
        -acc
    } else {
        acc
    };
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

    // ---- CROSS-MACHINE raw-contribution + DLEQ ----

    /// A holder's DLEQ proof round-trips: a raw contribution's proof verifies against the SAME
    /// holder's canonical `V_i` and its `D_i` (the honest-holder happy path).
    #[test]
    fn dleq_prove_verify_roundtrips() {
        let (kps, pk) = dealer_keyset();
        let peer = peer_point_from_xonly(&hex32(NIP44_VECTORS[0].1)).unwrap();
        for kp in &kps {
            let contrib = holder_ecdh_raw_contribution(kp, &peer).unwrap();
            let v_i = verifying_share_point(&pk, kp.identifier()).unwrap();
            verify_dleq_share(&contrib.proof, &peer, &v_i, &contrib.d_i)
                .expect("an honest holder's DLEQ must verify against its canonical V_i");
        }
        println!("DLEQ-ROUNDTRIP PASS: each honest raw contribution's DLEQ verifies against its canonical V_i");
    }

    /// F3 (codex LOW, secret hygiene): the hand-written Debug on [`EcdhContribution`] / [`DleqProof`]
    /// REDACTS the secret-derived point material. `D_i` (a threshold of which reconstructs K_self) must
    /// never reach a log via a stray `{:?}`. Assert the Debug string carries NEITHER the hex NOR the
    /// derived decimal-array dump of `D_i` (nor the DLEQ transcript points/scalar), while the struct
    /// name stays visible for diagnostics.
    #[test]
    fn debug_redacts_secret_ecdh_point_material() {
        let (kps, _pk) = dealer_keyset();
        let peer = peer_point_from_xonly(&hex32(NIP44_VECTORS[0].1)).unwrap();
        let contrib = holder_ecdh_raw_contribution(&kps[0], &peer).unwrap();

        let dbg = format!("{contrib:?}");

        // D_i absent in EVERY dump form (hex + the derived decimal-array form).
        assert!(!dbg.contains(&hex::encode(contrib.d_i.0)), "Debug leaked raw D_i hex: {dbg}");
        assert!(!dbg.contains(&format!("{:?}", contrib.d_i.0)), "Debug leaked raw D_i byte array: {dbg}");
        // The DLEQ transcript points/scalar are redacted too — in EVERY dump form (hex + the derived
        // decimal-array form), mirroring the D_i coverage. (A derived Debug on DleqProof would dump
        // these as decimal arrays, which the hex checks alone would miss — codex F3 tooth-gap follow-up.)
        assert!(!dbg.contains(&hex::encode(contrib.proof.r1.0)), "Debug leaked R1 hex: {dbg}");
        assert!(!dbg.contains(&format!("{:?}", contrib.proof.r1.0)), "Debug leaked R1 byte array: {dbg}");
        assert!(!dbg.contains(&hex::encode(contrib.proof.r2.0)), "Debug leaked R2 hex: {dbg}");
        assert!(!dbg.contains(&format!("{:?}", contrib.proof.r2.0)), "Debug leaked R2 byte array: {dbg}");
        assert!(!dbg.contains(&hex::encode(contrib.proof.z)), "Debug leaked z hex: {dbg}");
        assert!(!dbg.contains(&format!("{:?}", contrib.proof.z)), "Debug leaked z byte array: {dbg}");
        // Struct stays identifiable; the secret is marked redacted.
        assert!(dbg.contains("EcdhContribution"), "struct name should remain: {dbg}");
        assert!(dbg.contains("redacted"), "expected a redacted placeholder: {dbg}");
        println!("F3 PASS: EcdhContribution/DleqProof Debug redacts D_i + DLEQ transcript (no secret point hex/bytes in the dump)");
    }

    /// The DLEQ is load-bearing: a raw contribution with a TAMPERED `D_i` (a valid on-curve point,
    /// but not `s_i·B`) does NOT verify — the proof binds `D_i` to the same `s_i` as `V_i`, and the
    /// Fiat-Shamir transcript binds `D_i`, so swapping it breaks BOTH equations.
    #[test]
    fn dleq_verify_rejects_tampered_d() {
        let (kps, pk) = dealer_keyset();
        let peer = peer_point_from_xonly(&hex32(NIP44_VECTORS[0].1)).unwrap();
        let c0 = holder_ecdh_raw_contribution(&kps[0], &peer).unwrap();
        let c1 = holder_ecdh_raw_contribution(&kps[1], &peer).unwrap();
        let v0 = verifying_share_point(&pk, kps[0].identifier()).unwrap();
        // Verify holder 0's proof but against holder 1's D — must fail (D is bound in the proof).
        let res = verify_dleq_share(&c0.proof, &peer, &v0, &c1.d_i);
        assert!(
            matches!(res, Err(EcdhError::DleqVerifyFailed(_))),
            "a tampered D must fail DLEQ verification, got {res:?}"
        );
        // And verifying holder 0's proof against the WRONG V (holder 1's canonical V) fails too.
        let v1 = verifying_share_point(&pk, kps[1].identifier()).unwrap();
        assert!(
            matches!(verify_dleq_share(&c0.proof, &peer, &v1, &c0.d_i), Err(EcdhError::DleqVerifyFailed(_))),
            "verifying a proof against the wrong canonical V must fail"
        );
        println!("DLEQ-TAMPER PASS: a tampered D_i and a wrong-V both fail DLEQ verification (fail-closed)");
    }

    /// THE CORRECTNESS ORACLE: the cross-machine raw+DLEQ+aggregate path derives the SAME tweaked-Q
    /// shared point as the co-located [`threshold_ecdh_tweaked_q`] — which is itself validated
    /// against the paulmillr/nip44 v2 vectors + peer symmetry. So the distributed path inherits that
    /// validation transitively, for a real peer AND for self-decrypt (B == Q), across BOTH parities
    /// of the group key P and all three 2-of-3 quorums.
    #[test]
    fn aggregate_raw_matches_tweaked_q_both_parities() {
        // A fixed real peer, plus self-decrypt (peer == Q) exercised per keyset.
        let real_peer = hex32(NIP44_VECTORS[0].1);
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
        for (parity, (kps, pk)) in [("even-Y P", even.unwrap()), ("odd-Y P", odd.unwrap())] {
            let self_q = tweaked_q_xonly(&pk).unwrap();
            for peer_xonly in [real_peer, self_q] {
                let peer = peer_point_from_xonly(&peer_xonly).unwrap();
                for (a, c, label) in [(0usize, 1usize, "{1,2}"), (0, 2, "{1,3}"), (1, 2, "{2,3}")] {
                    let ca = holder_ecdh_raw_contribution(&kps[a], &peer).unwrap();
                    let cc = holder_ecdh_raw_contribution(&kps[c], &peer).unwrap();
                    let contribs = vec![(*kps[a].identifier(), ca), (*kps[c].identifier(), cc)];
                    let distributed =
                        aggregate_raw_contributions_tweaked_q(&contribs, &pk, 2, &peer_xonly).unwrap();
                    let colocated =
                        threshold_ecdh_tweaked_q(&[&kps[a], &kps[c]], &pk, &peer_xonly).unwrap();
                    assert_eq!(
                        distributed, colocated,
                        "{parity} quorum {label}: distributed raw+DLEQ aggregate must equal the co-located tweaked-Q ECDH"
                    );
                }
            }
        }
        println!("AGGREGATE-MATCHES PASS: distributed raw+DLEQ aggregate == co-located tweaked-Q ECDH (real peer + self-decrypt, both parities, all quorums)");
    }

    /// THE FAIL-CLOSED + IDENTIFIABLE-BLAME TOOTH: a single byzantine holder that returns a valid
    /// on-curve `D_i` which is NOT `s_i·B` (here, another holder's contribution point) is CAUGHT by
    /// the coordinator (its DLEQ fails against the canonical V_i) and the error NAMES that holder —
    /// the aggregate is never computed over an unverified contribution.
    #[test]
    fn tooth_aggregate_catches_and_attributes_tampered_contribution() {
        let (kps, pk) = dealer_keyset();
        let peer_xonly = hex32(NIP44_VECTORS[0].1);
        let peer = peer_point_from_xonly(&peer_xonly).unwrap();
        let c0 = holder_ecdh_raw_contribution(&kps[0], &peer).unwrap();
        let mut c1 = holder_ecdh_raw_contribution(&kps[1], &peer).unwrap();
        // Byzantine holder 1 swaps in holder 0's D (a valid point, wrong for holder 1's s_i).
        c1.d_i = c0.d_i;
        let contribs = vec![(*kps[0].identifier(), c0), (*kps[1].identifier(), c1)];
        let res = aggregate_raw_contributions_tweaked_q(&contribs, &pk, 2, &peer_xonly);
        let expected_blame = format!("holder {:?}", kps[1].identifier());
        match res {
            Err(EcdhError::DleqVerifyFailed(msg)) => assert_eq!(
                msg, expected_blame,
                "the refusal must ATTRIBUTE the failure to the byzantine holder"
            ),
            other => panic!("a tampered contribution must be caught + attributed, got {other:?}"),
        }
        println!("AGGREGATE-BLAME PASS: a byzantine D_i is caught and the refusal names the cheating holder (fail-closed)");
    }

    /// A sub-threshold responding set is rejected up front (an ECDH aggregate has no self-check to
    /// catch a wrong-scalar fold, so the threshold gate is load-bearing).
    #[test]
    fn tooth_aggregate_rejects_subthreshold() {
        let (kps, pk) = dealer_keyset();
        let peer_xonly = hex32(NIP44_VECTORS[0].1);
        let peer = peer_point_from_xonly(&peer_xonly).unwrap();
        let c0 = holder_ecdh_raw_contribution(&kps[0], &peer).unwrap();
        let contribs = vec![(*kps[0].identifier(), c0)];
        let res = aggregate_raw_contributions_tweaked_q(&contribs, &pk, 2, &peer_xonly);
        assert!(
            matches!(res, Err(EcdhError::SubThreshold(_))),
            "a lone responder (1 of 2-of-3) must be rejected as SubThreshold, got {res:?}"
        );
        println!("AGGREGATE-SUBTHRESHOLD PASS: a sub-threshold responding set is rejected (no wrong-scalar fold)");
    }

    /// The wire types survive serde_json (the remote-holder seam serializes an `EcdhContribution`):
    /// a round-trip is byte-preserving and the recovered contribution still DLEQ-verifies.
    #[test]
    fn ecdh_contribution_serde_roundtrips() {
        let (kps, pk) = dealer_keyset();
        let peer = peer_point_from_xonly(&hex32(NIP44_VECTORS[0].1)).unwrap();
        let contrib = holder_ecdh_raw_contribution(&kps[0], &peer).unwrap();
        let json = serde_json::to_vec(&contrib).unwrap();
        let back: EcdhContribution = serde_json::from_slice(&json).unwrap();
        assert_eq!(contrib, back, "EcdhContribution must round-trip through serde_json");
        let v0 = verifying_share_point(&pk, kps[0].identifier()).unwrap();
        verify_dleq_share(&back.proof, &peer, &v0, &back.d_i)
            .expect("the deserialized contribution must still verify");
        println!("ECDH-SERDE PASS: EcdhContribution round-trips through serde_json and still verifies");
    }
}
