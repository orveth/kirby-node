//! H1: Shamir 2-of-3 secret sharing of the master seed + domain-separated subkey
//! derivation (`plans/build-spec-kirby-hibernation-thinslice.md`, chunk H1).
//!
//! The bootstrap secret is a single high-entropy [`MasterSeed`] (the thin slice's
//! master seed == the node seed, the F3 one-key invariant). Two independent jobs:
//!
//! 1. **Split / combine.** [`split_seed`] cuts the seed into [`SEAL_SHARES`] shares
//!    (one per holder); any [`SEAL_THRESHOLD`] of them reconstruct it via
//!    [`combine_shares`]. Losing one holder is survivable.
//! 2. **Derive.** [`derive_subkeys`] expands the seed into three INDEPENDENT subkeys
//!    (identity key, state-encryption key, wallet seed). The agent's npub, its sealed
//!    state encryption, and its ecash wallet therefore all trace to the one seed but
//!    never share key material.
//!
//! ## Why `blahaj` for the SSS
//!
//! `blahaj` is the maintained, RUSTSEC-recommended fix of the `sharks` crate
//! (RUSTSEC-2024-0398: `sharks` drew polynomial coefficients from `[1, 255]` instead
//! of `[0, 255]`, a bias Cure53 found exploitable when the SAME secret is re-shared
//! ~500-1500 times — exactly this design's "re-derive + re-split on every seal"
//! pattern). It implements textbook GF(256) byte-wise Shamir, which is the correct
//! construction for splitting a raw byte seed (each secret byte is shared
//! independently in GF(2^8); a share is `[x, y_0, y_1, ...]`). Minimal, fully
//! auditable, no elliptic-curve machinery. The crate is encapsulated behind this
//! module's functions, so swapping the SSS backend (e.g. to `vsss-rs`) stays local to
//! [`split_seed`] / [`combine_shares`].
//!
//! ## Corrupt-share detection (honest-actor scope)
//!
//! Each [`Share`] carries a [`share_commitment`]: `sha256(domain ‖ index ‖ epoch ‖
//! share_bytes)`. [`combine_shares`] recomputes and checks it before reconstruction,
//! so a GARBLED share (a bit flip, truncation, an epoch mixup) is caught rather than
//! silently poisoning the recovered seed. This is a self-consistency CHECKSUM, NOT
//! verifiable secret sharing: it does not defend against a malicious holder who
//! recomputes the commitment for a forged share. That cross-check — released share vs.
//! the commitment published in the [`super::Seal`] / [`super::WatcherRecord`] — is the
//! unseal ceremony's job (H5), which reuses [`share_commitment`] against the EXTERNAL
//! committed value.
//!
//! ## Secret hygiene
//!
//! [`MasterSeed`] and [`Subkeys`] zeroize on drop and deliberately implement no
//! `Debug` / `Display` / `Serialize`, so seed material can never be logged or
//! serialized by accident. Subkeys are HKDF-expanded DIRECTLY into the (zeroizing)
//! [`Subkeys`] fields and the recovered seed is copied straight into [`MasterSeed`], so
//! no staging buffer is left un-wiped on the stack; the reconstruction buffer is
//! [`Zeroizing`]. The share payload rides in [`super::ShareBytes`] — zeroizing, with a
//! redacted `Debug` — so a stray `{:?}` on a [`Share`] can't dump share material.
//! Nothing in this module emits tracing for seed or share bytes.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{Share, ShareBytes, SEAL_SHARES, SEAL_THRESHOLD};

/// The master-seed length in bytes: a 256-bit root secret (the thin slice's master
/// seed == the node's secp256k1/BIP340 secret key width).
pub const MASTER_SEED_LEN: usize = 32;

/// The derived identity-key length (a secp256k1 secret-scalar width; the agent's
/// Nostr/identity key is keyed from this subkey downstream).
pub const IDENTITY_KEY_LEN: usize = 32;
/// The derived state-encryption-key length (an AEAD key width).
pub const STATE_KEY_LEN: usize = 32;
/// The derived wallet-seed length (the cdk `Wallet::new` seed width).
pub const WALLET_SEED_LEN: usize = 64;

/// HKDF `info` for the identity subkey. The three `info` labels are DISTINCT, which
/// is what makes the subkeys cryptographically independent (HKDF domain separation).
const INFO_IDENTITY: &[u8] = b"kirby-hibernate/v1/identity-key";
/// HKDF `info` for the state-encryption subkey.
const INFO_STATE: &[u8] = b"kirby-hibernate/v1/state-encryption-key";
/// HKDF `info` for the wallet-seed subkey.
const INFO_WALLET: &[u8] = b"kirby-hibernate/v1/wallet-seed";
/// Domain tag prefixing every share commitment, so the checksum can't collide with
/// any other sha256 use in the protocol.
const COMMIT_DOMAIN: &[u8] = b"kirby-hibernate/v1/share-commitment";

/// The master seed: the 256-bit root secret that the agent's identity, state-key, and
/// wallet subkeys all derive from, and the secret the Shamir shares reconstruct.
///
/// Zeroized on drop; intentionally NOT `Debug`/`Clone`/`Serialize` so the raw seed
/// cannot be logged, copied, or persisted by accident. Read only internally, via the
/// private [`MasterSeed::expose_secret`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed([u8; MASTER_SEED_LEN]);

impl MasterSeed {
    /// Wrap raw seed bytes (the thin slice passes the node seed here). The returned
    /// seed zeroizes on drop; the caller still owns hygiene for its own source buffer
    /// (a move is a bitwise copy and does not wipe the origin), so callers holding the
    /// seed elsewhere should zeroize that copy themselves.
    pub fn from_bytes(bytes: [u8; MASTER_SEED_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw seed bytes. Private: only [`split_seed`] / [`derive_subkeys`]
    /// touch the raw secret; callers work with shares and subkeys, never the seed.
    fn expose_secret(&self) -> &[u8; MASTER_SEED_LEN] {
        &self.0
    }
}

/// The three domain-separated subkeys derived from a [`MasterSeed`].
///
/// Zeroized on drop and not `Debug`/`Serialize`. The fields are public so the seal /
/// unseal ceremonies can read them, but a consumer that copies a field out (the
/// arrays are `Copy`) owns that copy's hygiene — treat copied subkey bytes as secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Subkeys {
    /// The agent identity subkey (downstream: the Nostr/identity key).
    pub identity_key: [u8; IDENTITY_KEY_LEN],
    /// The state-bundle encryption subkey.
    pub state_key: [u8; STATE_KEY_LEN],
    /// The ecash wallet seed subkey.
    pub wallet_seed: [u8; WALLET_SEED_LEN],
}

/// What can go wrong reconstructing a seed from shares.
#[derive(Debug, thiserror::Error)]
pub enum ShamirError {
    /// Fewer than [`SEAL_THRESHOLD`] shares were supplied.
    #[error("need at least the {SEAL_THRESHOLD}-share threshold to combine, got {0}")]
    NotEnoughShares(usize),
    /// A share failed its commitment check (corrupt, garbled, or wrong-epoch).
    #[error("share {0} failed its commitment check (corrupt or wrong share)")]
    CorruptShare(u8),
    /// Two shares carried the same evaluation point (x-coordinate); Shamir
    /// reconstruction needs DISTINCT points, so a duplicate is refused rather than
    /// risking a divide-by-zero or a silently wrong seed.
    #[error("duplicate share index {0} (shares must have distinct evaluation points)")]
    DuplicateShareIndex(u8),
    /// A share's bytes were not a well-formed Shamir share.
    #[error("malformed share bytes (not a valid Shamir share)")]
    MalformedShare,
    /// The supplied shares did not all belong to the same seal epoch.
    #[error("shares span multiple seal epochs (expected one, refusing to combine)")]
    EpochMismatch,
    /// Reconstruction itself failed (e.g. duplicate share indices).
    #[error("secret reconstruction failed")]
    ReconstructionFailed,
    /// The reconstructed secret was not [`MASTER_SEED_LEN`] bytes.
    #[error("reconstructed seed had unexpected length {0} (expected {MASTER_SEED_LEN})")]
    WrongSeedLen(usize),
}

/// Expand a [`MasterSeed`] into three independent subkeys via HKDF-SHA256.
///
/// One extract (seed as IKM, empty salt — the seed is already uniformly random), then
/// one expand per subkey with a DISTINCT `info` label. Distinct labels => independent
/// keys: learning one subkey reveals nothing about the others. Deterministic: the same
/// seed always yields the same subkeys (so a reconstituted agent re-derives identical
/// keys).
pub fn derive_subkeys(seed: &MasterSeed) -> Subkeys {
    let hk = Hkdf::<Sha256>::new(None, seed.expose_secret());

    // Expand directly into the (zeroizing) Subkeys fields — no separate staging arrays
    // that, once moved into the struct, would leave un-wiped secret bytes on the stack.
    let mut subkeys = Subkeys {
        identity_key: [0u8; IDENTITY_KEY_LEN],
        state_key: [0u8; STATE_KEY_LEN],
        wallet_seed: [0u8; WALLET_SEED_LEN],
    };
    // expand only fails when the output length exceeds 255*HashLen; our lengths are
    // small compile-time constants, so this is an invariant, not a runtime condition.
    hk.expand(INFO_IDENTITY, &mut subkeys.identity_key)
        .expect("identity subkey length is valid");
    hk.expand(INFO_STATE, &mut subkeys.state_key)
        .expect("state subkey length is valid");
    hk.expand(INFO_WALLET, &mut subkeys.wallet_seed)
        .expect("wallet subkey length is valid");
    subkeys
}

/// The corrupt-share commitment: `sha256(domain ‖ index ‖ epoch ‖ share_bytes)`,
/// lowercase hex. Binding the index + epoch in means a share can't be silently
/// re-labelled or replayed under a different epoch and still match. Reused by the
/// unseal ceremony (H5) to check a released share against the published commitment.
pub fn share_commitment(share_index: u8, seal_epoch: u64, share_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    h.update([share_index]);
    h.update(seal_epoch.to_le_bytes());
    h.update(share_bytes);
    hex::encode(h.finalize())
}

/// Recompute a share's commitment and check it matches the stored one. `Ok` means the
/// share is self-consistent; `Err(CorruptShare)` means it was garbled or mismatched.
pub fn verify_share(share: &Share) -> Result<(), ShamirError> {
    let expected = share_commitment(
        share.share_index,
        share.seal_epoch,
        share.share_bytes.as_slice(),
    );
    // Plain comparison is fine: the commitment is a PUBLIC value (carried in the
    // wake-request / watcher record), not a secret, so there is no timing oracle to
    // protect against — this only detects accidental garbling.
    if expected != share.commitment {
        return Err(ShamirError::CorruptShare(share.share_index));
    }
    Ok(())
}

/// Split `seed` into exactly [`SEAL_SHARES`] shares under a [`SEAL_THRESHOLD`]-of-
/// [`SEAL_SHARES`] policy, stamping each with `seal_epoch` and its commitment.
///
/// Shares get 1-based indices (the GF(256) x-coordinates `1..=SEAL_SHARES`). The split
/// draws its random polynomial coefficients from the OS CSPRNG (`blahaj`'s default
/// `dealer`), uniformly over the full field — the property the `sharks` advisory was
/// about.
pub fn split_seed(seed: &MasterSeed, seal_epoch: u64) -> Vec<Share> {
    let sharks = blahaj::Sharks(SEAL_THRESHOLD);
    let dealer = sharks.dealer(seed.expose_secret());

    let mut shares = Vec::with_capacity(SEAL_SHARES as usize);
    for sss in dealer.take(SEAL_SHARES as usize) {
        // blahaj serializes a share as [x, y_0, y_1, ...]; byte 0 is the x-coordinate
        // (the 1-based share index), the source of truth for reconstruction.
        let raw: Vec<u8> = (&sss).into();
        let share_index = raw[0];
        let commitment = share_commitment(share_index, seal_epoch, &raw);
        shares.push(Share {
            share_index,
            share_bytes: ShareBytes::new(raw),
            seal_epoch,
            commitment,
        });
    }
    debug_assert_eq!(shares.len(), SEAL_SHARES as usize);
    shares
}

/// Reconstruct the [`MasterSeed`] from `shares` (any [`SEAL_THRESHOLD`] suffice).
///
/// Guards before reconstructing: at least threshold shares present, all from one seal
/// epoch, each self-consistent against its commitment, each x-coordinate valid
/// (`1..=SEAL_SHARES`) and matching its labeled index, and no two sharing a point. The
/// recovered secret lives in a [`Zeroizing`] buffer and is copied straight into the
/// returned seed, so no plaintext copy lingers.
pub fn combine_shares(shares: &[Share]) -> Result<MasterSeed, ShamirError> {
    if shares.len() < SEAL_THRESHOLD as usize {
        return Err(ShamirError::NotEnoughShares(shares.len()));
    }

    let epoch = shares[0].seal_epoch;
    let mut seen_points = std::collections::BTreeSet::new();
    for share in shares {
        if share.seal_epoch != epoch {
            return Err(ShamirError::EpochMismatch);
        }
        verify_share(share)?;
        // The reconstruction x-coordinate is byte 0 of the share (blahaj's wire
        // layout). Validate it before trusting it: a structurally-bad point (0, or
        // outside 1..=SEAL_SHARES) is malformed, and a point that disagrees with the
        // labeled share_index is a self-recommitted inconsistency verify_share CANNOT
        // catch — the commitment binds the labeled index, not byte 0, so a forger can
        // relabel the index and reconstruct at a different point. Reject all three.
        let point = *share
            .share_bytes
            .as_slice()
            .first()
            .ok_or(ShamirError::MalformedShare)?;
        if point == 0 || point > SEAL_SHARES {
            return Err(ShamirError::MalformedShare);
        }
        if point != share.share_index {
            return Err(ShamirError::CorruptShare(share.share_index));
        }
        if !seen_points.insert(point) {
            return Err(ShamirError::DuplicateShareIndex(point));
        }
    }

    let sss_shares: Result<Vec<blahaj::Share>, _> = shares
        .iter()
        .map(|s| blahaj::Share::try_from(s.share_bytes.as_slice()))
        .collect();
    let sss_shares = sss_shares.map_err(|_| ShamirError::MalformedShare)?;

    let sharks = blahaj::Sharks(SEAL_THRESHOLD);
    let secret = Zeroizing::new(
        sharks
            .recover(sss_shares.as_slice())
            .map_err(|_| ShamirError::ReconstructionFailed)?,
    );

    if secret.len() != MASTER_SEED_LEN {
        return Err(ShamirError::WrongSeedLen(secret.len()));
    }
    // Copy the recovered secret straight into the (zeroizing) MasterSeed field — no
    // intermediate stack array that would be moved-from and left un-wiped.
    let mut seed = MasterSeed([0u8; MASTER_SEED_LEN]);
    seed.0.copy_from_slice(&secret);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random 32-byte secret stream (no `rand` dep needed): a
    /// sha256 of a counter. The split→combine property holds for any secret.
    fn pseudo_secret(n: u64) -> [u8; MASTER_SEED_LEN] {
        let mut h = Sha256::new();
        h.update(b"shamir-test-secret");
        h.update(n.to_le_bytes());
        let digest = h.finalize();
        let mut seed = [0u8; MASTER_SEED_LEN];
        seed.copy_from_slice(&digest);
        seed
    }

    #[test]
    fn split_then_combine_roundtrips_for_all_2_subsets() {
        for n in 0..64u64 {
            let secret = pseudo_secret(n);
            let shares = split_seed(&MasterSeed::from_bytes(secret), 1);
            assert_eq!(shares.len(), 3);
            // indices are the 1-based x-coordinates 1,2,3.
            assert_eq!(
                [
                    shares[0].share_index,
                    shares[1].share_index,
                    shares[2].share_index
                ],
                [1, 2, 3]
            );

            // every 2-of-3 subset reconstructs the original secret.
            for combo in [[0usize, 1], [0, 2], [1, 2]] {
                let subset = [shares[combo[0]].clone(), shares[combo[1]].clone()];
                let recovered = combine_shares(&subset).expect("combine 2-subset");
                assert_eq!(
                    recovered.expose_secret(),
                    &secret,
                    "subset {combo:?}, n={n}"
                );
            }
            // all three together also reconstruct.
            let recovered_all = combine_shares(&shares).expect("combine all three");
            assert_eq!(recovered_all.expose_secret(), &secret);
        }
    }

    #[test]
    fn one_share_is_below_threshold() {
        let shares = split_seed(&MasterSeed::from_bytes(pseudo_secret(7)), 1);
        match combine_shares(&shares[..1]) {
            Err(ShamirError::NotEnoughShares(1)) => {}
            Err(e) => panic!("expected NotEnoughShares(1), got {e:?}"),
            Ok(_) => panic!("expected NotEnoughShares(1), but combine succeeded"),
        }
    }

    #[test]
    fn a_corrupted_share_is_detected() {
        let shares = split_seed(&MasterSeed::from_bytes(pseudo_secret(3)), 1);
        let mut garbled = shares[0].clone();
        // flip a payload byte but leave the (now stale) commitment in place.
        let mut raw = garbled.share_bytes.as_slice().to_vec();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        garbled.share_bytes = ShareBytes::new(raw);
        let subset = [garbled.clone(), shares[1].clone()];
        match combine_shares(&subset) {
            Err(ShamirError::CorruptShare(idx)) => assert_eq!(idx, garbled.share_index),
            Err(e) => panic!("expected CorruptShare, got {e:?}"),
            Ok(_) => panic!("expected CorruptShare, but combine succeeded"),
        }
    }

    #[test]
    fn mixed_epoch_shares_are_refused() {
        let a = split_seed(&MasterSeed::from_bytes(pseudo_secret(5)), 1);
        let b = split_seed(&MasterSeed::from_bytes(pseudo_secret(5)), 2);
        let subset = [a[0].clone(), b[1].clone()];
        assert!(matches!(
            combine_shares(&subset),
            Err(ShamirError::EpochMismatch)
        ));
    }

    #[test]
    fn duplicate_share_indices_are_refused() {
        let shares = split_seed(&MasterSeed::from_bytes(pseudo_secret(9)), 1);
        // two copies of the same share = one distinct evaluation point.
        let dup = [shares[0].clone(), shares[0].clone()];
        match combine_shares(&dup) {
            Err(ShamirError::DuplicateShareIndex(x)) => {
                assert_eq!(x, shares[0].share_bytes.as_slice()[0])
            }
            Err(e) => panic!("expected DuplicateShareIndex, got {e:?}"),
            Ok(_) => panic!("expected DuplicateShareIndex, but combine succeeded"),
        }
    }

    #[test]
    fn mismatched_x_coordinate_is_rejected() {
        let shares = split_seed(&MasterSeed::from_bytes(pseudo_secret(13)), 1);
        // Forge a share whose LABELED index disagrees with its byte-0 x-coord, and
        // re-commit so verify_share (which binds the labeled index) still passes.
        let mut forged = shares[0].clone();
        let real_point = forged.share_bytes.as_slice()[0];
        forged.share_index = real_point + 1; // a lie (real_point is 1 here, so still in range)
        forged.commitment = share_commitment(
            forged.share_index,
            forged.seal_epoch,
            forged.share_bytes.as_slice(),
        );
        // verify_share passes — the commitment matches the labeled index...
        assert!(verify_share(&forged).is_ok());
        // ...but combine catches that the labeled index != the reconstruction point.
        let subset = [forged.clone(), shares[1].clone()];
        match combine_shares(&subset) {
            Err(ShamirError::CorruptShare(idx)) => assert_eq!(idx, forged.share_index),
            Err(e) => panic!("expected CorruptShare, got {e:?}"),
            Ok(_) => panic!("expected CorruptShare, but combine succeeded"),
        }
    }

    #[test]
    fn subkeys_are_deterministic_and_domain_separated() {
        let seed = MasterSeed::from_bytes(pseudo_secret(11));
        let a = derive_subkeys(&seed);
        let b = derive_subkeys(&seed);
        // deterministic: same seed => same subkeys.
        assert_eq!(a.identity_key, b.identity_key);
        assert_eq!(a.state_key, b.state_key);
        assert_eq!(a.wallet_seed, b.wallet_seed);
        // domain-separated: distinct `info` => distinct keys (identity and state are
        // the same length, so equality here would mean separation failed).
        assert_ne!(a.identity_key, a.state_key);
        assert_ne!(&a.wallet_seed[..32], &a.identity_key[..]);
        assert_ne!(&a.wallet_seed[..32], &a.state_key[..]);
        assert_ne!(&a.wallet_seed[32..], &a.wallet_seed[..32]);
        // different seed => different subkeys.
        let other = derive_subkeys(&MasterSeed::from_bytes(pseudo_secret(12)));
        assert_ne!(a.identity_key, other.identity_key);
        assert_ne!(a.state_key, other.state_key);
        assert_ne!(a.wallet_seed, other.wallet_seed);
    }

    #[test]
    fn commitment_binds_index_and_epoch() {
        let bytes = vec![9u8, 8, 7, 6, 5];
        // same bytes, different epoch or index => different commitment.
        assert_ne!(
            share_commitment(1, 1, &bytes),
            share_commitment(1, 2, &bytes)
        );
        assert_ne!(
            share_commitment(1, 1, &bytes),
            share_commitment(2, 1, &bytes)
        );
        // recomputing the same inputs is stable.
        assert_eq!(
            share_commitment(1, 1, &bytes),
            share_commitment(1, 1, &bytes)
        );
    }
}
