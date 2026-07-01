//! Kirby custody backbone, chunk C-1: scaffold + trusted-dealer 2-of-3 keygen
//! + taproot address derivation (key-path only, merkle_root = None).
//!
//! Crate base is ZF frost-secp256k1-tr 3.0.0 (D-15). The taproot output key Q is
//! derived from the group internal key P via the BIP-341 tweak with no script tree
//! (D-16): t = TapTweak(P, None), Q = P + t*G, address = P2TR(Q), key-path only.
//! C-2 will prove a signature verifies under exactly THIS Q and fails under P, so
//! the address MUST be derived with merkle_root = None.

use std::collections::BTreeMap;

use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::{Address, KnownHrp};

use rand::{CryptoRng, RngCore};

use frost_secp256k1_tr as frost;
use frost::keys::{IdentifierList, PublicKeyPackage, SecretShare};
use frost::Identifier;

pub mod coordinator;
pub mod cosign_net;
pub mod ecdh;
pub mod guardian;
pub mod persist;
pub mod reshare;
pub mod seam;
pub use coordinator::{commit_for, key_packages, Coordinator, SessionState, SignError};
pub use ecdh::{
    holder_ecdh_contribution, nip44_conversation_key, threshold_ecdh_tweaked_q,
    threshold_ecdh_untweaked, EcdhError, WirePoint,
};
pub use reshare::{reshare_same_membership, RefreshedKeyset};
pub use seam::{coordinate_2of3_over_seam, CoSignEvent, GuardianId, InMemoryRelay, RelayAdapter};

/// A trusted-dealer keyset: the per-guardian secret shares plus the group public
/// key package. Honest label (D-2): the full key exists at the dealer at setup;
/// native DKG (ZF keys::dkg) removes that later, out of C-1 scope.
pub struct DealerKeyset {
    pub shares: BTreeMap<Identifier, SecretShare>,
    pub pubkeys: PublicKeyPackage,
}

/// Core trusted-dealer t-of-n keygen over a caller-supplied CSPRNG, with default
/// identifiers (1..=n). For the demo this is the 2-of-3 guardian set (D-6). The
/// RNG is injectable so the tests can pin a deterministic, reproducible keyset.
pub fn generate_dealer_keyset_with_rng<R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    rng: &mut R,
) -> Result<DealerKeyset, Box<dyn std::error::Error>> {
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(max_signers, min_signers, IdentifierList::Default, rng)?;
    Ok(DealerKeyset { shares, pubkeys })
}

/// Production trusted-dealer keygen: fresh entropy from the OS CSPRNG (OsRng), so
/// the keyset (and therefore the address) differs every run by design. A fixed
/// seed is a test-only fixture, never the production path.
pub fn generate_dealer_keyset(
    min_signers: u16,
    max_signers: u16,
) -> Result<DealerKeyset, Box<dyn std::error::Error>> {
    let mut rng = rand::rngs::OsRng;
    generate_dealer_keyset_with_rng(min_signers, max_signers, &mut rng)
}

/// Derive the BIP-341 taproot address for a FROST group verifying key.
///
/// P (group verifying key, x-only internal key) -> t = TapTweak(P, merkle_root=None)
/// -> Q = P + t*G -> address = P2TR(Q), KEY-PATH ONLY (no script tree). Returns the
/// address and the x-only internal key P (so callers can show P alongside Q). The
/// tweak is the one place to get wrong (spec section 8): C-2 closes G1 empirically.
pub fn taproot_address(
    pubkeys: &PublicKeyPackage,
    hrp: KnownHrp,
) -> Result<(Address, XOnlyPublicKey), Box<dyn std::error::Error>> {
    // ZF serializes the group verifying key as 33-byte compressed SEC1.
    let vk_bytes = pubkeys.verifying_key().serialize()?;
    let full = bitcoin::secp256k1::PublicKey::from_slice(&vk_bytes)?;
    // Internal key P (x-only); the parity is dropped per the BIP-340 even-Y rule.
    let (internal_key, _parity) = full.x_only_public_key();

    let secp = Secp256k1::verification_only();
    let untweaked: UntweakedPublicKey = internal_key;
    // merkle_root = None: key-path only, no script leaf committed (D-16 / G1).
    let (tweaked, _parity): (TweakedPublicKey, _) = untweaked.tap_tweak(&secp, None);
    let address = Address::p2tr_tweaked(tweaked, hrp);
    Ok((address, internal_key))
}

/// Derive the group's TWEAKED taproot output key Q as a 32-byte x-only key. This is
/// the BIP-340 verifying key the aggregate FROST signature checks under (and the
/// Nostr pubkey / npub identity of the group). Q = TapTweak(P, merkle_root=None),
/// keeping the exact derivation chain C-1 and the coordinator tests use. Additive;
/// does not change any signing path.
pub fn group_xonly_q(
    pubkeys: &PublicKeyPackage,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let (_addr, internal_p) = taproot_address(pubkeys, KnownHrp::Testnets)?;
    let secp = Secp256k1::verification_only();
    let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
    let q_xonly = q_tweaked.to_x_only_public_key();
    Ok(q_xonly.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Non-secret, zero-funds Mutinynet fixture seed. It pins a deterministic
    /// keyset so the derived taproot address is exactly reproducible by a
    /// different-agent verifier (G8). Production keygen uses OsRng, NEVER this.
    const FIXTURE_SEED: [u8; 32] = *b"kirby-custody-c1-seed-mutinynet!";

    /// The reproducible taproot address derived from FIXTURE_SEED (regression
    /// lock on the load-bearing P -> Q -> P2TR(Q) derivation).
    const FIXTURE_ADDRESS: &str =
        "tb1phuk09kvd7e392qxutmfudfydr4yylhzvgm2n3wv4xpx0dsq2mcws8dw7hf";

    #[test]
    fn dealer_keyset_is_2_of_3() {
        let ks = generate_dealer_keyset(2, 3).expect("keygen");
        assert_eq!(ks.shares.len(), 3, "2-of-3 produces 3 shares");
        let (addr, _p) = taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        // Key-path taproot on the testnet/signet HRP is a bech32m `tb1p` address.
        assert!(addr.to_string().starts_with("tb1p"), "got {addr}");
    }

    #[test]
    fn fixture_address_is_stable() {
        let mut rng = StdRng::from_seed(FIXTURE_SEED);
        let ks = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let (addr, _p) = taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("address");
        assert_eq!(addr.to_string(), FIXTURE_ADDRESS);
    }
}
