//! NIP-60 wallet-event key derivation (the separate-key P2 wallet model).
//!
//! Derives the NIP-60 wallet-event encryption key (a 32-byte nostr secp256k1 secret) from the
//! agent's wallet seed by domain-separated HKDF-SHA256. The wallet's proof-backup events (NIP-60)
//! are self-encrypted under a key the agent derives from its OWN wallet seed, so a reborn instance
//! holding the same seed decrypts its own backup. The event key is NEITHER the FROST Q (which
//! cannot ECDH) NOR the DM key — capability isolation.
//!
//! SEPARATE-KEY, not threshold: this is the shipping P2 model — the wallet holds its own key,
//! derived from a single wallet seed. Threshold-custody money (a Q-held wallet key that is never
//! reassembled) is P3 (FROST-unify), which supersedes any reconstruct-on-lease carriage.

use zeroize::Zeroizing;

use hkdf::Hkdf;
use sha2::Sha256;

/// The NIP-60 wallet-event encryption key length: a 32-byte nostr secp256k1 secret.
pub const NIP60_EVENT_KEY_LEN: usize = 32;

/// HKDF `info` for the NIP-60 wallet-event key. DISTINCT from every
/// `hibernate::shamir::derive_subkeys` label (`kirby-hibernate/v1/{identity-key,
/// state-encryption-key,wallet-seed}`); the `kirby/seed-keyring/v1/` prefix guarantees domain
/// separation, so this key is independent of the identity/state/spend subkeys.
const HKDF_NIP60_EVENT_KEY_INFO: &[u8] = b"kirby/seed-keyring/v1/nip60-wallet-event-key";

/// Derive the NIP-60 wallet-event encryption key (a 32-byte nostr secp256k1 secret) from the
/// wallet seed, by domain-separated HKDF-SHA256.
///
/// WALLET-PLANE + cap-isolated: this key NIP-44-encrypts the wallet's proof EVENTS on relays
/// (NIP-60). Under the L1 model it grants the same trust as the wallet seed (decrypting the
/// proof backup ⇒ spend access), so it is derived ON the wallet plane (from `wallet_seed`) —
/// never from the identity/state subkeys (no cross-plane reuse), never the DM key. One-way: an
/// event-key leak does NOT reveal the wallet seed (HKDF is not invertible).
///
/// Deterministic ⇒ reconstructible: the same wallet seed always yields the same event key, so a
/// reborn instance with the restored seed decrypts its own NIP-60 backup.
pub fn derive_nip60_event_key(wallet_seed: &[u8; 64]) -> Zeroizing<[u8; NIP60_EVENT_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, wallet_seed);
    let mut okm = Zeroizing::new([0u8; NIP60_EVENT_KEY_LEN]);
    hk.expand(HKDF_NIP60_EVENT_KEY_INFO, &mut *okm)
        .expect("32-byte OKM is within HKDF-SHA256's 255*32 limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nip60_event_key_is_deterministic_and_distinct() {
        let wallet_seed = [9u8; 64];
        let k1 = derive_nip60_event_key(&wallet_seed);
        let k2 = derive_nip60_event_key(&wallet_seed);
        assert_eq!(*k1, *k2, "the NIP-60 event-key derivation is deterministic (reconstructible)");
        assert_ne!(
            k1.as_slice(),
            &wallet_seed[..NIP60_EVENT_KEY_LEN],
            "the event key is a distinct HKDF derivation, not a slice of the wallet seed"
        );
    }
}
