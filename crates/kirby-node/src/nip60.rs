//! NIP-60 wallet — Cashu proofs as NIP-44-encrypted nostr events for cross-machine
//! PORTABILITY of an agent's ecash.
//!
//! ⚠️ NIP-60 buys PORTABILITY, NOT SAFETY (money-continuity design): the spec mandates nothing
//! about double-spend / durability / concurrent writers. Money-safety comes from the CASHU
//! layer — the MINT is the source of truth (NUT-07 check-state), the lease gates the mint-swap,
//! and a takeover reconciles against the mint BEFORE its first spend. These events are a durable
//! encrypted backup/sync over the cdk working store; NEVER make a spend decision from
//! relay-stored token state.
//!
//! This module is the kind:7375 token-event ENCODE / ENCRYPT / DECODE core (N1a) — pure and
//! relay-free. The quorum publish + reconcile-on-load + confirm-before-delete (N1b) ride the
//! nostr connection on top.
//!
//! SELF-ENCRYPTION model (mirrors [`crate::engram`]'s `K_self`): the agent NIP-44-encrypts to
//! its OWN NIP-60 event key (a wallet-plane key the keyring derives,
//! [`crate::seed_keyring::derive_nip60_event_key`]), so a reborn / failed-over instance with the
//! same reconstructed seed decrypts its own proof events. The event key is NEITHER the FROST Q
//! (which cannot ECDH) NOR the DM key (capability isolation).

use cdk::nuts::Proof;
use nostr_sdk::nips::nip44::{self, Version};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

/// The plaintext content of a NIP-60 kind:7375 token event (before NIP-44 encryption): the
/// mint the proofs are drawn on + the proofs themselves + the token-event ids this event
/// supersedes (NIP-09 delete targets, populated only at a confirm-before-delete rollover in
/// N1b). The whole struct is NIP-44-encrypted into the event content, so the mint URL and the
/// proof secrets never appear in cleartext on a relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenEventContent {
    /// The mint URL these proofs are drawn on.
    pub mint: String,
    /// The Cashu unit these proofs are denominated in (NIP-60 `unit`, e.g. "sat"). kirby is
    /// sat-only today; carried explicitly for spec-completeness + future multi-unit. Set from
    /// the wallet's `CurrencyUnit` when the content is built (N1b).
    pub unit: String,
    /// The Cashu proofs (cdk's serde-serializable `Proof`: amount / id / secret / C / ...).
    pub proofs: Vec<Proof>,
    /// Token-event ids this event supersedes (NIP-09 delete targets). Empty until a rollover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub del: Vec<String>,
}

/// The NIP-60 event-encryption identity: a nostr keypair built from the keyring-derived 32-byte
/// wallet-event key. Self-encrypts (sender == recipient == this key — the [`crate::engram`]
/// `K_self` model), so the same reconstructed key both writes and reads the agent's token
/// events. Holds the secret; treat it as wallet-plane spend-adjacent material.
pub struct Nip60Crypto {
    keys: Keys,
}

impl Nip60Crypto {
    /// Build from the 32-byte keyring-derived event key
    /// ([`crate::seed_keyring::derive_nip60_event_key`]). Errs only if the bytes are not a valid
    /// secp256k1 scalar (negligible for HKDF output, but propagated, never panicked).
    pub fn from_event_key(event_key: &[u8; 32]) -> anyhow::Result<Self> {
        let sk = SecretKey::from_slice(event_key)
            .map_err(|e| anyhow::anyhow!("NIP-60 event key is not a valid secp256k1 secret: {e}"))?;
        Ok(Self { keys: Keys::new(sk) })
    }

    /// The nostr pubkey these token events are published under and self-encrypted to.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// NIP-44 (v2) self-encrypt a token-event content → the event-content string. Mirrors
    /// [`crate::engram`]'s self-encrypt: encrypt to our OWN pubkey via self-ECDH.
    pub fn encrypt(&self, content: &TokenEventContent) -> anyhow::Result<String> {
        let json = serde_json::to_string(content)
            .map_err(|e| anyhow::anyhow!("serialize NIP-60 token content: {e}"))?;
        nip44::encrypt(self.keys.secret_key(), &self.keys.public_key(), json, Version::V2)
            .map_err(|e| anyhow::anyhow!("NIP-44 self-encrypt NIP-60 token: {e}"))
    }

    /// NIP-44 self-decrypt an event-content string back to its proofs. A wrong key fails the
    /// MAC (returns `Err`), never silently yields garbage.
    pub fn decrypt(&self, ciphertext: &str) -> anyhow::Result<TokenEventContent> {
        let bytes = nip44::decrypt_to_bytes(self.keys.secret_key(), &self.keys.public_key(), ciphertext)
            .map_err(|e| anyhow::anyhow!("NIP-44 self-decrypt NIP-60 token: {e}"))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parse NIP-60 token content: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed_keyring::derive_nip60_event_key;

    #[test]
    fn token_event_roundtrips_through_self_encryption() {
        let event_key = *derive_nip60_event_key(&[3u8; 64]);
        let crypto = Nip60Crypto::from_event_key(&event_key).expect("derived key is a valid secret");
        let content = TokenEventContent {
            mint: "https://mint.example".to_string(),
            unit: "sat".to_string(),
            // Empty proofs exercise the encrypt/decrypt + serde of the content envelope without
            // hand-constructing a valid Cashu Proof (whose serde is cdk's own tested concern).
            proofs: Vec::new(),
            del: vec!["deadbeefcafe".to_string()],
        };
        let ciphertext = crypto.encrypt(&content).expect("encrypt");
        assert!(
            !ciphertext.contains("mint.example"),
            "the mint URL must NOT appear in the NIP-44 ciphertext (it is encrypted, not cleartext)"
        );
        let back = crypto.decrypt(&ciphertext).expect("decrypt");
        assert_eq!(back, content, "token content round-trips through NIP-44 self-encryption");
    }

    #[test]
    fn a_different_event_key_cannot_decrypt() {
        let a = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[1u8; 64])).unwrap();
        let b = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[2u8; 64])).unwrap();
        let content = TokenEventContent {
            mint: "https://m".to_string(),
            unit: "sat".to_string(),
            proofs: Vec::new(),
            del: Vec::new(),
        };
        let ciphertext = a.encrypt(&content).unwrap();
        assert!(
            b.decrypt(&ciphertext).is_err(),
            "a different event key MUST NOT decrypt another agent's token event (key-bound)"
        );
    }
}
