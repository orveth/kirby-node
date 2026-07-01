//! `QuorumEcdh` — the DM/wallet-side threshold-ECDH provider (P1).
//!
//! Wraps the agent's co-located FROST keyset and derives NIP-44 conversation keys under
//! the group taproot key **Q** via the kirby-custody threshold-ECDH primitive
//! ([`kirby_custody::threshold_ecdh_tweaked_q`] + [`kirby_custody::nip44_conversation_key`]),
//! **without ever reconstructing the group secret** on any machine. The output is a
//! `nostr_sdk` [`ConversationKey`], which the NIP-17 seal/wrap (and later the NIP-60
//! wallet) feed straight into `nip44` — so the DM identity becomes Q, not a separate
//! plain `dm_keys`.
//!
//! Co-located shares (P1): the "ceremony" is in-process (sub-millisecond). The
//! cross-machine transport is P2; this provider's method surface is the seam it drops
//! into (a real ceremony makes `conversation_key` an async round-trip — the callers
//! already `.await` their DM work).
//!
//! ## Caching
//!
//! The (Q, target) ECDH is deterministic, so for a STABLE target — a DM peer's real key
//! (the NIP-17 seal layer) or Q's own key (the NIP-60 wallet self-encrypt) — the derived
//! conversation key can be cached to a single derivation ([`conversation_key`]). An
//! EPHEMERAL target — the per-message NIP-17 gift-wrap (kind:1059) key, which is unique
//! per message — must NOT be cached ([`conversation_key_uncached`]); caching it would
//! grow unbounded and buys nothing (it is never reused). Caching the conversation key (a
//! derived secret) — never a share — preserves the never-reconstruct property.
//!
//! [`conversation_key`]: QuorumEcdh::conversation_key
//! [`conversation_key_uncached`]: QuorumEcdh::conversation_key_uncached

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context as _;
use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use nostr_sdk::nips::nip44::v2::ConversationKey;
use nostr_sdk::PublicKey;

/// The co-located threshold-ECDH provider for one agent's FROST group key Q.
pub struct QuorumEcdh {
    /// The 2-of-3 secret shares (co-located, P1). The Lagrange point-combine reads these;
    /// the group secret scalar is never formed. Cross-machine share distribution (P2)
    /// replaces this with a transport to remote holders.
    key_packages: Vec<KeyPackage>,
    /// The group verifying material — drives the BIP-341 tweak fold + the Q derivation.
    pubkeys: PublicKeyPackage,
    /// The group threshold (min signers); the combine uses exactly this many shares.
    min_signers: usize,
    /// The agent's taproot Nostr identity Q (32-byte x-only) — the npub peers DM and the
    /// key the wallet self-encrypts to.
    q_xonly: [u8; 32],
    /// Per-target conversation-key cache for STABLE targets only (see the module docs).
    /// Holds derived conversation keys (not shares). Only reached via [`Self::conversation_key`];
    /// the ephemeral path never inserts, so this stays bounded by the number of distinct
    /// stable correspondents.
    cache: Mutex<HashMap<[u8; 32], [u8; 32]>>,
}

impl QuorumEcdh {
    /// Build a provider over the co-located keyset. Derives Q up front (and validates the
    /// keyset is coherent enough to do so).
    pub fn new(key_packages: Vec<KeyPackage>, pubkeys: PublicKeyPackage) -> anyhow::Result<Self> {
        let first = key_packages
            .first()
            .context("QuorumEcdh needs at least the threshold of shares")?;
        let min_signers = *first.min_signers() as usize;
        anyhow::ensure!(
            key_packages.len() >= min_signers,
            "QuorumEcdh has {} shares, below the threshold {}",
            key_packages.len(),
            min_signers
        );
        let q_xonly =
            kirby_custody::group_xonly_q(&pubkeys).map_err(|e| anyhow::anyhow!("derive group Q: {e}"))?;
        Ok(Self {
            key_packages,
            pubkeys,
            min_signers,
            q_xonly,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The agent's taproot Nostr identity Q as 32-byte x-only (the npub peers DM; the
    /// `#p` value the inbound subscription filters on).
    pub fn q_xonly(&self) -> [u8; 32] {
        self.q_xonly
    }

    /// Q as a `nostr_sdk::PublicKey`.
    pub fn q_public_key(&self) -> anyhow::Result<PublicKey> {
        PublicKey::from_slice(&self.q_xonly).context("group Q x-only -> nostr PublicKey")
    }

    /// Derive the raw 32-byte NIP-44 conversation key for (Q, target) via a single-round
    /// threshold ECDH under Q. The group secret is never reconstructed. No caching.
    fn derive_bytes(&self, target_xonly: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
        // Exactly the threshold of shares — the well-tested combine path; any ≥-threshold
        // subset of ONE group reconstructs the same secret point.
        let refs: Vec<&KeyPackage> = self.key_packages.iter().take(self.min_signers).collect();
        let shared = kirby_custody::threshold_ecdh_tweaked_q(&refs, &self.pubkeys, target_xonly)
            .map_err(|e| anyhow::anyhow!("threshold ECDH under Q: {e}"))?;
        kirby_custody::nip44_conversation_key(&shared)
            .map_err(|e| anyhow::anyhow!("NIP-44 conversation key: {e}"))
    }

    /// The NIP-44 `ConversationKey` for (Q, target), NOT cached. Use for an EPHEMERAL
    /// target — the per-message NIP-17 gift-wrap (kind:1059) key — which must never be
    /// cached (unique per message).
    pub fn conversation_key_uncached(&self, target: &PublicKey) -> anyhow::Result<ConversationKey> {
        Ok(ConversationKey::new(self.derive_bytes(&target.to_bytes())?))
    }

    /// The NIP-44 `ConversationKey` for (Q, target), CACHED per target. Use for a STABLE
    /// target — a DM peer's real key (the seal layer) or Q's own key (the wallet). The
    /// cached value is the derived conversation key, never a share, so caching preserves
    /// the never-reconstruct property.
    pub fn conversation_key(&self, target: &PublicKey) -> anyhow::Result<ConversationKey> {
        let t = target.to_bytes();
        if let Some(k) = self.cache.lock().expect("QuorumEcdh cache poisoned").get(&t) {
            return Ok(ConversationKey::new(*k));
        }
        let k = self.derive_bytes(&t)?;
        self.cache.lock().expect("QuorumEcdh cache poisoned").insert(t, k);
        Ok(ConversationKey::new(k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::nips::nip44::v2::{decrypt_to_bytes, encrypt_to_bytes};
    use nostr_sdk::Keys;

    fn provider() -> QuorumEcdh {
        // A fresh co-located 2-of-3 keyset (OsRng — the provider is target-agnostic, so a
        // random keyset exercises it fully).
        let keyset = kirby_custody::generate_dealer_keyset(2, 3).expect("keygen");
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&keyset)
            .expect("key packages")
            .into_values()
            .collect();
        QuorumEcdh::new(kps, keyset.pubkeys).expect("provider")
    }

    /// The provider derives the SAME NIP-44 conversation key a real nostr peer computes
    /// against the agent's npub Q — and a NIP-44 payload round-trips between the two sides.
    /// This is the end-to-end proof that a peer DMing Q and the agent (via threshold ECDH)
    /// share one conversation key.
    #[test]
    fn provider_conv_key_matches_peer_and_roundtrips() {
        let qe = provider();
        let q_pub = qe.q_public_key().expect("Q pubkey");

        let peer = Keys::generate();
        // Agent side: threshold ECDH under Q against the peer's key.
        let ck_agent = qe.conversation_key(&peer.public_key()).expect("agent ck");
        // Peer side: ordinary NIP-44 ECDH against the agent's npub Q.
        let ck_peer = ConversationKey::derive(peer.secret_key(), &q_pub).expect("peer ck");
        assert_eq!(
            ck_agent.as_bytes(),
            ck_peer.as_bytes(),
            "agent (threshold ECDH under Q) and peer must derive the same conversation key"
        );

        // NIP-44 payload round-trips both directions under the shared key.
        let msg = b"kirby dm under Q";
        let ct = encrypt_to_bytes(&ck_agent, msg).expect("encrypt");
        assert_eq!(decrypt_to_bytes(&ck_peer, &ct).expect("peer decrypt"), msg);
        let ct2 = encrypt_to_bytes(&ck_peer, msg).expect("encrypt2");
        assert_eq!(decrypt_to_bytes(&ck_agent, &ct2).expect("agent decrypt"), msg);
    }

    /// The self-encrypt case (the NIP-60 wallet target = Q's own key) derives a valid
    /// conversation key and round-trips — the wallet can encrypt to itself under Q.
    #[test]
    fn self_encrypt_under_q_roundtrips() {
        let qe = provider();
        let q_pub = qe.q_public_key().expect("Q pubkey");
        let ck = qe.conversation_key(&q_pub).expect("self ck");
        let msg = b"wallet state under Q";
        let ct = encrypt_to_bytes(&ck, msg).expect("encrypt");
        assert_eq!(decrypt_to_bytes(&ck, &ct).expect("decrypt"), msg);
    }

    /// The cache is transparent: the cached and uncached derivations agree for a stable
    /// target, and a second (cache-hit) call returns the same key.
    #[test]
    fn cache_is_transparent() {
        let qe = provider();
        let peer = Keys::generate().public_key();
        let cached = qe.conversation_key(&peer).expect("cached");
        let again = qe.conversation_key(&peer).expect("cache hit");
        let uncached = qe.conversation_key_uncached(&peer).expect("uncached");
        assert_eq!(cached.as_bytes(), again.as_bytes(), "cache hit must match");
        assert_eq!(cached.as_bytes(), uncached.as_bytes(), "cached must match uncached derivation");
    }
}
