//! `QSigner` — a `nostr_sdk::NostrSigner` backed by the agent's FROST group key Q (P1).
//!
//! This is the seam that moves NIP-17 DMs onto Q **without hand-rolling NIP-59**. Pass a
//! `&QSigner` exactly where a plain `&Keys` DM identity used to go, and nostr's OWN audited
//! machinery does the layering: `EventBuilder::private_msg` (outbound rumor→seal→gift-wrap)
//! and `UnwrappedGift::from_gift_wrap` (inbound unwrap→seal-verify→rumor) call back into this
//! signer for the two operations that need Q:
//!
//! - **`nip44_encrypt` / `nip44_decrypt`** → threshold ECDH under Q via [`QuorumEcdh`]
//!   (`kirby_custody::threshold_ecdh_tweaked_q`), **never reconstructing the group secret**;
//!   the derived conversation key feeds nostr's own `nip44::v2` (byte-identical to
//!   `ConversationKey::derive`).
//! - **`sign_event`** → the FROST quorum, ROUTED THROUGH the guardian-membrane-gated
//!   [`QuorumSigner::sign_nostr_event_with_tags`], so only authorizable kinds (incl. the
//!   kind:13 seal) are signable under Q — a non-authorizable kind is refused fail-closed.
//!   nostr calls `sign_event` here ONLY for the seal; the gift-wrap (kind:1059) is signed by a
//!   fresh EPHEMERAL local key inside nostr, never this signer.
//!
//! ## Caching / fail-closed
//!
//! `nip44_decrypt` is invoked for BOTH the per-message ephemeral gift-wrap layer and the
//! stable seal layer, and cannot tell them apart per call — so it uses the UNCACHED
//! [`QuorumEcdh::conversation_key_uncached`] (caching per-message ephemeral keys would leak
//! and buys nothing). Co-located shares (P1) make each ceremony in-process (~free); a
//! cross-machine transport (P2) adds a caching layer at a seam that CAN distinguish the
//! layers. A quorum-unreachable failure surfaces as `Err` → `from_gift_wrap` `Err` →
//! the inbound wall defers the DM (fail-closed; never a partial/plaintext).

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use nostr_sdk::base64::engine::general_purpose::STANDARD as BASE64;
use nostr_sdk::base64::Engine as _;
use nostr_sdk::nips::nip44::v2::{decrypt_to_bytes, encrypt_to_bytes};
use nostr_sdk::signer::{SignerBackend, SignerError};
use nostr_sdk::util::BoxedFuture;
use nostr_sdk::{Event, JsonUtil, NostrSigner, PublicKey, UnsignedEvent};

use crate::quorum_ecdh::QuorumEcdh;
use crate::quorum_signer::QuorumSigner;

/// A `NostrSigner` whose identity is the agent's FROST group taproot key Q. Cheap to clone
/// (two `Arc`s). The seal signs via the quorum (membrane-gated); the NIP-44 crypto rides the
/// threshold-ECDH provider.
#[derive(Clone)]
pub struct QSigner {
    ecdh: Arc<QuorumEcdh>,
    quorum: Arc<QuorumSigner>,
}

impl fmt::Debug for QSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Identify by the public Q only; never expose key material.
        write!(f, "QSigner(Q={})", hex::encode(self.ecdh.q_xonly()))
    }
}

impl QSigner {
    pub fn new(ecdh: Arc<QuorumEcdh>, quorum: Arc<QuorumSigner>) -> Self {
        Self { ecdh, quorum }
    }
}

/// Wrap any `Display` error as a `SignerError` (nostr's `SignerError::backend` needs
/// `std::error::Error`, which `anyhow::Error` does not impl — go through the string form).
fn signer_err<E: fmt::Display>(e: E) -> SignerError {
    SignerError::from(e.to_string())
}

impl NostrSigner for QSigner {
    fn backend(&self) -> SignerBackend<'_> {
        SignerBackend::Custom(Cow::Borrowed("kirby-frost-q"))
    }

    fn get_public_key(&self) -> BoxedFuture<'_, Result<PublicKey, SignerError>> {
        Box::pin(async move { self.ecdh.q_public_key().map_err(signer_err) })
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> BoxedFuture<'_, Result<Event, SignerError>> {
        Box::pin(async move {
            // Route through the membrane-gated quorum signer: it re-checks the kind per holder,
            // so only authorizable kinds (incl. the kind:13 seal) sign under Q; anything else is
            // refused fail-closed. It recomputes the NIP-01 id over (Q, created_at, kind, tags,
            // content) and FROST-signs it — the same fields as `unsigned`, so the id matches.
            let tags: Vec<Vec<String>> =
                unsigned.tags.iter().map(|t| t.as_slice().to_vec()).collect();
            let signed = self
                .quorum
                .sign_nostr_event_with_tags(
                    unsigned.kind.as_u16() as u32,
                    unsigned.created_at.as_secs(),
                    &tags,
                    &unsigned.content,
                )
                .map_err(signer_err)?;
            let json = serde_json::to_string(&signed).map_err(signer_err)?;
            let event = Event::from_json(&json).map_err(signer_err)?;
            event.verify().map_err(signer_err)?; // fail-closed: never emit an unverifiable event
            Ok(event)
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        _public_key: &'a PublicKey,
        _content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            Err(SignerError::from(
                "NIP-04 is unsupported under Q (Kirby DMs use NIP-44/NIP-17)",
            ))
        })
    }

    fn nip04_decrypt<'a>(
        &'a self,
        _public_key: &'a PublicKey,
        _encrypted_content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            Err(SignerError::from(
                "NIP-04 is unsupported under Q (Kirby DMs use NIP-44/NIP-17)",
            ))
        })
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            // Stable target (a seal recipient) — cacheable. base64(STANDARD) matches nostr's
            // own nip44 (mod.rs), so the recipient decodes it identically.
            let ck = self.ecdh.conversation_key(public_key).map_err(signer_err)?;
            let payload = encrypt_to_bytes(&ck, content.as_bytes()).map_err(signer_err)?;
            Ok(BASE64.encode(payload))
        })
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            // UNCACHED (see module docs): called for both the ephemeral gift-wrap layer and the
            // seal layer, indistinguishable here. Err (quorum unreachable OR MAC fail) → the
            // caller (from_gift_wrap) fails → the inbound wall defers, fail-closed.
            let bytes = BASE64.decode(payload).map_err(signer_err)?;
            let ck = self
                .ecdh
                .conversation_key_uncached(public_key)
                .map_err(signer_err)?;
            let plaintext = decrypt_to_bytes(&ck, &bytes).map_err(signer_err)?;
            String::from_utf8(plaintext).map_err(signer_err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::{EventBuilder, Keys, Kind};

    fn qsigner() -> QSigner {
        let keyset = kirby_custody::generate_dealer_keyset(2, 3).expect("keygen");
        let kps: Vec<_> = kirby_custody::key_packages(&keyset)
            .expect("key packages")
            .into_values()
            .collect();
        let ecdh = Arc::new(QuorumEcdh::new(kps.clone(), keyset.pubkeys.clone()).expect("ecdh"));
        let quorum = Arc::new(
            QuorumSigner::from_local_key_packages(kps, keyset.pubkeys.clone())
                .expect("quorum signer"),
        );
        QSigner::new(ecdh, quorum)
    }

    /// END-TO-END, the P1 headline tooth: a full NIP-17 DM round-trips under Q against a REAL
    /// nostr peer, BOTH directions, using nostr's own NIP-59 (private_msg / from_gift_wrap) —
    /// the QSigner supplies the Q-ECDH + Q-sign, nostr does the layering.
    #[tokio::test]
    async fn nip17_dm_roundtrips_under_q_both_ways() {
        let agent = qsigner();
        let q = agent.get_public_key().await.expect("Q");
        let peer = Keys::generate();

        // OUTBOUND: agent (Q) → peer. The seal is signed under Q (FROST); the peer unwraps it
        // with its own plain key and reads the plaintext + learns Q as the sender.
        let out = "hello from Q";
        let wrap = EventBuilder::private_msg(&agent, peer.public_key(), out, [])
            .await
            .expect("agent seals+wraps under Q");
        let unwrapped = nostr_sdk::nips::nip59::UnwrappedGift::from_gift_wrap(&peer, &wrap)
            .await
            .expect("peer unwraps the Q-authored DM");
        assert_eq!(unwrapped.rumor.content, out, "peer must read the agent's plaintext");
        assert_eq!(unwrapped.rumor.pubkey, q, "the DM's author must be Q");
        assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage);

        // INBOUND: peer → agent (Q). The agent unwraps via threshold ECDH under Q (two
        // Q-ECDH decrypts: the ephemeral gift-wrap layer + the seal layer), reads the plaintext,
        // and learns the real peer as the sender.
        let inbound = "hello to Q";
        let to_q = EventBuilder::private_msg(&peer, q, inbound, [])
            .await
            .expect("peer seals+wraps to Q");
        let got = nostr_sdk::nips::nip59::UnwrappedGift::from_gift_wrap(&agent, &to_q)
            .await
            .expect("agent unwraps under Q via threshold ECDH");
        assert_eq!(got.rumor.content, inbound, "agent must read the peer's plaintext");
        assert_eq!(got.sender, peer.public_key(), "the seal-verified sender must be the peer");
        assert_eq!(got.rumor.pubkey, peer.public_key(), "rumor author == seal sender (anti-spoof)");
    }

    /// The agent's DM identity really is Q: a DM sealed under Q does NOT unwrap under a
    /// different key (red-on-revert that the identity moved off any plain dm_keys).
    #[tokio::test]
    async fn dm_under_q_does_not_unwrap_under_a_foreign_key() {
        let agent = qsigner();
        let recipient = Keys::generate();
        let wrap = EventBuilder::private_msg(&agent, recipient.public_key(), "for the recipient", [])
            .await
            .expect("seal under Q");
        // A DIFFERENT key (not the recipient) cannot unwrap it.
        let stranger = Keys::generate();
        assert!(
            nostr_sdk::nips::nip59::UnwrappedGift::from_gift_wrap(&stranger, &wrap)
                .await
                .is_err(),
            "a non-recipient key must NOT unwrap a Q-sealed DM"
        );
    }
}
