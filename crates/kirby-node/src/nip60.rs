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

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use cdk::nuts::Proof;
use nostr_sdk::nips::nip44::{self, Version};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

/// The kind of a NIP-60 TOKEN event (the encrypted proofs). REGULAR + MULTIPLE → aggregate,
/// never lww-head (see [`reconcile_token_set`]). NIP-60 also defines kind:17375 (the REPLACEABLE
/// wallet config — lww-head, distinct from this 7375 SET) and kind:7376 (spending history);
/// those layer on in later cuts.
const KIND_NIP60_TOKEN: u16 = 7375;

/// The relay-set fetch timeout for a reconcile (mirrors EngramStore's read timeout).
const NIP60_READ_TIMEOUT_SECS: u64 = 4;

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
#[derive(Clone)]
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

    /// The signing keypair for the NIP-60 relay client (the SAME event key that self-encrypts,
    /// so the wallet's events are authored by + encrypted to one identity). Cloned for the
    /// `Client` builder's signer.
    pub fn signer_keys(&self) -> Keys {
        self.keys.clone()
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

/// The event-ids of the LIVE (non-superseded) kind:7375 token events — the AGGREGATE set, NOT
/// an LWW head.
///
/// ⚠️ MONEY-SAFETY: kind:7375 token events are REGULAR + MULTIPLE; a wallet's proofs are spread
/// across MANY of them. The live set is EVERY non-superseded event (so their proofs all
/// aggregate), NOT the latest-wins head — a head would drop every other event's proofs = MONEY
/// LOSS. An LWW head is correct ONLY for the REPLACEABLE kind:17375 wallet CONFIG, never the
/// 7375 token SET. A token event's `del` names the event-ids it supersedes (a rollover swaps N
/// inputs for 1 output); any id named in ANY event's `del` is dropped here.
pub fn live_token_event_ids(events: &[(String, TokenEventContent)]) -> Vec<&str> {
    let superseded: std::collections::HashSet<&str> = events
        .iter()
        .flat_map(|(_, c)| c.del.iter().map(String::as_str))
        .collect();
    events
        .iter()
        .map(|(id, _)| id.as_str())
        .filter(|id| !superseded.contains(id))
        .collect()
}

/// Reconcile a wallet's kind:7375 token events into its LIVE proof set: AGGREGATE the proofs of
/// every [`live_token_event_ids`] event (NOT a head — see its money-safety note), deduped by the
/// serialized proof so a duplicate re-publish can't double-count. The returned set is the
/// CANDIDATE proofs; NUT-07 check-state (N2) then filters it to UNSPENT before any spend (NIP-60
/// is portability, not safety — the mint is the source of truth).
pub fn reconcile_token_set(events: &[(String, TokenEventContent)]) -> Vec<Proof> {
    let live: std::collections::HashSet<&str> = live_token_event_ids(events).into_iter().collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut proofs = Vec::new();
    for (id, content) in events {
        if !live.contains(id.as_str()) {
            continue;
        }
        for proof in &content.proofs {
            let key = serde_json::to_string(proof).unwrap_or_default();
            if seen.insert(key) {
                proofs.push(proof.clone());
            }
        }
    }
    proofs
}

/// The NIP-60 wallet relay store: publishes the agent's Cashu proofs as NIP-44-encrypted
/// kind:7375 token events to the [`crate::config::Nip60Config`] relay set (signed by + encrypted
/// to the event key) and reconciles them back on load. Mirrors [`crate::rail::EngramStore`]'s
/// publish+reconcile shape — a nostr `Client` over N relays with a K-of-N ack quorum.
///
/// The Client round-trip is exercised END-TO-END (the nostr `Client` is not unit-mockable, same
/// as EngramStore); the pure encode/decode ([`Nip60Crypto`]) + the aggregate reconcile
/// ([`reconcile_token_set`]) ARE unit-tested. Cheap to clone (an `Arc` over the client).
#[derive(Clone)]
pub struct Nip60Store {
    crypto: Nip60Crypto,
    client: Arc<Client>,
    /// The relay-set size N (durability = how many relays a publish reaches).
    n: usize,
    /// The K-of-N ack threshold a publish must reach to count as durable.
    k: usize,
    read_timeout: Duration,
}

impl Nip60Store {
    /// Connect a NIP-60 store: build a nostr client SIGNED by the event key, add the relays,
    /// connect, and resolve the K-of-N threshold (`write_k` defaults to strict majority
    /// `floor(N/2)+1`, clamped to `[1, N]`). Mirrors `EngramStore::connect`. The caller resolves
    /// the relay set + emits the [`crate::config::Nip60Durability`] warning (via
    /// `Nip60Config::resolve`) before calling this.
    pub async fn connect(
        event_key: &[u8; 32],
        relays: &[String],
        write_k: Option<usize>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !relays.is_empty(),
            "Nip60Store requires at least one relay (the [nip60] set, or the [relay].url fallback)"
        );
        let crypto = Nip60Crypto::from_event_key(event_key)?;
        let client = Client::builder().signer(crypto.signer_keys()).build();
        for url in relays {
            client
                .add_relay(url)
                .await
                .with_context(|| format!("add NIP-60 wallet relay {url}"))?;
        }
        client.connect().await;
        let n = relays.len();
        let k = write_k.unwrap_or(n / 2 + 1).clamp(1, n);
        tracing::info!(npub = %crypto.public_key().to_hex(), n, k, "NIP-60 wallet store connected");
        Ok(Nip60Store {
            crypto,
            client: Arc::new(client),
            n,
            k,
            read_timeout: Duration::from_secs(NIP60_READ_TIMEOUT_SECS),
        })
    }

    /// Publish one kind:7375 token event (the proofs, NIP-44 self-encrypted) to the relay set,
    /// requiring K-of-N acks. Returns the published event id (a rollover's `del` references it,
    /// cut-2c). Fewer than K acks (or a total send failure) is an error — the write did NOT
    /// durably land, so the caller must NOT treat those proofs as backed up (money-safety: a
    /// non-durable publish over a single-relay set is exactly the drop the durability warning is
    /// about).
    pub async fn publish_token(&self, content: &TokenEventContent) -> anyhow::Result<EventId> {
        let ciphertext = self.crypto.encrypt(content)?;
        let builder = EventBuilder::new(Kind::from(KIND_NIP60_TOKEN), ciphertext);
        let output = self
            .client
            .send_event_builder(builder)
            .await
            .map_err(|e| anyhow::anyhow!("publish NIP-60 token event: {e}"))?;
        let acks = output.success.len();
        anyhow::ensure!(
            acks >= self.k,
            "NIP-60 token publish reached only {acks} of {} relays (need k={}); NOT durable — \
             refusing to treat the proofs as backed up",
            self.n,
            self.k
        );
        Ok(output.val)
    }

    /// Reconcile the wallet's LIVE proof set on load: fetch ALL kind:7375 token events authored
    /// by the event key across the relay set, decrypt each, and AGGREGATE via
    /// [`reconcile_token_set`] (NOT an lww head — a head would drop money). An undecryptable
    /// event (a foreign event under our author) is SKIPPED, not fatal. The returned set is the
    /// CANDIDATE proofs; NUT-07 check-state (N2) filters it to UNSPENT before any spend (NIP-60
    /// is portability, not safety — the mint is the source of truth).
    pub async fn reconcile_on_load(&self) -> anyhow::Result<Vec<Proof>> {
        let filter = Filter::new()
            .kind(Kind::from(KIND_NIP60_TOKEN))
            .author(self.crypto.public_key());
        let events = self
            .client
            .fetch_events(filter, self.read_timeout)
            .await
            .map_err(|e| anyhow::anyhow!("fetch NIP-60 token events for reconcile: {e}"))?;
        let mut decoded: Vec<(String, TokenEventContent)> = Vec::new();
        for ev in events.into_iter() {
            match self.crypto.decrypt(&ev.content) {
                Ok(content) => decoded.push((ev.id.to_hex(), content)),
                Err(e) => tracing::warn!(
                    event_id = %ev.id,
                    error = %e,
                    "NIP-60 reconcile: skipping an undecryptable token event (foreign under our author)"
                ),
            }
        }
        Ok(reconcile_token_set(&decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed_keyring::derive_nip60_event_key;

    /// A token-event content with empty proofs + the given `del` ids. The reconcile money-safety
    /// teeth turn on the event-id / del-chain logic, not the (cdk-owned) proof internals.
    fn tec(del: &[&str]) -> TokenEventContent {
        TokenEventContent {
            mint: "https://m".to_string(),
            unit: "sat".to_string(),
            proofs: Vec::new(),
            del: del.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A dummy-but-distinct cdk `Proof` for the aggregation teeth, built by deserializing a
    /// minimal NUT-00 proof JSON: the `C` point is the secp256k1 generator (a valid point), the
    /// keyset `id` a valid v0 16-hex, and distinctness comes from `secret`. cdk `Proof`'s serde is
    /// its own tested concern; we only need DISTINCT proofs to exercise aggregate + dedup.
    fn dummy_proof(secret: &str) -> Proof {
        let json = format!(
            r#"{{"amount":1,"id":"00ad268c4d1f5826","secret":"{secret}","C":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}}"#
        );
        serde_json::from_str(&json).expect("dummy proof JSON deserializes")
    }

    fn tec_with(del: &[&str], proofs: Vec<Proof>) -> TokenEventContent {
        TokenEventContent {
            mint: "https://m".to_string(),
            unit: "sat".to_string(),
            proofs,
            del: del.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn token_reconcile_aggregates_real_proofs_across_live_events_and_dedups() {
        let p1 = dummy_proof("s1");
        let p2 = dummy_proof("s2");
        // Two live events with DISTINCT proofs → BOTH aggregate (a head would yield only 1).
        let evs = vec![
            ("a".to_string(), tec_with(&[], vec![p1.clone()])),
            ("b".to_string(), tec_with(&[], vec![p2.clone()])),
        ];
        assert_eq!(
            reconcile_token_set(&evs).len(),
            2,
            "proofs from ALL live events aggregate (an lww-head would drop one = money loss)"
        );
        // A duplicate of p1 in a third live event → deduped, NOT double-counted.
        let evs_dup = vec![
            ("a".to_string(), tec_with(&[], vec![p1.clone()])),
            ("b".to_string(), tec_with(&[], vec![p2])),
            ("c".to_string(), tec_with(&[], vec![p1])),
        ];
        assert_eq!(
            reconcile_token_set(&evs_dup).len(),
            2,
            "a duplicate proof is deduped (no double-count)"
        );
    }

    #[test]
    fn token_reconcile_aggregates_all_live_events_not_a_head() {
        // 3 token events, none superseded → ALL 3 live. An LWW head would return 1 and DROP the
        // other 2 events' proofs = MONEY LOSS. This is the kind:7375 money-safety invariant.
        let evs = vec![
            ("a".to_string(), tec(&[])),
            ("b".to_string(), tec(&[])),
            ("c".to_string(), tec(&[])),
        ];
        let mut live = live_token_event_ids(&evs);
        live.sort_unstable();
        assert_eq!(
            live,
            vec!["a", "b", "c"],
            "every non-superseded 7375 event is live (AGGREGATE, not a head)"
        );
    }

    #[test]
    fn token_reconcile_applies_the_del_chain() {
        // A rollover: event c swaps inputs a + b for itself (del = [a, b]) → only c is live.
        let evs = vec![
            ("a".to_string(), tec(&[])),
            ("b".to_string(), tec(&[])),
            ("c".to_string(), tec(&["a", "b"])),
        ];
        assert_eq!(
            live_token_event_ids(&evs),
            vec!["c"],
            "del-superseded inputs are dropped; the rollover output is live"
        );
        // Empty-proof events reconcile to an empty set (the proof aggregation rides the live-id logic).
        assert!(reconcile_token_set(&evs).is_empty());
    }

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
