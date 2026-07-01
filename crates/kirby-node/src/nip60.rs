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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use cdk::nuts::{Id, Proof};
use nostr_sdk::nips::nip44::{self, Version};
use nostr_sdk::prelude::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The kind of a NIP-60 TOKEN event (the encrypted proofs). REGULAR + MULTIPLE → aggregate,
/// never lww-head (see [`reconcile_token_set`]). Distinct from the REPLACEABLE wallet config
/// ([`KIND_NIP60_WALLET_CONFIG`], lww-head); kind:7376 (spending history) layers on later.
const KIND_NIP60_TOKEN: u16 = 7375;

/// The kind of a NIP-60 WALLET-CONFIG event: REPLACEABLE (10000–19999) → the relay set keeps
/// only the latest per author, so it is read lww-head ([`crate::engram::lww_head`]), NEVER
/// aggregated. kirby carries the wallet's mints + the per-keyset NUT-13 counter high-water-mark
/// here ([`WalletConfigContent`]) so the spend-critical counter survives a cross-machine
/// reconstruct — the ONE piece of wallet state the mint alone cannot rebuild.
const KIND_NIP60_WALLET_CONFIG: u16 = 17375;

/// The relay-set fetch timeout for a reconcile (mirrors EngramStore's read timeout).
const NIP60_READ_TIMEOUT_SECS: u64 = 4;

/// The kind of a NIP-09 event-deletion request (kind:5). ADVISORY — relays MAY ignore it, so a
/// NIP-60 rollover NEVER trusts it: the `del` chain in the new token event is the authoritative
/// supersede, and the mint (NUT-07) is the ultimate truth. The delete just helps relays prune.
const KIND_NIP09_DELETE: u16 = 5;

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

/// The plaintext content of a NIP-60 kind:17375 wallet-config event (before NIP-44 encryption):
/// the mints the wallet uses + the per-keyset NUT-13 counter high-water-mark. The whole struct is
/// NIP-44-encrypted into the (REPLACEABLE, lww-head) event, so the keyset ids and counters never
/// appear in cleartext on a relay.
///
/// ⚠️ MONEY-SAFETY: `counters` is the cross-machine floor a reconstruct seeds from
/// ([`crate::nip60_counter::Nip60CounterDb::with_counters`]) so a restored wallet never re-derives
/// already-spent NUT-13 secrets. It is keyed by the keyset id's canonical HEX string (`Id`'s
/// `Display`), NOT `Id` itself — cashu's `Id` serializes as a struct, unusable as a JSON map key;
/// hex is the portable, cdk-canonical form the publish/load boundary converts at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WalletConfigContent {
    /// The mint URLs this wallet draws on (interop + a reconstruct hint). May be empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mints: Vec<String>,
    /// keyset-id hex → the highest NUT-13 counter the wallet has reached for that keyset. Empty
    /// for a brand-new wallet that has not yet advanced any counter.
    #[serde(default)]
    pub counters: HashMap<String, u32>,
}

impl WalletConfigContent {
    /// Build a config from the decorator's observed counters
    /// ([`crate::nip60_counter::Nip60CounterDb::keyset_counters`]) + the wallet's mints. Each
    /// keyset [`Id`] is stringified to its canonical HEX (`Id`'s `Display`) — the exact form
    /// [`Id::from_str`] reverses, so the reconstruct seed
    /// ([`crate::nip60_counter::Nip60CounterDb::with_counters`]) re-attributes each counter to the
    /// SAME keyset. A misattributed or dropped counter here = a reconstructed wallet re-deriving
    /// the wrong / already-spent secrets, so the round-trip is a money-safety invariant (teeth).
    pub fn from_counters(counters: HashMap<Id, u32>, mints: Vec<String>) -> Self {
        Self {
            mints,
            counters: counters
                .into_iter()
                .map(|(id, counter)| (id.to_string(), counter))
                .collect(),
        }
    }
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

    /// NIP-44 (v2) self-encrypt any serializable content → the event-content string. Mirrors
    /// [`crate::engram`]'s self-encrypt: encrypt to our OWN pubkey via self-ECDH. Shared by the
    /// token ([`Self::encrypt`]) and wallet-config ([`Self::encrypt_config`]) events so the crypto
    /// incantation lives in ONE place.
    fn encrypt_json<T: Serialize>(&self, content: &T) -> anyhow::Result<String> {
        let json = serde_json::to_string(content)
            .map_err(|e| anyhow::anyhow!("serialize NIP-60 content: {e}"))?;
        nip44::encrypt(self.keys.secret_key(), &self.keys.public_key(), json, Version::V2)
            .map_err(|e| anyhow::anyhow!("NIP-44 self-encrypt NIP-60 content: {e}"))
    }

    /// NIP-44 self-decrypt an event-content string back to `T`. A wrong key fails the MAC
    /// (returns `Err`), never silently yields garbage.
    fn decrypt_json<T: DeserializeOwned>(&self, ciphertext: &str) -> anyhow::Result<T> {
        let bytes = nip44::decrypt_to_bytes(self.keys.secret_key(), &self.keys.public_key(), ciphertext)
            .map_err(|e| anyhow::anyhow!("NIP-44 self-decrypt NIP-60 content: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("parse NIP-60 content: {e}"))
    }

    /// NIP-44 (v2) self-encrypt a token-event content → the event-content string.
    pub fn encrypt(&self, content: &TokenEventContent) -> anyhow::Result<String> {
        self.encrypt_json(content)
    }

    /// NIP-44 self-decrypt an event-content string back to its proofs. A wrong key fails the
    /// MAC (returns `Err`), never silently yields garbage.
    pub fn decrypt(&self, ciphertext: &str) -> anyhow::Result<TokenEventContent> {
        self.decrypt_json(ciphertext)
    }

    /// NIP-44 (v2) self-encrypt a wallet-config content → the (kind:17375) event-content string.
    pub fn encrypt_config(&self, config: &WalletConfigContent) -> anyhow::Result<String> {
        self.encrypt_json(config)
    }

    /// NIP-44 self-decrypt a wallet-config event-content string back to its mints + counters. A
    /// wrong key fails the MAC (returns `Err`).
    pub fn decrypt_config(&self, ciphertext: &str) -> anyhow::Result<WalletConfigContent> {
        self.decrypt_json(ciphertext)
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
/// every [`live_token_event_ids`] event (NOT a head — see its money-safety note) whose mint is in
/// `mint_allowlist`, deduped by the serialized proof so a duplicate re-publish can't double-count.
///
/// ⚠️ MONEY-SAFETY (N7 mint-allowlist): a token event drawn on a mint NOT in the allowlist is
/// DROPPED — a rogue relay/event cannot make the wallet adopt (and later swap at) an attacker's
/// mint. The allowlist is the PRIMARY theft-guard: it blocks the untrusted-mint entry, the
/// precondition of the swap-at-attacker's-mint attack (a malicious ALLOWLISTED mint is the
/// accepted mint-trust SPOF, orthogonal to v0/v1 — so the allowlist subsumes the v0-keyset risk
/// and we support trusted v0 mints rather than refuse them). The agent's own mint is always in the
/// effective allowlist. The default `[mint_url]` is intentionally strict: a payer's OTHER-mint
/// proofs are dropped (safe-by-default) — cross-mint RECEIVE (accept-foreign-then-swap-to-trusted,
/// with its own guard at the swap) is the earn-loop's future concern, not this filter.
///
/// The returned set is the CANDIDATE proofs; NUT-07 check-state (N2) then filters it to UNSPENT
/// before any spend (NIP-60 is portability, not safety — the mint is the source of truth).
pub fn reconcile_token_set(
    events: &[(String, TokenEventContent)],
    mint_allowlist: &[String],
) -> Vec<Proof> {
    let live: std::collections::HashSet<&str> = live_token_event_ids(events).into_iter().collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut proofs = Vec::new();
    for (id, content) in events {
        if !live.contains(id.as_str()) {
            continue;
        }
        // MONEY-SAFETY (N7): adopt proofs ONLY from an allowlisted mint — the theft-guard.
        if !mint_allowlist.iter().any(|m| m == &content.mint) {
            tracing::warn!(
                mint = %content.mint,
                event_id = %id,
                "NIP-60 reconcile: dropping proofs from a non-allowlisted mint"
            );
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

/// The raw nostr I/O a [`Nip60Store`] performs, behind a trait so the money-critical
/// ORCHESTRATION on top of it — the ≥k publish durability gate, the aggregate reconcile, and the
/// confirm-before-delete rollover ORDERING — is unit-testable against a mock transport instead of
/// only exercised end-to-end against a live relay. The production impl ([`ClientTransport`]) is a
/// thin wrapper over a signed nostr `Client`; the transport reports raw results (an ack count, the
/// fetched events) and the [`Nip60Store`] owns every money decision made from them.
#[async_trait]
pub trait Nip60Transport: Send + Sync {
    /// Send a signed event (built from `kind` + the already-encrypted `content` + `tags`) to the
    /// relay set; return its id and the number of relays that ACKED. The caller applies the ≥k
    /// durability gate — the transport only reports the count, it never decides durability.
    async fn send_event(
        &self,
        kind: u16,
        content: String,
        tags: Vec<Tag>,
    ) -> anyhow::Result<SendOutcome>;

    /// Fetch every event matching `filter`, waiting up to `timeout`.
    async fn fetch_events(&self, filter: Filter, timeout: Duration) -> anyhow::Result<Vec<Event>>;
}

/// The outcome of a [`Nip60Transport::send_event`]: the published event id + how many relays acked.
pub struct SendOutcome {
    /// The id of the published event (a rollover's `del` references a token event's id).
    pub event_id: EventId,
    /// The number of relays that acknowledged the write (the ≥k gate is applied by the caller).
    pub acks: usize,
}

/// The production [`Nip60Transport`]: a signed nostr `Client` over the relay set.
struct ClientTransport {
    client: Client,
}

#[async_trait]
impl Nip60Transport for ClientTransport {
    async fn send_event(
        &self,
        kind: u16,
        content: String,
        tags: Vec<Tag>,
    ) -> anyhow::Result<SendOutcome> {
        let builder = EventBuilder::new(Kind::from(kind), content).tags(tags);
        let output = self
            .client
            .send_event_builder(builder)
            .await
            .map_err(|e| anyhow::anyhow!("send NIP-60 event (kind {kind}): {e}"))?;
        Ok(SendOutcome {
            event_id: output.val,
            acks: output.success.len(),
        })
    }

    async fn fetch_events(&self, filter: Filter, timeout: Duration) -> anyhow::Result<Vec<Event>> {
        let events = self
            .client
            .fetch_events(filter, timeout)
            .await
            .map_err(|e| anyhow::anyhow!("fetch NIP-60 events: {e}"))?;
        Ok(events.into_iter().collect())
    }
}

/// The NIP-60 wallet relay store: publishes the agent's Cashu proofs as NIP-44-encrypted
/// kind:7375 token events to the [`crate::config::Nip60Config`] relay set (signed by + encrypted
/// to the event key) and reconciles them back on load. Mirrors [`crate::rail::EngramStore`]'s
/// publish+reconcile shape — over N relays with a K-of-N ack quorum.
///
/// The relay I/O sits behind [`Nip60Transport`], so the money-critical orchestration (the ≥k
/// publish gate, the aggregate reconcile, the confirm-before-delete rollover ordering) is
/// unit-tested against a mock transport; the pure encode/decode ([`Nip60Crypto`]) + aggregate
/// ([`reconcile_token_set`]) are unit-tested too. Cheap to clone (an `Arc` over the transport).
#[derive(Clone)]
pub struct Nip60Store {
    crypto: Nip60Crypto,
    transport: Arc<dyn Nip60Transport>,
    /// The relay-set size N (durability = how many relays a publish reaches).
    n: usize,
    /// The K-of-N ack threshold a publish must reach to count as durable.
    k: usize,
    read_timeout: Duration,
    /// The mints whose relay-stored proofs this wallet will adopt on reconcile (N7 theft-guard;
    /// [`crate::config::BrainConfig::effective_mint_allowlist`]). Always includes the agent's own
    /// mint. Proofs drawn on any other mint are dropped by [`reconcile_token_set`].
    mint_allowlist: Vec<String>,
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
        mint_allowlist: Vec<String>,
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
            transport: Arc::new(ClientTransport { client }),
            n,
            k,
            read_timeout: Duration::from_secs(NIP60_READ_TIMEOUT_SECS),
            mint_allowlist,
        })
    }

    /// Build a store over an arbitrary [`Nip60Transport`] — the seam the unit tests inject a mock
    /// through to exercise the ≥k gate + confirm-before-delete ordering without a live relay.
    #[cfg(test)]
    fn with_transport(
        crypto: Nip60Crypto,
        transport: Arc<dyn Nip60Transport>,
        n: usize,
        k: usize,
        mint_allowlist: Vec<String>,
    ) -> Self {
        Nip60Store {
            crypto,
            transport,
            n,
            k,
            read_timeout: Duration::from_secs(NIP60_READ_TIMEOUT_SECS),
            mint_allowlist,
        }
    }

    /// Publish one kind:7375 token event (the proofs, NIP-44 self-encrypted) to the relay set,
    /// requiring K-of-N acks. Returns the published event id (a rollover's `del` references it,
    /// cut-2c). Fewer than K acks (or a total send failure) is an error — the write did NOT
    /// durably land, so the caller must NOT treat those proofs as backed up (money-safety: a
    /// non-durable publish over a single-relay set is exactly the drop the durability warning is
    /// about).
    pub async fn publish_token(&self, content: &TokenEventContent) -> anyhow::Result<EventId> {
        let ciphertext = self.crypto.encrypt(content)?;
        let outcome = self
            .transport
            .send_event(KIND_NIP60_TOKEN, ciphertext, Vec::new())
            .await
            .context("publish NIP-60 token event")?;
        anyhow::ensure!(
            outcome.acks >= self.k,
            "NIP-60 token publish reached only {} of {} relays (need k={}); NOT durable — \
             refusing to treat the proofs as backed up",
            outcome.acks,
            self.n,
            self.k
        );
        Ok(outcome.event_id)
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
            .transport
            .fetch_events(filter, self.read_timeout)
            .await
            .context("fetch NIP-60 token events for reconcile")?;
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
        Ok(reconcile_token_set(&decoded, &self.mint_allowlist))
    }

    /// Publish the kind:17375 wallet-config (mints + per-keyset NUT-13 counters, NIP-44
    /// self-encrypted), requiring K-of-N acks. Being REPLACEABLE, the relay set keeps only the
    /// latest per author, so a new config supersedes the old with NO NIP-09 delete needed.
    ///
    /// ⚠️ MONEY-SAFETY: the counters here are the cross-machine floor a reconstruct seeds from
    /// ([`crate::nip60_counter::Nip60CounterDb::with_counters`]). They are monotonic (the
    /// decorator's `max`) and written under the single-live LEASE (N4), so the lww-head never
    /// regresses in correct operation; a takeover still scans GENEROUSLY past the mirrored value
    /// (N5) to heal a slightly-stale counter from a mid-mint crash. Same ≥k durability gate as a
    /// token publish — a sub-quorum config write is NOT durable and errors.
    pub async fn publish_config(&self, config: &WalletConfigContent) -> anyhow::Result<EventId> {
        let ciphertext = self.crypto.encrypt_config(config)?;
        let outcome = self
            .transport
            .send_event(KIND_NIP60_WALLET_CONFIG, ciphertext, Vec::new())
            .await
            .context("publish NIP-60 wallet-config event")?;
        anyhow::ensure!(
            outcome.acks >= self.k,
            "NIP-60 wallet-config publish reached only {} of {} relays (need k={}); NOT durable \
             — refusing to treat the counters as backed up",
            outcome.acks,
            self.n,
            self.k
        );
        Ok(outcome.event_id)
    }

    /// Publish the wallet-config from the decorator's observed counters + the wallet's mints:
    /// convert ([`WalletConfigContent::from_counters`]) then [`Self::publish_config`] (≥k-durable).
    /// This is the counter-carrying publish the boot-push wires to
    /// [`crate::nip60_counter::Nip60CounterDb::keyset_counters`]; kept parameterized (takes the
    /// counters directly) so the LOGIC is non-boot and unit-exercised without the wallet handle.
    pub async fn publish_wallet_config(
        &self,
        counters: HashMap<Id, u32>,
        mints: Vec<String>,
    ) -> anyhow::Result<EventId> {
        self.publish_config(&WalletConfigContent::from_counters(counters, mints))
            .await
    }

    /// Load the wallet-config lww-head: fetch every kind:17375 event authored by the event key,
    /// pick the latest ([`crate::engram::lww_head`] — greatest created_at, tombstone-aware), and
    /// decrypt it. `Ok(None)` when the agent has never published one (a fresh wallet).
    ///
    /// ⚠️ Unlike [`Self::reconcile_on_load`] (which SKIPS an undecryptable token event as a
    /// possible foreign event), an undecryptable config HEAD is a hard error: the counter floor is
    /// money-critical, so a decrypt failure is surfaced (fail-closed at the caller), NEVER silently
    /// treated as an empty floor — an empty floor would let a later publish regress the counter.
    pub async fn load_config(&self) -> anyhow::Result<Option<WalletConfigContent>> {
        let filter = Filter::new()
            .kind(Kind::from(KIND_NIP60_WALLET_CONFIG))
            .author(self.crypto.public_key());
        let events = self
            .transport
            .fetch_events(filter, self.read_timeout)
            .await
            .context("fetch NIP-60 wallet-config events")?;
        match crate::engram::lww_head(&events) {
            Some(head) => {
                let mut config = self
                    .crypto
                    .decrypt_config(&head.content)
                    .context("decrypt the NIP-60 wallet-config lww-head")?;
                // N7: keep only allowlisted mints in the (informational) mints hint-list. The
                // self-authored COUNTERS are NOT filtered — they are keyset-keyed in the agent's
                // OWN signed+encrypted event (unforgeable) and ride the keyset→mint trust; the
                // theft-guard is the proof-mint-filter in `reconcile_token_set`, not here.
                config
                    .mints
                    .retain(|m| self.mint_allowlist.iter().any(|a| a == m));
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    /// Roll over token events: replace the `superseded` events (their proofs consolidated into
    /// `new_proofs`) with ONE new kind:7375 event, CONFIRM-BEFORE-DELETE.
    ///
    /// ⚠️ MONEY-SAFETY ORDERING (design doc point 6): (1) the new event carries `del = superseded`
    /// — the del-chain, the AUTHORITATIVE supersede honored by [`reconcile_token_set`] even if the
    /// NIP-09 delete is ignored; (2) it is published and MUST reach >=k relays
    /// ([`Self::publish_token`] ERRORS otherwise) BEFORE anything is deleted, so a non-durable new
    /// event leaves the OLD events LIVE (never delete an input until its replacement is durable on
    /// quorum); (3) ONLY THEN are the old events NIP-09-deleted — best-effort + advisory (relays
    /// may ignore; the del-chain + the mint are the real supersede/truth), so a delete failure is
    /// logged, NOT fatal.
    pub async fn rollover(
        &self,
        mint: &str,
        unit: &str,
        new_proofs: Vec<Proof>,
        superseded: Vec<String>,
    ) -> anyhow::Result<EventId> {
        let content = TokenEventContent {
            mint: mint.to_string(),
            unit: unit.to_string(),
            proofs: new_proofs,
            del: superseded.clone(),
        };
        // CONFIRM: the new event must be >=k durable before ANYTHING is deleted. `?` returns here
        // on a sub-quorum publish → nothing is deleted and the old proofs stay live (money-safe).
        let new_id = self.publish_token(&content).await.context(
            "rollover: the new token event is NOT durable on >=k relays — deleted NOTHING, the old \
             proofs stay live",
        )?;
        // Only now (the new event is >=k durable) prune the superseded events. Advisory — never
        // trusted; a failure is logged, not fatal.
        if !superseded.is_empty() {
            if let Err(e) = self.delete_events(&superseded).await {
                tracing::warn!(
                    error = %e,
                    "rollover: NIP-09 delete of superseded token events failed (advisory — the \
                     del-chain still supersedes them and the mint remains the source of truth)"
                );
            }
        }
        Ok(new_id)
    }

    /// Publish a NIP-09 (kind:5) deletion for the given token-event ids. ADVISORY: relays MAY
    /// ignore it and it is NEVER trusted (the del-chain + the mint are authoritative), so this is
    /// best-effort and does NOT gate on a K-of-N quorum.
    async fn delete_events(&self, event_ids: &[String]) -> anyhow::Result<()> {
        let tags: Vec<Tag> = event_ids
            .iter()
            .filter_map(|id| EventId::from_hex(id.as_str()).ok().map(Tag::event))
            .collect();
        anyhow::ensure!(!tags.is_empty(), "NIP-09 delete: no valid token-event ids to delete");
        let count = tags.len();
        let outcome = self
            .transport
            .send_event(
                KIND_NIP09_DELETE,
                "superseded by a NIP-60 rollover".to_string(),
                tags,
            )
            .await
            .context("publish NIP-09 delete event")?;
        tracing::debug!(deleted = count, acks = outcome.acks, "NIP-09 delete published (advisory)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::seed_keyring::derive_nip60_event_key;

    /// The allowlist matching the `tec`/`tec_with` helpers' mint ("https://m"), so the aggregate /
    /// del-chain / transport teeth exercise their own logic without the N7 mint-filter dropping
    /// anything. The N7 filter itself has a dedicated tooth (`reconcile_drops_...`).
    fn allow_m() -> Vec<String> {
        vec!["https://m".to_string()]
    }

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
            reconcile_token_set(&evs, &allow_m()).len(),
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
            reconcile_token_set(&evs_dup, &allow_m()).len(),
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
        assert!(reconcile_token_set(&evs, &allow_m()).is_empty());
    }

    #[test]
    fn reconcile_drops_proofs_from_a_non_allowlisted_mint() {
        // Two live events with distinct proofs: one on the TRUSTED mint ("https://m"), one on a
        // ROGUE mint a relay/event could inject.
        let trusted = tec_with(&[], vec![dummy_proof("s1")]);
        let rogue = TokenEventContent {
            mint: "https://rogue".to_string(),
            unit: "sat".to_string(),
            proofs: vec![dummy_proof("s2")],
            del: Vec::new(),
        };
        let evs = vec![("a".to_string(), trusted), ("b".to_string(), rogue)];

        // Allowlist = only the trusted mint → the rogue mint's proof is DROPPED.
        assert_eq!(
            reconcile_token_set(&evs, &allow_m()).len(),
            1,
            "MONEY-SAFETY: only allowlisted-mint proofs are adopted; a rogue mint's proofs are dropped"
        );
        // Sanity: allowlisting BOTH admits both — proving it is the mint filter, not another drop.
        let allow_both = vec!["https://m".to_string(), "https://rogue".to_string()];
        assert_eq!(reconcile_token_set(&evs, &allow_both).len(), 2);
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

    #[test]
    fn wallet_config_roundtrips_through_self_encryption() {
        let crypto =
            Nip60Crypto::from_event_key(&derive_nip60_event_key(&[7u8; 64])).expect("valid key");
        let mut counters = HashMap::new();
        counters.insert("00ad268c4d1f5826".to_string(), 42u32);
        counters.insert("009a1f293253e41e".to_string(), 7u32);
        let config = WalletConfigContent {
            mints: vec!["https://mint.example".to_string()],
            counters,
        };
        let ciphertext = crypto.encrypt_config(&config).expect("encrypt config");
        assert!(
            !ciphertext.contains("mint.example") && !ciphertext.contains("00ad268c4d1f5826"),
            "the mints AND keyset ids must be NIP-44-encrypted, never cleartext on a relay"
        );
        let back = crypto.decrypt_config(&ciphertext).expect("decrypt config");
        assert_eq!(
            back, config,
            "the wallet config round-trips through NIP-44 self-encryption (mints + counters)"
        );
        // The spend-critical value survives verbatim (a lossy counter = money loss on reconstruct).
        assert_eq!(back.counters.get("00ad268c4d1f5826").copied(), Some(42));
        assert_eq!(back.counters.get("009a1f293253e41e").copied(), Some(7));
    }

    #[test]
    fn a_different_event_key_cannot_decrypt_wallet_config() {
        let a = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[1u8; 64])).unwrap();
        let b = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[2u8; 64])).unwrap();
        let config = WalletConfigContent {
            mints: vec!["https://m".to_string()],
            counters: HashMap::from([("00ad268c4d1f5826".to_string(), 5u32)]),
        };
        let ciphertext = a.encrypt_config(&config).unwrap();
        assert!(
            b.decrypt_config(&ciphertext).is_err(),
            "a different event key MUST NOT decrypt another agent's wallet config (key-bound)"
        );
    }

    #[test]
    fn wallet_config_from_counters_hex_keys_round_trip_to_the_same_keyset() {
        let id_a: Id = "00ad268c4d1f5826".parse().expect("valid keyset id");
        let id_b: Id = "009a1f293253e41e".parse().expect("valid keyset id");
        let config = WalletConfigContent::from_counters(
            HashMap::from([(id_a, 42u32), (id_b, 7u32)]),
            vec!["https://m".to_string()],
        );
        assert_eq!(config.counters.len(), 2, "every counter is carried");
        assert_eq!(
            config.mints,
            vec!["https://m".to_string()],
            "mints carried verbatim"
        );
        // Each keyset's counter is keyed by its canonical hex AND that hex parses back to the SAME
        // Id — so the reconstruct (N5) re-attributes each counter to the right keyset. A
        // non-canonical stringification would break the round-trip = misattributed/dropped counter
        // = a reconstructed wallet re-deriving the wrong/already-spent secrets (money loss).
        for (id, expected) in [(id_a, 42u32), (id_b, 7u32)] {
            let hex = id.to_string();
            assert_eq!(
                config.counters.get(&hex).copied(),
                Some(expected),
                "counter keyed by the keyset's canonical hex"
            );
            let parsed: Id = hex.parse().expect("the hex key parses back to an Id");
            assert_eq!(
                parsed, id,
                "the hex round-trips to the SAME keyset (no counter misattribution on reconstruct)"
            );
        }
    }

    /// A test [`Nip60Transport`] that records the KIND of every send in order, returns a
    /// configurable ack count, and replays a fixed event set on fetch — so the money-critical
    /// orchestration (≥k gate, confirm-before-delete ordering, aggregate reconcile, fail-closed
    /// load) is exercised without a live relay.
    struct MockTransport {
        acks: usize,
        sends: Mutex<Vec<u16>>,
        fetch_result: Vec<Event>,
    }

    impl MockTransport {
        fn new(acks: usize) -> Self {
            Self {
                acks,
                sends: Mutex::new(Vec::new()),
                fetch_result: Vec::new(),
            }
        }

        fn with_fetch(acks: usize, fetch_result: Vec<Event>) -> Self {
            Self {
                acks,
                sends: Mutex::new(Vec::new()),
                fetch_result,
            }
        }

        /// The kinds sent so far, in call order (asserts the confirm-before-delete sequence).
        fn sent_kinds(&self) -> Vec<u16> {
            self.sends.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Nip60Transport for MockTransport {
        async fn send_event(
            &self,
            kind: u16,
            _content: String,
            _tags: Vec<Tag>,
        ) -> anyhow::Result<SendOutcome> {
            self.sends.lock().unwrap().push(kind);
            Ok(SendOutcome {
                event_id: EventId::from_slice(&[0u8; 32]).expect("a 32-byte event id"),
                acks: self.acks,
            })
        }

        async fn fetch_events(
            &self,
            _filter: Filter,
            _timeout: Duration,
        ) -> anyhow::Result<Vec<Event>> {
            Ok(self.fetch_result.clone())
        }
    }

    /// A token event encrypted + SIGNED by `crypto` (so it passes the author filter and `crypto`
    /// decrypts it) — the shape the transport replays on fetch.
    fn signed_token_event(crypto: &Nip60Crypto, content: TokenEventContent) -> Event {
        let ciphertext = crypto.encrypt(&content).expect("encrypt token content");
        EventBuilder::new(Kind::from(KIND_NIP60_TOKEN), ciphertext)
            .sign_with_keys(&crypto.signer_keys())
            .expect("sign token event")
    }

    #[tokio::test]
    async fn publish_token_requires_k_of_n_acks() {
        let crypto = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[4u8; 64])).unwrap();
        let content = tec(&[]);
        // n=3, k=2. Only 1 ack (< k) → NOT durable → error (proofs not backed up).
        let under = Arc::new(MockTransport::new(1));
        let store = Nip60Store::with_transport(crypto.clone(), under, 3, 2, allow_m());
        assert!(
            store.publish_token(&content).await.is_err(),
            "a sub-quorum publish (<k acks) must error — the proofs are NOT durably backed up"
        );
        // 2 acks (== k) → durable → ok.
        let quorum = Arc::new(MockTransport::new(2));
        let store_ok = Nip60Store::with_transport(crypto, quorum, 3, 2, allow_m());
        assert!(
            store_ok.publish_token(&content).await.is_ok(),
            "k-of-n acks → a durable publish"
        );
    }

    #[tokio::test]
    async fn rollover_confirms_publish_before_delete_and_skips_delete_when_not_durable() {
        let crypto = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[5u8; 64])).unwrap();
        let superseded =
            vec!["0000000000000000000000000000000000000000000000000000000000000001".to_string()];

        // Durable (2 == k): the new token event is published, THEN the old is deleted — in order.
        let durable = Arc::new(MockTransport::new(2));
        let store = Nip60Store::with_transport(crypto.clone(), durable.clone(), 3, 2, allow_m());
        store
            .rollover("https://m", "sat", Vec::new(), superseded.clone())
            .await
            .expect("a durable rollover succeeds");
        assert_eq!(
            durable.sent_kinds(),
            vec![KIND_NIP60_TOKEN, KIND_NIP09_DELETE],
            "confirm-before-delete: the new token event is published BEFORE the NIP-09 delete"
        );

        // Sub-quorum (1 < k): the new event is NOT durable → rollover errors and NEVER deletes.
        let sub = Arc::new(MockTransport::new(1));
        let store2 = Nip60Store::with_transport(crypto, sub.clone(), 3, 2, allow_m());
        assert!(
            store2
                .rollover("https://m", "sat", Vec::new(), superseded)
                .await
                .is_err(),
            "a non-durable new event must fail the rollover"
        );
        assert_eq!(
            sub.sent_kinds(),
            vec![KIND_NIP60_TOKEN],
            "MONEY-SAFETY: the delete is NOT sent when the new event is not durable — the old \
             proofs stay live"
        );
    }

    #[tokio::test]
    async fn reconcile_on_load_decrypts_and_aggregates_through_the_transport() {
        let crypto = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[6u8; 64])).unwrap();
        // Two live token events, distinct proofs → both aggregate (a head would drop one = loss).
        let e1 = signed_token_event(&crypto, tec_with(&[], vec![dummy_proof("s1")]));
        let e2 = signed_token_event(&crypto, tec_with(&[], vec![dummy_proof("s2")]));
        let mock = Arc::new(MockTransport::with_fetch(2, vec![e1, e2]));
        let store = Nip60Store::with_transport(crypto, mock, 3, 2, allow_m());
        let proofs = store.reconcile_on_load().await.expect("reconcile");
        assert_eq!(
            proofs.len(),
            2,
            "both live events' proofs aggregate through the fetch→decrypt→aggregate path"
        );
    }

    #[tokio::test]
    async fn load_config_is_none_when_fresh_and_fails_closed_on_undecryptable_head() {
        let crypto = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[8u8; 64])).unwrap();
        // No config event → None (a fresh wallet), NOT an error.
        let empty = Arc::new(MockTransport::with_fetch(2, Vec::new()));
        let fresh = Nip60Store::with_transport(crypto.clone(), empty, 3, 2, allow_m());
        assert!(
            fresh.load_config().await.expect("load").is_none(),
            "no config event → None (fresh wallet)"
        );
        // A config head we cannot decrypt (encrypted to a DIFFERENT key, but signed by us so it
        // passes the author filter) → hard error, NEVER a silent empty floor.
        let other = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[9u8; 64])).unwrap();
        let foreign_ct = other
            .encrypt_config(&WalletConfigContent::default())
            .unwrap();
        let head = EventBuilder::new(Kind::from(KIND_NIP60_WALLET_CONFIG), foreign_ct)
            .sign_with_keys(&crypto.signer_keys())
            .unwrap();
        let corrupt = Arc::new(MockTransport::with_fetch(2, vec![head]));
        let store = Nip60Store::with_transport(crypto, corrupt, 3, 2, allow_m());
        assert!(
            store.load_config().await.is_err(),
            "an undecryptable config head fails CLOSED (never a silent empty floor → no regression)"
        );
    }
}
