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
//! [`crate::nip60_key::derive_nip60_event_key`]), so a reborn / failed-over instance with the
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

    /// The inverse of [`Self::from_counters`]: parse the hex keyset ids back to [`Id`] for seeding
    /// the counter mirror on a reconstruct
    /// ([`crate::nip60_counter::Nip60CounterDb::with_counters`]). A key that fails to parse is
    /// DROPPED with a warning — our own writes always round-trip (the hex is `Id`'s `Display`), so
    /// a parse failure is relay corruption, not a normal case; dropping one keyset's floor (mint
    /// remains truth; only that keyset is at risk, logged loudly) is safer than failing the boot.
    pub fn counters_by_id(&self) -> HashMap<Id, u32> {
        self.counters
            .iter()
            .filter_map(|(hex, &counter)| match hex.parse::<Id>() {
                Ok(id) => Some((id, counter)),
                Err(e) => {
                    tracing::warn!(
                        keyset_hex = %hex,
                        error = %e,
                        "NIP-60 load: dropping a counter with an unparseable keyset id (corruption)"
                    );
                    None
                }
            })
            .collect()
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
    /// ([`crate::nip60_key::derive_nip60_event_key`]). Errs only if the bytes are not a valid
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

    /// Per-relay read: how many DISTINCT relays SERVED events + the deduped union.
    /// Consumed by the read-quorum tally (Cut A) and the ≥k-served check.
    ///
    /// Default impl delegates to `fetch_events` as ONE served relay (total=1, served=1)
    /// so existing single-relay impls (MockTransport, InMemoryRelay) inherit served=1 ≥
    /// read_k=1 → authoritative under any single-relay config — zero behavior change.
    async fn fetch_events_per_relay(
        &self,
        filter: Filter,
        timeout: Duration,
    ) -> anyhow::Result<PerRelayRead> {
        let events = self.fetch_events(filter, timeout).await?;
        Ok(PerRelayRead { served: 1, total: 1, events })
    }
}

/// The per-relay read result: how many DISTINCT relays SERVED events + the deduped union.
/// Produced by [`Nip60Transport::fetch_events_per_relay`] and consumed by the read-quorum tally
/// (Cut A) — `served >= read_k` is the authoritativeness gate.
pub struct PerRelayRead {
    /// DISTINCT relays that responded (served at least one event, or confirmed empty within timeout).
    pub served: usize,
    /// READ-capable relays in the pool (denominator for the quorum tally).
    pub total: usize,
    /// Deduped union of events across all served relays.
    pub events: Vec<Event>,
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

    /// Per-relay read against the PRODUCTION relay pool.
    ///
    /// Fan-out across every READ-capable relay concurrently.  Down / half-open
    /// relays are caught in two layers:
    ///   1. Cheap status precheck (one atomic load) — skips obviously-dead relays
    ///      at ~0ns without touching the socket.
    ///   2. Outer `tokio::time::timeout(guard, …)` — ensures a deaf socket can
    ///      never stall the whole tally beyond `timeout + 500ms`.
    ///
    /// Served classification: `Ok(events)` (including an EOSE'd empty set) counts
    /// as served; `Err` or elapsed counts as not-served.  Dedup is by event id so
    /// the union returned to the caller contains no duplicates.
    async fn fetch_events_per_relay(
        &self,
        filter: Filter,
        timeout: Duration,
    ) -> anyhow::Result<PerRelayRead> {
        // READ-capable relays = the quorum denominator.
        let relays = self
            .client
            .pool()
            .relays_with_flag(RelayServiceFlags::READ, FlagCheck::All)
            .await; // HashMap<RelayUrl, Relay>
        let total = relays.len();
        // Down/half-open relays do NOT err fast — they ride the full timeout
        // (the #103 deaf-socket problem).  Defences: cheap status precheck (1
        // atomic load) + defensive outer timeout + full concurrency (join_all).
        let guard = timeout + std::time::Duration::from_millis(500);
        let reads = relays.into_values().map(|relay| {
            let filter = filter.clone();
            async move {
                if !relay.is_connected() {
                    return None; // down → not-served, ~0ns
                }
                match tokio::time::timeout(
                    guard,
                    relay.fetch_events(filter, timeout, ReqExitPolicy::ExitOnEOSE),
                )
                .await
                {
                    Ok(Ok(events)) => Some(events.into_iter().collect::<Vec<Event>>()), // served
                    _ => None, // Err / elapsed → not-served
                }
            }
        });
        let results = futures::future::join_all(reads).await;
        let mut served = 0usize;
        let mut seen = std::collections::HashSet::new();
        let mut events = Vec::new();
        for evs in results.into_iter().flatten() {
            served += 1;
            for e in evs {
                if seen.insert(e.id) {
                    events.push(e);
                }
            }
        }
        Ok(PerRelayRead { served, total, events })
    }
}

/// The result of a load-time reconcile (returned by [`Nip60Store::reconcile_on_load_with_ids`]).
/// Carries the per-relay quorum metadata alongside the candidate proofs so the boot solvency
/// gate can use the same read's authority verdict (R2 condition a).
pub struct ReconcileRead {
    /// The aggregated candidate proofs (to be NUT-07-gated before import).
    pub candidates: Vec<Proof>,
    /// Hex ids of EVERY kind:7375 token event seen (decryptable or not) — seeds the flusher's
    /// live-id set so the first flush del-chains ALL prior events into one clean snapshot.
    pub fetched_ids: Vec<String>,
    /// DISTINCT relays that served events (or confirmed empty) within the read timeout.
    pub served: usize,
    /// READ-capable relays in the pool (denominator).
    pub total: usize,
    /// The read_k threshold this store was configured with.
    pub read_k: usize,
    /// `served >= read_k` — the boot solvency gate uses this to decide Assert vs Proceed.
    pub authoritative: bool,
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
    /// The K-of-N READ threshold: served >= read_k ⇒ authoritative. Default = majority.
    read_k: usize,
    read_timeout: Duration,
    /// The mints whose relay-stored proofs this wallet will adopt on reconcile (N7 theft-guard;
    /// [`crate::config::BrainConfig::effective_mint_allowlist`]). Always includes the agent's own
    /// mint. Proofs drawn on any other mint are dropped by [`reconcile_token_set`].
    mint_allowlist: Vec<String>,
    /// R2: set to `true` when a reconcile_on_load_with_ids returned served >= read_k.
    /// `false` at construction; flipped by the reconcile. Accessed via SeqCst atomics so
    /// the rollover gate (which holds `&self`) can read it without `&mut self`.
    read_established: Arc<std::sync::atomic::AtomicBool>,
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
        read_k_opt: Option<usize>,
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
        let read_k = read_k_opt.unwrap_or(n / 2 + 1).clamp(1, n);
        tracing::info!(npub = %crypto.public_key().to_hex(), n, k, read_k, "NIP-60 wallet store connected");
        Ok(Nip60Store {
            crypto,
            transport: Arc::new(ClientTransport { client }),
            n,
            k,
            read_k,
            read_timeout: Duration::from_secs(NIP60_READ_TIMEOUT_SECS),
            mint_allowlist,
            read_established: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Build a store over an arbitrary [`Nip60Transport`] — the seam the unit tests inject a mock
    /// through to exercise the ≥k gate + confirm-before-delete ordering without a live relay.
    /// `read_k` defaults to `k` (write quorum); `read_established` starts TRUE so existing tests
    /// that don't exercise the R2 read-quorum gate (e.g. the R1 rollover tests that call `rollover`
    /// directly without a prior reconcile) keep working unchanged.
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
            read_k: k, // default: same as write_k
            read_timeout: Duration::from_secs(NIP60_READ_TIMEOUT_SECS),
            mint_allowlist,
            // TRUE: existing tests that go straight to `rollover` without a prior reconcile don't
            // hit the R2 gate. R2 drill tests use `with_transport_and_read_k` + explicit reconcile.
            read_established: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// `with_transport` variant with an explicit `read_k` and `read_established = false` — used by
    /// R2 drill tests that model a below-quorum boot (the D_b tooth, etc.). The test drives the
    /// reconcile explicitly to flip `read_established` when it wants to simulate quorum recovery.
    #[cfg(test)]
    fn with_transport_and_read_k(
        crypto: Nip60Crypto,
        transport: Arc<dyn Nip60Transport>,
        n: usize,
        k: usize,
        read_k: usize,
        mint_allowlist: Vec<String>,
    ) -> Self {
        Nip60Store {
            crypto,
            transport,
            n,
            k,
            read_k,
            read_timeout: Duration::from_secs(NIP60_READ_TIMEOUT_SECS),
            mint_allowlist,
            // FALSE: the R2 drill tests start with a below-quorum boot and drive reconcile to flip.
            read_established: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
    ///
    /// ⚠️ This convenience wrapper drops the quorum metadata; prefer
    /// [`Self::reconcile_on_load_with_ids`] when the boot solvency gate needs `authoritative`.
    pub async fn reconcile_on_load(&self) -> anyhow::Result<Vec<Proof>> {
        Ok(self.reconcile_on_load_with_ids().await?.candidates)
    }

    /// As [`Self::reconcile_on_load`], but ALSO returns the hex ids of EVERY kind:7375 token event
    /// fetched under the event key (decryptable or not), and the per-relay quorum metadata. The
    /// Cut A (#115) backup flusher seeds its live-id set with `fetched_ids` so the FIRST flush's
    /// rollover del-chains ALL prior token events into ONE clean new snapshot. The `authoritative`
    /// flag is `served >= read_k`; when false the R2 solvency gate proceeds non-authoritatively
    /// and the rollover gate holds until a >=k read re-establishes.
    pub async fn reconcile_on_load_with_ids(&self) -> anyhow::Result<ReconcileRead> {
        let filter = Filter::new()
            .kind(Kind::from(KIND_NIP60_TOKEN))
            .author(self.crypto.public_key());
        // R2: use per-relay read so we can count how many DISTINCT relays served events.
        let per = self
            .transport
            .fetch_events_per_relay(filter, self.read_timeout)
            .await
            .context("fetch NIP-60 token events for reconcile (per-relay)")?;
        let authoritative = per.served >= self.read_k;
        // Store the verdict so the rollover gate can read it without a new relay fetch.
        self.read_established
            .store(authoritative, std::sync::atomic::Ordering::SeqCst);
        tracing::info!(
            served = per.served,
            total = per.total,
            read_k = self.read_k,
            authoritative,
            "NIP-60 reconcile: per-relay read quorum"
        );
        let mut fetched_ids: Vec<String> = Vec::with_capacity(per.events.len());
        let mut decoded: Vec<(String, TokenEventContent)> = Vec::new();
        for ev in per.events.into_iter() {
            let id_hex = ev.id.to_hex();
            fetched_ids.push(id_hex.clone());
            match self.crypto.decrypt(&ev.content) {
                Ok(content) => decoded.push((id_hex, content)),
                Err(e) => tracing::warn!(
                    event_id = %ev.id,
                    error = %e,
                    "NIP-60 reconcile: skipping an undecryptable token event (foreign under our author)"
                ),
            }
        }
        let candidates = reconcile_token_set(&decoded, &self.mint_allowlist);
        Ok(ReconcileRead {
            candidates,
            fetched_ids,
            served: per.served,
            total: per.total,
            read_k: self.read_k,
            authoritative,
        })
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
    /// ⚠️ MONEY-SAFETY ORDERING (design doc point 6, + R1 read-after-write + R2 read-quorum gate):
    /// (0, R2) ABORT if the boot-time reconcile was NOT authoritative (below read-quorum): the
    /// restored proof set may be INCOMPLETE, so publishing a rollover here would del-chain/prune
    /// events that were merely un-fetched — turning a thin READ into a backup WRITE-LOSS. Publish
    /// and prune NOTHING; keep the prior backup; re-arm dirty (flusher retries next tick); (1) the
    /// new event carries `del = superseded` — the del-chain, the AUTHORITATIVE supersede honored by
    /// [`reconcile_token_set`] even if the NIP-09 delete is ignored; (2) it is published and MUST
    /// reach >=k relays ([`Self::publish_token`] ERRORS otherwise) BEFORE anything is deleted, so a
    /// non-durable new event leaves the OLD events LIVE (never delete an input until its replacement
    /// is durable on quorum); (2b, R1) then a bounded READ-AFTER-WRITE confirms the new event is
    /// actually RETRIEVABLE (not merely acked) — if it is not, nothing is deleted and this returns
    /// an Err the flusher retries (closing the acked-but-not-served → delete-old → backup-GONE
    /// hole); (3) ONLY THEN are the old events NIP-09-deleted — best-effort + advisory (relays may
    /// ignore; the del-chain + the mint are the real supersede/truth), so a delete failure is
    /// logged, NOT fatal.
    pub async fn rollover(
        &self,
        mint: &str,
        unit: &str,
        new_proofs: Vec<Proof>,
        superseded: Vec<String>,
    ) -> anyhow::Result<EventId> {
        // R2 condition (b): a below-read-quorum boot is NON-AUTHORITATIVE — its restored proof set
        // may be INCOMPLETE. Publishing a rollover here would del-chain/prune events that were
        // merely un-fetched (not truly superseded), turning a thin READ into a backup WRITE-LOSS.
        // Publish/prune NOTHING; keep the prior backup; the flusher's `?` + RearmOnDrop re-arms
        // dirty, so the snapshot is retried next tick (after a >=k read re-establishes authority).
        if !self.read_established.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::warn!(
                "rollover: read not established (below read-quorum boot) — kept prior backup, \
                 published/pruned nothing; will retry once a >=k read lands"
            );
            anyhow::bail!(
                "rollover skipped: read not established (non-authoritative boot)"
            );
        }

        let content = TokenEventContent {
            mint: mint.to_string(),
            unit: unit.to_string(),
            proofs: new_proofs,
            del: superseded.clone(),
        };
        // CONFIRM (1/2 — DURABLE): the new event must be >=k durable before ANYTHING is deleted.
        // `?` returns here on a sub-quorum publish → nothing is deleted and the old proofs stay
        // live (money-safe).
        let new_id = self.publish_token(&content).await.context(
            "rollover: the new token event is NOT durable on >=k relays — deleted NOTHING, the old \
             proofs stay live",
        )?;

        // CONFIRM (2/2 — RETRIEVABLE, R1): >=k ACKED is not the same as SERVED. A relay can ack a
        // write yet not serve it back (acked-but-not-served); if we deleted the old events on the
        // strength of the ack alone and the new event were unretrievable, the ONLY backup would be
        // gone. So before deleting anything, do a bounded read (author + kind:7375, read_timeout)
        // and CONFIRM the just-published id is in the returned (unioned) set. If it is NOT present
        // (or the read errored) we DO NOT delete the superseded events (the old backup stays
        // intact), warn, and return an Err — the SAME self-heal posture as a sub-quorum publish:
        // the backup flusher's `?` re-arms its dirty flag (see `crate::rail::Nip60BackupFlusher::
        // flush`, RearmOnDrop) so the snapshot is retried next tick. This is off the spend hot path
        // (rollover is only ever called by the flusher/estate/boot, never a spend), so the extra
        // read costs a spend nothing.
        //
        // R1 SCOPE: this confirms RETRIEVABLE (present on >=1 relay of the union) — it upgrades the
        // guard from "confirmed ACKED" to "confirmed RETRIEVABLE", closing the acked-but-not-served
        // → delete-old → backup-GONE hole. A true ">=k SERVED" read-quorum needs per-relay READ
        // visibility (a `Nip60Transport` extension), which R2 adds for its read-quorum reconcile;
        // R1 deliberately stays minimal and trait-compatible.
        let confirm_filter = Filter::new()
            .kind(Kind::from(KIND_NIP60_TOKEN))
            .author(self.crypto.public_key());
        match self.transport.fetch_events(confirm_filter, self.read_timeout).await {
            Ok(events) if events.iter().any(|e| e.id == new_id) => {
                // Retrievable — fall through to the (advisory) prune below.
            }
            Ok(_) => {
                tracing::warn!(
                    new_event_id = %new_id,
                    "rollover: the new token event ACKED >=k but is NOT retrievable yet \
                     (acked-but-not-served) — KEEPING the prior events, deleted NOTHING; the backup \
                     flusher will retry the snapshot next tick"
                );
                anyhow::bail!(
                    "rollover: the new token event {new_id} is not retrievable after publish \
                     (acked-but-not-served) — deleted NOTHING, the old proofs stay live"
                );
            }
            Err(e) => {
                tracing::warn!(
                    new_event_id = %new_id,
                    error = %e,
                    "rollover: the read-after-write confirm FETCH errored — cannot confirm the new \
                     token event is retrievable, so KEEPING the prior events, deleted NOTHING; the \
                     backup flusher will retry next tick"
                );
                return Err(e).context(
                    "rollover: read-after-write confirm failed — deleted NOTHING, the old proofs \
                     stay live",
                );
            }
        }

        // Only now (the new event is >=k durable AND retrievable) prune the superseded events.
        // Advisory — never trusted; a failure is logged, not fatal.
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
    use crate::nip60_counter::Nip60CounterDb;
    use crate::nip60_key::derive_nip60_event_key;

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

        // Durable (2 == k) AND retrievable: over a round-tripping multi-relay double, the new token
        // event publishes to >=k relays, the read-after-write confirm finds it, THEN the old event
        // is deleted — in order. (First seed a real prior snapshot to supersede; a MockTransport
        // does NOT round-trip writes to reads, so the R1 RAW confirm needs the storing double here.)
        let durable = Arc::new(MultiRelayTransport::new(3, crypto.clone()));
        let store = Nip60Store::with_transport(crypto.clone(), durable.clone(), 3, 2, allow_m());
        let first_id = store
            .rollover("https://m", "sat", vec![dummy_proof("s1")], Vec::new())
            .await
            .expect("seed a real prior snapshot");
        assert!(!durable.any_delete_sent(), "no delete on the first snapshot (no superseded input)");
        store
            .rollover("https://m", "sat", vec![dummy_proof("s2")], vec![first_id.to_hex()])
            .await
            .expect("a durable + retrievable rollover succeeds");
        assert!(
            durable.any_delete_sent(),
            "confirm-before-delete: the new token event is published + confirmed retrievable BEFORE \
             the NIP-09 delete is sent"
        );

        // Sub-quorum (1 < k): the new event is NOT durable → rollover errors and NEVER deletes. A
        // MockTransport records sends in order; the sub-quorum publish fails the >=k gate BEFORE the
        // RAW confirm is ever reached, so exactly one send (the failed token publish) is recorded.
        let superseded =
            vec!["0000000000000000000000000000000000000000000000000000000000000001".to_string()];
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

    #[test]
    fn counters_by_id_is_the_inverse_of_from_counters() {
        let id_a: Id = "00ad268c4d1f5826".parse().unwrap();
        let id_b: Id = "009a1f293253e41e".parse().unwrap();
        let original = HashMap::from([(id_a, 42u32), (id_b, 7u32)]);
        let config = WalletConfigContent::from_counters(original.clone(), vec!["https://m".into()]);
        // hex → Id recovers the EXACT original floors (lossless both ways) — so a reconstruct
        // seeds the SAME keyset counters it published, with no misattribution or drop.
        assert_eq!(
            config.counters_by_id(),
            original,
            "counters_by_id inverts from_counters"
        );
    }

    /// The boot-push money-MUST at the seam: on a reconstruct the loaded 17375 floor is seeded
    /// into the counter mirror BEFORE the config is published, so the published counter can never
    /// regress below what the relay already recorded (a regression would let a restored wallet
    /// re-derive already-spent NUT-13 secrets). RED-on-revert: swap `with_counters(floor)` for
    /// `new()` (the "unseeded" boot) and the published counter drops to None < the floor.
    #[tokio::test]
    async fn boot_seeds_the_loaded_floor_into_the_mirror_before_publishing() {
        let crypto = Nip60Crypto::from_event_key(&derive_nip60_event_key(&[11u8; 64])).unwrap();
        let id: Id = "00ad268c4d1f5826".parse().unwrap();
        // A prior 17375 config on the relay carrying a counter FLOOR of 100 for the keyset.
        let prior = WalletConfigContent {
            mints: vec!["https://m".to_string()],
            counters: HashMap::from([(id.to_string(), 100u32)]),
        };
        let signed = EventBuilder::new(
            Kind::from(KIND_NIP60_WALLET_CONFIG),
            crypto.encrypt_config(&prior).unwrap(),
        )
        .sign_with_keys(&crypto.signer_keys())
        .unwrap();
        let store = Nip60Store::with_transport(
            crypto,
            Arc::new(MockTransport::with_fetch(2, vec![signed])),
            3,
            2,
            allow_m(),
        );

        // The boot sequence: load the floor → convert to Ids → SEED the mirror BEFORE publishing.
        let loaded = store.load_config().await.unwrap().expect("prior config present");
        let floor = loaded.counters_by_id();
        let mem = cdk_sqlite::wallet::memory::empty().await.unwrap();
        let counter_db = Nip60CounterDb::with_counters(Arc::new(mem), floor);

        // What the (ordered-after-seed) publish carries: the mirror, which holds the loaded floor.
        let to_publish = counter_db.keyset_counters();
        assert_eq!(
            to_publish.get(&id).copied(),
            Some(100),
            "the loaded floor is seeded into the mirror BEFORE publish → the published counter \
             never regresses below 100 (revert with_counters→new and this drops to None)"
        );
        // And the publish lands durably (≥k), carrying the seeded floor.
        store
            .publish_wallet_config(to_publish, loaded.mints)
            .await
            .expect("durable config publish");
    }

    // ========================================================================
    // Cut A (#115): NIP-60 backup write-half teeth. The decorator + flusher live
    // in `crate::rail`; the DI-transport `Nip60Store` + the crypto/proof helpers
    // live here, so the end-to-end round-trip is exercised without a live relay.
    // ========================================================================

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};

    use crate::rail::{EcashProvider, Nip60BackedEcash, OperationId, SendHandle};

    /// A minimal in-crate ecash stub for the decorator teeth: every mutation succeeds and bumps a
    /// per-method call counter, EXCEPT when armed to fail (to prove an Err leaves dirty untouched).
    /// Distinct from the integration `StubEcash` (that one lives in `tests/common`, unreachable from
    /// a lib unit test); this one only needs to model success/failure + count calls.
    struct CountingEcash {
        fail: bool,
        mint_calls: AtomicU64,
        redeem_calls: AtomicU64,
    }

    impl CountingEcash {
        fn healthy() -> Self {
            Self {
                fail: false,
                mint_calls: AtomicU64::new(0),
                redeem_calls: AtomicU64::new(0),
            }
        }
        fn failing() -> Self {
            Self {
                fail: true,
                mint_calls: AtomicU64::new(0),
                redeem_calls: AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl EcashProvider for CountingEcash {
        async fn mint_send_token(&self, _amount_sats: u64) -> anyhow::Result<SendHandle> {
            self.mint_calls.fetch_add(1, AtomicOrdering::SeqCst);
            if self.fail {
                anyhow::bail!("counting-ecash mint failure");
            }
            Ok(SendHandle {
                token: "cashuTEST".to_string(),
                operation_id: OperationId::from_u128(1),
            })
        }
        async fn redeem_foreign(&self, _token: &str) -> anyhow::Result<u64> {
            self.redeem_calls.fetch_add(1, AtomicOrdering::SeqCst);
            if self.fail {
                anyhow::bail!("counting-ecash redeem failure");
            }
            Ok(0)
        }
        async fn revoke_send(&self, _op: &OperationId) -> anyhow::Result<u64> {
            Ok(0)
        }
        async fn recover_incomplete_sagas(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// A recording, round-tripping in-memory relay double: on `send_event` it STORES the (kind,
    /// encrypted content) and returns a UNIQUE event id (so distinct sends get distinct ids); on
    /// `fetch_events` it REPLAYS every stored kind:7375 event as a signed event authored by
    /// `crypto` — so `reconcile_on_load` reads back exactly what a flush published. `acks` is the
    /// per-send ack count (>= k → durable; 0 → the publish/rollover fails, modelling a doomed
    /// backup). NIP-09 deletes are recorded but not applied (advisory; the del-chain is what the
    /// reconcile honors, and a snapshot flush del-chains the PRIOR ids each time).
    struct InMemoryRelay {
        acks: usize,
        crypto: Nip60Crypto,
        // The fully-signed events stored, in send order. Each is SIGNED ONCE in `send_event` and
        // served back VERBATIM on fetch — so the id `send_event` returns (the id a rollover records
        // into `live_ids`) is EXACTLY the id a fetch serves back (as in the production
        // `ClientTransport`). This id-stability is what the R1 read-after-write confirm inside
        // `rollover` relies on, and it lets the codex-#2 tooth pair each published token event with
        // the id the flusher tracks and run `live_token_event_ids` on the chain.
        sends: Mutex<Vec<Event>>,
    }

    impl InMemoryRelay {
        fn new(acks: usize, crypto: Nip60Crypto) -> Self {
            Self {
                acks,
                crypto,
                sends: Mutex::new(Vec::new()),
            }
        }
        /// The kinds sent so far, in order (asserts publish count / sequencing).
        fn sent_kinds(&self) -> Vec<u16> {
            self.sends.lock().unwrap().iter().map(|ev| ev.kind.as_u16()).collect()
        }
        /// How many kind:7375 token events were published (the rollover snapshots).
        fn token_publishes(&self) -> usize {
            self.sent_kinds()
                .iter()
                .filter(|k| **k == KIND_NIP60_TOKEN)
                .count()
        }
        /// Every kind:17375 wallet-config published, decrypted (Cut B, #115: the counter-estate
        /// re-publish carries the current counter mirror; a tooth asserts on its `counters`).
        fn decoded_config_events(&self) -> Vec<WalletConfigContent> {
            self.sends
                .lock()
                .unwrap()
                .iter()
                .filter(|ev| ev.kind == Kind::from(KIND_NIP60_WALLET_CONFIG))
                .map(|ev| self.crypto.decrypt_config(&ev.content).expect("decrypt a config event"))
                .collect()
        }
    }

    #[async_trait]
    impl Nip60Transport for InMemoryRelay {
        async fn send_event(
            &self,
            kind: u16,
            content: String,
            tags: Vec<Tag>,
        ) -> anyhow::Result<SendOutcome> {
            // Sign ONCE; the id is the real NIP-01 id (as `ClientTransport` returns), served back
            // verbatim on fetch so the send id and the fetch id are the same event.
            let event = EventBuilder::new(Kind::from(kind), content)
                .tags(tags)
                .sign_with_keys(&self.crypto.signer_keys())
                .expect("sign the event");
            let event_id = event.id;
            self.sends.lock().unwrap().push(event);
            Ok(SendOutcome {
                event_id,
                acks: self.acks,
            })
        }

        async fn fetch_events(
            &self,
            _filter: Filter,
            _timeout: Duration,
        ) -> anyhow::Result<Vec<Event>> {
            // Serve every stored TOKEN event back VERBATIM (already signed + author-matching, so the
            // reconcile's author filter + decrypt succeed, and each id equals what `send_event`
            // returned).
            let events = self
                .sends
                .lock()
                .unwrap()
                .iter()
                .filter(|ev| ev.kind == Kind::from(KIND_NIP60_TOKEN))
                .cloned()
                .collect();
            Ok(events)
        }

        /// R2: model `InMemoryRelay` as serving `acks` distinct relays so that tests that
        /// configure it with `InMemoryRelay::new(2, ...)` + `read_k=2` remain authoritative
        /// (served=2 >= read_k=2 → `read_established=true`). A 0-ack relay → served=0 → not
        /// authoritative (models a doomed relay). The union is from `fetch_events` above.
        async fn fetch_events_per_relay(
            &self,
            filter: Filter,
            timeout: Duration,
        ) -> anyhow::Result<PerRelayRead> {
            let events = self.fetch_events(filter, timeout).await?;
            // served = acks models "this many relay confirmations" — deduplication is already
            // handled (only one store, one signing) so total=served=acks.
            Ok(PerRelayRead { served: self.acks, total: self.acks.max(1), events })
        }
    }

    fn test_crypto(seed_byte: u8) -> Nip60Crypto {
        Nip60Crypto::from_event_key(&derive_nip60_event_key(&[seed_byte; 64])).unwrap()
    }

    /// An EMPTY in-memory cdk wallet pointed at a dead URL. `get_proofs_with` reads the LOCAL store
    /// only (no network), so this yields an empty unspent set for the decorator/coalesce teeth that
    /// do not assert on proof contents (only tooth 2 funds a wallet, which needs a live mint).
    async fn empty_wallet() -> Arc<cdk::Wallet> {
        crate::mint_rig::build_wallet("http://127.0.0.1:1")
            .await
            .expect("build an empty in-memory wallet (no network at construction)")
    }

    // ---- Tooth 1 (the load-bearer): a spend is NEVER blocked by a doomed backup. --------------
    #[tokio::test]
    async fn spend_succeeds_even_when_the_backup_publish_fails() {
        let crypto = test_crypto(0x11);
        // A 0-ack relay: every publish is sub-quorum → rollover ERRORS → the backup is DOOMED.
        let relay = Arc::new(InMemoryRelay::new(0, crypto.clone()));
        let store = Arc::new(Nip60Store::with_transport(crypto, relay, 3, 2, allow_m()));
        let wallet = empty_wallet().await;
        let ecash = CountingEcash::healthy();
        let (decorated, flusher) = Nip60BackedEcash::with_flusher(
            ecash,
            wallet,
            store,
            "https://m".to_string(),
            "sat".to_string(),
            Vec::new(),
        );
        // Start from a clean flag so the mutation's SET is what we observe (the constructor seeds
        // dirty=true for the initial snapshot; clear it first).
        flusher.force_clean();
        assert!(!flusher.is_dirty(), "baseline: clean before the mutation");

        // The spend runs through the decorator and SUCCEEDS even though the backup is doomed —
        // the hot path only flips a flag, it never touches the (doomed) relay.
        let handle = decorated
            .mint_send_token(42)
            .await
            .expect("the spend must NOT be blocked by the backup path");
        assert_eq!(handle.token, "cashuTEST", "the inner spend result is returned unchanged");
        assert!(
            flusher.is_dirty(),
            "a successful mutation marks the backup dirty (the hot-path signal)"
        );

        // And proving the backup really is doomed: a flush now ERRORS (sub-quorum rollover) yet the
        // spend above already succeeded, and the failed flush RE-ARMS dirty for a later retry.
        assert!(
            flusher.flush().await.is_err(),
            "the doomed backup fails to publish (0 acks < k) — but the spend already succeeded"
        );
        assert!(flusher.is_dirty(), "a failed flush stays dirty (re-armed for retry)");

        // The complement MONEY-MUST: a FAILED mutation changed nothing, so it must NOT dirty the
        // backup (there are no new proofs to snapshot).
        let crypto2 = test_crypto(0x12);
        let relay2 = Arc::new(InMemoryRelay::new(2, crypto2.clone()));
        let store2 = Arc::new(Nip60Store::with_transport(crypto2, relay2, 3, 2, allow_m()));
        let (decorated_fail, flusher_fail) = Nip60BackedEcash::with_flusher(
            CountingEcash::failing(),
            empty_wallet().await,
            store2,
            "https://m".to_string(),
            "sat".to_string(),
            Vec::new(),
        );
        flusher_fail.force_clean();
        assert!(
            decorated_fail.mint_send_token(9).await.is_err(),
            "the inner mint failed → the decorator propagates the Err"
        );
        assert!(
            !flusher_fail.is_dirty(),
            "a FAILED mutation must NOT mark the backup dirty (nothing changed to back up)"
        );
    }

    // ---- Tooth 2 (non-vacuity): a real funded wallet's proofs round-trip through a flush. ------
    //
    // The ONLY tooth that needs a live mint (real unspent proofs). Boots a compact local cdk-mintd
    // fakewallet fixture, funds a wallet, wraps it in the decorator, does a mutation, flushes, then
    // asserts `reconcile_on_load` reads back a NON-EMPTY proof set. RED-on-revert: neuter the flush
    // (make it a no-op) and the relay stays empty → reconcile returns empty → the assert fails.
    #[tokio::test]
    async fn restore_finds_the_proofs_after_a_spend_then_flush() {
        let mint = mint_fixture::FakeMint::start(18860)
            .await
            .expect("boot the local fakewallet mint");
        let mint_url = mint.url();

        let wallet = crate::mint_rig::build_wallet(&mint_url)
            .await
            .expect("build wallet");
        crate::mint_rig::fund_wallet(wallet.clone(), 1000)
            .await
            .expect("fund the wallet on the fakewallet mint");

        let crypto = test_crypto(0x22);
        // A 2-ack (>= k=2) relay: publishes are durable and round-trip on fetch.
        let relay = Arc::new(InMemoryRelay::new(2, crypto.clone()));
        let store = Arc::new(Nip60Store::with_transport(
            crypto,
            relay.clone(),
            3,
            2,
            vec![mint_url.clone()],
        ));

        let ecash = crate::rail::CdkEcash::new(wallet.clone());
        let (decorated, flusher) = Nip60BackedEcash::with_flusher(
            ecash,
            wallet.clone(),
            store.clone(),
            mint_url.clone(),
            "sat".to_string(),
            Vec::new(),
        );

        // BEFORE any flush the relay is empty → reconcile finds nothing (the pre-condition the
        // production-dead write-chain was stuck at).
        let before = store
            .reconcile_on_load()
            .await
            .expect("reconcile (empty backup)");
        assert!(before.is_empty(), "no backup yet → reconcile returns empty");

        // A spend-path mutation (mint a send token) marks dirty; the flush publishes the wallet's
        // CURRENT UNSPENT snapshot (the change proofs left after the send).
        decorated
            .mint_send_token(100)
            .await
            .expect("mint a send token from the funded wallet");
        flusher.flush().await.expect("the backup flush publishes durably");

        // The non-vacuity proof: reconcile now reads back the wallet's unspent proofs.
        let restored = store
            .reconcile_on_load()
            .await
            .expect("reconcile after the flush");
        let live_unspent = wallet
            .get_proofs_with(Some(vec![cdk::nuts::State::Unspent]), None)
            .await
            .expect("read the wallet's current unspent proofs");
        assert!(
            !restored.is_empty(),
            "AFTER a spend+flush the relay-backed proofs are non-empty (the write-chain is LIVE, \
             not vacuous) — revert the flush wiring and this is empty"
        );
        assert_eq!(
            restored.len(),
            live_unspent.len(),
            "the backup snapshot is exactly the wallet's current-unspent set"
        );
        assert_eq!(relay.token_publishes(), 1, "the flush published exactly one snapshot");

        mint.shutdown().await;
    }

    // ---- Tooth 3: a failed flush stays dirty and a later working flush publishes. --------------
    #[tokio::test]
    async fn a_failed_flush_stays_dirty_and_retries() {
        let crypto = test_crypto(0x33);
        // Start doomed (0 acks): the first flush fails and re-arms dirty.
        let relay = Arc::new(InMemoryRelay::new(0, crypto.clone()));
        let store = Arc::new(Nip60Store::with_transport(crypto, relay.clone(), 3, 2, allow_m()));
        let wallet = empty_wallet().await;
        let (decorated, flusher) = Nip60BackedEcash::with_flusher(
            ecash_healthy(),
            wallet,
            store,
            "https://m".to_string(),
            "sat".to_string(),
            Vec::new(),
        );
        flusher.force_clean();
        decorated.mint_send_token(7).await.expect("spend ok");
        assert!(flusher.is_dirty(), "the mutation dirtied the state");

        assert!(
            flusher.flush().await.is_err(),
            "the failing transport (0 acks) makes the flush error"
        );
        assert!(flusher.is_dirty(), "a failed flush STAYS dirty (not consumed)");
        assert_eq!(relay.token_publishes(), 1, "it attempted the publish (which was sub-quorum)");

        // Now swap in a working relay (>= k) and flush again: it publishes durably and the retry
        // succeeds. (A fresh store over a healthy relay models the next-tick retry landing.)
        let good_relay = Arc::new(InMemoryRelay::new(2, test_crypto(0x33)));
        let good_store =
            Arc::new(Nip60Store::with_transport(test_crypto(0x33), good_relay.clone(), 3, 2, allow_m()));
        let wallet2 = empty_wallet().await;
        let (_decorated2, flusher2) = Nip60BackedEcash::with_flusher(
            ecash_healthy(),
            wallet2,
            good_store,
            "https://m".to_string(),
            "sat".to_string(),
            Vec::new(),
        );
        // The constructor seeded dirty=true (an initial snapshot is pending) → this flush publishes.
        assert!(flusher2.is_dirty(), "a fresh flusher is dirty (initial snapshot pending)");
        flusher2.flush().await.expect("the working transport publishes durably");
        assert_eq!(good_relay.token_publishes(), 1, "the retry landed one durable publish");
    }

    // ---- Tooth 4: two mutations coalesce into ONE snapshot publish. ----------------------------
    #[tokio::test]
    async fn two_mutations_coalesce_into_one_snapshot() {
        let crypto = test_crypto(0x44);
        let relay = Arc::new(InMemoryRelay::new(2, crypto.clone()));
        let store = Arc::new(Nip60Store::with_transport(crypto, relay.clone(), 3, 2, allow_m()));
        let wallet = empty_wallet().await;
        let (decorated, flusher) = Nip60BackedEcash::with_flusher(
            ecash_healthy(),
            wallet,
            store,
            "https://m".to_string(),
            "sat".to_string(),
            Vec::new(),
        );
        flusher.force_clean();

        // TWO successful mutations before any flush.
        decorated.mint_send_token(1).await.expect("spend 1 ok");
        decorated.redeem_foreign("cashuX").await.expect("spend 2 ok");
        assert!(flusher.is_dirty(), "the two mutations left the state dirty (coalesced)");

        // ONE flush → exactly ONE rollover publish of the current set (not one-per-mutation).
        flusher.flush().await.expect("the single flush publishes once");
        assert_eq!(
            relay.token_publishes(),
            1,
            "two mutations then one flush → ONE snapshot publish (the dirty flag coalesces them)"
        );

        // A second flush with NO new mutation is a no-op (nothing new to back up).
        flusher.flush().await.expect("a clean flush is Ok");
        assert_eq!(
            relay.token_publishes(),
            1,
            "a flush with no intervening mutation republishes nothing"
        );
    }

    /// A gating relay for the codex-#2 serialization tooth: it BLOCKS the FIRST `send_event` on a
    /// `Notify` (until the test releases it) and lets every later send through immediately. That
    /// deterministically pins flush A INSIDE its rollover publish while flush B runs, so the test
    /// can force the exact interleave the `flush_lock` must prevent. Stores the fully-signed events
    /// (like [`InMemoryRelay`]) so `decoded_token_events` computes the live set and the R1
    /// read-after-write confirm serves back the same id `send_event` returned.
    struct GatedRelay {
        acks: usize,
        crypto: Nip60Crypto,
        sends: Mutex<Vec<Event>>,
        // Fires when the FIRST send may proceed (the test controls when flush A leaves its publish).
        release_first: tokio::sync::Notify,
        // Signals that flush A has ENTERED its (blocked) first send — so the test can start flush B
        // only once A is provably parked mid-publish (holding its cloned live_ids).
        first_entered: tokio::sync::Notify,
        sends_started: AtomicU64,
    }

    impl GatedRelay {
        fn new(acks: usize, crypto: Nip60Crypto) -> Self {
            Self {
                acks,
                crypto,
                sends: Mutex::new(Vec::new()),
                release_first: tokio::sync::Notify::new(),
                first_entered: tokio::sync::Notify::new(),
                sends_started: AtomicU64::new(0),
            }
        }
        fn decoded_token_events(&self) -> Vec<(String, TokenEventContent)> {
            self.sends
                .lock()
                .unwrap()
                .iter()
                .filter(|ev| ev.kind == Kind::from(KIND_NIP60_TOKEN))
                .map(|ev| {
                    let content = self.crypto.decrypt(&ev.content).expect("decrypt a token event");
                    (ev.id.to_hex(), content)
                })
                .collect()
        }
    }

    #[async_trait]
    impl Nip60Transport for GatedRelay {
        async fn send_event(
            &self,
            kind: u16,
            content: String,
            tags: Vec<Tag>,
        ) -> anyhow::Result<SendOutcome> {
            let started = self.sends_started.fetch_add(1, AtomicOrdering::SeqCst);
            if started == 0 {
                // The FIRST send (flush A's rollover publish): announce entry, then park until the
                // test releases it — pinning A mid-publish while flush B is driven.
                self.first_entered.notify_one();
                self.release_first.notified().await;
            }
            // Sign ONCE; the real id is served back verbatim on fetch (R1 read-after-write id-match).
            let event = EventBuilder::new(Kind::from(kind), content)
                .tags(tags)
                .sign_with_keys(&self.crypto.signer_keys())
                .expect("sign the event");
            let event_id = event.id;
            self.sends.lock().unwrap().push(event);
            Ok(SendOutcome {
                event_id,
                acks: self.acks,
            })
        }

        async fn fetch_events(
            &self,
            _filter: Filter,
            _timeout: Duration,
        ) -> anyhow::Result<Vec<Event>> {
            // Serve stored TOKEN events back VERBATIM (like `InMemoryRelay`) so the R1
            // read-after-write confirm inside `rollover` retrieves the just-published event (same id)
            // and the flush commits. This does not perturb the serialization tooth (it reads
            // `decoded_token_events()` off `sends`).
            let events = self
                .sends
                .lock()
                .unwrap()
                .iter()
                .filter(|ev| ev.kind == Kind::from(KIND_NIP60_TOKEN))
                .cloned()
                .collect();
            Ok(events)
        }
    }

    // ---- Codex #2: two overlapping flushes NEVER leak a stale live event. ----------------------
    //
    // Without the flush_lock, a periodic + estate flush can BOTH consume-then-publish from the same
    // `live_ids` if a mutation re-dirties between them: each rollover del-chains the SAME prior set
    // (here the empty seed), so NEITHER new event supersedes the other → TWO live events (an orphan
    // that leaks + grows the relay set unbounded). With serialization, flush B waits for flush A to
    // COMMIT its new live id, so B del-chains THAT (a single chain), leaving EXACTLY one live event.
    //
    // The `GatedRelay` pins flush A inside its rollover publish (holding its cloned live_ids) while
    // flush B is driven — the deterministic form of the race. Without the lock, B reads the SAME
    // stale live_ids and publishes an ORPHAN; with the lock, B blocks on flush_lock until A commits.
    //
    // RED-on-revert: remove `let _flush_guard = self.flush_lock.lock().await;` from `flush()` and
    // this fails — `live_token_event_ids` returns 2 (the leaked orphan).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_flushes_do_not_leak_a_stale_live_event() {
        let crypto = test_crypto(0x55);
        let relay = Arc::new(GatedRelay::new(2, crypto.clone()));
        let store = Arc::new(Nip60Store::with_transport(crypto, relay.clone(), 3, 2, allow_m()));
        let wallet = empty_wallet().await;
        let (decorated, flusher) = Nip60BackedEcash::with_flusher(
            ecash_healthy(),
            wallet,
            store,
            "https://m".to_string(),
            "sat".to_string(),
            Vec::new(),
        );
        // Start clean, then a first mutation dirties the state (flush A's snapshot pending).
        flusher.force_clean();
        decorated.mint_send_token(10).await.expect("spend 1 ok");
        assert!(flusher.is_dirty(), "the first mutation dirtied the state");

        // Flush A: consumes dirty + clones live_ids (=[]), then PARKS inside its rollover publish
        // (the GatedRelay holds the first send). Spawned so the main task can proceed.
        let fa = flusher.clone();
        let a = tokio::spawn(async move { fa.flush().await });

        // Wait until A is provably parked mid-publish (holding its stale live_ids clone).
        relay.first_entered.notified().await;

        // A mutation re-dirties the state WHILE A is mid-publish — the exact window the fix guards.
        decorated.mint_send_token(20).await.expect("interleaved spend ok");
        assert!(flusher.is_dirty(), "the interleaved mutation re-dirtied the state");

        // Flush B: WITHOUT the lock it now consumes dirty + clones the SAME live_ids A is holding and
        // publishes an orphan; WITH the lock it blocks on flush_lock until A commits. Give it a beat
        // to reach that point, THEN release A.
        let fb = flusher.clone();
        let b = tokio::spawn(async move { fb.flush().await });
        // Let B run up to its (locked) wait or (unlocked) publish.
        tokio::task::yield_now().await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        // Release A's parked publish; both flushes now complete.
        relay.release_first.notify_one();
        a.await.expect("join A").expect("flush A publishes durably");
        b.await.expect("join B").expect("flush B publishes durably");

        // The invariant: the del-chain left EXACTLY ONE live (non-superseded) token event, and
        // `live_ids` points at the last published snapshot — no orphaned live event.
        let decoded = relay.decoded_token_events();
        let live = live_token_event_ids(&decoded);
        assert_eq!(
            live.len(),
            1,
            "serialized flushes leave EXACTLY one live snapshot chain (no orphaned live event); got live ids {live:?} across {} publishes",
            decoded.len()
        );
        let live_ids = flusher.live_ids();
        assert_eq!(live_ids.len(), 1, "live_ids tracks a single live event");
        assert_eq!(
            live_ids[0],
            live[0].to_string(),
            "live_ids points at the one event still live on the relay (the last published snapshot)"
        );
    }

    // ---- Codex #3: the AWAITED graceful estate flush publishes the final snapshot exactly once. -
    //
    // `ServeGuard::flush_estate()` is what the metered-run driver calls at graceful teardown (after
    // the run returns for die-when-broke / max_run, BEFORE the guard drops) so the last-interval
    // mutation is AWAITED to the relay, not raced against process exit. This exercises that seam
    // directly (a full VM boot is far too heavy for a unit test).
    //
    // RED-on-revert: make `flush_estate` a no-op (drop the `flusher.flush().await` call) and the
    // "published a snapshot" assert fails (the relay stays empty).
    #[tokio::test]
    async fn flush_estate_awaited_publishes_a_pending_dirty_snapshot() {
        let crypto = test_crypto(0x56);
        let relay = Arc::new(InMemoryRelay::new(2, crypto.clone()));
        let store = Arc::new(Nip60Store::with_transport(crypto, relay.clone(), 3, 2, allow_m()));
        let wallet = empty_wallet().await;
        let (decorated, flusher) = Nip60BackedEcash::with_flusher(
            ecash_healthy(),
            wallet,
            store,
            "https://m".to_string(),
            "sat".to_string(),
            Vec::new(),
        );
        flusher.force_clean();
        // A last-interval mutation the periodic flusher never got to (it dirties, nothing published).
        decorated.mint_send_token(5).await.expect("spend ok");
        assert!(flusher.is_dirty(), "the mutation left a pending dirty snapshot");
        assert_eq!(relay.token_publishes(), 0, "nothing published before the estate flush");

        // The graceful teardown seam: build the guard the driver holds and AWAIT its estate flush.
        let guard = crate::boot::ServeGuard::for_estate_test(flusher.clone());
        guard.flush_estate().await;

        assert_eq!(
            relay.token_publishes(),
            1,
            "the awaited estate flush published the final snapshot (revert flush_estate → 0)"
        );
        assert!(!flusher.is_dirty(), "the estate flush consumed the dirty flag");

        // NO DOUBLE PUBLISH: the drop-fired abrupt-death fallback is another `flush()`. Because the
        // estate flush consumed `dirty`, that fallback is a no-op — model it with a direct flush and
        // assert the publish count did not grow (the property the graceful call-site guarantees).
        flusher.flush().await.expect("the drop-fallback flush is Ok (no-op)");
        assert_eq!(
            relay.token_publishes(),
            1,
            "the drop-fired fallback no-ops after the awaited estate flush → EXACTLY one publish on the graceful path"
        );
    }

    // ---- T5 (Cut B, #115): the graceful estate flush re-publishes the CURRENT counter mirror. -----
    //
    // At graceful teardown `ServeGuard::flush_estate()` must, AFTER the proof flush, publish a
    // kind:17375 wallet-config carrying the counter decorator's current `keyset_counters()` — so the
    // relay's counter floor never lags the wallet's true derivation counter at death. This drives the
    // seam directly (a full VM boot is far too heavy for a unit test): a `ServeGuard` carrying ONLY
    // the counter-estate bundle, over the in-memory relay double.
    //
    // RED-on-revert: neuter the counter-publish arm in `flush_estate` (drop the
    // `store.publish_wallet_config(...)` call) → NO 17375 is published → `config_events` is empty →
    // the `Some(4096)` assert fails.
    #[tokio::test]
    async fn t5_flush_estate_republishes_the_current_counter_mirror() {
        let crypto = test_crypto(0x5b);
        let relay = Arc::new(InMemoryRelay::new(2, crypto.clone()));
        let store = Arc::new(Nip60Store::with_transport(
            crypto,
            relay.clone(),
            3,
            2,
            allow_m(),
        ));
        // A counter decorator whose mirror already holds a known high-water counter (as it would
        // after a run of increments). The wrapped inner store is irrelevant to the publish — the
        // publish reads the SHADOW via `keyset_counters()`.
        let k: Id = "009a1f293253e41e".parse().unwrap();
        let inner = cdk_sqlite::wallet::memory::empty().await.unwrap();
        let counter_db = Arc::new(Nip60CounterDb::with_counters(
            Arc::new(inner),
            HashMap::from([(k, 4096u32)]),
        ));

        assert_eq!(
            relay.decoded_config_events().len(),
            0,
            "nothing published before the estate flush"
        );

        // The graceful-teardown seam: a guard carrying only the counter estate, then AWAIT it.
        let guard = crate::boot::ServeGuard::for_counter_estate_test((
            store,
            counter_db,
            "https://m".to_string(),
        ));
        guard.flush_estate().await;

        let configs = relay.decoded_config_events();
        assert_eq!(
            configs.len(),
            1,
            "the awaited estate flush published exactly one kind:17375 counter mirror (revert the \
             counter-publish arm → 0)"
        );
        assert_eq!(
            configs[0].counters.get(&k.to_string()).copied(),
            Some(4096),
            "the published 17375 carries the CURRENT counter mirror (the decorator's high-water 4096)"
        );
        assert_eq!(
            configs[0].mints,
            vec!["https://m".to_string()],
            "the published config carries the wallet's mint"
        );
    }

    fn ecash_healthy() -> CountingEcash {
        CountingEcash::healthy()
    }

    // ============================================================================================
    // R1 (#40 reliability leg): write-durability made RETRIEVABLE + the multi-relay drill harness.
    //
    // `MultiRelayTransport` models N DISTINCT relays (unlike `InMemoryRelay`'s single scalar-ack
    // log): a per-relay event log + a per-relay UP flag, so a test can express "relay 0 has the
    // latest, the rest are down", "an outage drops a publish below k", and "acked-but-not-served"
    // (phantom-ack). It is the harness for the read-after-write tooth (c) and the outage drill (d),
    // and for R2's read-quorum drills.
    // ============================================================================================

    /// A [`Nip60Transport`] over N DISTINCT relays, each with its own event log + an UP flag.
    ///
    /// - `send_event` SIGNS the event once (so its id is the REAL NIP-01 id — exactly what the
    ///   production [`ClientTransport`] returns as `output.val`), STORES that signed event on every
    ///   UP relay, and returns `acks` = the count of UP relays it landed on (a DOWN relay neither
    ///   acks nor stores). Storing the signed event (not just the ciphertext) is what lets the R1
    ///   read-after-write confirm work: the id `send_event` returns is the id `fetch_events` serves
    ///   back, matching production — unlike a double that re-signs on fetch and mints a fresh id.
    /// - `fetch_events` UNIONS the signed events stored across all UP relays, DEDUPS by event id
    ///   (mimicking the SDK pool union of overlapping relays), and filters to the filter's kinds. A
    ///   DOWN relay contributes nothing to the union.
    /// - PHANTOM-ACK mode (`set_phantom_ack(true)`): `send_event` returns `acks = n_relays` (as if
    ///   every relay acked) but STORES NOTHING — the "acked but not served/persisted" failure the
    ///   read-after-write confirm exists to catch.
    struct MultiRelayTransport {
        crypto: Nip60Crypto,
        /// One event log per relay: the fully-signed events stored, in send order.
        relays: Vec<Mutex<Vec<Event>>>,
        /// Per-relay outage flag (true = up = acks + stores).
        up: Vec<AtomicBool>,
        /// When set, `send_event` reports a full-quorum ack but stores nothing (acked-but-not-served).
        phantom_ack: AtomicBool,
        /// Every send's KIND, recorded at send time BEFORE the phantom/up branching — so a tooth can
        /// assert on what was ATTEMPTED (e.g. "no NIP-09 delete was attempted") independent of whether
        /// phantom-ack or an outage suppressed the actual storage.
        attempts: Mutex<Vec<u16>>,
    }

    impl MultiRelayTransport {
        fn new(n_relays: usize, crypto: Nip60Crypto) -> Self {
            let mut relays = Vec::with_capacity(n_relays);
            let mut up = Vec::with_capacity(n_relays);
            for _ in 0..n_relays {
                relays.push(Mutex::new(Vec::new()));
                up.push(AtomicBool::new(true));
            }
            Self {
                crypto,
                relays,
                up,
                phantom_ack: AtomicBool::new(false),
                attempts: Mutex::new(Vec::new()),
            }
        }

        /// Bring relay `idx` up (`true`) or down (`false`). A down relay neither acks nor serves.
        fn set_up(&self, idx: usize, up: bool) {
            self.up[idx].store(up, AtomicOrdering::SeqCst);
        }

        /// Toggle acked-but-not-served: sends report a full-quorum ack but store nothing.
        fn set_phantom_ack(&self, on: bool) {
            self.phantom_ack.store(on, AtomicOrdering::SeqCst);
        }

        /// The number of UP relays (the ack count a normal send reaches).
        fn up_count(&self) -> usize {
            self.up.iter().filter(|u| u.load(AtomicOrdering::SeqCst)).count()
        }

        /// Total kind:7375 token events currently stored across ALL relays (up or down), deduped by
        /// id — lets a tooth assert the OLD backup is still on the relays after a retained rollover.
        fn distinct_token_ids(&self) -> std::collections::HashSet<EventId> {
            let mut set = std::collections::HashSet::new();
            for log in &self.relays {
                for ev in log.lock().unwrap().iter() {
                    if ev.kind == Kind::from(KIND_NIP60_TOKEN) {
                        set.insert(ev.id);
                    }
                }
            }
            set
        }

        /// Whether a kind:5 NIP-09 delete was ever ATTEMPTED (recorded at send time, independent of
        /// per-relay up/down or phantom-ack — both of which suppress the actual STORAGE, so scanning
        /// stored events would falsely report "no delete"). The retain tooth's "no delete" assertion
        /// must catch an ATTEMPTED prune: the rollover must not even attempt `delete_events` when the
        /// new event is not durable+retrievable.
        fn any_delete_sent(&self) -> bool {
            self.attempts.lock().unwrap().contains(&KIND_NIP09_DELETE)
        }
    }

    #[async_trait]
    impl Nip60Transport for MultiRelayTransport {
        async fn send_event(
            &self,
            kind: u16,
            content: String,
            tags: Vec<Tag>,
        ) -> anyhow::Result<SendOutcome> {
            // Record the send ATTEMPT (every kind) BEFORE the phantom/up branching, so a tooth can
            // assert "no NIP-09 delete was attempted" even under phantom-ack (which stores nothing).
            self.attempts.lock().unwrap().push(kind);
            // Sign the event ONCE — its id is the real NIP-01 id (what `ClientTransport` returns and
            // what a real fetch serves back), so the R1 read-after-write id-match holds as in prod.
            let event = EventBuilder::new(Kind::from(kind), content)
                .tags(tags)
                .sign_with_keys(&self.crypto.signer_keys())
                .expect("sign the event");
            let event_id = event.id;

            // PHANTOM-ACK: report a full-quorum ack but persist NOTHING (acked-but-not-served).
            if self.phantom_ack.load(AtomicOrdering::SeqCst) {
                return Ok(SendOutcome {
                    event_id,
                    acks: self.relays.len(),
                });
            }

            // Normal path: store the signed event on every UP relay; ack = the number that stored it.
            let mut acks = 0usize;
            for (log, up) in self.relays.iter().zip(self.up.iter()) {
                if up.load(AtomicOrdering::SeqCst) {
                    log.lock().unwrap().push(event.clone());
                    acks += 1;
                }
            }
            Ok(SendOutcome { event_id, acks })
        }

        async fn fetch_events(&self, filter: Filter, _timeout: Duration) -> anyhow::Result<Vec<Event>> {
            // UNION across UP relays, dedup by event id (the SDK pool union of overlapping relays);
            // a DOWN relay contributes nothing. Honor the filter's kinds when set (so a token fetch
            // does not pull config events and vice-versa); an unset kinds replays everything.
            let mut seen: std::collections::HashSet<EventId> = std::collections::HashSet::new();
            let mut events = Vec::new();
            for (log, up) in self.relays.iter().zip(self.up.iter()) {
                if !up.load(AtomicOrdering::SeqCst) {
                    continue;
                }
                for ev in log.lock().unwrap().iter() {
                    if let Some(kinds) = &filter.kinds {
                        if !kinds.contains(&ev.kind) {
                            continue;
                        }
                    }
                    // Honor the author filter too (production fetches by author via `.author(pk)`), so
                    // the double cannot mask a foreign-author pollution bug in a reconcile drill.
                    if let Some(authors) = &filter.authors {
                        if !authors.contains(&ev.pubkey) {
                            continue;
                        }
                    }
                    if seen.insert(ev.id) {
                        events.push(ev.clone());
                    }
                }
            }
            Ok(events)
        }

        /// R2: per-relay read — counts DISTINCT served relays (UP flag) and unions their events.
        /// An UP relay counts as served even if its log is empty (it answered within timeout).
        /// A DOWN relay is not served (mirrors the prod precheck on a half-open socket).
        async fn fetch_events_per_relay(
            &self,
            filter: Filter,
            timeout: Duration,
        ) -> anyhow::Result<PerRelayRead> {
            let total = self.relays.len();
            let mut served = 0usize;
            let mut seen: std::collections::HashSet<EventId> = std::collections::HashSet::new();
            let mut events = Vec::new();
            for (log, up) in self.relays.iter().zip(self.up.iter()) {
                if !up.load(AtomicOrdering::SeqCst) {
                    continue; // down = not served
                }
                served += 1; // an UP relay counts as served (even if its log is empty)
                for ev in log.lock().unwrap().iter() {
                    // Apply the SAME kind + author filters as `fetch_events`.
                    if let Some(kinds) = &filter.kinds {
                        if !kinds.contains(&ev.kind) {
                            continue;
                        }
                    }
                    if let Some(authors) = &filter.authors {
                        if !authors.contains(&ev.pubkey) {
                            continue;
                        }
                    }
                    if seen.insert(ev.id) {
                        events.push(ev.clone());
                    }
                }
            }
            let _ = timeout; // no actual I/O in the double; the UP flag models reachability
            Ok(PerRelayRead { served, total, events })
        }
    }

    // ---- Tooth (c): READ-AFTER-WRITE in rollover — an acked-but-not-served new event is caught. --
    //
    // In PHANTOM-ACK mode the transport reports acks >= k (so the >=k publish gate PASSES) but stores
    // the new event NOWHERE, so a follow-up fetch cannot retrieve it. `rollover` must then treat the
    // new backup as NOT-yet-durable: it must NOT delete the superseded events (the old backup stays
    // intact) and it must take the retain/retry path. First we seed a real prior backup (phantom OFF),
    // then flip phantom ON and roll it over.
    //
    // RED-on-revert: remove the read-after-write confirm block in `rollover` (go straight to
    // delete_events after publish_token) and this fails — the superseded delete IS sent even though
    // the new event is not retrievable, and `rollover` returns Ok, so the only backup on the relays
    // is an event no relay actually serves (backup silently LOST).
    #[tokio::test]
    async fn rollover_retains_the_old_backup_when_the_new_event_is_acked_but_not_served() {
        let crypto = test_crypto(0x60);
        let transport = Arc::new(MultiRelayTransport::new(3, crypto.clone()));
        // n=3, k=2. Phantom OFF: publish a REAL first snapshot (lands on all 3 up relays, acks=3>=k).
        let store = Nip60Store::with_transport(crypto, transport.clone(), 3, 2, allow_m());
        let first_id = store
            .rollover("https://m", "sat", vec![dummy_proof("s1")], Vec::new())
            .await
            .expect("the first (real) snapshot publishes durably");
        assert_eq!(
            transport.distinct_token_ids().len(),
            1,
            "the first snapshot is stored on the relays"
        );
        assert!(!transport.any_delete_sent(), "no delete on the first snapshot (no superseded input)");

        // Now the new event is ACKED-BUT-NOT-SERVED: the publish reports full quorum, but the event
        // is stored NOWHERE, so the read-after-write confirm cannot retrieve it.
        transport.set_phantom_ack(true);
        let superseded = vec![first_id.to_hex()];
        let result = store
            .rollover("https://m", "sat", vec![dummy_proof("s2")], superseded.clone())
            .await;

        // The RAW confirm caught it: the rollover did NOT commit the delete, so the old backup is
        // retained. The flusher tolerates the returned Err by re-arming dirty (retry next tick).
        assert!(
            result.is_err(),
            "an acked-but-not-served new event must NOT be treated as a committed rollover — the \
             read-after-write confirm fails, leaving the old backup intact for a retry"
        );
        assert!(
            !transport.any_delete_sent(),
            "MONEY-SAFETY: the superseded events are NOT deleted when the new event is not \
             retrievable — the old backup stays live (revert the RAW confirm and a delete IS sent)"
        );
        // The old snapshot is STILL the only real backup on the relays (phantom stored nothing new).
        assert!(
            transport.distinct_token_ids().contains(&first_id),
            "the prior snapshot event is still stored on the relays (never pruned)"
        );

        // Recovery: turn phantom OFF and roll over again → the new event is really served → the RAW
        // confirm passes, the rollover commits, and a reconcile sees the new snapshot's proof.
        transport.set_phantom_ack(false);
        store
            .rollover("https://m", "sat", vec![dummy_proof("s2")], superseded)
            .await
            .expect("with the event really served, the rollover commits");
        let restored = store.reconcile_on_load().await.expect("reconcile after recovery");
        assert!(
            !restored.is_empty(),
            "once the new event is actually served, the backup converges (reconcile is non-empty)"
        );
    }

    // ---- Tooth (d): DRILL — estate-flush RACED a relay outage. ----------------------------------
    //
    // Enough relays DOWN that a publish reaches < k. `rollover` must HARD-ERROR on the existing >=k
    // gate, delete NOTHING (the existing backup is never corrupted), and lose nothing. Then the
    // outage clears (relays back UP) and a re-publish reaches >=k and succeeds; a subsequent
    // reconcile sees the event (the backup converges once the outage clears).
    //
    // RED-on-revert: this leans on the SAME >=k ensure the `publish_token` tooth already guards
    // (removing it makes the sub-quorum publish silently "succeed"); here the drill additionally
    // proves the OLD backup is not corrupted by the failed publish and that recovery converges.
    #[tokio::test]
    async fn drill_estate_flush_raced_a_relay_outage_never_corrupts_the_backup() {
        let crypto = test_crypto(0x61);
        let transport = Arc::new(MultiRelayTransport::new(3, crypto.clone()));
        // n=3, k=2. Seed a real prior backup while all relays are UP (acks=3 >= k).
        let store = Nip60Store::with_transport(crypto, transport.clone(), 3, 2, allow_m());
        let first_id = store
            .rollover("https://m", "sat", vec![dummy_proof("s1")], Vec::new())
            .await
            .expect("the prior backup lands durably before the outage");
        let before = transport.distinct_token_ids();
        assert!(before.contains(&first_id), "the prior backup is on the relays before the outage");

        // OUTAGE: two of three relays go down → only 1 up → a publish reaches acks=1 < k=2.
        transport.set_up(1, false);
        transport.set_up(2, false);
        assert_eq!(transport.up_count(), 1, "the outage leaves a sub-quorum relay set");
        let superseded = vec![first_id.to_hex()];
        let outage = store
            .rollover("https://m", "sat", vec![dummy_proof("s2")], superseded.clone())
            .await;
        assert!(
            outage.is_err(),
            "a below-k publish HARD-ERRORS (the >=k durability gate) — the new event is not durable"
        );
        assert!(
            !transport.any_delete_sent(),
            "the failed rollover deleted NOTHING — the existing backup is not corrupted"
        );
        assert!(
            transport.distinct_token_ids().contains(&first_id),
            "the prior backup is still intact after the failed sub-quorum publish"
        );

        // RECOVERY: the outage clears (relays back up) → a re-publish reaches >=k → succeeds, and a
        // reconcile sees the new snapshot's proof (the backup converges).
        transport.set_up(1, true);
        transport.set_up(2, true);
        assert_eq!(transport.up_count(), 3, "the outage cleared");
        store
            .rollover("https://m", "sat", vec![dummy_proof("s2")], superseded)
            .await
            .expect("once the outage clears the re-publish reaches >=k and succeeds");
        let restored = store.reconcile_on_load().await.expect("reconcile after recovery");
        // CONVERGENCE (stronger than !is_empty): reconcile recovers EXACTLY the committed snapshot —
        // one proof. The sub-quorum publish during the outage partially stored an ORPHAN token event
        // on the one up relay; it is never superseded (the failed rollover returned Err before
        // recording its id, so the flusher's live_ids never advanced to it). Its proof is IDENTICAL to
        // the committed retry's, so reconcile's proof-level dedup collapses them → len 1. A DIVERGENT
        // orphan would be over-included, then filtered by the mint (NUT-07) on import — never a
        // double-spend or phantom. Event-level orphan cleanup (del-chaining partial-publish ids) is
        // deferred to #127 (relay hygiene; needs flusher plumbing = rail.rs, out of R1 scope).
        assert_eq!(
            restored.len(),
            1,
            "after the outage clears, reconcile converges to EXACTLY the committed snapshot proof — \
             the sub-quorum partial-publish orphan's identical proof deduped away (no phantom/extra \
             proof); !is_empty alone would not prove convergence (see #127)"
        );
    }

    /// The compact local fakewallet mint fixture for tooth 2 (real unspent proofs need a live mint).
    /// Mirrors the `tests/full_loop.rs` fixture, trimmed to the fakewallet+sqlite features the daemon
    /// build already carries; cdk-mintd is a dev-dependency, so this is test-only.
    mod mint_fixture {
        use std::sync::Arc;
        use std::time::Duration;

        use cdk::nuts::CurrencyUnit;
        use tokio::sync::Notify;

        pub struct FakeMint {
            port: u16,
            shutdown: Arc<Notify>,
            handle: tokio::task::JoinHandle<()>,
            _work_dir: TempDir,
        }

        impl FakeMint {
            pub async fn start(port: u16) -> anyhow::Result<Self> {
                let work_dir = TempDir::new(&format!("kirby-nip60-mint-{port}"));
                let settings = fake_wallet_settings(port);
                let shutdown = Arc::new(Notify::new());

                let work_dir_path = work_dir.path().to_path_buf();
                let shutdown_for_task = shutdown.clone();
                let handle = tokio::spawn(async move {
                    let shutdown_future = async move {
                        shutdown_for_task.notified().await;
                    };
                    if let Err(e) = cdk_mintd::run_mintd_with_shutdown(
                        &work_dir_path,
                        &settings,
                        shutdown_future,
                        None,
                        None,
                        vec![],
                    )
                    .await
                    {
                        eprintln!("local fakewallet mint exited with error: {e}");
                    }
                });

                wait_ready(port, Duration::from_secs(30)).await?;
                Ok(FakeMint {
                    port,
                    shutdown,
                    handle,
                    _work_dir: work_dir,
                })
            }

            pub fn url(&self) -> String {
                format!("http://127.0.0.1:{}", self.port)
            }

            pub async fn shutdown(self) {
                self.shutdown.notify_waiters();
                let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
            }
        }

        async fn wait_ready(port: u16, timeout: Duration) -> anyhow::Result<()> {
            let url = format!("http://127.0.0.1:{port}");
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                if let Ok(wallet) = crate::mint_rig::build_wallet(&url).await {
                    if wallet.fetch_mint_info().await.is_ok() {
                        return Ok(());
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("local fakewallet mint on port {port} did not become ready in time");
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }

        fn fake_wallet_settings(port: u16) -> cdk_mintd::config::Settings {
            let info = cdk_mintd::config::Info {
                url: format!("http://127.0.0.1:{port}"),
                listen_host: "127.0.0.1".to_string(),
                listen_port: port,
                seed: None,
                // A throwaway fixture mnemonic (local fakewallet, tests only; no real funds).
                mnemonic: Some(
                    "eye survey guilt napkin crystal cup whisper salt luggage manage unveil loyal"
                        .to_string(),
                ),
                signatory_url: None,
                signatory_certs: None,
                input_fee_ppk: None,
                use_keyset_v2: None,
                http_cache: Default::default(),
                logging: Default::default(),
                enable_info_page: None,
                quote_ttl: None,
            };

            let fake_wallet = cdk_mintd::config::FakeWallet {
                supported_units: vec![CurrencyUnit::Sat],
                fee_percent: 0.0,
                reserve_fee_min: 1.into(),
                ..Default::default()
            };

            cdk_mintd::config::Settings {
                info,
                // cdk 0.17.x takes a Vec<Ln>; boot a single fakewallet backend.
                ln: vec![cdk_mintd::config::Ln {
                    ln_backend: cdk_mintd::config::LnBackend::FakeWallet,
                    ..Default::default()
                }],
                fake_wallet: Some(fake_wallet),
                ..Default::default()
            }
        }

        pub struct TempDir {
            path: std::path::PathBuf,
        }
        impl TempDir {
            pub fn new(prefix: &str) -> Self {
                let path = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
                std::fs::create_dir_all(&path).expect("create temp dir");
                TempDir { path }
            }
            pub fn path(&self) -> &std::path::Path {
                &self.path
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    // ============================================================================================
    // R2 (#131 reliability leg): read-quorum safety — solvency gate, rollover gate, per-relay
    // union, split-brain dedup.
    //
    // These teeth use `MultiRelayTransport` (N=3, k=2, read_k=2) or `with_transport_and_read_k`.
    // ============================================================================================

    // ---- D1 (condition a): solvency_gate(false) = ProceedNonAuthoritative ---------
    //
    // A below-quorum reconcile must NOT be treated as insolvent — wallet is a lower bound only.
    // RED-on-revert: change `solvency_gate` to always return `Assert`; the test below calls
    // `assert_wallet_backs_counter` which would bail on wallet < counter.
    #[test]
    fn r2_d1_solvency_gate_below_quorum_proceeds_non_authoritative() {
        use crate::boot::{SolvencyGate, solvency_gate};
        // Authoritative read → Assert (unchanged path).
        assert!(matches!(solvency_gate(true), SolvencyGate::Assert));
        // Below-quorum read → ProceedNonAuthoritative (never brick a funded agent).
        assert!(matches!(solvency_gate(false), SolvencyGate::ProceedNonAuthoritative));
        // ProceedNonAuthoritative means we DO NOT call assert_wallet_backs_counter.
        // Verify: a below-quorum read with wallet < counter does NOT bail.
        match solvency_gate(false) {
            SolvencyGate::Assert => {
                // We'd call assert_wallet_backs_counter here — but this branch should not be reached.
                crate::boot::assert_wallet_backs_counter(0, 100)
                    .expect_err("a zero wallet should fail the assert");
                panic!("D1 FAILED: a below-quorum read chose Assert, it should be Proceed");
            }
            SolvencyGate::ProceedNonAuthoritative => {
                // Correct: we proceed even though wallet(0) < counter(100).
            }
        }
    }

    // ---- D_b (condition b): below-quorum boot → rollover sends NO delete AND no publish --------
    //
    // A below-quorum boot leaves `read_established=false`. `rollover` must bail BEFORE
    // `publish_token` (so no NIP-09 delete attempt and no kind:7375 publish).
    // RED-on-revert: remove the §4 gate → the rollover proceeds → `any_delete_sent()` is true.
    // Recovery: set_up all relays → reconcile_on_load_with_ids → read_established=true → next
    // rollover DOES publish+prune.
    #[tokio::test]
    async fn r2_db_below_quorum_boot_rollover_sends_nothing_and_is_retried_on_recovery() {
        let crypto = test_crypto(0x62);
        // n=3, k=2, read_k=2 — a quorum relay set.
        // Seed a REAL prior snapshot while all 3 relays are UP (authoritative read).
        let transport = Arc::new(MultiRelayTransport::new(3, crypto.clone()));
        let store_setup = Nip60Store::with_transport(crypto.clone(), transport.clone(), 3, 2, allow_m());
        let first_id = store_setup
            .rollover("https://m", "sat", vec![dummy_proof("init")], Vec::new())
            .await
            .expect("seed a real prior snapshot (all relays UP)");
        assert_eq!(transport.distinct_token_ids().len(), 1);
        assert!(!transport.any_delete_sent(), "no delete on the initial snapshot");

        // Now simulate a BELOW-QUORUM boot: bring 2 relays DOWN so only 1 UP.
        // The new store uses `with_transport_and_read_k` (read_established=false).
        transport.set_up(1, false);
        transport.set_up(2, false);
        assert_eq!(transport.up_count(), 1);
        let store_low = Nip60Store::with_transport_and_read_k(
            crypto.clone(),
            transport.clone(),
            3,
            2,
            2, // read_k=2; served will be 1 (only relay 0 UP) → NOT authoritative
            allow_m(),
        );
        // Reconcile under the below-quorum boot → served=1 < read_k=2 → NOT authoritative.
        let read = store_low
            .reconcile_on_load_with_ids()
            .await
            .expect("reconcile ok even below-quorum");
        assert_eq!(read.served, 1, "only 1 relay is UP");
        assert_eq!(read.total, 3);
        assert!(!read.authoritative, "below-quorum → NOT authoritative");
        // read_established should be false now.
        assert!(
            !store_low.read_established.load(std::sync::atomic::Ordering::SeqCst),
            "read_established is false after a below-quorum reconcile"
        );

        // Attempt a rollover — must bail WITHOUT publishing or deleting.
        let attempt_attempts_before = transport.attempts.lock().unwrap().len();
        let result = store_low
            .rollover("https://m", "sat", vec![dummy_proof("new")], vec![first_id.to_hex()])
            .await;
        assert!(result.is_err(), "rollover must bail when read not established");
        assert!(
            result.unwrap_err().to_string().contains("read not established"),
            "error message mentions 'read not established'"
        );
        // No new sends — not even a publish attempt (gate fires before publish_token).
        let attempt_count_after = transport.attempts.lock().unwrap().len();
        assert_eq!(
            attempt_count_after,
            attempt_attempts_before,
            "D_b: zero sends attempted (gate fires before publish_token)"
        );
        assert!(!transport.any_delete_sent(), "D_b: no NIP-09 delete attempted");
        // The old backup is still on the relays (not corrupted).
        assert!(
            transport.distinct_token_ids().contains(&first_id),
            "D_b: the prior snapshot is still intact after the gated rollover"
        );

        // RECOVERY: bring the downed relays back UP.
        transport.set_up(1, true);
        transport.set_up(2, true);
        assert_eq!(transport.up_count(), 3);
        // Re-reconcile → served=3 >= read_k=2 → authoritative → read_established=true.
        let read2 = store_low
            .reconcile_on_load_with_ids()
            .await
            .expect("reconcile ok after recovery");
        assert!(read2.authoritative, "recovery: served=3 >= read_k=2 → authoritative");
        assert!(
            store_low.read_established.load(std::sync::atomic::Ordering::SeqCst),
            "read_established is now true after a quorum reconcile"
        );
        // Now the rollover DOES publish+prune.
        store_low
            .rollover("https://m", "sat", vec![dummy_proof("new")], vec![first_id.to_hex()])
            .await
            .expect("rollover succeeds after read_established=true");
        assert!(
            transport.any_delete_sent(),
            "D_b recovery: after read_established=true, rollover deletes the superseded event"
        );
    }

    // ---- D2 (partial-set union): the per-relay union includes events from all UP relays ----------
    //
    // relay 0 has the LATEST token event (two proofs), relays 1+2 only have the older event (one
    // proof). `fetch_events_per_relay` with all UP must return a union containing the latest event's
    // proofs. Pulling only the first relay's events and ignoring 1+2 when relay 0 is DOWN would
    // miss the latest → wrong candidate count.
    //
    // RED-on-revert: override `fetch_events_per_relay` to always return only the first relay's
    // events → when relay 0 is the only one with the new event and 0+1+2 are all UP, a single-relay
    // read would miss the relay-0-only new event → candidates under-count.
    // (The positive assertion below captures this: the 3-relay union must include the proof only
    // on relay 0 by counting total candidates > relays-1+2-only candidates.)
    #[tokio::test]
    async fn r2_d2_per_relay_union_includes_events_from_all_up_relays() {
        let crypto = test_crypto(0x63);
        let transport = Arc::new(MultiRelayTransport::new(3, crypto.clone()));
        // n=3, k=2, read_k=2. Start with all relays UP + read_established=true.
        let store = Nip60Store::with_transport_and_read_k(
            crypto.clone(),
            transport.clone(),
            3,
            2,
            2,
            allow_m(),
        );
        store.read_established.store(true, std::sync::atomic::Ordering::SeqCst);

        // Phase 1: publish OLD snapshot (one proof) → lands on all 3 relays.
        let old_id = store
            .rollover("https://m", "sat", vec![dummy_proof("old")], Vec::new())
            .await
            .expect("old snapshot to all 3 relays");
        assert_eq!(transport.up_count(), 3);

        // Phase 2: publish a DIVERGENT new event to a NON-FIRST relay (relay 2) ONLY.
        // Bring relays 0+1 DOWN so only relay 2 stores it — this proves the union reads
        // BEYOND relay[0]: a first-relay-only impl would miss this event by id.
        transport.set_up(0, false);
        transport.set_up(1, false);
        let new_content = TokenEventContent {
            mint: "https://m".to_string(),
            unit: "sat".to_string(),
            proofs: vec![dummy_proof("new1"), dummy_proof("new2")],
            del: vec![old_id.to_hex()],
        };
        // acks=1 < k=2 → publish_token errors on the >=k gate but STILL stores on the one UP relay (2).
        let _ = store.publish_token(&new_content).await;
        // Capture the divergent event's id from relay 2's log (the token event that is NOT the old one).
        let new_id = {
            let log = transport.relays[2].lock().unwrap();
            log.iter()
                .find(|ev| ev.kind == Kind::from(KIND_NIP60_TOKEN) && ev.id != old_id)
                .expect("relay 2 stored the divergent new token event")
                .id
        };
        assert_ne!(new_id, old_id, "the divergent event is distinct from the old snapshot");
        // The divergent event lives ONLY on relay 2 (absent from the first relays).
        assert!(
            !transport.relays[0]
                .lock()
                .unwrap()
                .iter()
                .any(|ev| ev.id == new_id),
            "divergent event must be absent from relay 0"
        );
        assert!(
            !transport.relays[1]
                .lock()
                .unwrap()
                .iter()
                .any(|ev| ev.id == new_id),
            "divergent event must be absent from relay 1"
        );

        // Phase 3: bring all relays UP → the 3-relay union MUST include the relay-2-only event
        // BY ID MEMBERSHIP (not a count). This is what proves the per-relay read genuinely unions
        // across a NON-FIRST relay, and it stays RED if the impl drops non-first relays' events.
        transport.set_up(0, true);
        transport.set_up(1, true);
        let read_all = store
            .reconcile_on_load_with_ids()
            .await
            .expect("reconcile with all 3 UP");
        assert_eq!(read_all.served, 3, "all 3 UP → served=3");
        assert!(
            read_all.fetched_ids.contains(&new_id.to_hex()),
            "D2: the 3-relay union MUST include the relay-2-only divergent event by id; \
             fetched_ids={:?} missing {}",
            read_all.fetched_ids,
            new_id.to_hex()
        );

        // Partial-set: with relay 2 DOWN, the union must NOT contain the divergent event by id
        // (it lived only there) — the id-membership negative complements the positive above.
        transport.set_up(2, false);
        let read_01 = store
            .reconcile_on_load_with_ids()
            .await
            .expect("reconcile with relays 0+1 only");
        assert_eq!(read_01.served, 2, "relays 0+1 UP → served=2");
        assert!(
            !read_01.fetched_ids.contains(&new_id.to_hex()),
            "D2: the partial-set (0+1) union must NOT contain the relay-2-only event by id; \
             fetched_ids={:?} unexpectedly has {}",
            read_01.fetched_ids,
            new_id.to_hex()
        );
        transport.set_up(2, true);
    }

    // ---- D4 (split-brain): keep_unspent drops a proof the mint calls spent; no double-count ----
    //
    // This exercises the `nip60_reconcile::keep_unspent` / `check_states` path via the existing
    // `reconcile_import` machinery (unit-tested in nip60_reconcile). We test the integration:
    // two reconcile runs restore the same candidate set; a mint mock that marks one spent →
    // only the unspent one imports; second run is novel-only no-op (no double-count).
    //
    // RED-on-revert: change `keep_unspent` to accept all proofs regardless of state → both
    // proofs would be imported → double-count.
    #[tokio::test]
    async fn r2_d4_split_brain_keep_unspent_prevents_double_count() {
        use crate::nip60_reconcile::{ReconcileWallet, reconcile_import};
        use cdk::nuts::{Proof, ProofState, PublicKey, State};
        use std::sync::Mutex;

        fn dummy_proof_r2(secret: &str) -> Proof {
            let json = format!(
                r#"{{"amount":1,"id":"00ad268c4d1f5826","secret":"{secret}","C":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}}"#
            );
            serde_json::from_str(&json).expect("dummy proof")
        }

        fn y_of_r2(p: &Proof) -> PublicKey { p.y().expect("proof Y") }

        struct SplitBrainWallet {
            known: Mutex<Vec<PublicKey>>,
            states: Vec<ProofState>,
            imported: Mutex<Vec<Proof>>,
        }

        #[async_trait]
        impl ReconcileWallet for SplitBrainWallet {
            async fn known_ys(&self) -> anyhow::Result<Vec<PublicKey>> {
                Ok(self.known.lock().unwrap().clone())
            }
            async fn check_states(&self, _proofs: Vec<Proof>) -> anyhow::Result<Vec<ProofState>> {
                Ok(self.states.clone())
            }
            async fn import_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<u64> {
                let n = proofs.len() as u64;
                // Track imported Ys as "known" for the second run (novel-only gate).
                for p in &proofs {
                    if let Ok(y) = p.y() {
                        self.known.lock().unwrap().push(y);
                    }
                }
                self.imported.lock().unwrap().extend(proofs);
                Ok(n)
            }
        }

        let p_unspent = dummy_proof_r2("unspent");
        let p_spent = dummy_proof_r2("spent");
        let y_unspent = y_of_r2(&p_unspent);
        let y_spent = y_of_r2(&p_spent);

        let wallet = SplitBrainWallet {
            known: Mutex::new(vec![]),
            states: vec![
                ProofState::from((y_unspent, State::Unspent)),
                ProofState::from((y_spent, State::Spent)),
            ],
            imported: Mutex::new(vec![]),
        };

        // First restore: both proofs are candidates; mint marks one spent.
        let candidates = vec![p_unspent.clone(), p_spent.clone()];
        let imported1 = reconcile_import(candidates.clone(), &wallet)
            .await
            .expect("first restore ok");
        assert_eq!(imported1, 1, "D4: only the UNSPENT proof imports (not the spent one)");
        let got1 = wallet.imported.lock().unwrap().clone();
        assert_eq!(got1.len(), 1);
        assert_eq!(y_of_r2(&got1[0]), y_unspent, "D4: the imported proof is the unspent one");

        // Second restore (split-brain scenario: same candidates offered again).
        // Novel-only gate: the unspent proof is now KNOWN → neither candidate is novel → no import.
        let imported2 = reconcile_import(candidates, &wallet)
            .await
            .expect("second restore ok");
        assert_eq!(imported2, 0, "D4: the second restore is a no-op (novel-only gate prevents double-count)");
        let got2 = wallet.imported.lock().unwrap().clone();
        assert_eq!(got2.len(), 1, "D4: still only one proof imported total (no double-count)");
    }
}
