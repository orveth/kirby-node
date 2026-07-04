//! NIP-60 counter-mirror wallet-database decorator.
//!
//! The NUT-13 deterministic-secret counter is the one spend-critical piece of wallet
//! state a fresh `cdk` [`cdk::wallet::Wallet`] cannot recover from the mint alone:
//! proofs can be restored from the seed via NUT-09, but if the per-keyset counter is
//! behind, the wallet re-derives blinding secrets it has already spent — colliding
//! with used outputs (money loss) or reusing them (privacy loss + mint rejection). To
//! survive a cross-machine reconstruct we carry the counter out of band, in the agent's
//! NIP-60 wallet-config event (kind 17375), alongside the token proofs.
//!
//! [`Nip60CounterDb`] is a thin decorator over the concrete wallet store. Every method
//! is a verbatim pass-through EXCEPT [`WalletDatabase::increment_keyset_counter`], which
//! additionally mirrors the returned (post-increment) value into an in-memory shadow
//! map. [`Nip60CounterDb::keyset_counters`] snapshots that map so the publisher can fold
//! the counters into the 17375 event when it publishes the proofs.
//!
//! Scope: this layer only OBSERVES and EXPOSES the counter. Priming a reconstructed
//! store's counter up to the relay value (the fast-forward) and the publish itself are
//! the reconcile / publish steps that sit above this decorator.
//!
//! Invariants:
//!   - the mirror is monotonic (`max`) — a published counter never regresses, even if
//!     seeded with a reconstruct floor above the freshly-opened inner store;
//!   - the decorator never blocks a spend — inner errors pass through unchanged and a
//!     poisoned shadow lock is recovered rather than propagated;
//!   - cdk always reads its counter from the inner store; the shadow is a write-through
//!     observation only, never read back into the wallet.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::bip32::DerivationPath;
use cdk::cdk_database::{Error, WalletDatabase};
use cdk::mint_url::MintUrl;
use cdk::nuts::{
    CurrencyUnit, Id, KeySet, KeySetInfo, Keys, MintInfo, PublicKey, SpendingConditions, State,
};
use cdk::wallet::types::{
    MeltQuote, MintQuote as WalletMintQuote, P2PKSigningKey, ProofInfo, Transaction,
    TransactionDirection, TransactionId, WalletSaga,
};
use uuid::Uuid;

/// The wrapped concrete wallet store (e.g. the cdk-sqlite localstore).
type InnerStore = Arc<dyn WalletDatabase<Error> + Send + Sync>;

/// A [`WalletDatabase`] decorator that mirrors the NUT-13 keyset counter for NIP-60
/// cross-machine money continuity. See the module docs for why the counter must travel.
#[derive(Debug)]
pub struct Nip60CounterDb {
    inner: InnerStore,
    /// Highest counter value observed per keyset this session, seeded optionally with a
    /// reconstruct floor. Snapshotted by [`Self::keyset_counters`] for the publisher.
    shadow: Mutex<HashMap<Id, u32>>,
    /// The config-plane cut's ONE-SHOT BOOT-TIME establishment latch (§2.2). When `false`, the
    /// choke-point gate on [`WalletDatabase::increment_keyset_counter`] REFUSES every NUT-13
    /// derivation (a clean recoverable `Error::Database`), so a fresh-box below-quorum boot cannot
    /// derive at reused indices. Flipped to `true` EXACTLY ONCE — the moment the floor is
    /// legitimately established (RESUME, or a ≥k config read) — after which every derivation is a
    /// single cheap atomic load (runtime-free; no per-op quorum check, no stall on a healthy node).
    ///
    /// ★ INVARIANT #2 — MONOTONIC (false→true only, NEVER back). cdk touches the counter multiple
    /// times per op incl. a POST-network increment (receive/saga); a true→false mid-op flip would
    /// strand already-minted proofs. [`Self::establish`] only ever stores `true`.
    counter_established: AtomicBool,
}

impl Nip60CounterDb {
    /// Wrap `inner` with an empty counter mirror. The establishment latch defaults `true` (bare
    /// wrappers — the plain rail wallet, unit tests — derive freely); the config-plane boot path
    /// constructs via [`Self::with_counters_established`] and computes the four-state latch (§2.2).
    pub fn new(inner: InnerStore) -> Self {
        Self::with_counters(inner, HashMap::new())
    }

    /// Wrap `inner`, seeding the mirror with `initial` counters (the values loaded from
    /// the 17375 wallet-config on a reconstruct). The mirror only ever rises above these
    /// floors, so a later publish cannot regress the counter below what the relay already
    /// recorded. Latch defaults `true` (see [`Self::new`]).
    pub fn with_counters(inner: InnerStore, initial: HashMap<Id, u32>) -> Self {
        Self::with_counters_established(inner, initial, true)
    }

    /// Wrap `inner` with seeded `initial` floors AND an explicit establishment-latch value
    /// (config-plane §2.2). The boot path passes `established` computed from the four-state
    /// discrimination (RESUME → true; fresh-box + ≥k config → true; fresh-box + below-quorum →
    /// FALSE = defer). A `false` latch gates every derivation at the choke point until
    /// [`Self::establish`] flips it (the bounded retry, on a ≥k config read).
    pub fn with_counters_established(
        inner: InnerStore,
        initial: HashMap<Id, u32>,
        established: bool,
    ) -> Self {
        Self {
            inner,
            shadow: Mutex::new(initial),
            counter_established: AtomicBool::new(established),
        }
    }

    /// Flip the establishment latch `true` (MONOTONIC — false→true only, idempotent). Called once
    /// the floor is legitimately established: at construction for RESUME / ≥k-fresh-box, or by the
    /// bounded retry (§2.4) after a ≥k config read fast-forwards the true floor. Never reverts
    /// (invariant #2), so a post-network increment can never be stranded by a mid-op un-establish.
    pub fn establish(&self) {
        self.counter_established.store(true, Ordering::SeqCst);
    }

    /// Whether the establishment latch is set (a single cheap atomic load — the healthy-node hot
    /// path). The boot solvency gate (§2.8) and the retry (§2.4) read it.
    pub fn is_established(&self) -> bool {
        self.counter_established.load(Ordering::SeqCst)
    }

    /// Fold fresh `floors` into the publish-mirror (monotonic max per keyset), so a subsequent
    /// [`Self::fast_forward_inner_to_floor`] lifts the inner derivation counter to the NEWLY-learned
    /// TRUE floor. Used by the bounded retry (§2.4): the mirror was seeded at open with a THIN /
    /// empty below-quorum floor; on a ≥k config read the retry re-seeds the true floor HERE before
    /// fast-forwarding + establishing, so the counter never establishes below the real head.
    pub fn seed_floor(&self, floors: HashMap<Id, u32>) {
        for (id, c) in floors {
            self.observe(&id, c);
        }
    }

    /// Snapshot the mirrored counters for publishing into the 17375 event.
    pub fn keyset_counters(&self) -> HashMap<Id, u32> {
        self.shadow
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Fold `counter` into the mirror for `keyset_id`, keeping the max (monotonic). A
    /// poisoned lock is recovered — mirroring the counter must never block a spend.
    fn observe(&self, keyset_id: &Id, counter: u32) {
        let mut shadow = self
            .shadow
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = shadow.entry(*keyset_id).or_insert(0);
        *entry = (*entry).max(counter);
    }

    /// Fast-forward the INNER store's NUT-13 derivation counter up to the seeded floor for every
    /// keyset, so a fresh-store restore never re-derives an already-used secret. [`Self::with_counters`]
    /// seeds the SHADOW (the publish-mirror), but cdk derives from the INNER counter — which starts
    /// at 0 on a fresh store. Without this, `receive_proofs` on a reconstruct re-issues secrets at
    /// indices the prior instance already spent → collision / loss. Reads the inner counter with a
    /// no-op `increment_keyset_counter(id, 0)` (cdk returns the current value) and advances only when
    /// the floor is higher — never regresses. Idempotent. Call ONCE at open, BEFORE the wallet
    /// derives anything. This lifts ONLY the inner derivation counter (the read/restore side); making
    /// the PUBLISHED mirror complete + non-regressing across keysets is deferred to the write-side
    /// counter-publish cut (the mirror is vacuous until the proof-publish write half lands).
    pub async fn fast_forward_inner_to_floor(&self) -> Result<(), Error> {
        // Snapshot the seeded floors, releasing the std Mutex BEFORE any await.
        let floors: Vec<(Id, u32)> = {
            let shadow = self.shadow.lock().unwrap_or_else(|p| p.into_inner());
            shadow.iter().map(|(id, c)| (*id, *c)).collect()
        };
        for (id, floor) in floors {
            // ★ INVARIANT #1 (config-plane §2.2, LOAD-BEARING — do NOT route through the decorated
            // `self.increment_keyset_counter`): fast-forward IS the establishment ACTION and must be
            // GATE-EXEMPT. It calls `self.inner` (the concrete store) directly so it can lift the
            // counter to the true floor BEFORE the establishment latch flips true. Rerouting it
            // through the gated method would SELF-DEADLOCK — establishment blocked by the
            // not-yet-established latch it is trying to establish. (Regression-guarded by T7.)
            let cur = self.inner.increment_keyset_counter(&id, 0).await?;
            if floor > cur {
                self.inner.increment_keyset_counter(&id, floor - cur).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl WalletDatabase<Error> for Nip60CounterDb {
    async fn get_mint(&self, mint_url: MintUrl) -> Result<Option<MintInfo>, Error> {
        self.inner.get_mint(mint_url).await
    }

    async fn get_mints(&self) -> Result<HashMap<MintUrl, Option<MintInfo>>, Error> {
        self.inner.get_mints().await
    }

    async fn get_mint_keysets(&self, mint_url: MintUrl) -> Result<Option<Vec<KeySetInfo>>, Error> {
        self.inner.get_mint_keysets(mint_url).await
    }

    async fn get_keyset_by_id(&self, keyset_id: &Id) -> Result<Option<KeySetInfo>, Error> {
        self.inner.get_keyset_by_id(keyset_id).await
    }

    async fn get_mint_quote(&self, quote_id: &str) -> Result<Option<WalletMintQuote>, Error> {
        self.inner.get_mint_quote(quote_id).await
    }

    async fn get_mint_quotes(&self) -> Result<Vec<WalletMintQuote>, Error> {
        self.inner.get_mint_quotes().await
    }

    async fn get_unissued_mint_quotes(&self) -> Result<Vec<WalletMintQuote>, Error> {
        self.inner.get_unissued_mint_quotes().await
    }

    async fn get_melt_quote(&self, quote_id: &str) -> Result<Option<MeltQuote>, Error> {
        self.inner.get_melt_quote(quote_id).await
    }

    async fn get_melt_quotes(&self) -> Result<Vec<MeltQuote>, Error> {
        self.inner.get_melt_quotes().await
    }

    async fn get_keys(&self, id: &Id) -> Result<Option<Keys>, Error> {
        self.inner.get_keys(id).await
    }

    async fn get_proofs(
        &self,
        mint_url: Option<MintUrl>,
        unit: Option<CurrencyUnit>,
        state: Option<Vec<State>>,
        spending_conditions: Option<Vec<SpendingConditions>>,
    ) -> Result<Vec<ProofInfo>, Error> {
        self.inner
            .get_proofs(mint_url, unit, state, spending_conditions)
            .await
    }

    async fn get_proofs_by_ys(&self, ys: Vec<PublicKey>) -> Result<Vec<ProofInfo>, Error> {
        self.inner.get_proofs_by_ys(ys).await
    }

    async fn get_balance(
        &self,
        mint_url: Option<MintUrl>,
        unit: Option<CurrencyUnit>,
        state: Option<Vec<State>>,
    ) -> Result<u64, Error> {
        self.inner.get_balance(mint_url, unit, state).await
    }

    async fn get_transaction(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<Transaction>, Error> {
        self.inner.get_transaction(transaction_id).await
    }

    async fn list_transactions(
        &self,
        mint_url: Option<MintUrl>,
        direction: Option<TransactionDirection>,
        unit: Option<CurrencyUnit>,
    ) -> Result<Vec<Transaction>, Error> {
        self.inner.list_transactions(mint_url, direction, unit).await
    }

    async fn update_proofs(
        &self,
        added: Vec<ProofInfo>,
        removed_ys: Vec<PublicKey>,
    ) -> Result<(), Error> {
        self.inner.update_proofs(added, removed_ys).await
    }

    async fn update_proofs_state(&self, ys: Vec<PublicKey>, state: State) -> Result<(), Error> {
        self.inner.update_proofs_state(ys, state).await
    }

    async fn add_transaction(&self, transaction: Transaction) -> Result<(), Error> {
        self.inner.add_transaction(transaction).await
    }

    async fn update_mint_url(
        &self,
        old_mint_url: MintUrl,
        new_mint_url: MintUrl,
    ) -> Result<(), Error> {
        self.inner.update_mint_url(old_mint_url, new_mint_url).await
    }

    /// The one intercept + the config-plane CHOKE POINT (§2.2): this is the ONLY counter-mutating
    /// method in the entire `WalletDatabase` trait, so EVERY NUT-13 derivation (swap / receive /
    /// mint-issue / melt-change / send / restore, AND `mint_unissued_quotes`'s recovery-mint)
    /// reserves its index range through here. When the establishment latch is NOT set, REFUSE with
    /// a clean recoverable `Error::Database` — cdk reserves the counter range BEFORE its network
    /// call, so this `Err` trips at the first reserve, `?`-propagates, and the op aborts with NO
    /// half-minted proofs (no panic, no partial commit). This is the bypass-proof gate that keeps a
    /// fresh-box below-quorum boot from deriving at a reused / thin-floor index (money loss). On a
    /// healthy (established) node it is a single cheap atomic load — runtime-free.
    async fn increment_keyset_counter(&self, keyset_id: &Id, count: u32) -> Result<u32, Error> {
        if !self.counter_established.load(Ordering::SeqCst) {
            return Err(Error::Database(Box::from(
                "NIP-60 NUT-13 counter not established (below-quorum fresh-box restore): derivation \
                 deferred until a ≥k config read establishes the true floor (config-plane §2.2)",
            )));
        }
        let new_counter = self.inner.increment_keyset_counter(keyset_id, count).await?;
        self.observe(keyset_id, new_counter);
        Ok(new_counter)
    }

    async fn add_mint(&self, mint_url: MintUrl, mint_info: Option<MintInfo>) -> Result<(), Error> {
        self.inner.add_mint(mint_url, mint_info).await
    }

    async fn remove_mint(&self, mint_url: MintUrl) -> Result<(), Error> {
        self.inner.remove_mint(mint_url).await
    }

    async fn add_mint_keysets(
        &self,
        mint_url: MintUrl,
        keysets: Vec<KeySetInfo>,
    ) -> Result<(), Error> {
        self.inner.add_mint_keysets(mint_url, keysets).await
    }

    async fn add_mint_quote(&self, quote: WalletMintQuote) -> Result<(), Error> {
        self.inner.add_mint_quote(quote).await
    }

    async fn remove_mint_quote(&self, quote_id: &str) -> Result<(), Error> {
        self.inner.remove_mint_quote(quote_id).await
    }

    async fn add_melt_quote(&self, quote: MeltQuote) -> Result<(), Error> {
        self.inner.add_melt_quote(quote).await
    }

    async fn remove_melt_quote(&self, quote_id: &str) -> Result<(), Error> {
        self.inner.remove_melt_quote(quote_id).await
    }

    async fn add_keys(&self, keyset: KeySet) -> Result<(), Error> {
        self.inner.add_keys(keyset).await
    }

    async fn remove_keys(&self, id: &Id) -> Result<(), Error> {
        self.inner.remove_keys(id).await
    }

    async fn remove_transaction(&self, transaction_id: TransactionId) -> Result<(), Error> {
        self.inner.remove_transaction(transaction_id).await
    }

    async fn add_saga(&self, saga: WalletSaga) -> Result<(), Error> {
        self.inner.add_saga(saga).await
    }

    async fn get_saga(&self, id: &Uuid) -> Result<Option<WalletSaga>, Error> {
        self.inner.get_saga(id).await
    }

    async fn update_saga(&self, saga: WalletSaga) -> Result<bool, Error> {
        self.inner.update_saga(saga).await
    }

    async fn delete_saga(&self, id: &Uuid) -> Result<(), Error> {
        self.inner.delete_saga(id).await
    }

    async fn get_incomplete_sagas(&self) -> Result<Vec<WalletSaga>, Error> {
        self.inner.get_incomplete_sagas().await
    }

    async fn reserve_proofs(
        &self,
        ys: Vec<PublicKey>,
        operation_id: &Uuid,
    ) -> Result<(), Error> {
        self.inner.reserve_proofs(ys, operation_id).await
    }

    async fn release_proofs(&self, operation_id: &Uuid) -> Result<(), Error> {
        self.inner.release_proofs(operation_id).await
    }

    async fn get_reserved_proofs(&self, operation_id: &Uuid) -> Result<Vec<ProofInfo>, Error> {
        self.inner.get_reserved_proofs(operation_id).await
    }

    async fn reserve_melt_quote(
        &self,
        quote_id: &str,
        operation_id: &Uuid,
    ) -> Result<(), Error> {
        self.inner.reserve_melt_quote(quote_id, operation_id).await
    }

    async fn release_melt_quote(&self, operation_id: &Uuid) -> Result<(), Error> {
        self.inner.release_melt_quote(operation_id).await
    }

    async fn reserve_mint_quote(
        &self,
        quote_id: &str,
        operation_id: &Uuid,
    ) -> Result<(), Error> {
        self.inner.reserve_mint_quote(quote_id, operation_id).await
    }

    async fn release_mint_quote(&self, operation_id: &Uuid) -> Result<(), Error> {
        self.inner.release_mint_quote(operation_id).await
    }

    async fn kv_read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.inner
            .kv_read(primary_namespace, secondary_namespace, key)
            .await
    }

    async fn kv_list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, Error> {
        self.inner
            .kv_list(primary_namespace, secondary_namespace)
            .await
    }

    async fn kv_write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), Error> {
        self.inner
            .kv_write(primary_namespace, secondary_namespace, key, value)
            .await
    }

    async fn kv_remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<(), Error> {
        self.inner
            .kv_remove(primary_namespace, secondary_namespace, key)
            .await
    }

    async fn add_p2pk_key(
        &self,
        pubkey: &PublicKey,
        derivation_path: DerivationPath,
        derivation_index: u32,
    ) -> Result<(), Error> {
        self.inner
            .add_p2pk_key(pubkey, derivation_path, derivation_index)
            .await
    }

    async fn get_p2pk_key(&self, pubkey: &PublicKey) -> Result<Option<P2PKSigningKey>, Error> {
        self.inner.get_p2pk_key(pubkey).await
    }

    async fn list_p2pk_keys(&self) -> Result<Vec<P2PKSigningKey>, Error> {
        self.inner.list_p2pk_keys().await
    }

    async fn latest_p2pk(&self) -> Result<Option<P2PKSigningKey>, Error> {
        self.inner.latest_p2pk().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh in-memory cdk wallet store, wrapped by the decorator under test.
    async fn wrapped_memory_db() -> Nip60CounterDb {
        let mem = cdk_sqlite::wallet::memory::empty()
            .await
            .expect("in-memory wallet store");
        Nip60CounterDb::new(Arc::new(mem))
    }

    fn test_keyset_id() -> Id {
        // A valid v0 keyset id (leading `00` version byte + 14 hex).
        "009a1f293253e41e".parse().expect("valid keyset id")
    }

    /// The intercept mirrors the inner store's returned counter, and the snapshot
    /// reflects the highest value observed. RED if the intercept drops the mirror.
    #[tokio::test]
    async fn intercept_mirrors_observed_counter() {
        let db = wrapped_memory_db().await;
        let id = test_keyset_id();

        // Before any increment the keyset is absent from the mirror.
        assert_eq!(db.keyset_counters().get(&id), None);

        let first = db
            .increment_keyset_counter(&id, 3)
            .await
            .expect("increment");
        let second = db
            .increment_keyset_counter(&id, 2)
            .await
            .expect("increment");

        // The inner counter is monotonic, and the mirror tracks its high-water mark.
        assert!(second >= first, "inner counter must not regress");
        assert_eq!(
            db.keyset_counters().get(&id).copied(),
            Some(first.max(second)),
            "mirror must equal the highest counter the inner store returned"
        );
    }

    /// A reconstruct floor is never regressed by a freshly-opened (lower) inner store:
    /// the mirror stays at the seeded value so a later publish cannot lose ground. RED
    /// if `observe` overwrites instead of taking the max.
    #[tokio::test]
    async fn seeded_floor_is_not_regressed() {
        let mem = cdk_sqlite::wallet::memory::empty()
            .await
            .expect("in-memory wallet store");
        let id = test_keyset_id();
        // Seed a floor well above anything a fresh store will return.
        let floor: u32 = 10_000;
        let db = Nip60CounterDb::with_counters(Arc::new(mem), HashMap::from([(id, floor)]));

        let inner_now = db
            .increment_keyset_counter(&id, 1)
            .await
            .expect("increment");
        assert!(
            inner_now < floor,
            "the fresh inner store must be below the seeded floor for this test to bite"
        );
        assert_eq!(
            db.keyset_counters().get(&id).copied(),
            Some(floor),
            "the seeded floor must hold — the published counter must never regress"
        );
    }

    /// The reconstruct floor is fast-forwarded into the INNER derivation counter (not just the
    /// publish-mirror), so a fresh-store restore's `receive_proofs` derives BEYOND the prior
    /// instance's used secrets. RED-on-revert: if `fast_forward_inner_to_floor` is a no-op the
    /// inner counter stays at 0 and re-issues already-used indices.
    #[tokio::test]
    async fn fast_forward_lifts_the_inner_derivation_counter_to_the_floor() {
        let mem = cdk_sqlite::wallet::memory::empty()
            .await
            .expect("in-memory wallet store");
        let id = test_keyset_id();
        let floor: u32 = 10_000;
        let db = Nip60CounterDb::with_counters(Arc::new(mem), HashMap::from([(id, floor)]));

        db.fast_forward_inner_to_floor().await.expect("fast-forward");

        // A no-op read (increment by 0) of the INNER counter must now be at least the floor.
        let inner_now = db.increment_keyset_counter(&id, 0).await.expect("read inner counter");
        assert!(
            inner_now >= floor,
            "the INNER derivation counter must be fast-forwarded to >= the seeded floor \
             (got {inner_now}, floor {floor}) — else receive_proofs re-derives used secrets"
        );
    }

    // ---- T2 (config-plane §2.2): the choke-point gate DEFERS every derivation when the latch is
    // not established (a fresh-box below-quorum boot). Any NUT-13 derivation reserves its index
    // range through `increment_keyset_counter` (swap/receive/mint/melt/send/restore + recovery-mint)
    // — with the latch FALSE it must return a clean recoverable Err and mutate NOTHING (no
    // reused-index derivation), so the wallet cannot derive from a thin floor.
    //
    // RED-on-revert: remove the `!counter_established` guard block in `increment_keyset_counter` →
    // the increment succeeds from the thin state → the `expect_err` fails (derivation was NOT
    // blocked).
    #[tokio::test]
    async fn t2_choke_point_defers_derivation_when_not_established() {
        let mem = cdk_sqlite::wallet::memory::empty()
            .await
            .expect("in-memory wallet store");
        let id = test_keyset_id();
        // Fresh-box + below-quorum → latch starts FALSE (deferred).
        let db = Nip60CounterDb::with_counters_established(Arc::new(mem), HashMap::new(), false);
        assert!(!db.is_established(), "precondition: latch deferred");

        let err = db
            .increment_keyset_counter(&id, 1)
            .await
            .expect_err("a derivation MUST be blocked while the counter is not established");
        let msg = err.to_string();
        assert!(
            msg.contains("not established"),
            "the gate returns a clean recoverable 'counter not established' Error::Database (got: {msg})"
        );

        // The inner store was never mutated: after establishing, a no-op read is still 0.
        db.establish();
        let inner_now = db
            .increment_keyset_counter(&id, 0)
            .await
            .expect("read inner counter after establish");
        assert_eq!(inner_now, 0, "the blocked increment mutated NOTHING (no reserved index burned)");
    }

    // ---- establish() is MONOTONIC (invariant #2) and unblocks derivation. -------------------------
    #[tokio::test]
    async fn establish_is_monotonic_and_unblocks_derivation() {
        let mem = cdk_sqlite::wallet::memory::empty().await.expect("store");
        let id = test_keyset_id();
        let db = Nip60CounterDb::with_counters_established(Arc::new(mem), HashMap::new(), false);
        // Blocked before establish.
        assert!(db.increment_keyset_counter(&id, 1).await.is_err());
        db.establish();
        assert!(db.is_established());
        // Unblocked after establish.
        let v = db.increment_keyset_counter(&id, 3).await.expect("derives after establish");
        assert!(v >= 3, "the inner counter advanced once established");
        // Monotonic: `establish` again stays true (never reverts); there is no un-establish path.
        db.establish();
        assert!(db.is_established(), "establish is idempotent and never reverts (invariant #2)");
    }

    // ---- T7 (config-plane §2.2 invariant #1): fast_forward_inner_to_floor is GATE-EXEMPT because
    // it routes through `self.inner`, NOT the decorated `self.increment_keyset_counter`. This test
    // pins the exemption: fast-forward must succeed AND lift the inner counter even while the latch
    // is FALSE (establishment happens BEFORE the latch flips). If a refactor rerouted fast-forward
    // through the decorated (gated) method, establishment would SELF-DEADLOCK (the gate blocks the
    // very op trying to establish) — this test would then RED (fast-forward returns Err / does not
    // lift).
    //
    // RED-on-revert: change `fast_forward_inner_to_floor` to call `self.increment_keyset_counter`
    // instead of `self.inner.increment_keyset_counter` → with the latch false the calls Err →
    // `expect("fast-forward")` panics / the inner counter is not lifted → RED (self-deadlock proven).
    #[tokio::test]
    async fn t7_fast_forward_is_gate_exempt_via_self_inner() {
        let mem = cdk_sqlite::wallet::memory::empty().await.expect("store");
        let id = test_keyset_id();
        let floor: u32 = 5_000;
        // Latch FALSE (deferred) — the choke point would block a decorated derivation.
        let db = Nip60CounterDb::with_counters_established(
            Arc::new(mem),
            HashMap::from([(id, floor)]),
            false,
        );
        assert!(!db.is_established(), "precondition: latch is not established");

        // fast_forward MUST still succeed and lift the inner counter (it is the establishment
        // ACTION and is gate-exempt via self.inner). A reroute through the gated method would
        // self-deadlock here.
        db.fast_forward_inner_to_floor()
            .await
            .expect("fast-forward is gate-exempt and must succeed even while the latch is false");

        // Now establish (as the boot path does after fast-forward) and confirm the inner counter was
        // genuinely lifted to the floor — proving fast-forward reached the inner store.
        db.establish();
        let inner_now = db
            .increment_keyset_counter(&id, 0)
            .await
            .expect("read inner counter after establish");
        assert!(
            inner_now >= floor,
            "fast-forward (gate-exempt) lifted the inner counter to >= the floor even while the \
             latch was false (got {inner_now}, floor {floor}) — invariant #1 holds"
        );
    }
}
