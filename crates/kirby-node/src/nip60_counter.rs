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
}

impl Nip60CounterDb {
    /// Wrap `inner` with an empty counter mirror.
    pub fn new(inner: InnerStore) -> Self {
        Self::with_counters(inner, HashMap::new())
    }

    /// Wrap `inner`, seeding the mirror with `initial` counters (the values loaded from
    /// the 17375 wallet-config on a reconstruct). The mirror only ever rises above these
    /// floors, so a later publish cannot regress the counter below what the relay already
    /// recorded.
    pub fn with_counters(inner: InnerStore, initial: HashMap<Id, u32>) -> Self {
        Self {
            inner,
            shadow: Mutex::new(initial),
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

    /// The one intercept: pass the increment straight through to the inner store (which
    /// stays cdk's source of truth), then mirror the returned counter for later publish.
    async fn increment_keyset_counter(&self, keyset_id: &Id, count: u32) -> Result<u32, Error> {
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
}
