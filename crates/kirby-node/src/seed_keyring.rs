//! Reconstruct-on-lease keyring (money-continuity Phase 2) — the wallet-side of the
//! cross-machine KEY carriage.
//!
//! REUSES the RUSTSEC-audited Shamir math from [`crate::hibernate::shamir`]
//! (`split_seed` / `combine_shares` / `derive_subkeys` over a 2-of-3 `MasterSeed`, with a
//! 64-byte `wallet_seed` subkey). This module adds the two pieces hibernate does NOT have:
//!
//! 1. The LEASE-GATED retrieval surface [`ShareReconstructor`] — the `get_when_lease_fresh`
//!    seam, kept DELIBERATELY SEPARATE from [`crate::keyset_provisioning::ShareSink`]. A
//!    `ShareSink::get_share` returns `Err` by design (a FROST quorum key is threshold-USED,
//!    never reassembled), so it stays the single auditable custody surface; this trait is
//!    the ONLY surface that returns a share's bytes, and ONLY while a lease authorizes it. A
//!    FROST keyset's type cannot implement this (it has no such method) = a compile-time
//!    custody boundary.
//! 2. The wallet-seed provider [`KeyringWalletSeed`] behind
//!    [`crate::mint_rig::WalletKey::Keyring`]: gather a threshold of shares under the lease
//!    gate, reconstruct the master seed, derive ONLY the wallet seed onto the spend plane.
//!
//! TRANSPORT-INDEPENDENT. The cross-machine carriage (a relay-backed
//! [`ShareReconstructor`] composing the `relay_transport` `RemoteShareSink` pattern +
//! `share_seal` at-rest + `CoordinatorAuthorizer`/fresh-lease) is a SEPARATE impl that
//! slots in behind this same trait with no change here; this module's logic is exercised
//! vs an in-memory double. hibernate's own Holder lease-fence is a logic template only
//! (welded to local disk, no concurrent-holder safety), so it informs — does not become —
//! the relay carriage's gate.
//!
//! CAPABILITY ISOLATION: a [`crate::mint_rig::WalletKey`] only ever yields the wallet seed
//! onto the spend plane — never a FROST key, never the DM key. The DM tick constructs no
//! `WalletKey`, so it can never reach spend authority.

use std::sync::Arc;

use crate::hibernate::{shamir, Share, SEAL_THRESHOLD};
use crate::mint_rig::WalletSeedProvider;

/// The lease-gated share-retrieval surface for reconstruct-on-lease — SEPARATE from
/// [`crate::keyset_provisioning::ShareSink`] by design (that trait's `get_share` stays the
/// one `Err`-returning custody-audit surface). The relay-backed seed sink and the in-memory
/// test double both implement THIS trait, so the keyring logic is identical across them.
pub trait ShareReconstructor: Send + Sync {
    /// Return the serialized [`Share`] bytes for the 1-based `share_index`, but ONLY if a
    /// fresh lease currently authorizes reconstruction. A stale/absent lease, or a
    /// missing/unreachable share, is an `Err` — the reconstruct-on-lease invariant (no live
    /// lease ⇒ no reassembly).
    fn get_when_lease_fresh(&self, share_index: u8) -> anyhow::Result<Vec<u8>>;
}

/// Serialize a [`Share`] to its wire bytes — the form a [`ShareReconstructor`] returns and a
/// holder sink ships/seals. `Share` is `serde`-serializable (it carries `share_index`,
/// `share_bytes`, `seal_epoch`, `commitment`), and [`shamir::combine_shares`] re-verifies the
/// commitment + epoch on the way back, so a tampered ship cannot silently corrupt the seed.
pub fn serialize_share(share: &Share) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(share).map_err(|e| anyhow::anyhow!("serialize keyring share: {e}"))
}

/// Parse a [`Share`] from its wire bytes (the inverse of [`serialize_share`]).
fn deserialize_share(bytes: &[u8]) -> anyhow::Result<Share> {
    serde_json::from_slice(bytes).map_err(|e| anyhow::anyhow!("parse keyring share: {e}"))
}

/// The reconstruct-on-lease wallet-seed provider (the wallet plane of the keyring): gathers a
/// threshold of shares via the lease-gated [`ShareReconstructor`], reconstructs the
/// [`shamir`] master seed, and derives ONLY the wallet seed. Slots behind
/// [`crate::mint_rig::WalletKey::Keyring`]; the wallet-open path is oblivious to HOW the seed
/// is obtained.
pub struct KeyringWalletSeed {
    /// The 1-based share indices to try (`1..=SEAL_SHARES`). Gathering stops once the
    /// `SEAL_THRESHOLD` is reached, so a healthy quorum needs only the threshold reachable.
    share_indices: Vec<u8>,
    /// The lease-gated retrieval surface: the in-memory double in tests, the relay-backed
    /// seed sink in production — swapped behind this same trait with no change here.
    reconstructor: Arc<dyn ShareReconstructor>,
}

impl KeyringWalletSeed {
    pub fn new(share_indices: Vec<u8>, reconstructor: Arc<dyn ShareReconstructor>) -> Self {
        Self { share_indices, reconstructor }
    }
}

impl WalletSeedProvider for KeyringWalletSeed {
    fn wallet_seed(&self) -> anyhow::Result<[u8; 64]> {
        // Gather shares under the lease gate; reconstruction needs >= SEAL_THRESHOLD. A stale
        // lease makes get_when_lease_fresh refuse for EVERY index, so we fall through to the
        // threshold check and REFUSE (the reconstruct-on-lease invariant) rather than ever
        // opening a wallet without a live lease. A reachable-but-undecodable share is skipped
        // (a corrupt holder shouldn't strand a recoverable quorum); combine_shares re-verifies
        // every share that does make it through.
        let mut shares: Vec<Share> = Vec::with_capacity(self.share_indices.len());
        for &idx in &self.share_indices {
            match self.reconstructor.get_when_lease_fresh(idx) {
                Ok(bytes) => match deserialize_share(&bytes) {
                    Ok(share) => shares.push(share),
                    Err(e) => {
                        tracing::warn!(share_index = idx, error = %e, "keyring: undecodable share, skipping")
                    }
                },
                Err(e) => tracing::debug!(
                    share_index = idx,
                    error = %e,
                    "keyring: share unavailable (lease stale or holder unreachable)"
                ),
            }
            if shares.len() >= SEAL_THRESHOLD as usize {
                break;
            }
        }
        anyhow::ensure!(
            shares.len() >= SEAL_THRESHOLD as usize,
            "reconstruct-on-lease: only {} of {} shares available, need {} (no fresh lease, or \
             too few holders reachable) — refusing to open the wallet",
            shares.len(),
            self.share_indices.len(),
            SEAL_THRESHOLD
        );

        // REUSE the audited math: combine_shares re-verifies commitment + epoch + distinct
        // points before reconstructing, then derive_subkeys expands the master seed into its
        // domain-separated subkeys. We return ONLY the wallet seed (capability isolation); the
        // identity + state subkeys are dropped (zeroized) here, never crossing onto the spend
        // plane via this provider.
        let master = shamir::combine_shares(&shares)
            .map_err(|e| anyhow::anyhow!("reconstruct master seed from lease-gated shares: {e}"))?;
        let subkeys = shamir::derive_subkeys(&master);
        Ok(subkeys.wallet_seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibernate::shamir::{self, MasterSeed};
    use std::collections::BTreeMap;

    /// An in-memory [`ShareReconstructor`] double — stands in for the relay-backed seed sink,
    /// which slots in behind the SAME trait. Gates retrieval on a plain `fresh` flag (the real
    /// sink gates on a relay `LeaseView`); the keyring logic is identical either way.
    struct InMemoryReconstructor {
        fresh: bool,
        shares: BTreeMap<u8, Vec<u8>>,
    }

    impl ShareReconstructor for InMemoryReconstructor {
        fn get_when_lease_fresh(&self, share_index: u8) -> anyhow::Result<Vec<u8>> {
            anyhow::ensure!(self.fresh, "no fresh lease: reconstruct refused");
            self.shares
                .get(&share_index)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("share {share_index} absent"))
        }
    }

    /// Split a fixed test seed and stash the serialized shares in an in-memory double.
    /// Returns the double plus the wallet seed derived DIRECTLY from the same master seed (the
    /// value the keyring must reconstruct to). A fixed seed makes the derived wallet seed
    /// deterministic to assert against; the real master seed is host CSPRNG.
    fn split_and_store(fresh: bool) -> (InMemoryReconstructor, [u8; 64]) {
        let seed = MasterSeed::from_bytes([7u8; shamir::MASTER_SEED_LEN]);
        let expected_wallet = shamir::derive_subkeys(&seed).wallet_seed;
        let shares = shamir::split_seed(&seed, 1);
        let mut map = BTreeMap::new();
        for s in &shares {
            map.insert(s.share_index, serialize_share(s).expect("serialize share"));
        }
        (InMemoryReconstructor { fresh, shares: map }, expected_wallet)
    }

    #[test]
    fn fresh_lease_reconstructs_the_directly_derived_wallet_seed() {
        let (double, expected) = split_and_store(true);
        let provider = KeyringWalletSeed::new(vec![1, 2, 3], Arc::new(double));
        let got = provider
            .wallet_seed()
            .expect("fresh lease + a full quorum reconstructs the wallet seed");
        assert_eq!(
            got, expected,
            "the keyring-reconstructed wallet seed must equal the directly-derived subkey \
             (reuse of hibernate::shamir round-trips through the lease-gated retrieval)"
        );
    }

    #[test]
    fn a_threshold_of_shares_suffices() {
        // SEAL_THRESHOLD = 2: dropping one share of the 3 still reconstructs.
        let (mut double, expected) = split_and_store(true);
        double.shares.remove(&3);
        let provider = KeyringWalletSeed::new(vec![1, 2, 3], Arc::new(double));
        let got = provider.wallet_seed().expect("2 of 3 shares meet the threshold");
        assert_eq!(got, expected, "any SEAL_THRESHOLD shares reconstruct the same seed");
    }

    #[test]
    fn a_stale_lease_refuses_to_open_the_wallet() {
        // fresh = false: every get_when_lease_fresh refuses → no shares gathered → REFUSE.
        // This is the reconstruct-on-lease invariant and is RED-on-revert: drop the lease
        // gate and the wallet would open without a live lease.
        let (double, _expected) = split_and_store(false);
        let provider = KeyringWalletSeed::new(vec![1, 2, 3], Arc::new(double));
        let err = provider
            .wallet_seed()
            .expect_err("a stale lease MUST refuse to open the wallet");
        assert!(
            format!("{err:#}").contains("refusing to open the wallet"),
            "stale-lease refusal must be loud: {err:#}"
        );
    }

    #[test]
    fn too_few_shares_refuses_to_open_the_wallet() {
        // Only ONE share reachable (< SEAL_THRESHOLD) even under a fresh lease → REFUSE,
        // rather than opening a wallet whose seed can't be reconstructed.
        let (mut double, _expected) = split_and_store(true);
        double.shares.retain(|&idx, _| idx == 1);
        let provider = KeyringWalletSeed::new(vec![1, 2, 3], Arc::new(double));
        let err = provider
            .wallet_seed()
            .expect_err("fewer than the threshold of shares MUST refuse");
        assert!(
            format!("{err:#}").contains("refusing to open the wallet"),
            "too-few-shares refusal must be loud: {err:#}"
        );
    }
}
