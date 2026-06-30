//! Wallet helpers for the C-6 brokered act (gate G5, D-16): build a `cdk::Wallet`
//! against a mint and fund it on the local fakewallet mint.
//!
//! These wrap the CDK wallet API so the real rail ([`crate::rail::CdkEcashRail`])
//! and the G5 test share one funded-wallet path. The wallet IS the host-only
//! credential the genome never sees; it is constructed and funded host-side and
//! never serialized across vsock.
//!
//! The mint itself (a real cdk-mintd HTTP mint with the cdk-fake-wallet Lightning
//! backend) is BOOTED in the G5 test (it uses cdk-mintd, a dev-dependency); these
//! lib helpers only build and fund a wallet against a mint URL, using the runtime
//! cdk deps.

use std::path::Path;
use std::sync::Arc;

use cdk::amount::{Amount, SplitTarget};
use cdk::nuts::{CurrencyUnit, PaymentMethod};
use cdk::wallet::Wallet;
use cdk::StreamExt;

/// Build a `cdk::Wallet` (Sat unit) against `mint_url`, backed by an in-memory
/// sqlite store, with a fresh random seed. The wallet is the rail's host-only
/// credential. `mint_url` is the local fakewallet mint (e.g. `http://127.0.0.1:8086`).
pub async fn build_wallet(mint_url: &str) -> anyhow::Result<Arc<Wallet>> {
    use rand::TryRngCore;

    // A fresh random 64-byte wallet seed (the cdk Wallet derives its keys from
    // it). Host-only; never serialized to the genome. Drawn from the host CSPRNG,
    // the same source the gateway entropy nonce uses.
    let mut seed = [0u8; 64];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| anyhow::anyhow!("draw wallet seed from the host CSPRNG: {e}"))?;

    let localstore = cdk_sqlite::wallet::memory::empty()
        .await
        .map_err(|e| anyhow::anyhow!("open in-memory wallet store: {e}"))?;

    let wallet = Wallet::new(mint_url, CurrencyUnit::Sat, Arc::new(localstore), seed, None)
        .map_err(|e| anyhow::anyhow!("build cdk wallet against {mint_url}: {e}"))?;
    Ok(Arc::new(wallet))
}

/// Fund `wallet` with `amount` sats on the local fakewallet mint. Mirrors the cdk
/// integration-tests `fund_wallet`: request a BOLT11 mint quote, which the
/// fakewallet backend auto-marks paid, then mint the proofs (the proof stream
/// resolves once the quote is paid). After this the wallet holds spendable proofs
/// the rail can settle with.
pub async fn fund_wallet(wallet: Arc<Wallet>, amount_sats: u64) -> anyhow::Result<()> {
    let amount = Amount::from(amount_sats);
    let quote = wallet
        .mint_quote(PaymentMethod::BOLT11, Some(amount), None, None)
        .await
        .map_err(|e| anyhow::anyhow!("mint_quote for funding: {e}"))?;

    // The fakewallet backend marks the quote paid after a short delay; the proof
    // stream yields the minted proofs once paid.
    wallet
        .proof_stream(quote, SplitTarget::default(), None)
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("funding proof stream ended with no proofs"))?
        .map_err(|e| anyhow::anyhow!("funding proofs errored: {e}"))?;
    Ok(())
}

/// The Phase-2 wallet-seed provider behind [`WalletKey::Keyring`]: the reconstruct mechanism
/// (the reconstruct-on-lease keyring, [`crate::seed_keyring`]) sits BEHIND this trait, so the
/// wallet-open path stays oblivious to HOW the seed is obtained. PURPOSE-SCOPED: an impl
/// yields ONLY the 64-byte wallet spend seed onto the spend plane — never a FROST key, never
/// the DM key.
pub trait WalletSeedProvider: Send + Sync {
    /// Provide the 64-byte wallet spend seed. The keyring impl reconstructs the master seed
    /// (gated on a fresh lease) and derives the wallet seed; an error (no fresh lease, too
    /// few shares) REFUSES to open the wallet (loud + safe).
    fn wallet_seed(&self) -> anyhow::Result<[u8; 64]>;
}

/// The source of a wallet's spend key — the 64-byte cdk seed that is spend authority over
/// the wallet's proofs (HIGH-4). THE Phase-2 seam: the interim variant load-or-creates a
/// local 0600 keyfile (byte-identical to the pre-seam behavior); the reconstruct-on-lease
/// keyring (the #26 generalization) drops in as a new variant resolved by [`Self::resolve_seed`]
/// with NO change to [`open_persistent_wallet`] or its callers. PURPOSE-SCOPED: resolving a
/// `WalletKey` yields ONLY the wallet seed onto the spend plane — it shares no loader with the
/// DM key (`with_dm_keys`), so the DM tick can never reach the wallet seed (capability
/// isolation by construction; the two key seams stay independent).
pub enum WalletKey {
    /// Interim host custody: a 64-byte spend-seed keyfile, load-or-create (0600), the
    /// authority the genome never sees. For a fleet tenant this lands in the per-agent durable
    /// dir because its `wallet_db_path` is per-agent ([`crate::boot::agent_state_dir_for`]); the
    /// bare default is the wallet store's sibling `<db_path>.seed` ([`WalletKey::sibling_seed_of`]).
    Keyfile(std::path::PathBuf),
    /// PHASE-2: a [`WalletSeedProvider`] (the reconstruct-on-lease keyring) supplies the seed.
    /// The reconstruct mechanism sits BEHIND the trait, so the wallet-open hot path doesn't
    /// move; the variant CHOICE is made at the construction site (`build_routstr_brain`).
    /// Resolved by `resolve_seed` exactly like `Keyfile`.
    Keyring(std::sync::Arc<dyn WalletSeedProvider>),
}

impl WalletKey {
    /// The interim default for a wallet store at `db_path`: the sibling `<db_path>.seed`
    /// keyfile. BYTE-IDENTICAL to the pre-seam `open_persistent_wallet`, which always read the
    /// seed from this exact path — so a bare `kirby run` is unchanged (G-CLEAN), and a fleet
    /// tenant's seed rides its per-agent `db_path` into the per-agent durable dir.
    pub fn sibling_seed_of(db_path: &Path) -> Self {
        WalletKey::Keyfile(db_path.with_extension("seed"))
    }

    /// Resolve the 64-byte spend seed onto the spend plane. PURPOSE-SCOPED: wallet seed ONLY
    /// — no DM key, no shared loader.
    fn resolve_seed(&self) -> anyhow::Result<[u8; 64]> {
        match self {
            WalletKey::Keyfile(path) => load_or_create_wallet_seed(path),
            WalletKey::Keyring(provider) => provider.wallet_seed(),
        }
    }
}

/// Open a PERSISTENT `cdk::Wallet` (Sat unit) against `mint_url`, backed by a cdk-sqlite
/// FILE store at `db_path` (NOT the in-memory store [`build_wallet`] uses): a live
/// RoutstrBrain wallet must survive a reboot, since the agent's whole point is persisting
/// across sessions (brain-routstr §7.1). The wallet SEED is persisted too (HIGH-4): a
/// persistent store with a FRESH random seed each boot is still broken, because the seed
/// is the deterministic key material that can reconstruct/spend the persisted proofs. So
/// the seed is supplied through the `wallet_key` SEAM (spend authority — treat it like the
/// rail credential the genome never sees): the interim [`WalletKey::sibling_seed_of`]
/// load-or-creates (0600) the byte-identical sibling `<db_path>.seed`, and Phase-2's
/// reconstruct-on-lease keyring resolves the seed there instead with no caller change.
/// Funding the live wallet is out-of-band (§11); this only OPENS an already-funded (or
/// fresh) store.
pub async fn open_persistent_wallet(
    mint_url: &str,
    db_path: &Path,
    wallet_key: WalletKey,
) -> anyhow::Result<Arc<Wallet>> {
    // The store + seed live in db_path's directory; ensure it exists.
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("create wallet dir {}: {e}", parent.display()))?;
        }
    }

    // The wallet's 64-byte spend seed comes through the `wallet_key` seam (HIGH-4). The
    // interim `WalletKey::Keyfile` is the SAME 0600 load-or-create as before (byte-identical
    // when the sibling `<db_path>.seed` is used); Phase-2's keyring resolves here instead,
    // with no change to this function or its callers.
    let seed = wallet_key.resolve_seed()?;

    // The PERSISTENT (file) cdk-sqlite store — `WalletSqliteDatabase::new(path)` opens a
    // file db (memory::empty passes ":memory:"); a file path persists the proofs.
    let localstore = cdk_sqlite::wallet::WalletSqliteDatabase::new(db_path.to_path_buf())
        .await
        .map_err(|e| anyhow::anyhow!("open persistent wallet store {}: {e}", db_path.display()))?;

    let wallet = Wallet::new(mint_url, CurrencyUnit::Sat, Arc::new(localstore), seed, None)
        .map_err(|e| anyhow::anyhow!("build persistent cdk wallet against {mint_url}: {e}"))?;
    Ok(Arc::new(wallet))
}

/// Load the 64-byte wallet seed from `seed_path`, or generate-and-persist a fresh one
/// (host CSPRNG, 0600) on first run. The seed is spend authority over the wallet's
/// proofs (HIGH-4); a wrong-sized/corrupt file is a loud error, never a silent re-mint
/// (which would orphan the persisted proofs).
fn load_or_create_wallet_seed(seed_path: &Path) -> anyhow::Result<[u8; 64]> {
    use std::io::Write as _;

    if seed_path.exists() {
        let bytes = std::fs::read(seed_path)
            .map_err(|e| anyhow::anyhow!("read wallet seed {}: {e}", seed_path.display()))?;
        let seed: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "wallet seed {} is {} bytes, expected 64 (corrupt or wrong file); refusing to \
                 mint a new seed that cannot spend the persisted proofs",
                seed_path.display(),
                bytes.len()
            )
        })?;
        return Ok(seed);
    }

    use rand::TryRngCore as _;
    let mut seed = [0u8; 64];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| anyhow::anyhow!("draw wallet seed from the host CSPRNG: {e}"))?;

    // Create 0600 from the start (do not briefly expose spend authority as 0644), the
    // same idiom the node key uses (nerve.rs).
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(seed_path)
        .map_err(|e| anyhow::anyhow!("create wallet seed file {}: {e}", seed_path.display()))?;
    f.write_all(&seed)
        .map_err(|e| anyhow::anyhow!("write wallet seed {}: {e}", seed_path.display()))?;
    f.flush().ok();

    // Belt and suspenders: enforce 0600 even if the file pre-existed via a race.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(seed_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("set 0600 on {}: {e}", seed_path.display()))?;
    }
    Ok(seed)
}
