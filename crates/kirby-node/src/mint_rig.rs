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

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use cdk::amount::{Amount, SplitTarget};
use cdk::nuts::{CurrencyUnit, Id, PaymentMethod};
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

/// The source of a wallet's spend key — the 64-byte cdk seed that is spend authority over the
/// wallet's proofs (HIGH-4). The SEPARATE-KEY P2 model: the wallet's seed is a local 0600 keyfile
/// (the sibling `<db_path>.seed`), resolved by [`Self::resolve_seed`] and handed to
/// [`open_persistent_wallet`]. Threshold-custody money — a Q-held wallet key never reassembled —
/// is P3 (FROST-unify), which would add its own variant here WITHOUT moving the wallet-open path.
/// PURPOSE-SCOPED: resolving a `WalletKey` yields ONLY the wallet seed onto the spend plane — it
/// shares no loader with the DM key (`with_dm_keys`), so the DM tick can never reach the wallet
/// seed (capability isolation by construction; the two key seams stay independent).
pub enum WalletKey {
    /// Host custody: a 64-byte spend-seed keyfile, load-or-create (0600), the authority the genome
    /// never sees. For a fleet tenant this lands in the per-agent durable dir because its
    /// `wallet_db_path` is per-agent ([`crate::boot::agent_state_dir_for`]); the bare default is
    /// the wallet store's sibling `<db_path>.seed` ([`WalletKey::sibling_seed_of`]).
    Keyfile(std::path::PathBuf),
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
    /// — no DM key, no shared loader (the DM tick holds no `WalletKey` and never calls this, so
    /// capability isolation is structural, not visibility-based). `pub` so the boot site resolves
    /// it ONCE and both derives the NIP-60 event key from it
    /// ([`crate::nip60_key::derive_nip60_event_key`]) and hands it to [`open_persistent_wallet`]
    /// — the boot site needs the event key BEFORE the wallet opens (to load the counter floor it
    /// seeds the store with) — and the live-wallet integration test opens its funded store the same
    /// way. Reading a `Keyfile` seed exposes nothing a path-holder couldn't read directly. A
    /// `match` (not an irrefutable `let`) so P3's FROST-unify threshold variant just adds an arm.
    pub fn resolve_seed(&self) -> anyhow::Result<[u8; 64]> {
        match self {
            WalletKey::Keyfile(path) => load_or_create_wallet_seed(path),
        }
    }
}

/// Open a PERSISTENT `cdk::Wallet` (Sat unit) against `mint_url`, backed by a cdk-sqlite
/// FILE store at `db_path` (NOT the in-memory store [`build_wallet`] uses): a live
/// RoutstrBrain wallet must survive a reboot, since the agent's whole point is persisting
/// across sessions (brain-routstr §7.1). The wallet SEED is persisted too (HIGH-4): a
/// persistent store with a FRESH random seed each boot is still broken, because the seed
/// is the deterministic key material that can reconstruct/spend the persisted proofs. So
/// the caller resolves the 64-byte `seed` through the `WalletKey` seam (spend authority — treat
/// it like the rail credential the genome never sees) and passes it in: the interim
/// [`WalletKey::sibling_seed_of`] load-or-creates (0600) the byte-identical sibling
/// `<db_path>.seed`. The
/// caller resolves ONCE so it can also derive the NIP-60 event key from the seed; `initial_counters`
/// seeds the returned NUT-13 counter mirror (the 17375 floor on a reconstruct, empty otherwise) and
/// the returned handle exposes `keyset_counters()` for the publisher.
/// Funding the live wallet is out-of-band (§11); this only OPENS an already-funded (or
/// fresh) store.
pub async fn open_persistent_wallet(
    mint_url: &str,
    db_path: &Path,
    seed: [u8; 64],
    initial_counters: HashMap<Id, u32>,
) -> anyhow::Result<(Arc<Wallet>, Arc<crate::nip60_counter::Nip60CounterDb>)> {
    // The store lives in db_path's directory; ensure it exists.
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("create wallet dir {}: {e}", parent.display()))?;
        }
    }

    // The PERSISTENT (file) cdk-sqlite store — `WalletSqliteDatabase::new(path)` opens a
    // file db (memory::empty passes ":memory:"); a file path persists the proofs.
    let localstore = cdk_sqlite::wallet::WalletSqliteDatabase::new(db_path.to_path_buf())
        .await
        .map_err(|e| anyhow::anyhow!("open persistent wallet store {}: {e}", db_path.display()))?;

    // Mirror the NUT-13 keyset counter through the NIP-60 decorator so it can travel in the
    // 17375 wallet-config for a cross-machine reconstruct. `initial_counters` is the counter
    // FLOOR loaded from the relay's 17375 head (empty on a fresh / non-reconstruct boot, where
    // this is byte-identical to the plain store): the mirror is SEEDED with it so a later publish
    // can never regress the counter below what the relay already recorded (the no-regress
    // MONEY-MUST). The returned handle exposes `keyset_counters()` for the publisher.
    let counter_db = Arc::new(crate::nip60_counter::Nip60CounterDb::with_counters(
        Arc::new(localstore),
        initial_counters,
    ));
    // Fast-forward the INNER NUT-13 derivation counter to the seeded floor BEFORE the wallet
    // derives anything, so a fresh-store reconstruct never re-issues an already-used secret (the
    // shadow seed alone fixes only the PUBLISH mirror, not what cdk derives from). No-op on a
    // fresh / non-reconstruct boot (empty floor).
    counter_db
        .fast_forward_inner_to_floor()
        .await
        .map_err(|e| anyhow::anyhow!("fast-forward NUT-13 counter to the reconstruct floor: {e}"))?;

    let wallet = Wallet::new(mint_url, CurrencyUnit::Sat, counter_db.clone(), seed, None)
        .map_err(|e| anyhow::anyhow!("build persistent cdk wallet against {mint_url}: {e}"))?;
    Ok((Arc::new(wallet), counter_db))
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
