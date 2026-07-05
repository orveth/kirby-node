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
/// `config_authoritative`: whether the 17375 counter-floor config read that produced
/// `initial_counters` reached read-quorum (config-plane §2.1). It drives the FOUR-STATE
/// establishment latch (§2.2): on a fresh box (empty local counter table) a BELOW-quorum config
/// read cannot be trusted to establish the floor (a real head may live on an unreached relay →
/// index reuse), so the counter is DEFERRED (latch false, fast-forward NOT run, every derivation
/// blocked at the choke point until the bounded retry lands a ≥k read). A RESUME (non-empty local
/// counter) is always safe (fast-forward is lift-up-only) and establishes immediately; a fresh box
/// with a ≥k read establishes at the true floor (or at 0 when genuinely new — sound only under the
/// quorum-intersection invariant, §2.8b). Callers with no relays (NIP-60 off) pass `true`.
///
/// `token_authoritative` / `token_empty`: the TOKEN-plane (kind 7375 proofs) read result, threaded
/// in for the finding-4 AIRTIGHT establish-at-0 guard (config-plane revision). `token_authoritative`
/// = the token read reached read-quorum (`served >= read_k`); `token_empty` = it fetched NO token
/// events. establish-at-0 (state 4) fires ONLY when BOTH planes are quorum-confirmed-empty:
/// `config_authoritative AND config-head-absent AND token_authoritative AND token_empty`. A
/// below-quorum token read (can't confirm empty) OR present token backups → DEFER, never
/// establish-at-0 against possibly-unread proofs (that would derive at index 0 = reuse). Callers
/// with no relays (NIP-60 off) pass `true`/`true` (a genuinely-new local wallet).
pub async fn open_persistent_wallet(
    mint_url: &str,
    db_path: &Path,
    seed: [u8; 64],
    initial_counters: HashMap<Id, u32>,
    config_authoritative: bool,
    token_authoritative: bool,
    token_empty: bool,
) -> anyhow::Result<(Arc<Wallet>, Arc<crate::nip60_counter::Nip60CounterDb>)> {
    // The store lives in db_path's directory; ensure it exists.
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("create wallet dir {}: {e}", parent.display()))?;
        }
    }

    // The PERSISTENT (file) cdk-sqlite store — `WalletSqliteDatabase::new(path)` opens a
    // file db (memory::empty passes ":memory:"); a file path persists the proofs. On return the
    // `keyset_counter` table exists + is committed (cdk runs its migrations in `new`), so the
    // second-connection read below sees the live schema.
    let localstore = cdk_sqlite::wallet::WalletSqliteDatabase::new(db_path.to_path_buf())
        .await
        .map_err(|e| anyhow::anyhow!("open persistent wallet store {}: {e}", db_path.display()))?;

    // COMPLETENESS (#115 Cut B): read EVERY local NUT-13 counter straight from the on-disk
    // `keyset_counter` table. `initial_counters` (the 17375 FLOOR) only names keysets the relay has
    // seen; a keyset with a live LOCAL counter that is absent from the floor and untouched this
    // session would otherwise be OMITTED from the publish-mirror (and, if local > floor, published
    // STALE) — a self-perpetuating gap across boots that re-collides a same-seed fresh-store
    // re-derivation. `localstore` is STILL ALIVE here (moved into the decorator below), so this opens
    // a SECOND connection to the same live WAL db — intentional, and it mirrors production (the
    // background flusher + gateway share the store the same way). Fail-safe: an empty map on any
    // error == today's floor-only behavior (the floor still applies).
    let local_map = read_local_keyset_counters(db_path);

    // Seed the mirror with the UNION-MAX of the loaded floor and the local counters: for every
    // keyset in EITHER set, take the higher of the two. This makes the publish-mirror COMPLETE (no
    // local-only keyset omitted) and NON-REGRESSING (never below the relay floor NOR below the local
    // counter). max() also makes a stale local read harmless (the floor wins) and a stale floor
    // harmless (the local counter wins).
    let merged = union_max_counters(&initial_counters, &local_map);

    // FOUR-STATE establishment (config-plane §2.2), authority-first. The RESUME signal is the LOCAL
    // counter table: a NON-empty local counter means a prior instance already derived here, so
    // fast-forward (lift-up-only) is safe and the latch establishes immediately (state 1). A fresh
    // box (empty local table) can only conclude the floor is safe to establish from an
    // AUTHORITATIVE (≥k) config read (states 3+4); a below-quorum config read on a fresh box is
    // DEFERRED (state 2) — we cannot distinguish genuinely-new from restore-pending-on-an-unreached
    // relay, and fast-forwarding to a thin/stale floor would derive at reused NUT-13 indices.
    let resume = !local_map.is_empty();
    // The merged floor (config 17375 ∪ local) is EMPTY exactly when there is no counter to establish
    // above 0 — i.e. establishing here means establishing AT 0 (state 4). On a fresh box (local
    // empty) merged == the config floor, so `floor_empty` ⟺ config-head-absent (or a head with no
    // counters). Establish-at-0 is the ONLY reuse-hazard establishment (an existing head is a real
    // floor we lift UP to, always safe); it needs the finding-4 airtight guard.
    let floor_empty = merged.is_empty();
    // FOUR-STATE, authority-first, with the finding-4 airtight establish-at-0 guard:
    //   state 1 RESUME (local counter present)                       → establish (lift-up-only safe).
    //   state 2 fresh-box + config below-quorum                      → DEFER (can't trust the floor).
    //   state 4 fresh-box + config ≥k + EMPTY floor (no head)        → establish AT 0 ONLY when the
    //           TOKEN plane is ALSO quorum-confirmed-empty (token_authoritative AND token_empty);
    //           a below-quorum token read or present token backups → DEFER (else index-0 reuse
    //           against possibly-unread proofs — finding 4, token-quorum-symmetric).
    //   state 3 fresh-box + config ≥k + NON-empty floor (real head)  → establish at the true floor.
    let established = if resume {
        true
    } else if !config_authoritative {
        false
    } else if floor_empty {
        token_authoritative && token_empty
    } else {
        true
    };

    // Mirror the NUT-13 keyset counter through the NIP-60 decorator so it can travel in the
    // 17375 wallet-config for a cross-machine reconstruct. The mirror is SEEDED with `merged` (floor
    // ∪ local, max per keyset) so a later publish can never regress the counter below what the relay
    // OR the local store recorded (the no-regress + completeness MONEY-MUST). The establishment
    // latch is seeded by the four-state discrimination above; when `false` the choke-point gate
    // blocks every derivation until the bounded retry (§2.4) lands a ≥k read.
    let counter_db = Arc::new(crate::nip60_counter::Nip60CounterDb::with_counters_established(
        Arc::new(localstore),
        merged,
        established,
    ));
    if established {
        // Fast-forward the INNER NUT-13 derivation counter to the seeded floor BEFORE the wallet
        // derives anything, so a fresh-store reconstruct never re-issues an already-used secret (the
        // shadow seed alone fixes only the PUBLISH mirror, not what cdk derives from). It lifts the
        // inner counter for the COMPLETE merged set (floor ∪ local); for a local-only keyset the
        // merged value equals the inner counter already, so that arm is a no-op (never a spurious
        // burn). No-op on a genuinely-new boot (empty floor + empty local table → establish at 0,
        // state 4, sound under the §2.8b quorum-intersection invariant).
        counter_db.fast_forward_inner_to_floor().await.map_err(|e| {
            anyhow::anyhow!("fast-forward NUT-13 counter to the reconstruct floor: {e}")
        })?;
    } else {
        // State 2 (fresh box + below-quorum config): DEFER. Do NOT fast-forward to a thin/stale
        // floor; the latch stays false so the choke point blocks derivations until a ≥k config read
        // establishes the true floor (the bounded retry re-drives this exact sequence).
        tracing::warn!(
            db = %db_path.display(),
            "NIP-60 counter DEFERRED: fresh-box restore below config read-quorum — derivations \
             blocked at the choke point (money-safe, no reused NUT-13 index) until a ≥k config read \
             establishes the true floor (stalled: below-quorum config, awaiting k relays)"
        );
    }

    let wallet = Wallet::new(mint_url, CurrencyUnit::Sat, counter_db.clone(), seed, None)
        .map_err(|e| anyhow::anyhow!("build persistent cdk wallet against {mint_url}: {e}"))?;
    Ok((Arc::new(wallet), counter_db))
}

/// The UNION-MAX merge of two keyset-counter maps: for every keyset present in EITHER `floor` (the
/// 17375 relay floor) or `local` (the on-disk store's live counters), the result holds the HIGHER of
/// the two values (a keyset absent from one side counts as 0 there). This is the completeness +
/// no-regress seed for the publish-mirror (#115 Cut B): a local-only keyset is carried at its local
/// value (completeness), and neither a stale floor nor a stale local read can pull a counter DOWN
/// (max). Pure + total; unit-tested by the mint_rig teeth.
fn union_max_counters(
    floor: &HashMap<Id, u32>,
    local: &HashMap<Id, u32>,
) -> HashMap<Id, u32> {
    let mut merged = floor.clone();
    for (id, &local_c) in local {
        let entry = merged.entry(*id).or_insert(0);
        *entry = (*entry).max(local_c);
    }
    merged
}

/// Read EVERY local NUT-13 keyset counter directly from the cdk-sqlite wallet store at `db_path`.
///
/// WHY A DIRECT READ: the cdk-0.17.1 `WalletDatabase` trait exposes NO bulk enumeration of counters
/// — only `increment_keyset_counter(&Id, u32)` (a read is an increment-by-0, which needs the keyset
/// id up front) — and the concrete `WalletSqliteDatabase` (`SQLWalletDatabase<SqliteConnectionManager>`)
/// exposes no pool/path accessor. So the on-disk table is the ONLY complete, unit-agnostic source of
/// the local counters, which #115 Cut B needs to make the 17375 publish-mirror COMPLETE (the shadow
/// map alone omits any keyset absent from the loaded floor + untouched this session).
///
/// SCHEMA COUPLING (cdk 0.17.1, migration `20251111000000_keyset_counter_table.sql` in
/// `cdk-sql-common`): the counters live in a flat, unencrypted table
/// `keyset_counter(keyset_id TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0)`, where
/// `keyset_id` is exactly `Id::to_string()` (canonical hex; `Id::from_str` reverses it). kirby opens
/// the store single-arg (`WalletSqliteDatabase::new(db_path)`, no password) so the db is NOT
/// sqlcipher-encrypted and a plain rusqlite connection reads it. The `T4` schema-guard tooth
/// exercises this SELECT against a REAL `WalletSqliteDatabase`, so a future cdk that renames the
/// table/columns turns this SELECT into an error → an empty map → the tooth's `{K1,K2}` expectation
/// fails LOUDLY (drift caught, not silently swallowed).
///
/// FLAG CHOICE: we open READ-ONLY (`SQLITE_OPEN_READ_ONLY`) — we only SELECT, and read-only makes the
/// intent explicit + cannot mutate the live store the wallet still owns. If a read-only open fails
/// (e.g. a `-wal`/`-shm` sidecar the SQLITE_OPEN_READ_ONLY path will not create), we retry with the
/// DEFAULT read-write flags. That retry is safe here: nothing writes during this open window (the
/// read happens synchronously at boot, before the wallet derives anything), so we still only SELECT;
/// the read-write flags merely let sqlite materialize the WAL sidecar it needs to see committed data.
///
/// T6 FAIL-SAFE: on ANY error (open failure, missing table, unparseable keyset id) this WARNs and
/// returns an EMPTY map — NEVER panics, NEVER propagates an error that could fail boot. An empty map
/// degrades to today's floor-only seeding (the 17375 floor still applies), so completeness is a
/// best-effort ADDITION that can only ever match-or-beat the prior behavior.
fn read_local_keyset_counters(db_path: &Path) -> HashMap<Id, u32> {
    use rusqlite::OpenFlags;
    use std::str::FromStr as _;

    // Open read-only first; fall back to read-write on failure (see the FLAG CHOICE note). A closure
    // so both attempts share one body and any error lands in the single fail-safe below.
    let open = || -> rusqlite::Result<rusqlite::Connection> {
        rusqlite::Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .or_else(|_| rusqlite::Connection::open(db_path))
    };

    let read = || -> rusqlite::Result<HashMap<Id, u32>> {
        let conn = open()?;
        let mut stmt = conn.prepare("SELECT keyset_id, counter FROM keyset_counter")?;
        let rows = stmt.query_map([], |row| {
            let keyset_id: String = row.get(0)?;
            let counter: i64 = row.get(1)?;
            Ok((keyset_id, counter))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (keyset_hex, counter) = row?;
            // Parse the hex id back to a cdk `Id`; a non-parseable id (only possible from a foreign
            // writer / corruption — cdk always stores `Id::to_string()`) drops THAT keyset with a
            // warn rather than failing the whole read (the floor still covers it).
            // Validate BOTH the id parse and the u32 range before inserting; a bad row (only possible
            // from a foreign writer / corruption — cdk always stores `Id::to_string()` and a u32
            // counter) is SKIPPED with a warn, never inserted, never a panic. SKIPPING (not clamping)
            // is the fail-safe direction: the 17375 floor still covers that keyset, and we never seed
            // an INFLATED counter that `fast_forward_inner_to_floor` would then burn a huge derivation
            // range to reach (clamping a corrupt value UP to u32::MAX would do exactly that).
            let id = match Id::from_str(&keyset_hex) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(
                        keyset_hex = %keyset_hex,
                        error = %e,
                        "NIP-60 counter read: skipping a local keyset_counter row with an unparseable keyset id (corruption)"
                    );
                    continue;
                }
            };
            let counter = match u32::try_from(counter) {
                Ok(c) => c,
                Err(_) => {
                    tracing::warn!(
                        keyset_hex = %keyset_hex,
                        counter,
                        "NIP-60 counter read: skipping a keyset_counter row whose counter is out of u32 range (corruption); the 17375 floor still covers it"
                    );
                    continue;
                }
            };
            map.insert(id, counter);
        }
        Ok(map)
    };

    match read() {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                db_path = %db_path.display(),
                error = %e,
                "NIP-60 counter read: could not read the local keyset_counter table; \
                 seeding the mirror from the 17375 floor only (fail-safe — completeness is skipped, \
                 no regression vs the prior floor-only behavior)"
            );
            HashMap::new()
        }
    }
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

#[cfg(test)]
mod tests {
    //! #115 Cut B teeth: the 17375 counter-mirror COMPLETENESS + no-regress at wallet open.
    //!
    //! T1/T2/T3 exercise the REAL `open_persistent_wallet` seed path (create a persistent
    //! `WalletSqliteDatabase`, write local counters, drop it, then reopen through
    //! `open_persistent_wallet` with a floor and assert the resulting mirror). Reverting the
    //! union-max merge to floor-only seeding makes T1/T2 RED. T4 is the schema-guard against a real
    //! `WalletSqliteDatabase`; T6 is the fail-safe.

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A unique temp path per call (pid + a process-global counter), removed on drop. Mirrors the
    /// nip60 `mint_fixture::TempDir` idiom (no `tempfile` direct dep); unique so parallel tests never
    /// collide on the same sqlite file.
    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("kirby-cutb-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }
        /// The wallet sqlite file inside this temp dir.
        fn db_path(&self) -> PathBuf {
            self.path.join("wallet.sqlite")
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn kid(hex: &str) -> Id {
        hex.parse().expect("valid keyset id")
    }

    /// Create a REAL persistent cdk-sqlite wallet store at `db_path`, write each `(keyset, counter)`
    /// via `increment_keyset_counter` (cdk's only counter mutator; from a 0 base a single increment
    /// sets the value), then DROP the store so the file is closed. This is the on-disk local state a
    /// subsequent open reads back.
    async fn seed_local_store(db_path: &Path, counters: &[(Id, u32)]) {
        use cdk::cdk_database::WalletDatabase as _;
        let store = cdk_sqlite::wallet::WalletSqliteDatabase::new(db_path.to_path_buf())
            .await
            .expect("open real persistent wallet store");
        for (id, c) in counters {
            store
                .increment_keyset_counter(id, *c)
                .await
                .expect("increment local keyset counter");
        }
        // Drop closes the connection/pool so the reopen below is a clean second open.
        drop(store);
    }

    /// A throwaway 64-byte seed for `open_persistent_wallet` (the seed is spend authority but these
    /// teeth assert only on the counter mirror, never spend).
    fn test_seed() -> [u8; 64] {
        [7u8; 64]
    }

    // ---- T1 COMPLETENESS: a local-only keyset (absent from the floor) is in the mirror. ----------
    // RED-on-revert: seed floor-only (drop the union-max merge) → K is absent from the mirror → the
    // `Some(100)` assert fails.
    #[tokio::test]
    async fn t1_local_only_keyset_absent_from_floor_is_in_the_mirror() {
        let tmp = TempDir::new("t1");
        let db_path = tmp.db_path();
        let k_local = kid("009a1f293253e41e");
        // Local store has K at 100; the floor (17375) does NOT mention K.
        seed_local_store(&db_path, &[(k_local, 100)]).await;
        let floor: HashMap<Id, u32> = HashMap::new();

        let (_wallet, counter_db) =
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true)
                .await
                .expect("open persistent wallet");

        assert_eq!(
            counter_db.keyset_counters().get(&k_local).copied(),
            Some(100),
            "COMPLETENESS: a local-only keyset (absent from the floor) must be carried into the \
             publish-mirror at its local value (revert union-max → floor-only → this is None)"
        );
    }

    // ---- T2 NO-REGRESS: local=100 > floor=50 → mirror holds 100, not the stale floor. ------------
    // RED-on-revert: floor-only seeding → the mirror holds 50 → the `Some(100)` assert fails.
    #[tokio::test]
    async fn t2_local_higher_than_floor_is_not_regressed_to_the_floor() {
        let tmp = TempDir::new("t2");
        let db_path = tmp.db_path();
        let k = kid("009a1f293253e41e");
        seed_local_store(&db_path, &[(k, 100)]).await;
        let floor = HashMap::from([(k, 50u32)]);

        let (_wallet, counter_db) =
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true)
                .await
                .expect("open persistent wallet");

        assert_eq!(
            counter_db.keyset_counters().get(&k).copied(),
            Some(100),
            "NO-REGRESS: union-max keeps the higher local counter (100), never the stale floor (50) \
             (revert union-max → floor-only → this is 50)"
        );
    }

    // ---- T3 INNER NO-REGRESS / NO SPURIOUS BURN: fast-forward does not advance a local-only keyset.
    // For a local-only keyset (local=100, absent from floor) the merged seed == the inner counter, so
    // the fast-forward's lift arm is a no-op: reading the inner counter (increment by 0) after open is
    // still exactly 100 — the union-max seeding never burns a derivation index.
    #[tokio::test]
    async fn t3_local_only_keyset_inner_counter_is_not_advanced_past_its_value() {
        use cdk::cdk_database::WalletDatabase as _;
        let tmp = TempDir::new("t3");
        let db_path = tmp.db_path();
        let k = kid("009a1f293253e41e");
        seed_local_store(&db_path, &[(k, 100)]).await;
        let floor: HashMap<Id, u32> = HashMap::new();

        let (_wallet, counter_db) =
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true)
                .await
                .expect("open persistent wallet");

        // A no-op read (increment by 0) of the INNER derivation counter must be EXACTLY 100 — not
        // advanced. A spurious lift would derive swap outputs beyond used indices (waste) or, worse,
        // any regression would re-derive spent secrets; union-max seeding does neither.
        let inner_now = counter_db
            .increment_keyset_counter(&k, 0)
            .await
            .expect("read inner counter");
        assert_eq!(
            inner_now, 100,
            "the INNER counter for a local-only keyset stays at its local value (100) — fast-forward \
             is a no-op there, never a spurious burn"
        );
    }

    // ---- T4 SCHEMA GUARD: read_local_keyset_counters matches cdk-sqlite's real on-disk schema. ----
    // Writing KNOWN counters first makes "empty" unambiguously a DRIFT (a renamed table/column errors
    // the SELECT → fail-safe empty → this exact-match assert fails loudly), not merely "no data".
    #[tokio::test]
    async fn t4_read_local_keyset_counters_matches_real_cdk_sqlite_schema() {
        use cdk::cdk_database::WalletDatabase as _;
        let tmp = TempDir::new("t4");
        let db_path = tmp.db_path();
        let k1 = kid("009a1f293253e41e");
        let k2 = kid("00ad268c4d1f5826");

        // Create a REAL WalletSqliteDatabase, write known counters, and KEEP it alive/in scope so the
        // read below is a genuine concurrent SECOND connection to the live WAL db.
        let store = cdk_sqlite::wallet::WalletSqliteDatabase::new(db_path.to_path_buf())
            .await
            .expect("open real persistent wallet store");
        store.increment_keyset_counter(&k1, 7).await.expect("k1");
        store.increment_keyset_counter(&k2, 3).await.expect("k2");

        let read = read_local_keyset_counters(&db_path);

        assert_eq!(
            read,
            HashMap::from([(k1, 7u32), (k2, 3u32)]),
            "the SELECT reads EXACTLY cdk's keyset_counter rows over a concurrent second connection; \
             an empty/wrong map here means the on-disk schema drifted from the hard-coded SELECT"
        );
        drop(store);
    }

    // ---- T6 FAIL-SAFE: any read error → empty map, never a panic. ---------------------------------
    #[tokio::test]
    async fn t6_read_local_keyset_counters_is_fail_safe_on_missing_db_and_missing_table() {
        // (a) A path with no db file at all → empty, no panic.
        let tmp = TempDir::new("t6a");
        let missing = tmp.db_path();
        assert!(!missing.exists(), "precondition: no db file yet");
        assert!(
            read_local_keyset_counters(&missing).is_empty(),
            "a nonexistent db path yields an empty map (fail-safe), not a panic"
        );

        // (b) A real sqlite file that LACKS the keyset_counter table → the SELECT errors → empty.
        let tmp2 = TempDir::new("t6b");
        let no_table = tmp2.db_path();
        {
            let conn = rusqlite::Connection::open(&no_table).expect("create bare sqlite db");
            conn.execute_batch("CREATE TABLE unrelated (x INTEGER);")
                .expect("make a table-less-of-keyset_counter db");
        }
        assert!(
            read_local_keyset_counters(&no_table).is_empty(),
            "a db missing the keyset_counter table yields an empty map (fail-safe), not a panic"
        );
    }

    // ---- T4 (config-plane §2.2, resume unaffected): a RESUME (local counter present) + a
    // BELOW-quorum config read must NOT be deferred — the latch establishes immediately (resume is
    // safe: fast-forward is lift-up-only) and derivations flow. A false-defer on resume would freeze
    // a healthy reboot (regression).
    //
    // RED-on-revert: change the four-state logic in `open_persistent_wallet` to key on
    // `config_authoritative` ALONE (drop the `resume ||`) → resume + below-quorum → established=false
    // → `is_established()` is false / the derivation below is blocked → RED.
    #[tokio::test]
    async fn t4_resume_with_below_quorum_config_is_not_deferred() {
        use cdk::cdk_database::WalletDatabase as _;
        let tmp = TempDir::new("t4cp");
        let db_path = tmp.db_path();
        let k = kid("009a1f293253e41e");
        // A prior instance already derived here → local counter table is NON-empty (RESUME).
        seed_local_store(&db_path, &[(k, 100)]).await;
        let floor: HashMap<Id, u32> = HashMap::new();

        // config_authoritative = FALSE (a below-quorum config read).
        let (_wallet, counter_db) =
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, false, true, true)
                .await
                .expect("open persistent wallet (resume)");

        assert!(
            counter_db.is_established(),
            "RESUME must establish immediately even below config-quorum (no false-defer, §2.2 state 1)"
        );
        // Derivations flow (the choke point does not bite on resume).
        let v = counter_db
            .increment_keyset_counter(&k, 1)
            .await
            .expect("a resume wallet derives freely (not deferred)");
        assert!(v >= 100, "the resume inner counter is at least its local value");
    }

    // ---- T8 (config-plane §2.2 state 4, create-fund guard): a fresh box + a ≥k config read + NO
    // prior head → the counter establishes at 0 and derivations FLOW (a genuinely-new agent must NOT
    // be false-blocked — this is create-fund / new-agent creation). Sound ONLY under the
    // quorum-intersection invariant (§2.8b, T9): ≥k-with-no-head ⟹ no head was ever written.
    //
    // RED-on-revert: change the four-state logic to establish ONLY on `resume` (defer even at ≥k) →
    // a fresh-box ≥k boot is deferred → the derivation below is blocked → a new agent can't operate
    // → RED.
    #[tokio::test]
    async fn t8_fresh_box_quorum_no_head_establishes_at_zero_and_derives() {
        use cdk::cdk_database::WalletDatabase as _;
        let tmp = TempDir::new("t8cp");
        let db_path = tmp.db_path();
        let k = kid("009a1f293253e41e");
        // Genuinely new: NO local store seeding, empty floor. config_authoritative = TRUE (≥k read).
        let floor: HashMap<Id, u32> = HashMap::new();

        let (_wallet, counter_db) =
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true)
                .await
                .expect("open persistent wallet (fresh box, ≥k, no head)");

        assert!(
            counter_db.is_established(),
            "fresh-box + ≥k + no-head → establish at 0 (state 4); a new agent must NOT be false-blocked"
        );
        // The counter starts at 0 (nothing to fast-forward) and derivations flow from index 0.
        let first = counter_db
            .increment_keyset_counter(&k, 0)
            .await
            .expect("read the fresh inner counter");
        assert_eq!(first, 0, "a genuinely-new counter establishes at 0 (no phantom floor)");
        let after = counter_db
            .increment_keyset_counter(&k, 5)
            .await
            .expect("a new agent derives freely from 0 (create-fund flows)");
        assert!(after >= 5, "derivations flow for a genuinely-new agent");
    }

    // ---- T13 (config-plane REVISION, finding-4 AIRTIGHT establish-at-0 guard, TOKEN-QUORUM-
    // SYMMETRIC): establish-at-0 requires BOTH planes quorum-confirmed-empty. Two cases must bite:
    //   (a) token backups PRESENT (token read ≥k, NON-empty) → establish-at-0 REFUSED (defer).
    //   (b) token read BELOW quorum (can't confirm empty)    → establish-at-0 REFUSED (defer).
    // Both: a fresh box (empty local) + ≥k config + NO config head (empty floor). Reverting the guard
    // to ignore the token plane (establish whenever config_authoritative) establishes at 0 against
    // possibly-unread proofs → derives at reused index → RED.

    // ---- T13(a): token backups PRESENT → establish-at-0 REFUSED. ---------------------------------
    // RED-on-revert: change the state-4 arm from `token_authoritative && token_empty` to `true`
    // (ignore the token plane) → this establishes at 0 → `is_established()` is true → the assert
    // fails (establish-at-0 fired against present token backups = index-0 reuse hazard).
    #[tokio::test]
    async fn t13a_establish_at_zero_refused_when_token_backups_present() {
        use cdk::cdk_database::WalletDatabase as _;
        let tmp = TempDir::new("t13a");
        let db_path = tmp.db_path();
        let k = kid("009a1f293253e41e");
        // Fresh box: NO local seeding, empty floor. config ≥k (config_authoritative=true), no head.
        let floor: HashMap<Id, u32> = HashMap::new();
        // Token plane: read reached quorum (authoritative) but token backups are PRESENT (NOT empty).
        let (_wallet, counter_db) = open_persistent_wallet(
            "http://127.0.0.1:1",
            &db_path,
            test_seed(),
            floor,
            true,  // config_authoritative
            true,  // token_authoritative (≥k)
            false, // token_empty = false → token backups PRESENT
        )
        .await
        .expect("open persistent wallet (fresh box, ≥k config, token backups present)");

        assert!(
            !counter_db.is_established(),
            "establish-at-0 REFUSED when token backups are present (defer, no index-0 reuse) — \
             revert (ignore the token plane) → establishes at 0 → RED"
        );
        // Deferred ⇒ derivations are BLOCKED at the choke point (no reused-index derivation).
        assert!(
            counter_db.increment_keyset_counter(&k, 1).await.is_err(),
            "a deferred fresh box blocks derivations at the choke point"
        );
    }

    // ---- T13(b) ★ TOKEN-QUORUM-SYMMETRY: token read BELOW quorum → establish-at-0 REFUSED. -------
    // The critical case the corrected guard adds over "NOT token_backups_exist": a below-quorum token
    // read CANNOT confirm empty, so treating it as empty would establish-at-0 against unread proofs.
    // RED-on-revert: change the state-4 arm to allow establish-at-0 on a below-quorum token read
    // (e.g. `token_empty` alone, or `true`) → this establishes → `is_established()` true → RED.
    #[tokio::test]
    async fn t13b_establish_at_zero_refused_when_token_read_below_quorum() {
        use cdk::cdk_database::WalletDatabase as _;
        let tmp = TempDir::new("t13b");
        let db_path = tmp.db_path();
        let k = kid("009a1f293253e41e");
        // Fresh box: NO local seeding, empty floor. config ≥k, no head.
        let floor: HashMap<Id, u32> = HashMap::new();
        // Token plane: read is BELOW quorum → cannot confirm empty (even though fetched_ids is empty,
        // token_authoritative=false means the emptiness is unproven).
        let (_wallet, counter_db) = open_persistent_wallet(
            "http://127.0.0.1:1",
            &db_path,
            test_seed(),
            floor,
            true,  // config_authoritative
            false, // token_authoritative = false → token read BELOW quorum (can't confirm empty)
            true,  // token_empty (apparent) — but unproven below quorum
        )
        .await
        .expect("open persistent wallet (fresh box, ≥k config, below-quorum token read)");

        assert!(
            !counter_db.is_established(),
            "establish-at-0 REFUSED when the token read is below quorum (emptiness unproven) — \
             revert (treat below-quorum as empty) → establishes at 0 against possibly-unread proofs \
             → RED (token-quorum-symmetry)"
        );
        assert!(
            counter_db.increment_keyset_counter(&k, 1).await.is_err(),
            "a deferred fresh box blocks derivations at the choke point"
        );
    }

    // ---- union_max_counters unit coverage (the pure merge under T1/T2). --------------------------
    #[test]
    fn union_max_takes_the_higher_over_the_union_of_keys() {
        let a = kid("009a1f293253e41e");
        let b = kid("00ad268c4d1f5826");
        let c = kid("00c0ffee00c0ffee");
        let floor = HashMap::from([(a, 50u32), (b, 200u32)]);
        let local = HashMap::from([(a, 100u32), (c, 9u32)]);
        let merged = union_max_counters(&floor, &local);
        assert_eq!(merged.get(&a).copied(), Some(100), "a: max(50,100)=100 (local wins)");
        assert_eq!(merged.get(&b).copied(), Some(200), "b: floor-only key carried (200)");
        assert_eq!(merged.get(&c).copied(), Some(9), "c: local-only key carried (9)");
        assert_eq!(merged.len(), 3, "the union of both key sets");
    }
}
