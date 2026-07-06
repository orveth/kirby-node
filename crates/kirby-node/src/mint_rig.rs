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
///
/// `config_floor_dropped` (config-plane ROUND-4, category (d) — HOLEY-FLOOR-NOT-GENUINE): whether the
/// config floor read that produced `initial_counters` DROPPED any keyset (an unparseable-hex keyset in
/// [`crate::nip60::WalletConfigContent::counters_by_id_checked`]). Combined with the LOCAL read's own
/// dropped signal ([`read_local_keyset_counters`]) into `floor_complete`; a holey floor from EITHER
/// source DEFERS establishment (the per-db latch must not flip on a partial floor — else the dropped
/// keyset derives from index 0 = NUT-13 reuse). Callers with no config drop (NIP-60 off, clean read)
/// pass `false`.
// The plane-read inputs (config/token authority + emptiness + holey signals) are each a distinct
// money-safety decision the establishment gate consumes; grouping them into a struct would only
// obscure the four-state + holey-floor logic. The arg count is deliberate.
#[allow(clippy::too_many_arguments)]
pub async fn open_persistent_wallet(
    mint_url: &str,
    db_path: &Path,
    seed: [u8; 64],
    initial_counters: HashMap<Id, u32>,
    config_authoritative: bool,
    token_authoritative: bool,
    token_empty: bool,
    config_floor_dropped: bool,
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
    let (local_map, local_floor_dropped) = read_local_keyset_counters(db_path);

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

    // ★★★ INVARIANT #3 — HOLEY-FLOOR-NOT-GENUINE (config-plane ROUND-4, category (d)): the floor is
    // GENUINE (complete) only when NEITHER read source dropped a keyset — the config floor read
    // (`config_floor_dropped`, from `counters_by_id_checked`) AND the local counter read
    // (`local_floor_dropped`, from `read_local_keyset_counters`). A holey floor from EITHER source
    // must NOT flip the per-db establishment latch: the latch is global but the floor is per-keyset, so
    // a dropped keyset would derive from index 0 = NUT-13 reuse. `floor_complete=false` DEFERS below
    // (regardless of resume/config/token) — the ONE guard covering BOTH read sources.
    let floor_complete = !(config_floor_dropped || local_floor_dropped);

    // Mirror the NUT-13 keyset counter through the NIP-60 decorator so it can travel in the
    // 17375 wallet-config for a cross-machine reconstruct. The mirror is SEEDED with `merged` (floor
    // ∪ local, max per keyset) so a later publish can never regress the counter below what the relay
    // OR the local store recorded (the no-regress + completeness MONEY-MUST). Constructed DEFERRED
    // (latch false); the SINGLE guarded establish choke point below flips it only when sound.
    let counter_db = Arc::new(crate::nip60_counter::Nip60CounterDb::with_counters_established(
        Arc::new(localstore),
        merged.clone(),
        false,
    ));
    // ★ R2-#1: route the establish DECISION through the ONE guarded choke point
    // ([`Nip60CounterDb::establish_if_sound`]) — the SAME function the bounded retry
    // ([`crate::boot::try_establish_counter`]) calls, so no site can establish-at-0 without ALL FOUR
    // conditions (four-state, authority-first, finding-4 token-quorum-symmetric guard). It seeds the
    // floor (idempotent with the construction seed), fast-forwards the INNER derivation counter
    // (gate-exempt) to the seeded floor BEFORE the wallet derives anything — so a fresh-store
    // reconstruct never re-issues an already-used secret — and flips the latch ONLY when sound.
    let established = counter_db
        .establish_if_sound(merged, resume, config_authoritative, token_authoritative, token_empty, floor_complete)
        .await
        .map_err(|e| {
            anyhow::anyhow!("establish the NUT-13 counter to the reconstruct floor: {e}")
        })?;
    if !established {
        // State 2 (fresh box + below-quorum config), OR state 4 with an unproven-empty token plane:
        // DEFER. Nothing was seeded/lifted; the latch stays false so the choke point blocks every
        // derivation until a ≥k config read (the bounded retry) establishes the true floor.
        tracing::warn!(
            db = %db_path.display(),
            "NIP-60 counter DEFERRED: fresh-box restore below config read-quorum OR an unproven-empty \
             token plane — derivations blocked at the choke point (money-safe, no reused NUT-13 \
             index) until a ≥k config read establishes the true floor (stalled: below-quorum config, \
             awaiting k relays)"
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
///
/// ★ RETURNS `(map, dropped)` (config-plane ROUND-4, category (d) — HOLEY-FLOOR-NOT-GENUINE): `dropped`
/// is `true` when this read is INCOMPLETE — a corrupt row was skipped (unparseable keyset id / out-of-range
/// counter) OR the whole read errored (open/table/query failure → empty-on-error). A genuinely EMPTY
/// table (a fresh box — 0 rows, clean read) is `dropped=false` (it is NOT holey, just new). The caller
/// gates establishment on `!dropped`: a holey floor must not flip the per-db latch (else the dropped
/// keyset derives from index 0 = NUT-13 reuse). The behavior is otherwise UNCHANGED — a dropped row is
/// still skipped with a warn, the map still degrades to floor-only; we merely SIGNAL the incompleteness.
fn read_local_keyset_counters(db_path: &Path) -> (HashMap<Id, u32>, bool) {
    use rusqlite::OpenFlags;
    use std::str::FromStr as _;

    // Open read-only first; fall back to read-write on failure (see the FLAG CHOICE note). A closure
    // so both attempts share one body and any error lands in the single fail-safe below.
    let open = || -> rusqlite::Result<rusqlite::Connection> {
        rusqlite::Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .or_else(|_| rusqlite::Connection::open(db_path))
    };

    // Returns `(map, dropped)`: `dropped` set if ANY row was skipped (corruption) so the caller can
    // fail-closed on an incomplete floor (category (d)).
    let read = || -> rusqlite::Result<(HashMap<Id, u32>, bool)> {
        let conn = open()?;
        let mut stmt = conn.prepare("SELECT keyset_id, counter FROM keyset_counter")?;
        let rows = stmt.query_map([], |row| {
            let keyset_id: String = row.get(0)?;
            let counter: i64 = row.get(1)?;
            Ok((keyset_id, counter))
        })?;
        let mut map = HashMap::new();
        let mut dropped = false;
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
                    // (d) HOLEY-FLOOR: this keyset's floor is now missing from the read → mark dropped.
                    dropped = true;
                    tracing::warn!(
                        keyset_hex = %keyset_hex,
                        error = %e,
                        "NIP-60 counter read: skipping a local keyset_counter row with an unparseable keyset id (corruption) — floor read marked HOLEY (establishment defers, category (d))"
                    );
                    continue;
                }
            };
            let counter = match u32::try_from(counter) {
                Ok(c) => c,
                Err(_) => {
                    dropped = true;
                    tracing::warn!(
                        keyset_hex = %keyset_hex,
                        counter,
                        "NIP-60 counter read: skipping a keyset_counter row whose counter is out of u32 range (corruption) — floor read marked HOLEY (establishment defers, category (d))"
                    );
                    continue;
                }
            };
            map.insert(id, counter);
        }
        Ok((map, dropped))
    };

    match read() {
        Ok((map, dropped)) => (map, dropped),
        Err(e) => {
            // (d) A whole-read failure cannot confirm completeness → HOLEY (dropped=true): the caller
            // fails-closed (defers establishment) rather than establishing on a floor it could not read.
            tracing::warn!(
                db_path = %db_path.display(),
                error = %e,
                "NIP-60 counter read: could not read the local keyset_counter table; \
                 seeding the mirror from the 17375 floor only (fail-safe) and marking the floor read \
                 HOLEY so establishment defers (category (d) — never establish on an unread floor)"
            );
            (HashMap::new(), true)
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

/// The result of an operator-pays funding mint ([`mint_into_wallet_operator_pays`]).
#[derive(Debug, Clone)]
pub struct FundWalletOutcome {
    /// The BOLT11 invoice (the mint quote's `request`) an operator paid to fund the wallet.
    pub bolt11: String,
    /// The mint quote id (the daemon-side handle the mint was looked up + minted by).
    pub quote_id: String,
    /// The mint-VERIFIED sats minted into the wallet (the summed proofs, NEVER the requested
    /// amount): the only sanctioned source for a credit (money-MUST), mirrored from the rail.
    pub minted_sats: u64,
    /// The wallet's total spendable balance AFTER the mint.
    pub balance_sats: u64,
}

/// ★FIX 3 (silent under-funding guard): a NUT-04 BOLT11 mint quote issues its FULL requested
/// amount — LN routing fees are the PAYER's, never deducted from the minted proofs — so the minted
/// sats MUST equal the requested sats. A shortfall means the wallet is under-funded (a mint that
/// yielded less than asked), and any mismatch is refused rather than reported as a success. Shared
/// by BOTH the fresh-mint path and the drain-first resume path so the invariant has ONE home.
fn ensure_minted_matches_requested(
    minted_sats: u64,
    requested_sats: u64,
    quote_id: &str,
) -> anyhow::Result<()> {
    if minted_sats != requested_sats {
        anyhow::bail!(
            "fund-wallet: minted {minted_sats} sats but {requested_sats} were requested (quote {quote_id}) \
             — a BOLT11 mint issues the FULL quote amount (LN fees are payer-side), so a mismatch means \
             the wallet is under-funded. Refusing to report success on a partial/mismatched fund."
        );
    }
    Ok(())
}

/// ★THE FUND INVARIANT READ (the 1a rail mechanism, [`crate::rail::LightningSettlement::held_unspent_for_quote`],
/// applied verbatim to the fund drain): sum the sats the wallet ACTUALLY HOLDS (unspent) for a
/// specific mint `quote_id`, and report whether ANY wallet [`Transaction`](cdk::wallet::types::Transaction)
/// records that quote.
///
/// This is the ONLY sanctioned signal for a funded-vs-not / amount decision in the drain — NEVER
/// the quote STATE (`Paid`/`Issued`/…), NEVER `amount_issued`, NEVER any mint-CLAIMED amount. The
/// wallet writes a durable Incoming `Transaction{quote_id, ys}` ONLY after the minted proofs
/// persist, so the record's PRESENCE ⇒ proofs were stored and its `ys` name them; we read those
/// proofs back and sum only the still-`Unspent` ones. Summing held-Unspent (not the claim) is
/// deterministic + idempotent: a second drain re-sums the same live set → the same number, and a
/// proof later spent drops out. Returns `(held_sats, found_transaction)`; `(0, true)` (tx exists
/// but every proof spent/removed) and `(0, false)` (no tx — the true lost-response) both mean
/// "the wallet holds NOTHING for this quote" to the caller.
async fn held_unspent_for_quote(wallet: &Wallet, quote_id: &str) -> anyhow::Result<(u64, bool)> {
    use cdk::nuts::State;
    use cdk::wallet::types::TransactionDirection;

    // The wallet writes an Incoming (mint) Transaction only AFTER the proofs persist. `get_transaction`
    // takes a TransactionId (a hash of the ys), NOT a quote_id, so we list Incoming txs + filter by quote.
    let txs = wallet
        .localstore
        .list_transactions(
            Some(wallet.mint_url.clone()),
            Some(TransactionDirection::Incoming),
            Some(wallet.unit.clone()),
        )
        .await
        .map_err(|e| anyhow::anyhow!("fund-wallet: list wallet transactions for quote {quote_id}: {e}"))?;

    // The ys of every Incoming tx naming this quote (normally exactly one).
    let ys: Vec<cdk::nuts::PublicKey> = txs
        .iter()
        .filter(|t| t.quote_id.as_deref() == Some(quote_id))
        .flat_map(|t| t.ys.iter().copied())
        .collect();
    let found_transaction = !ys.is_empty();
    if !found_transaction {
        // No durable record that proofs for this quote ever persisted ⇒ the TRUE lost-response.
        return Ok((0, false));
    }

    // Read those proofs back and sum ONLY the still-Unspent ones (the deterministic held set). The
    // sum is CHECKED (task #59): a raw u64 sum would WRAP on overflow and mis-report the held amount.
    let proofs = wallet
        .localstore
        .get_proofs_by_ys(ys)
        .await
        .map_err(|e| anyhow::anyhow!("fund-wallet: read proofs for quote {quote_id}: {e}"))?;
    let held = checked_held_sum(
        proofs
            .iter()
            .filter(|p| p.state == State::Unspent)
            .map(|p| p.proof.amount),
    )
    .map_err(|e| anyhow::anyhow!("fund-wallet: held-proofs sum for quote {quote_id}: {e}"))?;
    Ok((held, found_transaction))
}

/// Sum a set of held unspent proof amounts, CHECKED (closes tracked follow-up task #59).
///
/// A raw `iter.map(u64::from).sum::<u64>()` WRAPS on overflow in a RELEASE build (Rust panics on
/// arithmetic overflow only in debug), silently reporting a WRONG (small, wrapped) held amount — and a
/// wrapped total could even satisfy an `== requested` check on garbage. [`cdk::Amount::try_sum`] folds
/// with `checked_add` and returns `Err` on overflow instead, so an overflowing held set FAILS CLOSED
/// (refused) rather than being mis-credited. Pure over the amounts so the overflow tooth drives it
/// directly (no wallet/store needed).
fn checked_held_sum(amounts: impl IntoIterator<Item = Amount>) -> anyhow::Result<u64> {
    let total = Amount::try_sum(amounts).map_err(|e| {
        anyhow::anyhow!(
            "summing held unspent proofs overflowed the u64 amount space ({e}) — refusing to report \
             a WRAPPED (wrong, small) held amount (task #59: checked held-sum, fail-closed)"
        )
    })?;
    Ok(u64::from(total))
}

/// Refuse to fresh-quote unless saga recovery CLEANLY completed (FIX #1 report-capture half).
/// [`cdk::wallet::Wallet::recover_incomplete_sagas`] returns `Ok(report)` even when it left work
/// UNDONE: `failed > 0` (a saga that could NOT be recovered) or `skipped > 0` (a saga still pending —
/// mint unreachable / payment pending) can each leave a paid-but-proofless quote that a fresh invoice
/// would DOUBLE-PAY. So an incomplete recovery is a hard STOP before the drain scan: we cannot prove
/// no stranded paid quote exists. (`recovered` / `compensated` are clean terminal outcomes — a
/// compensated saga released its resources — and do NOT block; the all-quotes proofless-issued scan
/// below is the report-INDEPENDENT backstop that also catches a compensated-but-still-issued quote.)
fn check_recovery_report(report: &cdk::wallet::RecoveryReport) -> anyhow::Result<()> {
    if report.failed > 0 || report.skipped > 0 {
        anyhow::bail!(
            "fund-wallet: saga recovery did not cleanly complete before the drain scan ({} failed, {} \
             skipped) — refusing to issue a new invoice while an unrecovered/pending issue saga may \
             leave a paid-but-proofless quote (a fresh invoice over it would double-pay). Resolve mint \
             reachability and re-run.",
            report.failed,
            report.skipped
        );
    }
    Ok(())
}

/// Mint `amount_sats` of ecash into an ALREADY-OPENED persistent wallet via an OPERATOR-PAID
/// BOLT11 mint quote. This is the `fund-wallet` CLI's money dance: it mirrors the rail's
/// settlement flow ([`crate::rail::LightningSettlement`]: `mint_quote` → check-status → `mint`)
/// but WITHOUT the fakewallet auto-pay of [`fund_wallet`] — an operator pays the printed bolt11
/// out of band, so this POLLS the mint until the quote flips to `Paid` before minting.
///
/// The flow (the money-safety ordering is load-bearing):
///   1. ★NUT-13 ESTABLISHMENT GUARD (bail-loudly-never-silent-0): a DEFERRED counter blocks every
///      NUT-13 derivation at the choke point ([`crate::nip60_counter::Nip60CounterDb`]), so
///      `wallet.mint` would silently yield ZERO proofs (nip60.rs choke-point tooth). We REFUSE to
///      proceed when the counter is not established — never mint-quote, never report success on 0.
///   2. ★DRAIN-FIRST (timeout double-pay + phantom-credit guards): BEFORE issuing a new quote, walk
///      each paid-but-unissued quote a prior timed-out run left behind EXPLICITLY — re-check its
///      state with the mint, mint a PAID one with `wallet.mint(id)`, and count the proofs ACTUALLY
///      minted to the LOCAL store (NEVER `mint_unissued_quotes`'s `amount_issued` aggregate, which a
///      lost mint-response can inflate into a phantom credit). If a paid quote resolved cleanly we
///      RETURN it (issuing no new invoice) — resuming that EXACT stranded quote. A quote the mint
///      calls Issued while it is still unissued locally (no proofs landed) BAILS loudly; more than
///      one paid-unissued quote (ambiguous attribution) BAILS too.
///   3. `mint_quote(BOLT11, amount, memo)` → hand the bolt11 (`quote.request`) to `on_bolt11` for
///      an operator to pay (the CLI prints it to stdout); the quote id is persisted + logged to resume.
///   4. POLL `check_mint_quote_status` until `Paid` (bounded by `timeout`, `poll_interval` apart).
///   5. `mint` the ecash; the summed proofs are the mint-VERIFIED amount, which MUST equal the
///      requested amount (FIX 3 — a BOLT11 quote mints its full amount; a mismatch is an under-fund).
///   6. A SECOND establishment/derivation guard: assert the mint yielded NON-ZERO proofs — a 0-proof
///      mint means the derivation was silently gated, and we bail rather than claim success.
///
/// The wallet + counter_db MUST be the pair returned by [`open_persistent_wallet`] opened the
/// SAME way the boot path opens them (seed via the [`WalletKey`] seam), so the minted proofs land
/// in the store a subsequent boot reads and are derived under the boot-path seed (else unspendable).
///
/// # ★THE INVARIANT (rev-4 comprehensive closure — audited, not asserted)
/// A mint quote is FUNDED **iff the wallet HOLDS unspent proofs for it**; the funded/credited/minted
/// amount is the **SUM OF HELD UNSPENT PROOFS** for that quote id ([`held_unspent_for_quote`]) —
/// NEVER the quote STATE (`Paid`/`Issued`/…), NEVER `amount_issued`, NEVER any mint-CLAIMED amount.
/// This is the 1a rail invariant (credit == proofs actually held) applied to the fund drain. The
/// table below is EXHAUSTIVE over EVERY branch of this fn — the drain scan, the post-drain fresh-quote
/// poll loop, and the guards/outcome. Each row is either a funded-vs-not / amount decision that decides
/// on held-unspent-proofs, or an eligibility / refusal / identity branch that credits NOTHING (any
/// branch found in the code is on this list):
///
/// | Branch / path | What it decides | Signal it decides on | held-proofs? |
/// |---|---|---|---|
/// | (z) `amount_sats == 0` guard (pre-flight) | refuse (nothing to mint) | requested amount == 0 | N/A — input guard, credits nothing |
/// | (a) NUT-13 establishment guard | refuse to mint (derivation gated) | counter established? (pre-req) | N/A — gates derivation, credits nothing |
/// | (b) `recover_incomplete_sagas()` @ drain START | land in-flight/crashed issue-saga proofs BEFORE the scans | — (makes the held reads truthful); hard `Err` bails | ✓ its landed proofs feed every held check below |
/// | (b′) `check_recovery_report(report)` — FIX #1(a) | refuse to fresh-quote on an unclean recovery | `report.failed > 0 \|\| skipped > 0` | N/A — refusal; a stranded paid quote may remain, do not double-pay |
/// | (b″) ★ALL-QUOTES proofless-issued scan — FIX #1(b) | BAIL on a stranded paid-but-proofless quote INVISIBLE to get_unissued | for every quote with `amount_issued > 0`: **HELD unspent proofs == 0** | ✓ — decides purely on held proofs, report-independent; the definitive recovery-half close |
/// | (c) `get_unissued_mint_quotes()` + per-quote `check_mint_quote_status` | which pending quotes to classify | mint re-check | N/A — enumeration only, credits nothing |
/// | (d) loop arm `Paid` → `NeedsMint` | eligible-to-mint (drain) | state `Paid` gates minting; the CREDIT is the post-mint HELD sum (branch h) | ✓ funded amount is held/minted proofs, not state |
/// | (e) loop arm `Issued` → held>0 SUCCEED / held==0 BAIL (#1) | funded? + amount | **HELD unspent proofs for the quote** | ✓ — the crux; `Issued` alone NEVER funds |
/// | (f) loop arm `Unpaid` (explicit, exhaustive — no `_` catch-all) | not a candidate | `Unpaid` ⇒ never paid ⇒ holds nothing | ✓ Unpaid ⇒ 0 held by definition; compile-exhaustive over the 3-variant enum |
/// | (g) misattribution guard (`candidates.len() > 1`) | refuse (ambiguous attribution) | count of ALREADY-held-decided candidates | N/A — refusal; each candidate already held-decided |
/// | (h) resolve `NeedsMint` → `wallet.mint()`; drained==0 → BAIL | funded amount | proofs `mint()` PERSISTED (held, unspent) — never `amount_issued` | ✓ |
/// | (i) resolve `AlreadyHeld` → report `held_sats` | funded amount | **HELD unspent proofs sum** | ✓ |
/// | (j) `ensure_minted_matches_requested(funded, requested)` (resume path) | accept/refuse the fund | the HELD/minted funded amount vs requested | ✓ asserts on held, never on claim |
/// | (p) fresh `mint_quote()` (+ its failure → bail) | request a new bolt11 (no drain candidate) | — (creates the quote; failure bails, credits nothing) | N/A — no funding decision |
/// | (q) poll arm `Ok(Paid)` → `break` | eligible-to-mint (fresh) | state `Paid` gates minting; CREDIT is the post-mint HELD sum (branch k) | ✓ funded amount is minted proofs, not state |
/// | (r) poll arm `Ok(Issued)` → BAIL | refuse (minted elsewhere; nothing to mint) | state `Issued` on a fresh quote we never minted | N/A — refusal; credits nothing |
/// | (s) poll arm `Ok(_)` (Unpaid/pending) → continue | keep waiting | state not yet `Paid` | N/A — no decision; loops |
/// | (t) poll arm `Err(_)` → warn + retry | transient; keep waiting to the deadline | mint check error | N/A — no decision; loops |
/// | (u) poll timeout (`>= deadline`) → BAIL | refuse (not paid in time) | wall-clock deadline | N/A — refusal; credits nothing (quote persisted for a drain-resume) |
/// | (k) fresh-mint `wallet.mint()` → `minted_sats` | funded amount | proofs `mint()` PERSISTED (held, unspent) | ✓ |
/// | (j2) `ensure_minted_matches_requested(minted, requested)` (fresh path) | accept/refuse the fund | minted proofs vs requested | ✓ asserts on minted proofs, never on claim |
/// | (l) post-fresh-mint `minted_sats == 0` → BAIL | refuse silent-success-on-0 | held/minted proofs total | ✓ |
/// | (m) `FundWalletOutcome.minted_sats` | reported credit | = the held/minted funded amount (b–l) | ✓ |
/// | (n) `FundWalletOutcome.balance_sats` | reported total balance | `wallet.total_balance()` (all held proofs) | ✓ |
/// | (o) `FundWalletOutcome.quote_id` / `bolt11` | identity only | quote id / request string | N/A — no funding decision |
///
/// **Quote-visibility hiding paths** (every way a paid-but-proofless quote can hide) and their closure
/// — after rev-4 the closure is REPORT-INDEPENDENT: the all-quotes scan (b″) decides on held proofs
/// over EVERY quote regardless of the get_unissued filter or recovery completeness:
/// - `get_unissued_mint_quotes()` EXCLUDES bolt11 quotes once `amount_issued != 0`, and CDK's
///   `mint()` writes `amount_issued` BEFORE proofs ⇒ a crash in that gap leaves an issued-but-proofless
///   quote invisible to (c) → CLOSED by (b″): the all-quotes scan sees it (`amount_issued > 0`, held==0)
///   and bails; (b) also tries to land its proofs first, and (b′) refuses to proceed on an unclean recovery.
/// - in-flight / crashed issue sagas → (b) lands their proofs; (b′) bails if recovery is unclean; (b″) is the backstop.
/// - a COMPENSATED (rolled-back) saga that stays `amount_issued > 0` with no proofs → CLOSED by (b″).
/// - `Issued`-state quote still in the unissued list → closed by (e): decided on HELD proofs.
/// - partially-minted → (b″)/(e)/(h)/(i) sum only the still-Unspent held proofs (checked-sum, FIX #2).
pub async fn mint_into_wallet_operator_pays(
    wallet: &Wallet,
    counter_db: &crate::nip60_counter::Nip60CounterDb,
    amount_sats: u64,
    memo: &str,
    poll_interval: std::time::Duration,
    timeout: std::time::Duration,
    on_bolt11: impl FnOnce(&str),
) -> anyhow::Result<FundWalletOutcome> {
    use cdk::nuts::nut00::ProofsMethods as _;
    use cdk::nuts::MintQuoteState;

    if amount_sats == 0 {
        anyhow::bail!("fund-wallet: --amount-sats must be > 0 (nothing to mint)");
    }

    // 1) ★NUT-13 ESTABLISHMENT GUARD. A deferred counter gates every derivation at the choke point,
    //    so a mint would silently yield ZERO proofs. Refuse loudly BEFORE quoting — never report
    //    success on a wallet that cannot derive (the "silent-success-on-0" money bug this guards).
    if !counter_db.is_established() {
        anyhow::bail!(
            "fund-wallet: the NUT-13 counter is DEFERRED (not established) — every wallet \
             derivation is blocked at the choke point, so a mint would silently yield ZERO \
             proofs. This happens when NIP-60 is configured but the config read is below \
             read-quorum (a fresh-box restore that cannot safely establish the counter floor). \
             Run fund-wallet with NIP-60 OFF (empty `[nip60] relays`) so the counter establishes \
             immediately, or wait for a >=k config read. Refusing to mint into a deferred wallet."
        );
    }

    // 2) ★SAGA RECOVERY FIRST (#2 — crash-gap closure). `get_unissued_mint_quotes()` EXCLUDES a
    //    bolt11 quote once its LOCAL `amount_issued != 0`, and CDK's `mint()` writes `amount_issued`
    //    BEFORE the proofs persist — so a crash in that gap leaves an ISSUED-but-proofless quote
    //    INVISIBLE to the scan below, and a naive re-run would issue a FRESH invoice (double-pay)
    //    while its already-paid proofs are recoverable. We run the SAME boot-time recovery
    //    (rail `EcashProvider::recover_incomplete_sagas`, CDK `Wallet::recover_incomplete_sagas`;
    //    boot.rs calls it too) BEFORE the scan so any in-flight / crashed issue saga is completed
    //    and its proofs LAND FIRST; the per-quote held-proofs check then covers whatever recovery
    //    landed. Fail CLOSED on a recovery error: if we cannot recover, we cannot prove a stranded
    //    quote is not paid, and issuing a fresh invoice over it would double-pay.
    let recovery_report = wallet.recover_incomplete_sagas().await.map_err(|e| {
        anyhow::anyhow!(
            "fund-wallet: recovering incomplete mint sagas before the drain scan failed ({e}) — \
             refusing to issue a new invoice while a crash-gap issued-but-proofless quote may be \
             recoverable (a fresh invoice over it would double-pay). Resolve mint reachability and \
             re-run."
        )
    })?;
    // ★FIX #1 (a) CAPTURE the report — a hard `Err` is not the only failure. CDK returns `Ok(report)`
    //    even when `report.failed > 0` (unrecoverable) or `report.skipped > 0` (still pending). Refuse
    //    to fresh-quote unless recovery CLEANLY completed (see `check_recovery_report`).
    check_recovery_report(&recovery_report)?;

    // 2b) ★FIX #1 (b) THE DEFINITIVE, REPORT-INDEPENDENT CLOSE — an ALL-QUOTES proofless-issued scan
    //    BEFORE issuing any fresh quote. This is the RECOVERY half of the invariant, closed the SAME
    //    way the credit half was: a scan over EVERY mint quote deciding on HELD PROOFS — never on the
    //    `get_unissued` filter (which EXCLUDES `amount_issued != 0`) nor on recovery completeness.
    //    `get_unissued_mint_quotes()` (the drain scan below) cannot see a quote once `amount_issued != 0`
    //    (a crash-gap / compensated / failed-recovery / lost-response leaves exactly that), so a fresh
    //    invoice would DOUBLE-PAY over it. We enumerate ALL quotes for THIS wallet and BAIL on any that
    //    is ISSUED-against (`amount_issued > 0`) yet holds ZERO unspent proofs — a stranded paid quote.
    //    This single scan covers every hiding place at once, independent of the recovery report.
    let all_quotes = wallet.localstore.get_mint_quotes().await.map_err(|e| {
        anyhow::anyhow!(
            "fund-wallet: list ALL mint quotes for the proofless-issued scan ({e}) — refusing to \
             issue a new invoice while a stranded paid-but-proofless quote may be invisible to the \
             get_unissued drain scan (a fresh invoice over it would double-pay)."
        )
    })?;
    for q in &all_quotes {
        // Scope to THIS wallet (mint + unit), mirroring get_unissued's own filter.
        if q.mint_url != wallet.mint_url || q.unit != wallet.unit {
            continue;
        }
        // Only a quote the mint has ISSUED against (`amount_issued > 0`) can be a proofless-issued
        // stranded quote that hides from get_unissued; `amount_issued == 0` quotes are handled by the
        // get_unissued drain scan below (decided there on held proofs too).
        if u64::from(q.amount_issued) == 0 {
            continue;
        }
        // The 1a rail mechanism (checked-sum, FIX #2): held unspent proofs for THIS quote id.
        let (held, _found) = held_unspent_for_quote(wallet, &q.id).await?;
        if held == 0 {
            anyhow::bail!(
                "fund-wallet: mint quote {} is ISSUED against (amount_issued={}) but the wallet HOLDS \
                 NO unspent proofs for it — a stranded PAID-but-proofless quote INVISIBLE to the \
                 get_unissued drain scan (crash-gap / compensated / failed-recovery / lost \
                 mint-response). Refusing to issue a fresh invoice: it would DOUBLE-PAY the already-paid \
                 quote. Resolve this stranded quote out of band, then re-run.",
                q.id,
                u64::from(q.amount_issued)
            );
        }
    }

    // 3) ★DRAIN-FIRST (money-safety: timeout double-pay + phantom-credit guards) — EXPLICIT per-quote,
    //    every decision on HELD unspent proofs (see the invariant table above). If an operator paid
    //    the printed bolt11 AFTER this tool timed out, its quote sits Paid-but-unissued in the store;
    //    a naive re-run would issue a FRESH invoice (double payment) and strand the already-paid quote.
    //    We do NOT reuse `mint_unissued_quotes()`'s blind batch return (an `amount_issued` DELTA — the
    //    mint's book, which a lost mint-response inflates into a PHANTOM fund). We walk each pending
    //    quote by hand, re-check its state WITH THE MINT, and classify it into a funded CANDIDATE
    //    decided on HELD proofs:
    //      - Paid   → `NeedsMint`: mint EXPLICITLY below and count the proofs `mint()` PERSISTED into
    //                 the LOCAL store (held, unspent) — NEVER `amount_issued`.
    //      - Issued → decide on HELD proofs (#1): `check_mint_quote_status` can COMPLETE a crashed
    //                 issue saga and LAND proofs, THEN return `Issued`, so `Issued` alone must NOT bail.
    //                 held > 0 ⇒ `AlreadyHeld` (already funded; report the held sum, mint nothing more);
    //                 held == 0 ⇒ BAIL (genuine lost-response / stranded — we hold NOTHING, never a
    //                 phantom credit on the mint's `amount_issued`, never a fresh invoice).
    //      - Unpaid → not a drain candidate; leave it and fall through to a fresh quote. (The match is
    //                 EXHAUSTIVE over cdk 0.17.1's 3-variant `MintQuoteState` — NO `_` catch-all that
    //                 could silently drop a funded quote; a new CDK variant would fail to compile here,
    //                 forcing a re-audit.) Unpaid ⇒ never paid ⇒ holds nothing, so dropping it is correct.
    //    A check error means we cannot prove a pending quote is NOT paid, so we fail closed. MORE THAN
    //    ONE funded candidate cannot be unambiguously attributed to one quote id → BAIL.
    enum DrainCandidate {
        /// Paid at the mint, proofs NOT yet minted locally → mint (drain) then count the HELD sum.
        NeedsMint(cdk::wallet::MintQuote),
        /// Issued at the mint AND holds unspent proofs locally (a saga completed during the re-check
        /// landed them) → already funded; report the HELD sum, mint nothing more.
        AlreadyHeld { quote: cdk::wallet::MintQuote, held_sats: u64 },
    }
    impl DrainCandidate {
        fn quote_id(&self) -> &str {
            match self {
                DrainCandidate::NeedsMint(q) => &q.id,
                DrainCandidate::AlreadyHeld { quote, .. } => &quote.id,
            }
        }
    }

    let pending_before = wallet
        .get_unissued_mint_quotes()
        .await
        .map_err(|e| anyhow::anyhow!("fund-wallet: list unissued mint quotes (drain-first): {e}"))?;

    let mut candidates: Vec<DrainCandidate> = Vec::new();
    for q in &pending_before {
        let fresh = wallet.check_mint_quote_status(&q.id).await.map_err(|e| {
            anyhow::anyhow!(
                "fund-wallet: re-checking pending mint quote {} with the mint failed ({e}) — refusing \
                 to issue a new invoice while a prior quote's paid state is unknown (a fresh invoice \
                 over a stranded PAID quote would double-pay). Pay/resolve the printed invoice and \
                 re-run.",
                q.id
            )
        })?;
        match fresh.state {
            MintQuoteState::Paid => candidates.push(DrainCandidate::NeedsMint(fresh)),
            MintQuoteState::Issued => {
                // ★#1 — decide on HELD proofs, NEVER on `state == Issued`. `check_mint_quote_status`
                // (above) can complete a crashed issue saga and LAND proofs into the LOCAL store,
                // then return `Issued`; bailing on the state alone would false-bail a genuinely-funded
                // quote. Sum the HELD unspent proofs for THIS quote id (the 1a rail mechanism):
                //   held > 0 ⇒ already funded — resume this EXACT quote, report the held sum.
                //   held == 0 ⇒ genuine lost-response / stranded (mint claims Issued, we hold NOTHING):
                //              BAIL — never a phantom credit on `amount_issued`, never a fresh invoice.
                let (held, _found) = held_unspent_for_quote(wallet, &fresh.id).await?;
                if held > 0 {
                    candidates.push(DrainCandidate::AlreadyHeld { quote: fresh, held_sats: held });
                } else {
                    anyhow::bail!(
                        "fund-wallet: pending mint quote {} is ISSUED at the mint but the wallet HOLDS \
                         NO unspent proofs for it (a lost mint-response / recovery failure — recovery \
                         ran and still landed nothing). Refusing to report a PHANTOM fund on the mint's \
                         claimed amount_issued — we credit ONLY proofs actually held — and refusing to \
                         issue a new invoice. Resolve this stranded quote out of band.",
                        fresh.id
                    );
                }
            }
            // Unpaid ⇒ never paid ⇒ holds nothing: not a drain candidate. Fall through to a fresh
            // quote below. (Exhaustive over the 3-variant enum — no catch-all silent drop.)
            MintQuoteState::Unpaid => {}
        }
    }

    if candidates.len() > 1 {
        // ★MISATTRIBUTION GUARD: more than one funded candidate (each already decided on held proofs)
        // is pending, so a drained fund cannot be attributed to ONE quote id — and a blind aggregate
        // could satisfy `== requested` across UNRELATED quotes. Refuse rather than guess (first()).
        let ids: Vec<&str> = candidates.iter().map(|c| c.quote_id()).collect();
        anyhow::bail!(
            "fund-wallet: {} paid-but-unissued mint quotes are pending ({ids:?}) — cannot unambiguously \
             attribute a fund to a single quote, and refusing to blindly aggregate-drain across \
             unrelated quotes (misattribution guard). Mint/resolve the stray quotes out of band, then \
             re-run.",
            candidates.len()
        );
    }

    if let Some(candidate) = candidates.into_iter().next() {
        // Exactly ONE funded candidate: resolve it, computing the credited amount from HELD proofs.
        let (quote, funded_sats) = match candidate {
            DrainCandidate::NeedsMint(quote) => {
                // Paid → DRAIN it EXPLICITLY. `wallet.mint()` returns the proofs it PERSISTED into the
                // LOCAL store (held, unspent) — count those, NEVER the mint's `amount_issued`.
                let proofs = wallet
                    .mint(&quote.id, SplitTarget::default(), None)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("fund-wallet: drain (mint) the paid-but-unissued quote {}: {e}", quote.id)
                    })?;
                let drained_sats: u64 = proofs
                    .total_amount()
                    .map_err(|e| anyhow::anyhow!("fund-wallet: total the drained proofs for {}: {e}", quote.id))?
                    .into();

                // ★PHANTOM-CREDIT SECOND GUARD (defence in depth): a PAID quote that yielded ZERO
                // local proofs means nothing actually landed — never report a fund not received.
                if drained_sats == 0 {
                    anyhow::bail!(
                        "fund-wallet: draining the paid quote {} yielded ZERO local proofs — refusing to \
                         report a fund the wallet did not receive (phantom credit).",
                        quote.id
                    );
                }
                (quote, drained_sats)
            }
            DrainCandidate::AlreadyHeld { quote, held_sats } => {
                // Issued AND proofs already landed (saga completed during the re-check): the credit is
                // the HELD sum computed above — mint NOTHING more (re-minting an Issued quote is a no-op
                // / error). This is the #1 fix: an Issued-with-held-proofs quote SUCCEEDS, not bails.
                (quote, held_sats)
            }
        };

        // FIX 3: a BOLT11 quote mints its FULL amount (LN fees are payer-side), so a funded amount
        // != requested is a mismatch we refuse rather than silently under/over-report the fund.
        ensure_minted_matches_requested(funded_sats, amount_sats, &quote.id)?;

        let balance_sats: u64 = wallet
            .total_balance()
            .await
            .map_err(|e| anyhow::anyhow!("fund-wallet: read the wallet balance after draining: {e}"))?
            .into();
        tracing::info!(
            quote_id = %quote.id,
            funded_sats,
            "fund-wallet: RESUMED a prior paid-but-unissued quote from HELD proofs (its EXACT quote id) \
             — issued NO new invoice"
        );
        return Ok(FundWalletOutcome {
            bolt11: quote.request,
            quote_id: quote.id,
            minted_sats: funded_sats,
            balance_sats,
        });
    }

    // 3) A NUT-04 BOLT11 mint quote: the mint returns a bolt11 an operator pays with any Lightning
    //    wallet. The quote id is the handle we poll + mint by (mirrors the rail's `issue`).
    let quote = wallet
        .mint_quote(
            PaymentMethod::BOLT11,
            Some(Amount::from(amount_sats)),
            Some(memo.to_string()),
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("fund-wallet: request a bolt11 mint quote: {e}"))?;

    // PERSIST + PRINT the quote id: it is already persisted in the wallet store by `mint_quote`;
    // logging it (and naming it in the timeout bail below) lets an operator RESUME this exact quote
    // via the drain-first step on a re-run instead of paying a fresh invoice.
    tracing::info!(
        quote_id = %quote.id,
        amount_sats,
        "fund-wallet: created bolt11 mint quote (persisted); a re-run resumes it via drain-first"
    );

    on_bolt11(&quote.request);

    // 4) Poll the MINT for the quote's state until PAID (an operator pays the bolt11 out of band).
    //    Bounded by `timeout`; a check error is transient (retry until the deadline), a terminal
    //    Issued state is a hard error (already minted elsewhere).
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match wallet.check_mint_quote_status(&quote.id).await {
            Ok(q) if q.state == MintQuoteState::Paid => break,
            Ok(q) if q.state == MintQuoteState::Issued => anyhow::bail!(
                "fund-wallet: mint quote {} is already ISSUED (its proofs were minted elsewhere) \
                 — nothing left to mint",
                quote.id
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(
                quote_id = %quote.id,
                error = %e,
                "fund-wallet: transient error checking the mint quote status; retrying"
            ),
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "fund-wallet: timed out after {:?} waiting for the bolt11 mint quote {} to be \
                 PAID. Pay the printed invoice and re-run, or raise the timeout.",
                timeout,
                quote.id
            );
        }
        tokio::time::sleep(poll_interval).await;
    }

    // 5) PAID: mint the ecash into the wallet. The summed proofs are the mint-VERIFIED amount (the
    //    ONLY sanctioned source, mirroring the rail — never the requested `amount_sats`).
    let proofs = wallet
        .mint(&quote.id, SplitTarget::default(), None)
        .await
        .map_err(|e| anyhow::anyhow!("fund-wallet: mint the bolt11-settled ecash for {}: {e}", quote.id))?;
    let minted_sats: u64 = proofs
        .total_amount()
        .map_err(|e| anyhow::anyhow!("fund-wallet: total the minted proofs: {e}"))?
        .into();

    // ★FIX 3: minted MUST equal requested. A NUT-04 BOLT11 mint quote issues the FULL quote amount
    //    (LN routing fees are payer-side, never minted-side), so `minted < requested` is a SILENT
    //    under-fund and `minted > requested` an anomaly — either way we bail rather than report a
    //    fund that does not match what was asked for.
    ensure_minted_matches_requested(minted_sats, amount_sats, &quote.id)?;

    // 6) SECOND guard (defence in depth): the establishment check above should make this
    //    unreachable, but a 0-proof mint means derivation was silently gated — bail rather than
    //    claim success on a wallet that gained nothing.
    if minted_sats == 0 {
        anyhow::bail!(
            "fund-wallet: the mint yielded ZERO proofs for a PAID quote ({}) — the NUT-13 \
             derivation was gated. Refusing to report a successful fund on 0 minted sats.",
            quote.id
        );
    }

    let balance_sats: u64 = wallet
        .total_balance()
        .await
        .map_err(|e| anyhow::anyhow!("fund-wallet: read the wallet balance after minting: {e}"))?
        .into();

    Ok(FundWalletOutcome {
        bolt11: quote.request,
        quote_id: quote.id,
        minted_sats,
        balance_sats,
    })
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
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true, false)
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
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true, false)
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
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true, false)
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

        let (read, dropped) = read_local_keyset_counters(&db_path);

        assert_eq!(
            read,
            HashMap::from([(k1, 7u32), (k2, 3u32)]),
            "the SELECT reads EXACTLY cdk's keyset_counter rows over a concurrent second connection; \
             an empty/wrong map here means the on-disk schema drifted from the hard-coded SELECT"
        );
        assert!(!dropped, "a clean read of well-formed rows is NOT holey (category (d))");
        drop(store);
    }

    // ---- T6 FAIL-SAFE: any read error → empty map, never a panic. ---------------------------------
    #[tokio::test]
    async fn t6_read_local_keyset_counters_is_fail_safe_on_missing_db_and_missing_table() {
        // (a) A path with no db file at all → empty, no panic.
        let tmp = TempDir::new("t6a");
        let missing = tmp.db_path();
        assert!(!missing.exists(), "precondition: no db file yet");
        let (missing_map, missing_dropped) = read_local_keyset_counters(&missing);
        assert!(
            missing_map.is_empty(),
            "a nonexistent db path yields an empty map (fail-safe), not a panic"
        );
        assert!(missing_dropped, "a whole-read failure is HOLEY (dropped=true → establishment defers, category (d))");

        // (b) A real sqlite file that LACKS the keyset_counter table → the SELECT errors → empty.
        let tmp2 = TempDir::new("t6b");
        let no_table = tmp2.db_path();
        {
            let conn = rusqlite::Connection::open(&no_table).expect("create bare sqlite db");
            conn.execute_batch("CREATE TABLE unrelated (x INTEGER);")
                .expect("make a table-less-of-keyset_counter db");
        }
        let (no_table_map, no_table_dropped) = read_local_keyset_counters(&no_table);
        assert!(
            no_table_map.is_empty(),
            "a db missing the keyset_counter table yields an empty map (fail-safe), not a panic"
        );
        assert!(no_table_dropped, "a missing-table read is HOLEY (dropped=true, category (d))");
    }

    // ---- T27 (config-plane ROUND-4, category (d), LOCAL-SOURCE half): `read_local_keyset_counters`
    // SIGNALS an incomplete read. A corrupt row (unparseable keyset id) is skipped AND `dropped=true`;
    // a genuinely-empty table (fresh box) is `dropped=false` (NOT holey, just new). This is the local
    // read source the establishment guard (`floor_complete`) fails-closed on.
    //
    // RED-on-revert: stop setting `dropped=true` on a skipped corrupt row (return `false`) → the
    // corrupt-row read looks complete → the caller establishes on a holey local floor → the dropped
    // keyset derives from index 0 = NUT-13 reuse → this `dropped` assert fails → RED.
    #[tokio::test]
    async fn t27_local_keyset_read_signals_a_dropped_corrupt_row() {
        // (a) A corrupt row (keyset_id NOT valid hex) → skipped + dropped=true.
        let tmp = TempDir::new("t27-corrupt");
        let db_path = tmp.db_path();
        {
            let conn = rusqlite::Connection::open(&db_path).expect("create sqlite db");
            conn.execute_batch(
                "CREATE TABLE keyset_counter (keyset_id TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0);\
                 INSERT INTO keyset_counter (keyset_id, counter) VALUES ('009a1f293253e41e', 5);\
                 INSERT INTO keyset_counter (keyset_id, counter) VALUES ('not-a-valid-keyset-hex', 9);",
            )
            .expect("seed a keyset_counter table with one good + one corrupt row");
        }
        let (map, dropped) = read_local_keyset_counters(&db_path);
        assert!(dropped, "a skipped corrupt row marks the read HOLEY (revert dropped→false → RED)");
        assert_eq!(map.len(), 1, "only the well-formed row is read; the corrupt one is skipped");

        // (b) A genuinely-empty table (fresh box) → NOT holey.
        let tmp2 = TempDir::new("t27-empty");
        let empty_path = tmp2.db_path();
        {
            let conn = rusqlite::Connection::open(&empty_path).expect("create sqlite db");
            conn.execute_batch(
                "CREATE TABLE keyset_counter (keyset_id TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0);",
            )
            .expect("seed an EMPTY keyset_counter table");
        }
        let (empty_map, empty_dropped) = read_local_keyset_counters(&empty_path);
        assert!(empty_map.is_empty(), "a fresh box has no local counters");
        assert!(!empty_dropped, "a genuinely-empty table is NOT holey (a fresh box must still establish)");
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
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, false, true, true, false)
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
            open_persistent_wallet("http://127.0.0.1:1", &db_path, test_seed(), floor, true, true, true, false)
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
            false, // config_floor_dropped = false (clean floor)
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
            false, // config_floor_dropped = false (clean floor)
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

    // ---- FIX 3 (silent under-funding guard): minted MUST equal requested. -----------------------
    // The shared invariant called by BOTH the fresh-mint path and the drain-first resume path. A
    // BOLT11 mint issues the FULL quote amount, so minted < requested is a silent under-fund and
    // any mismatch is refused.
    //
    // RED-on-revert: make `ensure_minted_matches_requested` always return `Ok(())` (drop the assert)
    // → the `minted < requested` case below no longer errors → `is_err()` goes false → RED.
    #[test]
    fn fix3_minted_must_equal_requested_or_it_bails() {
        // Exact match → Ok (the happy path, no false bail).
        assert!(
            ensure_minted_matches_requested(5_000, 5_000, "q-ok").is_ok(),
            "minted == requested is the correct fund → Ok"
        );
        // Under-fund (minted < requested) → BAIL (the silent under-funding this guards).
        let under = ensure_minted_matches_requested(4_999, 5_000, "q-under");
        assert!(
            under.is_err(),
            "★ minted < requested (under-fund) MUST bail — revert the assert → this is Ok → RED"
        );
        assert!(
            format!("{:#}", under.unwrap_err()).contains("under-funded"),
            "the bail names the under-fund cause"
        );
        // Over-mint (minted > requested) → also bail (an anomaly, never silently accepted).
        assert!(
            ensure_minted_matches_requested(5_001, 5_000, "q-over").is_err(),
            "minted > requested is an anomaly → bail"
        );
    }

    // ---- FIX #2 (task #59): checked_held_sum FAILS CLOSED on u64 overflow, never wraps. ----------
    // A raw `iter.map(u64::from).sum::<u64>()` WRAPS in release (reporting a wrong, small held amount);
    // the checked sum returns Err instead. RED-on-revert: replace the `Amount::try_sum` body with a raw
    // `amounts.into_iter().map(u64::from).sum::<u64>()` → the overflowing set wraps to a small value and
    // returns Ok(that) instead of Err → this `is_err()` assert goes false → RED.
    #[test]
    fn fix2_checked_held_sum_fails_closed_on_overflow() {
        // A normal held set sums exactly (no false bail).
        let ok = checked_held_sum([Amount::from(1_000u64), Amount::from(2_048u64)])
            .expect("a normal held set does not overflow");
        assert_eq!(ok, 3_048, "the checked sum totals a normal held set exactly");

        // An overflowing set (u64::MAX + 1) MUST fail closed (Err), never wrap to a small value.
        let overflow = checked_held_sum([Amount::from(u64::MAX), Amount::from(1u64)]);
        assert!(
            overflow.is_err(),
            "★ an overflowing held set MUST fail closed (Err) — revert to a raw u64 `.sum()` → it WRAPS \
             to a small value and returns Ok → RED (task #59: checked held-sum)"
        );
    }

    // ---- FIX #1(a): check_recovery_report BAILS on an unclean recovery (failed/skipped > 0). ------
    // CDK returns Ok(report) even when it left work undone; the drain must refuse to fresh-quote then.
    // RED-on-revert: make check_recovery_report always return Ok (drop the failed/skipped bail) → the
    // failed/skipped cases below no longer error → their `is_err()` asserts go false → RED.
    #[test]
    fn fix1a_check_recovery_report_bails_on_failed_or_skipped() {
        use cdk::wallet::RecoveryReport;
        // A clean recovery (recovered/compensated only) does NOT block the drain.
        let clean = RecoveryReport { recovered: 3, compensated: 1, skipped: 0, failed: 0 };
        assert!(check_recovery_report(&clean).is_ok(), "a clean recovery proceeds (recovered/compensated ok)");
        assert!(check_recovery_report(&RecoveryReport::default()).is_ok(), "an empty recovery is clean");

        // failed > 0 → BAIL (a saga could not be recovered; a stranded paid quote may remain).
        let failed = RecoveryReport { recovered: 0, compensated: 0, skipped: 0, failed: 1 };
        assert!(check_recovery_report(&failed).is_err(), "★ failed > 0 must bail — revert → Ok → RED");
        // skipped > 0 → BAIL (a saga still pending; cannot prove no stranded paid quote exists).
        let skipped = RecoveryReport { recovered: 0, compensated: 0, skipped: 2, failed: 0 };
        assert!(check_recovery_report(&skipped).is_err(), "★ skipped > 0 must bail — revert → Ok → RED");
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
