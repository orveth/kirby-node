//! The daemon-owned, persisted, unforgeable treasury (spec 3.2, 4.2, D-9, D-20).
//!
//! The treasury is a single authoritative counter `remaining_sats` that lives
//! ON THE DAEMON (host), never in the VM. The genome can observe it (the
//! `treasury_remaining` field on a receipt) but cannot mutate it: NO gateway RPC
//! or genome-reachable path adds, sets, or subtracts `remaining`. Every mutating
//! method (`debit_metered`, `debit_and_record`, `credit_verified`,
//! `reconcile_to_observed`) is reachable only from daemon-side code that holds a
//! `&Treasury`. This is the unforgeability core (D-9, gate G3b).
//!
//! Two daemon-only paths RAISE (or, for a sync, SET) the balance, and neither
//! widens the genome's authority by one sat -- the only callers are host code:
//!
//! `credit_verified` -- the sole idempotent ADD (a verified inbound settlement):
//! - Callable only by daemon-side settlement-verification code holding a
//!   `&Treasury` (e.g. the host has independently verified an inbound ecash /
//!   lightning settlement). NO gateway RPC reaches it -- the genome cannot ASSERT
//!   a credit any more than it can assert a debit; a self-reported "I was paid"
//!   over ReportEvent moves nothing (gate G3c).
//! - Idempotent on `credit_id`: a re-delivered settlement, or a daemon restart
//!   mid-verify, credits EXACTLY ONCE (the no-double-credit wall, deduped inside
//!   the same transaction that mutates the balance).
//! - Never wraps: an add that would overflow u64 is refused with no mutation.
//!
//! `reconcile_to_observed` -- a daemon-only SET that syncs the counter to an
//! externally-probed spendable truth (BOTH directions), for the prepaid-key brain
//! where the external key balance is authoritative. Callable only by daemon-side
//! boot code holding a `&Treasury` (no gateway RPC); the caller MUST pass a
//! verified, successful probe and is fail-closed on a failed / zero reading. It is
//! idempotent -- re-observing the same total is a no-op.
//!
//! Invariants this module enforces (spec 4.2):
//! - Unforgeable: only daemon-side code debits or credits; no genome-reachable
//!   path adds, sets, or subtracts balance.
//! - Never-negative / never-overspend: a debit that would drive the balance
//!   below zero is refused BEFORE it happens (and, per the gateway order, before
//!   the act). The estimate gate refuses pre-perform; the post-perform debit is
//!   capped at the estimate (D-20) so it can never exceed what was checked.
//! - Idempotent across resume: a `RequestCapability` carries an idempotency_key;
//!   a re-issue of an already-performed key returns the stored receipt and
//!   performs nothing.
//! - Atomic debit+receipt: the balance decrement and the receipt record persist
//!   together in one transaction, so a crash between them cannot leave value
//!   debited with no receipt or an act recorded with no debit.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sled::transaction::{ConflictableTransactionError, TransactionError};
use sled::Transactional;

/// Sled key for the authoritative balance (a single u64, big-endian).
const BALANCE_KEY: &[u8] = b"remaining_sats";

/// The `proof` marker on a credit row that CREDITED the balance (the normal path).
/// Distinguishes a genuine credit from the terminal-overflow marker below when a
/// stored `credit_ledger` row is read back.
const CREDIT_PROOF_MARKER: &[u8] = b"credit-verified";

/// The `proof` marker on a TERMINAL settlement row written when a credit OVERFLOWED
/// (finding-2). An overflow means the token was ALREADY redeemed into the wallet but
/// the u64 add would wrap, so NOTHING was credited -- yet the charge must never reach
/// the wallet again (drain-only discipline: a redeemed token is spent for good). This
/// row is the durable terminal wall: it credits NOTHING (it is NOT a credit row) but
/// `credit_lookup` surfaces it and `credit_verified`'s in-txn dedupe honours it, so a
/// retry with a fresh token short-circuits to `CreditOutcome::Terminal` and never
/// redeems again. It reuses the `PerformedRecord` shape (the only serde row type in
/// this db) with this distinguishing proof marker and `cost_sats = 0`.
const CREDIT_TERMINAL_OVERFLOW_MARKER: &[u8] = b"credit-terminal-overflow";

/// Errors the treasury surfaces to the daemon. These are host-side faults
/// (storage, encoding), never genome-driven outcomes: a genome that asks for
/// too much gets a DENIED receipt, not an error.
#[derive(Debug, thiserror::Error)]
pub enum TreasuryError {
    #[error("treasury storage error: {0}")]
    Storage(#[from] sled::Error),
    #[error("treasury value is corrupt: {0}")]
    Corrupt(String),
}

/// Whether a `TreasuryError` is a transient sled lock contention (a same-host
/// reopen racing the prior holder's still-reclaiming flock) rather than a real
/// fault. sled (0.34) reports a failed `flock` as
/// `Error::Io(ErrorKind::Other, "could not acquire lock on <path>: <WouldBlock>")`,
/// folding the underlying `WouldBlock` into the message rather than the outer io
/// kind, so the stable discriminator is that message. Any other storage error
/// (corruption, a real I/O fault) is NOT lock contention and must not be retried.
///
/// Lives here (platform-independent — it only inspects a `TreasuryError`) so the
/// Linux-only orchestration retry loops and the cross-platform `boot`
/// treasury-reopen retry can share it without dragging Linux orchestration onto
/// macOS.
pub(crate) fn is_lock_contention(err: &TreasuryError) -> bool {
    matches!(
        err,
        TreasuryError::Storage(sled::Error::Io(io))
            if io.to_string().contains("could not acquire lock")
    )
}

/// A persisted record of one performed capability, keyed by idempotency_key.
/// Storing the whole receipt (not just a flag) lets a resume-replay return the
/// exact prior receipt (spec step 1, gate G9).
///
/// `completion` (brain-stub R1) holds the assistant reply TEXT for a Completion act
/// (empty for every other act), so a post-resume `DUPLICATE_IGNORED` replay returns
/// the WORDS the brain needs, not just the proof. It is `#[serde(default)]` so an
/// OLD-shape record (the `{cost_sats, treasury_remaining_after, proof}` rows already
/// persisted in sled before this field existed) still deserializes on resume -- it
/// decodes with an empty completion, never a decode error.
///
/// `memory` (durable-mind-state) holds the prost-encoded `MemoryResult` for a Memory
/// WRITE act (empty for every other act, and never recorded for a free READ -- reads
/// bypass the ledger entirely, design doc 12 G3), so a post-resume `DUPLICATE_IGNORED`
/// write replay returns the SAME structured result, not just the proof. It is the LAST
/// field and `#[serde(default)]` for the EXACT same reason `completion` is: an older
/// record (incl. every brain-era row, which has `completion` but no `memory`) still
/// deserializes on resume, decoding with an empty `memory`, never a decode error.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformedRecord {
    pub cost_sats: u64,
    pub treasury_remaining_after: u64,
    pub proof: Vec<u8>,
    #[serde(default)]
    pub completion: Vec<u8>,
    #[serde(default)]
    pub memory: Vec<u8>,
    /// R2-4 (content-aware dedupe, defense-in-depth): a deterministic hash over the
    /// EFFECTIVE request that produced this record (for a Memory WRITE: op+slug+value).
    /// The gateway STEP-1 dedupe validates an incoming request's hash against this
    /// before returning `DUPLICATE_IGNORED`, so a same-key replay carrying DIFFERENT
    /// content -- a wseq desync / stale-checkpoint collision (the F1 bug class) -- is
    /// REFUSED, not silently served the prior result. Empty for acts that compute no
    /// hash (every non-Memory act today), which the validator treats as "skip".
    /// `#[serde(default)]` + LAST field for the SAME back-compat reason as
    /// `completion`/`memory`: an older row (no `request_hash`) deserializes with an
    /// empty hash on resume, never a decode error.
    #[serde(default)]
    pub request_hash: Vec<u8>,
}

/// A READ-ONLY economics snapshot derived from the treasury's own ledgers plus the caller's
/// authoritative rent + initial figures. NOT a money door: nothing here mutates the balance -- it
/// only reads trees that already exist, so the report surfaces (B2) and the runway estimate can
/// reason over one consistent view. `rent_sats` (the meter's cumulative `burned_sats`) and
/// `initial_sats` (the genesis budget) are the CALLER's authoritative figures; the treasury does
/// not hold them (rent lives in the meter, initial in config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicsSnapshot {
    /// The live balance == [`Treasury::remaining`] (the ground truth).
    pub remaining_sats: u64,
    /// Total mint-verified income this life. DERIVED from the balance identity
    /// (`remaining + spent + rent - initial`) -- the read-only equivalent of summing credits.
    /// A credit row records NO amount (its `cost_sats` is 0), so income cannot be summed
    /// directly; but `credit_verified` is the ONLY balance-raising path besides `initial`, so the
    /// identity recovers it exactly. Because it is derived from the DAEMON's authoritative balance
    /// and ledger (never a genome-supplied number), a genome cannot inflate it (the no-self-credit
    /// property is structural). CAVEAT: `reconcile_to_observed` SETS the balance out-of-band,
    /// which would break this derivation; the cashu treasury the oracle uses never calls it (that
    /// path is the prepaid-Routstr-key brain's).
    pub income_sats: u64,
    /// Total capability-act spend this life == Σ of the debit `ledger` rows' `cost_sats` (think +
    /// egress + publish + memory writes). EXCLUDES rent: rent debits via `debit_metered`, which
    /// writes NO ledger row, so it never appears here (and is passed in separately as `rent_sats`).
    pub spent_sats: u64,
    /// The count of genuine settled credits (credit rows carrying the credit-verified proof
    /// marker; terminal-overflow markers are excluded -- they credited nothing). "How many
    /// strangers actually paid."
    pub jobs_settled: u64,
}

/// The daemon-owned treasury. Cheap to clone (an `Arc` over the sled handles),
/// so the gateway service can hold one per VM/CID.
#[derive(Clone)]
pub struct Treasury {
    inner: Arc<Inner>,
}

struct Inner {
    /// Single-value tree holding `remaining_sats`.
    balance: sled::Tree,
    /// idempotency_key -> PerformedRecord (the dedupe ledger for DEBITS / capability
    /// acts). These keys are genome-supplied (the `idempotency_key` on a
    /// `CapabilityRequest`) and free-form.
    ledger: sled::Tree,
    /// credit_id -> credit row (the dedupe ledger for CREDITS). A SEPARATE tree from
    /// `ledger` on purpose: credit_ids are daemon-assigned settlement ids, and keeping
    /// them in their own tree makes the credit namespace STRUCTURALLY disjoint from the
    /// genome-supplied capability keys (a genome cannot pre-occupy a credit key by
    /// choosing a colliding `idempotency_key`), and keeps `lookup()` /
    /// `max_idempotency_seq` (which scan only `ledger`) blind to credits.
    credit_ledger: sled::Tree,
    /// charge_id -> a single method-tag byte: the DURABLE, daemon-owned index of ISSUED charges
    /// (#62). A THIRD tree, disjoint from both `ledger` and `credit_ledger` ON PURPOSE: it is the
    /// settlement poller's poll SOURCE, and ONLY `authorize_issue_charge` (the one IssueCharge act)
    /// writes it, via `record_issued_charge`. Sourcing the poll set structurally from THIS tree —
    /// not from a scan of the polymorphic `ledger` `proof` field, which non-charge acts also write
    /// (a generic/brain/memory/capability row) — means a non-charge proof can NEVER be mistaken for
    /// a charge and falsely credited: it simply has no key here (money-safety, #2). The value byte
    /// records the charge's settlement rail (see `ChargeMethodTag`) so the Lightning poller filters
    /// to Lightning charges only (#4). PROTO-FREE: the gateway maps the proto `ChargeMethod` to the
    /// plain tag byte before calling in, so the treasury core carries no `kirby_proto`/`prost` dep.
    issued_charges: sled::Tree,
    /// Held so the database is flushed and dropped with the treasury.
    db: sled::Db,
    /// The cumulative metered VM-rent burned THIS RUN (Σ of the actual amounts `debit_metered`
    /// debited). Rent leaves NO ledger row (it debits via `debit_metered`, spec 3.3), so it is
    /// otherwise invisible to a treasury reader; this in-memory accumulator is the ONE place the
    /// rent total is recoverable from the treasury handle. B2 needs it because the read-only
    /// economics surfaces (the BOOKS DM composed in the gateway; the 31000 emitter) both derive
    /// income via the balance identity `income = remaining + spent + rent - initial`, which
    /// requires the SAME authoritative rent on every surface. Fed ONLY by `debit_metered` (the
    /// daemon's meter path — never a genome act), so it cannot be inflated by a self-report. It is
    /// per-run in-memory (NOT persisted), matching the meter's `burned_sats` semantics: a resume
    /// starts it at 0 exactly as a fresh `Meter` does, so the two stay byte-equal. Shared across
    /// treasury clones via the `Arc<Inner>`, so the gateway (a clone) reads the meter's live rent.
    /// CAVEAT (keeper follow-up): because rent is per-run while the balance persists, the reconcile
    /// identity is exact only WITHIN a run (design §B.3 "within one in-flight tick"); after a RESUME
    /// the balance already reflects the prior run's rent but this counter is 0, so income would be
    /// over-derived by that prior rent. Persisting rent would DIVERGE it from the meter's per-run
    /// `burned_sats` (which the runway rate + G2 evidence depend on), so the fix is a keeper call,
    /// not a unilateral B2 change. B2's live surfaces (a running agent's books) reconcile exactly.
    rent_sats: AtomicU64,
    /// A read-only DISPLAY hint: the seconds-to-broke the daemon's meter loop last computed
    /// (`estimate_runway_secs`, the SAME runway the 31000 emitter publishes). NOT a ledger
    /// quantity and NEVER read by the money path — it exists solely so the per-call BOOKS percept
    /// composed in the gateway (which has no burn-rate clock of its own) can surface the live
    /// runway the metered run computes. `u64::MAX` is the sentinel for "unknown" (`None`): the
    /// initial value and what the loop publishes until a burn rate is established. Shared across
    /// clones via the `Arc<Inner>`; published by [`Treasury::publish_runway_hint`], read by
    /// [`Treasury::runway_secs_hint`].
    runway_hint: AtomicU64,
}

/// The `runway_hint` sentinel meaning "unknown" (serialized as a `None`/null runway).
const RUNWAY_HINT_UNKNOWN: u64 = u64::MAX;

/// The profit margin = `income / (spent + rent)`, or `None` when no cost has been incurred yet
/// (there is nothing to be a margin OVER — avoids a divide-by-zero and a bogus infinite margin).
/// A single source so BOTH economics surfaces (the gateway BOOKS percept and the 31000 emitter)
/// compute the ratio identically. `> 1.0` is profit; `< 1.0` is running at a loss this life.
pub fn margin_ratio(income_sats: u64, spent_sats: u64, rent_sats: u64) -> Option<f64> {
    let cost = spent_sats.saturating_add(rent_sats);
    if cost == 0 {
        None
    } else {
        Some(income_sats as f64 / cost as f64)
    }
}

/// The settlement RAIL a charge was issued on, persisted as a single byte in the treasury's
/// `issued_charges` index (#62). PROTO-FREE by design: the treasury core carries no
/// `kirby_proto`/`prost` dependency, so the gateway (the proto-aware layer) maps the proto
/// `ChargeMethod` to this plain tag before calling [`Treasury::record_issued_charge`]. The Lightning
/// settlement poller filters the poll set to [`ChargeMethodTag::Lightning`] (a Cashu charge is
/// settled by token evidence, never the `settle_charge(id, "")` mint-quote poll — #4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeMethodTag {
    /// A bolt11 / mint-quote (Lightning) charge — the `settle_charge(id, "")` poll path.
    Lightning,
    /// A Cashu charge — settled by token evidence, NOT polled on the Lightning path.
    Cashu,
}

impl ChargeMethodTag {
    /// The single byte persisted in `issued_charges`. Non-zero so an absent/empty value can never
    /// be silently read as a valid tag.
    fn as_byte(self) -> u8 {
        match self {
            ChargeMethodTag::Lightning => 1,
            ChargeMethodTag::Cashu => 2,
        }
    }

    /// Decode a persisted tag byte; `None` for any unknown byte (a corrupt/foreign value is never
    /// mistaken for a rail — the poller then skips that row rather than guessing).
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(ChargeMethodTag::Lightning),
            2 => Some(ChargeMethodTag::Cashu),
            _ => None,
        }
    }
}

impl Treasury {
    /// Open (or create) a persisted treasury at `path`, seeding the balance to
    /// `initial_sats` ONLY if it does not already exist. On a resume from an
    /// existing store the persisted balance and ledger are authoritative and the
    /// seed is ignored, so resume does not silently refill the treasury.
    ///
    /// This is the one and only place a balance is established, and it is
    /// daemon-side at boot. It takes no genome input.
    pub fn open(path: impl AsRef<Path>, initial_sats: u64) -> Result<Self, TreasuryError> {
        let db = sled::open(path)?;
        let balance = db.open_tree("balance")?;
        let ledger = db.open_tree("ledger")?;
        let credit_ledger = db.open_tree("credit_ledger")?;
        let issued_charges = db.open_tree("issued_charges")?;

        // Seed only on first creation. compare_and_swap with expected None makes
        // this idempotent across daemon restarts and resumes: the outer result
        // is a storage error (propagated); the inner Err means a value already
        // exists, i.e. a resume from a persisted treasury, so the seed is
        // correctly ignored and the persisted balance stays authoritative.
        let _ = balance.compare_and_swap(
            BALANCE_KEY,
            None as Option<&[u8]>,
            Some(&initial_sats.to_be_bytes()),
        )?;
        db.flush()?;

        Ok(Treasury {
            inner: Arc::new(Inner {
                balance,
                ledger,
                credit_ledger,
                issued_charges,
                db,
                rent_sats: AtomicU64::new(0),
                runway_hint: AtomicU64::new(RUNWAY_HINT_UNKNOWN),
            }),
        })
    }

    /// Open a treasury backed by a temporary in-memory store. Used by tests and
    /// by harnesses that do not need persistence across a process restart. The
    /// money-path logic is identical to the on-disk path.
    pub fn open_temporary(initial_sats: u64) -> Result<Self, TreasuryError> {
        let db = sled::Config::new().temporary(true).open()?;
        let balance = db.open_tree("balance")?;
        let ledger = db.open_tree("ledger")?;
        let credit_ledger = db.open_tree("credit_ledger")?;
        let issued_charges = db.open_tree("issued_charges")?;
        balance.insert(BALANCE_KEY, &initial_sats.to_be_bytes())?;
        Ok(Treasury {
            inner: Arc::new(Inner {
                balance,
                ledger,
                credit_ledger,
                issued_charges,
                db,
                rent_sats: AtomicU64::new(0),
                runway_hint: AtomicU64::new(RUNWAY_HINT_UNKNOWN),
            }),
        })
    }

    /// The authoritative remaining balance. Read-only; this is what the genome
    /// observes on a receipt (D-9).
    pub fn remaining(&self) -> Result<u64, TreasuryError> {
        let raw = self
            .inner
            .balance
            .get(BALANCE_KEY)?
            .ok_or_else(|| TreasuryError::Corrupt("balance key missing".into()))?;
        decode_u64(&raw)
    }

    /// If `key` was already performed, return its stored record. Used by the
    /// gateway dedupe step (spec step 1) and for resume-replay (G9).
    pub fn lookup(&self, key: &str) -> Result<Option<PerformedRecord>, TreasuryError> {
        match self.inner.ledger.get(key.as_bytes())? {
            Some(raw) => {
                let rec: PerformedRecord = serde_json::from_slice(&raw)
                    .map_err(|e| TreasuryError::Corrupt(format!("ledger record: {e}")))?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// If `credit_id` was already credited, return its stored credit record; else
    /// `None`. The read-only mirror of `lookup()` for the CREDIT namespace: it scans
    /// the SEPARATE `credit_ledger` tree (never the debit `ledger`), so it is blind to
    /// genome-supplied capability keys exactly as `lookup()` is blind to credit rows.
    ///
    /// This is the durable settled-charge query the settlement path consults BEFORE
    /// touching the wallet/mint: if a `charge_id` already has a row, the settlement was
    /// already resolved, so the caller returns the prior outcome without redeeming any
    /// (fresh or replayed) token. It reads the SAME rows `credit_verified` writes, so it
    /// can never disagree with the durable wall.
    ///
    /// A row is either a genuine credit (`proof == CREDIT_PROOF_MARKER`) OR a TERMINAL
    /// overflow marker (`proof == CREDIT_TERMINAL_OVERFLOW_MARKER`, finding-2): both mean
    /// "do not touch the wallet for this charge again", but only the former credited
    /// anything. The caller (`settle_charge`) inspects the proof marker to map the row to
    /// `Duplicate` (credited) vs `Terminal` (settled-dead, credited nothing). Either way
    /// an overflowed charge is now SURFACED here (it once left no row), so a retry with a
    /// fresh token can no longer miss the lookup and redeem again.
    pub fn credit_lookup(&self, credit_id: &str) -> Result<Option<PerformedRecord>, TreasuryError> {
        match self.inner.credit_ledger.get(credit_id.as_bytes())? {
            Some(raw) => {
                let rec: PerformedRecord = serde_json::from_slice(&raw)
                    .map_err(|e| TreasuryError::Corrupt(format!("credit record: {e}")))?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// Map a prior `credit_ledger` row (from `credit_lookup`) to the `CreditOutcome` a
    /// settlement retry should return WITHOUT touching the wallet. A terminal-overflow
    /// marker (finding-2) becomes `Terminal` (settled-dead, credited nothing); any other
    /// row is a genuine credit, so `Duplicate` (credited already). The marker proof bytes
    /// are private to this module, so this classification lives here rather than at the
    /// gateway call site.
    pub fn classify_prior(&self, prior: PerformedRecord) -> CreditOutcome {
        if prior.proof == CREDIT_TERMINAL_OVERFLOW_MARKER {
            CreditOutcome::Terminal(prior)
        } else {
            CreditOutcome::Duplicate(prior)
        }
    }

    /// (#62) Record `charge_id` in the DURABLE, daemon-owned `issued_charges` index with its
    /// settlement `method` — called by `authorize_issue_charge` right after the charge's ledger
    /// row lands. This index is the settlement poller's poll SOURCE
    /// ([`Treasury::issued_uncredited_charge_ids`]); writing here (and ONLY here) is what makes an
    /// issued charge visible to the poller. Idempotent: a re-issue of the same `charge_id`
    /// overwrites with the same tag (a no-op in effect), so a resume replay is harmless.
    ///
    /// STRUCTURAL money-safety (#2): because ONLY this call — reached ONLY from the single
    /// IssueCharge act — writes `issued_charges`, a non-charge act's polymorphic `ledger` `proof`
    /// can never enter the poll set: it has no key here. No decode/round-trip heuristic guards a
    /// non-charge proof out; it is excluded by construction.
    pub fn record_issued_charge(
        &self,
        charge_id: &str,
        method: ChargeMethodTag,
    ) -> Result<(), TreasuryError> {
        self.inner
            .issued_charges
            .insert(charge_id.as_bytes(), &[method.as_byte()])?;
        // Durability: flush so a crash right after IssueCharge cannot lose the poll-source entry
        // (mirrors debit_and_record's post-write flush — the ledger row and this index persist
        // together across a crash).
        self.inner.db.flush()?;
        Ok(())
    }

    /// (#62 earn-loop deployability) The DURABLE, daemon-owned set of charge_ids that were ISSUED
    /// but not yet CREDITED, filtered to the LIGHTNING rail — the settlement poller's poll source.
    ///
    /// SOURCE = THE DEDICATED `issued_charges` INDEX, NOT A LEDGER SCAN (the money-safety core of
    /// #62, kirby's ruling). ONLY `authorize_issue_charge` writes `issued_charges` (via
    /// `record_issued_charge`), so this set contains EXACTLY the real IssueCharge acts. It does NOT
    /// scan the `ledger`'s `proof` field, which is POLYMORPHIC — non-charge acts (generic/brain,
    /// memory, capability rows) write it too. A ledger scan had to HEURISTICALLY tell a charge proof
    /// from a colliding non-charge proof (decode + round-trip guard); a false positive there would
    /// FALSELY CREDIT a non-charge act (#2). Sourcing structurally from `issued_charges` removes the
    /// heuristic entirely: a non-charge act simply has no key here, so it can never be polled.
    ///
    /// HOW IT FILTERS:
    /// - Iterate `issued_charges` keys (each is a `charge_id`, plain UTF-8).
    /// - INCLUDE a charge_id iff (i) its recorded rail is [`ChargeMethodTag::Lightning`] — a Cashu
    ///   charge is settled by token evidence, never the `settle_charge(id, "")` mint-quote poll (#4)
    ///   — AND (ii) `credit_lookup(charge_id)` is `None` (neither credited nor settled-dead
    ///   terminal). A row in the SEPARATE `credit_ledger` means the charge is already resolved.
    ///
    /// BACK-COMPAT: a charge issued by a PRIOR binary (before `issued_charges` existed) has no key
    /// here, so it is not polled — acceptable: a re-fire issues a fresh charge (which IS recorded).
    ///
    /// PERF: one O(rows) scan of the small per-agent `issued_charges` tree per poll cycle plus one
    /// `credit_ledger` point-lookup per row. Cheap on the poll cadence; NOT for the hot path.
    pub fn issued_uncredited_charge_ids(&self) -> Result<Vec<String>, TreasuryError> {
        let mut out = Vec::new();
        for item in self.inner.issued_charges.iter() {
            let (key, val) = item?;
            // The value is the single method-tag byte written by `record_issued_charge` /
            // `record_charge_atomic`. An unknown/corrupt byte is skipped (never poll a row we
            // cannot classify) — fail-CLOSED, but no longer SILENT: an unclassifiable index row is
            // a real data anomaly (corruption / a foreign write) worth surfacing.
            let Some(tag) = val.first().copied().and_then(ChargeMethodTag::from_byte) else {
                tracing::warn!(
                    charge_id = %String::from_utf8_lossy(&key),
                    tag_byte = ?val.first().copied(),
                    "issued_charges row has an unknown/empty method-tag byte; skipping it (never \
                     poll a row we cannot classify) — possible index corruption"
                );
                continue;
            };
            // #4: only Lightning charges are settled on the settle_charge(id, "") poll path.
            if tag != ChargeMethodTag::Lightning {
                continue;
            }
            let Ok(charge_id) = std::str::from_utf8(&key) else {
                tracing::warn!(
                    charge_id_hex = %key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "issued_charges key is not valid UTF-8; skipping it (a charge_id is always \
                     UTF-8) — possible index corruption"
                );
                continue;
            };
            // INCLUDE iff not yet resolved (no credited/terminal row under this charge_id).
            if self.credit_lookup(charge_id)?.is_none() {
                out.push(charge_id.to_string());
            }
        }
        Ok(out)
    }

    /// The maximum numeric suffix among recorded ledger keys with `prefix` (e.g.
    /// `"mem-write-"`), or `None` if none exist. The gateway seeds the wseq_floor boot
    /// barrier from this (R2-7): on resume `wseq_floor = 1 + max(mem-write-* in ledger)`,
    /// so a restarted genome whose checkpoint regressed cannot reuse an already-recorded
    /// write-seq for a NEW write (the daemon is the wseq AUTHORITY -- a sub-floor fresh
    /// write is refused). Memory READS bypass the ledger, so only WRITE keys appear here.
    /// A key whose suffix is not a `u64` is ignored (a foreign key namespace).
    pub fn max_idempotency_seq(&self, prefix: &str) -> Result<Option<u64>, TreasuryError> {
        let mut max: Option<u64> = None;
        for item in self.inner.ledger.scan_prefix(prefix.as_bytes()) {
            let (key, _val) = item?;
            if let Ok(suffix) = std::str::from_utf8(key.as_ref()) {
                if let Some(n) = suffix.strip_prefix(prefix).and_then(|s| s.parse::<u64>().ok()) {
                    max = Some(max.map_or(n, |m| m.max(n)));
                }
            }
        }
        Ok(max)
    }

    /// Σ of the debit `ledger` rows' `cost_sats`: total capability-act spend this life (think,
    /// egress, publish, memory writes). READ-ONLY. EXCLUDES rent (rent debits via `debit_metered`,
    /// which writes no ledger row) and free reads (they bypass the ledger). Used by
    /// [`Treasury::economics_snapshot`] and by the meter's total-burn runway estimate (F0-C).
    pub fn spent_sats(&self) -> Result<u64, TreasuryError> {
        let mut total: u64 = 0;
        for item in self.inner.ledger.iter() {
            let (_key, raw) = item?;
            let rec: PerformedRecord = serde_json::from_slice(&raw)
                .map_err(|e| TreasuryError::Corrupt(format!("ledger record: {e}")))?;
            total = total.saturating_add(rec.cost_sats);
        }
        Ok(total)
    }

    /// A READ-ONLY economics snapshot (B1): fold the debit + credit ledgers and derive income
    /// from the balance identity. Adds NO mutation and NO money door -- it only reads trees that
    /// already exist. `initial_sats` (the genesis budget) and `rent_sats` (the meter's cumulative
    /// `burned_sats`) are the caller's authoritative figures, combined here so the snapshot is
    /// self-contained. NOT for the hot path: summing the ledgers is O(rows), so call it on the
    /// agent-state emission cadence, not per meter tick.
    ///
    /// The identity it upholds (design B.3): `initial + income - spent - rent == remaining`.
    /// `spent` is Σ of the debit `ledger` (capability acts; rent is excluded because
    /// `debit_metered` writes no ledger row). `income` is derived so it can never be inflated by a
    /// genome self-report (it reads only the daemon's authoritative balance + ledger).
    pub fn economics_snapshot(
        &self,
        initial_sats: u64,
        rent_sats: u64,
    ) -> Result<EconomicsSnapshot, TreasuryError> {
        let remaining_sats = self.remaining()?;

        // Σ capability-act debits (rent excluded -- debit_metered writes no ledger row).
        let spent_sats = self.spent_sats()?;

        // Count genuine credits (a terminal-overflow marker credited nothing -- exclude it).
        let mut jobs_settled: u64 = 0;
        for item in self.inner.credit_ledger.iter() {
            let (_key, raw) = item?;
            let rec: PerformedRecord = serde_json::from_slice(&raw)
                .map_err(|e| TreasuryError::Corrupt(format!("credit record: {e}")))?;
            if rec.proof == CREDIT_PROOF_MARKER {
                jobs_settled = jobs_settled.saturating_add(1);
            }
        }

        // income = remaining + spent + rent - initial (the balance identity, rearranged).
        // Saturating so a balance that (via reconcile_to_observed) dropped below `initial` cannot
        // underflow -- income floors at 0 rather than wrapping.
        let income_sats = remaining_sats
            .saturating_add(spent_sats)
            .saturating_add(rent_sats)
            .saturating_sub(initial_sats);

        Ok(EconomicsSnapshot { remaining_sats, income_sats, spent_sats, jobs_settled })
    }

    /// Debit `amount_sats` of metered burn (CPU time, memory time, egress bytes)
    /// from the balance in one transaction, WITHOUT writing an idempotency-keyed
    /// ledger row (spec 3.3 metering, C-4). Metering is not idempotency-keyed:
    /// only capability acts carry a key (the dedupe ledger is theirs). Every
    /// metered tick debits the SAME authoritative counter as a capability spend
    /// (D-9), through the SAME never-negative `checked_sub` path, so the
    /// never-overspend invariant lives in one place.
    ///
    /// Returns `DebitOutcome::Insufficient { remaining }` (no mutation) when the
    /// tick's burn would drive the balance below zero. That refusal is the
    /// budget-exhaustion signal the daemon uses to HALT the VM: cumulative
    /// metered burn has reached the genome's budget, so the daemon pauses then
    /// kills the VM and records `terminated:budget_exhausted` (spec 3.3 / 4.1,
    /// gate G2). Kirby's death by exhaustion, proven at spike scale. This call
    /// never returns `Duplicate` (metering writes no ledger key).
    pub fn debit_metered(&self, amount_sats: u64) -> Result<DebitOutcome, TreasuryError> {
        let outcome = (&self.inner.balance, &self.inner.ledger).transaction(
            move |(balance, _ledger)| {
                let current_raw = balance
                    .get(BALANCE_KEY)?
                    .ok_or_else(|| abort("balance key missing".into()))?;
                let current = decode_u64_tx(&current_raw)?;

                // Never-negative / never-overspend: refuse BEFORE mutating, the
                // same invariant the capability path enforces. A burn that would
                // overshoot zero is clamped to a refusal (the halt trigger), not
                // a negative balance.
                let Some(next) = current.checked_sub(amount_sats) else {
                    return Ok(DebitOutcome::Insufficient { remaining: current });
                };

                balance.insert(BALANCE_KEY, &next.to_be_bytes())?;
                Ok(DebitOutcome::Debited {
                    cost_sats: amount_sats,
                    remaining: next,
                })
            },
        );

        let outcome = match outcome {
            Ok(o) => o,
            Err(TransactionError::Abort(msg)) => return Err(TreasuryError::Corrupt(msg)),
            Err(TransactionError::Storage(e)) => return Err(TreasuryError::Storage(e)),
        };

        // Durability: flush so a crash after a metered debit cannot lose it.
        self.inner.db.flush()?;
        // Accumulate the rent total (B2): rent leaves no ledger row, so this in-memory counter is
        // the ONLY treasury-side record of cumulative metered burn. Add the ACTUAL debited amount
        // (never the requested `amount_sats`) so it stays exactly equal to the meter's `burned_sats`
        // (which also adds `cost_sats` on `Debited`). A refused (`Insufficient`) tick debited
        // nothing, so it adds nothing — the counter mirrors the balance movement precisely.
        if let DebitOutcome::Debited { cost_sats, .. } = &outcome {
            self.inner.rent_sats.fetch_add(*cost_sats, Ordering::Relaxed);
        }
        Ok(outcome)
    }

    /// The cumulative metered VM-rent burned this run (Σ actual `debit_metered` debits). READ-ONLY;
    /// the rent term of the economics identity `initial + income - spent - rent == remaining`. Fed
    /// only by the daemon's meter path, so a genome cannot move it. Equals the live
    /// `Meter::burned_sats`; the gateway (a treasury clone) reads it to compose the BOOKS percept
    /// without holding the meter. Per-run in-memory (0 on a fresh open/resume, like the meter).
    pub fn rent_sats(&self) -> u64 {
        self.inner.rent_sats.load(Ordering::Relaxed)
    }

    /// Publish the latest seconds-to-broke the meter loop computed (the SAME runway the 31000
    /// emitter shows), so the per-call BOOKS percept can surface it. `None` clears it to the
    /// "unknown" sentinel. Display-only; never touched by the money path. Idempotent, last-writer.
    pub fn publish_runway_hint(&self, runway_secs: Option<u64>) {
        self.inner
            .runway_hint
            .store(runway_secs.unwrap_or(RUNWAY_HINT_UNKNOWN), Ordering::Relaxed);
    }

    /// The last-published seconds-to-broke display hint, or `None` when unknown (no burn rate yet,
    /// or no meter loop is running — e.g. a bare gateway with no metered run). Display-only.
    pub fn runway_secs_hint(&self) -> Option<u64> {
        match self.inner.runway_hint.load(Ordering::Relaxed) {
            RUNWAY_HINT_UNKNOWN => None,
            secs => Some(secs),
        }
    }

    /// Atomically debit `cost_sats` from the balance AND record the performed
    /// receipt under `key`, in a single transaction (spec 4.2 atomic
    /// debit+receipt). The debit is refused (no mutation, returns
    /// `DebitOutcome::Insufficient`) if it would drive the balance below zero;
    /// the caller (the gateway) only reaches here after the pre-perform estimate
    /// gate, and `cost_sats` is the capped actual (`<=` estimate, D-20), so this
    /// refusal is a defense-in-depth backstop that the never-overspend invariant
    /// holds even if an upstream cap were wrong.
    ///
    /// `key` is assumed already checked absent by the caller's dedupe step; if a
    /// concurrent request inserted it, the transaction returns the existing
    /// record via `DebitOutcome::Duplicate` and performs no debit.
    pub fn debit_and_record(
        &self,
        key: &str,
        cost_sats: u64,
        proof: Vec<u8>,
        completion: Vec<u8>,
        memory: Vec<u8>,
        request_hash: Vec<u8>,
    ) -> Result<DebitOutcome, TreasuryError> {
        let key_bytes = key.as_bytes();
        let record_json = serde_json::to_vec(&PerformedRecord {
            cost_sats,
            // placeholder; the real post-debit balance is written inside the txn
            treasury_remaining_after: 0,
            proof: proof.clone(),
            // The assistant reply TEXT for a Completion act (empty otherwise), so a
            // resume-replay returns the words verbatim (brain-stub R1). The txn
            // re-decodes the WHOLE record below, so this rides through unchanged.
            completion,
            // The prost-encoded MemoryResult for a Memory WRITE act (empty otherwise),
            // so a resume-replay returns the same structured result. Rides through the
            // re-decode below unchanged, exactly like `completion` (durable-mind-state).
            memory,
            // The content hash of the effective request (R2-4): empty for acts that
            // compute none. Persisted so STEP-1 can refuse a same-key, different-content
            // replay. Rides through the re-decode below unchanged.
            request_hash,
        })
        .map_err(|e| TreasuryError::Corrupt(format!("encode record: {e}")))?;

        let outcome = (&self.inner.balance, &self.inner.ledger).transaction(
            move |(balance, ledger)| {
                // Dedupe inside the transaction closes the concurrent-replay race.
                if let Some(existing) = ledger.get(key_bytes)? {
                    let rec: PerformedRecord = serde_json::from_slice(&existing)
                        .map_err(|e| abort(format!("ledger record: {e}")))?;
                    return Ok(DebitOutcome::Duplicate(rec));
                }

                let current_raw = balance
                    .get(BALANCE_KEY)?
                    .ok_or_else(|| abort("balance key missing".into()))?;
                let current = decode_u64_tx(&current_raw)?;

                // Never-negative / never-overspend: refuse BEFORE mutating.
                let Some(next) = current.checked_sub(cost_sats) else {
                    return Ok(DebitOutcome::Insufficient { remaining: current });
                };

                balance.insert(BALANCE_KEY, &next.to_be_bytes())?;

                // Re-encode the record with the true post-debit balance so the
                // stored receipt matches what the genome was told.
                let mut rec: PerformedRecord = serde_json::from_slice(&record_json)
                    .map_err(|e| abort(format!("decode record: {e}")))?;
                rec.treasury_remaining_after = next;
                let rec_bytes = serde_json::to_vec(&rec)
                    .map_err(|e| abort(format!("re-encode record: {e}")))?;
                ledger.insert(key_bytes, rec_bytes)?;

                Ok(DebitOutcome::Debited {
                    cost_sats,
                    remaining: next,
                })
            },
        );

        let outcome = match outcome {
            Ok(o) => o,
            Err(TransactionError::Abort(msg)) => return Err(TreasuryError::Corrupt(msg)),
            Err(TransactionError::Storage(e)) => return Err(TreasuryError::Storage(e)),
        };

        // Durability: flush so a crash after a debit cannot lose the record.
        self.inner.db.flush()?;
        Ok(outcome)
    }

    /// (#62 money-safety) Atomically record an ISSUED charge: the charge's cost=0 ledger row AND
    /// its `issued_charges` poll-index entry commit in ONE sled MULTI-TREE TRANSACTION over
    /// (balance, ledger, issued_charges). This is the charge-specific sibling of `debit_and_record`
    /// (generic acts must NOT touch `issued_charges`, so THEY keep calling `debit_and_record`).
    ///
    /// WHY ATOMIC (the gap this closes): `authorize_issue_charge` used to do TWO separate sled
    /// writes — `debit_and_record` (the ledger row) then `record_issued_charge` (the poll index).
    /// A crash BETWEEN them stranded a real payable charge with a ledger row but NO index entry:
    /// the settlement poller (sourced from `issued_charges`) never saw it, so a customer could pay
    /// a charge that the daemon never settled — took-money-never-answered. Worse, a resume replay
    /// hit the ledger-dedupe (`Duplicate`) and skipped the index write, so the charge stayed
    /// unindexed FOREVER. Committing both writes in one transaction removes the window: after this
    /// call there is NEVER a ledger-row-without-index (or index-without-ledger-row) state.
    ///
    /// IDEMPOTENCY (preserved INSIDE the txn, mirrors `debit_and_record`): if `idempotency_key`
    /// already has a ledger row (a resume replay or a concurrent re-issue), NO second ledger row is
    /// written and the balance is untouched — it returns `Duplicate` with the stored record, EXACTLY
    /// as `debit_and_record` does. The `issued_charges` index entry is written ONLY on the fresh
    /// ledger-write branch, in the SAME txn as the ledger row, so `issued_charges` holds a
    /// `charge_id` IFF a ledger row exists for it (the canonical winner). A Duplicate/replay writes
    /// neither ledger nor index — a concurrent same-key re-issue that mints a second (loser) id can
    /// therefore never leave an index-without-ledger orphan in the poll set.
    /// Net: a fresh issue writes both (atomically); a replay writes neither.
    ///
    /// Cost is 0 (issuing a charge costs the genome nothing), so the never-negative debit can never
    /// go `Insufficient`; the guard is kept for parity with `debit_and_record`. Returns the same
    /// `DebitOutcome` semantics the caller already maps.
    pub fn record_charge_atomic(
        &self,
        idempotency_key: &str,
        charge_id: &str,
        method: ChargeMethodTag,
        proof: Vec<u8>,
        request_hash: Vec<u8>,
    ) -> Result<DebitOutcome, TreasuryError> {
        let key_bytes = idempotency_key.as_bytes();
        let charge_id_bytes = charge_id.as_bytes();
        let method_byte = method.as_byte();
        // A charge is recorded with cost=0: a ledger row for STEP-1 dedupe, but no spend.
        let cost_sats: u64 = 0;
        let record_json = serde_json::to_vec(&PerformedRecord {
            cost_sats,
            // placeholder; the real post-debit balance is written inside the txn
            treasury_remaining_after: 0,
            proof: proof.clone(),
            // A charge carries no assistant completion or memory result (those are Completion /
            // Memory acts). Empty here, exactly as the gateway passed for the old two-write path.
            completion: Vec::new(),
            memory: Vec::new(),
            // The effective-request hash (over amount/memo/method) so a same-key, DIVERGENT-terms
            // re-issue is refused at STEP-1 (rides the re-decode below unchanged).
            request_hash,
        })
        .map_err(|e| TreasuryError::Corrupt(format!("encode record: {e}")))?;

        let outcome =
            (&self.inner.balance, &self.inner.ledger, &self.inner.issued_charges).transaction(
                move |(balance, ledger, issued_charges)| {
                    // Idempotency (mirrors debit_and_record): a ledger row already under this key
                    // means the charge was already issued (resume replay / concurrent re-issue), so
                    // write NO second ledger row, make NO balance change, and index NOTHING. A
                    // concurrent same-key re-issue mints its OWN (loser) charge_id; indexing it here
                    // would strand an index-without-ledger orphan in the poll set (a charge_id the
                    // poller can never correlate to a ledger row). Index only the winner, below.
                    if let Some(existing) = ledger.get(key_bytes)? {
                        let rec: PerformedRecord = serde_json::from_slice(&existing)
                            .map_err(|e| abort(format!("ledger record: {e}")))?;
                        return Ok(DebitOutcome::Duplicate(rec));
                    }

                    let current_raw = balance
                        .get(BALANCE_KEY)?
                        .ok_or_else(|| abort("balance key missing".into()))?;
                    let current = decode_u64_tx(&current_raw)?;

                    // Never-negative / never-overspend, kept for parity. cost=0 can never refuse.
                    let Some(next) = current.checked_sub(cost_sats) else {
                        return Ok(DebitOutcome::Insufficient { remaining: current });
                    };

                    balance.insert(BALANCE_KEY, &next.to_be_bytes())?;

                    // Re-encode the record with the true post-debit balance so the stored receipt
                    // matches what the genome was told (same shape debit_and_record writes).
                    let mut rec: PerformedRecord = serde_json::from_slice(&record_json)
                        .map_err(|e| abort(format!("decode record: {e}")))?;
                    rec.treasury_remaining_after = next;
                    let rec_bytes = serde_json::to_vec(&rec)
                        .map_err(|e| abort(format!("re-encode record: {e}")))?;
                    ledger.insert(key_bytes, rec_bytes)?;

                    // ATOMIC PAIRING (index the WINNER only): the poll-index entry is written in the
                    // SAME txn as the fresh ledger row, and ONLY on this fresh-write branch — so
                    // `issued_charges` holds a charge_id IFF a ledger row exists for it (the
                    // canonical winner). Ledger row and index commit together or not at all; the
                    // Duplicate arm above indexes nothing, so no index-without-ledger orphan is
                    // possible even under a concurrent same-idempotency-key re-issue.
                    issued_charges.insert(charge_id_bytes, &[method_byte])?;

                    Ok(DebitOutcome::Debited { cost_sats, remaining: next })
                },
            );

        let outcome = match outcome {
            Ok(o) => o,
            Err(TransactionError::Abort(msg)) => return Err(TreasuryError::Corrupt(msg)),
            Err(TransactionError::Storage(e)) => return Err(TreasuryError::Storage(e)),
        };

        // Durability: flush so a crash after the atomic write cannot lose the ledger row OR the
        // poll-index entry — they persist together (mirrors debit_and_record's post-write flush).
        self.inner.db.flush()?;
        Ok(outcome)
    }

    /// The treasury's ONE and ONLY credit path: atomically ADD `amount_sats` to
    /// the balance AND record a credit row, in a single transaction, idempotent
    /// on `credit_id`. This is the inverse of `debit_and_record` and the only
    /// method on this type that can raise the balance.
    ///
    /// DAEMON-ONLY: there is no gateway RPC that reaches here. The genome cannot
    /// assert a credit; only daemon-side settlement-verification code holding a
    /// `&Treasury` calls this, AFTER the host has independently verified an
    /// inbound settlement (ecash redeemed, an invoice paid, etc). The genome's
    /// self-reported numbers (ReportEvent) move nothing (G3c) -- this path does
    /// not change that.
    ///
    /// DEDUPE (the no-double-credit wall): the dedupe lives INSIDE the txn, on
    /// `credit_id`, exactly as `debit_and_record` dedupes on its key. A row
    /// already present under the credit key means this settlement was already
    /// credited -- a re-delivered settlement or a daemon restart mid-verify -- so
    /// we return `Duplicate` with the stored record and make NO balance change.
    /// Credit happens EXACTLY ONCE per `credit_id`.
    ///
    /// OVERFLOW: the add uses `checked_add`. An add that would overflow u64 is
    /// REFUSED (`Overflow`, no BALANCE mutation), never wrapped. u64::MAX sats is
    /// unreachable in practice, but a credit must never silently wrap the balance
    /// to a smaller value. Because the token was ALREADY redeemed by the time we run
    /// (verify_settlement precedes us), an overflow ALSO writes a durable TERMINAL
    /// marker row under this `credit_id` (finding-2): the charge is settled-dead. The
    /// marker credits nothing (distinct proof marker, cost 0, no balance change) but
    /// makes the charge visible to `credit_lookup` and this in-txn dedupe, so a retry
    /// with a fresh token returns `Terminal` and NEVER redeems into the wallet again.
    /// The first overflow returns `Overflow`; every retry returns `Terminal`.
    ///
    /// KEY NAMESPACE (structural, not by convention): credit rows live in their OWN
    /// sled tree (`credit_ledger`), SEPARATE from the debit `ledger` that holds the
    /// genome-supplied capability `idempotency_key`s. This makes the credit namespace
    /// STRUCTURALLY disjoint from genome keys: a genome cannot pre-occupy a credit key
    /// by choosing a colliding `idempotency_key` (it writes to a different tree), so it
    /// cannot grief a future settlement into a skipped (`Duplicate`) credit. The
    /// `credit_id` is stored bare (daemon-assigned settlement id). The debit-side
    /// `lookup()` / `max_idempotency_seq` scan only `ledger`, so they never see a
    /// credit row at all -- there is no homogeneity or shape concern to manage.
    pub fn credit_verified(
        &self,
        credit_id: &str,
        amount_sats: u64,
    ) -> Result<CreditOutcome, TreasuryError> {
        let key_bytes = credit_id.as_bytes().to_vec();

        // Transact over (balance, credit_ledger): the credit tree is SEPARATE from the
        // debit `ledger`, so a credit can never alias a genome-supplied capability key.
        let outcome = (&self.inner.balance, &self.inner.credit_ledger).transaction(
            move |(balance, credit_ledger)| {
                // Dedupe inside the transaction is the no-double-credit wall: a row
                // already under this credit_id means this settlement was already
                // resolved (re-delivery, restart-mid-verify, or a prior overflow), so
                // make NO balance change and return the stored record. The row's proof
                // marker distinguishes a genuine credit (`Duplicate`) from a terminal
                // overflow marker (`Terminal`, finding-2) so a retry of an overflowed
                // charge is never mistaken for a credited one.
                if let Some(existing) = credit_ledger.get(&key_bytes)? {
                    let rec: PerformedRecord = serde_json::from_slice(&existing)
                        .map_err(|e| abort(format!("credit record: {e}")))?;
                    if rec.proof == CREDIT_TERMINAL_OVERFLOW_MARKER {
                        return Ok(CreditOutcome::Terminal(rec));
                    }
                    return Ok(CreditOutcome::Duplicate(rec));
                }

                let current_raw = balance
                    .get(BALANCE_KEY)?
                    .ok_or_else(|| abort("balance key missing".into()))?;
                let current = decode_u64_tx(&current_raw)?;

                // Never wrap: an add that would overflow u64 is refused with no balance
                // mutation, the mirror of the debit path's never-negative guard. But the
                // token that drove this attempt is ALREADY redeemed (verify_settlement ran
                // before us), so we write a DURABLE TERMINAL marker (finding-2): the charge
                // is settled-dead. This is NOT a credit row (cost_sats=0, distinct proof
                // marker, no balance change), so it credits nothing and the balance is
                // untouched -- but `credit_lookup` and this dedupe now surface it, so a
                // retry with a fresh token short-circuits and NEVER redeems again. The
                // FIRST overflow returns `Overflow`; the row makes every RETRY `Terminal`.
                let Some(next) = current.checked_add(amount_sats) else {
                    let marker = PerformedRecord {
                        cost_sats: 0,
                        treasury_remaining_after: current,
                        proof: CREDIT_TERMINAL_OVERFLOW_MARKER.to_vec(),
                        completion: Vec::new(),
                        memory: Vec::new(),
                        request_hash: Vec::new(),
                    };
                    let marker_bytes = serde_json::to_vec(&marker)
                        .map_err(|e| abort(format!("encode terminal-overflow marker: {e}")))?;
                    credit_ledger.insert(key_bytes.as_slice(), marker_bytes)?;
                    return Ok(CreditOutcome::Overflow { remaining: current });
                };

                balance.insert(BALANCE_KEY, &next.to_be_bytes())?;

                // The credit row reuses the PerformedRecord shape (it is the only
                // serde row type in this db) recorded as a credit marker: cost_sats = 0
                // (a credit costs nothing), the post-credit balance, and a
                // `credit-verified` proof marker. It lives in `credit_ledger`, never the
                // debit `ledger`.
                let rec = PerformedRecord {
                    cost_sats: 0,
                    treasury_remaining_after: next,
                    proof: CREDIT_PROOF_MARKER.to_vec(),
                    completion: Vec::new(),
                    memory: Vec::new(),
                    request_hash: Vec::new(),
                };
                let rec_bytes = serde_json::to_vec(&rec)
                    .map_err(|e| abort(format!("encode credit record: {e}")))?;
                credit_ledger.insert(key_bytes.as_slice(), rec_bytes)?;

                Ok(CreditOutcome::Credited {
                    amount_sats,
                    remaining: next,
                })
            },
        );

        let outcome = match outcome {
            Ok(o) => o,
            Err(TransactionError::Abort(msg)) => return Err(TreasuryError::Corrupt(msg)),
            Err(TransactionError::Storage(e)) => return Err(TreasuryError::Storage(e)),
        };

        // Durability: flush so a crash after a credit cannot lose it, exactly as
        // the debit paths do.
        self.inner.db.flush()?;
        Ok(outcome)
    }

    /// Reconcile the balance to an externally-observed spendable truth (e.g. a prepaid Routstr
    /// key balance probed at boot). Transactional SET: `balance := observed_sats`, BOTH directions
    /// -- it RAISES on a topup and LOWERS if the external source truly holds less.
    ///
    /// CONTRACT -- the caller MUST pass a VERIFIED external balance (a successful, non-zero probe
    /// of the authoritative source). Because this SETS unconditionally, a stale / failed / zero
    /// reading would wrongly brick or inflate the counter; the caller is fail-closed and does NOT
    /// call this on a probe error or a zero reading.
    ///
    /// This is the EXTERNAL-BALANCE-IS-TRUTH model (the prepaid-key brain): the key balance is the
    /// authoritative spendable money and the local counter mirrors it. It is NOT the cashu model
    /// -- there the local wallet proofs are truth and a shortfall REFUSES to boot
    /// (`assert_wallet_backs_counter`); do NOT use this to paper over a cashu shortfall.
    ///
    /// Idempotent: re-observing the same total is a no-op (`Unchanged`). Daemon-only (never
    /// genome-reachable, like the debit/credit paths). Durable (`db.flush()`).
    pub fn reconcile_to_observed(
        &self,
        observed_sats: u64,
    ) -> Result<ReconcileOutcome, TreasuryError> {
        let outcome = self.inner.balance.transaction(|balance| {
            let current_raw = balance
                .get(BALANCE_KEY)?
                .ok_or_else(|| abort("balance key missing".into()))?;
            let current = decode_u64_tx(&current_raw)?;

            if observed_sats == current {
                return Ok(ReconcileOutcome::Unchanged { at: current });
            }
            balance.insert(BALANCE_KEY, &observed_sats.to_be_bytes())?;
            Ok(if observed_sats > current {
                ReconcileOutcome::Raised { from: current, to: observed_sats }
            } else {
                ReconcileOutcome::Lowered { from: current, to: observed_sats }
            })
        });

        let outcome = match outcome {
            Ok(o) => o,
            Err(TransactionError::Abort(msg)) => return Err(TreasuryError::Corrupt(msg)),
            Err(TransactionError::Storage(e)) => return Err(TreasuryError::Storage(e)),
        };

        // Durability: flush so a crash after a reconcile cannot lose it, exactly as the
        // debit/credit paths do.
        self.inner.db.flush()?;
        Ok(outcome)
    }
}

/// The result of a `debit_and_record` attempt.
pub enum DebitOutcome {
    /// Debited successfully; the balance is now `remaining`.
    Debited { cost_sats: u64, remaining: u64 },
    /// The key was already performed (concurrent replay); no debit happened.
    Duplicate(PerformedRecord),
    /// The debit would have driven the balance below zero; refused, no mutation.
    Insufficient { remaining: u64 },
}

/// The result of a `credit_verified` attempt. The mirror of `DebitOutcome`:
/// `Credited` raised the balance, `Duplicate` is the no-double-credit no-op
/// (this `credit_id` was already credited), `Overflow` is the never-wrap
/// refusal (an add that would exceed u64::MAX, with no mutation), and `Terminal`
/// is the finding-2 dead-charge outcome (a prior attempt overflowed after redeeming
/// a token, so this charge is settled-dead: no credit ever happened and none ever
/// will, but the wallet must never be touched for it again).
pub enum CreditOutcome {
    /// Credited successfully; the balance is now `remaining`.
    Credited { amount_sats: u64, remaining: u64 },
    /// This `credit_id` was already credited (re-delivered settlement or a
    /// restart mid-verify); no credit happened. Carries the stored record.
    Duplicate(PerformedRecord),
    /// The credit would have overflowed u64; refused, no mutation. On this outcome
    /// `credit_verified` ALSO writes the durable terminal marker (finding-2), so the
    /// FIRST overflow returns `Overflow` and any RETRY returns `Terminal`.
    Overflow { remaining: u64 },
    /// This `charge_id` is settled-dead (finding-2): a prior settlement attempt
    /// redeemed a token but the credit overflowed u64, so NOTHING was ever credited
    /// and nothing ever will be -- yet the redeemed token is spent, so no future
    /// attempt may reach the wallet. Distinct from `Duplicate` (which means a credit
    /// DID happen): the caller/genome can tell "this charge is dead, nothing was
    /// credited". Carries the stored terminal record. NEVER a credit (drain-only).
    Terminal(PerformedRecord),
}

/// The result of a `reconcile_to_observed` sync. `Raised`/`Lowered` moved the balance to match
/// the observed external truth; `Unchanged` is the idempotent no-op (already equal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The observed balance was HIGHER (e.g. a topup); the counter rose to `to`.
    Raised { from: u64, to: u64 },
    /// The observed balance was LOWER (an external spend not yet in the counter); counter fell to `to`.
    Lowered { from: u64, to: u64 },
    /// The observed balance already equalled the counter; no mutation.
    Unchanged { at: u64 },
}

/// Abort a sled transaction with a corruption message (host-side fault).
fn abort(msg: String) -> ConflictableTransactionError<String> {
    ConflictableTransactionError::Abort(msg)
}

/// Decode a big-endian u64 from a sled value outside a transaction.
fn decode_u64(raw: &[u8]) -> Result<u64, TreasuryError> {
    let arr: [u8; 8] = raw
        .try_into()
        .map_err(|_| TreasuryError::Corrupt(format!("expected 8 bytes, got {}", raw.len())))?;
    Ok(u64::from_be_bytes(arr))
}

/// Decode a big-endian u64 inside a sled transaction (abort on a bad value).
fn decode_u64_tx(raw: &[u8]) -> Result<u64, ConflictableTransactionError<String>> {
    let arr: [u8; 8] = raw
        .try_into()
        .map_err(|_| abort(format!("expected 8 bytes, got {}", raw.len())))?;
    Ok(u64::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::{
        is_lock_contention, ChargeMethodTag, DebitOutcome, ReconcileOutcome, Treasury,
        TreasuryError,
    };

    // ---- #62 ATOMIC CHARGE WRITE (money-safety: no ledger-row-without-index) ----

    /// TOOTH (#62): `record_charge_atomic` commits the charge's ledger row AND its `issued_charges`
    /// poll-index entry TOGETHER — after the call there is NEVER a ledger-row-without-index state
    /// (both exist, or neither). This is the invariant that makes an issued charge always settleable:
    /// the settlement poller's source is `issued_uncredited_charge_ids` (the index), so a charge with
    /// a ledger row but no index entry would be a payable charge the poller NEVER settles
    /// (took-money-never-answered).
    ///
    /// RED-ON-REVERT (simulates the pre-fix crash between the two old writes): in
    /// `record_charge_atomic`, revert the tx-wrap back to two separate writes AND skip the index —
    /// i.e. replace the body with a plain `debit_and_record(...)` and DROP the
    /// `issued_charges.insert(...)`. The ledger row then lands but the index does NOT, so the
    /// `issued_uncredited_charge_ids` assertion below finds an EMPTY poll set → the charge is
    /// unindexed → the poller would never settle it → RED. With the atomic write both land → the
    /// charge is in the poll set → GREEN.
    #[test]
    fn record_charge_atomic_indexes_and_ledgers_together() {
        let t = Treasury::open_temporary(1_000).unwrap();

        // A fresh issue: both writes must land in one tx.
        let out = t
            .record_charge_atomic(
                "issue-key-1",
                "charge-abc",
                ChargeMethodTag::Lightning,
                b"charge-proof".to_vec(),
                b"req-hash".to_vec(),
            )
            .unwrap();
        assert!(
            matches!(out, DebitOutcome::Debited { cost_sats: 0, .. }),
            "a fresh charge issues at cost 0"
        );

        // (i) the LEDGER row exists (STEP-1 dedupe source) ...
        assert!(
            t.lookup("issue-key-1").unwrap().is_some(),
            "the charge's ledger row must exist after record_charge_atomic"
        );
        // (ii) ... AND the INDEX entry exists — the charge is in the poller's poll set. This is the
        // half the pre-fix crash window dropped; it is what goes RED if the index write is skipped.
        assert_eq!(
            t.issued_uncredited_charge_ids().unwrap(),
            vec!["charge-abc".to_string()],
            "the charge must be in the durable poll index (the poller's ONLY source)"
        );

        // Cost 0: a charge does not spend the treasury.
        assert_eq!(t.remaining().unwrap(), 1_000, "issuing a charge costs the genome nothing");
    }

    /// TOOTH (#62, Round-5 finding-1): idempotency is PRESERVED inside the atomic tx AND the
    /// Duplicate arm indexes NOTHING — so a same-key re-issue that mints a DIFFERENT (loser)
    /// charge_id (the concurrent-issue shape) can NEVER leave an index-without-ledger orphan. The
    /// first (winner) issue writes ledger row + index for its charge_id; a second call under the
    /// SAME `idempotency_key` but a DIFFERENT charge_id returns `Duplicate` (no second ledger row)
    /// and does NOT index the loser. Net: exactly ONE indexed charge_id, the canonical winner that
    /// holds the ledger row.
    ///
    /// RED-ON-REVERT (finding-1): move the `issued_charges.insert(...)` back to unconditional-FIRST
    /// (before the ledger dedupe). The Duplicate arm then indexes the loser id too, so the poll set
    /// becomes `[charge-winner, charge-LOSER]` (len 2) — an index-without-ledger orphan — and the
    /// `len == 1 / winner only` assertion below goes RED. (Note: the OLD unit tooth replayed the
    /// SAME charge_id, so it could not catch this; the deployable gateway twin in
    /// bolt11_settlement.rs drives the same defect through STEP1 under real concurrency.)
    #[test]
    fn record_charge_atomic_duplicate_key_does_not_index_a_loser_charge_id() {
        let t = Treasury::open_temporary(1_000).unwrap();

        let first = t
            .record_charge_atomic(
                "issue-key-2",
                "charge-winner",
                ChargeMethodTag::Lightning,
                b"p".to_vec(),
                b"h".to_vec(),
            )
            .unwrap();
        assert!(matches!(first, DebitOutcome::Debited { .. }), "first issue debits (cost 0)");

        // A same-key re-issue that minted a DIFFERENT (loser) charge_id — the concurrent-issue
        // shape. Must NOT write a second ledger row, and must NOT index the loser id.
        let replay = t
            .record_charge_atomic(
                "issue-key-2",
                "charge-LOSER",
                ChargeMethodTag::Lightning,
                b"p".to_vec(),
                b"h".to_vec(),
            )
            .unwrap();
        assert!(
            matches!(replay, DebitOutcome::Duplicate(_)),
            "a same-key re-issue returns Duplicate (no second ledger row)"
        );

        // Exactly ONE indexed charge — the canonical winner. The loser id is NOT in the poll set
        // (no index-without-ledger orphan), and there is no double-row.
        assert_eq!(
            t.issued_uncredited_charge_ids().unwrap(),
            vec!["charge-winner".to_string()],
            "only the winner is indexed; the loser charge_id must NOT be in the poll set (no orphan)"
        );
        assert_eq!(t.remaining().unwrap(), 1_000, "no balance movement on issue or replay");
    }

    // ---- B1 economics snapshot (Milestone 2 axis-2: the agent keeps its own books) ----

    /// TOOTH (B1): NO-SELF-CREDIT. `income_sats` reflects ONLY mint-verified credits
    /// (`credit_verified`, the daemon-only income path) -- never a capability debit, and never a
    /// genome-supplied number (the snapshot reads only the daemon's balance + ledger). RED on any
    /// income figure that counts a debit or a self-report as income.
    #[test]
    fn economics_income_only_reflects_credits_not_debits() {
        let t = Treasury::open_temporary(1_000).unwrap();

        // No credits yet: nothing earned.
        let snap = t.economics_snapshot(1_000, 0).unwrap();
        assert_eq!(snap.income_sats, 0, "no credit -> no income");
        assert_eq!(snap.jobs_settled, 0);

        // A capability DEBIT is spend, NOT income.
        let _ = t.debit_and_record("think-1", 50, b"proof".to_vec(), vec![], vec![], vec![]).unwrap();
        let snap = t.economics_snapshot(1_000, 0).unwrap();
        assert_eq!(snap.spent_sats, 50, "the debit is counted as spend");
        assert_eq!(snap.income_sats, 0, "a debit must NOT be counted as income (no-self-credit)");
        assert_eq!(snap.jobs_settled, 0, "a debit is not a settled job");

        // Only credit_verified (the daemon-only income path) raises income.
        let _ = t.credit_verified("charge-1", 200).unwrap();
        let snap = t.economics_snapshot(1_000, 0).unwrap();
        assert_eq!(snap.income_sats, 200, "the mint-verified credit is income");
        assert_eq!(snap.jobs_settled, 1, "one stranger paid");
        assert_eq!(snap.spent_sats, 50, "spend is unchanged by a credit");
    }

    /// TOOTH (B1): BOOKS RECONCILE. The snapshot's figures satisfy the design B.3 identity
    /// `initial + income - spent - rent == remaining` against the daemon's authoritative balance,
    /// and each fold matches its known ground truth (rent, debited via `debit_metered`, is
    /// EXCLUDED from `spent`). RED on a fold that miscounts (e.g. counting rent as spend, or
    /// summing credits wrong).
    #[test]
    fn economics_books_reconcile_against_the_identity() {
        let initial = 10_000u64;
        let rent = 300u64; // the meter's cumulative burn (passed in; the treasury does not hold it)
        let t = Treasury::open_temporary(initial).unwrap();

        // Two strangers pay; the agent spends on a couple of capability acts.
        let _ = t.credit_verified("c1", 500).unwrap();
        let _ = t.credit_verified("c2", 300).unwrap();
        let _ = t.debit_and_record("a1", 120, b"p".to_vec(), vec![], vec![], vec![]).unwrap();
        let _ = t.debit_and_record("a2", 80, b"p".to_vec(), vec![], vec![], vec![]).unwrap();
        // Rent: debit_metered writes NO ledger row (mirrors real VM-rent), so it must NOT appear
        // in `spent` -- it is accounted separately as `rent`.
        let _ = t.debit_metered(rent).unwrap();

        let snap = t.economics_snapshot(initial, rent).unwrap();

        // Every fold matches its known ground truth.
        assert_eq!(snap.remaining_sats, t.remaining().unwrap(), "remaining == the treasury truth");
        assert_eq!(snap.spent_sats, 200, "Σ ledger debits (120+80); rent EXCLUDED");
        assert_eq!(snap.jobs_settled, 2, "two credits settled");
        assert_eq!(snap.income_sats, 800, "Σ credited (500+300), derived read-only");

        // THE identity (design B.3): initial + income - spent - rent == remaining.
        assert_eq!(
            initial + snap.income_sats - snap.spent_sats - rent,
            snap.remaining_sats,
            "books reconcile against the daemon's authoritative balance"
        );
        assert_eq!(snap.remaining_sats, 10_000 + 800 - 200 - 300, "direct cross-check");
    }

    #[test]
    fn lock_contention_matches_sled_lock_message() {
        let err = TreasuryError::Storage(sled::Error::Io(std::io::Error::other(
            "could not acquire lock on /tmp/kirby-treasury: <WouldBlock>",
        )));

        assert!(is_lock_contention(&err));
    }

    #[test]
    fn lock_contention_ignores_other_storage_errors() {
        let err = TreasuryError::Storage(sled::Error::Io(std::io::Error::other(
            "disk is unavailable",
        )));

        assert!(!is_lock_contention(&err));
    }

    #[test]
    fn reconcile_raises_the_balance_to_a_higher_observed_truth() {
        let t = Treasury::open_temporary(700).unwrap();
        let out = t.reconcile_to_observed(1000).unwrap();
        assert_eq!(out, ReconcileOutcome::Raised { from: 700, to: 1000 });
        assert_eq!(t.remaining().unwrap(), 1000);
    }

    #[test]
    fn reconcile_lowers_the_balance_to_a_lower_observed_truth() {
        // The external source truly holds less than the counter believed -- mirror DOWN (no
        // phantom balance / overdraft) rather than refuse to boot (the key-brain truth model).
        let t = Treasury::open_temporary(700).unwrap();
        let out = t.reconcile_to_observed(500).unwrap();
        assert_eq!(out, ReconcileOutcome::Lowered { from: 700, to: 500 });
        assert_eq!(t.remaining().unwrap(), 500);
    }

    #[test]
    fn reconcile_is_idempotent_and_survives_a_revisited_value() {
        // The lost-reconcile bug a value-keyed credit_id would have hit: re-observing the same
        // total is a clean no-op, AND a topup BACK to a previously-seen total still reconciles
        // (no value-keyed dedup to collide with).
        let t = Treasury::open_temporary(1000).unwrap();
        assert_eq!(
            t.reconcile_to_observed(1000).unwrap(),
            ReconcileOutcome::Unchanged { at: 1000 }
        );
        t.reconcile_to_observed(700).unwrap(); // a spend the counter now mirrors
        let out = t.reconcile_to_observed(1000).unwrap(); // topup back to a seen total
        assert_eq!(out, ReconcileOutcome::Raised { from: 700, to: 1000 });
        assert_eq!(t.remaining().unwrap(), 1000);
    }
}
