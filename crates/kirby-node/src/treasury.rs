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
use std::sync::Arc;

use sled::transaction::{ConflictableTransactionError, TransactionError};
use sled::Transactional;

/// Sled key for the authoritative balance (a single u64, big-endian).
const BALANCE_KEY: &[u8] = b"remaining_sats";

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
    /// Held so the database is flushed and dropped with the treasury.
    db: sled::Db,
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
            inner: Arc::new(Inner { balance, ledger, credit_ledger, db }),
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
        balance.insert(BALANCE_KEY, &initial_sats.to_be_bytes())?;
        Ok(Treasury {
            inner: Arc::new(Inner { balance, ledger, credit_ledger, db }),
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
        Ok(outcome)
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
    /// REFUSED (`Overflow`, no mutation), never wrapped. u64::MAX sats is
    /// unreachable in practice, but a credit must never silently wrap the balance
    /// to a smaller value.
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
                // credited (re-delivery or restart-mid-verify), so make NO balance
                // change and return the stored record.
                if let Some(existing) = credit_ledger.get(&key_bytes)? {
                    let rec: PerformedRecord = serde_json::from_slice(&existing)
                        .map_err(|e| abort(format!("credit record: {e}")))?;
                    return Ok(CreditOutcome::Duplicate(rec));
                }

                let current_raw = balance
                    .get(BALANCE_KEY)?
                    .ok_or_else(|| abort("balance key missing".into()))?;
                let current = decode_u64_tx(&current_raw)?;

                // Never wrap: an add that would overflow u64 is refused with no
                // mutation, the mirror of the debit path's never-negative guard.
                let Some(next) = current.checked_add(amount_sats) else {
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
                    proof: b"credit-verified".to_vec(),
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
/// (this `credit_id` was already credited), and `Overflow` is the never-wrap
/// refusal (an add that would exceed u64::MAX, with no mutation).
pub enum CreditOutcome {
    /// Credited successfully; the balance is now `remaining`.
    Credited { amount_sats: u64, remaining: u64 },
    /// This `credit_id` was already credited (re-delivered settlement or a
    /// restart mid-verify); no credit happened. Carries the stored record.
    Duplicate(PerformedRecord),
    /// The credit would have overflowed u64; refused, no mutation.
    Overflow { remaining: u64 },
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
    use super::{is_lock_contention, ReconcileOutcome, Treasury, TreasuryError};

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
