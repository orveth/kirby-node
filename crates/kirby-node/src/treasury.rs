//! The daemon-owned, persisted, unforgeable treasury (spec 3.2, 4.2, D-9, D-20).
//!
//! The treasury is a single authoritative counter `remaining_sats` that lives
//! ON THE DAEMON (host), never in the VM. The genome can observe it (the
//! `treasury_remaining` field on a receipt) but cannot mutate it: there is no
//! public method on this type that lets a gateway request ADD balance or SET
//! `remaining` directly. The only mutation is `debit`, which only ever
//! decreases the balance, and it is reachable only from daemon-side code that
//! holds a `&Treasury`. This is the unforgeability core (D-9, gate G3b).
//!
//! Invariants this module enforces (spec 4.2):
//! - Unforgeable: only daemon-side code debits; no path adds or sets balance.
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
/// Lives here (platform-independent — it only inspects a `TreasuryError`) so both
/// the Linux-only `idempotent_run` retry loop and the cross-platform `boot`
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformedRecord {
    pub cost_sats: u64,
    pub treasury_remaining_after: u64,
    pub proof: Vec<u8>,
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
    /// idempotency_key -> PerformedRecord (the dedupe ledger).
    ledger: sled::Tree,
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
            inner: Arc::new(Inner { balance, ledger, db }),
        })
    }

    /// Open a treasury backed by a temporary in-memory store. Used by tests and
    /// by harnesses that do not need persistence across a process restart. The
    /// money-path logic is identical to the on-disk path.
    pub fn open_temporary(initial_sats: u64) -> Result<Self, TreasuryError> {
        let db = sled::Config::new().temporary(true).open()?;
        let balance = db.open_tree("balance")?;
        let ledger = db.open_tree("ledger")?;
        balance.insert(BALANCE_KEY, &initial_sats.to_be_bytes())?;
        Ok(Treasury {
            inner: Arc::new(Inner { balance, ledger, db }),
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
    ) -> Result<DebitOutcome, TreasuryError> {
        let key_bytes = key.as_bytes();
        let record_json = serde_json::to_vec(&PerformedRecord {
            cost_sats,
            // placeholder; the real post-debit balance is written inside the txn
            treasury_remaining_after: 0,
            proof: proof.clone(),
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
    use super::{is_lock_contention, TreasuryError};

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
}
