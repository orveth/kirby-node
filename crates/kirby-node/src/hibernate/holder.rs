//! Hibernation chunk H4a: the in-process share-holder + fencing lease — the shared
//! quorum primitive that both the seal ceremony (H4b) and the unseal ceremony (H5)
//! drive. It enforces two of the three hibernation barriers
//! (`plans/build-spec-kirby-hibernation-thinslice.md`):
//!
//! - **Barrier 2 — durable watcher record before ack/release.** A holder's ack means
//!   "fsynced": [`Holder::receive_share`] verifies and persists its [`WatcherRecord`]
//!   (with the held [`Share`]) with an atomic fsync write BEFORE it acks, and every
//!   lease issuance / share release is likewise persisted BEFORE it returns
//!   (write-before-release). All three mutating methods are PERSIST-BEFORE-COMMIT: the
//!   candidate state is fsynced first, and only then does the in-memory state advance,
//!   so a write failure can never leave memory ahead of disk.
//! - **Barrier 3 — single live lease before resurrected authority.** A holder issues
//!   AT MOST ONE live [`Lease`] per `(npub, resume_seq)` ([`LeaseKey`](super::LeaseKey)):
//!   a competing spawner (different `lease_id`/ephemeral pubkey) is refused while a
//!   lease is live, so it cannot reach the 2-of-3 quorum and is fenced. A lease that
//!   has expired frees the slot, so a retry gets a NEW `lease_id`.
//!
//! ## Quorum, and what "in-process" means here
//!
//! The 2-of-3 quorum is THREE [`Holder`] instances; assembling threshold-many holder
//! grants into the runtime's fencing token, and aggregating their `quorum_sigs`, is the
//! unseal ceremony's job (H5). This module is ONE holder. Each holder independently
//! enforces its single-live-lease fence, which is what makes the quorum un-equivocable:
//! a second spawner needs a fresh grant from ≥2 holders, but holders that already
//! granted the first lease refuse it.
//!
//! Thin-slice honesty (NOT the eventual security model):
//! - Holders are in-process structs persisting to the SAME local disk, so all three
//!   shares live on one disk — any reader of the disk can reconstruct the seed. The
//!   real model (Move-2) distributes holders across nodes/TEEs so no single host holds
//!   a threshold. The LOGIC here (durable-before-ack, single-live-lease, condition-gated
//!   release, seal-epoch honoring) is real and carries forward; the trust topology does
//!   not.
//! - **Single-instance invariant.** The fence lives in one [`Holder`]'s in-memory +
//!   on-disk state, so it holds only if there is at most ONE live `Holder` handle per
//!   `(agent_id, holder_id)` at a time. The thin-slice ceremony honors this by driving
//!   one handle per holder, sequentially. Concurrent / distributed holders (Move-2)
//!   REQUIRE a file lock (flock) or a holder registry to make the read-modify-write of
//!   `active_lease` atomic across handles; this is documented, not built, here.
//! - **No proof-of-possession.** Lease issuance, renewal, and release trust the
//!   caller-supplied `lease_id` + `spawner_ephemeral_pubkey` STRINGS; there is no proof
//!   the caller holds the spawner's ephemeral key, so a replay of those values reads as
//!   the same spawner. This is the honest-actor / assent-not-sig boundary: a holder's
//!   `quorum_sigs` entry is an in-process assent MARKER (its `holder_id`), not a
//!   signature. Move-2 adds a real schnorr proof-of-possession over the lease's
//!   canonical bytes and a real signature.
//!
//! ## Composition
//!
//! Share verification is H1 ([`verify_share`]); the share/seed types are H0
//! ([`Share`]/[`Lease`]/[`WatcherRecord`]/[`ActiveLease`]/[`ReleaseEntry`]). The durable
//! write mirrors H2's hardened `bundle::write_atomic` discipline (create_new + random
//! temp + 0600 + mandatory file & dir fsync) rather than sharing it: the two have
//! different error types and H4a is scoped to "holder only", so a self-contained copy
//! keeps it from touching merged code (cf. the `to_hex` / tempdir-helper dup already in
//! this crate). A later pass could factor the durable-write discipline into a shared
//! util if the team wants DRY across `bundle` and `holder`.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::shamir::{verify_share, ShamirError};
use super::{hibernate_dir, ActiveLease, Lease, ReleaseEntry, Share, WakeConditions, WatcherRecord};

/// What can go wrong driving a holder.
#[derive(Debug, thiserror::Error)]
pub enum HolderError {
    /// The offered share failed its commitment check (corrupt / garbled / wrong epoch).
    #[error("share rejected: {0}")]
    ShareRejected(#[from] ShamirError),
    /// A share from an already-superseded seal epoch was offered (a stale re-seal).
    #[error("stale seal epoch {got}: holder is sealed at epoch {current}")]
    StaleEpoch { got: u64, current: u64 },
    /// An operation needed a sealed holder, but it holds no share yet.
    #[error("holder is not sealed (receive a share first)")]
    NotSealed,
    /// The request named a different agent than the one this holder guards.
    #[error("request npub does not match the sealed record")]
    AgentMismatch,
    /// The wake condition is not yet satisfied (`now < wake_at`).
    #[error("too early to wake: now {now} < wake_at {wake_at}")]
    TooEarly { now: u64, wake_at: u64 },
    /// A different live lease is already held for this `(npub, resume_seq)` — the fence
    /// that refuses a second/competing spawner.
    #[error("a live lease {held} is already held for ({npub}, seq {resume_seq}); refusing a second")]
    LeaseHeld { held: String, npub: String, resume_seq: u64 },
    /// The presented lease is not this holder's current active lease (id / spawner /
    /// expiry mismatch — including a stale pre-renewal lease object).
    #[error("not the lease holder (lease does not match the active grant)")]
    NotLeaseHolder,
    /// The presented lease has expired.
    #[error("lease expired at {expires_at} (now {now})")]
    LeaseExpired { expires_at: u64, now: u64 },
    /// The presented lease does not match the sealed record (npub / resume_seq / digest).
    #[error("lease does not match the seal (npub / resume_seq / bundle_digest)")]
    LeaseMismatch,
    /// A filesystem operation on the holder's durable state failed.
    #[error("{op} holder state {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Serializing the holder state failed.
    #[error("serialize holder state: {0}")]
    Serialize(#[source] serde_json::Error),
    /// Deserializing the persisted holder state failed.
    #[error("deserialize holder state at {path}: {source}")]
    Deserialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// The ack a holder returns once it has durably (fsynced) received a share — proof to
/// the seal ceremony that this holder is guarding the seal. Carries only PUBLIC values
/// (commitments, digest, epoch), never the share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ack {
    /// Which holder acked.
    pub holder_id: String,
    /// The agent npub the seal is for.
    pub npub: String,
    /// The seal epoch acked.
    pub seal_epoch: u64,
    /// The bundle digest the seal commits to.
    pub bundle_digest: String,
    /// This holder's share commitment (public; lets the ceremony cross-check the seal).
    pub share_commitment: String,
}

/// An unseal request a spawner presents to a holder to obtain a lease.
///
/// `lease_id` is spawner-proposed and unique per resume attempt; a holder grants at
/// most one LIVE `lease_id` per `(npub, resume_seq)`. A competing spawner proposing a
/// different id is refused while the first is live (the fence).
///
/// Honest-actor scope: the `lease_id` + `spawner_ephemeral_pubkey` are trusted strings
/// (no proof-of-possession of the ephemeral key) — see the module docs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsealRequest {
    /// The agent npub being woken (must match the holder's sealed record).
    pub npub: String,
    /// The spawner-proposed lease id (unique per attempt).
    pub lease_id: String,
    /// The spawner's ephemeral pubkey — the lease binds to it (the fence target).
    pub spawner_ephemeral_pubkey: String,
    /// Requested lease lifetime in seconds; the holder sets `expires_at = now + this`.
    /// (A real holder would cap this; the thin slice trusts the ceremony's value.)
    pub lease_ttl_secs: u64,
}

/// The durable unit a holder fsyncs: its [`WatcherRecord`] plus the [`Share`] it guards.
///
/// The record is the barrier-2 watcher record; the share rides with it because a fresh
/// process must reload the share to reconstitute the seed (it cannot be re-derived). The
/// share is secret seed-reconstruction material, so the persisted file is `0600` and the
/// serialized buffer is zeroized after the write.
#[derive(Clone, Serialize, Deserialize)]
struct HolderState {
    record: WatcherRecord,
    share: Share,
}

/// One in-process share holder for a single agent's seal.
///
/// Constructed via [`Holder::open`], which loads any persisted state, so a holder
/// survives a process exit (the thin slice's "died & came back" at the holder layer).
///
/// INVARIANT: at most one live `Holder` handle per `(agent_id, holder_id)` at a time
/// (the single-instance invariant — see the module docs). The ceremony enforces it by
/// construction; concurrent handles would each load `active_lease` independently and
/// bypass the fence, which is why Move-2's concurrent holders need a file lock.
pub struct Holder {
    holder_id: String,
    state_path: PathBuf,
    state: Option<HolderState>,
}

/// The agent-scoped, holder-scoped path a holder persists its state at:
/// `<treasury_dir>/hibernate-{agent_id}/{holder_id}.holder.json`.
pub fn holder_path(treasury_dir: &Path, agent_id: &str, holder_id: &str) -> PathBuf {
    hibernate_dir(treasury_dir, agent_id).join(format!("{holder_id}.holder.json"))
}

/// Build the public ack for `record` (no secret material).
fn ack_from(holder_id: &str, record: &WatcherRecord) -> Ack {
    Ack {
        holder_id: holder_id.to_string(),
        npub: record.npub.clone(),
        seal_epoch: record.seal_epoch,
        bundle_digest: record.bundle_digest.clone(),
        share_commitment: record.share_commitment.clone(),
    }
}

impl Holder {
    /// Open holder `holder_id` for `agent_id`, loading any persisted state. A holder
    /// with no persisted state is "unsealed" until it receives a share. Reloading is how
    /// a fresh process re-instantiates a holder WITH its share after the prior process
    /// exited.
    ///
    /// Caller's responsibility (single-instance invariant): do not hold two live
    /// `Holder` handles for the same `(agent_id, holder_id)` concurrently — the fence is
    /// per-handle and concurrent handles would bypass it. The thin-slice ceremony drives
    /// one handle per holder; Move-2's concurrent holders need a file lock here.
    pub fn open(treasury_dir: &Path, agent_id: &str, holder_id: &str) -> Result<Self, HolderError> {
        let state_path = holder_path(treasury_dir, agent_id, holder_id);
        let state = if state_path.exists() {
            // The persisted bytes carry the share, so wipe the read buffer after parse.
            let raw = Zeroizing::new(fs::read(&state_path).map_err(|source| HolderError::Io {
                op: "read",
                path: state_path.clone(),
                source,
            })?);
            let state: HolderState = serde_json::from_slice(raw.as_slice())
                .map_err(|source| HolderError::Deserialize { path: state_path.clone(), source })?;
            Some(state)
        } else {
            None
        };
        Ok(Holder { holder_id: holder_id.to_string(), state_path, state })
    }

    /// This holder's id.
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// The current watcher record, if this holder is sealed.
    pub fn record(&self) -> Option<&WatcherRecord> {
        self.state.as_ref().map(|s| &s.record)
    }

    /// Whether this holder currently guards a seal.
    pub fn is_sealed(&self) -> bool {
        self.state.is_some()
    }

    /// Barrier 2: verify and durably accept a share, then ack.
    ///
    /// Verifies the share against its commitment (H1 [`verify_share`]), then by epoch:
    /// - `seal_epoch < current` → refused as a stale re-seal ([`HolderError::StaleEpoch`]).
    /// - `seal_epoch == current` → IDEMPOTENT no-op: a fresh seal BUMPS the epoch, so an
    ///   equal epoch means "already sealed here". The established record is left intact —
    ///   crucially preserving any LIVE lease + release history (rebuilding would silently
    ///   clear the fence) — and its ack is returned.
    /// - `seal_epoch > current` (or first seal) → a new generation: build the record,
    ///   persist `{record, share}` BEFORE acking (persist-before-commit), and ack.
    pub fn receive_share(
        &mut self,
        share: Share,
        npub: &str,
        bundle_digest: &str,
        resume_seq: u64,
        wake_conditions: WakeConditions,
    ) -> Result<Ack, HolderError> {
        verify_share(&share)?;

        if let Some(state) = &self.state {
            if share.seal_epoch < state.record.seal_epoch {
                return Err(HolderError::StaleEpoch {
                    got: share.seal_epoch,
                    current: state.record.seal_epoch,
                });
            }
            if share.seal_epoch == state.record.seal_epoch {
                // Idempotent: already sealed at this epoch. Preserve the live lease +
                // history; just re-ack the established record.
                return Ok(ack_from(&self.holder_id, &state.record));
            }
            // seal_epoch > current: a new seal generation supersedes — fall through.
        }

        let record = WatcherRecord {
            npub: npub.to_string(),
            seal_epoch: share.seal_epoch,
            bundle_digest: bundle_digest.to_string(),
            resume_seq,
            wake_conditions,
            share_commitment: share.commitment.clone(),
            active_lease: None,
            release_history: Vec::new(),
        };
        let ack = ack_from(&self.holder_id, &record);
        let candidate = HolderState { record, share };
        // Persist-before-commit: durable BEFORE the in-memory state advances + before ack.
        self.write_state(&candidate)?;
        self.state = Some(candidate);
        Ok(ack)
    }

    /// Barrier 3: validate the wake condition and issue a fencing lease, refusing a
    /// second live lease for the same `(npub, resume_seq)`.
    ///
    /// - Refuses unless `now >= wake_at` ([`HolderError::TooEarly`]).
    /// - If a DIFFERENT lease is live, refuses ([`HolderError::LeaseHeld`]) — the fence.
    /// - If the SAME `(lease_id, spawner)` is live, treats it as a renewal (extends
    ///   `expires_at`).
    /// - If the prior lease has expired (or none), grants the requested `lease_id` — so
    ///   a retry after expiry gets a NEW lease.
    ///
    /// Persist-before-commit: the updated record (with the new `active_lease`) is fsynced
    /// BEFORE the lease is returned. Honest-actor scope: the request's `lease_id` +
    /// `spawner_ephemeral_pubkey` are trusted strings (no proof-of-possession) — a replay
    /// reads as the same spawner; Move-2 adds a schnorr PoP.
    pub fn issue_lease(&mut self, req: &UnsealRequest, now: u64) -> Result<Lease, HolderError> {
        // The assent marker is captured before borrowing state (thin-slice stand-in for
        // a signature; see module docs).
        let assent = self.assent_tag();

        let (lease, candidate) = {
            let current = self.state.as_ref().ok_or(HolderError::NotSealed)?;
            let record = &current.record;

            if req.npub != record.npub {
                return Err(HolderError::AgentMismatch);
            }
            if now < record.wake_conditions.wake_at {
                return Err(HolderError::TooEarly { now, wake_at: record.wake_conditions.wake_at });
            }

            // Single-live-lease fence.
            if let Some(active) = &record.active_lease {
                if active.expires_at > now {
                    let same = active.lease_id == req.lease_id
                        && active.spawner_ephemeral_pubkey == req.spawner_ephemeral_pubkey;
                    if !same {
                        return Err(HolderError::LeaseHeld {
                            held: active.lease_id.clone(),
                            npub: record.npub.clone(),
                            resume_seq: record.resume_seq,
                        });
                    }
                    // else: renewal of the same lease by the same spawner — fall through.
                }
                // else: expired — fall through to grant (a retry's new lease_id is OK).
            }

            let expires_at = now.saturating_add(req.lease_ttl_secs);
            let mut candidate = current.clone();
            candidate.record.active_lease = Some(ActiveLease {
                lease_id: req.lease_id.clone(),
                expires_at,
                spawner_ephemeral_pubkey: req.spawner_ephemeral_pubkey.clone(),
            });
            let lease = Lease {
                npub: candidate.record.npub.clone(),
                resume_seq: candidate.record.resume_seq,
                lease_id: req.lease_id.clone(),
                bundle_digest: candidate.record.bundle_digest.clone(),
                expires_at,
                spawner_ephemeral_pubkey: req.spawner_ephemeral_pubkey.clone(),
                quorum_sigs: vec![assent],
            };
            (lease, candidate)
        };

        // Persist-before-commit (write-before-release).
        self.write_state(&candidate)?;
        self.state = Some(candidate);
        Ok(lease)
    }

    /// Release this holder's share to the holder of the current live lease, recording
    /// the release in `release_history` (fsynced BEFORE the share is returned).
    ///
    /// Refuses unless the presented lease matches the seal (npub / resume_seq /
    /// bundle_digest) AND is this holder's active, unexpired lease — bound to the EXACT
    /// current incarnation including `expires_at`, so a stale pre-renewal lease object
    /// cannot release after the lease was renewed. Releasing again to the SAME lease is
    /// idempotent (the requester already has the share), so history is not double-appended
    /// and no extra write is done. Honest-actor scope: no proof-of-possession of the
    /// spawner key (see module docs).
    pub fn release_share(&mut self, lease: &Lease, now: u64) -> Result<Share, HolderError> {
        let candidate = {
            let current = self.state.as_ref().ok_or(HolderError::NotSealed)?;
            let record = &current.record;

            if lease.npub != record.npub
                || lease.resume_seq != record.resume_seq
                || lease.bundle_digest != record.bundle_digest
            {
                return Err(HolderError::LeaseMismatch);
            }
            {
                let active = record.active_lease.as_ref().ok_or(HolderError::NotLeaseHolder)?;
                // Bind to the exact current incarnation (id + spawner + expiry), so a
                // stale pre-renewal lease object is rejected.
                if active.lease_id != lease.lease_id
                    || active.spawner_ephemeral_pubkey != lease.spawner_ephemeral_pubkey
                    || active.expires_at != lease.expires_at
                {
                    return Err(HolderError::NotLeaseHolder);
                }
                if active.expires_at <= now {
                    return Err(HolderError::LeaseExpired { expires_at: active.expires_at, now });
                }
            }
            // Idempotent: already released to this lease -> no state change, return share.
            let already = record.release_history.iter().any(|e| {
                e.lease_id == lease.lease_id
                    && e.spawner_ephemeral_pubkey == lease.spawner_ephemeral_pubkey
            });
            if already {
                return Ok(current.share.clone());
            }
            let mut candidate = current.clone();
            candidate.record.release_history.push(ReleaseEntry {
                lease_id: lease.lease_id.clone(),
                spawner_ephemeral_pubkey: lease.spawner_ephemeral_pubkey.clone(),
                released_at: now,
            });
            candidate
        };

        // Persist-before-commit: the release is durable BEFORE the share leaves.
        self.write_state(&candidate)?;
        let share = candidate.share.clone();
        self.state = Some(candidate);
        Ok(share)
    }

    /// The in-process assent marker (NOT a cryptographic signature — see module docs).
    fn assent_tag(&self) -> String {
        format!("holder:{}", self.holder_id)
    }

    /// Durably write a CANDIDATE state (atomic + fsync, 0600) WITHOUT touching
    /// `self.state` — the persist-before-commit primitive: callers persist the candidate,
    /// and only on success advance `self.state`. The serialized buffer carries the share,
    /// so it is zeroized after the write.
    fn write_state(&self, state: &HolderState) -> Result<(), HolderError> {
        let bytes = Zeroizing::new(serde_json::to_vec(state).map_err(HolderError::Serialize)?);
        write_atomic(&self.state_path, bytes.as_slice())
    }
}

/// Durable atomic write, mirroring `bundle::write_atomic`'s hardened discipline: create
/// a FRESH sibling temp file at `0600` (`O_EXCL` + random name — never reuse a stale
/// temp with looser perms), write, fsync it, atomically rename into place, then fsync
/// the directory so the rename itself is durable. Both fsyncs are mandatory (Linux/
/// Firecracker + macOS). `0600` because the holder file carries share material.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), HolderError> {
    let dir = path.parent().ok_or_else(|| HolderError::Io {
        op: "resolve-parent",
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "holder state path has no parent directory",
        ),
    })?;
    fs::create_dir_all(dir).map_err(|source| HolderError::Io {
        op: "create-dir",
        path: dir.to_path_buf(),
        source,
    })?;

    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("holder");
    let tmp = dir.join(format!(".{fname}.tmp.{:016x}", rand::random::<u64>()));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp).map_err(|source| HolderError::Io {
            op: "create-temp",
            path: tmp.clone(),
            source,
        })?;
        f.write_all(bytes).map_err(|source| HolderError::Io {
            op: "write-temp",
            path: tmp.clone(),
            source,
        })?;
        f.sync_all().map_err(|source| HolderError::Io {
            op: "fsync-temp",
            path: tmp.clone(),
            source,
        })?;
    }
    fs::rename(&tmp, path).map_err(|source| HolderError::Io {
        op: "rename",
        path: path.to_path_buf(),
        source,
    })?;
    let dirf = File::open(dir).map_err(|source| HolderError::Io {
        op: "open-dir",
        path: dir.to_path_buf(),
        source,
    })?;
    dirf.sync_all().map_err(|source| HolderError::Io {
        op: "fsync-dir",
        path: dir.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibernate::shamir::{split_seed, MasterSeed};
    use crate::hibernate::SEAL_SHARES;

    const NPUB: &str = "npub1agent";
    const DIGEST: &str = "bundledigest";
    const RESUME_SEQ: u64 = 5;
    const WAKE_AT: u64 = 1_000;

    fn shares(epoch: u64) -> Vec<Share> {
        // A deterministic non-secret seed is fine for the holder tests.
        split_seed(&MasterSeed::from_bytes([7u8; 32]), epoch)
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir()
            .join(format!("kirby-hibernate-holder-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    fn seal_one(dir: &Path, holder_id: &str, epoch: u64) -> (Holder, Share) {
        let mut h = Holder::open(dir, "agent-0", holder_id).unwrap();
        let share = shares(epoch).remove(0);
        let ack = h
            .receive_share(share.clone(), NPUB, DIGEST, RESUME_SEQ, WakeConditions { wake_at: WAKE_AT })
            .unwrap();
        assert_eq!(ack.holder_id, holder_id);
        assert_eq!(ack.npub, NPUB);
        assert_eq!(ack.seal_epoch, epoch);
        assert_eq!(ack.bundle_digest, DIGEST);
        assert_eq!(ack.share_commitment, share.commitment);
        (h, share)
    }

    fn unseal_req(lease_id: &str, spawner: &str, ttl: u64) -> UnsealRequest {
        UnsealRequest {
            npub: NPUB.to_string(),
            lease_id: lease_id.to_string(),
            spawner_ephemeral_pubkey: spawner.to_string(),
            lease_ttl_secs: ttl,
        }
    }

    #[test]
    fn receive_share_persists_a_durable_record_and_acks() {
        let dir = tempdir();
        let (h, _share) = seal_one(&dir, "holder-0", 1);
        assert!(h.is_sealed());
        let rec = h.record().unwrap();
        assert_eq!(rec.npub, NPUB);
        assert_eq!(rec.seal_epoch, 1);
        assert_eq!(rec.resume_seq, RESUME_SEQ);
        assert_eq!(rec.wake_conditions.wake_at, WAKE_AT);
        assert!(rec.active_lease.is_none());
        assert!(rec.release_history.is_empty());
        // durable: a fresh Holder reloads the record + share (the "fresh process" path).
        let reopened = Holder::open(&dir, "agent-0", "holder-0").unwrap();
        assert!(reopened.is_sealed());
        assert_eq!(reopened.record().unwrap().seal_epoch, 1);
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_holder_state_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        let _ = seal_one(&dir, "holder-0", 1);
        let mode = std::fs::metadata(holder_path(&dir, "agent-0", "holder-0"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "holder file carries share material; must be 0600, got {mode:o}");
        cleanup(&dir);
    }

    #[test]
    fn a_corrupt_share_is_rejected() {
        let dir = tempdir();
        let mut h = Holder::open(&dir, "agent-0", "holder-0").unwrap();
        let mut share = shares(1).remove(0);
        // garble the bytes but leave the (now stale) commitment.
        let mut raw = share.share_bytes.as_slice().to_vec();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        share.share_bytes = super::super::ShareBytes::new(raw);
        match h.receive_share(share, NPUB, DIGEST, RESUME_SEQ, WakeConditions { wake_at: WAKE_AT }) {
            Err(HolderError::ShareRejected(ShamirError::CorruptShare(_))) => {}
            other => panic!("expected ShareRejected(CorruptShare), got {other:?}"),
        }
        assert!(!h.is_sealed(), "a rejected share must not seal the holder");
        cleanup(&dir);
    }

    #[test]
    fn stale_epoch_share_is_refused() {
        let dir = tempdir();
        let mut h = Holder::open(&dir, "agent-0", "holder-0").unwrap();
        h.receive_share(shares(2).remove(0), NPUB, DIGEST, RESUME_SEQ, WakeConditions { wake_at: WAKE_AT })
            .unwrap();
        // an epoch-1 share now is stale vs the epoch-2 seal.
        match h.receive_share(shares(1).remove(0), NPUB, DIGEST, RESUME_SEQ, WakeConditions { wake_at: WAKE_AT }) {
            Err(HolderError::StaleEpoch { got: 1, current: 2 }) => {}
            other => panic!("expected StaleEpoch{{1,2}}, got {other:?}"),
        }
        assert_eq!(h.record().unwrap().seal_epoch, 2, "the current seal must be unchanged");
        cleanup(&dir);
    }

    #[test]
    fn receive_same_epoch_preserves_a_live_lease() {
        // FIX: a same-epoch re-delivery must NOT rebuild the record and clear the fence.
        let dir = tempdir();
        let (mut h, _) = seal_one(&dir, "holder-0", 1);
        h.issue_lease(&unseal_req("lease-A", "spawner-X", 100), WAKE_AT).unwrap();
        assert!(h.record().unwrap().active_lease.is_some());
        // re-deliver a share at the SAME epoch.
        let ack = h
            .receive_share(shares(1).remove(1), NPUB, DIGEST, RESUME_SEQ, WakeConditions { wake_at: WAKE_AT })
            .unwrap();
        assert_eq!(ack.seal_epoch, 1);
        let active = h
            .record()
            .unwrap()
            .active_lease
            .as_ref()
            .expect("the live lease must be preserved across a same-epoch receive");
        assert_eq!(active.lease_id, "lease-A");
        cleanup(&dir);
    }

    #[test]
    fn issue_lease_gates_on_wake_at() {
        let dir = tempdir();
        let (mut h, _) = seal_one(&dir, "holder-0", 1);
        let req = unseal_req("lease-A", "spawner-X", 60);
        // before wake_at: refused.
        match h.issue_lease(&req, WAKE_AT - 1) {
            Err(HolderError::TooEarly { now, wake_at }) => {
                assert_eq!(now, WAKE_AT - 1);
                assert_eq!(wake_at, WAKE_AT);
            }
            other => panic!("expected TooEarly, got {other:?}"),
        }
        // at wake_at: granted.
        let lease = h.issue_lease(&req, WAKE_AT).unwrap();
        assert_eq!(lease.lease_id, "lease-A");
        assert_eq!(lease.npub, NPUB);
        assert_eq!(lease.resume_seq, RESUME_SEQ);
        assert_eq!(lease.bundle_digest, DIGEST);
        assert_eq!(lease.expires_at, WAKE_AT + 60);
        assert_eq!(lease.quorum_sigs, vec!["holder:holder-0".to_string()]);
        cleanup(&dir);
    }

    #[test]
    fn refuses_a_second_live_lease_but_allows_same_spawner_renewal() {
        let dir = tempdir();
        let (mut h, _) = seal_one(&dir, "holder-0", 1);
        let now = WAKE_AT;
        let a = h.issue_lease(&unseal_req("lease-A", "spawner-X", 100), now).unwrap();
        // a competing spawner with a different lease_id while A is live: refused.
        match h.issue_lease(&unseal_req("lease-B", "spawner-Y", 100), now + 1) {
            Err(HolderError::LeaseHeld { held, npub, resume_seq }) => {
                assert_eq!(held, "lease-A");
                assert_eq!(npub, NPUB);
                assert_eq!(resume_seq, RESUME_SEQ);
            }
            other => panic!("expected LeaseHeld, got {other:?}"),
        }
        // the same spawner re-requesting the same lease_id: a renewal (extends expiry).
        let renewed = h.issue_lease(&unseal_req("lease-A", "spawner-X", 100), now + 10).unwrap();
        assert_eq!(renewed.lease_id, a.lease_id);
        assert_eq!(renewed.expires_at, now + 10 + 100, "renewal extends the expiry");
        cleanup(&dir);
    }

    #[test]
    fn an_expired_lease_lets_a_retry_get_a_new_lease_id() {
        let dir = tempdir();
        let (mut h, _) = seal_one(&dir, "holder-0", 1);
        let a = h.issue_lease(&unseal_req("lease-A", "spawner-X", 30), WAKE_AT).unwrap();
        // after A expires, a different spawner's retry with a new id is granted.
        let after = a.expires_at + 1;
        let b = h.issue_lease(&unseal_req("lease-B", "spawner-Y", 30), after).unwrap();
        assert_eq!(b.lease_id, "lease-B");
        assert_eq!(h.record().unwrap().active_lease.as_ref().unwrap().lease_id, "lease-B");
        cleanup(&dir);
    }

    #[test]
    fn release_share_requires_the_active_lease_and_records_history() {
        let dir = tempdir();
        let (mut h, share) = seal_one(&dir, "holder-0", 1);
        let lease = h.issue_lease(&unseal_req("lease-A", "spawner-X", 100), WAKE_AT).unwrap();

        // a forged lease (wrong id) cannot release.
        let mut forged = lease.clone();
        forged.lease_id = "lease-FORGED".to_string();
        assert!(matches!(h.release_share(&forged, WAKE_AT + 1), Err(HolderError::NotLeaseHolder)));

        // the real lease holder gets the share, and the release is recorded.
        let released = h.release_share(&lease, WAKE_AT + 1).unwrap();
        assert_eq!(released.share_bytes.as_slice(), share.share_bytes.as_slice());
        let hist = &h.record().unwrap().release_history;
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].lease_id, "lease-A");
        assert_eq!(hist[0].spawner_ephemeral_pubkey, "spawner-X");
        assert_eq!(hist[0].released_at, WAKE_AT + 1);

        // idempotent: releasing again to the same lease does not double-append history.
        let _ = h.release_share(&lease, WAKE_AT + 2).unwrap();
        assert_eq!(h.record().unwrap().release_history.len(), 1);
        cleanup(&dir);
    }

    #[test]
    fn a_stale_lease_object_is_rejected_after_renewal() {
        // FIX: binding the release match to expires_at stops a pre-renewal lease object
        // from releasing once the lease has been renewed to a later expiry.
        let dir = tempdir();
        let (mut h, _) = seal_one(&dir, "holder-0", 1);
        let stale = h.issue_lease(&unseal_req("lease-A", "spawner-X", 30), WAKE_AT).unwrap();
        let renewed = h.issue_lease(&unseal_req("lease-A", "spawner-X", 30), WAKE_AT + 5).unwrap();
        assert_ne!(stale.expires_at, renewed.expires_at);
        // the stale (pre-renewal) lease object — same id + spawner, OLD expiry — refused.
        match h.release_share(&stale, WAKE_AT + 6) {
            Err(HolderError::NotLeaseHolder) => {}
            other => panic!("expected NotLeaseHolder for the stale lease, got {other:?}"),
        }
        // the renewed lease object releases fine.
        let _ = h.release_share(&renewed, WAKE_AT + 6).unwrap();
        cleanup(&dir);
    }

    #[test]
    fn release_with_an_expired_lease_is_refused() {
        let dir = tempdir();
        let (mut h, _) = seal_one(&dir, "holder-0", 1);
        let lease = h.issue_lease(&unseal_req("lease-A", "spawner-X", 30), WAKE_AT).unwrap();
        match h.release_share(&lease, lease.expires_at + 1) {
            Err(HolderError::LeaseExpired { expires_at, now }) => {
                assert_eq!(expires_at, lease.expires_at);
                assert_eq!(now, lease.expires_at + 1);
            }
            other => panic!("expected LeaseExpired, got {other:?}"),
        }
        cleanup(&dir);
    }

    #[test]
    fn unsealed_holder_refuses_lease_and_release() {
        let dir = tempdir();
        let mut h = Holder::open(&dir, "agent-0", "holder-0").unwrap();
        assert!(matches!(
            h.issue_lease(&unseal_req("lease-A", "spawner-X", 60), WAKE_AT),
            Err(HolderError::NotSealed)
        ));
        cleanup(&dir);
    }

    #[test]
    fn a_three_holder_quorum_each_fences_independently() {
        // The 2-of-3 quorum = 3 holder instances; each independently refuses a second
        // live lease, so a competing spawner cannot reach threshold.
        let dir = tempdir();
        let mut holders: Vec<Holder> = (0..SEAL_SHARES)
            .map(|i| {
                let mut h = Holder::open(&dir, "agent-0", &format!("holder-{i}")).unwrap();
                let share = shares(1).remove(i as usize);
                h.receive_share(share, NPUB, DIGEST, RESUME_SEQ, WakeConditions { wake_at: WAKE_AT })
                    .unwrap();
                h
            })
            .collect();

        // spawner X obtains a grant from all three.
        let grants_x: Vec<_> = holders
            .iter_mut()
            .map(|h| h.issue_lease(&unseal_req("lease-X", "spawner-X", 100), WAKE_AT).unwrap())
            .collect();
        assert_eq!(grants_x.len(), 3);

        // spawner Y is refused by every holder (none free) -> cannot reach 2-of-3.
        let mut y_grants = 0;
        for h in holders.iter_mut() {
            if h.issue_lease(&unseal_req("lease-Y", "spawner-Y", 100), WAKE_AT + 1).is_ok() {
                y_grants += 1;
            }
        }
        assert_eq!(y_grants, 0, "a competing spawner must be fenced by every holder");
        cleanup(&dir);
    }
}
