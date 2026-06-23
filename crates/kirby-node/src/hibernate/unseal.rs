//! H5: the UNSEAL ceremony + lease-gated reconstitution
//! (`plans/build-spec-kirby-hibernation-thinslice.md`, chunk H5).
//!
//! This is the resurrection orchestration — the "came back as itself" half. It does NOT
//! reimplement crypto or storage; it COMPOSES the merged primitives:
//! H3 [`fetch_wake_request_by_agent`], H4a [`Holder::issue_lease`] / [`Holder::release_share`],
//! H1 [`combine_shares`] / [`derive_subkeys`], H2 [`load_bundle`].
//!
//! ## The ceremony
//!
//! 1. **Fetch** the agent's [`WakeRequest`] from the relay ([`fetch_wake_request_by_agent`]):
//!    the `bundle_digest`, seal block, `resume_seq`, and `wake_at`.
//! 2. **Open the roster the seal stamped in** — the holder ids travel in
//!    `wake.seal.holder_pubkeys` (the seal↔unseal contract), so unseal opens THOSE ids (same
//!    `agent_id` / `treasury_dir`); it never hardcodes the roster. It then requests an unseal
//!    from each with a fresh `lease_id` + `spawner_ephemeral_pubkey` ([`UnsealRequest`]) and
//!    collects ≥[`SEAL_THRESHOLD`] leases. The fence grants only THIS spawner, so a competitor
//!    is refused ([`HolderError::LeaseHeld`]) and cannot assemble a quorum.
//! 3. **Aggregate** the granted holder leases into the runtime's fencing token. Each holder
//!    issues its own [`Lease`] (its own `expires_at`, its own assent); the aggregate
//!    reconciles `expires_at` = MIN of the granted (most conservative liveness) and unions the
//!    per-holder assents into the quorum proof.
//! 4. **Release** ≥[`SEAL_THRESHOLD`] shares ([`Holder::release_share`], each holder handed
//!    its OWN issued lease), **bind each to the published seal** (commitment ∈
//!    `wake.seal.commitments` and `seal_epoch == wake.seal.seal_epoch`), then [`combine_shares`]
//!    (H1) → [`derive_subkeys`] (H1).
//! 5. **Restore** the bundle the wake-request commits to ([`load_bundle`] with the
//!    wake-request's `bundle_digest` — the digest MUST match, restore-consistency) and resume
//!    at `resume_seq + 1`.
//! 6. **Lease gates live authority** (barrier 3): the resumed [`LeasedRuntime`] exposes its
//!    identity / state / wallet keys ONLY inside [`LeasedRuntime::with_authority`], which
//!    re-checks liveness on EVERY call and scopes the keys to the closure — so a stale handle
//!    can never use them past `expires_at`. The runtime renews before `expires_at`
//!    ([`LeasedRuntime::renew`]) or must self-stop ([`LeasedRuntime::must_self_stop`]).
//!
//! ## Binding the shares to the seal (integrity)
//!
//! A holder's own commitment only proves a share is internally consistent — NOT that it is one
//! of THIS seal's shares. Tampered/stale holder state with a valid self-commitment would
//! otherwise combine to a DIFFERENT seed (a wrong identity / wallet) while the bundle digest
//! still passed. So before combining, each released share is bound to the PUBLISHED seal: its
//! `commitment` must be one of `wake.seal.commitments` and its `seal_epoch` must equal
//! `wake.seal.seal_epoch`. Set-membership (not a positional `commitments[i]`) is used so the
//! check stays correct when a holder is skipped (open failure) and roster indices no longer
//! line up — each share is still pinned to the published set, and the commitment's sha256
//! binding makes membership ⟺ "exactly one of this seal's shares".
//!
//! ## Single shared `now`
//!
//! The thin slice drives in-process holders synchronously, so the ceremony captures ONE `now`
//! and passes it to every holder. The holders therefore agree on `expires_at`, the aggregate's
//! MIN equals each, and each holder's own lease matches its durable record at release time. The
//! MIN-reconciliation is the GENERAL rule that stays correct when (Move-2) holders disagree.
//!
//! ## Holder lifecycle + the concurrency boundary
//!
//! Unseal OPENS the roster's holders, drives them, and drops them within the call — honoring
//! H4a's single-live-handle invariant by construction. The fence holds across SEQUENTIAL
//! attempts because each holder's `active_lease` is DURABLE: a later spawner opening the same
//! ids reloads the earlier live lease and is refused. A holder whose durable state cannot be
//! opened is skipped (a 2-of-3 quorum is meant to survive a lost holder), so it does not count.
//!
//! KNOWN GAP (inherited from H4a, not closed here): CONCURRENT spawners are NOT fenced. Two
//! attempts that open the roster at the same instant each read `active_lease = None` and both
//! persist a grant — a fork. The thin-slice round-trip is single-attempt, so it does not arise;
//! concurrent / distributed unseal needs a per-holder file lock (H4a's documented Move-2
//! hardening, the top flock item). Called out, not relied upon.
//!
//! ## Honest-actor scope
//!
//! Inherited from H4a: `lease_id` / `spawner_ephemeral_pubkey` are trusted strings (no schnorr
//! proof-of-possession yet). The lease gates *authority*, not the in-process key bytes a buggy
//! caller could deliberately copy out of [`with_authority`](LeasedRuntime::with_authority) — it
//! is the protocol fence, not a hardware boundary.
//!
//! ## Secret hygiene
//!
//! The recovered [`MasterSeed`](super::shamir) zeroizes the moment it leaves scope (after
//! derivation); the released [`Share`]s carry zeroizing [`ShareBytes`](super::ShareBytes) and
//! wipe on drop; the derived [`Subkeys`] live behind the authority gate and zeroize with the
//! runtime. No seed, subkey, or share byte is ever logged.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::bundle::{load_bundle, BundleError};
use super::holder::{Holder, HolderError, UnsealRequest};
use super::shamir::{
    combine_shares, derive_subkeys, ShamirError, Subkeys, IDENTITY_KEY_LEN, STATE_KEY_LEN,
    WALLET_SEED_LEN,
};
use super::wake::fetch_wake_request_by_agent;
use super::{Lease, Share, StateBundle, WakeRequest, SEAL_THRESHOLD};

/// A spawner's proposal for one resume attempt: a fresh, unique `lease_id` and the spawner's
/// `ephemeral_pubkey` (the fence target the lease binds to), plus the requested lifetime. A
/// competing spawner proposing a different id/key is fenced while the first lease is live.
#[derive(Debug, Clone)]
pub struct SpawnerProposal {
    /// The spawner-proposed lease id, unique per attempt.
    pub lease_id: String,
    /// The spawner's ephemeral pubkey — the lease binds to it.
    pub ephemeral_pubkey: String,
    /// Requested lease lifetime in seconds; each holder sets `expires_at = now + this`.
    pub lease_ttl_secs: u64,
}

/// What can go wrong unsealing / reconstituting.
#[derive(Debug, thiserror::Error)]
pub enum UnsealError {
    /// The relay holds no wake-request for this agent.
    #[error("no wake-request on the relay for this agent")]
    NoWakeRequest,
    /// The wake-request's seal block is malformed (wrong threshold, roster/commitment count
    /// mismatch, or a duplicate holder id). Carries a static reason.
    #[error("malformed wake-request seal: {0}")]
    MalformedSeal(&'static str),
    /// A released share is not bound to the published seal — its commitment is not one of
    /// `wake.seal.commitments`, or its `seal_epoch` differs. (Tampered / stale holder state.)
    #[error("share {share_index} is not bound to the published seal (commitment/epoch mismatch)")]
    ShareSealMismatch { share_index: u8 },
    /// Fewer than [`SEAL_THRESHOLD`] holders granted a lease for this seal — a competitor may
    /// hold the fence, holders are unavailable, or it is not yet `wake_at`.
    #[error("could not assemble a lease quorum: got {got} of {needed} required")]
    QuorumUnavailable { got: usize, needed: usize },
    /// The aggregated lease has expired: the runtime has NO live authority and must self-stop.
    #[error("lease expired at {expires_at} (now {now}); the runtime must self-stop")]
    LeaseExpired { expires_at: u64, now: u64 },
    /// A holder operation failed (e.g. a release after the lease lapsed).
    #[error("holder: {0}")]
    Holder(#[from] HolderError),
    /// Seed reconstruction failed (too few / corrupt shares).
    #[error("reconstruct seed: {0}")]
    Shamir(#[from] ShamirError),
    /// Restoring the bundle failed — notably a digest mismatch (restore-consistency).
    #[error("restore bundle: {0}")]
    Bundle(#[from] BundleError),
    /// Fetching the wake-request from the relay failed.
    #[error("fetch wake-request: {0}")]
    Fetch(String),
}

/// The live-authority capability exposed ONLY inside [`LeasedRuntime::with_authority`], whose
/// closure re-checks the lease at use. Holding it (transiently, within the closure) is the
/// runtime's proof it may identity-sign / wallet-spend / checkpoint (barrier 3); the subkeys are
/// reachable through nothing else, and the borrow cannot escape the closure.
pub struct Authority<'a> {
    subkeys: &'a Subkeys,
}

impl Authority<'_> {
    /// The agent identity subkey (downstream: the Nostr/identity signing key).
    pub fn identity_key(&self) -> &[u8; IDENTITY_KEY_LEN] {
        &self.subkeys.identity_key
    }
    /// The state-bundle encryption subkey.
    pub fn state_key(&self) -> &[u8; STATE_KEY_LEN] {
        &self.subkeys.state_key
    }
    /// The ecash wallet seed subkey.
    pub fn wallet_seed(&self) -> &[u8; WALLET_SEED_LEN] {
        &self.subkeys.wallet_seed
    }
}

/// A reconstituted, lease-gated agent runtime: the SAME identity + state the seal committed,
/// holding the quorum's aggregated fencing [`Lease`].
///
/// The derived [`Subkeys`] are PRIVATE and reachable only inside
/// [`with_authority`](Self::with_authority), which re-checks the lease on every call — so
/// identity-sign / wallet-spend / checkpoint are gated on a live lease at the moment of use
/// (barrier 3), and no key reference can outlive that check. It also retains where its holders
/// live (`treasury_dir` / `agent_id` / `holder_ids`) so [`renew`](Self::renew) can re-open the
/// same roster. Not `Debug`: it holds secret subkeys.
pub struct LeasedRuntime {
    npub: String,
    lease: Lease,
    subkeys: Subkeys,
    bundle: StateBundle,
    treasury_dir: PathBuf,
    agent_id: String,
    holder_ids: Vec<String>,
}

impl LeasedRuntime {
    /// The reconstituted agent's npub (its stable identity, preserved across the sleep).
    pub fn npub(&self) -> &str {
        &self.npub
    }

    /// The restored state bundle (memory / wallet / checkpoint snapshot).
    pub fn bundle(&self) -> &StateBundle {
        &self.bundle
    }

    /// The sequence the resumed agent runs at: one past the sealed `resume_seq`.
    pub fn next_resume_seq(&self) -> u64 {
        self.bundle.resume_seq.saturating_add(1)
    }

    /// The runtime's current aggregated fencing token.
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Whether the aggregated lease is still live at `now`.
    pub fn is_live(&self, now: u64) -> bool {
        now < self.lease.expires_at
    }

    /// Whether the runtime must self-stop: its lease has lapsed, so it holds no authority.
    pub fn must_self_stop(&self, now: u64) -> bool {
        !self.is_live(now)
    }

    /// Barrier 3: run `f` with live authority — the capability to identity-sign / wallet-spend /
    /// checkpoint — ONLY if the aggregated lease is live at `now`, else [`UnsealError::LeaseExpired`]
    /// (the caller must self-stop). The liveness is re-checked on EVERY call, and the
    /// [`Authority`] (hence the key references) cannot escape the closure, so keys can never be
    /// used past `expires_at`. (A caller that explicitly COPIES key bytes out owns that copy's
    /// hygiene — the honest-actor boundary.)
    pub fn with_authority<R>(
        &self,
        now: u64,
        f: impl FnOnce(&Authority<'_>) -> R,
    ) -> Result<R, UnsealError> {
        if !self.is_live(now) {
            return Err(UnsealError::LeaseExpired {
                expires_at: self.lease.expires_at,
                now,
            });
        }
        Ok(f(&Authority {
            subkeys: &self.subkeys,
        }))
    }

    /// Renew before `expires_at` by re-opening the roster and re-gathering the quorum's assent
    /// for the SAME lease (same `lease_id` + spawner → the holders' renewal path extends
    /// `expires_at`), then re-aggregating.
    ///
    /// An ALREADY-EXPIRED runtime is refused ([`UnsealError::LeaseExpired`]) BEFORE any holder is
    /// contacted: once the lease has lapsed the runtime has no authority, and the holders' fence
    /// slot is free — so a "renewal" would silently re-grant the same lease and resurrect dead
    /// authority. A lapsed runtime must fully re-reconstitute (re-fence through the quorum), not
    /// renew. On a gather failure the old lease is kept (a partial failure does not widen
    /// authority) and the caller self-stops once it lapses.
    pub fn renew(&mut self, lease_ttl_secs: u64, now: u64) -> Result<(), UnsealError> {
        if !self.is_live(now) {
            return Err(UnsealError::LeaseExpired {
                expires_at: self.lease.expires_at,
                now,
            });
        }
        let req = UnsealRequest {
            npub: self.npub.clone(),
            lease_id: self.lease.lease_id.clone(),
            spawner_ephemeral_pubkey: self.lease.spawner_ephemeral_pubkey.clone(),
            lease_ttl_secs,
        };
        let mut holders = open_roster(&self.treasury_dir, &self.agent_id, &self.holder_ids);
        let granted = gather_leases(
            &mut holders,
            &req,
            &self.lease.bundle_digest,
            self.lease.resume_seq,
            SEAL_THRESHOLD as usize,
            now,
        )?;
        self.lease = aggregate_lease(&granted);
        Ok(())
    }
}

/// Open the holder roster the seal stamped into the wake-request. A holder whose durable state
/// cannot be opened (corrupt / unreadable) is skipped rather than aborting — a 2-of-3 quorum is
/// meant to survive a lost holder — so it simply does not count toward the quorum.
fn open_roster(treasury_dir: &Path, agent_id: &str, holder_ids: &[String]) -> Vec<Holder> {
    let mut holders = Vec::with_capacity(holder_ids.len());
    for id in holder_ids {
        match Holder::open(treasury_dir, agent_id, id) {
            Ok(holder) => holders.push(holder),
            Err(e) => {
                tracing::warn!(holder_id = %id, error = %e, "skipping a holder that failed to open");
            }
        }
    }
    holders
}

/// Ask each opened holder for a lease and collect those that grant one FOR THIS SEAL.
///
/// A holder bound to a different `bundle_digest` / `resume_seq` (a stale generation) does not
/// count toward this quorum, and a refusal (fenced by a competitor, not sealed, too early)
/// simply does not contribute — the shortfall surfaces as [`UnsealError::QuorumUnavailable`].
/// Returns `(holder_index, lease)` pairs so the release step can hand each holder its OWN lease.
fn gather_leases(
    holders: &mut [Holder],
    req: &UnsealRequest,
    bundle_digest: &str,
    resume_seq: u64,
    needed: usize,
    now: u64,
) -> Result<Vec<(usize, Lease)>, UnsealError> {
    let mut granted: Vec<(usize, Lease)> = Vec::new();
    for (idx, holder) in holders.iter_mut().enumerate() {
        if let Ok(lease) = holder.issue_lease(req, now) {
            // Bind to the TARGET seal: ignore a holder guarding a different generation.
            if lease.bundle_digest == bundle_digest && lease.resume_seq == resume_seq {
                granted.push((idx, lease));
            }
        }
    }
    if granted.len() < needed {
        return Err(UnsealError::QuorumUnavailable {
            got: granted.len(),
            needed,
        });
    }
    Ok(granted)
}

/// Aggregate per-holder leases into the runtime's fencing token: `expires_at` = MIN of the
/// granted, `quorum_sigs` = the union of the holders' assents (the quorum proof). The leases
/// come from holders guarding the same seal for the same request, so they agree on
/// npub / resume_seq / bundle_digest / lease_id / spawner; only `expires_at` can differ.
fn aggregate_lease(leases: &[(usize, Lease)]) -> Lease {
    let base = &leases[0].1;
    let expires_at = leases
        .iter()
        .map(|(_, l)| l.expires_at)
        .min()
        .unwrap_or(base.expires_at);
    let mut quorum_sigs = Vec::new();
    for (_, lease) in leases {
        quorum_sigs.extend(lease.quorum_sigs.iter().cloned());
    }
    Lease {
        npub: base.npub.clone(),
        resume_seq: base.resume_seq,
        lease_id: base.lease_id.clone(),
        bundle_digest: base.bundle_digest.clone(),
        expires_at,
        spawner_ephemeral_pubkey: base.spawner_ephemeral_pubkey.clone(),
        quorum_sigs,
    }
}

/// Validate the wake-request's seal block before trusting it to drive the ceremony: it must ask
/// for the protocol threshold, pair each roster holder with a commitment, and name distinct
/// holders (duplicates would double-count toward the quorum and open two handles to one id).
fn validate_seal(wake: &WakeRequest) -> Result<(), UnsealError> {
    if wake.seal.threshold != SEAL_THRESHOLD {
        return Err(UnsealError::MalformedSeal(
            "threshold does not match the protocol",
        ));
    }
    if wake.seal.holder_pubkeys.len() != wake.seal.commitments.len() {
        return Err(UnsealError::MalformedSeal(
            "roster and commitment counts differ",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in &wake.seal.holder_pubkeys {
        if !seen.insert(id.as_str()) {
            return Err(UnsealError::MalformedSeal("duplicate holder id in roster"));
        }
    }
    Ok(())
}

/// The synchronous reconstitution core (steps 2–6): given an already-fetched [`WakeRequest`],
/// open the roster it names, drive the lease quorum, reconstruct the seed (binding each share to
/// the published seal), restore the bundle, and return the lease-gated [`LeasedRuntime`]. Split
/// out from the relay fetch so it is unit-testable without a live relay.
pub fn reconstitute(
    treasury_dir: &Path,
    agent_id: &str,
    npub: &str,
    wake: &WakeRequest,
    spawner: &SpawnerProposal,
    now: u64,
) -> Result<LeasedRuntime, UnsealError> {
    validate_seal(wake)?;
    let needed = SEAL_THRESHOLD as usize;

    let req = UnsealRequest {
        npub: npub.to_string(),
        lease_id: spawner.lease_id.clone(),
        spawner_ephemeral_pubkey: spawner.ephemeral_pubkey.clone(),
        lease_ttl_secs: spawner.lease_ttl_secs,
    };

    // (2) open the roster the seal stamped into the wake-request, gather a lease quorum bound to
    // this wake-request's seal, then (3) aggregate.
    let mut holders = open_roster(treasury_dir, agent_id, &wake.seal.holder_pubkeys);
    let granted = gather_leases(
        &mut holders,
        &req,
        &wake.bundle_digest,
        wake.resume_seq,
        needed,
        now,
    )?;
    let lease = aggregate_lease(&granted);

    // (4) release `needed` shares (each holder handed its OWN lease), bind each to the PUBLISHED
    // seal, then combine → derive.
    let mut shares: Vec<Share> = Vec::with_capacity(needed);
    for (idx, holder_lease) in granted.iter().take(needed) {
        let share = holders[*idx].release_share(holder_lease, now)?;
        if share.seal_epoch != wake.seal.seal_epoch
            || !wake.seal.commitments.contains(&share.commitment)
        {
            return Err(UnsealError::ShareSealMismatch {
                share_index: share.share_index,
            });
        }
        shares.push(share);
    }
    let seed = combine_shares(&shares)?;
    let subkeys = derive_subkeys(&seed);
    // `seed` and `shares` (zeroizing) drop here.

    // (5) restore exactly the bundle the wake-request commits to (digest MUST match).
    let bundle = load_bundle(treasury_dir, agent_id, &wake.bundle_digest)?;

    tracing::info!(
        npub,
        next_resume_seq = bundle.resume_seq.saturating_add(1),
        lease_expires_at = lease.expires_at,
        quorum = lease.quorum_sigs.len(),
        "reconstituted agent from seal (came back as itself)"
    );

    Ok(LeasedRuntime {
        npub: npub.to_string(),
        lease,
        subkeys,
        bundle,
        treasury_dir: treasury_dir.to_path_buf(),
        agent_id: agent_id.to_string(),
        holder_ids: wake.seal.holder_pubkeys.clone(),
    })
}

/// The full unseal ceremony: fetch this agent's wake-request from the relay (step 1), then
/// [`reconstitute`] (steps 2–6). A thin async wrapper — all the orchestration logic lives in
/// `reconstitute`, which the tests drive directly without a relay.
pub async fn unseal(
    relay_url: &str,
    treasury_dir: &Path,
    agent_id: &str,
    npub: &str,
    spawner: &SpawnerProposal,
    now: u64,
    fetch_timeout: Duration,
) -> Result<LeasedRuntime, UnsealError> {
    let record = fetch_wake_request_by_agent(relay_url, npub, agent_id, fetch_timeout)
        .await
        .map_err(|e| UnsealError::Fetch(e.to_string()))?
        .ok_or(UnsealError::NoWakeRequest)?;
    reconstitute(treasury_dir, agent_id, npub, &record.request, spawner, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibernate::bundle::{bundle_path, persist_bundle};
    use crate::hibernate::holder::holder_path;
    use crate::hibernate::shamir::{derive_subkeys, split_seed, MasterSeed};
    use crate::hibernate::{
        CheckpointPos, MemoryRef, Seal, StateBundle, WakeConditions, WalletState, SEAL_SHARES,
    };

    const AGENT: &str = "agent-0";
    const NPUB: &str = "npub1agent";

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirby-hibernate-unseal-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    /// Seal-side fixture: split `seed_bytes` into SEAL_SHARES shares, persist a bundle, and seal
    /// each holder with its share. Returns the wake-request (its `seal.holder_pubkeys` IS the
    /// roster unseal will open, and `seal.commitments` the shares it will bind to). Composes the
    /// H1/H2/H4a primitives exactly as the real seal ceremony (H4b) will.
    fn seal_fixture(
        dir: &Path,
        seed_bytes: [u8; 32],
        resume_seq: u64,
        wake_at: u64,
        seal_epoch: u64,
    ) -> WakeRequest {
        let shares = split_seed(&MasterSeed::from_bytes(seed_bytes), seal_epoch);
        assert_eq!(shares.len(), SEAL_SHARES as usize);
        let bundle = StateBundle {
            memory_ref: MemoryRef {
                digest: "mem-digest".to_string(),
            },
            wallet_state: WalletState {
                balance_sats: 4242,
                proofs: vec![1, 2, 3, 4],
            },
            checkpoint: CheckpointPos {
                sha256: "ckpt-sha".to_string(),
                len: 7,
            },
            resume_seq,
        };
        let digest = persist_bundle(dir, AGENT, &bundle).unwrap();
        let holder_ids: Vec<String> = (0..SEAL_SHARES).map(|i| format!("holder-{i}")).collect();
        for (i, hid) in holder_ids.iter().enumerate() {
            let mut h = Holder::open(dir, AGENT, hid).unwrap();
            h.receive_share(
                shares[i].clone(),
                NPUB,
                &digest,
                resume_seq,
                WakeConditions { wake_at },
            )
            .unwrap();
        }
        let seal = Seal {
            holder_pubkeys: holder_ids,
            threshold: SEAL_THRESHOLD,
            commitments: shares.iter().map(|s| s.commitment.clone()).collect(),
            seal_epoch,
        };
        WakeRequest {
            wake_at,
            bundle_digest: digest,
            image_ref: "image-ref".to_string(),
            seal,
            resume_seq,
            solvency_hint: 0,
        }
    }

    fn proposal(lease_id: &str, spawner: &str, ttl: u64) -> SpawnerProposal {
        SpawnerProposal {
            lease_id: lease_id.to_string(),
            ephemeral_pubkey: spawner.to_string(),
            lease_ttl_secs: ttl,
        }
    }

    #[test]
    fn happy_path_reconstitutes_same_identity_state_and_advances_seq() {
        let dir = tempdir();
        let seed_bytes = [42u8; 32];
        let wake = seal_fixture(&dir, seed_bytes, 5, 1_000, 1);
        let now = 1_000; // == wake_at
        let rt = reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            now,
        )
        .expect("reconstitute");

        // SAME identity: the gated subkeys match a fresh derivation from the original seed.
        let expected = derive_subkeys(&MasterSeed::from_bytes(seed_bytes));
        rt.with_authority(now, |auth| {
            assert_eq!(auth.identity_key(), &expected.identity_key);
            assert_eq!(auth.state_key(), &expected.state_key);
            assert_eq!(auth.wallet_seed(), &expected.wallet_seed);
        })
        .expect("live authority");

        // SAME state.
        assert_eq!(rt.npub(), NPUB);
        assert_eq!(rt.bundle().wallet_state.balance_sats, 4242);
        assert_eq!(rt.bundle().memory_ref.digest, "mem-digest");
        assert_eq!(rt.bundle().resume_seq, 5);
        // resumes one past the sealed sequence.
        assert_eq!(rt.next_resume_seq(), 6);
        // the aggregated token carries the quorum's assents and the sealed digest.
        assert!(rt.lease().quorum_sigs.len() >= SEAL_THRESHOLD as usize);
        assert_eq!(rt.lease().bundle_digest, wake.bundle_digest);

        cleanup(&dir);
    }

    #[test]
    fn a_competing_second_spawner_is_fenced() {
        let dir = tempdir();
        let wake = seal_fixture(&dir, [9u8; 32], 5, 1_000, 1);
        let now = 1_000;
        // spawner A wins the quorum (its live leases persist to the holders' durable state).
        let _a = reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-A", "spawner-A", 100),
            now,
        )
        .expect("A reconstitutes");
        // spawner B reopens the same roster while A's leases are live → cannot assemble a quorum.
        match reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-B", "spawner-B", 100),
            now,
        ) {
            Err(UnsealError::QuorumUnavailable { got, needed }) => {
                assert!(got < needed);
                assert_eq!(needed, SEAL_THRESHOLD as usize);
            }
            Err(e) => panic!("expected QuorumUnavailable, got {e:?}"),
            Ok(_) => panic!("expected QuorumUnavailable, but B reconstituted (fence broken)"),
        }
        cleanup(&dir);
    }

    #[test]
    fn an_expired_lease_refuses_authority_and_signals_self_stop() {
        let dir = tempdir();
        let wake = seal_fixture(&dir, [3u8; 32], 5, 1_000, 1);
        let now = 1_000;
        let rt = reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            now,
        )
        .unwrap();
        // expires_at = now + ttl = 1_100. Live inside the window: authority runs.
        assert!(rt.is_live(1_050));
        rt.with_authority(1_050, |_| ())
            .expect("authority while live");
        // at/after expiry: dead, must self-stop, and authority is refused at USE (re-checked).
        assert!(!rt.is_live(1_100));
        assert!(rt.must_self_stop(1_100));
        match rt.with_authority(1_200, |auth| auth.identity_key()[0]) {
            Err(UnsealError::LeaseExpired { expires_at, now }) => {
                assert_eq!(expires_at, 1_100);
                assert_eq!(now, 1_200);
            }
            Err(e) => panic!("expected LeaseExpired, got {e:?}"),
            Ok(_) => panic!("expected LeaseExpired, but authority ran past expiry"),
        }
        cleanup(&dir);
    }

    #[test]
    fn renewal_extends_the_lease_before_expiry() {
        let dir = tempdir();
        let wake = seal_fixture(&dir, [4u8; 32], 5, 1_000, 1);
        let mut rt = reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            1_000,
        )
        .unwrap();
        assert_eq!(rt.lease().expires_at, 1_100);
        // before expiry, renew at now=1_050 → expires_at advances to 1_150.
        rt.renew(100, 1_050).expect("renew");
        assert_eq!(rt.lease().expires_at, 1_150);
        // a time that would have been dead under the original lease is now live.
        rt.with_authority(1_120, |_| ())
            .expect("authority after renewal");
        cleanup(&dir);
    }

    #[test]
    fn renew_on_an_expired_runtime_is_refused() {
        let dir = tempdir();
        let wake = seal_fixture(&dir, [7u8; 32], 5, 1_000, 1);
        let mut rt = reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            1_000,
        )
        .unwrap();
        // the lease has lapsed (expires_at 1_100): a dead runtime must NOT renew its way back.
        match rt.renew(100, 1_200) {
            Err(UnsealError::LeaseExpired { expires_at, now }) => {
                assert_eq!(expires_at, 1_100);
                assert_eq!(now, 1_200);
            }
            Err(e) => panic!("expected LeaseExpired, got {e:?}"),
            Ok(()) => panic!("an expired runtime must not be allowed to renew"),
        }
        cleanup(&dir);
    }

    #[test]
    fn fewer_than_threshold_holders_cannot_reconstitute() {
        let dir = tempdir();
        let wake = seal_fixture(&dir, [5u8; 32], 5, 1_000, 1);
        // simulate two of the three holders being unreachable at wake time: remove their durable
        // state. Their ids remain in the wake-request roster, but an opened-but-unsealed holder
        // cannot issue a lease, so only one holder grants → no quorum.
        for id in ["holder-1", "holder-2"] {
            std::fs::remove_file(holder_path(&dir, AGENT, id)).unwrap();
        }
        match reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            1_000,
        ) {
            Err(UnsealError::QuorumUnavailable { got, needed }) => {
                assert_eq!(got, 1);
                assert_eq!(needed, 2);
            }
            Err(e) => panic!("expected QuorumUnavailable, got {e:?}"),
            Ok(_) => panic!("expected QuorumUnavailable with one reachable holder"),
        }
        cleanup(&dir);
    }

    #[test]
    fn a_tampered_bundle_fails_the_digest_check_on_load() {
        let dir = tempdir();
        let wake = seal_fixture(&dir, [6u8; 32], 5, 1_000, 1);
        // tamper the persisted bundle AFTER sealing: its recomputed digest no longer matches the
        // wake-request's bundle_digest (a restore-consistency violation).
        let bpath = bundle_path(&dir, AGENT);
        let mut tampered: StateBundle =
            serde_json::from_slice(&std::fs::read(&bpath).unwrap()).unwrap();
        tampered.wallet_state.balance_sats += 1;
        std::fs::write(&bpath, serde_json::to_vec(&tampered).unwrap()).unwrap();

        match reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            1_000,
        ) {
            Err(UnsealError::Bundle(BundleError::DigestMismatch { .. })) => {}
            Err(e) => panic!("expected Bundle(DigestMismatch), got {e:?}"),
            Ok(_) => panic!("expected a digest-mismatch rejection on load"),
        }
        cleanup(&dir);
    }

    #[test]
    fn a_share_not_bound_to_the_published_seal_is_rejected() {
        let dir = tempdir();
        let mut wake = seal_fixture(&dir, [2u8; 32], 5, 1_000, 1);
        // The holders are sealed with valid, self-consistent shares, but the published seal no
        // longer names their commitments (simulating tampered/stale holder state combining to a
        // foreign seed). bundle_digest + resume_seq + threshold stay valid so the ceremony gets
        // past the quorum and releases real shares, which must then fail the seal binding.
        wake.seal.commitments = wake
            .seal
            .commitments
            .iter()
            .map(|_| "deadbeef".to_string())
            .collect();
        match reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            1_000,
        ) {
            Err(UnsealError::ShareSealMismatch { .. }) => {}
            Err(e) => panic!("expected ShareSealMismatch, got {e:?}"),
            Ok(_) => panic!("expected a share-not-in-seal rejection"),
        }
        cleanup(&dir);
    }

    #[test]
    fn a_wake_request_with_a_foreign_threshold_is_rejected() {
        let dir = tempdir();
        let mut wake = seal_fixture(&dir, [8u8; 32], 5, 1_000, 1);
        wake.seal.threshold = 3; // not the protocol's SEAL_THRESHOLD (2)
        match reconstitute(&dir, AGENT, NPUB, &wake, &proposal("l", "s", 100), 1_000) {
            Err(UnsealError::MalformedSeal(_)) => {}
            Err(e) => panic!("expected MalformedSeal, got {e:?}"),
            Ok(_) => panic!("expected MalformedSeal"),
        }
        cleanup(&dir);
    }

    #[test]
    fn a_duplicate_holder_in_the_roster_is_rejected() {
        let dir = tempdir();
        let mut wake = seal_fixture(&dir, [1u8; 32], 5, 1_000, 1);
        // a duplicated holder id would double-count toward the quorum (and open two handles).
        wake.seal.holder_pubkeys = vec![
            "holder-0".to_string(),
            "holder-0".to_string(),
            "holder-1".to_string(),
        ];
        match reconstitute(
            &dir,
            AGENT,
            NPUB,
            &wake,
            &proposal("lease-1", "spawner-A", 100),
            1_000,
        ) {
            Err(UnsealError::MalformedSeal(_)) => {}
            Err(e) => panic!("expected MalformedSeal, got {e:?}"),
            Ok(_) => panic!("expected MalformedSeal for a duplicate roster"),
        }
        cleanup(&dir);
    }
}
