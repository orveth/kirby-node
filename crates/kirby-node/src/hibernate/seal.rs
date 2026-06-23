//! Hibernation chunk H4b: the SEAL ceremony — the atomic-commit orchestration that
//! takes a live agent to "hibernated" (`plans/build-spec-kirby-hibernation-thinslice.md`).
//!
//! It COMPOSES the merged primitives, reimplementing none of them: H1
//! [`split_seed`](super::shamir::split_seed), H2
//! [`persist_bundle`](super::bundle::persist_bundle) /
//! [`load_bundle`](super::bundle::load_bundle), H4a
//! [`Holder::receive_share`](super::holder::Holder::receive_share), H3
//! [`publish_wake_request`](super::wake::publish_wake_request) /
//! [`fetch_wake_request_by_digest`](super::wake::fetch_wake_request_by_digest).
//!
//! ## The ceremony (atomic commit with a point of no return)
//!
//! 1. **Quiesce** (barrier 1) — freeze state and snapshot it. Thin slice: the caller's
//!    `quiesce` hook stops the loop / drains effects / finalizes the wallet and returns
//!    the frozen [`StateBundle`]; nothing may change after it returns.
//! 2. **Persist** the bundle (H2) → the immutable `bundle_digest`.
//! 3. **Split** the master seed → [`SEAL_SHARES`] shares at the current `seal_epoch` (H1).
//! 4. **Distribute** share *i* → holder *i* via [`Holder::receive_share`] (barrier 2:
//!    each holder fsyncs a durable record before it acks); collect all the acks.
//! 5. **Publish** the wake-request (H3) — the public commitment (digest + the [`Seal`]
//!    block = holder roster / threshold / commitments / epoch + resume_seq + solvency).
//! 6. **VERIFY = the point of no return:** the persisted bundle still matches the digest
//!    (H2 read-back), all [`SEAL_SHARES`] acks are held and commit to this digest/epoch/
//!    commitments, and the wake-request is LIVE on the relay committing to this digest.
//! 7. Only after the PONR: **zeroize the master seed** and signal exit/deallocate.
//!
//! Any failure BEFORE the PONR → [`SealOutcome::Aborted`]: **bump `seal_epoch`** (so any
//! shares already distributed are orphaned — the next seal supersedes the holders'
//! records at the higher epoch, and the addressable wake-request is replaced), KEEP the
//! master seed (returned to the caller for the awake session), and stay awake. Crossing
//! the PONR is the only path that zeroizes the seed (the "clean final exit" of the
//! locked re-hibernation decision).
//!
//! ## What "in-process" means here (thin-slice honesty)
//!
//! The three holders are in-process [`Holder`]s under one agent-scoped directory (H4a's
//! documented one-disk limitation). The wake transport is abstracted behind
//! [`WakeTransport`] so the ceremony's publish + verify-live steps are testable without
//! a relay; [`RelayWakeTransport`] is the production composition of H3. The holder roster
//! ([`HOLDER_IDS`]) is carried in the wake-request's `seal.holder_pubkeys`, which is the
//! contract the unseal ceremony (H5) reads back to find the holders — so it is the
//! holder labels, not cryptographic pubkeys, in the thin slice (Move-2 = real pubkeys).

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use zeroize::Zeroize as _;

use super::bundle::{self, BundleError};
use super::holder::{Ack, Holder, HolderError};
use super::shamir::{self, MasterSeed};
use super::wake;
use super::{Seal, StateBundle, WakeConditions, WakeRequest, SEAL_SHARES, SEAL_THRESHOLD};
use crate::nerve::NodeIdentity;

/// The in-process holder roster: one stable label per share. Carried in the
/// wake-request's `seal.holder_pubkeys` (the roster the unseal ceremony reads back).
/// Thin-slice labels, not cryptographic pubkeys (Move-2 distributes real holders).
const HOLDER_IDS: [&str; SEAL_SHARES as usize] = ["holder-0", "holder-1", "holder-2"];

// The roster must have exactly one entry per share, or the distribute step's
// share<->holder zip would silently drop shares.
const _: () = assert!(
    HOLDER_IDS.len() == SEAL_SHARES as usize,
    "holder roster must have one holder per share"
);

/// The wake-request transport the seal ceremony publishes through and verifies against.
///
/// Abstracted so the ceremony's publish (step 5) and verify-live (step 6) are testable
/// without a relay. [`RelayWakeTransport`] is the production composition of H3.
#[async_trait]
pub trait WakeTransport {
    /// The agent/node npub this transport signs as — the holder records bind to it, and
    /// the verify step fetches by it. Single source of truth for the agent identity.
    fn npub(&self) -> String;

    /// Publish the wake-request (signed by the agent key). Returns the event id.
    async fn publish(&self, request: &WakeRequest) -> anyhow::Result<String>;

    /// Fetch this agent's current wake-request committing to `bundle_digest`, to confirm
    /// it is live on the relay. `None` if no such wake-request is present.
    async fn fetch_by_digest(&self, bundle_digest: &str) -> anyhow::Result<Option<WakeRequest>>;
}

/// The production [`WakeTransport`]: composes H3 over the nerve relay client, signing
/// with the node/agent [`NodeIdentity`].
pub struct RelayWakeTransport {
    identity: NodeIdentity,
    relay_url: String,
    agent_id: String,
    node_id: String,
    fetch_timeout: Duration,
}

impl RelayWakeTransport {
    /// Build the relay transport. `agent_id` MUST match the seal's
    /// [`SealConfig::agent_id`] (it is the wake-request's addressable `d` tag and the
    /// storage scope); the caller wires them consistently.
    pub fn new(
        identity: NodeIdentity,
        relay_url: String,
        agent_id: String,
        node_id: String,
        fetch_timeout: Duration,
    ) -> Self {
        RelayWakeTransport { identity, relay_url, agent_id, node_id, fetch_timeout }
    }
}

#[async_trait]
impl WakeTransport for RelayWakeTransport {
    fn npub(&self) -> String {
        self.identity.npub()
    }

    async fn publish(&self, request: &WakeRequest) -> anyhow::Result<String> {
        wake::publish_wake_request(
            &self.identity,
            &self.relay_url,
            &self.agent_id,
            &self.node_id,
            request,
        )
        .await
    }

    async fn fetch_by_digest(&self, bundle_digest: &str) -> anyhow::Result<Option<WakeRequest>> {
        let record = wake::fetch_wake_request_by_digest(
            &self.relay_url,
            &self.identity.npub(),
            bundle_digest,
            self.fetch_timeout,
        )
        .await?;
        Ok(record.map(|r| r.request))
    }
}

/// The ceremony inputs that are not the secret, the transport, or the quiesce hook.
pub struct SealConfig<'a> {
    /// The agent id — the storage scope (holder + bundle paths) and the wake-request's
    /// addressable `d` tag; MUST match the transport's `agent_id`.
    pub agent_id: &'a str,
    /// The node state directory the agent-scoped hibernation artifacts live under.
    pub treasury_dir: &'a Path,
    /// The current seal epoch (bumped on abort to orphan prior shares).
    pub seal_epoch: u64,
    /// The wake condition (unix seconds): the holder releases / a lease issues only once
    /// `now >= wake_at`.
    pub wake_at: u64,
    /// The genome image reference the agent reprovisions from on wake.
    pub image_ref: String,
    /// A hint of the agent's solvency (sats) at seal time, for the waker.
    pub solvency_hint: u64,
}

/// A committed seal (the PONR was crossed): the master seed has been zeroized and the
/// agent should now exit / deallocate.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The published wake-request (the public hibernation commitment).
    pub wake_request: WakeRequest,
    /// The immutable bundle digest the seal commits to.
    pub bundle_digest: String,
    /// The holder acks gathered (one per [`SEAL_SHARES`]).
    pub acks: Vec<Ack>,
}

/// Why a seal aborted before the point of no return.
#[derive(Debug, thiserror::Error)]
pub enum SealAbort {
    /// The quiesce hook failed (state could not be frozen / snapshotted).
    #[error("quiesce failed: {0}")]
    Quiesce(String),
    /// Persisting the state bundle failed.
    #[error("persist bundle: {0}")]
    Persist(#[source] BundleError),
    /// A holder failed to durably receive its share.
    #[error("holder {holder_id}: {source}")]
    Holder {
        holder_id: &'static str,
        #[source]
        source: HolderError,
    },
    /// Publishing the wake-request failed.
    #[error("publish wake-request: {0}")]
    Publish(String),
    /// Verify: the persisted bundle no longer matches the committed digest.
    #[error("verify: persisted bundle does not match the committed digest: {0}")]
    VerifyBundle(#[source] BundleError),
    /// Verify: the holder acks were incomplete or did not match the seal.
    #[error("verify: holder acks incomplete/inconsistent (have {have} of {expected})")]
    VerifyAcks { have: usize, expected: usize },
    /// Verify: the wake-request was not live on the relay (or its digest mismatched).
    #[error("verify: wake-request not live on the relay / digest mismatch")]
    VerifyWakeRequest,
    /// Verify: the fetch to confirm the wake-request is live failed.
    #[error("verify: fetch wake-request: {0}")]
    Fetch(String),
}

/// The outcome of a seal ceremony: either committed (sealed) or aborted (stay awake).
pub enum SealOutcome {
    /// The PONR was crossed and the seal committed; the seed was zeroized.
    Sealed(Sealed),
    /// A pre-PONR step failed: the `seal_epoch` was bumped to `next_seal_epoch` (orphaning
    /// any distributed shares), the master seed is RETURNED (kept for the awake session),
    /// and the agent stays awake. `reason` says which step failed.
    Aborted {
        master_seed: MasterSeed,
        next_seal_epoch: u64,
        reason: SealAbort,
    },
}

/// Run the seal ceremony. Returns [`SealOutcome::Sealed`] iff the point of no return was
/// crossed (seed zeroized; the caller should exit/deallocate); otherwise
/// [`SealOutcome::Aborted`] with the seed returned and the epoch bumped (stay awake).
///
/// `quiesce` freezes state and returns the frozen [`StateBundle`] snapshot (barrier 1);
/// the bundle is causally downstream of quiescence, so nothing changes after it returns.
pub async fn seal<T, Q>(
    config: SealConfig<'_>,
    mut master_seed: MasterSeed,
    transport: &T,
    quiesce: Q,
) -> SealOutcome
where
    T: WakeTransport + ?Sized,
    Q: FnOnce() -> anyhow::Result<StateBundle>,
{
    let npub = transport.npub();
    let epoch = config.seal_epoch;

    // 1. Quiesce -> the frozen state snapshot (barrier 1).
    let bundle = match quiesce() {
        Ok(b) => b,
        Err(e) => return abort(master_seed, epoch, SealAbort::Quiesce(e.to_string())),
    };
    let resume_seq = bundle.resume_seq;

    // 2. Persist the bundle -> the immutable committed digest (H2).
    let digest = match bundle::persist_bundle(config.treasury_dir, config.agent_id, &bundle) {
        Ok(d) => d,
        Err(e) => return abort(master_seed, epoch, SealAbort::Persist(e)),
    };

    // 3. Split the seed at the current epoch (H1). Capture the public commitments before
    //    the shares are consumed by distribution.
    let shares = shamir::split_seed(&master_seed, epoch);
    let commitments: Vec<String> = shares.iter().map(|s| s.commitment.clone()).collect();

    // 4. Distribute share[i] -> holder[i]; collect acks (barrier 2: each holder fsyncs
    //    before it acks). One holder handle at a time (the single-instance invariant).
    let mut acks: Vec<Ack> = Vec::with_capacity(SEAL_SHARES as usize);
    for (share, holder_id) in shares.into_iter().zip(HOLDER_IDS) {
        let mut holder = match Holder::open(config.treasury_dir, config.agent_id, holder_id) {
            Ok(h) => h,
            Err(source) => {
                return abort(master_seed, epoch, SealAbort::Holder { holder_id, source })
            }
        };
        match holder.receive_share(
            share,
            &npub,
            &digest,
            resume_seq,
            WakeConditions { wake_at: config.wake_at },
        ) {
            Ok(ack) => acks.push(ack),
            Err(source) => {
                return abort(master_seed, epoch, SealAbort::Holder { holder_id, source })
            }
        }
        // `holder` drops here (its state is fsynced to disk); H5 re-opens it on unseal.
    }

    // 5. Build + publish the wake-request (H3) — the public commitment.
    let request = WakeRequest {
        wake_at: config.wake_at,
        bundle_digest: digest.clone(),
        image_ref: config.image_ref.clone(),
        seal: Seal {
            holder_pubkeys: HOLDER_IDS.iter().map(|s| s.to_string()).collect(),
            threshold: SEAL_THRESHOLD,
            commitments,
            seal_epoch: epoch,
        },
        resume_seq,
        solvency_hint: config.solvency_hint,
    };
    if let Err(e) = transport.publish(&request).await {
        return abort(master_seed, epoch, SealAbort::Publish(e.to_string()));
    }

    // 6. VERIFY = the point of no return.
    //    (a) the persisted bundle still matches the committed digest (restore-consistency).
    if let Err(e) = bundle::load_bundle(config.treasury_dir, config.agent_id, &digest) {
        return abort(master_seed, epoch, SealAbort::VerifyBundle(e));
    }
    //    (b) all shares acked, each committing to this digest + epoch + the published
    //        commitment (so the holders provably guard the seal we published).
    if !acks_match(&acks, &digest, epoch, &request.seal.commitments) {
        return abort(
            master_seed,
            epoch,
            SealAbort::VerifyAcks { have: acks.len(), expected: SEAL_SHARES as usize },
        );
    }
    //    (c) the wake-request is live on the relay, committing to this digest/epoch/seq.
    match transport.fetch_by_digest(&digest).await {
        Ok(Some(live))
            if live.bundle_digest == digest
                && live.seal.seal_epoch == epoch
                && live.resume_seq == resume_seq => {}
        Ok(_) => return abort(master_seed, epoch, SealAbort::VerifyWakeRequest),
        Err(e) => return abort(master_seed, epoch, SealAbort::Fetch(e.to_string())),
    }

    // 7. PONR crossed -> zeroize the master seed (clean final exit) + signal exit.
    master_seed.zeroize();
    drop(master_seed);
    SealOutcome::Sealed(Sealed { wake_request: request, bundle_digest: digest, acks })
}

/// Build an [`SealOutcome::Aborted`]: bump the epoch (orphan distributed shares) and
/// return the (un-zeroized) seed for the awake session.
fn abort(master_seed: MasterSeed, seal_epoch: u64, reason: SealAbort) -> SealOutcome {
    SealOutcome::Aborted {
        master_seed,
        next_seal_epoch: seal_epoch.saturating_add(1),
        reason,
    }
}

/// All shares acked, each ack committing to the seal we published (digest + epoch +
/// the i-th published commitment). The acks are pushed in holder/share order, so the
/// i-th ack's `share_commitment` must equal the i-th published commitment.
fn acks_match(acks: &[Ack], digest: &str, epoch: u64, commitments: &[String]) -> bool {
    acks.len() == SEAL_SHARES as usize
        && acks.iter().enumerate().all(|(i, a)| {
            a.bundle_digest == digest
                && a.seal_epoch == epoch
                && commitments.get(i).is_some_and(|c| *c == a.share_commitment)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibernate::{CheckpointPos, MemoryRef, WalletState};
    use std::path::PathBuf;
    use std::sync::Mutex;

    const AGENT: &str = "agent-0";
    const NPUB: &str = "npub1agentseal";
    const WAKE_AT: u64 = 2_000;
    const RESUME_SEQ: u64 = 11;

    /// A mock wake transport: an in-memory "relay" (the latest published request) plus
    /// injectable failures for the publish (step 5) and verify-live (step 6) abort paths.
    struct MockTransport {
        store: Mutex<Option<WakeRequest>>,
        fail_publish: bool,
        drop_on_fetch: bool, // simulate a wake-request that is not live on fetch
    }
    impl MockTransport {
        fn ok() -> Self {
            MockTransport { store: Mutex::new(None), fail_publish: false, drop_on_fetch: false }
        }
        fn failing_publish() -> Self {
            MockTransport { store: Mutex::new(None), fail_publish: true, drop_on_fetch: false }
        }
        fn not_live_on_fetch() -> Self {
            MockTransport { store: Mutex::new(None), fail_publish: false, drop_on_fetch: true }
        }
        fn published(&self) -> Option<WakeRequest> {
            self.store.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl WakeTransport for MockTransport {
        fn npub(&self) -> String {
            NPUB.to_string()
        }
        async fn publish(&self, request: &WakeRequest) -> anyhow::Result<String> {
            if self.fail_publish {
                anyhow::bail!("injected publish failure");
            }
            *self.store.lock().unwrap() = Some(request.clone());
            Ok("event-id".to_string())
        }
        async fn fetch_by_digest(&self, bundle_digest: &str) -> anyhow::Result<Option<WakeRequest>> {
            if self.drop_on_fetch {
                return Ok(None);
            }
            Ok(self
                .store
                .lock()
                .unwrap()
                .clone()
                .filter(|r| r.bundle_digest == bundle_digest))
        }
    }

    fn sample_bundle() -> StateBundle {
        StateBundle {
            memory_ref: MemoryRef { digest: "aa".repeat(32) },
            wallet_state: WalletState { balance_sats: 3_899, proofs: vec![1, 2, 3] },
            checkpoint: CheckpointPos { sha256: "bb".repeat(32), len: 64 },
            resume_seq: RESUME_SEQ,
        }
    }

    fn config<'a>(treasury_dir: &'a Path, epoch: u64) -> SealConfig<'a> {
        SealConfig {
            agent_id: AGENT,
            treasury_dir,
            seal_epoch: epoch,
            wake_at: WAKE_AT,
            image_ref: "sha256:image".to_string(),
            solvency_hint: 3_899,
        }
    }

    fn seed(b: u8) -> MasterSeed {
        MasterSeed::from_bytes([b; 32])
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir()
            .join(format!("kirby-hibernate-seal-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    #[tokio::test]
    async fn happy_path_seals_persists_distributes_publishes_and_verifies() {
        let dir = tempdir();
        let transport = MockTransport::ok();
        let outcome = seal(config(&dir, 1), seed(7), &transport, || Ok(sample_bundle())).await;

        let sealed = match outcome {
            SealOutcome::Sealed(s) => s,
            SealOutcome::Aborted { reason, .. } => panic!("expected Sealed, aborted: {reason}"),
        };
        // the committed digest matches the bundle.
        assert_eq!(sealed.bundle_digest, sample_bundle().bundle_digest());
        assert_eq!(sealed.acks.len(), SEAL_SHARES as usize);

        // the bundle persisted + read-back matches the digest (H2).
        let loaded =
            bundle::load_bundle(&dir, AGENT, &sealed.bundle_digest).expect("bundle persisted");
        assert_eq!(loaded, sample_bundle());

        // all three holders durably hold a valid epoch-1 record committing to the digest,
        // with no live lease yet.
        for (i, holder_id) in HOLDER_IDS.iter().enumerate() {
            let h = Holder::open(&dir, AGENT, holder_id).unwrap();
            let rec = h.record().expect("holder is sealed");
            assert_eq!(rec.seal_epoch, 1);
            assert_eq!(rec.bundle_digest, sealed.bundle_digest);
            assert_eq!(rec.resume_seq, RESUME_SEQ);
            assert_eq!(rec.wake_conditions.wake_at, WAKE_AT);
            assert!(rec.active_lease.is_none());
            assert_eq!(rec.share_commitment, sealed.wake_request.seal.commitments[i]);
        }

        // the wake-request is published with the full Seal block (the roster H5 reads).
        let published = transport.published().expect("wake-request published");
        assert_eq!(published, sealed.wake_request);
        assert_eq!(published.seal.holder_pubkeys, HOLDER_IDS.map(String::from).to_vec());
        assert_eq!(published.seal.threshold, SEAL_THRESHOLD);
        assert_eq!(published.seal.seal_epoch, 1);
        assert_eq!(published.resume_seq, RESUME_SEQ);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_quiesce_fails_stays_awake_and_persists_nothing() {
        let dir = tempdir();
        let transport = MockTransport::ok();
        let outcome = seal(config(&dir, 5), seed(7), &transport, || {
            anyhow::bail!("loop would not drain")
        })
        .await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason, master_seed: _ } => {
                assert_eq!(next_seal_epoch, 6);
                assert!(matches!(reason, SealAbort::Quiesce(_)));
            }
            SealOutcome::Sealed(_) => panic!("must abort when quiesce fails"),
        }
        // nothing was persisted or published.
        assert!(bundle::load_bundle(&dir, AGENT, "any").is_err());
        assert!(transport.published().is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_persist_fails() {
        let dir = tempdir();
        // inject: a FILE where the agent hibernate dir must be, so persist's create_dir
        // fails.
        std::fs::write(super::super::hibernate_dir(&dir, AGENT), b"x").unwrap();
        let transport = MockTransport::ok();
        let outcome = seal(config(&dir, 2), seed(7), &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason, .. } => {
                assert_eq!(next_seal_epoch, 3);
                assert!(matches!(reason, SealAbort::Persist(_)));
            }
            SealOutcome::Sealed(_) => panic!("must abort when persist fails"),
        }
        assert!(transport.published().is_none(), "no publish before persist");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_a_holder_cannot_receive() {
        let dir = tempdir();
        // inject: a DIRECTORY where holder-1's state FILE must be, so its write_atomic
        // rename fails (persist + holder-0 still succeed first).
        let collide = super::super::hibernate_dir(&dir, AGENT).join("holder-1.holder.json");
        std::fs::create_dir_all(&collide).unwrap();
        let transport = MockTransport::ok();
        let outcome = seal(config(&dir, 4), seed(7), &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason, .. } => {
                assert_eq!(next_seal_epoch, 5);
                assert!(matches!(reason, SealAbort::Holder { holder_id: "holder-1", .. }));
            }
            SealOutcome::Sealed(_) => panic!("must abort when a holder cannot receive"),
        }
        // the bundle persisted (step 2 ran) but nothing was published (step 5 not reached).
        assert!(bundle::load_bundle(&dir, AGENT, &sample_bundle().bundle_digest()).is_ok());
        assert!(transport.published().is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_publish_fails() {
        let dir = tempdir();
        let transport = MockTransport::failing_publish();
        let outcome = seal(config(&dir, 7), seed(7), &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason, .. } => {
                assert_eq!(next_seal_epoch, 8);
                assert!(matches!(reason, SealAbort::Publish(_)));
            }
            SealOutcome::Sealed(_) => panic!("must abort when publish fails"),
        }
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_wake_request_not_live_at_verify() {
        let dir = tempdir();
        // publish "succeeds" but the wake-request is not live on fetch -> verify (PONR) fails.
        let transport = MockTransport::not_live_on_fetch();
        let outcome = seal(config(&dir, 9), seed(7), &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason, .. } => {
                assert_eq!(next_seal_epoch, 10);
                assert!(matches!(reason, SealAbort::VerifyWakeRequest));
            }
            SealOutcome::Sealed(_) => panic!("must abort when the wake-request is not live"),
        }
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_bumps_epoch_then_retry_with_returned_seed_supersedes_orphans() {
        let dir = tempdir();
        // Seal at epoch 5 distributes shares to the holders, THEN publish fails -> abort.
        let failing = MockTransport::failing_publish();
        let outcome = seal(config(&dir, 5), seed(7), &failing, || Ok(sample_bundle())).await;
        let (returned_seed, next_epoch) = match outcome {
            SealOutcome::Aborted { master_seed, next_seal_epoch, reason } => {
                assert!(matches!(reason, SealAbort::Publish(_)));
                (master_seed, next_seal_epoch)
            }
            SealOutcome::Sealed(_) => panic!("expected abort"),
        };
        assert_eq!(next_epoch, 6);
        // the holders hold the orphaned epoch-5 records (distribute ran before publish).
        for holder_id in HOLDER_IDS {
            let h = Holder::open(&dir, AGENT, holder_id).unwrap();
            assert_eq!(h.record().unwrap().seal_epoch, 5);
        }

        // Retry at the bumped epoch with the RETURNED seed + a working transport -> Sealed.
        let good = MockTransport::ok();
        let retry = seal(config(&dir, next_epoch), returned_seed, &good, || Ok(sample_bundle())).await;
        assert!(matches!(retry, SealOutcome::Sealed(_)), "retry must seal");

        // the orphaned epoch-5 records are superseded to epoch 6 (H4a `>` supersedes), so
        // no orphaned (epoch-5) share survives to be honored.
        for holder_id in HOLDER_IDS {
            let h = Holder::open(&dir, AGENT, holder_id).unwrap();
            assert_eq!(h.record().unwrap().seal_epoch, 6, "the orphaned epoch must be superseded");
        }
        cleanup(&dir);
    }
}
