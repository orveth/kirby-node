//! Hibernation chunk H4b: the SEAL ceremony — the atomic-commit orchestration that
//! takes a live agent to "hibernated" (`plans/build-spec-kirby-hibernation-thinslice.md`).
//!
//! It COMPOSES the merged primitives, reimplementing none: H1
//! [`split_seed`](super::shamir::split_seed), H2
//! [`persist_bundle`](super::bundle::persist_bundle) /
//! [`load_bundle`](super::bundle::load_bundle), H4a
//! [`Holder::receive_share`](super::holder::Holder::receive_share), H3
//! [`publish_wake_request`](super::wake::publish_wake_request) /
//! [`fetch_wake_request_by_digest`](super::wake::fetch_wake_request_by_digest).
//!
//! ## The point of no return is AT publish, not after it
//!
//! Publishing the wake-request is the side effect that makes the agent resurrectable (a
//! waker fetches it, then collects shares). So the ceremony does ALL local checks BEFORE
//! publishing, and the COMMIT decision is "is our exact wake-request confirmed LIVE on
//! the relay" (not publish()'s return value, which can be a false negative):
//!
//! 1. **Quiesce** (barrier 1) — the caller's hook freezes state + returns the snapshot
//!    [`StateBundle`]; nothing may change after it returns.
//! 2. **Persist** the bundle (H2) → the immutable `bundle_digest`.
//! 3. **Split** the master seed → [`SEAL_SHARES`] shares at the current `seal_epoch` (H1).
//! 4. **Distribute** share *i* → holder *i* (H4a; barrier 2: each holder fsyncs before
//!    it acks); collect the acks.
//! 5. **Local verify** (pre-publish): the persisted bundle reads back to the committed
//!    digest, and every ack commits to this digest/epoch/commitment. A failure here is a
//!    CLEAN abort — nothing public has happened.
//! 6. **Commit = publish + confirm-live.** Publish (best effort), then confirm OUR exact
//!    wake-request is live on the relay (bounded retries for propagation). Confirmed-live
//!    crosses the PONR → **zeroize the seed in place** + signal exit.
//!
//! If step 6 does NOT confirm-live, the publish may or may not have landed — so to leave
//! NOTHING resurrectable, the ceremony **REVOKES**: it supersedes the holders to a frozen
//! state (re-distributes at `epoch+1` with `wake_at = u64::MAX`, so every future lease
//! request is refused — H4a's wake gate), and best-effort tombstones the wake-request
//! (an addressable `wake_at = u64::MAX` replacement), THEN aborts (stay awake). A
//! pre-publish failure (steps 1–5) is a plain abort (bump `seal_epoch`, stay awake). No
//! abort path can leave a live wake-request + releasing holders.
//!
//! ## Cancellation safety
//!
//! The seed is borrowed (`&mut`), never owned by [`seal`], and is zeroized IN PLACE only
//! after the PONR. If the `seal` future is dropped mid-`await` (a timeout / `select!`),
//! the caller's seed is left intact — a cancelled seal never loses the seed.
//!
//! ## Thin-slice honesty
//!
//! The three holders are in-process [`Holder`]s under one agent dir (H4a's one-disk
//! limitation). The wake transport is abstracted behind [`WakeTransport`] so publish +
//! confirm-live are testable without a relay; [`RelayWakeTransport`] is the production
//! composition of H3. The holder roster ([`HOLDER_IDS`]) rides in the wake-request's
//! `seal.holder_pubkeys` — the contract the unseal ceremony (H5) reads to find the
//! holders (thin-slice labels, not cryptographic pubkeys; Move-2 = real pubkeys).

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

/// A wake-request fetched back from the transport, with its event id, for the
/// confirm-live check (so the seal confirms it is OUR exact published event).
#[derive(Debug, Clone)]
pub struct FetchedWake {
    pub request: WakeRequest,
    pub event_id: String,
}

/// The wake-request transport the seal ceremony publishes through and confirms against.
///
/// Abstracted so the ceremony's publish + confirm-live (step 6) are testable without a
/// relay. [`RelayWakeTransport`] is the production composition of H3.
#[async_trait]
pub trait WakeTransport {
    /// The agent/node npub this transport signs as — the holder records bind to it.
    fn npub(&self) -> String;

    /// Publish the wake-request (signed by the agent key). Returns the event id. A
    /// returned `Err` is advisory: the commit decision is confirm-live, not this result.
    async fn publish(&self, request: &WakeRequest) -> anyhow::Result<String>;

    /// Fetch this agent's current wake-request committing to `bundle_digest`, with its
    /// event id, to confirm it is live. `None` if no such wake-request is present.
    async fn fetch_by_digest(&self, bundle_digest: &str) -> anyhow::Result<Option<FetchedWake>>;
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
    /// [`SealConfig::agent_id`] (the wake-request's addressable `d` tag and the storage
    /// scope); the caller wires them consistently.
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

    async fn fetch_by_digest(&self, bundle_digest: &str) -> anyhow::Result<Option<FetchedWake>> {
        let record = wake::fetch_wake_request_by_digest(
            &self.relay_url,
            &self.identity.npub(),
            bundle_digest,
            self.fetch_timeout,
        )
        .await?;
        Ok(record.map(|r| FetchedWake { request: r.request, event_id: r.event_id }))
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
    /// The wake condition (unix seconds): a lease issues only once `now >= wake_at`.
    pub wake_at: u64,
    /// The genome image reference the agent reprovisions from on wake.
    pub image_ref: String,
    /// A hint of the agent's solvency (sats) at seal time, for the waker.
    pub solvency_hint: u64,
    /// How many times to poll the relay to confirm the wake-request is live (≥ 1).
    pub confirm_attempts: u32,
    /// Delay between confirm-live polls (relay propagation). Zero in tests.
    pub confirm_delay: Duration,
}

/// A committed seal (the PONR was crossed): the master seed has been zeroized in place
/// and the agent should now exit / deallocate.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The published wake-request (the public hibernation commitment).
    pub wake_request: WakeRequest,
    /// The immutable bundle digest the seal commits to.
    pub bundle_digest: String,
    /// The holder acks gathered (one per [`SEAL_SHARES`]).
    pub acks: Vec<Ack>,
}

/// Why a seal aborted.
#[derive(Debug, thiserror::Error)]
pub enum SealAbort {
    /// The seal epoch is exhausted (cannot bump for an abort) — sealing is refused.
    #[error("seal epoch exhausted (cannot bump); refusing to seal")]
    EpochExhausted,
    /// The quiesce hook failed (state could not be frozen / snapshotted).
    #[error("quiesce failed: {0}")]
    Quiesce(String),
    /// Persisting the state bundle failed (pre-publish, clean).
    #[error("persist bundle: {0}")]
    Persist(#[source] BundleError),
    /// A holder failed to durably receive its share (pre-publish, clean).
    #[error("holder {holder_id}: {source}")]
    Holder {
        holder_id: &'static str,
        #[source]
        source: HolderError,
    },
    /// Local verify (pre-publish): the persisted bundle did not read back to the digest.
    #[error("local verify: persisted bundle does not match the committed digest: {0}")]
    LocalVerifyBundle(#[source] BundleError),
    /// Local verify (pre-publish): the holder acks were incomplete or did not match.
    #[error("local verify: holder acks incomplete/inconsistent (have {have} of {expected})")]
    LocalVerifyAcks { have: usize, expected: usize },
    /// The wake-request could not be confirmed live after publish; the holders were
    /// REVOKED (frozen) so nothing is resurrectable, and the agent stays awake.
    #[error("wake-request not confirmed live; holders revoked, staying awake")]
    WakeRequestUnconfirmedRevoked,
    /// The wake-request could not be confirmed live AND the revoke (freeze) itself
    /// failed — a possibly-live publish could not be neutralized. The caller MUST resolve
    /// this (retry the revoke / escalate) before treating the agent as safely awake.
    #[error("DANGER: unconfirmed publish AND revoke failed (holder {holder_id}): {source}")]
    RevokeFailed {
        holder_id: &'static str,
        #[source]
        source: HolderError,
    },
}

/// The outcome of a seal ceremony.
#[derive(Debug)]
pub enum SealOutcome {
    /// The PONR was crossed and the seal committed; the caller's seed was zeroized in
    /// place — the agent should exit / deallocate.
    Sealed(Sealed),
    /// The seal did not commit. `next_seal_epoch` is the epoch a retry must use (the
    /// caller still owns its seed, intact, for the awake session). `reason` says why; a
    /// [`SealAbort::RevokeFailed`] reason is the DANGER case the caller must resolve.
    Aborted { next_seal_epoch: u64, reason: SealAbort },
}

/// Run the seal ceremony (see the module docs). The seed is BORROWED — on
/// [`SealOutcome::Sealed`] it has been zeroized in place (the agent should exit); on
/// [`SealOutcome::Aborted`] it is left intact (retry at `next_seal_epoch`). A dropped
/// future never zeroizes the seed (cancellation safety).
///
/// `quiesce` freezes state and returns the frozen snapshot (barrier 1).
pub async fn seal<T, Q>(
    config: SealConfig<'_>,
    master_seed: &mut MasterSeed,
    transport: &T,
    quiesce: Q,
) -> SealOutcome
where
    T: WakeTransport + ?Sized,
    Q: FnOnce() -> anyhow::Result<StateBundle>,
{
    let npub = transport.npub();
    let epoch = config.seal_epoch;

    // FIX (epoch overflow): refuse to seal if we could not bump for an abort/revoke
    // (which need epoch+1 and epoch+2). Guarded once here so all bumps below are safe.
    if epoch.checked_add(2).is_none() {
        return SealOutcome::Aborted { next_seal_epoch: epoch, reason: SealAbort::EpochExhausted };
    }

    // 1. Quiesce -> the frozen state snapshot (barrier 1).
    let bundle = match quiesce() {
        Ok(b) => b,
        Err(e) => return aborted(epoch + 1, SealAbort::Quiesce(e.to_string())),
    };
    let resume_seq = bundle.resume_seq;

    // 2. Persist the bundle -> the immutable committed digest (H2).
    let digest = match bundle::persist_bundle(config.treasury_dir, config.agent_id, &bundle) {
        Ok(d) => d,
        Err(e) => return aborted(epoch + 1, SealAbort::Persist(e)),
    };

    // 3. Split the seed at the current epoch (H1). Capture the public commitments before
    //    the shares are consumed by distribution.
    let shares = shamir::split_seed(master_seed, epoch);
    let commitments: Vec<String> = shares.iter().map(|s| s.commitment.clone()).collect();

    // 4. Distribute share[i] -> holder[i]; collect acks (barrier 2). One handle at a time.
    let mut acks: Vec<Ack> = Vec::with_capacity(SEAL_SHARES as usize);
    for (share, holder_id) in shares.into_iter().zip(HOLDER_IDS) {
        let mut holder = match Holder::open(config.treasury_dir, config.agent_id, holder_id) {
            Ok(h) => h,
            Err(source) => return aborted(epoch + 1, SealAbort::Holder { holder_id, source }),
        };
        match holder.receive_share(
            share,
            &npub,
            &digest,
            resume_seq,
            WakeConditions { wake_at: config.wake_at },
        ) {
            Ok(ack) => acks.push(ack),
            Err(source) => return aborted(epoch + 1, SealAbort::Holder { holder_id, source }),
        }
        // `holder` drops here (its state is fsynced to disk); H5 re-opens it on unseal.
    }

    // 5. LOCAL VERIFY (pre-publish): nothing public has happened yet, so any failure is a
    //    CLEAN abort. (a) the persisted bundle reads back to the committed digest (H2
    //    restore-consistency); (b) all shares acked, each committing to this digest +
    //    epoch + the published commitment (the holders provably guard this seal).
    if let Err(e) = bundle::load_bundle(config.treasury_dir, config.agent_id, &digest) {
        return aborted(epoch + 1, SealAbort::LocalVerifyBundle(e));
    }
    if !acks_match(&acks, &digest, epoch, &commitments) {
        return aborted(
            epoch + 1,
            SealAbort::LocalVerifyAcks { have: acks.len(), expected: SEAL_SHARES as usize },
        );
    }

    // Build the wake-request (the public commitment).
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

    // 6. COMMIT = publish + confirm-live. publish() is best effort; the commit decision
    //    is whether OUR exact wake-request is confirmed live on the relay.
    let published_id = transport.publish(&request).await.ok();
    if confirm_live(transport, &request, published_id.as_deref(), &config).await {
        // PONR crossed -> zeroize the seed IN PLACE (clean final exit) + signal exit.
        master_seed.zeroize();
        return SealOutcome::Sealed(Sealed { wake_request: request, bundle_digest: digest, acks });
    }

    // Not confirmed live: the publish may or may not have landed. REVOKE so nothing is
    // resurrectable — freeze the holders (refuse every future lease) + best-effort
    // tombstone the wake-request — THEN abort (the seed is left intact, agent stays awake).
    match revoke(&config, master_seed, &npub, &digest, resume_seq, epoch).await {
        Ok(frozen_epoch) => {
            best_effort_tombstone(transport, &request, frozen_epoch).await;
            aborted(frozen_epoch + 1, SealAbort::WakeRequestUnconfirmedRevoked)
        }
        Err((holder_id, source)) => {
            // Could not freeze the holders -> a possibly-live publish is NOT neutralized.
            best_effort_tombstone(transport, &request, epoch + 1).await;
            aborted(epoch + 2, SealAbort::RevokeFailed { holder_id, source })
        }
    }
}

/// Confirm OUR exact wake-request is live on the relay, with bounded retries to ride out
/// relay propagation. Live = a fetched request that fully equals `request` (FIX: full
/// equality, not just digest/epoch/seq) and, when we have the published event id, the
/// same event id (so it is provably the event we just published).
async fn confirm_live<T: WakeTransport + ?Sized>(
    transport: &T,
    request: &WakeRequest,
    published_id: Option<&str>,
    config: &SealConfig<'_>,
) -> bool {
    let attempts = config.confirm_attempts.max(1);
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(config.confirm_delay).await;
        }
        if let Ok(Some(fetched)) = transport.fetch_by_digest(&request.bundle_digest).await {
            let id_ok = match published_id {
                Some(id) => fetched.event_id == id,
                None => true,
            };
            if id_ok && fetched.request == *request {
                return true;
            }
        }
    }
    false
}

/// REVOKE: supersede the holders to a frozen state — re-distribute at `epoch+1` with
/// `wake_at = u64::MAX`, so each holder refuses EVERY future lease (H4a's wake gate), and
/// the just-distributed `epoch` shares are orphaned. After this, a possibly-live
/// wake-request cannot drive any reconstruction (the holders will not release). Returns
/// the frozen epoch on success, or the holder that could not be frozen on failure.
async fn revoke(
    config: &SealConfig<'_>,
    master_seed: &MasterSeed,
    npub: &str,
    digest: &str,
    resume_seq: u64,
    epoch: u64,
) -> Result<u64, (&'static str, HolderError)> {
    let frozen_epoch = epoch + 1; // safe: entry guard ensured epoch <= u64::MAX - 2
    let shares = shamir::split_seed(master_seed, frozen_epoch);
    for (share, holder_id) in shares.into_iter().zip(HOLDER_IDS) {
        let mut holder =
            Holder::open(config.treasury_dir, config.agent_id, holder_id).map_err(|e| (holder_id, e))?;
        holder
            .receive_share(share, npub, digest, resume_seq, WakeConditions { wake_at: u64::MAX })
            .map_err(|e| (holder_id, e))?;
    }
    Ok(frozen_epoch)
}

/// Best-effort tombstone: publish an addressable `wake_at = u64::MAX` replacement so the
/// PUBLIC wake-request also reads as un-wakeable. The holder freeze is the load-bearing
/// revoke; this is belt-and-suspenders and its failure is ignored (the relay may be the
/// very thing that was unreachable).
async fn best_effort_tombstone<T: WakeTransport + ?Sized>(
    transport: &T,
    request: &WakeRequest,
    frozen_epoch: u64,
) {
    let mut tombstone = request.clone();
    tombstone.wake_at = u64::MAX;
    tombstone.seal.seal_epoch = frozen_epoch;
    let _ = transport.publish(&tombstone).await;
}

/// Build an [`SealOutcome::Aborted`].
fn aborted(next_seal_epoch: u64, reason: SealAbort) -> SealOutcome {
    SealOutcome::Aborted { next_seal_epoch, reason }
}

/// All shares acked, each ack committing to the seal we are publishing (digest + epoch +
/// the i-th commitment). The acks are pushed in holder/share order, so the i-th ack's
/// `share_commitment` must equal the i-th commitment.
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
    use crate::hibernate::holder::UnsealRequest;
    use crate::hibernate::{CheckpointPos, MemoryRef, WalletState};
    use std::path::PathBuf;
    use std::sync::Mutex;

    const AGENT: &str = "agent-0";
    const NPUB: &str = "npub1agentseal";
    const WAKE_AT: u64 = 2_000;
    const RESUME_SEQ: u64 = 11;

    /// A mock wake transport: an in-memory "relay" (the latest published request + a
    /// synthetic event id) plus injectable failures.
    struct MockTransport {
        store: Mutex<Option<(WakeRequest, String)>>,
        fail_publish: bool,
        drop_on_fetch: bool,  // simulate a wake-request that is not live on fetch
        hang_publish: bool,   // publish never completes (for cancellation tests)
        tamper_fetch: bool,   // fetch returns a same-digest but DIFFERENT request
    }
    impl MockTransport {
        fn ok() -> Self {
            MockTransport { store: Mutex::new(None), fail_publish: false, drop_on_fetch: false, hang_publish: false, tamper_fetch: false }
        }
        fn failing_publish() -> Self {
            MockTransport { fail_publish: true, ..Self::ok() }
        }
        fn not_live_on_fetch() -> Self {
            MockTransport { drop_on_fetch: true, ..Self::ok() }
        }
        fn hanging_publish() -> Self {
            MockTransport { hang_publish: true, ..Self::ok() }
        }
        fn tampered_fetch() -> Self {
            MockTransport { tamper_fetch: true, ..Self::ok() }
        }
    }
    #[async_trait]
    impl WakeTransport for MockTransport {
        fn npub(&self) -> String {
            NPUB.to_string()
        }
        async fn publish(&self, request: &WakeRequest) -> anyhow::Result<String> {
            if self.hang_publish {
                std::future::pending::<()>().await; // never completes -> the future is cancelled
            }
            if self.fail_publish {
                anyhow::bail!("injected publish failure");
            }
            *self.store.lock().unwrap() = Some((request.clone(), "event-id".to_string()));
            Ok("event-id".to_string())
        }
        async fn fetch_by_digest(&self, bundle_digest: &str) -> anyhow::Result<Option<FetchedWake>> {
            if self.drop_on_fetch {
                return Ok(None);
            }
            Ok(self
                .store
                .lock()
                .unwrap()
                .clone()
                .filter(|(r, _)| r.bundle_digest == bundle_digest)
                .map(|(mut request, event_id)| {
                    if self.tamper_fetch {
                        // Same digest, but a DIFFERENT request: the old loose check
                        // (digest/epoch/resume_seq only) would have accepted this; full
                        // equality must reject it. Same event_id, to isolate the
                        // request-equality check from the event-id check.
                        request.wake_at += 1;
                    }
                    FetchedWake { request, event_id }
                }))
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

    fn config(treasury_dir: &Path, epoch: u64) -> SealConfig<'_> {
        SealConfig {
            agent_id: AGENT,
            treasury_dir,
            seal_epoch: epoch,
            wake_at: WAKE_AT,
            image_ref: "sha256:image".to_string(),
            solvency_hint: 3_899,
            confirm_attempts: 2,
            confirm_delay: Duration::ZERO,
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
    async fn happy_path_seals_persists_distributes_publishes_and_confirms_live() {
        let dir = tempdir();
        let transport = MockTransport::ok();
        let mut s = seed(7);
        let outcome = seal(config(&dir, 1), &mut s, &transport, || Ok(sample_bundle())).await;

        let sealed = match outcome {
            SealOutcome::Sealed(s) => s,
            SealOutcome::Aborted { reason, .. } => panic!("expected Sealed, aborted: {reason}"),
        };
        assert_eq!(sealed.bundle_digest, sample_bundle().bundle_digest());
        assert_eq!(sealed.acks.len(), SEAL_SHARES as usize);

        // the bundle persisted + read-back matches the digest (H2).
        let loaded =
            bundle::load_bundle(&dir, AGENT, &sealed.bundle_digest).expect("bundle persisted");
        assert_eq!(loaded, sample_bundle());

        // all three holders durably hold a valid epoch-1 record committing to the digest.
        for (i, holder_id) in HOLDER_IDS.iter().enumerate() {
            let h = Holder::open(&dir, AGENT, holder_id).unwrap();
            let rec = h.record().expect("holder is sealed");
            assert_eq!(rec.seal_epoch, 1);
            assert_eq!(rec.bundle_digest, sealed.bundle_digest);
            assert_eq!(rec.wake_conditions.wake_at, WAKE_AT);
            assert!(rec.active_lease.is_none());
            assert_eq!(rec.share_commitment, sealed.wake_request.seal.commitments[i]);
        }
        assert_eq!(
            sealed.wake_request.seal.holder_pubkeys,
            HOLDER_IDS.map(String::from).to_vec()
        );
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_quiesce_fails_stays_awake_and_persists_nothing() {
        let dir = tempdir();
        let transport = MockTransport::ok();
        let mut s = seed(7);
        let outcome =
            seal(config(&dir, 5), &mut s, &transport, || anyhow::bail!("loop would not drain")).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason } => {
                assert_eq!(next_seal_epoch, 6);
                assert!(matches!(reason, SealAbort::Quiesce(_)));
            }
            SealOutcome::Sealed(_) => panic!("must abort when quiesce fails"),
        }
        assert!(bundle::load_bundle(&dir, AGENT, "any").is_err());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_persist_fails() {
        let dir = tempdir();
        std::fs::write(super::super::hibernate_dir(&dir, AGENT), b"x").unwrap();
        let transport = MockTransport::ok();
        let mut s = seed(7);
        let outcome = seal(config(&dir, 2), &mut s, &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason } => {
                assert_eq!(next_seal_epoch, 3);
                assert!(matches!(reason, SealAbort::Persist(_)));
            }
            SealOutcome::Sealed(_) => panic!("must abort when persist fails"),
        }
        cleanup(&dir);
    }

    #[tokio::test]
    async fn abort_when_a_holder_cannot_receive() {
        let dir = tempdir();
        let collide = super::super::hibernate_dir(&dir, AGENT).join("holder-1.holder.json");
        std::fs::create_dir_all(&collide).unwrap();
        let transport = MockTransport::ok();
        let mut s = seed(7);
        let outcome = seal(config(&dir, 4), &mut s, &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason } => {
                assert_eq!(next_seal_epoch, 5);
                assert!(matches!(reason, SealAbort::Holder { holder_id: "holder-1", .. }));
            }
            SealOutcome::Sealed(_) => panic!("must abort when a holder cannot receive"),
        }
        cleanup(&dir);
    }

    #[tokio::test]
    async fn unconfirmed_publish_revokes_freezes_holders_and_stays_awake() {
        // The fork-integrity path: publish "succeeds" but the wake-request is not live on
        // fetch -> the seal cannot confirm-live -> it REVOKES (freezes the holders) and
        // aborts. No live wake-request + releasing holders can remain.
        let dir = tempdir();
        let transport = MockTransport::not_live_on_fetch();
        let mut s = seed(7);
        let outcome = seal(config(&dir, 9), &mut s, &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason } => {
                // frozen at epoch 10, so the retry uses 11 (supersedes the frozen holders).
                assert_eq!(next_seal_epoch, 11);
                assert!(matches!(reason, SealAbort::WakeRequestUnconfirmedRevoked));
            }
            SealOutcome::Sealed(_) => panic!("must abort + revoke when not confirmed live"),
        }
        // every holder is now FROZEN (wake_at = u64::MAX) -> refuses every lease -> a
        // waker can never get a share -> nothing is resurrectable.
        for holder_id in HOLDER_IDS {
            let mut h = Holder::open(&dir, AGENT, holder_id).unwrap();
            assert_eq!(h.record().unwrap().seal_epoch, 10, "holder superseded to the frozen epoch");
            assert_eq!(h.record().unwrap().wake_conditions.wake_at, u64::MAX);
            let req = UnsealRequest {
                npub: NPUB.to_string(),
                lease_id: "spawner-lease".to_string(),
                spawner_ephemeral_pubkey: "spawner".to_string(),
                lease_ttl_secs: 60,
            };
            // even far in the future, the frozen holder refuses (now < u64::MAX always).
            assert!(matches!(
                h.issue_lease(&req, u64::MAX - 1),
                Err(HolderError::TooEarly { .. })
            ));
        }
        cleanup(&dir);
    }

    #[tokio::test]
    async fn failing_publish_also_revokes_and_stays_awake() {
        // A definitively-failed publish also cannot confirm-live -> same revoke path
        // (the seal cannot tell a failed publish from an unconfirmable one, and revoking
        // is safe either way).
        let dir = tempdir();
        let transport = MockTransport::failing_publish();
        let mut s = seed(7);
        let outcome = seal(config(&dir, 7), &mut s, &transport, || Ok(sample_bundle())).await;
        assert!(matches!(
            outcome,
            SealOutcome::Aborted { next_seal_epoch: 9, reason: SealAbort::WakeRequestUnconfirmedRevoked }
        ));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn confirm_live_rejects_a_same_digest_but_different_request() {
        // FIX (verify-live too loose): the relay holds a request with the SAME digest (and
        // epoch + resume_seq) but a different wake_at. The old 3-field check would accept
        // it; full request-equality must reject it -> the seal does NOT commit, it revokes.
        let dir = tempdir();
        let transport = MockTransport::tampered_fetch();
        let mut s = seed(7);
        let outcome = seal(config(&dir, 3), &mut s, &transport, || Ok(sample_bundle())).await;
        assert!(
            matches!(outcome, SealOutcome::Aborted { reason: SealAbort::WakeRequestUnconfirmedRevoked, .. }),
            "a same-digest but non-equal request must NOT be accepted as confirmed-live"
        );
        cleanup(&dir);
    }

    #[tokio::test]
    async fn cancelled_mid_publish_does_not_lose_the_seed() {
        // FIX (cancellation): the seed is borrowed, zeroized only past the PONR. A seal
        // future dropped mid-publish (here via a timeout over a hanging publish) leaves
        // the caller's seed intact + reusable, NOT zeroized-and-lost.
        let dir = tempdir();
        let mut s = seed(7);

        let hanging = MockTransport::hanging_publish();
        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            seal(config(&dir, 1), &mut s, &hanging, || Ok(sample_bundle())),
        )
        .await;
        assert!(cancelled.is_err(), "the seal must still be hung in publish (cancelled)");

        // the same seed seals successfully afterwards (it survived the cancellation).
        let good = MockTransport::ok();
        let outcome = seal(config(&dir, 2), &mut s, &good, || Ok(sample_bundle())).await;
        assert!(matches!(outcome, SealOutcome::Sealed(_)), "the reused seed must still seal");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn revoke_then_retry_supersedes_and_seals() {
        // Unconfirmed publish -> revoke (freeze) -> the caller retries at next_seal_epoch
        // with the intact seed + a working transport -> Sealed, superseding the frozen
        // holders back to a real, wakeable state.
        let dir = tempdir();
        let mut s = seed(7);
        let bad = MockTransport::not_live_on_fetch();
        let next = match seal(config(&dir, 5), &mut s, &bad, || Ok(sample_bundle())).await {
            SealOutcome::Aborted { next_seal_epoch, .. } => next_seal_epoch,
            SealOutcome::Sealed(_) => panic!("expected revoke+abort"),
        };
        assert_eq!(next, 7); // frozen at 6, retry at 7

        let good = MockTransport::ok();
        let outcome = seal(config(&dir, next), &mut s, &good, || Ok(sample_bundle())).await;
        assert!(matches!(outcome, SealOutcome::Sealed(_)), "retry must seal");
        for holder_id in HOLDER_IDS {
            let rec_dir = Holder::open(&dir, AGENT, holder_id).unwrap();
            let rec = rec_dir.record().unwrap();
            assert_eq!(rec.seal_epoch, 7, "frozen holders superseded to the retry epoch");
            assert_eq!(rec.wake_conditions.wake_at, WAKE_AT, "wakeable again");
        }
        cleanup(&dir);
    }

    #[tokio::test]
    async fn refuses_to_seal_when_the_epoch_is_exhausted() {
        let dir = tempdir();
        let transport = MockTransport::ok();
        let mut s = seed(7);
        let outcome =
            seal(config(&dir, u64::MAX), &mut s, &transport, || Ok(sample_bundle())).await;
        match outcome {
            SealOutcome::Aborted { next_seal_epoch, reason } => {
                assert_eq!(next_seal_epoch, u64::MAX);
                assert!(matches!(reason, SealAbort::EpochExhausted));
            }
            SealOutcome::Sealed(_) => panic!("must refuse to seal at an exhausted epoch"),
        }
        // nothing was persisted.
        assert!(bundle::load_bundle(&dir, AGENT, "any").is_err());
        cleanup(&dir);
    }
}
