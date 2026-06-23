//! Hibernation chunk H6: the end-to-end round-trip integration test, the capstone that
//! proves "it died and came back as itself"
//! (`plans/build-spec-kirby-hibernation-thinslice.md`, chunk H6).
//!
//! This composes the merged ceremony primitives end to end and reimplements none of
//! them: H4b [`seal`](super::seal::seal) takes a live agent to hibernated, and H5
//! [`reconstitute`](super::unseal::reconstitute) brings a FRESH process back as the same
//! agent. The test asserts the milestone in one pass: the same npub, byte-identical
//! state (memory / wallet / checkpoint), the resume sequence advanced from N to N+1, and
//! a live fencing lease on the resurrected runtime.
//!
//! ## What "single node" means here, and how the wake-request survives the exit
//!
//! Move-1 is single-node: no cross-node watcher quorum, no real relay, no VM
//! reprovision (those are Move-2). The three share-holders are in-process
//! [`Holder`](super::holder::Holder)s on one disk, exactly as H4a/H4b/H5 model them.
//!
//! The seal ceremony publishes its wake-request through a
//! [`WakeTransport`](super::seal::WakeTransport); in production that is the Nostr relay
//! ([`RelayWakeTransport`](super::seal::RelayWakeTransport), H3), whose copy outlives the
//! sleeping agent. To model that durability faithfully on a single node WITHOUT a relay,
//! this test backs the transport with a FILE: [`seal`](super::seal::seal) genuinely
//! persists the wake-request to disk on publish and genuinely reads it back to
//! confirm-live, so the commitment is a real on-disk artifact, not a value held in
//! memory across the "process exit". The simulated exit then drops ALL in-memory state
//! (the sealed seed, the transport, every value the seal returned) by leaving an inner
//! scope; the fresh context reads the wake-request back from disk and reconstitutes from
//! the on-disk holder dir plus bundle store alone. Nothing but bytes-on-disk crosses the
//! boundary.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::seal::{seal, FetchedWake, SealConfig, SealOutcome, WakeTransport};
use super::shamir::{derive_subkeys, MasterSeed};
use super::unseal::{reconstitute, LeasedRuntime, SpawnerProposal};
use super::{
    bundle, hibernate_dir, holder::holder_path, CheckpointPos, MemoryRef, StateBundle, WakeRequest,
    WalletState, SEAL_SHARES, SEAL_THRESHOLD,
};

const AGENT: &str = "kirby-roundtrip";
const NPUB: &str = "npub1roundtripcapstone";
/// The sequence the known agent state is sealed at; a fresh process resumes at N+1.
const RESUME_N: u64 = 41;
/// The wake timer (unix seconds): a holder issues a lease only once `now >= wake_at`.
const WAKE_AT: u64 = 1_000;

/// A durable, file-backed [`WakeTransport`]: the single-node stand-in for the relay.
/// `publish` writes the wake-request JSON to a fixed path (the relay's durable copy) and
/// `fetch_by_digest` reads it back. The file outlives the in-memory seal state, so it is
/// exactly the artifact a fresh process must wake from, with no relay and no network.
struct FileWakeTransport {
    npub: String,
    wake_path: PathBuf,
}

impl FileWakeTransport {
    fn new(npub: &str, wake_path: PathBuf) -> Self {
        FileWakeTransport { npub: npub.to_string(), wake_path }
    }
}

#[async_trait::async_trait]
impl WakeTransport for FileWakeTransport {
    fn npub(&self) -> String {
        self.npub.clone()
    }

    async fn publish(&self, request: &WakeRequest) -> anyhow::Result<String> {
        if let Some(parent) = self.wake_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.wake_path, serde_json::to_vec(request)?)?;
        // The event id is the bundle digest: a stable, content-addressed id the
        // confirm-live check matches against (the relay returns its own id; here the
        // digest plays that role since it uniquely names this published request).
        Ok(request.bundle_digest.clone())
    }

    async fn fetch_by_digest(&self, bundle_digest: &str) -> anyhow::Result<Option<FetchedWake>> {
        match std::fs::read(&self.wake_path) {
            Ok(bytes) => {
                let request: WakeRequest = serde_json::from_slice(&bytes)?;
                if request.bundle_digest == bundle_digest {
                    let event_id = request.bundle_digest.clone();
                    Ok(Some(FetchedWake { request, event_id }))
                } else {
                    Ok(None)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// The known agent state we seal: a memory ref, an ecash wallet snapshot, a loop
/// checkpoint, all at sequence [`RESUME_N`].
fn known_state() -> StateBundle {
    StateBundle {
        memory_ref: MemoryRef { digest: "f0".repeat(32) },
        wallet_state: WalletState { balance_sats: 3_899, proofs: vec![0xde, 0xad, 0xbe, 0xef] },
        checkpoint: CheckpointPos { sha256: "c0".repeat(32), len: 4_096 },
        resume_seq: RESUME_N,
    }
}

/// Read the wake-request back from disk in the fresh context (the relay's durable copy).
fn read_wake_request(wake_path: &Path) -> WakeRequest {
    let bytes = std::fs::read(wake_path).expect("the seal persisted a wake-request to disk");
    serde_json::from_slice(&bytes).expect("the on-disk wake-request deserializes")
}

/// One full hibernate round-trip over the shared on-disk artifacts: seal `bundle` at
/// `seal_epoch` (consuming a seed built from `seed_bytes`, which the committed seal
/// zeroizes), simulate the process exit by dropping every in-memory seal value at the
/// inner scope, then reconstitute from the on-disk holder dir, bundle store, and
/// wake-request file alone. Returns the resurrected, lease-gated runtime. Asserts the
/// seal committed and that the expected artifacts are durably on disk.
#[allow(clippy::too_many_arguments)]
async fn hibernate_round_trip(
    dir: &Path,
    wake_path: &Path,
    seed_bytes: [u8; 32],
    bundle: StateBundle,
    seal_epoch: u64,
    wake_at: u64,
    now: u64,
    spawner: SpawnerProposal,
) -> LeasedRuntime {
    let committed_digest = bundle.bundle_digest();

    // ---- the agent runs, then SEALS and exits ----
    {
        let mut master_seed = MasterSeed::from_bytes(seed_bytes);
        let transport = FileWakeTransport::new(NPUB, wake_path.to_path_buf());
        let config = SealConfig {
            agent_id: AGENT,
            treasury_dir: dir,
            seal_epoch,
            wake_at,
            image_ref: "sha256:genome-image".to_string(),
            solvency_hint: bundle.wallet_state.balance_sats,
            // One confirm attempt is enough: publish writes the file synchronously, so the
            // immediate fetch finds it (no propagation delay to ride out, no sleep).
            confirm_attempts: 1,
            confirm_delay: Duration::ZERO,
        };
        match seal(config, &mut master_seed, &transport, move || Ok(bundle)).await {
            SealOutcome::Sealed(s) => {
                assert_eq!(s.bundle_digest, committed_digest, "the seal commits to the known state");
                assert_eq!(s.acks.len(), SEAL_SHARES as usize, "every holder durably acked");
            }
            SealOutcome::Aborted { reason, .. } => panic!("the seal must commit, but aborted: {reason}"),
        }
        // The committed seal zeroized `master_seed` in place. `transport`, the config, and
        // the Sealed outcome all drop at this closing brace. From here ONLY on-disk
        // artifacts remain: the holder dir, the bundle store, and the wake-request file.
    }

    // ---- the process has exited: only bytes-on-disk survive ----
    assert!(wake_path.exists(), "the wake-request is a durable on-disk artifact");
    assert!(
        bundle::bundle_path(dir, AGENT).exists(),
        "the sealed state bundle persists on disk",
    );

    // ---- a FRESH context reconstitutes from those artifacts alone ----
    let wake = read_wake_request(wake_path);
    assert_eq!(
        wake.bundle_digest, committed_digest,
        "the on-disk wake-request commits to the sealed state",
    );
    for holder_id in &wake.seal.holder_pubkeys {
        assert!(
            holder_path(dir, AGENT, holder_id).exists(),
            "holder {holder_id} that the seal named must persist its share on disk",
        );
    }

    reconstitute(dir, AGENT, NPUB, &wake, &spawner, now)
        .expect("a fresh process reconstitutes from the on-disk artifacts")
}

/// THE gate: a single-node agent runs, seals, the process exits, a fresh process
/// reconstitutes, and it is provably the same agent at the next sequence with intact
/// state and live authority.
#[tokio::test]
async fn round_trip_died_and_came_back_as_itself() {
    let dir = tempdir();
    let wake_path = hibernate_dir(&dir, AGENT).join("wake-request.json");
    let seed_bytes = [0xa5u8; 32];
    // The cryptographic identity the seed yields, captured via a sibling derivation so we
    // can prove the SAME secret returns (not just the npub label). The sealed seed itself
    // is consumed and zeroized by the committed seal, so it cannot be read back directly.
    let expected = derive_subkeys(&MasterSeed::from_bytes(seed_bytes));

    let original = known_state();
    assert_eq!(original.resume_seq, RESUME_N);

    let now = WAKE_AT; // the wake timer has elapsed (now >= wake_at)
    let rt = hibernate_round_trip(
        &dir,
        &wake_path,
        seed_bytes,
        original.clone(),
        1,
        WAKE_AT,
        now,
        SpawnerProposal {
            lease_id: "resume-lease-1".to_string(),
            ephemeral_pubkey: "spawner-fresh-process".to_string(),
            lease_ttl_secs: 300,
        },
    )
    .await;

    // 1. SAME identity: the npub label AND the secret behind the authority gate.
    assert_eq!(rt.npub(), NPUB, "the npub identity is preserved across the sleep");
    rt.with_authority(now, |auth| {
        assert_eq!(auth.identity_key(), &expected.identity_key, "the identity key returns");
        assert_eq!(auth.state_key(), &expected.state_key, "the state key returns");
        assert_eq!(auth.wallet_seed(), &expected.wallet_seed, "the wallet seed returns");
    })
    .expect("a live lease grants authority");

    // 2. SAME state, byte-identical (memory / wallet / checkpoint and the sequence).
    assert_eq!(
        rt.bundle(),
        &original,
        "the restored state bundle is byte-identical to what was sealed",
    );

    // 3. the resume sequence ADVANCED from N to N+1.
    assert_eq!(rt.bundle().resume_seq, RESUME_N, "the sealed sequence is preserved");
    assert_eq!(rt.next_resume_seq(), RESUME_N + 1, "the agent resumes at the next sequence");

    // 4. the resurrected runtime holds a LIVE quorum lease (barrier 3).
    assert!(rt.is_live(now), "the reconstituted runtime holds a live lease");
    assert!(!rt.must_self_stop(now), "a live-leased runtime need not self-stop");
    assert_eq!(
        rt.lease().bundle_digest,
        original.bundle_digest(),
        "the lease commits to the sealed state",
    );
    assert!(
        rt.lease().quorum_sigs.len() >= SEAL_THRESHOLD as usize,
        "the lease carries a 2-of-3 quorum's assent",
    );

    cleanup(&dir);
}

/// The loop is repeatable: an agent sleeps, wakes at N+1, runs, and hibernates AGAIN,
/// waking at N+2, with the same identity each time and the sequence advancing
/// monotonically across sleeps. The second seal is a new generation (epoch 2) that
/// supersedes the first generation's holders, so a stale lease cannot block the next wake.
#[tokio::test]
async fn round_trip_is_repeatable_across_successive_hibernations() {
    let dir = tempdir();
    let wake_path = hibernate_dir(&dir, AGENT).join("wake-request.json");
    let seed_bytes = [0x5au8; 32];
    let expected = derive_subkeys(&MasterSeed::from_bytes(seed_bytes));

    // cycle 1: seal at sequence N (epoch 1), then wake at N+1.
    let rt1 = hibernate_round_trip(
        &dir,
        &wake_path,
        seed_bytes,
        known_state(),
        1,
        WAKE_AT,
        WAKE_AT,
        SpawnerProposal {
            lease_id: "resume-1".to_string(),
            ephemeral_pubkey: "process-1".to_string(),
            lease_ttl_secs: 300,
        },
    )
    .await;
    assert_eq!(rt1.next_resume_seq(), RESUME_N + 1, "the first wake resumes at N+1");
    rt1.with_authority(WAKE_AT, |auth| {
        assert_eq!(auth.identity_key(), &expected.identity_key);
    })
    .expect("a live lease after the first wake");
    drop(rt1); // the first awakened runtime ends as the agent hibernates again.

    // cycle 2: the agent ran at N+1, then re-hibernates committing sequence N+1 (epoch 2,
    // a new generation that supersedes the cycle-1 holders), then wakes at N+2. The
    // wake_at is later, as a fresh sleep schedules a new wake time.
    let wake_at_2 = WAKE_AT + 500;
    let second = StateBundle {
        memory_ref: MemoryRef { digest: "e1".repeat(32) }, // memory grew while awake
        wallet_state: WalletState { balance_sats: 3_710, proofs: vec![0xca, 0xfe] }, // spent some sats
        checkpoint: CheckpointPos { sha256: "d2".repeat(32), len: 8_192 },
        resume_seq: RESUME_N + 1,
    };
    let rt2 = hibernate_round_trip(
        &dir,
        &wake_path,
        seed_bytes,
        second.clone(),
        2,
        wake_at_2,
        wake_at_2,
        SpawnerProposal {
            lease_id: "resume-2".to_string(),
            ephemeral_pubkey: "process-2".to_string(),
            lease_ttl_secs: 300,
        },
    )
    .await;

    // the sequence advanced again, the updated state restored, the identity unchanged.
    assert_eq!(rt2.bundle(), &second, "the second sleep restores the updated state");
    assert_eq!(
        rt2.next_resume_seq(),
        RESUME_N + 2,
        "the sequence advances monotonically across successive sleeps",
    );
    rt2.with_authority(wake_at_2, |auth| {
        assert_eq!(
            auth.identity_key(),
            &expected.identity_key,
            "the identity is stable across successive sleeps",
        );
    })
    .expect("a live lease after the second wake");

    cleanup(&dir);
}

/// Hand-rolled temp dir (no dev-dep), matching the other hibernate test modules.
fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let p =
        std::env::temp_dir().join(format!("kirby-hibernate-roundtrip-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn cleanup(p: &Path) {
    let _ = std::fs::remove_dir_all(p);
}
