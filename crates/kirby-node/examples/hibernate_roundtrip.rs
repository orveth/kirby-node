//! Runnable, human-watchable hibernation round-trip demo (chunk H6, additive to the
//! automated `hibernate::roundtrip` test). It boots a known agent state, seals it,
//! simulates a process exit, reconstitutes in a fresh context, and PRINTS npub +
//! resume_seq + a state digest + an identity fingerprint BEFORE and AFTER, so "same
//! identity, sequence advanced, state intact" is plainly readable on stdout rather than
//! hidden behind a green assertion.
//!
//! Single-node, no real reprovision (that is Move-2): the three share-holders are
//! in-process holders on one disk, and the wake-request is persisted to a local file
//! that stands in for the Nostr relay's durable copy. Nothing but bytes-on-disk crosses
//! the simulated process boundary.
//!
//! Run it:
//!     nix develop --command bash -c 'cargo run -p kirby-node --example hibernate_roundtrip'
//!
//! It exits 0 and prints "it died and came back as itself." when every invariant holds.

use std::path::PathBuf;
use std::time::Duration;

use kirby_node::hibernate::seal::{seal, FetchedWake, SealConfig, SealOutcome, WakeTransport};
use kirby_node::hibernate::shamir::{derive_subkeys, MasterSeed, IDENTITY_KEY_LEN};
use kirby_node::hibernate::unseal::{reconstitute, SpawnerProposal};
use kirby_node::hibernate::{
    hibernate_dir, CheckpointPos, MemoryRef, StateBundle, WakeRequest, WalletState,
};
use sha2::{Digest, Sha256};

const AGENT: &str = "kirby-demo";
const NPUB: &str = "npub1demohibernationroundtrip";
/// The sequence the agent is sealed at; a fresh process resumes at N+1.
const RESUME_N: u64 = 41;
/// The wake timer (unix seconds): a holder issues a lease only once `now >= wake_at`.
const WAKE_AT: u64 = 1_000;

/// A durable, file-backed [`WakeTransport`]: the single-node stand-in for the relay.
/// `publish` writes the wake-request JSON to a fixed path (the relay's durable copy) and
/// `fetch_by_digest` reads it back, so the commitment is a real on-disk artifact that
/// outlives the in-memory seal state.
struct FileWakeTransport {
    npub: String,
    wake_path: PathBuf,
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

/// A one-way fingerprint of the secret identity key: safe to print (it does NOT reveal
/// the key), and equal before and after the sleep iff the SAME secret returned.
fn identity_fingerprint(identity_key: &[u8; IDENTITY_KEY_LEN]) -> String {
    let mut h = Sha256::new();
    h.update(b"kirby-hibernate/demo/identity-fingerprint");
    h.update(identity_key);
    h.finalize()[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn yesno(ok: bool) -> &'static str {
    if ok {
        "yes"
    } else {
        "NO"
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A throwaway working dir for the demo's on-disk artifacts.
    let dir = std::env::temp_dir().join(format!("kirby-hibernate-demo-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let wake_path = hibernate_dir(&dir, AGENT).join("wake-request.json");

    // The agent's bootstrap secret (its identity derives from this) and its known state.
    let seed_bytes = [0xa5u8; 32];
    let before_fp = identity_fingerprint(&derive_subkeys(&MasterSeed::from_bytes(seed_bytes)).identity_key);
    let original = StateBundle {
        memory_ref: MemoryRef { digest: "f0".repeat(32) },
        wallet_state: WalletState { balance_sats: 3_899, proofs: vec![0xde, 0xad, 0xbe, 0xef] },
        checkpoint: CheckpointPos { sha256: "c0".repeat(32), len: 4_096 },
        resume_seq: RESUME_N,
    };
    let before_digest = original.bundle_digest();

    println!("=== kirby hibernation round-trip (single node, no reprovision) ===\n");
    println!("BEFORE  (the agent is alive)");
    println!("  npub          : {NPUB}");
    println!("  resume_seq    : {}", original.resume_seq);
    println!("  state digest  : {before_digest}");
    println!("  identity fp   : {before_fp}\n");

    // ---- the agent seals, then the process exits ----
    {
        let mut seed = MasterSeed::from_bytes(seed_bytes);
        let transport = FileWakeTransport { npub: NPUB.to_string(), wake_path: wake_path.clone() };
        let config = SealConfig {
            agent_id: AGENT,
            treasury_dir: &dir,
            seal_epoch: 1,
            wake_at: WAKE_AT,
            image_ref: "sha256:genome-image".to_string(),
            solvency_hint: original.wallet_state.balance_sats,
            confirm_attempts: 1,
            confirm_delay: Duration::ZERO,
        };
        let snapshot = original.clone();
        match seal(config, &mut seed, &transport, move || Ok(snapshot)).await {
            SealOutcome::Sealed(s) => {
                println!("SEAL    quiesced, persisted, split 2-of-3 to holders, published.");
                println!("        wake-request -> {}", wake_path.display());
                println!("        bundle digest  {}", s.bundle_digest);
                println!("        holder acks    {}\n", s.acks.len());
            }
            SealOutcome::Aborted { reason, .. } => anyhow::bail!("the seal aborted: {reason}"),
        }
        // The committed seal zeroized the seed in place; the transport and everything else
        // in this scope drop at the brace. Only on-disk artifacts remain.
    }
    println!("EXIT    the process is gone. all in-memory state dropped.");
    println!("        surviving on disk: holder dir + bundle store + wake-request.\n");

    // ---- a fresh context reconstitutes from the on-disk artifacts alone ----
    let wake: WakeRequest = serde_json::from_slice(&std::fs::read(&wake_path)?)?;
    let now = wake.wake_at; // the wake timer has elapsed.
    let spawner = SpawnerProposal {
        lease_id: "demo-resume-lease".to_string(),
        ephemeral_pubkey: "demo-fresh-process".to_string(),
        lease_ttl_secs: 300,
    };
    let rt = reconstitute(&dir, AGENT, NPUB, &wake, &spawner, now)?;
    let after_fp = rt.with_authority(now, |auth| identity_fingerprint(auth.identity_key()))?;
    let after_digest = rt.bundle().bundle_digest();

    println!("AFTER   (reconstituted in a fresh context)");
    println!("  npub          : {}", rt.npub());
    println!("  restored seq  : {}", rt.bundle().resume_seq);
    println!("  resumes at    : {}", rt.next_resume_seq());
    println!("  state digest  : {after_digest}");
    println!("  identity fp   : {after_fp}");
    println!("  lease live    : {}\n", rt.is_live(now));

    let same_identity = rt.npub() == NPUB && after_fp == before_fp;
    let state_intact = after_digest == before_digest;
    let seq_advanced = rt.next_resume_seq() == original.resume_seq + 1;
    let live_lease = rt.is_live(now);

    println!("VERDICT");
    println!("  same identity : {}", yesno(same_identity));
    println!("  state intact  : {}", yesno(state_intact));
    println!(
        "  seq advanced  : {} ({} -> {})",
        yesno(seq_advanced),
        original.resume_seq,
        rt.next_resume_seq()
    );
    println!("  live lease    : {}", yesno(live_lease));

    std::fs::remove_dir_all(&dir).ok();

    if same_identity && state_intact && seq_advanced && live_lease {
        println!("\nit died and came back as itself.");
        Ok(())
    } else {
        anyhow::bail!("round-trip FAILED: an invariant did not hold");
    }
}
