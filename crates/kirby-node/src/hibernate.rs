//! Kirby hibernation, thin slice (Move 1): the shared-types skeleton (chunk H0).
//!
//! Hibernation lets a Kirby persist its state + secret, "sleep" (the process exits /
//! the VM deallocates), and have a FRESH process reconstitute the SAME identity +
//! state and resume at the next sequence — the "it died and came back as itself"
//! milestone (`plans/build-spec-kirby-hibernation-thinslice.md`).
//!
//! Hibernation is a tiny distributed commit protocol, so the build honors three
//! barriers even with the thin slice's in-process share-holders:
//! 1. **Quiescence before seal** — freeze state (stop new work, drain effects,
//!    finalize the wallet, checkpoint) BEFORE computing [`StateBundle::bundle_digest`];
//!    nothing changes between snapshot and deallocation.
//! 2. **Durable watcher record before ack/release** — a holder's ack means "fsynced"
//!    (the [`WatcherRecord`] is written before any release).
//! 3. **Live lease before resurrected authority** — the awakened runtime must hold a
//!    live quorum [`Lease`] (the fencing token) to do ANYTHING with the identity /
//!    wallet / checkpoint keys; it renews before `expires_at` or self-stops.
//!
//! H0 is the CONTRACT only: the shared types (structs/enums + the
//! [`StateBundle::bundle_digest`] and [`hibernate_dir`] signatures) the parallel
//! front (H1 Shamir, H2 bundle+digest, H3 wake-request, H4 seal, H5 unseal) fills in.
//! There is no ceremony logic here — the digest method is a [`todo!`] stub for H2.
//!
//! Everything here is HOST-SIDE and serde-serializable: bundles persist to the local
//! store, watcher records fsync, leases and shares move between holders, and the
//! [`WakeRequest`] is the JSON content payload of a Nostr event (H3 wraps it in the
//! event + defines the kind, mirroring the `nerve` `*Content` types). It does not
//! touch the genome, the `SandboxBackend`/`SandboxInstance` trait, or any sudo/jailer
//! path.
//!
//! Agent-scoped discipline (bake now; keeps multi-agent-per-node open later): all
//! hibernation artifacts live under [`hibernate_dir`] = `<treasury_dir>/hibernate-{agent_id}`,
//! mirroring the existing `checkpoints-{agent_id}` precedent (`run_agent.rs`) — NEVER
//! in a node-singleton path. For the thin slice agent == node, so the sealed
//! bootstrap secret IS the node seed (the F3 one-key invariant); the agent-key /
//! host-key split is Move-2.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// H2: the bundle digest (canonical encoding) + the agent-scoped persist/read-back,
// in a submodule so the parallel-front chunks do not collide editing this file.
pub mod bundle;

/// The wake-request Nostr event (chunk H3): wrap a [`WakeRequest`] as the content of
/// an addressable Nostr event, sign + publish it via the slice-1 nerve relay client,
/// and fetch it back by npub / `bundle_digest`.
pub mod wake;

/// H1: Shamir secret-sharing of the master seed + domain-separated subkey derivation.
pub mod shamir;

/// H4a: the in-process share-holder + fencing lease — the durable [`WatcherRecord`]
/// (barrier 2), the single-live-lease-per-`(npub, resume_seq)` fence (barrier 3), and
/// condition-gated share release. The quorum primitive seal (H4b) + unseal (H5) drive.
pub mod holder;

/// H4b: the SEAL ceremony — the atomic-commit orchestration (quiesce -> persist -> split
/// -> distribute -> publish -> VERIFY=PONR -> zeroize) composing H1/H2/H3/H4a, with
/// abort-and-stay-awake (bump `seal_epoch`) before the point of no return.
pub mod seal;

/// The Shamir threshold for the thin slice: any `SEAL_THRESHOLD`-of-`SEAL_SHARES`
/// shares reconstruct the master seed. 2-of-3 (survive losing one holder).
pub const SEAL_THRESHOLD: u8 = 2;
/// The number of Shamir shares the master seed is split into (one per holder).
pub const SEAL_SHARES: u8 = 3;

/// The agent-scoped hibernation artifact directory: `<treasury_dir>/hibernate-{agent_id}`.
///
/// Mirrors the `checkpoints-{agent_id}` precedent (`run_agent.rs`): hibernation
/// artifacts (the sealed [`StateBundle`], watcher records, shares) are agent-scoped,
/// NOT in any node-singleton path (the treasury/wallet are node-singletons today).
/// Keying by `agent_id` is what keeps multi-agent-per-node cheap to add later.
pub fn hibernate_dir(treasury_dir: &Path, agent_id: &str) -> PathBuf {
    treasury_dir.join(format!("hibernate-{agent_id}"))
}

/// A content reference to the agent's engram (memory) snapshot.
///
/// Thin slice: `digest` resolves against the LOCAL engram store. Move-2: the same
/// digest resolves against Blossom (a content-addressed blob store), so the
/// reference shape is stable across the two. Content-addressed by sha256 (lowercase
/// hex), matching the checkpoint convention.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryRef {
    /// sha256 (lowercase hex) of the engram snapshot.
    pub digest: String,
}

/// A snapshot of the agent's ecash wallet at seal time.
///
/// `balance_sats` is the legible balance; `proofs` is the opaque serialized cdk
/// proof material restored verbatim on unseal (the daemon does not interpret it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletState {
    /// The wallet balance in sats at seal time.
    pub balance_sats: u64,
    /// Opaque serialized ecash proof material (the cdk proofs), restored verbatim.
    pub proofs: Vec<u8>,
}

/// The agent's resumable checkpoint (the loop position) committed into the bundle.
///
/// Mirrors the content-addressed `kirby_proto::CheckpointRef` shape (sha256 + len),
/// but as a serde-serializable hibernate-local type because the bundle is
/// JSON-serialized + digested over (the prost `CheckpointRef` is not serde).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPos {
    /// sha256 (lowercase hex) of the checkpoint payload.
    pub sha256: String,
    /// The checkpoint payload length in bytes.
    pub len: u64,
}

/// The sealed agent state: everything a fresh process needs to come back as itself.
///
/// The [`bundle_digest`](StateBundle::bundle_digest) is the IMMUTABLE commitment over
/// all of these fields; the [`WakeRequest`], [`Lease`], and [`WatcherRecord`] all
/// carry a copy of it, and restore must reproduce exactly the bundle the digest
/// commits to (the restore-consistency rule, H2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateBundle {
    /// Reference to the engram (memory) snapshot.
    pub memory_ref: MemoryRef,
    /// The ecash proofs / balance snapshot.
    pub wallet_state: WalletState,
    /// The loop-position checkpoint.
    pub checkpoint: CheckpointPos,
    /// The monotonic resume sequence; a fresh process resumes at `resume_seq + 1`.
    pub resume_seq: u64,
}

impl StateBundle {
    /// The immutable content digest (sha256, lowercase hex) committing to this
    /// bundle: a hash over the canonical serialization of all fields. The
    /// wake-request commits to it, and a tampered bundle fails the recomputed check.
    ///
    /// Implemented in [`bundle`] via a fixed-field, length-prefixed canonical
    /// encoding decoupled from the storage format, so the same bundle always hashes
    /// to the same digest regardless of field order or serialization whitespace.
    pub fn bundle_digest(&self) -> String {
        bundle::compute_digest(self)
    }
}

/// The raw Shamir share material, held as a secret newtype.
///
/// Serializes transparently as the underlying byte vector, so the holder-transport
/// wire shape is identical to a bare `Vec<u8>`. But it zeroizes on drop and its `Debug`
/// is redacted, so a stray `{:?}` on a [`Share`] can never dump share material. The
/// bytes ARE sensitive: any [`SEAL_THRESHOLD`] of them reconstruct the master seed.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct ShareBytes(Vec<u8>);

impl ShareBytes {
    /// Wrap raw share bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the raw share bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ShareBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShareBytes([{} bytes redacted])", self.0.len())
    }
}

/// A 2-of-3 Shamir share of the master seed (the wire format moved between holders).
///
/// `seal_epoch` binds the share to a seal attempt: aborting a seal before the point
/// of no return BUMPS the epoch so orphaned shares from the old epoch are never
/// honored. `commitment` is the corrupt-share detector (H1: a checksum/commitment,
/// NOT full VSS), as lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    /// The 1-based share index (`1..=SEAL_SHARES`).
    pub share_index: u8,
    /// The raw Shamir share material (zeroizing; see [`ShareBytes`]).
    pub share_bytes: ShareBytes,
    /// The seal epoch this share belongs to (an abort bumps it, invalidating prior shares).
    pub seal_epoch: u64,
    /// A commitment/checksum over the share for corrupt-share detection (hex).
    pub commitment: String,
}

/// The identity of a lease: a live lease is unique per `(npub, resume_seq)`.
///
/// Holders refuse to issue/sign a second live lease for the same key — the
/// anti-equivocation invariant that fences a stale/duplicate spawner (barrier 3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LeaseKey {
    /// The agent/node npub (its stable identity).
    pub npub: String,
    /// The resume sequence this lease authorizes.
    pub resume_seq: u64,
}

/// A quorum-issued fencing token: live authority to act as the resurrected agent.
///
/// The awakened runtime refuses identity-sign / wallet-spend / checkpoint unless it
/// holds a live lease, and renews before `expires_at` or self-stops (barrier 3). A
/// winner-dies-before-checkpoint retry gets a NEW `lease_id`, and the stale
/// instance's checkpoint is rejected. Keyed by [`LeaseKey`] = `(npub, resume_seq)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    /// The agent/node npub the lease is issued to.
    pub npub: String,
    /// The resume sequence this lease authorizes.
    pub resume_seq: u64,
    /// The unique lease id (a fresh one per issuance; a retry gets a new id).
    pub lease_id: String,
    /// The bundle digest this lease commits to (must match the restored bundle).
    pub bundle_digest: String,
    /// The lease expiry, unix seconds; the holder self-stops once past it.
    pub expires_at: u64,
    /// The ephemeral pubkey of the spawner this lease was issued to (the fence).
    pub spawner_ephemeral_pubkey: String,
    /// The quorum's signatures over the lease (one per assenting holder), as hex.
    pub quorum_sigs: Vec<String>,
}

impl Lease {
    /// This lease's identity key, `(npub, resume_seq)` — the uniqueness unit holders
    /// enforce (no two live leases per key).
    pub fn key(&self) -> LeaseKey {
        LeaseKey { npub: self.npub.clone(), resume_seq: self.resume_seq }
    }
}

/// The wake conditions a watcher checks before releasing shares.
///
/// Thin slice: timer only — release is allowed once `now >= wake_at`. The `wake_on`
/// event triggers (and their public-verifiability constraint) are deferred to Move-2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WakeConditions {
    /// The earliest unix-seconds time at which the agent may be woken.
    pub wake_at: u64,
}

/// The active-lease record a watcher tracks for a sealed agent (the anti-equivocation
/// state): the nested object under [`WatcherRecord`]. Present only while a lease is live.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveLease {
    /// The live lease's id.
    pub lease_id: String,
    /// The live lease's expiry, unix seconds.
    pub expires_at: u64,
    /// The spawner the live lease was issued to.
    pub spawner_ephemeral_pubkey: String,
}

/// One entry in a watcher's release history: an audit record of a past share release,
/// so a holder can detect double-release and reconstruct the lease lineage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseEntry {
    /// The lease id under which the share was released.
    pub lease_id: String,
    /// The spawner the share was released to.
    pub spawner_ephemeral_pubkey: String,
    /// When the release happened, unix seconds.
    pub released_at: u64,
}

/// A holder's durable record for a sealed agent, fsynced BEFORE any ack/release
/// (barrier 2: "ack means fsynced; write-before-release").
///
/// It pins what the holder is guarding (the seal epoch, the bundle digest + resume
/// sequence, the wake conditions, this holder's share commitment), the currently
/// live lease (if any), and the audit trail of past releases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatcherRecord {
    /// The agent/node npub this record guards.
    pub npub: String,
    /// The seal epoch this record is for (a bump retires prior epochs' shares).
    pub seal_epoch: u64,
    /// The bundle digest the seal commits to.
    pub bundle_digest: String,
    /// The resume sequence the seal commits to.
    pub resume_seq: u64,
    /// The conditions under which this holder may release its share.
    pub wake_conditions: WakeConditions,
    /// The commitment for this holder's share (corrupt-share detection), as hex.
    pub share_commitment: String,
    /// The currently live lease, if one has been issued (`None` = none live).
    pub active_lease: Option<ActiveLease>,
    /// The audit trail of past share releases.
    pub release_history: Vec<ReleaseEntry>,
}

/// The seal block of a [`WakeRequest`]: how to reconstruct the secret on wake.
///
/// It names the share holders, the threshold (`SEAL_THRESHOLD` = 2), the per-share
/// commitments, and the seal epoch (so a watcher honors only the current epoch).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seal {
    /// The share holders' pubkeys (one per share).
    pub holder_pubkeys: Vec<String>,
    /// The reconstruction threshold (`SEAL_THRESHOLD`, i.e. 2 for 2-of-3).
    pub threshold: u8,
    /// The per-share commitments (corrupt-share detection), as hex; one per holder.
    pub commitments: Vec<String>,
    /// The seal epoch this wake-request is for.
    pub seal_epoch: u64,
}

/// The wake-request: the signed, public commitment that an agent has hibernated and
/// how to wake it. The JSON content payload of a Nostr event (H3 wraps it in the
/// event, defines the kind, signs with the node/agent key, and publishes), mirroring
/// the `nerve` `*Content` types.
///
/// Thin slice carries `wake_at` (timer) only; the `wake_on` event triggers are
/// deferred to Move-2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WakeRequest {
    /// The earliest unix-seconds time at which the agent may be woken (the timer).
    pub wake_at: u64,
    /// The bundle digest the seal commits to (the immutable state commitment).
    pub bundle_digest: String,
    /// The genome image reference to reprovision the agent from (content-addressed).
    pub image_ref: String,
    /// How to reconstruct the secret on wake (holders, threshold, commitments, epoch).
    pub seal: Seal,
    /// The monotonic resume sequence; the awakened agent resumes at `resume_seq + 1`.
    pub resume_seq: u64,
    /// A hint of the agent's solvency at seal time, in sats, so a waker can gauge
    /// whether reprovisioning is fundable.
    pub solvency_hint: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hibernate_dir_mirrors_the_checkpoints_precedent() {
        let dir = hibernate_dir(Path::new("/var/lib/kirby/treasury"), "agent-0");
        assert_eq!(dir, PathBuf::from("/var/lib/kirby/treasury/hibernate-agent-0"));
        assert!(dir.ends_with("hibernate-agent-0"));
    }

    #[test]
    fn lease_key_is_npub_and_resume_seq() {
        let lease = Lease {
            npub: "npub1abc".to_string(),
            resume_seq: 7,
            lease_id: "lease-1".to_string(),
            bundle_digest: "deadbeef".to_string(),
            expires_at: 1_000,
            spawner_ephemeral_pubkey: "ephem-pub".to_string(),
            quorum_sigs: vec![],
        };
        assert_eq!(
            lease.key(),
            LeaseKey { npub: "npub1abc".to_string(), resume_seq: 7 }
        );
    }

    #[test]
    fn thin_slice_threshold_is_2_of_3() {
        assert_eq!(SEAL_THRESHOLD, 2);
        assert_eq!(SEAL_SHARES, 3);
    }
}
