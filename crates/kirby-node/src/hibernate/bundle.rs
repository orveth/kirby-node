//! Hibernation chunk H2: the [`StateBundle`] digest + the agent-scoped persist /
//! read-back. The bundle is the sealed agent state a fresh process reconstitutes to
//! "come back as itself"; this module makes its digest an immutable commitment and
//! its on-disk form durable + restore-consistent.
//!
//! ## Why the digest is stable (the crux of H2)
//!
//! [`compute_digest`] hashes a FIXED-FIELD, LENGTH-PREFIXED canonical encoding of the
//! bundle — NOT its serde/JSON form. This is deliberate:
//! - **Decoupled from storage.** The on-disk format ([`persist_bundle`] uses JSON)
//!   can change freely — whitespace, key order, even the serializer — without moving
//!   the commitment, because the digest never looks at the stored bytes.
//! - **No serde-representation dependence.** It does not rely on serde_json's
//!   (real but subtle) field-order guarantees, has no map-key-ordering or float
//!   ambiguity, and survives a crate bump.
//! - **Unambiguous field boundaries.** Every variable-length field is length-prefixed
//!   (`u64` big-endian length, then bytes) and every integer is fixed-width
//!   big-endian, so no two distinct bundles can encode to the same byte stream
//!   (e.g. `digest="ab"` + `sha256="c"` ≠ `digest="a"` + `sha256="bc"`).
//! - **Domain-separated + versioned.** A leading domain tag ([`DIGEST_DOMAIN`])
//!   prevents cross-protocol collisions and lets the encoding version if a field is
//!   ever added (a new field MUST be added here too, or it is not committed — the
//!   `every_field_is_committed` test guards that).
//!
//! The result is `sha256(canonical_bytes)` as lowercase hex, matching the
//! content-addressing convention in `checkpoint.rs`.
//!
//! ## Restore-consistency
//!
//! [`load_bundle`] reads the bundle, RECOMPUTES its digest, and returns it only if it
//! equals the digest the caller committed to (from the wake-request, H3) — so a
//! process can only resume exactly the bundle the commitment names; a tampered or
//! wrong bundle is refused.
//!
//! ## CheckpointPos vs kirby_proto::CheckpointRef (the H0-flagged unify question)
//!
//! Resolved: KEEP [`CheckpointPos`] as the bundle's serde-local checkpoint type (the
//! prost `CheckpointRef` is not serde, and the bundle must serialize + digest), but
//! provide LOSSLESS `From` conversions both ways. The daemon's checkpoint store deals
//! in `CheckpointRef`; the seal (H4) converts it into the bundle's `CheckpointPos`,
//! and unseal (H5) converts back — with no duplicated mapping and no change to the
//! `kirby-proto` wire crate.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use kirby_proto::CheckpointRef;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{hibernate_dir, CheckpointPos, StateBundle};

/// The file name the sealed bundle is stored under, inside the agent's hibernate dir.
const BUNDLE_FILE: &str = "state-bundle.json";

/// The domain-separation + version tag the canonical digest encoding is prefixed
/// with. Bump the version suffix if the canonical field set ever changes.
const DIGEST_DOMAIN: &[u8] = b"kirby-hibernate/state-bundle/v1";

/// Errors persisting or loading a [`StateBundle`].
#[derive(Debug, Error)]
pub enum BundleError {
    /// A filesystem operation failed.
    #[error("{op} bundle file {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Serializing the bundle to JSON failed.
    #[error("serialize bundle: {0}")]
    Serialize(#[source] serde_json::Error),
    /// Deserializing the stored bundle failed.
    #[error("deserialize bundle at {path}: {source}")]
    Deserialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// The loaded bundle's recomputed digest did not match the committed digest
    /// (restore-consistency violation — a tampered or wrong bundle).
    #[error("bundle digest mismatch: expected {expected}, recomputed {actual}")]
    DigestMismatch { expected: String, actual: String },
}

/// Compute the immutable [`StateBundle`] digest: `sha256` over the fixed-field,
/// length-prefixed canonical encoding, as lowercase hex. See the module docs for why
/// this is stable. Called by `StateBundle::bundle_digest`.
pub fn compute_digest(bundle: &StateBundle) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_bytes(bundle));
    to_hex(&hasher.finalize())
}

/// The canonical byte encoding the digest is taken over. Fixed field order; every
/// variable-length field length-prefixed; every integer fixed-width big-endian.
fn canonical_bytes(b: &StateBundle) -> Vec<u8> {
    let mut buf = Vec::new();
    push_bytes(&mut buf, DIGEST_DOMAIN);
    // memory_ref
    push_bytes(&mut buf, b.memory_ref.digest.as_bytes());
    // wallet_state
    push_u64(&mut buf, b.wallet_state.balance_sats);
    push_bytes(&mut buf, &b.wallet_state.proofs);
    // checkpoint
    push_bytes(&mut buf, b.checkpoint.sha256.as_bytes());
    push_u64(&mut buf, b.checkpoint.len);
    // resume_seq
    push_u64(&mut buf, b.resume_seq);
    buf
}

/// Append a length-prefixed byte field: the `u64` big-endian length, then the bytes.
fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// Append a fixed-width `u64` (big-endian, 8 bytes).
fn push_u64(buf: &mut Vec<u8>, n: u64) {
    buf.extend_from_slice(&n.to_be_bytes());
}

/// Lowercase-hex encode (matches `checkpoint.rs`; no `hex` crate dependency).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// The full path the sealed bundle is stored at:
/// `<treasury_dir>/hibernate-{agent_id}/state-bundle.json` (agent-scoped).
pub fn bundle_path(treasury_dir: &Path, agent_id: &str) -> PathBuf {
    hibernate_dir(treasury_dir, agent_id).join(BUNDLE_FILE)
}

/// Persist `bundle` to the agent-scoped hibernate path with an atomic, fsynced write
/// (temp file -> fsync -> rename -> dir fsync) at perms `0600`, and return the digest
/// it commits to. The `0600` is load-bearing: `wallet_state.proofs` are BEARER ecash,
/// so the bundle file must not be world-readable.
pub fn persist_bundle(
    treasury_dir: &Path,
    agent_id: &str,
    bundle: &StateBundle,
) -> Result<String, BundleError> {
    let path = bundle_path(treasury_dir, agent_id);
    let bytes = serde_json::to_vec(bundle).map_err(BundleError::Serialize)?;
    write_atomic(&path, &bytes)?;
    Ok(bundle.bundle_digest())
}

/// Read the bundle back from the agent-scoped path and enforce restore-consistency:
/// the loaded bundle's RECOMPUTED digest must equal `expected_digest` (the commitment
/// the caller holds, e.g. from the wake-request), else [`BundleError::DigestMismatch`].
pub fn load_bundle(
    treasury_dir: &Path,
    agent_id: &str,
    expected_digest: &str,
) -> Result<StateBundle, BundleError> {
    let path = bundle_path(treasury_dir, agent_id);
    let bytes = fs::read(&path).map_err(|source| BundleError::Io {
        op: "read",
        path: path.clone(),
        source,
    })?;
    let bundle: StateBundle = serde_json::from_slice(&bytes)
        .map_err(|source| BundleError::Deserialize { path: path.clone(), source })?;
    let actual = bundle.bundle_digest();
    if actual != expected_digest {
        return Err(BundleError::DigestMismatch {
            expected: expected_digest.to_string(),
            actual,
        });
    }
    Ok(bundle)
}

/// Durable atomic write: write `bytes` to a sibling temp file at `0600`, fsync it,
/// atomically rename it into place, then best-effort fsync the directory so the
/// rename survives a crash. The directory fsync is tolerated to fail on platforms
/// where a directory fd cannot be fsynced; the file fsync is mandatory.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), BundleError> {
    let dir = path.parent().ok_or_else(|| BundleError::Io {
        op: "resolve-parent",
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bundle path has no parent directory",
        ),
    })?;
    fs::create_dir_all(dir).map_err(|source| BundleError::Io {
        op: "create-dir",
        path: dir.to_path_buf(),
        source,
    })?;

    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("bundle");
    // pid in the temp name so a concurrent/leftover temp never collides.
    let tmp = dir.join(format!(".{fname}.tmp.{}", std::process::id()));

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp).map_err(|source| BundleError::Io {
            op: "create-temp",
            path: tmp.clone(),
            source,
        })?;
        f.write_all(bytes).map_err(|source| BundleError::Io {
            op: "write-temp",
            path: tmp.clone(),
            source,
        })?;
        f.sync_all().map_err(|source| BundleError::Io {
            op: "fsync-temp",
            path: tmp.clone(),
            source,
        })?;
    }
    fs::rename(&tmp, path).map_err(|source| BundleError::Io {
        op: "rename",
        path: path.to_path_buf(),
        source,
    })?;
    // Best-effort: fsync the directory so the rename is durable across a crash.
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

/// Lossless bridge from the daemon's prost `CheckpointRef` to the bundle's serde-local
/// [`CheckpointPos`] (same `{sha256, len}` shape). Used when assembling the bundle.
impl From<&CheckpointRef> for CheckpointPos {
    fn from(r: &CheckpointRef) -> Self {
        CheckpointPos { sha256: r.sha256.clone(), len: r.len }
    }
}

/// Lossless bridge back to the daemon's `CheckpointRef`. Used on restore (H5) to hand
/// the resumed checkpoint to the checkpoint store.
impl From<&CheckpointPos> for CheckpointRef {
    fn from(p: &CheckpointPos) -> Self {
        CheckpointRef { sha256: p.sha256.clone(), len: p.len }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibernate::{MemoryRef, WalletState};

    fn sample_bundle() -> StateBundle {
        StateBundle {
            memory_ref: MemoryRef { digest: "aa".repeat(32) },
            wallet_state: WalletState { balance_sats: 4_200, proofs: vec![1, 2, 3, 4] },
            checkpoint: CheckpointPos { sha256: "bb".repeat(32), len: 128 },
            resume_seq: 7,
        }
    }

    #[test]
    fn digest_is_deterministic_and_lowercase_hex() {
        let b = sample_bundle();
        let d1 = b.bundle_digest();
        let d2 = b.clone().bundle_digest();
        assert_eq!(d1, d2, "the same bundle must hash identically");
        assert_eq!(d1.len(), 64, "sha256 hex is 64 chars");
        assert!(
            d1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "digest must be lowercase hex, got {d1}"
        );
    }

    #[test]
    fn digest_is_over_canonical_form_not_stored_json() {
        // serialize -> deserialize -> the digest must not move (it is over the
        // canonical encoding, never the JSON bytes).
        let b = sample_bundle();
        let json = serde_json::to_vec(&b).unwrap();
        let back: StateBundle = serde_json::from_slice(&json).unwrap();
        assert_eq!(b, back);
        assert_eq!(b.bundle_digest(), back.bundle_digest());
    }

    #[test]
    fn every_field_is_committed() {
        let base = sample_bundle();
        let d = base.bundle_digest();

        let mut a = base.clone();
        a.memory_ref.digest = "cc".repeat(32);
        assert_ne!(a.bundle_digest(), d, "memory_ref must be committed");

        let mut a = base.clone();
        a.wallet_state.balance_sats += 1;
        assert_ne!(a.bundle_digest(), d, "balance_sats must be committed");

        let mut a = base.clone();
        a.wallet_state.proofs.push(9);
        assert_ne!(a.bundle_digest(), d, "proofs must be committed");

        let mut a = base.clone();
        a.checkpoint.sha256 = "dd".repeat(32);
        assert_ne!(a.bundle_digest(), d, "checkpoint.sha256 must be committed");

        let mut a = base.clone();
        a.checkpoint.len += 1;
        assert_ne!(a.bundle_digest(), d, "checkpoint.len must be committed");

        let mut a = base.clone();
        a.resume_seq += 1;
        assert_ne!(a.bundle_digest(), d, "resume_seq must be committed");
    }

    #[test]
    fn length_prefixing_disambiguates_field_boundaries() {
        // Without length-prefixing, moving a byte across adjacent string fields would
        // collide. With it, the digests differ.
        let mut x = sample_bundle();
        x.memory_ref.digest = "ab".to_string();
        x.checkpoint.sha256 = "c".to_string();
        let mut y = sample_bundle();
        y.memory_ref.digest = "a".to_string();
        y.checkpoint.sha256 = "bc".to_string();
        assert_ne!(x.bundle_digest(), y.bundle_digest());
    }

    #[test]
    fn persist_then_load_roundtrips_and_matches_digest() {
        let dir = tempdir();
        let b = sample_bundle();
        let digest = persist_bundle(&dir, "agent-0", &b).unwrap();
        assert_eq!(digest, b.bundle_digest());
        // it landed under the agent-scoped hibernate dir
        assert!(bundle_path(&dir, "agent-0").starts_with(dir.join("hibernate-agent-0")));
        let loaded = load_bundle(&dir, "agent-0", &digest).unwrap();
        assert_eq!(loaded, b, "read-back must equal what was persisted");
        cleanup(&dir);
    }

    #[test]
    fn tampered_bundle_fails_the_digest_check() {
        let dir = tempdir();
        let b = sample_bundle();
        let committed = persist_bundle(&dir, "agent-0", &b).unwrap();

        // Corrupt the stored bundle on disk (a different resume_seq).
        let mut tampered = b.clone();
        tampered.resume_seq = 999;
        let path = bundle_path(&dir, "agent-0");
        std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();

        // Loading with the ORIGINAL committed digest must be refused.
        match load_bundle(&dir, "agent-0", &committed) {
            Err(BundleError::DigestMismatch { expected, actual }) => {
                assert_eq!(expected, committed);
                assert_eq!(actual, tampered.bundle_digest());
                assert_ne!(expected, actual);
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_bundle_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        let b = sample_bundle();
        persist_bundle(&dir, "agent-0", &b).unwrap();
        let mode = std::fs::metadata(bundle_path(&dir, "agent-0"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "bundle holds bearer ecash; must be 0600, got {mode:o}");
        cleanup(&dir);
    }

    #[test]
    fn checkpoint_pos_bridges_checkpoint_ref_losslessly() {
        let pos = CheckpointPos { sha256: "ab12".to_string(), len: 4_096 };
        let r: CheckpointRef = (&pos).into();
        assert_eq!(r.sha256, pos.sha256);
        assert_eq!(r.len, pos.len);
        let back: CheckpointPos = (&r).into();
        assert_eq!(back, pos, "CheckpointPos -> CheckpointRef -> CheckpointPos must round-trip");
    }

    // Hand-rolled temp dir (no dev-dep), matching checkpoint.rs / nerve.rs.
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir()
            .join(format!("kirby-hibernate-bundle-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }
}
