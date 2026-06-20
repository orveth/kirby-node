//! App-level checkpoint primitives for portable resume.
//!
//! VM snapshots are backend/architecture-specific, so Linux/Firecracker cannot
//! hand a mem+vmstate snapshot to macOS/VZ. The app-checkpoint path carries only
//! the genome's logical state: an opaque payload, content-addressed by SHA-256.
//! The daemon stores and routes the blob but does not inspect it. Ephemeral
//! secrets are excluded by the genome schema and re-derived through
//! `GetEntropyNonce` after a fresh boot.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kirby_proto::{CheckpointBlob, CheckpointRef};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint store lock poisoned")]
    LockPoisoned,
    #[error("invalid checkpoint reference sha256={sha256:?} len={len}")]
    InvalidReference { sha256: String, len: u64 },
    #[error(
        "checkpoint reference mismatch: expected sha256={expected_sha256} len={expected_len}, got sha256={actual_sha256} len={actual_len}"
    )]
    ReferenceMismatch {
        expected_sha256: String,
        expected_len: u64,
        actual_sha256: String,
        actual_len: u64,
    },
    #[error("{op} checkpoint path {path:?}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// One content-addressed logical checkpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckpointArtifact {
    pub reference: CheckpointRef,
    pub payload: Vec<u8>,
}

impl CheckpointArtifact {
    pub fn new(payload: Vec<u8>) -> Self {
        CheckpointArtifact {
            reference: checkpoint_ref(&payload),
            payload,
        }
    }

    pub fn from_blob(blob: CheckpointBlob) -> Self {
        Self::new(blob.payload)
    }

    pub fn blob(&self) -> CheckpointBlob {
        CheckpointBlob {
            schema_version: kirby_proto::SCHEMA_VERSION,
            payload: self.payload.clone(),
        }
    }
}

/// Shared latest-checkpoint handle for one gateway/session.
#[derive(Debug, Clone, Default)]
pub struct LatestCheckpoint {
    inner: Arc<Mutex<Option<CheckpointArtifact>>>,
}

impl LatestCheckpoint {
    pub fn submit(&self, blob: CheckpointBlob) -> Result<CheckpointArtifact, CheckpointError> {
        let artifact = CheckpointArtifact::from_blob(blob);
        let mut latest = self
            .inner
            .lock()
            .map_err(|_| CheckpointError::LockPoisoned)?;
        *latest = Some(artifact.clone());
        Ok(artifact)
    }

    pub fn latest(&self) -> Result<Option<CheckpointArtifact>, CheckpointError> {
        let latest = self
            .inner
            .lock()
            .map_err(|_| CheckpointError::LockPoisoned)?;
        Ok(latest.clone())
    }
}

/// Durable checkpoint handoff seam. The local implementation stores by content
/// hash; a network/blob implementation can replace it without changing the
/// gateway or backend orchestration.
pub trait CheckpointStore: Send + Sync {
    fn put(&self, artifact: &CheckpointArtifact) -> Result<CheckpointRef, CheckpointError>;
    fn get(&self, reference: &CheckpointRef) -> Result<CheckpointArtifact, CheckpointError>;
}

/// Same-host default store: one file per checkpoint payload named by SHA-256.
#[derive(Debug, Clone)]
pub struct LocalDirCheckpointStore {
    root: PathBuf,
}

impl LocalDirCheckpointStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        LocalDirCheckpointStore { root: root.into() }
    }

    pub fn path_for_ref(&self, reference: &CheckpointRef) -> Result<PathBuf, CheckpointError> {
        validate_ref(reference)?;
        Ok(self.root.join(&reference.sha256))
    }
}

impl CheckpointStore for LocalDirCheckpointStore {
    fn put(&self, artifact: &CheckpointArtifact) -> Result<CheckpointRef, CheckpointError> {
        let reference = checkpoint_ref(&artifact.payload);
        if reference != artifact.reference {
            return Err(ref_mismatch(&artifact.reference, &reference));
        }
        validate_ref(&reference)?;
        std::fs::create_dir_all(&self.root).map_err(|source| CheckpointError::Io {
            op: "create",
            path: self.root.clone(),
            source,
        })?;
        let path = self.path_for_ref(&reference)?;
        std::fs::write(&path, &artifact.payload).map_err(|source| CheckpointError::Io {
            op: "write",
            path: path.clone(),
            source,
        })?;
        Ok(reference)
    }

    fn get(&self, reference: &CheckpointRef) -> Result<CheckpointArtifact, CheckpointError> {
        let path = self.path_for_ref(reference)?;
        let payload = std::fs::read(&path).map_err(|source| CheckpointError::Io {
            op: "read",
            path: path.clone(),
            source,
        })?;
        let artifact = CheckpointArtifact::new(payload);
        if artifact.reference != *reference {
            return Err(ref_mismatch(reference, &artifact.reference));
        }
        Ok(artifact)
    }
}

pub fn checkpoint_ref(payload: &[u8]) -> CheckpointRef {
    let digest = Sha256::digest(payload);
    CheckpointRef {
        sha256: to_hex(&digest),
        len: payload.len() as u64,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn validate_ref(reference: &CheckpointRef) -> Result<(), CheckpointError> {
    let valid_sha = reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if valid_sha {
        Ok(())
    } else {
        Err(CheckpointError::InvalidReference {
            sha256: reference.sha256.clone(),
            len: reference.len,
        })
    }
}

fn ref_mismatch(expected: &CheckpointRef, actual: &CheckpointRef) -> CheckpointError {
    CheckpointError::ReferenceMismatch {
        expected_sha256: expected.sha256.clone(),
        expected_len: expected.len,
        actual_sha256: actual.sha256.clone(),
        actual_len: actual.len,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kirby_proto::CheckpointRef;

    use super::{
        checkpoint_ref, CheckpointArtifact, CheckpointError, CheckpointStore,
        LocalDirCheckpointStore,
    };

    #[test]
    fn checkpoint_ref_uses_sha256_and_length() {
        let reference = checkpoint_ref(b"abc");
        assert_eq!(
            reference.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(reference.len, 3);
    }

    #[test]
    fn local_dir_checkpoint_store_round_trips_by_ref() {
        let dir = tempdir();
        let store = LocalDirCheckpointStore::new(dir.path.clone());
        let artifact = CheckpointArtifact::new(b"portable-state".to_vec());

        let reference = store.put(&artifact).unwrap();
        assert_eq!(reference, artifact.reference);
        assert_eq!(
            std::fs::read(store.path_for_ref(&reference).unwrap()).unwrap(),
            artifact.payload
        );

        let loaded = store.get(&reference).unwrap();
        assert_eq!(loaded, artifact);
        assert_eq!(loaded.blob().payload, b"portable-state");
    }

    #[test]
    fn local_dir_checkpoint_store_rejects_invalid_reference() {
        let dir = tempdir();
        let store = LocalDirCheckpointStore::new(dir.path.clone());
        let err = store
            .get(&CheckpointRef {
                sha256: "../not-a-hash".into(),
                len: 7,
            })
            .unwrap_err();

        assert!(matches!(err, CheckpointError::InvalidReference { .. }));
    }

    #[test]
    fn local_dir_checkpoint_store_detects_corrupt_payload() {
        let dir = tempdir();
        let store = LocalDirCheckpointStore::new(dir.path.clone());
        let artifact = CheckpointArtifact::new(b"good-state".to_vec());
        let reference = store.put(&artifact).unwrap();
        let path = store.path_for_ref(&reference).unwrap();

        std::fs::write(&path, b"bad-state").unwrap();
        let err = store.get(&reference).unwrap_err();

        assert!(matches!(
            err,
            CheckpointError::ReferenceMismatch {
                expected_sha256,
                expected_len: 10,
                actual_sha256: _,
                actual_len: 9
            } if expected_sha256 == reference.sha256
        ));
    }

    struct TempDir {
        path: PathBuf,
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};

        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "kirby-checkpoint-test-{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
}
