//! App-level checkpoint primitives for portable resume.
//!
//! VM snapshots are backend/architecture-specific, so Linux/Firecracker cannot
//! hand a mem+vmstate snapshot to macOS/VZ. The app-checkpoint path carries only
//! the genome's logical state: an opaque payload, content-addressed by SHA-256.
//! The daemon stores and routes the blob but does not inspect it. Ephemeral
//! secrets are excluded by the genome schema and re-derived through
//! `GetEntropyNonce` after a fresh boot.

use std::sync::{Arc, Mutex};

use kirby_proto::{CheckpointBlob, CheckpointRef};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint store lock poisoned")]
    LockPoisoned,
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

#[cfg(test)]
mod tests {
    use super::checkpoint_ref;

    #[test]
    fn checkpoint_ref_uses_sha256_and_length() {
        let reference = checkpoint_ref(b"abc");
        assert_eq!(
            reference.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(reference.len, 3);
    }
}
