//! Per-agent FROST identity (S3a graft).
//!
//! This is the FROST-side mirror of [`crate::nerve::NodeIdentity`]: where
//! `NodeIdentity` is a single secp256k1/BIP340 keypair (one node, one private
//! key), a `FrostIdentity` is the PUBLIC face of a FROST 2-of-3 threshold group
//! -- the group taproot output key Q and the `npub` that Q encodes. No single
//! holder owns the whole key (that is the point of FROST custody); the identity
//! here is derived from the group's [`PublicKeyPackage`] only, so this type holds
//! NO secret material.
//!
//! It loads the group `PublicKeyPackage` from a keystore file (JSON, hex-encoded
//! ZF serialization) and derives Q via [`kirby_custody::group_xonly_q`] -- the
//! SAME BIP-341 key-path tweak (merkle_root = None) the custody crate's taproot
//! address and coordinator use, so Q here is byte-identical to the key the
//! aggregate FROST signature verifies under.
//!
//! S3a SCOPE -- THIS CHANGES NO SIGNING PATH. `FrostIdentity` is a new, derive-only
//! type. It does not replace `NodeIdentity`, it is not wired into the
//! `rail::NostrActuator` or the `nerve` presence/lifecycle publishers, and nothing
//! here signs or co-signs. It is the foundation for a later per-agent FROST live
//! signer (fleet-tenant-only). The existing single-key path (`kirby run` /
//! `kirby agent` without a fleet) never constructs a `FrostIdentity` and is
//! byte-for-byte unchanged.
//!
//! Idempotency invariant (G-FROST-IDENTITY-STABLE): like
//! `NodeIdentity::load_or_create`, loading the same keystore file always yields the
//! same Q and the same npub. The keystore is the stable per-agent FROST identity
//! across restarts.

use std::path::{Path, PathBuf};

use anyhow::Context;
use bitcoin::secp256k1::XOnlyPublicKey;
use frost_secp256k1_tr::keys::PublicKeyPackage;
use kirby_custody::cosign_net::npub_encode;
use kirby_custody::group_xonly_q;
use serde::{Deserialize, Serialize};

/// On-disk form of the FROST identity keystore: the group `PublicKeyPackage` only
/// (the PUBLIC verifying material -- NO secret shares). Hex of the ZF
/// `PublicKeyPackage::serialize()`, the same encoding `kirby_custody::persist`
/// uses for the pubkeys half of a keyset. Secret shares live elsewhere (the
/// custody keyset, written 0600); this public file is safe to read for identity.
#[derive(Serialize, Deserialize)]
struct PersistedFrostPubkeys {
    /// Hex of `PublicKeyPackage::serialize()`.
    pubkeys: String,
}

/// The PUBLIC identity of a per-agent FROST 2-of-3 group: the taproot output key Q
/// (x-only) and the npub it encodes. Holds no secret material -- derived purely
/// from the group `PublicKeyPackage`. Cloneable; cheap to copy (Q is 32 bytes).
#[derive(Clone)]
pub struct FrostIdentity {
    /// The group's public key package (the FROST verifying material).
    pubkeys: PublicKeyPackage,
    /// The derived taproot output key Q as 32 x-only bytes (cached so npub/q_xonly
    /// are infallible accessors after load).
    q_bytes: [u8; 32],
    /// The keystore file this identity was loaded from.
    keystore_path: PathBuf,
}

impl FrostIdentity {
    /// Load a per-agent FROST identity from a keystore file at `keystore_path`.
    ///
    /// The file is JSON holding the hex of the group `PublicKeyPackage` (see
    /// [`save_pubkeys`]). The taproot key Q is derived once via
    /// [`kirby_custody::group_xonly_q`] (BIP-341, merkle_root = None) and cached.
    ///
    /// Idempotent (G-FROST-IDENTITY-STABLE): loading the same file always yields
    /// the same Q and npub. Unlike `NodeIdentity::load_or_create`, this does NOT
    /// generate-on-absence: a FROST group cannot be created by one node out of thin
    /// air (it needs a 2-of-3 dealer/DKG ceremony). Provisioning the keystore is
    /// the custody crate's job; this loads an already-provisioned group identity.
    pub fn load(keystore_path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(keystore_path).with_context(|| {
            format!("read FROST identity keystore {}", keystore_path.display())
        })?;
        let persisted: PersistedFrostPubkeys = serde_json::from_slice(&bytes)
            .with_context(|| {
                format!("parse FROST identity keystore {}", keystore_path.display())
            })?;
        let pubkeys_bytes = hex::decode(&persisted.pubkeys)
            .context("hex-decode the FROST PublicKeyPackage")?;
        let pubkeys = PublicKeyPackage::deserialize(&pubkeys_bytes)
            .map_err(|e| anyhow::anyhow!("deserialize FROST PublicKeyPackage: {e}"))?;
        let q_bytes = group_xonly_q(&pubkeys)
            .map_err(|e| anyhow::anyhow!("derive FROST group taproot key Q: {e}"))?;
        tracing::info!(
            npub = %npub_encode(&q_bytes).unwrap_or_default(),
            path = %keystore_path.display(),
            "loaded per-agent FROST identity (derive-only, no signing)"
        );
        Ok(FrostIdentity {
            pubkeys,
            q_bytes,
            keystore_path: keystore_path.to_path_buf(),
        })
    }

    /// Construct directly from an in-memory group `PublicKeyPackage` (e.g. right
    /// after a dealer/DKG ceremony), tagging it with the keystore path it will be
    /// persisted at. Derives and caches Q. Useful for the provisioning path and
    /// for tests; `load` is the steady-state restart path.
    pub fn from_pubkeys(
        pubkeys: PublicKeyPackage,
        keystore_path: &Path,
    ) -> anyhow::Result<Self> {
        let q_bytes = group_xonly_q(&pubkeys)
            .map_err(|e| anyhow::anyhow!("derive FROST group taproot key Q: {e}"))?;
        Ok(FrostIdentity {
            pubkeys,
            q_bytes,
            keystore_path: keystore_path.to_path_buf(),
        })
    }

    /// The group's taproot output key Q as an x-only BIP-340 public key. This is the
    /// verifying key the aggregate FROST signature checks under and the key the npub
    /// encodes.
    pub fn q_xonly(&self) -> XOnlyPublicKey {
        // q_bytes came straight out of group_xonly_q (a valid x-only serialization
        // of a TweakedPublicKey), so this never fails; expressed as an expect so the
        // accessor stays infallible at the call site, matching NodeIdentity's npub().
        XOnlyPublicKey::from_slice(&self.q_bytes)
            .expect("group_xonly_q always yields a valid 32-byte x-only key")
    }

    /// The group's taproot key Q as raw 32 x-only bytes (the value `group_xonly_q`
    /// returns and the npub encodes). Avoids reconstructing the `XOnlyPublicKey`
    /// when bytes are all the caller needs.
    pub fn q_bytes(&self) -> [u8; 32] {
        self.q_bytes
    }

    /// This identity's npub (NIP-19 bech32 of Q), the stable per-agent FROST
    /// identity. Derived via `kirby_custody::cosign_net::npub_encode`.
    pub fn npub(&self) -> String {
        npub_encode(&self.q_bytes).unwrap_or_default()
    }

    /// The group public key package this identity wraps (the FROST verifying
    /// material). Borrowed; a later live-signer chunk uses it to verify aggregate
    /// signatures.
    pub fn pubkeys(&self) -> &PublicKeyPackage {
        &self.pubkeys
    }

    /// The keystore file path this identity was loaded from (or is to be persisted
    /// at).
    pub fn keystore_path(&self) -> &Path {
        &self.keystore_path
    }
}

/// Persist the PUBLIC half of a FROST group identity (the `PublicKeyPackage`) to
/// `keystore_path` as JSON, so a `FrostIdentity` reloads to the same Q/npub on
/// restart. This writes NO secret material (the secret shares are held by the
/// custody keyset, written 0600 separately); the public keypackage is the identity
/// face only. Parent directories are created as needed.
pub fn save_pubkeys(
    pubkeys: &PublicKeyPackage,
    keystore_path: &Path,
) -> anyhow::Result<()> {
    if let Some(parent) = keystore_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("create FROST keystore dir {}", parent.display())
            })?;
        }
    }
    let pubkeys_hex = hex::encode(
        pubkeys
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize FROST PublicKeyPackage: {e}"))?,
    );
    let data = serde_json::to_vec_pretty(&PersistedFrostPubkeys { pubkeys: pubkeys_hex })
        .context("serialize FROST keystore JSON")?;
    std::fs::write(keystore_path, &data).with_context(|| {
        format!("write FROST identity keystore {}", keystore_path.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kirby_custody::generate_dealer_keyset;

    /// G-FROST-IDENTITY-STABLE: a per-agent FROST identity is idempotent across
    /// reloads. Generate a 2-of-3 dealer keyset, persist its PublicKeyPackage,
    /// load a FrostIdentity from it twice, and assert the npub AND Q are byte-stable
    /// across both loads (the same invariant NodeIdentity::load_or_create holds for
    /// the single-key path). This is fast and UNGATED -- no microVM, no relay, no
    /// hardware.
    #[test]
    fn frost_identity_npub_and_q_are_stable_across_reloads() {
        // A real 2-of-3 trusted-dealer keyset (OsRng; the public keypackage is what
        // we persist, never the secret shares).
        let keyset = generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");

        let dir = std::env::temp_dir().join(format!(
            "kirby-frost-identity-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mk test dir");
        let keystore = dir.join("frost-identity.json");
        let _ = std::fs::remove_file(&keystore);

        save_pubkeys(&keyset.pubkeys, &keystore).expect("persist FROST pubkeys");

        // Two independent loads of the SAME keystore file.
        let id_a = FrostIdentity::load(&keystore).expect("load #1");
        let id_b = FrostIdentity::load(&keystore).expect("load #2");

        // npub is stable across reloads.
        let npub_a = id_a.npub();
        let npub_b = id_b.npub();
        assert!(!npub_a.is_empty(), "npub must be non-empty");
        assert!(npub_a.starts_with("npub1"), "got {npub_a}");
        assert_eq!(npub_a, npub_b, "npub must be identical across reloads");

        // Q (x-only bytes AND the parsed XOnlyPublicKey) is stable across reloads.
        assert_eq!(
            id_a.q_bytes(),
            id_b.q_bytes(),
            "Q (x-only bytes) must be identical across reloads"
        );
        assert_eq!(
            id_a.q_xonly(),
            id_b.q_xonly(),
            "Q (XOnlyPublicKey) must be identical across reloads"
        );

        // And Q is exactly what the custody crate derives directly from the same
        // pubkeys (no drift between the identity helper and the custody source).
        let q_direct = group_xonly_q(&keyset.pubkeys).expect("direct Q");
        assert_eq!(
            id_a.q_bytes(),
            q_direct,
            "FrostIdentity Q must match kirby_custody::group_xonly_q exactly"
        );

        let _ = std::fs::remove_file(&keystore);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
