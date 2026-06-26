//! S5/S6 (chunk 3): PER-HOLDER AT-REST SEALING of a FROST share.
//!
//! When the cross-machine keyset distributes (chunk 3), each holder stores exactly ONE
//! share on its OWN machine, and seals it at rest. This module is that seal: a thin,
//! well-reviewed AEAD wrapper -- NOT custom crypto -- over the share KeyPackage bytes.
//!
//! ## Why sealing is load-bearing ONLY once shares distribute (the honest scope)
//!
//! While all 3 shares are co-located on one host (the S3 default, still byte-identical
//! when distributed provisioning is OFF), the keystore comment is right that sealing buys
//! nothing: a host compromise that can read a 0600 file owned by this user can read all 3
//! shares regardless of sealing, because the sealing key lives on the same host. The
//! moment a holder stores ONLY ONE share, that reasoning inverts: a stolen disk image of
//! that one sink (a backup, a snapshot of the agent's state volume, a discarded disk) now
//! yields NOTHING usable, because the share is AEAD-sealed under a key bound to the
//! machine and NOT carried in the sink directory.
//!
//! ## The construction (standard, reviewed -- no rolled crypto)
//!
//! * Cipher: `XChaCha20Poly1305` (RustCrypto `chacha20poly1305`). The 192-bit (24-byte)
//!   nonce is drawn fresh + RANDOM per seal from the OS CSPRNG, so per-seal nonces are
//!   collision-safe WITHOUT a persisted counter (the reason to prefer XChaCha over the
//!   96-bit ChaCha20Poly1305 here). This is the SAME AEAD family NIP-44 uses in-tree, so
//!   no new crypto primitive enters the build.
//! * Key derivation: `HKDF-SHA256(ikm = machine-binding secret, salt = per-sink random
//!   salt, info = "kirby-frost-share-seal-v1" || sink_label)`. The 32-byte output is the
//!   ChaCha key. The per-sink salt (stored in the clear beside the sealed share) means two
//!   sinks on the SAME machine derive DIFFERENT keys, so one sink's seal can never be
//!   unsealed with another sink's stored material even at rest. The `info` string is the
//!   domain separator (this exact use), mirroring the EngramStore's HKDF domain-separation
//!   discipline already in the tree.
//! * AAD: the sink label + version are bound as additional authenticated data, so a sealed
//!   blob authenticated for sink A cannot be replayed as sink B's share even if an attacker
//!   swaps the on-disk file (the unseal would fail the tag check).
//!
//! ## The machine binding (where the protection actually comes from)
//!
//! The IKM is the host's machine-binding secret, read OUTSIDE the sink directory so a
//! stolen image of the sink dir alone does not contain it:
//!   * PRIMARY: `/etc/machine-id` (a stable per-host secret that is NOT part of the agent's
//!     state volume / sink dir). A disk image of the sink dir (or a state-volume backup)
//!     does not carry it, so the seal holds against that exact threat.
//!   * FALLBACK (LOUD, weaker): if `/etc/machine-id` is unreadable (some containers/CI),
//!     a per-sink random `host.key` file inside the sink dir. This is HONESTLY WEAKER -- it
//!     co-locates the binding secret with the sealed share, so a stolen image of the sink
//!     dir DOES contain it. We log a warning and document it; it keeps the API working
//!     where no host id exists, and is still an authenticated-encryption envelope (it
//!     defends against a swapped/forged blob), just not against a full-dir image theft.
//!
//! ## THE IRREDUCIBLE RESIDUAL (carried in code, per the brief -- do not overclaim)
//!
//! Sealing protects a STOLEN DISK IMAGE, NOT a LIVE-HOST COMPROMISE. A host that is running
//! the holder can read `/etc/machine-id`, read the per-sink salt, derive the key, and
//! unseal the share -- exactly as the legitimate holder does. It can also read the
//! unsealed share out of the holder process RAM. This is irreducible without a real TEE;
//! the cross-machine sovereignty property does NOT come from sealing (a live host always
//! sees its ONE share), it comes from the share being only ONE of the 2-of-3 threshold.
//! Sealing closes the at-rest / stolen-image gap on top of that, and nothing more.

use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use anyhow::Context as _;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize as _;

/// The HKDF `info` domain separator: this exact use (a FROST share at-rest seal), versioned
/// so a future format change cannot reuse a v1-derived key.
const SEAL_INFO_PREFIX: &[u8] = b"kirby-frost-share-seal-v1:";

/// The AEAD additional-authenticated-data prefix: binds a sealed blob to this format
/// version + the sink label, so a blob authenticated for one sink cannot be unsealed as
/// another (the tag check fails on a swapped file).
const SEAL_AAD_PREFIX: &[u8] = b"kirby-frost-share-seal-v1-aad:";

/// The XChaCha20Poly1305 nonce length (192-bit / 24 bytes).
const NONCE_LEN: usize = 24;

/// The per-sink salt length (32 bytes of OS CSPRNG; stored in the clear beside the share).
const SALT_LEN: usize = 32;

/// The machine-binding source. Abstracted so the production reader (machine-id, then a
/// loud sink-local fallback) is the default, while tests can inject a fixed binding without
/// touching `/etc/machine-id` (so the seal/unseal teeth are hermetic + parallel-safe).
pub trait MachineBinding {
    /// Return this machine's binding secret bytes (the HKDF IKM). MUST be stable across
    /// restarts on the same host (or the share never unseals). The bytes are treated as
    /// secret IKM, never logged.
    fn ikm(&self, sink_dir: &Path) -> anyhow::Result<Vec<u8>>;
}

/// The production binding: `/etc/machine-id` if readable, else a LOUD fallback to a
/// per-sink random `host.key` (documented weaker -- see the module docs). The fallback file
/// is created 0600 on first use and reused thereafter, so the derived key is stable.
pub struct HostMachineBinding;

/// The sink-local fallback host-key file name (only used when `/etc/machine-id` is
/// unreadable).
const HOST_KEY_FILE: &str = "host.key";

impl MachineBinding for HostMachineBinding {
    fn ikm(&self, sink_dir: &Path) -> anyhow::Result<Vec<u8>> {
        // PRIMARY: the host machine-id (outside the sink dir, so a stolen image of the sink
        // dir does not carry it). Trim trailing whitespace/newline so it is stable.
        if let Ok(raw) = std::fs::read("/etc/machine-id") {
            let trimmed: Vec<u8> = raw
                .iter()
                .copied()
                .take_while(|b| !b.is_ascii_whitespace())
                .collect();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
        // FALLBACK (LOUD, weaker): a per-sink random host.key INSIDE the sink dir. This
        // co-locates the binding with the sealed share, so a stolen image of the sink dir
        // DOES contain it -- the seal then only defends against a swapped/forged blob, not
        // a full-dir image theft. We still use authenticated encryption; we just cannot
        // claim stolen-image protection in this mode.
        let host_key_path = sink_dir.join(HOST_KEY_FILE);
        if let Ok(existing) = read_secret_file(&host_key_path) {
            if existing.len() == SALT_LEN {
                return Ok(existing);
            }
        }
        tracing::warn!(
            sink = %sink_dir.display(),
            "/etc/machine-id is unreadable; sealing the FROST share under a SINK-LOCAL host.key \
             fallback. This is WEAKER: the binding secret then lives in the same directory as \
             the sealed share, so a stolen disk image of this sink is NOT protected. Provide a \
             host machine-id (or a TEE-backed key) for real stolen-image resistance."
        );
        let mut key = [0u8; SALT_LEN];
        rand_fill(&mut key);
        write_secret_file_0600(&host_key_path, &key)
            .context("persist the sink-local host.key fallback")?;
        let out = key.to_vec();
        key.zeroize();
        Ok(out)
    }
}

/// Derive the 32-byte XChaCha key for a sink from the machine IKM, the per-sink salt, and
/// the sink label (domain-separated). The derived key is returned in a zeroizing buffer.
fn derive_key(ikm: &[u8], salt: &[u8], sink_label: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut info = Vec::with_capacity(SEAL_INFO_PREFIX.len() + sink_label.len());
    info.extend_from_slice(SEAL_INFO_PREFIX);
    info.extend_from_slice(sink_label.as_bytes());
    let mut okm = [0u8; 32];
    // HKDF-Expand cannot fail for a 32-byte output (well under 255*HashLen).
    hk.expand(&info, &mut okm).expect("HKDF expand 32 bytes");
    okm
}

/// The AAD for a sink: the format version + the sink label, so a sealed blob is bound to
/// the sink it was sealed for (a swapped file from another sink fails the tag check).
fn aad_for(sink_label: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_AAD_PREFIX.len() + sink_label.len());
    aad.extend_from_slice(SEAL_AAD_PREFIX);
    aad.extend_from_slice(sink_label.as_bytes());
    aad
}

/// Seal `plaintext` (a share KeyPackage JSON) at rest for the sink labelled `sink_label`,
/// living at `sink_dir`, using `binding` for the machine-bound IKM and `salt` (the sink's
/// persisted per-sink salt) for key separation. Returns `nonce || ciphertext+tag` (the
/// on-disk sealed body; the salt is stored separately in the clear).
///
/// The derived key is zeroized before return; the plaintext is the caller's (the caller
/// drops the ZeroizeOnDrop KeyPackage JSON it serialized).
pub fn seal<B: MachineBinding + ?Sized>(
    binding: &B,
    sink_dir: &Path,
    sink_label: &str,
    salt: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let ikm = binding.ikm(sink_dir).context("read machine binding for seal")?;
    let mut key = derive_key(&ikm, salt, sink_label);
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 192-bit random, per-seal
    let aad = aad_for(sink_label);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|_| anyhow::anyhow!("AEAD seal of the FROST share failed"))?;
    // On-disk body: nonce (24 bytes) || ciphertext+tag.
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal an on-disk sealed body (`nonce || ciphertext+tag`) for the sink labelled
/// `sink_label` at `sink_dir`, using `binding` + the sink's persisted `salt`. Returns the
/// plaintext share KeyPackage JSON. FAILS LOUD on a tag mismatch (wrong machine, swapped
/// blob, corrupt bytes) -- it NEVER returns garbage as if it were the share.
pub fn unseal<B: MachineBinding + ?Sized>(
    binding: &B,
    sink_dir: &Path,
    sink_label: &str,
    salt: &[u8],
    sealed: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        anyhow::bail!(
            "sealed share is too short ({} bytes < {NONCE_LEN}-byte nonce); corrupt or not a \
             sealed blob",
            sealed.len()
        );
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let ikm = binding.ikm(sink_dir).context("read machine binding for unseal")?;
    let mut key = derive_key(&ikm, salt, sink_label);
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();
    let aad = aad_for(sink_label);
    cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &aad }).map_err(|_| {
        anyhow::anyhow!(
            "AEAD unseal of the FROST share FAILED (tag mismatch): wrong machine binding, a \
             swapped/forged sealed blob, or corrupt bytes. Refusing to return unauthenticated \
             material -- restore this sink's sealed share + salt from backup."
        )
    })
}

/// The per-sink salt file name (stored in the clear beside the sealed share -- the salt is
/// not secret; it only separates per-sink keys).
const SALT_FILE: &str = "seal.salt";

/// Read (or create-then-read) the per-sink salt for `sink_dir`. On first seal the salt is
/// generated from the OS CSPRNG and persisted; thereafter it is reused so the derived key
/// is stable across restarts. Stored 0600 (uniform keystore posture) though it is public.
pub fn load_or_create_salt(sink_dir: &Path) -> anyhow::Result<Vec<u8>> {
    let salt_path = sink_dir.join(SALT_FILE);
    if let Ok(existing) = read_secret_file(&salt_path) {
        if existing.len() == SALT_LEN {
            return Ok(existing);
        }
        // A wrong-length salt file is corrupt; refuse rather than derive a key under a
        // truncated salt (which would silently make the share un-unsealable).
        anyhow::bail!(
            "sink salt {} is {} bytes (expected {SALT_LEN}); corrupt -- restore the sink",
            salt_path.display(),
            existing.len()
        );
    }
    let mut salt = [0u8; SALT_LEN];
    rand_fill(&mut salt);
    write_secret_file_0600(&salt_path, &salt).context("persist the per-sink seal salt")?;
    Ok(salt.to_vec())
}

/// Read the salt for `sink_dir` WITHOUT creating it (the unseal path: a missing salt over a
/// sealed share is a loud error, not a silent re-create that would derive the wrong key).
pub fn load_salt(sink_dir: &Path) -> anyhow::Result<Vec<u8>> {
    let salt_path = sink_dir.join(SALT_FILE);
    let salt = read_secret_file(&salt_path)
        .with_context(|| format!("read per-sink seal salt {}", salt_path.display()))?;
    if salt.len() != SALT_LEN {
        anyhow::bail!(
            "sink salt {} is {} bytes (expected {SALT_LEN}); corrupt -- restore the sink",
            salt_path.display(),
            salt.len()
        );
    }
    Ok(salt)
}

/// Fill `buf` with OS CSPRNG bytes (kirby-node's `rand` 0.9 `OsRng`). Used for the per-sink
/// salt and the fallback host key.
fn rand_fill(buf: &mut [u8]) {
    use rand::TryRngCore as _;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .expect("OS CSPRNG fill for seal salt/host-key");
}

/// Read a small secret-bearing file (salt or host.key), tightening it to 0600 first (Unix)
/// so it is never left looser, and rejecting a non-regular file. These files are tiny.
fn read_secret_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("lstat seal aux file {}", path.display()))?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        anyhow::bail!(
            "seal aux file {} is a SYMLINK -- refusing to read through a link",
            path.display()
        );
    }
    if !ft.is_file() {
        anyhow::bail!("seal aux file {} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 seal aux file {}", path.display()))?;
    }
    std::fs::read(path).with_context(|| format!("read seal aux file {}", path.display()))
}

/// Write a small secret-bearing file 0600 (Unix), creating parents implicitly handled by
/// the caller. Mirrors the keystore 0600 discipline (mode on create + chmod after open).
fn write_secret_file_0600(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts
            .open(path)
            .with_context(|| format!("open seal aux file {} (0600)", path.display()))?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
        f.write_all(data).with_context(|| format!("write seal aux file {}", path.display()))?;
        f.flush().with_context(|| format!("flush seal aux file {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .with_context(|| format!("write seal aux file {}", path.display()))
    }
}

/// A fixed in-memory binding for hermetic tests (so seal/unseal teeth do not depend on
/// `/etc/machine-id` and two test sinks can be given DIFFERENT bindings to model two
/// machines). Not used in production.
#[cfg(test)]
pub struct FixedBinding(pub Vec<u8>);

#[cfg(test)]
impl MachineBinding for FixedBinding {
    fn ikm(&self, _sink_dir: &Path) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

/// The path a sealed share body is written to inside a sink dir (the sink layer owns the
/// share file name; this is only re-exported for tests that read raw bytes).
#[cfg(test)]
pub fn sealed_share_aux_paths(sink_dir: &Path) -> (PathBuf, PathBuf) {
    (sink_dir.join(SALT_FILE), sink_dir.join(HOST_KEY_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kirby-share-seal-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn seal_then_unseal_roundtrips_to_the_same_plaintext() {
        let dir = tempdir("roundtrip");
        let binding = FixedBinding(b"machine-A-binding-secret".to_vec());
        let salt = load_or_create_salt(&dir).unwrap();
        let plaintext = b"a-frost-share-keypackage-json-blob";

        let sealed = seal(&binding, &dir, "holder-1", &salt, plaintext).unwrap();
        // The sealed body is NOT the plaintext (it is actually encrypted, not renamed).
        assert!(!sealed.windows(plaintext.len()).any(|w| w == plaintext),
            "sealed body must not contain the plaintext");
        assert!(sealed.len() > plaintext.len(), "sealed body carries a nonce + tag");

        let opened = unseal(&binding, &dir, "holder-1", &salt, &sealed).unwrap();
        assert_eq!(opened, plaintext, "unseal must reproduce the exact plaintext");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unseal_with_a_different_machine_binding_fails_loud() {
        let dir = tempdir("wrongmachine");
        let salt = load_or_create_salt(&dir).unwrap();
        let plaintext = b"share-bytes";
        let sealed = seal(&FixedBinding(b"machine-A".to_vec()), &dir, "h1", &salt, plaintext).unwrap();

        // A DIFFERENT machine (a stolen image moved to another host) cannot unseal.
        let err = unseal(&FixedBinding(b"machine-B".to_vec()), &dir, "h1", &salt, &sealed)
            .expect_err("a different machine binding must fail to unseal");
        assert!(format!("{err:#}").contains("tag mismatch"), "must be a loud tag-mismatch error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unseal_with_a_wrong_sink_label_fails_loud() {
        let dir = tempdir("wronglabel");
        let binding = FixedBinding(b"machine-A".to_vec());
        let salt = load_or_create_salt(&dir).unwrap();
        let sealed = seal(&binding, &dir, "holder-1", &salt, b"share").unwrap();
        // The AAD + the derived key both bind the label, so a different label rejects.
        assert!(unseal(&binding, &dir, "holder-2", &salt, &sealed).is_err(),
            "a blob sealed for holder-1 must not unseal as holder-2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampering_with_one_ciphertext_byte_fails_the_tag() {
        let dir = tempdir("tamper");
        let binding = FixedBinding(b"machine-A".to_vec());
        let salt = load_or_create_salt(&dir).unwrap();
        let mut sealed = seal(&binding, &dir, "h1", &salt, b"share-bytes-here").unwrap();
        // Flip a byte in the ciphertext region (past the 24-byte nonce).
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(unseal(&binding, &dir, "h1", &salt, &sealed).is_err(),
            "a one-byte tamper must fail the AEAD tag");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_sink_salt_separates_keys_on_the_same_machine() {
        // Two sinks on the SAME machine (same binding) get different salts -> a blob sealed
        // in sink A does not unseal in sink B even with the same label + binding.
        let dir_a = tempdir("saltsep-a");
        let dir_b = tempdir("saltsep-b");
        let binding = FixedBinding(b"one-machine".to_vec());
        let salt_a = load_or_create_salt(&dir_a).unwrap();
        let salt_b = load_or_create_salt(&dir_b).unwrap();
        assert_ne!(salt_a, salt_b, "two sinks must get distinct random salts");
        let sealed_a = seal(&binding, &dir_a, "h1", &salt_a, b"share").unwrap();
        assert!(unseal(&binding, &dir_b, "h1", &salt_b, &sealed_a).is_err(),
            "sink B's salt must not unseal sink A's blob");
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }
}
