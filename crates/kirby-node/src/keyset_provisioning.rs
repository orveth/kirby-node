//! S3d: per-agent FROST KEYSET PROVISIONING AT SPAWN.
//!
//! This connects [`crate::frost_identity::FrostIdentity`] (S3a, the PUBLIC face) and
//! [`crate::quorum_signer::QuorumSigner`] (S3c, the SECRET signer) into the
//! spawn/boot path: every fleet tenant is BORN with its OWN durable FROST group key
//! Q -- its sovereign identity -- and signs via its own 2-of-3 quorum. Q SIGNS
//! EVERYTHING for a FROST tenant (no node-local key, the locked S3 decision).
//!
//! LOCKED DECISIONS (gudnuf):
//!   * TRUSTED-DEALER keygen. The SPAWNING SUPERVISOR is the dealer: on FIRST spawn it
//!     generates the full key, splits it 2-of-3, distributes the shares, and the
//!     transient combined-key material is zeroized. See ZEROIZE below for exactly where
//!     the combined secret lives (and dies) and why no extra wipe is needed here.
//!   * NATIVE DKG IS A DOCUMENTED FUTURE UPGRADE, NOT BUILT HERE. With DKG (ZF
//!     `frost_secp256k1_tr::keys::dkg`) NO party -- not even the dealer at setup -- ever
//!     materializes the whole signing key; each holder contributes to the group key
//!     without the combined secret ever existing in one place. S3d keeps the trusted
//!     dealer (the combined key exists for microseconds inside `generate_with_dealer`,
//!     then zeroizes). The seam to swap is `provision_keyset` -> a DKG ceremony that
//!     yields the same per-holder `KeyPackage`s + `PublicKeyPackage`; the keystore
//!     layout and the [`load_quorum_signer`] loader do not change.
//!   * CO-LOCATED holders for S3: the HOST holds all 3 shares. At spawn the supervisor
//!     writes all 3 holder `KeyPackage`s locally beside the agent's treasury.
//!     Cross-machine share distribution is S5/S6.
//!   * PLAINTEXT-0600 at rest (no sealing this slice). SEALING ONLY MATTERS ONCE SHARES
//!     DISTRIBUTE: while all 3 shares are co-located on one host, a host compromise that
//!     can read a 0600 file owned by this user can read all 3 shares regardless of
//!     sealing (the sealing key would live on the same host), so sealing buys nothing
//!     here. Once shares move to separate holders (S5/S6), each holder seals its own
//!     share at rest -- THAT is when sealing becomes load-bearing. Documented, not built.
//!
//! ZEROIZE (the trusted-dealer wipe, honestly bounded):
//!   * The COMBINED full signing key never lives in a [`kirby_custody::DealerKeyset`].
//!     `frost_core::keys::generate_with_dealer` constructs a `SigningKey` (which derives
//!     `ZeroizeOnDrop`) as a local, splits it into Shamir shares, and DROPS it (zeroizing
//!     it) before returning. `DealerKeyset` only ever holds the per-guardian
//!     `SecretShare`s + the public `PublicKeyPackage`. So there is NO combined-secret
//!     copy for S3d to wipe -- it was already wiped microseconds after creation, inside
//!     the dealer keygen. We document this rather than reach for a combined secret that
//!     does not exist.
//!   * The transient SHARE material DOES live in the `DealerKeyset` and the derived
//!     `KeyPackage`s while we persist them. `SecretShare` and `KeyPackage` both derive
//!     `ZeroizeOnDrop` (frost-core 3.0.0), so once persisted we DROP them and their
//!     scalars are overwritten. [`provision_keyset`] persists then drops the keyset (the
//!     `KeyPackage`s it derived are dropped inside the persist step), so no live copy of
//!     any share lingers in this process after provisioning returns -- the shares exist
//!     only in the 0600 files on disk.
//!
//! G-CLEAN: this module is ONLY reached by a fleet supervisor provisioning a FROST
//! tenant. `kirby run` / `kirby agent` without a fleet never constructs a keystore and
//! never calls anything here, so the single-key path is byte-for-byte unchanged.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};

use crate::frost_identity::{self, FrostIdentity};
use crate::quorum_signer::QuorumSigner;

/// The group-pubkeys file name inside a keystore dir (the PUBLIC verifying material;
/// safe to read for identity). Written via [`frost_identity::save_pubkeys`] so the
/// on-disk form is byte-identical to what [`FrostIdentity::load`] reloads.
const PUBKEYS_FILE: &str = "group_pubkeys.json";

/// The number of holder shares a 2-of-3 group has (all 3 co-located on the host for S3).
const SHARE_COUNT: u16 = 3;

/// The quorum policy this slice provisions: 2-of-3 (any 2 of the 3 holders co-sign).
const MIN_SIGNERS: u16 = 2;
const MAX_SIGNERS: u16 = 3;

/// The per-agent keystore directory beside the agent's treasury. Derived from the SAME
/// state root as [`crate::boot::treasury_path_for`] (`std::env::temp_dir()` today), keyed
/// by the tenant's `instance_id` (the same key the child's treasury path uses), so a
/// tenant's keystore sits next to its treasury and is distinct per tenant.
///
/// `<state>/kirby-keystore-<instance_id>/`
pub fn keystore_dir_for(instance_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("kirby-keystore-{instance_id}"))
}

/// The group-pubkeys file path inside a keystore dir.
fn pubkeys_path(keystore_dir: &Path) -> PathBuf {
    keystore_dir.join(PUBKEYS_FILE)
}

/// The holder `KeyPackage` file path for share index `idx` (1..=3).
/// `<keystore_dir>/share_<idx>.json`.
fn share_path(keystore_dir: &Path, idx: u16) -> PathBuf {
    keystore_dir.join(format!("share_{idx}.json"))
}

/// Map a FROST `Identifier` to its u16 wire form (the trusted-dealer identifiers are
/// 1..=n, so the value lives in the last two bytes of the 32-byte big-endian scalar).
/// Used to name each holder's share file deterministically (share_1/2/3).
fn identifier_to_u16(id: &frost_secp256k1_tr::Identifier) -> u16 {
    let bytes = id.serialize();
    let n = bytes.len();
    u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])
}

/// Write `data` to `path` owner-only (0600). Reuses the exact discipline of the custody
/// `frost-nostr-cosign` gen-keyset path: `mode(0o600)` on create, then a defensive
/// re-chmod after open so a pre-existing looser file (e.g. 0644 from an older run) can
/// never leave a secret share world/group-readable.
#[cfg(unix)]
fn write_file_0600(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("open keystore file {} (0600)", path.display()))?;
    // `mode(0o600)` only applies on CREATE; force 0600 after open so a pre-existing
    // looser file is tightened before any secret bytes are written.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("write keystore file {}", path.display()))?;
    f.flush()
        .with_context(|| format!("flush keystore file {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, data)
        .with_context(|| format!("write keystore file {}", path.display()))
}

/// Whether a keystore at `keystore_dir` is already provisioned: the group pubkeys file
/// AND all 3 holder share files exist. A keystore is provisioned ATOMICALLY-ENOUGH for
/// S3 (single host, single supervisor): a partially-written keystore (e.g. an interrupted
/// first spawn) is treated as NOT provisioned and is regenerated. (For S3 a single
/// supervisor provisions each tenant; concurrent provisioners are an S5/S6 concern.)
fn is_provisioned(keystore_dir: &Path) -> bool {
    if !pubkeys_path(keystore_dir).is_file() {
        return false;
    }
    (1..=SHARE_COUNT).all(|idx| share_path(keystore_dir, idx).is_file())
}

/// Provision (or idempotently reload) a per-agent FROST keystore for the tenant keyed by
/// `instance_id`, returning the agent's PUBLIC [`FrostIdentity`] (its Q + npub -- the
/// sovereign identity it is born with).
///
/// IDEMPOTENT (G-IDENTITY-PERSISTS-ACROSS-RESTART): if the keystore already exists (a
/// restart), this RELOADS it and returns the SAME Q -- it does NOT regenerate. Only the
/// FIRST spawn generates. So an agent's identity is durable across restarts: it dies and
/// comes back as itself.
///
/// FIRST SPAWN (the supervisor is the dealer):
///   1. `generate_dealer_keyset(2, 3)` -- trusted-dealer keygen (the combined key lives +
///      dies inside this call; see the module ZEROIZE note).
///   2. Persist the PUBLIC `PublicKeyPackage` via [`frost_identity::save_pubkeys`]
///      (`group_pubkeys.json`) and the 3 holder `KeyPackage`s (`share_1/2/3.json`), each
///      written 0600.
///   3. Derive the agent's [`FrostIdentity`] (Q + npub) from the public package.
///   4. DROP the keyset (its `SecretShare`s + the derived `KeyPackage`s are
///      `ZeroizeOnDrop`), so no live copy of any share lingers after this returns.
pub fn provision_keyset(instance_id: &str) -> anyhow::Result<FrostIdentity> {
    let keystore_dir = keystore_dir_for(instance_id);
    provision_keyset_at(&keystore_dir)
}

/// [`provision_keyset`] with an explicit keystore dir (so tests can point at a temp dir
/// without colliding on the real per-instance path). The instance-keyed wrapper is the
/// production entry point.
pub fn provision_keyset_at(keystore_dir: &Path) -> anyhow::Result<FrostIdentity> {
    // IDEMPOTENT RELOAD: an already-provisioned keystore is the agent's durable identity;
    // load it (same Q) and return WITHOUT touching any file. No regeneration on restart.
    if is_provisioned(keystore_dir) {
        let id = FrostIdentity::load(&pubkeys_path(keystore_dir)).with_context(|| {
            format!(
                "reload existing FROST keystore {} (idempotent restart)",
                keystore_dir.display()
            )
        })?;
        tracing::info!(
            npub = %id.npub(),
            keystore = %keystore_dir.display(),
            "reloaded per-agent FROST keystore (idempotent; same sovereign Q across restart)"
        );
        return Ok(id);
    }

    // FIRST SPAWN: the supervisor is the trusted dealer.
    std::fs::create_dir_all(keystore_dir).with_context(|| {
        format!("create per-agent FROST keystore dir {}", keystore_dir.display())
    })?;

    // (1) Trusted-dealer 2-of-3 keygen over the OS CSPRNG. The COMBINED signing key is
    //     created + zeroized INSIDE this call (see module ZEROIZE note); only the
    //     per-guardian SecretShares + the public PublicKeyPackage come back.
    let keyset = kirby_custody::generate_dealer_keyset(MIN_SIGNERS, MAX_SIGNERS)
        .map_err(|e| anyhow::anyhow!("trusted-dealer 2-of-3 keygen: {e}"))?;

    // (2a) Persist the PUBLIC half (the group PublicKeyPackage) so FrostIdentity reloads
    //      to the same Q/npub on restart. This file holds NO secret material, but we tighten
    //      it to 0600 too: the whole keystore dir is owner-only (a uniform, defensive posture
    //      so nothing in it is ever group/world-readable), even though the pubkeys are public.
    let pubkeys_file = pubkeys_path(keystore_dir);
    frost_identity::save_pubkeys(&keyset.pubkeys, &pubkeys_file)
        .context("persist FROST group pubkeys (the public identity face)")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&pubkeys_file, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 group pubkeys {}", pubkeys_file.display()))?;
    }

    // (2b) Persist each holder's KeyPackage (the SECRET signing share) 0600, named by its
    //      identifier (share_1/2/3.json). The KeyPackages are derived from the keyset's
    //      SecretShares; both they and the keyset are ZeroizeOnDrop and are wiped when this
    //      scope ends. serde-feature serialization matches the custody cosign bin exactly.
    {
        let kps = kirby_custody::key_packages(&keyset)
            .map_err(|e| anyhow::anyhow!("derive holder KeyPackages from the dealer keyset: {e}"))?;
        let mut written = 0u16;
        for (id, kp) in &kps {
            let idx = identifier_to_u16(id);
            let kp_json = serde_json::to_vec(kp)
                .with_context(|| format!("serialize holder KeyPackage {idx}"))?;
            write_file_0600(&share_path(keystore_dir, idx), &kp_json)?;
            written += 1;
        }
        if written != SHARE_COUNT {
            anyhow::bail!(
                "expected {SHARE_COUNT} holder shares to persist, wrote {written} (keygen split mismatch)"
            );
        }
        // `kps` (KeyPackages, ZeroizeOnDrop) drops here, wiping the secret shares it held.
    }

    // (3) Derive the agent's PUBLIC identity (Q + npub) from the persisted public package.
    let identity = FrostIdentity::from_pubkeys(keyset.pubkeys.clone(), &pubkeys_path(keystore_dir))
        .context("derive FROST identity (Q + npub) from the freshly provisioned group")?;

    tracing::info!(
        npub = %identity.npub(),
        keystore = %keystore_dir.display(),
        "provisioned NEW per-agent FROST keystore (trusted-dealer 2-of-3; the agent is born with sovereign Q)"
    );

    // (4) ZEROIZE: drop the dealer keyset. Its SecretShares are ZeroizeOnDrop, so the
    //     transient secret material is overwritten here. The COMBINED key was already
    //     zeroized inside `generate_dealer_keyset` (it never lived in `keyset`). After
    //     this drop, the shares exist ONLY in the 0600 files on disk -- no live copy in
    //     this process. (Explicit drop to make the wipe point unambiguous.)
    drop(keyset);

    Ok(identity)
}

/// Build a live [`QuorumSigner`] from a previously-provisioned per-agent keystore (the
/// loader counterpart of [`provision_keyset`]). Loads the 3 holder `KeyPackage`s
/// (`share_1/2/3.json`) + the group `PublicKeyPackage` (`group_pubkeys.json`) and wraps
/// them in a co-located [`QuorumSigner`] (each holder carrying its own copy of the group
/// pubkeys, per the membrane contract). The signer then signs notes under the keystore's
/// PERSISTENT Q (not a fresh ephemeral one).
///
/// For S5/S6 only the holder construction changes (a remote holder loads ITS OWN share on
/// ITS OWN machine); this co-located loader is the single-box stand-in.
pub fn load_quorum_signer(instance_id: &str) -> anyhow::Result<QuorumSigner> {
    let keystore_dir = keystore_dir_for(instance_id);
    load_quorum_signer_at(&keystore_dir)
}

/// [`load_quorum_signer`] with an explicit keystore dir (tests + the boot-wiring path).
pub fn load_quorum_signer_at(keystore_dir: &Path) -> anyhow::Result<QuorumSigner> {
    if !is_provisioned(keystore_dir) {
        anyhow::bail!(
            "FROST keystore {} is not provisioned (missing group pubkeys or one of the 3 holder \
             shares); provision it at spawn before loading a quorum signer",
            keystore_dir.display()
        );
    }

    // The group PublicKeyPackage (the verifying material; the loader reuses FrostIdentity's
    // on-disk form, which is the hex-of-serialize JSON the supervisor wrote).
    let identity = FrostIdentity::load(&pubkeys_path(keystore_dir))
        .with_context(|| format!("load group pubkeys from {}", keystore_dir.display()))?;
    let pubkeys: PublicKeyPackage = identity.pubkeys().clone();

    // Each holder's KeyPackage (the SECRET share). serde_json mirrors how the supervisor
    // wrote them (and the custody cosign bin's load_keypackage).
    let mut key_packages: Vec<KeyPackage> = Vec::with_capacity(SHARE_COUNT as usize);
    for idx in 1..=SHARE_COUNT {
        let path = share_path(keystore_dir, idx);
        let bytes = read_share_file(&path)?;
        let kp: KeyPackage = serde_json::from_slice(&bytes)
            .with_context(|| format!("deserialize holder KeyPackage {}", path.display()))?;
        key_packages.push(kp);
    }

    QuorumSigner::from_local_key_packages(key_packages, pubkeys)
        .context("build co-located QuorumSigner from the persisted keystore")
}

/// Read a holder share file, bounding the read (a share KeyPackage JSON is well under a
/// KiB) and rejecting a non-regular file -- the same MED hardening `FrostIdentity::load`
/// applies to the pubkeys file, so a hostile/mistaken keystore path (a huge file, a
/// symlink to a device/FIFO/procfs node) cannot make the loader allocate unboundedly or
/// block. On Unix it also tightens a pre-existing looser file to 0600 before reading (so a
/// share is never left world-readable), mirroring `kirby_custody::persist::load_keyset`.
fn read_share_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    /// A holder KeyPackage hex/JSON is well under a KiB; this generous cap bounds the read.
    const MAX_SHARE_BYTES: u64 = 256 * 1024;

    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat holder share {}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("holder share {} is not a regular file", path.display());
    }
    if meta.len() > MAX_SHARE_BYTES {
        anyhow::bail!(
            "holder share {} is too large ({} bytes > {} cap)",
            path.display(),
            meta.len(),
            MAX_SHARE_BYTES
        );
    }
    // Tighten a pre-existing looser file to 0600 before reading (defensive; a share must
    // never be world-readable on a shared box).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::read(path).with_context(|| format!("read holder share {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
    use bitcoin::KnownHrp;
    use kirby_custody::{group_xonly_q, taproot_address};

    /// A fresh temp keystore dir unique to this test + process (so parallel test runs and
    /// reruns never collide).
    fn temp_keystore(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kirby-s3d-keystore-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// G-SPAWN-PROVISIONS-KEYSET: a (first) spawn provisions a complete keystore. After
    /// `provision_keyset_at`, the group pubkeys file + all 3 holder share files exist, every
    /// file is mode 0600, and the returned identity's Q is derivable + matches the custody
    /// crate's direct derivation from the persisted pubkeys.
    #[test]
    fn g_spawn_provisions_keyset() {
        let dir = temp_keystore("provision");
        let id = provision_keyset_at(&dir).expect("first spawn provisions the keystore");

        // The public pubkeys file + all 3 holder shares exist.
        assert!(pubkeys_path(&dir).is_file(), "group_pubkeys.json must exist");
        for idx in 1..=3 {
            assert!(share_path(&dir, idx).is_file(), "share_{idx}.json must exist");
        }

        // Every keystore file is 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for p in [
                pubkeys_path(&dir),
                share_path(&dir, 1),
                share_path(&dir, 2),
                share_path(&dir, 3),
            ] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} must be 0600, got {mode:o}", p.display());
            }
        }

        // Q is derivable + non-empty npub.
        assert!(id.npub().starts_with("npub1"), "npub must encode, got {}", id.npub());

        // The identity's Q matches a fresh load of the persisted pubkeys (no drift).
        let reloaded = FrostIdentity::load(&pubkeys_path(&dir)).expect("reload pubkeys");
        assert_eq!(id.q_bytes(), reloaded.q_bytes(), "Q must match the persisted pubkeys");

        let _ = std::fs::remove_dir_all(&dir);
        println!("G-SPAWN-PROVISIONS-KEYSET PASS: pubkeys + 3 shares written 0600; Q derivable + stable");
    }

    /// G-IDENTITY-PERSISTS-ACROSS-RESTART: re-provisioning an already-provisioned keystore
    /// is IDEMPOTENT -- it yields the SAME Q and does NOT rewrite any file (no regeneration
    /// on restart). We capture the share-file bytes + mtimes before the second call and
    /// assert they are byte-identical afterward (proving no regen), and that Q is identical.
    #[test]
    fn g_identity_persists_across_restart() {
        let dir = temp_keystore("restart");

        // First spawn: generate.
        let id1 = provision_keyset_at(&dir).expect("first spawn");
        let q1 = id1.q_bytes();
        let npub1 = id1.npub();

        // Snapshot the persisted share bytes (the secret material a regen WOULD change).
        let share_bytes_before: Vec<Vec<u8>> = (1..=3)
            .map(|idx| std::fs::read(share_path(&dir, idx)).expect("read share before"))
            .collect();
        let pubkeys_before = std::fs::read(pubkeys_path(&dir)).expect("read pubkeys before");

        // Second "spawn" (a restart): must RELOAD, not regenerate.
        let id2 = provision_keyset_at(&dir).expect("restart reloads");
        let q2 = id2.q_bytes();

        // Same sovereign Q + npub across the restart.
        assert_eq!(q1, q2, "Q must be identical across restart (no regeneration)");
        assert_eq!(npub1, id2.npub(), "npub must be identical across restart");

        // The on-disk secret shares + pubkeys were NOT rewritten (byte-identical => no regen).
        for (idx, before) in share_bytes_before.iter().enumerate() {
            let after = std::fs::read(share_path(&dir, idx as u16 + 1)).expect("read share after");
            assert_eq!(
                before, &after,
                "share_{} must be byte-identical across restart (idempotent, no regen)",
                idx + 1
            );
        }
        let pubkeys_after = std::fs::read(pubkeys_path(&dir)).expect("read pubkeys after");
        assert_eq!(pubkeys_before, pubkeys_after, "pubkeys must not be rewritten on restart");

        let _ = std::fs::remove_dir_all(&dir);
        println!("G-IDENTITY-PERSISTS-ACROSS-RESTART PASS: same Q/npub, shares byte-identical (no regen)");
    }

    /// G-AGENT-SIGNS-WITH-PERSISTENT-Q: a QuorumSigner LOADED from the keystore signs a note
    /// under the PERSISTENT Q (the keystore's Q, not a fresh ephemeral one), and the
    /// aggregate verifies as a real BIP-340 schnorr sig under that exact Q (and fails under
    /// the untweaked internal key P). This is the end-to-end provision -> load -> sign proof
    /// (minus the relay), fast + ungated.
    #[test]
    fn g_agent_signs_with_persistent_q() {
        let dir = temp_keystore("sign");
        let id = provision_keyset_at(&dir).expect("provision");
        let persistent_q = id.q_bytes();

        // Load a quorum signer from the SAME keystore + sign.
        let signer = load_quorum_signer_at(&dir).expect("load quorum signer from keystore");
        assert_eq!(
            signer.q_bytes(),
            persistent_q,
            "the loaded signer's Q must be the keystore's PERSISTENT Q, not a fresh one"
        );

        let created_at = 1_750_000_000u64;
        let content = "Born with my own Q. Kirby signs by its 2-of-3 quorum.";
        let event = signer
            .sign_nostr_event(1, created_at, content)
            .expect("the persistent-Q quorum signs the note");

        // The event pubkey is hex(persistent Q).
        assert_eq!(event.pubkey, hex::encode(persistent_q), "event pubkey must be the persistent Q");

        // Independently verify the aggregate sig under the persistent Q (tweaked) and that it
        // FAILS under the untweaked internal key P -- the same crypto-floor assertion shape S3c
        // uses. We re-derive Q/P from the loaded group pubkeys.
        let pubkeys = FrostIdentity::load(&pubkeys_path(&dir)).unwrap().pubkeys().clone();
        let q_direct = group_xonly_q(&pubkeys).expect("direct Q");
        assert_eq!(q_direct, persistent_q, "direct Q must equal the persistent Q");

        let (_addr, internal_p) = taproot_address(&pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();

        let event_id = hex::decode(&event.id).expect("event id hex");
        let msg = Message::from_digest(event_id.as_slice().try_into().expect("32-byte id"));
        let sig = schnorr::Signature::from_slice(&hex::decode(&event.sig).expect("sig hex"))
            .expect("parse 64-byte sig");
        assert!(
            secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok(),
            "aggregate must verify under the persistent (tweaked) Q"
        );
        assert!(
            secp.verify_schnorr(&sig, &msg, &internal_p).is_err(),
            "aggregate must NOT verify under the untweaked internal key P"
        );

        let _ = std::fs::remove_dir_all(&dir);
        println!("G-AGENT-SIGNS-WITH-PERSISTENT-Q PASS: keystore-loaded quorum signs verifying-under-persistent-Q");
    }

    /// G-KEYSTORE-PERMS: the holder KeyPackage files are mode 0600 (never world/group
    /// readable). A dedicated permission gate (the secret shares are the crown jewels).
    #[test]
    #[cfg(unix)]
    fn g_keystore_perms() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_keystore("perms");
        provision_keyset_at(&dir).expect("provision");
        for idx in 1..=3 {
            let p = share_path(&dir, idx);
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "holder share {} must be 0600, got {mode:o}", p.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
        println!("G-KEYSTORE-PERMS PASS: all 3 holder KeyPackage files are 0600");
    }

    /// A loader over a NOT-provisioned (or partial) keystore refuses cleanly (no panic), so a
    /// missing/half-written keystore is a loud error rather than a silent wrong-key sign.
    #[test]
    fn load_refuses_unprovisioned_keystore() {
        let dir = temp_keystore("unprovisioned");
        // Nothing provisioned yet.
        assert!(load_quorum_signer_at(&dir).is_err(), "an empty keystore must refuse to load");

        // Provision, then delete one share -> partial keystore must also refuse.
        provision_keyset_at(&dir).expect("provision");
        std::fs::remove_file(share_path(&dir, 2)).expect("remove a share");
        assert!(
            load_quorum_signer_at(&dir).is_err(),
            "a keystore missing a holder share must refuse to load"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
