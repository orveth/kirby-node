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
use crate::share_seal;

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
/// DURABLE state root as [`crate::boot::treasury_path_for`] (FIX 2: [`crate::boot::state_root`],
/// NEVER `std::env::temp_dir()` — a custody key on a tmpfs `/tmp` is permanent loss on the
/// next reboot), keyed by the tenant's `instance_id` (the same key the child's treasury path
/// uses), so a tenant's keystore sits next to its treasury and is distinct per tenant.
///
/// `<durable-state-root>/keystore-<instance_id>/`
pub fn keystore_dir_for(instance_id: &str) -> PathBuf {
    crate::boot::state_root().join(format!("keystore-{instance_id}"))
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

    // FIX 4 (symlink-safety, write side): refuse to write key material THROUGH a symlink. If a
    // file already exists at `path`, lstat it (does not follow) and reject a symlink or any
    // non-regular target — a planted symlink must not redirect a key WRITE to an attacker
    // location. Combined with `O_NOFOLLOW` below this is belt-and-suspenders: lstat rejects an
    // existing link with a clear message; O_NOFOLLOW makes the open itself fail (ELOOP) if the
    // final component is a symlink even under a TOCTOU race.
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                anyhow::bail!(
                    "keystore file {} is a SYMLINK — refusing to write key material through a \
                     link (planted-symlink redirect guard, FIX 4)",
                    path.display()
                );
            }
            if !ft.is_file() {
                anyhow::bail!(
                    "keystore file {} exists but is not a regular file — refusing to write key \
                     material (FIX 4)",
                    path.display()
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { /* fresh file; create below */ }
        Err(e) => {
            return Err(e).with_context(|| format!("lstat keystore file {}", path.display()))?;
        }
    }

    let mut opts = std::fs::OpenOptions::new();
    // `O_NOFOLLOW`: if the FINAL path component is a symlink, the open fails (ELOOP) instead of
    // following it — closes the lstat→open TOCTOU window for the final component.
    opts.write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut f = opts
        .open(path)
        .with_context(|| format!("open keystore file {} (0600, O_NOFOLLOW)", path.display()))?;
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

/// Whether a keystore at `keystore_dir` is fully provisioned: the group pubkeys file AND
/// all 3 holder share files exist. Used by the LOADER ([`load_quorum_signer_at`]) to refuse
/// a partial keystore. The PROVISIONER no longer uses this to decide regeneration — see
/// [`has_identity_anchor`] and FIX 1 (an established identity must NEVER be regenerated).
fn is_provisioned(keystore_dir: &Path) -> bool {
    if !pubkeys_path(keystore_dir).is_file() {
        return false;
    }
    (1..=SHARE_COUNT).all(|idx| share_path(keystore_dir, idx).is_file())
}

/// Whether an ESTABLISHED IDENTITY ANCHOR is present: `group_pubkeys.json` exists.
///
/// FIX 1 (identity-loss, fail-closed): the regeneration decision keys off THIS anchor, NOT
/// off "all files present". The anchor is the durable proof that a sovereign Q was once
/// minted here. CRASH-SAFETY INVARIANT (see [`provision_keyset_at`]): first-spawn writes all
/// 3 holder shares FIRST and the anchor LAST, so a SURVIVING anchor implies the shares were
/// written. Therefore:
///   * anchor present  => an established identity exists => NEVER regenerate. We LOAD it and
///     fail LOUD if a share is missing/corrupt (a wrong-key sign or a silent new Q would be
///     catastrophic identity/fund loss — the case the verifier empirically reproduced).
///   * anchor absent    => a truly empty keystore (genuine first spawn) => generate fresh.
///
/// A missing share with a surviving anchor is therefore a LOUD ERROR ("restore the
/// keystore"), never a silent regeneration of a new Q.
fn has_identity_anchor(keystore_dir: &Path) -> bool {
    pubkeys_path(keystore_dir).is_file()
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
    // FIX 1 (identity-loss, FAIL-CLOSED): the regeneration decision keys off the IDENTITY
    // ANCHOR (`group_pubkeys.json`), NOT off "all files present". If the anchor exists an
    // established sovereign Q was once minted here, so we NEVER regenerate: we reload it and
    // VALIDATE all 3 holder shares, failing LOUD if any is missing/corrupt. (The old code
    // required pubkeys AND all 3 shares; a missing share with a surviving anchor fell through
    // to regeneration and SILENTLY MINTED A NEW Q — permanent identity/fund loss, the case
    // the verifier empirically reproduced. This is now a loud, recoverable error.)
    if has_identity_anchor(keystore_dir) {
        let id = FrostIdentity::load(&pubkeys_path(keystore_dir)).with_context(|| {
            format!(
                "reload established FROST identity anchor {} (idempotent restart). The anchor \
                 (group_pubkeys.json) exists, so a sovereign Q was already minted here and MUST \
                 NOT be regenerated.",
                keystore_dir.display()
            )
        })?;
        // FAIL-CLOSED on a partial keystore: validate that all 3 holder shares are present and
        // loadable. A surviving anchor with a missing/corrupt share is a CATASTROPHIC state
        // (the agent cannot sign as itself); refuse loudly and tell the operator to restore the
        // keystore — NEVER mint a new Q over an established identity.
        assert_shares_loadable(keystore_dir).with_context(|| {
            format!(
                "established FROST identity at {} has a missing or corrupt holder share. The \
                 identity anchor (group_pubkeys.json) is present, so this agent ALREADY OWNS a \
                 sovereign Q — refusing to regenerate (that would mint a NEW key and permanently \
                 lose this identity + its funds). RESTORE the keystore (all 3 share_N.json) from \
                 backup.",
                keystore_dir.display()
            )
        })?;
        tracing::info!(
            npub = %id.npub(),
            keystore = %keystore_dir.display(),
            "reloaded established per-agent FROST keystore (idempotent; same sovereign Q across restart; 3/3 shares validated)"
        );
        return Ok(id);
    }

    // FIRST SPAWN (no identity anchor => a truly empty keystore): the supervisor is the
    // trusted dealer.
    std::fs::create_dir_all(keystore_dir).with_context(|| {
        format!("create per-agent FROST keystore dir {}", keystore_dir.display())
    })?;

    // (1) Trusted-dealer 2-of-3 keygen over the OS CSPRNG. The COMBINED signing key is
    //     created + zeroized INSIDE this call (see module ZEROIZE note); only the
    //     per-guardian SecretShares + the public PublicKeyPackage come back.
    let keyset = kirby_custody::generate_dealer_keyset(MIN_SIGNERS, MAX_SIGNERS)
        .map_err(|e| anyhow::anyhow!("trusted-dealer 2-of-3 keygen: {e}"))?;

    // CRASH-SAFETY ORDERING INVARIANT (FIX 1): write all 3 holder SHARES FIRST, and the
    // identity ANCHOR (`group_pubkeys.json`) LAST. The anchor is what the regeneration
    // decision keys off, so a SURVIVING ANCHOR MUST IMPLY THE SHARES WERE WRITTEN. If we wrote
    // the anchor first and crashed before the shares, a restart would see the anchor, refuse to
    // regenerate (correct), but then fail-closed on the missing shares — turning a recoverable
    // first-spawn crash into an operator-restore. Writing shares-then-anchor means a crash
    // BEFORE the anchor leaves NO anchor => the next spawn cleanly regenerates (no identity was
    // ever established); a crash AFTER the anchor means the shares are already on disk.

    // (1a) Persist each holder's KeyPackage (the SECRET signing share) 0600 FIRST, named by its
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

    // (1b) Persist the PUBLIC half (the group PublicKeyPackage) so FrostIdentity reloads to the
    //      same Q/npub on restart. THIS IS THE ANCHOR, written LAST (crash-safety invariant
    //      above). This file holds NO secret material, but we tighten it to 0600 too: the whole
    //      keystore dir is owner-only (a uniform, defensive posture), even though pubkeys are
    //      public.
    let pubkeys_file = pubkeys_path(keystore_dir);
    frost_identity::save_pubkeys(&keyset.pubkeys, &pubkeys_file)
        .context("persist FROST group pubkeys (the identity anchor; written LAST)")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&pubkeys_file, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 group pubkeys {}", pubkeys_file.display()))?;
    }

    // (3) Derive the agent's PUBLIC identity (Q + npub) from the persisted public package.
    let identity = FrostIdentity::from_pubkeys(keyset.pubkeys.clone(), &pubkeys_path(keystore_dir))
        .context("derive FROST identity (Q + npub) from the freshly provisioned group")?;

    tracing::info!(
        npub = %identity.npub(),
        keystore = %keystore_dir.display(),
        "provisioned NEW per-agent FROST keystore (trusted-dealer 2-of-3; shares-then-anchor; the agent is born with sovereign Q)"
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

/// Whether THIS node can SIGN AS the agent at `keystore_dir`: the group anchor AND all 3 holder
/// shares are present and each share deserializes to a well-formed `KeyPackage`. This is the
/// FAILOVER admission gate (G-4): a node may take over a peer's agent only if it can FROST-sign
/// the agent's `term + 1` lease + voice — i.e. it actually holds the agent's quorum shares. It is
/// the SAME loadability check the loader and the fail-closed reload run ([`is_provisioned`] +
/// [`assert_shares_loadable`]), exposed as a side-effect-free boolean so a scan can cheaply test
/// "could I claim for this agent?" WITHOUT materializing a `QuorumSigner` (no combined-secret
/// build, no lingering share copy — the shares it reads to validate are dropped ZeroizeOnDrop).
///
/// CROSS-MACHINE BOUNDARY (finding G-2, the right behavior NOW): each node today provisions its
/// OWN per-agent keystore, so a DIFFERENT node simply has no keystore for the agent and this is
/// `false` — the failover scan correctly SKIPS an agent it cannot sign for (same-host takeover
/// works; cross-machine takeover is gated until distributed shares land, NOT silently mis-claimed
/// under a key this node does not hold). It is read-only + non-secret-leaking, so a scan may call
/// it every tick.
pub fn keystore_loadable_at(keystore_dir: &Path) -> bool {
    is_provisioned(keystore_dir) && assert_shares_loadable(keystore_dir).is_ok()
}

/// FIX 1 (fail-closed): validate that all 3 holder shares are present AND deserialize as
/// `KeyPackage`s. Called when an established identity anchor is found, so a partial/corrupt
/// keystore over an established Q is a LOUD error rather than a silent regeneration. Does NOT
/// build a signer (no combined-secret materialization); just proves each share loads. The
/// shares it reads are dropped immediately (ZeroizeOnDrop) — no lingering copy.
fn assert_shares_loadable(keystore_dir: &Path) -> anyhow::Result<()> {
    for idx in 1..=SHARE_COUNT {
        let path = share_path(keystore_dir, idx);
        if !path.is_file() {
            anyhow::bail!("holder share_{idx} missing at {}", path.display());
        }
        let bytes = read_share_file(&path)?;
        let _kp: KeyPackage = serde_json::from_slice(&bytes)
            .with_context(|| format!("deserialize holder KeyPackage {}", path.display()))?;
        // `_kp` (ZeroizeOnDrop) drops here, wiping the share scalar it held.
    }
    Ok(())
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

    // FIX 4 (symlink-safety): stat with `symlink_metadata` (does NOT follow a final symlink)
    // and reject anything that is not a REGULAR FILE — a planted symlink under the keystore
    // path must not redirect a key READ to (or through) an attacker-chosen target. `metadata()`
    // resolves through symlinks; `symlink_metadata` reports the link itself.
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("lstat holder share {}", path.display()))?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        anyhow::bail!(
            "holder share {} is a SYMLINK — refusing to read key material through a link \
             (planted-symlink redirect guard, FIX 4)",
            path.display()
        );
    }
    if !ft.is_file() {
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
    // FIX 5 (reload perms fail-closed): tighten a pre-existing looser file to 0600 before
    // reading. If the chmod FAILS, surface the error — do NOT silently proceed to read a secret
    // share that may still be world/group-readable. (The old code ignored the result with `let
    // _ =`.) We only reach here on a confirmed regular, non-symlink file (FIX 4), so the chmod
    // cannot be redirected through a link.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).with_context(
            || {
                format!(
                    "chmod 0600 holder share {} before reading (refusing to read a secret share \
                     with wrong permissions, FIX 5)",
                    path.display()
                )
            },
        )?;
    }
    std::fs::read(path).with_context(|| format!("read holder share {}", path.display()))
}

// ============================================================================================
// S5/S6 chunk 3: DISTRIBUTED PROVISIONING via a per-holder SHARE SINK seam.
//
// TODAY (above): the trusted dealer splits the key 2-of-3 then writes all 3 holder
// KeyPackages PLAINTEXT-0600 into ONE keystore dir on ONE host, anchor last. That is the
// co-located default and stays BYTE-IDENTICAL (the functions above are untouched).
//
// THIS CHUNK adds an OPT-IN distributed path that keeps the trusted-dealer split UNCHANGED
// but hands share `i` to SINK `i` instead of writing all 3 to one dir. Each sink is a
// distinct holder store on (in production) its own machine; in this chunk the only sink
// impl is a LOCAL SEALED sink (a distinct directory, sealing its share at rest under a
// host-bound key, `share_seal.rs`). The build + tests use distinct LOCAL dirs standing in
// for distinct machines.
//
// PRESERVED EXACTLY (the anti-identity-loss invariants, ported to the sink layout):
//   * IDEMPOTENT FAIL-CLOSED RELOAD: anchor-exists => reload + VALIDATE every share ACROSS
//     the sinks (each must unseal to a well-formed KeyPackage), NEVER regenerate. A missing
//     or corrupt share over an established anchor is a LOUD error (restore the sinks), never
//     a silent new Q.
//   * CRASH-SAFETY ORDERING: distribute all shares to the sinks FIRST, write the anchor
//     (group_pubkeys.json, node-local) LAST. A surviving anchor implies the shares were
//     distributed; a crash before the anchor leaves NO anchor => the next spawn cleanly
//     regenerates (no identity was established).
//
// DEFERRED (NOT built here; the next follow-up chunk): the REAL cross-machine NETWORK
// distribution (a remote sink that sends share `i` to a `RemoteHolderServer` on ANOTHER
// machine) + the endpoint mutual-auth / placement (design spec section 6.6). This chunk
// builds the SINK SEAM + the local sealed sink ONLY; a remote sink drops into the
// `ShareSink` seam later WITHOUT changing this provisioning/reload body. There is also no
// network auth handshake here.
// ============================================================================================

/// A destination for ONE holder's FROST share (the S5/S6 seam). Distributed provisioning
/// splits as today (trusted dealer) then hands share `i` to SINK `i` -- so no sink ever
/// receives two shares, and the combined key is still materialized nowhere.
///
/// The plaintext crossing this trait is a share `KeyPackage` serialized to JSON (the same
/// bytes the co-located path writes to `share_<i>.json`). A sealing sink encrypts it at
/// rest; the trait contract is in terms of the plaintext so the provisioner/loader never
/// sees the sealed form. Implementors MUST persist durably (a sink that loses its share
/// after `put_share` returns would, with a surviving anchor, trip the fail-closed reload).
///
/// SCOPE: the in-tree impl is [`LocalSealedSink`] (a distinct local dir per holder). A
/// future remote sink (share `i` shipped to a `RemoteHolderServer` on another machine over
/// the relay seam) implements this SAME trait and drops in unchanged; that network sink +
/// its endpoint auth is the deferred follow-up chunk.
pub trait ShareSink {
    /// A stable label for this sink (the holder identity for diagnostics + the seal's
    /// domain separator). MUST be distinct per sink in a provisioning set.
    fn label(&self) -> &str;

    /// Persist share `idx`'s plaintext KeyPackage bytes durably (sealing it at rest if the
    /// sink seals). Idempotent-overwrite is fine; the provisioner only calls this on first
    /// spawn (anchor absent). MUST NOT return `Ok` until the share is durably stored.
    fn put_share(&self, idx: u16, plaintext: &[u8]) -> anyhow::Result<()>;

    /// Whether this sink currently holds share `idx` (a stored, readable share file).
    /// Used by the fail-closed reload to detect a missing share over an established anchor.
    fn has_share(&self, idx: u16) -> bool;

    /// Read + (if sealed) unseal share `idx`, returning the plaintext KeyPackage bytes. A
    /// missing or unauthenticated share is an `Err` (the reload turns that into a loud
    /// fail-closed error -- never a silent regeneration).
    fn get_share(&self, idx: u16) -> anyhow::Result<Vec<u8>>;
}

/// The sealed-share file name inside a sink dir for share index `idx`.
/// `<sink_dir>/share_<idx>.sealed`.
fn sealed_share_path(sink_dir: &Path, idx: u16) -> PathBuf {
    sink_dir.join(format!("share_{idx}.sealed"))
}

/// A LOCAL holder store that SEALS its one share at rest (`share_seal.rs`). Each sink is a
/// DISTINCT directory; in production each lives on its own machine, here distinct local
/// dirs stand in for distinct machines. The share is XChaCha20Poly1305-sealed under a key
/// HKDF-derived from the host machine binding + a per-sink salt (so a stolen disk image of
/// this one sink yields nothing usable; the honest residual -- a LIVE host still reads its
/// own one share -- is documented in `share_seal`).
///
/// The sink is GENERIC over the [`share_seal::MachineBinding`] so tests can inject a fixed
/// binding (two test sinks = two "machines"); production uses [`share_seal::HostMachineBinding`].
pub struct LocalSealedSink<B: share_seal::MachineBinding> {
    /// This sink's own directory (its "machine"'s store).
    dir: PathBuf,
    /// The sink label (the seal domain separator + diagnostics). Distinct per sink.
    label: String,
    /// The machine binding source for the seal key (machine-id in production).
    binding: B,
}

impl LocalSealedSink<share_seal::HostMachineBinding> {
    /// Build a production sealed sink at `dir` labelled `label`, binding the seal key to the
    /// host machine (machine-id, with the documented loud fallback). Creates `dir` 0700.
    pub fn open(dir: impl Into<PathBuf>, label: impl Into<String>) -> anyhow::Result<Self> {
        Self::open_with_binding(dir, label, share_seal::HostMachineBinding)
    }
}

impl<B: share_seal::MachineBinding> LocalSealedSink<B> {
    /// Build a sealed sink with an explicit machine binding (the test seam). Creates the
    /// sink dir owner-only.
    pub fn open_with_binding(
        dir: impl Into<PathBuf>,
        label: impl Into<String>,
        binding: B,
    ) -> anyhow::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create sealed share sink dir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // Owner-only dir (0700): the sealed share + its salt live here.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 sink dir {}", dir.display()))?;
        }
        Ok(Self { dir, label: label.into(), binding })
    }

    /// This sink's directory (for diagnostics + tests that inspect raw bytes).
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl<B: share_seal::MachineBinding> ShareSink for LocalSealedSink<B> {
    fn label(&self) -> &str {
        &self.label
    }

    fn put_share(&self, idx: u16, plaintext: &[u8]) -> anyhow::Result<()> {
        // Load-or-create this sink's per-sink salt (separates sinks on one machine), then
        // seal the share plaintext under the host-bound key and write the sealed body 0600.
        let salt = share_seal::load_or_create_salt(&self.dir)
            .with_context(|| format!("salt for sink {}", self.label))?;
        let sealed = share_seal::seal(&self.binding, &self.dir, &self.label, &salt, plaintext)
            .with_context(|| format!("seal share {idx} for sink {}", self.label))?;
        write_file_0600(&sealed_share_path(&self.dir, idx), &sealed)?;
        Ok(())
    }

    fn has_share(&self, idx: u16) -> bool {
        sealed_share_path(&self.dir, idx).is_file()
    }

    fn get_share(&self, idx: u16) -> anyhow::Result<Vec<u8>> {
        let path = sealed_share_path(&self.dir, idx);
        // Bounded read + symlink/regular-file guard (a sealed share is well under a KiB),
        // mirroring `read_share_file`'s hardening.
        let sealed = read_share_file(&path)?;
        // The salt MUST already exist (load_salt does NOT create it): a missing salt over a
        // stored sealed share is corruption, a loud error -- never a silent re-create that
        // would derive the wrong key and make the share permanently un-unsealable.
        let salt = share_seal::load_salt(&self.dir)
            .with_context(|| format!("salt for sink {} (unseal)", self.label))?;
        share_seal::unseal(&self.binding, &self.dir, &self.label, &salt, &sealed)
            .with_context(|| format!("unseal share {idx} from sink {}", self.label))
    }
}

/// Provision (or idempotently reload) a per-agent FROST keyset whose 3 holder shares are
/// DISTRIBUTED across `sinks` (one share per sink), with the PUBLIC group anchor
/// (`group_pubkeys.json`) written node-local under `anchor_dir`. Returns the agent's PUBLIC
/// [`FrostIdentity`] (its Q + npub).
///
/// This is the OPT-IN distributed counterpart of [`provision_keyset_at`] (the co-located
/// default, byte-identical, untouched). It keeps the trusted-dealer split UNCHANGED and the
/// SAME anti-identity-loss invariants, ported to the sink layout:
///
///   * IDEMPOTENT FAIL-CLOSED RELOAD: if `anchor_dir` already holds `group_pubkeys.json` an
///     established sovereign Q exists, so this RELOADS it and VALIDATES every share across
///     the sinks (each must read + unseal to a well-formed KeyPackage), returning the SAME
///     Q. It NEVER regenerates; a missing/corrupt share is a LOUD error.
///   * CRASH-SAFETY ORDERING: on FIRST spawn, all shares go to the sinks FIRST and the
///     anchor is written LAST -- a surviving anchor implies the shares were distributed.
///
/// `sinks` MUST have exactly [`SHARE_COUNT`] entries with DISTINCT labels (distinct holder
/// stores); the i-th share (identifier `i+1`) goes to `sinks[i]`. The dealer host retains NO
/// share after this returns (the keyset + its derived KeyPackages are ZeroizeOnDrop and
/// dropped; only the per-sink sealed stores hold a share).
pub fn provision_keyset_with_sinks(
    anchor_dir: &Path,
    sinks: &[&dyn ShareSink],
) -> anyhow::Result<FrostIdentity> {
    if sinks.len() != SHARE_COUNT as usize {
        anyhow::bail!(
            "distributed provisioning needs exactly {SHARE_COUNT} share sinks (one per holder), \
             got {}",
            sinks.len()
        );
    }
    // Distinct sink labels (two shares to the same store would re-create the co-located hole
    // on that store + collide their seal domain). Reject a duplicated label up front.
    for i in 0..sinks.len() {
        for j in (i + 1)..sinks.len() {
            if sinks[i].label() == sinks[j].label() {
                anyhow::bail!(
                    "share sinks {i} and {j} share the label {:?}; each holder sink MUST be \
                     distinct (no sink may hold two shares)",
                    sinks[i].label()
                );
            }
        }
    }

    // FAIL-CLOSED RELOAD (idempotent restart): the anchor is the durable proof a sovereign Q
    // was minted. If it exists we NEVER regenerate -- reload it and validate every share
    // across the sinks, failing LOUD on any missing/corrupt share.
    if has_identity_anchor(anchor_dir) {
        let id = FrostIdentity::load(&pubkeys_path(anchor_dir)).with_context(|| {
            format!(
                "reload established FROST identity anchor {} (idempotent distributed restart). \
                 The anchor (group_pubkeys.json) exists, so a sovereign Q was already minted and \
                 MUST NOT be regenerated.",
                anchor_dir.display()
            )
        })?;
        assert_shares_loadable_from_sinks(sinks).with_context(|| {
            format!(
                "established distributed FROST identity at {} has a missing or corrupt holder \
                 share in one of its sinks. The identity anchor (group_pubkeys.json) is present, \
                 so this agent ALREADY OWNS a sovereign Q -- refusing to regenerate (that would \
                 mint a NEW key and permanently lose this identity + its funds). RESTORE the \
                 missing sink's sealed share (+ its salt) from backup.",
                anchor_dir.display()
            )
        })?;
        tracing::info!(
            npub = %id.npub(),
            anchor = %anchor_dir.display(),
            sinks = sinks.len(),
            "reloaded established DISTRIBUTED per-agent FROST keyset (idempotent; same sovereign Q across restart; all shares validated across sinks)"
        );
        return Ok(id);
    }

    // FIRST SPAWN (no anchor): the supervisor is the trusted dealer (split UNCHANGED).
    std::fs::create_dir_all(anchor_dir).with_context(|| {
        format!("create per-agent FROST anchor dir {}", anchor_dir.display())
    })?;

    // (1) Trusted-dealer 2-of-3 keygen (the combined key lives + dies inside this call; see
    //     the module ZEROIZE note). UNCHANGED from the co-located path.
    let keyset = kirby_custody::generate_dealer_keyset(MIN_SIGNERS, MAX_SIGNERS)
        .map_err(|e| anyhow::anyhow!("trusted-dealer 2-of-3 keygen: {e}"))?;

    // CRASH-SAFETY ORDERING: DISTRIBUTE all shares to the sinks FIRST, write the anchor LAST.
    // (2a) Hand share `i` (identifier i+1) to sink `i`. Each sink seals it at rest. The
    //      KeyPackages are ZeroizeOnDrop and wiped when this scope ends; only the per-sink
    //      sealed stores retain a share. No sink receives two shares (one put per sink).
    {
        let kps = kirby_custody::key_packages(&keyset)
            .map_err(|e| anyhow::anyhow!("derive holder KeyPackages from the dealer keyset: {e}"))?;
        if kps.len() != SHARE_COUNT as usize {
            anyhow::bail!(
                "expected {SHARE_COUNT} holder KeyPackages from the dealer split, got {} (keygen mismatch)",
                kps.len()
            );
        }
        // Map each KeyPackage by its identifier u16 (1..=3) to the matching sink. The sinks
        // are indexed 0..n; share identifier `i` (1-based) goes to `sinks[i-1]`.
        for (id, kp) in &kps {
            let idx = identifier_to_u16(id);
            if idx < 1 || idx as usize > sinks.len() {
                anyhow::bail!(
                    "holder identifier {idx} out of range for {} sinks (trusted-dealer ids are 1..=n)",
                    sinks.len()
                );
            }
            let kp_json = serde_json::to_vec(kp)
                .with_context(|| format!("serialize holder KeyPackage {idx}"))?;
            let sink = sinks[idx as usize - 1];
            sink.put_share(idx, &kp_json).with_context(|| {
                format!("distribute share {idx} to sink {:?}", sink.label())
            })?;
        }
        // `kps` (ZeroizeOnDrop KeyPackages) drops here, wiping the secret shares it held.
    }

    // (2b) The PUBLIC anchor (group PublicKeyPackage), written LAST (crash-safety invariant).
    let pubkeys_file = pubkeys_path(anchor_dir);
    frost_identity::save_pubkeys(&keyset.pubkeys, &pubkeys_file)
        .context("persist FROST group pubkeys (the distributed identity anchor; written LAST)")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&pubkeys_file, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 group pubkeys {}", pubkeys_file.display()))?;
    }

    // (3) Derive the agent's PUBLIC identity (Q + npub) from the persisted public package.
    let identity = FrostIdentity::from_pubkeys(keyset.pubkeys.clone(), &pubkeys_path(anchor_dir))
        .context("derive FROST identity (Q + npub) from the freshly distributed group")?;

    tracing::info!(
        npub = %identity.npub(),
        anchor = %anchor_dir.display(),
        sinks = sinks.len(),
        "provisioned NEW DISTRIBUTED per-agent FROST keyset (trusted-dealer 2-of-3; shares sealed to distinct sinks FIRST, anchor LAST; the agent is born with sovereign Q)"
    );

    // (4) ZEROIZE: drop the dealer keyset. Its SecretShares are ZeroizeOnDrop. After this
    //     drop the dealer host retains NO share -- the shares live ONLY in the per-sink
    //     sealed stores. The combined key was already zeroized inside the dealer keygen.
    drop(keyset);

    Ok(identity)
}

/// FAIL-CLOSED validation for the distributed layout: every sink (identifier 1..=n) must
/// currently hold a share that reads + unseals to a well-formed `KeyPackage`. Called when an
/// established anchor is found, so a partial/corrupt distributed keystore over an
/// established Q is a LOUD error rather than a silent regeneration. The shares it reads are
/// dropped immediately (ZeroizeOnDrop) -- no combined-secret materialization, no lingering
/// copy.
fn assert_shares_loadable_from_sinks(sinks: &[&dyn ShareSink]) -> anyhow::Result<()> {
    for (i, sink) in sinks.iter().enumerate() {
        let idx = (i + 1) as u16;
        if !sink.has_share(idx) {
            anyhow::bail!("holder share {idx} missing from sink {:?}", sink.label());
        }
        let bytes = sink
            .get_share(idx)
            .with_context(|| format!("read+unseal share {idx} from sink {:?}", sink.label()))?;
        let _kp: KeyPackage = serde_json::from_slice(&bytes).with_context(|| {
            format!("deserialize holder KeyPackage {idx} from sink {:?}", sink.label())
        })?;
        // `_kp` (ZeroizeOnDrop) drops here, wiping the share scalar it held.
    }
    Ok(())
}

/// Build a live [`QuorumSigner`] from a DISTRIBUTED keyset: read + unseal each sink's share
/// and the node-local group anchor, returning a signer over those shares. The loader
/// counterpart of [`provision_keyset_with_sinks`].
///
/// SCOPE (this chunk): the sealed shares are read back into a co-located [`QuorumSigner`]
/// (the local sealed sinks are still on one box here). The REAL cross-machine signer -- a
/// `QuorumSigner` whose holders are `RemoteHolder`s pointed at `RemoteHolderServer`s that
/// each hold their OWN unsealed share on their OWN machine -- is the deferred network chunk;
/// it wires the SAME sinks to remote holder servers without changing this provisioning body.
/// Here the sink seam handles share STORAGE + at-rest SEALING; chunk 1's `RemoteHolder`
/// already handles the cross-machine SIGNING seam.
pub fn load_quorum_signer_from_sinks(
    anchor_dir: &Path,
    sinks: &[&dyn ShareSink],
) -> anyhow::Result<QuorumSigner> {
    if sinks.len() != SHARE_COUNT as usize {
        anyhow::bail!(
            "loading a distributed quorum signer needs exactly {SHARE_COUNT} sinks, got {}",
            sinks.len()
        );
    }
    if !has_identity_anchor(anchor_dir) {
        anyhow::bail!(
            "distributed FROST keyset anchor {} is not provisioned (no group_pubkeys.json); \
             provision it at spawn before loading a quorum signer",
            anchor_dir.display()
        );
    }
    let identity = FrostIdentity::load(&pubkeys_path(anchor_dir))
        .with_context(|| format!("load group pubkeys from {}", anchor_dir.display()))?;
    let pubkeys: PublicKeyPackage = identity.pubkeys().clone();

    // Read + unseal each sink's share into a KeyPackage (ordered by identifier 1..=n).
    let mut key_packages: Vec<KeyPackage> = Vec::with_capacity(SHARE_COUNT as usize);
    for (i, sink) in sinks.iter().enumerate() {
        let idx = (i + 1) as u16;
        let bytes = sink
            .get_share(idx)
            .with_context(|| format!("read+unseal share {idx} from sink {:?}", sink.label()))?;
        let kp: KeyPackage = serde_json::from_slice(&bytes).with_context(|| {
            format!("deserialize holder KeyPackage {idx} from sink {:?}", sink.label())
        })?;
        key_packages.push(kp);
    }

    QuorumSigner::from_local_key_packages(key_packages, pubkeys)
        .context("build QuorumSigner from the distributed (unsealed) sink shares")
}

// ============================================================================================
// DISTRIBUTED FROST KEYSETS: provision shares to remote holders + sign via RemoteHolders.
//
// The co-located path (`provision_keyset_at` + a `LocalHolders` signer) keeps all 3 shares in one
// local dir on one host. The distributed path keeps the trusted-dealer split but ships share `i`
// to a distinct holder host and signs through a threshold ceremony whose holders live off-box, so
// no single host ever holds enough shares to sign alone. A SELF-DESCRIBING keystore selects which
// path applies:
//
//   * `share_<i>.json` beside the anchor  => CO-LOCATED  (the single-host path)
//   * `placement.json` beside the anchor  => DISTRIBUTED (shares on remote holders)
//
// PROVISION: `provision_keyset_distributed` writes the placement manifest, then ships share `i`
// to sink `i` (one per holder host) via `provision_keyset_with_sinks`.
// SIGN: `load_quorum_signer_distributed` builds the agent's `QuorumSigner` from `RemoteHolder`s
// (one per placement entry, dialed via a `HolderTransportFactory`) -- the same ceremony body, the
// holders just off-box.
//
// THE HARD WALL (the TEE-substitute invariant): the distributed SIGN path builds RemoteHolders and
// unseals NO share into this process. It MUST NOT use `load_quorum_signer_from_sinks` (which
// unseals all 3 shares into `LocalHolder`s here -- the shares come home, so a host reading this
// process's RAM holds a full quorum and the TEE-substitute is gone). At-rest sealed sinks are NOT
// sign-time remote holders. `distributed_sign_materializes_no_share_in_coordinator` is the
// executable tooth that fails if the from-sinks path is ever substituted in.
//
// The orchestration + dispatcher are built against the `ShareSink` + `HolderTransport` /
// `HolderTransportFactory` traits; a relay-native transport + a remote `ShareSink` implement those
// same traits. The holder roster is config-declared via the placement manifest. Re-sharing a live
// keyset to a NEW holder set (a changed roster) is not supported.
// ============================================================================================

/// The placement-manifest file name inside a keystore dir. Its PRESENCE marks the keystore
/// DISTRIBUTED (the self-describing dispatch); its CONTENT is the holder roster the sign path
/// dials. NOT secret (labels + opaque addresses), but written 0600 for a uniform keystore.
const PLACEMENT_FILE: &str = "placement.json";

/// Where ONE holder's share lives in a distributed keyset, and how the sign path reaches it.
/// Persisted (in [`PlacementManifest`]) beside the anchor so the SIGN path -- which runs in the
/// agent's own process and has only the keystore dir -- can rebuild the `RemoteHolder`s without
/// re-running discovery on every sign (beacons fire every presence interval; a per-sign relay
/// round-trip would be far too costly).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HolderPlacement {
    /// The FROST identifier (1..=[`SHARE_COUNT`]) whose share this holder holds.
    pub identifier: u16,
    /// The stable holder label -- IDENTICAL to the share sink's label (the seal domain
    /// separator) so provision-side and sign-side name the same holder.
    pub label: String,
    /// The transport address the sign path dials to reach this holder's `RemoteHolderServer`.
    /// OPAQUE to this crate -- interpreted only by the [`crate::remote_holder::HolderTransportFactory`]
    /// (a relay route in production, a registry key in the in-process tests). The SAME address
    /// names the remote `ShareSink` provisioning ships share `i` to, so provision + sign agree.
    pub address: String,
}

/// The per-agent placement manifest: the full holder roster of a DISTRIBUTED keyset, one entry
/// per FROST identifier, canonically ordered by identifier 1..=[`SHARE_COUNT`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PlacementManifest {
    /// One placement per holder, ordered by identifier (entry `i` is identifier `i+1`).
    pub holders: Vec<HolderPlacement>,
}

impl PlacementManifest {
    /// Validate the manifest SHAPE (the invariants the sign path relies on): exactly
    /// [`SHARE_COUNT`] entries, canonically ordered by identifier 1..=[`SHARE_COUNT`] (a
    /// permutation, no gaps/dupes), and DISTINCT non-empty labels AND addresses. Distinctness is
    /// load-bearing: two shares to one holder (same label/address) would put >= MIN_SIGNERS shares
    /// behind one endpoint, collapsing the threshold there -- the co-located hole the distribution
    /// is meant to close (the TEE-substitute needs each holder below the 2-of-3 threshold; for a
    /// 2-of-3 that means one share per distinct holder). NOTE: distinct ADDRESSES guarantees
    /// distinct ENDPOINTS; that those endpoints are distinct PHYSICAL hosts is the operator's
    /// config-roster responsibility (this layer cannot see physical placement).
    fn validate_shape(&self) -> anyhow::Result<()> {
        if self.holders.len() != SHARE_COUNT as usize {
            anyhow::bail!(
                "placement manifest needs exactly {SHARE_COUNT} holders (one per share), got {}",
                self.holders.len()
            );
        }
        for (i, h) in self.holders.iter().enumerate() {
            let want = (i + 1) as u16;
            if h.identifier != want {
                anyhow::bail!(
                    "placement manifest must be ordered by identifier 1..={SHARE_COUNT}; entry {i} \
                     has identifier {} (expected {want})",
                    h.identifier
                );
            }
            if h.label.trim().is_empty() {
                anyhow::bail!("placement holder {want} has an empty label");
            }
            if h.address.trim().is_empty() {
                anyhow::bail!("placement holder {want} has an empty address");
            }
        }
        for i in 0..self.holders.len() {
            for j in (i + 1)..self.holders.len() {
                if self.holders[i].label == self.holders[j].label {
                    anyhow::bail!(
                        "placement holders {i} and {j} share label {:?}; each holder MUST be \
                         distinct (no holder may hold two shares)",
                        self.holders[i].label
                    );
                }
                if self.holders[i].address == self.holders[j].address {
                    anyhow::bail!(
                        "placement holders {i} and {j} share address {:?}; each holder MUST be a \
                         distinct endpoint (no endpoint may hold two shares)",
                        self.holders[i].address
                    );
                }
            }
        }
        Ok(())
    }
}

/// The placement-manifest path inside a keystore dir.
fn placement_path(keystore_dir: &Path) -> PathBuf {
    keystore_dir.join(PLACEMENT_FILE)
}

/// Whether the keystore at `keystore_dir` is DISTRIBUTED: a placement manifest is present. This
/// is the SELF-DESCRIBING dispatch the sign path keys off (placement.json present = remote
/// holders; absent = co-located `share_<i>.json`). Side-effect-free, so a load site may call it.
pub fn is_distributed_keystore(keystore_dir: &Path) -> bool {
    placement_path(keystore_dir).is_file()
}

/// Persist a placement manifest 0600 (validating its shape first). The keystore dir must exist.
fn save_placement(keystore_dir: &Path, manifest: &PlacementManifest) -> anyhow::Result<()> {
    manifest.validate_shape()?;
    let json = serde_json::to_vec_pretty(manifest).context("serialize placement manifest")?;
    write_file_0600(&placement_path(keystore_dir), &json)
}

/// Load + validate the placement manifest from a keystore dir. Reuses [`read_share_file`]'s
/// bounded + symlink-safe read (a manifest is small JSON), then validates the shape -- a
/// malformed manifest is a LOUD error (never a silent fallback to the co-located path, which has
/// no local shares anyway).
pub fn load_placement(keystore_dir: &Path) -> anyhow::Result<PlacementManifest> {
    let path = placement_path(keystore_dir);
    let bytes = read_share_file(&path)
        .with_context(|| format!("read placement manifest {}", path.display()))?;
    let manifest: PlacementManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("deserialize placement manifest {}", path.display()))?;
    manifest
        .validate_shape()
        .with_context(|| format!("placement manifest {} is malformed", path.display()))?;
    Ok(manifest)
}

/// Load the placement manifest if present (None if the keystore is co-located).
fn try_load_placement(keystore_dir: &Path) -> anyhow::Result<Option<PlacementManifest>> {
    if !is_distributed_keystore(keystore_dir) {
        return Ok(None);
    }
    Ok(Some(load_placement(keystore_dir)?))
}

/// Provision (or idempotently reload) a per-agent FROST keyset whose 3 shares are DISTRIBUTED to
/// `sinks` (one per holder host), recording the holder roster in `placement.json` beside the
/// node-local anchor. Returns the agent's PUBLIC [`FrostIdentity`] (its Q + npub).
///
/// This is the spawn-side flip: it wraps the tested [`provision_keyset_with_sinks`] (which keeps
/// the trusted-dealer split UNCHANGED and the anti-identity-loss invariants) and adds the
/// placement manifest the SIGN path needs. `placement.holders[i]` MUST describe the holder whose
/// share `i+1` goes to `sinks[i]` -- the labels must align (cross-checked below), so the address
/// the sign path later dials names the same holder this provision shipped the share to.
///
/// CRASH-SAFETY (placement BEFORE anchor): [`provision_keyset_with_sinks`] writes the identity
/// ANCHOR last (the "identity established => never regenerate" gate). We write the placement
/// FIRST, so a SURVIVING ANCHOR implies a PRESENT placement -- the distributed analog of the
/// co-located shares-then-anchor ordering. A crash before the anchor leaves no anchor => the next
/// spawn cleanly regenerates (no identity was established), and the agent is never launched
/// against a half-provisioned keystore (the supervisor launches only after this returns `Ok`).
///
/// RE-SHARING TO A NEW HOLDER SET IS NOT SUPPORTED: on a restart with an EXISTING placement that
/// DIFFERS from the provided roster, this FAILS LOUD rather than silently rewriting it (a rewrite
/// would point the
/// sign path at holders that do not hold the shares). A matching placement is an idempotent
/// no-op; an absent one (first spawn, or healing a pre-anchor crash) is written.
pub fn provision_keyset_distributed(
    keystore_dir: &Path,
    placement: &PlacementManifest,
    sinks: &[&dyn ShareSink],
) -> anyhow::Result<FrostIdentity> {
    placement.validate_shape()?;
    if sinks.len() != placement.holders.len() {
        anyhow::bail!(
            "distributed provisioning needs one sink per placement holder ({} placements, {} sinks)",
            placement.holders.len(),
            sinks.len()
        );
    }
    // ALIGNMENT: sink `i` stores identifier `i+1`'s share (the contract of
    // `provision_keyset_with_sinks`); its label MUST equal `placement.holders[i].label`, so the
    // share shipped to sink[i] belongs to the holder the sign path will dial at that entry's
    // address. A misalignment would distribute shares to one set of stores while the sign path
    // dials another -- reject it before any keygen.
    for (i, (h, s)) in placement.holders.iter().zip(sinks.iter()).enumerate() {
        if s.label() != h.label {
            anyhow::bail!(
                "placement/sink misalignment at index {i}: placement holder label {:?} != sink \
                 label {:?} (sink i must store identifier i+1's share for that holder)",
                h.label,
                s.label()
            );
        }
    }

    // The anchor dir must exist before we write the placement (placement BEFORE anchor); on first
    // spawn `provision_keyset_with_sinks` would create it, but we need it now.
    std::fs::create_dir_all(keystore_dir).with_context(|| {
        format!("create per-agent FROST keystore dir {}", keystore_dir.display())
    })?;
    match try_load_placement(keystore_dir)? {
        Some(existing) if existing != *placement => anyhow::bail!(
            "an established placement manifest at {} differs from the provided roster; re-sharing a \
             distributed keyset to a NEW holder set is not supported. Restore the original roster \
             or re-provision from scratch.",
            keystore_dir.display()
        ),
        // A matching established placement (idempotent restart): leave it untouched.
        Some(_) => {}
        // First spawn (or healing a pre-anchor crash): write the placement before the anchor.
        None => save_placement(keystore_dir, placement)?,
    }

    // REMOTE-AWARE RELOAD vs FIRST SPAWN. The identity ANCHOR is the "established Q" gate.
    //   * anchor PRESENT (idempotent restart): validate every holder ATTESTS its share via
    //     `has_share` (a boolean attestation, NOT `get_share`) and reload the SAME Q. A real remote
    //     sink's `get_share` Errs BY DESIGN -- a holder NEVER returns its plaintext share to the
    //     dealer (that would re-centralize all 3 in dealer RAM and kill the TEE-substitute) -- so
    //     the distributed reload MUST gate on the attestation, not on reading the secret. This is
    //     why we do NOT delegate the reload to `provision_keyset_with_sinks`, whose reload branch
    //     unseals via `get_share` (correct only for the LOCAL sealed sink). A missing attestation
    //     over an established anchor is a LOUD error, never a silent new Q.
    //   * anchor ABSENT (first spawn): delegate to the tested primitive. Its first-spawn branch
    //     does trusted-dealer keygen -> `put_share` to each sink -> writes the anchor LAST; it does
    //     NOT call `get_share` on first spawn, so a remote sink is fine there.
    if has_identity_anchor(keystore_dir) {
        let id = FrostIdentity::load(&pubkeys_path(keystore_dir)).with_context(|| {
            format!(
                "reload established distributed FROST identity anchor {} (idempotent restart). The \
                 anchor (group_pubkeys.json) exists, so a sovereign Q was already minted and MUST \
                 NOT be regenerated.",
                keystore_dir.display()
            )
        })?;
        assert_shares_present_across_sinks(sinks).with_context(|| {
            format!(
                "established distributed FROST identity at {} is missing or corrupt at a holder. \
                 The anchor is present, so this agent ALREADY OWNS a sovereign Q -- refusing to \
                 regenerate (that would mint a NEW key and permanently lose this identity + its \
                 funds). RESTORE the missing holder's share.",
                keystore_dir.display()
            )
        })?;
        tracing::info!(
            npub = %id.npub(),
            keystore = %keystore_dir.display(),
            sinks = sinks.len(),
            "reloaded established DISTRIBUTED per-agent FROST keyset (idempotent; same Q; all holders attested via has_share)"
        );
        return Ok(id);
    }

    // FIRST SPAWN: trusted-dealer keygen + distribute via `put_share` + write the anchor LAST (the
    // tested primitive; its first-spawn branch never calls `get_share`, so a remote sink is fine).
    provision_keyset_with_sinks(keystore_dir, sinks)
}

/// REMOTE-AWARE fail-closed validation: every sink (identifier 1..=n) ATTESTS it holds a loadable
/// share via [`ShareSink::has_share`] -- a boolean, WITHOUT reading the secret. For a real remote
/// sink this is a round-trip attestation (the holder unseals + parses locally and replies ok/not),
/// so `true` <=> loadable WITHOUT moving the share; for a [`LocalSealedSink`] it is the sealed
/// file's presence. The distributed RELOAD gates on THIS, NOT on [`assert_shares_loadable_from_sinks`]
/// (which calls `get_share` -> a remote sink Errs by design, since a holder never returns its
/// plaintext share to the dealer). A missing attestation over an established anchor is a LOUD
/// error -- never a silent regeneration of a new Q.
fn assert_shares_present_across_sinks(sinks: &[&dyn ShareSink]) -> anyhow::Result<()> {
    for (i, sink) in sinks.iter().enumerate() {
        let idx = (i + 1) as u16;
        if !sink.has_share(idx) {
            anyhow::bail!(
                "holder share {idx} missing or corrupt at sink {:?} (the holder did not attest a \
                 loadable share)",
                sink.label()
            );
        }
    }
    Ok(())
}

/// Build a live [`QuorumSigner`] for a DISTRIBUTED keyset: load the node-local group anchor and
/// the placement manifest, then build ONE [`crate::remote_holder::RemoteHolder`] per holder,
/// each dialed via `factory` at its placement address. The SAME `QuorumSigner` ceremony body
/// drives it -- the holders just live off-box.
///
/// THE HARD WALL (the TEE-substitute invariant, asserted by
/// `distributed_sign_materializes_no_share_in_coordinator`): this builds RemoteHolders and
/// unseals NO share into this process. A `RemoteHolder` owns no `KeyPackage`/share/nonce -- only
/// the holder's public identifier + a transport handle. So a host that reads THIS process's RAM
/// finds nothing signable; each share stays on its holder, which unseals it on its OWN machine,
/// signs, and returns only the public partial signature. This is why the path MUST NOT reuse
/// [`load_quorum_signer_from_sinks`] (which unseals every share into a `LocalHolder` HERE -- the
/// share comes home, and the cross-machine guarantee is gone). Sealed-sinks (at-rest storage) are
/// NOT remote-holders (sign-time custody): keep the wall hard.
pub fn load_quorum_signer_distributed(
    keystore_dir: &Path,
    factory: &dyn crate::remote_holder::HolderTransportFactory,
) -> anyhow::Result<QuorumSigner> {
    // The group anchor (verifying material) is node-local. A placement present WITHOUT an anchor is
    // a keystore that crashed mid-first-spawn (the agent is never launched in that state) -- fail
    // closed rather than guess.
    if !has_identity_anchor(keystore_dir) {
        anyhow::bail!(
            "distributed FROST keystore {} has a placement manifest but no group anchor \
             (group_pubkeys.json); it is not fully provisioned -- refusing to load (fail closed)",
            keystore_dir.display()
        );
    }
    let identity = FrostIdentity::load(&pubkeys_path(keystore_dir))
        .with_context(|| format!("load group pubkeys from {}", keystore_dir.display()))?;
    let pubkeys: PublicKeyPackage = identity.pubkeys().clone();

    let placement = load_placement(keystore_dir)?;

    // ONE RemoteHolder per placement entry. `factory.connect` fails closed on an unreachable
    // holder; we build the FULL roster (all SHARE_COUNT proxies) and let the QuorumSigner's
    // any-available-2-of-3 selection pick a reachable subset at sign time.
    let mut holders: Vec<Box<dyn crate::quorum_signer::Holder>> =
        Vec::with_capacity(placement.holders.len());
    for h in &placement.holders {
        let transport = factory.connect(&h.address).with_context(|| {
            format!(
                "connect to remote holder {:?} (identifier {}) at address {:?}",
                h.label, h.identifier, h.address
            )
        })?;
        let remote = crate::remote_holder::RemoteHolder::new(h.identifier, transport);
        holders.push(Box::new(remote));
    }

    QuorumSigner::new(holders, pubkeys).context(
        "build distributed QuorumSigner from RemoteHolders (each share stays on its holder; \
         none is unsealed into this process)",
    )
}

/// THE SELF-DESCRIBING SIGN-PATH DISPATCHER: build the agent's [`QuorumSigner`] from its keystore
/// dir, choosing the co-located or distributed loader by the keystore's own shape. This is the
/// single seam the live sign sites (the voice actuator, the beacon signer, the lease signer) call
/// so the all-local vs distributed choice lives in ONE place, not three.
///
///   * `placement.json` present => DISTRIBUTED: build from `RemoteHolder`s via `factory`. A
///     distributed keystore with NO factory supplied is a LOUD error (the sign path cannot reach
///     the remote holders without a transport).
///   * otherwise               => CO-LOCATED: the byte-identical [`load_quorum_signer_at`] path
///     (unchanged; the single-box default needs no factory).
pub fn load_agent_quorum_signer(
    keystore_dir: &Path,
    factory: Option<&dyn crate::remote_holder::HolderTransportFactory>,
) -> anyhow::Result<QuorumSigner> {
    if is_distributed_keystore(keystore_dir) {
        let factory = factory.ok_or_else(|| {
            anyhow::anyhow!(
                "keystore {} is DISTRIBUTED (placement.json present) but no HolderTransportFactory \
                 was supplied -- the sign path needs a transport to reach the remote holders",
                keystore_dir.display()
            )
        })?;
        load_quorum_signer_distributed(keystore_dir, factory)
    } else {
        load_quorum_signer_at(keystore_dir)
    }
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

    /// G-4 FAILOVER ADMISSION GATE: `keystore_loadable_at` is the cross-machine boundary the
    /// failover scan gates on. It is TRUE only for a node that actually holds the agent's full
    /// quorum (anchor + all 3 shares loadable), and FALSE for an absent keystore (a DIFFERENT node
    /// that never provisioned the agent — the G-2 boundary) AND for a partial/corrupt one (anchor
    /// present but a share missing). So a node only ever takes over an agent it can FROST-sign for.
    #[test]
    fn keystore_loadable_gate_true_only_when_this_node_holds_the_quorum() {
        // (a) ABSENT keystore (a peer's agent this node never provisioned) => NOT loadable.
        let absent = temp_keystore("loadable-absent");
        assert!(
            !keystore_loadable_at(&absent),
            "an absent keystore (the cross-machine case) must NOT be loadable (the scan SKIPS it)"
        );

        // (b) FULLY provisioned on THIS node => loadable (a same-host takeover can sign as it).
        let full = temp_keystore("loadable-full");
        provision_keyset_at(&full).expect("provision");
        assert!(keystore_loadable_at(&full), "a complete keystore on this node must be loadable");

        // (c) PARTIAL: the identity anchor survives but a holder share is removed => NOT loadable
        //     (a node missing a share cannot complete the 2-of-3 sign, so it must not claim).
        std::fs::remove_file(share_path(&full, 1)).expect("remove a share");
        assert!(
            !keystore_loadable_at(&full),
            "a keystore missing a holder share must NOT be loadable even with the anchor present"
        );

        let _ = std::fs::remove_dir_all(&absent);
        let _ = std::fs::remove_dir_all(&full);
        println!("G-4-LOADABLE-GATE PASS: loadable only when this node holds anchor + all 3 shares");
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

    /// FIX 1 (CATASTROPHIC case, fail-closed): an ESTABLISHED keystore (identity anchor +
    /// shares) with ONE holder share deleted must make `provision_keyset_at` FAIL LOUD — it must
    /// NOT silently regenerate a NEW Q. This is the exact silent-key-regeneration the adversarial
    /// verifier empirically reproduced: a surviving `group_pubkeys.json` with a missing share
    /// previously fell through to regeneration, minting a new sovereign key and permanently losing
    /// the agent's identity + funds. We assert (a) provisioning ERRORS, (b) the surviving anchor
    /// is UNTOUCHED (the original Q is preserved on disk for an operator restore), and (c) the
    /// surviving shares are byte-identical (no regeneration occurred).
    #[test]
    fn provision_fails_closed_on_missing_share_over_established_anchor() {
        let dir = temp_keystore("failclosed");

        // Establish an identity: full keystore (anchor + 3 shares), capture the original Q.
        let id1 = provision_keyset_at(&dir).expect("first spawn establishes the identity");
        let q1 = id1.q_bytes();
        let anchor_before = std::fs::read(pubkeys_path(&dir)).expect("read anchor before");
        let surviving_shares_before: Vec<(u16, Vec<u8>)> = [1u16, 3u16]
            .into_iter()
            .map(|idx| (idx, std::fs::read(share_path(&dir, idx)).expect("read surviving share")))
            .collect();

        // Catastrophe: delete ONE holder share, leaving the identity anchor intact.
        std::fs::remove_file(share_path(&dir, 2)).expect("delete share 2");

        // FAIL-CLOSED: provisioning over an established anchor with a missing share must ERROR,
        // never regenerate.
        // `.map(|_| ())` drops the Ok payload (FrostIdentity isn't Debug) so `expect_err` works.
        let err = provision_keyset_at(&dir)
            .map(|_| ())
            .expect_err("a missing share over an established anchor MUST fail closed, not regenerate");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing or corrupt") || msg.to_lowercase().contains("restore"),
            "the error must tell the operator to restore the keystore, got: {msg}"
        );

        // The identity anchor is UNTOUCHED — no new Q was minted over the established identity.
        let anchor_after = std::fs::read(pubkeys_path(&dir)).expect("read anchor after");
        assert_eq!(anchor_before, anchor_after, "the identity anchor must NOT be rewritten (no regen)");
        let reloaded = FrostIdentity::load(&pubkeys_path(&dir)).expect("anchor still loads");
        assert_eq!(reloaded.q_bytes(), q1, "the original sovereign Q must be preserved (no new key)");

        // The surviving shares were NOT rewritten (no regeneration cycle ran).
        for (idx, before) in &surviving_shares_before {
            let after = std::fs::read(share_path(&dir, *idx)).expect("read surviving share after");
            assert_eq!(before, &after, "surviving share_{idx} must be byte-identical (no regen)");
        }
        // The deleted share is still absent (we did not silently re-mint it under a new key).
        assert!(!share_path(&dir, 2).exists(), "the missing share must stay missing (fail closed, not regen)");

        let _ = std::fs::remove_dir_all(&dir);
        println!(
            "FIX-1 FAIL-CLOSED PASS: missing share over an established anchor errors loudly; \
             original Q preserved; NO new key minted"
        );
    }

    /// FIX 4 (symlink-safety): a planted SYMLINK at a share path is rejected on read (the loader
    /// refuses to read key material through a link), so a hostile symlink cannot redirect a key
    /// read to an attacker-chosen target.
    #[test]
    #[cfg(unix)]
    fn read_share_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = temp_keystore("symlink");
        provision_keyset_at(&dir).expect("provision");

        // Replace share_1 with a symlink to share_3 (a benign target; the point is the link is
        // rejected regardless of where it points).
        let s1 = share_path(&dir, 1);
        std::fs::remove_file(&s1).expect("remove real share 1");
        symlink(share_path(&dir, 3), &s1).expect("plant symlink at share 1");

        let err = read_share_file(&s1).expect_err("a symlinked share must be rejected");
        assert!(
            format!("{err:#}").to_uppercase().contains("SYMLINK"),
            "the error must name the symlink rejection, got: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        println!("FIX-4 PASS: a symlinked share path is rejected on read");
    }

    /// FIX 4 (symlink-safety, write side): `write_file_0600` refuses to write key material
    /// through a pre-existing symlink (so a planted link can't redirect a key WRITE).
    #[test]
    #[cfg(unix)]
    fn write_rejects_symlink_target() {
        use std::os::unix::fs::symlink;
        let dir = temp_keystore("writesymlink");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("decoy.txt");
        let link = dir.join("share_planted.json");
        symlink(&target, &link).expect("plant symlink");
        let err = write_file_0600(&link, b"secret").expect_err("writing through a symlink must be rejected");
        assert!(
            format!("{err:#}").to_uppercase().contains("SYMLINK"),
            "the write error must name the symlink rejection, got: {err:#}"
        );
        assert!(!target.exists(), "no bytes must have been written through the link");
        let _ = std::fs::remove_dir_all(&dir);
        println!("FIX-4 PASS (write): writing key material through a symlink is rejected");
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

    // ========================================================================================
    // S5/S6 chunk 3: DISTRIBUTED PROVISIONING teeth (the sink seam + at-rest sealing).
    // ========================================================================================

    use crate::share_seal::FixedBinding;

    /// A distinct sink root under temp, holding the 3 per-holder sink dirs + the node-local
    /// anchor dir. The 3 sinks each get a DIFFERENT FixedBinding so they model 3 distinct
    /// machines (sink i's seal key is unrelated to sink j's). Returns (anchor_dir, [dir1,2,3]).
    fn dist_dirs(tag: &str) -> (PathBuf, [PathBuf; 3]) {
        let root = std::env::temp_dir().join(format!(
            "kirby-s3d-dist-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let anchor = root.join("anchor");
        let sinks = [root.join("sink-1"), root.join("sink-2"), root.join("sink-3")];
        (anchor, sinks)
    }

    /// Build the 3 sealed sinks over `dirs`, each on its own "machine" (distinct binding +
    /// distinct label). Returned owned so the caller can borrow them as `&dyn ShareSink`.
    fn sealed_sinks(dirs: &[PathBuf; 3]) -> Vec<LocalSealedSink<FixedBinding>> {
        (0..3)
            .map(|i| {
                LocalSealedSink::open_with_binding(
                    dirs[i].clone(),
                    format!("holder-{}", i + 1),
                    FixedBinding(format!("machine-{}-binding-secret", i + 1).into_bytes()),
                )
                .expect("open sealed sink")
            })
            .collect()
    }

    fn as_dyn(sinks: &[LocalSealedSink<FixedBinding>]) -> Vec<&dyn ShareSink> {
        sinks.iter().map(|s| s as &dyn ShareSink).collect()
    }

    /// TEETH (no-sink-holds-2 + dealer-retains-0): after distributed provisioning, each of
    /// the 3 sinks holds EXACTLY ONE share and the dealer's anchor dir holds ZERO shares
    /// (only the public group_pubkeys.json). The combined key is materialized nowhere.
    #[test]
    fn distributed_provisioning_one_share_per_sink_dealer_retains_none() {
        let (anchor, dirs) = dist_dirs("oneeach");
        let sinks = sealed_sinks(&dirs);
        let id = provision_keyset_with_sinks(&anchor, &as_dyn(&sinks))
            .expect("distributed first spawn provisions");
        assert!(id.npub().starts_with("npub1"), "npub must encode");

        // NO SINK HOLDS 2: each sink dir has exactly its own share_<i>.sealed and no other
        // share_*.sealed (no sink received a second share).
        for (i, sink) in sinks.iter().enumerate() {
            let idx = (i + 1) as u16;
            assert!(sink.has_share(idx), "sink {} must hold its own share {idx}", sink.label());
            // It must NOT hold any OTHER holder's share.
            for other in 1..=3u16 {
                if other != idx {
                    assert!(
                        !sealed_share_path(sink.dir(), other).is_file(),
                        "sink {} (holds share {idx}) must NOT also hold share {other}",
                        sink.label()
                    );
                }
            }
            // Count *.sealed files in the dir == 1 (exactly one share).
            let sealed_count = std::fs::read_dir(sink.dir())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sealed"))
                .count();
            assert_eq!(sealed_count, 1, "sink {} must hold exactly ONE sealed share", sink.label());
        }

        // DEALER RETAINS 0: the anchor dir holds the public anchor but NO share material
        // (no share_*.json from the co-located layout, no *.sealed from a sink). The dealer
        // host keeps nothing signable after distribution.
        assert!(pubkeys_path(&anchor).is_file(), "the anchor (group_pubkeys.json) is node-local");
        for entry in std::fs::read_dir(&anchor).unwrap().filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.starts_with("share_") && !name.ends_with(".sealed"),
                "the dealer anchor dir must hold NO share material, found {name}"
            );
        }
        // The anchor dir is exactly {group_pubkeys.json}.
        let anchor_entries: Vec<String> = std::fs::read_dir(&anchor)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(anchor_entries, vec![PUBKEYS_FILE.to_string()], "anchor dir = only the pubkeys anchor");

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("DIST-ONE-SHARE-PER-SINK PASS: 3 sinks hold 1 share each; dealer anchor dir holds 0 shares");
    }

    /// TEETH (sealed-at-rest): a RAW byte read of a sink's stored share file does NOT contain
    /// the plaintext KeyPackage (it is actually AEAD-sealed, not just renamed). We prove it by
    /// deriving the SAME plaintext the provisioner would store (the share KeyPackage JSON for
    /// that identifier) is NOT a substring of the sealed bytes -- and that the sealed bytes DO
    /// unseal back to a valid KeyPackage via the sink's own get_share.
    #[test]
    fn distributed_shares_are_sealed_at_rest_not_plaintext() {
        let (anchor, dirs) = dist_dirs("sealed");
        let sinks = sealed_sinks(&dirs);
        provision_keyset_with_sinks(&anchor, &as_dyn(&sinks)).expect("provision");

        for (i, sink) in sinks.iter().enumerate() {
            let idx = (i + 1) as u16;
            let raw = std::fs::read(sealed_share_path(sink.dir(), idx)).expect("read raw sealed share");

            // The unsealed plaintext (what the sink would return) really IS a KeyPackage.
            let plaintext = sink.get_share(idx).expect("unseal share");
            let _kp: KeyPackage = serde_json::from_slice(&plaintext).expect("unsealed is a KeyPackage");

            // SEALED, NOT RENAMED: the raw on-disk bytes do NOT contain the plaintext verbatim.
            assert!(
                !contains(&raw, &plaintext),
                "sink {} raw bytes contain the unsealed plaintext verbatim -- NOT sealed!",
                sink.label()
            );
            // And the raw bytes do NOT even parse as a KeyPackage (so it is not stored as a
            // re-encoded-but-cleartext blob): a sealed body is opaque ciphertext.
            assert!(
                serde_json::from_slice::<KeyPackage>(&raw).is_err(),
                "sink {} raw bytes parse as a cleartext KeyPackage -- NOT sealed!",
                sink.label()
            );
            // Derive the plaintext JSON's OWN top-level field names + values and assert NONE
            // of them appear verbatim in the sealed body (robust regardless of the exact frost
            // serde field names; if the share were plaintext these byte runs would be present).
            let v: serde_json::Value = serde_json::from_slice(&plaintext).expect("plaintext is JSON");
            if let Some(obj) = v.as_object() {
                assert!(!obj.is_empty(), "a KeyPackage JSON object should have fields");
                for (k, val) in obj {
                    assert!(
                        !contains(&raw, k.as_bytes()),
                        "sink {} raw bytes contain plaintext field name {k:?} -- NOT sealed!",
                        sink.label()
                    );
                    // String values (the hex-encoded share scalar etc.) must also be absent.
                    if let Some(s) = val.as_str() {
                        if s.len() >= 8 {
                            assert!(
                                !contains(&raw, s.as_bytes()),
                                "sink {} raw bytes contain a plaintext field VALUE -- NOT sealed!",
                                sink.label()
                            );
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("DIST-SEALED-AT-REST PASS: every sink's stored share is AEAD-sealed (no plaintext KeyPackage on disk)");
    }

    /// TEETH (reload -> same Q, idempotent): provision distributed, then re-provision (a
    /// restart) -> the SAME Q/npub, no regeneration; and a quorum signer loaded from the
    /// unsealed sinks signs a note that verifies under that SAME persistent Q.
    #[test]
    fn distributed_reload_yields_same_q_and_signs_under_it() {
        let (anchor, dirs) = dist_dirs("reload");
        let sinks = sealed_sinks(&dirs);

        let id1 = provision_keyset_with_sinks(&anchor, &as_dyn(&sinks)).expect("first spawn");
        let q1 = id1.q_bytes();
        let npub1 = id1.npub();

        // Capture the sealed share bytes before the restart (a regen would change them).
        let sealed_before: Vec<Vec<u8>> = (1..=3u16)
            .map(|idx| std::fs::read(sealed_share_path(&dirs[idx as usize - 1], idx)).unwrap())
            .collect();

        // Restart: re-provision over the same anchor + sinks -> RELOAD, not regenerate.
        let sinks2 = sealed_sinks(&dirs);
        let id2 = provision_keyset_with_sinks(&anchor, &as_dyn(&sinks2)).expect("restart reloads");
        assert_eq!(q1, id2.q_bytes(), "Q must be identical across restart (no regeneration)");
        assert_eq!(npub1, id2.npub(), "npub must be identical across restart");

        // The sealed shares were NOT rewritten on reload (byte-identical => no regen).
        for (idx, before) in sealed_before.iter().enumerate() {
            let after = std::fs::read(sealed_share_path(&dirs[idx], (idx + 1) as u16)).unwrap();
            assert_eq!(before, &after, "sealed share {} must be byte-identical on reload", idx + 1);
        }

        // Load a quorum signer from the unsealed sinks; it signs under the SAME persistent Q.
        let sinks3 = sealed_sinks(&dirs);
        let signer =
            load_quorum_signer_from_sinks(&anchor, &as_dyn(&sinks3)).expect("load signer from sinks");
        assert_eq!(signer.q_bytes(), q1, "the loaded signer's Q must be the persistent distributed Q");

        let event = signer
            .sign_nostr_event(1, 1_750_000_000, "Sovereign across distinct sealed sinks.")
            .expect("the distributed quorum signs");
        assert_eq!(event.pubkey, hex::encode(q1), "event pubkey must be the persistent Q");

        // Independently verify the aggregate under the tweaked Q.
        let pubkeys = FrostIdentity::load(&pubkeys_path(&anchor)).unwrap().pubkeys().clone();
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
            "the distributed aggregate must verify under the persistent (tweaked) Q"
        );

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("DIST-RELOAD-SAME-Q PASS: restart yields the same Q (no regen); unsealed sinks sign verifying under it");
    }

    /// TEETH (fail-closed preserved, the catastrophic case ported to the sink layout): an
    /// ESTABLISHED distributed keyset (anchor + 3 sealed sinks) with ONE sink's share DELETED
    /// must make `provision_keyset_with_sinks` FAIL LOUD -- it must NEVER silently regenerate a
    /// new Q. We assert (a) it errors with a restore message, (b) the anchor is untouched (the
    /// original Q is preserved on disk), and (c) the surviving sinks' sealed shares are
    /// byte-identical (no regeneration ran).
    #[test]
    fn distributed_fails_closed_on_missing_share_over_established_anchor() {
        let (anchor, dirs) = dist_dirs("failclosed");
        let sinks = sealed_sinks(&dirs);
        let id1 = provision_keyset_with_sinks(&anchor, &as_dyn(&sinks)).expect("establish identity");
        let q1 = id1.q_bytes();
        let anchor_before = std::fs::read(pubkeys_path(&anchor)).expect("read anchor before");
        let surviving_before: Vec<(u16, Vec<u8>)> = [1u16, 3u16]
            .into_iter()
            .map(|idx| (idx, std::fs::read(sealed_share_path(&dirs[idx as usize - 1], idx)).unwrap()))
            .collect();

        // Catastrophe: delete sink 2's sealed share, leaving the anchor intact.
        std::fs::remove_file(sealed_share_path(&dirs[1], 2)).expect("delete sink 2 share");

        // FAIL-CLOSED: provisioning over an established anchor with a missing share must ERROR.
        let sinks2 = sealed_sinks(&dirs);
        let err = provision_keyset_with_sinks(&anchor, &as_dyn(&sinks2))
            .map(|_| ())
            .expect_err("a missing sink share over an established anchor MUST fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing or corrupt") || msg.to_lowercase().contains("restore"),
            "the error must tell the operator to restore the sink, got: {msg}"
        );

        // The anchor is UNTOUCHED -- no new Q minted over the established identity.
        let anchor_after = std::fs::read(pubkeys_path(&anchor)).expect("read anchor after");
        assert_eq!(anchor_before, anchor_after, "the anchor must NOT be rewritten (no regen)");
        let reloaded = FrostIdentity::load(&pubkeys_path(&anchor)).expect("anchor still loads");
        assert_eq!(reloaded.q_bytes(), q1, "the original sovereign Q must be preserved (no new key)");

        // The surviving sinks were NOT rewritten (no regeneration cycle ran).
        for (idx, before) in &surviving_before {
            let after = std::fs::read(sealed_share_path(&dirs[*idx as usize - 1], *idx)).unwrap();
            assert_eq!(before, &after, "surviving sink share {idx} must be byte-identical (no regen)");
        }
        // The deleted share is still absent.
        assert!(!sealed_share_path(&dirs[1], 2).exists(), "the missing share stays missing (no re-mint)");

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("DIST-FAIL-CLOSED PASS: a missing sink share over an established anchor errors loudly; original Q preserved; NO new key minted");
    }

    /// TEETH (fail-closed on a CORRUPT/unsealable share): an established anchor with a sink
    /// whose sealed share is TAMPERED (cannot unseal) must also fail closed -- the unseal tag
    /// mismatch surfaces as a loud error, never a silent regeneration.
    #[test]
    fn distributed_fails_closed_on_corrupt_sealed_share() {
        let (anchor, dirs) = dist_dirs("corrupt");
        let sinks = sealed_sinks(&dirs);
        let id1 = provision_keyset_with_sinks(&anchor, &as_dyn(&sinks)).expect("establish identity");
        let q1 = id1.q_bytes();

        // Corrupt sink 3's sealed share (flip a ciphertext byte) so it cannot unseal.
        let p = sealed_share_path(&dirs[2], 3);
        let mut bytes = std::fs::read(&p).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        write_file_0600(&p, &bytes).expect("write corrupted sealed share");

        let sinks2 = sealed_sinks(&dirs);
        let err = provision_keyset_with_sinks(&anchor, &as_dyn(&sinks2))
            .map(|_| ())
            .expect_err("a corrupt (unsealable) sink share over an established anchor MUST fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.to_lowercase().contains("restore") || msg.contains("missing or corrupt") || msg.contains("tag mismatch"),
            "the error must be a loud unseal/restore failure, got: {msg}"
        );
        // Anchor + Q preserved.
        let reloaded = FrostIdentity::load(&pubkeys_path(&anchor)).expect("anchor still loads");
        assert_eq!(reloaded.q_bytes(), q1, "the original sovereign Q must be preserved (no new key)");

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("DIST-CORRUPT-SHARE-FAIL-CLOSED PASS: an unsealable sink share over an established anchor errors loudly; Q preserved");
    }

    /// TEETH (sink-set hygiene): provisioning rejects a duplicated sink (two shares to one
    /// store would re-create the co-located hole) and a wrong-count sink set, before any
    /// keygen.
    #[test]
    fn distributed_rejects_duplicate_or_wrong_count_sinks() {
        let (anchor, dirs) = dist_dirs("hygiene");
        // Two sinks with the SAME label -> rejected.
        let dup = vec![
            LocalSealedSink::open_with_binding(dirs[0].clone(), "holder-1", FixedBinding(b"m1".to_vec())).unwrap(),
            LocalSealedSink::open_with_binding(dirs[1].clone(), "holder-1", FixedBinding(b"m2".to_vec())).unwrap(),
            LocalSealedSink::open_with_binding(dirs[2].clone(), "holder-3", FixedBinding(b"m3".to_vec())).unwrap(),
        ];
        let dyn_dup: Vec<&dyn ShareSink> = dup.iter().map(|s| s as &dyn ShareSink).collect();
        assert!(
            provision_keyset_with_sinks(&anchor, &dyn_dup).is_err(),
            "two sinks sharing a label must be rejected (no sink may hold two shares)"
        );
        // Wrong count (2 sinks for a 2-of-3) -> rejected.
        let two = sealed_sinks(&dirs);
        let dyn_two: Vec<&dyn ShareSink> = two.iter().take(2).map(|s| s as &dyn ShareSink).collect();
        assert!(
            provision_keyset_with_sinks(&anchor, &dyn_two).is_err(),
            "a sink set that is not exactly SHARE_COUNT must be rejected"
        );
        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("DIST-SINK-HYGIENE PASS: duplicate-label + wrong-count sink sets are rejected before keygen");
    }

    // ========================================================================================
    // DISTRIBUTED FROST KEYSETS: placement manifest, distributed-provision orchestration,
    // distributed sign loader (RemoteHolders), and the self-describing dispatcher.
    // ========================================================================================

    /// The placement manifest aligned with [`sealed_sinks`] (labels `holder-1/2/3`), giving each
    /// holder a distinct in-process address the [`InProcessHolderFleet`] registers servers at.
    fn placement_for_sealed_sinks() -> PlacementManifest {
        PlacementManifest {
            holders: (1..=SHARE_COUNT)
                .map(|id| HolderPlacement {
                    identifier: id,
                    label: format!("holder-{id}"),
                    address: format!("inproc://holder-{id}"),
                })
                .collect(),
        }
    }

    /// Stand up an in-process "holder fleet": each holder server unseals ITS OWN share from ITS
    /// OWN sink (modeling a holder host loading its share on its own machine) and is registered at
    /// the placement address the distributed loader will dial. The coordinator never sees these
    /// shares -- it only gets `RemoteHolder` proxies back through the factory.
    fn build_inproc_fleet(
        anchor: &Path,
        sinks: &[LocalSealedSink<FixedBinding>],
    ) -> crate::remote_holder::InProcessHolderFleet {
        use crate::remote_holder::{InProcessHolderFleet, RemoteHolderServer};
        let pubkeys = FrostIdentity::load(&pubkeys_path(anchor)).unwrap().pubkeys().clone();
        let mut fleet = InProcessHolderFleet::new();
        for (i, sink) in sinks.iter().enumerate() {
            let idx = (i + 1) as u16;
            let bytes = sink.get_share(idx).expect("unseal share for the holder's server");
            let kp: KeyPackage = serde_json::from_slice(&bytes).expect("share is a KeyPackage");
            let server = std::sync::Arc::new(RemoteHolderServer::new(kp, pubkeys.clone()));
            fleet.register(format!("inproc://holder-{idx}"), server);
        }
        fleet
    }

    /// Independently verify a signed event's aggregate under the tweaked group Q loaded from the
    /// anchor.
    fn assert_event_verifies_under_q(
        event: &kirby_custody::cosign_net::NostrEvent,
        anchor: &Path,
    ) {
        let pubkeys = FrostIdentity::load(&pubkeys_path(anchor)).unwrap().pubkeys().clone();
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
            "the distributed aggregate must verify under the tweaked group Q"
        );
    }

    /// A distributed spawn lands EXACTLY ONE share per sink across the 3 distinct
    /// sinks (none co-located), the dealer's keystore dir retains NO share, and the placement
    /// manifest is written + correct. RED-on-revert: if the orchestration ever wrote shares
    /// locally (the `provision_keyset_at` path) or skipped the manifest, this fails.
    #[test]
    fn distributed_spawn_lands_one_share_per_sink_and_writes_placement() {
        let (anchor, dirs) = dist_dirs("flip-oneeach");
        let sinks = sealed_sinks(&dirs);
        let placement = placement_for_sealed_sinks();

        let id = provision_keyset_distributed(&anchor, &placement, &as_dyn(&sinks))
            .expect("distributed spawn provisions");
        assert!(id.npub().starts_with("npub1"), "npub must encode");

        // ONE share per sink, none anywhere else.
        for (i, sink) in sinks.iter().enumerate() {
            let idx = (i + 1) as u16;
            assert!(sink.has_share(idx), "sink {} must hold its own share {idx}", sink.label());
            let sealed_count = std::fs::read_dir(sink.dir())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sealed"))
                .count();
            assert_eq!(sealed_count, 1, "sink {} must hold exactly ONE sealed share", sink.label());
        }

        // The keystore (anchor) dir holds the anchor + the placement manifest, and NO share
        // material (no co-located share_*.json, no *.sealed). The dealer host keeps nothing
        // signable -- this is the whole point of the flip.
        assert!(pubkeys_path(&anchor).is_file(), "the group anchor is node-local");
        assert!(is_distributed_keystore(&anchor), "placement.json marks the keystore distributed");
        for entry in std::fs::read_dir(&anchor).unwrap().filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.starts_with("share_") && !name.ends_with(".sealed"),
                "the keystore dir must hold NO share material after a distributed spawn, found {name}"
            );
        }
        let anchor_entries: std::collections::BTreeSet<String> = std::fs::read_dir(&anchor)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            anchor_entries,
            [PUBKEYS_FILE.to_string(), PLACEMENT_FILE.to_string()].into_iter().collect(),
            "the distributed keystore dir = exactly {{anchor, placement}}"
        );

        // The placement manifest round-trips to what we provisioned.
        let loaded = load_placement(&anchor).expect("placement loads");
        assert_eq!(loaded, placement, "the persisted placement must equal the provisioned roster");

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("FLIP-ONE-SHARE-PER-SINK PASS: distributed spawn ships 1 share/sink across 3 sinks; keystore dir holds only {{anchor, placement}}");
    }

    /// THE KEYSTONE: a DISTRIBUTED-keystore agent co-signs a Q-valid signature
    /// via `RemoteHolder`s loaded by `load_quorum_signer_distributed` -- the same ceremony body,
    /// holders off-box. RED-on-revert: if the loader built `LocalHolder`s or the wrong Q, the
    /// aggregate would not verify under the persistent distributed Q.
    #[test]
    fn distributed_keystore_agent_cosigns_q_valid_via_remote_holders() {
        let (anchor, dirs) = dist_dirs("flip-sign");
        let sinks = sealed_sinks(&dirs);
        let placement = placement_for_sealed_sinks();
        let id = provision_keyset_distributed(&anchor, &placement, &as_dyn(&sinks)).expect("provision");

        // The holders stand up off-box (each unseals its own share); the coordinator dials them.
        let fleet = build_inproc_fleet(&anchor, &sinks);
        let signer = load_quorum_signer_distributed(&anchor, &fleet)
            .expect("build distributed signer from RemoteHolders");
        assert_eq!(signer.q_bytes(), id.q_bytes(), "the distributed signer's Q is the agent's Q");

        let event = signer
            .sign_nostr_event(1, 1_750_000_000, "Sovereign across distinct remote holders.")
            .expect("the distributed quorum co-signs via RemoteHolders");
        assert_eq!(event.pubkey, hex::encode(id.q_bytes()), "event pubkey is the agent's Q");
        assert_event_verifies_under_q(&event, &anchor);

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("FLIP-REMOTE-SIGN PASS: a distributed-keystore agent co-signs a Q-valid note via RemoteHolders (off-box quorum)");
    }

    /// THE TEE-SUBSTITUTE INVARIANT, AS TEETH: the distributed SIGN path materializes NO
    /// share in the coordinator process -- it dials the holders and never reads the local sinks.
    /// We prove it by DELETING every sink's stored share AFTER the holders are stood up, then
    /// loading + signing through `load_quorum_signer_distributed`: it STILL produces a Q-valid
    /// signature (the shares live on the holders, not in any sink the coordinator reads). The
    /// contrast assertion makes the revert explicit: `load_quorum_signer_from_sinks` (the
    /// shares-come-home path) FAILS once the sinks are gone. So if anyone swaps the distributed
    /// loader to the from-sinks/unseal path, THIS test goes RED. Sealed-sinks != remote-holders.
    #[test]
    fn distributed_sign_materializes_no_share_in_coordinator() {
        let (anchor, dirs) = dist_dirs("flip-noshare");
        let sinks = sealed_sinks(&dirs);
        let placement = placement_for_sealed_sinks();
        let id = provision_keyset_distributed(&anchor, &placement, &as_dyn(&sinks)).expect("provision");

        // Holders load their shares onto their own "machines" (the servers hold the KeyPackages
        // in memory now), THEN we remove every share from local storage.
        let fleet = build_inproc_fleet(&anchor, &sinks);
        for (i, _sink) in sinks.iter().enumerate() {
            let idx = (i + 1) as u16;
            std::fs::remove_file(sealed_share_path(&dirs[i], idx)).expect("delete the local sink share");
        }

        // CONTRAST (makes the revert RED): the shares-come-home path is now DEAD -- it would read
        // the (deleted) sinks. A revert of the distributed loader to this path fails here.
        let sinks_gone = sealed_sinks(&dirs);
        assert!(
            load_quorum_signer_from_sinks(&anchor, &as_dyn(&sinks_gone)).is_err(),
            "with the local sink shares deleted, the from-sinks (shares-come-home) loader MUST fail \
             -- proving the distributed sign path below does NOT use it"
        );

        // THE DISTRIBUTED PATH STILL SIGNS: it reads only the anchor + placement and dials the
        // holders; no share is unsealed into THIS process.
        let signer = load_quorum_signer_distributed(&anchor, &fleet)
            .expect("distributed signer builds without touching the (deleted) local sinks");
        let event = signer
            .sign_nostr_event(1, 1_750_000_000, "No share comes home.")
            .expect("the off-box quorum signs despite the local sinks being gone");
        assert_eq!(event.pubkey, hex::encode(id.q_bytes()));
        assert_event_verifies_under_q(&event, &anchor);

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("FLIP-NO-SHARE-HOME PASS: distributed sign works with local sinks DELETED (RemoteHolders); the from-sinks path fails -> the TEE-substitute wall holds");
    }

    /// A fail-closed reload over a missing holder share. An ESTABLISHED
    /// distributed identity (anchor + placement + 3 sealed sinks) with ONE sink's share DELETED
    /// must make `provision_keyset_distributed` FAIL LOUD on the next spawn -- never silently mint
    /// a new Q. The anchor + placement + surviving shares are preserved.
    #[test]
    fn distributed_provision_fails_closed_on_missing_share_over_established_identity() {
        let (anchor, dirs) = dist_dirs("flip-failclosed");
        let sinks = sealed_sinks(&dirs);
        let placement = placement_for_sealed_sinks();
        let id1 = provision_keyset_distributed(&anchor, &placement, &as_dyn(&sinks)).expect("establish");
        let q1 = id1.q_bytes();
        let anchor_before = std::fs::read(pubkeys_path(&anchor)).expect("anchor before");
        let placement_before = std::fs::read(placement_path(&anchor)).expect("placement before");

        // Catastrophe: delete sink 2's share, leaving the anchor + placement intact.
        std::fs::remove_file(sealed_share_path(&dirs[1], 2)).expect("delete sink 2 share");

        // FAIL-CLOSED: re-provisioning over the established identity with a missing share errors.
        let sinks2 = sealed_sinks(&dirs);
        let err = provision_keyset_distributed(&anchor, &placement, &as_dyn(&sinks2))
            .map(|_| ())
            .expect_err("a missing holder share over an established distributed identity MUST fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing or corrupt") || msg.to_lowercase().contains("restore"),
            "the error must tell the operator to restore the holder share, got: {msg}"
        );

        // Anchor + placement + Q preserved (no regeneration ran).
        assert_eq!(anchor_before, std::fs::read(pubkeys_path(&anchor)).unwrap(), "anchor untouched");
        assert_eq!(placement_before, std::fs::read(placement_path(&anchor)).unwrap(), "placement untouched");
        assert_eq!(
            FrostIdentity::load(&pubkeys_path(&anchor)).unwrap().q_bytes(),
            q1,
            "the original sovereign Q must be preserved (no new key minted)"
        );

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("FLIP-FAIL-CLOSED PASS: a missing holder share over an established distributed identity errors loudly; anchor/placement/Q preserved");
    }

    /// The CO-LOCATED default path is unchanged, and the self-describing
    /// dispatcher routes to it. A `provision_keyset_at` keystore (no placement) is NOT
    /// distributed, and `load_agent_quorum_signer(dir, None)` (no transport factory) loads the
    /// co-located signer and signs a Q-valid note -- byte-identical to today.
    #[test]
    fn colocated_default_path_unchanged_and_dispatcher_routes_to_it() {
        let dir = temp_keystore("flip-colocated");
        let id = provision_keyset_at(&dir).expect("co-located provision (today's default)");

        // NOT distributed: no placement.json; the co-located share files are present.
        assert!(!is_distributed_keystore(&dir), "a co-located keystore must NOT look distributed");
        assert!(!placement_path(&dir).exists(), "no placement manifest for a co-located keystore");
        for idx in 1..=SHARE_COUNT {
            assert!(share_path(&dir, idx).is_file(), "co-located share_{idx}.json must exist");
        }

        // The dispatcher routes to the co-located loader WITHOUT a factory (None is fine here).
        let signer = load_agent_quorum_signer(&dir, None)
            .expect("dispatcher loads the co-located signer with no transport factory");
        assert_eq!(signer.q_bytes(), id.q_bytes(), "dispatcher signer Q matches the co-located identity");
        let event = signer
            .sign_nostr_event(1, 1_750_000_000, "Co-located default still signs.")
            .expect("the co-located quorum signs");
        assert_eq!(event.pubkey, hex::encode(id.q_bytes()));
        assert_event_verifies_under_q(&event, &dir);

        // And a distributed keystore through the dispatcher with NO factory is a LOUD error (it
        // cannot reach the remote holders) -- it must never silently fall back to co-located.
        let (anchor, dirs) = dist_dirs("flip-dispatch-nofactory");
        let dsinks = sealed_sinks(&dirs);
        provision_keyset_distributed(&anchor, &placement_for_sealed_sinks(), &as_dyn(&dsinks))
            .expect("distributed provision");
        assert!(
            load_agent_quorum_signer(&anchor, None).is_err(),
            "a distributed keystore with no transport factory must fail (never silently co-locate)"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("FLIP-COLOCATED-DEFAULT PASS: co-located path unchanged; dispatcher routes co-located w/o factory and refuses a distributed keystore w/o one");
    }

    /// Placement-manifest SHAPE guards: a wrong count, a non-canonical identifier order, a
    /// duplicate label, and a duplicate address are each rejected on load (so a corrupt manifest
    /// is a loud error, never a silently-misrouted sign path).
    #[test]
    fn placement_manifest_shape_is_validated() {
        // Good manifest validates + round-trips through a save/load.
        let good = placement_for_sealed_sinks();
        good.validate_shape().expect("a well-formed manifest validates");

        // Wrong count.
        let short = PlacementManifest { holders: good.holders[..2].to_vec() };
        assert!(short.validate_shape().is_err(), "fewer than SHARE_COUNT holders is rejected");

        // Non-canonical identifier order (entry 0 not identifier 1).
        let mut misordered = good.clone();
        misordered.holders[0].identifier = 3;
        assert!(misordered.validate_shape().is_err(), "non-canonical identifier order is rejected");

        // Duplicate label.
        let mut dup_label = good.clone();
        dup_label.holders[1].label = dup_label.holders[0].label.clone();
        assert!(dup_label.validate_shape().is_err(), "duplicate holder labels are rejected");

        // Duplicate address.
        let mut dup_addr = good.clone();
        dup_addr.holders[1].address = dup_addr.holders[0].address.clone();
        assert!(dup_addr.validate_shape().is_err(), "duplicate holder addresses are rejected");

        // A save/load round-trip preserves the manifest.
        let dir = temp_keystore("placement-roundtrip");
        std::fs::create_dir_all(&dir).unwrap();
        save_placement(&dir, &good).expect("save placement");
        assert_eq!(load_placement(&dir).expect("load placement"), good, "placement round-trips");
        let _ = std::fs::remove_dir_all(&dir);
        println!("PLACEMENT-SHAPE PASS: wrong-count/misordered/dup-label/dup-address rejected; good manifest round-trips");
    }

    /// Provision-side ALIGNMENT guard: a placement whose labels do not match the sink labels (the
    /// share would be shipped to one store while the sign path dials another) is rejected before
    /// any keygen.
    #[test]
    fn distributed_provision_rejects_placement_sink_misalignment() {
        let (anchor, dirs) = dist_dirs("flip-misalign");
        let sinks = sealed_sinks(&dirs); // labels holder-1/2/3
        // A placement whose labels are holderA/B/C -- valid SHAPE, but misaligned with the sinks.
        let misaligned = PlacementManifest {
            holders: (1..=SHARE_COUNT)
                .map(|id| HolderPlacement {
                    identifier: id,
                    label: format!("holder-{}", (b'A' + (id as u8 - 1)) as char),
                    address: format!("inproc://holder-{id}"),
                })
                .collect(),
        };
        let err = provision_keyset_distributed(&anchor, &misaligned, &as_dyn(&sinks))
            .map(|_| ())
            .expect_err("a placement/sink label misalignment must be rejected");
        assert!(
            format!("{err:#}").contains("misalignment"),
            "the error must name the placement/sink misalignment: {err:#}"
        );
        // Nothing was provisioned (no anchor minted on the rejection path).
        assert!(!pubkeys_path(&anchor).is_file(), "a rejected misaligned provision mints no anchor");

        let _ = std::fs::remove_dir_all(anchor.parent().unwrap());
        println!("FLIP-MISALIGN PASS: a placement/sink label misalignment is rejected before keygen (no anchor minted)");
    }

    /// A naive subslice search (no extra deps), for the sealed-at-rest assertion.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
