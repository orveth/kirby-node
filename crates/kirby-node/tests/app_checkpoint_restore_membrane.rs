//! FAST UNGATED proof of the app-checkpoint RESTORE-side egress membrane.
//!
//! The submit-side rejection (node 1's checkpoint scanned before it is stored) is
//! already covered by the unit tests in `app_checkpoint_run`. The RESTORE side, where
//! node 2 loads a stored blob and boots from it, is otherwise only exercised in the
//! HW-gated VM e2e. This isolates the restore-side check: it injects smuggled-secret
//! markers into a checkpoint blob, runs it through the SAME content-addressed store
//! the orchestration uses (`LocalDirCheckpointStore` put/get), then asserts the blob
//! LOADED back from the store is REJECTED by the membrane that gates node 2's boot.
//! No VM, no image, no network, no debit: a rejected blob never reaches
//! `GetSessionContext`, so node 2 loads and debits nothing from it.

use kirby_node::app_checkpoint_run::validate_checkpoint_membrane;
use kirby_node::checkpoint::{CheckpointArtifact, CheckpointStore, LocalDirCheckpointStore};

/// A unique temp dir for the store, removed on drop (mirrors the harness TempDir).
struct TempDir {
    path: std::path::PathBuf,
}
impl TempDir {
    fn new(prefix: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&path).expect("create store dir");
        TempDir { path }
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// RESTORE-side rejection: a checkpoint carrying a smuggled `stale_nonce=` marker,
/// stored and then LOADED back from the content-addressed store (the exact blob the
/// orchestration would hand node 2), is rejected by the restore-gating membrane. The
/// rejection is on the LOADED bytes, so even a blob tampered at rest is caught before
/// node 2 boots from it.
#[test]
fn restore_path_rejects_stored_blob_with_smuggled_stale_nonce() {
    let dir = TempDir::new("kirby-restore-membrane");
    let store = LocalDirCheckpointStore::new(dir.path.clone());

    // A checkpoint that smuggles ephemeral secret material across the restore boundary
    // (the negative-control marker the gate must catch: a reused nonce leaking a key).
    let smuggled = CheckpointArtifact::new(
        b"task=demo budget_sats=7 stale_nonce=reused-across-restore-leaks-the-key".to_vec(),
    );

    // It goes through the SAME store round-trip the orchestration uses for node 2.
    let reference = store.put(&smuggled).expect("store accepts the opaque blob");
    let loaded = store.get(&reference).expect("blob loads back by content hash");
    assert_eq!(
        loaded, smuggled,
        "the store is content-addressed: the loaded blob is exactly what node 2 would restore"
    );

    // THE RESTORE-SIDE GATE: validate the LOADED blob (what gates node 2's boot). It
    // must fail closed with a membrane violation, so node 2 never reaches
    // GetSessionContext with it (loads/debits nothing).
    let err = validate_checkpoint_membrane(&loaded)
        .expect_err("the restore path must reject a smuggled-secret blob");
    let msg = err.to_string();
    assert!(
        msg.contains("checkpoint membrane violation"),
        "rejection must be a membrane violation, got: {msg}"
    );
    assert!(
        msg.contains("stale_nonce="),
        "the violation must name the smuggled marker, got: {msg}"
    );
}

/// The membrane covers the full secret-marker set on the restore side, not only one
/// marker. Each forbidden marker, smuggled into a stored-and-loaded blob, is rejected.
#[test]
fn restore_path_rejects_every_smuggled_secret_marker() {
    let dir = TempDir::new("kirby-restore-membrane-all");
    let store = LocalDirCheckpointStore::new(dir.path.clone());

    for marker in [
        "stale_nonce=",
        "ephemeral_secret=",
        "credential=",
        "private_key=",
        "secret_key=",
    ] {
        let payload = format!("task=demo {marker}deadbeef").into_bytes();
        let artifact = CheckpointArtifact::new(payload);
        let reference = store.put(&artifact).expect("store accepts the blob");
        let loaded = store.get(&reference).expect("blob loads back");
        let err = validate_checkpoint_membrane(&loaded)
            .expect_err(&format!("restore must reject marker {marker:?}"));
        assert!(
            err.to_string().contains("checkpoint membrane violation"),
            "marker {marker:?} must trigger a membrane violation"
        );
    }
}

/// Positive control: a clean logical-state blob (no secret markers) survives the
/// store round-trip and PASSES the restore-side membrane, so the rejection above is
/// specific to smuggled secrets, not a blanket refusal that would block every restore.
#[test]
fn restore_path_accepts_clean_logical_state() {
    let dir = TempDir::new("kirby-restore-membrane-clean");
    let store = LocalDirCheckpointStore::new(dir.path.clone());

    let clean =
        CheckpointArtifact::new(b"task=demo budget_sats=7 cursor=42 restore=none".to_vec());
    let reference = store.put(&clean).expect("store accepts the clean blob");
    let loaded = store.get(&reference).expect("clean blob loads back");

    validate_checkpoint_membrane(&loaded)
        .expect("a clean logical-state blob must pass the restore-side membrane");
}
