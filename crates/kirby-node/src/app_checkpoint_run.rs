//! Portable app-checkpoint resume orchestration.
//!
//! This is the cross-backend sibling of the VM-snapshot resume path: node 1 boots
//! a checkpoint-aware genome, accepts its logical-state checkpoint over the shared
//! gateway, stores that opaque blob by content hash, then boots node 2 FRESH with
//! the stored checkpoint in `GetSessionContext`. No VM memory state crosses this
//! seam, so the path is valid for Firecracker<->VZ and Linux<->macOS. The backend
//! still only does an ordinary `boot()`; the restore semantics live in the
//! agnostic gateway/genome contract.

use std::path::PathBuf;
use std::time::Duration;

use kirby_proto::{CheckpointRef, Event};

use crate::boot::{self, BootConfig, EventStream};
use crate::checkpoint::{CheckpointArtifact, CheckpointStore, LocalDirCheckpointStore};

/// Inputs for a portable app-checkpoint handoff run.
pub struct AppCheckpointRunConfig {
    /// Node 1 boot config. `new` forces the `app-checkpoint` workload and disables
    /// VM snapshot/egress because this path is a fresh logical restore.
    pub boot: BootConfig,
    /// Node 2's fresh-boot identity.
    pub node2_id: String,
    /// Node 2's guest CID. It can differ because this is not a VM snapshot; the
    /// genome reads the fresh boot command line.
    pub node2_guest_cid: u32,
    /// Node 2's gateway port. It can differ for the same reason.
    pub node2_gateway_port: u32,
    /// Durable local checkpoint store used for the same-host proof.
    pub store_dir: PathBuf,
    /// Node 1 workload. The normal proof uses `app-checkpoint`; the negative
    /// control smuggles raw entropy material into the checkpoint.
    pub node1_workload: String,
    /// Node 2 workload. The normal proof re-derives from fresh entropy after the
    /// app checkpoint restore; the negative control reuses the smuggled material.
    pub node2_workload: String,
    /// How long to wait for node 1 to submit a checkpoint.
    pub checkpoint_timeout: Duration,
    /// How long to wait for node 2 to report that it saw the restore checkpoint.
    pub restore_timeout: Duration,
}

impl AppCheckpointRunConfig {
    pub fn new(mut boot: BootConfig) -> Self {
        boot.workload = Some("app-checkpoint".to_string());
        boot.lockdown_egress = false;
        boot.snapshot_capable = false;
        boot.restore_checkpoint = None;
        let node2_id = format!("{}-app-n2", boot.node_id);
        let node2_guest_cid = boot.guest_cid.saturating_add(1);
        let node2_gateway_port = boot.gateway_port.saturating_add(1);
        let store_dir = std::env::temp_dir().join(format!("kirby-app-checkpoint-{}", boot.node_id));
        AppCheckpointRunConfig {
            boot,
            node2_id,
            node2_guest_cid,
            node2_gateway_port,
            store_dir,
            node1_workload: "app-checkpoint".to_string(),
            node2_workload: "app-checkpoint".to_string(),
            checkpoint_timeout: Duration::from_secs(40),
            restore_timeout: Duration::from_secs(40),
        }
    }

    pub fn new_negative_control(mut boot: BootConfig) -> Self {
        boot.workload = Some("app-checkpoint-smuggle-secret".to_string());
        let mut config = Self::new(boot);
        config.node1_workload = "app-checkpoint-smuggle-secret".to_string();
        config.node2_workload = "app-checkpoint-reuse-smuggled-nonce".to_string();
        config
    }
}

#[derive(Debug, Clone)]
pub struct AppCheckpointRunOutcome {
    pub node1_reached_running: bool,
    pub first_checkpoint_submitted: bool,
    pub first_checkpoint_ref: Option<CheckpointRef>,
    pub first_checkpoint_bytes: u64,
    pub store_round_trip: bool,
    pub node1_halted: bool,
    pub node2_reached_running: bool,
    pub restore_seen: bool,
    pub restore_detail: Option<String>,
    pub second_checkpoint_submitted: bool,
    pub second_checkpoint_ref: Option<CheckpointRef>,
    pub fingerprint_pre: Option<String>,
    pub fingerprint_post: Option<String>,
    pub entropy_call_before_restore_act: bool,
}

impl AppCheckpointRunOutcome {
    pub fn handoff_passed(&self) -> bool {
        self.node1_reached_running
            && self.first_checkpoint_submitted
            && self.first_checkpoint_ref.is_some()
            && self.first_checkpoint_bytes > 0
            && self.store_round_trip
            && self.node1_halted
            && self.node2_reached_running
            && self.restore_seen
            && self.second_checkpoint_submitted
            && self.second_checkpoint_ref.is_some()
    }

    pub fn fingerprints_equal(&self) -> bool {
        self.fingerprint_pre.is_some()
            && self.fingerprint_post.is_some()
            && self.fingerprint_pre == self.fingerprint_post
    }

    pub fn entropy_redrive_passed(&self) -> bool {
        self.handoff_passed()
            && self.fingerprint_pre.is_some()
            && self.fingerprint_post.is_some()
            && !self.fingerprints_equal()
            && self.entropy_call_before_restore_act
    }

    pub fn passed(&self) -> bool {
        self.entropy_redrive_passed()
    }
}

pub fn evidence_line(outcome: &AppCheckpointRunOutcome) -> String {
    format!(
        "APP-CHECKPOINT {}: node1_running={} first_checkpoint_ref={} first_checkpoint_bytes={} store_round_trip={} node1_halted={} node2_running={} restore_seen={} restore_detail={:?} second_checkpoint_ref={} fingerprint_pre={} fingerprint_post={} fingerprints_equal={} entropy_call_before_restore_act={}",
        if outcome.passed() { "PASS" } else { "FAIL" },
        outcome.node1_reached_running,
        outcome
            .first_checkpoint_ref
            .as_ref()
            .map(|r| format!("{}:{}", r.sha256, r.len))
            .unwrap_or_else(|| "<none>".to_string()),
        outcome.first_checkpoint_bytes,
        outcome.store_round_trip,
        outcome.node1_halted,
        outcome.node2_reached_running,
        outcome.restore_seen,
        outcome.restore_detail,
        outcome
            .second_checkpoint_ref
            .as_ref()
            .map(|r| format!("{}:{}", r.sha256, r.len))
            .unwrap_or_else(|| "<none>".to_string()),
        outcome.fingerprint_pre.as_deref().unwrap_or("<none>"),
        outcome.fingerprint_post.as_deref().unwrap_or("<none>"),
        outcome.fingerprints_equal(),
        outcome.entropy_call_before_restore_act
    )
}

pub async fn run(config: AppCheckpointRunConfig) -> anyhow::Result<AppCheckpointRunOutcome> {
    let _ = std::fs::remove_dir_all(&config.store_dir);
    let store = LocalDirCheckpointStore::new(config.store_dir.clone());

    let mut node1_boot = config.boot.clone();
    node1_boot.workload = Some(config.node1_workload.clone());
    node1_boot.lockdown_egress = false;
    node1_boot.snapshot_capable = false;
    node1_boot.restore_checkpoint = None;

    let (node1, node1_outcome, _treasury1, mut node1_events) =
        boot::boot_and_observe(node1_boot).await?;
    if !node1_outcome.reached_running {
        node1.halt().await;
        anyhow::bail!("app-checkpoint node 1 did not reach Running");
    }

    let first_observation =
        wait_for_checkpoint_submit(&mut node1_events, config.checkpoint_timeout, Some("pre")).await;
    let checkpoint = latest_checkpoint(&node1_outcome.checkpoints)?;
    if let Err(e) = validate_checkpoint_membrane(&checkpoint) {
        node1.halt().await;
        return Err(e);
    }
    let stored_ref = match store.put(&checkpoint) {
        Ok(reference) => reference,
        Err(e) => {
            node1.halt().await;
            return Err(e.into());
        }
    };
    let loaded = match store.get(&stored_ref) {
        Ok(artifact) => artifact,
        Err(e) => {
            node1.halt().await;
            return Err(e.into());
        }
    };
    let store_round_trip = loaded == checkpoint;

    node1.halt().await;
    let node1_halted = true;

    let mut node2_boot = config.boot.clone();
    node2_boot.node_id = config.node2_id.clone();
    node2_boot.guest_cid = config.node2_guest_cid;
    node2_boot.gateway_port = config.node2_gateway_port;
    node2_boot.workload = Some(config.node2_workload.clone());
    node2_boot.lockdown_egress = false;
    node2_boot.snapshot_capable = false;
    node2_boot.restore_checkpoint = Some(loaded.clone());

    let (node2, node2_outcome, _treasury2, mut node2_events) =
        boot::boot_and_observe(node2_boot).await?;
    if !node2_outcome.reached_running {
        node2.halt().await;
        anyhow::bail!("app-checkpoint node 2 did not reach Running");
    }

    let restore_observation =
        wait_for_restore_seen(&mut node2_events, config.restore_timeout).await;
    let restore_seen = restore_observation
        .restore
        .as_ref()
        .map(|event| restore_detail_matches(event, &loaded))
        .unwrap_or(false);
    let restore_detail = restore_observation.restore.map(|event| event.detail);
    let second_observation =
        wait_for_checkpoint_submit(&mut node2_events, config.restore_timeout, None).await;
    let second_checkpoint = node2_outcome
        .checkpoints
        .latest()
        .map_err(|e| anyhow::anyhow!("read node 2 checkpoint handle: {e}"))?
        .map(|artifact| {
            validate_checkpoint_membrane(&artifact)?;
            Ok::<CheckpointRef, anyhow::Error>(artifact.reference)
        })
        .transpose()?;

    node2.halt().await;

    Ok(AppCheckpointRunOutcome {
        node1_reached_running: node1_outcome.reached_running,
        first_checkpoint_submitted: first_observation.submit.is_some(),
        first_checkpoint_ref: Some(stored_ref),
        first_checkpoint_bytes: checkpoint.payload.len() as u64,
        store_round_trip,
        node1_halted,
        node2_reached_running: node2_outcome.reached_running,
        restore_seen,
        restore_detail,
        second_checkpoint_submitted: second_observation.submit.is_some(),
        second_checkpoint_ref: second_checkpoint,
        fingerprint_pre: first_observation.fingerprint,
        fingerprint_post: restore_observation.fingerprint,
        entropy_call_before_restore_act: restore_observation.entropy_call_before_restore,
    })
}

fn latest_checkpoint(
    checkpoints: &crate::checkpoint::LatestCheckpoint,
) -> anyhow::Result<CheckpointArtifact> {
    checkpoints
        .latest()
        .map_err(|e| anyhow::anyhow!("read checkpoint handle: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("genome did not submit a checkpoint"))
}

fn restore_detail_matches(event: &Event, artifact: &CheckpointArtifact) -> bool {
    event
        .detail
        .contains(&format!("sha256={}", artifact.reference.sha256))
        && event
            .detail
            .contains(&format!("len={}", artifact.reference.len))
        && event
            .detail
            .contains(&format!("blob_len={}", artifact.payload.len()))
}

fn validate_checkpoint_membrane(artifact: &CheckpointArtifact) -> anyhow::Result<()> {
    let payload = String::from_utf8_lossy(&artifact.payload);
    let forbidden_markers = [
        "stale_nonce=",
        "ephemeral_secret=",
        "credential=",
        "private_key=",
        "secret_key=",
    ];
    if let Some(marker) = forbidden_markers
        .iter()
        .find(|marker| payload.contains(**marker))
    {
        anyhow::bail!(
            "checkpoint membrane violation: payload contains forbidden marker {marker:?}"
        );
    }
    Ok(())
}

#[derive(Default)]
struct CheckpointSubmitObservation {
    submit: Option<Event>,
    fingerprint: Option<String>,
}

struct RestoreObservation {
    restore: Option<Event>,
    fingerprint: Option<String>,
    entropy_call_before_restore: bool,
}

async fn wait_for_checkpoint_submit(
    events: &mut EventStream,
    timeout: Duration,
    fingerprint_phase: Option<&str>,
) -> CheckpointSubmitObservation {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut observation = CheckpointSubmitObservation::default();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return observation;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(event)) if event.kind == "checkpoint_submitted" => {
                observation.submit = Some(event);
                return observation;
            }
            Ok(Some(event)) if event.kind == "app_checkpoint_fingerprint" => {
                if fingerprint_phase
                    .map(|phase| detail_field(&event.detail, "phase") == Some(phase))
                    .unwrap_or(true)
                {
                    observation.fingerprint = detail_field(&event.detail, "fingerprint")
                        .map(str::to_string)
                        .filter(|fingerprint| fingerprint != "<none>");
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => return observation,
            Err(_) => return observation,
        }
    }
}

async fn wait_for_restore_seen(events: &mut EventStream, timeout: Duration) -> RestoreObservation {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut fingerprint = None;
    let mut entropy_call_before_restore = false;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return RestoreObservation {
                restore: None,
                fingerprint,
                entropy_call_before_restore,
            };
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(event)) if event.kind == "entropy_nonce_call" => {
                entropy_call_before_restore = true;
            }
            Ok(Some(event)) if event.kind == "app_checkpoint_fingerprint" => {
                if detail_field(&event.detail, "phase") == Some("post") {
                    fingerprint = detail_field(&event.detail, "fingerprint")
                        .map(str::to_string)
                        .filter(|fingerprint| fingerprint != "<none>");
                }
            }
            Ok(Some(event)) if event.kind == "checkpoint_restore_seen" => {
                return RestoreObservation {
                    restore: Some(event),
                    fingerprint,
                    entropy_call_before_restore,
                };
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                return RestoreObservation {
                    restore: None,
                    fingerprint,
                    entropy_call_before_restore,
                };
            }
            Err(_) => {
                return RestoreObservation {
                    restore: None,
                    fingerprint,
                    entropy_call_before_restore,
                };
            }
        }
    }
}

fn detail_field<'a>(detail: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    detail
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
}

#[cfg(test)]
mod tests {
    use kirby_proto::Event;

    use crate::checkpoint::CheckpointArtifact;

    use super::{detail_field, restore_detail_matches, validate_checkpoint_membrane};

    #[test]
    fn restore_detail_match_requires_hash_len_and_blob_len() {
        let artifact = CheckpointArtifact::new(b"state".to_vec());
        let event = Event {
            schema_version: kirby_proto::SCHEMA_VERSION,
            kind: "checkpoint_restore_seen".into(),
            detail: format!(
                "restore_seen sha256={} len={} blob_len={}",
                artifact.reference.sha256,
                artifact.reference.len,
                artifact.payload.len()
            ),
        };

        assert!(restore_detail_matches(&event, &artifact));
        assert!(!restore_detail_matches(
            &Event {
                detail: "restore_seen sha256=bad len=5 blob_len=5".into(),
                ..event
            },
            &artifact
        ));
    }

    #[test]
    fn checkpoint_membrane_accepts_clean_logical_state() {
        let artifact = CheckpointArtifact::new(b"task=demo budget_sats=7 restore=none".to_vec());

        validate_checkpoint_membrane(&artifact).unwrap();
    }

    #[test]
    fn checkpoint_membrane_rejects_smuggled_ephemeral_secret() {
        let artifact = CheckpointArtifact::new(
            b"task=demo budget_sats=7 stale_nonce=negative-control-reused-across-restore".to_vec(),
        );

        let err = validate_checkpoint_membrane(&artifact).unwrap_err();
        assert!(
            err.to_string().contains("checkpoint membrane violation"),
            "negative-control checkpoint must fail closed, got: {err}"
        );
    }

    #[test]
    fn detail_field_extracts_app_checkpoint_fingerprint_fields() {
        let detail = "phase=post source=fresh fingerprint=deadbeef fp_gen=0 unrelated=value";

        assert_eq!(detail_field(detail, "phase"), Some("post"));
        assert_eq!(detail_field(detail, "fingerprint"), Some("deadbeef"));
        assert_eq!(detail_field(detail, "fp_gen"), Some("0"));
        assert_eq!(detail_field(detail, "missing"), None);
    }
}
