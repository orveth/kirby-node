//! `kirby run` keystone gates (G-run-1, G-run-2, G-run-3).
//!
//! These drive the SAME `kirby run` sequence the `kirby-node agent` subcommand
//! runs: build a [`KirbyConfig`] in code (the equivalent of a `kirby.toml`), then
//! call [`run_agent::run`] and assert the gate evidence. The full run boots a REAL
//! microVM under the backend and beacons a relay, so each test needs:
//!   - the host prerequisites (KVM, vsock, the jailer privilege path on Linux), AND
//!   - the built genome image (the `KIRBY_GENOME_IMAGE` env var, the
//!     `nix build .#genome-image` output, holding vmlinux + rootfs.squashfs), AND
//!   - a reachable fleet relay (`KIRBY_TEST_RELAY`, e.g. `ws://127.0.0.1:7777`).
//!
//! When `KIRBY_GENOME_IMAGE` is unset each test SKIPS with a clear message rather
//! than failing, so `cargo test` stays green on a host that has not built the image;
//! the keeper runs them on the harness with the vars set as the producing commands.
//! The relay defaults to `ws://127.0.0.1:7777` when `KIRBY_TEST_RELAY` is unset so a
//! local relay needs no extra config; lifecycle publishing is best-effort and never
//! aborts an otherwise-live agent, so a transient relay miss does not fail the boot
//! gates (G-run-1's relay assertion is the keeper's relay-query step, documented).

use std::path::PathBuf;
use std::time::Duration;

use kirby_node::config::{
    Backend, FundingConfig, GenomeImage, IdentityConfig, KirbyConfig, RelayConfig, RunMode,
    Workload,
};
use kirby_node::nerve;
use kirby_node::run_agent::{self, EndReason, RunAgentConfig};

/// The image dir, or `None` (skip) when `KIRBY_GENOME_IMAGE` is unset.
fn image_dir_or_skip(test: &str) -> Option<PathBuf> {
    match std::env::var_os("KIRBY_GENOME_IMAGE") {
        Some(dir) => Some(PathBuf::from(dir)),
        None => {
            eprintln!(
                "SKIP {test}: set KIRBY_GENOME_IMAGE to the `nix build .#genome-image` output \
                 (and KIRBY_TEST_RELAY to a reachable relay) to run the `kirby run` gate"
            );
            None
        }
    }
}

/// The relay URL for the test fleet (defaults to a local relay).
fn test_relay() -> String {
    std::env::var("KIRBY_TEST_RELAY").unwrap_or_else(|_| "ws://127.0.0.1:7777".to_string())
}

/// A per-test state dir under the OS temp dir so parallel tests stay distinct.
fn test_state_dir(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("kirby-run-gate-{test}-{}", std::process::id()))
}

/// Build a v0 bootstrap config for a test (the in-code `kirby.toml`).
fn bootstrap_config(test: &str, image_dir: PathBuf, funding_sats: u64) -> KirbyConfig {
    let state = test_state_dir(test);
    KirbyConfig {
        identity: IdentityConfig {
            key_path: state.join("node.nostr.key"),
            treasury_dir: Some(state.clone()),
        },
        relay: RelayConfig {
            url: test_relay(),
            presence_interval_secs: 5,
            presence_stale_after_secs: 15,
        },
        // auto resolves to the native backend (Firecracker on Linux, VZ on macOS),
        // so the SAME config drives both the Linux gates here and the Mac G-run-4.
        backend: Backend::Auto,
        genome_image: GenomeImage::Path(image_dir),
        workload: Workload::AppCheckpoint,
        brain: Default::default(),
        mode: RunMode::Bootstrap,
        funding: FundingConfig {
            initial_sats: funding_sats,
        },
        agent_id: format!("agent-{test}"),
        node_id: format!("node-{test}-{}", std::process::id()),
    }
}

/// G-run-1: a fresh config mints the identity, boots the agent on the resolved
/// backend, joins the fleet (presence + heartbeat), and emits a 9100 born. The
/// one-command sovereign-node BIRTH. (The keeper verifies the relay-side 9100 born
/// + 10100 presence by querying the relay with `kirby-node presence`; this test
/// proves the run sequence reaches Running and emits born from the run side.)
#[tokio::test]
async fn g_run_1_fresh_config_boots_and_is_born() {
    let Some(image_dir) = image_dir_or_skip("g_run_1") else {
        return;
    };
    let config = bootstrap_config("grun1", image_dir, 3_000);
    let relay_url = config.relay.url.clone();
    let node_id = config.node_id.clone();
    let stale_after = config.relay.presence_stale_after_secs;
    let run = RunAgentConfig::from_config(config).expect("build run config");
    let backend = run.backend();

    let outcome = run_agent::run(run).await.expect("kirby run sequence");
    eprintln!("{}", run_agent::evidence_line(&outcome));

    assert!(
        outcome.reached_running,
        "the agent must reach Running (the one-command sovereign-node birth)"
    );
    assert_eq!(
        outcome.backend, backend,
        "the run resolved the native backend"
    );
    assert!(
        outcome.born_emitted,
        "a bootstrap run must emit a 9100 born (the signed birth log)"
    );
    assert!(
        !outcome.npub.is_empty() && outcome.npub.starts_with("npub1"),
        "the node minted/loaded a Nostr identity (npub), got {:?}",
        outcome.npub
    );
    let records = nerve::read_fleet_once(
        &relay_url,
        Duration::from_secs(stale_after),
        Duration::from_secs(5),
    )
    .await
    .expect("query relay presence after bootstrap");
    assert!(
        records
            .iter()
            .any(|record| record.npub == outcome.npub && record.node_id == node_id && record.alive),
        "the node's 10100 presence must land on the relay; records={records:?}"
    );
    assert!(
        outcome.bootstrap_birth_passed(),
        "G-run-1 birth predicate must hold: {}",
        run_agent::evidence_line(&outcome)
    );
}

/// G-run-2: die-when-broke under `kirby run`. A small budget so the v0 metered
/// workload exhausts it quickly; the daemon HALTS the agent on exhaustion (the
/// genome cannot stop it) and a 9100 died is emitted.
#[tokio::test]
async fn g_run_2_dies_when_broke() {
    let Some(image_dir) = image_dir_or_skip("g_run_2") else {
        return;
    };
    // A small budget so VM-time metering drains it in a few seconds.
    let config = bootstrap_config("grun2", image_dir, 3_000);
    let run = RunAgentConfig::from_config(config).expect("build run config");

    let outcome = run_agent::run(run).await.expect("kirby run sequence");
    eprintln!("{}", run_agent::evidence_line(&outcome));

    assert_eq!(
        outcome.end_reason,
        EndReason::BudgetExhausted,
        "the agent must die by budget exhaustion (the daemon halted it), got {:?}",
        outcome.end_reason
    );
    assert!(
        outcome.burned_sats > 0,
        "the meter must have read real usage (non-zero burn), got 0"
    );
    assert!(
        outcome.died_emitted,
        "a budget-death must emit a 9100 died (the signed death log)"
    );
    assert!(
        outcome.die_when_broke_passed(),
        "G-run-2 die-when-broke predicate must hold: {}",
        run_agent::evidence_line(&outcome)
    );
}

/// G-run-3: `resume` mode restores the agent from the latest checkpoint (rejoin =
/// resume, not cold-restart): a fresh boot whose gateway hands the genome the stored
/// logical state, the genome reports the restore, and NO born is emitted (resume is
/// continue, not birth).
///
#[tokio::test]
async fn g_run_3_resume_restores_from_checkpoint() {
    let Some(image_dir) = image_dir_or_skip("g_run_3") else {
        return;
    };
    let mut config = bootstrap_config("grun3", image_dir, 3_000);
    let bootstrap_run =
        RunAgentConfig::from_config(config.clone()).expect("build bootstrap run config");
    let checkpoint_dir = bootstrap_run.checkpoint_dir.clone();
    let seed = run_agent::run(bootstrap_run)
        .await
        .expect("kirby run bootstrap seed sequence");
    eprintln!("{}", run_agent::evidence_line(&seed));
    assert!(
        seed.bootstrap_birth_passed(),
        "bootstrap must seed the agent before resume: {}",
        run_agent::evidence_line(&seed)
    );
    assert!(
        std::fs::read_dir(&checkpoint_dir)
            .map(|mut d| d.any(|e| e.is_ok()))
            .unwrap_or(false),
        "bootstrap must persist a checkpoint in {}",
        checkpoint_dir.display()
    );

    config.mode = RunMode::Resume;
    let run = RunAgentConfig::from_config(config).expect("build resume run config");
    let outcome = run_agent::run(run)
        .await
        .expect("kirby run resume sequence");
    eprintln!("{}", run_agent::evidence_line(&outcome));

    assert!(
        outcome.reached_running,
        "the resumed agent must reach Running (rejoin = resume)"
    );
    assert!(
        outcome.restore_seen,
        "the resumed agent must observe its restored checkpoint"
    );
    assert!(
        !outcome.born_emitted,
        "a resume run must NOT emit born (the agent is continuing, not being born)"
    );
    assert!(
        outcome.resume_passed(),
        "G-run-3 resume predicate must hold: {}",
        run_agent::evidence_line(&outcome)
    );
}
