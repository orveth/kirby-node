//! The C-2 boot orchestration (gate G1): boot the genome guest through the
//! sandbox backend, serve the agnostic gateway over its vsock transport, and
//! observe the genome's boot round-trip.
//!
//! This ties the pieces together so both the daemon binary (`kirby-node boot`)
//! and the integration test drive the SAME path: prepare the gateway with an
//! event observer, boot the guest through a [`SandboxBackend`] (Firecracker today),
//! serve the gateway on the instance's [`GatewayTransport`], and wait for the
//! genome's "hello" event (`session=<task>`) to arrive over vsock. That arriving
//! event is the machine-checkable G1 proof the genome booted and completed a
//! `GetSessionContext` round-trip.
//!
//! This module is the AGNOSTIC orchestration: it speaks the [`crate::sandbox`]
//! seam (`GuestSpec` in, `SandboxInstance` out), the agnostic gateway, treasury,
//! and rail. The backend MECHANICS (which binaries, the jail, the cgroup parent,
//! the TAP) live behind the backend; this module never names a Firecracker type.
//!
//! Everything past boot plus the vsock round-trip is out of C-2 scope: metering
//! and the budget halt (C-4), the brokered act (C-6), snapshot and resume (C-7),
//! the entropy re-derive (C-8), and consensus (C-9).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kirby_proto::Event;

use crate::checkpoint::{CheckpointArtifact, LatestCheckpoint};
#[cfg(target_os = "linux")]
use crate::firecracker::FirecrackerBackend;
use crate::gateway::{GatewayService, Session};
use crate::rail::{MockRail, Rail};
use crate::sandbox::{GatewayTransport, GuestImage, GuestSpec, SandboxBackend, SandboxInstance};
use crate::treasury::Treasury;
#[cfg(target_os = "macos")]
use crate::vz::VzBackend;

/// Where the genome image artifacts live (built by `nix build .#genome-image`).
/// Resolved from `--image-dir` or the `KIRBY_GENOME_IMAGE` env var, both of
/// which point at the image output (containing vmlinux and rootfs.squashfs).
#[derive(Clone)]
pub struct ImagePaths {
    pub vmlinux: PathBuf,
    pub rootfs: PathBuf,
}

impl ImagePaths {
    /// Resolve the image artifacts from an image directory (the `genome-image`
    /// nix output). The directory holds `vmlinux` and `rootfs.squashfs`.
    pub fn from_dir(image_dir: &std::path::Path) -> anyhow::Result<Self> {
        let vmlinux = image_dir.join("vmlinux");
        let rootfs = image_dir.join("rootfs.squashfs");
        if !vmlinux.exists() {
            anyhow::bail!("vmlinux not found at {}", vmlinux.display());
        }
        if !rootfs.exists() {
            anyhow::bail!("rootfs.squashfs not found at {}", rootfs.display());
        }
        Ok(ImagePaths { vmlinux, rootfs })
    }
}

/// Inputs for one boot demonstration.
#[derive(Clone)]
pub struct BootConfig {
    pub image: ImagePaths,
    pub node_id: String,
    pub task: String,
    pub budget_sats: u64,
    pub initial_sats: u64,
    pub allow: Vec<String>,
    pub guest_cid: u32,
    pub gateway_port: u32,
    pub vcpu_count: u8,
    pub mem_size_mib: usize,
    /// How long to wait for the genome's boot hello event after the VM is up.
    pub hello_timeout: Duration,
    /// The genome workload the daemon requests on the kernel command line. `None`
    /// idles after the boot round-trip (C-2 / G1); `Some("burn")` runs the C-4
    /// metering workload (allocate memory + spin CPU) so the meter trips the halt
    /// (G2); `Some("app-checkpoint")` submits portable logical state for resume;
    /// `Some("raw-egress")` runs the C-5 egress probe (attempt direct outbound,
    /// which must fail, gate G4).
    pub workload: Option<String>,
    /// Wire a per-VM TAP into the VM and lock it down with nftables default-deny
    /// egress (C-5, spec 3.7, gate G4). When true, the VM gets a network interface
    /// it can ATTEMPT egress on, the host kernel drops that egress (counted), and
    /// an eBPF TC classifier meters the bytes. When false (the C-2/C-4 default),
    /// the VM is vsock-only (no TAP), already egress-isolated structurally.
    pub lockdown_egress: bool,
    /// Boot the VM so it can be SNAPSHOTTED and resumed on another node (C-7, gate
    /// G6): the backend applies the cross-CPU template (T2CL) at create. The
    /// C-2..C-6 default is false (no template, no snapshot).
    pub snapshot_capable: bool,
    /// Optional app-level checkpoint to hand to a freshly booted genome through
    /// `GetSessionContext`. This is the portable Linux<->macOS resume path: the
    /// backend performs an ordinary cold boot, while the shared gateway tells the
    /// genome which logical state blob to rehydrate.
    pub restore_checkpoint: Option<CheckpointArtifact>,
}

/// The gateway event receiver the genome's `ReportEvent`s arrive on (diagnostic
/// only, never billed, G3c). Returned by `boot_and_observe` so a caller can read
/// post-boot events (the C-5 raw-egress probe outcomes, gate G4).
pub type EventStream = tokio::sync::mpsc::UnboundedReceiver<Event>;

/// Aborts the detached gateway serve task when the run tears down. The serve task
/// holds a `GatewayService` clone, and that clone holds a `Treasury` Arc, which
/// holds the sled exclusive lock on the per-node treasury dir. `serve_gateway_over`
/// is a listener loop that never returns on its own (the genome legitimately
/// reconnects during a live run), so without this the task outlives the VM and
/// pins the treasury lock indefinitely. A same-process resume on the same `node_id`
/// (the G-run-3 sequence) then cannot reopen the treasury (sled `WouldBlock`).
///
/// Dropping this guard aborts the task; the runtime then drops the serve task's
/// `GatewayService` (and its `Treasury` Arc), releasing the lock. The abort is
/// asynchronous, so the next [`open_treasury_retrying`] absorbs the brief window
/// until the dropped Arc actually frees the lock. The money / authorize-order /
/// dedupe logic is untouched: this only ends a listener task, it never debits.
///
/// Bound by every caller (as `_serve_guard`) so it lives exactly as long as the
/// run that owns the VM, then drops at run-end alongside the instance halt.
#[must_use = "dropping the ServeGuard aborts the gateway serve task and frees the treasury lock; bind it for the run's lifetime"]
pub struct ServeGuard {
    handle: tokio::task::AbortHandle,
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// The outcome of a boot demonstration (the G1 evidence).
pub struct BootOutcome {
    /// The VM reached Running.
    pub reached_running: bool,
    /// The genome's boot hello event, if it arrived in time. Its detail is
    /// `session=<task>` (the G1 assertion target).
    pub hello: Option<Event>,
    /// The session context the gateway handed the genome (the budget snapshot).
    pub budget_sats: u64,
    /// Shared handle to checkpoints this boot's gateway accepted from the genome.
    /// Most boot/meter/egress paths ignore it; app-checkpoint resume uses it to
    /// persist the exact logical-state blob the daemon accepted.
    pub checkpoints: LatestCheckpoint,
}

/// Open the daemon treasury, tolerating a transient sled exclusive-lock (the FIX-4
/// race): when a prior holder on the same `node_id` (e.g. a just-finished bootstrap
/// run, before a `resume` run) drops its sled handle, the OS file-descriptor reclaim
/// can lag, so a back-to-back open occasionally races the lock. Retry ONLY on lock
/// contention, up to `timeout`; any other error (corruption, real I/O) returns at once.
/// Same store, balance, and dedupe ledger; only the open is retried.
async fn open_treasury_retrying(
    path: &std::path::Path,
    seed_sats: u64,
    timeout: Duration,
) -> Result<Treasury, crate::treasury::TreasuryError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match Treasury::open(path, seed_sats) {
            Ok(t) => return Ok(t),
            Err(e)
                if crate::idempotent_run::is_lock_contention(&e)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Boot the genome through the sandbox backend, serve the agnostic gateway over
/// its vsock transport, and wait for the boot hello event (gate G1). Returns the
/// booted instance (so the caller halts it after inspecting the outcome), the
/// outcome, the daemon-owned treasury (so a metered run, C-4, debits the SAME
/// counter the gateway uses, D-9), the gateway event receiver (so the caller
/// can keep reading post-boot genome events, e.g. the C-5 raw-egress probe
/// outcomes, gate G4), and a [`ServeGuard`] the caller binds for the run's
/// lifetime (its drop aborts the gateway serve task so the treasury lock is
/// freed for a same-process resume). On a boot failure the guest is halted here
/// and the error is returned.
///
/// Uses the mock rail (the C-2/C-4/C-5 paths do no real brokered act); the C-6
/// brokered act injects the real rail via [`boot_and_observe_with_rail`].
pub async fn boot_and_observe(
    config: BootConfig,
) -> anyhow::Result<(Box<dyn SandboxInstance>, BootOutcome, Treasury, EventStream, ServeGuard)> {
    boot_and_observe_with_rail(config, Arc::new(MockRail::new())).await
}

/// As [`boot_and_observe`], but the caller supplies the [`Rail`] the gateway's
/// perform step (spec 3.2 step 4) uses. The C-6 brokered act (gate G5) passes the
/// real [`crate::rail::CdkEcashRail`] so a genome `RequestCapability` settles ecash
/// on the local mint; the other chunks use the mock rail. Everything else (the
/// gateway service, the treasury, the authorize order, the metering) is identical.
///
/// The backend is selected by platform: Firecracker on Linux, VZ on macOS. The
/// daemon boots through the [`SandboxBackend`] trait, never through a concrete VM
/// type, so the gateway/treasury/rail wiring stays shared.
pub async fn boot_and_observe_with_rail(
    config: BootConfig,
    rail: Arc<dyn Rail>,
) -> anyhow::Result<(Box<dyn SandboxInstance>, BootOutcome, Treasury, EventStream, ServeGuard)> {
    // The persisted, daemon-owned treasury (D-9). A per-node temp store keeps two
    // node processes distinct on one host. The session is the non-secret snapshot
    // the genome pulls at boot (spec 3.1).
    let treasury_path = std::env::temp_dir().join(format!("kirby-treasury-{}", config.node_id));
    let treasury = open_treasury_retrying(&treasury_path, config.initial_sats, Duration::from_secs(5)).await?;
    let session = Session {
        task_descriptor: config.task.clone(),
        budget_sats: config.budget_sats,
        allowlisted_destinations: config.allow.clone(),
    };
    // The meter and the gateway share ONE treasury instance (one authoritative
    // counter, D-9): metered ticks and capability spends debit the same balance.
    let meter_treasury = treasury.clone();
    let mut service = GatewayService::new(treasury, rail, session);
    if let Some(checkpoint) = config.restore_checkpoint.clone() {
        service = service.with_restore_checkpoint(checkpoint);
    }

    // Observe ReportEvents so we can await the genome's boot hello (G1).
    let mut events = service.observe_events();

    // The backend-neutral guest spec. The backend translates it into its own
    // launch (the Firecracker backend builds the jail, the cgroup parent, and the
    // per-VM TAP from it); this orchestration never names a Firecracker type.
    let spec = GuestSpec {
        image: GuestImage {
            kernel: config.image.vmlinux.clone(),
            rootfs: config.image.rootfs.clone(),
        },
        instance_id: config.node_id.clone(),
        guest_cid: config.guest_cid,
        gateway_port: config.gateway_port,
        vcpu_count: config.vcpu_count,
        mem_size_mib: config.mem_size_mib,
        workload: config.workload.clone(),
        lockdown_egress: config.lockdown_egress,
        snapshot_capable: config.snapshot_capable,
    };

    tracing::info!(
        node_id = %config.node_id,
        cid = config.guest_cid,
        port = config.gateway_port,
        backend = backend_label(),
        "booting genome guest through the sandbox backend"
    );

    let backend = default_backend();
    let mut instance = backend.boot(spec).await?;

    // The boot evidence: the guest reached Running.
    let reached_running = instance.is_running();
    tracing::info!(reached_running, "guest state after start");
    if !reached_running {
        instance.halt().await;
        anyhow::bail!("guest did not reach the running state");
    }

    // Stream the guest serial console (supplementary boot evidence).
    instance.stream_console();

    // Serve the agnostic gateway over the instance's vsock transport so the
    // genome's boot round-trip lands. The genome (already booting) retries
    // connecting until this listener is bound. The gateway SERVICE is identical on
    // every backend; only the transport it binds is backend-specific.
    let transport = instance.gateway_transport();
    let serve_service = service.clone();
    let serve_task = tokio::spawn(async move {
        if let Err(e) = serve_gateway_over(serve_service, transport).await {
            tracing::error!(error = %e, "gateway serve loop ended with error");
        }
    });
    // The serve task holds a GatewayService clone (and thus a Treasury Arc, holding
    // the sled lock). It is a listener loop that never returns on its own, so it
    // must be aborted at run-end to release the lock; the ServeGuard does that on
    // drop. The caller binds it for the run's lifetime.
    let serve_guard = ServeGuard {
        handle: serve_task.abort_handle(),
    };

    // Wait for the genome's boot hello event (session=<task>). This is the G1
    // round-trip proof: the genome connected over vsock, pulled the session
    // context, and reported hello.
    let hello = wait_for_hello(&mut events, &config.task, config.hello_timeout).await;
    match &hello {
        Some(ev) => {
            tracing::info!(detail = %ev.detail, "genome boot hello received (G1 round-trip proven)")
        }
        None => tracing::warn!("genome boot hello did NOT arrive before the timeout"),
    }

    let outcome = BootOutcome {
        reached_running,
        hello,
        budget_sats: config.budget_sats,
        checkpoints: service.checkpoint_handle(),
    };
    Ok((instance, outcome, meter_treasury, events, serve_guard))
}

/// Serve the agnostic [`GatewayService`] over a guest's backend-specific
/// [`GatewayTransport`]. The gateway is identical on every backend; this dispatch
/// is the one place the host-side listen mechanism differs. Firecracker is the
/// only transport today; a macOS VZ endpoint adds a match arm here.
async fn serve_gateway_over(
    service: GatewayService,
    transport: GatewayTransport,
) -> anyhow::Result<()> {
    serve_gateway_over_pub(service, transport).await
}

/// The public form of [`serve_gateway_over`] so other orchestrations (the C-7
/// snapshot run serves a fresh gateway over the restored guest's transport) reuse
/// the one transport-dispatch site. Adding a backend means one match arm here, for
/// every caller.
pub async fn serve_gateway_over_pub(
    service: GatewayService,
    transport: GatewayTransport,
) -> anyhow::Result<()> {
    match transport {
        GatewayTransport::FirecrackerVsockUds { uds_base, port } => {
            service.serve_firecracker_vsock(&uds_base, port).await
        }
        #[cfg(target_os = "macos")]
        GatewayTransport::VzVsockProxyUds { uds_path, port } => {
            tracing::info!(path = %uds_path.display(), port, "NodeGateway serving over VZ helper proxy");
            service.serve_unix_socket(&uds_path).await
        }
    }
}

#[cfg(target_os = "linux")]
fn default_backend() -> impl SandboxBackend {
    FirecrackerBackend::new()
}

#[cfg(target_os = "macos")]
fn default_backend() -> impl SandboxBackend {
    VzBackend::new()
}

#[cfg(target_os = "linux")]
fn backend_label() -> &'static str {
    "firecracker"
}

#[cfg(target_os = "macos")]
fn backend_label() -> &'static str {
    "vz"
}

/// Wait for the genome's boot hello event with the expected `session=<task>`
/// detail, up to `timeout`. Other events (none expected at boot in C-2) are
/// drained while waiting.
async fn wait_for_hello(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    task: &str,
    timeout: Duration,
) -> Option<Event> {
    let expected_detail = format!("session={task}");
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(ev)) if ev.kind == "hello" && ev.detail == expected_detail => return Some(ev),
            Ok(Some(_)) => continue, // some other event; keep waiting for hello
            Ok(None) => return None, // observer dropped
            Err(_) => return None,   // timed out
        }
    }
}
