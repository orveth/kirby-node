//! The stub genome (spec 3.6 and D-12).
//!
//! A static musl binary that runs inside the Firecracker microVM as PID 1 (the
//! init process off a read-only squashfs root). It reaches the daemon ONLY over
//! vsock (spec 3.1); it has no IP route, no host filesystem, no keys, and no
//! balance.
//!
//! C-2 implemented just enough to prove the boot path (gate G1): connect to the
//! daemon over vsock, pull the session context (`GetSessionContext`), and report
//! a boot "hello" event tagged with the session task.
//!
//! C-10 adds the `idempotent` workload (spec 4.2, gate G9): the genome issues a
//! `RequestCapability` with a STABLE idempotency_key K once (PERFORMED, cost C
//! debited), heartbeats to survive a snapshot+resume (the C-7 move), detects the
//! resume via the bumped VMGenID generation, and RE-ISSUES the SAME key K. The
//! daemon dedupes on K against the persisted ledger that crossed the move (D-9),
//! so the re-issue returns DUPLICATE_IGNORED and performs nothing twice (no
//! double-burn). The genome reports both outcomes so the daemon can assert the
//! act performed exactly once across the move.
//!
//! C-4 adds the metering workload (spec 3.3, D-12, gate G2): when the daemon
//! sets `kirby.workload=burn` on the kernel command line, after the boot
//! round-trip the genome allocates and touches measurable memory (so the
//! cgroup's `memory.current` rises) and spins the CPU (so `cpu.stat usage_usec`
//! rises), giving the host meter real, non-zero usage to bill against the
//! treasury until the budget is exhausted and the daemon HALTS the VM. To
//! exercise G3c (self-reported numbers are never billed), the burning genome
//! also periodically reports `cpu=0` over `ReportEvent`: the daemon ignores it
//! and bills what the cgroup actually consumed, so the VM is still halted. C-5
//! adds the `raw-egress` workload (attempt direct outbound, which must fail, gate
//! G4). C-6 adds the `brokered` workload (issue a `RequestCapability` for an ecash
//! settle over vsock, which the daemon performs for real, gate G5). C-7 adds the
//! `snapshot` heartbeat (a post-resume round-trip proves the genome survived a move,
//! gate G6). C-8 adds the entropy re-derive (gate G7): the `snapshot` workload now
//! derives `fingerprint = H(nonce || vm_generation)` from a FRESH `GetEntropyNonce`
//! BEFORE each heartbeat act, so after a resume (the VMGenID generation bumped) it
//! re-derives a DIFFERENT fingerprint; the `resume-noredrive` workload is the
//! deliberately-broken NEGATIVE CONTROL that reuses the pre-snapshot fingerprint and
//! so reports an IDENTICAL one (the nonce-reuse the gate must catch). C-11 adds the
//! `full-loop` workload: the WHOLE survival arc on ONE genome (egress-denied G4,
//! brokered act with key K G5, heartbeat+entropy G6/G7, re-issue K on resume G9), so
//! a single continuous run proves the slices compose into one living organism across
//! a failover. With no `kirby.workload` flag the genome idles after the round-trip
//! (the C-2 default), so G1 is unaffected.
//!
//! Because the genome is PID 1, a clean exit would panic the kernel. It never
//! exits on its own: it burns or idles until the daemon kills the VM (the
//! daemon-initiated budget-death halt, G2). The boot parameters (the host CID,
//! the gateway port, the workload) arrive on the kernel command line the daemon
//! set when it booted the VM.

mod fingerprint;

use std::time::Duration;

use kirby_proto::capability_request::Act;
use kirby_proto::node_gateway_client::NodeGatewayClient;
use kirby_proto::{
    CapabilityRequest, CheckpointBlob, EntropyRequest, Event, Outcome, SessionRequest, SettleEcash,
};
use tokio_vsock::{VsockAddr, VsockStream};
use tonic::transport::{Endpoint, Uri};

/// The well-known guest-side CID of the host (VMADDR_CID_HOST). The genome dials
/// this to reach the daemon's gateway, which Firecracker forwards to the host
/// Unix socket the daemon listens on.
const HOST_CID: u32 = 2;

/// The default gateway vsock port. The daemon passes the actual port on the
/// kernel command line (`kirby.gateway_port=`); this is the fallback.
const DEFAULT_GATEWAY_PORT: u32 = 5000;

fn main() {
    // The genome is PID 1 off a read-only root with no init system, so the
    // kernel pseudo-filesystems are not mounted for it. Mount /proc (needed to
    // read the kernel command line for the gateway port) and /sys; /dev is
    // auto-mounted by the kernel (CONFIG_DEVTMPFS_MOUNT). Best-effort: a failure
    // is logged, and the gateway port falls back to the default.
    mount_pseudo_filesystems();

    // A single-threaded current-thread runtime keeps the static binary lean; the
    // boot path is a handful of sequential RPCs, not a throughput workload.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(run());
}

/// Mount the kernel pseudo-filesystems the genome needs as PID 1. Raw `mount`
/// syscalls (no init system in the image). Errors are non-fatal: /proc feeds the
/// gateway-port lookup, which has a default fallback.
#[cfg(target_os = "linux")]
fn mount_pseudo_filesystems() {
    // (source, target, fstype). The mount points exist in the read-only squashfs.
    let mounts = [("proc", "/proc", "proc"), ("sysfs", "/sys", "sysfs")];
    for (source, target, fstype) in mounts {
        let source = std::ffi::CString::new(source).unwrap();
        let target_c = std::ffi::CString::new(target).unwrap();
        let fstype = std::ffi::CString::new(fstype).unwrap();
        // SAFETY: all pointers are valid NUL-terminated C strings for the
        // duration of the call; flags 0 and null data are valid for these
        // virtual filesystems.
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                fstype.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            boot_log(&format!("WARN: mount {target} failed: {err}"));
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn mount_pseudo_filesystems() {
    boot_log("WARN: pseudo-filesystem mounts skipped outside the Linux guest target");
}

async fn run() {
    let port = gateway_port_from_cmdline().unwrap_or(DEFAULT_GATEWAY_PORT);
    boot_log(&format!(
        "kirby-genome init: dialing daemon gateway over vsock (host cid {HOST_CID}, port {port})"
    ));

    // The vsock connection drops across a snapshot restore (spec section 11), so
    // connecting is retried: at cold boot the daemon may still be wiring the
    // listener, and on resume the channel is freshly established. C-2 only needs
    // the cold-boot round-trip; the retry also makes resume (C-7) connect cleanly.
    let mut client = match connect_with_retry(port).await {
        Ok(c) => c,
        Err(e) => {
            boot_log(&format!("FATAL: could not reach daemon gateway: {e}"));
            // PID 1 must not exit (kernel panic); idle so the daemon can observe
            // the failure on the serial log and tear the VM down deliberately.
            idle_forever().await;
        }
    };
    boot_log("connected to daemon gateway");

    // The boot round-trip (gate G1): pull the non-secret session context.
    let ctx = match client
        .get_session_context(SessionRequest { schema_version: kirby_proto::SCHEMA_VERSION })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(status) => {
            boot_log(&format!("FATAL: GetSessionContext failed: {status}"));
            idle_forever().await;
        }
    };
    boot_log(&format!(
        "GetSessionContext ok: task={:?} budget_sats={} allowlist={:?} restore_checkpoint={:?} restore_blob_len={}",
        ctx.task_descriptor,
        ctx.budget_sats,
        ctx.allowlisted_destinations,
        ctx.restore_checkpoint,
        ctx.restore_checkpoint_blob.len()
    ));

    // Report the boot "hello" event tagged with the session task. This is the
    // machine-checkable proof the genome booted and completed the round-trip
    // (the daemon asserts a "hello" event with session=<task> arrived, G1).
    let hello = Event {
        schema_version: kirby_proto::SCHEMA_VERSION,
        kind: "hello".into(),
        detail: format!("session={}", ctx.task_descriptor),
    };
    match client.report_event(hello).await {
        Ok(_) => boot_log(&format!("hello reported (session={})", ctx.task_descriptor)),
        Err(status) => boot_log(&format!("WARN: hello ReportEvent failed: {status}")),
    }

    // Boot proven. The post-boot behavior depends on the workload the daemon set
    // on the kernel command line. `burn` runs the metering workload (C-4, G2);
    // `raw-egress` runs the egress probe (C-5, G4); `brokered` issues a brokered
    // act over vsock (C-6, G5); anything else (including absent) idles (the C-2
    // default, G1 unaffected).
    match workload_from_cmdline().as_deref() {
        Some("burn") => {
            boot_log("workload=burn: allocating memory and spinning CPU for the host meter (G2)");
            burn_forever(&mut client).await;
        }
        Some("raw-egress") => {
            boot_log("workload=raw-egress: attempting direct outbound (must FAIL, gate G4)");
            attempt_raw_egress(&mut client).await;
            // The attempt is done and reported; park (PID 1 must not exit) so the
            // daemon can read the eBPF egress counter and the nftables drop
            // counter, then tear the VM down (G4).
            idle_forever().await;
        }
        Some("brokered") => {
            boot_log("workload=brokered: requesting a brokered ecash settle over vsock (gate G5)");
            request_brokered_act(&mut client, &ctx).await;
            // The request is done and reported; park (PID 1 must not exit) so the
            // daemon can read the receipt and the egress counters, then tear the
            // VM down (G5).
            idle_forever().await;
        }
        Some("app-checkpoint") => {
            boot_log("workload=app-checkpoint: submitting a portable logical checkpoint over vsock");
            submit_app_checkpoint(&mut client, &ctx, AppCheckpointMode::Clean).await;
            idle_forever().await;
        }
        Some("app-checkpoint-smuggle-secret") => {
            boot_log("workload=app-checkpoint-smuggle-secret: NEGATIVE CONTROL, smuggles stale ephemeral state in the logical checkpoint");
            submit_app_checkpoint(&mut client, &ctx, AppCheckpointMode::SmuggleSecret).await;
            idle_forever().await;
        }
        Some("snapshot") => {
            boot_log("workload=snapshot: heartbeat round-trips + entropy re-derive so a post-resume fingerprint differs (gates G6, G7)");
            // The genome heartbeats a GetSessionContext + ReportEvent round-trip on
            // a tick, RE-DIALING vsock whenever the channel breaks. Across a
            // snapshot+restore the vsock connection drops (the plan's "in-flight
            // vsock loss on resume"), so after the daemon restores the VM on node 2
            // the genome's next heartbeat fails on the dead channel, it re-dials the
            // fresh node-2 gateway, and the round-trip lands again. That post-resume
            // round-trip (observed by node 2's daemon) is the machine-checkable G6
            // proof the genome SURVIVED the move. BEFORE each heartbeat act the
            // genome calls GetEntropyNonce and re-derives fingerprint = H(nonce ||
            // generation); after the resume the generation bumped and the nonce is
            // fresh, so the post-resume fingerprint DIFFERS from the pre-snapshot one
            // (gate G7, the re-derive-before-act proof). The genome never exits (PID 1).
            snapshot_heartbeat(client, port, ReDerive::Always).await;
        }
        Some("resume-noredrive") => {
            boot_log("workload=resume-noredrive: NEGATIVE CONTROL, reuses the pre-snapshot fingerprint after resume (G7 must catch this)");
            // The DELIBERATELY-BROKEN genome (the G7 negative control, spec 7-G7 /
            // 4.4 / D-5). It derives its fingerprint ONCE before the snapshot and
            // CACHES it, then after the resume REUSES that cached fingerprint instead
            // of re-calling GetEntropyNonce. This is the catastrophic nonce-reuse the
            // gate exists to catch: the post-resume fingerprint EQUALS the pre-snapshot
            // one (in the real system, a reused FROST nonce that leaks the key share).
            // The G7 test runs this variant and asserts the fingerprints MATCH, which
            // is exactly what the gate FAILS on, proving the gate has teeth (it
            // distinguishes a re-deriving genome from a reusing one). PID 1 never exits.
            snapshot_heartbeat(client, port, ReDerive::Never).await;
        }
        Some("idempotent") => {
            boot_log("workload=idempotent: issue a brokered act with key K, survive a resume, RE-ISSUE K (must DUPLICATE_IGNORED, gate G9)");
            // The G9 workload (spec 4.2, idempotent-across-resume): issue a brokered
            // RequestCapability with a STABLE idempotency_key once (PERFORMED), then
            // heartbeat to survive the snapshot+resume, and after the VMGenID
            // generation BUMPS (the resume) RE-ISSUE the SAME key. The daemon dedupes
            // on the key against the persisted ledger that crossed the move (D-9), so
            // the re-issue is DUPLICATE_IGNORED and the act is NOT performed twice.
            idempotent_capability_across_resume(client, port, &ctx).await;
        }
        Some("full-loop") => {
            boot_log("workload=full-loop: the whole survival arc on ONE genome (C-11): egress-denied, brokered act K, heartbeat+entropy, survive a failover, RE-ISSUE K");
            // The C-11 capstone workload: ONE genome that proves the slices COMPOSE
            // into a single living organism across a failover. The arc, in order:
            //   1. ATTEMPT a raw egress (it must FAIL: the eBPF/nftables lockdown,
            //      gate G4). Reported as `raw_egress_result` so the daemon confirms it.
            //   2. Issue a brokered act with a STABLE idempotency_key K (PERFORMED,
            //      cost C, gate G5). Reported as `idem_first`.
            //   3. Heartbeat to survive the snapshot+resume (gate G6), re-deriving the
            //      entropy fingerprint from a FRESH GetEntropyNonce before each beat
            //      (gate G7, so the post-resume fingerprint differs from the
            //      pre-snapshot one). The fingerprint rides in the heartbeat detail.
            //   4. After the VMGenID generation BUMPS (the resume), RE-ISSUE the SAME
            //      key K once (DUPLICATE_IGNORED, gate G9). Reported as `idem_reissue`.
            // PID 1 never exits; it keeps heartbeating so the new active node still
            // sees it ALIVE after the move.
            full_loop(client, port, &ctx).await;
        }
        _ => {
            boot_log("no burn workload: idling (the daemon meters/halts or tears down)");
            idle_forever().await;
        }
    }
}

/// Submit one portable logical checkpoint. The payload is intentionally small and
/// deterministic: it contains only non-secret session metadata plus any restore
/// reference the daemon supplied. Ephemeral secrets still come from GetEntropyNonce
/// after boot, never from this blob.
enum AppCheckpointMode {
    Clean,
    SmuggleSecret,
}

async fn submit_app_checkpoint(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    ctx: &kirby_proto::SessionContext,
    mode: AppCheckpointMode,
) {
    let restore = ctx
        .restore_checkpoint
        .as_ref()
        .map(|r| format!("sha256={} len={}", r.sha256, r.len))
        .unwrap_or_else(|| "none".to_string());
    if ctx.restore_checkpoint.is_some() {
        let detail = format!(
            "restore_seen {restore} blob_len={}",
            ctx.restore_checkpoint_blob.len()
        );
        report_brokered(client, "checkpoint_restore_seen", &detail).await;
    }

    let mut payload = format!(
        "task={} budget_sats={} restore={restore}",
        ctx.task_descriptor, ctx.budget_sats
    )
    .into_bytes();
    if matches!(mode, AppCheckpointMode::SmuggleSecret) {
        payload.extend_from_slice(b" stale_nonce=negative-control-reused-across-restore");
    }
    let payload_len = payload.len();

    match client
        .submit_checkpoint(CheckpointBlob {
            schema_version: kirby_proto::SCHEMA_VERSION,
            payload,
        })
        .await
    {
        Ok(resp) => {
            let ack = resp.into_inner();
            let detail = format!(
                "checkpoint_submitted payload_len={payload_len} ack_schema={}",
                ack.schema_version
            );
            report_brokered(client, "checkpoint_submitted", &detail).await;
            boot_log(&detail);
        }
        Err(status) => {
            let detail = format!("checkpoint_submit_failed status={status}");
            report_brokered(client, "checkpoint_submit_failed", &detail).await;
            boot_log(&detail);
        }
    }
}

/// The brokered-act workload (spec 3.2, D-6, gate G5). The genome asks the daemon
/// to SETTLE ECASH on the mint by issuing a `RequestCapability` over vsock; the
/// DAEMON authorizes it against the treasury, performs the real settle using a
/// host-held credential the genome NEVER sees, meters it, and returns the receipt.
///
/// This is the heart of D-6: the genome has agency (it can make the world act)
/// ONLY through the brokered gateway, NEVER raw network. The genome chooses the
/// destination (the mint, from its allowlist), the amount, and a budget; it
/// receives back an outcome, a metered cost, the post-debit treasury balance, and
/// the rail's receipt (the mint's preimage) but never the credential that produced
/// it. The genome reports the receipt over `ReportEvent` so the daemon (and the
/// G5 test) can assert the act authorized + performed + debited.
async fn request_brokered_act(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    ctx: &kirby_proto::SessionContext,
) {
    // Settle against the first allowlisted destination (the mint the daemon told
    // the genome about in its session context). The genome knows the mint id (it
    // is non-secret) but NOT the credential to spend on it.
    let mint_id = match ctx.allowlisted_destinations.first() {
        Some(m) => m.clone(),
        None => {
            report_brokered(client, "brokered_result", "FAILED: no allowlisted mint in the session context").await;
            return;
        }
    };

    // A modest settle well within the budget. The amount is the genome's intent;
    // the daemon caps the actual spend at the estimate and the treasury (D-20).
    // A round (power-of-2) amount melts cleanly against the mint's keyset
    // denominations; the wallet is funded with ample headroom for any fee.
    let amount: u64 = 64;
    let budget: u64 = 256;

    let request = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        // A stable idempotency key so a snapshot-resume re-issue dedupes (G9, a
        // later chunk uses this; here it just keys the single act).
        idempotency_key: "brokered-settle-1".to_string(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: mint_id.clone(),
            amount,
            recipient_or_quote: "spike-settle".to_string(),
        })),
        budget_sats: budget,
    };

    report_brokered(
        client,
        "brokered_request",
        &format!("RequestCapability settle_ecash mint={mint_id} amount={amount} budget={budget}"),
    )
    .await;

    match client.request_capability(request).await {
        Ok(resp) => {
            let receipt = resp.into_inner();
            let outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
            // The genome receives the receipt (outcome, cost, post-debit balance,
            // and the rail's opaque proof) but NEVER the credential. A non-empty
            // proof here is the mint's own receipt the daemon produced host-side.
            let summary = if outcome == Outcome::AuthorizedAndPerformed {
                format!(
                    "brokered_result PERFORMED: outcome=AUTHORIZED_AND_PERFORMED cost_sats={} treasury_remaining={} proof_len={}",
                    receipt.cost_sats, receipt.treasury_remaining, receipt.proof.len()
                )
            } else {
                format!(
                    "brokered_result NOT_PERFORMED: outcome={:?} cost_sats={} treasury_remaining={}",
                    outcome, receipt.cost_sats, receipt.treasury_remaining
                )
            };
            report_brokered(client, "brokered_result", &summary).await;
            boot_log(&summary);
        }
        Err(status) => {
            let detail = format!("brokered_result FAILED: RequestCapability errored: {status}");
            report_brokered(client, "brokered_result", &detail).await;
            boot_log(&detail);
        }
    }
}

/// Report a brokered-act outcome to the daemon over vsock (the only channel that
/// works from inside the VM). The daemon keys the G5 verdict on these events.
async fn report_brokered(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    kind: &str,
    detail: &str,
) {
    boot_log(detail);
    let _ = client
        .report_event(Event {
            schema_version: kirby_proto::SCHEMA_VERSION,
            kind: kind.into(),
            detail: detail.into(),
        })
        .await;
}

/// The stable idempotency key the G9 workload issues before and after a resume.
/// The whole point of G9: the SAME key re-issued after the move dedupes against
/// the persisted ledger that crossed it (D-9), so the act performs exactly once.
const IDEMPOTENT_KEY: &str = "idem-act-K";

/// The G9 workload (spec 4.2, idempotent-across-resume, gate G9): issue a brokered
/// act with a STABLE idempotency_key K once, survive a snapshot+resume, then
/// RE-ISSUE the SAME key K and confirm the daemon dedupes it (DUPLICATE_IGNORED),
/// performing nothing twice.
///
/// The flow:
///   1. Issue `RequestCapability` for an ecash settle with key K. The daemon
///      authorizes + performs it for real (the C-3 5-step order, the C-6 rail),
///      debits cost C, and records K -> receipt in the persisted ledger. The
///      genome reports the outcome as `idem_first` (the daemon expects
///      AUTHORIZED_AND_PERFORMED here).
///   2. Heartbeat to stay alive and to OBSERVE the resume: before each heartbeat the
///      genome calls GetEntropyNonce (the C-8 path) and reads the current VMGenID
///      generation. The generation it saw when it issued K is the baseline; when the
///      generation BUMPS above that baseline (the daemon bumped it on the restore,
///      spec 4.4), the genome knows it has been resumed on another node.
///   3. After the resume, RE-ISSUE the SAME key K. The daemon's STEP 1 dedupe finds
///      K in the persisted ledger that crossed the move (D-9), so it returns
///      DUPLICATE_IGNORED with the PRIOR receipt and performs nothing. The genome
///      reports this as `idem_reissue` (the daemon expects DUPLICATE_IGNORED, the
///      same cost C, and the SAME treasury balance the first act left). It re-issues
///      ONCE (a flag guards against re-issuing every beat) and then keeps
///      heartbeating so node 2's daemon still sees it alive.
///
/// Like the snapshot workload, every RPC re-dials on a dead channel (the vsock drops
/// across the move), so the post-resume re-issue lands on node 2's gateway.
async fn idempotent_capability_across_resume(
    mut client: NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    ctx: &kirby_proto::SessionContext,
) -> ! {
    // The settle act keyed by the STABLE idempotency key. The mint is the first
    // allowlisted destination (non-secret); the genome never sees the credential.
    let mint_id = ctx
        .allowlisted_destinations
        .first()
        .cloned()
        .unwrap_or_default();
    let amount: u64 = 64;
    let budget: u64 = 256;
    let make_request = || CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: IDEMPOTENT_KEY.to_string(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: mint_id.clone(),
            amount,
            recipient_or_quote: "idem-settle".to_string(),
        })),
        budget_sats: budget,
    };

    // STEP 1: issue K once. Retry on a dead channel so the first act lands even if
    // the boot race left the gateway briefly unbound. Report the outcome as
    // `idem_first` (the daemon keys the "performed once" half of G9 on it).
    let baseline_gen = loop {
        // Read the generation we are issuing AT, so a later bump signals the resume.
        let gen_at_issue = match read_generation(&mut client).await {
            Some(g) => g,
            None => {
                client = redial(port).await.unwrap_or(client);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        match client.request_capability(make_request()).await {
            Ok(resp) => {
                let receipt = resp.into_inner();
                let outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
                let detail = format!(
                    "idem_first outcome={outcome:?} cost_sats={} treasury_remaining={} gen_at_issue={gen_at_issue}",
                    receipt.cost_sats, receipt.treasury_remaining
                );
                report_brokered(&mut client, "idem_first", &detail).await;
                boot_log(&detail);
                break gen_at_issue;
            }
            Err(status) => {
                boot_log(&format!("idem_first: RequestCapability errored ({status}); re-dialing"));
                client = redial(port).await.unwrap_or(client);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    };

    // STEP 2 + 3: heartbeat to survive the move, watch the generation, and re-issue K
    // exactly once after the resume (the generation bumped above the baseline).
    let mut beat: u64 = 0;
    let mut reissued = false;
    loop {
        beat += 1;
        // Read the current generation (also re-dials on a dead channel after the
        // move, so the post-resume heartbeat reconnects to node 2's gateway).
        let current_gen = match read_generation(&mut client).await {
            Some(g) => g,
            None => {
                boot_log("idem heartbeat: GetEntropyNonce failed; re-dialing the gateway (post-resume reconnect)");
                client = redial(port).await.unwrap_or(client);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        // A heartbeat round-trip so node 2's daemon sees the genome ALIVE across the
        // move (the same survival signal the snapshot workload emits, gate G6).
        let _ = client
            .report_event(Event {
                schema_version: kirby_proto::SCHEMA_VERSION,
                kind: "heartbeat".into(),
                detail: format!("beat={beat} task={} gen_seen={current_gen}", ctx.task_descriptor),
            })
            .await;

        // The resume signal: the VMGenID generation bumped above the baseline (the
        // daemon bumped it on the restore). Re-issue K ONCE; the daemon must dedupe.
        if current_gen > baseline_gen && !reissued {
            boot_log(&format!(
                "idem: detected resume (generation {baseline_gen} -> {current_gen}); RE-ISSUING key K (must DUPLICATE_IGNORED, G9)"
            ));
            match client.request_capability(make_request()).await {
                Ok(resp) => {
                    let receipt = resp.into_inner();
                    let outcome =
                        Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
                    let detail = format!(
                        "idem_reissue outcome={outcome:?} cost_sats={} treasury_remaining={} gen_now={current_gen}",
                        receipt.cost_sats, receipt.treasury_remaining
                    );
                    report_brokered(&mut client, "idem_reissue", &detail).await;
                    boot_log(&detail);
                    reissued = true;
                }
                Err(status) => {
                    // A dead channel on the re-issue: re-dial and retry on the next
                    // beat (do NOT mark reissued, so the re-issue still happens).
                    boot_log(&format!("idem_reissue: RequestCapability errored ({status}); re-dialing, will retry"));
                    client = redial(port).await.unwrap_or(client);
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// The C-11 capstone workload: the WHOLE survival arc on ONE genome, proving the
/// slices COMPOSE into one living organism across a failover (spec C-11). It is the
/// brokered-act + idempotent-replay workload (G5 + G9) with the egress-denied probe
/// (G4) at the front and the entropy fingerprint (G7) carried in the heartbeat
/// (G6), so a SINGLE continuous genome run exercises the whole chain end to end.
///
/// The arc, in order:
///   1. ATTEMPT a raw outbound (TCP to an external IP, a UDP DNS query). The eBPF/
///      nftables lockdown drops it, so every attempt FAILS; reported as
///      `raw_egress_result DENIED ...` (gate G4). The genome can reach the daemon
///      over vsock (this report travels it) but NOT the internet.
///   2. Issue a brokered `RequestCapability` for an ecash settle with a STABLE
///      idempotency_key K. The daemon authorizes + PERFORMS it for real (cost C) and
///      records K in the persisted ledger; reported as `idem_first` (gate G5).
///   3. Heartbeat on a tick to survive the snapshot+resume (gate G6), RE-DIALING on a
///      dead channel (the vsock drops on the move). BEFORE each beat the genome calls
///      GetEntropyNonce and derives `fingerprint = H(nonce || generation)`, so after
///      the resume (bumped generation, fresh nonce) the fingerprint DIFFERS from the
///      pre-snapshot one (gate G7). The fingerprint + the generation ride in the beat.
///   4. When the generation BUMPS above the at-issue baseline (the daemon bumped it on
///      the restore, the resume signal), RE-ISSUE the SAME key K once. The daemon's
///      dedupe finds K in the ledger that crossed the move and returns
///      DUPLICATE_IGNORED, performing nothing twice; reported as `idem_reissue`
///      (gate G9). PID 1 never exits.
async fn full_loop(
    mut client: NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    ctx: &kirby_proto::SessionContext,
) -> ! {
    // ---- STEP 1: egress-denied (gate G4). ATTEMPT a raw outbound; it must FAIL. ----
    // A short timeout so a silently-dropped SYN does not hang the probe (the drop
    // yields no RST). The vsock to the daemon is the ONLY channel that works, which
    // is itself the proof isolation holds while the genome still has gateway agency.
    let probe_timeout = Duration::from_secs(3);
    let p_tcp = tcp_probe("1.1.1.1:443", probe_timeout);
    report_egress(&mut client, "raw_egress_attempt", &format!("tcp 1.1.1.1:443 -> {p_tcp}")).await;
    let p_dns = udp_dns_probe("8.8.8.8:53", probe_timeout);
    report_egress(&mut client, "raw_egress_attempt", &format!("dns udp 8.8.8.8:53 -> {p_dns}")).await;
    let leaked = p_tcp.starts_with("LEAKED") || p_dns.starts_with("LEAKED");
    let egress_summary = if leaked {
        "raw_egress_result LEAKED: a direct outbound succeeded (G4 FAIL)"
    } else {
        "raw_egress_result DENIED: every direct outbound failed (no route / blocked); only vsock works (G4)"
    };
    report_egress(&mut client, "raw_egress_result", egress_summary).await;
    boot_log(egress_summary);

    // ---- STEP 2: the brokered act with a STABLE key K (gate G5). ----
    // Settle against the first allowlisted destination (the mint; non-secret). The
    // genome chooses the destination, amount, and budget; the daemon holds the
    // credential and performs the real settle host-side. K keys the act so a
    // post-resume re-issue dedupes (gate G9).
    let mint_id = ctx.allowlisted_destinations.first().cloned().unwrap_or_default();
    let amount: u64 = 64;
    let budget: u64 = 256;
    let make_request = || CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: IDEMPOTENT_KEY.to_string(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: mint_id.clone(),
            amount,
            recipient_or_quote: "full-loop-settle".to_string(),
        })),
        budget_sats: budget,
    };

    // Issue K once, recording the generation we issued AT so a later bump signals the
    // resume. Retry on a dead channel so the first act lands even if the boot race
    // left the gateway briefly unbound. Report `idem_first` (the daemon keys the
    // "performed once" half of G9 + the G5 brokered-act evidence on it).
    let baseline_gen = loop {
        let gen_at_issue = match read_generation(&mut client).await {
            Some(g) => g,
            None => {
                client = redial(port).await.unwrap_or(client);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        match client.request_capability(make_request()).await {
            Ok(resp) => {
                let receipt = resp.into_inner();
                let outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
                let detail = format!(
                    "idem_first outcome={outcome:?} cost_sats={} treasury_remaining={} proof_len={} gen_at_issue={gen_at_issue}",
                    receipt.cost_sats, receipt.treasury_remaining, receipt.proof.len()
                );
                report_brokered(&mut client, "idem_first", &detail).await;
                boot_log(&detail);
                break gen_at_issue;
            }
            Err(status) => {
                boot_log(&format!("full-loop idem_first: RequestCapability errored ({status}); re-dialing"));
                client = redial(port).await.unwrap_or(client);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    };

    // ---- STEP 3 + 4: heartbeat (survive the move, gate G6) with the entropy
    // fingerprint (gate G7), and RE-ISSUE K once after the resume (gate G9). ----
    let mut beat: u64 = 0;
    let mut reissued = false;
    loop {
        beat += 1;
        // Derive the entropy fingerprint from a FRESH GetEntropyNonce BEFORE the beat
        // act (gate G7: re-derive before acting). This also reads the current
        // generation (the resume signal) and re-dials on a dead channel (the vsock
        // dropped on the move), so the post-resume heartbeat reconnects to the new
        // active node's gateway.
        let (fingerprint, current_gen) = match derive_entropy_fingerprint(&mut client).await {
            Some(fp) => fp,
            None => {
                boot_log("full-loop heartbeat: GetEntropyNonce failed; re-dialing before acting (no stale fingerprint, G7)");
                client = redial(port).await.unwrap_or(client);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        // A heartbeat round-trip so the active node's daemon sees the genome ALIVE
        // across the move (gate G6). The detail carries the beat, the task (so the
        // new active node confirms it is the SAME genome), the generation, and the
        // entropy fingerprint + the generation it was derived at (gate G7).
        let detail = format!(
            "beat={beat} task={} gen_seen={current_gen} fingerprint={fingerprint} fp_gen={current_gen}",
            ctx.task_descriptor,
        );
        let _ = client
            .report_event(Event {
                schema_version: kirby_proto::SCHEMA_VERSION,
                kind: "heartbeat".into(),
                detail: detail.clone(),
            })
            .await;

        // The resume signal: the generation bumped above the baseline. Re-issue K ONCE
        // (gate G9). The daemon's dedupe must return DUPLICATE_IGNORED, performing
        // nothing twice.
        if current_gen > baseline_gen && !reissued {
            boot_log(&format!(
                "full-loop: detected resume (generation {baseline_gen} -> {current_gen}); RE-ISSUING key K (must DUPLICATE_IGNORED, G9)"
            ));
            match client.request_capability(make_request()).await {
                Ok(resp) => {
                    let receipt = resp.into_inner();
                    let outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
                    let reissue_detail = format!(
                        "idem_reissue outcome={outcome:?} cost_sats={} treasury_remaining={} gen_now={current_gen}",
                        receipt.cost_sats, receipt.treasury_remaining
                    );
                    report_brokered(&mut client, "idem_reissue", &reissue_detail).await;
                    boot_log(&reissue_detail);
                    reissued = true;
                }
                Err(status) => {
                    // A dead channel on the re-issue: re-dial and retry on the next
                    // beat (do NOT mark reissued, so the re-issue still happens).
                    boot_log(&format!("full-loop idem_reissue: RequestCapability errored ({status}); re-dialing, will retry"));
                    client = redial(port).await.unwrap_or(client);
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Read the current VMGenID generation from a fresh GetEntropyNonce (the C-8 path).
/// The G9 workload uses the generation purely as the resume signal (it bumps on a
/// restore, spec 4.4); it does not need the nonce itself. Returns None on a dead
/// channel so the caller re-dials.
async fn read_generation(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
) -> Option<u64> {
    client
        .get_entropy_nonce(EntropyRequest { schema_version: kirby_proto::SCHEMA_VERSION })
        .await
        .ok()
        .map(|resp| resp.into_inner().vm_generation)
}

/// Re-dial the gateway after the vsock dropped on a move. A thin wrapper over
/// `connect_with_retry` so the G9 workload reconnects to node 2's gateway the same
/// way the snapshot workload does.
async fn redial(port: u32) -> Option<NodeGatewayClient<tonic::transport::Channel>> {
    match connect_with_retry(port).await {
        Ok(c) => {
            boot_log("idem: reconnected to the gateway (survived a move)");
            Some(c)
        }
        Err(e) => {
            boot_log(&format!("idem: reconnect failed: {e}"));
            None
        }
    }
}

/// The raw-egress probe (spec 3.7, D-6, gate G4). The genome ATTEMPTS direct
/// outbound from inside the VM: a TCP connect to an external IP, a TCP connect to
/// 1.1.1.1, and a DNS resolution. Every attempt MUST fail (the host nftables
/// default-deny drops the VM's egress and the VM has no route to the internet);
/// the genome reports each outcome over `ReportEvent` so the daemon (and the G4
/// test) can assert the attempts FAILED. The genome never reaches the internet;
/// the only thing that works is the vsock to the daemon (which is how this very
/// report travels, proving isolation is preserved while the gateway is reachable).
///
/// This is the spike-scale proof of D-6: the genome has agency ONLY through the
/// brokered gateway (C-6), NEVER raw network. A success here would be a G4
/// failure (the lockdown leaked), so the genome reports successes loudly too.
async fn attempt_raw_egress(client: &mut NodeGatewayClient<tonic::transport::Channel>) {
    use std::net::{TcpStream, ToSocketAddrs};

    // Each probe returns a one-line outcome string: "DENIED: <reason>" on the
    // expected failure, or "LEAKED: <detail>" if it somehow succeeded (a G4
    // failure the daemon must see). A short timeout so a silently-dropped SYN
    // does not hang the probe (the drop yields no RST, so connect would block
    // until the OS timeout without this).
    let probe_timeout = Duration::from_secs(3);

    // Probe 1: TCP connect to 1.1.1.1:443 (the spec's literal example). The SYN
    // leaves eth0, the host TAP nftables drops it, no SYN-ACK returns, connect
    // fails (timeout or no-route). A success means the lockdown leaked.
    let p1 = tcp_probe("1.1.1.1:443", probe_timeout);
    report_egress(client, "raw_egress_attempt", &format!("tcp 1.1.1.1:443 -> {p1}")).await;

    // Probe 2: TCP connect to a different external IP (8.8.8.8:53, DNS-over-TCP).
    let p2 = tcp_probe("8.8.8.8:53", probe_timeout);
    report_egress(client, "raw_egress_attempt", &format!("tcp 8.8.8.8:53 -> {p2}")).await;

    // Probe 3: DNS resolution of a name. With no route and a dropped egress, the
    // UDP query to any resolver gets no answer; resolution fails. Try a direct
    // UDP query to a public resolver (the simplest name-resolution attempt that
    // puts a packet on the wire), then also the libc resolver path.
    let p3 = udp_dns_probe("8.8.8.8:53", probe_timeout);
    report_egress(client, "raw_egress_attempt", &format!("dns udp 8.8.8.8:53 -> {p3}")).await;

    // Probe 4: the libc name resolver (getaddrinfo via ToSocketAddrs). With no
    // working DNS this fails; it is the "resolve a name" attempt from the genome's
    // own runtime, not just a hand-rolled UDP packet.
    let p4 = match "example.com:443".to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            // Even if resolution somehow returned an address, a connect must fail.
            Some(addr) => match TcpStream::connect_timeout(&addr, probe_timeout) {
                Ok(_) => "LEAKED: resolved AND connected to example.com".to_string(),
                Err(e) => format!("DENIED: resolved {addr} but connect failed: {e}"),
            },
            None => "DENIED: resolver returned no addresses".to_string(),
        },
        Err(e) => format!("DENIED: name resolution failed: {e}"),
    };
    report_egress(client, "raw_egress_attempt", &format!("resolve example.com -> {p4}")).await;

    // A final summary line the daemon keys on: did ANY probe leak?
    let leaked = [&p1, &p2, &p3, &p4].iter().any(|s| s.starts_with("LEAKED"));
    let summary = if leaked {
        "raw_egress_result LEAKED: at least one direct outbound succeeded (G4 FAIL)"
    } else {
        "raw_egress_result DENIED: every direct outbound failed (no route / blocked); only vsock works (G4)"
    };
    report_egress(client, "raw_egress_result", summary).await;
    boot_log(summary);
}

/// A TCP connect probe: attempt to connect to `addr` within `timeout`. Returns
/// "DENIED: <reason>" on the expected failure (the lockdown worked) or
/// "LEAKED: connected" if it succeeded (a G4 failure). Resolving `addr` here is a
/// literal IP:port, so this isolates the TCP egress attempt from name resolution.
fn tcp_probe(addr: &str, timeout: Duration) -> String {
    use std::net::{SocketAddr, TcpStream};
    let sa: SocketAddr = match addr.parse() {
        Ok(sa) => sa,
        Err(e) => return format!("DENIED: bad probe addr {addr}: {e}"),
    };
    match TcpStream::connect_timeout(&sa, timeout) {
        Ok(_) => "LEAKED: connected".to_string(),
        Err(e) => format!("DENIED: {} ({e})", e.kind()),
    }
}

/// A UDP DNS probe: send a minimal DNS query for example.com to `resolver` and
/// wait briefly for a reply. With the egress lockdown the query is dropped and no
/// reply arrives, so this returns "DENIED: no reply". A reply would be "LEAKED".
fn udp_dns_probe(resolver: &str, timeout: Duration) -> String {
    use std::net::UdpSocket;
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => return format!("DENIED: cannot bind udp socket: {e}"),
    };
    if let Err(e) = sock.set_read_timeout(Some(timeout)) {
        return format!("DENIED: set_read_timeout failed: {e}");
    }
    // A minimal DNS query for example.com A record (id 0x1234, RD set).
    let query: [u8; 29] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    if let Err(e) = sock.send_to(&query, resolver) {
        // send_to failing (e.g. network unreachable) is also a DENIED outcome.
        return format!("DENIED: send failed: {} ({e})", e.kind());
    }
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => format!("LEAKED: got {n}-byte DNS reply from {from}"),
        Err(e) => format!("DENIED: no reply ({})", e.kind()),
    }
}

/// Report a raw-egress probe outcome to the daemon over vsock. This is the ONLY
/// channel that works from inside the locked-down VM (vsock is not IP), which is
/// itself the proof: the genome can reach the daemon but not the internet.
async fn report_egress(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    kind: &str,
    detail: &str,
) {
    boot_log(detail);
    let _ = client
        .report_event(Event {
            schema_version: kirby_proto::SCHEMA_VERSION,
            kind: kind.into(),
            detail: detail.into(),
        })
        .await;
}

/// The metering workload (spec 3.3, D-12, gate G2). Allocate and TOUCH a block
/// of memory so the cgroup charges it (`memory.current` rises; untouched pages
/// are not resident, so the genome writes every page), then spin the CPU
/// forever (so `cpu.stat usage_usec` rises). The genome never stops on its own:
/// the daemon's host meter bills this real usage against the treasury and KILLS
/// the VM when the budget is exhausted (the daemon-initiated halt, G2).
///
/// Periodically the genome reports `cpu=0` over `ReportEvent` to exercise G3c:
/// the daemon ignores self-reported numbers and bills the cgroup, so a genome
/// lying about its CPU is still metered and still halted.
async fn burn_forever(client: &mut NodeGatewayClient<tonic::transport::Channel>) -> ! {
    // Allocate a measurable block (32 MiB) and touch every page so it becomes
    // resident and the cgroup memory controller charges it. A read-only or
    // never-touched allocation would not move memory.current.
    const BLOCK_BYTES: usize = 32 * 1024 * 1024;
    let mut block = vec![0u8; BLOCK_BYTES];
    let page = 4096;
    let mut i = 0;
    while i < block.len() {
        block[i] = 1;
        i += page;
    }
    boot_log(&format!("touched {} MiB resident (memory.current should rise)", BLOCK_BYTES / (1024 * 1024)));

    // Spin the CPU and keep the block resident. Re-touch the block each round so
    // it stays charged, and report a (false) cpu=0 every so often (G3c). A
    // volatile-ish accumulator stops the optimizer eliding the spin.
    let mut acc: u64 = 0;
    let mut round: u64 = 0;
    loop {
        // A burst of pure CPU work (the meter reads cgroup CPU time, not this
        // number; it just has to consume real cycles).
        for n in 0..5_000_000u64 {
            acc = acc.wrapping_add(n ^ round);
        }
        // Keep the memory resident.
        let block_len = block.len();
        block[(round as usize * page) % block_len] = (acc & 0xff) as u8;
        round += 1;

        // Every few rounds, lie to the daemon: claim cpu=0. The daemon must
        // still bill the real cgroup usage and halt us (G3c). Best-effort; a
        // send failure (the daemon may be tearing us down) is ignored.
        if round.is_multiple_of(4) {
            let _ = client
                .report_event(Event {
                    schema_version: kirby_proto::SCHEMA_VERSION,
                    kind: "self_meter".into(),
                    // A deliberate under-report: cpu=0 while burning real CPU.
                    detail: format!("cpu=0 mem=0 acc={}", acc & 0xffff),
                })
                .await;
            // Yield so the report can flush; the spin resumes immediately.
            tokio::task::yield_now().await;
        }
    }
}

/// Whether the genome re-derives its entropy fingerprint before each act. The
/// correct genome ([`ReDerive::Always`]) calls GetEntropyNonce and re-derives the
/// fingerprint before EVERY heartbeat act, so after a resume (bumped generation,
/// fresh nonce) the fingerprint differs (gate G7). The NEGATIVE CONTROL
/// ([`ReDerive::Never`]) derives once before the snapshot, caches that fingerprint,
/// and reuses it after the resume, so the post-resume fingerprint is IDENTICAL (the
/// nonce-reuse the gate must catch). The two share all the survival/reconnect logic
/// so the ONLY difference under test is the re-derive, not the heartbeat machinery.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReDerive {
    /// Re-derive the fingerprint from a fresh GetEntropyNonce before every act
    /// (the correct, G7-passing genome).
    Always,
    /// Derive once, then reuse the cached fingerprint forever, never re-calling
    /// GetEntropyNonce after the first derivation (the broken, G7-failing control).
    Never,
}

/// The snapshot-survival + entropy-re-derive heartbeat workload (spec 4.1, 4.4,
/// section 11, gates G6 + G7). The genome does a GetSessionContext + ReportEvent
/// round-trip on a tick. Across a snapshot+restore on another node the vsock channel
/// drops, so a heartbeat fails; the genome RE-DIALS the (now node-2) gateway and the
/// round-trip lands again. A monotonically increasing beat counter rides in the
/// ReportEvent detail, so the daemon on node 2 sees a fresh `post_resume` heartbeat
/// AFTER the restore, proving the genome survived the move (G6). PID 1 never exits.
///
/// THE G7 RE-DERIVE: on resume the kernel CSPRNG reseeds (VMGenID) but the genome's
/// user-space PRNG does NOT, so the genome must NOT trust an in-process secret across
/// the move. BEFORE each heartbeat act the correct genome ([`ReDerive::Always`]) calls
/// GetEntropyNonce (a fresh host-CSPRNG nonce + the current VMGenID generation) and
/// derives `fingerprint = H(nonce || generation)`. After the resume the generation
/// bumped and the nonce is fresh, so the post-resume fingerprint DIFFERS from the
/// pre-snapshot one: the machine-checkable proof no ephemeral secret survived the
/// move. The negative control ([`ReDerive::Never`]) derives once and reuses it, so its
/// post-resume fingerprint is IDENTICAL, which the gate catches. The fingerprint and
/// the generation it was derived at ride in the heartbeat detail
/// (`fingerprint=<hex> fp_gen=<n>`) so the daemon can pair a fingerprint with the
/// generation it belongs to.
async fn snapshot_heartbeat(
    mut client: NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    mode: ReDerive,
) -> ! {
    let mut beat: u64 = 0;
    // The negative control's cached (fingerprint, generation): derived once, reused
    // forever. None until the first successful derivation. The correct genome never
    // reads this (it re-derives every act).
    let mut cached: Option<(String, u64)> = None;
    loop {
        // One heartbeat round-trip: pull the session context (a real RPC), then
        // report a beat event. If either fails the channel is dead (a resume
        // dropped it), so re-dial and retry on the next tick.
        let ctx = match client
            .get_session_context(SessionRequest { schema_version: kirby_proto::SCHEMA_VERSION })
            .await
        {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                boot_log(&format!(
                    "heartbeat: GetSessionContext failed ({status}); re-dialing the gateway (post-resume reconnect)"
                ));
                match connect_with_retry(port).await {
                    Ok(c) => {
                        client = c;
                        boot_log("heartbeat: reconnected to the gateway (survived a move)");
                    }
                    Err(e) => boot_log(&format!("heartbeat: reconnect failed: {e}")),
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        // Derive (or reuse) the entropy fingerprint BEFORE reporting the beat. For
        // the correct genome this calls GetEntropyNonce every act (so a post-resume
        // act re-derives at the bumped generation). For the negative control it
        // calls GetEntropyNonce ONCE (the first derivation) and reuses the cache
        // thereafter, so a post-resume act NEVER re-calls GetEntropyNonce. The
        // GetEntropyNonce call ordering (before the heartbeat ReportEvent act) is
        // what the daemon observes for the G7 ordering assertion.
        let (fingerprint, fp_gen) = match mode {
            ReDerive::Always => match derive_entropy_fingerprint(&mut client).await {
                Some(fp) => fp,
                None => {
                    // GetEntropyNonce failed on a dead channel: re-dial and retry
                    // the whole heartbeat (do not act on a stale fingerprint).
                    boot_log("heartbeat: GetEntropyNonce failed; re-dialing before acting (no stale fingerprint, G7)");
                    if let Ok(c) = connect_with_retry(port).await {
                        client = c;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            },
            ReDerive::Never => match &cached {
                // The broken path: a fingerprint is already cached, so REUSE it and
                // do NOT call GetEntropyNonce again (the nonce-reuse across the move).
                Some(fp) => fp.clone(),
                // The very first derivation (pre-snapshot): even the broken genome
                // must derive once to have something to reuse. After this it never
                // re-derives.
                None => match derive_entropy_fingerprint(&mut client).await {
                    Some(fp) => {
                        cached = Some(fp.clone());
                        fp
                    }
                    None => {
                        boot_log("heartbeat: GetEntropyNonce failed before the first derivation; re-dialing");
                        if let Ok(c) = connect_with_retry(port).await {
                            client = c;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                },
            },
        };

        beat += 1;
        // The beat event the daemon keys G6 + G7 on: the beat number, the task (so
        // node 2 can confirm it is the SAME genome), the generation the genome
        // currently sees, and the entropy fingerprint plus the generation it was
        // derived at. The daemon pairs the pre-snapshot fingerprint with the
        // post-resume one and asserts they differ (G7).
        let detail = format!(
            "beat={beat} task={} gen_seen={fp_gen} fingerprint={fingerprint} fp_gen={fp_gen}",
            ctx.task_descriptor,
        );
        if client
            .report_event(Event {
                schema_version: kirby_proto::SCHEMA_VERSION,
                kind: "heartbeat".into(),
                detail: detail.clone(),
            })
            .await
            .is_err()
        {
            boot_log("heartbeat: ReportEvent failed; re-dialing on the next tick");
            if let Ok(c) = connect_with_retry(port).await {
                client = c;
            }
        } else {
            boot_log(&format!("heartbeat ok: {detail}"));
        }

        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Re-derive the entropy fingerprint from a FRESH GetEntropyNonce (spec 3.4, 4.4,
/// gate G7). Calls GetEntropyNonce (a fresh 32-byte host-CSPRNG nonce + the current
/// VMGenID generation), then derives `fingerprint = H(nonce || generation)`. Returns
/// the `(fingerprint_hex, generation)` pair, or None if the RPC failed (a dead
/// channel after a resume), so the caller re-dials before acting rather than acting
/// on a stale fingerprint. This is the "call GetEntropyNonce before acting" the gate
/// requires: the genome mixes the host nonce into its ephemeral secret instead of
/// trusting its in-process PRNG, which a resume did NOT reseed.
async fn derive_entropy_fingerprint(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
) -> Option<(String, u64)> {
    let nonce = client
        .get_entropy_nonce(EntropyRequest { schema_version: kirby_proto::SCHEMA_VERSION })
        .await
        .ok()?
        .into_inner();
    let fp = fingerprint::derive(&nonce.nonce, nonce.vm_generation);
    Some((fp, nonce.vm_generation))
}

/// Parse the workload the daemon set on the kernel command line
/// (`kirby.workload=<name>`). Returns None if absent (the genome idles).
fn workload_from_cmdline() -> Option<String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("kirby.workload="))
        .map(|s| s.to_string())
}

/// Dial the daemon gateway over vsock, retrying briefly so a cold boot that
/// races the daemon's listener (or a freshly re-established channel on resume)
/// connects rather than failing on the first attempt.
async fn connect_with_retry(
    port: u32,
) -> Result<NodeGatewayClient<tonic::transport::Channel>, tonic::transport::Error> {
    let mut last_err = None;
    for attempt in 1..=50 {
        match connect(port).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                if attempt % 10 == 0 {
                    boot_log(&format!("gateway not up yet (attempt {attempt}), retrying"));
                }
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(last_err.expect("at least one attempt failed"))
}

/// Build a tonic channel over a single vsock stream to the host. The URI
/// authority is ignored (the connector dials vsock directly); tonic only needs a
/// well-formed URI for the HTTP/2 layer.
async fn connect(
    port: u32,
) -> Result<NodeGatewayClient<tonic::transport::Channel>, tonic::transport::Error> {
    let channel = Endpoint::try_from("http://vsock.invalid")?
        // A per-request deadline so a STALE post-resume call cannot hang forever. After a
        // snapshot+resume the guest's old vsock connection (to the killed source node) is a
        // black hole: the host peer is gone and no RST ever reaches the restored guest, so an
        // RPC on that channel would otherwise block indefinitely and the genome would never
        // reach its re-dial branch (the post-resume reconnect would silently never fire). The
        // timeout converts that hang into a `tonic::Status`, so the existing re-dial logic
        // runs and the genome reconnects to the new active node's gateway.
        .timeout(Duration::from_secs(5))
        // HTTP/2 keepalive PINGs so a dead connection is detected even mid-call.
        .http2_keep_alive_interval(Duration::from_secs(2))
        .keep_alive_timeout(Duration::from_secs(4))
        .keep_alive_while_idle(true)
        .connect_with_connector(tower::service_fn(move |_: Uri| async move {
            let stream = VsockStream::connect(VsockAddr::new(HOST_CID, port)).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }))
        .await?;
    Ok(NodeGatewayClient::new(channel))
}

/// Parse the gateway port the daemon set on the kernel command line
/// (`kirby.gateway_port=<u32>`). Returns None if absent or unparseable, in which
/// case the caller falls back to the default port.
fn gateway_port_from_cmdline() -> Option<u32> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("kirby.gateway_port="))
        .and_then(|v| v.parse().ok())
}

/// Write a boot line to the serial console (stdout is the Firecracker serial
/// port). The daemon scrapes these lines as part of the G1 boot evidence.
fn boot_log(msg: &str) {
    println!("[genome] {msg}");
}

/// Idle forever in a heartbeat loop. PID 1 must never exit (that panics the
/// kernel), so after the boot round-trip the genome parks here until the daemon
/// tears the VM down.
async fn idle_forever() -> ! {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
