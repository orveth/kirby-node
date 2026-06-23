//! The durable-mind-state workload (memory-stub, Chunk-1): the in-VM harness loop that
//! exercises the `Memory` brokered act -- the SIBLING of the brain's `Completion`. Each
//! WRITE (SET/RM) drains the treasury by a HOST-computed storage cost; each READ (GET/LS)
//! is FREE. The genome never speaks to a relay; the daemon's `StubMemory` performs the
//! store op (Chunk-2 swaps in the real NIP-AE engram store, same wire).
//!
//! The loop proves the seam, then lives on it:
//!   1. SET `core` (a write -> drains), then GET it back (the contract returns the VALUE,
//!      not just a hash), then LS (both free), then RE-ISSUE the SET under the SAME
//!      write-seq -> DUPLICATE_IGNORED with NO second debit (idempotent replay, F1).
//!   2. then keep forming memories on a tick (each a fresh write -> drains), recalling
//!      each (a free read), and PARK (`idle_forever`) when a write can no longer be
//!      afforded -- the daemon then halts the VM. Death is the host halt, NOT the loop
//!      breaking (PID 1 must never exit, F4).
//!
//! Dependency-free (F5): the request carries STRUCTURED prost fields, so the genome needs
//! no JSON encoder. WRITES key on a MONOTONIC write-seq (`mem-write-{wseq}`) so a resume
//! retry reuses the seq = exactly-once debit (design doc 10 F1 -- NOT a content hash,
//! which would falsely dedupe a legitimate future re-write); READS key uniquely per call
//! (`mem-get-{slug}-{tick}` / `mem-ls-{tick}`) so each is a fresh, free fetch.

use std::time::Duration;

use kirby_proto::capability_request::Act;
use kirby_proto::node_gateway_client::NodeGatewayClient;
use kirby_proto::{CapabilityRequest, CheckpointBlob, Memory, MemoryOp, Outcome};

use super::{boot_log, idle_forever, redial, report_brokered};

/// The memory checkpoint blob format (Chunk-2 wseq-persist): a 5-byte magic followed by
/// the monotonic `wseq` as 8 big-endian bytes. Dep-free (no JSON, F5) -- the daemon
/// stores it opaquely (content-addressed) and serves it back inline on resume
/// (`SessionContext.restore_checkpoint_blob`), the SAME run-agent restore path the
/// app-checkpoint workload uses. The magic guards against decoding a foreign blob.
const MEM_CKPT_MAGIC: &[u8] = b"KMEM1";

/// Encode the wseq checkpoint blob (magic ‖ wseq big-endian).
fn encode_wseq_checkpoint(wseq: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(MEM_CKPT_MAGIC.len() + 8);
    payload.extend_from_slice(MEM_CKPT_MAGIC);
    payload.extend_from_slice(&wseq.to_be_bytes());
    payload
}

/// Restore the monotonic `wseq` from the session's inline checkpoint blob, or `0` for a
/// fresh boot (no/foreign/short blob). On resume this is the LAST wseq the genome
/// checkpointed, so the next write takes `wseq + 1` -- a NEW seq, never a reset-to-0 that
/// would re-issue `mem-write-1` and false-dedupe against the persistent ledger (the F1
/// bug on a durable store, design doc §16). The daemon's wseq_floor (R2-7) is the
/// authoritative backstop if this blob is ever stale.
fn restore_wseq(ctx: &kirby_proto::SessionContext) -> u64 {
    let blob = &ctx.restore_checkpoint_blob;
    if blob.len() == MEM_CKPT_MAGIC.len() + 8 && blob.starts_with(MEM_CKPT_MAGIC) {
        let mut be = [0u8; 8];
        be.copy_from_slice(&blob[MEM_CKPT_MAGIC.len()..]);
        u64::from_be_bytes(be)
    } else {
        0
    }
}

/// Submit a checkpoint carrying the current `wseq` (Chunk-2). Called after a successful
/// write so the daemon always holds the highest issued seq for a resume. A submit failure
/// is logged, not fatal (the wseq_floor backstop still protects correctness on resume).
async fn submit_wseq_checkpoint(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    wseq: u64,
) {
    let payload = encode_wseq_checkpoint(wseq);
    match client
        .submit_checkpoint(CheckpointBlob { schema_version: kirby_proto::SCHEMA_VERSION, payload })
        .await
    {
        Ok(_) => boot_log(&format!("memory_checkpoint wseq={wseq} submitted")),
        Err(status) => {
            boot_log(&format!("memory_checkpoint wseq={wseq} submit failed: {status}"))
        }
    }
}

// Defaults when the daemon set no `kirby.memory_*=` on the cmdline. They MATCH
// `kirby_node::config::MemoryConfig`'s defaults so a bare `[memory]` and the cmdline path
// agree.
const DEFAULT_MEMORY_MAX_COST_SATS: u64 = 64;
const DEFAULT_MEMORY_TICK_SECS: u64 = 5;

/// The memory loop's runtime knobs, read from the kernel command line (the daemon writes
/// `kirby.memory_max_cost_sats=` and `kirby.memory_tick_secs=` when the workload is
/// `memory`, exactly as the gateway port and workload already travel).
struct MemoryParams {
    /// The per-WRITE budget CEILING the genome attaches to each SET/RM (design doc 12 G2).
    max_cost_sats: u64,
    /// The cadence between scripted ops.
    tick: Duration,
}

/// Parse the memory knobs from `/proc/cmdline`, falling back to the defaults for any
/// absent or unparseable value (so a bare config still runs).
fn memory_params_from_cmdline() -> MemoryParams {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let get = |key: &str| {
        cmdline
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
            .map(|s| s.to_string())
    };
    let max_cost_sats = get("kirby.memory_max_cost_sats=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MAX_COST_SATS);
    let tick_secs = get("kirby.memory_tick_secs=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_TICK_SECS);
    MemoryParams {
        max_cost_sats,
        // At least one second so a misconfigured 0 cannot busy-spin the loop.
        tick: Duration::from_secs(tick_secs.max(1)),
    }
}

/// What a WRITE attempt resolved to, for the loop's control flow.
enum WriteOutcome {
    /// The write was performed (or deduped) -- the agent keeps living.
    Performed,
    /// The write could not be afforded (DENIED over budget / insufficient treasury):
    /// EARN-OR-DIE applied to memory -- the agent can recall but can no longer RECORD.
    Broke,
    /// A transient hiccup (unexpected outcome or a re-dialed channel); keep ticking.
    Transient,
}

/// The memory loop (durable-mind-state §9): SET/GET/LS/RM through the brokered Memory act,
/// proving the seam then living on it. Never returns (PID 1): it parks on a write denial
/// so the daemon halts the VM (death is the host halt, F4).
pub(super) async fn memory_loop(
    mut client: NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    ctx: &kirby_proto::SessionContext,
) -> ! {
    let params = memory_params_from_cmdline();
    boot_log(&format!(
        "memory_loop: task={} max_cost_sats={} tick_secs={} — writes drain the treasury (storage cost), reads are free; the agent records before it forgets",
        ctx.task_descriptor,
        params.max_cost_sats,
        params.tick.as_secs()
    ));

    // The monotonic write-seq: each WRITE gets a fresh seq -> a distinct idempotency key.
    // RESTORED from the app checkpoint on resume (Chunk-2): a restart does NOT reset it to
    // 0 (which would re-issue `mem-write-1` and false-dedupe a NEW memory against the
    // persistent engram store, the F1 bug). A fresh boot starts at 0. The tick counter
    // keys the unique-per-call READs.
    let restored_wseq = restore_wseq(ctx);
    let mut wseq: u64 = restored_wseq;
    let mut tick: u64 = 0;

    if restored_wseq == 0 {
        // ---- Phase 1 (FRESH boot only): prove the seam (SET -> GET -> LS -> dup replay) ----
        wseq += 1;
        let core_wseq = wseq;
        let core_value = format!("kirby-core:task={}", ctx.task_descriptor).into_bytes();

        // SET core (a write: drains by the host-computed storage cost).
        perform_write(
            &mut client,
            port,
            core_wseq,
            MemoryOp::Set,
            "core",
            core_value.clone(),
            params.max_cost_sats,
        )
        .await;

        // GET core (a free read: the contract returns the VALUE, proving the round-trip).
        tick += 1;
        perform_read(&mut client, port, MemoryOp::Get, "core", tick).await;

        // LS (a free read: enumerate the live slugs).
        tick += 1;
        perform_read(&mut client, port, MemoryOp::Ls, "", tick).await;

        // RE-ISSUE the SET under the SAME write-seq: the daemon dedupes on the key, so this
        // is DUPLICATE_IGNORED with NO second debit (idempotent replay, the F1 exactly-once
        // property -- a resume that retries a write does not double-pay for it).
        perform_write(
            &mut client,
            port,
            core_wseq,
            MemoryOp::Set,
            "core",
            core_value,
            params.max_cost_sats,
        )
        .await;

        // Checkpoint the seam-proving wseq so a resume continues PAST it (does not re-run
        // phase 1, which would re-set `core` at a shifted seq).
        submit_wseq_checkpoint(&mut client, wseq).await;
    } else {
        // ---- RESUMED: skip the seam-proving; `core` + the prior notes already persist on
        // the relays, and `wseq` is restored so the next write is a NEW seq (not a
        // false-dedupe of an old one). The daemon's wseq_floor (R2-7) backstops this. ----
        boot_log(&format!(
            "memory_loop RESUMED: wseq restored to {restored_wseq} from the app checkpoint; continuing to form memories (next write > {restored_wseq})"
        ));
    }

    // ---- Phase 2: keep forming memories on a tick; drain; park when broke (F4) ----
    loop {
        tick += 1;
        wseq += 1;
        let slug = format!("mem/note-{wseq}");
        let value =
            format!("note {wseq}: my runway is finite; I record this before I forget").into_bytes();
        match perform_write(
            &mut client,
            port,
            wseq,
            MemoryOp::Set,
            &slug,
            value,
            params.max_cost_sats,
        )
        .await
        {
            WriteOutcome::Performed => {
                // A free recall, proving reads stay free even as writes drain the runway.
                perform_read(&mut client, port, MemoryOp::Get, &slug, tick).await;
                // Checkpoint the advanced wseq: a restart restores THIS value and continues
                // past it, so a new write never collides with the persistent ledger (F1).
                submit_wseq_checkpoint(&mut client, wseq).await;
            }
            WriteOutcome::Broke => {
                // EARN-OR-DIE, applied to memory: the treasury can no longer cover a write.
                // The genome does NOT exit (PID 1 -> kernel panic, F4): it parks, and the
                // daemon's meter -- watching the SAME treasury counter -- HALTS the VM.
                // THIS is death, host-side, not the loop breaking. A broke mind can still
                // RECALL its past (reads are free), it just cannot FORM new memories.
                boot_log(&format!(
                    "memory_dead wseq={wseq}: out of runway for a write; parking for the daemon to halt the VM (F4)"
                ));
                idle_forever().await;
            }
            WriteOutcome::Transient => { /* a hiccup; keep ticking */ }
        }
        tokio::time::sleep(params.tick).await;
    }
}

/// Issue a WRITE (SET/RM) and report the outcome. WRITES key on the monotonic `wseq`
/// (`mem-write-{wseq}`) so a resume retry is deduped to exactly one debit (F1). On a dead
/// channel it re-dials (the daemon may have bounced) and reports a transient hiccup.
async fn perform_write(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    wseq: u64,
    op: MemoryOp,
    slug: &str,
    value: Vec<u8>,
    max_cost_sats: u64,
) -> WriteOutcome {
    let request = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        // The WRITE idempotency key is the monotonic write-seq (design doc 10 F1): a
        // resume retry reuses the same seq -> exactly-once debit; a genuinely new write
        // increments it -> a new act. NOT a content hash (which would falsely dedupe a
        // legitimate future re-write of the same value forever).
        idempotency_key: format!("mem-write-{wseq}"),
        act: Some(Act::Memory(Memory {
            op: op as i32,
            slug: slug.to_string(),
            value,
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    };

    match client.request_capability(request).await {
        Ok(resp) => {
            let receipt = resp.into_inner();
            let outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
            match outcome {
                Outcome::AuthorizedAndPerformed | Outcome::DuplicateIgnored => {
                    let status = receipt
                        .memory
                        .as_ref()
                        .map(|m| m.write_status)
                        .unwrap_or(0);
                    let detail = format!(
                        "memory_write wseq={wseq} op={op:?} slug={slug} outcome={outcome:?} cost_sats={} treasury_remaining={} write_status={status}",
                        receipt.cost_sats, receipt.treasury_remaining
                    );
                    report_brokered(client, "memory_write", &detail).await;
                    boot_log(&detail);
                    WriteOutcome::Performed
                }
                Outcome::DeniedInsufficientTreasury | Outcome::DeniedOverBudget => {
                    let detail = format!(
                        "memory_write wseq={wseq} op={op:?} slug={slug} outcome={outcome:?} treasury_remaining={} — cannot afford to record (earn-or-die)",
                        receipt.treasury_remaining
                    );
                    report_brokered(client, "memory_write", &detail).await;
                    boot_log(&detail);
                    WriteOutcome::Broke
                }
                other => {
                    let detail = format!(
                        "memory_write wseq={wseq} op={op:?} slug={slug} UNEXPECTED outcome={other:?} treasury_remaining={}",
                        receipt.treasury_remaining
                    );
                    report_brokered(client, "memory_write", &detail).await;
                    boot_log(&detail);
                    WriteOutcome::Transient
                }
            }
        }
        Err(status) => {
            boot_log(&format!(
                "memory_write wseq={wseq}: RequestCapability errored ({status}); re-dialing the gateway"
            ));
            if let Some(c) = redial(port).await {
                *client = c;
            }
            WriteOutcome::Transient
        }
    }
}

/// Issue a READ (GET/LS) and report the outcome. READS are FREE (zero debit) and key
/// UNIQUELY per call (so each is a fresh fetch, never deduped). The receipt carries the
/// structured `MemoryResult`, proving the brokered contract returns the VALUE/slugs, not
/// just a proof hash.
async fn perform_read(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    op: MemoryOp,
    slug: &str,
    tick: u64,
) {
    let idempotency_key = match op {
        MemoryOp::Ls => format!("mem-ls-{tick}"),
        _ => format!("mem-get-{slug}-{tick}"),
    };
    let request = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key,
        act: Some(Act::Memory(Memory {
            op: op as i32,
            slug: slug.to_string(),
            value: Vec::new(), // a read carries no payload
            max_cost_sats: 0,  // reads are free; the ceiling is meaningless
        })),
        budget_sats: 0,
    };

    match client.request_capability(request).await {
        Ok(resp) => {
            let receipt = resp.into_inner();
            let outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
            let (found, value_len, slug_count) = receipt
                .memory
                .as_ref()
                .map(|m| (m.found, m.value.len(), m.slugs.len()))
                .unwrap_or((false, 0, 0));
            let detail = format!(
                "memory_read op={op:?} slug={slug} outcome={outcome:?} cost_sats={} found={found} value_len={value_len} slug_count={slug_count}",
                receipt.cost_sats
            );
            report_brokered(client, "memory_read", &detail).await;
            boot_log(&detail);
        }
        Err(status) => {
            boot_log(&format!(
                "memory_read op={op:?} slug={slug}: RequestCapability errored ({status}); re-dialing the gateway"
            ));
            if let Some(c) = redial(port).await {
                *client = c;
            }
        }
    }
}
