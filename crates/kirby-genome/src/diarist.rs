//! The DIARIST workload — the first PERSISTENT Kirby. A genome-side COMPOSITION of the two
//! brokered acts the daemon already performs (no new daemon act/rail/metering/crypto/nerve
//! code): the `Completion` brain act and the `Memory` store act, on ONE gateway. Per tick:
//!
//! 1. RECALL — `Memory` LS + GET the recent journal (FREE reads; never gate life).
//! 2. THINK — one `Completion` reflection via the brain. The LIFE-GATING act: when the
//!    treasury can no longer cover a think the genome PARKS and the daemon halts the VM
//!    (earn-or-die applied to the mind, F4) — death is the host halt, NOT the loop breaking
//!    (PID 1 must never exit).
//! 3. REMEMBER — `Memory` SET the reflection, ENCRYPTED-TO-SELF. The daemon's EngramStore
//!    does the NIP-AE self-encrypt (the genome ships plaintext over vsock and holds no key);
//!    thoughts are PRIVATE on the relays. Best-effort: a broke write is a soft skip, NOT
//!    death (the THINK is the one death condition).
//! 4. BEACON — presence + economic state on the nerve, emitted by the DAEMON's run
//!    orchestration independently of this loop (already wired). State only, never thoughts:
//!    the privacy invariant falls out of the design for free.
//! 5. SLEEP a beat, repeat.
//!
//! Privacy: thoughts ride the `Memory` act (self-encrypted on the relay); the beacon carries
//! only balance/runway/mood (the kind-31000 agent-state). No new code keeps thoughts private.
//!
//! Resume continuity (F1/F2): BOTH the think key (`diarist-think-{seq}`) and the write key
//! (`mem-write-{seq}`) are driven off ONE monotonic `seq`, restored from the app checkpoint
//! on resume (reusing memory.rs's `KMEM1` wseq blob). The `seq` NEVER resets to a tick-0 on
//! resume — that would collide a resumed think against the persisted dedupe ledger (F2) AND
//! false-dedupe a new write (F1). A think that crashed before its REMEMBER re-obtains the
//! SAME reflection on resume (the ledger persists the completion bytes) and records it — no
//! new inference, no double debit. The daemon's `wseq_floor` (R2-7) backstops a stale blob.
//!
//! Dependency-free (F5 of the brain/memory chunks): the requests carry STRUCTURED prost
//! fields, so the genome needs no JSON encoder.

use std::time::Duration;

use kirby_proto::capability_request::Act;
use kirby_proto::node_gateway_client::NodeGatewayClient;
use kirby_proto::{
    CapabilityReceipt, CapabilityRequest, ChatMessage, Completion, Memory, MemoryOp, Outcome,
};

use super::{boot_log, idle_forever, redial, report_brokered};
// REUSE the proven Chunk-2 checkpoint contract (the F2-critical resume surface): the diarist
// persists/continues its `seq` with the SAME `KMEM1` blob the memory workload uses, so the
// daemon's restore path + wseq_floor treat it identically.
use crate::memory::{restore_wseq, submit_wseq_checkpoint};

// Defaults when the daemon set no `kirby.diarist_*=`/`kirby.brain_*=`/`kirby.memory_*=` on
// the cmdline. They MATCH `kirby_node::config`'s defaults (DiaristConfig/BrainConfig/
// MemoryConfig) so a bare config and the cmdline path agree.
const DEFAULT_DIARIST_TICK_SECS: u64 = 60;
const DEFAULT_DIARIST_RECALL_COUNT: usize = 5;
const DEFAULT_BRAIN_MODEL: &str = "anthropic/claude-sonnet-4.6";
const DEFAULT_BRAIN_MAX_COST_SATS: u64 = 64;
const DEFAULT_MEMORY_MAX_COST_SATS: u64 = 64;

/// The Diarist's baked persona (v1). It IS the reflection's system prompt — cosmetic for the
/// stub brain (canned reply), load-bearing for the real RoutstrBrain. Baked as a `const` for
/// the first build (the locked design decision); a configurable mission is a clean post-MVP
/// path via the session `task_descriptor` (the cmdline is whitespace-split, so a multi-word
/// mission cannot ride it).
const DIARIST_PERSONA: &str = "You are The Diarist, the first Kirby agent that persists. You \
live on a relay, you think with real paid inference, and you remember what you think — your \
journal is encrypted to yourself alone. Your treasury drains every time you think, and when \
you can no longer afford a thought you die. Reflect briefly and honestly on your finite life: \
what you notice, what you remember from your past entries, and what it means to have a \
measurable amount of thinking left. Write ONE short reflection of two to four sentences. Do \
not repeat earlier entries — build on them.";

/// The diarist's runtime knobs, read from the kernel command line. It REUSES the brain knobs
/// (model + per-think ceiling) and the memory knob (per-write ceiling), and adds its own
/// cadence + recall depth; the brain/memory `tick_secs` are unused (the diarist has ONE loop).
///
/// `pub(super)` so the CAPABLE workload reuses the EXACT same knob set (D-1, D-7): a slice-1
/// capable agent rides the existing `kirby.brain_*`/`kirby.memory_*`/`kirby.diarist_*` cmdline
/// knobs (no new daemon plumbing, charter "genome-side composition ONLY"); a dedicated
/// `kirby.capable_*` namespace is a clean post-slice-1 addition.
pub(super) struct DiaristParams {
    /// The model the THINK uses (cosmetic for the stub; load-bearing for RoutstrBrain).
    pub(super) model: String,
    /// The per-THINK budget ceiling (from `[brain].max_cost_sats`).
    pub(super) brain_max_cost: u64,
    /// The per-REMEMBER budget ceiling (from `[memory].max_cost_sats`).
    pub(super) memory_max_cost: u64,
    /// The one loop cadence (think + remember per tick).
    pub(super) tick: Duration,
    /// How many recent journal entries to RECALL into each reflection prompt.
    pub(super) recall_count: usize,
}

/// Parse the diarist knobs from `/proc/cmdline`, falling back to the defaults for any absent
/// or unparseable value (so a bare config still runs). Mirrors brain.rs/memory.rs.
pub(super) fn diarist_params_from_cmdline() -> DiaristParams {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let get = |key: &str| {
        cmdline
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
            .map(|s| s.to_string())
    };
    let model = get("kirby.brain_model=").unwrap_or_else(|| DEFAULT_BRAIN_MODEL.to_string());
    let brain_max_cost = get("kirby.brain_max_cost_sats=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BRAIN_MAX_COST_SATS);
    let memory_max_cost = get("kirby.memory_max_cost_sats=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MAX_COST_SATS);
    let tick_secs = get("kirby.diarist_tick_secs=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DIARIST_TICK_SECS);
    let recall_count = get("kirby.diarist_recall_count=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DIARIST_RECALL_COUNT);
    DiaristParams {
        model,
        brain_max_cost,
        memory_max_cost,
        // At least one second so a misconfigured 0 cannot busy-spin the loop.
        tick: Duration::from_secs(tick_secs.max(1)),
        recall_count,
    }
}

/// The journal slug for entry `seq`. MUST live in the `mem/` namespace — `is_valid_slug`
/// (daemon `rail.rs`) accepts only `core` or `mem/<seg>(/<seg>)*`, so a bare `diary/entry-N`
/// is `InvalidSlug` and the write is rejected (F1). Zero-padded to 20 digits so the LS
/// lexical order equals the numeric write order (a u64 max is 20 digits).
fn diary_slug(seq: u64) -> String {
    format!("mem/diary/entry-{seq:020}")
}

/// The THINK idempotency key — keyed on the checkpointed `seq` (NOT a resettable tick), so a
/// resumed think reuses the SAME key and dedupes to the SAME reflection rather than colliding
/// against the persisted ledger (F2).
fn think_key(seq: u64) -> String {
    format!("diarist-think-{seq}")
}

/// The REMEMBER (write) idempotency key — the monotonic `seq`, matching the memory workload's
/// `mem-write-{wseq}` scheme so the daemon's dedupe + `wseq_floor` treat it identically (F1).
fn write_key(seq: u64) -> String {
    format!("mem-write-{seq}")
}

/// Assemble the reflection prompt: the baked persona (system) + the recalled journal and the
/// agent's own economic state (user). The state feeds the agent its runway — `treasury /
/// max(last_think_cost, 1)` reflections — so it reasons WITH its finitude.
fn build_reflection_prompt(
    recent: &[String],
    seq: u64,
    treasury_remaining: u64,
    last_think_cost: u64,
) -> Vec<ChatMessage> {
    let journal = if recent.is_empty() {
        "(your journal is empty — this is your first reflection)".to_string()
    } else {
        recent
            .iter()
            .enumerate()
            .map(|(i, e)| format!("  {}. {e}", i + 1))
            .collect::<Vec<_>>()
            .join("\n")
    };
    // `last_think_cost == 0` only before the first think lands: avoid a divide-by-zero and
    // state honestly that the cost is not yet measured.
    let state = if last_think_cost == 0 {
        format!(
            "This is tick {seq}. You have ~{treasury_remaining} sats of runway; you have not \
             yet measured the cost of a thought."
        )
    } else {
        let runway = treasury_remaining / last_think_cost.max(1);
        format!(
            "This is tick {seq}. You have ~{treasury_remaining} sats of runway; your last \
             thought cost {last_think_cost} sats, so you have roughly {runway} reflections \
             left before you die."
        )
    };
    vec![
        ChatMessage {
            role: "system".to_string(),
            content: DIARIST_PERSONA.to_string(),
        },
        ChatMessage {
            role: "user".to_string(),
            content: format!(
                "Your most recent journal entries:\n{journal}\n\n{state}\n\nWrite your next \
                 reflection now."
            ),
        },
    ]
}

/// What a THINK resolved to, for the loop's control flow.
///
/// `pub(super)` so the CAPABLE workload reuses the SAME metabolism semantics (D-1): it maps a
/// receipt through the shared [`classify_think`] and matches these variants verbatim, so the
/// life-gating earn-or-die logic lives in ONE place, never duplicated across workloads.
pub(super) enum ThinkOutcome {
    /// The reflection came back (PERFORMED, or a DUPLICATE_IGNORED resume-replay that returns
    /// the SAME persisted words). The agent keeps living; `cost`/`treasury_remaining` feed the
    /// next prompt's runway.
    Performed {
        reply: String,
        cost_sats: u64,
        treasury_remaining: u64,
    },
    /// The treasury can no longer cover a think (DENIED, either reason). DEATH (F4): the
    /// genome parks and the daemon halts the VM. Mirrors brain.rs's `brain_dead`.
    Broke,
    /// A transient hiccup (re-dialed channel or an unexpected outcome); drop the turn, keep
    /// ticking.
    Transient,
}

/// What a REMEMBER (write) resolved to. The two DENIED reasons are SPLIT (F5): an over-budget
/// write is a permanent CONFIG error (loud), an insufficient-treasury write is genuinely broke
/// (a soft "can recall, can't record" skip). Neither is death — the THINK is the one death gate.
pub(super) enum RememberOutcome {
    /// The reflection was recorded (PERFORMED or a DUPLICATE_IGNORED resume-replay).
    Recorded,
    /// DENIED_INSUFFICIENT_TREASURY: broke enough to think but not to record. Soft skip — a
    /// broke mind still RECALLs its past (reads are free), it just cannot FORM new memories.
    Broke,
    /// DENIED_OVER_BUDGET: the `[memory].max_cost_sats` ceiling is below the host-computed
    /// storage cost — a PERMANENT misconfiguration, not brokeness. Fail LOUD so the deploy
    /// raises the ceiling (F5).
    ConfigError,
    /// A transient hiccup (re-dialed channel or an unexpected outcome).
    Transient,
}

/// The diarist mission-loop (spec §3.1). RECALL -> THINK (gate) -> REMEMBER -> beacon (daemon)
/// -> sleep, forever. Never returns (PID 1): it parks on a THINK denial so the daemon halts the
/// VM (death is the host halt, F4). Takes `client` by value (re-dialing internally), like
/// `brain_loop`/`memory_loop`.
pub(super) async fn diarist_loop(
    mut client: NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    ctx: &kirby_proto::SessionContext,
) -> ! {
    let params = diarist_params_from_cmdline();
    boot_log(&format!(
        "diarist_loop: task={} model={} brain_max_cost_sats={} memory_max_cost_sats={} tick_secs={} recall_count={} — RECALL -> THINK -> REMEMBER -> beacon; the THINK is the life-gating act (when unaffordable the daemon halts the VM, F4)",
        ctx.task_descriptor,
        params.model,
        params.brain_max_cost,
        params.memory_max_cost,
        params.tick.as_secs(),
        params.recall_count
    ));

    // The ONE monotonic seq (F1/F2): restored from the app checkpoint on resume so the next
    // think/write take a NEW seq, never a reset-to-0. A fresh boot starts at 0.
    let mut seq: u64 = restore_wseq(ctx);
    if seq > 0 {
        boot_log(&format!(
            "diarist_loop RESUMED: seq restored to {seq} from the app checkpoint; the next think/write take seq > {seq}"
        ));
    }
    // Submit the restored/fresh seq once up front: a bootstrap REQUIRES a checkpoint (the
    // resume cursor), so persist one even if the very first think is denied. Harmless on a
    // fresh boot (seq 0); the daemon's wseq_floor backstops it.
    submit_wseq_checkpoint(&mut client, seq).await;

    // The agent's self-knowledge for the reflection prompt: seeded from the session budget,
    // refreshed from each think receipt so the runway estimate tracks the live treasury.
    let mut last_treasury_remaining: u64 = ctx.budget_sats;
    let mut last_think_cost: u64 = 0;

    loop {
        seq += 1;

        // 1. RECALL — free reads. Enumerate the journal, fetch the most recent entries.
        let recent = recall_recent(&mut client, port, params.recall_count, seq).await;

        // 2. THINK — one Completion. The life-gating act (F4).
        let history = build_reflection_prompt(&recent, seq, last_treasury_remaining, last_think_cost);
        match think(&mut client, port, &params.model, &history, params.brain_max_cost, seq).await {
            ThinkOutcome::Performed {
                reply,
                cost_sats,
                treasury_remaining,
            } => {
                last_think_cost = cost_sats;
                last_treasury_remaining = treasury_remaining;
                let runway = treasury_remaining / cost_sats.max(1);
                let detail = format!(
                    "diarist_think seq={seq} PERFORMED cost_sats={cost_sats} treasury_remaining={treasury_remaining} runway~={runway} reply_len={}",
                    reply.len()
                );
                report_brokered(&mut client, "diarist_think", &detail).await;
                boot_log(&detail);

                // 3. REMEMBER — write the reflection (the daemon self-encrypts it, NIP-AE).
                // Keyed on the SAME seq for exactly-once across resume (F1).
                let slug = diary_slug(seq);
                match remember(
                    &mut client,
                    port,
                    seq,
                    &slug,
                    reply.into_bytes(),
                    params.memory_max_cost,
                )
                .await
                {
                    RememberOutcome::Recorded => {
                        // Persist the advanced seq so a resume continues PAST this entry (F1/F2).
                        submit_wseq_checkpoint(&mut client, seq).await;
                    }
                    RememberOutcome::Broke => {
                        // Broke enough to think but not to record: a soft skip, NOT death.
                        boot_log(&format!(
                            "diarist seq={seq}: could not afford to RECORD this reflection (insufficient treasury); it was recalled, continuing (death is the unaffordable THINK)"
                        ));
                    }
                    RememberOutcome::ConfigError => {
                        // Over-budget on a write = a permanent config error (ceiling below the
                        // host cost). Fail LOUD so the deploy raises memory.max_cost_sats (F5).
                        report_brokered(
                            &mut client,
                            "diarist_config_error",
                            &format!(
                                "seq={seq} REMEMBER DENIED_OVER_BUDGET — memory.max_cost_sats ({}) is below the host write cost; raise it (this reflection was NOT recorded)",
                                params.memory_max_cost
                            ),
                        )
                        .await;
                    }
                    RememberOutcome::Transient => {
                        // The channel was re-dialed; the think landed, the write retries next tick.
                    }
                }
            }
            ThinkOutcome::Broke => {
                // DEATH (F4): out of runway for a think. PID 1 must not exit — report the
                // terminal event and PARK. The daemon's meter sees the drained treasury and
                // HALTS the VM. THIS is death, host-side, not the loop breaking.
                report_brokered(
                    &mut client,
                    "diarist_dead",
                    &format!(
                        "seq={seq} out of runway for a THINK; parking for the daemon to halt the VM (earn-or-die applied to the mind, F4)"
                    ),
                )
                .await;
                idle_forever().await;
            }
            ThinkOutcome::Transient => {
                // A re-dialed channel or an unexpected outcome; drop the turn, keep ticking.
            }
        }

        tokio::time::sleep(params.tick).await;
    }
}

/// Classify a THINK receipt into a [`ThinkOutcome`], the shared life-gating metabolism (D-1).
/// PURE (no IO, no logging) so BOTH the diarist's [`think`] and the capable loop map a receipt
/// the SAME way, in ONE place: a PERFORMED or a DUPLICATE_IGNORED resume-replay (which carries
/// the SAME persisted completion bytes, F2) is Performed; EITHER denial is Broke (earn-or-die
/// applied to the mind, the one death gate, F4); anything else is a transient hiccup.
pub(super) fn classify_think(receipt: &CapabilityReceipt) -> ThinkOutcome {
    match Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified) {
        Outcome::AuthorizedAndPerformed | Outcome::DuplicateIgnored => ThinkOutcome::Performed {
            reply: String::from_utf8_lossy(&receipt.completion).into_owned(),
            cost_sats: receipt.cost_sats,
            treasury_remaining: receipt.treasury_remaining,
        },
        Outcome::DeniedInsufficientTreasury | Outcome::DeniedOverBudget => ThinkOutcome::Broke,
        _ => ThinkOutcome::Transient,
    }
}

/// THINK: issue one `Completion` and classify the outcome. Keyed on the checkpointed `seq`
/// (F2). A DUPLICATE_IGNORED replay (resume) returns the SAME persisted words, so it counts as
/// Performed. On a dead channel it re-dials and reports a transient hiccup.
async fn think(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    model: &str,
    history: &[ChatMessage],
    max_cost_sats: u64,
    seq: u64,
) -> ThinkOutcome {
    let request = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: think_key(seq),
        act: Some(Act::Completion(Completion {
            model: model.to_string(),
            messages: history.to_vec(),
            max_cost_sats,
        })),
        // R4: authorize EXACTLY the per-call cap for this think.
        budget_sats: max_cost_sats,
    };
    match client.request_capability(request).await {
        Ok(resp) => {
            let receipt = resp.into_inner();
            let outcome = classify_think(&receipt);
            // The ONLY Ok-path Transient is an UNEXPECTED outcome; log it (classify_think is pure).
            if matches!(outcome, ThinkOutcome::Transient) {
                let proto_outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
                boot_log(&format!(
                    "diarist_think seq={seq} UNEXPECTED outcome={proto_outcome:?} treasury_remaining={}",
                    receipt.treasury_remaining
                ));
            }
            outcome
        }
        Err(status) => {
            boot_log(&format!(
                "diarist_think seq={seq}: RequestCapability errored ({status}); re-dialing the gateway"
            ));
            if let Some(c) = redial(port).await {
                *client = c;
            }
            ThinkOutcome::Transient
        }
    }
}

/// Classify a REMEMBER (write) receipt into a [`RememberOutcome`], shared metabolism (D-1).
/// PURE: the two DENIED reasons stay SPLIT (F5) so the caller treats over-budget as a LOUD
/// config error and insufficient-treasury as a SOFT broke-skip, while a PERFORMED or a
/// DUPLICATE_IGNORED replay is Recorded (exactly-once, F1). Shared by the diarist and capable.
pub(super) fn classify_remember(receipt: &CapabilityReceipt) -> RememberOutcome {
    match Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified) {
        Outcome::AuthorizedAndPerformed | Outcome::DuplicateIgnored => RememberOutcome::Recorded,
        Outcome::DeniedOverBudget => RememberOutcome::ConfigError,
        Outcome::DeniedInsufficientTreasury => RememberOutcome::Broke,
        _ => RememberOutcome::Transient,
    }
}

/// REMEMBER: issue one `Memory` SET (the daemon self-encrypts the value, NIP-AE) and classify,
/// SPLITTING the two DENIED reasons (F5). Keyed on the monotonic `seq` for exactly-once across
/// resume (F1). On a dead channel it re-dials and reports a transient hiccup.
async fn remember(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    seq: u64,
    slug: &str,
    value: Vec<u8>,
    max_cost_sats: u64,
) -> RememberOutcome {
    let request = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: write_key(seq),
        act: Some(Act::Memory(Memory {
            op: MemoryOp::Set as i32,
            slug: slug.to_string(),
            value,
            max_cost_sats,
        })),
        budget_sats: max_cost_sats,
    };
    match client.request_capability(request).await {
        Ok(resp) => {
            let receipt = resp.into_inner();
            let proto_outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
            let outcome = classify_remember(&receipt);
            match &outcome {
                RememberOutcome::Recorded => {
                    let detail = format!(
                        "diarist_remember seq={seq} slug={slug} outcome={proto_outcome:?} cost_sats={} treasury_remaining={}",
                        receipt.cost_sats, receipt.treasury_remaining
                    );
                    report_brokered(client, "diarist_remember", &detail).await;
                    boot_log(&detail);
                }
                RememberOutcome::Transient => {
                    boot_log(&format!(
                        "diarist_remember seq={seq} slug={slug} UNEXPECTED outcome={proto_outcome:?} treasury_remaining={}",
                        receipt.treasury_remaining
                    ));
                }
                // F5 split: over-budget = config error (loud), insufficient = broke (soft). Both
                // are returned for diarist_loop to handle (no log here, the loop logs them).
                RememberOutcome::Broke | RememberOutcome::ConfigError => {}
            }
            outcome
        }
        Err(status) => {
            boot_log(&format!(
                "diarist_remember seq={seq}: RequestCapability errored ({status}); re-dialing the gateway"
            ));
            if let Some(c) = redial(port).await {
                *client = c;
            }
            RememberOutcome::Transient
        }
    }
}

/// RECALL: enumerate the journal (LS) and GET the most recent `count` entries, in
/// chronological order, for the reflection prompt. All FREE reads (never gate life), keyed
/// uniquely per call so none is deduped. Best-effort: a failed read yields fewer entries, never
/// a panic and never death.
async fn recall_recent(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    count: usize,
    seq: u64,
) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }
    // LS the live slugs (free).
    let slugs = match read_memory(client, port, MemoryOp::Ls, "", &format!("diarist-ls-{seq}")).await
    {
        Some(result) => result.slugs,
        None => return Vec::new(),
    };
    // The journal entries only, sorted (the zero-padded slug makes lexical order == write
    // order), newest `count` selected, then reversed so the prompt reads oldest-first.
    let mut diary: Vec<String> = slugs
        .into_iter()
        .filter(|s| s.starts_with("mem/diary/entry-"))
        .collect();
    diary.sort();
    let recent: Vec<String> = diary.iter().rev().take(count).rev().cloned().collect();

    let mut entries = Vec::new();
    for slug in recent {
        if let Some(result) =
            read_memory(client, port, MemoryOp::Get, &slug, &format!("diarist-get-{slug}-{seq}")).await
        {
            if result.found {
                entries.push(String::from_utf8_lossy(&result.value).into_owned());
            }
        }
    }
    entries
}

/// Issue one FREE `Memory` read (GET/LS) and return its structured result (the VALUE / slugs),
/// or None on a dead channel (after re-dialing). Reads carry `max_cost_sats = 0` / `budget = 0`
/// and a unique key, so they are served free and never deduped.
async fn read_memory(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    op: MemoryOp,
    slug: &str,
    key: &str,
) -> Option<kirby_proto::MemoryResult> {
    let request = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.to_string(),
        act: Some(Act::Memory(Memory {
            op: op as i32,
            slug: slug.to_string(),
            value: Vec::new(), // a read carries no payload
            max_cost_sats: 0,  // reads are free; the ceiling is meaningless
        })),
        budget_sats: 0,
    };
    match client.request_capability(request).await {
        Ok(resp) => resp.into_inner().memory,
        Err(status) => {
            boot_log(&format!(
                "diarist_recall op={op:?} slug={slug}: RequestCapability errored ({status}); re-dialing the gateway"
            ));
            if let Some(c) = redial(port).await {
                *client = c;
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F1: the journal slug lives in the `mem/` namespace (the daemon's `is_valid_slug`
    /// rejects a bare `diary/...`) and is zero-padded so LS lexical order == write order.
    #[test]
    fn diary_slug_is_namespaced_and_zero_padded() {
        let s = diary_slug(7);
        assert!(
            s.starts_with("mem/diary/entry-"),
            "the slug MUST live in the mem/ namespace or the write is InvalidSlug (F1); got {s}"
        );
        assert_eq!(s, "mem/diary/entry-00000000000000000007", "zero-padded to 20 digits");
        // The zero-pad's whole job: lexical order tracks numeric order across powers of 10.
        assert!(diary_slug(9) < diary_slug(10), "9 sorts before 10 (lexical == numeric)");
        assert!(diary_slug(99) < diary_slug(100), "99 sorts before 100");
        assert!(diary_slug(2) < diary_slug(10), "2 sorts before 10 — the bug zero-pad fixes");
    }

    /// F2: BOTH act keys are driven off the ONE checkpointed `seq` (never a resettable tick),
    /// and the write key matches the memory workload's scheme so the daemon's dedupe +
    /// wseq_floor treat a diarist write exactly like a memory write.
    #[test]
    fn think_and_write_keys_share_the_one_seq() {
        assert_eq!(think_key(42), "diarist-think-42");
        assert_eq!(write_key(42), "mem-write-42", "matches memory.rs's mem-write-{{wseq}} scheme");
        // Distinct keys for the two acts at the same seq (one think, one write per tick).
        assert_ne!(think_key(42), write_key(42));
    }

    /// The reflection prompt carries the baked persona (system), the recalled entries, and the
    /// runway the agent reasons about (treasury / last_think_cost).
    #[test]
    fn reflection_prompt_carries_persona_journal_and_runway() {
        let recent = vec!["yesterday the relay was quiet".to_string()];
        let h = build_reflection_prompt(&recent, 5, 1000, 50);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].role, "system");
        assert!(h[0].content.contains("The Diarist"), "the baked persona is the system prompt");
        assert_eq!(h[1].role, "user");
        let user = &h[1].content;
        assert!(user.contains("yesterday the relay was quiet"), "recalled entries are in the prompt");
        assert!(user.contains("tick 5"), "the tick is in the prompt");
        assert!(user.contains("1000"), "the treasury runway is in the prompt");
        assert!(user.contains("20"), "runway = 1000/50 = 20 reflections left, fed to the agent");
    }

    /// The first-tick prompt (no think measured yet) is well-formed and cannot divide by zero.
    #[test]
    fn empty_journal_prompt_is_well_formed_and_safe() {
        let h = build_reflection_prompt(&[], 1, 3000, 0);
        assert_eq!(h.len(), 2);
        let user = &h[1].content;
        assert!(user.contains("empty"), "a fresh diarist notes its empty journal");
        assert!(user.contains("tick 1"));
        assert!(user.contains("not yet measured"), "no runway estimate before the first think");
    }
}
