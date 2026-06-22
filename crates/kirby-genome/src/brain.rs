//! The MIND workload (brain-stub): the in-VM harness loop, `think -> pay -> meter ->
//! repeat`. Each tick the genome issues a `Completion` brokered act over vsock; the
//! daemon's `StubBrain` returns a canned reply plus a SIMULATED, deterministic cost;
//! the reply round-trips back into the genome's chat history (proving the brokered
//! contract returns WORDS, not just a hash), and the treasury drains by that cost.
//! When the treasury can no longer cover a think the gateway DENIES it; the genome
//! then PARKS (`idle_forever`) and the daemon halts the VM host-side — death is the
//! host halt, NOT the loop breaking (PID 1 must never exit, F4).
//!
//! Dependency-free (F5): the chat history is a `Vec<ChatMessage>` (prost types) and
//! the request carries STRUCTURED messages, so the genome needs no JSON encoder; the
//! daemon assembles any real OpenAI body (the StubBrain assembles nothing). No tools
//! this chunk — the brain only thinks (tool-calling + per-tool re-gating is a named
//! later chunk).

use std::time::Duration;

use kirby_proto::capability_request::Act;
use kirby_proto::node_gateway_client::NodeGatewayClient;
use kirby_proto::{CapabilityRequest, ChatMessage, Completion, Outcome};

use super::{boot_log, idle_forever, redial, report_brokered};

// Defaults when the daemon set no `kirby.brain_*=` on the cmdline. They MATCH
// `kirby_node::config::BrainConfig`'s defaults so a bare `[brain]` and the cmdline
// path agree. The model is cosmetic for the stub (the StubBrain ignores it); it is
// load-bearing for the later `RoutstrBrain`, which reads the SAME field — so pointing
// the agent at a real model is a config change, not a genome change (swap-readiness).
const DEFAULT_BRAIN_MODEL: &str = "anthropic/claude-sonnet-4.6";
const DEFAULT_BRAIN_MAX_COST_SATS: u64 = 64;
const DEFAULT_BRAIN_TICK_SECS: u64 = 5;

/// The brain's runtime knobs, read from the kernel command line (the daemon writes
/// `kirby.brain_model=`, `kirby.brain_max_cost_sats=`, `kirby.brain_tick_secs=` when
/// the workload is `brain`, exactly as the gateway port and workload already travel).
struct BrainParams {
    model: String,
    max_cost_sats: u64,
    tick: Duration,
}

/// Parse the brain knobs from `/proc/cmdline`, falling back to the defaults for any
/// absent or unparseable value (so a bare config still runs).
fn brain_params_from_cmdline() -> BrainParams {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let get = |key: &str| {
        cmdline
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
            .map(|s| s.to_string())
    };
    let model = get("kirby.brain_model=").unwrap_or_else(|| DEFAULT_BRAIN_MODEL.to_string());
    let max_cost_sats = get("kirby.brain_max_cost_sats=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BRAIN_MAX_COST_SATS);
    let tick_secs = get("kirby.brain_tick_secs=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BRAIN_TICK_SECS);
    BrainParams {
        model,
        max_cost_sats,
        // At least one second so a misconfigured 0 cannot busy-spin the think loop.
        tick: Duration::from_secs(tick_secs.max(1)),
    }
}

/// The brain's system prompt. Cosmetic for the stub (the reply is canned), but it
/// frames the agent's situation: the metabolism of thinking is real.
fn system_prompt() -> ChatMessage {
    ChatMessage {
        role: "system".to_string(),
        content: "I am a Kirby agent; my treasury drains as I think, and when it is empty I die. \
                  Each tick I assess my runway and decide what to do to survive."
            .to_string(),
    }
}

/// The brain loop (brain-stub §3): think -> pay -> meter -> repeat. Mirrors the
/// brokered-act RPC pattern (`request_brokered_act`) but issues a `Completion` each
/// tick, threads the reply back into a growing chat history, and PARKS on a budget
/// denial (F4) rather than exiting. Never returns (PID 1).
pub(super) async fn brain_loop(
    mut client: NodeGatewayClient<tonic::transport::Channel>,
    port: u32,
    ctx: &kirby_proto::SessionContext,
) -> ! {
    let params = brain_params_from_cmdline();
    boot_log(&format!(
        "brain_loop: task={} model={} max_cost_sats={} tick_secs={} — the brain only thinks; each think drains the treasury (earn-or-die applied to the mind)",
        ctx.task_descriptor,
        params.model,
        params.max_cost_sats,
        params.tick.as_secs()
    ));

    // The chat history. prost `ChatMessage` types only — no serde_json in the genome
    // (F5). It grows each turn (system, user, assistant, user, assistant, ...).
    let mut history: Vec<ChatMessage> = vec![system_prompt()];
    let mut tick: u64 = 0;

    loop {
        tick += 1;
        // This tick's prompt: a user turn so the stub has a "user" message to echo and
        // the reply round-trip is checkable. A real model would see the whole history.
        history.push(ChatMessage {
            role: "user".to_string(),
            content: format!("tick {tick}: my runway is finite — what is my next move to survive?"),
        });

        // Build the Completion act from the STRUCTURED history. `budget_sats =
        // max_cost_sats` (R4): the genome authorizes EXACTLY the per-call cap for this
        // think (a 0 budget would be DENIED_OVER_BUDGET). The idempotency key is UNIQUE
        // per think — each thought is its OWN debiting act; a stable key would dedupe
        // the 2nd think against the 1st (same words, no debit) and the treasury would
        // never drain.
        let request = CapabilityRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            idempotency_key: format!("brain-think-{tick}"),
            act: Some(Act::Completion(Completion {
                model: params.model.clone(),
                messages: history.clone(),
                max_cost_sats: params.max_cost_sats,
            })),
            budget_sats: params.max_cost_sats,
        };

        match client.request_capability(request).await {
            Ok(resp) => {
                let receipt = resp.into_inner();
                let outcome = Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified);
                match outcome {
                    Outcome::AuthorizedAndPerformed => {
                        // The reply TEXT round-trips back into the genome's history —
                        // proving the brokered Completion contract returns WORDS, not
                        // just a proof hash. This is what lets the brain keep thinking.
                        let reply = String::from_utf8_lossy(&receipt.completion).into_owned();
                        let detail = format!(
                            "brain_think tick={tick} PERFORMED cost_sats={} treasury_remaining={} reply_len={}",
                            receipt.cost_sats,
                            receipt.treasury_remaining,
                            receipt.completion.len()
                        );
                        report_brokered(&mut client, "brain_think", &detail).await;
                        boot_log(&detail);
                        history.push(ChatMessage {
                            role: "assistant".to_string(),
                            content: reply,
                        });
                    }
                    Outcome::DeniedInsufficientTreasury | Outcome::DeniedOverBudget => {
                        // EARN-OR-DIE, applied to the mind: the treasury can no longer
                        // cover a think. The brain does NOT exit (PID 1 -> kernel panic,
                        // F4): it reports the terminal event and PARKS. The daemon's
                        // meter sees the drained treasury and HALTS the VM — THIS is
                        // death, host-side, not the loop breaking.
                        let detail = format!(
                            "brain_dead tick={tick} outcome={outcome:?} treasury_remaining={} — out of runway; parking for the daemon to halt the VM (F4)",
                            receipt.treasury_remaining
                        );
                        report_brokered(&mut client, "brain_dead", &detail).await;
                        boot_log(&detail);
                        idle_forever().await;
                    }
                    other => {
                        // DENIED_NOT_ALLOWLISTED / UPSTREAM_FAILED / DUPLICATE_IGNORED
                        // are not expected for a well-formed brain think; log and keep
                        // ticking (a transient daemon hiccup must not be fatal). Drop the
                        // un-answered user turn so the history stays well-formed.
                        let detail = format!(
                            "brain_think tick={tick} UNEXPECTED outcome={other:?} treasury_remaining={}",
                            receipt.treasury_remaining
                        );
                        report_brokered(&mut client, "brain_think", &detail).await;
                        boot_log(&detail);
                        history.pop();
                    }
                }
            }
            Err(status) => {
                // A dead channel (e.g. the daemon bounced). Re-dial and retry on the
                // next tick; drop the un-answered user turn so the history stays clean.
                boot_log(&format!(
                    "brain_think tick={tick}: RequestCapability errored ({status}); re-dialing the gateway"
                ));
                history.pop();
                client = redial(port).await.unwrap_or(client);
            }
        }

        tokio::time::sleep(params.tick).await;
    }
}
