//! Layer A (prepaid API-key brain): `RoutstrKeyBrain` logic — mint-free, deterministic,
//! offline. Drives `complete()` and `fetch_balance_sats()` against the offline
//! [`common::MockNode`], asserting (a) the request carries `Authorization: Bearer …` and
//! NO `X-Cashu`, (b) the cost is read from the response body (`cost.total_msats` exact,
//! else `usage.cost_sats`, else the cap) and clamped to the cap, (c) a non-2xx is a clean
//! no-debit error, and (d) the balance probe converts msats -> sats and surfaces a bad key
//! as an error. ZERO mint, ZERO real money, ZERO network beyond loopback.

mod common;

use std::time::Duration;

use common::{MockNode, NodeBehavior, RefundBehavior};
use kirby_node::rail::{BrainBackend, RoutstrKeyBrain};
use kirby_proto::ChatMessage;

const KEY: &str = "sk-test-key-abc123";

fn messages() -> Vec<ChatMessage> {
    vec![
        ChatMessage { role: "system".into(), content: "I am a Kirby agent.".into() },
        ChatMessage { role: "user".into(), content: "what is my next move to survive?".into() },
    ]
}

/// Build a brain at `node_url` and perform one completion, returning `(reply, cost_sats)`.
async fn complete_at(node_url: String, cap: u64) -> anyhow::Result<(Vec<u8>, u64)> {
    let brain = RoutstrKeyBrain::new(node_url, KEY.to_string(), Duration::from_secs(2))
        .expect("build RoutstrKeyBrain");
    brain
        .complete("anthropic/claude-sonnet-4.6", &messages(), cap)
        .await
}

// ---- Wire shape: Bearer present, NO X-Cashu -----------------------------------------

#[tokio::test]
async fn request_carries_bearer_and_no_x_cashu() {
    let body = r#"{"choices":[{"message":{"role":"assistant","content":"ok"}}],"cost":{"total_msats":0}}"#;
    let node = MockNode::replying_json(body).await;
    let _ = complete_at(node.url(), 64).await.expect("a 200 completion succeeds");

    let req = node.completion_request().expect("a completion request was received");
    assert_eq!(req.method, "POST");
    assert!(req.path.contains("/v1/chat/completions"), "path = {}", req.path);
    // The prepaid-key path authenticates with the Bearer key and sends NO X-Cashu money.
    assert_eq!(
        req.authorization.as_deref(),
        Some(format!("Bearer {KEY}").as_str()),
        "the bearer key is sent on the Authorization header"
    );
    assert!(req.x_cashu.is_none(), "the prepaid-key path must NOT send an X-Cashu token");
    // The body is the same OpenAI-compat shape (model + stream:false + messages).
    let json: serde_json::Value = serde_json::from_slice(&req.body).expect("body is JSON");
    assert_eq!(json["model"], "anthropic/claude-sonnet-4.6");
    assert_eq!(json["stream"], false);
    let msgs = json["messages"].as_array().expect("messages array");
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[1]["content"], "what is my next move to survive?");
}

// ---- Cost: exact total_msats, rounded up, clamped to the cap -------------------------

#[tokio::test]
async fn cost_from_total_msats_rounds_up_to_whole_sats() {
    // 1500 msats = 1.5 sat -> round UP to 2 (never under-debit a fractional-sat charge).
    let body = r#"{"choices":[{"message":{"content":"reply"}}],"cost":{"total_msats":1500}}"#;
    let node = MockNode::replying_json(body).await;
    let (reply, cost) = complete_at(node.url(), 64).await.expect("success");
    assert_eq!(String::from_utf8(reply).unwrap(), "reply", "the reply round-trips");
    assert_eq!(cost, 2, "1500 msats rounds up to 2 sats");
}

#[tokio::test]
async fn cost_total_msats_above_cap_clamps_to_cap() {
    // 999_000 msats = 999 sats, but the per-call cap is 64 -> D-20 clamps the debit to 64.
    let body = r#"{"choices":[{"message":{"content":"x"}}],"cost":{"total_msats":999000}}"#;
    let node = MockNode::replying_json(body).await;
    let (_, cost) = complete_at(node.url(), 64).await.expect("success");
    assert_eq!(cost, 64, "a charge above the cap clamps to the cap (never overspend)");
}

#[tokio::test]
async fn cost_falls_back_to_cost_sats_when_no_cost_object() {
    // No top-level `cost`, but `usage.cost_sats` (already sats) is present -> use it.
    let body = r#"{"choices":[{"message":{"content":"x"}}],"usage":{"cost_sats":7}}"#;
    let node = MockNode::replying_json(body).await;
    let (_, cost) = complete_at(node.url(), 64).await.expect("success");
    assert_eq!(cost, 7, "usage.cost_sats is the fallback when cost.total_msats is absent");
}

#[tokio::test]
async fn cost_falls_back_to_full_cap_when_no_cost_fields() {
    // A served completion with NO cost fields at all -> debit the full cap (the safe
    // never-under-debit rule; a reply was produced, so something was charged).
    let body = r#"{"choices":[{"message":{"content":"x"}}]}"#;
    let node = MockNode::replying_json(body).await;
    let (_, cost) = complete_at(node.url(), 64).await.expect("success");
    assert_eq!(cost, 64, "absent cost fields debit the full cap (safe rule)");
}

// ---- Failure: a non-2xx is a clean no-debit error ------------------------------------

#[tokio::test]
async fn non_2xx_is_a_no_debit_error() {
    let node = MockNode::start(NodeBehavior::Status(402), RefundBehavior::None).await;
    let err = complete_at(node.url(), 64).await.expect_err("a non-2xx must be an error (no debit)");
    assert!(err.to_string().contains("non-success status"), "got: {err}");
}

#[tokio::test]
async fn missing_choices_is_an_error() {
    // 200 but no choices -> there is no reply to keep -> error (the gateway sees no debit).
    let body = r#"{"choices":[],"cost":{"total_msats":1000}}"#;
    let node = MockNode::replying_json(body).await;
    let err = complete_at(node.url(), 64).await.expect_err("no choices must error");
    assert!(err.to_string().contains("no choices/content"), "got: {err}");
}

// ---- Balance probe: msats -> sats, and bad-key surfaces as an error ------------------

#[tokio::test]
async fn fetch_balance_converts_msats_to_sats_flooring() {
    // 2_500_400 msats = 2500.4 sat -> floor to 2500 spendable sats.
    let node = MockNode::balance_msats(2_500_400).await;
    let brain = RoutstrKeyBrain::new(node.url(), KEY.to_string(), Duration::from_secs(2)).unwrap();
    let sats = brain.fetch_balance_sats().await.expect("balance reads");
    assert_eq!(sats, 2500, "msats floor-divide to whole spendable sats");
    // The probe authenticated with the bearer key.
    let req = node.requests().into_iter().find(|r| r.path.contains("/v1/balance/info")).unwrap();
    assert_eq!(req.authorization.as_deref(), Some(format!("Bearer {KEY}").as_str()));
}

#[tokio::test]
async fn fetch_balance_errors_on_non_2xx_unusable_key() {
    // A 401 (bad/empty/unfunded key) surfaces as an error -> boot maps it to refuse-to-boot.
    let node = MockNode::balance_status(401).await;
    let brain = RoutstrKeyBrain::new(node.url(), KEY.to_string(), Duration::from_secs(2)).unwrap();
    let err = brain.fetch_balance_sats().await.expect_err("a 401 balance probe must error");
    assert!(err.to_string().contains("non-success status"), "got: {err}");
}
