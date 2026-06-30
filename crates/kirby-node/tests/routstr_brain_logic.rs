//! Layer A (brain-routstr §8): RoutstrBrain logic — mint-free, deterministic, offline.
//! Drives `RoutstrBrain<StubEcash>` through a `CompositeRail` against an offline mock
//! Routstr node ([`common::MockNode`]), asserting the full §5 error taxonomy each maps to
//! the right `RailOutcome` + debit, plus the request wire shape (JSON + `X-Cashu` header).
//! ZERO mint, ZERO real money, ZERO network beyond loopback. (`reconcile_cost` itself is
//! unit-tested in `rail.rs`.)

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{MockNode, NodeBehavior, RefundBehavior, StubEcash};
use kirby_node::rail::{CompositeRail, MockRail, Rail, RailOutcome, RoutstrBrain};
use kirby_proto::capability_request::Act;
use kirby_proto::{ChatMessage, Completion};

/// A `Completion` act with a system + user turn and the per-call cap.
fn completion_act(cap: u64) -> Act {
    Act::Completion(Completion {
        model: "anthropic/claude-sonnet-4.6".into(),
        messages: vec![
            ChatMessage {
                role: "system".into(),
                content: "I am a Kirby agent.".into(),
            },
            ChatMessage {
                role: "user".into(),
                content: "what is my next move to survive?".into(),
            },
        ],
        max_cost_sats: cap,
    })
}

/// Build the brain over `ecash` + `node_url` and perform one completion through a
/// `CompositeRail` (the real routing path), returning the `RailOutcome`. Short timeouts
/// keep the taxonomy tests fast.
async fn perform(node_url: String, ecash: StubEcash, cap: u64) -> RailOutcome {
    let brain = RoutstrBrain::new(
        node_url,
        ecash,
        Duration::from_millis(400),
        Duration::from_millis(400),
    )
    .expect("build RoutstrBrain");
    let rail = CompositeRail::new(Arc::new(MockRail::new()), Arc::new(brain));
    rail.perform(&completion_act(cap), cap).await
}

/// A loopback URL with nothing listening (bind then drop) -> connect refused immediately.
async fn closed_node_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

// ---- Happy path + wire shape -------------------------------------------------------

#[tokio::test]
async fn happy_path_returns_reply_and_debits_cap_minus_change() {
    // cap 64, the node charges 14 and returns 50 change -> debit 14, reply comes back.
    let node = MockNode::replying("survive: earn more sats", Some("ecash:50")).await;
    let outcome = perform(node.url(), StubEcash::healthy(), 64).await;
    match outcome {
        RailOutcome::Performed {
            actual_cost,
            completion,
            ..
        } => {
            assert_eq!(actual_cost, 14, "debit = cap(64) - change(50)");
            assert_eq!(
                String::from_utf8(completion).unwrap(),
                "survive: earn more sats",
                "the assistant reply text round-trips"
            );
        }
        RailOutcome::UpstreamFailed => panic!("the happy path must be Performed"),
    }
}

#[tokio::test]
async fn request_carries_model_messages_stream_false_and_x_cashu_token() {
    let node = MockNode::replying("ok", Some("ecash:0")).await;
    let _ = perform(node.url(), StubEcash::healthy(), 64).await;

    let req = node.completion_request().expect("a completion request was received");
    assert_eq!(req.method, "POST");
    assert!(req.path.contains("/v1/chat/completions"), "path = {}", req.path);
    // The X-Cashu bearer is the minted token worth the cap (StubEcash mints `ecash:<cap>`).
    assert_eq!(req.x_cashu.as_deref(), Some("ecash:64"));
    let json: serde_json::Value = serde_json::from_slice(&req.body).expect("body is JSON");
    assert_eq!(json["model"], "anthropic/claude-sonnet-4.6");
    assert_eq!(json["stream"], false, "stateless X-Cashu mode pins stream:false");
    let messages = json["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(messages[1]["content"], "what is my next move to survive?");
}

#[tokio::test]
async fn reply_with_no_change_header_debits_full_cap() {
    // 200 + reply but NO X-Cashu change header -> change counts 0 -> debit the full cap.
    let node = MockNode::replying("no change here", None).await;
    let outcome = perform(node.url(), StubEcash::healthy(), 64).await;
    match outcome {
        RailOutcome::Performed {
            actual_cost,
            completion,
            ..
        } => {
            assert_eq!(actual_cost, 64, "no redeemable change -> debit the cap");
            assert_eq!(String::from_utf8(completion).unwrap(), "no change here");
        }
        RailOutcome::UpstreamFailed => panic!("a 200 with a reply must be Performed"),
    }
}

#[tokio::test]
async fn change_redeem_failure_keeps_reply_and_debits_cap() {
    // 200 + reply + a change header the wallet can't redeem (non-synthetic) -> the safe
    // rule counts change as 0 -> debit the cap, but the reply we already hold is KEPT.
    let node = MockNode::replying("kept reply", Some("not-a-redeemable-token")).await;
    let outcome = perform(node.url(), StubEcash::healthy(), 64).await;
    match outcome {
        RailOutcome::Performed {
            actual_cost,
            completion,
            ..
        } => {
            assert_eq!(actual_cost, 64, "lost change -> debit cap (safe rule)");
            assert_eq!(String::from_utf8(completion).unwrap(), "kept reply");
        }
        RailOutcome::UpstreamFailed => panic!("a parsed reply must be Performed even if change is lost"),
    }
}

// ---- The error taxonomy (each row of §5) -------------------------------------------

#[tokio::test]
async fn pre_mint_failure_is_upstream_failed_with_no_debit() {
    // The mint itself fails: no token, no sats spent -> UpstreamFailed, and no POST.
    let node = MockNode::replying("never reached", Some("ecash:0")).await;
    let ecash = StubEcash::failing_mint();
    let probe = ecash.clone();
    let outcome = perform(node.url(), ecash, 64).await;
    assert!(matches!(outcome, RailOutcome::UpstreamFailed), "pre-mint failure -> UpstreamFailed");
    assert_eq!(probe.mint_calls(), 1, "the mint was attempted");
    assert!(node.completion_request().is_none(), "no POST after a failed mint");
}

#[tokio::test]
async fn post_mint_connect_fail_then_revoke_recovers_is_upstream_failed_zero() {
    // Minted, then the POST can't connect. revoke_send reclaims our own un-consumed send
    // fully -> the wallet is whole -> UpstreamFailed (debit 0). revoke WAS attempted (R2-1).
    let ecash = StubEcash::healthy();
    let probe = ecash.clone();
    let outcome = perform(closed_node_url().await, ecash, 64).await;
    assert!(
        matches!(outcome, RailOutcome::UpstreamFailed),
        "a fully-reclaimed post-mint failure is UpstreamFailed/0"
    );
    assert_eq!(probe.revoke_calls(), 1, "the self-redeem (revoke_send) was attempted (R2-1)");
}

#[tokio::test]
async fn post_mint_connect_fail_unrecoverable_debits_the_cap_not_zero() {
    // Minted, POST fails, revoke FAILS (token "consumed"), no refund offered -> nothing
    // recovered -> Performed{empty, cap}. The invariant: money left the wallet, so the
    // debit is NEVER 0 here.
    let ecash = StubEcash::revoke_fails();
    let probe = ecash.clone();
    let outcome = perform(closed_node_url().await, ecash, 64).await;
    match outcome {
        RailOutcome::Performed {
            actual_cost,
            completion,
            ..
        } => {
            assert_eq!(actual_cost, 64, "money left the wallet, unrecovered -> debit the cap");
            assert!(completion.is_empty(), "no reply -> empty completion (a legal Performed)");
        }
        RailOutcome::UpstreamFailed => {
            panic!("money left the wallet and was NOT reclaimed -> must debit, never UpstreamFailed/0")
        }
    }
    assert_eq!(probe.revoke_calls(), 1, "revoke was attempted before eating the remainder");
}

#[tokio::test]
async fn non_2xx_with_successful_refund_is_upstream_failed_zero() {
    // 402 payment rejected; revoke fails (consumed) but the RIP-01 refund returns the full
    // value -> recovered == cap -> wallet whole -> UpstreamFailed/0. Exercises the refund path.
    let node = MockNode::start(NodeBehavior::Status(402), RefundBehavior::Token("ecash:64".into())).await;
    let ecash = StubEcash::revoke_fails();
    let probe = ecash.clone();
    let outcome = perform(node.url(), ecash, 64).await;
    assert!(
        matches!(outcome, RailOutcome::UpstreamFailed),
        "a fully-refunded 4xx is UpstreamFailed/0"
    );
    assert_eq!(probe.revoke_calls(), 1, "revoke is tried first");
    assert_eq!(probe.redeem_calls(), 1, "the refund token was redeemed");
}

#[tokio::test]
async fn refund_is_posted_to_the_canonical_balance_refund_path() {
    // The bug fix: the RIP-01 refund must POST to the canonical /v1/balance/refund, NOT the
    // deprecated /v1/wallet/refund alias (which the node may drop). A 402 + revoke-fail
    // forces recovery to fall through to the refund POST. The mock accepts EITHER path, so
    // this path assertion is what PINS the URL — a regression to /v1/wallet/refund would
    // still "work" against the mock but is caught here.
    let node = MockNode::start(NodeBehavior::Status(402), RefundBehavior::Token("ecash:64".into())).await;
    let _ = perform(node.url(), StubEcash::revoke_fails(), 64).await;
    let refund = node
        .requests()
        .into_iter()
        .find(|r| r.path.contains("/refund"))
        .expect("a refund request was sent after the 402 + revoke-fail");
    assert_eq!(refund.method, "POST");
    assert!(
        refund.path.contains("/v1/balance/refund"),
        "refund must POST to the canonical /v1/balance/refund, got {}",
        refund.path
    );
    assert!(
        !refund.path.contains("/v1/wallet/refund"),
        "refund must NOT use the deprecated /v1/wallet/refund alias, got {}",
        refund.path
    );
    // It carries the original token as the X-Cashu bearer (the refund request shape).
    assert!(refund.x_cashu.is_some(), "the refund posts the original token as X-Cashu");
}

#[tokio::test]
async fn server_error_unrecoverable_debits_the_cap() {
    // 500 model error; revoke fails, no refund -> debit cap.
    let node = MockNode::start(NodeBehavior::Status(500), RefundBehavior::None).await;
    let outcome = perform(node.url(), StubEcash::revoke_fails(), 64).await;
    match outcome {
        RailOutcome::Performed { actual_cost, .. } => assert_eq!(actual_cost, 64),
        RailOutcome::UpstreamFailed => panic!("money left the wallet, unrecovered -> debit the cap"),
    }
}

#[tokio::test]
async fn malformed_body_recovered_is_upstream_failed_zero() {
    // 200 but an unparseable body (paid, no usable words) -> reclaim; revoke recovers
    // fully -> UpstreamFailed/0.
    let node = MockNode::start(NodeBehavior::Malformed, RefundBehavior::None).await;
    let outcome = perform(node.url(), StubEcash::healthy(), 64).await;
    assert!(
        matches!(outcome, RailOutcome::UpstreamFailed),
        "a malformed 200 that is fully reclaimed is UpstreamFailed/0"
    );
}

#[tokio::test]
async fn timeout_during_post_attempts_recovery_and_never_debits_zero_after_spend() {
    // The node hangs; the kill-window fires. Money has left the wallet (minted), revoke
    // fails (consumed) and no refund -> the outcome debits the cap, NEVER UpstreamFailed/0
    // (the "no debit-0-after-spend" invariant under a timeout).
    let node = MockNode::start(NodeBehavior::Hang, RefundBehavior::None).await;
    let ecash = StubEcash::revoke_fails();
    let probe = ecash.clone();
    let outcome = perform(node.url(), ecash, 64).await;
    match outcome {
        RailOutcome::Performed { actual_cost, .. } => {
            assert_eq!(actual_cost, 64, "timeout after spend, unrecovered -> debit the cap")
        }
        RailOutcome::UpstreamFailed => {
            panic!("a timeout AFTER the mint must not debit 0 while money is still out")
        }
    }
    assert_eq!(probe.revoke_calls(), 1, "recovery (revoke) was attempted after the timeout");
}

#[tokio::test]
async fn timeout_during_mint_is_upstream_failed_zero() {
    // The mint itself hangs (no token confirmed) -> the kill-window fires -> no sats left
    // the wallet -> UpstreamFailed/0, and no POST.
    let node = MockNode::replying("never reached", Some("ecash:0")).await;
    let outcome = perform(node.url(), StubEcash::hanging_mint(), 64).await;
    assert!(matches!(outcome, RailOutcome::UpstreamFailed), "a mint timeout is UpstreamFailed/0");
    assert!(node.completion_request().is_none(), "no POST when the mint never completes");
}
