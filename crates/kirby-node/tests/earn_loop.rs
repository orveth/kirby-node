//! E6: the earn-loop SETTLEMENT half, end-to-end against a local fakewallet mint.
//!
//! Proves the "earn" arc closes with NO real money and NO real relay: the genome asks
//! the daemon to ISSUE a charge (an IssueCharge act through the gateway), a customer PAYS
//! it (mints a real cashu token at the local fakewallet mint), and the daemon VERIFIES
//! the settlement at the mint (`wallet.receive`), CREDITS the treasury with the
//! MINT-VERIFIED amount, and enqueues a PAYMENT_SETTLED inbound event the genome can
//! poll for.
//!
//! The money-MUSTs, each toothed:
//!   - E6 the loop closes: issue -> settle -> treasury credited by the mint-verified
//!     amount -> PAYMENT_SETTLED enqueued  .. `earn_loop_issue_settle_credit_notice`
//!   - MONEY-MUST (over-claim): a settlement that redeems FEWER sats than the charge
//!     requested credits ONLY what the mint proved, never the requested amount
//!     .. `over_claimed_settlement_credits_only_mint_verified`
//!   - E3 no double-credit: a re-delivered settlement for the same charge_id credits
//!     EXACTLY ONCE (the second settle is a Duplicate no-op)
//!     .. `double_settle_credits_exactly_once`
//!
//! Layer B (a real cdk-mintd fakewallet mint, no real money) mirrors the rig used by
//! routstr_brain_ecash.rs / full_loop.rs. The mint boot is slow, so these are grouped in
//! one module and share the fixture where practical (each test boots its own mint on a
//! free port to stay independent).

mod common;

use std::sync::Arc;

use cdk::wallet::SendOptions;
use cdk::Amount;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::mint_rig::{build_wallet, fund_wallet};
use kirby_node::nerve::InboundQueue;
use kirby_node::rail::{CashuSettlement, MockRail, ISSUE_CHARGE_DESTINATION};
use kirby_node::treasury::{CreditOutcome, Treasury};

use kirby_proto::capability_request::Act;
use kirby_proto::{
    CapabilityRequest, ChargeMethod, InboundKind, IssueCharge, Outcome, PaymentSettled,
};
use prost::Message;

use common::mint_fixture::FakeMint;

/// Build a settlement-mode gateway: a treasury seeded at `initial_sats`, a `CashuSettlement`
/// wrapping the daemon's (host-held) wallet, and an inbound queue so `settle_charge` can
/// enqueue the PAYMENT_SETTLED notice. Returns the service + the shared queue handle.
fn settlement_gateway(
    initial_sats: u64,
    node_wallet: Arc<cdk::Wallet>,
) -> (GatewayService, InboundQueue) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let session = Session {
        task_descriptor: "earn-loop-e6".into(),
        budget_sats: initial_sats,
        allowlisted_destinations: vec![ISSUE_CHARGE_DESTINATION.to_string()],
        allowlisted_inbound_kinds: vec![InboundKind::PaymentSettled],
    };
    let queue = InboundQueue::new();
    let svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_settlement_provider(CashuSettlement::new(node_wallet))
        .with_inbound_queue(queue.clone());
    (svc, queue)
}

/// Issue a charge through the gateway (the genome's IssueCharge act) and return the
/// daemon-assigned charge_id.
async fn issue_charge_via_gateway(
    svc: &GatewayService,
    idempotency_key: &str,
    amount_sats: u64,
) -> String {
    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: idempotency_key.to_string(),
        act: Some(Act::IssueCharge(IssueCharge {
            amount_sats,
            memo: "render this job".into(),
            method: ChargeMethod::Cashu as i32,
        })),
        budget_sats: 0,
    };
    let receipt = svc
        .authorize_capability(&req)
        .await
        .expect("authorize IssueCharge");
    assert_eq!(
        receipt.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "IssueCharge must be authorized when a settlement provider is attached"
    );
    assert_eq!(receipt.cost_sats, 0, "issuing a charge is zero-cost");
    let charge = receipt.charge.expect("receipt carries ChargeIssued");
    assert_eq!(charge.amount_sats, amount_sats);
    charge.charge_id
}

/// A customer PAYS a charge: mint a cashu token worth `amount_sats` from a funded payer
/// wallet at the mint. This is the "evidence" the daemon verifies via `wallet.receive`.
async fn customer_pays(payer: &Arc<cdk::Wallet>, amount_sats: u64) -> String {
    let prepared = payer
        .prepare_send(Amount::from(amount_sats), SendOptions::default())
        .await
        .expect("prepare the customer's payment token");
    prepared
        .confirm(None)
        .await
        .expect("confirm the customer's payment token")
        .to_string()
}

/// Drain the inbox for PAYMENT_SETTLED events past `ack_seq` (non-blocking).
async fn poll_payment_settled(svc: &GatewayService, ack_seq: u64) -> Vec<PaymentSettled> {
    use kirby_proto::node_gateway_server::NodeGateway;
    let resp = svc
        .poll_inbox(tonic::Request::new(kirby_proto::InboxRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            want_kinds: vec![InboundKind::PaymentSettled as i32],
            ack_seq,
            wait_ms: 0,
        }))
        .await
        .expect("poll_inbox");
    resp.into_inner()
        .events
        .into_iter()
        .filter(|e| e.kind == InboundKind::PaymentSettled as i32)
        .map(|e| PaymentSettled::decode(e.payload.as_slice()).expect("decode PaymentSettled"))
        .collect()
}

/// E6 (the loop closes): issue a charge -> customer pays -> daemon settles -> treasury is
/// credited by the MINT-VERIFIED amount -> a PAYMENT_SETTLED notice is enqueued for the
/// genome, correlated to the charge_id.
#[tokio::test]
async fn earn_loop_issue_settle_credit_notice() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    // The daemon's (host-held) wallet: `CashuSettlement` redeems the customer's token INTO it.
    let node_wallet = build_wallet(&mint.url()).await.expect("build node wallet");
    // The customer's wallet, funded so it can pay the charge.
    let payer = build_wallet(&mint.url()).await.expect("build payer wallet");
    fund_wallet(payer.clone(), 500).await.expect("fund payer");

    let (svc, _queue) = settlement_gateway(0, node_wallet);

    // The treasury starts EMPTY: the agent has earned nothing yet.
    assert_eq!(svc.treasury_remaining().unwrap(), 0);

    // 1. The genome issues a 100-sat charge.
    let charge_id = issue_charge_via_gateway(&svc, "earn-charge-1", 100).await;

    // Issuing did NOT credit (money-MUST: only host-verified settlement credits).
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        0,
        "issuing a charge must not credit the treasury"
    );

    // 2. The customer pays: mints a 100-sat token at the mint.
    let token = customer_pays(&payer, 100).await;

    // 3. The daemon settles: verifies at the mint + credits + enqueues PAYMENT_SETTLED.
    let outcome = svc
        .settle_charge(&charge_id, &token)
        .await
        .expect("settle the charge");
    let credited = match outcome {
        CreditOutcome::Credited { amount_sats, .. } => amount_sats,
        _ => panic!("expected Credited"),
    };

    // The treasury rose by the MINT-VERIFIED amount (100, within any fakewallet fee).
    let balance = svc.treasury_remaining().unwrap();
    assert_eq!(
        balance, credited,
        "treasury balance equals the credited (mint-verified) amount"
    );
    assert!(
        balance > 0 && balance <= 100,
        "credited the mint-verified amount ({balance}), never more than requested"
    );

    // 4. A PAYMENT_SETTLED notice is enqueued, correlated to the charge_id, carrying the
    //    mint-verified amount (NOT the requested amount, if they differ).
    let notices = poll_payment_settled(&svc, 0).await;
    assert_eq!(notices.len(), 1, "exactly one PAYMENT_SETTLED notice");
    assert_eq!(
        notices[0].charge_id, charge_id,
        "PAYMENT_SETTLED correlates to the charge_id"
    );
    assert_eq!(
        notices[0].verified_sats, balance,
        "PAYMENT_SETTLED carries the mint-verified sats, matching what was credited"
    );

    mint.shutdown().await;
}

/// MONEY-MUST (over-claim): if the customer's token redeems FEWER sats than the charge
/// requested, the treasury is credited ONLY by what the mint proved -- never by the
/// requested amount. This is the tooth on "credit_verified receives the mint-verified
/// amount ONLY". The charge asks for 100; the customer pays a 40-sat token; the credit
/// is 40, not 100.
///
/// RED-on-revert: if `settle_charge` credited `IssueCharge.amount_sats` (100) instead of
/// the `verify_settlement` return (40), the balance would be 100 and this fails.
#[tokio::test]
async fn over_claimed_settlement_credits_only_mint_verified() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let node_wallet = build_wallet(&mint.url()).await.expect("build node wallet");
    let payer = build_wallet(&mint.url()).await.expect("build payer wallet");
    fund_wallet(payer.clone(), 500).await.expect("fund payer");

    let (svc, _queue) = settlement_gateway(0, node_wallet);

    // The genome issues a charge for 100 sats.
    let charge_id = issue_charge_via_gateway(&svc, "earn-charge-overclaim", 100).await;

    // The customer UNDER-pays: a token worth only 40 sats.
    let underpaid = customer_pays(&payer, 40).await;

    let outcome = svc
        .settle_charge(&charge_id, &underpaid)
        .await
        .expect("settle the under-paid charge");
    let credited = match outcome {
        CreditOutcome::Credited { amount_sats, .. } => amount_sats,
        _ => panic!("expected Credited"),
    };

    // The credit is the mint-verified 40 (within fee), NEVER the requested 100.
    assert!(
        (1..=40).contains(&credited),
        "credited the mint-verified amount ({credited}), never the requested 100"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        credited,
        "treasury holds only the mint-verified sats"
    );
    assert!(
        svc.treasury_remaining().unwrap() < 100,
        "MONEY-MUST: an over-claimed charge never credits the requested amount"
    );

    // The PAYMENT_SETTLED notice also reports the mint-verified amount, not the request.
    let notices = poll_payment_settled(&svc, 0).await;
    assert_eq!(notices.len(), 1);
    assert_eq!(
        notices[0].verified_sats, credited,
        "the notice reports the mint-verified sats, not the requested amount"
    );

    mint.shutdown().await;
}

/// E3 (no double-credit): a re-delivered settlement for the SAME charge_id credits EXACTLY
/// ONCE. The first settle credits; a second settle of the same charge is a Duplicate no-op
/// (the treasury does not rise again). This is the dedupe wall on the credit path.
///
/// RED-on-revert: break `credit_verified`'s dedupe and the balance doubles here.
#[tokio::test]
async fn double_settle_credits_exactly_once() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let node_wallet = build_wallet(&mint.url()).await.expect("build node wallet");
    let payer = build_wallet(&mint.url()).await.expect("build payer wallet");
    fund_wallet(payer.clone(), 500).await.expect("fund payer");

    let (svc, _queue) = settlement_gateway(0, node_wallet);

    let charge_id = issue_charge_via_gateway(&svc, "earn-charge-dup", 50).await;

    // First settle: the customer's 50-sat token is redeemed + credited.
    let token = customer_pays(&payer, 50).await;
    let first = svc
        .settle_charge(&charge_id, &token)
        .await
        .expect("first settle");
    let credited = match first {
        CreditOutcome::Credited { amount_sats, .. } => amount_sats,
        _ => panic!("expected Credited"),
    };
    let after_first = svc.treasury_remaining().unwrap();
    assert_eq!(after_first, credited, "balance rose by the credited amount");
    assert!(after_first > 0);

    // The customer re-submits (a re-delivered settlement notice) for the SAME charge_id.
    // Even a fresh, genuinely-valid token must NOT double-credit: the dedupe is on
    // charge_id, so `credit_verified` returns Duplicate and the balance does not rise.
    let replay_token = customer_pays(&payer, 50).await;
    let second = svc
        .settle_charge(&charge_id, &replay_token)
        .await
        .expect("second settle (same charge_id)");
    assert!(
        matches!(second, CreditOutcome::Duplicate(_)),
        "a second settle of the same charge_id must be a Duplicate no-op"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        after_first,
        "E3: no double-credit -- the balance is unchanged after the re-delivered settlement"
    );

    mint.shutdown().await;
}

/// MONEY-MUST (finding-1, the money tooth): a FRESH, genuinely-valid token replayed
/// against an ALREADY-SETTLED charge_id must NEVER be redeemed into the host wallet.
/// Settle charge X with token A (credited), then replay charge X with a DIFFERENT valid
/// token B. Because settlement STATE is consulted first, the replay short-circuits to the
/// prior settled record: token B is never redeemed, the daemon wallet balance does not
/// change, and the treasury is unchanged. This is the wallet-treasury desync guard.
///
/// RED-on-revert: with the old verify-then-dedupe order, `settle_charge` would call
/// `wallet.receive` on token B (redeeming its sats into the wallet) BEFORE the credit
/// dedupe dropped it as Duplicate. The wallet balance would then rise by ~50 while the
/// treasury stayed flat -- the desync this tooth forbids -- and the wallet-balance
/// assertion below fails.
#[tokio::test]
async fn fresh_token_replay_of_settled_charge_never_touches_the_wallet() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let node_wallet = build_wallet(&mint.url()).await.expect("build node wallet");
    let payer = build_wallet(&mint.url()).await.expect("build payer wallet");
    fund_wallet(payer.clone(), 500).await.expect("fund payer");

    // Keep a handle to the daemon's wallet so we can observe its balance across the settle
    // and the replay; the gateway takes its own Arc clone.
    let node_wallet_probe = node_wallet.clone();
    let (svc, _queue) = settlement_gateway(0, node_wallet);

    let charge_id = issue_charge_via_gateway(&svc, "earn-charge-fresh-replay", 50).await;

    // First settle with token A: the wallet redeems it, the treasury is credited.
    let token_a = customer_pays(&payer, 50).await;
    let first = svc
        .settle_charge(&charge_id, &token_a)
        .await
        .expect("first settle with token A");
    let credited = match first {
        CreditOutcome::Credited { amount_sats, .. } => amount_sats,
        _ => panic!("expected Credited on the first settle"),
    };
    let treasury_after_first = svc.treasury_remaining().unwrap();
    assert_eq!(treasury_after_first, credited, "treasury rose by the credited amount");
    let wallet_after_first: u64 = node_wallet_probe
        .total_balance()
        .await
        .expect("read node wallet balance after the first settle")
        .into();
    assert!(wallet_after_first > 0, "the daemon wallet holds token A's redeemed sats");

    // Replay the SAME charge_id with a DIFFERENT, genuinely-valid token B. Settlement state
    // is consulted first, so this returns Duplicate WITHOUT redeeming token B.
    let token_b = customer_pays(&payer, 50).await;
    let replay = svc
        .settle_charge(&charge_id, &token_b)
        .await
        .expect("replay settle with token B");
    assert!(
        matches!(replay, CreditOutcome::Duplicate(_)),
        "a replay of an already-settled charge is a Duplicate no-op"
    );

    // The money tooth: token B was NEVER redeemed, so the wallet balance is UNCHANGED.
    let wallet_after_replay: u64 = node_wallet_probe
        .total_balance()
        .await
        .expect("read node wallet balance after the replay")
        .into();
    assert_eq!(
        wallet_after_replay, wallet_after_first,
        "MONEY-MUST: the fresh replay token was never redeemed -- wallet balance unchanged"
    );

    // Token B is still spendable at the mint (the daemon never touched it): the payer can
    // still redeem it back, proving it was not silently consumed by the daemon.
    let reclaim: u64 = payer
        .receive(&token_b, cdk::wallet::ReceiveOptions::default())
        .await
        .expect("token B is still valid and unspent")
        .into();
    assert!(reclaim > 0, "token B was never redeemed by the daemon -- still spendable");

    // The treasury is unchanged by the replay (the prior settled outcome, no new credit).
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        treasury_after_first,
        "treasury unchanged: the replay returned the prior settled record, credited nothing"
    );

    mint.shutdown().await;
}

/// Finding-2 tooth: a Duplicate settle attempt emits NO second PAYMENT_SETTLED. After a
/// fresh-token replay of an already-settled charge, exactly ONE PAYMENT_SETTLED sits in the
/// queue -- the one the original settlement emitted. The replay (a Duplicate) enqueues
/// nothing new.
///
/// RED-on-revert: if PAYMENT_SETTLED were enqueued for every CreditOutcome (the old
/// behaviour), the Duplicate replay would push a SECOND notice and this asserts 2, failing.
#[tokio::test]
async fn duplicate_settle_emits_no_second_payment_settled() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let node_wallet = build_wallet(&mint.url()).await.expect("build node wallet");
    let payer = build_wallet(&mint.url()).await.expect("build payer wallet");
    fund_wallet(payer.clone(), 500).await.expect("fund payer");

    let (svc, _queue) = settlement_gateway(0, node_wallet);

    let charge_id = issue_charge_via_gateway(&svc, "earn-charge-dup-notice", 50).await;

    // First settle: credited, emits its one PAYMENT_SETTLED.
    let token_a = customer_pays(&payer, 50).await;
    let first = svc
        .settle_charge(&charge_id, &token_a)
        .await
        .expect("first settle");
    assert!(matches!(first, CreditOutcome::Credited { .. }), "first settle credits");

    // Replay with a fresh token B: a Duplicate no-op that must emit NOTHING new.
    let token_b = customer_pays(&payer, 50).await;
    let replay = svc
        .settle_charge(&charge_id, &token_b)
        .await
        .expect("replay settle");
    assert!(matches!(replay, CreditOutcome::Duplicate(_)), "replay is a Duplicate");

    // Exactly ONE PAYMENT_SETTLED in the queue -- the original's. The Duplicate added none.
    let notices = poll_payment_settled(&svc, 0).await;
    assert_eq!(
        notices.len(),
        1,
        "exactly one PAYMENT_SETTLED: the original settlement's, none from the Duplicate replay"
    );
    assert_eq!(notices[0].charge_id, charge_id);

    mint.shutdown().await;
}

/// Finding-1 (the concurrency money tooth): two CONCURRENT settles of the SAME charge_id,
/// each carrying a DISTINCT genuinely-valid token, must redeem into the wallet EXACTLY
/// ONCE. The per-charge async lock serializes the lookup -> verify -> credit sequence, so
/// the first settle redeems + credits and the second sees the durable row and short-circuits
/// (Duplicate) WITHOUT redeeming its token. Exactly one credit, one PAYMENT_SETTLED, one
/// wallet redemption; the loser's token stays unspent.
///
/// RED-on-revert: drop the `settle_locks` serialization (revert `settle_charge` to the bare
/// lookup -> verify -> credit with no per-charge guard) and both futures miss the lookup,
/// BOTH call `wallet.receive` on their distinct tokens, and the wallet redeems ~100 sats
/// (both tokens) while only ~50 is credited -- the wallet-redeemed-once assert below fails.
#[tokio::test]
async fn concurrent_settles_of_same_charge_redeem_exactly_once() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let node_wallet = build_wallet(&mint.url()).await.expect("build node wallet");
    let payer = build_wallet(&mint.url()).await.expect("build payer wallet");
    fund_wallet(payer.clone(), 500).await.expect("fund payer");

    // Keep a probe handle to the daemon wallet to prove it redeemed exactly one token.
    let node_wallet_probe = node_wallet.clone();
    let (svc, _queue) = settlement_gateway(0, node_wallet);

    let charge_id = issue_charge_via_gateway(&svc, "earn-charge-concurrent", 50).await;

    // Two DISTINCT genuinely-valid tokens for the SAME charge_id.
    let token_a = customer_pays(&payer, 50).await;
    let token_b = customer_pays(&payer, 50).await;

    // Race both settles. tokio::join! drives them concurrently, maximizing the window in
    // which both could pass the lookup -- the lock is what forces exactly-once.
    let (res_a, res_b) = tokio::join!(
        svc.settle_charge(&charge_id, &token_a),
        svc.settle_charge(&charge_id, &token_b),
    );
    let out_a = res_a.expect("settle A");
    let out_b = res_b.expect("settle B");

    // EXACTLY ONE Credited, EXACTLY ONE Duplicate (order is nondeterministic).
    let credited_count = [&out_a, &out_b]
        .iter()
        .filter(|o| matches!(o, CreditOutcome::Credited { .. }))
        .count();
    let duplicate_count = [&out_a, &out_b]
        .iter()
        .filter(|o| matches!(o, CreditOutcome::Duplicate(_)))
        .count();
    assert_eq!(credited_count, 1, "exactly ONE of the racing settles credits");
    assert_eq!(duplicate_count, 1, "the loser is a Duplicate no-op");

    let credited = match (&out_a, &out_b) {
        (CreditOutcome::Credited { amount_sats, .. }, _)
        | (_, CreditOutcome::Credited { amount_sats, .. }) => *amount_sats,
        _ => panic!("one settle must have credited"),
    };

    // The treasury rose by exactly ONE credit (never both tokens).
    let balance = svc.treasury_remaining().unwrap();
    assert_eq!(balance, credited, "treasury credited exactly once");
    assert!(balance > 0 && balance <= 50, "credited one token's worth, never two");

    // The MONEY tooth: the wallet redeemed exactly ONE token. If both had redeemed, the
    // wallet would hold ~100; it holds ~50 (one token, within fee).
    let wallet_balance: u64 = node_wallet_probe
        .total_balance()
        .await
        .expect("read node wallet balance")
        .into();
    assert!(
        wallet_balance > 0 && wallet_balance <= 50,
        "MONEY-MUST: exactly ONE token was redeemed into the wallet ({wallet_balance}), never both"
    );

    // Exactly ONE PAYMENT_SETTLED (the winner's); the loser emitted none.
    let notices = poll_payment_settled(&svc, 0).await;
    assert_eq!(notices.len(), 1, "exactly one PAYMENT_SETTLED from the winning settle");
    assert_eq!(notices[0].charge_id, charge_id);

    // The loser's token is still unspent: one of A/B was never redeemed and is reclaimable.
    // Whichever lost is still valid at the mint; try both, exactly one must reclaim.
    let reclaim_a = payer
        .receive(&token_a, cdk::wallet::ReceiveOptions::default())
        .await
        .map(u64::from)
        .unwrap_or(0);
    let reclaim_b = payer
        .receive(&token_b, cdk::wallet::ReceiveOptions::default())
        .await
        .map(u64::from)
        .unwrap_or(0);
    assert!(
        (reclaim_a > 0) ^ (reclaim_b > 0),
        "exactly one token was redeemed by the daemon; the loser's is still reclaimable"
    );

    mint.shutdown().await;
}

/// Finding-2 (the terminal money tooth, end-to-end): force an OVERFLOW (treasury seeded near
/// u64::MAX so a real mint-verified credit would wrap), then RETRY with a FRESH token. The
/// first attempt redeems its token into the wallet but overflows (credits nothing) and writes
/// the durable terminal marker; the retry sees that marker, returns `Terminal`, and NEVER
/// redeems its fresh token -- the wallet balance is unchanged by the retry and still no credit.
///
/// RED-on-revert: delete the terminal-marker insert in `credit_verified`'s overflow branch
/// and the retry's `credit_lookup` misses, the retry redeems token B into the wallet (wallet
/// balance RISES on the retry), and the outcome is `Overflow`, not `Terminal` -- the
/// wallet-unchanged and Terminal asserts below fail.
#[tokio::test]
async fn overflow_marks_terminal_and_blocks_further_redemption() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let node_wallet = build_wallet(&mint.url()).await.expect("build node wallet");
    let payer = build_wallet(&mint.url()).await.expect("build payer wallet");
    fund_wallet(payer.clone(), 500).await.expect("fund payer");

    let node_wallet_probe = node_wallet.clone();
    // Seed the treasury just below u64::MAX so ANY positive credit overflows.
    let (svc, _queue) = settlement_gateway(u64::MAX - 5, node_wallet);

    let charge_id = issue_charge_via_gateway(&svc, "earn-charge-overflow", 50).await;

    // First settle: the token IS redeemed into the wallet, but the credit overflows u64, so
    // the balance is untouched and the outcome is Overflow (the terminal marker is written).
    let token_a = customer_pays(&payer, 50).await;
    let first = svc
        .settle_charge(&charge_id, &token_a)
        .await
        .expect("first (overflowing) settle");
    assert!(
        matches!(first, CreditOutcome::Overflow { .. }),
        "a credit that would wrap u64 is Overflow"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        u64::MAX - 5,
        "an overflow must not wrap or move the balance"
    );
    let wallet_after_first: u64 = node_wallet_probe
        .total_balance()
        .await
        .expect("wallet balance after the overflowing settle")
        .into();
    assert!(wallet_after_first > 0, "the first attempt DID redeem token A into the wallet");

    // Retry with a FRESH token B. The terminal marker short-circuits it BEFORE the wallet.
    let token_b = customer_pays(&payer, 50).await;
    let retry = svc
        .settle_charge(&charge_id, &token_b)
        .await
        .expect("retry after overflow");
    assert!(
        matches!(retry, CreditOutcome::Terminal(_)),
        "a retry of an overflowed charge is Terminal (settled-dead), not a fresh credit"
    );

    // The MONEY tooth: token B was NEVER redeemed -- the wallet is unchanged by the retry.
    let wallet_after_retry: u64 = node_wallet_probe
        .total_balance()
        .await
        .expect("wallet balance after the retry")
        .into();
    assert_eq!(
        wallet_after_retry, wallet_after_first,
        "finding-2: the retry never reached the wallet -- balance unchanged"
    );

    // Still no credit (the balance never moved), and token B is still reclaimable.
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        u64::MAX - 5,
        "a terminal charge credits NOTHING"
    );
    let reclaim: u64 = payer
        .receive(&token_b, cdk::wallet::ReceiveOptions::default())
        .await
        .expect("token B is unspent -- the daemon never redeemed it")
        .into();
    assert!(reclaim > 0, "token B was never redeemed by the daemon");

    // No PAYMENT_SETTLED at all: neither an overflow nor a terminal is a credit.
    let notices = poll_payment_settled(&svc, 0).await;
    assert!(notices.is_empty(), "no PAYMENT_SETTLED for a charge that never credited");

    mint.shutdown().await;
}
