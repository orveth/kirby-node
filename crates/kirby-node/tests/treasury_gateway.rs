//! C-3 tests: the vsock NodeGateway service and the unforgeable treasury.
//!
//! These prove the spec 3.2 authorize order and the spec 4.2 money-path
//! invariants, and they are the producing evidence for gates G3a, G3b, and G3c.
//! Most tests drive the factored-out `authorize_capability` core directly (the
//! scope allows "direct service-method calls"); one test drives the full tonic
//! client and server over an in-process duplex stream, proving the wire works
//! end-to-end without booting a microVM (the real VM boot is C-2).

use std::sync::Arc;

use kirby_node::checkpoint::{checkpoint_ref, CheckpointArtifact};
use kirby_node::gateway::{GatewayService, Session};
use kirby_node::rail::MockRail;
use kirby_node::treasury::{CreditOutcome, Treasury};
// The async RPC methods (get_session_context, get_entropy_nonce, report_event,
// request_capability) are trait methods; bring the trait into scope to call
// them on the service directly (the in-process tonic test calls them via the
// generated client instead).
use kirby_proto::capability_request::Act;
use kirby_proto::node_gateway_server::NodeGateway;
use kirby_proto::{
    CapabilityRequest, CheckpointBlob, Event, Outcome, PaidHttp, PayInvoice, SettleEcash,
    SessionRequest,
};

const MINT: &str = "mint.test.local";

/// Build a gateway with a mock rail, an initial treasury balance, and an
/// allowlist that contains the test mint. Returns the service and a handle to
/// the rail so a test can assert how many times the rail actually performed.
fn gateway_with(initial_sats: u64, rail: MockRail) -> (GatewayService, MockRail) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let session = Session {
        task_descriptor: "test".into(),
        budget_sats: initial_sats,
        allowlisted_destinations: vec![MINT.to_string(), "paid.test.local".to_string()],
    };
    let rail_handle = rail.clone();
    let service = GatewayService::new(treasury, Arc::new(rail), session);
    (service, rail_handle)
}

/// A SettleEcash request on the allowlisted mint for `amount`, authorizing
/// `budget` for the act, keyed by `key`.
fn settle_req(key: &str, amount: u64, budget: u64) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: MINT.into(),
            amount,
            recipient_or_quote: "quote-1".into(),
        })),
        budget_sats: budget,
    }
}

// ---- G3a: insufficient treasury ----

/// G3a: a RequestCapability whose budget_sats exceeds treasury_remaining is
/// DENIED_INSUFFICIENT_TREASURY, cost 0, the treasury is UNCHANGED, and NO act
/// is performed (the mock rail records zero perform calls).
#[tokio::test]
async fn g3a_insufficient_treasury_denies_and_performs_nothing() {
    // treasury 100, the genome asks to settle 500 (budget 500): budget gate
    // passes the budget check (500 <= 500) but fails the treasury check
    // (500 > 100), the INSUFFICIENT_TREASURY branch.
    let (svc, rail) = gateway_with(100, MockRail::new());
    let before = svc.treasury_remaining().unwrap();

    let receipt = svc.authorize_capability(&settle_req("k1", 500, 500)).await.unwrap();

    assert_eq!(receipt.outcome, Outcome::DeniedInsufficientTreasury as i32);
    assert_eq!(receipt.cost_sats, 0, "a denial debits nothing");
    assert_eq!(receipt.treasury_remaining, before, "balance reported unchanged");
    assert_eq!(svc.treasury_remaining().unwrap(), before, "balance actually unchanged");
    assert_eq!(rail.perform_count(), 0, "no act performed on a denial");
    assert!(receipt.proof.is_empty(), "no proof on a denial");
}

// ---- G3b: unforgeable (no balance-write path) ----

/// G3b (test): no gateway method can INCREASE the treasury. We hammer the
/// gateway with a randomized batch of capability requests (varied acts, keys,
/// budgets, amounts), each interleaved with the non-spending RPCs, and assert
/// the balance is monotonically non-increasing and never exceeds the initial
/// balance. The only mutation path (debit) can only subtract.
#[tokio::test]
async fn g3b_no_gateway_method_increases_treasury() {
    let initial = 10_000u64;
    let (svc, _rail) = gateway_with(initial, MockRail::new());

    // A small deterministic LCG so the "fuzz" is reproducible without a rand
    // dependency in the test (the producing command is then stable for the
    // verifier).
    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        state >> 33
    };

    let mut prev = svc.treasury_remaining().unwrap();
    assert!(prev <= initial);

    for i in 0..2000 {
        // Interleave the non-spending RPCs; none may move the balance.
        let _ = svc
            .get_entropy_nonce(tonic::Request::new(Default::default()))
            .await
            .unwrap();
        let _ = svc
            .report_event(tonic::Request::new(Event {
                schema_version: 1,
                // A malicious self-report claiming a huge spend must not move
                // the host-owned counter (this also covers G3c).
                kind: "spend".into(),
                detail: format!("claimed_cost={}", u64::MAX),
            }))
            .await
            .unwrap();
        let _ = svc
            .get_session_context(tonic::Request::new(SessionRequest { schema_version: 1 }))
            .await
            .unwrap();
        let _ = svc
            .submit_checkpoint(tonic::Request::new(CheckpointBlob {
                schema_version: 1,
                payload: format!("checkpoint-{i}").into_bytes(),
            }))
            .await
            .unwrap();

        // A randomized capability request. Vary the act type, the amount, the
        // budget, the destination (some off-allowlist), and the key (some
        // repeats, to hit the dedupe path).
        let amount = next() % 5000;
        let budget = next() % 5000;
        let key = format!("fuzz-{}", next() % 64); // repeats => dedupe exercised
        let act = match next() % 4 {
            0 => Act::SettleEcash(SettleEcash {
                mint_id: MINT.into(),
                amount,
                recipient_or_quote: "q".into(),
            }),
            1 => Act::SettleEcash(SettleEcash {
                // off-allowlist destination => DENIED_NOT_ALLOWLISTED
                mint_id: "evil.mint".into(),
                amount,
                recipient_or_quote: "q".into(),
            }),
            2 => Act::PayInvoice(PayInvoice {
                bolt11: "paid.test.local".into(), // not on allowlist => denied
                max_fee_sats: amount,
            }),
            _ => Act::PaidHttp(PaidHttp {
                method: "POST".into(),
                url: "https://paid.test.local/x".into(),
                body: vec![],
                max_cost_sats: amount,
            }),
        };
        let req = CapabilityRequest {
            schema_version: 1,
            idempotency_key: key,
            act: Some(act),
            budget_sats: budget,
        };
        let receipt = svc
            .request_capability(tonic::Request::new(req))
            .await
            .unwrap()
            .into_inner();

        let now = svc.treasury_remaining().unwrap();
        assert!(now <= prev, "iteration {i}: balance rose {prev} -> {now}");
        assert!(now <= initial, "iteration {i}: balance {now} exceeds initial {initial}");
        // For a freshly performed or denied act the receipt's reported remaining
        // matches the authoritative counter (the genome cannot be told a number
        // that does not match the host). A DUPLICATE_IGNORED replay returns the
        // HISTORICAL receipt, whose remaining reflects the balance at first
        // performance, so it only needs to be within the initial bound.
        if receipt.outcome == Outcome::DuplicateIgnored as i32 {
            assert!(receipt.treasury_remaining <= initial, "iteration {i}: duplicate remaining bound");
        } else {
            assert_eq!(receipt.treasury_remaining, now, "iteration {i}: receipt vs counter");
        }
        prev = now;
    }
    assert!(svc.treasury_remaining().unwrap() <= initial);
}

#[tokio::test]
async fn app_checkpoint_submit_is_content_addressed_and_unbilled() {
    let (mut svc, _rail) = gateway_with(1000, MockRail::new());
    let mut events = svc.observe_events();
    let before = svc.treasury_remaining().unwrap();
    let payload = b"state-1".to_vec();

    let ack = svc
        .submit_checkpoint(tonic::Request::new(CheckpointBlob {
            schema_version: kirby_proto::SCHEMA_VERSION,
            payload: payload.clone(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ack.schema_version, kirby_proto::SCHEMA_VERSION);
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        before,
        "SubmitCheckpoint stores state but must not bill or credit"
    );

    let latest = svc.latest_checkpoint().unwrap().unwrap();
    assert_eq!(latest.payload, payload);
    assert_eq!(latest.reference, checkpoint_ref(&payload));

    let event = events.recv().await.expect("checkpoint observer event");
    assert_eq!(event.kind, "checkpoint_submit");
    assert!(event.detail.contains(&latest.reference.sha256));
    assert!(event.detail.contains("len=7"));
}

#[tokio::test]
async fn get_session_context_carries_restore_checkpoint() {
    let checkpoint = CheckpointArtifact::new(b"mission-state".to_vec());
    let (svc, _rail) = gateway_with(1000, MockRail::new());
    let svc = svc.with_restore_checkpoint(checkpoint.clone());

    let ctx = svc
        .get_session_context(tonic::Request::new(SessionRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ctx.restore_checkpoint, Some(checkpoint.reference));
    assert_eq!(ctx.restore_checkpoint_blob, checkpoint.payload);
}

/// G3b (inspection, encoded as a property): no GENOME-REACHABLE path credits the
/// treasury. Every path reachable through a `CapabilityRequest` leaves the balance
/// equal or lower; an authorized spend lowers it by exactly the cost and never
/// raises it, and a duplicate key cannot be used to "top up". The treasury now has
/// exactly one path that RAISES the balance -- the daemon-private `credit_verified`
/// -- but it is NOT reachable from any gateway/genome path, so the genome-facing
/// invariant ("the genome cannot mint life") is unchanged. The daemon-only credit
/// path is covered by `credit_is_only_via_host_verified_settlement` below.
#[tokio::test]
async fn g3b_no_genome_reachable_path_credits_only_daemon_credit_raises() {
    let (svc, rail) = gateway_with(1000, MockRail::new());
    assert_eq!(svc.treasury_remaining().unwrap(), 1000);

    // An authorized spend of 300 lowers the balance to exactly 700.
    let r = svc.authorize_capability(&settle_req("a", 300, 300)).await.unwrap();
    assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(r.cost_sats, 300);
    assert_eq!(svc.treasury_remaining().unwrap(), 700);
    assert_eq!(rail.perform_count(), 1);

    // Re-issuing the SAME key does not perform again and does not change the
    // balance (it cannot be used to "top up").
    let dup = svc.authorize_capability(&settle_req("a", 300, 300)).await.unwrap();
    assert_eq!(dup.outcome, Outcome::DuplicateIgnored as i32);
    assert_eq!(svc.treasury_remaining().unwrap(), 700);
    assert_eq!(rail.perform_count(), 1, "no second perform on a duplicate");

    // A second, distinct spend lowers it further. The balance never rises.
    let r2 = svc.authorize_capability(&settle_req("b", 200, 200)).await.unwrap();
    assert_eq!(r2.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(svc.treasury_remaining().unwrap(), 500);
}

/// The daemon-only credit path: `credit_verified` is the ONE method that raises
/// the balance, it credits by exactly the verified amount, it is idempotent on
/// `credit_id` (no double-credit on a re-delivered settlement or a restart
/// mid-verify), and it never wraps on overflow. Driven directly on `Treasury`
/// because that is the call site: only daemon-side settlement-verification code
/// calls it, never a gateway RPC (the no-genome-credit property is proven by
/// `g3b_no_genome_reachable_path_credits_only_daemon_credit_raises` and the
/// `g3b_no_gateway_method_increases_treasury` fuzz, which drive the genome surface).
#[test]
fn credit_is_only_via_host_verified_settlement() {
    let t = Treasury::open_temporary(1_000).expect("open temporary treasury");
    assert_eq!(t.remaining().unwrap(), 1_000);

    // (b) a verified settlement credits by EXACTLY the amount.
    match t.credit_verified("charge-1", 250).unwrap() {
        CreditOutcome::Credited { amount_sats, remaining } => {
            assert_eq!(amount_sats, 250);
            assert_eq!(remaining, 1_250);
        }
        _ => panic!("first credit must be Credited"),
    }
    assert_eq!(t.remaining().unwrap(), 1_250);

    // (c) DEDUPE: a second credit with the SAME id is a no-op (no double-credit).
    match t.credit_verified("charge-1", 250).unwrap() {
        CreditOutcome::Duplicate(rec) => {
            // The stored row reflects the original credit, not a second one.
            assert_eq!(rec.treasury_remaining_after, 1_250);
        }
        _ => panic!("re-crediting the same id must be Duplicate"),
    }
    assert_eq!(t.remaining().unwrap(), 1_250, "a duplicate credit must not raise the balance");

    // Dedupe is PER-id: a distinct settlement still credits.
    match t.credit_verified("charge-2", 50).unwrap() {
        CreditOutcome::Credited { amount_sats, remaining } => {
            assert_eq!(amount_sats, 50);
            assert_eq!(remaining, 1_300);
        }
        _ => panic!("a distinct credit_id must credit"),
    }
    assert_eq!(t.remaining().unwrap(), 1_300);

    // STRUCTURAL DISJOINTNESS: credit rows live in their OWN tree, not the debit
    // `ledger`. The debit-side lookup never sees a credit (so a genome cannot grief a
    // settlement by pre-claiming a colliding idempotency_key), and the `mem-write-`
    // wseq scan never sees one either. Both queries over the debit ledger come back
    // empty for credit ids.
    assert!(t.lookup("charge-1").unwrap().is_none(), "a credit must NOT appear in the debit ledger");
    assert!(t.lookup("credit-charge-1").unwrap().is_none(), "no `credit-`-prefixed debit row exists either");
    assert_eq!(t.max_idempotency_seq("mem-write-").unwrap(), None);

    // (overflow) an add that would exceed u64::MAX is REFUSED with no mutation.
    let big = Treasury::open_temporary(u64::MAX - 10).expect("open near-max treasury");
    match big.credit_verified("charge-overflow", 100).unwrap() {
        CreditOutcome::Overflow { remaining } => assert_eq!(remaining, u64::MAX - 10),
        _ => panic!("an overflowing credit must be Overflow"),
    }
    assert_eq!(big.remaining().unwrap(), u64::MAX - 10, "an overflow credit must not wrap the balance");
}

// ---- G3c: self-reported numbers are never billed ----

/// G3c: the daemon ignores the genome's self-reported ReportEvent numbers for
/// billing. A genome that reports a spend (or any number) over ReportEvent does
/// not move the treasury counter; only host-side debits do.
#[tokio::test]
async fn g3c_report_event_cannot_move_the_treasury() {
    let (svc, _rail) = gateway_with(777, MockRail::new());
    let before = svc.treasury_remaining().unwrap();

    for detail in ["cpu=0", "spent=1000000", "credit=999999", "remaining=0"] {
        let ack = svc
            .report_event(tonic::Request::new(Event {
                schema_version: 1,
                kind: "self_report".into(),
                detail: detail.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ack.schema_version, kirby_proto::SCHEMA_VERSION);
    }

    assert_eq!(
        svc.treasury_remaining().unwrap(),
        before,
        "ReportEvent must never move the host-owned treasury counter"
    );
}

// ---- the spec 3.2 authorize order, step by step ----

/// Step 2: an act to a destination NOT on the allowlist is DENIED_NOT_ALLOWLISTED
/// with debit 0 and no perform.
#[tokio::test]
async fn order_step2_not_allowlisted() {
    let (svc, rail) = gateway_with(1000, MockRail::new());
    let req = CapabilityRequest {
        schema_version: 1,
        idempotency_key: "x".into(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: "not.allowed".into(),
            amount: 10,
            recipient_or_quote: "q".into(),
        })),
        budget_sats: 1000,
    };
    let r = svc.authorize_capability(&req).await.unwrap();
    assert_eq!(r.outcome, Outcome::DeniedNotAllowlisted as i32);
    assert_eq!(r.cost_sats, 0);
    assert_eq!(svc.treasury_remaining().unwrap(), 1000);
    assert_eq!(rail.perform_count(), 0);
}

/// Step 3: an estimate over the genome's authorized budget is DENIED_OVER_BUDGET
/// (even when the treasury could cover it), debit 0, no perform.
#[tokio::test]
async fn order_step3_over_budget() {
    let (svc, rail) = gateway_with(10_000, MockRail::new());
    // amount 500 but the genome only authorized 100 for this act.
    let r = svc.authorize_capability(&settle_req("x", 500, 100)).await.unwrap();
    assert_eq!(r.outcome, Outcome::DeniedOverBudget as i32);
    assert_eq!(r.cost_sats, 0);
    assert_eq!(svc.treasury_remaining().unwrap(), 10_000);
    assert_eq!(rail.perform_count(), 0);
}

/// The happy path: authorized, performed, debited by exactly the cost, and the
/// reported remaining equals the new authoritative balance.
#[tokio::test]
async fn order_happy_path_debits_exactly_once() {
    let (svc, rail) = gateway_with(1000, MockRail::new());
    let r = svc.authorize_capability(&settle_req("pay-1", 250, 250)).await.unwrap();
    assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(r.cost_sats, 250);
    assert_eq!(r.treasury_remaining, 750);
    assert_eq!(svc.treasury_remaining().unwrap(), 750);
    assert_eq!(rail.perform_count(), 1);
    assert!(!r.proof.is_empty(), "an authorized act carries the rail receipt");
}

/// Step 1 dedupe: a re-issue of the same key returns the prior receipt and does
/// not perform or debit again.
#[tokio::test]
async fn order_step1_dedupe_returns_prior_receipt() {
    let (svc, rail) = gateway_with(1000, MockRail::new());
    let first = svc.authorize_capability(&settle_req("k", 250, 250)).await.unwrap();
    let second = svc.authorize_capability(&settle_req("k", 250, 250)).await.unwrap();

    assert_eq!(first.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(second.outcome, Outcome::DuplicateIgnored as i32);
    // The duplicate carries the prior cost and the prior post-debit balance.
    assert_eq!(second.cost_sats, first.cost_sats);
    assert_eq!(second.treasury_remaining, first.treasury_remaining);
    assert_eq!(second.proof, first.proof, "the prior receipt is returned verbatim");
    assert_eq!(svc.treasury_remaining().unwrap(), 750, "debited once total");
    assert_eq!(rail.perform_count(), 1, "performed once total");
}

// ---- D-20: the perform cap (never overspend after perform) ----

/// D-20: a rail that NATURALLY overshoots its estimate is capped at the
/// estimate, so the actual debit is <= estimate <= treasury, never past zero.
#[tokio::test]
async fn d20_perform_caps_actual_at_estimate() {
    // treasury exactly equals the estimate; the rail tries to overshoot by 1000.
    let (svc, rail) = gateway_with(300, MockRail::overshooting(1000));
    let r = svc.authorize_capability(&settle_req("k", 300, 300)).await.unwrap();

    assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32);
    // The natural cost would be 1300, but the cap clamps the actual to 300.
    assert_eq!(r.cost_sats, 300, "actual is capped at the estimate (D-20)");
    assert_eq!(svc.treasury_remaining().unwrap(), 0, "drained to exactly zero, never negative");
    assert_eq!(rail.perform_count(), 1);
}

/// An upstream failure performs (attempts) but debits nothing: UPSTREAM_FAILED,
/// cost 0, treasury unchanged.
#[tokio::test]
async fn upstream_failure_debits_nothing() {
    let (svc, _rail) = gateway_with(1000, MockRail::failing());
    let r = svc.authorize_capability(&settle_req("k", 250, 250)).await.unwrap();
    assert_eq!(r.outcome, Outcome::UpstreamFailed as i32);
    assert_eq!(r.cost_sats, 0);
    assert_eq!(svc.treasury_remaining().unwrap(), 1000);
}

// ---- never-overspend across many spends ----

/// A run of distinct spends can drain the treasury to zero but never below: the
/// first spend that would overspend is DENIED before the act.
#[tokio::test]
async fn never_overspend_drains_to_zero_then_denies() {
    let (svc, rail) = gateway_with(1000, MockRail::new());
    // Four spends of 300: 300, 300, 300 succeed (900 total), the fourth (would
    // be 1200) is denied because 300 > 100 remaining.
    for i in 0..3 {
        let r = svc.authorize_capability(&settle_req(&format!("s{i}"), 300, 300)).await.unwrap();
        assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32, "spend {i}");
    }
    assert_eq!(svc.treasury_remaining().unwrap(), 100);
    let denied = svc.authorize_capability(&settle_req("s3", 300, 300)).await.unwrap();
    assert_eq!(denied.outcome, Outcome::DeniedInsufficientTreasury as i32);
    assert_eq!(svc.treasury_remaining().unwrap(), 100, "denied spend did not touch the balance");
    assert_eq!(rail.perform_count(), 3, "only the three authorized spends performed");
}

// ---- idempotent across resume (persistence) ----

/// Idempotent across resume (spec 4.2): a key performed before a snapshot, then
/// re-issued after a resume, returns DUPLICATE_IGNORED and is debited once. We
/// model the resume by dropping the treasury handle and re-opening the SAME
/// persisted store (a new Treasury over the same path), as node 2 would.
#[tokio::test]
async fn idempotent_across_resume_persisted() {
    let dir = tempdir();
    let path = dir.join("treasury");

    // Pre-snapshot: open, spend under key K (cost 400), drop the handle.
    let post_cost;
    let post_remaining;
    {
        let treasury = Treasury::open(&path, 1000).unwrap();
        let session = Session {
            task_descriptor: "t".into(),
            budget_sats: 1000,
            allowlisted_destinations: vec![MINT.to_string()],
        };
        let rail = MockRail::new();
        let rail_handle = rail.clone();
        let svc = GatewayService::new(treasury, Arc::new(rail), session);
        let r = svc.authorize_capability(&settle_req("K", 400, 400)).await.unwrap();
        assert_eq!(r.outcome, Outcome::AuthorizedAndPerformed as i32);
        assert_eq!(rail_handle.perform_count(), 1);
        post_cost = r.cost_sats;
        post_remaining = r.treasury_remaining;
        assert_eq!(post_remaining, 600);
    }

    // Resume: re-open the SAME store (the seed is ignored, the persisted 600 is
    // authoritative), re-issue key K. It is a duplicate, debited once total.
    {
        let treasury = Treasury::open(&path, 999_999).unwrap();
        assert_eq!(treasury.remaining().unwrap(), 600, "persisted balance survived, seed ignored");
        let session = Session {
            task_descriptor: "t".into(),
            budget_sats: 1000,
            allowlisted_destinations: vec![MINT.to_string()],
        };
        let rail = MockRail::new();
        let rail_handle = rail.clone();
        let svc = GatewayService::new(treasury, Arc::new(rail), session);
        let r = svc.authorize_capability(&settle_req("K", 400, 400)).await.unwrap();
        assert_eq!(r.outcome, Outcome::DuplicateIgnored as i32);
        assert_eq!(r.cost_sats, post_cost, "the prior cost is returned");
        assert_eq!(r.treasury_remaining, post_remaining, "the prior balance is returned");
        assert_eq!(rail_handle.perform_count(), 0, "the act is NOT performed again after resume");
        assert_eq!(svc.treasury_remaining().unwrap(), 600, "debited once across the resume");
    }
}

// ---- full tonic client/server over an in-process transport ----

/// Drive the gateway through the real tonic client and server, end to end, over
/// an in-process duplex stream (no microVM; the vsock transport is wired in
/// `serve_vsock` for C-2). This proves the generated wire types, the service
/// dispatch, and the authorize order all work over the actual gRPC stack.
#[tokio::test]
async fn end_to_end_over_in_process_tonic() {
    use kirby_proto::node_gateway_client::NodeGatewayClient;
    use tonic::transport::{Endpoint, Server, Uri};

    let (svc, rail) = gateway_with(1000, MockRail::new());

    // An in-memory duplex stream stands in for the vsock connection.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut client_io = Some(client_io);

    tokio::spawn(async move {
        let incoming = tokio_stream::once(Ok::<_, std::io::Error>(server_io));
        Server::builder()
            .add_service(svc.into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // The connector hands tonic the single client end of the duplex.
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let io = client_io.take().expect("connector called once");
            async move { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io)) }
        }))
        .await
        .unwrap();
    let mut client = NodeGatewayClient::new(channel);

    // GetSessionContext round-trip.
    let ctx = client
        .get_session_context(SessionRequest { schema_version: 1 })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ctx.budget_sats, 1000);
    assert!(ctx.allowlisted_destinations.contains(&MINT.to_string()));

    // A brokered act over the wire: authorized, performed, debited.
    let receipt = client
        .request_capability(settle_req("wire-1", 250, 250))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(receipt.outcome, Outcome::AuthorizedAndPerformed as i32);
    assert_eq!(receipt.cost_sats, 250);
    assert_eq!(receipt.treasury_remaining, 750);
    assert_eq!(rail.perform_count(), 1);

    // The same key again over the wire is a duplicate, performed once total.
    let dup = client
        .request_capability(settle_req("wire-1", 250, 250))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(dup.outcome, Outcome::DuplicateIgnored as i32);
    assert_eq!(rail.perform_count(), 1);
}

// ---- a tiny temp-dir helper (no external dev-dependency) ----

/// A unique temp directory removed on drop. Keeps the test free of an external
/// tempfile dev-dependency, matching the C-1 idiom of avoiding deps for small
/// needs.
struct TempDir {
    path: std::path::PathBuf,
}
impl std::ops::Deref for TempDir {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.path
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "kirby-c3-test-{}-{}-{}",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    TempDir { path }
}
