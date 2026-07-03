//! Increment 1a: the bolt11 mint-quote settlement lane (`LightningSettlement`), end-to-end
//! against a local fakewallet mint (no real money, no real Lightning).
//!
//! An agent QUOTES a bolt11 (a cashu NUT-04 mint quote) that a stranger pays with any
//! Lightning wallet; settlement asks the MINT whether the quote is PAID and, when it is,
//! MINTS the ecash into the agent's wallet BEFORE the treasury is credited. The mint quote's
//! `id` is the `charge_id`, so `verify_settlement` looks the payment up by id (the `evidence`
//! arg is unused for bolt11).
//!
//! The money teeth (each RED-on-revert; see the per-test RED-on-revert notes):
//!   - TOOTH 1 (issue → bolt11): `issue()` returns a `ChargeIssuedData` whose
//!     `invoice_or_request` parses as a valid bolt11 .. `issue_returns_a_valid_bolt11_invoice`
//!   - TOOTH 2 (unpaid-gate, integration arm): a quote that is NOT yet paid does not mint or
//!     credit through the settle path .. `unpaid_quote_settle_credits_nothing`
//!     (the DETERMINISTIC gate tooth lives in rail.rs `lightning_settlement_gate_tests`)
//!   - TOOTH 3 (orphaned-proofs recovery + IDEMPOTENT): a crash between `mint()` and the credit
//!     recovers on the settle RETRY via the ISSUED branch — treasury credited exactly the summed
//!     HELD-UNSPENT amount (NOT the mint-claimed amount_issued), mint() ran exactly once, no proof
//!     loss, AND a second settle credits nothing more .. `issued_quote_recovers_the_orphaned_mint`
//!   - TOOTH (ii) (★PHANTOM-GUARD): an ISSUED quote whose mint-claimed `amount_issued` diverges
//!     from the ZERO sats actually held FAILS CLEAN (credits nothing, records a stranded quote),
//!     never crediting the phantom `amount_issued`
//!     .. `issued_quote_with_no_held_proofs_fails_clean_and_records_stranded`
//!   - MINT-DOWN-CLEAN: an unreachable mint during settle errors, credits nothing, no panic
//!     .. `mint_unreachable_during_settle_errs_and_credits_nothing`
//!
//! The fakewallet mint (a real cdk-mintd with the cdk-fake-wallet backend) auto-marks a mint
//! quote PAID after a short random delay (mintd default min..=max = 1..=3s), so "the stranger
//! pays" is simulated by waiting for that flip. There is NO way to hold a quote UNPAID
//! indefinitely; the deterministic gate unit test carries the fail-closed tooth, and the
//! integration arm below observes the FRESH (pre-flip) UNPAID window.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cdk::amount::SplitTarget;
use cdk::nuts::nut00::ProofsMethods as _;
use cdk::nuts::{MintQuoteState, State};

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::mint_rig::build_wallet;
use kirby_node::nerve::InboundQueue;
use kirby_node::rail::{
    ChargeIssuedData, LightningSettlement, MockRail, SettlementProvider, StrandedQuoteSink,
    ISSUE_CHARGE_DESTINATION,
};
use kirby_node::treasury::{CreditOutcome, Treasury};

use kirby_proto::InboundKind;

use common::mint_fixture::FakeMint;

/// A capturing [`StrandedQuoteSink`] for the phantom-guard tooth: records every
/// `record_stranded` call so the test can assert the TRUE lost-response path (mint ISSUED,
/// wallet empty) recorded the stranded quote instead of crediting.
#[derive(Default)]
struct CapturingStrandedSink {
    calls: Mutex<Vec<(String, u64, String)>>,
    count: AtomicU64,
}

impl StrandedQuoteSink for CapturingStrandedSink {
    fn record_stranded(&self, quote_id: &str, amount_issued: u64, reason: &str) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.calls
            .lock()
            .unwrap()
            .push((quote_id.to_string(), amount_issued, reason.to_string()));
    }
}

impl CapturingStrandedSink {
    fn count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
    fn last(&self) -> Option<(String, u64, String)> {
        self.calls.lock().unwrap().last().cloned()
    }
}

/// A settlement-mode gateway wired with a `LightningSettlement` over the daemon's host-held
/// wallet (mirrors E6's `settlement_gateway`, swapping the provider). Returns the service +
/// the shared inbound queue.
fn lightning_gateway(initial_sats: u64, node_wallet: Arc<cdk::Wallet>) -> (GatewayService, InboundQueue) {
    let treasury = Treasury::open_temporary(initial_sats).expect("open temporary treasury");
    let session = Session {
        task_descriptor: "bolt11-settlement-1a".into(),
        budget_sats: initial_sats,
        allowlisted_destinations: vec![ISSUE_CHARGE_DESTINATION.to_string()],
        allowlisted_inbound_kinds: vec![InboundKind::PaymentSettled],
    };
    let queue = InboundQueue::new();
    let svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_settlement_provider(LightningSettlement::new(node_wallet))
        .with_inbound_queue(queue.clone());
    (svc, queue)
}

/// Poll a mint quote until it reaches `want` (or a bounded deadline). The fakewallet flips a
/// mint quote to PAID after ~1-3s; this waits for that "the stranger paid" event without
/// coupling the test to the exact delay.
async fn await_quote_state(wallet: &Arc<cdk::Wallet>, quote_id: &str, want: MintQuoteState) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let q = wallet
            .check_mint_quote_status(quote_id)
            .await
            .expect("check mint quote status");
        if q.state == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "mint quote {quote_id} did not reach {want:?} in time (last state {:?})",
            q.state
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// --------------------------------------------------------------------------------------------
// TOOTH 1 — issue → bolt11: `issue()` returns a real, parseable bolt11 invoice.
//
// RED-on-revert: revert `LightningSettlement::issue` to `anyhow::bail!("lightning settlement
// not yet implemented")`. `issue()` then returns Err, the `.expect("issue a bolt11 charge")`
// panics, and this test FAILS (it never reaches the parse assertion). Observed RED = the
// expect panic on the bailed issue.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn issue_returns_a_valid_bolt11_invoice() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");
    let settlement = LightningSettlement::new(wallet);

    let charge: ChargeIssuedData = settlement
        .issue(1234, "render this frame")
        .await
        .expect("issue a bolt11 charge");

    // The requested amount is echoed on the ChargeIssuedData (the credit still comes only from
    // the mint-verified settlement, never this field).
    assert_eq!(charge.amount_sats, 1234, "the charge carries the requested amount");
    assert!(!charge.charge_id.is_empty(), "the quote id is the (non-empty) charge_id");

    // THE TOOTH: the invoice_or_request must be a REAL bolt11. Parse it with the
    // lightning-invoice crate; a non-bolt11 string (or an empty one from a bailed issue) fails
    // to parse here.
    let invoice: lightning_invoice::Bolt11Invoice = charge
        .invoice_or_request
        .parse()
        .expect("invoice_or_request must parse as a valid bolt11 invoice");

    // Sanity: the invoice is denominated for the requested amount (1234 sat = 1_234_000 msat).
    assert_eq!(
        invoice.amount_milli_satoshis(),
        Some(1_234_000),
        "the bolt11 invoice is for the requested amount"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 2 (integration arm) — unpaid-gate: a quote that is NOT yet paid credits NOTHING.
//
// The fakewallet auto-pays after ~1-3s, so we exercise the FRESH (pre-flip) UNPAID window:
// issue → IMMEDIATELY settle (no wait). At that instant the quote is UNPAID, so
// `verify_settlement`'s `ensure_quote_paid` gate errors → `settle_charge` returns Err → the
// treasury is untouched.
//
// TIMING HONESTY: this races the ~1s auto-pay. If a slow scheduler let the flip happen before
// the immediate settle, the settle could instead Credit; we GUARD against a false pass by
// asserting the quote is observably UNPAID right before the settle, and treat that guard as
// the integration signal. The DETERMINISTIC fail-closed tooth is the rail.rs unit test
// `unpaid_quote_is_rejected_by_the_gate` (no mint, no race). In practice the immediate settle
// wins comfortably (the flip needs a ≥1s tokio sleep to elapse first).
//
// RED-on-revert: relax `ensure_quote_paid` to accept every state (`Ok(())`). The immediate
// settle of the UNPAID quote would then NOT error at the gate; it would try to `wallet.mint`
// an unpaid quote (the mint refuses → a DIFFERENT error) — so the crisp fail-closed signal is
// the unit tooth. This integration arm proves the wired settle path credits nothing while the
// quote is unpaid.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn unpaid_quote_settle_credits_nothing() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");
    // Issue directly through the provider to get the quote id, then check it is UNPAID.
    let probe = LightningSettlement::new(wallet.clone());
    let charge = probe.issue(100, "unpaid-gate").await.expect("issue");

    // GUARD against a false pass: the quote must be observably UNPAID at this instant.
    let q = wallet
        .check_mint_quote_status(&charge.charge_id)
        .await
        .expect("check quote status");
    assert_eq!(
        q.state,
        MintQuoteState::Unpaid,
        "precondition: the freshly-issued quote is UNPAID before the auto-pay flip"
    );

    // Wire a gateway over the SAME wallet and settle the (still-unpaid) charge. The gate errors,
    // so settle_charge is Err and nothing is credited.
    let (svc, _queue) = lightning_gateway(0, wallet.clone());
    assert_eq!(svc.treasury_remaining().unwrap(), 0, "treasury starts empty");

    let settled = svc.settle_charge(&charge.charge_id, "").await;
    assert!(
        settled.is_err(),
        "settling an UNPAID bolt11 quote must error at the paid-gate (it did not error)"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        0,
        "MONEY-MUST: an unpaid quote credits NOTHING"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// The happy path (context for tooth 3): issue → wait for PAID → settle mints + credits the
// MINT-VERIFIED amount, and the minted proofs are in the wallet.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn paid_quote_settle_mints_and_credits_the_verified_amount() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");
    let probe = LightningSettlement::new(wallet.clone());
    let charge = probe.issue(200, "paid-path").await.expect("issue");

    // The stranger pays: the fakewallet flips the quote to PAID.
    await_quote_state(&wallet, &charge.charge_id, MintQuoteState::Paid).await;

    let (svc, _queue) = lightning_gateway(0, wallet.clone());
    let outcome = svc
        .settle_charge(&charge.charge_id, "")
        .await
        .expect("settle a paid bolt11 charge");
    let credited = match outcome {
        CreditOutcome::Credited { amount_sats, .. } => amount_sats,
        _ => panic!("expected Credited on a paid bolt11 settle"),
    };

    // The credit is the MINT-VERIFIED minted amount (200, fee-free fakewallet), never a
    // re-interpreted request.
    assert_eq!(credited, 200, "credited the mint-verified minted amount");
    assert_eq!(svc.treasury_remaining().unwrap(), credited, "treasury == credited");

    // The minted proofs are really in the wallet.
    let bal: u64 = wallet.total_balance().await.expect("wallet balance").into();
    assert_eq!(bal, 200, "the minted proofs landed in the daemon wallet");

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 3 — orphaned-proofs recovery: a crash between mint() and credit recovers on retry.
//
// Simulate the crash window: mint the proofs DIRECTLY into the wallet (this is exactly what
// `verify_settlement` does, and it flips the quote to ISSUED at the mint) WITHOUT crediting —
// modelling a daemon that died after `wallet.mint` but before `credit_verified`. Then drive
// the settle RETRY (`settle_charge`), which re-enters `verify_settlement`, sees the quote is
// ISSUED, takes the recovery branch (returns `amount_issued`, does NOT re-mint), and lets the
// idempotent credit proceed.
//
// Asserts:
//   (a) the treasury ends credited EXACTLY the minted amount;
//   (b) mint() ran EXACTLY once — proven two ways: the pre-settle direct mint is the only mint
//       (the wallet balance does not rise across the settle), AND a would-be second
//       `wallet.mint(charge_id)` on an already-ISSUED quote ERRORS (so had the retry re-minted,
//       it would have failed, not credited);
//   (c) no proof loss — the wallet balance equals the minted amount throughout.
//
// RECOVERY MECHANISM PINNED: this is the ISSUED-branch credit — sum the still-Unspent proofs the
// wallet holds for the quote (via its durable Incoming Transaction) and credit THAT, NEVER the
// mint-claimed amount_issued — NOT reconcile_to_observed / NIP-60 restore. NIP-60 is portability-only
// and downstream (a background snapshot of the wallet's unspent set); it plays no part in this
// same-process crash-window recovery, and this increment does not wire it. The proof is below:
// reverting ONLY the ISSUED branch breaks recovery even with everything else intact.
//
// RED-on-revert: in `verify_settlement`, remove the `if quote.state == Issued { return ... }`
// branch (let ISSUED fall through to `ensure_quote_paid`, which rejects ISSUED). The settle
// RETRY then Errs instead of crediting → the treasury stays 0 → the "treasury credited exactly
// the minted amount" assertion fails. Observed RED = settle_charge returns Err on the ISSUED
// retry (the recovery no longer happens).
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn issued_quote_recovers_the_orphaned_mint() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");
    let probe = LightningSettlement::new(wallet.clone());
    let charge = probe.issue(300, "orphaned-recovery").await.expect("issue");

    // The stranger pays.
    await_quote_state(&wallet, &charge.charge_id, MintQuoteState::Paid).await;

    // CRASH WINDOW: mint the proofs directly (what a settle would do), WITHOUT crediting the
    // treasury — the daemon "died" after mint() but before credit_verified.
    let minted_proofs = wallet
        .mint(&charge.charge_id, SplitTarget::default(), None)
        .await
        .expect("mint the settled ecash (the pre-crash mint)");
    let minted: u64 = minted_proofs
        .total_amount()
        .expect("total the minted proofs")
        .into();
    assert_eq!(minted, 300, "the pre-crash mint produced the full amount");

    // The quote is now ISSUED at the mint, and a SECOND mint of it ERRORS (there is nothing
    // left to mint). This is the guarantee the retry must NOT re-mint.
    assert_eq!(
        wallet
            .check_mint_quote_status(&charge.charge_id)
            .await
            .expect("check quote")
            .state,
        MintQuoteState::Issued,
        "after mint() the quote is ISSUED at the mint"
    );
    assert!(
        wallet
            .mint(&charge.charge_id, SplitTarget::default(), None)
            .await
            .is_err(),
        "a second mint() of an ISSUED quote errors — so a retry that re-minted would FAIL, \
         not credit; recovery must take the no-re-mint ISSUED branch"
    );

    let wallet_after_mint: u64 = wallet.total_balance().await.expect("balance").into();
    assert_eq!(wallet_after_mint, 300, "the minted proofs are in the wallet pre-retry");

    // THE RETRY: settle the charge. verify_settlement sees ISSUED → sums the still-Unspent proofs
    // held for the quote and returns THAT (here == the minted 300; none were spent — never
    // amount_issued), no re-mint → the treasury is credited idempotently.
    let (svc, _queue) = lightning_gateway(0, wallet.clone());
    assert_eq!(svc.treasury_remaining().unwrap(), 0, "treasury empty before the retry");

    let outcome = svc
        .settle_charge(&charge.charge_id, "")
        .await
        .expect("the ISSUED-quote settle retry recovers (does not error)");
    let credited = match outcome {
        CreditOutcome::Credited { amount_sats, .. } => amount_sats,
        _ => panic!("expected Credited on the recovery retry"),
    };

    // (a) treasury credited EXACTLY the minted amount.
    assert_eq!(credited, minted, "recovery credits exactly the already-minted amount");
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        minted,
        "MONEY-MUST: the treasury ends credited exactly the minted amount (300)"
    );

    // (b) mint() ran EXACTLY once: the wallet balance did NOT rise across the retry (the retry
    //     took the ISSUED branch and did not mint again).
    let wallet_after_retry: u64 = wallet.total_balance().await.expect("balance").into();
    assert_eq!(
        wallet_after_retry, wallet_after_mint,
        "the retry did NOT re-mint — wallet balance unchanged across the recovery settle"
    );

    // (c) no proof loss: the minted proofs are all still there.
    assert_eq!(wallet_after_retry, 300, "no proof loss — the minted 300 sat remain in the wallet");

    // (d) IDEMPOTENT: a SECOND settle of the SAME charge credits nothing more. The gateway's
    //     credit_lookup hits the now-recorded credit and short-circuits (never re-verifying), so
    //     the treasury stays at exactly 300 and the credit is Duplicate. verify_settlement is
    //     safe-to-call-more-than-once by construction (its ISSUED re-sum of Unspent proofs is
    //     deterministic), and the gateway is the double-credit wall.
    let second = svc
        .settle_charge(&charge.charge_id, "")
        .await
        .expect("a second settle of the same charge must not error");
    assert!(
        matches!(second, CreditOutcome::Duplicate(_)),
        "a second settle of an already-credited charge must be Duplicate (credited nothing more)"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        minted,
        "IDEMPOTENT: the treasury is still exactly the once-credited amount (300) after a re-settle"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH (ii) — ★PHANTOM-GUARD: an ISSUED quote whose mint-claimed `amount_issued` DIVERGES from
// the sats actually HELD in the wallet must NEVER credit `amount_issued`.
//
// CONSTRUCTING THE DIVERGENCE (amount_issued=300, held=0): mint the proofs (quote flips to
// ISSUED at the mint, so `amount_issued`=300), then mark those proofs SPENT in the wallet's
// localstore (models a daemon that already spent/melted them, or a lost mint-response that left
// the mint's book ISSUED while the wallet holds nothing Unspent for the quote). Now the mint
// CLAIMS 300 issued, but the wallet holds ZERO Unspent for the quote. The tx still names the
// proofs (found_transaction=true), so this is the "tx exists but every proof is gone" arm.
//
// Correct code: `held_unspent_for_quote` sums the Unspent proofs = 0 → verify_settlement
// FAILS CLEAN (Err), credits nothing, and records the stranded quote via the injected sink.
//
// RED-on-revert: replace the ISSUED branch body with `return Ok(quote.amount_issued.into());`
// (the old phantom bug). verify_settlement then credits the mint-claimed 300 the wallet does
// NOT hold → settle_charge returns Credited{300} → the "treasury stays 0 / settle errs"
// assertions fail. Observed RED = the treasury is credited 300 phantom sats. This is what
// proves "never amount_issued".
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn issued_quote_with_no_held_proofs_fails_clean_and_records_stranded() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");
    let probe = LightningSettlement::new(wallet.clone());
    let charge = probe.issue(300, "phantom-guard").await.expect("issue");

    // The stranger pays; mint the proofs (this flips the quote to ISSUED and sets amount_issued).
    await_quote_state(&wallet, &charge.charge_id, MintQuoteState::Paid).await;
    let minted_proofs = wallet
        .mint(&charge.charge_id, SplitTarget::default(), None)
        .await
        .expect("mint the settled ecash");
    let minted_ys = minted_proofs.ys().expect("minted proof ys");
    let minted: u64 = minted_proofs.total_amount().expect("total").into();
    assert_eq!(minted, 300, "the mint produced the full amount");

    // Precondition: the quote is ISSUED and the mint claims amount_issued == 300.
    let issued_quote = wallet
        .check_mint_quote_status(&charge.charge_id)
        .await
        .expect("check quote");
    assert_eq!(issued_quote.state, MintQuoteState::Issued, "quote is ISSUED at the mint");
    assert_eq!(
        u64::from(issued_quote.amount_issued),
        300,
        "the mint CLAIMS 300 issued — this is the phantom amount the buggy branch would credit"
    );

    // MAKE THEM DIVERGE: mark the minted proofs SPENT so the wallet holds ZERO Unspent for the
    // quote while the mint's book still says amount_issued=300.
    wallet
        .localstore
        .update_proofs_state(minted_ys, State::Spent)
        .await
        .expect("mark the minted proofs spent (the wallet no longer holds them)");
    let held_unspent: u64 = wallet
        .localstore
        .get_proofs(None, None, Some(vec![State::Unspent]), None)
        .await
        .expect("read unspent proofs")
        .iter()
        .map(|p| u64::from(p.proof.amount))
        .sum();
    assert_eq!(held_unspent, 0, "precondition: the wallet holds ZERO Unspent — divergence is real");

    // Wire settlement with a CAPTURING stranded sink so we can assert the fail-clean record.
    let sink = Arc::new(CapturingStrandedSink::default());
    let treasury = Treasury::open_temporary(0).expect("treasury");
    let session = Session {
        task_descriptor: "phantom-guard".into(),
        budget_sats: 0,
        allowlisted_destinations: vec![ISSUE_CHARGE_DESTINATION.to_string()],
        allowlisted_inbound_kinds: vec![InboundKind::PaymentSettled],
    };
    let svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_settlement_provider(
            LightningSettlement::new(wallet.clone()).with_stranded_sink(sink.clone()),
        );
    assert_eq!(svc.treasury_remaining().unwrap(), 0, "treasury starts empty");

    // THE TOOTH: settling the ISSUED-but-not-held quote FAILS CLEAN — no credit, no phantom sats.
    let settled = svc.settle_charge(&charge.charge_id, "").await;
    assert!(
        settled.is_err(),
        "settling an ISSUED quote with NO held proofs must FAIL CLEAN (never credit amount_issued)"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        0,
        "MONEY-MUST: a phantom amount_issued (300) with an empty wallet credits NOTHING — \
         reverting the ISSUED branch to `Ok(amount_issued)` credits 300 here (RED-on-revert)"
    );

    // The stranded quote was recorded for out-of-band (saga/NUT-09) recovery.
    assert_eq!(sink.count(), 1, "the lost-response path recorded exactly one stranded quote");
    let (rec_id, rec_amt, rec_reason) = sink.last().expect("a stranded record");
    assert_eq!(rec_id, charge.charge_id, "the stranded record carries the quote id");
    assert_eq!(rec_amt, 300, "the stranded record carries the mint-claimed amount_issued");
    assert!(
        rec_reason.contains("issued-but-proofs-not-held"),
        "the stranded record reason names the lost-response (got {rec_reason:?})"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// MINT-DOWN-CLEAN: the mint is unreachable during settlement → verify Errs, nothing is
// credited, no panic, no partial/committed state a retry would double-count.
//
// Construct: issue a charge against a LIVE mint (so we hold a real quote id), then SHUT THE
// MINT DOWN and settle. `verify_settlement`'s `check_mint_quote_status` hits a dead URL → Err →
// `settle_charge` returns Err → the treasury is untouched. Because the FIRST wall (credit_lookup)
// found nothing and verify_settlement never reached the wallet, a later retry (against a live
// mint) would still credit exactly once — no committed state was written on the failed attempt.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn mint_unreachable_during_settle_errs_and_credits_nothing() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");

    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");
    let probe = LightningSettlement::new(wallet.clone());
    let charge = probe.issue(150, "mint-down").await.expect("issue while the mint is up");

    // The mint goes DOWN before settlement.
    mint.shutdown().await;

    let (svc, _queue) = lightning_gateway(0, wallet.clone());
    assert_eq!(svc.treasury_remaining().unwrap(), 0, "treasury starts empty");

    // Settling now must ERROR (the mint status check cannot reach a dead mint) — not panic.
    let settled = svc.settle_charge(&charge.charge_id, "").await;
    assert!(
        settled.is_err(),
        "settling against an unreachable mint must return Err (no credit)"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        0,
        "MONEY-MUST: a mint-down settle credits NOTHING and leaves no state a retry would double-count"
    );
}
