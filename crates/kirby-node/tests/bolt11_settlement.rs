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
    ChargeIssuedData, LightningSettlement, MockRail, SettlementProvider, SledStrandedSink,
    StrandedQuoteSink, ISSUE_CHARGE_DESTINATION,
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
    fn record_stranded(
        &self,
        quote_id: &str,
        amount_issued: u64,
        reason: &str,
    ) -> anyhow::Result<()> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.calls
            .lock()
            .unwrap()
            .push((quote_id.to_string(), amount_issued, reason.to_string()));
        // An in-memory capture has no durable store to fail.
        Ok(())
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

/// A [`StrandedQuoteSink`] whose durable write ALWAYS fails (models a full disk / sled error) — for
/// the Fix-2 tooth that a failed durable record HARD-FAILS the Lightning settlement instead of being
/// silently swallowed.
struct FailingStrandedSink;

impl StrandedQuoteSink for FailingStrandedSink {
    fn record_stranded(
        &self,
        _quote_id: &str,
        _amount_issued: u64,
        _reason: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("simulated durable stranded-sink write failure (disk/sled error)")
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

// --------------------------------------------------------------------------------------------
// TOOTH 4 (★DURABLE-SINK, Inc 1b/D4): a stranded-quote record written via `SledStrandedSink`
// SURVIVES a real process restart (drop the store handle, REOPEN the tree from the SAME path).
// This is what separates the durable sink from the in-memory `LoudErrorStrandedSink`: an orphaned
// real sat's recovery marker must not evaporate on a crash.
//
// RED-on-revert: revert `SledStrandedSink::record_stranded` to NOT persist (e.g. delete the
// `self.tree.insert(...) + self.db.flush()` block so it only logs — the in-memory/LoudError-only
// behavior), and the reopened tree holds NOTHING → `reopened.get(...)` returns `None` → the
// `assert_eq!(Some(..))` below FAILS (RED). It is NOT an in-memory check: the assertion reads a
// freshly-`open`ed handle after the writer was dropped.
// --------------------------------------------------------------------------------------------
#[test]
fn stranded_record_survives_a_store_reopen() {
    // A unique on-disk path (mirrors the test TempDir pattern; NOT temp_dir for prod, but a test
    // scratch dir is fine). Removed at the end.
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "kirby-stranded-tooth-{}-{}",
        std::process::id(),
        n
    ));

    let quote_id = "quote-stranded-abc123";
    let amount_issued = 4242u64;
    let reason = "issued-but-proofs-not-held (tooth 4 durability)";

    // 1) Write the record through the durable sink, then DROP the handle (models a process exit).
    {
        let sink = SledStrandedSink::open(&path).expect("open durable stranded sink");
        sink.record_stranded(quote_id, amount_issued, reason)
            .expect("durable write of the stranded record succeeds");
        // handle (and its sled Db) dropped here.
    }

    // 2) REOPEN the tree from the SAME path in a fresh handle and assert the record is present.
    let reopened = SledStrandedSink::open(&path).expect("reopen durable stranded sink");
    let got = reopened.get(quote_id).expect("read stranded record after reopen");
    assert_eq!(
        got,
        Some(kirby_node::rail::StrandedRecord {
            quote_id: quote_id.to_string(),
            amount_issued,
            reason: reason.to_string(),
        }),
        "MONEY-SAFETY (D4): a stranded-quote record MUST survive a store drop + reopen \
         (durable, not in-memory) — reverting the sled insert/flush makes this None (RED)"
    );

    drop(reopened);
    let _ = std::fs::remove_dir_all(&path);
}

// --------------------------------------------------------------------------------------------
// TOOTH 1 (WIRE, Inc 1b/D1): a LIGHTNING provider attached to the gateway via the NEW
// `with_settlement_provider_dyn` (the boot-attach seam) serves an IssueCharge END-TO-END —
// the gateway returns a real bolt11. This is the thing 1a proved MISSING (no production path
// attached any provider). The genome sends `method = Lightning`; the wired provider is Lightning.
//
// RED-on-revert: delete the `.with_settlement_provider_dyn(...)` line below (leave the gateway
// with `settlement: None`, exactly today's production default). `authorize_issue_charge` then
// fails closed (denied, no `ChargeIssued`), so `receipt.charge` is `None`, the
// `.expect("gateway returns a ChargeIssued")` panics, and this test FAILS (RED).
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn lightning_provider_attached_dyn_issues_a_bolt11_through_the_gateway() {
    use kirby_proto::capability_request::Act;
    use kirby_proto::{CapabilityRequest, ChargeMethod, IssueCharge, Outcome};

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");

    let treasury = Treasury::open_temporary(0).expect("open temporary treasury");
    let session = Session {
        task_descriptor: "bolt11-wire-tooth".into(),
        budget_sats: 0,
        allowlisted_destinations: vec![ISSUE_CHARGE_DESTINATION.to_string()],
        allowlisted_inbound_kinds: vec![InboundKind::PaymentSettled],
    };
    // THE ATTACH under test: the boot-path seam that threads a provider we hold as Arc<dyn ..>.
    let provider: Arc<dyn SettlementProvider> = Arc::new(LightningSettlement::new(wallet));
    let svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_settlement_provider_dyn(provider);

    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "wire-charge-1".into(),
        act: Some(Act::IssueCharge(IssueCharge {
            amount_sats: 777,
            memo: "a stranger pays real sats".into(),
            method: ChargeMethod::Lightning as i32,
        })),
        budget_sats: 0,
    };
    let receipt = svc.authorize_capability(&req).await.expect("authorize IssueCharge");
    assert_eq!(
        receipt.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "a wired Lightning provider must authorize a Lightning IssueCharge"
    );
    let charge = receipt.charge.expect("gateway returns a ChargeIssued");
    // THE TOOTH: the invoice_or_request is a REAL bolt11 the stranger can pay from any wallet.
    let _invoice: lightning_invoice::Bolt11Invoice = charge
        .invoice_or_request
        .parse()
        .expect("the gateway-issued invoice_or_request must be a valid bolt11");
    assert_eq!(charge.method, ChargeMethod::Lightning as i32, "echoes the Lightning rail");
}

// --------------------------------------------------------------------------------------------
// TOOTH 2 (★METHOD-GUARD, Inc 1b/D2): with a LIGHTNING provider wired, an IssueCharge carrying
// `method = Cashu` (a rail MISMATCH) is REJECTED fail-closed (denied, debit 0) — the charge is
// NEVER settled on the wrong rail. The mint is LIVE, so the guard is the ONLY thing stopping the
// mismatched charge from minting a bolt11.
//
// RED-on-revert: delete the method-guard block in `authorize_issue_charge` (the
// `if ic.method != wired_method { .. }`); the mismatched Cashu charge then proceeds into
// `settlement.issue` on the LIVE Lightning provider, a `ChargeIssued` is returned, the outcome
// flips to AuthorizedAndPerformed, and both assertions below FAIL (RED).
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn issue_charge_with_mismatched_method_is_rejected_fail_closed() {
    use kirby_proto::capability_request::Act;
    use kirby_proto::{CapabilityRequest, ChargeMethod, IssueCharge, Outcome};

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");

    // lightning_gateway wires a LightningSettlement (method() == Lightning) over the wallet.
    let (svc, _queue) = lightning_gateway(0, wallet);

    let req = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: "mismatch-charge-1".into(),
        act: Some(Act::IssueCharge(IssueCharge {
            amount_sats: 500,
            memo: "cashu charge on a lightning rail".into(),
            // MISMATCH: the wired provider is Lightning; the charge asks for Cashu.
            method: ChargeMethod::Cashu as i32,
        })),
        budget_sats: 0,
    };
    let receipt = svc.authorize_capability(&req).await.expect("authorize IssueCharge");
    assert_eq!(
        receipt.outcome,
        Outcome::UpstreamFailed as i32,
        "MONEY-SAFETY: a method mismatch (Cashu charge, Lightning provider) must be DENIED fail-closed"
    );
    assert!(
        receipt.charge.is_none(),
        "a rejected mismatched charge must NOT carry a ChargeIssued (never settled on the wrong rail)"
    );
    assert_eq!(receipt.cost_sats, 0, "a rejected charge debits nothing");
}

// --------------------------------------------------------------------------------------------
// ★ FIX 1 (HIGH, load-bearing) — settlement-minted proofs are MIRRORED to the NIP-60 relay backup
// WITHOUT needing a later spend. This is the failover sats-loss guard: a stranger pays → we mint →
// the node dies before any spend → on a restore-from-relay the minted proofs must ALREADY be on the
// backup or they are LOST.
//
// The provider mints proofs DIRECTLY into the raw wallet (it does not go through the
// Nip60BackedEcash decorator that flips the backup `dirty` flag), and the flusher is DIRTY-GATED
// (`if !dirty { return }`). So without the provider's `mark_dirty` wiring, a settlement mint never
// re-dirties the backup and the next flush is a NO-OP — the minted proofs never reach the relay.
//
// This tooth asserts REAL MIRROR CONTENT (not just the dirty flag): after a settlement mint + a
// flush, it reads the PUBLISHED kind:7375 backup back off a real in-process relay
// (`reconcile_on_load`, the exact set a failover restore recovers), decrypts+aggregates it, and
// asserts every minted proof `y` is present. A baseline flush FIRST consumes the constructor-seeded
// dirty=true, so the settlement's `mark_dirty` is the ONLY thing that can re-dirty the backup.
//
// RED-on-revert: delete the `if let Some(notifier) = &self.backup_notifier { notifier.mark_dirty(); }`
// block on `LightningSettlement::verify_settlement`'s freshly-minted (PAID) path in rail.rs. The
// settlement then mints proofs but never re-dirties the backup; flush #2 sees `!dirty` and no-ops;
// the published backup still holds only flush #1's EMPTY snapshot; the minted `y`s are ABSENT from
// the reconciled set → the `contains(y)` assertion FAILS (RED). Real sats-loss made visible.
// --------------------------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settlement_minted_proofs_are_mirrored_to_the_nip60_backup_without_a_later_spend() {
    use std::collections::HashSet;
    use std::sync::atomic::AtomicBool;

    use cdk::nuts::State;
    use kirby_node::nip60::Nip60Store;
    use kirby_node::rail::{CdkEcash, Nip60BackedEcash};
    use nostr_relay_builder::MockRelay;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");

    // A real in-process nostr relay is the NIP-60 backup target (the mirror we inspect).
    let relay = MockRelay::run().await.expect("boot in-process nostr relay");
    let relay_url = relay.url().await.to_string();

    // The NIP-60 store over the relay. Open the same write gates boot opens: mark recovery complete
    // and run a reconcile to establish the read quorum, so the flusher's rollover can publish.
    let event_key = [7u8; 32];
    let mut store = Nip60Store::connect(
        &event_key,
        std::slice::from_ref(&relay_url),
        None,
        None,
        vec![mint.url()], // trust this mint on reconcile (the proofs' token event names it)
    )
    .await
    .expect("connect nip60 store");
    store.set_recovery_complete(Arc::new(AtomicBool::new(true)));
    // The nostr client connects asynchronously; poll the per-relay reconcile until it reports the
    // read quorum established (served >= read_k), so the flusher's rollover is not skipped as a
    // "non-authoritative boot". Bounded so a genuinely-unreachable relay fails loudly.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let read = store
            .reconcile_on_load_with_ids()
            .await
            .expect("reconcile the relay");
        if read.authoritative {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the in-process relay never reached read quorum (served < read_k)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let store = Arc::new(store);

    // The flusher + a dirty-notifier over the SAME shared BackupState (exactly the boot seam).
    let (_decorator, flusher) = Nip60BackedEcash::with_flusher(
        CdkEcash::new(wallet.clone()),
        wallet.clone(),
        store.clone(),
        mint.url(),
        "sat".to_string(),
        Vec::new(),
    );
    let notifier = flusher.dirty_notifier();

    // The provider under test, wired with the notifier (as boot wires it after the flusher exists).
    let settlement = LightningSettlement::new(wallet.clone()).with_backup_notifier(notifier);

    // FLUSH #1 (baseline): consume the constructor-seeded dirty=true (publishes the current — empty —
    // snapshot). After this, dirty is clear, so the settlement mint's mark_dirty is the ONLY thing
    // that can re-dirty the backup — which is what makes the revert bite.
    flusher
        .flush()
        .await
        .expect("baseline flush publishes the empty snapshot and clears the seeded dirty flag");

    // A stranger pays: issue a bolt11, wait for the mint to mark it PAID, then settle. verify_settlement
    // MINTS the ecash into the wallet and (via the notifier) marks the backup dirty. NO spend happens.
    let charge = settlement
        .issue(128, "a stranger pays real sats")
        .await
        .expect("issue a bolt11 charge");
    await_quote_state(&wallet, &charge.charge_id, MintQuoteState::Paid).await;
    let minted = settlement
        .verify_settlement(&charge.charge_id, "")
        .await
        .expect("settle mints the ecash");
    assert_eq!(minted, 128, "the mint minted the full requested amount");

    // The minted proofs' ys — the wallet truth that MUST be mirrored.
    let held = wallet
        .get_proofs_with(Some(vec![State::Unspent]), None)
        .await
        .expect("read the wallet's unspent proofs");
    let minted_ys: HashSet<_> = held.ys().expect("minted proof ys").into_iter().collect();
    assert!(!minted_ys.is_empty(), "the settlement minted at least one unspent proof");

    // FLUSH #2 (the mirror flush): must publish the minted proofs. Without the notifier wiring, dirty
    // is still false here (flush #1 cleared it; the mint never re-set it), so this no-ops → RED.
    flusher.flush().await.expect("mirror flush publishes the minted proofs");

    // THE TOOTH: read the PUBLISHED relay backup back and assert it CARRIES every minted proof y.
    // reconcile_on_load fetches the live kind:7375 events off the relay, decrypts + aggregates them —
    // the exact proof set a failover restore recovers. A minted y missing here = sats lost on restore.
    let backed_up = store
        .reconcile_on_load()
        .await
        .expect("reconcile the published relay backup");
    let backed_up_ys: HashSet<_> = backed_up
        .ys()
        .expect("backup proof ys")
        .into_iter()
        .collect();
    for y in &minted_ys {
        assert!(
            backed_up_ys.contains(y),
            "MONEY-SAFETY (Fix 1): a settlement-minted proof (y={y}) is MISSING from the published \
             NIP-60 relay backup — it would be LOST on a failover restore-from-relay. Reverting the \
             provider's mark_dirty wiring leaves flush #2 a no-op (dirty stays false), so the backup \
             carries only flush #1's empty snapshot and lacks these ys (RED-on-revert)."
        );
    }

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// FIX 2 (MED) — a durable stranded-sink WRITE FAILURE hard-fails the Lightning settlement instead of
// being silently swallowed. If we cannot durably record a stranded PAID quote, we must NOT proceed
// as if the money-safety record exists.
//
// Setup mirrors `issued_quote_with_no_held_proofs_...`: mint the proofs (quote → ISSUED), mark them
// SPENT so the wallet holds ZERO unspent for the quote (the TRUE lost-response), then settle with a
// sink whose durable write ALWAYS fails.
//
// RED-on-revert: revert the call site in `LightningSettlement::verify_settlement` to SWALLOW the sink
// error (e.g. `let _ = self.stranded_sink.record_stranded(...);` before the fail-clean bail). The
// settle then returns the ordinary fail-clean error whose message does NOT mention the durability
// failure, so the `contains("DURABLY FAILED")` assertion FAILS (RED). (settle_charge still returns
// Err either way — the tooth pins the HARD, LOUD durability-failure surfacing, not merely `is_err`.)
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn stranded_sink_write_failure_hard_fails_the_lightning_settlement() {
    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");

    let probe = LightningSettlement::new(wallet.clone());
    let charge = probe.issue(300, "sink-fail-guard").await.expect("issue");

    // The stranger pays; mint the proofs (flips the quote to ISSUED), then mark them SPENT so the
    // wallet holds ZERO unspent → the ISSUED-but-not-held lost-response path (which records stranded).
    await_quote_state(&wallet, &charge.charge_id, MintQuoteState::Paid).await;
    let minted_proofs = wallet
        .mint(&charge.charge_id, SplitTarget::default(), None)
        .await
        .expect("mint the settled ecash");
    let minted_ys = minted_proofs.ys().expect("minted proof ys");
    wallet
        .localstore
        .update_proofs_state(minted_ys, State::Spent)
        .await
        .expect("mark the minted proofs spent (wallet holds ZERO unspent)");

    let treasury = Treasury::open_temporary(0).expect("treasury");
    let session = Session {
        task_descriptor: "sink-fail-guard".into(),
        budget_sats: 0,
        allowlisted_destinations: vec![ISSUE_CHARGE_DESTINATION.to_string()],
        allowlisted_inbound_kinds: vec![InboundKind::PaymentSettled],
    };
    let svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_settlement_provider(
            LightningSettlement::new(wallet.clone())
                .with_stranded_sink(Arc::new(FailingStrandedSink)),
        );

    // THE TOOTH: the durable record fails → the settlement HARD-fails with a loud durability error.
    // (CreditOutcome is not Debug, so match rather than unwrap_err.)
    let err = match svc.settle_charge(&charge.charge_id, "").await {
        Ok(_) => panic!("a failed durable stranded record must hard-fail the settlement"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("DURABLY FAILED"),
        "the error must name the DURABLE record failure (swallowing it — the revert — yields the \
         plain fail-clean message instead); got {msg:?}"
    );
    assert_eq!(
        svc.treasury_remaining().unwrap(),
        0,
        "MONEY-MUST: a hard-failed settlement credits NOTHING",
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// FIX 4 (MED) — the R2-4 content-aware dedupe now covers IssueCharge: a same-key re-issue with
// DIVERGENT terms is REFUSED (debit 0) instead of returning a charge that no longer matches the
// request. A same-key SAME-terms resume still returns the ORIGINAL ChargeIssued (dedupe intact).
//
// The replay below keeps the SAME method (Lightning) and diverges only on `amount_sats` — so the
// D2 method-guard is NOT the thing rejecting it; the request_hash comparison is. That isolates this
// tooth to Fix 4.
//
// RED-on-revert: revert the `Act::IssueCharge(ic) => issue_charge_request_hash(ic)` STEP-1 arm to
// `_ => Vec::new()` (or revert the persist of `issue_charge_request_hash(ic)` in
// `authorize_issue_charge` back to `Vec::new()`). Either revert leaves the stored/compared hash
// empty, so the divergent replay is NOT refused — it returns the prior charge as DuplicateIgnored,
// and the `Outcome::Unspecified` assertion FAILS (RED).
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn issue_charge_replay_with_divergent_terms_is_refused() {
    use kirby_proto::capability_request::Act;
    use kirby_proto::{CapabilityRequest, ChargeMethod, IssueCharge, Outcome};

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let wallet = build_wallet(&mint.url()).await.expect("build daemon wallet");
    // lightning_gateway wires a LightningSettlement (method() == Lightning) over the wallet.
    let (svc, _queue) = lightning_gateway(0, wallet);

    let key = "issue-dedupe-key-1";
    let first = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::IssueCharge(IssueCharge {
            amount_sats: 100,
            memo: "job".into(),
            method: ChargeMethod::Lightning as i32,
        })),
        budget_sats: 0,
    };
    let r1 = svc.authorize_capability(&first).await.expect("first issue");
    assert_eq!(
        r1.outcome,
        Outcome::AuthorizedAndPerformed as i32,
        "the first issue is authorized"
    );
    let charge1 = r1.charge.clone().expect("the first issue returns a charge");

    // Same key, SAME method (so the method-guard is NOT what rejects), DIVERGENT amount (200 vs 100).
    let divergent = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::IssueCharge(IssueCharge {
            amount_sats: 200,
            memo: "job".into(),
            method: ChargeMethod::Lightning as i32,
        })),
        budget_sats: 0,
    };
    let r2 = svc.authorize_capability(&divergent).await.expect("divergent replay");
    assert_eq!(
        r2.outcome,
        Outcome::Unspecified as i32,
        "a same-key IssueCharge replay with DIVERGENT terms (200 vs 100) must be REFUSED (debit 0); \
         reverting the IssueCharge request_hash arm returns DuplicateIgnored here (RED-on-revert)"
    );
    assert!(r2.charge.is_none(), "a refused divergent replay carries no ChargeIssued");

    // A same-key SAME-terms resume still dedupes to the ORIGINAL charge (the contract is preserved).
    let resume = CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: key.into(),
        act: Some(Act::IssueCharge(IssueCharge {
            amount_sats: 100,
            memo: "job".into(),
            method: ChargeMethod::Lightning as i32,
        })),
        budget_sats: 0,
    };
    let r3 = svc.authorize_capability(&resume).await.expect("same-terms resume");
    assert_eq!(
        r3.outcome,
        Outcome::DuplicateIgnored as i32,
        "a same-key SAME-terms resume dedupes (returns the stored charge, not a refusal)"
    );
    assert_eq!(
        r3.charge.expect("resume returns a charge").charge_id,
        charge1.charge_id,
        "the resume returns the SAME charge_id (customer correlation preserved)"
    );

    mint.shutdown().await;
}
