//! `fund-wallet` teeth (increment C): mint real ecash into the per-request (backend="routstr")
//! treasury wallet via an OPERATOR-PAID bolt11 mint quote, so a subsequent `kirby-node agent`
//! boot clears the solvency floor (`assert_wallet_backs_counter`).
//!
//! These drive the reusable money dance ([`kirby_node::mint_rig::mint_into_wallet_operator_pays`])
//! against the repo's local fakewallet mint harness ([`common::mint_fixture::FakeMint`], a real
//! cdk-mintd with the cdk-fake-wallet backend that auto-marks a quote PAID after ~1-3s), so they
//! are deterministic in CI with no real Lightning and no real money. The wallet is always OPENED
//! the boot way ([`kirby_node::mint_rig::open_persistent_wallet`] + the [`WalletKey`] seed seam),
//! so the tests exercise exactly the store + seed a `kirby-node agent` boot would read.
//!
//! LIVE-MINT NOTE (1c): the ONLY thing the fakewallet simulates is "a stranger paid the bolt11"
//! (the auto-pay flip). At 1c, an operator pays the printed bolt11 by hand and the SAME poll loop
//! observes the real PAID flip — no other change. The mint dance, the seed seam, and the
//! establishment guard are identical.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kirby_node::boot::assert_wallet_backs_counter;
use kirby_node::mint_rig::{
    mint_into_wallet_operator_pays, open_persistent_wallet, WalletKey,
};

use common::mint_fixture::{FakeMint, TempDir};

/// Open the wallet the BOOT way: seed via the `WalletKey` sibling-seed seam, NIP-60 OFF (the
/// all-true / floor-not-dropped establishment args boot.rs passes when `[nip60] relays` is empty),
/// so the NUT-13 counter establishes immediately. Returns the same `(wallet, counter_db)` pair the
/// boot path builds.
async fn open_boot_way(
    mint_url: &str,
    db_path: &Path,
) -> (
    Arc<cdk::Wallet>,
    Arc<kirby_node::nip60_counter::Nip60CounterDb>,
) {
    let seed = WalletKey::sibling_seed_of(db_path)
        .resolve_seed()
        .expect("resolve the boot-path wallet seed");
    open_persistent_wallet(
        mint_url, db_path, seed, HashMap::new(), true, true, true, false,
    )
    .await
    .expect("open the persistent wallet the boot way")
}

// --------------------------------------------------------------------------------------------
// TOOTH 2 — ★end-to-end mint → boot-unblock (the headline): fund-wallet mints N (>= initial_sats)
// into the per-request wallet store → `assert_wallet_backs_counter(balance, initial_sats)` PASSES.
//
// RED-on-revert: fund 0 (skip the mint) → the wallet balance stays 0 → `assert_wallet_backs_counter`
// bails "wallet < treasury" → the `.expect(..)` on it panics → RED. (Modelled below by the
// `assert_wallet_backs_counter(0, INITIAL)` companion assertion, which IS the reverted state.)
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn mint_funds_the_wallet_and_boot_solvency_passes() {
    const INITIAL_SATS: u64 = 5_000;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t2");
    let db_path = work.path().join("wallet.sqlite");

    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // Fund N >= the treasury floor.
    let mut printed_bolt11 = String::new();
    let outcome = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        INITIAL_SATS,
        "t2-fund",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |bolt11| printed_bolt11 = bolt11.to_string(),
    )
    .await
    .expect("fund-wallet mints the requested sats");

    // The tool handed out a real, parseable bolt11 (the operator-pays invoice).
    eprintln!("[fund-wallet tooth-2] printed bolt11: {printed_bolt11}");
    assert!(printed_bolt11.starts_with("ln"), "a bolt11 invoice was printed: {printed_bolt11}");
    assert_eq!(printed_bolt11, outcome.bolt11, "the printed bolt11 == the outcome's bolt11");
    assert!(
        outcome.minted_sats >= INITIAL_SATS,
        "minted at least the treasury floor: minted={} floor={INITIAL_SATS}",
        outcome.minted_sats
    );
    assert!(outcome.balance_sats >= INITIAL_SATS, "wallet balance backs the floor: {}", outcome.balance_sats);

    // ★ THE HEADLINE: the funded balance clears the boot solvency floor.
    assert_wallet_backs_counter(outcome.balance_sats, INITIAL_SATS)
        .expect("a funded wallet backs the treasury counter → boot proceeds");

    // The REVERTED state (fund 0): the SAME assert bails — the tooth's RED side.
    assert!(
        assert_wallet_backs_counter(0, INITIAL_SATS).is_err(),
        "an UNfunded wallet (the revert) fails the solvency floor → boot refuses"
    );

    // And it is genuinely visible when the wallet is RE-OPENED the boot way (a fresh boot).
    drop(wallet);
    drop(counter_db);
    let (reopened, _cdb) = open_boot_way(&mint.url(), &db_path).await;
    let boot_balance: u64 = reopened.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(
        boot_balance, outcome.balance_sats,
        "a fresh boot-way open sees the funded balance"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 3 — ★seed-seam correctness: the proofs are minted into the store the boot path reads,
// under the seed the boot path derives. Opening the wallet the boot way (SAME db_path → SAME
// sibling `<db_path>.seed`) sees the balance.
//
// Two guards, both TRUE and machine-checked:
//  (a) the seed the tool resolves == the seed a boot resolves, BYTE-IDENTICAL (both go through
//      `WalletKey::sibling_seed_of(db_path).resolve_seed()`); a fresh/random seed differs.
//  (b) minting into `db_path` and re-opening THAT db_path the boot way sees the balance; opening a
//      DIFFERENT (fresh) db_path — the "wrong store" the boot would not read — sees 0.
//
// RED-on-revert: point the fund tool at a different store than boot reads (guard (b): open a fresh
// db_path) → the boot-way balance is 0 → the `assert_eq!(.., minted)` fails → RED. This is the
// "proofs land where the seam directs — get it wrong and boot sees nothing" guard.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn minted_proofs_are_visible_under_the_boot_path_seed_seam() {
    const AMOUNT: u64 = 1_024;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t3");
    let db_path = work.path().join("wallet.sqlite");

    // (a) the seam is deterministic + byte-identical across resolves (this is the seam boot uses).
    let seed_first = WalletKey::sibling_seed_of(&db_path).resolve_seed().expect("first resolve");
    let seed_again = WalletKey::sibling_seed_of(&db_path).resolve_seed().expect("second resolve");
    assert_eq!(seed_first, seed_again, "the sibling-seed seam is byte-identical across resolves");

    // Fund the wallet through the boot-way open (seed = the sibling seam).
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;
    let outcome = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t3-seed-seam",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| {},
    )
    .await
    .expect("fund the wallet");
    drop(wallet);
    drop(counter_db);

    // (b) re-open the SAME db_path the boot way → the balance is visible.
    let (reopened, _cdb) = open_boot_way(&mint.url(), &db_path).await;
    let boot_balance: u64 = reopened.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(boot_balance, outcome.minted_sats, "the SAME store the boot reads holds the proofs");
    assert!(boot_balance >= AMOUNT, "the boot-way balance backs the funded amount");

    // The REVERTED state (guard (b)): a DIFFERENT store — the wrong seam target — the boot would
    // read holds NOTHING. If the tool wrote to the wrong store, this is what boot would see.
    let other_db = work.path().join("wallet-other.sqlite");
    let (other, _ocdb) = open_boot_way(&mint.url(), &other_db).await;
    let other_balance: u64 = other.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(other_balance, 0, "a store the boot would NOT read (wrong seam) sees nothing");

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 4 — NUT-13 establishment guard: with the counter ESTABLISHED (NIP-60 off, the boot-way
// open) the mint yields NON-ZERO proofs; with the counter DEFERRED (a fresh box + a below-quorum
// config read) the handler BAILS LOUDLY and NEVER silently reports success on 0 minted proofs.
//
// This is the "never silent-success-on-0" money guard: a deferred counter gates every NUT-13
// derivation at the choke point, so a naive `wallet.mint` would return ZERO proofs (nip60.rs
// choke-point tooth). The handler must refuse rather than claim a fund happened.
//
// RED-on-revert: delete the `if !counter_db.is_established() { bail!(..) }` guard (and the
// post-mint `if minted_sats == 0 { bail!(..) }` belt) in `mint_into_wallet_operator_pays` → the
// deferred call would return `Ok` with `minted_sats == 0` (silent success on 0) → the
// `is_err()` assertion below goes false → RED.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn deferred_counter_bails_loudly_never_silent_success_on_zero() {
    const AMOUNT: u64 = 512;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t4");

    // ESTABLISHED arm: the boot-way open (NIP-60 off) establishes the counter → a real mint.
    let est_db = work.path().join("wallet-established.sqlite");
    let (est_wallet, est_cdb) = open_boot_way(&mint.url(), &est_db).await;
    assert!(est_cdb.is_established(), "precondition: NIP-60-off open establishes the counter");
    let ok = mint_into_wallet_operator_pays(
        &est_wallet,
        &est_cdb,
        AMOUNT,
        "t4-established",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| {},
    )
    .await
    .expect("an established counter mints");
    assert!(ok.minted_sats >= AMOUNT, "established → non-zero mint: {}", ok.minted_sats);

    // DEFERRED arm: a FRESH box opened with a BELOW-QUORUM config read (config_authoritative=false)
    // leaves the NUT-13 counter DEFERRED (state 2) — the exact fresh-box restore condition boot
    // defers on. The handler must BAIL, never mint into a wallet that cannot derive.
    let def_db = work.path().join("wallet-deferred.sqlite");
    let seed = WalletKey::sibling_seed_of(&def_db).resolve_seed().expect("resolve deferred seed");
    let (def_wallet, def_cdb) = open_persistent_wallet(
        &mint.url(),
        &def_db,
        seed,
        HashMap::new(),
        /* config_authoritative */ false,
        /* token_authoritative */ false,
        /* token_empty */ false,
        /* config_floor_dropped */ false,
    )
    .await
    .expect("open a deferred (below-quorum, fresh-box) wallet");
    assert!(!def_cdb.is_established(), "precondition: below-quorum fresh-box open DEFERS the counter");

    let deferred = mint_into_wallet_operator_pays(
        &def_wallet,
        &def_cdb,
        AMOUNT,
        "t4-deferred",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| panic!("a deferred counter must bail BEFORE quoting a bolt11 — it should not mint"),
    )
    .await;
    assert!(
        deferred.is_err(),
        "★ a DEFERRED counter must bail LOUDLY, never silently report a successful fund on 0 proofs"
    );
    let msg = format!("{:#}", deferred.unwrap_err());
    assert!(
        msg.contains("DEFERRED") || msg.contains("deferred"),
        "the bail names the deferred-counter cause: {msg}"
    );

    // And the deferred wallet gained nothing (no silent partial fund).
    let def_balance: u64 = def_wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(def_balance, 0, "the deferred wallet minted nothing");

    mint.shutdown().await;
}

/// Wait (bounded) until the wallet holds at least one PAID-but-unissued mint quote — i.e. the
/// fakewallet has auto-marked a stranded quote paid (the "operator pays AFTER the timeout" event).
/// Polls `check_mint_quote_status` exactly as an operator's re-run would; returns once one is Paid.
async fn wait_until_a_stranded_quote_is_paid(wallet: &cdk::Wallet, timeout: Duration) {
    use cdk::nuts::MintQuoteState;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let pending = wallet
            .get_unissued_mint_quotes()
            .await
            .expect("list unissued mint quotes");
        for q in &pending {
            if let Ok(s) = wallet.check_mint_quote_status(&q.id).await {
                if s.state == MintQuoteState::Paid {
                    return;
                }
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the fakewallet did not mark the stranded quote PAID within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// --------------------------------------------------------------------------------------------
// TOOTH 5 (FIX 2) — ★DRAIN-FIRST (the money-critical timeout double-pay guard): the operator pays
// the printed bolt11 AFTER the tool timed out. A re-run must DRAIN the already-paid quote (mint the
// existing proofs) and issue NO new invoice — never a second payment / stranded funds.
//
// This proves `mint_unissued_quotes` is safe-to-call-blindly: it re-checks each unissued quote with
// the mint and mints ONLY when `amount_mintable() > 0`, so the paid quote is drained (minted) and an
// already-issued quote would be a no-op.
//
// RED-on-revert: remove the drain-first step in `mint_into_wallet_operator_pays` → run 2 goes
// straight to the fresh path → it quotes + prints a NEW invoice (invoice count → 2) and mints a
// SECOND quote (double payment) → the `invoices == 1` assertion goes false → RED.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn pay_after_timeout_drains_the_paid_quote_and_issues_no_new_invoice() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const AMOUNT: u64 = 2_048;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t5");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // A shared invoice counter across BOTH runs: each printed bolt11 == one issued invoice.
    let invoices = Arc::new(AtomicUsize::new(0));

    // RUN 1: a tiny timeout so it gives up BEFORE the fakewallet auto-pays (~1-3s). It quotes +
    // PRINTS one bolt11 (count → 1), then times out, leaving a persisted unissued quote behind.
    let inv1 = invoices.clone();
    let run1 = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t5-run1",
        Duration::from_millis(10),
        Duration::from_millis(1), // time out ~immediately (before any auto-pay)
        move |_bolt11| {
            inv1.fetch_add(1, Ordering::SeqCst);
        },
    )
    .await;
    assert!(run1.is_err(), "run 1 times out (the operator has not paid yet)");
    assert_eq!(invoices.load(Ordering::SeqCst), 1, "run 1 printed exactly one invoice");

    // The operator pays that invoice AFTER the timeout: the fakewallet auto-marks the quote PAID.
    wait_until_a_stranded_quote_is_paid(&wallet, Duration::from_secs(20)).await;

    // RUN 2: a re-run with the SAME amount. DRAIN-FIRST mints the already-paid quote and issues NO
    // new invoice — the closure must NOT fire again (count stays 1).
    let inv2 = invoices.clone();
    let outcome = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t5-run2",
        Duration::from_millis(50),
        Duration::from_secs(25),
        move |_bolt11| {
            inv2.fetch_add(1, Ordering::SeqCst);
        },
    )
    .await
    .expect("★ run 2 DRAINS the stranded paid quote (no new invoice)");

    assert_eq!(
        invoices.load(Ordering::SeqCst),
        1,
        "★ DRAIN-FIRST: run 2 issued NO new invoice (still 1 total) — revert the drain → run 2 \
         quotes a fresh invoice (count 2) + double-mints → RED"
    );
    assert_eq!(
        outcome.minted_sats, AMOUNT,
        "the drained quote minted exactly the requested amount"
    );
    let balance: u64 = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(
        balance, AMOUNT,
        "the wallet holds exactly the drained amount — no double-mint (a second minted quote would show 2x)"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 6 (FIX 3) — ★minted==requested (silent under-funding guard), driven against the fakewallet:
// a prior run left a PAID-but-unissued quote for 1000 sats; a re-run that asks for MORE (2000) drains
// only the 1000 actually paid. The handler must BAIL (minted 1000 != requested 2000) rather than
// silently report a 2000-sat fund when only 1000 landed.
//
// RED-on-revert: drop the `ensure_minted_matches_requested` assert (make it always Ok) → run 2
// returns Ok reporting a mismatched/under-fund → the `is_err()` assertion goes false → RED.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn drained_amount_below_requested_bails_never_silent_under_fund() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const PAID: u64 = 1_000; // what the prior run quoted + the operator paid
    const REQUESTED_AGAIN: u64 = 2_000; // the re-run asks for MORE than the stranded quote

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t6");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // Run 1: quote PAID sats, time out (leave a paid-but-unissued quote for the operator to pay).
    let run1 = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        PAID,
        "t6-run1",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| {},
    )
    .await;
    assert!(run1.is_err(), "run 1 times out");
    wait_until_a_stranded_quote_is_paid(&wallet, Duration::from_secs(20)).await;

    // Run 2: ask for MORE than the stranded quote. Drain mints the paid 1000, which != the requested
    // 2000 → BAIL. It must NOT issue a fresh invoice (the drain path ran, then bailed on the mismatch).
    let invoices = Arc::new(AtomicUsize::new(0));
    let inv = invoices.clone();
    let res = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        REQUESTED_AGAIN,
        "t6-run2",
        Duration::from_millis(50),
        Duration::from_secs(25),
        move |_| {
            inv.fetch_add(1, Ordering::SeqCst);
        },
    )
    .await;
    assert!(
        res.is_err(),
        "★ FIX 3: a drained amount ({PAID}) below the requested ({REQUESTED_AGAIN}) MUST bail — \
         revert the minted==requested assert → silent under-fund success → RED"
    );
    let msg = format!("{:#}", res.unwrap_err());
    assert!(
        msg.contains("under-funded") || msg.contains("requested"),
        "the bail names the amount mismatch: {msg}"
    );
    assert_eq!(
        invoices.load(Ordering::SeqCst),
        0,
        "no fresh invoice was issued on the drain path (the mismatch bailed after draining)"
    );

    mint.shutdown().await;
}

/// Wait (bounded) until AT LEAST `n` of the wallet's unissued mint quotes are PAID at the mint (the
/// fakewallet auto-pays each ~1-3s after quoting). Polls exactly as an operator re-run's drain would.
async fn wait_until_n_quotes_paid(wallet: &cdk::Wallet, n: usize, timeout: Duration) {
    use cdk::nuts::MintQuoteState;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let pending = wallet
            .get_unissued_mint_quotes()
            .await
            .expect("list unissued mint quotes");
        let mut paid = 0usize;
        for q in &pending {
            if let Ok(s) = wallet.check_mint_quote_status(&q.id).await {
                if s.state == MintQuoteState::Paid {
                    paid += 1;
                }
            }
        }
        if paid >= n {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {paid}/{n} unissued quotes became PAID within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// --------------------------------------------------------------------------------------------
// TOOTH 7 (rev-2, ★PHANTOM-CREDIT — the crux): a quote the mint reports ISSUED while it is STILL
// unissued locally (no proofs landed = a lost mint-response / recovery failure) must make the drain
// BAIL LOUDLY. The mint's claimed `amount_issued` is NOT a fund — the wallet holds nothing — so the
// tool must never report a success (phantom credit) nor issue a fresh invoice. Mirrors the rail's
// issued-but-proofs-not-held fail-clean (1a Tooth ii): credit ONLY proofs actually held.
//
// Construction (faithful lost-response): fund a quote normally (proofs land, quote ISSUED at the
// mint), then reset its LOCAL record to unissued (amount_issued = 0) and REMOVE the local proofs —
// exactly the state a lost mint-response leaves: mint says ISSUED, wallet holds nothing, quote back
// in the unissued list. A re-run's drain must detect this and bail.
//
// RED-on-revert: change the drain's ISSUED arm from a bail to counting the mint's `amount_issued`
// as "drained" (the old blind `mint_unissued_quotes` aggregate) → it returns Ok reporting a funded
// AMOUNT while the wallet balance is 0 (phantom credit) → the `is_err()` assertion below goes false
// → RED. This proves credit == proofs-actually-held, NEVER amount_issued.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn issued_at_mint_without_local_proofs_bails_never_phantom_credit() {
    use cdk::cdk_database::WalletDatabase as _;
    use cdk::nuts::MintQuoteState;
    const AMOUNT: u64 = 4_096;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t7");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // 1) Fund a quote normally — proofs land locally, the quote is ISSUED at the mint.
    let funded = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t7-fund",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| {},
    )
    .await
    .expect("the fresh fund mints proofs");
    assert_eq!(funded.minted_sats, AMOUNT, "the initial fund minted the requested amount");
    let pre_balance: u64 = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(pre_balance, AMOUNT, "the wallet holds the funded proofs before the reset");

    // 2) Simulate the lost mint-response: reset the LOCAL quote to unissued (amount_issued = 0) so it
    //    re-enters the unissued list, and REMOVE the local proofs so the wallet holds nothing. The
    //    mint still remembers the quote as ISSUED.
    let mut q = counter_db
        .get_mint_quote(&funded.quote_id)
        .await
        .expect("read the funded quote")
        .expect("the funded quote is stored");
    q.amount_issued = cdk::Amount::ZERO;
    q.state = MintQuoteState::Paid; // back in the unissued list; the mint re-check will flip it Issued
    q.used_by_operation = None; // no saga-resume path — a genuinely lost response
    counter_db.add_mint_quote(q).await.expect("re-insert the quote as unissued");

    let held = counter_db
        .get_proofs(None, None, None, None)
        .await
        .expect("read local proofs");
    let ys: Vec<_> = held.iter().map(|p| p.y).collect();
    counter_db
        .update_proofs(vec![], ys)
        .await
        .expect("remove the local proofs (lost-response: nothing landed)");
    let after_reset: u64 = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(after_reset, 0, "precondition: the wallet holds NO proofs (lost mint-response)");

    // 3) A re-run's drain must BAIL — the mint says ISSUED but we hold nothing; never phantom-credit,
    //    never a fresh invoice (the closure must not fire).
    let res = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t7-rerun",
        Duration::from_millis(50),
        Duration::from_secs(25),
        |_| panic!("phantom-credit: an ISSUED-without-local-proofs quote must bail BEFORE quoting a new invoice"),
    )
    .await;
    assert!(
        res.is_err(),
        "★ PHANTOM-CREDIT: an ISSUED-at-mint quote with NO local proofs must BAIL — revert the ISSUED \
         arm to count amount_issued → Ok on 0 held proofs (phantom fund) → RED"
    );
    let msg = format!("{:#}", res.unwrap_err());
    assert!(
        msg.contains("PHANTOM") || msg.contains("ISSUED") || msg.contains("lost mint-response"),
        "the bail names the phantom-credit / lost-response cause: {msg}"
    );
    let final_balance: u64 = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert_eq!(final_balance, 0, "the wallet still holds NOTHING — no phantom fund was credited");

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 8 (rev-2, ★MISATTRIBUTION): more than one paid-but-unissued quote is pending. The drain
// cannot unambiguously attribute a fund to ONE quote id, and a blind aggregate could satisfy
// `== requested` across UNRELATED quotes. The tool must BAIL rather than guess (find-by-amount /
// first()) and cross-quote-aggregate.
//
// Construction: create TWO unrelated 1000-sat quotes, wait until BOTH are paid, then re-run asking
// for 2000 (== the sum of the two unrelated quotes). The blind aggregate would drain both = 2000 and
// (mis)report success attributing to a guessed quote id.
//
// RED-on-revert: replace the `paid_pending.len() > 1` bail + explicit single-quote drain with the old
// blind `mint_unissued_quotes()` aggregate + find-by-amount/first() guess → run 2 drains BOTH quotes
// (2000 == requested) and returns Ok on a guessed/cross-quote attribution → the `is_err()` below goes
// false → RED.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn multiple_paid_unissued_quotes_refuse_cross_quote_aggregate() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use cdk::nuts::PaymentMethod;
    const EACH: u64 = 1_000;
    const REQUESTED: u64 = 2_000; // == the SUM of the two unrelated quotes (the aggregate trap)

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t8");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // Two UNRELATED paid-but-unissued quotes (quote them directly; the fakewallet auto-pays each).
    let _q1 = wallet
        .mint_quote(PaymentMethod::BOLT11, Some(cdk::Amount::from(EACH)), Some("t8-q1".to_string()), None)
        .await
        .expect("quote 1");
    let _q2 = wallet
        .mint_quote(PaymentMethod::BOLT11, Some(cdk::Amount::from(EACH)), Some("t8-q2".to_string()), None)
        .await
        .expect("quote 2");
    wait_until_n_quotes_paid(&wallet, 2, Duration::from_secs(20)).await;

    // A re-run for 2000 (the SUM). With two paid-unissued quotes pending, the drain must refuse to
    // attribute — never a blind cross-quote aggregate, never a fresh invoice.
    let invoices = Arc::new(AtomicUsize::new(0));
    let inv = invoices.clone();
    let res = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        REQUESTED,
        "t8-rerun",
        Duration::from_millis(50),
        Duration::from_secs(25),
        move |_| {
            inv.fetch_add(1, Ordering::SeqCst);
        },
    )
    .await;
    assert!(
        res.is_err(),
        "★ MISATTRIBUTION: two paid-but-unissued quotes must make the drain BAIL — revert to the blind \
         aggregate + guess → it drains both (2000 == requested) and reports a guessed attribution → RED"
    );
    let msg = format!("{:#}", res.unwrap_err());
    assert!(
        msg.contains("attribute") || msg.contains("paid-but-unissued") || msg.contains("unambiguously"),
        "the bail names the ambiguous-attribution cause: {msg}"
    );
    // No fresh invoice was issued (the ambiguity bailed before quoting anew).
    assert_eq!(
        invoices.load(Ordering::SeqCst),
        0,
        "the ambiguity refusal issued NO new invoice"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 9 (rev-3, ★#1 ISSUED-WITH-LOCAL-PROOFS → SUCCEEDS — the crux): a quote the mint reports
// ISSUED while the wallet HOLDS unspent proofs for it (the state a completed-during-re-check saga
// leaves: `check_mint_quote_status` completes a crashed issue saga, LANDS proofs, THEN returns
// Issued) must make the drain SUCCEED — report the HELD sum as the fund and resume the EXACT quote,
// NEVER bail on `state == Issued`. This is the invariant: FUNDED iff proofs are HELD; `Issued` alone
// never decides funded-vs-not.
//
// Construction (mirrors the phantom-credit tooth 7, but KEEPS the proofs): fund a quote normally
// (proofs land locally, quote ISSUED at the mint, an Incoming Transaction{quote_id, ys} recorded),
// then reset ONLY the LOCAL quote record to unissued (amount_issued = 0) so it re-enters the
// get_unissued list — but do NOT remove the proofs. A re-run's drain re-checks it (mint says Issued),
// sums the HELD unspent proofs (> 0), and SUCCEEDS reporting the held amount, issuing NO new invoice.
//
// RED-on-revert: revert the ISSUED arm to the old unconditional `bail!` (decide on state, not held
// proofs) → the re-run false-bails on a genuinely-funded quote → the `.expect(..)` panics → RED.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn issued_at_mint_with_local_proofs_succeeds_never_false_bail() {
    use cdk::cdk_database::WalletDatabase as _;
    use cdk::nuts::MintQuoteState;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const AMOUNT: u64 = 4_096;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t9");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // 1) Fund a quote normally — proofs land locally, the quote is ISSUED at the mint, an Incoming
    //    Transaction{quote_id, ys} is recorded.
    let funded = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t9-fund",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| {},
    )
    .await
    .expect("the fresh fund mints proofs");
    assert_eq!(funded.minted_sats, AMOUNT, "the initial fund minted the requested amount");
    assert_eq!(
        wallet.total_balance().await.map(u64::from).unwrap_or(0),
        AMOUNT,
        "the wallet holds the funded proofs before the reset"
    );

    // 2) Re-enter the quote into the unissued list WITHOUT removing its proofs: the state a
    //    completed-during-re-check saga leaves (mint ISSUED, proofs HELD locally, quote back in the
    //    unissued scan). Reset ONLY amount_issued (→ 0, so get_unissued includes it); KEEP the proofs.
    let mut q = counter_db
        .get_mint_quote(&funded.quote_id)
        .await
        .expect("read the funded quote")
        .expect("the funded quote is stored");
    q.amount_issued = cdk::Amount::ZERO;
    q.state = MintQuoteState::Paid; // back in the unissued list; the mint re-check will flip it Issued
    counter_db.add_mint_quote(q).await.expect("re-insert the quote as unissued (proofs kept)");
    assert_eq!(
        wallet.total_balance().await.map(u64::from).unwrap_or(0),
        AMOUNT,
        "precondition: the wallet STILL HOLDS the proofs (only the local quote record was reset)"
    );

    // 3) A re-run's drain must SUCCEED on the HELD proofs — resume the EXACT quote, report the held
    //    sum, issue NO new invoice (the closure must NOT fire).
    let invoices = Arc::new(AtomicUsize::new(0));
    let inv = invoices.clone();
    let resumed = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t9-rerun",
        Duration::from_millis(50),
        Duration::from_secs(25),
        move |_| {
            inv.fetch_add(1, Ordering::SeqCst);
        },
    )
    .await
    .expect(
        "★ #1: an ISSUED-at-mint quote that HOLDS unspent proofs must SUCCEED (report the held sum) \
         — revert the ISSUED arm to bail-on-state → false-bail on a funded quote → RED",
    );
    assert_eq!(
        resumed.minted_sats, AMOUNT,
        "the resumed fund reports the HELD proofs (not amount_issued / not the mint's claim)"
    );
    assert_eq!(
        resumed.quote_id, funded.quote_id,
        "it resumed the EXACT stranded quote id (no fresh quote)"
    );
    assert_eq!(
        invoices.load(Ordering::SeqCst),
        0,
        "★ NO new invoice was issued — the held-proofs resume path ran, not the fresh-quote path"
    );
    assert_eq!(
        wallet.total_balance().await.map(u64::from).unwrap_or(0),
        AMOUNT,
        "no double-mint: the wallet still holds exactly the original proofs"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 10 (rev-3, ★#2 SAGA RECOVERY runs at drain START, before the get_unissued scan): the drain
// MUST call `recover_incomplete_sagas()` before scanning, so a crash-gap quote (CDK's `mint()` writes
// `amount_issued` BEFORE proofs → a crash leaves an issued-but-proofless quote INVISIBLE to
// get_unissued, since it filters `amount_issued = 0`) has its in-flight issue saga completed and its
// proofs LANDED first — closing the double-pay hole.
//
// ★INFEASIBILITY NOTE (why this is an execution+ordering proof, not a full e2e crash-gap tooth): the
// full e2e (partial mint → crash mid-saga → recover lands proofs → no fresh invoice) requires a REAL
// incomplete Issue saga carrying mint-SIGNED blinded messages. The fakewallet mint completes `mint()`
// atomically and CDK 0.17.1 exposes no public seam to inject a half-signed issue saga (a fabricated
// `IssueSagaState::SecretsPrepared` saga with `blinded_messages: None` is COMPENSATED — rolled back —
// not recovered-with-proofs; see cdk recovery.rs::test_recover_issue_secrets_prepared). So we prove
// the load-bearing fact deterministically via recovery's OTHER observable effect:
// `recover_incomplete_sagas()` first runs `cleanup_orphaned_quote_reservations()`, which RELEASES a
// mint quote reserved by an operation whose saga does not exist (sets `used_by_operation = None`).
// We seed exactly that orphaned reservation, then assert the drain RELEASED it — proving the recovery
// call executes as part of the drain. Ordering (BEFORE the scan) is guaranteed by source placement:
// the `recover_incomplete_sagas()` call is the first fallible step after the establishment guard and
// precedes `get_unissued_mint_quotes()` with no branch between (see mint_rig.rs).
//
// RED-on-revert: remove the `recover_incomplete_sagas()` call from the drain → the orphaned
// reservation is NOT released → the `used_by_operation.is_none()` assertion goes false → RED.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn recover_incomplete_sagas_runs_at_drain_start() {
    use cdk::cdk_database::WalletDatabase as _;
    use cdk::nuts::PaymentMethod;
    const AMOUNT: u64 = 1_500;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t10");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // Seed an ORPHANED mint-quote reservation: a quote reserved by an operation whose saga does not
    // exist (exactly what a crash between reserving a quote and persisting its saga leaves). Recovery's
    // `cleanup_orphaned_quote_reservations()` releases these — the observable proof recovery ran.
    let quote = wallet
        .mint_quote(PaymentMethod::BOLT11, Some(cdk::Amount::from(AMOUNT)), Some("t10-orphan".to_string()), None)
        .await
        .expect("quote a bolt11 mint");
    // A valid UUID string for which no saga exists (an orphaned reservation). A literal avoids a
    // dependency on uuid's `v4` feature; cleanup only `parse_str`s it then looks up a (missing) saga.
    let orphan_op = "d1e2f3a4-b5c6-4d7e-8f90-1a2b3c4d5e6f".to_string();
    let mut stored = counter_db
        .get_mint_quote(&quote.id)
        .await
        .expect("read the quote")
        .expect("the quote is stored");
    stored.used_by_operation = Some(orphan_op.clone());
    counter_db.add_mint_quote(stored).await.expect("mark the quote reserved by an orphaned operation");

    // Precondition: the quote IS reserved by the orphaned operation.
    let before = counter_db
        .get_mint_quote(&quote.id)
        .await
        .expect("read the quote")
        .expect("stored");
    assert_eq!(
        before.used_by_operation.as_deref(),
        Some(orphan_op.as_str()),
        "precondition: the quote is reserved by an orphaned operation (no saga)"
    );

    // Run the drain. Its FIRST fallible step is `recover_incomplete_sagas()`, which releases the
    // orphaned reservation. (The fakewallet auto-pays the quote ~1-3s, but this run uses a tiny
    // timeout: whatever the drain does after recovery, recovery already RAN.)
    let _ = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t10-run",
        Duration::from_millis(10),
        Duration::from_millis(1), // time out fast; we only care that recovery ran first
        |_| {},
    )
    .await;

    // ★ Recovery ran as part of the drain: the orphaned reservation was released.
    let after = counter_db
        .get_mint_quote(&quote.id)
        .await
        .expect("read the quote")
        .expect("stored");
    assert!(
        after.used_by_operation.is_none(),
        "★ #2: recover_incomplete_sagas() ran at drain start and RELEASED the orphaned reservation \
         — remove the recover call → the reservation stays Some(..) → RED. (was: {:?})",
        after.used_by_operation
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 11 (rev-4, ★FIX #1 — the ALL-QUOTES proofless-issued scan, the definitive recovery-half
// close): a quote the mint ISSUED against (amount_issued > 0) while the wallet HOLDS NO unspent
// proofs for it (a crash-gap / compensated / failed-recovery / lost mint-response) is INVISIBLE to
// `get_unissued_mint_quotes()` (which excludes amount_issued != 0), so the get_unissued drain scan
// never sees it — a fresh invoice would DOUBLE-PAY the already-paid quote. The all-quotes scan
// (`wallet.localstore.get_mint_quotes()`) enumerates EVERY quote and BAILS on any that is
// issued-against yet holds zero proofs, deciding purely on HELD proofs (report-independent).
//
// Construction (a faithful proofless-issued quote INVISIBLE to get_unissued — the key difference
// from the phantom-credit tooth 7, which resets amount_issued=0 to make the quote VISIBLE to
// get_unissued): fund a quote normally (proofs land, amount_issued = AMOUNT, quote ISSUED at the
// mint → EXCLUDED from get_unissued), then REMOVE the local proofs AND the Incoming tx naming the
// quote but KEEP amount_issued > 0 — the TRUE lost-response (`held == 0 && !found_transaction`: a
// crash-gap quote whose proofs NEVER landed also has no tx). The quote is now stranded-paid +
// proofless AND hidden from the get_unissued drain scan; only the all-quotes scan catches it.
// (A SPENT quote — tx REMAINS, proofs spent — is NOT stranded and PROCEEDS; that is tooth 12.)
//
// RED-on-revert: remove the all-quotes proofless-issued scan from `mint_into_wallet_operator_pays`
// → the invisible quote is not caught → the drain falls through to the fresh-quote path → it quotes
// + prints a NEW invoice (the `panic!` closure fires = double-pay) → RED.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn all_quotes_scan_bails_on_a_proofless_issued_quote_invisible_to_get_unissued() {
    use cdk::cdk_database::WalletDatabase as _;
    const AMOUNT: u64 = 3_333;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t11");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // 1) Fund a quote normally — proofs land locally, amount_issued = AMOUNT, quote ISSUED at the mint
    //    (so it is EXCLUDED from get_unissued).
    let funded = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t11-fund",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| {},
    )
    .await
    .expect("the fresh fund mints proofs");
    assert_eq!(funded.minted_sats, AMOUNT, "the initial fund minted the requested amount");

    // Precondition (the crux): the quote has amount_issued > 0 (so get_unissued excludes it) — it is
    // INVISIBLE to the drain scan below.
    let stored = counter_db
        .get_mint_quote(&funded.quote_id)
        .await
        .expect("read the funded quote")
        .expect("the funded quote is stored");
    assert!(
        u64::from(stored.amount_issued) > 0,
        "precondition: the funded quote is ISSUED against (amount_issued > 0)"
    );
    let unissued = wallet.get_unissued_mint_quotes().await.expect("list unissued");
    assert!(
        !unissued.iter().any(|q| q.id == funded.quote_id),
        "precondition: the issued-against quote is INVISIBLE to get_unissued (the drain scan cannot see it)"
    );

    // 2) Remove the local proofs AND the Incoming transaction that names the quote, but KEEP
    //    amount_issued > 0: the TRUE stranded PAID-but-proofless quote hidden from get_unissued
    //    (crash-gap / compensated / lost mint-response). This is FAITHFUL to a real crash-gap: CDK's
    //    issue saga writes the Incoming Transaction ONLY after proofs persist, so a quote whose proofs
    //    NEVER landed also has NO transaction — `held == 0 && !found_transaction`. (Contrast tooth 12,
    //    the SPENT case, where the tx REMAINS and the scan must PROCEED.)
    use cdk::wallet::types::TransactionDirection;
    let held = counter_db
        .get_proofs(None, None, None, None)
        .await
        .expect("read local proofs");
    let ys: Vec<_> = held.iter().map(|p| p.y).collect();
    counter_db
        .update_proofs(vec![], ys)
        .await
        .expect("remove the local proofs (stranded proofless-issued quote)");
    // Remove the Incoming tx(s) naming this quote so there is NO durable record proofs ever landed
    // (found_transaction == false = the true lost-response). Without this the quote would look SPENT.
    let txs = counter_db
        .list_transactions(Some(wallet.mint_url.clone()), Some(TransactionDirection::Incoming), Some(wallet.unit.clone()))
        .await
        .expect("list incoming transactions");
    for t in txs.iter().filter(|t| t.quote_id.as_deref() == Some(funded.quote_id.as_str())) {
        counter_db
            .remove_transaction(t.id())
            .await
            .expect("remove the Incoming tx (proofs never landed = true stranded)");
    }
    assert_eq!(
        wallet.total_balance().await.map(u64::from).unwrap_or(0),
        0,
        "precondition: the wallet holds NO proofs, yet the quote stays amount_issued > 0 (invisible to get_unissued)"
    );

    // 3) A re-run must BAIL via the ALL-QUOTES scan, issuing NO fresh invoice (the panic closure must
    //    NOT fire — a fresh invoice would double-pay the already-paid quote).
    let res = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t11-rerun",
        Duration::from_millis(50),
        Duration::from_secs(25),
        |_| panic!(
            "double-pay: a proofless-issued quote invisible to get_unissued must BAIL via the \
             all-quotes scan BEFORE quoting a fresh invoice"
        ),
    )
    .await;
    assert!(
        res.is_err(),
        "★ FIX #1: a proofless-issued quote INVISIBLE to get_unissued must make the drain BAIL — \
         remove the all-quotes scan → it falls through to a fresh invoice (double-pay) → RED"
    );
    let msg = format!("{:#}", res.unwrap_err());
    assert!(
        msg.contains("proofless") || msg.contains("double-pay") || msg.contains("stranded"),
        "the bail names the proofless-issued / double-pay cause: {msg}"
    );
    assert_eq!(
        wallet.total_balance().await.map(u64::from).unwrap_or(0),
        0,
        "the wallet still holds NOTHING — no fresh invoice, no double-pay"
    );

    mint.shutdown().await;
}

// --------------------------------------------------------------------------------------------
// TOOTH 12 (rev-4.1, ★FIX #1(b) DISCRIMINATOR — the spent-vs-stranded split in the ALL-QUOTES
// scan): a quote the mint ISSUED against (amount_issued > 0) whose proofs LANDED and were then
// SPENT holds ZERO unspent proofs (held == 0) — the SAME held signal as the stranded case (tooth
// 11) — but it is NOT stranded: an Incoming Transaction still records that its proofs once landed
// (`found_transaction == true`). The per-request wallet is SPENT BY DESIGN, so a fully-spent quote
// MUST NOT brick a repeat fund. The all-quotes scan bails ONLY on the TRUE lost-response
// (`held == 0 && !found_transaction`); a spent quote (tx exists) PROCEEDS to a fresh fund.
//
// Construction (the SPENT state, contrast tooth 11's no-tx stranded state): fund a quote normally
// (proofs land, the Incoming tx persists, amount_issued = AMOUNT), then mark its proofs SPENT
// (State::Spent) so held == 0 while the Incoming tx REMAINS (found_transaction == true).
//
// RED-on-revert: revert the discriminator to `held == 0` alone (drop `&& !found_transaction`) → the
// spent quote FALSE-BAILS at the all-quotes scan → the re-run errors instead of funding → RED.
// This proves the fix does not merely fail-safe (never double-pay) but keeps the tool USABLE for
// the by-design repeat-spend wallet.
// --------------------------------------------------------------------------------------------
#[tokio::test]
async fn all_quotes_scan_proceeds_on_a_spent_quote_never_false_bails() {
    use cdk::cdk_database::WalletDatabase as _;
    use cdk::nuts::State;
    use cdk::wallet::types::TransactionDirection;
    const AMOUNT: u64 = 4_444;

    let port = common::free_port().await;
    let mint = FakeMint::start(port).await.expect("boot local fakewallet mint");
    let work = TempDir::new("kirby-fund-wallet-t12");
    let db_path = work.path().join("wallet.sqlite");
    let (wallet, counter_db) = open_boot_way(&mint.url(), &db_path).await;

    // 1) Fund a quote normally — proofs land locally, the Incoming tx persists, amount_issued = AMOUNT,
    //    quote ISSUED at the mint (EXCLUDED from get_unissued).
    let funded = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t12-fund",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| {},
    )
    .await
    .expect("the fresh fund mints proofs");
    assert_eq!(funded.minted_sats, AMOUNT, "the initial fund minted the requested amount");

    // 2) SPEND the proofs (mark them State::Spent) — held drops to 0, but the Incoming tx REMAINS.
    let held = counter_db
        .get_proofs(None, None, None, None)
        .await
        .expect("read local proofs");
    let ys: Vec<_> = held.iter().map(|p| p.y).collect();
    counter_db
        .update_proofs_state(ys, State::Spent)
        .await
        .expect("mark the proofs SPENT (held drops to 0, the Incoming tx remains)");
    assert_eq!(
        wallet.total_balance().await.map(u64::from).unwrap_or(0),
        0,
        "precondition: the wallet holds NO unspent proofs (the quote was fully SPENT)"
    );
    // Precondition (the discriminator crux): the Incoming tx naming the spent quote STILL EXISTS
    // (found_transaction == true), and the quote stays amount_issued > 0 (invisible to get_unissued).
    let txs = counter_db
        .list_transactions(Some(wallet.mint_url.clone()), Some(TransactionDirection::Incoming), Some(wallet.unit.clone()))
        .await
        .expect("list incoming transactions");
    assert!(
        txs.iter().any(|t| t.quote_id.as_deref() == Some(funded.quote_id.as_str())),
        "precondition: an Incoming tx still records the SPENT quote (found_transaction == true) — the \
         discriminator that separates a spent quote from a true stranded one"
    );
    let stored = counter_db
        .get_mint_quote(&funded.quote_id)
        .await
        .expect("read the spent quote")
        .expect("the spent quote is stored");
    assert!(
        u64::from(stored.amount_issued) > 0,
        "precondition: the spent quote stays ISSUED against (amount_issued > 0, invisible to get_unissued)"
    );

    // 3) A re-run must PROCEED past the all-quotes scan (the spent quote is NOT stranded), reach the
    //    fresh-quote path, and successfully mint a NEW fund. (on_bolt11 does NOT panic here — a fresh
    //    invoice is LEGITIMATE: the prior quote was genuinely spent, not stranded.)
    let refund = mint_into_wallet_operator_pays(
        &wallet,
        &counter_db,
        AMOUNT,
        "t12-rerun",
        Duration::from_millis(150),
        Duration::from_secs(25),
        |_| {},
    )
    .await
    .expect(
        "★ FIX #1(b) discriminator: a SPENT quote (held==0 but an Incoming tx exists) must NOT \
         false-bail the all-quotes scan — revert the discriminator to `held == 0` alone → the spent \
         quote false-bails → the re-run errors → RED",
    );
    assert_eq!(
        refund.minted_sats, AMOUNT,
        "the re-run funds afresh (proceeds past the spent quote), minting the requested amount"
    );
    assert_ne!(
        refund.quote_id, funded.quote_id,
        "the re-run minted a FRESH quote (it proceeded past the spent one, did not resume it)"
    );

    mint.shutdown().await;
}
