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
