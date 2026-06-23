//! Layer B (brain-routstr §8): the ecash round-trip against a REAL local fakewallet mint
//! (no real money, no real Routstr). Exercises the cdk plumbing `RoutstrBrain<CdkEcash>`
//! drives — `prepare_send`/`confirm` (mint the X-Cashu token), `receive` (redeem the real
//! change), `revoke_send` (reclaim our own un-consumed send, R2-1), `recover_incomplete_sagas`
//! (R2-4) — plus the money invariants: the wallet balance DELTA equals the metered debit
//! within a bounded fee (R2-3, `>=`-model not strict equality), the per-think net spend
//! never exceeds the cap, the persistent wallet survives a reopen-after-drop (HIGH-4), and
//! the boot reconcile REFUSES TO BOOT on `wallet < counter` (R2-5). The mock Routstr node
//! ([`common::MockNode`]) returns a real change token pre-minted from the same fake mint.

mod common;

use std::time::Duration;

use cdk::amount::Amount;
use cdk::wallet::{ReceiveOptions, SendOptions};
use common::mint_fixture::{FakeMint, TempDir};
use common::{free_port, MockNode};
use kirby_node::boot::assert_wallet_backs_counter;
use kirby_node::mint_rig::{build_wallet, fund_wallet, open_persistent_wallet};
use kirby_node::rail::{BrainBackend, CdkEcash, EcashProvider, RoutstrBrain};
use kirby_proto::ChatMessage;

/// A bounded fee allowance: the 0-fee fake mint (input_fee_ppk = 0) should make the
/// wallet delta equal the debit exactly, but we assert against a small bound (R2-3: the
/// invariant is `>=`, never strict equality, because real mint/swap fees exist).
const FEE_BOUND: u64 = 4;

async fn balance(wallet: &std::sync::Arc<cdk::Wallet>) -> u64 {
    wallet.total_balance().await.map(u64::from).unwrap_or(0)
}

#[tokio::test]
async fn token_round_trip_debits_actual_and_wallet_delta_matches() {
    let port = free_port().await;
    let mint = FakeMint::start(port).await.expect("start fake mint");
    let mint_url = mint.url();

    // The brain wallet, funded.
    let w = build_wallet(&mint_url).await.expect("build brain wallet");
    fund_wallet(w.clone(), 1000).await.expect("fund brain wallet");

    // A SECOND wallet mints the change token: it is a FOREIGN token to W (same mint), so
    // W.receive(change) is the real foreign-redeem path (R2-1: change is `receive`, not revoke).
    let w2 = build_wallet(&mint_url).await.expect("build change wallet");
    fund_wallet(w2.clone(), 1000).await.expect("fund change wallet");
    let change_amount = 50u64;
    let prepared = w2
        .prepare_send(Amount::from(change_amount), SendOptions::default())
        .await
        .expect("prepare change token");
    let change_token = prepared.confirm(None).await.expect("confirm change").to_string();

    let node = MockNode::replying("real-mint round trip", Some(&change_token)).await;

    let cap = 64u64;
    let w_before = balance(&w).await;
    let brain = RoutstrBrain::new(
        node.url(),
        CdkEcash::new(w.clone()),
        Duration::from_secs(20),
        Duration::from_secs(10),
    )
    .expect("build brain");
    let msgs = vec![ChatMessage {
        role: "user".into(),
        content: "what is my next move?".into(),
    }];
    let (reply, cost) = brain
        .complete("anthropic/claude-sonnet-4.6", &msgs, cap)
        .await
        .expect("complete against the fake mint");

    assert_eq!(String::from_utf8(reply).unwrap(), "real-mint round trip");
    assert_eq!(cost, cap - change_amount, "actual_cost = cap - change redeemed");

    // The money invariant (R2-3): assert against the REAL wallet balance delta, not the
    // face-value math, within a bounded fee. `>=` direction is the safety (counter debit
    // must not exceed the real spend by more than the reserve).
    let w_after = balance(&w).await;
    let wallet_delta = w_before - w_after;
    assert!(
        wallet_delta >= cost.saturating_sub(FEE_BOUND) && wallet_delta <= cost + FEE_BOUND,
        "wallet delta {wallet_delta} should match debit {cost} within fee {FEE_BOUND}"
    );
    // Overspend guard: a think's net spend never exceeds the cap + bounded fee (overspend
    // of the ceiling would be a HIGH bug).
    assert!(
        wallet_delta <= cap + FEE_BOUND,
        "wallet net spend {wallet_delta} exceeded cap {cap} + fee {FEE_BOUND}"
    );

    mint.shutdown().await;
}

#[tokio::test]
async fn revoke_send_round_trip_restores_balance() {
    // mint -> revoke (the post-mint reclaim path, R2-1) restores the wallet balance.
    let port = free_port().await;
    let mint = FakeMint::start(port).await.expect("start fake mint");
    let w = build_wallet(&mint.url()).await.expect("build wallet");
    fund_wallet(w.clone(), 500).await.expect("fund");
    let ecash = CdkEcash::new(w.clone());

    let before = balance(&w).await;
    let handle = ecash.mint_send_token(64).await.expect("mint token");
    let mid = balance(&w).await;
    assert!(mid < before, "minting reserves the token's proofs (spendable drops)");

    let recovered = ecash
        .revoke_send(&handle.operation_id)
        .await
        .expect("revoke our own un-consumed send");
    let after = balance(&w).await;
    assert!(recovered >= 64 - FEE_BOUND, "revoke reclaims ~the token value, got {recovered}");
    assert!(
        after >= before.saturating_sub(FEE_BOUND) && after <= before,
        "balance restored after revoke: {after} vs before {before}"
    );
    mint.shutdown().await;
}

#[tokio::test]
async fn revoke_of_consumed_token_fails_cleanly_without_corruption() {
    // R2-1: an already-consumed token must revoke with a clean Err (not a panic / not
    // corrupting wallet state), so the recovery can fall through to the refund.
    let port = free_port().await;
    let mint = FakeMint::start(port).await.expect("start fake mint");
    let w = build_wallet(&mint.url()).await.expect("build wallet");
    fund_wallet(w.clone(), 500).await.expect("fund");
    // A second wallet stands in for the node that REDEEMS (consumes) our token.
    let consumer = build_wallet(&mint.url()).await.expect("build consumer wallet");
    let ecash = CdkEcash::new(w.clone());

    let handle = ecash.mint_send_token(64).await.expect("mint token");
    let consumed = consumer
        .receive(&handle.token, ReceiveOptions::default())
        .await
        .expect("the node redeems our token");
    assert_eq!(u64::from(consumed), 64, "the node consumed the full token");

    // Our own revoke now fails cleanly.
    let result = ecash.revoke_send(&handle.operation_id).await;
    assert!(result.is_err(), "revoke of a consumed token must fail cleanly");
    // No corruption: the wallet is still queryable and the consumed value is gone.
    let bal = balance(&w).await;
    assert!(bal <= 500 - 64 + FEE_BOUND, "the consumed token's value left spendable; bal {bal}");
    mint.shutdown().await;
}

#[tokio::test]
async fn persistent_wallet_reopen_after_drop_is_spendable() {
    // HIGH-4: a persistent store + a PERSISTED seed survive a process drop — the balance
    // is still there AND spendable (a fresh seed would desync derivation). Also R2-4:
    // recover_incomplete_sagas runs clean on a healthy wallet.
    let port = free_port().await;
    let mint = FakeMint::start(port).await.expect("start fake mint");
    let mint_url = mint.url();

    let dir = TempDir::new("kirby-routstr-persist");
    let db_path = dir.path().join("brain-wallet.sqlite");

    // First open creates the store + persists a fresh 0600 seed.
    let w = open_persistent_wallet(&mint_url, &db_path)
        .await
        .expect("open persistent wallet");
    fund_wallet(w.clone(), 300).await.expect("fund");
    assert_eq!(balance(&w).await, 300);
    // R2-4 smoke: recovery runs clean on a healthy funded wallet.
    CdkEcash::new(w.clone())
        .recover_incomplete_sagas()
        .await
        .expect("recover_incomplete_sagas runs clean");
    drop(w); // drop the process's handle; proofs + seed persist to disk

    // The seed persisted alongside the store, 0600 (spend authority).
    let seed_path = db_path.with_extension("seed");
    assert!(seed_path.exists(), "the wallet seed persisted");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the seed file is 0600");
    }

    // Reopen with the SAME db_path + the persisted seed: balance survives and is spendable.
    let w2 = open_persistent_wallet(&mint_url, &db_path)
        .await
        .expect("reopen persistent wallet");
    assert_eq!(balance(&w2).await, 300, "balance survived the reopen (store + seed)");
    let handle = CdkEcash::new(w2.clone())
        .mint_send_token(64)
        .await
        .expect("spendable after reopen");
    assert!(
        handle.token.starts_with("cashu"),
        "minted a real cashu token after reopen, got {:?}",
        &handle.token[..handle.token.len().min(8)]
    );
    mint.shutdown().await;
}

#[test]
fn boot_reconcile_refuses_when_wallet_under_counter_and_accepts_with_headroom() {
    // R2-5: a wallet that can't back the counter REFUSES TO BOOT.
    assert!(
        assert_wallet_backs_counter(100, 200).is_err(),
        "wallet < counter must refuse to boot"
    );
    // Exactly backed is fine.
    assert!(assert_wallet_backs_counter(200, 200).is_ok());
    // R2-3: `>=`, never `==` — a fee-reserve excess over the counter is correct, not an error.
    assert!(
        assert_wallet_backs_counter(208, 200).is_ok(),
        "wallet >= counter (with fee headroom) must boot"
    );
}
