//! Layer C (brain-routstr §8): the GATED live smoke test — ONE real completion against a
//! real Routstr node, paid from a real (tiny) funded wallet. It NEVER runs in CI: it is
//! `#[ignore]` AND returns early unless `KIRBY_ROUTSTR_LIVE=1`. Run it manually only once
//! the §11 money prereqs are met (the node + mint pinned by keeper:kirby/gudnuf, a funded
//! persistent wallet, explicit OK-to-spend a few sats):
//!
//!   KIRBY_ROUTSTR_LIVE=1 \
//!   KIRBY_ROUTSTR_NODE=https://api.routstr.com \
//!   KIRBY_ROUTSTR_MINT=<the node's accepted mint url> \
//!   KIRBY_ROUTSTR_WALLET=/path/to/funded/brain-wallet.sqlite \
//!   cargo test -p kirby-node --test routstr_brain_live -- --ignored --nocapture
//!
//! The wallet is funded OUT OF BAND (LN-mint into the store at the chosen mint, §11); this
//! test only opens it, spends one think, and asserts real words came back + sats drained.

use std::time::Duration;

use kirby_node::mint_rig::open_persistent_wallet;
use kirby_node::rail::{BrainBackend, CdkEcash, RoutstrBrain};
use kirby_proto::ChatMessage;

#[tokio::test]
#[ignore = "live: spends real sats against a real Routstr node; gated on KIRBY_ROUTSTR_LIVE + the §11 money prereqs"]
async fn live_one_real_completion_drains_sats() {
    if std::env::var("KIRBY_ROUTSTR_LIVE").as_deref() != Ok("1") {
        eprintln!(
            "SKIP routstr live: set KIRBY_ROUTSTR_LIVE=1 (+ KIRBY_ROUTSTR_NODE / KIRBY_ROUTSTR_MINT / \
             KIRBY_ROUTSTR_WALLET) to run the one real paid completion (§11 money prereqs)"
        );
        return;
    }

    let node = std::env::var("KIRBY_ROUTSTR_NODE")
        .unwrap_or_else(|_| "https://api.routstr.com".to_string());
    let mint =
        std::env::var("KIRBY_ROUTSTR_MINT").expect("KIRBY_ROUTSTR_MINT (the node's accepted mint, §11)");
    let wallet_db = std::env::var("KIRBY_ROUTSTR_WALLET")
        .expect("KIRBY_ROUTSTR_WALLET (a funded persistent wallet store)");
    let model = std::env::var("KIRBY_ROUTSTR_MODEL")
        .unwrap_or_else(|_| "anthropic/claude-sonnet-4.6".to_string());

    let wallet = open_persistent_wallet(&mint, std::path::Path::new(&wallet_db))
        .await
        .expect("open the funded live wallet");
    let before = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert!(before > 0, "the live wallet must be funded; balance {before}");

    let brain = RoutstrBrain::new(
        node,
        CdkEcash::new(wallet.clone()),
        Duration::from_secs(60),
        Duration::from_secs(20),
    )
    .expect("build the live brain");
    let msgs = vec![ChatMessage {
        role: "user".into(),
        content: "Reply with exactly one word: alive".into(),
    }];
    let cap = 64u64;
    let (reply, cost) = brain
        .complete(&model, &msgs, cap)
        .await
        .expect("one real completion against the live node");

    let words = String::from_utf8_lossy(&reply);
    eprintln!("LIVE routstr completion: cost={cost} sat, reply={words:?}");
    assert!(!reply.is_empty(), "real words must come back from the live node");
    assert!(cost > 0 && cost <= cap, "a real think drained 1..=cap sats, got {cost}");
    let after = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert!(after < before, "the wallet really drained: {after} < {before}");
}
