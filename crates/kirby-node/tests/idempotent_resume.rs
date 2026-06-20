//! C-10 test (gate G9): idempotent capability across resume (spec 4.2). A brokered
//! RequestCapability dedupes across a snapshot+resume, so a key K re-issued after the
//! VM moves to another node is DEDUPED, not performed twice or double-charged. This
//! closes the replay / double-burn money-path of spec 4.2 across a move.
//!
//! This file has TWO layers (the C-9 pattern):
//!  - `g9_dedupe_survives_persisted_store_reopen`: the IN-BAND proof on a REAL
//!    persisted (on-disk) treasury store, WITHOUT the genome image (fast, always
//!    runs). It issues K through a node-1 gateway over a SHARED MockRail (PERFORMED,
//!    cost C, the rail performed ONCE, the treasury dropped by C), then DROPS node 1's
//!    handles and RE-OPENS the SAME on-disk store as a node-2 gateway (the exact D-9
//!    move: node 2 opens the SAME persisted store, which holds K's ledger entry), and
//!    re-issues K -> DUPLICATE_IGNORED, the rail STILL performed ONCE (perform_count
//!    stays 1, NOT performed twice), and the treasury is debited by C EXACTLY ONCE
//!    total (not 2C). The dedupe + the single-debit are REAL (the persisted ledger,
//!    the atomic treasury debit); only the rail is a mock, and its perform_count is the
//!    clean perform-once evidence.
//!  - `g9_idempotent_capability_across_resume`: the FULL real-VM run where the genome
//!    issues K, the VM is snapshotted + transferred + node 1 killed, node 2 restores
//!    (the C-7 path) and opens the SAME persisted treasury, and the genome re-issues K
//!    after the resume. Needs the genome image, so it SKIPS cleanly (green) when
//!    `KIRBY_GENOME_IMAGE` is unset, exactly like the other real-VM gates.

use std::sync::Arc;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::rail::MockRail;
use kirby_node::treasury::Treasury;
use kirby_proto::{capability_request::Act, CapabilityRequest, Outcome, SettleEcash};

/// G9 (in-band, no image): the dedupe survives a REAL persisted-store re-open (the
/// D-9 continuation the C-7 resume does). Issue K on a node-1 gateway (PERFORMED,
/// cost C, the rail performed once, the treasury dropped by C); drop node 1's handles
/// and RE-OPEN the SAME on-disk store as a node-2 gateway; re-issue K -> the daemon's
/// STEP 1 dedupe finds K in the ledger that crossed the move and returns
/// DUPLICATE_IGNORED, the rail STILL performed once, the treasury debited C once total.
#[tokio::test]
async fn g9_dedupe_survives_persisted_store_reopen() {
    // A REAL on-disk persisted store (NOT temporary): the dedupe must survive a
    // process-level re-open, which is exactly what the C-7 resume does on node 2.
    let store_dir =
        std::env::temp_dir().join(format!("kirby-g9-inband-treasury-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store_dir);

    const INITIAL: u64 = 1_000_000;
    // The act amount; with a faithful MockRail the cost equals the amount, so C is
    // known and the treasury drop is exactly C.
    const AMOUNT: u64 = 64;
    const KEY: &str = "g9-K";

    // ONE shared MockRail across both gateways (so the perform_count is continuous
    // across the move, which makes "performed exactly once total" meaningful). In a
    // real two-host run each node has its own rail credential; the dedupe still blocks
    // the second perform because the gateway STEP 1 short-circuits BEFORE the rail.
    let rail = Arc::new(MockRail::new());

    let session = Session {
        task_descriptor: "g9-inband".to_string(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec!["mint.test.local".to_string()],
    };

    let request = || CapabilityRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
        idempotency_key: KEY.to_string(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: "mint.test.local".to_string(),
            amount: AMOUNT,
            recipient_or_quote: "q".to_string(),
        })),
        budget_sats: 256,
    };

    // ---- NODE 1: open the persisted store, issue K, it performs ----
    let cost;
    let treasury_after_first;
    {
        let treasury = Treasury::open(&store_dir, INITIAL).expect("node 1 opens the persisted store");
        let before = treasury.remaining().unwrap();
        assert_eq!(before, INITIAL);

        let gateway = GatewayService::new(treasury.clone(), rail.clone(), session.clone());
        let receipt = gateway
            .authorize_capability(&request())
            .await
            .expect("node 1 authorize");

        // The first act PERFORMED for a real cost C.
        assert_eq!(
            receipt.outcome,
            Outcome::AuthorizedAndPerformed as i32,
            "the first issue of K must be AUTHORIZED_AND_PERFORMED"
        );
        cost = receipt.cost_sats;
        assert!(cost > 0, "the act must debit a non-zero cost C");
        assert_eq!(cost, AMOUNT, "a faithful MockRail's cost equals the act amount");

        // The rail performed EXACTLY ONCE.
        assert_eq!(rail.perform_count(), 1, "the rail must have performed the act exactly once");

        // The authoritative treasury dropped by EXACTLY C.
        treasury_after_first = treasury.remaining().unwrap();
        assert_eq!(
            treasury_after_first,
            before - cost,
            "the treasury must drop by exactly the act cost C ({before} - {cost})"
        );

        // K is now recorded in the persisted ledger (the dedupe entry), and
        // debit_and_record flushed the db, so it is durable on disk.
        assert!(
            treasury.lookup(KEY).expect("ledger lookup").is_some(),
            "K must be recorded in the persisted ledger after the first act"
        );

        eprintln!(
            "G9 in-band: node 1 issued K -> AUTHORIZED_AND_PERFORMED, cost={cost}, \
             perform_count=1, treasury {before} -> {treasury_after_first}; K durable in the ledger"
        );
        // Drop the node-1 gateway + treasury handles at the end of this scope (releases
        // the sled lock so node 2 can open the SAME store, the C-7 resume pattern).
    }
    // Give the dropped handles a tick to release the sled lock before re-opening.
    tokio::task::yield_now().await;

    // ---- NODE 2: RE-OPEN the SAME persisted store, RE-ISSUE K, it dedupes ----
    // This is the D-9 move: node 2 opens the SAME store path, which holds K's ledger
    // entry. The seed (INITIAL) is IGNORED because the value already exists, so the
    // persisted balance (treasury_after_first) and the ledger are authoritative.
    let treasury2 = Treasury::open(&store_dir, INITIAL).expect("node 2 RE-opens the SAME persisted store");
    let on_reopen = treasury2.remaining().unwrap();
    assert_eq!(
        on_reopen, treasury_after_first,
        "re-opening the SAME store must show the persisted post-first balance (the seed is ignored on resume)"
    );
    // The dedupe ledger crossed the move: K is still there.
    assert!(
        treasury2.lookup(KEY).expect("ledger lookup after re-open").is_some(),
        "the dedupe ledger must survive the store re-open (K still present, D-9)"
    );

    let gateway2 = GatewayService::new(treasury2.clone(), rail.clone(), session.clone());
    let reissue = gateway2
        .authorize_capability(&request())
        .await
        .expect("node 2 authorize (re-issue)");

    // (i) The re-issue across the move is DEDUPED.
    assert_eq!(
        reissue.outcome,
        Outcome::DuplicateIgnored as i32,
        "the re-issue of K after the store re-open must be DUPLICATE_IGNORED (the dedupe survived the move)"
    );
    // The deduped receipt returns the PRIOR receipt's cost C and the SAME balance.
    assert_eq!(reissue.cost_sats, cost, "the deduped receipt must report the prior cost C");
    assert_eq!(
        reissue.treasury_remaining, treasury_after_first,
        "the deduped receipt must report the SAME treasury balance the first act left"
    );

    // (ii) The act was NOT performed twice on the rail: perform_count STAYS 1.
    assert_eq!(
        rail.perform_count(),
        1,
        "the act must NOT be performed twice on the rail across the move (perform_count must stay 1)"
    );

    // (iii) The treasury is debited by C EXACTLY ONCE total (not 2C): the balance is
    // UNCHANGED by the re-issue.
    let treasury_after_reissue = treasury2.remaining().unwrap();
    assert_eq!(
        treasury_after_reissue, treasury_after_first,
        "the re-issue must debit NOTHING: the treasury must be unchanged across it"
    );
    let total_debited = INITIAL - treasury_after_reissue;
    assert_eq!(
        total_debited, cost,
        "the treasury must be debited by C EXACTLY ONCE total across the move ({cost}), never 2C"
    );

    eprintln!(
        "G9 in-band PASS: node 2 re-opened the SAME persisted store and re-issued K -> \
         DUPLICATE_IGNORED ; the act was performed ONCE on the rail (perform_count=1) ; \
         the treasury was debited by C={cost} EXACTLY ONCE total ({INITIAL} -> {treasury_after_reissue}, \
         not 2C). The idempotency-key dedupe SURVIVES a persisted-store re-open (the D-9 \
         continuation the C-7 resume does). Replay / double-burn across a move closed (spec 4.2, gate G9)."
    );

    let _ = std::fs::remove_dir_all(&store_dir);
}

/// G9 (full real-VM run): the genome issues K, the VM is snapshotted + transferred +
/// node 1 killed, node 2 restores (the C-7 path) and opens the SAME persisted
/// treasury, and the genome re-issues K after the resume. Asserts the re-issue is
/// DUPLICATE_IGNORED, the act is NOT performed twice on the rail (perform_count stays
/// 1), and the treasury is debited by C EXACTLY ONCE total. Needs the genome image,
/// so it SKIPS cleanly (green) when `KIRBY_GENOME_IMAGE` is unset.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g9_idempotent_capability_across_resume() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP g9_idempotent_capability_across_resume: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the real snapshot+resume idempotency test (gate G9)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);

    let config = kirby_node::idempotent_run::IdempotentRunConfig::new(image_dir)
        .expect("genome image (vmlinux + rootfs.squashfs)");
    let outcome = kirby_node::idempotent_run::run(config)
        .await
        .expect("the idempotent-across-resume run completed");

    // A clear evidence line (the verifier reads it).
    eprintln!("{}", kirby_node::idempotent_run::evidence_line(&outcome));

    // The genome's FIRST act performed exactly once for a real cost C on node 1.
    assert!(
        outcome.first.is_performed(),
        "the genome's first issue of K must be AUTHORIZED_AND_PERFORMED on node 1; got {:?}",
        outcome.first.outcome
    );
    assert!(outcome.act_cost() > 0, "the first act must debit a non-zero cost C");
    assert_eq!(
        outcome.perform_count_after_first, 1,
        "the rail must have performed the act exactly once after the first issue"
    );
    assert_eq!(
        outcome.treasury_after_first,
        outcome.treasury_before - outcome.act_cost(),
        "node 1's treasury must drop by exactly the act cost C"
    );

    // The move actually happened (node 1 killed, node 2 restored from the snapshot,
    // the VMGenID generation bumped, the resume signal the genome re-issues on).
    assert!(outcome.node1_killed, "node 1's VMM must be killed after the snapshot");
    assert!(
        outcome.node2_reached_running,
        "node 2 must bring the VM to Running FROM the snapshot (the C-7 restore)"
    );
    assert_eq!(
        outcome.generation_post,
        outcome.generation_pre + 1,
        "the VMGenID generation must bump by 1 on restore (the genome's resume signal)"
    );

    // (i) THE G9 PROOF: the re-issue of K across the move is DEDUPED.
    assert!(
        outcome.reissue.is_duplicate_ignored(),
        "the genome's RE-ISSUE of K after the resume must be DUPLICATE_IGNORED; got {:?}",
        outcome.reissue.outcome
    );
    assert_eq!(
        outcome.reissue.cost_sats,
        outcome.act_cost(),
        "the deduped re-issue receipt must report the prior cost C"
    );

    // (ii) The act was NOT performed twice on the rail (perform_count stays 1).
    assert_eq!(
        outcome.perform_count_after_reissue, 1,
        "the act must NOT be performed twice on the rail across the move (perform_count must stay 1)"
    );

    // (iii) The treasury was debited by C EXACTLY ONCE total (not 2C): the post-resume
    // balance is unchanged from the post-first balance, so the total drop is C.
    assert_eq!(
        outcome.treasury_after_reissue, outcome.treasury_after_first,
        "the re-issue must debit NOTHING: the treasury must be unchanged across the resume"
    );
    assert_eq!(
        outcome.total_debited(),
        outcome.act_cost(),
        "the treasury must be debited by C EXACTLY ONCE total across the move, never 2C"
    );

    // The overall G9 verdict.
    assert!(outcome.passed(), "G9 must pass: {outcome:?}");

    eprintln!(
        "G9 PASS (real VM): the genome issued K -> PERFORMED (cost {}) on node 1 ; the VM was \
         snapshotted + transferred + node 1 KILLED ; node 2 RESTORED from the snapshot and opened \
         the SAME persisted treasury ; the genome re-issued K after the resume -> DUPLICATE_IGNORED ; \
         the act was performed ONCE on the rail (perform_count=1) ; the treasury was debited by C={} \
         EXACTLY ONCE total ({} -> {}, not 2C). Idempotent capability across resume proven (spec 4.2, gate G9).",
        outcome.act_cost(),
        outcome.act_cost(),
        outcome.treasury_before,
        outcome.treasury_after_reissue,
    );
}
