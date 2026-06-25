//! C-11 test (the CAPSTONE: gate G10 reproducibility + clean-cut, composing G1-G9):
//! the FULL LOOP, one capstone end-to-end run. ONE genome, ONE lease-driven failover,
//! the WHOLE survival arc proven to COMPOSE into a single living organism.
//!
//! The previous chunks each proved ONE gate in its OWN test on its OWN VM. C-11 is
//! DIFFERENT: it is the SINGLE CONTINUOUS SCENARIO on ONE genome instance across ONE
//! failover, the thing the slices individually do NOT prove (that the whole chain holds
//! together end to end). This is "the loop," the demo.
//!
//! THE ARC this run proves, in order, on ONE genome, asserting at each step:
//!  1. BOOT (G1): the active lease-holder boots the genome microVM under the jailer; the
//!     genome completes a GetSessionContext round-trip over vsock (Running + the
//!     heartbeat/entropy event).
//!  2. METER reads non-zero (G2 meter half, SURVIVAL not death): the genome burns a
//!     little CPU; the cgroup meter accumulates > 0 and debits the treasury, but the
//!     budget keeps ample runway so the VM SURVIVES (budget-DEATH is G2's own test).
//!  3. EGRESS DENIED throughout (G4): the genome attempts a raw outbound and it FAILS;
//!     the eBPF TAP egress counter shows ~0 IP bytes left the VM (asserted once mid-loop).
//!  4. BROKERED ACT (G5, the agency proof): the genome issues RequestCapability{K} =
//!     settle ecash on the LOCAL CDK fakewallet mint; the daemon authorizes it, PERFORMS
//!     it for real (the mint shows the spend), debits cost C (the treasury drops by
//!     exactly C), the VM issues NO raw network for it (TAP egress ~0), and the rail
//!     credential never crosses vsock.
//!  5. SNAPSHOT + KILL + RESUME ON NODE 2 (G6, lease-driven, G8): the active node
//!     snapshots the running VM, the mem+state pair moves to the new active node, the
//!     source node is KILLED, the surviving 2-of-3 majority elects a new leader at T+1
//!     that RESTORES the snapshot -> Running, and the genome completes a post-resume
//!     round-trip (survived the move).
//!  6. ENTROPY RE-DERIVED (G7): fingerprint_post != fingerprint_pre AND the generation
//!     bumped (VMGenID) AND the genome called GetEntropyNonce after resume before acting.
//!  7. IDEMPOTENT REPLAY (G9): the resumed genome re-issues the SAME key K; it is
//!     DUPLICATE_IGNORED, the act is NOT performed twice, and the treasury is debited by
//!     C EXACTLY ONCE total (not 2C).
//!  8. NO SPLIT-BRAIN (G8): the new active node claims the relay lease at T+1
//!     (latest-term-wins); the revived source node believing term T REFUSES to run/debit
//!     (term-fenced), no second VM, the treasury debited by at most one node, and no
//!     observed term boundary shows two actives.
//!
//! This boots a REAL local mint + REAL Firecracker microVMs under the jailer + the
//! relay-native lease fabric, so it SKIPS (green no-op) when `KIRBY_GENOME_IMAGE` is unset,
//! exactly like the other real-VM gates, so `cargo test` stays green on an image-less
//! host. The verifier runs it with the var set as the C-11 producing command.

#![cfg(target_os = "linux")]

use std::sync::Arc;

use kirby_node::full_loop_run::{self, FullLoopConfig};
use kirby_node::rail::CdkEcashRail;

/// The C-11 capstone: ONE genome through the whole survival arc across ONE failover.
/// Asserts every composed gate (G1-G9) held in the SINGLE continuous run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c11_full_loop_one_genome_survives_a_failover() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP c11_full_loop_one_genome_survives_a_failover: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the full-loop capstone (boot -> meter -> \
             brokered act -> snapshot -> resume on node 2 after node-1 kill -> no-split-brain -> \
             entropy re-derived). Composes G1-G9 in ONE continuous run."
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);

    // Surface cdk + daemon logs (the melt validation, the brokered authorize, the lease
    // handoff) so the per-step C-11 evidence is legible in the test output.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,cdk=debug")),
        )
        .with_test_writer()
        .try_init();

    // 1) Boot the REAL local fakewallet mint on a host port (the brokered act's
    // destination, gate G5). A high, mostly-unique port keeps the test isolated.
    let mint_port: u16 = 19000 + (std::process::id() % 2000) as u16;
    let mint = mint_fixture::FakeMint::start(mint_port)
        .await
        .expect("start the local fakewallet mint");
    let mint_url = mint.url();
    eprintln!("C11: local fakewallet mint up at {mint_url}");

    // 2) Build + fund the daemon's wallet (the rail credential, host-only). Fund enough
    // for the single brokered act (cost ~64 + the fake's flat fee) with headroom.
    let wallet = kirby_node::mint_rig::build_wallet(&mint_url).await.expect("build wallet");
    kirby_node::mint_rig::fund_wallet(wallet.clone(), 1000)
        .await
        .expect("fund the wallet on the local mint");
    let wallet_before = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert!(wallet_before > 0, "the wallet must be funded before the brokered settle; got {wallet_before}");
    eprintln!("C11: daemon wallet funded, balance={wallet_before} sat");

    // The proofs the rail will spend (captured BEFORE the act, so we can prove they are
    // SPENT on the mint afterwards, gate G5(ii)).
    let pre_proofs = wallet.get_unspent_proofs().await.expect("pre-act unspent proofs");
    assert!(!pre_proofs.is_empty(), "the funded wallet must hold spendable proofs");

    // 3) The real rail over the funded wallet (the C-6 rail). The SAME instance is used
    // on the active node and the restored node, so its perform_count is continuous across
    // the move (the G9 "performed once total" proof is meaningful).
    let rail = Arc::new(CdkEcashRail::new(wallet.clone(), mint_url.clone()));
    let rail_dyn: Arc<dyn kirby_node::rail::Rail> = rail.clone();
    let perform_rail = rail.clone();

    // 4) The full-loop config: the allowlisted destination is the mint URL (so the act
    // authorizes, spec step 2). A distinct CID/port range keeps the run isolated.
    let config = FullLoopConfig::new(image_dir, mint_url.clone());

    // 5) RUN the whole survival arc on ONE genome across ONE lease-driven failover. The
    // perform_count reader proves the act was performed EXACTLY ONCE across the move.
    let mut outcome = full_loop_run::run(config, rail_dyn, move || perform_rail.perform_count())
        .await
        .expect("the full-loop run completed");

    // Fill the G5(ii) wallet-balance + mint-spent-proof evidence directly against the
    // rail and the mint (the brokered_act pattern; the orchestration leaves these at 0).
    use cdk::nuts::State;
    let states = rail
        .wallet()
        .check_proofs_spent(pre_proofs.clone())
        .await
        .expect("query the mint for the pre-act proofs' state");
    let spent_count = states.iter().filter(|s| s.state == State::Spent).count() as u64;
    let wallet_after = rail.wallet().total_balance().await.map(u64::from).unwrap_or(0);
    outcome.wallet_before = wallet_before;
    outcome.wallet_after = wallet_after;
    outcome.mint_spent_proof_count = spent_count;

    // A clear, evidence-first block (the verifier reads it): the whole arc in one line,
    // then the decisive per-step details.
    eprintln!("{}", full_loop_run::evidence_line(&outcome));
    if let Some(pre) = &outcome.fingerprint_pre {
        eprintln!("  fingerprint_pre  = {pre}");
    }
    if let Some(post) = &outcome.fingerprint_post {
        eprintln!("  fingerprint_post = {post}");
    }

    let ebpf_zero_ceiling = kirby_node::meter_egress::EBPF_ZERO_CEILING_BYTES;

    // ---- STEP 1 (G1): BOOT. The genome booted under the jailer and round-tripped. ----
    assert!(
        outcome.boot_round_trip,
        "(G1) the genome must boot under the jailer and complete a vsock GetSessionContext round-trip"
    );
    eprintln!("C11 STEP 1 (G1): the genome booted under the jailer and completed a vsock round-trip.");

    // ---- STEP 2 (G2 meter half): METER reads non-zero, the VM SURVIVES. ----
    assert!(
        outcome.metered_burn_sats > 0,
        "(G2) the cgroup meter must bill real CPU (> 0 sats), not zero; got {}",
        outcome.metered_burn_sats
    );
    assert!(
        outcome.treasury_after_meter > 0,
        "(G2 survival) the budget must keep ample runway after metering so the VM SURVIVES (this is the LIVING organism, not the budget-death halt); got remaining={}",
        outcome.treasury_after_meter
    );
    eprintln!(
        "C11 STEP 2 (G2 meter half): the cgroup meter billed {} sats of real CPU and the VM SURVIVES (treasury remaining={}, ample runway; budget-death is G2's own test).",
        outcome.metered_burn_sats, outcome.treasury_after_meter
    );

    // ---- STEP 3 (G4): EGRESS DENIED, the eBPF TAP egress ~0. ----
    assert!(
        outcome.egress_denied,
        "(G4) the genome's raw egress attempt must be DENIED (no leak); the genome reported its probes"
    );
    assert!(
        outcome.ebpf_egress_bytes <= ebpf_zero_ceiling,
        "(G4) the eBPF TAP egress must show ~0 IP bytes left the VM (<= {ebpf_zero_ceiling}); got {} bytes",
        outcome.ebpf_egress_bytes
    );
    eprintln!(
        "C11 STEP 3 (G4): the genome's raw egress was DENIED and the eBPF TAP egress stayed ~0 ({} bytes <= {ebpf_zero_ceiling}); only vsock works.",
        outcome.ebpf_egress_bytes
    );

    // ---- STEP 4 (G5): the BROKERED ACT, the agency proof. ----
    // (i) the daemon authorized + performed it (the receipt outcome only the order produces).
    assert!(
        outcome.first.is_performed(),
        "(G5 i) the daemon must AUTHORIZE_AND_PERFORM the brokered act; got {:?}",
        outcome.first.outcome
    );
    // (iii) a non-zero cost C debited AND the treasury dropped by EXACTLY that.
    assert!(outcome.act_cost() > 0, "(G5 iii) a non-zero cost C must be debited; got 0");
    assert_eq!(
        outcome.act_treasury_drop(),
        outcome.act_cost(),
        "(G5 iii) the daemon-authoritative treasury must drop by EXACTLY C ({} debited, drop {})",
        outcome.act_cost(),
        outcome.act_treasury_drop()
    );
    // (ii) the settle was REAL: the mint shows the wallet's input proofs SPENT and the
    // wallet balance dropped (a mock would move neither).
    assert!(
        outcome.mint_spent_proof_count > 0,
        "(G5 ii) the settle must be REAL: the mint must show at least one of the wallet's input proofs SPENT; none of {} are Spent",
        pre_proofs.len()
    );
    assert!(
        outcome.wallet_after < outcome.wallet_before,
        "(G5 ii) the wallet balance must DROP after the real settle ({} -> {})",
        outcome.wallet_before,
        outcome.wallet_after
    );
    // (iv) the VM issued NO raw network for the act (the eBPF ~0 asserted in step 3).
    // (v) the credential never crossed vsock: structural (the wire types carry no
    // credential field) + the genome got only the rail receipt (a non-zero proof len).
    assert_no_credential_on_the_wire();
    assert!(
        outcome.first.proof_len > 0,
        "(G5 v) the genome should receive the rail's receipt (the mint preimage), proof_len > 0; the credential (the wallet) is never on the wire"
    );
    eprintln!(
        "C11 STEP 4 (G5): the daemon authorized + PERFORMED a REAL ecash settle on the mint over HOST networking ; cost C={} debited ; treasury {} -> {} ; {} input proof(s) SPENT on the mint ; wallet {} -> {} ; the VM TAP egress stayed ~0 ; the credential never crossed vsock (proof_len={}). Isolation preserved while agency granted (D-6).",
        outcome.act_cost(),
        outcome.treasury_before_act,
        outcome.treasury_after_act,
        outcome.mint_spent_proof_count,
        outcome.wallet_before,
        outcome.wallet_after,
        outcome.first.proof_len,
    );

    // ---- STEP 5 (G6, lease-driven, G8): SNAPSHOT + KILL + RESUME ON NODE 2. ----
    assert_ne!(outcome.new_leader, outcome.killed_node, "(G8) the new leader must not be the killed node (survive-one-loss)");
    assert!(outcome.term_t1 > outcome.term_t, "(G8) the handoff must commit the lease at a strictly higher term T+1");
    assert!(
        outcome.node2_reached_running,
        "(G6) the new active node must bring the VM to Running FROM the snapshot (not a cold boot)"
    );
    assert!(
        outcome.post_resume_round_trip,
        "(G6) the genome must complete a post-resume round-trip on the new active node (it survived the move)"
    );
    eprintln!(
        "C11 STEP 5 (G6 + G8): the active node (leader {}) snapshotted the VM ({} bytes), was KILLED; the surviving 2-of-3 majority elected leader {} @ T+1={} that RESTORED the snapshot and the genome SURVIVED (post-resume round-trip).",
        outcome.killed_node, outcome.snapshot_bytes, outcome.new_leader, outcome.term_t1
    );

    // ---- STEP 6 (G7): ENTROPY RE-DERIVED on resume. ----
    assert!(
        outcome.fingerprints_differ(),
        "(G7) the post-resume fingerprint must DIFFER from the pre-snapshot one (the entropy was re-derived): pre={:?} post={:?}",
        outcome.fingerprint_pre,
        outcome.fingerprint_post
    );
    assert_eq!(
        outcome.generation_post,
        outcome.generation_pre + 1,
        "(G7) the VMGenID generation must bump by exactly 1 on restore (pre={}, post={})",
        outcome.generation_pre,
        outcome.generation_post
    );
    assert!(
        outcome.entropy_call_before_post_resume_act,
        "(G7) the genome must call GetEntropyNonce after resume BEFORE acting (re-derive-before-act ordering)"
    );
    eprintln!(
        "C11 STEP 6 (G7): the genome RE-DERIVED its entropy on resume (fingerprint_pre != fingerprint_post), the VMGenID generation bumped {} -> {}, and it called GetEntropyNonce after resume before acting.",
        outcome.generation_pre, outcome.generation_post
    );

    // ---- STEP 7 (G9): IDEMPOTENT REPLAY across the resume. ----
    assert!(
        outcome.reissue.is_duplicate_ignored(),
        "(G9) the resumed genome's re-issue of K must be DUPLICATE_IGNORED; got {:?}",
        outcome.reissue.outcome
    );
    assert_eq!(
        outcome.perform_count_after_first, 1,
        "(G9) the act must have been performed exactly once on the rail before the move (got {})",
        outcome.perform_count_after_first
    );
    assert_eq!(
        outcome.perform_count_after_reissue, 1,
        "(G9) the act must NOT be performed twice on the rail across the move (perform_count stays 1; got {})",
        outcome.perform_count_after_reissue
    );
    // The re-issue debits NOTHING across the move: node 2's post-reissue balance equals
    // the handoff balance (treasury_after_meter = the act C + the small metered burn,
    // both on node 1 before the snapshot). So the act is charged C ONCE total, not 2C.
    assert_eq!(
        outcome.treasury_after_reissue, outcome.treasury_after_meter,
        "(G9) the re-issue must debit NOTHING (the balance equals the handoff balance): after_meter={} after_reissue={}",
        outcome.treasury_after_meter, outcome.treasury_after_reissue
    );
    assert_eq!(
        outcome.reissue_added_debit(),
        0,
        "(G9) the deduped re-issue must add 0 to the drop across the move (the act is charged C once, not 2C): added={}",
        outcome.reissue_added_debit()
    );
    // And the act's own debit on node 1 was exactly C (the brokered-act drop, G5(iii)).
    assert_eq!(
        outcome.act_treasury_drop(),
        outcome.act_cost(),
        "(G9/G5) the brokered act debited exactly C on the active node: drop={} C={}",
        outcome.act_treasury_drop(),
        outcome.act_cost()
    );
    eprintln!(
        "C11 STEP 7 (G9): the resumed genome re-issued K -> DUPLICATE_IGNORED ; the act was performed ONCE on the rail (perform_count 1 -> 1) ; the re-issue added 0 to the drop (the treasury is charged C={} EXACTLY ONCE, not 2C).",
        outcome.act_cost()
    );

    // ---- STEP 8 (G8): NO SPLIT-BRAIN. The revived stale node is fenced; no two actives. ----
    assert!(
        outcome.revived_stale_fenced,
        "(G8) the revived stale node (believing term T) must be FENCED (no second VM, no double-execute)"
    );
    assert!(
        !outcome.two_actives_ever_observed,
        "(G8 linearizability) at no observed term boundary may two nodes be active at once"
    );
    eprintln!(
        "C11 STEP 8 (G8): the new active node holds active_lease{{node {}, T+1={}}}; the revived source node (believing T={}) was FENCED (no second VM, the treasury untouched); no two actives ever observed.",
        outcome.new_leader, outcome.term_t1, outcome.term_t
    );

    // ---- The composite C-11 verdict: every composed gate held in ONE run. ----
    assert!(
        outcome.passed(ebpf_zero_ceiling),
        "C11 must pass: the whole survival arc (G1-G9) must hold in ONE continuous run: {outcome:?}"
    );

    eprintln!(
        "C11 PASS (THE FULL LOOP): ONE genome BORN under the jailer (G1), METERED alive (G2, burn {} > 0, survives), \
         EGRESS-DENIED throughout (G4, eBPF ~0), PERFORMED a real brokered ecash settle (G5, cost C={}, mint moved, \
         credential never crossed vsock), SNAPSHOTTED + the active node KILLED + RESTORED on the lease-elected new \
         leader @ T+1 (G6 + G8, the genome survived), RE-DERIVED its entropy (G7), RE-ISSUED K -> deduped/performed-once/\
         debited-once (G9), and the revived stale node was FENCED with no two actives (G8). The slices COMPOSE into one \
         living organism across a failover. Full loop proven (C-11).",
        outcome.metered_burn_sats, outcome.act_cost()
    );

    mint.shutdown().await;
}

/// (G5 v) machine-checkable assertion that the gateway wire types carry NO credential
/// field. We construct the exact messages the genome speaks (a SettleEcash
/// `CapabilityRequest` and a `CapabilityReceipt`) and destructure them field by field;
/// a future field addition forces this to be revisited (if someone adds a credential
/// field, this stops compiling). The credential (the wallet) lives only host-side.
fn assert_no_credential_on_the_wire() {
    use kirby_proto::capability_request::Act;
    use kirby_proto::{CapabilityReceipt, CapabilityRequest, SettleEcash};

    let req = CapabilityRequest {
        schema_version: 1,
        idempotency_key: "k".into(),
        act: Some(Act::SettleEcash(SettleEcash {
            mint_id: "mint".into(),
            amount: 1,
            recipient_or_quote: "q".into(),
        })),
        budget_sats: 1,
    };
    let CapabilityRequest {
        schema_version: _,
        idempotency_key: _,
        act,
        budget_sats: _,
    } = &req;
    if let Some(Act::SettleEcash(s)) = act {
        let SettleEcash { mint_id: _, amount: _, recipient_or_quote: _ } = s;
        // Only a mint id, an amount, and a recipient/quote string: the destination and
        // the intent, never the credential to spend.
    }

    let receipt = CapabilityReceipt {
        schema_version: 1,
        outcome: 1,
        cost_sats: 0,
        treasury_remaining: 0,
        proof: vec![],
        // The brain-act reply text (empty for an ecash settle); still not a credential.
        completion: vec![],
        // The durable-mind-state result (absent for an ecash settle); still not a credential.
        memory: None,
    };
    let CapabilityReceipt {
        schema_version: _,
        outcome: _,
        cost_sats: _,
        treasury_remaining: _,
        proof: _,
        completion: _,
        memory: _,
    } = &receipt;
}

/// A minimal local fakewallet mint fixture: boot a real cdk-mintd HTTP mint with the
/// cdk-fake-wallet Lightning backend on a host port, wait for it to be ready, and shut
/// it down on demand. Mirrors the C-6 (gate G5) test's fixture, trimmed to the
/// fakewallet + sqlite features the daemon build uses (no cln/lnd/ldk/bitcoind).
/// cdk-mintd is a dev-dependency, so this fixture is test-only; the daemon never embeds
/// a mint.
mod mint_fixture {
    use std::sync::Arc;
    use std::time::Duration;

    use cdk::nuts::CurrencyUnit;
    use tokio::sync::Notify;

    /// A running local fakewallet mint.
    pub struct FakeMint {
        port: u16,
        shutdown: Arc<Notify>,
        handle: tokio::task::JoinHandle<()>,
        // Hold the temp dir so the mint's sqlite db lives as long as the mint.
        _work_dir: TempDir,
    }

    impl FakeMint {
        /// Boot the mint on `port` and wait (bounded) for it to serve `/v1/info`.
        pub async fn start(port: u16) -> anyhow::Result<Self> {
            let work_dir = TempDir::new(&format!("kirby-c11-mint-{port}"));
            let settings = fake_wallet_settings(port);
            let shutdown = Arc::new(Notify::new());

            let work_dir_path = work_dir.path().to_path_buf();
            let shutdown_for_task = shutdown.clone();
            let handle = tokio::spawn(async move {
                let shutdown_future = async move {
                    shutdown_for_task.notified().await;
                };
                if let Err(e) = cdk_mintd::run_mintd_with_shutdown(
                    &work_dir_path,
                    &settings,
                    shutdown_future,
                    None,
                    None,
                    vec![],
                )
                .await
                {
                    eprintln!("local fakewallet mint exited with error: {e}");
                }
            });

            wait_ready(port, Duration::from_secs(30)).await?;
            Ok(FakeMint { port, shutdown, handle, _work_dir: work_dir })
        }

        /// The mint's base URL.
        pub fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// Signal the mint to shut down and await its task.
        pub async fn shutdown(self) {
            self.shutdown.notify_waiters();
            let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
        }
    }

    /// Poll a fresh wallet's mint-info call until the mint serves it (ready) or the
    /// deadline elapses.
    async fn wait_ready(port: u16, timeout: Duration) -> anyhow::Result<()> {
        let url = format!("http://127.0.0.1:{port}");
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Ok(wallet) = kirby_node::mint_rig::build_wallet(&url).await {
                if wallet.fetch_mint_info().await.is_ok() {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("local fakewallet mint on port {port} did not become ready in time");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Build the cdk-mintd settings for a local fakewallet mint on `port` (the C-6
    /// fixture's settings: fakewallet + sqlite, 0 fees so a settle's cost equals its
    /// amount, a 1-sat minimum reserve to cover the fake's flat +1 fee).
    fn fake_wallet_settings(port: u16) -> cdk_mintd::config::Settings {
        let info = cdk_mintd::config::Info {
            url: format!("http://127.0.0.1:{port}"),
            listen_host: "127.0.0.1".to_string(),
            listen_port: port,
            seed: None,
            // A fixed mnemonic so the mint derives a stable keyset. This is a
            // throwaway fixture for the local cdk-fakewallet mint used in tests
            // only: no real seed, no real funds.
            mnemonic: Some(
                "eye survey guilt napkin crystal cup whisper salt luggage manage unveil loyal"
                    .to_string(),
            ),
            signatory_url: None,
            signatory_certs: None,
            input_fee_ppk: None,
            use_keyset_v2: None,
            http_cache: Default::default(),
            logging: Default::default(),
            enable_info_page: None,
            quote_ttl: None,
        };

        let fake_wallet = cdk_mintd::config::FakeWallet {
            supported_units: vec![CurrencyUnit::Sat],
            fee_percent: 0.0,
            reserve_fee_min: 1.into(),
            ..Default::default()
        };

        cdk_mintd::config::Settings {
            info,
            // Upstream cdk 0.17.x takes a Vec<Ln> (multiple LN backends); the spike
            // boots a single fakewallet backend.
            ln: vec![cdk_mintd::config::Ln {
                ln_backend: cdk_mintd::config::LnBackend::FakeWallet,
                ..Default::default()
            }],
            fake_wallet: Some(fake_wallet),
            ..Default::default()
        }
    }

    /// A unique temp directory removed on drop (the mint's sqlite db lives here).
    pub struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("{prefix}-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&path).expect("create mint work dir");
            TempDir { path }
        }
        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
