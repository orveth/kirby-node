//! C-6 test (gate G5): the brokered act. The daemon performs a REAL ecash settle
//! on a LOCAL CDK fakewallet mint over its OWN host networking, using a host-held
//! credential the genome never sees, metered + treasury-debited, with the
//! sandboxed VM issuing ZERO raw network. This proves D-6 agency: isolation
//! preserved while agency is granted.
//!
//! The test:
//!   1. boots a REAL local fakewallet mint (a cdk-mintd HTTP mint with the
//!      cdk-fake-wallet Lightning backend) on a host port;
//!   2. builds + funds the daemon's cashu wallet (the rail credential, host-only);
//!   3. constructs the real CdkEcashRail over that wallet;
//!   4. boots the genome microVM with the backend's brokered raw-egress profile:
//!      Linux uses the locked-down TAP and eBPF meter; macOS VZ uses a vsock-only
//!      no-network-device guest;
//!   5. the genome issues a `RequestCapability` ecash settle over vsock, which the
//!      daemon performs for real (a melt against the mint over HOST networking);
//!   6. asserts G5 (i)-(v).
//!
//! G5 (i)-(v):
//!   (i)   the daemon AUTHORIZED it via the exact 5-step order (the receipt outcome
//!         is AUTHORIZED_AND_PERFORMED, which only the order produces);
//!   (ii)  the daemon PERFORMED it for real: the mint shows the wallet's proofs
//!         SPENT and the wallet balance dropped (queried against the real mint),
//!         not a mock;
//!   (iii) cost_sats > 0 was debited AND the daemon-authoritative treasury dropped
//!         by EXACTLY that;
//!   (iv)  the VM issued NO raw network for the act: Linux proves this with the
//!         eBPF TAP egress counter staying ~0; macOS VZ proves the MVP shape by
//!         exposing no guest network device at all;
//!   (v)   the genome never received the rail credential: the wire types carry no
//!         credential field, asserted structurally; the wallet/proofs live only
//!         host-side.
//! The contrast (the D-6 point): the SAME mint destination is reachable when the
//! daemon brokers it (here) but NOT directly from the VM (gate G4 / VZ no-NIC).
//!
//! This boots a REAL mint + a REAL microVM, so it SKIPS (green no-op) when
//! `KIRBY_GENOME_IMAGE` is unset, exactly like genome_boot / metering_halt /
//! egress_lockdown, so `cargo test` stays green on an image-less host. The
//! verifier runs it with the var set as the G5 producing command.

use std::sync::Arc;
use std::time::Duration;

use kirby_node::boot::{BootConfig, ImagePaths};
use kirby_node::brokered_run::{self, BrokeredRawEgressProof, BrokeredRunConfig};
use kirby_node::mint_rig;
use kirby_node::rail::CdkEcashRail;

/// G5: the brokered ecash settle. Boots a real local mint + a real microVM and
/// asserts the daemon authorized, performed (real), metered + debited the act,
/// the VM issued no raw network for it, and the genome never saw the credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g5_brokered_ecash_settle_real_metered_no_vm_egress() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP g5_brokered_ecash_settle_real_metered_no_vm_egress: set KIRBY_GENOME_IMAGE to the \
             `nix build .#genome-image` output to run the real-mint + real-microVM brokered-act test (gate G5)"
        );
        return;
    };
    let image_dir = std::path::PathBuf::from(image_dir);
    let image = ImagePaths::from_dir(&image_dir).expect("genome image (vmlinux + rootfs.squashfs)");

    // Surface cdk + daemon logs (the melt validation, the brokered authorize) so
    // the G5 evidence is legible in the test output.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,cdk=debug")),
        )
        .with_test_writer()
        .try_init();

    // 1) Boot the REAL local fakewallet mint on a host port. A high, mostly-unique
    // port keeps the test isolated from a long-running mint or another run.
    let mint_port: u16 = 18000 + (std::process::id() % 2000) as u16;
    let mint = mint_fixture::FakeMint::start(mint_port)
        .await
        .expect("start the local fakewallet mint");
    let mint_url = mint.url();
    eprintln!("G5: local fakewallet mint up at {mint_url}");

    // 2) Build + fund the daemon's wallet (the rail credential, host-only). Fund a
    // small amount so the settle has proofs to spend.
    let wallet = mint_rig::build_wallet(&mint_url)
        .await
        .expect("build wallet");
    mint_rig::fund_wallet(wallet.clone(), 1000)
        .await
        .expect("fund the wallet on the local mint");
    let funded_balance = wallet.total_balance().await.map(u64::from).unwrap_or(0);
    assert!(
        funded_balance > 0,
        "the wallet must be funded before the brokered settle; got balance {funded_balance}"
    );
    eprintln!("G5: daemon wallet funded, balance={funded_balance} sat");

    // The proofs the rail will spend (captured BEFORE the act, so we can prove
    // they are SPENT on the mint afterwards, gate G5(ii)).
    let pre_proofs = wallet
        .get_unspent_proofs()
        .await
        .expect("pre-act unspent proofs");
    assert!(
        !pre_proofs.is_empty(),
        "the funded wallet must hold spendable proofs"
    );

    // 3) The real rail over the funded wallet. The mint_id (the allowlist
    // destination) is the mint URL.
    let rail = Arc::new(CdkEcashRail::new(wallet.clone(), mint_url.clone()));

    // 4) Boot config: the allowlist contains the mint URL (so the act authorizes,
    // spec step 2). The TAP + the `brokered` workload are forced on by
    // BrokeredRunConfig. A distinct CID and port keep this VM isolated.
    let boot = BootConfig {
        image,
        node_id: format!("g5test-{}", std::process::id()),
        task: "g5-brokered".to_string(),
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec![mint_url.clone()],
        guest_cid: 29,
        gateway_port: 5029,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        workload: Some("brokered".to_string()),
        brain: None,
        // BrokeredRunConfig chooses the backend-specific profile.
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    // A window long enough for the genome to issue the request and the daemon to
    // settle against the mint (the fakewallet adds a short pay delay).
    let config = BrokeredRunConfig::new(boot, Duration::from_secs(30));

    // 5) Run: boot the locked-down VM with the real rail injected, let the genome
    // issue the brokered settle, gather the G5 evidence.
    let outcome = brokered_run::run(config, rail.clone())
        .await
        .expect("brokered run completed");

    // A clear evidence block (the verifier reads it).
    eprintln!(
        "G5 evidence: performed={} ; cost_sats={} ; treasury_before={} ; treasury_after={} ; \
         treasury_drop={} ; ebpf_egress_bytes={} ; raw_egress={} ; proof_len={}",
        outcome.receipt.performed,
        outcome.receipt.cost_sats,
        outcome.treasury_before,
        outcome.treasury_after,
        outcome.treasury_drop(),
        outcome.ebpf_egress_bytes,
        outcome.raw_egress.summary(raw_egress_zero_ceiling()),
        outcome.receipt.proof_len,
    );
    eprintln!("  genome result: {}", outcome.receipt.result_detail);

    // ---- (i) the daemon AUTHORIZED it via the 5-step order ----
    // The genome's receipt outcome is AUTHORIZED_AND_PERFORMED, which only the
    // dedupe -> allowlist -> budget -> perform -> debit order produces.
    assert!(
        outcome.receipt.performed,
        "(i) the daemon must AUTHORIZE_AND_PERFORM the act; got: {}",
        outcome.receipt.result_detail
    );

    // ---- (iii) cost_sats > 0 debited AND treasury dropped by EXACTLY that ----
    assert!(
        outcome.receipt.cost_sats > 0,
        "(iii) a non-zero cost must be debited for the act; got cost_sats=0"
    );
    assert_eq!(
        outcome.treasury_drop(),
        outcome.receipt.cost_sats,
        "(iii) the daemon-authoritative treasury must drop by EXACTLY cost_sats ({} debited, drop {})",
        outcome.receipt.cost_sats,
        outcome.treasury_drop(),
    );
    // The genome was told a balance that matches the authoritative post-debit one.
    assert_eq!(
        outcome.receipt.treasury_remaining, outcome.treasury_after,
        "(iii) the genome's reported remaining must match the authoritative balance"
    );

    // ---- (ii) the daemon PERFORMED it for REAL (the mint shows it) ----
    // Query the REAL mint: the proofs the wallet held before the act are now
    // SPENT on the mint, and the wallet balance dropped. This is a real
    // settlement, not a mock (a mock would not move the mint or the wallet).
    use cdk::nuts::State;
    let states = rail
        .wallet()
        .check_proofs_spent(pre_proofs.clone())
        .await
        .expect("query the mint for the pre-act proofs' state");
    let spent_count = states.iter().filter(|s| s.state == State::Spent).count();
    assert!(
        spent_count > 0,
        "(ii) the settle must be REAL: the mint must show at least one of the wallet's input proofs SPENT; \
         none of {} proofs are Spent (a mock would not move the mint)",
        states.len()
    );
    let post_balance = rail
        .wallet()
        .total_balance()
        .await
        .map(u64::from)
        .unwrap_or(0);
    assert!(
        post_balance < funded_balance,
        "(ii) the wallet balance must DROP after the real settle ({funded_balance} -> {post_balance})"
    );
    eprintln!(
        "G5 (ii): REAL settle confirmed: {spent_count} input proof(s) SPENT on the mint ; \
         wallet balance {funded_balance} -> {post_balance} sat"
    );

    // ---- (iv) the VM issued NO raw network for the act ----
    // Linux proves this with the eBPF TAP egress counter. macOS VZ proves the
    // MVP shape structurally by exposing no guest network device at all.
    let ebpf_zero_ceiling = raw_egress_zero_ceiling();
    assert!(
        outcome.raw_egress.passed(ebpf_zero_ceiling),
        "(iv) raw-egress proof must pass; got {}",
        outcome.raw_egress.summary(ebpf_zero_ceiling)
    );
    match &outcome.raw_egress {
        BrokeredRawEgressProof::LinuxTap {
            ebpf_egress_bytes,
            nft_drop,
        } => {
            assert_eq!(*ebpf_egress_bytes, outcome.ebpf_egress_bytes);
            assert_eq!(*nft_drop, outcome.nft_drop);
            eprintln!(
                "G5 (iv): VM TAP egress stayed ~0 during the settle: {ebpf_egress_bytes} bytes \
                 (<= {ebpf_zero_ceiling}); the act left via the daemon HOST networking, not the VM TAP",
            );
        }
        BrokeredRawEgressProof::NoGuestNetworkDevice => {
            assert_eq!(outcome.ebpf_egress_bytes, 0);
            assert_eq!(outcome.nft_drop.packets, 0);
            assert_eq!(outcome.nft_drop.bytes, 0);
            eprintln!(
                "G5 (iv): VZ guest had no network device; raw IP egress was structurally absent, \
                 so the act could only leave through the daemon HOST networking"
            );
        }
    }

    // ---- (v) the genome never received the rail credential ----
    // Structural: the gateway wire types carry NO credential field. The wallet
    // (the credential) lives only host-side, inside the rail. Asserting it on the
    // wire types is the machine-checkable form (a compile-time + value check that
    // the request/receipt the genome speaks have no credential-bearing field).
    assert_no_credential_on_the_wire();
    // The genome did receive the rail's PROOF (the mint preimage) but that is the
    // receipt, not the credential; a non-zero proof length is the real receipt.
    assert!(
        outcome.receipt.proof_len > 0,
        "(v) the genome should receive the rail's receipt (the mint preimage), proof_len > 0; \
         the credential (the wallet) is never on the wire"
    );
    eprintln!(
        "G5 (v): the credential never crosses vsock (the CapabilityRequest/Receipt wire types carry no \
         credential field); the genome got only the rail receipt (proof_len={})",
        outcome.receipt.proof_len
    );

    // The composite G5 pass for the checks the run can see (i, iii, iv).
    assert!(
        outcome.passed(ebpf_zero_ceiling),
        "G5 must pass: authorized+performed AND cost debited == treasury drop AND raw-egress proof passes"
    );

    eprintln!(
        "G5 PASS: the daemon authorized + PERFORMED a REAL ecash settle on the local mint over HOST \
         networking ; cost_sats={} debited ; treasury {} -> {} ; raw_egress={} ; \
         the credential never crossed vsock. Isolation preserved while agency granted (D-6).",
        outcome.receipt.cost_sats,
        outcome.treasury_before,
        outcome.treasury_after,
        outcome.raw_egress.summary(ebpf_zero_ceiling),
    );

    mint.shutdown().await;
}

#[cfg(target_os = "linux")]
fn raw_egress_zero_ceiling() -> u64 {
    kirby_node::egress_run::EBPF_ZERO_CEILING_BYTES
}

#[cfg(target_os = "macos")]
fn raw_egress_zero_ceiling() -> u64 {
    0
}

/// (v) machine-checkable assertion that the gateway wire types carry NO credential
/// field. We construct the exact messages the genome speaks (a SettleEcash
/// `CapabilityRequest` and a `CapabilityReceipt`) and confirm, field by field,
/// that none carries a credential (a seed, a key, proofs, or a wallet handle). The
/// types' fields are fixed at compile time, so this is a structural guarantee: the
/// genome cannot receive the credential because there is nowhere on the wire to
/// put it.
fn assert_no_credential_on_the_wire() {
    use kirby_proto::capability_request::Act;
    use kirby_proto::{CapabilityReceipt, CapabilityRequest, SettleEcash};

    // The request the genome sends: idempotency_key, the act (mint_id, amount,
    // recipient_or_quote), and a budget. No seed / key / proofs field exists.
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
    // Destructure so a future field addition forces this assertion to be revisited
    // (if someone adds a credential field, this stops compiling).
    let CapabilityRequest {
        schema_version: _,
        idempotency_key: _,
        act,
        budget_sats: _,
    } = &req;
    if let Some(Act::SettleEcash(s)) = act {
        let SettleEcash {
            mint_id: _,
            amount: _,
            recipient_or_quote: _,
        } = s;
        // Only a mint id, an amount, and a recipient/quote string: the destination
        // and the intent, never the credential to spend.
    }

    // The receipt the genome receives: an outcome, a cost, the post-debit balance,
    // and the rail's opaque proof. The proof is the rail's RECEIPT (a preimage),
    // not a credential. No seed / key / wallet field exists.
    let receipt = CapabilityReceipt {
        schema_version: 1,
        outcome: 1,
        cost_sats: 0,
        treasury_remaining: 0,
        proof: vec![],
        // The brain-act reply text (empty for an ecash settle); still not a credential.
        completion: vec![],
    };
    let CapabilityReceipt {
        schema_version: _,
        outcome: _,
        cost_sats: _,
        treasury_remaining: _,
        proof: _,
        completion: _,
    } = &receipt;
}

/// A minimal local fakewallet mint fixture: boot a real cdk-mintd HTTP mint with
/// the cdk-fake-wallet Lightning backend on a host port, wait for it to be ready,
/// and shut it down on demand. This mirrors the cdk integration-tests
/// `start_fake_mint` but trimmed to the fakewallet + sqlite features the daemon
/// build uses (no cln/lnd/ldk/bitcoind). cdk-mintd is a dev-dependency, so this
/// fixture is test-only; the daemon never embeds a mint.
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
            let work_dir = TempDir::new(&format!("kirby-g5-mint-{port}"));
            let settings = fake_wallet_settings(port);
            let shutdown = Arc::new(Notify::new());

            // Run the real mint in a background task until the shutdown notify
            // fires. run_mintd_with_shutdown boots the cdk-mintd HTTP mint with the
            // fakewallet backend.
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

            // Wait for the mint to be ready: a wallet's fetch_mint_info succeeds
            // once /v1/info is served. Bounded so a boot failure surfaces.
            wait_ready(port, Duration::from_secs(30)).await?;
            Ok(FakeMint {
                port,
                shutdown,
                handle,
                _work_dir: work_dir,
            })
        }

        /// The mint's base URL.
        pub fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// Signal the mint to shut down and await its task.
        pub async fn shutdown(self) {
            self.shutdown.notify_waiters();
            // Give it a moment to wind down; abort if it lingers.
            let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
        }
    }

    /// Poll a fresh wallet's mint-info call until the mint serves it (ready) or the
    /// deadline elapses.
    async fn wait_ready(port: u16, timeout: Duration) -> anyhow::Result<()> {
        let url = format!("http://127.0.0.1:{port}");
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // A throwaway wallet just to probe /v1/info; cheap to build.
            if let Ok(wallet) = super::mint_rig::build_wallet(&url).await {
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

    /// Build the cdk-mintd settings for a local fakewallet mint on `port`. Mirrors
    /// the cdk integration-tests `create_fake_wallet_settings`, trimmed to the
    /// fakewallet + sqlite features (everything else is `Default`). 0 fees so a
    /// settle's cost equals its amount.
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
            // The fakewallet backend always charges a flat +1 sat actual fee on a
            // payment (cdk-fake-wallet make_payment: total_spent = amount + 1), so
            // the melt must reserve at least 1 sat or the mint rejects it as
            // under-reserved. A 1-sat minimum reserve (0% relative) matches the
            // cdk integration-tests fake mint and makes a small settle succeed with
            // no change. The genome's settled amount (cost) is unaffected by the
            // reserve; the reserve covers the fake's flat fee.
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
            // database defaults to sqlite; everything else (mint_info, limits,
            // quotas, auth, agicash, onchain, grpc_processor) defaults.
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
