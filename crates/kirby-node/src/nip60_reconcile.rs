//! NIP-60 reconcile-IMPORT (N2): pull an agent's relay-backed candidate proofs into the live
//! cdk wallet — NUT-07-gated, FAIL-CLOSED, and NOVEL-ONLY.
//!
//! NIP-60 buys PORTABILITY, not safety: relay-stored token state is a durable encrypted backup,
//! NEVER a spend decision (see [`crate::nip60`]). This module is the READ-BACK — it takes the
//! candidate proofs [`crate::nip60::Nip60Store::reconcile_on_load`] aggregated from the relays and
//! adopts ONLY the ones the MINT confirms UNSPENT (NUT-07), importing them through a wallet swap
//! (`receive_proofs`, which re-verifies at the mint and re-issues fresh proofs the wallet owns).
//!
//! Two money-safety properties, both toothed:
//!   - FAIL-CLOSED: if the mint's NUT-07 check errors (mint unreachable), NOTHING is imported — an
//!     unverified proof is never adopted as spendable, because it might already be spent (adopting
//!     it would credit phantom balance and later overdraft). Every error path aborts the import.
//!   - NOVEL-ONLY: a candidate whose Y the wallet already tracks is skipped, so a normal reboot
//!     (relay == local) imports nothing — no needless swap-churn / NUT-13 counter burn. Only a
//!     fresh-store takeover, whose local wallet lacks the proofs, actually pulls them in.
//!
//! ⚠️ ORDER (counter safety): `receive_proofs` derives its swap-output secrets from the NUT-13
//! per-keyset counter. On a fresh-store restore the counter MUST be fast-forwarded to the loaded
//! floor BEFORE this import runs, or the swap re-derives already-spent secrets → collision. That
//! fast-forward happens at wallet-open (`mint_rig::open_persistent_wallet` →
//! `Nip60CounterDb::fast_forward_inner_to_floor`), which precedes this boot-time import; this
//! module is the import MECHANISM only.

use async_trait::async_trait;
use cdk::nuts::{Proof, ProofState, PublicKey, State};

/// The wallet operations the reconcile-import needs, behind a seam so the orchestration is
/// unit-testable without a live mint. [`cdk::Wallet`] is the production impl.
#[async_trait]
pub trait ReconcileWallet: Send + Sync {
    /// The Y's of EVERY proof the wallet already tracks (any state) — the novel-only gate reads
    /// this to skip candidates the wallet already holds.
    async fn known_ys(&self) -> anyhow::Result<Vec<PublicKey>>;
    /// NUT-07 check-state against the MINT. FAIL-CLOSED contract: an `Err` (mint unreachable) MUST
    /// abort the import so the caller adopts nothing rather than trust an unverified proof.
    async fn check_states(&self, proofs: Vec<Proof>) -> anyhow::Result<Vec<ProofState>>;
    /// Import proofs into the wallet (a mint swap: re-verifies unspent + re-issues fresh proofs the
    /// wallet controls). Returns the sats imported.
    async fn import_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<u64>;
}

/// Drop candidates whose Y the wallet already tracks (the novel-only gate). PURE. A proof whose Y
/// cannot be computed is dropped — an unusable proof is never importable.
fn novel_only(candidates: &[Proof], known_ys: &[PublicKey]) -> Vec<Proof> {
    candidates
        .iter()
        .filter(|p| match p.y() {
            Ok(y) => !known_ys.contains(&y),
            Err(_) => false,
        })
        .cloned()
        .collect()
}

/// Keep only proofs the mint reports UNSPENT (NUT-07). A proof with NO matching state entry, or
/// any non-Unspent state (Spent / Pending / Reserved / PendingSpent), is DROPPED. PURE. Pairs each
/// proof to its state by Y (not by list order — the mint's response order is not contractual).
fn keep_unspent(proofs: &[Proof], states: &[ProofState]) -> Vec<Proof> {
    proofs
        .iter()
        .filter(|p| match p.y() {
            Ok(y) => states.iter().any(|s| s.y == y && s.state == State::Unspent),
            Err(_) => false,
        })
        .cloned()
        .collect()
}

/// Reconcile-import (N2): adopt the relay-backed `candidates` into the wallet, NUT-07-gated,
/// FAIL-CLOSED and NOVEL-ONLY. Returns the sats imported (0 = nothing new / all already known /
/// none unspent). ANY mint or store error aborts with `Err` and imports nothing.
pub async fn reconcile_import(
    candidates: Vec<Proof>,
    wallet: &dyn ReconcileWallet,
) -> anyhow::Result<u64> {
    if candidates.is_empty() {
        return Ok(0);
    }
    // Novel-only: a proof the wallet already tracks is skipped (a normal reboot imports nothing).
    let known = wallet.known_ys().await?;
    let novel = novel_only(&candidates, &known);
    if novel.is_empty() {
        return Ok(0);
    }
    // FAIL-CLOSED: a mint error here propagates — we adopt nothing rather than trust an unverified
    // proof. Only proofs the mint confirms UNSPENT survive.
    let states = wallet.check_states(novel.clone()).await?;
    let importable = keep_unspent(&novel, &states);
    if importable.is_empty() {
        return Ok(0);
    }
    wallet.import_proofs(importable).await
}

/// Boot-time restore-from-backup: fetch the relay-backed candidate proofs and reconcile-import
/// them, DEGRADING (log + continue, return 0) on ANY error so an unreachable mint/relay never
/// fails boot — the downstream solvency check is the money gate (a fresh box that could not restore
/// has too low a balance and dies-broke, correctly). Returns the sats imported.
///
/// `candidates` is the result of [`crate::nip60::Nip60Store::reconcile_on_load`]; the caller passes
/// it in so this stays free of the relay transport and unit-testable. SAFE to call unconditionally
/// at boot: novel-only makes a normal reboot (relay == local) a no-op, and the mint-swap in
/// `import_proofs` is the single-writer arbiter — a lost double-restore race fails-closed here
/// (Err → degrade → 0), never corrupting local state.
pub async fn restore_from_relay_backup(
    candidates: anyhow::Result<Vec<Proof>>,
    wallet: &dyn ReconcileWallet,
) -> u64 {
    let candidates = match candidates {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "NIP-60 restore: relay fetch failed; booting on local wallet state");
            return 0;
        }
    };
    match reconcile_import(candidates, wallet).await {
        Ok(imported) => {
            if imported > 0 {
                tracing::info!(
                    imported_sats = imported,
                    "NIP-60 restore: imported proofs from the relay backup"
                );
            }
            imported
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "NIP-60 restore: import failed (mint unreachable or a lost restore-race); booting on local wallet state"
            );
            // A failed `receive_proofs` may leave an incomplete cdk receive-saga (reserved inputs +
            // stored blinded messages). We DELIBERATELY do NOT compensate it here. cdk's saga
            // recovery is designed to run once at STARTUP (boot step 2, `recover_sagas_within`);
            // running it in this Err arm — immediately after an ambiguous mint error — risks
            // compensating a swap whose request is still IN FLIGHT: the inputs read Unspent now, cdk
            // deletes the saga (and its blinded-message recovery data), then the mint commits the
            // swap, stranding the outputs. The reserved inputs are NOT spendable (Reserved, not
            // Unspent), so they never inflate the solvency check; the saga is safely recovered at the
            // next boot, once the mint has settled. Degrade to 0 and boot on durable local state.
            0
        }
    }
}

/// The production [`ReconcileWallet`]: the funded treasury `cdk::Wallet`. All ops are the daemon's
/// own host networking to the mint; nothing crosses vsock. `receive_proofs` is the saga-backed
/// swap-import (crash-recoverable); `check_proofs_spent` is the NUT-07 check-state.
#[async_trait]
impl ReconcileWallet for cdk::Wallet {
    async fn known_ys(&self) -> anyhow::Result<Vec<PublicKey>> {
        // Every proof this wallet tracks, ANY state (None = no state filter): a proof the wallet
        // already holds — even one it has marked spent — must not be re-imported.
        let proofs = self
            .get_proofs_with(None, None)
            .await
            .map_err(|e| anyhow::anyhow!("read wallet proofs for the novel-only gate: {e}"))?;
        let mut ys = Vec::with_capacity(proofs.len());
        for p in &proofs {
            ys.push(p.y().map_err(|e| anyhow::anyhow!("compute a tracked proof's Y: {e}"))?);
        }
        Ok(ys)
    }

    async fn check_states(&self, proofs: Vec<Proof>) -> anyhow::Result<Vec<ProofState>> {
        // NUT-07 against the mint. An Err (mint unreachable) is the FAIL-CLOSED trigger upstream.
        self.check_proofs_spent(proofs)
            .await
            .map_err(|e| anyhow::anyhow!("NUT-07 check-state (fail-closed on mint error): {e}"))
    }

    async fn import_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<u64> {
        // A mint swap: re-verifies the proofs unspent (belt-and-suspenders with check_states) and
        // re-issues fresh proofs the wallet controls. Uses the NUT-13 counter (see the module
        // ORDER note: on a takeover the counter must be fast-forwarded first, N5).
        let amount = self
            .receive_proofs(proofs, cdk::wallet::ReceiveOptions::default(), None, None)
            .await
            .map_err(|e| anyhow::anyhow!("receive_proofs (reconcile-import swap): {e}"))?;
        Ok(amount.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A dummy-but-distinct cdk `Proof` (the same NUT-00-JSON idiom the `nip60` teeth use): a valid
    /// `C` (the secp256k1 generator) and keyset id, with distinctness — and thus a distinct `y()` —
    /// from `secret`. cdk `Proof` serde is its own tested concern; we only need distinct proofs.
    fn dummy_proof(secret: &str) -> Proof {
        let json = format!(
            r#"{{"amount":1,"id":"00ad268c4d1f5826","secret":"{secret}","C":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}}"#
        );
        serde_json::from_str(&json).expect("dummy proof JSON deserializes")
    }

    fn y_of(p: &Proof) -> PublicKey {
        p.y().expect("proof Y")
    }

    fn unspent(p: &Proof) -> ProofState {
        ProofState::from((y_of(p), State::Unspent))
    }

    fn spent(p: &Proof) -> ProofState {
        ProofState::from((y_of(p), State::Spent))
    }

    /// A programmable [`ReconcileWallet`]: fixed known Y's, a NUT-07 verdict (`Some(states)` or
    /// `None` to model a mint-down = the fail-closed path), and a record of what got imported.
    struct StubWallet {
        known: Vec<PublicKey>,
        states: Option<Vec<ProofState>>,
        import_err: bool,
        imported: Mutex<Option<Vec<Proof>>>,
    }

    impl StubWallet {
        fn new(known: Vec<PublicKey>, states: Option<Vec<ProofState>>) -> Self {
            StubWallet { known, states, import_err: false, imported: Mutex::new(None) }
        }
        /// Model a FAILED import swap — e.g. the double-restore-race LOSER whose proofs the mint
        /// already spent for the winner. Records nothing (no partial adoption).
        fn failing_import(mut self) -> Self {
            self.import_err = true;
            self
        }
        fn imported(&self) -> Option<Vec<Proof>> {
            self.imported.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ReconcileWallet for StubWallet {
        async fn known_ys(&self) -> anyhow::Result<Vec<PublicKey>> {
            Ok(self.known.clone())
        }
        async fn check_states(&self, _proofs: Vec<Proof>) -> anyhow::Result<Vec<ProofState>> {
            match &self.states {
                Some(s) => Ok(s.clone()),
                None => anyhow::bail!("mint unreachable (fail-closed test)"),
            }
        }
        async fn import_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<u64> {
            // Bail BEFORE recording, so a failed swap (race loser) leaves NO partial adoption.
            anyhow::ensure!(!self.import_err, "import swap failed (e.g. a lost restore-race)");
            let n = proofs.len() as u64;
            *self.imported.lock().unwrap() = Some(proofs);
            Ok(n)
        }
    }

    /// Tooth (a): the NUT-07 gate imports ONLY the unspent candidate and drops the spent one.
    #[tokio::test]
    async fn imports_only_the_unspent_candidate_and_drops_the_spent_one() {
        let p_unspent = dummy_proof("u");
        let p_spent = dummy_proof("s");
        // Nothing known locally → both are novel; the mint reports one unspent, one spent.
        let wallet = StubWallet::new(vec![], Some(vec![unspent(&p_unspent), spent(&p_spent)]));
        let imported = reconcile_import(vec![p_unspent.clone(), p_spent.clone()], &wallet)
            .await
            .expect("reconcile ok");
        assert_eq!(imported, 1, "only the UNSPENT candidate imports");
        let got = wallet.imported().expect("import was called");
        assert_eq!(got.len(), 1);
        assert_eq!(
            y_of(&got[0]),
            y_of(&p_unspent),
            "the imported proof is the unspent one, not the spent one"
        );
    }

    /// Tooth (b): FAIL-CLOSED — a mint-check error aborts with `Err` and imports NOTHING.
    #[tokio::test]
    async fn fails_closed_and_imports_nothing_when_the_mint_check_errors() {
        let p = dummy_proof("x");
        // `None` states → check_states errors, modelling an unreachable mint.
        let wallet = StubWallet::new(vec![], None);
        let res = reconcile_import(vec![p], &wallet).await;
        assert!(res.is_err(), "a mint-check error MUST abort the import (fail-closed)");
        assert!(
            wallet.imported().is_none(),
            "NOTHING may be imported when the mint is unreachable"
        );
    }

    /// Tooth (c): NOVEL-ONLY — candidates the wallet already tracks import nothing (a normal reboot
    /// with relay == local causes no swap-churn), and the mint is never even consulted.
    #[tokio::test]
    async fn imports_nothing_when_every_candidate_is_already_known() {
        let p1 = dummy_proof("a");
        let p2 = dummy_proof("b");
        // Both Y's already tracked; even though the mint WOULD call them unspent, none is novel.
        let wallet = StubWallet::new(
            vec![y_of(&p1), y_of(&p2)],
            Some(vec![unspent(&p1), unspent(&p2)]),
        );
        let imported = reconcile_import(vec![p1, p2], &wallet)
            .await
            .expect("reconcile ok");
        assert_eq!(imported, 0, "a normal reboot (relay == local) imports nothing");
        assert!(wallet.imported().is_none(), "no import call when nothing is novel");
    }

    /// Property 1 (partial relay state): a mix of already-known + novel candidates imports ONLY
    /// the novel UNSPENT ones — the known proof (e.g. one mid-saga) is skipped (no double-count),
    /// the novel spent one is dropped.
    #[tokio::test]
    async fn partial_state_imports_only_novel_unspent_and_skips_known() {
        let known = dummy_proof("known");
        let novel_unspent = dummy_proof("novel_u");
        let novel_spent = dummy_proof("novel_s");
        // Wallet already tracks `known`; the mint verdicts cover only the novel two (known is
        // skipped pre-check by the novel-only gate).
        let wallet = StubWallet::new(
            vec![y_of(&known)],
            Some(vec![unspent(&novel_unspent), spent(&novel_spent)]),
        );
        let imported = reconcile_import(
            vec![known, novel_unspent.clone(), novel_spent],
            &wallet,
        )
        .await
        .expect("reconcile ok");
        assert_eq!(imported, 1, "only the novel UNSPENT proof imports");
        let got = wallet.imported().expect("import called");
        assert_eq!(got.len(), 1);
        assert_eq!(y_of(&got[0]), y_of(&novel_unspent), "the known proof was skipped, not re-imported");
    }

    /// Property 2 (graceful): a FAILED import swap (the double-restore-race loser) surfaces as Err
    /// with NO partial adoption — reconcile_import never half-commits.
    #[tokio::test]
    async fn a_failed_import_swap_propagates_gracefully_without_partial_state() {
        let p = dummy_proof("race");
        let wallet = StubWallet::new(vec![], Some(vec![unspent(&p)])).failing_import();
        let res = reconcile_import(vec![p], &wallet).await;
        assert!(res.is_err(), "a failed import swap (lost restore-race) surfaces as Err");
        assert!(wallet.imported().is_none(), "a failed import adopts nothing (no partial state)");
    }

    /// Boot tooth (happy): a fresh box restores its proofs from the relay backup.
    #[tokio::test]
    async fn boot_restore_imports_from_the_relay_backup() {
        let p = dummy_proof("restore");
        let wallet = StubWallet::new(vec![], Some(vec![unspent(&p)]));
        let restored = restore_from_relay_backup(Ok(vec![p]), &wallet).await;
        assert_eq!(restored, 1, "a fresh box restores its proofs from the relay backup");
        assert_eq!(wallet.imported().map(|v| v.len()), Some(1));
    }

    /// Boot tooth (degrade): a relay-FETCH error degrades to 0 (boot continues; solvency is the
    /// real gate) — never fails boot, never imports.
    #[tokio::test]
    async fn boot_restore_degrades_to_zero_when_the_relay_fetch_fails() {
        let wallet = StubWallet::new(vec![], Some(vec![]));
        let restored =
            restore_from_relay_backup(Err(anyhow::anyhow!("relay unreachable")), &wallet).await;
        assert_eq!(restored, 0, "a relay-fetch error degrades to 0 (boot continues)");
        assert!(wallet.imported().is_none(), "no import on a fetch failure");
    }

    /// Boot tooth (double-restore-race fail-closed): the race LOSER's swap fails → degrade to 0,
    /// GRACEFULLY — no crash, no state corruption, boot continues on local state.
    #[tokio::test]
    async fn boot_restore_degrades_gracefully_when_a_restore_race_is_lost() {
        let p = dummy_proof("lost_race");
        let wallet = StubWallet::new(vec![], Some(vec![unspent(&p)])).failing_import();
        let restored = restore_from_relay_backup(Ok(vec![p]), &wallet).await;
        assert_eq!(restored, 0, "the race LOSER degrades to 0 — no crash, boot continues");
        assert!(wallet.imported().is_none(), "the loser adopts nothing (no state corruption)");
    }

    /// Boot tooth (normal reboot no-op): relay == local → every candidate is already known →
    /// nothing imported, the mint is never consulted.
    #[tokio::test]
    async fn boot_restore_is_a_noop_on_a_normal_reboot() {
        let p1 = dummy_proof("a");
        let p2 = dummy_proof("b");
        let wallet = StubWallet::new(
            vec![y_of(&p1), y_of(&p2)],
            Some(vec![unspent(&p1), unspent(&p2)]),
        );
        let restored = restore_from_relay_backup(Ok(vec![p1, p2]), &wallet).await;
        assert_eq!(restored, 0, "a normal reboot imports nothing (novel-only no-op)");
        assert!(wallet.imported().is_none());
    }
}
