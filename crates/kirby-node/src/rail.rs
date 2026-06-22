//! The brokered-act rail (spec 3.2 step 4, D-6, D-11, D-16, D-18, D-20).
//!
//! The `perform` step of the authorize order: the DAEMON performs the act using
//! a host-held rail credential the genome never sees (settle ecash on the local
//! mint, pay a regtest LN invoice, or make a paid HTTP call). The genome NEVER
//! receives the credential: a `Rail` impl holds it internally and exposes only
//! `estimate` and `perform`. Nothing the rail holds crosses vsock (the gateway
//! wire types carry no credential field, gate G5(v)).
//!
//! Two impls:
//! - [`MockRail`]: a deterministic mock that fabricates a receipt and a natural
//!   cost. It backs the C-3 gateway/treasury unit tests (the spec 3.2 authorize
//!   order, the D-20 cap, never-overspend) WITHOUT a real rail.
//! - [`CdkEcashRail`]: the C-6 real rail (D-16). It holds a funded `cdk::Wallet`
//!   (the host-only credential) and SETTLES ecash by melting against the LOCAL
//!   fakewallet mint over HOST networking. The melt consumes the wallet's proofs
//!   (they are spent on the mint, the real settlement) and returns the mint's
//!   payment preimage as the receipt (D-18, the rail carries its own real proof,
//!   no stub signer). The VM issues no raw network for this; it goes out the
//!   daemon's own host networking (gate G5(iv)).
//!
//! D-20 (the never-overspend-after-perform refinement) is enforced HERE: every
//! `perform` takes a `cap_sats` and MUST cap the actual spend at it, so
//! `actual <= estimate <= treasury_remaining`. The real rail clamps the melt
//! amount to the cap BEFORE settling, so the mint can never debit past what the
//! gateway's pre-perform budget gate checked; the mock clamps its natural cost.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kirby_proto::capability_request::Act;
use kirby_proto::{ChatMessage, Memory, MemoryOp, MemoryResult, WriteStatus};

/// The fixed allowlist sentinel for a [`Act::Completion`] (brain-stub R2). The
/// allowlist step calls the free fn [`destination`] (it has no `[brain]`/
/// `CompositeRail` access, and a Completion has no endpoint field), so the
/// brain's "destination" is this constant. A brain-mode gateway allowlists
/// EXACTLY this string. The real `RoutstrBrain` (later) maps the sentinel to its
/// pinned host INSIDE the backend, so this destination/allowlist API never
/// changes when the real backend swaps in.
pub const BRAIN_COMPLETION_DESTINATION: &str = "brain.completion";

/// The fixed allowlist sentinel for an [`Act::Memory`] (durable-mind-state). Like the
/// brain's completion sentinel, a Memory act has no endpoint field, so its "destination"
/// is this constant. A memory-mode gateway allowlists EXACTLY this string. The real
/// `EngramStore` (Chunk-2) maps the sentinel to its nerve relay set INSIDE the backend,
/// so this destination/allowlist API never changes when the real backend swaps in.
pub const MEMORY_DESTINATION: &str = "memory.store";

/// The allowlist key for an act: the destination the daemon would reach. The
/// gateway allowlist step (spec step 2) matches this against its static set.
/// For a BOLT11 invoice the "destination" is the node it pays; the spike does
/// not parse BOLT11, so the invoice string itself is the key (the allowlist
/// holds the exact invoice or its node id as configured). For ecash it is the
/// mint id; for paid HTTP it is the URL host. A Completion has no endpoint field,
/// so its destination is the fixed [`BRAIN_COMPLETION_DESTINATION`] sentinel
/// (brain-stub R2).
pub fn destination(act: &Act) -> String {
    match act {
        Act::PayInvoice(p) => p.bolt11.clone(),
        Act::SettleEcash(s) => s.mint_id.clone(),
        Act::PaidHttp(h) => host_of(&h.url),
        Act::Completion(_) => BRAIN_COMPLETION_DESTINATION.to_string(),
        // A Memory act has no endpoint field; its destination is the fixed sentinel
        // (durable-mind-state), allowlisted exactly in memory mode.
        Act::Memory(_) => MEMORY_DESTINATION.to_string(),
    }
}

/// Extract the host from a URL for allowlist matching. Best-effort: takes the
/// authority between "scheme://" and the next "/" (or "?"), dropping any
/// userinfo and port. A URL with no scheme is treated as host-only.
fn host_of(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port)
        .to_string()
}

/// The per-act budget ceiling the genome attached to the act itself
/// (`max_fee_sats` / `max_cost_sats`). The gateway uses this as part of the
/// estimate cap. Ecash carries no per-act max in the schema, so its amount is
/// the natural cost.
pub fn act_max_sats(act: &Act) -> Option<u64> {
    match act {
        Act::PayInvoice(p) => Some(p.max_fee_sats),
        Act::PaidHttp(h) => Some(h.max_cost_sats),
        Act::SettleEcash(_) => None,
        // The Completion's per-call cap IS its estimate (brain-stub R5): the LLM
        // cost is unknown pre-call, so the genome-declared cap bounds it.
        Act::Completion(c) => Some(c.max_cost_sats),
        // Exhaustiveness only: a Memory act does NOT flow through the generic budget
        // gate (the gateway forks `Act::Memory` to its own metering path -- free reads,
        // host-computed writes that are NEVER clamped to this ceiling, design doc 12
        // G2/G3). This value is the caller's write ceiling, returned for completeness;
        // the generic clamp-to-act-max path is never reached for memory.
        Act::Memory(m) => Some(m.max_cost_sats),
    }
}

/// The outcome of a rail `perform`.
pub enum RailOutcome {
    /// The act was performed; `actual_cost` is what to debit (already capped at
    /// `cap_sats`, D-20) and `proof` is the rail's own receipt (ecash settle
    /// preimage, LN preimage, HTTP status+body hash; possibly empty for non-rail,
    /// D-18). `completion` is the assistant reply TEXT for a [`Act::Completion`]
    /// (brain-stub), empty for every other act -- it is the words the brain needs
    /// back, plumbed into `CapabilityReceipt.completion` and persisted in the
    /// ledger so a resume-replay returns it verbatim.
    Performed {
        actual_cost: u64,
        proof: Vec<u8>,
        completion: Vec<u8>,
    },
    /// The upstream rail failed; nothing was spent (the gateway debits 0 and
    /// returns UPSTREAM_FAILED).
    UpstreamFailed,
}

/// The brokered-act rail the daemon performs through. Implementors hold the
/// host-only credential; the genome never sees it. The methods are async because
/// the real rail (CdkEcashRail) settles over the network (a melt against the
/// mint); the mock satisfies the same async shape with an immediate result.
#[async_trait::async_trait]
pub trait Rail: Send + Sync {
    /// The pre-perform cost estimate for `act` (spec step 3, the budget gate
    /// input). Conservative: the gateway refuses if this exceeds the budget or
    /// the treasury, so an under-estimate that later overshoots is still capped
    /// at the estimate by `perform` (D-20).
    fn estimate(&self, act: &Act) -> u64;

    /// Perform `act`, capping the actual spend at `cap_sats` (D-20). Returns the
    /// capped actual cost and the rail receipt. MUST NOT spend more than
    /// `cap_sats` regardless of the rail's natural cost.
    async fn perform(&self, act: &Act, cap_sats: u64) -> RailOutcome;
}

/// A deterministic mock rail for the C-3 gateway/treasury unit tests (the real
/// rail is [`CdkEcashRail`]). It fabricates a receipt and a natural cost, records
/// every perform call (so a DENIED path can be asserted to have performed
/// nothing, gate G3a), and can be told to overshoot its estimate so a test can
/// prove the D-20 cap actually clamps.
#[derive(Clone)]
pub struct MockRail {
    /// How many times `perform` was actually invoked. A DENIED request must
    /// leave this unchanged (G3a: no act performed on a denial).
    perform_calls: Arc<AtomicU64>,
    /// Extra sats the rail's natural cost adds on top of the estimate, to model
    /// a rail overshoot. With `overshoot > 0` the natural cost exceeds the
    /// estimate, so the test sees the D-20 cap take effect.
    overshoot: u64,
    /// If true, `perform` reports UPSTREAM_FAILED (to exercise that path).
    fail_upstream: bool,
}

impl Default for MockRail {
    fn default() -> Self {
        MockRail {
            perform_calls: Arc::new(AtomicU64::new(0)),
            overshoot: 0,
            fail_upstream: false,
        }
    }
}

impl MockRail {
    /// A faithful mock: natural cost equals the estimate, never fails.
    pub fn new() -> Self {
        Self::default()
    }

    /// A mock whose natural cost exceeds its estimate by `overshoot` sats, used
    /// to prove the D-20 cap clamps actual spend to the estimate.
    pub fn overshooting(overshoot: u64) -> Self {
        MockRail { overshoot, ..Self::default() }
    }

    /// A mock whose upstream always fails (the gateway debits 0).
    pub fn failing() -> Self {
        MockRail { fail_upstream: true, ..Self::default() }
    }

    /// How many times `perform` was actually invoked.
    pub fn perform_count(&self) -> u64 {
        self.perform_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Rail for MockRail {
    fn estimate(&self, act: &Act) -> u64 {
        // The mock's estimate is the act's intrinsic amount: the ecash amount,
        // or the genome's declared per-act max for the fee-bearing acts (and the
        // Completion's per-call cap, brain-stub R5).
        match act {
            Act::SettleEcash(s) => s.amount,
            Act::PayInvoice(p) => p.max_fee_sats,
            Act::PaidHttp(h) => h.max_cost_sats,
            Act::Completion(c) => c.max_cost_sats,
            // Exhaustiveness only: a Memory act never routes through this rail (the
            // gateway performs memory through its own MemoryBackend path), so this arm
            // exists to satisfy the match; the value is the caller's write ceiling.
            Act::Memory(m) => m.max_cost_sats,
        }
    }

    async fn perform(&self, act: &Act, cap_sats: u64) -> RailOutcome {
        self.perform_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_upstream {
            return RailOutcome::UpstreamFailed;
        }
        let natural = self.estimate(act).saturating_add(self.overshoot);
        // D-20: never spend past the cap, even if the rail overshoots.
        let actual_cost = natural.min(cap_sats);
        let proof = format!("mock-receipt:{}:cost={actual_cost}", destination(act)).into_bytes();
        // The mock is not a brain; a Completion on it carries no reply text (a
        // brain-mode run uses CompositeRail, which routes Completion to the
        // BrainBackend, never to this mock base).
        RailOutcome::Performed { actual_cost, proof, completion: Vec::new() }
    }
}

/// The C-6 real rail (D-16): settle ecash on the LOCAL fakewallet mint by melting
/// against it over HOST networking, using a funded `cdk::Wallet` as the host-only
/// credential the genome never sees.
///
/// HOW PERFORM SETTLES (the real act, gate G5(ii)): a SettleEcash act melts
/// `min(amount, cap_sats)` sats from the wallet toward the mint. The rail builds a
/// fake BOLT11 invoice for that amount (the fakewallet backend marks it Paid), runs
/// the melt (`melt_quote` then `prepare_melt` then `confirm`), and the mint CONSUMES
/// the wallet's input proofs (they become spent on the mint, observable via
/// `check_proofs_spent` and a dropped `total_balance`, the real settlement). The
/// melt returns the mint's payment preimage, which the rail returns as the receipt
/// (D-18, the rail carries its own real proof; no stub signer). All of this is the
/// DAEMON's own host networking to the mint URL; the VM TAP sees no bytes for it
/// (gate G5(iv)). The wallet (its seed and proofs) lives only host-side and is
/// never serialized across vsock (gate G5(v)).
///
/// D-20: the melt amount is clamped to `cap_sats` BEFORE settling, and the debited
/// `actual_cost` is the melt's reported amount clamped again at `cap_sats`, so the
/// mint can never debit the treasury past what the gateway's budget gate checked.
pub struct CdkEcashRail {
    /// The funded wallet: the host-only credential. It holds the seed and the
    /// ecash proofs; the genome never sees it (it is not on any gateway message).
    wallet: Arc<cdk::Wallet>,
    /// The mint id this rail settles against (its URL). The gateway allowlist
    /// (spec step 2) must contain this for the act to authorize; the rail also
    /// refuses an act whose mint_id is not this mint (defense in depth, a wrong
    /// destination is an upstream failure, not a silent settle elsewhere).
    mint_id: String,
    /// How many times `perform` actually settled (a clean direct counter, the
    /// MockRail shape). The C-11 full-loop reads this to prove the brokered act was
    /// performed EXACTLY ONCE across a snapshot+resume (1 -> 1): a deduped re-issue
    /// short-circuits in the gateway BEFORE the rail, so this never reaches 2. It is
    /// host-side diagnostics; it has no path to the treasury and is never on the wire.
    perform_count: Arc<AtomicU64>,
}

impl CdkEcashRail {
    /// Build the real rail from a funded wallet and the mint id (URL) it settles
    /// against. The wallet must already hold spendable proofs (funded via
    /// [`fund_wallet`]); this rail only SPENDS them, never tops up.
    pub fn new(wallet: Arc<cdk::Wallet>, mint_id: String) -> Self {
        CdkEcashRail { wallet, mint_id, perform_count: Arc::new(AtomicU64::new(0)) }
    }

    /// How many times this rail actually settled (the count of `perform` calls that
    /// reached the settle, the MockRail shape). The C-11 full-loop reads this to prove
    /// the brokered act was performed EXACTLY ONCE across the move (1 -> 1).
    pub fn perform_count(&self) -> u64 {
        self.perform_count.load(Ordering::SeqCst)
    }

    /// The mint id (URL) this rail settles against (the allowlist destination).
    pub fn mint_id(&self) -> &str {
        &self.mint_id
    }

    /// The funded wallet (the host-only credential). Exposed so the G5 test can
    /// observe the REAL settlement against the mint (the wallet balance drops and
    /// `check_proofs_spent` shows the proofs spent ON THE MINT, gate G5(ii)). This
    /// is host-side only; the wallet is never exposed to the genome.
    pub fn wallet(&self) -> &Arc<cdk::Wallet> {
        &self.wallet
    }

    /// The wallet's current total spendable balance (host-side, for the G5 test to
    /// observe the drop after a settle). This is the CREDENTIAL's balance; it is
    /// never exposed to the genome.
    pub async fn wallet_balance_sats(&self) -> u64 {
        self.wallet
            .total_balance()
            .await
            .map(u64::from)
            .unwrap_or(0)
    }

    /// Settle `spend` sats from the wallet toward the mint by melting a fake
    /// BOLT11 invoice the fakewallet backend marks Paid. Returns the melt's
    /// reported spent amount and the mint's payment preimage (the receipt). The
    /// melt consumes the wallet's proofs (the real settlement, spent on the mint).
    async fn settle_ecash(&self, spend: u64) -> anyhow::Result<(u64, Vec<u8>)> {
        use cdk::nuts::{MeltQuoteState, PaymentMethod};
        use cdk_fake_wallet::{create_fake_invoice, FakeInvoiceDescription};

        // The fakewallet backend reads this JSON from the invoice description and
        // drives the melt to Paid (a real preimage), modelling a successful
        // settlement. amount in millisats for the fake invoice (sats * 1000).
        let description = FakeInvoiceDescription {
            pay_invoice_state: MeltQuoteState::Paid,
            check_payment_state: MeltQuoteState::Paid,
            pay_err: false,
            check_err: false,
        };
        let invoice = create_fake_invoice(
            spend.saturating_mul(1000),
            serde_json::to_string(&description)?,
        );

        // Melt against the LOCAL mint over the daemon's HOST networking. This is
        // the real settle: melt_quote reserves, prepare_melt selects the wallet's
        // input proofs, confirm spends them on the mint and returns the preimage.
        let melt_quote = self
            .wallet
            .melt_quote(PaymentMethod::BOLT11, invoice.to_string(), None, None)
            .await
            .map_err(|e| anyhow::anyhow!("melt_quote against the mint failed: {e}"))?;
        let prepared = self
            .wallet
            .prepare_melt(&melt_quote.id, std::collections::HashMap::new())
            .await
            .map_err(|e| anyhow::anyhow!("prepare_melt failed: {e}"))?;
        let melt = prepared
            .confirm()
            .await
            .map_err(|e| anyhow::anyhow!("melt confirm (settle) failed: {e}"))?;

        // The amount actually melted (spent toward the mint), plus the mint's
        // payment preimage as the receipt (D-18). amount() is in sats.
        let spent: u64 = melt.amount().into();
        // The rail's receipt is the mint's payment preimage. A real Lightning melt
        // carries one; the local fakewallet backend returns an EMPTY preimage
        // string (it does not simulate a preimage), so treat an empty (or absent)
        // preimage as "settled" and fall back to a settle-fact receipt keyed by the
        // quote id (D-18 allows the rail's own receipt to be the proof or, absent a
        // preimage, a status fact). The receipt is never empty: the settle DID
        // happen (the proofs are spent on the mint), so the genome gets a real
        // settle fact, never the credential.
        let preimage = match melt.payment_proof() {
            Some(p) if !p.is_empty() => p.as_bytes().to_vec(),
            _ => format!("settled:{}:amount={spent}", melt.quote_id()).into_bytes(),
        };
        Ok((spent, preimage))
    }
}

#[async_trait::async_trait]
impl Rail for CdkEcashRail {
    fn estimate(&self, act: &Act) -> u64 {
        // The natural cost of a settle is its amount; other act variants are not
        // this rail's job (the gateway's allowlist keeps them off this rail in
        // the spike, and perform refuses them as upstream failures).
        match act {
            Act::SettleEcash(s) => s.amount,
            Act::PayInvoice(p) => p.max_fee_sats,
            Act::PaidHttp(h) => h.max_cost_sats,
            Act::Completion(c) => c.max_cost_sats,
            // Exhaustiveness only: a Memory act never routes through this rail (the
            // gateway performs memory through its own MemoryBackend path), so this arm
            // exists to satisfy the match; the value is the caller's write ceiling.
            Act::Memory(m) => m.max_cost_sats,
        }
    }

    async fn perform(&self, act: &Act, cap_sats: u64) -> RailOutcome {
        let Act::SettleEcash(settle) = act else {
            // This rail only settles ecash; any other act on it is an upstream
            // failure (no spend), not a settle elsewhere.
            tracing::warn!("CdkEcashRail asked to perform a non-ecash act; refusing");
            return RailOutcome::UpstreamFailed;
        };
        // Defense in depth: refuse a mint_id that is not this rail's mint (the
        // gateway allowlist already gates the destination; this stops a settle
        // against an unexpected mint even if the allowlist were misconfigured).
        if settle.mint_id != self.mint_id {
            tracing::warn!(
                requested = %settle.mint_id,
                rail_mint = %self.mint_id,
                "CdkEcashRail asked to settle against a different mint; refusing"
            );
            return RailOutcome::UpstreamFailed;
        }

        // D-20: clamp the spend to the cap BEFORE settling, so the mint can never
        // debit past what the gateway's budget gate checked.
        let spend = settle.amount.min(cap_sats);
        if spend == 0 {
            return RailOutcome::UpstreamFailed;
        }

        match self.settle_ecash(spend).await {
            Ok((spent, preimage)) => {
                // Count the actual settle (the C-11 perform-once evidence, 1 -> 1 across
                // a move; a deduped re-issue never reaches here).
                self.perform_count.fetch_add(1, Ordering::SeqCst);
                // The actual cost is the melt's reported spend, clamped at the cap
                // again (the melt should already be <= spend <= cap; the clamp is
                // the never-overspend backstop D-20 requires post-perform).
                let actual_cost = spent.min(cap_sats);
                tracing::info!(
                    mint = %self.mint_id,
                    spent = actual_cost,
                    "brokered act PERFORMED: settled ecash on the local mint over host networking (receipt = mint preimage)"
                );
                RailOutcome::Performed { actual_cost, proof: preimage, completion: Vec::new() }
            }
            Err(e) => {
                tracing::error!(error = %e, "brokered ecash settle failed upstream; debiting nothing");
                RailOutcome::UpstreamFailed
            }
        }
    }
}

// ---- The brain (the think -> pay -> meter -> repeat seam), stub-first ----------------

/// The inference backend the daemon proxies a [`Act::Completion`] through (brain-stub).
/// Mirrors the [`Rail`] seam: the impl holds any host-only credential (a Cashu token,
/// later) the genome never sees, and exposes only `complete`. `StubBrain` is the
/// deterministic, no-network, no-money impl built now; `RoutstrBrain` swaps in later
/// (same trait, same proto, zero genome change) -- it assembles the OpenAI JSON,
/// attaches an X-Cashu token, POSTs, parses the reply + change, and computes
/// `actual_cost = token_in_value - change_out_value`.
#[async_trait::async_trait]
pub trait BrainBackend: Send + Sync {
    /// Produce a completion for `messages` under `model`, capping the actual cost at
    /// `max_cost_sats`. Returns `(completion_text, actual_cost_sats)`; the actual cost
    /// MUST be `<= max_cost_sats` (D-20, the never-overspend cap applied to thinking).
    /// The completion text is the assistant reply the brain needs back to keep thinking.
    async fn complete(
        &self,
        model: &str,
        messages: &[ChatMessage],
        max_cost_sats: u64,
    ) -> anyhow::Result<(Vec<u8>, u64)>;
}

/// The stub inference backend (brain-stub): NO network, NO money, NO real model. It
/// returns a deterministic canned reply (echoing the last user message plus a tick
/// marker) and a SIMULATED, deterministic, non-zero cost, so the metabolism of
/// thinking is real (the treasury visibly drains per think) while nothing is actually
/// spent or fetched. Deterministic so the tests are stable; non-zero so the runway
/// falls. The real `RoutstrBrain` swaps in behind [`BrainBackend`] with no change here.
#[derive(Clone)]
pub struct StubBrain {
    /// The simulated cost knob: sats charged per (message-bytes + reply-bytes)
    /// `bytes_per_sat`. A larger value charges fewer sats per byte. The cost is
    /// `ceil(total_bytes / bytes_per_sat)`, clamped to `>= 1` so a think is never
    /// free, then clamped to the per-call cap by [`Self::complete`].
    bytes_per_sat: u64,
}

impl StubBrain {
    /// A stub brain charging a deterministic `ceil(total_bytes / bytes_per_sat)` sats
    /// per completion (minimum 1). `bytes_per_sat` must be non-zero; 0 is treated as 1
    /// (charge a sat per byte) so the cost fn never divides by zero.
    pub fn new(bytes_per_sat: u64) -> Self {
        StubBrain {
            bytes_per_sat: bytes_per_sat.max(1),
        }
    }

    /// The canned, deterministic reply for a history: echo the last user message and
    /// tag it with the history depth (the "tick"), so a multi-turn loop produces a
    /// distinct-but-deterministic reply each turn and the round-trip TEXT is checkable.
    /// No model is consulted; this is the stub's only "thinking".
    fn canned_reply(messages: &[ChatMessage]) -> String {
        let last_user = messages
            .iter()
            .rev()
            .find(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .unwrap_or("(nothing)");
        let turn = messages.len();
        format!("[stub-brain turn {turn}] I am a Kirby agent; my runway is draining. You said: {last_user}")
    }

    /// The deterministic simulated cost of a completion: `ceil(total_bytes /
    /// bytes_per_sat)`, at least 1 sat, where `total_bytes` is the summed length of
    /// every message plus the reply. Deterministic (stable tests) and non-zero (the
    /// runway visibly falls each think). The caller clamps it to the per-call cap.
    fn simulated_cost(&self, messages: &[ChatMessage], reply: &str) -> u64 {
        let msg_bytes: usize = messages.iter().map(|m| m.role.len() + m.content.len()).sum();
        let total = (msg_bytes + reply.len()) as u64;
        total.div_ceil(self.bytes_per_sat).max(1)
    }
}

#[async_trait::async_trait]
impl BrainBackend for StubBrain {
    async fn complete(
        &self,
        _model: &str,
        messages: &[ChatMessage],
        max_cost_sats: u64,
    ) -> anyhow::Result<(Vec<u8>, u64)> {
        let reply = Self::canned_reply(messages);
        // D-20: the simulated cost is clamped to the per-call cap, so the brain can
        // never debit past what the gateway's budget gate checked.
        let actual_cost = self.simulated_cost(messages, &reply).min(max_cost_sats);
        Ok((reply.into_bytes(), actual_cost))
    }
}

/// A rail that routes the brain act to a [`BrainBackend`] and everything else to a
/// base [`Rail`] (brain-stub F3). The base is the existing performer (the MockRail in
/// the stub run, the CdkEcashRail later); the brain is the inference backend.
///
/// FAIL-CLOSED MEMBRANE (brain-stub R3): in brain mode the gateway's allowlist holds
/// ONLY [`BRAIN_COMPLETION_DESTINATION`], so a non-Completion act is denied at the
/// gateway's allowlist step (`DENIED_NOT_ALLOWLISTED`) before `perform` is ever
/// reached. As a defense-in-depth backstop, `perform` here ALSO refuses any
/// non-Completion act (returns `UpstreamFailed`, performing nothing on the base rail):
/// a buggy or hostile brain genome cannot smuggle an ecash settle through the brain
/// rail even if the allowlist were misconfigured. "The brain only thinks."
pub struct CompositeRail {
    base: Arc<dyn Rail>,
    brain: Arc<dyn BrainBackend>,
}

impl CompositeRail {
    /// Build a composite rail over a base performer and a brain backend.
    pub fn new(base: Arc<dyn Rail>, brain: Arc<dyn BrainBackend>) -> Self {
        CompositeRail { base, brain }
    }
}

#[async_trait::async_trait]
impl Rail for CompositeRail {
    fn estimate(&self, act: &Act) -> u64 {
        match act {
            // R5: the LLM cost is unknown pre-call, so the genome-declared per-call
            // cap IS the estimate (the gateway then enforces estimate <= budget <=
            // treasury, D-20, and perform caps the actual at it).
            Act::Completion(c) => c.max_cost_sats,
            // Every other act estimates through the base rail unchanged.
            other => self.base.estimate(other),
        }
    }

    async fn perform(&self, act: &Act, cap_sats: u64) -> RailOutcome {
        match act {
            Act::Completion(c) => match self.brain.complete(&c.model, &c.messages, cap_sats).await {
                Ok((completion, actual_cost)) => {
                    // D-20 backstop: the backend already capped, clamp again so the
                    // debit can never exceed the gateway-checked estimate.
                    let actual_cost = actual_cost.min(cap_sats);
                    // The proof is a brain-act fact (the thinking happened); the words
                    // ride in `completion`, which the gateway plumbs into the receipt.
                    let proof = format!(
                        "brain-completion:model={}:reply_len={}",
                        c.model,
                        completion.len()
                    )
                    .into_bytes();
                    RailOutcome::Performed { actual_cost, proof, completion }
                }
                Err(e) => {
                    tracing::error!(error = %e, "brain backend failed to complete; debiting nothing");
                    RailOutcome::UpstreamFailed
                }
            },
            // R3 fail-closed: the brain rail performs ONLY completions. A non-Completion
            // act is refused here (the allowlist already denied it; this is the
            // defense-in-depth backstop so a misconfigured allowlist still cannot route
            // a spend through the brain rail). Debit nothing.
            other => {
                tracing::warn!(
                    destination = %destination(other),
                    "CompositeRail (brain mode) asked to perform a non-Completion act; refusing (the brain only thinks, R3)"
                );
                RailOutcome::UpstreamFailed
            }
        }
    }
}

// ---- The memory store (durable mind-state Chunk-1): the second treasury, stub-first ----
//
// The Memory act is the SIBLING of the Completion act: a brokered, treasury-metered store
// op the genome reaches ONLY through the daemon (it has no egress). It mirrors the brain's
// stub-behind-a-trait shape -- `StubMemory` now (in-memory, deterministic, no crypto/relay),
// `EngramStore` (real NIP-AE over the nerve) later, same trait, same proto.
//
// The METERING POLICY diverges from the act-agnostic pipeline and lives in the GATEWAY
// (it owns the treasury + ledger), NOT in this trait (design doc 11/12): READS (GET/LS)
// are served FREE at zero debit and bypass the ledger entirely (G3); WRITES (SET/RM) are
// metered by the HOST-computed `write_cost` and the cost is NEVER clamped down to the
// caller's ceiling (G2). This trait only performs the store op and reports the host cost;
// it does not touch the treasury. That is WHY memory is held directly on the gateway
// rather than routed through the [`Rail`] like the brain: the read/write metering fork is
// unavoidably a gateway concern, so threading memory through `Rail::perform` (whose flat
// outcome feeds the uniform debit) could not express "free reads bypass the ledger" or
// "never clamp the write cost". §9 of the design doc sketched a rail-routed composite, but
// §11/§12 (which win on conflict) replace its estimate/clamp recipe with this fork.

/// The maximum engram value size: the NIP-44 plaintext cap (design doc 1). The stub
/// enforces it so Chunk-2's real `EngramStore` inherits the SAME contract (F6).
pub const MAX_MEMORY_VALUE_BYTES: usize = 65_535;

/// A typed memory-store fault (design doc 10 F6): the backend returns these so a caller
/// (and Chunk-2) can distinguish not-found from malformed-slug from over-size from an
/// unreachable store -- not one opaque failure. The gateway maps any of them to a
/// debit-nothing receipt; the store mutation and the debit never happen on a fault.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    /// The slug is not `core` and does not match the `mem/<seg>(/<seg>)*` grammar.
    #[error("invalid slug {0:?}: expected \"core\" or \"mem/<name>...\"")]
    InvalidSlug(String),
    /// A SET value exceeds the engram plaintext cap.
    #[error("value too large: {got} bytes exceeds the {max}-byte engram cap")]
    TooLarge { got: usize, max: usize },
    /// A request that is malformed for its op (e.g. a read carrying a write payload, an
    /// LS with a non-empty slug, or an op this method does not serve).
    #[error("malformed memory request for the requested op")]
    MalformedOp,
    /// The store could not be reached (Chunk-2: the relay; Chunk-1: an injected failure
    /// so the gateway's UPSTREAM_FAILED path is testable, F6 injectable failure).
    #[error("memory store unreachable")]
    Unreachable,
}

/// The commit status of a backend write (design doc 12 G6): how the daemon must debit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteCommit {
    /// A new store event committed under this write token: debit the host cost once.
    Stored,
    /// This exact write token already committed (a crash-replay re-perform). The store
    /// effect already landed, so the daemon STILL debits the ORIGINAL (recomputable)
    /// cost exactly once -- never zero (which would leave the write stored-but-unpaid)
    /// and never twice. In Chunk-1 the gateway STEP-1 dedupe normally short-circuits a
    /// same-key replay before perform; this models the crash window for Chunk-2's swap-in.
    AlreadyCommittedSameWseq,
}

/// The outcome of a [`MemoryBackend::write`]: the structured result plus the commit
/// status the daemon debits on.
pub struct MemoryWrite {
    pub result: MemoryResult,
    pub committed: WriteCommit,
}

/// The memory store the daemon performs an [`Act::Memory`] through (durable mind-state).
/// Mirrors the [`BrainBackend`] seam: the impl holds whatever it needs (Chunk-1: an
/// in-memory map; Chunk-2: the identity key + a nostr-sdk client to the nerve relay), and
/// the genome never touches the store directly. READS are free + side-effect-free; WRITES
/// are metered by `write_cost` and idempotent under a re-perform of the same write token.
#[async_trait::async_trait]
pub trait MemoryBackend: Send + Sync {
    /// The HOST-computed storage cost of a WRITE (design doc 12 G2): a pure function of
    /// the op + payload bytes, computed BEFORE perform so the gateway budget gate can
    /// require `cost <= max_cost_sats` (the caller's ceiling) WITHOUT clamping. Reads
    /// cost 0 (this is never called for a read).
    fn write_cost(&self, m: &Memory) -> u64;

    /// Serve a READ op (GET/LS): fetch from the store, NO mutation. Free + dedup-free at
    /// the gateway (design doc 12 G3).
    async fn read(&self, m: &Memory) -> Result<MemoryResult, MemoryError>;

    /// Perform a WRITE op (SET/RM) idempotently, keyed by `write_token` (the genome's
    /// monotonic write-seq, carried as the request idempotency_key `mem-write-{wseq}`)
    /// for store-event determinism (design doc 10 F3): a re-perform of the SAME
    /// (slug, write_token) reproduces the SAME store effect and reports
    /// `AlreadyCommittedSameWseq` so the single debit still lands (G6).
    async fn write(&self, m: &Memory, write_token: &str) -> Result<MemoryWrite, MemoryError>;
}

/// Validate a memory request's per-op invariants (design doc 12 G5), BEFORE any
/// cost-classification or store work. GET/RM carry a valid slug and no LS fields; SET
/// carries a valid slug + a within-cap value; LS carries an empty slug and no value; a
/// read op may NOT carry a write payload. Malformed => the gateway denies it (debit 0)
/// before classifying it as a read or a write, so a malformed request can never reach the
/// store, the signer, or the treasury.
pub fn validate_memory_request(m: &Memory) -> Result<(), MemoryError> {
    let op = MemoryOp::try_from(m.op).unwrap_or(MemoryOp::Unspecified);
    match op {
        MemoryOp::Get => {
            if !is_valid_slug(&m.slug) {
                return Err(MemoryError::InvalidSlug(m.slug.clone()));
            }
            // A read carries no write payload.
            if !m.value.is_empty() {
                return Err(MemoryError::MalformedOp);
            }
            Ok(())
        }
        MemoryOp::Ls => {
            // LS enumerates: empty slug, no value.
            if !m.slug.is_empty() || !m.value.is_empty() {
                return Err(MemoryError::MalformedOp);
            }
            Ok(())
        }
        MemoryOp::Set => {
            if !is_valid_slug(&m.slug) {
                return Err(MemoryError::InvalidSlug(m.slug.clone()));
            }
            if m.value.len() > MAX_MEMORY_VALUE_BYTES {
                return Err(MemoryError::TooLarge {
                    got: m.value.len(),
                    max: MAX_MEMORY_VALUE_BYTES,
                });
            }
            Ok(())
        }
        MemoryOp::Rm => {
            if !is_valid_slug(&m.slug) {
                return Err(MemoryError::InvalidSlug(m.slug.clone()));
            }
            // RM tombstones; it carries no value.
            if !m.value.is_empty() {
                return Err(MemoryError::MalformedOp);
            }
            Ok(())
        }
        MemoryOp::Unspecified => Err(MemoryError::MalformedOp),
    }
}

/// Whether `op` is a READ (GET/LS) -- served free and bypassing the ledger (design doc
/// 12 G3) -- as opposed to a metered WRITE (SET/RM). The gateway forks on this.
pub fn is_read_op(op: MemoryOp) -> bool {
    matches!(op, MemoryOp::Get | MemoryOp::Ls)
}

/// The NIP-AE slug grammar (design doc 1): `core` exactly, or `mem/<seg>(/<seg>)*` where
/// each `<seg>` is `[a-z0-9][a-z0-9_-]{0,63}`. Implemented by hand (no regex dep). The
/// stub enforces it so Chunk-2's `EngramStore` (which derives the `d` tag from the slug)
/// inherits the SAME namespace discipline.
fn is_valid_slug(slug: &str) -> bool {
    if slug == "core" {
        return true;
    }
    let Some(rest) = slug.strip_prefix("mem/") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    rest.split('/').all(is_valid_slug_segment)
}

fn is_valid_slug_segment(seg: &str) -> bool {
    let mut chars = seg.chars();
    let Some(first) = chars.next() else {
        return false; // empty segment (e.g. a trailing or double slash)
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    if seg.len() > 64 {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// The deterministic store-dedup id of a value: its SHA-256 digest (design doc 10 F3 --
/// the d-tag/event-seed analog). Recomputable, so a same-token re-perform reproduces it.
fn content_hash(value: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(value).to_vec()
}

/// The stub memory store (durable-mind-state Chunk-1): an in-memory map, NO crypto, NO
/// relay -- it proves the act SEAM exactly as the [`StubBrain`] proved the brain seam
/// without Routstr. FAITHFUL (design doc 10 F6): it enforces the slug grammar, the engram
/// size cap, tombstone semantics, and TYPED errors, and it models the write-token
/// idempotency (G6), so Chunk-2's `EngramStore` swaps in behind [`MemoryBackend`] with no
/// seam redesign.
///
/// The write cost is a deterministic `ceil((slug+value bytes) / bytes_per_sat)` (min 1)
/// so the treasury VISIBLY drains per write and the cost is RECOMPUTABLE (a same-token
/// re-perform yields the same number, so the single debit is exact, G6). Reads cost zero.
#[derive(Clone)]
pub struct StubMemory {
    inner: Arc<Mutex<StubMemoryState>>,
    /// The simulated storage-cost knob (daemon-side only, never on the wire): a write
    /// costs `ceil((slug+value bytes) / bytes_per_sat)` sats, min 1. A larger value
    /// charges fewer sats per byte.
    bytes_per_sat: u64,
    /// When true, every read/write returns [`MemoryError::Unreachable`] -- the injectable
    /// failure (F6) the gateway's UPSTREAM_FAILED path is tested against. Models a down
    /// relay for Chunk-2 without a real network.
    fail_unreachable: bool,
}

struct StubMemoryState {
    /// slug -> stored value (the live engrams). A tombstone (RM) removes the entry.
    store: HashMap<String, Vec<u8>>,
    /// write tokens already committed -> the result their first perform returned (design
    /// doc 12 G6). A re-perform of a token in here is a crash-replay: return the SAME
    /// result + `AlreadyCommittedSameWseq` so the single debit still lands.
    committed: HashMap<String, MemoryResult>,
}

impl StubMemory {
    /// A stub store charging a deterministic `ceil(bytes / bytes_per_sat)` sats per write
    /// (min 1). `bytes_per_sat` must be non-zero; 0 is treated as 1 so the cost fn never
    /// divides by zero.
    pub fn new(bytes_per_sat: u64) -> Self {
        StubMemory {
            inner: Arc::new(Mutex::new(StubMemoryState {
                store: HashMap::new(),
                committed: HashMap::new(),
            })),
            bytes_per_sat: bytes_per_sat.max(1),
            fail_unreachable: false,
        }
    }

    /// A stub store whose every op fails as [`MemoryError::Unreachable`] (the injected
    /// failure used to exercise the gateway's UPSTREAM_FAILED path, F6).
    pub fn unreachable(bytes_per_sat: u64) -> Self {
        StubMemory {
            fail_unreachable: true,
            ..Self::new(bytes_per_sat)
        }
    }

    /// The current stored value for `slug` (host-side, for tests to observe the store
    /// state directly without a gateway round-trip). Never exposed to the genome.
    pub fn peek(&self, slug: &str) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().store.get(slug).cloned()
    }
}

#[async_trait::async_trait]
impl MemoryBackend for StubMemory {
    fn write_cost(&self, m: &Memory) -> u64 {
        // Host-computed from the op's payload bytes (slug + value). Deterministic and
        // recomputable; an RM (no value) still costs >= 1 (a tombstone is a write).
        let bytes = (m.slug.len() + m.value.len()) as u64;
        bytes.div_ceil(self.bytes_per_sat).max(1)
    }

    async fn read(&self, m: &Memory) -> Result<MemoryResult, MemoryError> {
        if self.fail_unreachable {
            return Err(MemoryError::Unreachable);
        }
        let op = MemoryOp::try_from(m.op).unwrap_or(MemoryOp::Unspecified);
        let state = self.inner.lock().unwrap();
        match op {
            MemoryOp::Get => {
                if !is_valid_slug(&m.slug) {
                    return Err(MemoryError::InvalidSlug(m.slug.clone()));
                }
                match state.store.get(&m.slug) {
                    Some(v) => Ok(MemoryResult {
                        found: true,
                        value: v.clone(),
                        slugs: Vec::new(),
                        content_hash: content_hash(v),
                        write_status: WriteStatus::Unspecified as i32,
                    }),
                    None => Ok(MemoryResult {
                        found: false,
                        value: Vec::new(),
                        slugs: Vec::new(),
                        content_hash: Vec::new(),
                        write_status: WriteStatus::Unspecified as i32,
                    }),
                }
            }
            MemoryOp::Ls => {
                // Deterministic order so the result is stable for tests + head-select.
                let mut slugs: Vec<String> = state.store.keys().cloned().collect();
                slugs.sort();
                Ok(MemoryResult {
                    found: !slugs.is_empty(),
                    value: Vec::new(),
                    slugs,
                    content_hash: Vec::new(),
                    write_status: WriteStatus::Unspecified as i32,
                })
            }
            // read() serves only GET/LS; a write op here is a caller bug.
            _ => Err(MemoryError::MalformedOp),
        }
    }

    async fn write(&self, m: &Memory, write_token: &str) -> Result<MemoryWrite, MemoryError> {
        if self.fail_unreachable {
            return Err(MemoryError::Unreachable);
        }
        let op = MemoryOp::try_from(m.op).unwrap_or(MemoryOp::Unspecified);
        if !is_valid_slug(&m.slug) {
            return Err(MemoryError::InvalidSlug(m.slug.clone()));
        }
        let mut state = self.inner.lock().unwrap();

        // G6: a re-perform of a write token that already committed is a crash-replay --
        // the store effect already landed, so reproduce the SAME result and signal
        // AlreadyCommittedSameWseq (the daemon still debits the original cost once).
        if let Some(prior) = state.committed.get(write_token) {
            return Ok(MemoryWrite {
                result: prior.clone(),
                committed: WriteCommit::AlreadyCommittedSameWseq,
            });
        }

        let result = match op {
            MemoryOp::Set => {
                if m.value.len() > MAX_MEMORY_VALUE_BYTES {
                    return Err(MemoryError::TooLarge {
                        got: m.value.len(),
                        max: MAX_MEMORY_VALUE_BYTES,
                    });
                }
                let hash = content_hash(&m.value);
                state.store.insert(m.slug.clone(), m.value.clone());
                MemoryResult {
                    found: true,
                    value: Vec::new(),
                    slugs: Vec::new(),
                    content_hash: hash,
                    write_status: WriteStatus::Stored as i32,
                }
            }
            MemoryOp::Rm => {
                let existed = state.store.remove(&m.slug).is_some();
                MemoryResult {
                    found: existed,
                    value: Vec::new(),
                    slugs: Vec::new(),
                    content_hash: Vec::new(),
                    write_status: if existed {
                        WriteStatus::Removed as i32
                    } else {
                        WriteStatus::AlreadyAbsent as i32
                    },
                }
            }
            // write() serves only SET/RM; a read op here is a caller bug.
            _ => return Err(MemoryError::MalformedOp),
        };

        // Record the result under the write token so a same-token re-perform reproduces
        // it (G6). The first commit always reports `Stored` (a new event landed).
        state.committed.insert(write_token.to_string(), result.clone());
        Ok(MemoryWrite {
            result,
            committed: WriteCommit::Stored,
        })
    }
}
