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
use kirby_proto::{ChatMessage, Memory, MemoryOp, MemoryResult, NostrPublish, WriteStatus};
// `prost::Message` (brought in unnamed) for `decode`: the daemon prost-decodes the opaque
// `Actuate.payload` back into the typed `NostrPublish` (the genome encoded it the same way).
use prost::Message as _;
// The real EngramStore (Chunk-2) is a host-side nostr-sdk client over the nerve relay
// set. `Event` here is the nostr event, NOT `kirby_proto::Event` (which rail.rs never
// names) -- no conflict. `EventBuilder` builds the actuator's kind:1 note (the agent's voice).
use nostr_sdk::{Client, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, Timestamp, ToBech32};

use crate::engram::{EngramCrypto, EngramFrame, KIND_ENGRAM};

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
        // An Actuate's destination IS its `kind` (e.g. "nostr.publish"): the allowlist gates
        // PER-KIND, so a workload whose allowlist lacks this exact kind issues ZERO of it at the
        // gateway allowlist step (DENIED_NOT_ALLOWLISTED, before perform). One envelope, many
        // outward actions, each independently gated.
        Act::Actuate(a) => a.kind.clone(),
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
        // None (like ecash): an Actuate's cost is a KNOWN fixed host cost (the actuator's
        // `cost(kind)`), NOT an unknown-capped-at-the-ceiling cost like the brain. Returning None
        // means the estimate is NOT clamped down to the caller's ceiling, so a true cost ABOVE
        // the genome's authorized `budget_sats` is DENIED_OVER_BUDGET (surfaced as a loud config
        // error), never silently clamped + undercharged. The per-act ceiling rides in
        // `budget_sats` (the genome sets it = `Actuate.max_cost_sats`), which the gate enforces.
        Act::Actuate(_) => None,
    }
}

/// The D-20 never-overspend clamp on a real rail's spend: the actual spend toward
/// the mint may never exceed `cap_sats` (the gateway-checked estimate), regardless of
/// the act's requested amount or the mint's reported melt. Pure so the clamp is
/// fast-unit-testable WITHOUT a live mint; `CdkEcashRail::perform` calls it at BOTH
/// clamp sites (pre-settle on the requested amount, post-settle on the melt's reported
/// spend), so the test exercises the real code path, not a copy.
pub fn clamp_spend(requested: u64, cap_sats: u64) -> u64 {
    requested.min(cap_sats)
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

    /// Pre-perform validation for an OUTWARD act (the actuator path), run BEFORE the gateway
    /// RESERVES/debits the idempotency key, so a malformed outward payload is a FREE denial (never
    /// reserved or charged). Cheap + side-effect-free (decode + kind-restrict + re-sanitize). The
    /// default is `Ok(())` for rails/acts with no outward validation (the brain, ecash, paid HTTP);
    /// `CompositeRail` overrides it to delegate an `Act::Actuate` to its actuator. The actuator
    /// re-runs the same guard inside `perform` before publishing (defense in depth).
    fn validate_outward(&self, _act: &Act) -> Result<(), String> {
        Ok(())
    }
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
            // Exhaustiveness only: an Actuate is intercepted by the CompositeRail (which holds the
            // actuator) BEFORE it could reach this base rail, so this arm only satisfies the
            // match; the value is the caller's declared ceiling.
            Act::Actuate(a) => a.max_cost_sats,
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
            // Exhaustiveness only: an Actuate is intercepted by the CompositeRail (which holds the
            // actuator) BEFORE it could reach this base rail, so this arm only satisfies the
            // match; the value is the caller's declared ceiling.
            Act::Actuate(a) => a.max_cost_sats,
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
        let spend = clamp_spend(settle.amount, cap_sats);
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
                let actual_cost = clamp_spend(spent, cap_sats);
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

/// A rail that routes the brain act to a [`BrainBackend`], the OUTWARD actuator act to an
/// optional [`Actuator`], and everything else to a base [`Rail`] (brain-stub F3, extended for the
/// POST actuator). The base is the existing performer (the MockRail in the stub run, the
/// CdkEcashRail later); the brain is the inference backend; the actuator (when present) performs
/// `Act::Actuate` (e.g. signs + publishes a nostr note via the nerve).
///
/// FAIL-CLOSED MEMBRANE (brain-stub R3, extended for Actuate): the gateway's allowlist holds ONLY
/// the sentinels/kinds a workload may reach, so an unauthorized act is denied at the allowlist
/// step (`DENIED_NOT_ALLOWLISTED`) before `perform`. As a defense-in-depth backstop, `perform`
/// here ALSO refuses any act it has no backend for: a non-Completion/non-Actuate act, or an
/// Actuate when `actuator` is `None`, returns `UpstreamFailed` (performing nothing, debiting
/// nothing). "The brain only thinks; the actuator only acts on the kinds it is given."
pub struct CompositeRail {
    base: Arc<dyn Rail>,
    brain: Arc<dyn BrainBackend>,
    /// The outward actuator (the agent's voice). `None` for a workload with no outward acts (the
    /// brain/memory/diarist workloads); `Some` only when a `social`-configured workload injects it
    /// at boot. An `Act::Actuate` with `None` here is refused (fail-closed).
    actuator: Option<Arc<dyn Actuator>>,
}

impl CompositeRail {
    /// Build a composite rail over a base performer and a brain backend (no actuator).
    pub fn new(base: Arc<dyn Rail>, brain: Arc<dyn BrainBackend>) -> Self {
        CompositeRail { base, brain, actuator: None }
    }

    /// Attach an outward [`Actuator`] (the agent's voice): the rail then performs `Act::Actuate`
    /// through it. Builder style so the existing `new` callers stay unchanged.
    pub fn with_actuator(mut self, actuator: Arc<dyn Actuator>) -> Self {
        self.actuator = Some(actuator);
        self
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
            // The actuator's KNOWN fixed host cost for this kind (e.g. the publish cost). With no
            // actuator, u64::MAX so the budget gate refuses it OVER_BUDGET (fail-closed) rather
            // than estimating an outward act through the base rail.
            Act::Actuate(a) => {
                self.actuator.as_ref().map(|act| act.cost(&a.kind)).unwrap_or(u64::MAX)
            }
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
            // The OUTWARD actuator act: route to the actuator, which decodes + RE-VALIDATES the
            // payload (a NEW entry point: re-sanitize, re-cap, restrict the kind), then signs +
            // publishes. With no actuator configured, refuse (fail-closed): nothing performed,
            // nothing debited. The allowlist already gated the kind upstream; this is the backstop.
            Act::Actuate(a) => match &self.actuator {
                Some(actuator) => actuator.actuate(&a.kind, &a.payload, cap_sats).await,
                None => {
                    tracing::warn!(
                        kind = %a.kind,
                        "CompositeRail asked to perform an Actuate with no actuator configured; refusing (fail-closed)"
                    );
                    RailOutcome::UpstreamFailed
                }
            },
            // R3 fail-closed: the brain rail performs ONLY completions (and the actuator handles
            // Actuate above). Any OTHER act is refused here (the allowlist already denied it; this
            // is the defense-in-depth backstop so a misconfigured allowlist still cannot route a
            // spend through the brain rail). Debit nothing.
            other => {
                tracing::warn!(
                    destination = %destination(other),
                    "CompositeRail (brain mode) asked to perform a non-Completion/non-Actuate act; refusing (the brain only thinks, R3)"
                );
                RailOutcome::UpstreamFailed
            }
        }
    }

    /// Pre-publish validation for an `Act::Actuate`: delegate to the actuator's cheap, side-effect-
    /// free guard so the gateway can refuse a malformed outward payload BEFORE it reserves/debits
    /// (a free denial). No actuator => refuse (fail-closed). Non-Actuate acts pass (the default).
    fn validate_outward(&self, act: &Act) -> Result<(), String> {
        match act {
            Act::Actuate(a) => match &self.actuator {
                Some(actuator) => actuator.validate(&a.kind, &a.payload),
                None => Err("CompositeRail has no actuator configured for an Actuate".to_string()),
            },
            _ => Ok(()),
        }
    }
}

// ---- The outward actuator (the agent's first voice): sign + publish via the nerve ----
//
// `Act::Actuate` is the GENERAL outward envelope; it rides the SAME generic gateway path as the
// brain + ecash (estimate -> budget gate -> perform -> debit), so a publish is metered exactly
// like any other act (no fork, unlike memory). The `Actuator` trait is the swap-ready seam
// (mirrors `BrainBackend`): the `NostrActuator` impl holds the node identity key + a connected
// nostr-sdk client and publishes a kind:1 note via the SAME key + relay path nerve.rs uses for
// presence, so the note is followable as that agent's public feed. The genome NEVER publishes
// (egress lock); it only REQUESTS the act over vsock and the daemon signs + sends.

/// Decode + RE-VALIDATE a `nostr.publish` payload: the DAEMON-SIDE guard. The actuator is a NEW
/// entry point, so it NEVER trusts that the genome sanitized; it independently (1) decodes the
/// nested-prost [`NostrPublish`], (2) RESTRICTS the publishable nostr kind to
/// [`kirby_proto::NOSTR_KIND_TEXT_NOTE`] (1, a public text note; MVP), and (3) RE-runs the SHARED
/// [`kirby_proto::sanitize_note_for_publish`] guard on the content (strip control + the Unicode
/// separators, collapse, non-empty, within `MAX_NOTE_BYTES`). Returns the CLEAN content to
/// publish, or a reason to refuse. Pure (no network), so it is unit-tested directly. `pub` so the
/// daemon-side guard teeth live alongside the dispatch teeth (the post-actuator integration test).
pub fn validate_nostr_publish(payload: &[u8]) -> Result<String, String> {
    let np = NostrPublish::decode(payload)
        .map_err(|e| format!("nostr.publish payload failed to decode: {e}"))?;
    if np.kind != kirby_proto::NOSTR_KIND_TEXT_NOTE as u32 {
        return Err(format!(
            "nostr.publish refused: only kind {} (a public text note) is allowed (MVP), got kind {}",
            kirby_proto::NOSTR_KIND_TEXT_NOTE,
            np.kind
        ));
    }
    // MVP: `publish_note` composes a NO-TAG note, so a payload carrying tags would publish (and
    // return a receipt for) a DIFFERENT event than requested. Reject non-empty tags until tag
    // support is built AND plumbed through `publish_note` (so the signed event matches the request).
    if !np.tags.is_empty() {
        return Err(format!(
            "nostr.publish refused: tags are not supported in the MVP (got {} tag(s)); the published event would not match the request",
            np.tags.len()
        ));
    }
    kirby_proto::sanitize_note_for_publish(&np.content)
}

/// Decode + RE-VALIDATE a `nostr.dm_reply` payload: the DAEMON-SIDE guard, the private sibling of
/// [`validate_nostr_publish`]. The DM actuator is a NEW entry point eating semi-trusted genome
/// input, so it NEVER trusts the genome sanitized; it independently (1) decodes the nested-prost
/// [`NostrDmReply`], (2) PARSES `to_pubkey` into a real x-only [`nostr_sdk::PublicKey`] (a
/// malformed recipient is a free denial -- the reply could not be addressed), and (3) RE-runs the
/// SHARED [`kirby_proto::sanitize_dm_for_send`] guard on the text. Returns the parsed recipient +
/// CLEAN text to wrap, or a reason to refuse. Pure (no network), so it is unit-tested directly.
/// `pub` so the daemon-side guard teeth live alongside the dispatch teeth.
pub fn validate_nostr_dm_reply(payload: &[u8]) -> Result<(nostr_sdk::PublicKey, String), String> {
    let dm = kirby_proto::NostrDmReply::decode(payload)
        .map_err(|e| format!("nostr.dm_reply payload failed to decode: {e}"))?;
    let to = nostr_sdk::PublicKey::parse(&dm.to_pubkey)
        .map_err(|e| format!("nostr.dm_reply refused: recipient pubkey {:?} is invalid: {e}", dm.to_pubkey))?;
    let text = kirby_proto::sanitize_dm_for_send(&dm.text)?;
    Ok((to, text))
}

/// The outward actuator the daemon performs an [`Act::Actuate`] through (the agent's voice).
/// Mirrors the [`BrainBackend`]/[`MemoryBackend`] seam: the impl holds the host-only credential
/// (here the node identity key + a connected nostr-sdk client), and the genome reaches it ONLY
/// through the daemon. A `kind` this actuator does not serve is refused, so a misconfigured
/// allowlist still cannot route an unknown outward act.
#[async_trait::async_trait]
pub trait Actuator: Send + Sync {
    /// The HOST-computed cost (sats) of one actuate of `kind`: a small FIXED cost (like a memory
    /// write) so the agent cannot spam the world for free. A kind this actuator does not serve
    /// returns `u64::MAX`, so the gateway budget gate refuses it OVER_BUDGET (fail-closed).
    fn cost(&self, kind: &str) -> u64;
    /// Validate the payload for `kind` WITHOUT performing the side effect (decode + kind-restrict +
    /// re-sanitize). The gateway calls this BEFORE it reserves/debits the idempotency key, so a
    /// malformed outward payload is a FREE denial (never charged). `Err(reason)` refuses; `Ok(())`
    /// means it would publish. `actuate` re-runs the SAME guard before the network publish.
    fn validate(&self, kind: &str, payload: &[u8]) -> Result<(), String>;
    /// Perform the actuate: RE-VALIDATE the payload (defense in depth), then do the outward act
    /// (sign + publish) and return the proof (the event id). Caps the actual spend at `cap_sats`
    /// (D-20). A bad payload / disallowed kind / publish failure returns `UpstreamFailed` (the act
    /// did not happen, debit 0).
    async fn actuate(&self, kind: &str, payload: &[u8], cap_sats: u64) -> RailOutcome;
}

/// How the actuator signs the note it publishes (the S3c fork):
///   * `SingleKey` -- the existing path (non-fleet `kirby run` / `kirby agent`): a local
///     secp256k1/BIP340 `Keys` signs via `EventBuilder`. UNCHANGED and byte-identical (G-CLEAN).
///   * `Frost` -- the S3c per-agent FROST tenant: the agent's identity IS the threshold group
///     taproot key Q; there is NO node-local signing key. A 2-of-3 quorum signs the note (with the
///     guardian membrane on every holder) and the daemon publishes the PRE-SIGNED event.
#[derive(Clone)]
enum SigningMode {
    /// The single-key path: a local `Keys` is the nostr-sdk client's signer.
    SingleKey(Keys),
    /// The FROST path: a quorum signer produces the aggregate-signed event under Q. The client has
    /// NO signer set (we never call `send_event_builder`; we send a pre-built owned `Event`).
    ///
    /// The group taproot key Q is validated ONCE into a `nostr_sdk::PublicKey` at construction
    /// (`connect_frost`) and STORED here, so `public_key()` is a fail-closed accessor that returns
    /// the SAME identity the quorum signs under. There is NO silent wrong-key fallback: if Q ever
    /// failed to parse as an x-only key, construction would have errored loudly (it cannot, since
    /// `group_xonly_q` always yields a valid x-only key -- but a future drift fails loud, never
    /// exposing a mismatched npub).
    Frost {
        quorum: Arc<crate::quorum_signer::QuorumSigner>,
        /// The validated group public key Q (= `quorum.q_bytes()` as a nostr PublicKey). Stored so
        /// the identity reported by `public_key()` can never diverge from what the quorum signs.
        q_public_key: nostr_sdk::PublicKey,
    },
}

/// The real outward actuator (`nostr.publish`): holds the signing mode (single-key OR a FROST
/// quorum) + a connected nostr-sdk client to the relay set + a small fixed publish cost. Cheap to
/// clone (an `Arc` over the client). Built at boot from the SAME identity + relay the presence
/// beacon uses, so a published note is followable as that agent's public feed.
#[derive(Clone)]
pub struct NostrActuator {
    mode: SigningMode,
    client: Arc<Client>,
    /// The fixed host cost (sats) of one publish: small + non-zero (clamped to >= 1) so a post is
    /// never free, like a memory write. Configurable per deployment.
    cost_sats: u64,
    /// The DEDICATED PLAIN DM identity key, for the `nostr.dm_reply` kind (the agent's private
    /// voice). SEPARATE from the publish identity by design (the voice/money-plane split): NIP-17
    /// is NIP-44 = ECDH, which a FROST threshold key (`SigningMode::Frost`'s Q) CANNOT do, so DM
    /// replies are ALWAYS signed by this plain key the daemon holds in full, NEVER by Q. `None`
    /// when the workload has no DM reply path configured (a `nostr.dm_reply` is then refused
    /// fail-closed). Holding it as its OWN key (not the publish key, not the memory/engram key)
    /// means a DM-path compromise costs only DM privacy -- the "new entry point needs its own
    /// guards" discipline applied to key material.
    dm_keys: Option<Keys>,
}

impl NostrActuator {
    /// Connect a SINGLE-KEY actuator: build a nostr-sdk client signed by `keys`, add the relays,
    /// and connect (mirrors [`EngramStore::connect`]). Errors if no relay is configured (a
    /// misconfigured actuator is a boot bug, not a runtime outcome). This is the existing,
    /// byte-identical non-fleet path.
    pub async fn connect(keys: Keys, relays: &[String], cost_sats: u64) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        if relays.is_empty() {
            anyhow::bail!("NostrActuator requires at least one relay (the agent's publish relay)");
        }
        let client = Client::builder().signer(keys.clone()).build();
        for url in relays {
            client
                .add_relay(url)
                .await
                .with_context(|| format!("add actuator relay {url}"))?;
        }
        client.connect().await;
        tracing::info!(
            npub = %keys.public_key().to_bech32().unwrap_or_default(),
            relays = relays.len(),
            cost_sats = cost_sats.max(1),
            "NostrActuator connected (single-key, the agent's outward voice)"
        );
        Ok(NostrActuator {
            mode: SigningMode::SingleKey(keys),
            client: Arc::new(client),
            cost_sats: cost_sats.max(1),
            dm_keys: None,
        })
    }

    /// Attach the DEDICATED PLAIN DM identity key (enables the `nostr.dm_reply` kind). Builder
    /// form so DM replies are an OPT-IN seam wired at boot (when DM is configured) without
    /// touching the publish-path constructors. The key is a plain `Keys` the daemon holds in
    /// full -- it is what NIP-44-decrypts inbound DMs and signs NIP-17 reply gift-wraps; it is
    /// NEVER the FROST money key Q. Returns self so it chains after `connect`/`connect_frost`.
    pub fn with_dm_keys(mut self, dm_keys: Keys) -> Self {
        self.dm_keys = Some(dm_keys);
        self
    }

    /// Connect a FROST actuator (S3c, fleet-tenant): the agent has NO node-local signing key; its
    /// identity IS the group taproot key Q held by the `quorum`. The client carries NO signer
    /// (we publish a pre-signed, owned `Event` built by the quorum). Add the relays + connect.
    pub async fn connect_frost(
        quorum: Arc<crate::quorum_signer::QuorumSigner>,
        relays: &[String],
        cost_sats: u64,
    ) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        if relays.is_empty() {
            anyhow::bail!("NostrActuator requires at least one relay (the agent's publish relay)");
        }
        // No `.signer(..)`: a FROST event is signed by the quorum, never by a local key. Sending a
        // pre-built owned `Event` via `send_event` does not need a client signer.
        let client = Client::builder().build();
        for url in relays {
            client
                .add_relay(url)
                .await
                .with_context(|| format!("add actuator relay {url}"))?;
        }
        client.connect().await;
        // FAIL CLOSED on identity: validate Q -> nostr PublicKey ONCE here, where we can error
        // loudly, and store it. `public_key()` then returns this exact value -- there is NO silent
        // wrong-key fallback that could split-brain the reported npub from what the quorum signs.
        let q_public_key = nostr_sdk::PublicKey::from_slice(&quorum.q_bytes()).with_context(|| {
            format!(
                "FROST group key Q ({}) is not a valid x-only nostr public key; refusing to start a \
                 FROST actuator whose published identity would diverge from what it signs",
                hex::encode(quorum.q_bytes())
            )
        })?;
        let q_npub = q_public_key.to_bech32().unwrap_or_default();
        tracing::info!(
            npub = %q_npub,
            relays = relays.len(),
            cost_sats = cost_sats.max(1),
            "NostrActuator connected (FROST 2-of-3 quorum; the agent's voice is its threshold key Q)"
        );
        Ok(NostrActuator {
            mode: SigningMode::Frost { quorum, q_public_key },
            client: Arc::new(client),
            cost_sats: cost_sats.max(1),
            dm_keys: None,
        })
    }

    /// Compose, SIGN, and publish a kind:1 note carrying `content` to the relay set; return the
    /// event id hex (the receipt proof). `content` is ALREADY validated by
    /// [`validate_nostr_publish`]; the FROST path re-sanitizes again inside `sign_nostr_event`
    /// (a new signing entry point re-enforces the guards, never assuming the caller did).
    ///
    /// Two modes:
    ///   * SingleKey: reuse the nerve's `send_event_builder` path (UNCHANGED).
    ///   * Frost: run the 2-of-3 quorum (membrane on every holder) to build a PRE-SIGNED event,
    ///     verify the aggregate signature locally (fail-closed), then publish the OWNED event via
    ///     `send_event` (NOT `send_event_builder` -- the signing key is the threshold Q, there is
    ///     no local `Keys`).
    async fn publish_note(&self, content: &str) -> anyhow::Result<String> {
        use anyhow::Context as _;
        match &self.mode {
            SigningMode::SingleKey(_) => {
                let builder = EventBuilder::new(Kind::from(kirby_proto::NOSTR_KIND_TEXT_NOTE), content);
                let output = self
                    .client
                    .send_event_builder(builder)
                    .await
                    .context("publish kind:1 note to the relay set")?;
                Ok(output.val.to_hex())
            }
            SigningMode::Frost { quorum, .. } => {
                // Run the REAL FROST signing path (the 2-of-3 ceremony with the guardian membrane
                // on every holder + the local fail-closed verify-under-Q). This is the only
                // FROST-specific, load-bearing step; the `send_event` below is the generic relay
                // transport. `frost_sign_event` is what the in-crate test drives directly.
                let sdk_event = self.frost_sign_event(quorum, content)?;
                let output = self
                    .client
                    .send_event(&sdk_event)
                    .await
                    .context("publish pre-signed FROST kind:1 note to the relay set")?;
                Ok(output.val.to_hex())
            }
        }
    }

    /// The FROST-specific half of `publish_note`'s Frost branch, factored out so an in-crate test
    /// can drive the REAL signing path (not a copy) WITHOUT a live relay: run the 2-of-3 quorum
    /// ceremony (guardian membrane on every holder) to build the aggregate-signed kind:1 event under
    /// Q, re-materialize it as a nostr-sdk `Event`, and VERIFY it locally (id + BIP-340 sig under Q)
    /// before returning. Fail closed: if the aggregate is bad the event never gets built/sent.
    /// `created_at` is the host clock (the genome sees no bytes of this). Any refusal aborts here.
    fn frost_sign_event(
        &self,
        quorum: &crate::quorum_signer::QuorumSigner,
        content: &str,
    ) -> anyhow::Result<Event> {
        use anyhow::Context as _;
        let created_at = Timestamp::now().as_secs();
        let event = quorum
            .sign_nostr_event(kirby_proto::NOSTR_KIND_TEXT_NOTE as u32, created_at, content)
            .context("FROST quorum failed to co-sign the kind:1 note")?;
        // Re-materialize as a nostr-sdk Event from its NIP-01 JSON and VERIFY locally (id +
        // BIP-340 sig under Q) before sending -- fail closed if the aggregate is bad, so a
        // broken quorum never reaches the relay.
        let json = serde_json::to_string(&event).context("serialize FROST-signed event to JSON")?;
        let sdk_event =
            Event::from_json(&json).map_err(|e| anyhow::anyhow!("parse FROST-signed event: {e}"))?;
        sdk_event
            .verify()
            .map_err(|e| anyhow::anyhow!("FROST-signed event failed local verification: {e}"))?;
        Ok(sdk_event)
    }

    /// The agent's public key (the npub the note is signed by): the local key in single-key mode,
    /// or the FROST group taproot key Q in FROST mode. Exposed for the e2e to verify the published
    /// note's author; the SIGNING material never leaves the daemon.
    pub fn public_key(&self) -> nostr_sdk::PublicKey {
        match &self.mode {
            SigningMode::SingleKey(keys) => keys.public_key(),
            // FAIL CLOSED: return the Q public key VALIDATED ONCE at construction. No silent
            // wrong-key fallback -- the reported identity can never diverge from what the quorum
            // signs (a bad Q would have failed `connect_frost`, not landed here).
            SigningMode::Frost { q_public_key, .. } => *q_public_key,
        }
    }

    /// NIP-17-wrap, SIGN, and publish a DM reply to `to` carrying `text`; return the gift-wrap
    /// event id hex (the receipt proof). The reply is ALWAYS signed by the DEDICATED PLAIN
    /// [`Self::dm_keys`] -- NEVER the publish identity, and NEVER the FROST money key Q (a
    /// threshold key cannot ECDH, and the money plane must never touch the DM plane). The single
    /// `EventBuilder::private_msg` call builds the kind:14 rumor -> kind:13 seal (signed by the DM
    /// key) -> kind:1059 gift wrap (signed by a fresh per-message throwaway key, with a randomized
    /// `created_at` up to ~2 days back, both handled inside the builder for metadata privacy). The
    /// wrap is a fully-signed, OWNED event, so it publishes via `send_event` and needs NO client
    /// signer -- which is exactly why this works whether the publish path is single-key OR FROST
    /// (the FROST client has no signer). `text` is ALREADY validated by [`validate_nostr_dm_reply`].
    ///
    /// MVP relay policy: the wrap publishes to the actuator's OWN connected relay set. Correct
    /// NIP-17 would resolve the recipient's kind:10050 inbox relays and publish there; that
    /// resolution is a documented follow-up (the live test runs on a shared relay, so own-relay
    /// publish reaches the recipient).
    async fn publish_dm_reply(&self, to: nostr_sdk::PublicKey, text: &str) -> anyhow::Result<String> {
        use anyhow::Context as _;
        let wrap = self.build_dm_reply_event(to, text).await?;
        // Publish the pre-signed OWNED wrap (no client signer needed; mirrors the FROST publish).
        let output = self
            .client
            .send_event(&wrap)
            .await
            .context("publish the kind:1059 DM reply gift wrap to the relay set")?;
        Ok(output.val.to_hex())
    }

    /// Build the NIP-17 reply gift wrap, SIGNED BY THE PLAIN DM KEY (the seal author = the DM npub),
    /// WITHOUT publishing it -- the factored-out, relay-free half of [`Self::publish_dm_reply`], so an
    /// in-crate test drives the REAL wrapping code (not a copy) and asserts the DM key signs it (never
    /// the FROST money key Q). Mirrors how `frost_sign_event` factors `publish_note`'s Frost branch.
    async fn build_dm_reply_event(
        &self,
        to: nostr_sdk::PublicKey,
        text: &str,
    ) -> anyhow::Result<Event> {
        use anyhow::Context as _;
        let dm_keys = self
            .dm_keys
            .as_ref()
            .context("nostr.dm_reply requested but no DM key is configured (boot-wiring bug)")?;
        EventBuilder::private_msg(dm_keys, to, text, [])
            .await
            .context("NIP-17-wrap the DM reply")
    }
}

#[async_trait::async_trait]
impl Actuator for NostrActuator {
    fn cost(&self, kind: &str) -> u64 {
        match kind {
            // The public voice and the private DM reply share one small fixed host cost (the
            // agent spends to act; the DM is still FREE for the human -- no inbound charge).
            kirby_proto::ACTUATE_KIND_NOSTR_PUBLISH | kirby_proto::ACTUATE_KIND_NOSTR_DM_REPLY => {
                self.cost_sats
            }
            // An unknown kind: refuse it OVER_BUDGET at the gate (fail-closed), never perform.
            _ => u64::MAX,
        }
    }

    fn validate(&self, kind: &str, payload: &[u8]) -> Result<(), String> {
        // The shared daemon-side guards (decode + re-sanitize + re-cap). Discard the clean output
        // here; `actuate` re-runs it to get the content to publish. A free denial on malformed.
        match kind {
            kirby_proto::ACTUATE_KIND_NOSTR_PUBLISH => validate_nostr_publish(payload).map(|_| ()),
            kirby_proto::ACTUATE_KIND_NOSTR_DM_REPLY => validate_nostr_dm_reply(payload).map(|_| ()),
            _ => Err(format!("unknown actuator kind {kind:?}")),
        }
    }

    async fn actuate(&self, kind: &str, payload: &[u8], cap_sats: u64) -> RailOutcome {
        match kind {
            kirby_proto::ACTUATE_KIND_NOSTR_PUBLISH => {
                // DEFENSE IN DEPTH (new entry point): decode + restrict the kind + RE-sanitize the
                // content with the SAME shared rule, never trusting the genome did it. A rejection
                // => refuse + 0.
                let content = match validate_nostr_publish(payload) {
                    Ok(clean) => clean,
                    Err(reason) => {
                        tracing::warn!(%reason, "nostr.publish refused by the daemon-side guard");
                        return RailOutcome::UpstreamFailed;
                    }
                };
                // Sign + publish the kind:1 note (the daemon's host networking; the VM sees no bytes).
                match self.publish_note(&content).await {
                    Ok(event_id) => {
                        tracing::info!(event_id = %event_id, "published a kind:1 note (the agent's outward voice)");
                        let actual_cost = self.cost_sats.min(cap_sats);
                        RailOutcome::Performed { actual_cost, proof: event_id.into_bytes(), completion: Vec::new() }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "nostr.publish failed to reach the relay; debiting nothing");
                        RailOutcome::UpstreamFailed
                    }
                }
            }
            kirby_proto::ACTUATE_KIND_NOSTR_DM_REPLY => {
                // DEFENSE IN DEPTH (new entry point): decode + RE-parse the recipient + RE-sanitize
                // the text, never trusting the genome did it. A rejection => refuse + 0.
                let (to, text) = match validate_nostr_dm_reply(payload) {
                    Ok(parsed) => parsed,
                    Err(reason) => {
                        tracing::warn!(%reason, "nostr.dm_reply refused by the daemon-side guard");
                        return RailOutcome::UpstreamFailed;
                    }
                };
                // NIP-17-wrap + sign with the PLAIN DM key (never Q) + publish (host networking).
                match self.publish_dm_reply(to, &text).await {
                    Ok(event_id) => {
                        tracing::info!(event_id = %event_id, recipient = %to.to_hex(), "published a NIP-17 DM reply (the agent's private voice)");
                        let actual_cost = self.cost_sats.min(cap_sats);
                        RailOutcome::Performed { actual_cost, proof: event_id.into_bytes(), completion: Vec::new() }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "nostr.dm_reply failed to reach the relay; debiting nothing");
                        RailOutcome::UpstreamFailed
                    }
                }
            }
            _ => {
                tracing::warn!(kind, "NostrActuator asked for an unknown actuator kind; refusing");
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

// ---- RoutstrBrain: the REAL brain (Cashu-paid Routstr inference) --------------------
//
// A second [`BrainBackend`] impl (behind the already-merged trait, zero proto/genome
// change). `complete()` mints an X-Cashu token worth the per-call cap from the treasury
// wallet, POSTs the OpenAI-compat chat request to the pinned Routstr node with the token
// as the `X-Cashu` bearer, parses the reply + the change token from the `X-Cashu`
// response header, redeems the change back into the wallet, and debits
// `actual_cost = cap - change_received` (the never-overspend `reconcile_cost`). The
// node can never take more than the token's value, so the spend is bounded by the cap
// by construction (D-20). See plans/build-spec-kirby-routstr-brain-20260622.md (v3).
//
// Money-path invariants (load-bearing, NOT inferred — spec §4/§5/§7):
//   - The payment boundary is the MINT (`mint_send_token`), NOT the HTTP send (HIGH-1):
//     once the token is minted the wallet's proofs are pending-spent, so ANY post-mint
//     failure first reclaims our OWN un-consumed send via `revoke_send(operation_id)`
//     (R2-1 — NOT `receive`, which is for foreign tokens), then the RIP-01 refund, then
//     debits only the unrecovered remainder. Money-left-wallet => never UpstreamFailed/0
//     unless the token was FULLY reclaimed (wallet made whole).
//   - The kill-window is TWO bounded phases (R2-2): a `request_timeout`-bounded MAIN
//     path (mint -> POST -> parse -> redeem change) whose minted handle is STASHED so a
//     timeout that drops the main future leaves the handle for cleanup; then a
//     `recovery_timeout`-bounded CLEANUP phase (revoke -> refund) run OUTSIDE the expired
//     main future so it is never cancelled.
//   - `max_cost_sats` is a CEILING: unredeemed change counts as zero recovered
//     (`actual_cost = cap - change_SUCCESSFULLY_received`, §4 safe rule), keeping the
//     counter debit from ever over-crediting past the real wallet spend.
//   - Bearer-token safety (MED-3): the HTTP client disables redirects (a redirect would
//     resend the X-Cashu bearer ecash to another host); HTTPS is enforced for non-local
//     nodes at config-validate; the X-Cashu request/change/refund tokens are spendable
//     instruments and are NEVER written to a log/trace, even at debug.

use std::time::Duration;

/// The cdk send-saga operation id: `Wallet::prepare_send` -> `operation_id()` ->
/// `revoke_send(operation_id)`. Carried on a [`SendHandle`] so an un-consumed X-Cashu
/// send can be reclaimed (R2-1, the same-wallet reclaim primitive).
pub type OperationId = uuid::Uuid;

/// A freshly-minted, reclaimable X-Cashu send: the wire token (`cashuB…` V4) plus the
/// local send saga's [`OperationId`]. The operation id is what makes the send our OWN
/// (revocable) rather than a foreign token to `receive` (R2-1).
pub struct SendHandle {
    /// The encoded `cashuB…` token to hand the node as the `X-Cashu` bearer. SPENDABLE
    /// bearer money — never log it (MED-3).
    pub token: String,
    /// The local send saga id, for `revoke_send` (reclaim our own un-consumed send).
    pub operation_id: OperationId,
}

/// The ecash seam RoutstrBrain mints/redeems through, so the HTTP + reconcile logic is
/// testable without a live mint (a [`StubEcash`] models tokens/handles/amounts in CI;
/// [`CdkEcash`] wraps the real treasury wallet). Mirrors the [`Rail`]/[`BrainBackend`]
/// trait-seam idiom and is where the "which mint / how funded" money concern lives.
#[async_trait::async_trait]
pub trait EcashProvider: Send + Sync {
    /// Mint a send token worth EXACTLY `amount_sats` from the wallet (the spend cap).
    /// Returns the wire token + its operation id. THIS is the payment boundary (HIGH-1):
    /// on `Ok` the wallet's proofs are already pending-spent.
    async fn mint_send_token(&self, amount_sats: u64) -> anyhow::Result<SendHandle>;
    /// Redeem a FOREIGN token (the node's change token, or a RIP-01 refund token) into
    /// the wallet; returns the sats recovered. NOT for our own sends (use `revoke_send`).
    async fn redeem_foreign(&self, token: &str) -> anyhow::Result<u64>;
    /// Reclaim our OWN un-consumed send by its operation id (R2-1); returns sats back.
    /// MUST fail cleanly (without corrupting wallet state) if the node already redeemed
    /// the token (then the caller falls through to the RIP-01 refund).
    async fn revoke_send(&self, op: &OperationId) -> anyhow::Result<u64>;
    /// Boot-time recovery of any send/receive interrupted by a prior crash/timeout
    /// (R2-4), run BEFORE the §7.2 wallet<->counter reconcile.
    async fn recover_incomplete_sagas(&self) -> anyhow::Result<()>;
}

/// The real ecash provider: wraps the funded treasury `cdk::Wallet` (the host-only
/// credential the genome never sees). All ops are the daemon's own host networking to
/// the mint; nothing cdk crosses vsock.
pub struct CdkEcash {
    wallet: Arc<cdk::Wallet>,
}

impl CdkEcash {
    /// Build the provider over a funded wallet.
    pub fn new(wallet: Arc<cdk::Wallet>) -> Self {
        CdkEcash { wallet }
    }

    /// The wrapped wallet (host-side only; for boot-time reconcile + tests to observe
    /// the balance). Never exposed to the genome.
    pub fn wallet(&self) -> &Arc<cdk::Wallet> {
        &self.wallet
    }
}

#[async_trait::async_trait]
impl EcashProvider for CdkEcash {
    async fn mint_send_token(&self, amount_sats: u64) -> anyhow::Result<SendHandle> {
        // prepare_send selects/szwaps proofs to a token worth `amount_sats`; confirm
        // materializes the `cashuB…` token. The operation id is captured BEFORE confirm
        // (which consumes the PreparedSend) so an un-consumed send stays revocable.
        let prepared = self
            .wallet
            .prepare_send(
                cdk::Amount::from(amount_sats),
                cdk::wallet::SendOptions::default(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("prepare_send {amount_sats} sat: {e}"))?;
        let operation_id = prepared.operation_id();
        let token = prepared
            .confirm(None)
            .await
            .map_err(|e| anyhow::anyhow!("confirm send token: {e}"))?;
        Ok(SendHandle {
            token: token.to_string(),
            operation_id,
        })
    }

    async fn redeem_foreign(&self, token: &str) -> anyhow::Result<u64> {
        let amount = self
            .wallet
            .receive(token, cdk::wallet::ReceiveOptions::default())
            .await
            .map_err(|e| anyhow::anyhow!("receive (redeem) foreign token: {e}"))?;
        Ok(amount.into())
    }

    async fn revoke_send(&self, op: &OperationId) -> anyhow::Result<u64> {
        // revoke_send swaps our own un-consumed send proofs back; it returns a clean
        // Err ("Operation is not a pending send") if the node already redeemed it.
        let amount = self
            .wallet
            .revoke_send(*op)
            .await
            .map_err(|e| anyhow::anyhow!("revoke_send (reclaim our un-consumed send): {e}"))?;
        Ok(amount.into())
    }

    async fn recover_incomplete_sagas(&self) -> anyhow::Result<()> {
        self.wallet
            .recover_incomplete_sagas()
            .await
            .map_err(|e| anyhow::anyhow!("recover_incomplete_sagas: {e}"))?;
        Ok(())
    }
}

/// The never-overspend cost reconciliation (the money invariant, §4). `actual_cost =
/// cap - change_received`, clamped to `[0, cap]`: change greater than the cap clamps to
/// 0 (never a negative/underflowed debit), and zero change debits the full cap. PURE so
/// it is unit-tested directly, free of HTTP/cdk. `change_received` MUST be only the
/// change SUCCESSFULLY redeemed (unredeemed change counts as zero — the safe rule that
/// keeps the counter debit from over-crediting past the real wallet spend).
pub fn reconcile_cost(cap: u64, change_received: u64) -> u64 {
    cap.saturating_sub(change_received)
}

/// The OpenAI-compat chat request body (the daemon builds JSON; the genome stayed
/// dep-free). `stream:false` is pinned: stateless X-Cashu mode cannot stream (the change
/// is only knowable after the full response).
#[derive(serde::Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage<'a>>,
    stream: bool,
}

#[derive(serde::Serialize)]
struct WireMessage<'a> {
    role: &'a str,
    content: &'a str,
}

/// The OpenAI-compat chat response. Unknown fields (id/usage/…) are ignored. A null
/// `content` (tool-call replies, out of scope §10) fails to deserialize -> treated as a
/// malformed body -> cleanup path.
#[derive(serde::Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ResponseChoice>,
}

#[derive(serde::Deserialize)]
struct ResponseChoice {
    message: ResponseMessage,
}

#[derive(serde::Deserialize)]
struct ResponseMessage {
    content: String,
}

/// A RIP-01 refund response: a refund token to `receive`. Accepted from either the
/// `X-Cashu` response header or this JSON body (node-specific; best-effort, Layer-C).
#[derive(serde::Deserialize)]
struct RefundResponse {
    token: String,
}

/// The prepaid-API-key chat response ([`RoutstrKeyBrain`]): the OpenAI-compat `choices`
/// PLUS the Routstr cost metadata the node injects into the BODY on the bearer-key path
/// (there is NO cost HTTP header on that path — cost lives in the body). Every cost field
/// is optional/defaulted so a node that omits one still deserializes; the cost is then
/// resolved by [`KeyChatResponse::charged_sats`] (exact `total_msats` first, else the
/// already-sats `cost_sats`, else — at the call site — the full cap, the safe rule).
#[derive(serde::Deserialize)]
struct KeyChatResponse {
    choices: Vec<ResponseChoice>,
    #[serde(default)]
    cost: Option<KeyCost>,
    #[serde(default)]
    usage: Option<KeyUsage>,
}

/// The top-level `cost` object Routstr injects on the bearer-key path. `total_msats` is
/// the EXACT charge in MILLISATOSHIS (the authoritative figure; `1 sat = 1000 msats`).
#[derive(serde::Deserialize)]
struct KeyCost {
    #[serde(default)]
    total_msats: Option<u64>,
}

/// The OpenAI `usage` block, extended by Routstr with `cost_sats` (the charge already in
/// SATOSHIS, integer-truncated from msats by the node) — the fallback used when the exact
/// `cost.total_msats` is absent.
#[derive(serde::Deserialize)]
struct KeyUsage {
    #[serde(default)]
    cost_sats: Option<u64>,
}

/// The `/v1/balance/info` response (only the field we use). `balance` is the prepaid
/// key's SPENDABLE balance in MILLISATOSHIS (net of any reserved amount), the node's
/// authoritative figure. `1 sat = 1000 msats`.
#[derive(serde::Deserialize)]
struct BalanceInfo {
    balance: u64,
}

impl KeyChatResponse {
    /// The sats charged for this think, read from the response body: prefer the exact
    /// `cost.total_msats` (msats -> sats, rounded UP so a sub-sat charge still costs >= 1
    /// and we never under-debit), else the already-sats `usage.cost_sats`. Returns `None`
    /// only if the node returned NEITHER cost field (the caller then debits the cap — the
    /// safe never-under-debit rule, since a served completion was charged something).
    fn charged_sats(&self) -> Option<u64> {
        if let Some(msats) = self.cost.as_ref().and_then(|c| c.total_msats) {
            return Some(msats.div_ceil(1000));
        }
        self.usage.as_ref().and_then(|u| u.cost_sats)
    }
}

/// The result of the bounded MAIN path (after a successful mint).
enum MainOutcome {
    /// A usable reply came back; `change_received` is the sats redeemed from the change
    /// token (0 if absent/lost — §4 safe rule). The node consumed the token, so no
    /// revoke is needed; debit `cap - change_received`.
    Replied {
        reply: Vec<u8>,
        change_received: u64,
    },
    /// A post-mint failure (connect/send error, timeout, non-2xx, or malformed body):
    /// the token may or may not have been consumed -> run the revoke/refund cleanup.
    NeedsCleanup,
}

/// Why the main path produced no [`MainOutcome`].
enum MainErr {
    /// The mint itself failed: the token was NEVER (confirmed) minted, so no sats left
    /// the wallet -> UpstreamFailed/0 (the only debit-0-after-the-boundary-safe case
    /// besides full reclaim).
    PreMint(String),
    /// The whole main path exceeded `request_timeout` (the future was dropped). A token
    /// MAY have been minted (check the stash) -> cleanup if so.
    Timeout,
}

/// The real brain: Cashu-paid Routstr inference behind [`BrainBackend`]. Generic over
/// the [`EcashProvider`] seam ([`CdkEcash`] live, a stub in CI).
pub struct RoutstrBrain<E: EcashProvider> {
    /// Built ONCE with redirects disabled + the per-call timeout (MED-3 / §5).
    http: reqwest::Client,
    /// The pinned Routstr base URL (the `brain.completion` sentinel maps here, R2). The
    /// genome/gateway never see this host.
    node_url: String,
    ecash: E,
    /// The MAIN-path kill-window (mint -> POST -> parse -> redeem change).
    request_timeout: Duration,
    /// The CLEANUP (revoke/refund) budget, separate from the main path so cleanup is
    /// never cancelled by the main deadline (R2-2).
    recovery_timeout: Duration,
}

impl<E: EcashProvider> RoutstrBrain<E> {
    /// Build the brain over a pinned node URL and an ecash provider. The HTTP client is
    /// constructed once with redirects DISABLED (a redirect would leak the X-Cashu
    /// bearer ecash to another host, MED-3) and the per-call request timeout.
    pub fn new(
        node_url: String,
        ecash: E,
        request_timeout: Duration,
        recovery_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(request_timeout)
            .build()
            .map_err(|e| anyhow::anyhow!("build RoutstrBrain HTTP client: {e}"))?;
        Ok(RoutstrBrain {
            http,
            node_url,
            ecash,
            request_timeout,
            recovery_timeout,
        })
    }

    /// The MAIN path AFTER a successful mint: POST the completion with the X-Cashu token,
    /// parse the reply, read + redeem the change. Returns [`MainOutcome`]. Never panics;
    /// any error maps to [`MainOutcome::NeedsCleanup`] (a reply, once parsed, is kept
    /// even if the change redeem then fails/hangs — §4 safe rule).
    async fn main_path(&self, token: &str, model: &str, messages: &[ChatMessage]) -> MainOutcome {
        let url = format!("{}/v1/chat/completions", self.node_url.trim_end_matches('/'));
        let body = ChatCompletionRequest {
            model,
            messages: messages
                .iter()
                .map(|m| WireMessage {
                    role: &m.role,
                    content: &m.content,
                })
                .collect(),
            stream: false,
        };
        // The X-Cashu token is bearer money; it is attached as a header and NEVER logged.
        let resp = match self
            .http
            .post(&url)
            .header("X-Cashu", token)
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Connect/send/timeout: the node never accepted the token (or we can't
                // tell). Reclaim it. (e renders the URL but not our headers -> no token leak.)
                tracing::warn!(error = %e, "routstr POST failed before a usable response; reclaiming the token");
                return MainOutcome::NeedsCleanup;
            }
        };
        let status = resp.status();
        if !status.is_success() {
            tracing::warn!(%status, "routstr returned a non-success status; reclaiming the token");
            return MainOutcome::NeedsCleanup;
        }
        // Read the change token from the X-Cashu RESPONSE header before consuming the body.
        let change_token = resp
            .headers()
            .get("X-Cashu")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let parsed: ChatCompletionResponse = match resp.json().await {
            Ok(b) => b,
            Err(_) => {
                tracing::warn!("routstr 200 body was malformed / unparseable; reclaiming the token");
                return MainOutcome::NeedsCleanup;
            }
        };
        let reply = match parsed.choices.into_iter().next() {
            // A present content (even "") is a legal, paid (if wasted) think (§5): keep it.
            Some(choice) => choice.message.content.into_bytes(),
            None => {
                tracing::warn!("routstr 200 had no choices/content; reclaiming the token");
                return MainOutcome::NeedsCleanup;
            }
        };
        // The node consumed the token (we have a reply). Redeem the change, BOUNDED so a
        // hung redeem cannot cost us the reply we already hold (§4 safe rule: count 0).
        let change_received = match change_token {
            Some(tok) => tokio::time::timeout(self.recovery_timeout, self.ecash.redeem_foreign(&tok))
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0),
            None => 0,
        };
        MainOutcome::Replied {
            reply,
            change_received,
        }
    }

    /// Reclaim sats after a post-mint failure (§5 recovery order), BOUNDED by
    /// `recovery_timeout` and run OUTSIDE the (possibly expired) main future (R2-2).
    /// (1) `revoke_send` our OWN un-consumed send (R2-1); (2) if that recovered nothing
    /// (token consumed), the RIP-01 refund of the original token; (3) eat the remainder.
    /// Returns total sats recovered.
    async fn recover_after_failure(&self, handle: &SendHandle) -> u64 {
        let cleanup = async {
            let revoked = self.ecash.revoke_send(&handle.operation_id).await.unwrap_or(0);
            if revoked > 0 {
                return revoked;
            }
            // The node consumed the token; try the RIP-01 refund (works iff it reserved
            // but did not fully charge), then redeem the returned refund token.
            match self.request_refund(&handle.token).await {
                Ok(refund_token) => self.ecash.redeem_foreign(&refund_token).await.unwrap_or(0),
                Err(_) => 0,
            }
        };
        tokio::time::timeout(self.recovery_timeout, cleanup).await.unwrap_or(0)
    }

    /// The RIP-01 refund: POST the original token to `{node}/v1/balance/refund` and read
    /// the returned refund token (from the `X-Cashu` header or a JSON body). Best-effort
    /// (a failure just means we eat the remainder); the token is bearer money, never
    /// logged. Exercised live at Layer C; in CI via the mock node + StubEcash.
    ///
    /// The canonical endpoint is `/v1/balance/refund`; the node serves a deprecated
    /// `/v1/wallet/refund` alias for the SAME handler (it accepts an `x-cashu` header and
    /// returns the refund token in the `X-Cashu` response header or a `{ "token": … }`
    /// body), but the `/v1/wallet/*` aliases may be dropped — point at the stable path.
    async fn request_refund(&self, original_token: &str) -> anyhow::Result<String> {
        let url = format!("{}/v1/balance/refund", self.node_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .header("X-Cashu", original_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("routstr refund returned status {}", resp.status());
        }
        if let Some(tok) = resp.headers().get("X-Cashu").and_then(|v| v.to_str().ok()) {
            return Ok(tok.to_string());
        }
        let body: RefundResponse = resp.json().await?;
        Ok(body.token)
    }
}

#[async_trait::async_trait]
impl<E: EcashProvider> BrainBackend for RoutstrBrain<E> {
    async fn complete(
        &self,
        model: &str,
        messages: &[ChatMessage],
        max_cost_sats: u64,
    ) -> anyhow::Result<(Vec<u8>, u64)> {
        // The minted handle is stashed the instant the mint returns, so a timeout that
        // DROPS the main future still leaves the handle for the cleanup phase (R2-2 +
        // HIGH-1). A std Mutex is fine here: the guard is never held across an `.await`.
        let minted: Arc<std::sync::Mutex<Option<SendHandle>>> =
            Arc::new(std::sync::Mutex::new(None));

        let main = {
            let minted = minted.clone();
            async move {
                // Phase 1: MINT (the payment boundary). Stash IMMEDIATELY, before any
                // network, so cleanup can find it even if this future is later dropped.
                let handle = self
                    .ecash
                    .mint_send_token(max_cost_sats)
                    .await
                    .map_err(|e| MainErr::PreMint(format!("{e}")))?;
                let token = handle.token.clone();
                {
                    *minted.lock().unwrap() = Some(handle);
                }
                // Phase 2: POST -> parse -> redeem change.
                Ok::<MainOutcome, MainErr>(self.main_path(&token, model, messages).await)
            }
        };

        // The MAIN path is bounded by request_timeout; on expiry the future is dropped
        // (its handle survives in `minted`).
        let outcome = match tokio::time::timeout(self.request_timeout, main).await {
            Ok(inner) => inner,
            Err(_) => Err(MainErr::Timeout),
        };

        let handle = { minted.lock().unwrap().take() };

        match (outcome, handle) {
            // Mint never produced a (confirmed) token: no sats left the wallet.
            (Err(MainErr::PreMint(e)), _) => {
                Err(anyhow::anyhow!("routstr pre-mint failure (no sats spent): {e}"))
            }
            (Err(MainErr::Timeout), None) => Err(anyhow::anyhow!(
                "routstr mint timed out (no token confirmed; any reserved proofs are recovered on next boot)"
            )),
            // A usable reply: debit cap - change (the never-overspend reconcile).
            (Ok(MainOutcome::Replied { reply, change_received }), _) => {
                Ok((reply, reconcile_cost(max_cost_sats, change_received)))
            }
            // Post-mint failure WITH a minted token: reclaim, then debit the remainder.
            (Ok(MainOutcome::NeedsCleanup), Some(h)) | (Err(MainErr::Timeout), Some(h)) => {
                let recovered = self.recover_after_failure(&h).await;
                let unrecovered = max_cost_sats.saturating_sub(recovered);
                if unrecovered == 0 {
                    // Fully reclaimed: the wallet is whole -> UpstreamFailed/0 is correct.
                    Err(anyhow::anyhow!(
                        "routstr completion failed; token fully reclaimed (no debit)"
                    ))
                } else {
                    // Money left the wallet and was not fully recovered: debit it. The
                    // empty completion is a legal Performed (genome pushes an empty turn).
                    Ok((Vec::new(), unrecovered))
                }
            }
            // Defensive: NeedsCleanup is only produced AFTER the stash, so a missing
            // handle here means we never minted. No debit.
            (Ok(MainOutcome::NeedsCleanup), None) => Err(anyhow::anyhow!(
                "routstr failed before the mint stash (no sats spent)"
            )),
        }
    }
}

/// The prepaid API-KEY brain (config `backend = "routstr_key"`): real Routstr inference
/// paid from a CUSTODIAL, node-held balance via a bearer key on the `Authorization`
/// header. MINT-INDEPENDENT — it touches no Cashu mint, so it keeps thinking when the
/// treasury wallet's mint is unreachable. It is the resilience fallback that coexists with
/// the sovereign, self-custody per-request [`RoutstrBrain`] (the default); both impl the
/// SAME [`BrainBackend`], so selecting one is a config change, not a genome/proto change.
///
/// Unlike [`RoutstrBrain`] there is no mint / X-Cashu token / prepare_send / revoke /
/// refund saga: a think is a single authenticated POST. The money already left at funding
/// time (the Lightning invoice that minted the key), so a failed POST charges nothing
/// (there is no token to reclaim) and the cost of a SUCCESS is read straight from the
/// response body (`cost.total_msats`, exact). The runway still drains and "die-when-broke"
/// still holds: boot asserts the custodial balance backs the treasury counter, and the
/// gateway debits the counter by this returned cost on every think (the SAME counter the
/// Cashu path drains).
pub struct RoutstrKeyBrain {
    /// Built ONCE with redirects disabled (a redirect would leak the bearer key to another
    /// host — the MED-3 concern, identical to the X-Cashu token) and the per-call timeout.
    http: reqwest::Client,
    /// The pinned Routstr base URL. The genome/gateway never see this host.
    node_url: String,
    /// The prepaid bearer key (`sk-…`). Bearer money — attached via `Authorization` and
    /// NEVER logged; the struct is intentionally NOT `Debug` so it cannot leak through a
    /// derived formatter (the same discipline as the wallet seed / dm key).
    api_key: String,
}

impl RoutstrKeyBrain {
    /// Build the brain over a pinned node URL and a prepaid bearer key. The HTTP client is
    /// constructed once with redirects DISABLED (MED-3: a redirect would leak the bearer
    /// key to another host) and the per-call request timeout (the kill-window for a think,
    /// the same role `request_timeout` plays for [`RoutstrBrain`]).
    pub fn new(
        node_url: String,
        api_key: String,
        request_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(request_timeout)
            .build()
            .map_err(|e| anyhow::anyhow!("build RoutstrKeyBrain HTTP client: {e}"))?;
        Ok(RoutstrKeyBrain {
            http,
            node_url,
            api_key,
        })
    }

    /// Fetch the prepaid key's spendable balance from `{node}/v1/balance/info`, in SATS
    /// (the node reports MILLISATOSHIS; floor-divide by 1000 — sub-sat dust is not
    /// spendable for a sat-denominated think). Boot calls this to BOTH validate the key
    /// works (a bad/empty/unfunded key returns non-2xx, surfaced as an error) AND read the
    /// custodial balance for the wallet<->counter refuse-to-boot check. The key is bearer
    /// money, attached via `Authorization` and never logged.
    pub async fn fetch_balance_sats(&self) -> anyhow::Result<u64> {
        let url = format!("{}/v1/balance/info", self.node_url.trim_end_matches('/'));
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("routstr_key balance-info request failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!(
                "routstr_key balance-info returned a non-success status: {status} (is the prepaid api key valid + funded?)"
            );
        }
        let info: BalanceInfo = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("routstr_key balance-info body was malformed: {e}"))?;
        // msats -> whole spendable sats (1 sat = 1000 msats). Floor: a fractional sat is
        // not spendable for a sat-denominated think, so it must not inflate the backing check.
        Ok(info.balance / 1000)
    }
}

#[async_trait::async_trait]
impl BrainBackend for RoutstrKeyBrain {
    async fn complete(
        &self,
        model: &str,
        messages: &[ChatMessage],
        max_cost_sats: u64,
    ) -> anyhow::Result<(Vec<u8>, u64)> {
        let url = format!("{}/v1/chat/completions", self.node_url.trim_end_matches('/'));
        let body = ChatCompletionRequest {
            model,
            messages: messages
                .iter()
                .map(|m| WireMessage {
                    role: &m.role,
                    content: &m.content,
                })
                .collect(),
            stream: false,
        };
        // The bearer key is attached via `Authorization: Bearer …` and NEVER logged. NO
        // X-Cashu header: the balance is custodial, charged server-side per request. A
        // reqwest error renders the URL but not our headers, so the key cannot leak.
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("routstr_key POST failed before a usable response: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            // The custodial balance is debited server-side ONLY on a served completion, so
            // a non-2xx is a clean no-debit failure (UpstreamFailed/0): no token was spent,
            // nothing to reclaim. (A 401/403 here means the key is bad/empty — boot's
            // balance-info probe is what catches that before the VM ever starts.)
            anyhow::bail!("routstr_key node returned a non-success status: {status}");
        }
        let parsed: KeyChatResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("routstr_key response body was malformed/unparseable: {e}"))?;
        // The node returns the EXACT charge in the body (no cost header on this path).
        // Resolve it (exact total_msats -> sats rounded up, else the already-sats
        // cost_sats), falling back to the full cap when the node returned neither (the safe
        // never-under-debit rule). Clamp to the cap (D-20: a think never debits past the
        // gateway-checked per-call budget, exactly as the Cashu path's reconcile does).
        // Computed by an immutable borrow FIRST, so `choices` can then be consumed for the
        // reply (no clone).
        let cost_sats = parsed.charged_sats().unwrap_or(max_cost_sats).min(max_cost_sats);
        let reply = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content.into_bytes())
            .ok_or_else(|| anyhow::anyhow!("routstr_key response had no choices/content"))?;
        Ok((reply, cost_sats))
    }
}

#[cfg(test)]
mod routstr_reconcile_tests {
    use super::reconcile_cost;

    // The never-overspend money invariant (§4), tested as a pure fn (no HTTP, no cdk).
    #[test]
    fn reconcile_change_less_than_cap_debits_the_difference() {
        // cap 64, change 50 -> debit 14 (the real price the node charged).
        assert_eq!(reconcile_cost(64, 50), 14);
    }

    #[test]
    fn reconcile_zero_change_debits_the_full_cap() {
        // No/lost change (the safe rule counts unredeemed change as zero) -> debit cap.
        assert_eq!(reconcile_cost(64, 0), 64);
    }

    #[test]
    fn reconcile_change_equal_to_cap_debits_zero() {
        // The node charged nothing (full change) -> debit 0.
        assert_eq!(reconcile_cost(64, 64), 0);
    }

    #[test]
    fn reconcile_change_over_cap_clamps_to_zero_never_underflows() {
        // A bogus change greater than the cap must clamp to 0, never underflow to a huge
        // debit (or panic in debug). D-20 floor.
        assert_eq!(reconcile_cost(64, 1000), 0);
    }

    #[test]
    fn reconcile_is_bounded_by_the_cap() {
        // For any change, the debit is in [0, cap] — the never-overspend ceiling.
        for cap in [0u64, 1, 16, 64, 1000] {
            for change in [0u64, 1, 32, 64, 1000, u64::MAX] {
                let cost = reconcile_cost(cap, change);
                assert!(cost <= cap, "reconcile_cost({cap},{change})={cost} exceeded the cap");
            }
        }
    }
}

// ---- The real engram store (durable mind-state Chunk-2): NIP-AE over the nerve ----
//
// `EngramStore` is the production [`MemoryBackend`]: it swaps in for [`StubMemory`]
// behind `Arc<dyn MemoryBackend>` when `[memory].relays` is configured (boot.rs);
// `StubMemory` stays the test/dev default. It holds the node identity + a connected
// nostr-sdk client to the N-relay set and performs the Memory act as real NIP-AE
// engrams (design doc §16):
//   - each engram is an addressable kind-30174 event; `d` = HMAC(K_dtag, slug) (the
//     slug never appears in plaintext on a relay); content = NIP-44 self-encrypted
//     (encrypt to the agent's OWN pubkey) so memory is private to the identity key
//     (see [`crate::engram`]);
//   - a WRITE publishes to N relays and succeeds at K-of-N acks. The write-time copy
//     count IS the durability (design doc §16): there is NO ongoing rent and NO
//     renewal -- the engram then PERSISTS on the relays it reached;
//   - a READ unions the relay set, LWW-reconciles per d-tag (greatest created_at,
//     tie -> lowest id), decrypts locally (the daemon holds the key), drops tombstones.
//
// The METERING contract is UNCHANGED from `StubMemory` (the gateway owns it, design
// doc 11/12): `write_cost` is HOST-computed (G2); reads are free and bypass the ledger
// (G3). This backend performs + reports the host cost; the gateway debits on the
// Chunk-1 perform-then-debit flow.
//
// DOCUMENTED KNOWN GAP (design doc §16 -- accepted, bounded; closed by the shared
// gateway-hardening chunk, NOT a Chunk-2 bug): the stored-but-never-paid DEATH-WINDOW.
// A write can reach a relay (perform) and the agent can budget-die BEFORE the gateway
// debit lands -- one engram stored without a debit, at death. It is BOUNDED (one write,
// at the moment of death) and there is no leaked-storage growth (no rent). Exactly-once
// across a crash (the reservation/outbox primitive) is gateway-hardening's, shared with
// the brain F2 + routstr HIGH-2 paths; it is deliberately NOT built here.
//
// ALSO DEFERRED to gateway-hardening (design doc §16 F7), documented-not-silent:
// BACKGROUND REPAIR -- restoring a write's copy-count back to N after a transient
// relay miss (a publish that reached only some of the N relays). A write is already
// K-of-N MAJORITY-durable without it, so this is a durability top-up, NOT a
// correctness gap; the repair needs the lease-fenced-worker machinery (a single
// fenced owner re-publishing, so concurrent daemons don't storm the relays) that is
// gateway-hardening's -- NOT built here.
//
// The reservation primitive, ongoing retention rent, renewal, the
// degrade->at-risk->expire ladder, and `MemoryAtRisk` are all OUT of Chunk-2 scope
// (design doc §16): a write pays ONCE, the memory persists, a broke agent can still
// READ (reads are free) but cannot WRITE -- "recall but can't record" falls out for
// free with zero rent/ladder machinery.

/// The relay read timeout: how long a GET/LS fetch waits for the relay-set union
/// before reconciling what it has. Bounded so the daemon never hangs on a slow relay.
const ENGRAM_READ_TIMEOUT_SECS: u64 = 4;

/// The real NIP-AE engram store (design doc §16). Cheap to clone (an `Arc` over the
/// nostr client + the committed-token cache + the logical clock).
#[derive(Clone)]
pub struct EngramStore {
    /// Per-key crypto + addressing (self-ECDH root, d-tag HMAC, NIP-44 sealing).
    crypto: EngramCrypto,
    /// The connected nostr-sdk client to the N-relay set (an `Arc` so clones share
    /// the one connection pool).
    client: Arc<Client>,
    /// The relay-set size (copy-count N): `write_cost` scales by it, and a write's
    /// durability is the number of relays it reaches.
    n: usize,
    /// The K-of-N ack threshold a WRITE must reach to count as stored (default =
    /// majority; configurable). `K <= N`.
    k: usize,
    /// Host storage-cost knob: a write costs `ceil((slug+value bytes) / bytes_per_sat)`
    /// sats PER COPY, times `N` copies (min `N`). Deterministic + recomputable (G2).
    bytes_per_sat: u64,
    /// The per-write logical clock for event `created_at`: `max(now_secs, last + 1)`
    /// so LWW orders writes in issue order even within one wall-clock second (design
    /// doc §16 "simple monotonic-per-agent logical timestamp"). In-memory: it resets
    /// on restart, but wall-clock `now` has advanced past any pre-restart value, so
    /// monotonicity holds in practice. The persisted-grade clock is gateway-hardening's.
    clock: Arc<AtomicU64>,
    /// In-memory committed-token cache (write_token -> the first result). A re-perform
    /// of a token within THIS daemon lifetime returns `AlreadyCommittedSameWseq` with
    /// no re-publish (mirrors `StubMemory`'s G6 contract). NOT durable -- the durable
    /// outbox is gateway-hardening's; across a restart this is empty and a re-publish is
    /// absorbed by replaceable-LWW (same content, newer `created_at` wins). Reads bypass
    /// it (free).
    committed: Arc<Mutex<HashMap<String, MemoryResult>>>,
    /// The relay read timeout (a fetch waits this long for the union).
    read_timeout: Duration,
}

impl EngramStore {
    /// Connect an engram store: derive the crypto from `keys`, build a nostr-sdk
    /// client signed by them, add the N relays, and connect. `write_k` is the K-of-N
    /// threshold (defaults to majority `floor(N/2)+1`, clamped to `[1, N]`).
    ///
    /// Returns an error if no relay is configured (a misconfigured EngramStore is a
    /// boot bug, not a runtime Memory outcome) or the self-ECDH key derivation fails.
    pub async fn connect(
        keys: Keys,
        relays: &[String],
        write_k: Option<usize>,
        bytes_per_sat: u64,
    ) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        if relays.is_empty() {
            anyhow::bail!("EngramStore requires at least one [memory].relays entry");
        }
        let crypto = EngramCrypto::new(keys.clone())?;
        let client = Client::builder().signer(keys).build();
        for url in relays {
            client
                .add_relay(url)
                .await
                .with_context(|| format!("add memory relay {url}"))?;
        }
        client.connect().await;
        let n = relays.len();
        // Default K = strict majority; a configured K is clamped into [1, N].
        let k = write_k.unwrap_or(n / 2 + 1).clamp(1, n);
        tracing::info!(
            npub = %crypto.public_key().to_bech32().unwrap_or_default(),
            n, k, "EngramStore connected to the nerve relay set (durable mind-state)"
        );
        Ok(EngramStore {
            crypto,
            client: Arc::new(client),
            n,
            k,
            bytes_per_sat: bytes_per_sat.max(1),
            clock: Arc::new(AtomicU64::new(0)),
            committed: Arc::new(Mutex::new(HashMap::new())),
            read_timeout: Duration::from_secs(ENGRAM_READ_TIMEOUT_SECS),
        })
    }

    /// The next monotonic `created_at` (the logical clock): `max(now_secs, last + 1)`,
    /// advanced atomically so concurrent writes never collide on a timestamp.
    fn next_created_at(&self) -> Timestamp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let secs = loop {
            let last = self.clock.load(Ordering::SeqCst);
            let next = now.max(last + 1);
            if self
                .clock
                .compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break next;
            }
        };
        Timestamp::from_secs(secs)
    }

    /// Fetch + LWW-reconcile the LIVE head frame for one slug across the relay set.
    /// `None` means absent (no event) or tombstoned (the head is a RM). A fetch error
    /// is [`MemoryError::Unreachable`] (the relay-set is down), which the gateway maps
    /// to a debit-nothing receipt.
    async fn read_head(&self, slug: &str) -> Result<Option<EngramFrame>, MemoryError> {
        let filter = Filter::new()
            .kind(Kind::from(KIND_ENGRAM))
            .author(self.crypto.public_key())
            .identifier(self.crypto.dtag(slug));
        let events = self
            .client
            .fetch_events(filter, self.read_timeout)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, slug, "engram GET fetch failed; store unreachable");
                MemoryError::Unreachable
            })?;
        let evs: Vec<Event> = events.into_iter().collect();
        let Some(head) = crate::engram::lww_head(&evs) else {
            return Ok(None);
        };
        let frame = self.crypto.decrypt(&head.content).map_err(|e| {
            // A head we cannot decrypt is a foreign/corrupt event under our address; do
            // not silently treat it as absent (that would mask data loss) -- surface it.
            tracing::error!(error = %e, slug, "engram head failed to decrypt");
            MemoryError::Unreachable
        })?;
        Ok(if frame.tombstone { None } else { Some(frame) })
    }

    /// Enumerate the live slugs: fetch every engram authored by this key, group by
    /// d-tag, LWW-reconcile each group, decrypt, drop tombstones, and collect the
    /// surviving slugs (sorted, so the result is stable). A frame that fails to decrypt
    /// is skipped (a foreign event under our author) rather than aborting the whole LS.
    async fn list_slugs(&self) -> Result<Vec<String>, MemoryError> {
        let filter = Filter::new()
            .kind(Kind::from(KIND_ENGRAM))
            .author(self.crypto.public_key());
        let events = self
            .client
            .fetch_events(filter, self.read_timeout)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "engram LS fetch failed; store unreachable");
                MemoryError::Unreachable
            })?;
        let mut by_dtag: HashMap<String, Vec<Event>> = HashMap::new();
        for ev in events.into_iter() {
            if let Some(d) = crate::engram::event_dtag(&ev) {
                by_dtag.entry(d).or_default().push(ev);
            }
        }
        let mut slugs = Vec::new();
        for group in by_dtag.values() {
            if let Some(head) = crate::engram::lww_head(group) {
                match self.crypto.decrypt(&head.content) {
                    Ok(frame) if !frame.tombstone => slugs.push(frame.slug),
                    Ok(_) => {} // a tombstone head: the slug is removed
                    Err(e) => {
                        tracing::warn!(error = %e, "engram LS skipping an undecryptable head")
                    }
                }
            }
        }
        slugs.sort();
        Ok(slugs)
    }

    /// Publish one engram frame to the relay set and require K-of-N acks. Builds the
    /// event once with the next logical-clock `created_at`, signs it (the client's
    /// signer), and broadcasts. Fewer than K acks (or a total send failure) is
    /// [`MemoryError::Unreachable`] -- the write did not durably land, so the gateway
    /// debits nothing.
    async fn publish(&self, frame: &EngramFrame) -> Result<(), MemoryError> {
        let created_at = self.next_created_at();
        let builder = self.crypto.event_builder(frame, created_at).map_err(|e| {
            tracing::error!(error = %e, "build engram event failed");
            MemoryError::Unreachable
        })?;
        let output = self
            .client
            .send_event_builder(builder)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "engram publish failed on every relay");
                MemoryError::Unreachable
            })?;
        let acks = output.success.len();
        if acks < self.k {
            tracing::warn!(
                acks, k = self.k, n = self.n, failed = ?output.failed,
                "engram write did not reach K-of-N relays; treating as unreachable (no debit)"
            );
            return Err(MemoryError::Unreachable);
        }
        tracing::debug!(acks, k = self.k, n = self.n, "engram write reached K-of-N");
        Ok(())
    }
}

#[async_trait::async_trait]
impl MemoryBackend for EngramStore {
    fn write_cost(&self, m: &Memory) -> u64 {
        // Host-computed, ONE-TIME storage cost (design doc §16): the per-copy byte cost
        // times the copy count N. Deterministic + recomputable; an RM (no value) still
        // costs >= N (a tombstone is a write to every relay).
        let bytes = (m.slug.len() + m.value.len()) as u64;
        bytes.div_ceil(self.bytes_per_sat).max(1) * self.n as u64
    }

    async fn read(&self, m: &Memory) -> Result<MemoryResult, MemoryError> {
        let op = MemoryOp::try_from(m.op).unwrap_or(MemoryOp::Unspecified);
        match op {
            MemoryOp::Get => {
                if !is_valid_slug(&m.slug) {
                    return Err(MemoryError::InvalidSlug(m.slug.clone()));
                }
                match self.read_head(&m.slug).await? {
                    Some(frame) => Ok(MemoryResult {
                        found: true,
                        content_hash: content_hash(&frame.value),
                        value: frame.value,
                        slugs: Vec::new(),
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
                let slugs = self.list_slugs().await?;
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
        let op = MemoryOp::try_from(m.op).unwrap_or(MemoryOp::Unspecified);
        if !is_valid_slug(&m.slug) {
            return Err(MemoryError::InvalidSlug(m.slug.clone()));
        }

        // G6: a re-perform of a token committed earlier in THIS lifetime is a replay --
        // return the SAME result + AlreadyCommittedSameWseq (the gateway still debits the
        // recomputable host cost exactly once). Across a restart the cache is empty; a
        // re-publish is then absorbed by replaceable-LWW (same content, newer wins).
        if let Some(prior) = self.committed.lock().unwrap().get(write_token).cloned() {
            return Ok(MemoryWrite {
                result: prior,
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
                let frame = EngramFrame::live(m.slug.clone(), m.value.clone());
                self.publish(&frame).await?;
                MemoryResult {
                    found: true,
                    value: Vec::new(),
                    slugs: Vec::new(),
                    content_hash: content_hash(&m.value),
                    write_status: WriteStatus::Stored as i32,
                }
            }
            MemoryOp::Rm => {
                // A pre-read sets `found`/`write_status` faithfully (did the slug exist
                // before the tombstone?). The tombstone is then published regardless
                // (idempotent: a RM of an absent slug still writes a tombstone head).
                let existed = self.read_head(&m.slug).await?.is_some();
                let frame = EngramFrame::tombstone(m.slug.clone());
                self.publish(&frame).await?;
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

        self.committed
            .lock()
            .unwrap()
            .insert(write_token.to_string(), result.clone());
        Ok(MemoryWrite {
            result,
            committed: WriteCommit::Stored,
        })
    }
}

#[cfg(test)]
mod frost_actuator_tests {
    use super::*;
    use crate::quorum_signer::local_quorum_from_keyset;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
    use bitcoin::KnownHrp;
    use kirby_custody::{generate_dealer_keyset, taproot_address};

    /// G-FROST-ACTUATOR-PUBLISHES-QUORUM-SIGNED-EVENT: drive the REAL FROST publish path of the
    /// actuator (`frost_sign_event`, the FROST-specific body of `publish_note`) WITHOUT a live
    /// relay, and assert the event it would publish is signed under the group taproot key Q and
    /// verifies (NIP-01 id + BIP-340 schnorr under Q, NOT under the untweaked internal key P).
    ///
    /// This closes the gap that the gated e2e (`frost_quorum_publish.rs`) only tested a COPY of the
    /// construction: here we build an in-process FROST-mode `NostrActuator` over a dealer keyset and
    /// call the actuator's OWN `frost_sign_event` (the exact method `publish_note`'s Frost branch
    /// calls before `client.send_event`). Only the generic relay transport is not exercised (it
    /// cannot run without a relay); every FROST-specific, load-bearing step is the production code.
    #[tokio::test]
    async fn g_frost_actuator_publishes_quorum_signed_event() {
        // A real 2-of-3 keyset + co-located quorum signer (in-process holders).
        let keyset = generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
        let quorum = Arc::new(local_quorum_from_keyset(&keyset).expect("build quorum signer"));
        let q_bytes = quorum.q_bytes();

        // Build the REAL FROST-mode actuator. `connect_frost` validates Q -> nostr PublicKey at
        // construction (FIX 1) and queues the relay connection; nostr-sdk's `connect` is
        // non-blocking, so a dummy relay URL is fine (we never send over it here).
        let actuator = NostrActuator::connect_frost(
            quorum.clone(),
            std::slice::from_ref(&"ws://127.0.0.1:65535".to_string()),
            1,
        )
        .await
        .expect("connect FROST actuator");

        // public_key() must be the validated Q (FIX 1 fail-closed accessor), never a fallback.
        assert_eq!(
            actuator.public_key().to_hex(),
            hex::encode(q_bytes),
            "actuator.public_key() must be the group taproot key Q (fail-closed, no fallback)"
        );

        // Drive the REAL FROST signing path the actuator uses inside publish_note.
        let content = "Kirby speaks with a threshold voice: a 2-of-3 FROST quorum co-signed this.";
        let event = actuator
            .frost_sign_event(&quorum, content)
            .expect("the actuator's real FROST publish path signs + locally verifies the event");

        // The event is authored by Q, kind:1, content == input, no tags.
        assert_eq!(event.pubkey.to_hex(), hex::encode(q_bytes), "event author is Q");
        assert_eq!(event.kind, Kind::from(kirby_proto::NOSTR_KIND_TEXT_NOTE), "kind:1");
        assert_eq!(event.content, content, "the published content is the (clean) input");
        assert!(event.tags.is_empty(), "no tags (NIP-01 id is over tags=[])");

        // The NIP-01 id is over Q + created_at + kind + content (re-derive independently).
        let expect_id = kirby_custody::cosign_net::nip01_event_id(
            &hex::encode(q_bytes),
            event.created_at.as_secs(),
            1,
            content,
        );
        assert_eq!(event.id.to_hex(), hex::encode(expect_id), "the event id is the NIP-01 id under Q");

        // Independently re-verify the aggregate as a raw BIP-340 schnorr sig under the TWEAKED Q,
        // and assert it FAILS under the untweaked internal key P (the taproot tweak is real).
        let (_addr, internal_p) =
            taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("address");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let sig = schnorr::Signature::from_slice(event.sig.as_ref()).expect("64-byte sig");
        let msg = Message::from_digest(expect_id);
        assert!(
            secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok(),
            "the actuator's FROST event must verify under the tweaked group key Q"
        );
        assert!(
            secp.verify_schnorr(&sig, &msg, &internal_p).is_err(),
            "the actuator's FROST event must NOT verify under the untweaked internal key P"
        );
        // nostr-sdk's own verify already passed inside frost_sign_event (fail-closed) -- this is the
        // independent custody-chain re-verification on top.
        println!(
            "G-FROST-ACTUATOR-PUBLISHES-QUORUM-SIGNED-EVENT PASS: the actuator's real FROST publish \
             path produced a kind:1 event signed under Q (verifies under Q, rejected under P)"
        );
    }
}

#[cfg(test)]
mod dm_actuator_tests {
    use super::*;
    use nostr_sdk::nips::nip59::UnwrappedGift;

    fn dm_payload(to_pubkey: &str, text: &str) -> Vec<u8> {
        kirby_proto::NostrDmReply { to_pubkey: to_pubkey.to_string(), text: text.to_string() }
            .encode_to_vec()
    }

    #[test]
    fn validate_nostr_dm_reply_parses_a_valid_payload() {
        let recipient = Keys::generate();
        let payload = dm_payload(&recipient.public_key().to_hex(), "  hello   there  ");
        let (to, text) = validate_nostr_dm_reply(&payload).expect("a valid payload parses");
        assert_eq!(to, recipient.public_key(), "the recipient is parsed from the hex pubkey");
        assert_eq!(text, "hello there", "the text is sanitized to one clean line");
    }

    #[test]
    fn validate_nostr_dm_reply_rejects_a_bad_recipient() {
        let payload = dm_payload("not-a-pubkey", "hi");
        assert!(
            validate_nostr_dm_reply(&payload).is_err(),
            "an unparseable recipient is refused (a free denial; the reply could not be addressed)"
        );
    }

    #[test]
    fn validate_nostr_dm_reply_rejects_empty_text() {
        let recipient = Keys::generate();
        let payload = dm_payload(&recipient.public_key().to_hex(), "   \u{2028}\t  ");
        assert!(
            validate_nostr_dm_reply(&payload).is_err(),
            "text that is empty after sanitizing is refused"
        );
    }

    /// THE money/crypto tooth: in FROST mode the agent's PUBLISH identity is the threshold key Q,
    /// but a DM reply is signed by the DEDICATED PLAIN DM KEY -- NEVER Q (a threshold key cannot
    /// ECDH/seal a NIP-17 DM, and the money plane must never touch the DM plane). Build a FROST-mode
    /// actuator (publish = Q), attach a SEPARATE DM key, drive the REAL reply-wrap path (no relay),
    /// and prove the wrap's seal author is the DM key, not Q.
    #[tokio::test]
    async fn dm_reply_is_signed_by_the_dm_key_never_the_money_key() {
        use crate::quorum_signer::local_quorum_from_keyset;
        use kirby_custody::generate_dealer_keyset;

        let keyset = generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
        let quorum = Arc::new(local_quorum_from_keyset(&keyset).expect("build quorum signer"));
        let q_hex = hex::encode(quorum.q_bytes());

        let dm_keys = Keys::generate(); // the dedicated DM identity (plain, daemon-held)
        let recipient = Keys::generate(); // the human who DMed the agent

        let actuator = NostrActuator::connect_frost(
            quorum,
            std::slice::from_ref(&"ws://127.0.0.1:65535".to_string()),
            1,
        )
        .await
        .expect("connect FROST actuator")
        .with_dm_keys(dm_keys.clone());

        // The publish (voice) identity is Q; the DM identity is the SEPARATE plain key.
        assert_eq!(actuator.public_key().to_hex(), q_hex, "the publish voice is the threshold key Q");
        assert_ne!(
            dm_keys.public_key().to_hex(),
            q_hex,
            "the DM key MUST be a different key from the money/voice key Q"
        );

        // Drive the REAL reply-wrap path (the exact code `publish_dm_reply` runs) and unwrap it back
        // as the recipient would.
        let wrap = actuator
            .build_dm_reply_event(recipient.public_key(), "the threshold key never touched this")
            .await
            .expect("build the DM reply gift wrap");
        let unwrapped =
            UnwrappedGift::from_gift_wrap(&recipient, &wrap).await.expect("the recipient unwraps it");

        // The seal author IS the DM key: the DM was signed by the plain DM key, NEVER by Q.
        assert_eq!(
            unwrapped.sender.to_hex(),
            dm_keys.public_key().to_hex(),
            "the DM reply is sealed (signed) by the plain DM key"
        );
        assert_ne!(unwrapped.sender.to_hex(), q_hex, "the FROST money key Q never signs a DM");
        assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage, "the rumor is a kind:14 DM");
        assert_eq!(unwrapped.rumor.content, "the threshold key never touched this");
    }
}
