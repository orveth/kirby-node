//! The SPAWN CONTROL-PLANE (fleet-host #11): create a Kirby agent on ANY node in the
//! fleet from a SIGNED relay event — including a node behind a LAN/NAT — WITHOUT running
//! your own node. A user/operator publishes a [`KIND_KIRBY_SPAWN_REQUEST`] (31003) to the
//! relay; a node with capacity verifies it, runs it through the authorization + funding
//! SEAMS, CLAIMS the agent (the relay-lease, so exactly one node hosts it), provisions the
//! agent's sovereign FROST keyset, funds its treasury, and launches it. The agent is then
//! alive and observable entirely over the relay.
//!
//! **The NAT/LAN problem is solved by the substrate, not new code.** The relay IS the
//! transport: a node behind a LAN makes only OUTBOUND connections — it subscribes (to see
//! the request), publishes a lease (to claim), launches the agent, and publishes presence.
//! It never needs a public IP or an inbound port. The same property that lets the
//! turtle+LNVPS FROST cosign ride the relay lets a spawn cross machines.
//!
//! ## The trust boundary (a 31003 is a NEW ATTACKER-CONTROLLED ENTRY POINT)
//!
//! A relay event triggers a VM LAUNCH on the host. A signed event on a PUBLIC relay means
//! ANYONE can publish one — the signature proves WHICH key signed, NOT whether it MAY spawn
//! (`AUTH ≠ signature`). So [`SpawnConsumer::handle_event`] applies a layered battery before
//! anything is provisioned or launched (the `feedback_new_entry_point_needs_input_guards`
//! discipline, mirroring the inbound-delivery pipeline):
//!
//!   1. **kind + signature** — wrong kind or a bad NIP-01 id / BIP-340 sig is DROPPED.
//!   2. **bounded content** — oversized content / malformed JSON / a bad `agent_id` charset
//!      is DROPPED (never panics).
//!   3. **envelope-trust** — the requester identity is `event.pubkey` (the signer), NOT a
//!      body field; a `requester_pubkey` in the content that DISAGREES with the signer is
//!      rejected (do not auth off a forgeable body field).
//!   4. **image allowlist** — `image_ref` must name a pre-staged image (default-deny).
//!   5. **AUTHORIZATION SEAM** — `requester_pubkey ∈ operator allowlist` + a per-requester
//!      rate limit. THIS is the gate that stops the public relay from being an open
//!      spawn trigger (a resource / fund drain on every subscribed node). The seam is
//!      pops-ready: a proof-of-payment authorizer drops in later with no consumer change.
//!   6. **funding** — a DECLARATIVE seed amount only (deposit-and-meter). The event never
//!      carries bearer ecash in plaintext (anyone scraping the relay would redeem it); a
//!      real deposit is referenced out-of-band / NIP-44-encrypted (roadmap), behind the
//!      same seam.
//!   7. **capacity** — over the per-host tenant ceiling => do NOT claim (let another node
//!      take it).
//!   8. **DURABLE reserve-before-launch** — the agent_id is atomically reserved in a durable
//!      spawned-set BEFORE provisioning. This is the idempotency guarantee: a re-delivered
//!      or replayed stale request for an agent_id this node already spawned is a no-op
//!      (it does NOT resurrect a killed agent, and it does NOT double-launch). Reserve-
//!      before-act mirrors the actuator's at-most-once publish discipline (PR #31).
//!
//! ## Idempotency (no double-launch, no resurrection)
//!
//! 31003 is ADDRESSABLE (keyed `d = agent_id`), so the RELAY dedups re-publishes to the
//! latest event per `(pubkey, kind, agent_id)` — but addressable only enforces uniqueness
//! PER pubkey, so it is not the safety mechanism. The durable spawned-set (§8) is: the
//! consumer reserves the agent_id before launch and refuses any later request for an
//! already-spawned agent_id (a ONE-SHOT trigger — first valid request spawns; later ones for
//! a known agent_id are ignored). A failed launch RELEASES the reservation so a transient
//! failure does not permanently poison the agent_id. (Cross-node single-spawn — two nodes
//! both seeing one request — relies on the operator publishing once + the relay-lease claim;
//! that residual is bounded the same way the failover change-stranding residual is, and is
//! documented, not silently assumed.)

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context as _;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use kirby_proto::KIND_KIRBY_SPAWN_REQUEST;

use crate::config::{validate_agent_label, TenantConfig};
use crate::fleet_supervisor::{FleetSupervisor, TenantRecord};
use crate::lease::{LeaseNodeId, SpawnFenceView};

/// The maximum byte length of a spawn request's relay-event content (the JSON
/// [`SpawnRequest`]). A spawn request is small (an agent label, a brain/budget descriptor,
/// an image pointer, a declarative funding amount); anything larger is malformed or hostile
/// and is dropped before parsing. The relay also bounds total event size, but the host must
/// not rely on the relay for its own input guard.
pub const MAX_SPAWN_CONTENT_BYTES: usize = 8 * 1024;

/// The funding block of a spawn request. DECLARATIVE only (deposit-and-meter): it names a
/// seed amount the node funds the agent's treasury with before launch — it NEVER carries a
/// bearer ecash token (a token in a plaintext relay event would be redeemable by anyone
/// scraping the relay). A real ecash deposit is referenced out-of-band or NIP-44-encrypted
/// (roadmap) and redeemed behind the [`SpawnFunder`] seam.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FundingRequest {
    /// The declarative seed amount (sats) to fund the agent's treasury with before launch.
    /// The [`SpawnFunder`] seam validates/clamps it; an unfunded (0) request is refused in
    /// the real-money path.
    pub seed_sats: u64,
}

/// A spawn request: the signed-by-the-REQUESTER content of a [`KIND_KIRBY_SPAWN_REQUEST`].
/// The agent does not exist yet, so this is NOT signed by the agent's quorum Q — it is signed
/// by the CREATOR (the operator key in the three-keys model). The node verifies the signature
/// (which key) and then the authorization seam decides whether that key MAY spawn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnRequest {
    /// The requested agent identity label (the `d` tag, the treasury/lease/instance key).
    /// Validated `validate_agent_label`-identically (non-empty, `[A-Za-z0-9._-]`, <= 64).
    pub agent_id: String,
    /// Non-secret genome config: task descriptor, brain backend, budget, allowlists. Bounded
    /// by the overall content cap; kept small (large config bounces off the relay size limit).
    /// NOTE (MVP): this field is accepted + size-bounded but NOT yet consumed — the spawned
    /// child's config is derived entirely host-side from the node's own base config
    /// (`derive_tenant_config`), so no attacker-supplied config shapes the launch. Wiring
    /// selected, allowlisted genome_config fields into the child is a roadmap follow-up; until
    /// then it is inert (this is the safe default, not a silent drop of a load-bearing field).
    #[serde(default)]
    pub genome_config: serde_json::Value,
    /// Which genome image to run — a content-addressed / pre-staged tag. Validated against
    /// the node's pre-staged image allowlist (default-deny an unknown image).
    pub image_ref: String,
    /// The declarative funding (deposit-and-meter seed; never a bearer token, see [`FundingRequest`]).
    pub funding: FundingRequest,
    /// The requester's pubkey (hex), redundant with the signed `event.pubkey`. Informational:
    /// the consumer authorizes off the ENVELOPE (`event.pubkey`), and REJECTS a request whose
    /// `requester_pubkey` disagrees with the signer (do not auth off a forgeable body field).
    /// May be empty (then the envelope is the sole source of identity).
    #[serde(default)]
    pub requester_pubkey: String,
}

/// Why a spawn request was REJECTED (dropped + logged) — an attacker-controlled or
/// unauthorized event. None of these ever launch or panic; the consumer drops and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnReject {
    /// The event is not a [`KIND_KIRBY_SPAWN_REQUEST`].
    WrongKind(u16),
    /// The NIP-01 id or BIP-340 signature did not verify (forged / corrupt).
    BadSignature,
    /// The content exceeds [`MAX_SPAWN_CONTENT_BYTES`].
    OversizedContent(usize),
    /// The content is not valid [`SpawnRequest`] JSON.
    MalformedContent,
    /// The `agent_id` failed `validate_agent_label` (charset / length / path component).
    InvalidAgentId(String),
    /// The content's `requester_pubkey` disagrees with the signing `event.pubkey`.
    RequesterMismatch,
    /// The `image_ref` is not in the node's pre-staged image allowlist (default-deny).
    UnknownImage(String),
    /// The authorization seam denied the requester (not allowlisted, or rate-limited).
    Unauthorized(String),
    /// The funding seam refused the declarative amount (zero / over the per-spawn ceiling).
    Funding(String),
}

impl std::fmt::Display for SpawnReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnReject::WrongKind(k) => write!(f, "wrong kind {k} (not a spawn request)"),
            SpawnReject::BadSignature => write!(f, "bad signature / id (forged or corrupt)"),
            SpawnReject::OversizedContent(n) => write!(f, "content too large ({n} bytes)"),
            SpawnReject::MalformedContent => write!(f, "malformed spawn-request JSON"),
            SpawnReject::InvalidAgentId(e) => write!(f, "invalid agent_id: {e}"),
            SpawnReject::RequesterMismatch => {
                write!(f, "requester_pubkey disagrees with the signing key")
            }
            SpawnReject::UnknownImage(i) => write!(f, "image_ref {i:?} not in the pre-staged allowlist"),
            SpawnReject::Unauthorized(why) => write!(f, "unauthorized: {why}"),
            SpawnReject::Funding(why) => write!(f, "funding refused: {why}"),
        }
    }
}

/// Why a spawn request was SKIPPED — a WELL-FORMED, AUTHORIZED request this node simply does
/// not act on. Not an error and not hostile: another node may take it, or it is already
/// handled. Distinguished from [`SpawnReject`] so logs/metrics don't conflate "attack" with
/// "not my job".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnSkip {
    /// At/over the per-host tenant ceiling — do not claim; let another node host it.
    OverCapacity,
    /// This node already spawned this agent_id (durable spawned-set). A re-delivered or
    /// replayed request is a no-op (no double-launch, no resurrection).
    AlreadySpawned,
    /// ANOTHER node already holds a FRESH lease for this agent_id (the claim-before-launch
    /// fence, closes G-1). The request is well-formed and authorized, but launching here would
    /// be a cross-node DOUBLE-SPAWN — so this node backs off and lets the holder keep the agent.
    AlreadyClaimedElsewhere { holder: LeaseNodeId, term: u64 },
}

/// The outcome of handling one spawn event.
#[derive(Debug)]
pub enum SpawnOutcome {
    /// The agent was spawned: launched + tracked. Carries its sovereign npub + lease term.
    Launched { agent_id: String, frost_npub: String, lease_term: u64 },
    /// A well-formed, authorized request this node did not act on (see [`SpawnSkip`]).
    Skipped(SpawnSkip),
    /// The event was rejected (dropped + logged; see [`SpawnReject`]).
    Rejected(SpawnReject),
    /// The request passed every gate but the LAUNCH itself failed (e.g. provisioning error).
    /// The durable reservation was RELEASED so a transient failure can be retried. Carries
    /// the error string for logging; not attacker-caused.
    LaunchFailed(String),
}

// ----------------------------------------------------------------------------------------
// The AUTHORIZATION SEAM (the anti-spam / network-join gate; pops-ready)
// ----------------------------------------------------------------------------------------

/// The decision the authorization seam returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnDecision {
    /// The requester may spawn.
    Allow,
    /// The requester may not (carries a reason for the log: not allowlisted, rate-limited).
    Deny(String),
}

/// The single authorization check-point the consumer calls before claiming/launching. A
/// clean seam so a `pops` proof-of-payment authorizer drops in later with no consumer change
/// (gudnuf: the network-join + anti-spam gate, deferred). `requester` is the ENVELOPE pubkey
/// (`event.pubkey`), the authoritative identity. `now_secs` is the current unix time, passed
/// in so the rate limiter is DETERMINISTICALLY testable (no hidden clock).
pub trait SpawnAuthorizer: Send + Sync {
    fn authorize(&self, req: &SpawnRequest, requester: &str, now_secs: u64) -> SpawnDecision;
}

/// The MVP authorizer (pops deferred): an OPTIONAL operator allowlist + a fixed-window
/// per-requester rate limit. A NON-EMPTY allowlist is enforced (only a listed key may spawn —
/// a signature proves WHICH key, not WHETHER it may spawn). An EMPTY allowlist is OPEN: any
/// signer may spawn (the MVP DoS vector gudnuf explicitly accepts until pops is the gate). The
/// rate limit ALWAYS applies, so even in the open case one key cannot flood the fleet with VM
/// launches unbounded. pops (pay-to-spawn) replaces the allowlist as the real anti-spam gate.
pub struct AllowlistAuthorizer {
    allowed: HashSet<String>,
    max_per_window: u32,
    window_secs: u64,
    recent: std::sync::Mutex<std::collections::HashMap<String, (u64, u32)>>,
}

impl AllowlistAuthorizer {
    /// Build the allowlist authorizer. `allowed` is the set of operator pubkeys (hex) that may
    /// spawn; `max_per_window` spawns are permitted per `window_secs` per requester.
    pub fn new(allowed: HashSet<String>, max_per_window: u32, window_secs: u64) -> Self {
        AllowlistAuthorizer {
            allowed,
            max_per_window,
            window_secs,
            recent: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl SpawnAuthorizer for AllowlistAuthorizer {
    fn authorize(&self, _req: &SpawnRequest, requester: &str, now_secs: u64) -> SpawnDecision {
        // AUTH ≠ signature: the signed event only proves WHICH key; the allowlist decides
        // WHETHER it may spawn. NON-EMPTY allowlist => enforce; EMPTY => OPEN (the MVP
        // DoS-accepted mode — any signer may spawn until pops is the gate). The rate limit
        // below applies in BOTH cases.
        if !self.allowed.is_empty() && !self.allowed.contains(requester) {
            return SpawnDecision::Deny(format!("requester {requester} is not in the operator allowlist"));
        }
        // Fixed-window per-requester rate limit (anti-spam): even an allowlisted key cannot
        // trigger more than `max_per_window` launches per `window_secs`. Recover the guard on a
        // poisoned mutex (a prior panic while holding it) rather than panicking — this is an
        // attacker-facing path, so it must fail toward a clean decision, never a process crash.
        let mut recent = self.recent.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = recent.entry(requester.to_string()).or_insert((now_secs, 0));
        if now_secs.saturating_sub(entry.0) >= self.window_secs {
            *entry = (now_secs, 0);
        }
        if entry.1 >= self.max_per_window {
            return SpawnDecision::Deny(format!(
                "rate limit: {} spawns within {}s for {requester}",
                entry.1, self.window_secs
            ));
        }
        entry.1 += 1;
        SpawnDecision::Allow
    }
}

// ----------------------------------------------------------------------------------------
// The FUNDING SEAM (deposit-and-meter; pops/real-deposit drops in later)
// ----------------------------------------------------------------------------------------

/// What funding cleared to: the initial treasury balance the agent boots with (the local
/// meter for its pre-paid ecash, per the deposit-and-meter money model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Funding {
    pub initial_sats: u64,
}

/// The funding check-point the consumer calls before launch. A clean seam so a real
/// deposit-redeeming funder (redeem ONE deposit at the mint, seed the local meter, refund the
/// remainder on death) — or a pops-value funder — drops in later with no consumer change.
pub trait SpawnFunder: Send + Sync {
    /// Fund the agent (clear the deposit / validate the seed) and return the initial balance.
    /// Err refuses the spawn (logged as [`SpawnReject::Funding`]); an unfunded request is
    /// refused in the real-money path.
    fn fund(&self, req: &SpawnRequest) -> Result<Funding, String>;
}

/// The MVP funder: validate the DECLARATIVE seed amount (operator-seeded for the demo). Refuses
/// a zero seed (an unfunded agent boots into the FLOOR-HALT death guarantee immediately) and a
/// seed over the per-spawn ceiling (so one request cannot over-seed the host). The real
/// deposit-redeem-at-mint path is the roadmap behind this same seam.
pub struct SeedFunder {
    max_seed_sats: u64,
}

impl SeedFunder {
    pub fn new(max_seed_sats: u64) -> Self {
        SeedFunder { max_seed_sats }
    }
}

impl SpawnFunder for SeedFunder {
    fn fund(&self, req: &SpawnRequest) -> Result<Funding, String> {
        let seed = req.funding.seed_sats;
        if seed == 0 {
            return Err("seed amount is zero (the real-money path refuses an unfunded agent)".into());
        }
        if seed > self.max_seed_sats {
            return Err(format!("seed {seed} exceeds the per-spawn ceiling {}", self.max_seed_sats));
        }
        Ok(Funding { initial_sats: seed })
    }
}

// ----------------------------------------------------------------------------------------
// The DURABLE spawned-set (one-shot idempotency; no replay-resurrection)
// ----------------------------------------------------------------------------------------

/// The result of reserving an agent_id in the durable spawned-set. TWO-PHASE (the
/// reserve->perform->finalize atomicity family): the reservation carries STATE so a retry after
/// a CRASH between reserve and launch can tell "reserved-but-not-launched" (resume) from
/// "launched" (no-op). Without the state, a crash mid-spawn would strand the agent_id forever
/// (a bare reservation would block the legit retry, and the agent would never spawn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// FIRST reservation for this agent_id (durably marked PENDING) — proceed to launch, then
    /// finalize.
    Fresh,
    /// A PRIOR reservation is still PENDING (a previous attempt reserved but crashed BEFORE it
    /// finalized the launch). THIS node owns the reservation and may RE-ATTEMPT the launch — a
    /// re-published 31003 completes the half-done spawn rather than being stranded.
    ResumePending,
    /// This agent_id was already LAUNCHED (finalized) — skip (no double-launch / resurrection).
    AlreadyLaunched,
}

/// The durable record of every agent_id this node has spawned, with its phase (PENDING ->
/// LAUNCHED). Checked BEFORE launch (reserve-before-act) so a re-delivered or replayed stale
/// spawn request is a no-op: it does not double-launch a running agent and does not RESURRECT a
/// killed one. Durable (survives a restart) because liveness alone is not enough — a request
/// replayed after an agent died must still be refused. The two-phase reserve/finalize closes
/// the crash window between reserving and launching. A sled-backed impl is the real one; tests
/// use an in-memory impl.
pub trait SpawnLedger: Send + Sync {
    /// Atomically reserve `agent_id` (durably mark it PENDING on the first call). Returns
    /// [`ReserveOutcome::Fresh`] on the first reservation, [`ReserveOutcome::ResumePending`] if a
    /// prior reservation is still PENDING (a crash before finalize — re-attempt), and
    /// [`ReserveOutcome::AlreadyLaunched`] once finalized. The None->PENDING transition is an
    /// atomic compare-and-swap (first-writer-wins).
    fn reserve(&self, agent_id: &str) -> anyhow::Result<ReserveOutcome>;
    /// FINALIZE a reservation (PENDING -> LAUNCHED) after the launch has committed. From here a
    /// re-delivery is [`ReserveOutcome::AlreadyLaunched`] (a clean no-op).
    fn finalize(&self, agent_id: &str) -> anyhow::Result<()>;
    /// Release a reservation (ONLY to roll back an in-process FAILED launch, so a transient
    /// failure does not permanently poison the agent_id). A finalized spawn stands forever.
    fn release(&self, agent_id: &str) -> anyhow::Result<()>;
}

/// The durable phase byte stored in the spawned-set: PENDING (reserved, launch not yet
/// confirmed) or LAUNCHED (committed).
const SPAWN_STATE_PENDING: &[u8] = b"P";
const SPAWN_STATE_LAUNCHED: &[u8] = b"L";

/// A sled-backed durable spawned-set: one tree, key = agent_id, value = the phase byte. The
/// `compare_and_swap(None -> PENDING)` is the atomic reserve (the same idempotency primitive the
/// treasury credit-ledger uses); `finalize` writes LAUNCHED. Flushed after each mutation so a
/// crash cannot lose a reservation (which would re-open the resurrection window).
pub struct SledSpawnLedger {
    tree: sled::Tree,
    db: sled::Db,
}

impl SledSpawnLedger {
    /// Open (or create) the durable spawned-set at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let db = sled::open(path.as_ref())
            .map_err(|e| anyhow::anyhow!("open spawn ledger at {}: {e}", path.as_ref().display()))?;
        let tree = db.open_tree("spawned").map_err(|e| anyhow::anyhow!("open spawned tree: {e}"))?;
        Ok(SledSpawnLedger { tree, db })
    }
}

impl SpawnLedger for SledSpawnLedger {
    fn reserve(&self, agent_id: &str) -> anyhow::Result<ReserveOutcome> {
        // Atomic first-writer-wins for the None -> PENDING transition.
        let swapped = self
            .tree
            .compare_and_swap(
                agent_id.as_bytes(),
                None as Option<&[u8]>,
                Some(SPAWN_STATE_PENDING),
            )
            .map_err(|e| anyhow::anyhow!("spawn-ledger CAS for {agent_id:?}: {e}"))?;
        self.db.flush().map_err(|e| anyhow::anyhow!("flush spawn ledger: {e}"))?;
        match swapped {
            // We wrote PENDING: first reservation.
            Ok(()) => Ok(ReserveOutcome::Fresh),
            // A value already existed — distinguish PENDING (crash mid-spawn, re-attempt) from
            // LAUNCHED (committed, no-op).
            Err(cas_err) => match cas_err.current.as_deref() {
                Some(v) if v == SPAWN_STATE_LAUNCHED => Ok(ReserveOutcome::AlreadyLaunched),
                _ => Ok(ReserveOutcome::ResumePending),
            },
        }
    }

    fn finalize(&self, agent_id: &str) -> anyhow::Result<()> {
        self.tree
            .insert(agent_id.as_bytes(), SPAWN_STATE_LAUNCHED)
            .map_err(|e| anyhow::anyhow!("spawn-ledger finalize for {agent_id:?}: {e}"))?;
        self.db.flush().map_err(|e| anyhow::anyhow!("flush spawn ledger: {e}"))?;
        Ok(())
    }

    fn release(&self, agent_id: &str) -> anyhow::Result<()> {
        self.tree
            .remove(agent_id.as_bytes())
            .map_err(|e| anyhow::anyhow!("spawn-ledger release for {agent_id:?}: {e}"))?;
        self.db.flush().map_err(|e| anyhow::anyhow!("flush spawn ledger: {e}"))?;
        Ok(())
    }
}

// ----------------------------------------------------------------------------------------
// The launch SINK (the testability seam over the fleet supervisor)
// ----------------------------------------------------------------------------------------

/// What the consumer needs from the launch target. Behind a trait so the consumer's gate
/// logic (verify → authz → fund → capacity → reserve) is exercised with NO VM and NO real
/// supervisor (non-gated): a test supplies a stub sink that counts launches. The real impl is
/// [`FleetSupervisor`], whose `launch_one` already CLAIMS the relay-lease, provisions the
/// per-agent FROST keyset, seeds the treasury, and launches the tenant child.
#[async_trait::async_trait]
pub trait SpawnSink: Send {
    /// How many tenants this node currently hosts (for the capacity gate).
    fn tenant_count(&self) -> usize;
    /// Launch one tenant (claim + provision + fund-seed + launch). The agent_id has already
    /// been validated and reserved; funding has cleared to `tenant.initial_sats`.
    async fn launch(&mut self, tenant: &TenantConfig) -> anyhow::Result<TenantRecord>;
}

#[async_trait::async_trait]
impl SpawnSink for FleetSupervisor {
    fn tenant_count(&self) -> usize {
        FleetSupervisor::tenant_count(self)
    }
    async fn launch(&mut self, tenant: &TenantConfig) -> anyhow::Result<TenantRecord> {
        self.launch_one(tenant).await
    }
}

// ----------------------------------------------------------------------------------------
// The CONSUMER
// ----------------------------------------------------------------------------------------

/// The spawn consumer: the policy + seams that turn a verified relay event into a launched
/// agent (or a logged reject/skip). Holds the per-host tenant ceiling, the pre-staged image
/// allowlist, and the authorization / funding / durable-ledger seams. The relay subscribe
/// loop is the thin I/O shell (in `main.rs`, under the `fleet` command, off by default); it
/// feeds each received event to [`Self::handle_event`]. Keeping the policy here (and the I/O
/// out) makes the entire trust boundary unit-testable without a relay or a VM.
pub struct SpawnConsumer {
    max_tenants: usize,
    image_allowlist: HashSet<String>,
    authorizer: Arc<dyn SpawnAuthorizer>,
    funder: Arc<dyn SpawnFunder>,
    ledger: Arc<dyn SpawnLedger>,
    /// The CLAIM-BEFORE-LAUNCH fence read-side (closes G-1). When present, the consumer checks
    /// whether a FRESH lease for the agent already names ANOTHER node before launching, and backs
    /// off if so (no cross-node double-spawn). `None` disables the cross-node fence (the
    /// single-node path, and the pure-unit tests that drive the gate logic directly) — same-node
    /// idempotency is always enforced by the durable spawned-set regardless.
    fence: Option<Arc<dyn SpawnFenceView>>,
}

impl SpawnConsumer {
    /// Build a spawn consumer. `max_tenants` is the per-host ceiling (typically
    /// `fleet.max_tenants`); `image_allowlist` is the set of pre-staged `image_ref`s the node
    /// will run (empty => spawn nothing, default-deny). No cross-node fence by default; wire one
    /// with [`Self::with_fence`].
    pub fn new(
        max_tenants: usize,
        image_allowlist: HashSet<String>,
        authorizer: Arc<dyn SpawnAuthorizer>,
        funder: Arc<dyn SpawnFunder>,
        ledger: Arc<dyn SpawnLedger>,
    ) -> Self {
        SpawnConsumer { max_tenants, image_allowlist, authorizer, funder, ledger, fence: None }
    }

    /// Wire the CLAIM-BEFORE-LAUNCH fence (closes G-1). With a fence, before reserving/launching
    /// the consumer consults [`SpawnFenceView::active_lease_for`]; a FRESH lease naming ANOTHER
    /// node makes it back off ([`SpawnSkip::AlreadyClaimedElsewhere`]) so two nodes that both see
    /// one (retained) request do not both launch. Live, this is the relay
    /// [`crate::relay_lease::FleetLeaseObserver`]; tests inject a mock.
    pub fn with_fence(mut self, fence: Arc<dyn SpawnFenceView>) -> Self {
        self.fence = Some(fence);
        self
    }

    /// Handle ONE relay event: the full trust boundary + the spawn decision. `now_secs` is the
    /// current unix time (passed in for a deterministic rate limiter). Pure with respect to the
    /// relay (the caller does the I/O); the only side effects are the durable reservation and,
    /// on success, the launch through `sink`. NEVER panics on a malformed event.
    pub async fn handle_event<S: SpawnSink>(
        &self,
        event: &Event,
        now_secs: u64,
        sink: &mut S,
    ) -> SpawnOutcome {
        let req = match self.parse_and_validate(event) {
            Ok(req) => req,
            Err(reject) => {
                tracing::warn!(reject = %reject, "spawn: DROPPED event");
                return SpawnOutcome::Rejected(reject);
            }
        };

        // (4) Image allowlist (default-deny an unknown / un-staged image).
        if !self.image_allowlist.contains(&req.image_ref) {
            let reject = SpawnReject::UnknownImage(req.image_ref.clone());
            tracing::warn!(reject = %reject, "spawn: DROPPED event");
            return SpawnOutcome::Rejected(reject);
        }

        // (5) AUTHORIZATION SEAM — the gate. Authorize off the ENVELOPE pubkey (the signer),
        // never a body field. Allowlist + rate limit.
        let requester = event.pubkey.to_hex();
        if let SpawnDecision::Deny(why) = self.authorizer.authorize(&req, &requester, now_secs) {
            tracing::warn!(requester = %requester, why = %why, "spawn: UNAUTHORIZED");
            return SpawnOutcome::Rejected(SpawnReject::Unauthorized(why));
        }

        // (6) Funding — a declarative seed; the real deposit-redeem rides this same seam.
        let funding = match self.funder.fund(&req) {
            Ok(f) => f,
            Err(why) => {
                tracing::warn!(agent_id = %req.agent_id, why = %why, "spawn: funding refused");
                return SpawnOutcome::Rejected(SpawnReject::Funding(why));
            }
        };

        // (7) Capacity — over the ceiling => do not claim (another node may host it). Checked
        // BEFORE the reservation so an over-capacity node does not consume an agent_id it
        // cannot host.
        if sink.tenant_count() >= self.max_tenants {
            tracing::info!(agent_id = %req.agent_id, "spawn: at capacity, not claiming");
            return SpawnOutcome::Skipped(SpawnSkip::OverCapacity);
        }

        // (7.5) CLAIM-BEFORE-LAUNCH FENCE (closes G-1, the cross-node DOUBLE-SPAWN). If a FRESH
        // lease for this agent already names ANOTHER node, that node hosts it — do NOT launch a
        // duplicate. The per-node durable ledger below (8) only dedups within THIS node, so a
        // request re-delivered to a SECOND node (the relay retains the addressable 31003) would
        // double-spawn without this cross-node check. A lease naming THIS node, or no fresh lease
        // (none, or the holder stopped heartbeating → it died → re-spawn is allowed), proceeds.
        // The fence is consulted BEFORE reserving so a backed-off node does not consume the
        // agent_id (another node legitimately holds it). Checked only when a fence is wired (the
        // single-node path and the pure-gate unit tests pass `None`).
        if let Some(fence) = &self.fence {
            if let Some(lease) = fence.active_lease_for(&req.agent_id).await {
                if lease.node_id != fence.node_id() {
                    tracing::info!(
                        agent_id = %req.agent_id, holder = lease.node_id, term = lease.term,
                        "spawn: a fresh lease names another node; backing off (no cross-node double-spawn)"
                    );
                    return SpawnOutcome::Skipped(SpawnSkip::AlreadyClaimedElsewhere {
                        holder: lease.node_id,
                        term: lease.term,
                    });
                }
            }
        }

        // (8) DURABLE reserve-before-launch — the idempotency guarantee. Atomically mark the
        // agent_id PENDING; a re-delivery/replay/resurrection of an ALREADY-LAUNCHED agent is a
        // no-op. A PENDING reservation from a prior attempt that CRASHED before finalize is
        // RESUMED (re-attempt the launch) rather than stranded — the two-phase reserve/finalize
        // closes the crash window between reserving and launching (keeper:kirby-nostr).
        match self.ledger.reserve(&req.agent_id) {
            Ok(ReserveOutcome::Fresh) => {}
            Ok(ReserveOutcome::ResumePending) => {
                tracing::warn!(
                    agent_id = %req.agent_id,
                    "spawn: resuming a PENDING reservation (a prior attempt reserved but crashed before finalize); re-attempting launch"
                );
            }
            Ok(ReserveOutcome::AlreadyLaunched) => {
                tracing::info!(agent_id = %req.agent_id, "spawn: already launched, ignoring");
                return SpawnOutcome::Skipped(SpawnSkip::AlreadySpawned);
            }
            Err(e) => {
                // Could not durably reserve — refuse rather than risk a double-launch.
                tracing::error!(agent_id = %req.agent_id, error = %e, "spawn: ledger reserve failed");
                return SpawnOutcome::LaunchFailed(format!("durable reserve failed: {e}"));
            }
        }

        // Launch: claim the relay-lease + provision the FROST keyset + seed the treasury +
        // launch the tenant (all inside the supervisor), then FINALIZE the reservation
        // (PENDING -> LAUNCHED). On failure RELEASE the reservation so a transient failure can
        // be retried as Fresh (a persistent one is still bounded by authz + rate limit); no
        // permanent strand. (Full cross-restart reconciliation of a half-allocated slot rides
        // #15, the abandoned-allocation cleanup.)
        let tenant = TenantConfig { agent_id: req.agent_id.clone(), initial_sats: funding.initial_sats };
        match sink.launch(&tenant).await {
            Ok(record) => {
                if let Err(fe) = self.ledger.finalize(&req.agent_id) {
                    // The VM is up but the reservation stayed PENDING; a re-delivery will RESUME
                    // (re-attempt), not double-launch into a second VM, so this is safe — log it.
                    tracing::error!(
                        agent_id = %req.agent_id, error = %fe,
                        "spawn: finalize failed after a successful launch (VM is up; reservation stays PENDING)"
                    );
                }
                tracing::info!(
                    agent_id = %record.agent_id,
                    npub = %record.frost_npub,
                    term = record.lease_term,
                    "spawn: LAUNCHED"
                );
                SpawnOutcome::Launched {
                    agent_id: record.agent_id,
                    frost_npub: record.frost_npub,
                    lease_term: record.lease_term,
                }
            }
            Err(e) => {
                if let Err(re) = self.ledger.release(&req.agent_id) {
                    tracing::error!(agent_id = %req.agent_id, error = %re, "spawn: reservation release failed after a launch error");
                }
                tracing::error!(agent_id = %req.agent_id, error = %e, "spawn: launch failed");
                SpawnOutcome::LaunchFailed(e.to_string())
            }
        }
    }

    /// The structural + cryptographic + envelope validation (steps 1-3): verify the event is
    /// an authentic, well-formed spawn request before any policy runs. Returns the parsed
    /// [`SpawnRequest`] or the [`SpawnReject`] reason. Does NOT touch policy (image allowlist /
    /// authz / funding / capacity / ledger) — those are the consumer's job, so this is the pure
    /// "is it a real spawn request" gate.
    pub fn parse_and_validate(&self, event: &Event) -> Result<SpawnRequest, SpawnReject> {
        // (1) Kind.
        if event.kind.as_u16() != KIND_KIRBY_SPAWN_REQUEST {
            return Err(SpawnReject::WrongKind(event.kind.as_u16()));
        }
        // (1) Signature + id (NIP-01 id + BIP-340 sig). A forged/corrupt event is dropped.
        if event.verify().is_err() {
            return Err(SpawnReject::BadSignature);
        }
        // (2) Bounded content BEFORE parsing.
        if event.content.len() > MAX_SPAWN_CONTENT_BYTES {
            return Err(SpawnReject::OversizedContent(event.content.len()));
        }
        let req: SpawnRequest =
            serde_json::from_str(&event.content).map_err(|_| SpawnReject::MalformedContent)?;
        // (2) agent_id charset / length (the same guard the config + every fleet entry point
        // uses; agent_id feeds filesystem paths and host interface names).
        if let Err(e) = validate_agent_label("spawn.agent_id", &req.agent_id) {
            return Err(SpawnReject::InvalidAgentId(e.to_string()));
        }
        // (3) Envelope-trust: if the content names a requester_pubkey, it MUST equal the signer.
        // Authorization derives from event.pubkey regardless; this rejects a contradictory body
        // field rather than silently ignoring it.
        if !req.requester_pubkey.is_empty() && req.requester_pubkey != event.pubkey.to_hex() {
            return Err(SpawnReject::RequesterMismatch);
        }
        Ok(req)
    }
}

/// Build a SIGNED [`KIND_KIRBY_SPAWN_REQUEST`] event from a [`SpawnRequest`] (the operator /
/// UI side, and the tests). Signs with the requester's `keys`; sets the addressable `d` tag to
/// the agent_id (and `t=kirby`, `a=agent_id` per the unified vocabulary). The signing key IS
/// the requester identity the consumer authorizes against.
pub fn build_spawn_request_event(keys: &Keys, req: &SpawnRequest) -> anyhow::Result<Event> {
    let content = serde_json::to_string(req).context("serialize spawn request")?;
    let tags = vec![
        Tag::parse(["d", req.agent_id.as_str()])?,
        Tag::parse(["t", "kirby"])?,
        Tag::parse(["a", req.agent_id.as_str()])?,
    ];
    let event = EventBuilder::new(Kind::from(KIND_KIRBY_SPAWN_REQUEST), content)
        .tags(tags)
        .sign_with_keys(keys)
        .context("sign spawn request")?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(agent_id: &str, image: &str, seed: u64) -> SpawnRequest {
        SpawnRequest {
            agent_id: agent_id.to_string(),
            genome_config: serde_json::json!({"task": "demo"}),
            image_ref: image.to_string(),
            funding: FundingRequest { seed_sats: seed },
            requester_pubkey: String::new(),
        }
    }

    // ---- the AUTHORIZATION SEAM (the gate): allowlist is required, rate limit bounds floods ----

    #[test]
    fn unallowlisted_requester_is_denied_when_allowlist_is_nonempty() {
        // AUTH ≠ signature: with a NON-EMPTY allowlist, a key not in it is denied.
        let mut allowed = HashSet::new();
        allowed.insert("operator".to_string());
        let authz = AllowlistAuthorizer::new(allowed, 100, 60);
        let d = authz.authorize(&req("a", "img", 10), "deadbeef", 0);
        assert!(matches!(d, SpawnDecision::Deny(_)), "a key not in a non-empty allowlist must be denied");
    }

    #[test]
    fn empty_allowlist_is_open_mvp_dos_accepted() {
        // EMPTY allowlist => OPEN (the MVP DoS vector gudnuf accepts until pops). Any signer is
        // allowed, but the rate limit still applies.
        let authz = AllowlistAuthorizer::new(HashSet::new(), 1, 60);
        assert_eq!(authz.authorize(&req("a", "img", 10), "anyone", 0), SpawnDecision::Allow);
        // Rate limit still bounds even the open case.
        assert!(matches!(authz.authorize(&req("a", "img", 10), "anyone", 0), SpawnDecision::Deny(_)));
    }

    #[test]
    fn allowlisted_requester_is_allowed_until_the_rate_limit_then_denied() {
        let mut allowed = HashSet::new();
        allowed.insert("operator".to_string());
        let authz = AllowlistAuthorizer::new(allowed, 2, 60); // 2 per 60s
        let r = req("a", "img", 10);
        assert_eq!(authz.authorize(&r, "operator", 0), SpawnDecision::Allow);
        assert_eq!(authz.authorize(&r, "operator", 1), SpawnDecision::Allow);
        // Third within the window: denied (rate limit bounds even an allowlisted key).
        assert!(matches!(authz.authorize(&r, "operator", 2), SpawnDecision::Deny(_)));
        // After the window rolls, allowed again.
        assert_eq!(authz.authorize(&r, "operator", 61), SpawnDecision::Allow);
    }

    // ---- the FUNDING SEAM: declarative seed, refuse zero and over-ceiling ----

    #[test]
    fn funder_refuses_zero_and_over_ceiling_and_accepts_in_range() {
        let funder = SeedFunder::new(1_000_000);
        assert!(funder.fund(&req("a", "img", 0)).is_err(), "zero seed is refused (unfunded)");
        assert!(funder.fund(&req("a", "img", 1_000_001)).is_err(), "over-ceiling seed refused");
        assert_eq!(funder.fund(&req("a", "img", 500_000)).unwrap().initial_sats, 500_000);
    }

    // ---- the DURABLE spawned-set: reserve is atomic + idempotent + survives release ----

    /// In-memory two-state ledger for the in-module unit tests (the sled-backed one is covered
    /// by the integration test that opens a temp dir). Maps agent_id -> launched? (false=PENDING).
    #[derive(Default)]
    struct MemLedger {
        map: std::sync::Mutex<std::collections::HashMap<String, bool>>,
    }
    impl SpawnLedger for MemLedger {
        fn reserve(&self, agent_id: &str) -> anyhow::Result<ReserveOutcome> {
            let mut m = self.map.lock().unwrap();
            match m.get(agent_id) {
                None => {
                    m.insert(agent_id.to_string(), false); // PENDING
                    Ok(ReserveOutcome::Fresh)
                }
                Some(true) => Ok(ReserveOutcome::AlreadyLaunched),
                Some(false) => Ok(ReserveOutcome::ResumePending),
            }
        }
        fn finalize(&self, agent_id: &str) -> anyhow::Result<()> {
            self.map.lock().unwrap().insert(agent_id.to_string(), true);
            Ok(())
        }
        fn release(&self, agent_id: &str) -> anyhow::Result<()> {
            self.map.lock().unwrap().remove(agent_id);
            Ok(())
        }
    }

    #[test]
    fn ledger_is_one_shot_after_finalize_and_release_reopens() {
        let l = MemLedger::default();
        assert_eq!(l.reserve("kirby-1").unwrap(), ReserveOutcome::Fresh);
        // Before finalize, a repeat is RESUME (a crash-mid-spawn would re-attempt, not strand).
        assert_eq!(l.reserve("kirby-1").unwrap(), ReserveOutcome::ResumePending, "pending repeat resumes");
        l.finalize("kirby-1").unwrap();
        // After finalize, a repeat is a no-op (committed; no double-launch / resurrection).
        assert_eq!(l.reserve("kirby-1").unwrap(), ReserveOutcome::AlreadyLaunched, "finalized is one-shot");
        // Release (rollback of an in-process failure) reopens for a fresh retry.
        l.release("kirby-1").unwrap();
        assert_eq!(l.reserve("kirby-1").unwrap(), ReserveOutcome::Fresh, "release reopens for retry");
    }

    #[test]
    fn sled_ledger_two_phase_survives_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "kirby-spawn-ledger-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        // Phase 1: reserve (PENDING) but DO NOT finalize, then drop (simulate a crash mid-spawn).
        {
            let l = SledSpawnLedger::open(&dir).unwrap();
            assert_eq!(l.reserve("kirby-x").unwrap(), ReserveOutcome::Fresh);
        }
        // Reopen (the restart after the crash): the PENDING reservation is durable, so a
        // re-published request RESUMES (re-attempts) — it is NOT stranded forever.
        {
            let l = SledSpawnLedger::open(&dir).unwrap();
            assert_eq!(
                l.reserve("kirby-x").unwrap(),
                ReserveOutcome::ResumePending,
                "a PENDING reservation must survive the crash + resume (no permanent strand)"
            );
            // The resumed attempt now finalizes.
            l.finalize("kirby-x").unwrap();
        }
        // Reopen again: now LAUNCHED, so a replay is a clean no-op (no resurrection).
        {
            let l = SledSpawnLedger::open(&dir).unwrap();
            assert_eq!(
                l.reserve("kirby-x").unwrap(),
                ReserveOutcome::AlreadyLaunched,
                "a finalized reservation must survive a restart (no resurrection window)"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- parse_and_validate: the input battery (kind / sig / bounds / charset / envelope) ----

    fn consumer_for_parse() -> SpawnConsumer {
        let mut allowed = HashSet::new();
        allowed.insert("ignored-for-parse".to_string());
        SpawnConsumer::new(
            16,
            HashSet::from(["img".to_string()]),
            Arc::new(AllowlistAuthorizer::new(allowed, 10, 60)),
            Arc::new(SeedFunder::new(1_000_000)),
            Arc::new(MemLedger::default()),
        )
    }

    #[test]
    fn parse_accepts_a_well_formed_signed_request() {
        let keys = Keys::generate();
        let event = build_spawn_request_event(&keys, &req("kirby-ok", "img", 10)).unwrap();
        let parsed = consumer_for_parse().parse_and_validate(&event).unwrap();
        assert_eq!(parsed.agent_id, "kirby-ok");
    }

    #[test]
    fn parse_rejects_wrong_kind() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::from(1u16), "{}").sign_with_keys(&keys).unwrap();
        assert!(matches!(
            consumer_for_parse().parse_and_validate(&event),
            Err(SpawnReject::WrongKind(1))
        ));
    }

    #[test]
    fn parse_rejects_a_bad_agent_id_charset() {
        let keys = Keys::generate();
        let event = build_spawn_request_event(&keys, &req("bad/id", "img", 10)).unwrap();
        assert!(matches!(
            consumer_for_parse().parse_and_validate(&event),
            Err(SpawnReject::InvalidAgentId(_))
        ));
    }

    #[test]
    fn parse_rejects_oversized_content() {
        let keys = Keys::generate();
        let big = "x".repeat(MAX_SPAWN_CONTENT_BYTES + 1);
        let mut r = req("kirby-ok", "img", 10);
        r.genome_config = serde_json::json!({ "blob": big });
        let event = build_spawn_request_event(&keys, &r).unwrap();
        assert!(matches!(
            consumer_for_parse().parse_and_validate(&event),
            Err(SpawnReject::OversizedContent(_))
        ));
    }

    #[test]
    fn parse_rejects_a_requester_pubkey_that_disagrees_with_the_signer() {
        let keys = Keys::generate();
        let mut r = req("kirby-ok", "img", 10);
        r.requester_pubkey = "0".repeat(64); // not the signer
        let event = build_spawn_request_event(&keys, &r).unwrap();
        assert!(matches!(
            consumer_for_parse().parse_and_validate(&event),
            Err(SpawnReject::RequesterMismatch)
        ));
    }

    #[test]
    fn parse_rejects_malformed_json() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::from(KIND_KIRBY_SPAWN_REQUEST), "not json")
            .sign_with_keys(&keys)
            .unwrap();
        assert!(matches!(
            consumer_for_parse().parse_and_validate(&event),
            Err(SpawnReject::MalformedContent)
        ));
    }

    // ---- the full handle_event flow: the G-SPAWN-* gates (no VM, no real supervisor) ----

    use std::sync::atomic::{AtomicUsize, Ordering};
    use crate::fleet::TenantAllocation;

    /// A stub launch target: counts launches and can be told to FAIL. Models the supervisor's
    /// `launch_one` without a VM, so the consumer's gate logic is exercised non-gated.
    struct StubSink {
        tenant_count: usize,
        launches: Arc<AtomicUsize>,
        fail: bool,
    }

    impl StubSink {
        fn new(tenant_count: usize) -> (Self, Arc<AtomicUsize>) {
            let launches = Arc::new(AtomicUsize::new(0));
            (StubSink { tenant_count, launches: launches.clone(), fail: false }, launches)
        }
        fn failing() -> (Self, Arc<AtomicUsize>) {
            let launches = Arc::new(AtomicUsize::new(0));
            (StubSink { tenant_count: 0, launches: launches.clone(), fail: true }, launches)
        }
    }

    #[async_trait::async_trait]
    impl SpawnSink for StubSink {
        fn tenant_count(&self) -> usize {
            self.tenant_count
        }
        async fn launch(&mut self, tenant: &TenantConfig) -> anyhow::Result<TenantRecord> {
            if self.fail {
                anyhow::bail!("stub launch failure");
            }
            self.launches.fetch_add(1, Ordering::SeqCst);
            Ok(TenantRecord {
                agent_id: tenant.agent_id.clone(),
                allocation: TenantAllocation {
                    agent_id: tenant.agent_id.clone(),
                    guest_cid: 100,
                    instance_id: format!("kirby-{}", tenant.agent_id),
                    gateway_port: 9000,
                },
                treasury_path: std::path::PathBuf::from("/tmp/stub-treasury"),
                lease_term: 1,
                keystore_dir: std::path::PathBuf::from("/tmp/stub-keystore"),
                frost_npub: "npub1stub".to_string(),
            })
        }
    }

    /// Build a consumer whose operator allowlist contains exactly `operator_hex`, with a shared
    /// ledger so a test can inspect/observe the durable spawned-set across calls.
    fn consumer_with(
        max_tenants: usize,
        ledger: Arc<dyn SpawnLedger>,
        operator_hex: &str,
        max_per_window: u32,
    ) -> SpawnConsumer {
        let mut allowed = HashSet::new();
        allowed.insert(operator_hex.to_string());
        SpawnConsumer::new(
            max_tenants,
            HashSet::from(["img".to_string()]),
            Arc::new(AllowlistAuthorizer::new(allowed, max_per_window, 60)),
            Arc::new(SeedFunder::new(1_000_000)),
            ledger,
        )
    }

    /// G-SPAWN (happy path): a valid, allowlisted, funded request under capacity for a fresh
    /// agent_id LAUNCHES exactly one agent.
    #[tokio::test]
    async fn happy_path_launches_once() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let consumer = consumer_with(16, Arc::new(MemLedger::default()), &op, 100);
        let event = build_spawn_request_event(&keys, &req("kirby-a", "img", 5_000)).unwrap();
        let (mut sink, launches) = StubSink::new(0);

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::Launched { .. }), "valid request must launch: {out:?}");
        assert_eq!(launches.load(Ordering::SeqCst), 1, "exactly one launch");
    }

    /// G-SPAWN-IDEMPOTENT: re-delivering the SAME event does NOT launch a second agent (the
    /// durable reservation makes a replay a no-op — no double-launch, no resurrection).
    #[tokio::test]
    async fn redelivery_does_not_double_launch() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let ledger = Arc::new(MemLedger::default());
        let consumer = consumer_with(16, ledger, &op, 100);
        let event = build_spawn_request_event(&keys, &req("kirby-b", "img", 5_000)).unwrap();
        let (mut sink, launches) = StubSink::new(0);

        let first = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(first, SpawnOutcome::Launched { .. }));
        let second = consumer.handle_event(&event, 1, &mut sink).await;
        assert!(
            matches!(second, SpawnOutcome::Skipped(SpawnSkip::AlreadySpawned)),
            "a re-delivered request must skip, got {second:?}"
        );
        assert_eq!(launches.load(Ordering::SeqCst), 1, "still exactly one launch after re-delivery");
    }

    /// G-SPAWN-CLAIM (capacity): a node AT capacity does not claim/launch (it lets another node
    /// host the agent). The agent_id is NOT consumed (no reservation), so a node with room can
    /// still take it.
    #[tokio::test]
    async fn over_capacity_skips_without_reserving() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let ledger = Arc::new(MemLedger::default());
        let consumer = consumer_with(2, ledger.clone(), &op, 100);
        let event = build_spawn_request_event(&keys, &req("kirby-c", "img", 5_000)).unwrap();
        let (mut sink, launches) = StubSink::new(2); // already hosting 2 == cap

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::Skipped(SpawnSkip::OverCapacity)), "got {out:?}");
        assert_eq!(launches.load(Ordering::SeqCst), 0, "no launch at capacity");
        // The agent_id was NOT reserved (another node may host it).
        assert_eq!(ledger.reserve("kirby-c").unwrap(), ReserveOutcome::Fresh, "capacity-skip must not consume the agent_id");
    }

    /// G-SPAWN-AUTHZ-SEAM: a request signed by a key NOT in the operator allowlist is REJECTED
    /// (a valid signature is not authorization), and nothing launches.
    #[tokio::test]
    async fn unauthorized_signer_is_rejected_and_does_not_launch() {
        let operator = Keys::generate();
        let attacker = Keys::generate(); // a different, valid key
        let consumer = consumer_with(16, Arc::new(MemLedger::default()), &operator.public_key().to_hex(), 100);
        let event = build_spawn_request_event(&attacker, &req("kirby-d", "img", 5_000)).unwrap();
        let (mut sink, launches) = StubSink::new(0);

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::Rejected(SpawnReject::Unauthorized(_))), "got {out:?}");
        assert_eq!(launches.load(Ordering::SeqCst), 0, "an unauthorized request must not launch");
    }

    /// G-SPAWN-AUTHZ-SEAM (rate limit): an allowlisted key is bounded — past the per-window
    /// cap, further spawns are rejected.
    #[tokio::test]
    async fn rate_limit_bounds_an_allowlisted_key() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let consumer = consumer_with(16, Arc::new(MemLedger::default()), &op, 1); // 1 per window
        let (mut sink, launches) = StubSink::new(0);

        let e1 = build_spawn_request_event(&keys, &req("kirby-e1", "img", 5_000)).unwrap();
        let e2 = build_spawn_request_event(&keys, &req("kirby-e2", "img", 5_000)).unwrap();
        assert!(matches!(consumer.handle_event(&e1, 0, &mut sink).await, SpawnOutcome::Launched { .. }));
        let out = consumer.handle_event(&e2, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::Rejected(SpawnReject::Unauthorized(_))), "got {out:?}");
        assert_eq!(launches.load(Ordering::SeqCst), 1, "the rate limit bounds launches");
    }

    /// G-SPAWN-FUND: an unfunded (zero-seed) request is refused; nothing launches.
    #[tokio::test]
    async fn zero_funding_is_refused() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let consumer = consumer_with(16, Arc::new(MemLedger::default()), &op, 100);
        let event = build_spawn_request_event(&keys, &req("kirby-f", "img", 0)).unwrap();
        let (mut sink, launches) = StubSink::new(0);

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::Rejected(SpawnReject::Funding(_))), "got {out:?}");
        assert_eq!(launches.load(Ordering::SeqCst), 0);
    }

    /// G-SPAWN-INPUT: a FORGED-signature event is dropped and never launches (and never panics).
    #[tokio::test]
    async fn forged_signature_is_dropped() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let consumer = consumer_with(16, Arc::new(MemLedger::default()), &op, 100);
        // Build a valid event, then corrupt its content so the id/sig no longer match.
        let mut event = build_spawn_request_event(&keys, &req("kirby-g", "img", 5_000)).unwrap();
        event.content = r#"{"agent_id":"kirby-evil","image_ref":"img","funding":{"seed_sats":5000}}"#.to_string();
        let (mut sink, launches) = StubSink::new(0);

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::Rejected(SpawnReject::BadSignature)), "got {out:?}");
        assert_eq!(launches.load(Ordering::SeqCst), 0, "a forged event must not launch");
    }

    /// G-SPAWN-INPUT: an unknown / un-staged image_ref is default-denied.
    #[tokio::test]
    async fn unknown_image_is_denied() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let consumer = consumer_with(16, Arc::new(MemLedger::default()), &op, 100);
        let event = build_spawn_request_event(&keys, &req("kirby-h", "not-staged", 5_000)).unwrap();
        let (mut sink, launches) = StubSink::new(0);

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::Rejected(SpawnReject::UnknownImage(_))), "got {out:?}");
        assert_eq!(launches.load(Ordering::SeqCst), 0);
    }

    /// A LAUNCH failure RELEASES the durable reservation, so a transient failure can be retried
    /// (the agent_id is not permanently poisoned).
    #[tokio::test]
    async fn launch_failure_releases_the_reservation() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let ledger = Arc::new(MemLedger::default());
        let consumer = consumer_with(16, ledger.clone(), &op, 100);
        let event = build_spawn_request_event(&keys, &req("kirby-i", "img", 5_000)).unwrap();
        let (mut sink, _) = StubSink::failing();

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(matches!(out, SpawnOutcome::LaunchFailed(_)), "got {out:?}");
        // The reservation was released: a retry can reserve again (no permanent poison).
        assert_eq!(
            ledger.reserve("kirby-i").unwrap(),
            ReserveOutcome::Fresh,
            "a failed launch must release the reservation so a retry can proceed"
        );
    }

    // ---- the CLAIM-BEFORE-LAUNCH FENCE (closes G-1, the cross-node double-spawn) ----

    // `LeaseNodeId` + `SpawnFenceView` are already in scope via `use super::*`; only `ActiveLease`
    // is new here.
    use crate::lease::ActiveLease;

    /// A mock occupancy view for the consumer fence tests: a node id + a shared map of
    /// agent_id -> the lease currently held. Two mock fences can share one map (each reporting
    /// its OWN node id) to model two nodes observing the same relay-lease.
    #[derive(Clone)]
    struct MockFence {
        node_id: LeaseNodeId,
        leases: Arc<std::sync::Mutex<std::collections::HashMap<String, ActiveLease>>>,
    }
    impl MockFence {
        fn new(node_id: LeaseNodeId) -> Self {
            MockFence { node_id, leases: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())) }
        }
        /// Build another view over the SAME lease map but with a different node id (a second node).
        fn sharing(&self, node_id: LeaseNodeId) -> Self {
            MockFence { node_id, leases: self.leases.clone() }
        }
        fn record(&self, agent_id: &str, lease: ActiveLease) {
            self.leases.lock().unwrap().insert(agent_id.to_string(), lease);
        }
    }
    #[async_trait::async_trait]
    impl SpawnFenceView for MockFence {
        fn node_id(&self) -> LeaseNodeId {
            self.node_id
        }
        async fn active_lease_for(&self, agent_id: &str) -> Option<ActiveLease> {
            self.leases.lock().unwrap().get(agent_id).copied()
        }
    }

    /// FENCE: a FRESH lease naming ANOTHER node makes the consumer back off — no launch, and the
    /// agent_id is NOT consumed (the holder owns it).
    #[tokio::test]
    async fn fence_backs_off_when_another_node_holds_a_fresh_lease() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let ledger = Arc::new(MemLedger::default());
        let fence = Arc::new(MockFence::new(1)); // THIS node is 1
        fence.record("kirby-x", ActiveLease { node_id: 2, term: 1 }); // node 2 already holds it
        let consumer = consumer_with(16, ledger.clone(), &op, 100).with_fence(fence);
        let event = build_spawn_request_event(&keys, &req("kirby-x", "img", 5_000)).unwrap();
        let (mut sink, launches) = StubSink::new(0);

        let out = consumer.handle_event(&event, 0, &mut sink).await;
        assert!(
            matches!(out, SpawnOutcome::Skipped(SpawnSkip::AlreadyClaimedElsewhere { holder: 2, .. })),
            "a fresh lease held by another node must skip, got {out:?}"
        );
        assert_eq!(launches.load(Ordering::SeqCst), 0, "must not launch when another node holds the lease");
        assert_eq!(
            ledger.reserve("kirby-x").unwrap(),
            ReserveOutcome::Fresh,
            "a fence skip must NOT consume the agent_id (the holder owns it)"
        );
    }

    /// FENCE: no lease, or a lease naming THIS node, both PROCEED (a node's own lease — e.g. its
    /// own prior heartbeat — must not block its own launch; same-node idempotency is the ledger's job).
    #[tokio::test]
    async fn fence_allows_when_lease_is_absent_or_this_node() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        // (a) no lease -> launches.
        let consumer_a = consumer_with(16, Arc::new(MemLedger::default()), &op, 100)
            .with_fence(Arc::new(MockFence::new(1)));
        let e_a = build_spawn_request_event(&keys, &req("kirby-y", "img", 5_000)).unwrap();
        let (mut sink_a, launches_a) = StubSink::new(0);
        assert!(matches!(consumer_a.handle_event(&e_a, 0, &mut sink_a).await, SpawnOutcome::Launched { .. }));
        assert_eq!(launches_a.load(Ordering::SeqCst), 1);
        // (b) lease names THIS node -> still launches.
        let fence_b = Arc::new(MockFence::new(1));
        fence_b.record("kirby-z", ActiveLease { node_id: 1, term: 3 });
        let consumer_b = consumer_with(16, Arc::new(MemLedger::default()), &op, 100).with_fence(fence_b);
        let e_b = build_spawn_request_event(&keys, &req("kirby-z", "img", 5_000)).unwrap();
        let (mut sink_b, launches_b) = StubSink::new(0);
        assert!(
            matches!(consumer_b.handle_event(&e_b, 0, &mut sink_b).await, SpawnOutcome::Launched { .. }),
            "a lease naming THIS node must not block its own launch"
        );
        assert_eq!(launches_b.load(Ordering::SeqCst), 1);
    }

    /// THE SPEC'S TEETH: two nodes sharing one relay-lease view launch the agent EXACTLY ONCE.
    /// Node 1 sees no holder and launches; its claim reaches the shared view (modeled by the
    /// record, as the supervisor's claim-on-launch publishes the lease and both nodes observe
    /// it); node 2, handling the SAME (retained) request, sees node 1's fresh lease and backs off.
    #[tokio::test]
    async fn two_nodes_sharing_one_fence_launch_exactly_once() {
        let keys = Keys::generate();
        let op = keys.public_key().to_hex();
        let fence1 = MockFence::new(1);
        let fence2 = fence1.sharing(2); // node 2, SAME observed-lease map

        let consumer1 = consumer_with(16, Arc::new(MemLedger::default()), &op, 100)
            .with_fence(Arc::new(fence1.clone()));
        let consumer2 = consumer_with(16, Arc::new(MemLedger::default()), &op, 100)
            .with_fence(Arc::new(fence2));
        let event = build_spawn_request_event(&keys, &req("kirby-shared", "img", 5_000)).unwrap();
        let (mut sink1, launches1) = StubSink::new(0);
        let (mut sink2, launches2) = StubSink::new(0);

        // Node 1: no holder yet -> launches.
        assert!(matches!(consumer1.handle_event(&event, 0, &mut sink1).await, SpawnOutcome::Launched { .. }));
        // Node 1's claim-on-launch publishes the lease; both nodes' observers fold it.
        fence1.record("kirby-shared", ActiveLease { node_id: 1, term: 1 });
        // Node 2: the SAME request, but now a fresh lease names node 1 -> backs off.
        let out2 = consumer2.handle_event(&event, 1, &mut sink2).await;
        assert!(
            matches!(out2, SpawnOutcome::Skipped(SpawnSkip::AlreadyClaimedElsewhere { holder: 1, .. })),
            "node 2 must back off once node 1 holds the lease, got {out2:?}"
        );
        assert_eq!(launches1.load(Ordering::SeqCst) + launches2.load(Ordering::SeqCst), 1, "exactly one launch across the fleet");
    }
}
