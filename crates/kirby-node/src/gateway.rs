//! The NodeGateway service (spec 3.1, 3.2), tonic gRPC over vsock.
//!
//! The daemon is the gRPC server; the genome is the client. This module wires
//! the four RPCs and enforces the load-bearing piece, the spec 3.2 authorize
//! order for `RequestCapability`, host-side, in EXACTLY this sequence for every
//! request:
//!   1. dedupe on idempotency_key  (replay safety across a resume)
//!   2. allowlist the destination
//!   3. budget gate: estimate <= budget_sats AND estimate <= treasury_remaining
//!   4. perform (capped at the estimate, D-20)
//!   5. meter + debit actual atomically with recording the receipt
//!
//! Steps 1-3 debit nothing on a denial. The genome can never spend more than
//! the treasury holds (D-9), and the post-perform debit is capped at the
//! checked estimate (D-20), so never-overspend holds even after the act.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use kirby_proto::capability_request::Act;
use kirby_proto::node_gateway_server::{NodeGateway, NodeGatewayServer};
use kirby_proto::{
    Ack, CapabilityReceipt, CapabilityRequest, CheckpointBlob, EntropyNonce, EntropyRequest, Event,
    InboundBatch, InboundKind, InboxRequest, Memory, MemoryOp, MemoryResult, Outcome,
    SessionContext, SessionRequest, WriteStatus,
};
use prost::Message;
use rand::TryRngCore;
use tonic::{Request, Response, Status};

use crate::checkpoint::{CheckpointArtifact, LatestCheckpoint};
use crate::lease::{FenceVerdict, LeaseAuthority};
use crate::nerve::InboundQueue;
use crate::rail::{self, MemoryBackend, MemoryWrite, Rail, RailOutcome};
use crate::treasury::{DebitOutcome, Treasury, TreasuryError};

/// The host ceiling on a `PollInbox` long-poll budget (1.2): the daemon CLAMPS the
/// genome's `wait_ms` to this so a hostile value cannot pin a server task forever. 30s is
/// generous for a tick-loop consumer that re-polls.
const MAX_INBOX_WAIT_MS: u64 = 30_000;

/// Non-secret session snapshot handed to the genome at boot (spec 3.1). Holds
/// NO credentials: the task descriptor, the budget snapshot, and the allowlist
/// of destinations (mint ids and endpoint hosts).
#[derive(Clone)]
pub struct Session {
    pub task_descriptor: String,
    pub budget_sats: u64,
    pub allowlisted_destinations: Vec<String>,
    /// The set of INBOUND kinds this VM is permitted to receive (earn-loop Component 1,
    /// 1.4) -- the inbound mirror of `allowlisted_destinations`. `PollInbox` delivers
    /// only `want_kinds INTERSECT allowlisted_inbound_kinds`: the genome can NARROW but
    /// never widen what the session permits. Empty => inbound is DISABLED for this VM
    /// (default-deny: a workload not configured for inbound receives nothing).
    pub allowlisted_inbound_kinds: Vec<InboundKind>,
}

/// The gateway service for one VM/CID. Cheap to clone. It owns a `&Treasury`
/// (the unforgeable counter, D-9), the rail it performs acts through (host
/// credential held inside the rail, never crossing vsock), the static allowlist,
/// and the session snapshot. The `vm_generation` counter is the VMGenID value
/// the daemon owns and bumps on restore (the full resume gate is C-8; the
/// `GetEntropyNonce` method belongs to this surface, so it is wired here).
#[derive(Clone)]
pub struct GatewayService {
    treasury: Treasury,
    rail: Arc<dyn Rail>,
    allowlist: Arc<HashSet<String>>,
    session: Session,
    vm_generation: Arc<AtomicU64>,
    restore_checkpoint: Option<CheckpointArtifact>,
    checkpoints: LatestCheckpoint,
    /// An optional observer of genome `ReportEvent`s. The daemon (and the C-2
    /// boot test) attaches one to await the genome's boot "hello" event (gate
    /// G1). It is diagnostic only and NEVER touches the treasury (G3c); a
    /// malicious genome's events still cannot move the host-owned counter.
    event_observer: Option<tokio::sync::mpsc::UnboundedSender<Event>>,
    /// The OPTIONAL lease fence on the treasury-debit path (spec 3.5, 4.3, D-4,
    /// gate G8). When set, `authorize_capability` checks "does THIS node hold the
    /// active lease at the current committed term?" BEFORE any debit, and a
    /// non-active or term-fenced node returns `DENIED_NOT_ACTIVE_LEASE` and debits
    /// 0. When `None` (C-3..C-8, every gate before C-9) the gateway behaves exactly
    /// as before, so no prior gate regresses. This is the consensus binding made
    /// in-band: the lease gates the money-path inside the gateway, not only in the
    /// orchestration.
    lease_fence: Option<LeaseFence>,
    /// The OPTIONAL memory store for the durable-mind-state (Memory) act. `Some` for a
    /// memory-mode gateway (the durable-mind-state workload); `None` for every other
    /// workload, where a Memory act fails closed (debit 0, perform nothing). It is held
    /// HERE, on the gateway, rather than inside the [`Rail`] like the brain, because a
    /// Memory act's metering DIVERGES from the act-agnostic pipeline (free reads bypass
    /// the ledger; writes are host-costed and never clamped, design doc 11/12) -- and
    /// that fork is a treasury/ledger concern the gateway owns. `Arc<dyn MemoryBackend>`
    /// keeps the service cheap to clone (the serve path clones it per connection).
    memory: Option<Arc<dyn MemoryBackend>>,
    /// The wseq_floor boot barrier (durable-mind-state Chunk-2, R2-7). The daemon is
    /// the AUTHORITY on the Memory write-seq: a WRITE keyed `mem-write-{wseq}` with
    /// `wseq < wseq_floor` (and not an exact-key replay, which STEP-1 already absorbed)
    /// is a regressed/stale-checkpoint genome reusing an already-superseded seq for a
    /// NEW write -- the F1 false-dedupe bug class -- and is REFUSED (debit 0). Seeded on
    /// boot/resume to `1 + max(mem-write-* in the ledger)` (so it survives a restart via
    /// the persisted treasury) and advanced past each committed write. Shared across the
    /// service's clones (`Arc<AtomicU64>`); 0 when no memory backend is attached.
    wseq_floor: Arc<AtomicU64>,
    /// The OPTIONAL per-genome INBOUND queue (earn-loop Component 1, the daemon -> genome
    /// inbox). `Some` for an inbound-enabled gateway (the nerve's `run_inbound` task feeds
    /// the SAME `InboundQueue` handle, the gateway's `PollInbox` drains it); `None` for a
    /// workload without inbound, where `PollInbox` returns an empty batch immediately
    /// (default-deny: no queue, nothing to receive). An `InboundQueue` is itself
    /// `Arc`-backed, so it stays cheap to clone with the service.
    inbox: Option<InboundQueue>,
    /// The set of INBOUND kinds this gateway is permitted to deliver, collected from the
    /// session (1.4) -- the inbound mirror of `allowlist`. `PollInbox` intersects the
    /// genome's `want_kinds` with this set; the genome can only NARROW. Empty => inbound
    /// disabled.
    allowlisted_inbound_kinds: Arc<Vec<InboundKind>>,
}

/// The lease fence attached to a gateway (spec 4.3): the node's lease handle plus
/// the term its VM was started under. The gateway debits only if the handle's fence
/// for `vm_term` returns `Active` (this node still holds the committed lease at a
/// term >= the term it was started at). A revived stale node started at the old term
/// T, after the lease moved to T+1, fences out here and cannot debit.
#[derive(Clone)]
pub struct LeaseFence {
    /// The lease authority for THIS node (reads the committed lease + leadership). Held
    /// behind the [`LeaseAuthority`] TRAIT, not a concrete impl, so the relay-native lease
    /// (and a future iroh-QUIC Raft) drops in WITHOUT touching the gateway (the fleet
    /// scaling seam). `Arc<dyn>` keeps the fence cheap to clone (the serve path clones it
    /// per connection), mirroring the `Rail`/`MemoryBackend` seams.
    pub handle: Arc<dyn LeaseAuthority>,
    /// The agent_id this gateway serves (fleet-host S1): the fence reads only THIS
    /// agent's per-agent lease entry, so a tenant is fenced on its OWN lease and a grant
    /// for another tenant never un-fences or fences this one. The single-agent path uses
    /// [`crate::lease::DEFAULT_AGENT`].
    pub agent_id: crate::lease::AgentId,
    /// The term this VM/gateway was started under (the term the node believes it is
    /// active at FOR THIS AGENT). The fence compares the CURRENT committed term to this.
    pub vm_term: u64,
}

impl GatewayService {
    /// Build a gateway over a treasury, a rail, and a session. The allowlist is
    /// taken from the session's destinations (the daemon's static set for this
    /// VM, spec step 2).
    pub fn new(treasury: Treasury, rail: Arc<dyn Rail>, session: Session) -> Self {
        let allowlist = session
            .allowlisted_destinations
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let allowlisted_inbound_kinds = Arc::new(session.allowlisted_inbound_kinds.clone());
        GatewayService {
            treasury,
            rail,
            allowlist: Arc::new(allowlist),
            session,
            vm_generation: Arc::new(AtomicU64::new(0)),
            restore_checkpoint: None,
            checkpoints: LatestCheckpoint::default(),
            event_observer: None,
            lease_fence: None,
            memory: None,
            wseq_floor: Arc::new(AtomicU64::new(0)),
            inbox: None,
            allowlisted_inbound_kinds,
        }
    }

    /// Attach the per-genome INBOUND queue (earn-loop Component 1): the gateway's `PollInbox`
    /// now drains this `InboundQueue`, the SAME handle the nerve's `run_inbound` task feeds
    /// (the daemon clones one queue, gives the task the producer side and the gateway the
    /// consumer side). Without it `PollInbox` returns an empty batch immediately (a workload
    /// with no inbox receives nothing -- default-deny). Mirrors `with_memory_backend`'s
    /// optional-seam shape; the `InboundQueue` is `Arc`-backed so the service stays cheap to
    /// clone (the serve path clones it per connection).
    pub fn with_inbound_queue(mut self, queue: InboundQueue) -> Self {
        self.inbox = Some(queue);
        self
    }

    /// Clone the inbound queue handle (if any), so the daemon's `run_inbound` task can feed
    /// the SAME queue this gateway drains. `None` when inbound is not attached.
    pub fn inbound_queue(&self) -> Option<InboundQueue> {
        self.inbox.clone()
    }

    /// Attach the durable-mind-state memory store (the Memory act backend). A memory-mode
    /// gateway sets this (the `boot_and_observe` path injects a `StubMemory`/`EngramStore`
    /// for the durable-mind-state workload); without it a Memory act fails closed. Mirrors
    /// the brain's swap-ready seam: `StubMemory` now, `EngramStore` later, same call.
    ///
    /// Seeds the wseq_floor boot barrier (R2-7) from the PERSISTED ledger:
    /// `wseq_floor = 1 + max(mem-write-* recorded)`. On a fresh boot the ledger has no
    /// memory writes so the floor is 1 (the genome's first write is `mem-write-1`); on a
    /// RESUME it reflects the highest already-committed write-seq, so a restarted genome
    /// whose checkpoint regressed cannot reuse a superseded seq for a new write. A scan
    /// error is non-fatal (the barrier is defense-in-depth atop STEP-1 + R2-4): it logs
    /// and leaves the floor at 0 (no barrier), never blocking boot.
    pub fn with_memory_backend(mut self, backend: Arc<dyn MemoryBackend>) -> Self {
        let floor = match self.treasury.max_idempotency_seq(MEM_WRITE_KEY_PREFIX) {
            Ok(max) => max.map_or(1, |m| m + 1),
            Err(e) => {
                tracing::error!(error = %e, "failed to seed wseq_floor from the ledger; barrier disabled (STEP-1 + R2-4 still guard)");
                0
            }
        };
        self.wseq_floor.store(floor, Ordering::SeqCst);
        tracing::info!(wseq_floor = floor, "durable-mind-state: wseq_floor boot barrier seeded (R2-7)");
        self.memory = Some(backend);
        self
    }

    /// Boot this gateway with an app-level checkpoint for the genome to
    /// rehydrate from. This is the portable resume path: the backend boots a
    /// fresh guest, and `GetSessionContext` carries the logical-state blob.
    pub fn with_restore_checkpoint(mut self, checkpoint: CheckpointArtifact) -> Self {
        self.restore_checkpoint = Some(checkpoint);
        self
    }

    /// Return the latest checkpoint this gateway has accepted, if any.
    pub fn latest_checkpoint(
        &self,
    ) -> Result<Option<CheckpointArtifact>, crate::checkpoint::CheckpointError> {
        self.checkpoints.latest()
    }

    /// Clone the shared latest-checkpoint handle so orchestration can observe
    /// checkpoint submissions while the gateway service is being served.
    pub fn checkpoint_handle(&self) -> LatestCheckpoint {
        self.checkpoints.clone()
    }

    /// Attach the lease fence to the treasury-debit path (spec 3.5, 4.3, D-4, gate
    /// G8): the gateway now debits only when THIS node holds the active lease at the
    /// current committed term (a non-active or term-fenced node gets
    /// `DENIED_NOT_ACTIVE_LEASE`, debits 0). `vm_term` is the term the node was the
    /// active lease-holder at when this VM started; the fence compares the live
    /// committed term to it, so a revived stale node (started at the old term) fences
    /// out once the lease has moved to a higher term. Without this (C-3..C-8) the
    /// gateway is unfenced, exactly as before.
    pub fn with_lease_fence<A>(self, handle: A, vm_term: u64) -> Self
    where
        A: LeaseAuthority + 'static,
    {
        // The single-agent path fences on the DEFAULT slot, so a bare run behaves
        // exactly as the pre-fleet single-value fence did.
        self.with_lease_fence_for(handle, crate::lease::DEFAULT_AGENT.to_string(), vm_term)
    }

    /// Attach the lease fence from any [`LeaseAuthority`] (the trait seam, not a concrete
    /// impl): the relay-native lease (and a future iroh-QUIC Raft) attaches here with no
    /// gateway change. The concrete-typed constructors above are thin convenience wrappers
    /// that box into this; this is the general entry point the supervisor (or a swapped impl)
    /// uses.
    pub fn with_lease_authority(
        mut self,
        authority: Arc<dyn LeaseAuthority>,
        agent_id: crate::lease::AgentId,
        vm_term: u64,
    ) -> Self {
        self.lease_fence = Some(LeaseFence { handle: authority, agent_id, vm_term });
        self
    }

    /// Attach the PER-AGENT lease fence (fleet-host S1, spec 2.2): the gateway debits
    /// only when THIS node holds `agent_id`'s active lease at the current committed term;
    /// otherwise STEP 0 of `authorize_capability` returns `DENIED_NOT_ACTIVE_LEASE` and
    /// debits 0. A fleet tenant attaches this with its own `agent_id`, so it is fenced on
    /// its OWN lease and a grant moving another tenant's lease never affects it. `vm_term`
    /// is the term the node held this agent's lease at when the VM started.
    pub fn with_lease_fence_for<A>(
        self,
        handle: A,
        agent_id: crate::lease::AgentId,
        vm_term: u64,
    ) -> Self
    where
        A: LeaseAuthority + 'static,
    {
        // Box the concrete authority into the trait seam; the fence stores only
        // `Arc<dyn LeaseAuthority>`, so the debit path never depends on the concrete type.
        self.with_lease_authority(Arc::new(handle), agent_id, vm_term)
    }

    /// Attach an observer that receives a copy of every genome `ReportEvent`.
    /// The daemon and the C-2 boot test use it to await the boot "hello" event
    /// (gate G1). Returns the receiver end. The observer is diagnostic only: it
    /// is fed AFTER the event is logged and has no path to the treasury (G3c).
    pub fn observe_events(&mut self) -> tokio::sync::mpsc::UnboundedReceiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.event_observer = Some(tx);
        rx
    }

    /// Wrap this service as a tonic server, ready for `Server::builder()
    /// .add_service(..)` over a vsock incoming (the daemon's serve path, used by
    /// C-2 to actually serve a genome).
    pub fn into_server(self) -> NodeGatewayServer<Self> {
        NodeGatewayServer::new(self)
    }

    /// Serve this gateway over a raw host AF_VSOCK listener on `port` for guest
    /// `cid`. This is the transport shape for a bare AF_VSOCK peer; a Firecracker
    /// guest's vsock is host-side a Unix socket instead, so the booted-VM path
    /// uses `serve_firecracker_vsock`. Kept for a non-Firecracker peer and for
    /// symmetry with spec 3.1. Runs until the listener errors or the task is
    /// cancelled.
    #[cfg(target_os = "linux")]
    pub async fn serve_vsock(self, cid: u32, port: u32) -> anyhow::Result<()> {
        use tokio_vsock::{VsockAddr, VsockListener};
        let listener = VsockListener::bind(VsockAddr::new(cid, port))?;
        tracing::info!(cid, port, "NodeGateway serving over raw AF_VSOCK");
        tonic::transport::Server::builder()
            .add_service(self.into_server())
            .serve_with_incoming(listener.incoming())
            .await?;
        Ok(())
    }

    /// Raw AF_VSOCK is a Linux host API in this daemon. macOS VZ exposes the host
    /// side through Virtualization.framework, so the VZ backend uses a helper
    /// process and a Unix-socket proxy instead.
    #[cfg(not(target_os = "linux"))]
    pub async fn serve_vsock(self, _cid: u32, _port: u32) -> anyhow::Result<()> {
        anyhow::bail!(
            "raw AF_VSOCK serving is only available on Linux; use the VZ backend on macOS"
        )
    }

    /// Serve this gateway over an already-chosen Unix socket path. Firecracker
    /// derives its path from a vsock base plus port; the macOS VZ helper uses an
    /// explicit proxy socket path. The tonic service is identical.
    pub async fn serve_unix_socket(self, listen_path: &std::path::Path) -> anyhow::Result<()> {
        use tokio::net::UnixListener;
        use tokio_stream::wrappers::UnixListenerStream;

        let _ = std::fs::remove_file(listen_path);
        let listener = UnixListener::bind(listen_path).map_err(|e| {
            anyhow::anyhow!("bind gateway unix socket {}: {e}", listen_path.display())
        })?;
        tracing::info!(path = %listen_path.display(), "NodeGateway serving over unix socket");
        tonic::transport::Server::builder()
            .add_service(self.into_server())
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await?;
        Ok(())
    }

    /// Serve this gateway over a booted genome's Firecracker vsock (spec 3.1, the
    /// C-2 boot path). Firecracker's vsock is host-side a Unix socket: when the
    /// guest dials the host CID on `port`, Firecracker connects to the host Unix
    /// socket `<uds_base>_<port>`. The daemon binds that path and serves tonic
    /// over the accepted Unix streams, so the genome (the gRPC client) reaches
    /// the daemon (the gRPC server) and one genome cannot reach another's daemon
    /// (distinct uds_base per VM). Runs until the listener errors or the task is
    /// cancelled.
    pub async fn serve_firecracker_vsock(
        self,
        uds_base: &std::path::Path,
        port: u32,
    ) -> anyhow::Result<()> {
        let listen_path = firecracker_vsock_listen_path(uds_base, port);
        tracing::info!(
            path = %listen_path.display(),
            port,
            "NodeGateway serving over Firecracker vsock (host unix socket)"
        );
        self.serve_unix_socket(&listen_path).await
    }

    /// The current VMGenID generation the daemon believes the VM is at. Bumped
    /// by `bump_generation` on restore (C-8 drives this).
    pub fn vm_generation(&self) -> u64 {
        self.vm_generation.load(Ordering::SeqCst)
    }

    /// Bump the generation (called by the daemon on a snapshot restore, the
    /// VMGenID semantics of D-5 / 4.4). Returns the new value.
    pub fn bump_generation(&self) -> u64 {
        self.vm_generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The authoritative treasury balance (host-owned, D-9). Exposed for the
    /// daemon and for tests to assert the never-overspend invariant.
    pub fn treasury_remaining(&self) -> Result<u64, TreasuryError> {
        self.treasury.remaining()
    }

    /// The core spec 3.2 authorize order, factored out of the RPC wrapper so it
    /// is callable directly (the C-3 test harness drives this without a vsock
    /// round-trip; the verifier may also fuzz it). Returns the receipt the RPC
    /// hands back. Debits nothing on any DENIED or DUPLICATE outcome. The error
    /// type is the domain treasury fault (host-side storage or encoding); the
    /// RPC wrapper maps it to a gRPC Status at the boundary. A request with no
    /// `act` is reported via a sentinel receipt rather than an error, so the
    /// core never needs the gRPC error type.
    ///
    /// Async because step 4 (perform) goes through the [`Rail`], whose real impl
    /// settles over the network (a melt against the mint). The order, the gates,
    /// and the treasury economics are unchanged; only the perform call awaits.
    pub async fn authorize_capability(
        &self,
        req: &CapabilityRequest,
    ) -> Result<CapabilityReceipt, TreasuryError> {
        // STEP 0 (the lease fence, spec 3.5 / 4.3 / D-4, gate G8): when a lease is
        // attached, THIS node may debit the treasury only if it holds the active
        // lease at the current committed term. A non-active node, or a revived stale
        // node whose term was superseded (the committed term moved to T+1 while it
        // believed T), is term-fenced: return DENIED_NOT_ACTIVE_LEASE, debit 0,
        // perform nothing. This is the money-path binding of no-split-brain: at most
        // one node (the active lease-holder) ever debits, so there is no double-burn.
        // Without a lease attached (every gate before C-9) this is a no-op.
        if let Some(fence) = &self.lease_fence {
            match fence.handle.fence_for(&fence.agent_id, fence.vm_term).await {
                FenceVerdict::Active { .. } => {}
                FenceVerdict::Fenced {
                    committed_term,
                    committed_holder,
                    believed_term,
                } => {
                    tracing::warn!(
                        committed_term,
                        committed_holder,
                        believed_term,
                        node = fence.handle.node_id(),
                        "RequestCapability FENCED: this node does not hold the active lease at the current term; debiting 0 (no double-burn, gate G8)"
                    );
                    return Ok(denied(Outcome::DeniedNotActiveLease, self.balance()?));
                }
            }
        }

        // The act variant is required. A request with no act is a malformed
        // client; treat it as an unspecified outcome (debit 0) so the core
        // returns a receipt, not a gRPC error.
        let Some(act) = req.act.as_ref() else {
            return Ok(denied(Outcome::Unspecified, self.balance()?));
        };

        // STEP 1: dedupe on idempotency_key. A re-issue of an already-performed
        // key returns the stored receipt and performs nothing (resume-replay
        // safety, spec 4.2 idempotent-across-resume, gate G9). For a Completion the
        // stored `completion` rides back too (brain-stub R1), so a post-resume
        // re-issue gets the SAME assistant words, not just the proof.
        //
        // R2-4 (durable-mind-state Chunk-2, content-aware dedupe): a Memory act carries
        // a deterministic hash over its EFFECTIVE request (op+slug+value). If a prior
        // record under this same key has a DIFFERENT hash, the key was reused for
        // different content -- a wseq desync / stale-checkpoint collision (the F1 bug
        // class) -- so we REFUSE rather than silently serve the stale result. Empty on
        // either side (an old pre-R2-4 row, or a non-memory act) => skip (back-compat).
        let request_hash: Vec<u8> = match act {
            Act::Memory(m) => memory_request_hash(m),
            _ => Vec::new(),
        };
        if let Some(prior) = self.treasury.lookup(&req.idempotency_key)? {
            if !request_hash.is_empty()
                && !prior.request_hash.is_empty()
                && request_hash != prior.request_hash
            {
                tracing::error!(
                    key = %req.idempotency_key,
                    "idempotency key reused with a DIFFERENT memory request (wseq desync / stale checkpoint); refusing, debit 0 (R2-4)"
                );
                return Ok(denied(Outcome::Unspecified, self.balance()?));
            }
            return Ok(receipt(
                Outcome::DuplicateIgnored,
                prior.cost_sats,
                prior.treasury_remaining_after,
                prior.proof,
                prior.completion,
                // A Memory WRITE replay returns the SAME structured result (the ledger
                // persists the encoded MemoryResult); decode it back (None for a brain or
                // any non-memory act, whose `memory` is empty).
                decode_memory(&prior.memory),
            ));
        }

        // STEP 2: allowlist the destination (mint id / invoice / URL host). Not
        // on the static set => DENIED_NOT_ALLOWLISTED, debit 0.
        let dest = rail::destination(act);
        if !self.allowlist.contains(&dest) {
            return Ok(denied(Outcome::DeniedNotAllowlisted, self.balance()?));
        }

        // FORK (durable-mind-state): a Memory act diverges from the act-agnostic
        // STEP3/4/5 here. STEP0 (lease), STEP1 (dedupe), and STEP2 (allowlist) above
        // ALREADY ran for it -- the divergence is only the metering, which the
        // treasury-owning gateway must do itself (design doc 11/12): READS are free and
        // bypass the ledger (G3); WRITES are HOST-costed and never clamped to the caller's
        // ceiling (G2). Everything else (the brain, ecash, paid HTTP) stays on the
        // uniform path below, unchanged (no regression).
        if let Act::Memory(m) = act {
            return self.authorize_memory(req, m).await;
        }

        // FORK (outward actuator): an Actuate act diverges from the uniform STEP3/4/5 too, for two
        // reasons. (1) Its host cost is KNOWN + FIXED (not unknown-capped like the brain), so it is
        // gated against BOTH the per-act ceiling (max_cost_sats) AND budget_sats and DENIED when
        // over either, NEVER clamped down (a hostile max_cost_sats can't free/under-charge a future
        // variable-cost kind). (2) The act has a NETWORK side effect (a public publish), so the
        // idempotency key must be RESERVED (recorded + debited) BEFORE the publish (record-then-
        // publish), giving AT-MOST-ONCE on the outward effect even under a same-session retry /
        // concurrent same-key. STEP0/1/2 already ran above.
        if let Act::Actuate(a) = act {
            return self.authorize_actuate(req, act, a).await;
        }

        // STEP 3: budget gate. The estimate must be within BOTH the genome's
        // authorized budget for this act AND the treasury (D-9, never-overspend
        // checked before the act). A per-act max on the act itself
        // (max_fee_sats / max_cost_sats) tightens the estimate further.
        let mut estimate = self.rail.estimate(act);
        if let Some(act_max) = rail::act_max_sats(act) {
            estimate = estimate.min(act_max);
        }
        let remaining = self.balance()?;
        if estimate > req.budget_sats {
            return Ok(denied(Outcome::DeniedOverBudget, remaining));
        }
        if estimate > remaining {
            return Ok(denied(Outcome::DeniedInsufficientTreasury, remaining));
        }

        // STEP 4: perform. The daemon performs via the host-held credential the
        // genome never sees. D-20: the actual spend is capped at the estimate,
        // so actual <= estimate <= treasury_remaining even after the act. For a
        // Completion the rail also returns the assistant reply TEXT (brain-stub).
        let performed = self.rail.perform(act, estimate).await;
        let (actual_cost, proof, completion) = match performed {
            RailOutcome::Performed {
                actual_cost,
                proof,
                completion,
            } => (actual_cost, proof, completion),
            RailOutcome::UpstreamFailed => {
                // The act did not happen; debit nothing.
                return Ok(denied(Outcome::UpstreamFailed, remaining));
            }
        };

        // STEP 5: meter + debit actual atomically with recording the receipt
        // (spec 4.2 atomic debit+receipt). The debit is keyed by idempotency_key
        // so the record is the dedupe entry future replays match. The Completion
        // reply text is persisted alongside the proof so a replay returns it
        // verbatim (brain-stub R1).
        match self.treasury.debit_and_record(
            &req.idempotency_key,
            actual_cost,
            proof.clone(),
            completion.clone(),
            // The generic path performs no Memory act (a Memory act forks to
            // `authorize_memory` before STEP3), so no memory result is persisted here.
            Vec::new(),
            // No content hash for a non-memory act (R2-4 is memory-specific).
            Vec::new(),
        )? {
            DebitOutcome::Debited {
                cost_sats,
                remaining,
            } => Ok(receipt(
                Outcome::AuthorizedAndPerformed,
                cost_sats,
                remaining,
                proof,
                completion,
                None,
            )),
            // A concurrent request performed this key first: return its stored
            // receipt (the act we just did on the rail is the same idempotent
            // act; the dedupe key collapses them to one debit, G9). The stored
            // completion rides back too (brain-stub R1).
            DebitOutcome::Duplicate(prior) => Ok(receipt(
                Outcome::DuplicateIgnored,
                prior.cost_sats,
                prior.treasury_remaining_after,
                prior.proof,
                prior.completion,
                decode_memory(&prior.memory),
            )),
            // Defense-in-depth: the estimate gate already refused over-treasury
            // spends, and the actual is capped at that estimate, so this is
            // unreachable unless an invariant upstream broke. Surface it as a
            // denial that debited nothing rather than overspending.
            DebitOutcome::Insufficient { remaining } => {
                Ok(denied(Outcome::DeniedInsufficientTreasury, remaining))
            }
        }
    }

    /// The Memory act's authorize path (durable-mind-state), forked out of the
    /// act-agnostic order because its metering DIVERGES (design doc 11/12). STEP0 (lease),
    /// STEP1 (dedupe), and STEP2 (allowlist) already ran in `authorize_capability`; this
    /// does only the memory-specific STEP3/4/5:
    ///   - validate the per-op invariants (G5); a malformed request denies + debits 0
    ///     BEFORE any store work or cost classification;
    ///   - READ (GET/LS): serve FREE and BYPASS `debit_and_record` -- no ledger row, no
    ///     debit (G3). A broke agent still recalls its past (zero treasury bypasses
    ///     PAYMENT, not the lease/allowlist gates above);
    ///   - WRITE (SET/RM): the cost is HOST-computed (G2); `max_cost_sats` is the caller's
    ///     CEILING (a real cost above it is OVER_BUDGET, NEVER clamped down); then it
    ///     performs, debits, and records exactly once (the wseq idempotency key dedupes a
    ///     resume replay via STEP1; a concurrent insert collapses to one debit in the txn).
    async fn authorize_memory(
        &self,
        req: &CapabilityRequest,
        m: &Memory,
    ) -> Result<CapabilityReceipt, TreasuryError> {
        // A memory-mode gateway MUST have a backend; if not, fail closed (this is a
        // wiring bug, not a genome outcome) -- debit nothing, perform nothing.
        let Some(backend) = self.memory.as_ref() else {
            tracing::error!(
                "Memory act on a gateway with no memory backend; refusing (fail-closed)"
            );
            return Ok(denied(Outcome::UpstreamFailed, self.balance()?));
        };

        // G5: validate BEFORE classifying read-vs-write or computing cost. A malformed
        // request (bad slug, oversize value, a read carrying a write payload) is denied,
        // debits 0, and reaches neither the store nor the treasury.
        if let Err(e) = rail::validate_memory_request(m) {
            tracing::warn!(error = %e, op = m.op, "Memory request malformed; refusing (debit 0, G5)");
            return Ok(denied(Outcome::UpstreamFailed, self.balance()?));
        }
        let op = MemoryOp::try_from(m.op).unwrap_or(MemoryOp::Unspecified);

        // READ PATH (GET/LS): free, and it must BYPASS `debit_and_record` so NO ledger row
        // is ever written for a read (G3 -- otherwise free, unique-keyed reads would grow
        // the dedupe ledger without bound). This is the one deliberate divergence from the
        // act-agnostic pipeline.
        if rail::is_read_op(op) {
            return match backend.read(m).await {
                Ok(result) => {
                    let remaining = self.balance()?; // unchanged: a read debits nothing
                    let proof =
                        format!("memory-read:op={op:?}:found={}", result.found).into_bytes();
                    Ok(receipt(
                        Outcome::AuthorizedAndPerformed,
                        0,
                        remaining,
                        proof,
                        Vec::new(),
                        Some(result),
                    ))
                }
                Err(e) => {
                    tracing::error!(error = %e, "memory read failed; debiting nothing");
                    Ok(denied(Outcome::UpstreamFailed, self.balance()?))
                }
            };
        }

        // wseq_floor boot barrier (R2-7, durable-mind-state Chunk-2): the daemon is the
        // write-seq AUTHORITY. STEP-1 already absorbed an exact-key replay, so a write
        // REACHING here is fresh. If its `mem-write-{wseq}` is BELOW the floor, the genome
        // regressed (a stale checkpoint) and is reusing an already-superseded seq for new
        // content -- refuse it (debit 0) before it can collide with the persistent ledger.
        // (An unparseable key skips the barrier; STEP-1 + R2-4 still guard.)
        if let Some(wseq) = parse_mem_write_seq(&req.idempotency_key) {
            let floor = self.wseq_floor.load(Ordering::SeqCst);
            if wseq < floor {
                tracing::error!(
                    key = %req.idempotency_key, wseq, floor,
                    "Memory write-seq below the wseq_floor (regressed/stale-checkpoint genome); refusing, debit 0 (R2-7)"
                );
                return Ok(denied(Outcome::Unspecified, self.balance()?));
            }
        }

        // WRITE PATH (SET/RM): the HOST computes the cost (G2). `max_cost_sats` is a
        // CEILING -- a real cost above it is DENIED_OVER_BUDGET (the cost is NEVER clamped
        // down to the cap, which would silently under-charge the store). The act budget
        // and then the treasury gate it too, before any mutation.
        let cost = backend.write_cost(m);
        let remaining = self.balance()?;
        if cost > m.max_cost_sats || cost > req.budget_sats {
            return Ok(denied(Outcome::DeniedOverBudget, remaining));
        }
        if cost > remaining {
            return Ok(denied(Outcome::DeniedInsufficientTreasury, remaining));
        }

        // Perform the write, keyed by the wseq write token for store-event determinism
        // (F3/G6). On a same-token re-perform the backend reports AlreadyCommittedSameWseq;
        // the cost is the SAME recomputable `cost`, so the single debit still lands (G6).
        let MemoryWrite { result, committed } = match backend.write(m, &req.idempotency_key).await
        {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "memory write failed upstream; debiting nothing");
                return Ok(denied(Outcome::UpstreamFailed, remaining));
            }
        };
        tracing::debug!(?committed, cost, "memory write performed");

        // Persist the encoded result so a resume replay returns the SAME structured result
        // (not just the proof). The proof is the store fact (D-18 analog).
        let memory_bytes = result.encode_to_vec();
        let proof = format!(
            "memory-write:op={op:?}:status={:?}",
            WriteStatus::try_from(result.write_status).unwrap_or(WriteStatus::Unspecified)
        )
        .into_bytes();

        match self.treasury.debit_and_record(
            &req.idempotency_key,
            cost,
            proof.clone(),
            Vec::new(), // not a brain act -- no completion text
            memory_bytes,
            // R2-4: persist the effective-request hash so a future same-key replay with
            // DIFFERENT content is refused at STEP-1 (content-aware dedupe).
            memory_request_hash(m),
        )? {
            DebitOutcome::Debited {
                cost_sats,
                remaining,
            } => {
                // Advance the wseq_floor past this committed write (R2-7): the daemon's
                // authoritative monotonic baseline only ever rises, so a later regressed
                // genome is caught even without re-reading the ledger.
                if let Some(wseq) = parse_mem_write_seq(&req.idempotency_key) {
                    self.wseq_floor.fetch_max(wseq + 1, Ordering::SeqCst);
                }
                Ok(receipt(
                    Outcome::AuthorizedAndPerformed,
                    cost_sats,
                    remaining,
                    proof,
                    Vec::new(),
                    Some(result),
                ))
            }
            // A concurrent request performed this wseq first: return its stored receipt
            // (one debit, G6); the stored memory result rides back.
            DebitOutcome::Duplicate(prior) => Ok(receipt(
                Outcome::DuplicateIgnored,
                prior.cost_sats,
                prior.treasury_remaining_after,
                prior.proof,
                prior.completion,
                decode_memory(&prior.memory),
            )),
            // Defense-in-depth: the ceiling + treasury gate already refused over-treasury
            // writes and the host cost is exact, so this is unreachable unless an
            // invariant upstream broke. Surface a denial that debited nothing.
            DebitOutcome::Insufficient { remaining } => {
                Ok(denied(Outcome::DeniedInsufficientTreasury, remaining))
            }
        }
    }

    /// The Actuate act's authorize path (the OUTWARD actuator), forked out of the uniform order for
    /// its FIXED-cost budget gate + RECORD-THEN-PUBLISH ordering (a network side effect). STEP0
    /// (lease), STEP1 (dedupe), STEP2 (allowlist) already ran in `authorize_capability`. Here, in
    /// order:
    ///   1. VALIDATE the outward payload (decode + kind-restrict + re-sanitize) BEFORE any debit,
    ///      so a malformed payload is a FREE denial (debit 0) -- never reserved or charged.
    ///   2. the host cost is the actuator's FIXED `estimate`; DENY if it exceeds the per-act ceiling
    ///      (`max_cost_sats`) OR the authorized `budget_sats` OR the treasury -- NEVER clamping the
    ///      host cost down (a hostile/zero ceiling cannot free- or under-charge a future
    ///      variable-cost kind, the [MED] gate).
    ///   3. RESERVE the idempotency key (record + debit the host cost) BEFORE the network publish,
    ///      so a same-session retry / concurrent same-key dedupes at STEP1 and never republishes
    ///      (AT-MOST-ONCE on the outward effect, the [HIGH] ordering). A `Duplicate` returns the
    ///      stored receipt and publishes NOTHING; then `perform` publishes and the live receipt
    ///      carries the event-id proof.
    ///
    /// DOCUMENTED RESIDUALS (bounded, fixed-cost, gateway-hardening fast-follows, symmetric to the
    /// memory act's stored-but-unpaid window; a refund/release primitive is over-engineering for the
    /// MVP -- the cardinal sin for a PUBLIC act is DOUBLE-publishing, which this prevents):
    ///   (a) a relay-FAILED publish keeps the reserved fixed cost debited (the debit-only ledger has
    ///       no refund); the genome advances to a new key and may post again.
    ///   (b) a daemon CRASH in the narrow reserve->publish window can leave one paid-but-unpublished
    ///       note (the reserved key dedupes a resume re-issue, so it is never republished).
    async fn authorize_actuate(
        &self,
        req: &CapabilityRequest,
        act: &Act,
        a: &kirby_proto::Actuate,
    ) -> Result<CapabilityReceipt, TreasuryError> {
        let remaining = self.balance()?;
        // 1. VALIDATE before any debit: a malformed outward payload is a FREE denial (debit 0).
        if let Err(reason) = self.rail.validate_outward(act) {
            tracing::warn!(
                kind = %a.kind,
                %reason,
                "Actuate refused by the pre-publish guard (malformed payload); debiting nothing"
            );
            return Ok(denied(Outcome::UpstreamFailed, remaining));
        }
        // 2. FIXED host cost + ceiling gate (MED: deny over EITHER ceiling, NEVER clamp down).
        let estimate = self.rail.estimate(act);
        if estimate > a.max_cost_sats || estimate > req.budget_sats {
            return Ok(denied(Outcome::DeniedOverBudget, remaining));
        }
        if estimate > remaining {
            return Ok(denied(Outcome::DeniedInsufficientTreasury, remaining));
        }
        // 3. RESERVE (record + debit) BEFORE the publish (HIGH: record-then-publish). A concurrent
        //    or same-session-retry same-key sees this reservation at STEP1/in-txn and dedupes ->
        //    at-most-once publish. The reserved record carries an EMPTY proof (the event id is not
        //    known until the publish below); a resume replay returns the note as already-published.
        let (cost_sats, post_remaining) = match self.treasury.debit_and_record(
            &req.idempotency_key,
            estimate,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )? {
            DebitOutcome::Debited { cost_sats, remaining } => (cost_sats, remaining),
            // Already reserved/performed (concurrent or replay): return the stored receipt and
            // publish NOTHING. This is the dedupe that makes the retry at-most-once.
            DebitOutcome::Duplicate(prior) => {
                return Ok(receipt(
                    Outcome::DuplicateIgnored,
                    prior.cost_sats,
                    prior.treasury_remaining_after,
                    prior.proof,
                    prior.completion,
                    None,
                ));
            }
            // Defense-in-depth: the treasury gate above already refused, so this is unreachable
            // unless an invariant broke. Debit nothing.
            DebitOutcome::Insufficient { remaining } => {
                return Ok(denied(Outcome::DeniedInsufficientTreasury, remaining));
            }
        };
        // 4. PUBLISH (the network side effect). The actual spend is capped at the estimate (D-20);
        //    for a fixed-cost actuator it equals `cost_sats` (the reserved amount).
        match self.rail.perform(act, estimate).await {
            RailOutcome::Performed { proof, .. } => {
                // Published. The reserved record holds an empty proof; the LIVE receipt carries the
                // real event id (a future finalize() could persist it for replay fidelity).
                Ok(receipt(Outcome::AuthorizedAndPerformed, cost_sats, post_remaining, proof, Vec::new(), None))
            }
            RailOutcome::UpstreamFailed => {
                // The publish failed AFTER the reserve+debit (residual (a)): the key STAYS recorded
                // (a retry of THIS key dedupes -> never republishes) and the fixed cost STAYS
                // debited (the debit-only ledger has no refund). The genome advances to a new key.
                Ok(receipt(Outcome::UpstreamFailed, cost_sats, post_remaining, Vec::new(), Vec::new(), None))
            }
        }
    }

    fn balance(&self) -> Result<u64, TreasuryError> {
        self.treasury.remaining()
    }
}

#[tonic::async_trait]
impl NodeGateway for GatewayService {
    /// Hand the genome its non-secret session context at boot (spec 3.1). No
    /// credentials cross this method.
    async fn get_session_context(
        &self,
        _request: Request<SessionRequest>,
    ) -> Result<Response<SessionContext>, Status> {
        Ok(Response::new(SessionContext {
            schema_version: kirby_proto::SCHEMA_VERSION,
            task_descriptor: self.session.task_descriptor.clone(),
            budget_sats: self.session.budget_sats,
            allowlisted_destinations: self.session.allowlisted_destinations.clone(),
            restore_checkpoint: self
                .restore_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.reference.clone()),
            restore_checkpoint_blob: self
                .restore_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.payload.clone())
                .unwrap_or_default(),
        }))
    }

    /// Return a fresh per-call nonce from the host CSPRNG, tagged with the
    /// current VMGenID generation (spec 3.4). The genome mixes this into any
    /// ephemeral secret and MUST re-call after a resume; this method is the
    /// re-derive-before-act path the C-8 gate (G7) leans on.
    ///
    /// THE G7 CALL-ORDERING SIGNAL: the daemon records that the genome called
    /// GetEntropyNonce by feeding a synthetic `entropy_nonce_call` event (tagged
    /// with the generation the nonce was issued at) into the SAME observer the
    /// genome's ReportEvents flow through. Because the genome calls
    /// GetEntropyNonce BEFORE it reports its heartbeat act (it derives the
    /// fingerprint first), the observer sees this `entropy_nonce_call` ahead of
    /// the post-resume `heartbeat` event, so the test can assert the genome
    /// re-derived AFTER the resume and BEFORE acting. Like every observer feed it
    /// is diagnostic only and NEVER touches the treasury (G3c). The nonce itself
    /// is NOT logged or observed (only that a call happened, and at what
    /// generation), so the entropy stays between the host CSPRNG and the genome.
    async fn get_entropy_nonce(
        &self,
        _request: Request<EntropyRequest>,
    ) -> Result<Response<EntropyNonce>, Status> {
        let mut nonce = vec![0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| Status::internal(format!("host CSPRNG failure: {e}")))?;
        let generation = self.vm_generation();
        // The ordering signal: a genome called GetEntropyNonce at this generation.
        // Feed the observer (the same stream the heartbeat ReportEvent uses) so the
        // test sees the entropy call land before the post-resume heartbeat act (G7).
        tracing::info!(
            generation,
            "genome called GetEntropyNonce (entropy re-derive, G7 ordering)"
        );
        if let Some(observer) = &self.event_observer {
            let _ = observer.send(Event {
                schema_version: kirby_proto::SCHEMA_VERSION,
                kind: "entropy_nonce_call".into(),
                detail: format!("generation={generation}"),
            });
        }
        Ok(Response::new(EntropyNonce {
            schema_version: kirby_proto::SCHEMA_VERSION,
            nonce,
            vm_generation: generation,
        }))
    }

    /// Record a genome self-reported event (spec 3.3). INVARIANT: these numbers
    /// are advisory and diagnostic ONLY; they NEVER move the treasury counter
    /// (host metering via cgroups and eBPF is authoritative, gate G3c). This
    /// method touches no treasury state; it only logs.
    async fn report_event(&self, request: Request<Event>) -> Result<Response<Ack>, Status> {
        let event = request.into_inner();
        tracing::info!(
            kind = %event.kind,
            detail = %event.detail,
            "genome ReportEvent (advisory, not billed)"
        );
        // Feed the optional observer AFTER logging. This is diagnostic only (the
        // daemon awaits the boot hello here, G1); it never touches the treasury,
        // so a genome's self-reported numbers still cannot move the counter (G3c).
        if let Some(observer) = &self.event_observer {
            let _ = observer.send(event);
        }
        Ok(Response::new(Ack {
            schema_version: kirby_proto::SCHEMA_VERSION,
        }))
    }

    /// Accept a genome-pushed app checkpoint. This is diagnostic/storage only:
    /// it does not debit or credit the treasury, and the daemon treats the
    /// payload as opaque logical state.
    async fn submit_checkpoint(
        &self,
        request: Request<CheckpointBlob>,
    ) -> Result<Response<Ack>, Status> {
        let artifact = self
            .checkpoints
            .submit(request.into_inner())
            .map_err(|e| Status::internal(format!("checkpoint store fault: {e}")))?;
        tracing::info!(
            sha256 = %artifact.reference.sha256,
            len = artifact.reference.len,
            "genome submitted app checkpoint"
        );
        if let Some(observer) = &self.event_observer {
            let _ = observer.send(Event {
                schema_version: kirby_proto::SCHEMA_VERSION,
                kind: "checkpoint_submit".into(),
                detail: format!(
                    "sha256={} len={}",
                    artifact.reference.sha256, artifact.reference.len
                ),
            });
        }
        Ok(Response::new(Ack {
            schema_version: kirby_proto::SCHEMA_VERSION,
        }))
    }

    /// The brokered-act path (spec 3.2). Delegates to `authorize_capability`,
    /// which runs the fixed authorize order host-side.
    async fn request_capability(
        &self,
        request: Request<CapabilityRequest>,
    ) -> Result<Response<CapabilityReceipt>, Status> {
        let req = request.into_inner();
        // The authorize order returns a receipt for every genome-driven outcome
        // (including denials); only a host-side treasury fault becomes a gRPC
        // error, mapped here at the boundary.
        let receipt = self.authorize_capability(&req).await.map_err(internal)?;
        Ok(Response::new(receipt))
    }

    /// The earn-loop INBOUND long-poll (Component 1, 1.1/1.2). The genome polls for the
    /// typed, daemon-verified events the nerve's `run_inbound` task has queued. Semantics:
    ///   * The delivered kinds = `want_kinds INTERSECT allowlisted_inbound_kinds`: the genome
    ///     can only NARROW what the session permits (1.4). A `want_kind` NOT in the allowlist
    ///     is silently ignored (not an error); an EMPTY effective set means deliver the full
    ///     allowlisted set. If the session allowlists NOTHING, inbound is disabled (every poll
    ///     returns empty) -- default-deny.
    ///   * Only events with `inbox_seq > ack_seq` are returned (the monotonic cursor: never
    ///     re-deliver, never skip; a redial + re-poll is exactly-once at the genome).
    ///   * The daemon holds the request open up to `wait_ms`, CLAMPED to [`MAX_INBOX_WAIT_MS`]
    ///     so a hostile value cannot pin a server task forever; it returns the instant >=1
    ///     matching event is queued, else an EMPTY batch on the deadline (so the genome
    ///     re-polls). `high_seq` is the max `inbox_seq` in the batch (the genome's next
    ///     `ack_seq`); 0 on an empty batch (the cursor is unchanged).
    ///
    /// This is one more OUTBOUND call on the existing vsock: the genome gets a typed QUEUE,
    /// never a socket, so the C-5 egress lockdown is untouched.
    async fn poll_inbox(
        &self,
        request: Request<InboxRequest>,
    ) -> Result<Response<InboundBatch>, Status> {
        let req = request.into_inner();

        // Resolve the effective want set: the genome's request INTERSECTED with the session
        // allowlist. The genome can only narrow. Unknown/UNSPECIFIED want kinds and kinds not
        // in the allowlist are silently dropped (default-deny). An empty effective set after
        // intersection means "the full allowlisted set" ONLY when the genome asked for nothing;
        // if it asked for kinds that are all disallowed, it gets nothing (it narrowed to empty).
        let want: Vec<InboundKind> = if req.want_kinds.is_empty() {
            // Default: the full allowlisted set.
            (*self.allowlisted_inbound_kinds).clone()
        } else {
            req.want_kinds
                .iter()
                .filter_map(|k| InboundKind::try_from(*k).ok())
                .filter(|k| *k != InboundKind::Unspecified)
                .filter(|k| self.allowlisted_inbound_kinds.contains(k))
                .collect()
        };

        // No queue attached, or the genome narrowed to the empty set: nothing to deliver.
        // (Distinguish from "want all": `want` is empty here ONLY because the genome asked for
        // kinds none of which are allowlisted, OR the session allowlists nothing AND the genome
        // asked for all. Either way an empty `want` against an empty allowlist = deliver nothing,
        // so we short-circuit when the allowlist is empty.)
        let queue = match &self.inbox {
            Some(q) if !self.allowlisted_inbound_kinds.is_empty() => q,
            _ => {
                return Ok(Response::new(InboundBatch {
                    schema_version: kirby_proto::SCHEMA_VERSION,
                    events: Vec::new(),
                    high_seq: 0,
                }));
            }
        };
        // The genome explicitly asked only for disallowed kinds: it narrowed to empty, deliver
        // nothing (do NOT fall back to the full set, which would WIDEN past its request).
        if !req.want_kinds.is_empty() && want.is_empty() {
            return Ok(Response::new(InboundBatch {
                schema_version: kirby_proto::SCHEMA_VERSION,
                events: Vec::new(),
                high_seq: 0,
            }));
        }

        let wait_ms = req.wait_ms.min(MAX_INBOX_WAIT_MS);
        let events = queue
            .poll(
                req.ack_seq,
                &want,
                std::time::Duration::from_millis(wait_ms),
            )
            .await;
        let high_seq = events.iter().map(|e| e.inbox_seq).max().unwrap_or(0);
        Ok(Response::new(InboundBatch {
            schema_version: kirby_proto::SCHEMA_VERSION,
            events,
            high_seq,
        }))
    }
}

/// Build a receipt with the standard schema version. `completion` is the assistant
/// reply TEXT for a Completion act (brain-stub), empty for every other act and every
/// denial. `memory` is the structured result of a Memory act (durable-mind-state),
/// `None` for every other act and every denial.
fn receipt(
    outcome: Outcome,
    cost_sats: u64,
    treasury_remaining: u64,
    proof: Vec<u8>,
    completion: Vec<u8>,
    memory: Option<MemoryResult>,
) -> CapabilityReceipt {
    CapabilityReceipt {
        schema_version: kirby_proto::SCHEMA_VERSION,
        outcome: outcome as i32,
        cost_sats,
        treasury_remaining,
        proof,
        completion,
        memory,
    }
}

/// A DENIED receipt: cost 0, no proof, no completion, no memory result, the current
/// (unchanged) treasury balance.
fn denied(outcome: Outcome, treasury_remaining: u64) -> CapabilityReceipt {
    receipt(outcome, 0, treasury_remaining, Vec::new(), Vec::new(), None)
}

/// Decode a persisted `PerformedRecord.memory` (the prost-encoded `MemoryResult` bytes)
/// back into the structured receipt field for a resume replay. Empty bytes => no memory
/// result (a non-memory act, or a free read which is never recorded), so this returns
/// `None`; non-empty bytes decode to `Some`. Only WRITE acts ever persist a non-empty
/// `memory` (reads bypass the ledger, G3), and a write result always has a non-default
/// `write_status`, so its encoding is never empty -- the empty/None mapping is unambiguous.
fn decode_memory(bytes: &[u8]) -> Option<MemoryResult> {
    if bytes.is_empty() {
        None
    } else {
        MemoryResult::decode(bytes).ok()
    }
}

/// The idempotency-key prefix the genome's Memory WRITE loop uses (`mem-write-{wseq}`).
/// The wseq_floor barrier (R2-7) scans the ledger for this prefix and parses the seq.
const MEM_WRITE_KEY_PREFIX: &str = "mem-write-";

/// Parse the monotonic write-seq out of a `mem-write-{wseq}` idempotency key, or
/// `None` if the key is not a Memory write key (the barrier then skips it). The genome
/// keys every SET/RM this way (genome `memory_loop`), so real write traffic always parses.
fn parse_mem_write_seq(key: &str) -> Option<u64> {
    key.strip_prefix(MEM_WRITE_KEY_PREFIX)
        .and_then(|s| s.parse::<u64>().ok())
}

/// A deterministic hash over the EFFECTIVE Memory request (R2-4, content-aware dedupe):
/// the op + slug + value -- the fields that determine the performed store effect.
/// `max_cost_sats` is a per-call CEILING, not content, so it is excluded (a retry may
/// legitimately carry a different ceiling). Length-delimiting the slug makes the
/// (slug, value) boundary unambiguous, so two distinct requests cannot collide.
fn memory_request_hash(m: &Memory) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((m.op as u32).to_be_bytes());
    h.update((m.slug.len() as u64).to_be_bytes());
    h.update(m.slug.as_bytes());
    h.update(&m.value);
    h.finalize().to_vec()
}

/// Map a host-side treasury fault to a gRPC internal error. Genome-driven
/// outcomes are receipts, not errors; only storage and encoding faults reach
/// here.
fn internal(e: crate::treasury::TreasuryError) -> Status {
    Status::internal(format!("treasury fault: {e}"))
}

/// The host-side Unix socket path Firecracker connects to for a guest-initiated
/// vsock connection to `port`: the base uds with a `_<port>` suffix. This is the
/// Firecracker vsock convention (the daemon listens here; the firecracker
/// process connects when the genome dials the host CID).
pub fn firecracker_vsock_listen_path(uds_base: &std::path::Path, port: u32) -> std::path::PathBuf {
    let mut name = uds_base.as_os_str().to_os_string();
    name.push(format!("_{port}"));
    std::path::PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::firecracker_vsock_listen_path;
    use std::path::Path;

    /// The Firecracker host-side vsock socket for a guest-initiated connection to
    /// port P is the base uds with a `_P` suffix (the daemon binds this; the
    /// firecracker process connects to it). The suffix is appended to the full
    /// path, not inserted before the extension.
    #[test]
    fn firecracker_vsock_listen_path_appends_underscore_port() {
        assert_eq!(
            firecracker_vsock_listen_path(Path::new("/jail/root/v.vsock"), 5000),
            Path::new("/jail/root/v.vsock_5000")
        );
        assert_eq!(
            firecracker_vsock_listen_path(Path::new("/tmp/x.sock"), 17),
            Path::new("/tmp/x.sock_17")
        );
    }
}
