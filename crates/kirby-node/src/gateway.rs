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

use kirby_proto::node_gateway_server::{NodeGateway, NodeGatewayServer};
use kirby_proto::{
    Ack, CapabilityReceipt, CapabilityRequest, CheckpointBlob, EntropyNonce, EntropyRequest, Event,
    Outcome, SessionContext, SessionRequest,
};
use rand::TryRngCore;
use tonic::{Request, Response, Status};

use crate::checkpoint::{CheckpointArtifact, LatestCheckpoint};
use crate::raft_lease::{FenceVerdict, LeaseHandle};
use crate::rail::{self, Rail, RailOutcome};
use crate::treasury::{DebitOutcome, Treasury, TreasuryError};

/// Non-secret session snapshot handed to the genome at boot (spec 3.1). Holds
/// NO credentials: the task descriptor, the budget snapshot, and the allowlist
/// of destinations (mint ids and endpoint hosts).
#[derive(Clone)]
pub struct Session {
    pub task_descriptor: String,
    pub budget_sats: u64,
    pub allowlisted_destinations: Vec<String>,
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
}

/// The lease fence attached to a gateway (spec 4.3): the node's lease handle plus
/// the term its VM was started under. The gateway debits only if the handle's fence
/// for `vm_term` returns `Active` (this node still holds the committed lease at a
/// term >= the term it was started at). A revived stale node started at the old term
/// T, after the lease moved to T+1, fences out here and cannot debit.
#[derive(Clone)]
pub struct LeaseFence {
    /// The lease handle for THIS node (reads the committed lease + leadership).
    pub handle: LeaseHandle,
    /// The term this VM/gateway was started under (the term the node believes it is
    /// active at). The fence compares the CURRENT committed term to this.
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
        }
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
    pub fn with_lease_fence(mut self, handle: LeaseHandle, vm_term: u64) -> Self {
        self.lease_fence = Some(LeaseFence { handle, vm_term });
        self
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
            match fence.handle.fence(fence.vm_term).await {
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
                        node = fence.handle.id(),
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
        // safety, spec 4.2 idempotent-across-resume, gate G9).
        if let Some(prior) = self.treasury.lookup(&req.idempotency_key)? {
            return Ok(receipt(
                Outcome::DuplicateIgnored,
                prior.cost_sats,
                prior.treasury_remaining_after,
                prior.proof,
            ));
        }

        // STEP 2: allowlist the destination (mint id / invoice / URL host). Not
        // on the static set => DENIED_NOT_ALLOWLISTED, debit 0.
        let dest = rail::destination(act);
        if !self.allowlist.contains(&dest) {
            return Ok(denied(Outcome::DeniedNotAllowlisted, self.balance()?));
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
        // so actual <= estimate <= treasury_remaining even after the act.
        let performed = self.rail.perform(act, estimate).await;
        let (actual_cost, proof) = match performed {
            RailOutcome::Performed { actual_cost, proof } => (actual_cost, proof),
            RailOutcome::UpstreamFailed => {
                // The act did not happen; debit nothing.
                return Ok(denied(Outcome::UpstreamFailed, remaining));
            }
        };

        // STEP 5: meter + debit actual atomically with recording the receipt
        // (spec 4.2 atomic debit+receipt). The debit is keyed by idempotency_key
        // so the record is the dedupe entry future replays match.
        match self
            .treasury
            .debit_and_record(&req.idempotency_key, actual_cost, proof.clone())?
        {
            DebitOutcome::Debited {
                cost_sats,
                remaining,
            } => Ok(receipt(
                Outcome::AuthorizedAndPerformed,
                cost_sats,
                remaining,
                proof,
            )),
            // A concurrent request performed this key first: return its stored
            // receipt (the act we just did on the rail is the same idempotent
            // act; the dedupe key collapses them to one debit, G9).
            DebitOutcome::Duplicate(prior) => Ok(receipt(
                Outcome::DuplicateIgnored,
                prior.cost_sats,
                prior.treasury_remaining_after,
                prior.proof,
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
}

/// Build a receipt with the standard schema version.
fn receipt(
    outcome: Outcome,
    cost_sats: u64,
    treasury_remaining: u64,
    proof: Vec<u8>,
) -> CapabilityReceipt {
    CapabilityReceipt {
        schema_version: kirby_proto::SCHEMA_VERSION,
        outcome: outcome as i32,
        cost_sats,
        treasury_remaining,
        proof,
    }
}

/// A DENIED receipt: cost 0, no proof, the current (unchanged) treasury balance.
fn denied(outcome: Outcome, treasury_remaining: u64) -> CapabilityReceipt {
    receipt(outcome, 0, treasury_remaining, Vec::new())
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
