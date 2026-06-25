//! The kirby-node daemon library (spec 5).
//!
//! The daemon's logic lives here so it is unit- and integration-testable and so
//! a public API is legitimately public (not dead code from a binary's view).
//! The thin binary in `main.rs` parses the CLI and drives these modules.
//!
//! C-1 shipped the host-prereqs gate (`prereqs`). C-3 added the vsock gateway
//! and the unforgeable persisted treasury:
//! - [`treasury`]: the daemon-owned, persisted, unforgeable counter (D-9) and
//!   the idempotency-key dedupe ledger, with the atomic debit+receipt invariant.
//! - [`rail`]: the brokered-act rail (the `perform` step) and a deterministic
//!   mock rail; the D-20 spend cap is enforced here.
//! - [`gateway`]: the tonic `NodeGateway` service (spec 3.1) and the spec 3.2
//!   authorize order for `RequestCapability`.
//!
//! The sandbox is a BACKEND behind a trait so a second backend (Apple
//! Virtualization.framework on macOS, built later on a Mac) can slot in without
//! touching the gateway/treasury/rail/meter-math/genome (the cross-platform plan,
//! `kirby-cross-platform-sandbox-20260617.md`):
//! - [`sandbox`]: the [`sandbox::SandboxBackend`] + [`sandbox::SandboxInstance`]
//!   seam capturing the backend-specific mechanics (boot a guest, the host-vsock
//!   gateway transport, the meter source, the egress lockdown+meter, halt), scoped
//!   to the currently-built capabilities. The genome talks ONLY vsock to the
//!   gateway, never the host, so it is portable across backends unchanged.
//!
//! C-2 adds the microVM boot path (spec 3.6, D-7, gate G1):
//! - [`firecracker`]: the FIRST [`sandbox::SandboxBackend`] impl
//!   ([`firecracker::FirecrackerBackend`]). Boots the genome microVM via fctools
//!   plus the jailer (launched through sudo, the locked decision), from the
//!   content-addressed genome image; exposes the host-side vsock Unix socket the
//!   gateway serves on.
//! - [`gateway::GatewayService::serve_firecracker_vsock`]: serves the gateway
//!   over the booted VM's Firecracker vsock so the genome's boot round-trip
//!   (`GetSessionContext`) lands.
//!
//! C-4 adds host-authoritative metering and the budget-death halt (spec 3.3,
//! 4.1, gate G2):
//! - [`meter`]: cgroups-rs reads the VM's dedicated cgroup `cpu.stat` (usage_usec)
//!   and `memory.current` on a tick, converts to a synthetic burn, and debits the
//!   treasury (`Treasury::debit_metered`); a refused tick is the halt trigger.
//! - [`metered_run`]: boots the genome, meters it, and HALTS it (pause then kill,
//!   daemon-initiated) on budget exhaustion, recording `Terminated{budget_exhausted}`.
//! - The cgroup placement (the jailer nests the VM cgroup under the daemon's
//!   delegated user slice) lives in [`firecracker`] and [`boot`].
//!
//! C-5 adds the per-VM egress lockdown and the eBPF egress-byte meter (spec 3.7,
//! 3.3, gate G4):
//! - [`network`]: the per-VM TAP (wired into the VM's `network_interfaces`) and
//!   the nftables DEFAULT-DENY egress lockdown on it (host-kernel-enforced, the
//!   genome cannot touch host rules). The VM has NO route to the internet; DNS is
//!   blocked; only the vsock to the daemon works (vsock is not IP, structural).
//! - [`meter_egress`]: the aya/eBPF TC classifier on the TAP counting egress
//!   bytes, billed per-byte via [`treasury::Treasury::debit_metered`] (the same
//!   counter CPU and memory debit, D-9). The kernel program is built by build.rs
//!   from the `kirby-ebpf` crate and embedded. CAP_BPF is unavailable to the
//!   unprivileged daemon, so the load/attach/read run in a child via the same
//!   sudo path the jailer uses (the D-7 boundary, not weakened).
//! - [`meter`] gained an egress-byte term in `BurnRates::burn_for_tick`, so the
//!   tick bills CPU + memory + egress against the one treasury counter.
//!
//! C-6 adds the real brokered act (spec 3.2, D-6, D-16, gate G5):
//! - [`rail::CdkEcashRail`]: the real rail. It holds a funded `cdk::Wallet` (the
//!   host-only credential the genome never sees) and SETTLES ecash by melting
//!   against the LOCAL fakewallet mint over the daemon's HOST networking, returning
//!   the mint's preimage as the receipt (D-18). The [`rail::Rail`] trait is async
//!   so the real settle awaits; the gateway's [`gateway::GatewayService::authorize_capability`]
//!   awaits the perform step (the order and the treasury economics are unchanged).
//! - [`mint_rig`]: build and fund a `cdk::Wallet` against the mint (the rail's
//!   credential), shared by the rail and the G5 test.
//! - [`brokered_run`]: boot the VM with the real rail injected, let the genome
//!   issue a `RequestCapability` ecash settle over vsock, and gather the G5
//!   evidence (the daemon authorized + performed it, cost_sats debited, treasury
//!   dropped by exactly that, and the guest raw-egress proof held). Linux proves
//!   raw-egress absence with the eBPF TAP meter; macOS VZ's MVP proves it
//!   structurally by booting a vsock-only guest with no network device. The mint is
//!   booted in the G5 test (cdk-mintd, dev-only).
//!
//! C-7 adds snapshot + cross-node resume (spec D-8, 4.1, section 5 transfer seam,
//! gate G6), the spike's hardest seam:
//! - [`sandbox`] gains the resume surface: [`sandbox::SandboxInstance::snapshot`]
//!   (pause + produce a [`sandbox::SnapshotArtifact`] tagged with a
//!   [`sandbox::SnapshotClass`] = backend x arch x CPU-class),
//!   [`sandbox::SnapshotTransfer`] (the D-13 seam; [`sandbox::LocalDirTransfer`]
//!   same-host, a two-host impl drops in later), and
//!   [`sandbox::SandboxBackend::restore`] (a fresh jailed VMM loads a matching-class
//!   artifact -> Running). [`sandbox::BackendCapabilities`] now carry
//!   `snapshot: Option<SnapshotClass>` and `app_checkpoint: bool` so the scheduler
//!   picks the resume mechanism by class match, and the portable app-checkpoint path
//!   (kirby-mac's VZ work, NOT built here) is a documented sibling.
//! - [`firecracker`] implements it: pause -> create-snapshot with the T2CL Intel CPU
//!   template (cross-CPU restore, D-8) -> the mem+vmstate pair; restore boots a fresh
//!   jailed firecracker (the same D-7 sudo path) and loads+resumes the snapshot.
//! - [`snapshot_run`]: the G6 flow. Node 1 boots the genome, snapshots it, transfers
//!   the pair, KILLS node 1, node 2 restores from the pair and the genome continues
//!   ALIVE (it re-dials the node-2 gateway and completes a post-resume round-trip);
//!   the VMGenID generation BUMPS on restore (node 2's gateway `bump_generation`, the
//!   hook C-8 uses). The single persisted treasury continues across the move (D-9).
//!
//! C-9 adds the openraft lease + no-split-brain consensus (spec 3.5, 4.3, D-4,
//! D-14, D-17, red-team gate 1, gate G8): the consensus keystone.
//! - [`raft_lease`]: the embedded openraft cluster (3 nodes, D-14), the single
//!   replicated state-machine value `active_lease { node_id, term }`, the openraft
//!   transport over plain loopback TCP (D-17, no iroh), and the
//!   [`raft_lease::LeaseHandle`] the fence rides on. Only the node that is BOTH the
//!   Raft leader AND holds the lease at the current committed term may run + debit;
//!   a revived stale node believing an old term is term-fenced
//!   ([`raft_lease::FenceVerdict::Fenced`]).
//! - [`gateway::GatewayService`] gained an OPTIONAL [`raft_lease::LeaseHandle`]: when
//!   a lease is attached, `RequestCapability` checks "do I hold the lease at the
//!   current term?" BEFORE any treasury debit (the fence wired into the debit path);
//!   a non-active or fenced node returns a DENIED receipt and debits 0. Without a
//!   lease attached (C-3..C-8) the gateway behaves exactly as before, so no prior
//!   gate regresses.
//! - [`nosplitbrain_run`]: the G8 3-node harness. It brings up a 3-node lease
//!   cluster on loopback, kills the active node, asserts the 2-of-3 majority elects a
//!   new leader and commits `active_lease{node2, T+1}` (survive-one-loss, D-14),
//!   has node 2 RESTORE the killed node's snapshot (the C-7 path) and continue, then
//!   revives the stale node and asserts it REFUSES to run/debit (fenced), with the
//!   money-path invariant (at-most-one-node-debits) and the linearizability witness
//!   (no two actives per committed term). The pure-Raft mechanics run WITHOUT the
//!   genome image (fast); the handoff-restores-the-VM part needs the image and SKIPS
//!   cleanly when `KIRBY_GENOME_IMAGE` is unset.
//!
//! The lease GATES the run + debit; it does NOT change what the run/debit does. The
//! agnostic core (gateway authorize-order, treasury economics, rail, genome) is
//! unchanged; D-9 holds (the lease-holder debits the SAME persisted treasury, no
//! double-store).
//!
//! C-10 adds idempotent capability across resume (spec 4.2, gate G9): a brokered
//! RequestCapability dedupes across a snapshot+resume, so a key re-issued after the
//! VM moves to another node is DEDUPED, not performed twice or double-charged.
//! - This composes the EXISTING pieces with no fix to the persistence: the C-3
//!   dedupe ledger is a tree in the SAME sled database as the treasury balance, and
//!   `treasury::Treasury::debit_and_record` records K -> receipt and FLUSHES it in the
//!   atomic debit+receipt transaction (spec 4.2), so K is durable on disk the instant
//!   the first act completes. The C-7 resume opens the SAME persisted store path on
//!   node 2 (D-9), so the resumed gateway's STEP 1 dedupe (`gateway::GatewayService::
//!   authorize_capability`) reads K's entry across the move and short-circuits. C-10
//!   PROVES the persistence (D-9) + the dedupe (C-3) + the resume (C-7) compose.
//! - [`idempotent_run`]: the G9 orchestration. Node 1 boots the genome with the
//!   `idempotent` workload (issue K -> PERFORMED, cost C), snapshots + transfers +
//!   KILLS node 1; node 2 restores from the snapshot and opens the SAME persisted
//!   treasury; the genome detects the resume (the bumped VMGenID generation) and
//!   RE-ISSUES K, which the daemon dedupes (DUPLICATE_IGNORED). The G9 evidence: the
//!   rail performed the act EXACTLY ONCE (perform_count stays 1 across the move) and
//!   the treasury was debited by C EXACTLY ONCE total (not 2C). Uses the MockRail (its
//!   perform_count is the clean perform-once evidence; the dedupe + single-debit are
//!   rail-agnostic, living in the persisted treasury). Skips cleanly without the image.
//! - The genome gains the `idempotent` workload in `kirby-genome`.
//!
//! C-11 is the CAPSTONE (spec C-11, gate G10 reproducibility + clean-cut, composing
//! G1-G9): the SINGLE CONTINUOUS SURVIVAL ARC on ONE genome across ONE lease-driven
//! failover, the thing the slices individually do NOT prove (that the whole chain holds
//! together end to end). This is "the loop," the demo.
//! - [`full_loop_run`]: the C-11 orchestration. ONE genome boots under the jailer (G1),
//!   the cgroup meter bills its real CPU with the VM surviving (G2 meter half, NOT
//!   death), its raw egress is denied with the eBPF TAP counter ~0 (G4), it issues a
//!   brokered ecash settle the daemon performs for real with the credential never
//!   crossing vsock (G5), the running VM is snapshotted, the active node is killed, the
//!   surviving 2-of-3 majority elects a new leader at T+1 that restores the snapshot and
//!   the genome continues alive (G6, lease-driven, G8), the resumed genome re-derives
//!   its entropy (G7) and re-issues the same idempotency key which is deduped, performed
//!   once total, and debited once (G9), and the revived stale node is term-fenced with
//!   no two actives ever observed (G8). It COMPOSES the existing, individually-green
//!   machinery (the lease/fence, the UNCHANGED C-7 snapshot/restore, the gateway
//!   authorize order + the persisted treasury, the real CdkEcashRail + the local mint,
//!   the cgroup meter, the eBPF egress meter); it reinvents nothing.
//! - The genome gains the `full-loop` workload in `kirby-genome` (the whole arc on the
//!   guest side: egress-denied, brokered act with key K, heartbeat + entropy
//!   fingerprint, re-issue K on resume).

pub mod app_checkpoint_run;
pub mod boot;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod brokered_run;
pub mod checkpoint;
pub mod config;
// EngramStore crypto/addressing/LWW (durable mind-state Chunk-2). Platform-agnostic
// (host-side nostr-sdk + crypto), like `nerve`/`rail` -- NOT cfg-gated, so the
// cross-platform `rail::EngramStore` can reference it on macOS too.
pub mod engram;
#[cfg(target_os = "linux")]
pub mod egress_run;
#[cfg(target_os = "linux")]
pub mod firecracker;
pub mod fleet;
// FROST per-agent identity (S3a graft). Loads a per-agent FROST PublicKeyPackage
// from a keystore and derives the group taproot key Q + npub. NOT wired into any
// signing path; fleet-tenant-only, behind the custody graft. Platform-agnostic
// host-side type (like `nerve`), so NOT cfg-gated.
pub mod frost_identity;
// S3c per-agent FROST live quorum signer. The signing counterpart of
// `frost_identity::FrostIdentity`: holds the per-guardian KeyPackages (in-process
// for S3, behind a Holder seam for S5/S6 remote swap) and produces aggregate
// BIP-340 signatures under Q, with the guardian-validation membrane wired into
// every holder. Platform-agnostic host-side type (like `frost_identity`), so NOT
// cfg-gated.
pub mod quorum_signer;
// S3d per-agent FROST keyset provisioning at spawn. Connects `frost_identity` (the
// PUBLIC Q) + `quorum_signer` (the SECRET 2-of-3 signer) into the spawn path: a fleet
// tenant is born with its OWN durable FROST group key Q (trusted-dealer keygen by the
// supervisor, 0600 holder shares at rest, idempotent reload across restart). Wired into
// the supervisor's launch path; the single-key `kirby run` path never reaches it.
// Platform-agnostic host-side type (like `quorum_signer`), so NOT cfg-gated.
pub mod keyset_provisioning;
pub mod fleet_supervisor;
#[cfg(target_os = "linux")]
pub mod full_loop_run;
pub mod gateway;
// Hibernation thin-slice shared types (H0): StateBundle/Share/Lease/WatcherRecord/
// WakeRequest + the agent-scoped path helper. Platform-agnostic host-side serde
// types (no genome/trait/sudo surface), like `nerve`/`engram` -- NOT cfg-gated.
pub mod hibernate;
#[cfg(target_os = "linux")]
pub mod idempotent_run;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod meter;
#[cfg(target_os = "linux")]
pub mod meter_egress;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod metered_run;
pub mod mint_rig;
pub mod nerve;
#[cfg(target_os = "linux")]
pub mod network;
#[cfg(target_os = "linux")]
pub mod nosplitbrain_run;
pub mod prereqs;
pub mod raft_lease;
pub mod rail;
pub mod run_agent;
pub mod sandbox;
#[cfg(target_os = "linux")]
pub mod snapshot_run;
pub mod treasury;
#[cfg(target_os = "macos")]
pub mod vz;
