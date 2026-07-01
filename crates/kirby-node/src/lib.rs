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
//! - The G5 brokered-act path: boot the VM with the real rail injected, let the genome
//!   issue a `RequestCapability` ecash settle over vsock, and assert the G5 evidence
//!   (the daemon authorized + performed it, cost_sats debited, treasury dropped by
//!   exactly that, and the guest raw-egress proof held). Linux proves raw-egress
//!   absence with the eBPF TAP meter; macOS VZ's MVP proves it structurally by booting
//!   a vsock-only guest with no network device. The mint is booted in the G5 test
//!   (cdk-mintd, dev-only). (The standalone `brokered`/`egress` demo subcommands and
//!   their `brokered_run`/`egress_run` orchestration modules were removed when Kirby
//!   collapsed to the single `capable` agent; the G5/G4 invariants are now proven by
//!   the kept full-loop test.)
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
//! C-9 / #9 add the lease + no-split-brain fence (build-spec
//! `build-spec-kirby-failover-relay-lease-20260625.md`, gate G8 / F9): the consensus
//! keystone. The loopback Raft cluster was CUT (it was same-host only; plain-TCP Raft
//! cannot form across NAT); the ACTIVE lease is now relay-native + FROST-signed, so it works
//! across LAN/NAT by riding the SAME relay the nerve already uses.
//! - [`lease`]: the transport-free SEAM -- the [`lease::LeaseAuthority`] trait the gateway
//!   money-fence reads, plus the shared value types (`ActiveLease` / `FenceVerdict` /
//!   `LeaseNodeId`). A node ACTS for an agent only while it holds the latest non-stale term;
//!   a node on a stale term is term-fenced ([`lease::FenceVerdict::Fenced`]).
//! - [`relay_lease`]: the ACTIVE relay-native FROST-signed lease impl. A claim FROST-signs a
//!   `Lease { agent_id, holder_node_id, term, issued_at }` event under the agent's quorum Q
//!   and publishes it to the relay (latest-term-wins); a failover claims `term + 1`. The
//!   fleet supervisor claims an agent's lease on launch via the
//!   [`relay_lease::RelayLeaseGrantor`].
//! - [`gateway::GatewayService`] has an OPTIONAL lease fence: when one is attached,
//!   `RequestCapability` checks "do I hold the lease at the current term?" BEFORE any treasury
//!   debit (the fence wired into the debit path); a non-active or fenced node returns a DENIED
//!   receipt and debits 0. Without a lease attached the gateway behaves exactly as before, so
//!   no prior gate regresses.
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
//! - The G9 orchestration (the removed `idempotent_run` module; the invariant is now
//!   proven by the kept full-loop test). Node 1 boots the genome with the
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
pub mod checkpoint;
pub mod config;
// EngramStore crypto/addressing/LWW (durable mind-state Chunk-2). Platform-agnostic
// (host-side nostr-sdk + crypto), like `nerve`/`rail` -- NOT cfg-gated, so the
// cross-platform `rail::EngramStore` can reference it on macOS too.
pub mod engram;
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
// S5/S6 (chunk 1): the RemoteHolder -- a `quorum_signer::Holder` whose FROST share lives
// on ANOTHER machine. It exchanges OPAQUE CoSignEvents with a holder-side server; the
// secret SigningNonces NEVER crosses the wire (each holder owns its nonce locally) and the
// guardian membrane runs holder-side. The QuorumSigner ceremony body is unchanged when
// holders go remote (the whole point of the Holder seam). Platform-agnostic host-side
// type (like `quorum_signer`), so NOT cfg-gated. Chunk-1 scope: identity/signing only,
// with an in-process mock transport for fast ungated teeth; the real relay transport is a
// later chunk boundary.
pub mod remote_holder;
// S5/S6 keystone: the RELAY-NATIVE HolderTransport + holder-side server loop. The real
// transport `remote_holder`'s InProcessHolderLink stood in for -- it carries the SAME opaque
// CoSignEvents over the shared Nostr fleet relay so a coordinator reaches a share-holder on
// ANOTHER machine. Host-side host network (like `nerve`); NOT cfg-gated.
pub mod relay_transport;
// S3d per-agent FROST keyset provisioning at spawn. Connects `frost_identity` (the
// PUBLIC Q) + `quorum_signer` (the SECRET 2-of-3 signer) into the spawn path: a fleet
// tenant is born with its OWN durable FROST group key Q (trusted-dealer keygen by the
// supervisor, 0600 holder shares at rest, idempotent reload across restart). Wired into
// the supervisor's launch path; the single-key `kirby run` path never reaches it.
// Platform-agnostic host-side type (like `quorum_signer`), so NOT cfg-gated.
pub mod keyset_provisioning;
// S5/S6 chunk 3: per-holder AT-REST SEALING of a FROST share. When the keyset distributes
// (each holder stores ONE share on its own machine), that holder seals its share with
// XChaCha20Poly1305 under a host-bound key (HKDF over the machine binding + a per-sink
// salt). Reused by `keyset_provisioning`'s sealed share sink. Host-side only; a sealed
// share never crosses vsock. Sealing protects a stolen disk image, NOT a live host (the
// irreducible residual, carried in the module docs).
pub mod share_seal;
pub mod fleet_supervisor;
// RE-ADOPT / REAP on supervisor restart (closes resilience finding G-3, the orphan-zombie).
// The PID sidecar + PID-reuse-safe liveness probe + supervise-by-PID tenant + the PURE
// reconcile decision ({ReAdopt | Reap}) a restarted `kirby fleet` runs over its persisted state
// before the listen loop. Platform-agnostic host-side logic (the pure decision + registry are
// VM-free); `libc::kill`/`/proc` liveness is unix. Fleet-supervisor-only — a bare `kirby run`
// never reconciles. NOT cfg-gated (like `fleet_supervisor`); the `/proc` probe degrades to
// not-alive off Linux.
pub mod fleet_reconcile;
// AUTOMATIC FAILOVER DETECTION (closes resilience finding G-4, the no-failover gap): the PURE
// decision a surviving node runs over its observed fleet-lease snapshot to decide which PEER
// agents (their relay-lease went stale) to take over -- with the observer-blind fail-safe that
// stands a relay-blind node down rather than mass-false-taking-over the fleet. Transport-free +
// VM-free pure logic (like `lease`/`fleet_reconcile`), so NOT cfg-gated; the daemon wiring +
// actual `claim(term+1)` are a later chunk.
pub mod failover_detect;
#[cfg(target_os = "linux")]
pub mod full_loop_run;
pub mod gateway;
// Hibernation thin-slice shared types (H0): StateBundle/Share/Lease/WatcherRecord/
// WakeRequest + the agent-scoped path helper. Platform-agnostic host-side serde
// types (no genome/trait/sudo surface), like `nerve`/`engram` -- NOT cfg-gated.
pub mod hibernate;
// The lease SEAM + shared value types (the no-split-brain fence). Transport-free, so NOT
// cfg-gated; the relay-native impl lives in `relay_lease`.
pub mod lease;
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
pub mod nip60;
pub mod nip60_counter;
pub mod prereqs;
pub mod rail;
pub mod relay_lease;
pub mod run_agent;
pub mod sandbox;
pub mod seed_keyring;
pub mod spawn;
#[cfg(target_os = "linux")]
pub mod snapshot_run;
pub mod treasury;
#[cfg(target_os = "macos")]
pub mod vz;
