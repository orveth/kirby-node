# Kirby VZ backend: build sequence for the heterogeneous MVP cluster (2026-06-18)

> The GOAL, the CHUNK SEQUENCE, and the CLUSTER acceptance gate. This doc does NOT
> repeat the backend design (docs/cross-platform-sandbox.md), the work-item plan
> (docs/vz-macos-backend-sketch.md), or the resume design
> (docs/vz-app-checkpoint-resume.md). It sequences them into reviewable chunks against
> a concrete cluster outcome. No em-dashes per house style (the `clean` gate checks).

## 1. The goal (sharpened 2026-06-18)

Run a kirby node on a Mac (Apple Silicon, VZ backend) as the THIRD node of the MVP
cluster, peering with two x86 Linux/Firecracker nodes (the operator's stated target).
Not a standalone Mac sandbox, not a post-MVP afterthought: a full cluster PEER.

Why this is sound by construction: everything above the `SandboxBackend` seam is
platform-agnostic. Raft lease (C-9), treasury + brokered acts (C-3/C-6), idempotent
capability (C-10), and the nerve/presence layer all run in the daemon, identically on
every node. The Mac node differs only BELOW the seam, and only in two node-LOCAL ways,
neither of which is visible to consensus or custody:

- Metering is coarser: `MeterSource::HostRusage` (host-thread rusage/Mach + boot-time
  memory cap) instead of cgroup v2. The daemon widens the budget-halt margin via a
  `MeterFidelity` tag. Same `MeterSample` shape, same treasury debit (D-9).
- Resume is app-checkpoint only: `BackendCapabilities { snapshot: None,
  app_checkpoint: true }`. No VM-snapshot can reach a VZ node (structural: a
  mem+vmstate save is Mac-bound + arm64). The Mac node resumes by booting fresh and
  rehydrating logical state.

## 2. The cluster acceptance gate (the definition of done)

The VZ work is DONE when, with two x86 Firecracker nodes already running:

- **G-VZ-CLUSTER**: the Mac VZ node joins the running Raft cluster, takes a lease,
  and performs ONE real brokered act (the C-6 settle) from inside the VZ-sandboxed
  genome, with VZ-host egress locked down (TAP/vmnet default-deny holds during the
  act, credential never crosses vsock), then survives a kill -> restart via the
  app-checkpoint path and rejoins with the same node identity. The per-node gates
  (G1 boot, G2 budget-halt, G4 egress, G7 entropy-on-resume) all hold on the VZ node.

This is the integration test the operator asked for: run a kirby node on a Mac
alongside the other two x86 nodes. The per-chunk gates below build up to it.

## 3. Two tracks and their dependency

The VZ goal splits into an AGNOSTIC track (Linux, main build loop, NOT Mac-gated) and
a VZ track (the operator's Apple Silicon Mac). They converge at G-VZ-CLUSTER.

### Track A: agnostic app-checkpoint machinery (Linux, main loop)

FINDING (2026-06-18, verified in tree): `firecracker.rs:220` already declares
`app_checkpoint: true`, but the machinery behind it does NOT exist yet. No
`CheckpointRef`, no `CheckpointStore`, no `SubmitCheckpoint` RPC in
node_gateway.proto, no `app_checkpoint_run.rs` scheduler branch, no `restore_from`
boot field, no checkpoint-aware genome workload. The capability flag is set AHEAD of
the implementation. The scheduler would find no machinery if it trusted the flag
today. So Track A is a real prerequisite, not a flag flip.

Track A is the design in docs/vz-app-checkpoint-resume.md, built as numbered chunks
(fresh-agent impl + different-agent verifier, keeper commits on GO). It is pure
agnostic core (sandbox.rs types, kirby-proto, gateway.rs, genome, a new
app_checkpoint_run.rs) and runs/verifies entirely on Linux/Firecracker. Firecracker
GAINS app-checkpoint resume for free once it lands; until then, the `app_checkpoint:
true` flag should be treated as aspirational (consider gating it behind the machinery
to remove the smell).

Track A depends on C-8 (the `GetEntropyNonce` re-derive surface), which has landed
(C-7..C-11 are in main @ 35446ca). So Track A is unblocked and can start now.

### Track B: the VZ backend (Mac, M4 Max)

The five backend methods + resume, behind the trait. Mac-gated (needs Apple Silicon
+ the framework). Builds against the existing Firecracker impl as the parity target.

Convergence: G-VZ-CLUSTER needs Track A built (so the VZ node can resume) AND Track B
through its resume chunk. Track B chunks 1-5 do NOT depend on Track A and can proceed
in parallel; only the resume chunk (VZ-6) and the cluster gate (VZ-7) need it.

## 4. Chunk sequence (Track B, on the trait)

Each chunk: fresh-agent impl + different-agent verifier; keeper reviews + commits on
GO. Gates map to the Firecracker spike's gates (docs/build-spec.md). Verify on the
M4 Max manually until a self-hosted Mac runner exists (section 6).

- **VZ-0 (image delivery, do first):** get the aarch64-linux genome image onto the
  Mac. Build `.#genome-image-aarch64` on any Linux box (x86_64-linux cross-builds it),
  `nix copy` the content-addressed closure to the Mac, point `KIRBY_GENOME_IMAGE` at
  the store path. NOT a code chunk; a setup step. Gate: the store path resolves on the
  Mac and hashes identically to the Linux-built path. (Resolved + documented in
  README "Getting the arm64 genome image on macOS"; this is no longer a blocker.)

- **VZ-1 (FFI shim, the long pole):** decide objc2-in-process vs a sidecar Swift
  helper the daemon drives, then stand up the minimal surface to construct + run a
  `VZVirtualMachine`. Budget the most time here. Gate: a trivial VZ guest starts +
  stops under the shim.

- **VZ-2 (boot, macOS G1):** `VZLinuxBootLoader` + the uncompressed `vmlinux` ELF +
  the same squashfs genome image. Gate G1: the Linux genome microVM boots headless on
  the Mac and the genome process starts.

- **VZ-3 (vsock host shim):** the guest side is identical (genome dials AF_VSOCK);
  the host side is `VZVirtioSocketDevice` / `VZVirtioSocketConnection`, not a Unix
  socket. Add a `GatewayTransport::VzVsock` variant; the `NodeGateway` tonic service
  is unchanged. CARRY FIX-3's host-side liveness from the start (see
  docs/vz-app-checkpoint-resume.md section "Resume liveness"): `serve_vz_vsock` reaps
  dead connections + keeps accepting, and guards per-connection reads against a
  half-dead `VZVirtioSocketConnection`. Gate: the genome completes a gateway
  round-trip (GetSessionContext) over VZ vsock, AND a killed-guest connection does not
  wedge the serve loop (the FIX-3 host-side probe, section 5).

- **VZ-4 (egress lockdown + meter, macOS G4):** pf default-deny + counters on the
  vmnet interface in place of nftables + eBPF. Resolve the entitlement fork first
  (NAT attachment = no entitlement but limited data-plane control; bridged/raw vmnet =
  needs com.apple.vm.networking or root, gives pf rules + counters directly). Gate G4:
  egress is default-denied + counted; the brokered-act allowlist is the only opening.

- **VZ-5 (metering + halt, macOS G2):** `MeterSource::HostRusage` returning the same
  `MeterSample` shape + a `MeterFidelity` so the daemon widens the halt margin;
  boot-time memory cap. Halt = `VZVirtualMachine` stop + vmnet/pf teardown. Gate G2:
  a budget-exhausted VZ genome is halted by the daemon (the genome cannot stop it),
  within the widened margin.

- **VZ-6 (boot-with-restore_from):** the VZ side of Track A. `boot()` honors
  `GuestSpec.restore_from: Option<CheckpointRef>` (kernel cmdline
  `kirby.restore_from=` or via SessionContext) so a fresh VZ guest rehydrates instead
  of cold-starting. Gate G7-sibling: resume a VZ genome from a checkpoint and assert
  its ephemeral nonce is FRESH (re-fetched via GetEntropyNonce, differs from any
  pre-checkpoint value) -- a blob cannot smuggle a stale nonce across the move.
  Depends on Track A.

- **VZ-7 (cluster integration):** the Mac node joins the 2-x86 cluster. Gate
  G-VZ-CLUSTER (section 2). This is the headline proof.

## 5. The two VERIFY-ON-MAC probes (do not assume framework semantics)

Both are boot-confirm items the design flags as MUST-verify on real VZ, not assumed:

1. **Dead-fd semantics (FIX-3):** does a `VZVirtioSocketConnection` whose guest peer
   is gone return EOF promptly, or hang? If it holds the connection object alive past
   guest-death, the host-side read deadline in VZ-3 is mandatory, not optional.
   Baseline for the A/B: Firecracker's host uds appears to EOF promptly (inferred from
   reliable spike failover); ideally probe the uds directly rather than leaving it
   inferred.
2. **Console + arch boot:** the arm64 guest kernel uses PL011 console + GIC v3;
   confirm the `VZLinuxBootLoader` + vmlinux path boots clean on the actual framework
   version (macOS 26 on the M4 Max).

## 6. Resolved decisions (open questions, now answered by the operator's direction)

- **Mac hardware (sketch Q1):** dev + initial verify on the operator's Apple Silicon
  Mac (M4, macOS 26, bare metal, no nested-virt issue). A self-hosted Mac mini as a GitHub Actions
  runner is the automated-verify path LATER; not needed to start the build.
- **macOS version:** apply the portable keychain fix (unlock login.keychain at boot)
  regardless of version; confirm keychain behavior on 26 at bring-up.
- **Checkpoint direction (app-checkpoint Q1):** genome-client shape confirmed. The
  genome PUSHES its logical-state blob via `SubmitCheckpoint` at mission-defined safe
  points; the boot-time ref rides in `GetSessionContext`. No daemon-initiated
  genome->daemon call.
- **Build-ownership (app-checkpoint Q2/Q3):** Track A (agnostic machinery) is built
  by the main loop as numbered chunks from the resume design, sequenced now (C-8 has
  landed). Track B (VZ backend) is built on the Mac off this repo; the design owner
  owns the design + reviews each chunk; the Mac implementer builds. The design owner
  cannot test VZ on Linux, so VZ gates are verified on the Mac.

## 7. Isolation caveat to carry (documented risk, not a build step)

No jailer-equivalent on macOS, so a VZ escape lands in an unconfined user process.
Mitigate: run the VZ host process as a dedicated low-priv user, no VirtioFS, minimal
home. Weaker post-escape defense-in-depth than Firecracker's jailed escape. Named, not
hidden.

## Related
docs/cross-platform-sandbox.md, docs/vz-macos-backend-sketch.md,
docs/vz-app-checkpoint-resume.md, docs/build-spec.md,
crates/kirby-node/src/{sandbox.rs, firecracker.rs}.
