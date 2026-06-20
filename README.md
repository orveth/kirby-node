# kirby-node

## What Kirby is

Kirby is an autonomous agent that holds its own funds under a key no human holds, runs its
mission code inside a hardware-isolated sandbox, pays its own way (rent, compute, external
acts), and dies when its balance hits zero. No operator controls it at runtime; the custody
quorum and the metered sandbox enforce the rules instead.

**This repo is the compute + metabolism + failover spike**, on play-money with zero custody.
It proves that a node daemon can: boot a genome inside a microVM, meter its resource use
against a daemon-owned treasury the genome cannot forge, let the genome act in the world
through a single brokered vsock gateway (the only channel out), survive a node kill by
snapshotting and resuming on a second node, and die cleanly when its budget runs out.
Everything here runs on a local CDK fakewallet mint; no real keys, no mainnet, no FROST.

## Architecture

### The agnostic core (platform-neutral)

Every load-bearing piece that does NOT change with the choice of hypervisor:

| Component | Crate / file | What it does |
|-----------|-------------|--------------|
| Treasury | `kirby-node/src/treasury.rs` | Daemon-owned authoritative balance. The genome can observe it but cannot write it; only daemon-side code debits. |
| Gateway | `kirby-node/src/gateway.rs` | The genome's ONLY interface: four tonic/vsock RPCs (`GetSessionContext`, `GetEntropyNonce`, `ReportEvent`, `RequestCapability`). Enforces the authorize-order (dedupe -> allowlist -> budget gate -> perform -> debit) on every brokered act. |
| Rail | `kirby-node/src/rail.rs` | Performs the brokered act (ecash settle, LN pay, paid HTTP) using a host-held credential the genome never sees. |
| Meter | `kirby-node/src/meter.rs` | Host-authoritative CPU+memory billing off cgroup v2; triggers budget-death halt. |
| Egress meter | `kirby-node/src/meter_egress.rs` | Egress byte billing via the aya/eBPF TC classifier on the VM's TAP. |
| Raft lease | `kirby-node/src/raft_lease.rs` | openraft `active_lease{node,term}` ensures at most one node is active at any term boundary. |
| Nerve | `kirby-node/src/nerve.rs` | Nostr-based node presence/heartbeat (slice 1). |
| Genome | `kirby-genome/src/main.rs` | The musl-Rust stub that runs inside the microVM. Talks only to the gateway over vsock; carries no keys, no balance. |
| Proto | `kirby-proto/proto/node_gateway.proto` | The gateway wire contract. |

### The SandboxBackend trait (the cross-platform seam)

`crates/kirby-node/src/sandbox.rs` is the interface the daemon drives so a second hypervisor
backend can slot in without touching any gateway, treasury, rail, meter-math, or genome code.
It captures: boot a genome guest, expose the host-side vsock transport the gateway serves
over, provide the CPU+memory meter source, install and meter the egress lockdown, snapshot a
running guest, restore from a snapshot artifact, and halt.

The **Firecracker backend** (`src/firecracker.rs`) is impl #1: Linux/KVM under the jailer
(chroot + seccomp L2 + namespaces + uid-drop). The genome talks only vsock regardless of
which backend is running it; that invariant is what makes the seam honest.

### The life-arc the spike proves (gates G1-G10)

```
born        -> G1  genome boots inside a Firecracker microVM; vsock GetSessionContext round-trip lands
runs        -> G2  cgroup+eBPF meters accumulate; daemon halts the VM when budget is exhausted (not the genome)
pays        -> G3  treasury is unforgeable: no gateway path adds balance; budget gate denies overspends
isolated    -> G4  raw egress from the VM is denied by nftables; the genome cannot reach the outside directly
acts        -> G5  brokered act: genome RequestCapability -> daemon authorizes + performs via HOST net -> receipt;
                   credential never crosses vsock; VM TAP egress unchanged during the act
survives    -> G6  snapshot the running VM (CPU-template normalized), transfer mem+vmstate, kill node 1,
                   restore on node 2; genome continues from the snapshot
no-replay   -> G7  entropy re-derived on resume: VMGenID bumps vm_generation; genome calls GetEntropyNonce
                   and re-derives ephemeral secrets before acting; pre != post fingerprint (negative control
                   proves a skip-rederive genome fails)
no-split    -> G8  openraft active_lease{node,term}: kill node 1, node 2 acquires the lease at term+1;
                   revived node 1 sees the higher term and refuses to run/debit (term-fencing)
idempotent  -> G9  RequestCapability with idempotency_key K survives snapshot+resume: re-issue returns
                   DUPLICATE_IGNORED; the act is performed and billed exactly once
clean       -> G10 genome image content-addressed (same hash on every node); daemon builds clean;
                   no em-dashes in comments/docs; verifier reproduces G1-G9 from a clean checkout
```

Both red-team gates (G7 entropy-on-resume and G8 no-split-brain) are first-class, not
optional hardening. The spike does not pass without both.

## Layout

```
crates/
  kirby-node/    Tokio node daemon (one process per node)
    src/
      sandbox.rs       SandboxBackend trait + SnapshotArtifact types (the cross-platform seam)
      firecracker.rs   Firecracker backend: impl #1 of SandboxBackend
      gateway.rs       NodeGateway service + authorize-order
      treasury.rs      Authoritative daemon-owned balance
      rail.rs          Brokered-act rail (MockRail + CdkEcashRail)
      meter.rs         Host-authoritative CPU+memory meter
      meter_egress.rs  eBPF egress byte meter
      raft_lease.rs    openraft active_lease (no-split-brain)
      nerve.rs         Nostr presence/heartbeat
      prereqs.rs       Host-prereqs gate (KVM, cgroup v2, nftables, vsock, jailer)
    tests/
      genome_boot.rs       G1
      metering_halt.rs     G2
      treasury_gateway.rs  G3
      egress_lockdown.rs   G4
      brokered_act.rs      G5
      snapshot_resume.rs   G6
      entropy_resume.rs    G7
      no_split_brain.rs    G8
      idempotent_resume.rs G9
      full_loop.rs         G1-G10 end-to-end

  kirby-proto/   Gateway wire contract (tonic/protobuf over vsock)
  kirby-genome/  musl-Rust stub genome (runs inside the microVM as PID 1)
  kirby-ebpf/    eBPF TC egress classifier (aya, nightly Rust)

nix/
  genome-image.nix          x86_64 genome image (kernel + squashfs rootfs)
  guest-kernel.nix          stripped Linux 6.1 LTS guest kernel, VMGenID, x86_64
  genome-image-aarch64.nix  arm64 genome image (for the VZ backend on Apple Silicon)
  guest-kernel-aarch64.nix  arm64 guest kernel (PL011 console, GIC v3)

docs/
  build-spec.md             Frozen build spec (C-1..C-11, G1..G10, decisions D-1..D-20)
  cross-platform-sandbox.md Backend assessment + SandboxBackend parity map
  vz-macos-backend-sketch.md  VZ backend build plan + CI-verify options
  vz-app-checkpoint-resume.md App-checkpoint portable resume design (the next work)
```

## Build and run

The Nix dev shell provides the Rust toolchain (stable 1.90 + nightly for the eBPF subtree),
Firecracker + jailer, and nftables. The bare host needs KVM, cgroup v2, nftables,
`/dev/vhost-vsock`, and a way to run the Firecracker jailer (root, a capable user, or a
passwordless-sudo wrapper around the jailer binary).

```sh
nix develop
cargo build
cargo clippy -- -D warnings
cargo run -p kirby-node -- prereqs        # host-prereqs gate (G1 pre-check)
cargo run -p kirby-node -- prereqs --json # machine-readable evidence
```

The `prereqs` command exits non-zero if any hard requirement is unmet (KVM, cgroup v2,
nftables, vsock, jailer path).

### Running the gate tests

Most gate tests require a real microVM environment (KVM, vsock, jailer, cgroup v2). The
integration tests are gated behind the `real_vm` feature; cargo runs them when the feature
is enabled and the host-prereqs gate passes.

```sh
# Unit tests only (no VM required)
cargo test

# Integration tests against real microVMs (requires KVM + cgroup v2 + vsock + jailer)
KIRBY_GENOME_IMAGE=$(nix build --no-link --print-out-paths .#genome-image) \
  cargo test --features real_vm
```

The `KIRBY_GENOME_IMAGE` variable points at the Nix-built genome image (kernel + squashfs
rootfs). The image is content-addressed; the same store path on every node is how gate G10
verifies reproducibility.

## macOS / Apple Virtualization.framework backend (the next work)

The compute spike is complete on Linux/KVM (all eleven chunks, gates G1-G10 green). The
next work is a **second `SandboxBackend` impl for macOS**, using Apple's
Virtualization.framework (VZ) to run the same Linux genome image on Apple Silicon.

### Where to start

- **The trait:** `crates/kirby-node/src/sandbox.rs` -- read the module-level doc first.
  The VZ backend implements `SandboxBackend` + `SandboxInstance` + `EgressControl`.
- **The reference impl:** `crates/kirby-node/src/firecracker.rs` -- the Firecracker
  backend is the parity target. Mirror its structure: one stateless backend struct, one
  per-instance struct that owns the running guest's host state.
- **The arm64 genome image:** `nix/genome-image-aarch64.nix` (squashfs + static-musl
  /init) and `nix/guest-kernel-aarch64.nix` (stripped Linux 6.1 LTS, PL011 console, GIC
  v3). The image ships `vmlinux`; the VZ backend derives the raw arm64 `Image` that
  `VZLinuxBootLoader` boots. The squashfs is the same format as x86.
- **Design docs:**
  - `docs/cross-platform-sandbox.md` -- backend assessment, parity map, known caveats
  - `docs/vz-macos-backend-sketch.md` -- build plan (FFI shim, boot, vsock shim, egress,
    metering, halt, resume) + CI-verify options (self-hosted runner on a Mac mini)
  - `docs/vz-app-checkpoint-resume.md` -- the portable app-checkpoint resume design (the
    VZ backend's resume path, since VZ's Linux-guest VM-checkpoint is broken/Mac-bound)

### Getting the arm64 genome image on macOS (do this first)

The genome image is an **aarch64-linux** Nix derivation (a Linux kernel + musl rootfs),
not a macOS one. `nix build .#genome-image-aarch64` therefore CANNOT run on an
Apple-Silicon Mac directly: Nix on `aarch64-darwin` has no way to produce Linux build
outputs without a Linux builder, so a fresh clone on a Mac fails at this step. Plan for it
up front. Two supported paths:

- **Build on Linux, deliver to the Mac (simplest).** On any Linux box (x86_64-linux
  cross-compiles the aarch64 image; this is how the image is built today),
  `nix build .#genome-image-aarch64 --no-link --print-out-paths` yields a
  `/nix/store/...-kirby-genome-image-aarch64` path. Ship the closure to the Mac via a
  binary cache (`nix copy --to ...`, cachix, or attic) or `nix copy` over SSH, then point
  the harness at the store path:
  `KIRBY_GENOME_IMAGE=/nix/store/...-kirby-genome-image-aarch64 cargo test --features real_vm`.
- **A Linux builder on the Mac.** Configure a remote Linux builder, or nix-darwin's
  `nix.linux-builder` (a lightweight NixOS VM), so `nix build .#genome-image-aarch64`
  resolves the Linux derivation locally. Heavier to set up; only worth it to have the Mac
  build the image itself.

The image is content-addressed, so the store path is identical however it was produced.
`KIRBY_GENOME_IMAGE` is the same handoff the Linux gate tests use (see "Build and run").

### What the VZ backend must implement

| Item | Firecracker equivalent | VZ approach |
|------|----------------------|-------------|
| Boot | `fctools` + jailer | `VZLinuxBootLoader` + `VZVirtualMachine` through the Swift sidecar helper; backend converts ELF `vmlinux` to raw arm64 `Image` |
| vsock host-side | Firecracker Unix socket per CID: `GatewayTransport::FirecrackerVsockUds` | `VZVirtioSocketDevice` / `VZVirtioSocketConnection`: add a `GatewayTransport::VzVsock` variant; the gateway service itself is unchanged |
| Egress lockdown | TAP + nftables default-deny + eBPF byte counter | vmnet interface + pf default-deny + pf counters (or vsock-proxied) |
| CPU+memory meter | cgroup v2 `cpu.stat` / `memory.current`: `MeterSource::CgroupV2` | host-process rusage for the VZ helper + VM service pids, plus boot-time memory cap: `MeterSource::HostProcess`; `MeterFidelity::HostCoarse` declares the looser accounting |
| Halt | cgroup-kill + TAP teardown | `VZVirtualMachine` stop + vmnet/pf teardown |
| Resume | VM-snapshot (mem+vmstate): `snapshot()` / `restore()` | App-level checkpoint (boot fresh + rehydrate logical state): `BackendCapabilities { snapshot: None, app_checkpoint: true }` -- see `docs/vz-app-checkpoint-resume.md` |
| Isolation | Hardware VM + jailer (chroot/seccomp/namespaces) | Hardware VM only; no jailer equivalent. Run the VZ host process as a dedicated low-priv user, no VirtioFS, minimal home. Document the weaker post-escape profile. |

### Key implementation notes

1. The host-side vsock shim (`serve_vz_vsock`) is the load-bearing new surface. A dead
   `VZVirtioSocketConnection` (guest killed) must not wedge the accept loop or any
   per-connection server task. Add a per-connection read deadline and confirm on real VZ
   hardware whether a dead connection fd returns EOF promptly or hangs. See the
   "stale-transport black hole" section in `docs/vz-app-checkpoint-resume.md`.

2. The genome binary is unchanged (it talks only vsock to the gateway; guest-side AF_VSOCK
   + tonic client are identical). Only the host-side backend mechanics differ.

3. Keychain (unlock at boot is the portable fix). VZ needs an unlocked login.keychain at
   runtime (else "Interaction is not allowed with the Security Server"). This was a macOS 15
   issue; the dev/test box is on macOS 26, where it is UNVERIFIED, so treat it as
   version-independent and just unlock login.keychain at boot (works on any version). The
   macOS-14-Sonoma preference is fleet-node advice (Sonoma never had the regression), not a
   dev-box requirement; do not assume a downgrade. The entitlement
   `com.apple.security.virtualization` must be present (ad-hoc self-sign is sufficient; App
   Store is not required).

4. CI: GitHub-hosted macOS runners cannot run a nested VZ guest (Apple disables nested
   virtualization; the feature request was closed "not planned"). Use a self-hosted runner
   on a bare-metal Mac mini M4 (recommended), or AWS EC2 mac-m4pro.metal. See
   `docs/vz-macos-backend-sketch.md` section 1 for the ranked options.

5. Networking entitlement for egress. The G4 egress lockdown needs an interface to police.
   A framework-managed `VZNATNetworkDeviceAttachment` needs NO extra entitlement but gives
   less direct data-plane control; a bridged or raw `vmnet` attachment (for pf rules +
   byte counters straight on the interface) needs `com.apple.vm.networking` (or root).
   Decide this fork early; it shapes how G4 (egress denied + byte-metered) is built.
