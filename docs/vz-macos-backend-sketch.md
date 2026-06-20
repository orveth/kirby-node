# Kirby on macOS: VZ backend + CI-verify sketch (2026-06-17)

> The BACKEND DESIGN already lives in docs/cross-platform-sandbox.md (the SandboxBackend
> trait, the Apple Virtualization.framework assessment, the hybrid-resume model, the honest
> caveats) and is NOT repeated here. This doc adds the two things that were open: the
> VERIFY PATH (the GitHub Actions answer) and a concrete BUILD SEQUENCING for the VZ
> backend on the trait. No em-dashes per house style.

## 1. The verify path (the GitHub Actions answer) = RESOLVED

Question: can GitHub Actions build + automatically verify the Apple
Virtualization.framework backend?

Answer: YES via a self-hosted runner on a Mac the operator owns; NO on GitHub-HOSTED runners.

- GitHub-HOSTED macOS runners cannot run a VZ guest. Their Apple Silicon runners are
  themselves virtualized, so a VZ VM would need NESTED virtualization; GitHub disables
  it ("not supported due to the limitation of Apple's Virtualization Framework"), and
  the feature request (actions/runner-images #13505) was closed "not planned" (Jan
  2026). They also offer no M3/M4 (Apple only exposes nested virt on M3+/macOS 15
  anyway). Do not plan around hosted runners.
- GitHub Actions still works as the ORCHESTRATOR via a SELF-HOSTED runner: a bare-metal
  Mac mini IS the hypervisor, so VZVirtualMachine runs NATIVELY (no nesting). Register
  the mini as `runs-on: [self-hosted, macos]`; the macOS verify job boots a real VZ
  Linux microVM and runs the backend integration tests there, exactly as the Firecracker
  job does on Linux. CI marginal cost after hardware = electricity.

### Ranked verify options (cost is the discriminator)
1. RECOMMENDED: a self-hosted Mac mini M4 (~$599 to $799 one-time) on macOS, registered
   as a GitHub Actions self-hosted runner. Cheapest path that works, and it DOUBLES as
   the dev box AND the CI verify runner, so one purchase unblocks build AND automated
   verify. Limit: one machine = one concurrent macOS job (add a second later for
   parallelism/HA).
2. Cirrus Runners (managed, ~$150/mo per concurrent slot, M4 Pro, Tart-based): no
   hardware to own, but their runners are themselves Tart VMs, so CONFIRM with them that
   a nested VZ guest is allowed inside a runner slot (undocumented) before relying on it.
3. AWS EC2 Mac (mac-m4pro.metal, ~$1.97/hr, 24h MINIMUM allocation = ~$47/day): true
   bare metal, VZ works, but the 24h floor makes per-PR CI expensive. Use a scheduled or
   reserved host, not per-PR spin-up. Good as an on-demand fallback or a one-off bring-up
   before buying hardware.
4. MacStadium Orka: bare-metal Apple Silicon, enterprise pricing. For sustained team CI
   load; overkill now.
5. GitHub-hosted runners: NO (listed to close the door explicitly).

## 2. VZ backend build plan (mapped onto the SandboxBackend trait)

The `SandboxBackend` / `SandboxInstance` seam (crates/kirby-node/src/sandbox.rs) is the
prerequisite; Firecracker is already the first impl (crates/kirby-node/src/firecracker.rs).
The VZ backend is a second impl behind the same trait. Per the parity map (cross-platform-sandbox.md)
the genome is unchanged (it only ever talks to the gateway over vsock); only the backend
mechanics differ. Work items, roughly sequenced:

0. Prerequisite: get the arm64 genome image. It is an aarch64-LINUX Nix derivation, so a
   Mac cannot `nix build .#genome-image-aarch64` without a Linux builder. Build it on a
   Linux box (x86_64-linux cross-compiles it) and deliver the closure to the Mac via a
   binary cache or `nix copy`, then point KIRBY_GENOME_IMAGE at the store path; or set up
   nix-darwin `nix.linux-builder`. See the README ("Getting the arm64 genome image on
   macOS"). Boot (item 2) needs this in hand.

1. Swift sidecar helper (the platform-engineering long pole): there is no production Rust
   VZ.framework crate, so the daemon drives a small Swift helper that owns
   VZVirtualMachine. This is resolved as sidecar Swift, not objc2-in-process. Budget real
   time here; this is the macOS-specific cost.
2. Boot (macOS G1): VZLinuxBootLoader + a raw arm64 `Image` derived from the shipped
   `vmlinux` ELF + the SAME content-addressed squashfs + static-musl /init genome image
   (the image is portable; only the loader differs). Prove a Linux microVM boots
   headless.
3. vsock host-gateway shim: the guest side is identical (the genome dials vsock), but the
   HOST side is NOT raw AF_VSOCK on macOS (ENODEV); it is VZVirtioSocketConnection via the
   framework. So the daemon's gateway transport gets a VZ-specific listener that serves the
   SAME NodeGateway tonic service over the VZ socket. (The Firecracker side already taught
   us the host-side-is-a-socket lesson; this is the VZ analogue.)
4. Egress lockdown + meter (macOS G4): pf on the vmnet interface (default-deny + counters)
   in place of nftables; egress bytes via pf counters or a vsock-proxied data plane in
   place of eBPF. Entitlement fork: a framework-managed VZNATNetworkDeviceAttachment needs
   no extra entitlement but limits data-plane control; a bridged/raw vmnet attachment (for
   pf rules + counters directly on the interface) needs com.apple.vm.networking (or root).
   Pick before building G4.
5. Metering (macOS G2, honestly looser): no cgroups, so CPU via host-thread rusage/Mach,
   memory hard-capped at boot (no running ceiling). The implemented source is
   `MeterSource::HostProcess`: helper + discovered VM service pids for CPU, memory cap
   for mem-time. Return the same burn/debit shape so the treasury debit (D-9) is shared,
   plus a MeterFidelity so the daemon trusts the macOS sample less.
6. Halt: VZVirtualMachine stop + teardown of the vmnet/pf plumbing (the macOS analogue of
   the cgroup-kill + TAP teardown).
7. Resume (the C-7 sync point, see section 3 and docs/vz-app-checkpoint-resume.md):
   VZ's Linux-guest VM-checkpoint is broken/Mac-bound, so the macOS backend's resume is
   the APP-LEVEL checkpoint (boot a fresh VM + rehydrate the genome's logical blob), NOT
   a VM-snapshot. The same-platform fast VM-snapshot path stays Firecracker-only.

Isolation caveat to carry (a documented risk, not a build step): no jailer-equivalent on
macOS, so a VZ escape lands in an unconfined user process. Mitigate by running the VZ host
process as a dedicated low-priv user, no VirtioFS, minimal home. Weaker post-escape
defense-in-depth than Firecracker's jailed escape; name it, do not hide it.

## 3. How this threads with the Firecracker spike (the sequencing)

- SHARED FOUNDATION: the SandboxBackend trait (crates/kirby-node/src/sandbox.rs) is the
  prerequisite for the VZ backend. No conflict.
- THE ONE COLLISION = checkpoint/resume (spike C-7). A VM-memory snapshot cannot cross
  hypervisors or arch (structural, see cross-platform-sandbox.md), so the cross-platform resume
  is the app-level checkpoint, and that SHAPES the trait's resume API. Build C-7
  Firecracker-only and the resume seam gets carved Firecracker-shaped and reworked for VZ.
  So C-7 is designed Mac-aware: the trait's resume surface expresses BOTH the same-platform
  VM-snapshot (Firecracker fast path) AND the app-checkpoint (the portable path), with a
  SnapshotClass capability the scheduler matches on. The G7 entropy invariant (no ephemeral
  secret survives a move) is duplicated onto the app-checkpoint path. C-8 (entropy-on-
  resume) rides on C-7.
- NO COLLISION: C-6 (the brokered-act earn half) is daemon-side host networking,
  backend-agnostic; safe to do next on Firecracker while the Mac track proceeds.
- The VZ backend BUILD is gated on Mac hardware access. Until a bare-metal Mac or an EC2 Mac
  instance exists, the Mac track is exactly: this sketch + the trait shape + the C-7
  resume-seam design. The moment hardware lands, the VZ build (section 2) starts and
  verifies on the self-hosted runner.

## 4. Open decisions
1. The Mac hardware: buy a mini M4 (recommended), bring up on EC2 Mac first, or dev on
   a Mac laptop with verify on EC2/mini. This gates the VZ build.
2. macOS version on the verify node: the dev/test box (M4 Max) is on macOS 26; the keychain
   regression was a macOS-15 issue and is UNVERIFIED on 26, so apply the portable fix
   (unlock login.keychain at boot) regardless of version. macOS 14 Sonoma never had the
   regression and needs no nested virt on bare metal, so it stays a fine fleet-node option;
   do not assume the dev box must downgrade. Confirm the keychain behavior on 26 at bring-up.
3. Sequencing confirm: finish the Firecracker reference THROUGH the C-7 resume seam
   designed Mac-aware, in parallel with the VZ bring-up once hardware lands; C-6 proceeds
   now.

Related: docs/cross-platform-sandbox.md (backend design + parity map + caveats),
docs/build-spec.md (spike chunks/gates), docs/vz-app-checkpoint-resume.md.
