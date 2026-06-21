# AGENTS.md -- running a kirby node

This file is for an agent (or an operator) tasked with **setting up and running a kirby node**.
It is the ground-truth runbook. Read it top to bottom; do not skip the prereqs gate.

If a human says *"I want to run a kirby node"*, your job is to: pick the platform, build the
toolchain and genome image, fill in `kirby.toml`, prove the host with the prereqs gate, then run
`kirby run`. That single command takes the node from nothing to a live sovereign agent in the
Nostr fleet.

## First, set expectations

- This is a **play-money spike**, not a product. No real keys, no mainnet, no FROST. The
  brokered-act mint is a local CDK fakewallet. Nothing here moves real value.
- **The run path is one command:** `kirby-node agent --config kirby.toml` (a.k.a. `kirby run`).
  It runs a single **sovereign** agent joined to a Nostr fleet. It is NOT the Raft cluster
  (that is a resilience showcase, see the bottom of this file).
- It runs on **Linux** (Firecracker backend) and **Apple Silicon macOS** (Apple Virtualization
  backend). `backend = "auto"` in the config picks the right one per platform.

## What `kirby run` actually does

From a config file to a live agent, composing pieces that already exist:

1. Load and validate the config; resolve the backend by platform (unless pinned).
2. Load or mint the node's Nostr identity (same npub across restarts).
3. Join the fleet: presence + heartbeat + a `9100` lifecycle event.
4. `mode = "bootstrap"`: fund the treasury to "born". `mode = "resume"`: restore the agent from
   its latest app-checkpoint instead.
5. Boot the agent in the sandbox via the resolved backend.
6. Run the v0 workload (`workload = "app-checkpoint"`): the genome submits an app checkpoint for
   future resume, then stays alive while the host meters VM time.
7. Meter every tick against the treasury; on exhaustion HALT (die-when-broke) and emit a `9100`
   died. A clean shutdown also emits died.

## 1. Prereqs (platform-aware)

The prereqs gate checks the host for your platform. Run it before anything else:

```sh
nix develop
cargo run -p kirby-node -- prereqs          # human report (add --json for machine output)
```

It exits non-zero if any hard requirement is missing. A WARN does not fail the gate.

**Linux host needs:** `/dev/kvm` (group `kvm`), `/dev/vhost-vsock` (`modprobe vhost_vsock`),
cgroup v2 with `cpu` + `memory` controllers, `nft` (nftables), `firecracker` + `jailer` (from
the dev shell), and **jailer privilege**: root, passwordless sudo, or `CAP_SYS_ADMIN`. The
jailer privilege is the check that usually bites: the daemon launches the jailer through
passwordless `sudo` (it tries `/run/wrappers/bin/sudo` then `/usr/bin/sudo`, verifying with
`sudo -n true`). A sudo password prompt fails the gate. Add a passwordless sudoers rule for the
jailer, or run as root, or grant `CAP_SYS_ADMIN`.

**macOS host needs (Apple Silicon, aarch64 only):** macOS with Virtualization.framework, Xcode
or the Command Line Tools (for `xcrun`, `swiftc`, `codesign`), Nix, and Git. No Homebrew is
required. A passing gate looks like `RESULT: PASS (6 checks, 1 warn)` -- the warn is the login
keychain note. See the macOS section below and [`docs/mac-build-and-run.md`](docs/mac-build-and-run.md).

## 2. Build

```sh
nix develop                    # Rust toolchain, protoc, Firecracker + jailer (Linux), nftables
cargo build --workspace
```

## 3. Get the genome image

The genome image is a content-addressed Linux kernel + musl rootfs (`vmlinux` +
`rootfs.squashfs`). On Linux, build it:

```sh
nix build --no-link --print-out-paths .#genome-image          # x86_64
nix build --no-link --print-out-paths .#genome-image-aarch64  # arm64 (for macOS/VZ)
```

The aarch64 image is a **Linux derivation** and cannot be built on `aarch64-darwin` without a
Linux builder. On a Mac, get the prebuilt aarch64 image (from keeper:kirby, or build on a Linux
box and `nix copy` the closure over), unpack it, and point the config at it.

## 4. Configure

```sh
cp kirby.toml.example kirby.toml
```

Edit the three fields a teammate normally changes; everything else has a sane default:

- `genome_image = { path = "./.kirby/genome-image" }` -- the image directory from step 3.
- `[identity] key_path = "./.kirby/state/node.nostr.key"` -- minted 0600 on first run, loaded
  after (stable npub). `treasury_dir` defaults next to it.
- `[relay] url = "ws://..."` -- the fleet relay websocket.

Other keys: `backend` (`auto` / `firecracker` / `vz`), `workload` (`app-checkpoint`),
`mode` (`bootstrap` first run, `resume` to restore from the latest checkpoint), `agent_id` /
`node_id` labels, and `[funding] initial_sats` (play-money, seeded only on first creation).
The annotated template is [`kirby.toml.example`](kirby.toml.example).

## 5. Run

```sh
cargo run -p kirby-node -- prereqs               # must pass first
cargo run -p kirby-node -- agent --config kirby.toml
```

Verify it is alive: it publishes presence to the relay and emits a `9100` born event. Read the
fleet with `cargo run -p kirby-node -- presence --relay-url <url>` (or `nerve-events`). Start a
local relay for testing with `nix run .#relay` (defaults to `127.0.0.1:7777`).

To see the gates individually, each has a demo subcommand (`--help`): `boot` (G1), `meter`
(G2), `egress` (G4), `brokered` (G5, needs a running fakewallet mint via `--mint-url`),
`snapshot` (G6), `app-checkpoint`.

## macOS specifics

The macOS backend uses Apple Virtualization.framework to run the same Linux genome image on
Apple Silicon. Beyond the prereqs above:

- The VM process needs the `com.apple.security.virtualization` entitlement. An ad-hoc self-sign
  is sufficient; the App Store is not required.
- Keep `login.keychain` unlocked at runtime, or VZ fails with "Interaction is not allowed with
  the Security Server." Unlocking at boot works on any macOS version.
- The genome image must be the prebuilt **aarch64-linux** image (you cannot build it on the Mac
  without a Linux builder). Export `KIRBY_GENOME_IMAGE=/abs/path/to/image` or set the config
  `genome_image.path`.

[`docs/mac-build-and-run.md`](docs/mac-build-and-run.md) has the verified clean-clone cold-boot
walkthrough on an M-series Mac.

## Environment variables

| Var | Meaning |
|---|---|
| `KIRBY_GENOME_IMAGE` | Path to the genome image dir. Overrides / substitutes for the config `genome_image.path`; required by every VM subcommand. |
| `KIRBY_CPU_TEMPLATE` | CPU template for snapshot/resume normalization. Load-bearing for any cross-CPU or two-host move. |
| `KIRBY_EBPF_CARGO` | Absolute path to the nightly cargo that builds the eBPF subtree. Set by the dev shell. |

## Resilience showcase (not the run path)

`kirby run` is one sovereign node. The spike separately proves an agent survives the loss of its
host: `snapshot`/resume and `app-checkpoint` move a running agent to a fresh boot, and the Raft
lease (`raft_lease`) fences a term so two hosts never run the same agent at once. The full
multi-node fleet failover (kill a node, a peer takes over, no money lost) is shown live at
**http://185.18.221.222/**. The networked multi-node cluster itself is a separate line of work,
not part of the `kirby run` path.

## What this spike does NOT prove

Be honest about the boundary when reporting:

- No real custody: no real keys, no mainnet, no FROST. Play-money fakewallet mint only.
- The everyday run path is one sovereign node; networked multi-node failover is a showcase, not
  a runnable part of this command.
- No production hardening.
- A known caveat: the genome's vsock request timeout is short (safe for a local fakewallet
  settle, which is fast); a real non-local Lightning melt could exceed it. Revisit before any
  non-local mint.

## Where to read more

- [`kirby.toml.example`](kirby.toml.example) -- the annotated run config
- [`docs/build-spec.md`](docs/build-spec.md) -- gates, decisions, money-paths, the honest boundary
- [`docs/mac-build-and-run.md`](docs/mac-build-and-run.md) -- macOS cold-boot walkthrough
- [`docs/README.md`](docs/README.md) -- index of all design docs
