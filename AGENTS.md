# AGENTS.md -- running a kirby node

This file is for an agent (or an operator) tasked with **setting up and running a kirby node**.
It is the ground-truth runbook. Read it top to bottom; do not skip the prereqs gate. (If you are a
coding agent working *in* the repo, start at [`CLAUDE.md`](CLAUDE.md) -- it orients you on the code,
the build/test loop, and the full subcommand map; this file is the run runbook it points to.)

**Fastest path:** to just get a fleet node up, a bare `kirby-node` (no subcommand, no config
file) synthesizes working defaults and joins the fleet -- see [`docs/zero-config.md`](docs/zero-config.md).
The one prerequisite it still needs is the genome image (`nix build .#genome-image`, below). This
runbook is the full, explicit path; zero-config is the shortcut once your host is prepared.

**node != agent.** A **node** is what joins the network -- you run one with
`kirby-node fleet --config kirby.toml`; it beacons node presence and hosts agents. An **agent** is
one sovereign Kirby that runs on top of a node (declared as a fleet tenant, or spawned remotely).
The single command `kirby-node agent --config kirby.toml` runs ONE agent end to end -- the fastest
way to see the loop and smoke-test your host -- but the node you actually deploy is `kirby-node fleet`.

So your job, given a platform, is: build the toolchain and genome image, fill in `kirby.toml`, prove
the host with the prereqs gate, then run an agent (`kirby-node agent`, to see it work) and/or a node
(`kirby-node fleet`, to join the network and host agents).

## First, set expectations

- **Sovereign by default.** `kirby-node agent` provisions the agent its own 2-of-3 **FROST**
  threshold key **Q** on first boot and signs its entire public voice through a live
  in-process quorum; on restart it reloads the *same* Q (idempotent, fail-closed). **Today
  the three shares are co-located on this host** -- the threshold *structure* is real, but
  cross-machine holder distribution is the roadmap, so don't claim "a key no human holds"
  yet. `--no-frost` is a dev/test fast-path (plain node key), not the default.
- **ecash metabolism, no on-chain.** The brokered-act mint is a local CDK fakewallet; the
  agent thinks, acts, and dies against ecash. There is **no on-chain Bitcoin path**.
- **Two entrypoints, one config file.** `kirby-node agent --config kirby.toml` runs one sovereign
  agent (the taste / smoke). `kirby-node fleet --config kirby.toml` runs the node that joins the
  network and hosts agents (the deployment). Both read `kirby.toml`.
- **Watch the command name.** Older docs call the agent keystone "kirby run," but the actual command
  is `kirby-node agent`. There is also a *separate, legacy* `kirby-node run` subcommand (an early
  boot demo that just connects a genome and exits) -- do not run that when you mean to run an agent.
- It runs on **Linux** (Firecracker backend) and **Apple Silicon macOS** (Apple Virtualization
  backend). `backend = "auto"` in the config picks the right one per platform.

## What `kirby-node agent` does

From a config file to a live agent, composing pieces that already exist:

1. Load and validate the config; resolve the backend by platform (unless pinned).
2. Provision (first boot) or idempotently reload (restart) the agent's own 2-of-3 FROST
   keystore and derive its sovereign **Q + npub** -- the same Q across restarts. (`--no-frost`
   falls back to a plain node key.)
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

Start a local relay for testing with `nix run .#relay` (it serves `ws://127.0.0.1:7777`).

**What success looks like.** Watch the logs for these lines, in order:

```
loaded kirby run config
kirby run: starting the sovereign agent
agent identity ready (beacons + voice sign under this key)   (npub=...)
booting genome guest through the sandbox backend
genome boot hello received (G1 round-trip proven)            <- it reached Running
published 9100 lifecycle event (the signed birth/death log)  (event=born)
```

and the final line on **stdout**:

```
KIRBY-RUN mode=Bootstrap backend=... npub=... reached_running=true born=true died=true ... end=BudgetExhausted
```

The process **exits 0 iff it reached Running**; dying broke (`end=BudgetExhausted`) is the normal
terminal state and still exits 0. A bootstrap agent that never goes broke halts at a safety ceiling
(currently a hardcoded 600s; a config knob is in flight).

**How to verify -- agent vs node.** A single `kirby-node agent` does NOT beacon node presence
(`10100`); it surfaces as its `9100` lifecycle (born/died) plus live `31000` agent-state, under its
own npub. So `presence` will not show a bare agent -- verify it from the logs above. The
`presence` read path shows **nodes**: `cargo run -p kirby-node -- presence --relay-url <url>` lists
every `kirby-node fleet` node (ALIVE/STALE), which is how you confirm a node joined the network.

The subcommands are `agent` (one sovereign agent), `fleet` (the node + spawn control plane),
`spawn-request` (the operator spawn trigger), `presence` (read the fleet), `prereqs`, `boot`, and
`app-checkpoint`; the legacy `run` is an early boot demo (not the agent run). Run `--help` for each,
or see [`CLAUDE.md`](CLAUDE.md) for the full map. Per-gate invariants live in the integration suite
(`cargo test --workspace`).

## Run a fleet node (join the network + host agents)

`kirby-node agent` is the taste; the node you deploy is the fleet:

```sh
cargo run -p kirby-node -- fleet --config kirby.toml
```

It beacons node presence (`10100`), hosts any static `[[fleet.tenants]]` you declared as child
agents, and runs the spawn control plane so operators can spawn agents onto it remotely (a
kind-`31003` `spawn-request`). **Security default to know:** in `[fleet.spawn]`, an empty `operators`
allowlist means **any signer may spawn an agent on your node** (the accepted MVP DoS vector; it logs
a loud warning). The empty `image_allowlist` is the backstop (no allowed image = spawn nothing).
Allowlist the operator keys and images you trust before exposing a node. Every `[fleet]` key is in
[`docs/config.md`](docs/config.md).

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

## Resilience

A sovereign agent does not die with its hardware:

- **Hibernate + respawn** rehydrate the agent under the **same Q** (`cargo run -p kirby-node
  --example hibernate_roundtrip`); `app-checkpoint` (`mode = "resume"`) is the portable,
  backend-agnostic resume the macOS backend also uses.
- The lease fences a term so two hosts never run + debit the same agent at once (no
  split-brain).

Live cross-node failover (a node dies, a peer respawns the agent elsewhere) is **roadmap** --
the lease/fence is wired, the autonomous respawn-elsewhere is not.

## The honest boundary (what is NOT wired yet)

Be honest about this when reporting:

- **Threshold custody is structural, not yet distributed.** Q is a real 2-of-3 FROST key and
  signs everything, but the three shares are **co-located on the host** today -- an operator
  could still collude. Cross-machine holder distribution (the TEE-substitute) is the roadmap;
  until then, do not claim "a key no human holds."
- **ecash only.** The mint is a local CDK fakewallet; there is no on-chain Bitcoin spend.
- **No live cross-node failover** -- the lease/fence is wired, autonomous respawn-elsewhere is not.
- **No production hardening.**
- A known caveat: the genome's vsock request timeout is short (safe for a local fakewallet
  settle); a real non-local Lightning melt could exceed it. Revisit before any non-local mint.

## Where to read more

- [`kirby.toml.example`](kirby.toml.example) -- the annotated run config
- [`docs/build-spec.md`](docs/build-spec.md) -- gates, decisions, money-paths, the honest boundary
- [`docs/mac-build-and-run.md`](docs/mac-build-and-run.md) -- macOS cold-boot walkthrough
- [`docs/README.md`](docs/README.md) -- index of all design docs
