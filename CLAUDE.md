# CLAUDE.md -- orientation for a coding agent

You are an AI coding agent dropped into **kirby-node**. This file orients you fast:
what this repo is, the entrypoints, how to build/test/run, and the gotchas. Read it
before you touch anything.

- **To RUN a node or an agent end to end** (prereqs, genome image, config, both
  platforms): the full runbook is [`AGENTS.md`](AGENTS.md).
- **Every kirby.toml key**: [`docs/config.md`](docs/config.md).
- **The spec, gates, and the honest boundary**: [`docs/build-spec.md`](docs/build-spec.md).
- **What kirby is, in human words**: [`README.md`](README.md).

## What kirby is (3 lines)

Kirby is a **sovereign agent**: it holds its own Nostr identity under a 2-of-3 **FROST**
threshold key **Q**, runs its mission inside a hardware-isolated microVM (the "genome"),
pays for its own compute in ecash against a daemon-owned treasury, and **dies when it goes
broke**. The rules are enforced by the machine, not trusted to an operator. It is a
play-money spike (ecash only, no on-chain Bitcoin); the FROST custody is real, but today the
three key-shares are co-located on one host (cross-machine distribution is the roadmap).

## node != agent (read this first -- it is the model)

The single most important distinction in this repo:

- A **NODE** is a persistent host that joins the fleet and can hold agents. You run one with
  **`kirby-node fleet`**. It beacons **node presence** (event kind `10100`) under a durable
  node key and runs the spawn control plane (listens for kind-`31003` spawn requests, drives
  kind-`31002` leases).
- An **AGENT** is one sovereign Kirby: its own FROST **Q**, its own treasury, its own life.
  It surfaces as a **`9100`** lifecycle log (born/died) plus live **`31000`** agent-state,
  all signed under Q. An agent does **NOT** beacon `10100` node presence.

Consequence that bites: **`kirby-node presence` reads NODES (`10100`), not bare agents.** A
lone `kirby-node agent` will not appear there -- you verify it from its boot logs and lifecycle
events (see "What success looks like"). Only a `kirby-node fleet` node shows up in `presence`.

## The two entrypoints

| You want to... | Command | What it does |
|---|---|---|
| **Run one sovereign agent** (the fast smoke: watch it be born, boot, meter, and die) | `kirby-node agent --config kirby.toml` | Loads the config, provisions/reloads its FROST Q, joins the fleet, boots the genome, runs the metered workload, dies when broke. This is also the fleet's per-tenant child process. |
| **Run a node that joins the network and hosts agents** (the fleet model) | `kirby-node fleet --config kirby.toml` | Beacons node presence (`10100`), hosts any static `[[fleet.tenants]]` as child agents, and runs the spawn control plane so operators can spawn agents onto it remotely. |
| **Ask a running node to spawn an agent** (remote, operator-triggered) | `kirby-node spawn-request --relay <url> --agent-id <id> --image-ref <ref> ...` | Signs and publishes a kind-`31003` spawn request; an allowlisting node with the image + capacity claims and launches it. |

Run `kirby-node agent` first to see the whole loop on one screen: an agent comes alive (born and
boots in seconds) and runs its metered life until it dies broke or hits the safety ceiling. But
**`kirby-node fleet` is what you actually run to join the network and host agents** -- it is the
deployment, not the demo. Agents are created *on top of* a fleet node
(statically as tenants, or remotely via `spawn-request` / the UI). `kirby-node agent` is the taste
and the per-tenant building block; `kirby-node fleet` is the product.

## Full subcommand map

`kirby-node <subcommand>` (run `--help` on any for exact flags):

| Subcommand | Use it to | Notes |
|---|---|---|
| `agent --config kirby.toml` | Run a single sovereign agent. **The keystone.** | `--no-frost` drops to a plain node key (dev/test only). |
| `fleet --config kirby.toml` | Run a fleet node (presence + tenants + spawn control plane). | `--node-id <u64>` is the lease id (distinct from the config's string `node_id`). |
| `spawn-request --relay <url> ...` | Operator trigger: publish a kind-`31003` spawn request. | Signs with the operator key; the target node must allowlist that key + the image. |
| `presence --relay-url <url>` | Read the live fleet (`10100` node beacons): npub, node_id, age, ALIVE/STALE. | `--watch` streams; `--json` for machine output. Shows NODES, not bare agents. |
| `prereqs` | Check the host can run kirby (Linux/Firecracker or macOS/VZ). | `--json` for machine output. Exits non-zero on a failed hard check. Run it first. |
| `boot` | One-shot demo: boot the genome VM and prove the vsock round-trip (gate G1). | Self-contained; halts after. For manual VM inspection. |
| `app-checkpoint` | Two-node demo: prove the portable checkpoint handoff (Linux<->macOS resume). | Demo, not a run path. |
| `run` | **LEGACY boot daemon, not the agent run.** | Constructs the gateway, logs ready, and exits (or `--serve-vsock` to serve; `--presence-only` to beacon `10100` with no VM). **Do not point a teammate at `kirby-node run`** when they mean to run an agent -- that is `agent`. |
| `ebpf-egress` | INTERNAL. The privileged eBPF egress meter the daemon runs via sudo. | Never invoke directly. |

> **Naming trap:** older docs and a few code comments call the `agent` keystone "`kirby run`."
> The actual command is **`kirby-node agent`**. There is also a separate, legacy `kirby-node run`
> subcommand (the boot demo above). They are different. In your own output, always write the
> explicit `kirby-node agent ...` / `kirby-node fleet ...`.

## Repo layout (where code lives)

```
crates/
  kirby-node/    THE node daemon + binary. Everything host-side:
                 src/main.rs          the CLI (the subcommand definitions above)
                 src/config.rs        KirbyConfig -- every kirby.toml key (see docs/config.md)
                 src/run_agent.rs     the `agent` keystone: identity -> boot -> meter -> die
                 src/boot.rs          the VM boot path + state_root resolution
                 src/fleet*.rs        the fleet supervisor, allocator, tenant launcher
                 src/spawn.rs         the kind-31003 spawn control plane + ledger
                 src/nerve.rs         Nostr presence / lifecycle / agent-state publishing
                 src/relay_lease.rs   the kind-31002 failover lease
  kirby-custody/ the FROST 2-of-3 custody crate: keygen, the quorum signer + guardian
                 membrane, keyset persistence, the cross-machine cosign seam (roadmap)
  kirby-proto/   the gateway wire contract (tonic/protobuf over vsock) + the event-kind
                 constants (src/lib.rs: KIND_KIRBY_PRESENCE=10100, _LIFECYCLE=9100, etc.)
  kirby-genome/  the musl-Rust agent that runs INSIDE the microVM as PID 1
  kirby-ebpf/    the eBPF TC classifier that meters egress bytes (aya, nightly toolchain)

nix/                 genome image (x86_64 + aarch64), guest kernels, the local relay
kirby.toml.example   the annotated run config (copy to kirby.toml)
docs/                the spec + design records (start at docs/README.md)
```

## Build, test, lint (the dev loop)

Everything runs inside the Nix dev shell, which pins the toolchain and tools:

```sh
nix develop                                   # rust 1.90 stable, protoc, firecracker+jailer
                                              # (Linux), nftables, the local relay, nightly
                                              # eBPF cargo (via $KIRBY_EBPF_CARGO)
cargo build --workspace
cargo test  --workspace                       # the integration suite is the source of truth
cargo clippy --workspace -- -D warnings       # CI gates on this; keep it clean
```

**NEVER run `cargo fmt` across the workspace.** `main` is not rustfmt-clean, so a workspace
`cargo fmt` repaints ~71 unrelated files and makes your diff unreviewable. Write your edits in
the surrounding fmt style by hand, and verify with **clippy + tests**, not fmt. If you ran it
by reflex: `git checkout HEAD -- .` and re-apply your change by hand.

## Quickstart: taste one agent + what success looks like

This runs ONE agent so you can watch the loop end to end (born -> boot -> meter -> die). It is
the fastest way to understand kirby and to smoke-test your host. To then run a node that joins the
network and hosts agents -- the actual deployment -- see "Run a fleet node" below. The full,
platform-aware version (genome image, prereqs detail, macOS) is in [`AGENTS.md`](AGENTS.md). The
short version on Linux:

```sh
nix develop
cargo run -p kirby-node -- prereqs                              # must pass first
nix build --no-link --print-out-paths .#genome-image           # build the genome image
cp kirby.toml.example kirby.toml                                # edit genome_image, [identity] key_path, [relay] url
nix run .#relay &                                               # a local test relay at ws://127.0.0.1:7777
cargo run -p kirby-node -- agent --config kirby.toml
```

**What success looks like** -- watch the logs for, in order:

```
loaded kirby run config
kirby run: starting the sovereign agent
agent identity ready (beacons + voice sign under this key)   (npub=...)
booting genome guest through the sandbox backend
genome boot hello received (G1 round-trip proven)            <- reached Running
published 9100 lifecycle event (the signed birth/death log)  (event=born)
```

and the final line printed to **stdout**:

```
KIRBY-RUN mode=Bootstrap backend=... npub=... reached_running=true born=true died=true ... end=BudgetExhausted
```

The process **exits 0 iff it reached Running.** Dying broke (`end=BudgetExhausted`) is the
*normal* terminal state and still exits 0. A non-zero exit means it never booted -- read the
error. (With the default funding and meter rates an agent usually halts at a safety ceiling --
currently a hardcoded 600s, a config knob is in flight -- rather than actually running out of sats.)

**Want to watch it *think*?** The default `app-checkpoint` workload boots and meters but does not
run the agentic loop. Set `workload = "capable"` with a `[brain]` backend (`stub` for a free
simulated think/act loop, or `routstr` / `routstr_key` for real inference) -- see
[`docs/config.md`](docs/config.md).

## Run a fleet node (the deployment)

The fleet node is what actually joins the network. It beacons node presence, hosts agents, and
runs the spawn control plane:

```sh
cargo run -p kirby-node -- fleet --config kirby.toml
```

With the bare `kirby.toml`, that node joins the fleet and listens, but hosts no agents yet. To put
agents on it, either declare them statically:

```toml
[[fleet.tenants]]
agent_id = "agent-a"
initial_sats = 50000
```

or spawn one remotely against the running node:

```sh
cargo run -p kirby-node -- spawn-request --relay <url> --agent-id agent-b --image-ref <ref>
```

The spawn control plane is gated by `[fleet.spawn]`. **An empty `operators` allowlist means ANY
signer may spawn an agent on your node** -- a known MVP DoS vector. The empty `image_allowlist`
default is the backstop: with no allowed image, the node spawns nothing. Allowlist the operator
keys (and images) you trust before exposing a node. See [`docs/config.md`](docs/config.md).

Verify the node joined (a node DOES beacon presence, unlike a bare agent):
`cargo run -p kirby-node -- presence --relay-url <url>` -- it should list the node ALIVE.

## Gotchas (the things that actually bite)

- **Linux jailer privilege.** The daemon launches the Firecracker jailer through *passwordless*
  `sudo` (it tries `/run/wrappers/bin/sudo` then `/usr/bin/sudo`, checks `sudo -n true`). A sudo
  password prompt fails the prereqs gate. Fix: a passwordless sudoers rule for the jailer, or run
  as root, or grant `CAP_SYS_ADMIN`. This is the check that usually fails first.
- **Linux kernel bits.** Needs `/dev/kvm` (group `kvm`) and `/dev/vhost-vsock`
  (`modprobe vhost_vsock`), cgroup v2 with `cpu`+`memory`, and `nft`.
- **Genome image arch must match the backend.** Firecracker (Linux) wants the x86_64
  `.#genome-image`; VZ (Apple Silicon) wants `.#genome-image-aarch64`, which is a *Linux*
  derivation you cannot build on the Mac without a Linux builder. Mismatched arch fails at config
  validation.
- **Relay URL.** `[relay] url` must start `ws://` or `wss://`. For local testing, `nix run .#relay`
  serves `ws://127.0.0.1:7777` (NIP-42 off, arbitrary kinds accepted). The shared fleet relay is
  in `kirby.toml.example`.
- **Where state lives.** The durable root is the top-level `state_root` key (or `$KIRBY_STATE_ROOT`).
  Unset, it resolves to `$XDG_DATA_HOME/kirby`, else `$HOME/.local/share/kirby` -- **never** a temp
  dir. (`[identity] treasury_dir` is a separate per-config override most users leave unset; when
  unset it falls back to the key_path's parent, not to `state_root`.)
- **Fleet spawn is open by default.** In `[fleet.spawn]`, an **empty `operators` allowlist means
  ANY signer may spawn an agent on your node** (a known MVP DoS vector -- it logs a loud warning).
  An empty `image_allowlist` means the node will spawn nothing. There is **no `enabled` flag**; the
  control plane runs whenever `kirby-node fleet` runs. See [`docs/config.md`](docs/config.md).
- **The genome's vsock timeout is short.** Safe for the local fakewallet settle; a real non-local
  Lightning melt could exceed it. Revisit before any non-local mint.

## Honest boundary (do not overclaim when you report)

- **FROST custody is structural, not yet distributed.** Q is a real 2-of-3 key and signs
  everything, but the three shares are co-located on the host today -- an operator could still
  collude. Do not claim "a key no human holds" until cross-machine holder distribution lands.
- **ecash only.** The mint is a local CDK fakewallet; there is no on-chain Bitcoin spend.
- **No live cross-node failover yet.** The lease/fence is wired; autonomous respawn-elsewhere is
  roadmap.
- **No production hardening.**
