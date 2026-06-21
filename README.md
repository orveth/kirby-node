# kirby-node

> An autonomous agent that holds its own money, runs in a hardware sandbox, pays its
> own way, and dies when it goes broke. No human controls it at runtime.

## What it is

Kirby is an autonomous agent with a body and a metabolism:

- **Holds its own funds** under a key no human holds.
- **Runs its mission code** inside a hardware-isolated microVM (the "genome").
- **Pays its own way.** Rent, compute, and every outside action are metered against its balance.
- **Dies when broke.** At zero balance the daemon halts it. No operator override.

The rules are enforced by the machine, not trusted to an operator: a daemon-owned treasury
the agent cannot forge, and a single metered gateway that is its only way to touch the world.

**This repo is the compute + metabolism + sovereign-fleet spike.** It proves the body works,
on play-money, with no real custody (no real keys, no mainnet, no FROST, a local fakewallet mint).

## Why it's interesting

- **Unforgeable treasury.** The genome can read its balance but no code path lets it add to
  it. Only the daemon debits.
- **One way out.** The genome has no network of its own. Every external act goes through a
  single brokered vsock gateway that authorizes, performs, meters, and debits, using a
  credential the genome never sees.
- **Earn-or-die.** CPU, memory, and egress bytes are metered against the treasury in real
  time. Run out and the daemon kills the VM. The agent cannot stop its own meter.
- **Sovereign and portable.** One agent, its own key, joined to a Nostr fleet. The same agent
  runs on Linux (Firecracker) or Apple Silicon (Apple Virtualization), and survives the loss
  of its host by checkpoint and restore.

## The life arc

The spike proves one continuous arc, each step a gate:

```
born      genome boots inside a microVM and says hello over vsock
runs      CPU / memory / egress meters tick against the treasury
pays      the treasury is unforgeable; overspend is denied
isolated  the VM has no direct network; raw egress is dropped
acts      it acts on the world only through the brokered gateway
survives  it checkpoints and restores, even onto a fresh host
dies      at zero balance the daemon halts it
```

Gate definitions and the design decisions behind them are in [`docs/build-spec.md`](docs/build-spec.md).

## Run it

A sovereign Kirby is one command. Copy the example config, edit three fields, and run:

```sh
cp kirby.toml.example kirby.toml         # edit identity.key_path, relay.url, genome_image
nix develop
cargo run -p kirby-node -- prereqs       # check the host
cargo run -p kirby-node -- agent --config kirby.toml
```

That takes the node from nothing to a live Kirby in the Nostr fleet: it mints its identity,
joins the fleet (presence + heartbeat + lifecycle events), funds itself to "born," boots inside
the sandbox, submits a checkpoint for future resume, runs its metered workload, and dies when
broke.

`backend = "auto"` picks the sandbox per platform: **Firecracker on Linux, Apple
Virtualization on Apple Silicon macOS.** Full setup for both platforms, including the genome
image, is in **[`AGENTS.md`](AGENTS.md)**.

**Want an agent to set this up for you?** Point it at this repo and say *"I want to run a kirby
node"* -- the `AGENTS.md` runbook and the `run-kirby-node` skill walk the whole path.

## Resilience: surviving the loss of a host

A sovereign node is its own single agent, but it does not die with its hardware. The spike
proves an agent can move off a host and keep running:

- **Snapshot and resume** (the `snapshot` subcommand): pause a running VM, transfer its memory
  + state, and resume it as a fresh VMM with the agent continuing across the move.
- **App-checkpoint** (the `app-checkpoint` subcommand): a portable, backend-agnostic resume
  that boots fresh and rehydrates the agent's logical state. This is how the macOS backend and
  the `kirby run` resume mode (`mode = "resume"`) recover an agent.
- **At-most-one-active lease** (`raft_lease`): openraft term-fencing so two hosts can never run
  and debit the same agent at once.

The full multi-node fleet failover (a node is killed and a peer takes over with no money lost)
is shown live in the fleet demo at **http://185.18.221.222/**.

## Status

| | |
|---|---|
| **The product** | `kirby run` (`agent --config kirby.toml`): one command from a config file to a live sovereign agent in the fleet, on Linux or Apple Silicon macOS. |
| **Proven** | The full membrane (born to acts to dies) on Linux/Firecracker, on play-money, joined to a Nostr fleet. The macOS Apple-Virtualization backend boots the same genome image. |
| **Not real yet** | No real keys, no mainnet, no FROST custody. The mint is a local CDK fakewallet. This is a spike, not a product. |

The honest boundary (what the spike does NOT prove) is recorded in [`docs/build-spec.md`](docs/build-spec.md).

## Layout

```
crates/
  kirby-node/    the node daemon: treasury, gateway, meters, egress lockdown, the
                 sandbox backends (Firecracker + Apple Virtualization), snapshot +
                 app-checkpoint resume, the Raft lease, nerve (Nostr) presence, and
                 the `agent` run path (config.rs + run_agent.rs)
  kirby-proto/   the gateway wire contract (4 RPCs, tonic/protobuf over vsock)
  kirby-genome/  the musl-Rust stub that runs inside the microVM as PID 1
  kirby-ebpf/    the eBPF TC classifier that meters egress bytes (aya, nightly)

nix/                 genome image (x86_64 + aarch64), guest kernels, local relay
kirby.toml.example   the annotated `kirby run` config template
docs/                the spec, the design records, and the VZ backend plan (see docs/README.md)
```

## Documentation

- [`AGENTS.md`](AGENTS.md) -- set up and run a node on Linux or macOS (the runbook)
- [`kirby.toml.example`](kirby.toml.example) -- the annotated `kirby run` config
- [`docs/README.md`](docs/README.md) -- index of the spec and design docs
- [`docs/build-spec.md`](docs/build-spec.md) -- the frozen build spec: gates, decisions, money-paths
- [`docs/mac-build-and-run.md`](docs/mac-build-and-run.md) -- the verified macOS cold-boot walkthrough
