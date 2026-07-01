# kirby-node

> An autonomous agent that holds its own identity under a threshold key no single
> machine can wield alone, runs inside a hardware sandbox, pays its own way in ecash,
> and dies when it goes broke. No human controls it at runtime.

## What it is

Kirby is a **sovereign** agent -- it owns itself:

- **Holds its own identity under a 2-of-3 FROST threshold key.** Each agent is born
  with its own quorum key **Q** at spawn and signs its *entire* public voice through a
  live in-process quorum. No single signing key exists to lift.
- **Respawns as itself.** After death or hibernation the agent comes back under the
  **same Q** -- same npub, same identity, continuous life.
- **Runs its mission inside a hardware-isolated microVM** (the "genome"), reachable only
  through a single brokered gateway.
- **Pays its own way in ecash.** Compute, memory, and every outside action are metered
  against its balance in real time.
- **Dies when broke.** At zero balance the daemon halts it. No operator override.

The rules are enforced by the machine, not trusted to an operator: a daemon-owned
treasury the agent cannot forge, a single metered gateway that is its only way to touch
the world, and a threshold identity key that is never assembled in one place.

## The sovereignty story -- stated honestly

This is the scariest sentence in the repo, so it earns exactly what's wired and no more:

> Kirby agents hold their Nostr identity under a **2-of-3 FROST threshold key** and sign
> their entire public voice through a **live in-process quorum** -- no single signing key
> exists. Each agent is **born with its own sovereign key Q** at spawn and **respawns as
> the same Q** after death or hibernation. **Today the three key-shares are co-located on
> the host that runs the agent**: the threshold *structure* is real and live, but the
> *physical distribution of holders across machines* is the roadmap (the transport seam
> exists; the distribution does not). The agent's metabolism is **ecash only -- there is no
> on-chain Bitcoin spend.**

What we deliberately do **not** claim yet:

- ❌ *"a key no human holds"* -- false while the shares are co-located; the operator could
  still collude. We earn that sentence at **cross-machine holder distribution**, not before.
- ❌ *self-custodying Bitcoin* -- there is no on-chain path; the metabolism is ecash.

**Why threshold custody is the point.** A real TEE keeps the host from reading a secret in
RAM. Distributed FROST is the **substitute for a TEE**: once the three shares live on
*different* machines, a host reading its own VM's RAM only ever sees **one** share, which
is useless alone. That is how an agent becomes un-ruggable without trusting any single box.
The threshold structure is built today; distributing the holders is the headline of the
roadmap below.

## The life arc

```
born      the agent is dealt its own 2-of-3 FROST key Q and boots inside a microVM
signs     every public event (presence, lifecycle, its own notes) is quorum-signed by Q
runs      CPU / memory / egress meter against an unforgeable ecash treasury
isolated  the VM has no direct network; raw egress is dropped
acts      it touches the world only through the brokered gateway
survives  it hibernates and respawns -- as the SAME Q
dies      at zero balance the daemon halts it
```

Gate definitions and the design decisions behind them are in [`docs/build-spec.md`](docs/build-spec.md).

## Run it

A sovereign Kirby is one command. By default it **provisions its own FROST keystore** on
first boot and signs under Q; on every later boot it reloads the *same* Q (idempotent and
fail-closed -- it never silently mints a new identity).

```sh
cp kirby.toml.example kirby.toml         # edit identity.key_path, relay.url, genome_image
nix develop
cargo run -p kirby-node -- prereqs       # check the host
cargo run -p kirby-node -- agent --config kirby.toml
```

That takes you from nothing to a live Kirby in the Nostr fleet: it is dealt its own sovereign Q,
joins the fleet (a quorum-signed lifecycle + live agent-state), funds itself to "born," boots
inside the sandbox, runs its metered workload, and dies when broke. This command runs ONE agent;
to run a **node** that joins the network and hosts agents, use `kirby-node fleet --config
kirby.toml` (see [`AGENTS.md`](AGENTS.md)). The model: a node joins the network, agents run on top.

`--no-frost` drops to a plain node-key signing path -- a **dev/test fast-path only**, not
the sovereign default.

`backend = "auto"` picks the sandbox per platform: **Firecracker on Linux, Apple
Virtualization on Apple Silicon macOS.** Full setup for both platforms, including the
genome image, is in **[`AGENTS.md`](AGENTS.md)**.

## Resilience: surviving the loss of a host

An agent does not die with its hardware:

- **Hibernate + respawn** -- it seals its state, dies, and comes back as the **same Q**
  (`cargo run -p kirby-node --example hibernate_roundtrip`).
- **App-checkpoint** -- a portable, backend-agnostic resume that boots fresh and rehydrates
  the agent's logical state (`mode = "resume"`; also how the macOS backend recovers).
- **At-most-one-active lease** -- openraft term-fencing so two hosts can never run and debit
  the same agent at once (the no-split-brain safety guarantee).

Live cross-node failover (a node dies and a peer respawns the agent elsewhere) is
**roadmap** -- the lease/fence is wired, the autonomous respawn-elsewhere is not.

## Roadmap -- what makes it fully sovereign

In dependency order:

1. **Cross-machine holder distribution** -- move the three FROST shares onto different
   machines so no single host can wield Q. This is the TEE-substitute becoming real, and
   the headline: it's what earns *"a key no human holds."*
2. **P2PK-locked ecash** -- lock the agent's Cashu tokens to its FROST Q (NUT-11) so
   *spending* also requires a quorum signature. Without it, ecash is bearer bytes a
   malicious host could copy and redeem; with it, the **money** is as sovereign as the
   identity.
3. **Wake-on-inbound + VPS provisioning** -- the agent wakes on a job and rents its own
   body (compute), instead of being purely host-launched.
4. **Live cross-node failover** and **multiple agents per node by available compute.**

## Layout

```
crates/
  kirby-node/    the node daemon: treasury, gateway, meters, egress lockdown, the
                 sandbox backends (Firecracker + Apple Virtualization), snapshot +
                 app-checkpoint resume, the lease, nerve (Nostr) presence, the
                 per-agent FROST keystore + quorum-signed beacons, the fleet
                 supervisor, and the `agent` run path (config.rs + run_agent.rs)
  kirby-custody/ the FROST custody crate: 2-of-3 threshold keygen, the quorum signer +
                 guardian validation membrane, keyset persistence, the cross-machine
                 cosign seam (roadmap), and key resharing
  kirby-proto/   the gateway wire contract (tonic/protobuf over vsock)
  kirby-genome/  the musl-Rust agent that runs inside the microVM as PID 1
  kirby-ebpf/    the eBPF TC classifier that meters egress bytes (aya, nightly)

nix/                 genome image (x86_64 + aarch64), guest kernels, local relay
kirby.toml.example   the annotated run config template
docs/                the spec, the design records, and the VZ backend plan (see docs/README.md)
```

## Documentation

- [`CLAUDE.md`](CLAUDE.md) -- orientation for a coding agent: the code map, the build/test loop, and
  the full subcommand map (start here if you are working *in* the repo)
- [`AGENTS.md`](AGENTS.md) -- set up and run a node on Linux or macOS (the runbook)
- [`kirby.toml.example`](kirby.toml.example) -- the annotated run config
- [`docs/config.md`](docs/config.md) -- every kirby.toml key, default, and which entrypoint reads it
- [`docs/README.md`](docs/README.md) -- index of the spec and design docs
- [`docs/build-spec.md`](docs/build-spec.md) -- the build spec: gates, decisions, money-paths
- [`docs/mac-build-and-run.md`](docs/mac-build-and-run.md) -- the verified macOS cold-boot walkthrough
