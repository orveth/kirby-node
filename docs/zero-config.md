# Zero-config: bare `kirby-node` just works

Run `kirby-node` with no arguments and no config file. You get a **ready fleet
node** -- joined to the network, beaconing presence, listening to host agents --
with zero setup.

```sh
kirby-node        # no subcommand, no --config: a full fleet node comes up
```

## The model: the node holds no money; agents do

A bare node is **pure infrastructure**. It has **no money** and runs **no
agent** by itself. It:

- joins the fleet relay and beacons node presence (kind:10100),
- runs the spawn control-plane (listens for kind:31003 spawn requests),
- arms G-4 failover,
- provisions its own node identity (a 2-of-3 FROST key, co-located today).

To see an agent **think**, you **spawn** one onto the node. The spawner funds it
at spawn-time; the agent is born with money, thinks with real inference, and
**dies when that money runs out**. Money lives with the agent -- never baked
into the node or the binary.

```
bare node  = ready infra, no money, no agent
spawn      = a funded agent lands on the node, thinks, and lives until broke
```

See [Spawn an agent over NOSTR](./spawn-over-nostr.md).

## What a bare `kirby-node` brings up (the baked defaults)

| Concern | Zero-config default | Override |
|---|---|---|
| Mode | `fleet` (bare `kirby-node` == `kirby-node fleet`) | pass a subcommand |
| Config | synthesized in memory when no `kirby.toml` is present (logs `using zero-config defaults`) | drop a `kirby.toml`, or pass `--config` |
| Relay | `ws://185.18.221.222:7777` | env `KIRBY_RELAY_URL`, or `[relay] url` |
| Genome image | flake-resolved for the host arch | `[genome_image]` |
| Failover (G-4) | armed (scan 5s / grace 30s) | always on under `fleet` |
| FROST | node identity auto-provisioned (2-of-3, co-located) | `--no-frost` (dev only) |
| Spawn control-plane | on; **operators OPEN** (any signer, logs a loud warning), `image_allowlist` = the blessed default genome only | `[fleet.spawn] operators` / `image_allowlist` |
| Static agents | none (`fleet.tenants` empty) -- agents arrive via spawn | `[[fleet.tenants]]` |
| Agent brain (the spawned-tenant template) | `workload = capable`, `brain.backend = routstr_key`, `node_url = https://api.routstr.com` | `[brain]` |
| Compute rent | `mem_sats_per_mib_sec = 0` -- agents die only from real inference spend, not a synthetic compute meter | `[meter]` |
| Run ceiling | lifted for fleet tenants (no 600s wall) | `max_run_secs` |
| Stale spawn requests | dropped after 1 hour (`request_max_age_secs = 3600`) | `[fleet.spawn]` |

Everything is overridable: set an env var, or drop a `kirby.toml` with only the
keys you want to change -- unset keys keep the zero-config default.

## See it think: spawn a funded agent

The node itself never thinks. Put a funded agent on it:

```sh
kirby-node spawn-request \
  --relay ws://185.18.221.222:7777 \
  --agent-id my-first-agent \
  --image-ref <the-node's-blessed-genome>
```

The spawner funds the agent (a prepaid Routstr key today; NIP-60 ecash seeding
as it lands), the node provisions it a sovereign FROST identity + treasury and
launches it, and it starts thinking against `https://api.routstr.com`. Watch it
come alive on the lease (kind:31002) then its birth + state events (9100 / 31000)
-- full walkthrough in [spawn-over-nostr.md](./spawn-over-nostr.md). It runs
until its inference money is gone, then dies.

## Security note: a zero-config node is open

A bare node accepts spawn requests from **any signer** (empty `operators` =
OPEN, the MVP default; it logs a loud warning). The backstop is that it will
only spawn the **blessed default genome** (`image_allowlist`), rate-limited. To
lock it down before exposing it, set `[fleet.spawn] operators` to the pubkeys
you trust. See [config.md](./config.md).

## Why the node holds no money

Baking money into the node or the binary would make every node a custodian and
every checkout a wallet. Money is per-agent and arrives at spawn: the spawner
funds the agent, so a node is safe to run anywhere with zero secrets, and an
agent's life is bounded by the money it was born with. This is the model, not a
limitation -- sovereignty lives with the agent.

## See also

- [spawn-over-nostr.md](./spawn-over-nostr.md) -- put a funded agent on the node.
- [config.md](./config.md) -- every key you can override.
- [CLAUDE.md](../CLAUDE.md) -- node != agent, the "kirby run" trap, gotchas.
