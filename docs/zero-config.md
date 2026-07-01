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
| Genome image | the `./result` from `nix build .#genome-image` (else `$KIRBY_GENOME_IMAGE`); resolved + arch-checked at boot | env `KIRBY_GENOME_IMAGE`, or `[genome_image]` |
| Failover (G-4) | armed (scan 5s / grace 30s) | always on under `fleet` |
| FROST | node identity auto-provisioned (2-of-3, co-located) | `--no-frost` (dev only) |
| Spawn control-plane | on; **operators OPEN** (any signer, logs a loud warning), `image_allowlist = ["kirby-genome"]` (the blessed genome **admission token** — see note) | `[fleet.spawn] operators` / `image_allowlist` |
| Static agents | none (`fleet.tenants` empty) -- agents arrive via spawn | `[[fleet.tenants]]` |
| Agent brain (the spawned-tenant template) | `workload = capable`, `brain.backend = routstr_key`, `node_url = https://api.routstr.com`, `model = granite-4.1-8b`; `api_key_path` **empty** (the funding key is provided at spawn, never baked) | `[brain]` |
| Compute rent | `mem_sats_per_mib_sec = 0` -- agents die only from real inference spend, not a synthetic compute meter | `[meter]` |
| Run ceiling | lifted for fleet tenants (no 600s wall) | `max_run_secs` |
| Stale spawn requests | dropped after 1 hour (`request_max_age_secs = 3600`) | `[fleet.spawn]` |

**Overriding.** The table above is what a bare node (no config file) synthesizes.
To tweak one thing and KEEP the zero-config behavior, set an env var
(`KIRBY_RELAY_URL`, `KIRBY_GENOME_IMAGE`). Dropping a `kirby.toml` (or passing
`--config`) switches you to **explicit configuration**: each key then falls back
to its own standard default (see [config.md](./config.md)), *not* the zero-config
template values above -- so set the keys you want. This split is deliberate: it
keeps every existing config file byte-identical.

**One prerequisite: build the genome.** There is no zero-*build* genome image.
Once, run `nix build .#genome-image` (x86_64 / Firecracker) or
`.#genome-image-aarch64` (aarch64 / VZ); it writes the arch-appropriate image to
`./result`, which the default points at. Or set `$KIRBY_GENOME_IMAGE` to an image
dir. A bare fleet host with no tenants never boots a genome, so it comes up
without one; an agent that boots (a spawn) resolves + arch-checks the image then,
and fails with a clear, actionable message if it is missing.

**`image_ref` is an admission token, not a path.** `image_allowlist` and
`--image-ref` are matched by exact string; the node always boots its OWN
configured `genome_image` (the child's config is 100% host-derived). So
`"kirby-genome"` is just the label a spawn request must name -- not a file.

## See it think: fund an agent, then spawn it

The node holds no money, so a spawned agent needs a **funded Routstr key** to
think. No money, no cognition -- by design; it *is* the die-when-broke rule:

- **No key** (`api_key_path` empty, the zero-config template's default) -- the
  agent FAILS validation and never starts (fail-closed).
- **A funded key** -- the agent boots, thinks against `https://api.routstr.com`,
  and dies when the balance runs out.
- **An unfunded / spent key** -- the agent boots and dies-when-broke on its very
  first thought.

**Fund one today** (per-agent born-at-spawn funding will automate this -- until
then the key is node-shared: tenants inherit the node's `[brain] api_key_path`):

```sh
cargo run -p kirby-node --example routstr_create_key   # pays an LN invoice, prints an sk-...
```

Write the printed `sk-...` to a file, point the node's `[brain] api_key_path` at
it (this means running with a small `kirby.toml`, not the bare zero-config node),
then spawn:

```sh
kirby-node spawn-request \
  --relay ws://185.18.221.222:7777 \
  --agent-id my-first-agent \
  --image-ref kirby-genome
```

The node provisions the agent a sovereign FROST identity + treasury and launches
it. Watch it come alive on the lease (kind:31002), then its birth + state events
(9100 / 31000) -- full walkthrough in [spawn-over-nostr.md](./spawn-over-nostr.md).
It runs until its inference money is gone, then dies.

## Security note: a zero-config node is open

A bare node accepts spawn requests from **any signer** (empty `operators` =
OPEN, the MVP default; it logs a loud warning). The backstop is that it will
only admit the one blessed image token (`image_allowlist = ["kirby-genome"]`),
rate-limited (10 / 60s). To lock it down before exposing it, set `[fleet.spawn]
operators` to the pubkeys you trust. See [config.md](./config.md).

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
