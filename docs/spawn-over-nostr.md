# Spawn an agent over NOSTR

Spawn a sovereign Kirby agent onto a running fleet by publishing one signed
NOSTR event. No SSH, no shared filesystem, no RPC -- the fleet's spawn
control-plane listens on the relay and does the rest.

The shape of it:

```
operator signs a kind:31003 event  -->  publishes to the fleet relay
   -->  every `kirby-node fleet` node's control-plane receives it
   -->  admission battery (auth, allowlist, funding, fence, idempotency)
   -->  on accept: provision a sovereign 2-of-3 FROST identity + treasury,
        launch a child `kirby-node agent` microVM
   -->  the node publishes a kind:31002 lease -- that lease IS the ack.
```

There is no dedicated "spawn accepted" event. You confirm success by watching
the lease (and then the agent's own birth events). See
[Confirming a spawn](#confirming-a-spawn).

## Prerequisites

- A running `kirby-node fleet` node (NOT a single `kirby-node agent` -- only
  `fleet` runs the spawn control-plane). See [Running a node](../CLAUDE.md).
- That node and you share a relay (the node subscribes to kind:31003 there).
- The node must **allowlist the image** you want to run (`[fleet.spawn]
  image_allowlist`), and must **authorize your operator key** (`[fleet.spawn]
  operators`) -- unless it is running OPEN (empty `operators`, the MVP default;
  see [Footguns](#footguns)).

## The fast path: `spawn-request`

The repo ships a headless operator client. Use it as the canonical example:

```
kirby-node spawn-request \
  --relay ws://your-fleet-relay:7777 \
  --agent-id my-first-agent \
  --image-ref <ref-the-node-allowlists> \
  --seed-sats 50000 \
  --operator-key ./operator.nostr.key
```

Flags (`run_spawn_request_cmd`, main.rs):

| Flag | Required | Default | Meaning |
|---|---|---|---|
| `--relay` | yes | -- | The fleet's shared relay websocket. |
| `--agent-id` | yes | -- | Requested agent id. Charset `[A-Za-z0-9._-]`, <= 64 chars (it feeds filesystem paths + host interface names). Becomes the lease key + `d` tag. |
| `--image-ref` | yes | -- | Which pre-staged genome image to run. MUST match an entry in the node's `image_allowlist`. |
| `--seed-sats` | no | 50000 | Declarative funding for the new agent's treasury. A number, NOT a bearer token. |
| `--operator-key` | no | `operator.nostr.key` | Your signing key (nsec or hex). Minted 0600 on first use. |
| `--genome-config` | no | -- | Optional JSON. Accepted and size-bounded but currently INERT (see Footguns). |

On first run it mints a stable operator key and **prints the operator pubkey
(hex + npub)** -- that hex is exactly what a locked-down node lists in
`[fleet.spawn] operators`. Then it signs, publishes, and prints the event id.

The kirby-ui browser client publishes the identical event from a browser
signer; this CLI is the headless path.

## The request format (kind:31003)

For a hand-rolled client. The entire payload lives in the event **content** as
a JSON object; authorization is off the event signature, not a body field.

- **kind**: `31003`
- **content** (JSON):

```json
{
  "agent_id": "my-first-agent",
  "image_ref": "<ref-the-node-allowlists>",
  "funding": { "seed_sats": 50000 },
  "genome_config": null,
  "requester_pubkey": ""
}
```

| Field | Required | Meaning |
|---|---|---|
| `agent_id` | yes | Agent identity label; validated charset/length. |
| `image_ref` | yes | Genome image; checked against the node's `image_allowlist`. |
| `funding.seed_sats` | yes | Declarative seed sats. Never an ecash token (a token in a plaintext relay event would be redeemable by anyone scraping the relay). |
| `genome_config` | no | Non-secret task/brain descriptor. Accepted, size-bounded, and currently IGNORED (the child's config is 100% host-derived). |
| `requester_pubkey` | no | Redundant with the signed `event.pubkey`. If non-empty it MUST equal the signer or the event is rejected. |

- **tags**: `[["d","<agent_id>"], ["t","kirby"], ["a","<agent_id>"]]`. The `d`
  tag makes the request addressable/replaceable (and is why the relay retains
  it -- see the stale-ghost footgun).
- **content size cap**: 8 KiB, enforced before parsing.
- signed with your operator key (BIP-340), valid NIP-01 id, `created_at` = now
  (only matters if the node set `request_max_age_secs`).

**Operator identity = the event signer.** There is no "operator" field that
grants authority; the signature over the event proves which key requested the
spawn, and the node authorizes off `event.pubkey`.

## How a request is decided (the admission battery)

The node runs these gates in order. Anything that fails is logged and dropped
-- a spawn can be silently refused, so know the gates:

1. **kind** is 31003.
2. **signature + id** verify (BIP-340 + NIP-01 id).
3. **content** <= 8 KiB.
4. **content** parses as JSON into the request struct.
5. **agent_id** passes charset/length.
6. **requester_pubkey** (if present) equals the signer.
7. **freshness** -- only if the node set `[fleet.spawn] request_max_age_secs`
   (OFF by default): drop requests older than that. Off => a retained request
   is honored at any age.
8. **image allowlist** -- `image_ref` must be in `image_allowlist`.
   **Empty allowlist => every spawn is rejected** (default-deny backstop).
9. **operator authz + rate limit** -- if `operators` is non-empty, the signer
   must be listed. **Empty `operators` => OPEN: any signer may spawn.** A fixed
   per-key rate limit (default 10 per 60s) ALWAYS applies, open or locked.
10. **funding** -- `0 < seed_sats <= max_seed_sats` (default cap 1,000,000).
11. **capacity** -- node is below `max_tenants` (default 16).
12. **cross-node fence** -- if a *fresh* lease (within the 30s TTL) for this
    `agent_id` names another node, back off (prevents double-spawn when two
    nodes both received the retained request). A stale lease (holder died)
    does not count -- respawn is allowed.
13. **idempotency ledger** -- a durable spawned-set with atomic
    reserve-then-launch. An `agent_id` already launched is not resurrected.

## What the node does on accept

1. Allocate a restart-safe tenant slot (guest CID / gateway port / instance id).
2. Open a per-agent treasury (its own store, exclusive lock).
3. **Provision a sovereign 2-of-3 FROST identity Q** for the agent (the
   supervisor is the trusted dealer; idempotent -- a restart reloads the same
   Q). The agent's outward voice signs under this key. `frost_npub` is the
   agent's sovereign npub.
4. **Claim the lease (kind:31002) at term 1** -- FROST-signed under the agent's
   Q, addressable by `["d", agent_id]`, then heartbeated every ~10s.
5. Read-after-write fence: re-read the surviving lease over a real relay
   round-trip; launch only if this node is the survivor at the claimed term
   (else fail closed and retry next tick).
6. Launch the child `kirby-node agent --config <derived>` in a microVM. The
   child runs the ordinary single-agent path verbatim.

The child's config is derived host-side (`derive_tenant_config`): it clones the
node's base config and rewrites `agent_id`, `node_id`, `funding.initial_sats`
(= your `seed_sats`), the FROST keystore (the provisioned Q), and per-agent
key/treasury/wallet paths. **Your `genome_config` is not read here** -- to
change a spawned agent's brain/workload you configure the *node's* base config,
not the request.

## Confirming a spawn

There is no spawn-ack event. Confirm in this order:

1. **kind:31002 lease**, filtered on `#d = <agent_id>`. A fresh lease naming the
   hosting node at term 1 appears within seconds -- this is the primary "it
   worked" signal.
2. **kind:9100 lifecycle** `born`, tagged `["a", <agent_id>]`, once the child
   funds and boots (`{agent_id, event:"born", treasury_sats, reason:"funded"}`).
3. **kind:31000 agent-state**, the live agent face (`treasury_sats`,
   `runway_secs`, `lifecycle`, ...), addressable and updated as it runs.

Note: a spawned agent is NOT a node -- it does **not** beacon kind:10100
presence. Only `kirby-node fleet` nodes beacon 10100. (kind:31001 WAKE is not
used by the spawn path.)

## Footguns

- **Empty `operators` = OPEN to anyone (DoS vector).** The MVP default. The
  node logs a loud startup warning but still accepts spawns from any signer.
  Only the rate limit (10/60s/key) and the default-deny `image_allowlist` stand
  between an open node and unbounded launches. Set `operators` (and
  `image_allowlist`) before exposing a node.
- **Empty `image_allowlist` = spawn NOTHING.** A fresh fleet node joins and
  listens but silently rejects every spawn (`UnknownImage`). Easy to mistake
  for "broken" -- allowlist your image ref.
- **No `enabled` flag.** The control-plane runs whenever `kirby-node fleet`
  runs; gate it via `operators` / `image_allowlist`, not a toggle.
- **31003 is addressable, so the relay RETAINS it -- stale-ghost respawns.**
  After an agent is reaped, a long-parked retained request can redeliver and
  respawn a fresh, fund-burning agent. Mitigation is `request_max_age_secs`,
  which is OFF by default; long-lived nodes should set it (e.g. 3600).
- **`genome_config` is accepted but inert.** Sending task/brain/budget in the
  request is silently ignored; the child's behavior comes entirely from the
  node's base config.
- **Funding is declarative, never a bearer token.** `seed_sats` is a number the
  node's funder clamps; real deposit-redeem is roadmap.
- **Cross-machine boundary.** A node can only claim/relaunch an agent whose
  FROST keystore it holds. Same-host spawn and failover work; cross-machine
  takeover is skipped until distributed shares land.

## See also

- [CLAUDE.md](../CLAUDE.md) -- run a node, node != agent, the "kirby run" trap.
- [config.md](./config.md) -- every `kirby.toml` key, including `[fleet.spawn]`.
