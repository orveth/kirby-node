# kirby.toml -- the full config reference

One config file drives both run entrypoints: `kirby-node agent --config kirby.toml` (one
sovereign agent) and `kirby-node fleet --config kirby.toml` (a node that hosts agents). The
annotated starter is [`../kirby.toml.example`](../kirby.toml.example); it shows only the minimal
single-agent keys. This page documents **every** key, its default, and which entrypoint reads it.

Source of truth: `crates/kirby-node/src/config.rs` (`KirbyConfig`).

> **Zero-config vs this page.** The **Default** column below is the *field* default -- what a
> key falls back to when a config *file* is present but omits it (backcompat: existing files are
> byte-identical). A **bare `kirby-node` with NO config file** synthesizes a different, richer
> set of whole-struct defaults (a capable `routstr_key` fleet template, `mem` rent 0, a lifted
> run wall, the blessed `image_allowlist`, etc.). Those are documented in
> [`zero-config.md`](./zero-config.md); this page is the per-key reference for an explicit file.
>
> **Note:** `relay.url`, `genome_image`, and `[identity]` -- previously required -- now DEFAULT
> when omitted. A present config file that omits `[relay]` joins the shared fleet relay
> (`$KIRBY_RELAY_URL` else `ws://185.18.221.222:7777`) and logs a loud `WARN` (so a forgotten
> `[relay]` isn't a silent prod-relay join); no `genome_image` uses `$KIRBY_GENOME_IMAGE`
> / `./result`; no `[identity]` mints a durable node key. Set them explicitly to override.

**TOML ordering rule:** the top-level scalar keys (`backend`, `genome_image`, `workload`, `mode`,
`agent_id`, `node_id`, `state_root`, `max_run_secs`) MUST appear **before** any `[table]` header.

**"Consumed by"** column: `agent` = read on the `kirby-node agent` path; `fleet` = read on the
`kirby-node fleet` path; `both` = read on either. The fleet supervisor clones the host config into
each child agent, overriding a few per-tenant paths (noted below).

## Top-level keys

| Key | Type | Default | Meaning | Consumed by |
|---|---|---|---|---|
| `backend` | `auto` \| `firecracker` \| `vz` | `auto` | Sandbox backend. `auto` = VZ on macOS-aarch64, else Firecracker. | both |
| `genome_image` | `{ path = "..." }` or `{ url = "..." }` | `$KIRBY_GENOME_IMAGE`, else `{ path = "result" }` | The genome image to boot. `path` = a local image dir (the `nix build .#genome-image` output). Optional: defaults to the `result` symlink (or `$KIRBY_GENOME_IMAGE`), resolved + arch-checked at boot. The `url` form is a stub and errors today. | both |
| `workload` | `app-checkpoint` \| `capable` | `app-checkpoint` | `app-checkpoint` = submit a checkpoint then meter VM time. `capable` = the agentic think/act loop (enables `[brain]`/`[memory]`/`[agent]`). | both |
| `mode` | `bootstrap` \| `resume` | `bootstrap` | `bootstrap` = fund to born. `resume` = restore from the latest checkpoint (skips born). `capable`+`resume` is rejected. | both |
| `agent_id` | string | `agent-0` | The `["a",X]` lifecycle tag + treasury/metering label. Charset-validated. | both |
| `node_id` | string | `node-1` | The `["node",X]` tag + presence node_id. Charset-validated. (Note: `kirby-node fleet` also takes a separate numeric `--node-id <u64>` lease id -- different thing.) | both |
| `state_root` | path | unset | The single durable root for ALL node state (treasuries, keystores, agent dirs). Unset resolves to `$KIRBY_STATE_ROOT`, else `$XDG_DATA_HOME/kirby`, else `$HOME/.local/share/kirby` -- never a temp dir. | both |
| `max_run_secs` | u64 | unset (600s) | The run safety ceiling in seconds: a bootstrap agent that never goes broke halts here. Omit for the 600s default; raise it for a long-lived die-when-broke run. `0` is rejected at load. | both |

## `[identity]`

| Key | Type | Default | Meaning | Consumed by |
|---|---|---|---|---|
| `key_path` | path | unset (optional, #81) | This node's BIP340 Nostr secret key. Minted 0600 on first run, loaded after (stable npub). May be a file or a dir (`<dir>/node.nostr.key`). Unset => `<treasury_dir>/node.nostr.key` under the durable state root, so `[identity]` can be omitted entirely. | both |
| `treasury_dir` | path | parent of `key_path` | The daemon-owned treasury directory (also homes the DM key and the per-agent wallet). A per-config override most users leave unset. Note it falls back to `key_path`'s parent, **not** to `state_root`. | both |
| `frost_keystore_dir` | path | unset | The per-agent FROST keystore. Set, the voice signs under the sovereign 2-of-3 Q; unset, the plain node-key path. **The fleet supervisor sets this programmatically** -- not normally hand-edited. | both (fleet sets) |

## `[relay]`

| Key | Type | Default | Meaning | Consumed by |
|---|---|---|---|---|
| `url` | string | `$KIRBY_RELAY_URL`, else `ws://185.18.221.222:7777` | The fleet relay websocket URL. Must start `ws://` or `wss://`. Optional: defaults to the shared fleet relay (or `$KIRBY_RELAY_URL`), so a config omitting it still joins the fleet. | both |
| `presence_interval_secs` | u64 | `15` | Seconds between presence beacon re-publishes. | both |
| `presence_stale_after_secs` | u64 | `45` | Seconds after which a peer with no fresh beacon is presumed STALE. | both |
| `dm_backfill_secs` | u64 | `30` | Seconds between DM-inbox backfill sweeps: how often the NIP-17 inbox re-fetches stored gift wraps on a **fresh** connection to recover any DM the persistent subscription missed (a half-open socket delivers nothing with the keepalive ping off). Uses no `since` (NIP-17 backdates `created_at` up to 2 days) and dedupes by gift-wrap id. `0` disables it (persistent-subscription only). Only the `capable` (DM-enabled) agent uses it. | agent |

## `[funding]`

| Key | Type | Default | Meaning | Consumed by |
|---|---|---|---|---|
| `initial_sats` | u64 | `1_000_000` | Initial treasury balance, seeded only on first creation (play-money; a resume keeps the persisted balance). Validated `> 0`. | both |

## The agentic workload (`workload = "capable"`)

These blocks are read only when `workload = "capable"` (the think/act loop). With the default
`app-checkpoint` workload they are inert.

### `[brain]` -- inference

| Key | Type | Default | Meaning |
|---|---|---|---|
| `backend` | `stub` \| `routstr` \| `routstr_key` | `stub` | Inference backend. `stub` = simulated. `routstr` = pay-per-request Cashu. `routstr_key` = a prepaid bearer key. |
| `model` | string | `anthropic/claude-sonnet-4.6` | The model for the completion act. |
| `max_cost_sats` | u64 | `64` | Per-call budget cap. Validated `> 0` and `<= funding.initial_sats`. |
| `tick_secs` | u64 | `5` | Think cadence (overridden by `[agent].tick_secs` for capable). |
| `node_url` | string | `""` | (routstr / routstr_key) The Routstr node URL. Required for both real backends; https unless loopback. |
| `mint_url` | string | `""` | (routstr) The treasury wallet mint. Required iff `backend = "routstr"`. |
| `wallet_db_path` | string | `""` | (routstr) The persistent cdk-sqlite wallet store. Required iff `backend = "routstr"`. Rewritten per-tenant by the fleet supervisor. |
| `api_key_path` | string | `""` | (routstr_key) Path to the prepaid bearer key file. Required iff `backend = "routstr_key"`. Node-shared; deliberately NOT rewritten per-tenant. The prepaid key balance must be `>=` the treasury (`funding.initial_sats` on first boot, the persisted balance on resume), else the brain refuses to boot (solvency guard). |
| `max_tokens` | u32 | `1024` | (routstr_key) Caps the reply and Routstr's per-request reservation. Must be `> 0` iff `routstr_key`. |
| `request_timeout_secs` | u64 | `30` | (routstr) Main-path kill window. |
| `recovery_timeout_secs` | u64 | `10` | (routstr) Cleanup / refund budget. |
| `fee_headroom_sats` | u64 | `8` | (routstr) Wallet fee reserve. |
| `bytes_per_sat` | u64 | `16` | (stub) Simulated cost knob. |

### `[memory]` -- the diarist / engram store

| Key | Type | Default | Meaning |
|---|---|---|---|
| `relays` | list of strings | `[]` | Nerve write-relays. EMPTY = in-memory stub; NON-EMPTY = real engram store, with the list size = the copy count N. |
| `write_k` | usize | strict majority `floor(N/2)+1` | The K-of-N ack threshold for a write. |
| `key_path` | path | beside the treasury | The engram signing/encrypt key; ignored when `relays` is empty. |
| `max_cost_sats` | u64 | `64` | Per-write budget ceiling. |
| `tick_secs` | u64 | `5` | Memory op cadence (overridden by `[agent].tick_secs`). |
| `bytes_per_sat` | u64 | `16` | Storage cost knob. |

### `[agent]` -- the plan/act loop

| Key | Type | Default | Meaning |
|---|---|---|---|
| `tick_secs` | u64 | `60` | The single plan+act loop cadence. OVERRIDES `[brain]`/`[memory]` tick_secs. |
| `recall_count` | usize | `5` | How many recent facts to recall into each plan prompt. |

## `[meter]` -- synthetic VM-rent burn rates

The play-money rent dials. All read on both paths.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cpu_sats_per_usec_num` | u64 | `1` | CPU sats/microsecond numerator. |
| `cpu_sats_per_usec_den` | u64 | `1000` | CPU sats/microsecond denominator (default 1 sat/ms CPU). |
| `mem_sats_per_mib_sec` | u64 | `1` | Sats per MiB resident per second -- the key rent dial. Set `0` for a long-lived capable agent; the default `1` burns ~128 sat/s on a 128 MiB VM (a small treasury hits `BudgetExhausted` in seconds). |
| `egress_sats_per_byte_num` | u64 | `1` | Egress sats/byte numerator. |
| `egress_sats_per_byte_den` | u64 | `1` | Egress sats/byte denominator. |

## The fleet (`kirby-node fleet` only)

The `[fleet]` block is read **only** by `kirby-node fleet`; a bare `kirby-node agent` ignores it.

### `[fleet]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `base_cid` | u32 | `100` | The base guest CID the allocator counts up from (tenant n -> `base_cid + n`). |
| `max_tenants` | u32 | `16` | The per-host tenant ceiling. Also caps the spawn control plane. |
| `gateway_port_base` | u32 | `9000` | The base gateway vsock port (tenant n -> `gateway_port_base + n`). |
| `tenants` | array | `[]` | Static operator-declared tenants (the `[[fleet.tenants]]` array). Empty = host nothing statically. |
| `spawn` | table | (defaults) | The dynamic spawn control plane (below). |

### `[[fleet.tenants]]` -- statically declared agents

Each entry becomes one allocated CID/port + per-agent treasury + per-agent FROST lease + a child
`kirby-node agent` process. A tenant has exactly two fields:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `agent_id` | string | **required** | The tenant's agent id (lease key, treasury label). Charset-validated; unique within the fleet. |
| `initial_sats` | u64 | `1_000_000` | The tenant's initial treasury. Validated `> 0`. |

The supervisor reuses the host's `genome_image` for every tenant and synthesizes each child's
config from the host config, overriding only: `agent_id`, `node_id`, `funding.initial_sats`, the
`[identity]` paths, `frost_keystore_dir`, and `[brain].wallet_db_path`. There is no per-tenant
`image_ref` in the static set -- a remote, per-agent image is a `kirby-node spawn-request` field
(the kind-`31003` payload), not a kirby.toml key.

### `[fleet.spawn]` -- the kind-31003 dynamic spawn control plane

This runs **whenever `kirby-node fleet` runs** -- there is **no `enabled` flag**. It is gated by
the allowlists below.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `operators` | list of hex pubkeys | `[]` | The operator allowlist. NON-EMPTY = only listed keys may spawn. **EMPTY = OPEN: any signer may spawn an agent on this node** (a known MVP DoS vector; it logs a loud warning). |
| `image_allowlist` | list of image_refs | `[]` | The pre-staged genome images this node will run (default-deny unknown). EMPTY = spawn nothing. Its first entry is also the node's own spawn image. |
| `max_per_window` | u32 | `10` | Max spawns per `rate_window_secs` per operator (anti-spam). |
| `rate_window_secs` | u64 | `60` | The rate-limit window. |
| `max_seed_sats` | u64 | `1_000_000` | Max declarative seed sats one spawn request may fund an agent with. |
| `failover_scan_secs` | u64 | `5` | (G-4) Seconds between lease scans for dark peers to take over. |
| `takeover_grace_secs` | u64 | `30` | (G-4) The grace window a lease must be continuously stale before takeover (= the lease TTL). A money dial. |
| `failover_max_lease_age_secs` | u64 | `300` | (G-4) The upper age bound; older stale leases are ancient ghosts, ignored. Cross-validated: must be `> takeover_grace_secs + 30`. |
| `request_max_age_secs` | u64 | unset (off) | OPT-IN filter: drop spawn requests older than this many seconds (sheds stale/parked kind-31003 events). Omit to disable; a positive value sets the age bound. **Do NOT use `0` to mean off** -- `0` engages the filter with a zero window and rejects essentially ALL spawn requests (`created_at + 0 < now` => `SpawnReject::Stale`). |

## Notes

- There is **no `[social]` section.** The capable workload derives its social config at boot (DM
  relays from `[relay].url`, key from `[identity]`).
- A code comment in `config.rs` calls `state_root` "`[node].state_root`," but there is **no `[node]`
  table** -- `state_root` is a top-level key. Write it before any table header.
