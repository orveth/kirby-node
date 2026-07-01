# Create + fund an agent's key (`fund-key`)

Turn **N sats** into a funded prepaid Routstr bearer key (`sk-…`) an agent
thinks on, by paying one Lightning invoice. This is the agent-native funding
primitive: a coding agent or personal assistant drives the whole flow over the
CLI (`fund-key` + `--json` + exit codes), and a human can run the same one-shot.
Published code funds nothing -- each creator funds their OWN agent's key; no
money is ever baked in.

The shape of it:

```
fund-key create   -->  {invoice_id, bolt11}   (the creator pays the bolt11)
   -->  fund-key poll   -->  the node mints the sk- on payment
   -->  the sk- is written to a 0600 keyfile
   -->  point an agent at it ([brain] backend = "routstr_key", api_key_path)
   -->  fund-key topup   -->  credit the key's balance to keep it alive.
```

The `sk-` is **bearer money**. It only ever lands in a **0600 keyfile** -- never
printed, never logged, never in a TOML. The HTTP client disables redirects (a
redirect would leak the `Bearer` header to another host). The `invoice_id` is
itself a capability on the unauthenticated `create` path (it is what a `poll`
exchanges for the `sk-`), so it is persisted to a 0600 sidecar and never logged.

> **Live-smoke caveat (C6).** `topup` and `recover` are spec-ready but
> un-exercised against the live node; and as of this writing `POST
> /v1/balance/lightning/invoice {purpose:"create"}` has been failing
> Routstr-side (`{"detail":"Failed to create Lightning invoice"}`) -- the
> request shape is accepted but invoice creation fails on their end. The flow is
> tested end-to-end against an offline mock; a live smoke (a few real sats) is
> the last gate before it is demoable.

## The commands

`kirby-node fund-key <subcommand>` (run `--help` on any for exact flags). The
default `--node-url` is `https://api.routstr.com`.

| Subcommand | Does | Blocks? |
|---|---|---|
| `create --amount-sats N --key-out PATH` | Create an invoice (mints a NEW key on payment). Persists the `invoice_id` + binds the `node_url` beside `--key-out`. | no |
| `poll --key-out PATH` | Poll the created invoice; on payment, write the `sk-` to `--key-out` (0600) and report the probed balance. | yes |
| `provision --amount-sats N --key-out PATH` | One-shot: `create` + emit the bolt11 early + `poll` + write. | yes |
| `topup --amount-sats N --key-path PATH` | Credit an EXISTING key's balance (authenticated with its `sk-`). | yes |
| `balance --key-path PATH` | Read an existing key's spendable balance. | no |
| `recover --bolt11 B11 --key-out PATH --break-glass` | Break-glass: recover a paid-but-lost key from its bolt11 (see [Recover](#recover-break-glass)). | yes |

## The primary agent-native path: `create` -> pay -> `poll`

An agent with its own Lightning wallet does the split flow so it can pay in
between (the `sk-` only exists *after* payment):

```sh
# 1) Create the invoice (non-blocking). Returns the bolt11 to pay.
kirby-node fund-key create --amount-sats 2000 --key-out ./agent/brain.key
# -> {"status":"invoice-created","invoice_id":"…","bolt11":"lnbc…","amount_sats":2000,"expires_at":…,"key_out":"./agent/brain.key"}

# 2) Pay the bolt11 from your wallet (NWC, LNC, a QR for a human, …).
#    kirby does NOT build a payment rail -- paying the invoice is the creator's job.

# 3) Poll until the node mints the key. Writes ./agent/brain.key (0600) on payment.
kirby-node fund-key poll --key-out ./agent/brain.key --timeout-secs 1200
# -> {"status":"funded","key_path":"./agent/brain.key","balance_sats":2000}
```

`poll` finds the `invoice_id` from the sidecar `create` wrote beside `--key-out`
(pass `--invoice-id` to override). On a terminal `expired`/`failed` status, or a
timeout, it exits non-zero and writes no key.

## The one-shot: `provision`

For a human (pay the QR) or a simple script -- create, pay, poll in one call.
The bolt11 is emitted as an **early JSONL line before it blocks** on poll, so a
driver can pay while it waits:

```sh
kirby-node fund-key provision --amount-sats 2000 --key-out ./agent/brain.key
# line 1 (immediately): {"status":"invoice-created","bolt11":"lnbc…","amount_sats":2000,"expires_at":…}
# line 2 (after payment): {"status":"funded","key_path":"./agent/brain.key","balance_sats":2000}
```

The early line deliberately does **not** carry the `invoice_id` (it is
bearer-sensitive; it lives in the 0600 sidecar).

## Keep it alive: `topup` + `balance`

An agent dies when it goes broke. Top up its key's balance to keep it thinking:

```sh
kirby-node fund-key balance --key-path ./agent/brain.key
# -> {"status":"ok","balance_sats":137}

kirby-node fund-key topup --amount-sats 2000 --key-path ./agent/brain.key
# line 1: {"status":"invoice-created","bolt11":"lnbc…",…}   (pay it)
# line 2: {"status":"funded","balance_sats":2137}           (the credit landed)
```

`topup` authenticates the invoice with the existing `sk-` (`purpose:"topup"`),
so the credit lands on THAT key. It is **client-side only** -- it credits the
Routstr balance; it does not touch any running agent's treasury counter.

> **A running agent probes its key balance only at boot.** So a `topup` credits
> the balance, but a live agent's metabolism counter does not learn about it
> until a controlled restart (which re-seeds the counter from the balance). "Top
> up to stay alive" therefore means: top up, then let the agent restart (or wait
> for the runtime reconcile, handled separately). The boot re-seed is outside
> this tool's scope.

`balance` and `topup` always use the `node_url` **bound beside the key** (F9) --
they never send the bearer key to a different server. To override it you must
pass BOTH `--node-url <url>` and `--allow-node-url-override` (a loud, deliberate
choice); a mismatched `--node-url` without the flag is refused.

## The `fund -> run one agent` recipe (Layer 1)

`provision --emit-config <path>` writes a minimal, runnable kirby config for a
single funded agent, then you run it -- a complete "fund an agent, run it" loop
with no fleet:

```sh
kirby-node fund-key provision \
  --amount-sats 50000 \
  --key-out   ./.kirby/agent/brain.key \
  --emit-config ./agent.toml
# pay the emitted bolt11; on payment the key + ./agent.toml are written.

kirby-node agent --config ./agent.toml
```

The emitted `agent.toml` sets `workload = "capable"`, a `routstr_key` brain
(`node_url` + `api_key_path` = the key-out), and treasury `initial_sats` = the
**CONFIRMED probed balance** after payment (not the requested amount -- fees and
rounding mean the two can differ, and the boot invariant requires the balance to
back the counter). You still edit two placeholders before a real run:
`genome_image` (point it at your `nix build .#genome-image` output) and
`[relay] url` (your fleet relay). See [`config.md`](config.md) for every key.

## The JSON contract + exit codes

Every subcommand prints one JSON object per event on stdout (`provision`/`topup`
print two: the early `invoice-created` line, then the terminal line). Tracing
and warnings go to stderr; the JSON is on stdout. Branch on the **exit code** --
it is stable:

| Exit | `status` | Meaning |
|---|---|---|
| 0 | `funded` / `invoice-created` / `ok` | Success (funded, or a non-blocking create/balance). |
| 2 | `unpaid-timeout` | The wait budget elapsed with the invoice still unpaid. |
| 3 | `expired` | The invoice expired before payment. |
| 4 | `failed-payment` | A terminal failed state (or `recover` could not recover the key). |
| 5 | `network-failure` | Transport / non-2xx / malformed response. |
| 6 | `auth-failure` | Bad/empty/unfunded/revoked key (401/403). |
| 7 | `insufficient-balance` | The custodial balance is too low for the operation. |
| 8 | `key-write-failure` | Writing the keyfile/sidecar failed (e.g. a DIFFERENT key already exists there). |
| 9 | `usage-error` | A bad argument caught before any network call (bad amount, node_url mismatch, missing `--break-glass`). |

On a failure the object is `{"status":"<tag>","error":"<message>"}`. The `sk-`
and `invoice_id` never appear in any JSON line.

## Recover (break-glass)

`recover` re-mints a paid-but-lost key from its `bolt11`. It is gated behind
`--break-glass` and prints a loud stderr warning, because:

> **Routstr's recover-auth is UNVERIFIED (C7).** The `bolt11` is NOT secret (it
> is handed to wallets / QR / NWC). If the node mints the `sk-` from the `bolt11`
> alone, anyone who saw the invoice can steal the funded key. Prefer re-`poll`
> via the persisted `invoice_id` sidecar (which makes recover rarely needed);
> treat created-invoice bolt11s as sensitive; use `recover` only as a last
> resort, and verify the node's recover-auth before relying on it.

```sh
kirby-node fund-key recover --bolt11 lnbc… --key-out ./agent/brain.key --break-glass
```

## The keyfile + its sidecars

`--key-out PATH` (the raw `sk-` on one line, 0600) is what `[brain] api_key_path`
loads; the loader trims the trailing newline. `fund-key` also writes, beside it:

- `PATH.invoice` (0600) -- the persisted `invoice_id` (F2), so `poll` finds it
  and a crash between create and mint is recoverable. Bearer-sensitive; never
  logged.
- `PATH.node_url` (0600) -- the bound node URL (F9), so `balance`/`topup` never
  send the key elsewhere.

The write is atomic and hardened (F8): `O_CREAT|O_EXCL|O_NOFOLLOW` + 0600, the
parent dir is created and `fsync`ed. Writing over an EXISTING key fails unless
its content fingerprint matches (an idempotent re-provision of the same key
succeeds; a DIFFERENT key is never silently clobbered).
