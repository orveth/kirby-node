# Create + fund an agent's key (`fund-key`)

Turn **N sats** into a funded prepaid Routstr bearer key (`sk-…`) an agent
thinks on, by paying one Lightning invoice. This is the agent-native funding
primitive: a coding agent or personal assistant drives the whole flow over the
CLI (`fund-key` + `--json` + exit codes), and a human can run the same one-shot.
Published code funds nothing -- each creator funds their OWN agent's key; no
money is ever baked in.

The shape of it -- two funding sources, one keyfile:

```
# Lightning (pay an invoice):
fund-key create --amount-sats N --key-out K  -->  {bolt11}  (the creator pays it)
   -->  fund-key poll --key-out K   -->  the node mints the sk- on payment
   -->  the sk- is written to a 0600 keyfile (K)

# OR ecash (redeem a Cashu token you already hold -- one call, no poll):
fund-key create --from-token <cashu> --key-out K  -->  the sk- is written to K

   -->  point an agent at it ([brain] backend = "routstr_key", api_key_path)
   -->  fund-key topup (--amount-sats N | --from-token <cashu>)  -->  keep it alive.
```

The `sk-` is **bearer money**. It only ever lands in a **0600 keyfile** -- never
printed, never logged, never in a TOML. The HTTP client disables redirects (a
redirect would leak the `Bearer` header to another host), and a bearer `sk-` is
sent only over `https://` (or a real loopback `http://` for local dev/tests) --
never plaintext http to a public host. The `invoice_id` is itself a capability
on the unauthenticated `create` path (it is what a `poll` exchanges for the
`sk-`), so it is **never printed** -- it is persisted (with the `node_url`) to a
0600 sidecar beside `--key-out` and `poll` reads it back from there.

> **Live-smoke caveat (C6).** The LN `topup` is spec-ready but un-exercised against
> the live node; and as of this writing `POST /v1/balance/lightning/invoice
> {purpose:"create"}` has been failing Routstr-side (`{"detail":"Failed to
> create Lightning invoice"}`) -- the request shape is accepted but invoice
> creation fails on their end. **The ECASH path routes around that outage** (mint a
> token at minibits, then `create/topup --from-token`) and is the live-smoke path
> that works today -- see "Fund with ECASH" below. All flows are tested end-to-end
> against an offline mock; a live smoke (a few real sats) is the last gate before a
> flow is demoable. One ecash detail is empirical until the smoke: the minted-key
> field name in the loose `GET /v1/balance/create` response (kirby parses it
> tolerantly, expecting `api_key`).

## The commands

`kirby-node fund-key <subcommand>` (run `--help` on any for exact flags). The
default `--node-url` is `https://api.routstr.com`.

| Subcommand | Does | Blocks? |
|---|---|---|
| `create --amount-sats N --key-out PATH` | LN: create an invoice (mints a NEW key on payment). Persists the `invoice_id` + `node_url` to a 0600 sidecar beside `--key-out`. Refuses if `--key-out` already exists. | no |
| `create --from-token <cashu> --key-out PATH` | Ecash: redeem a Cashu token into a NEW funded key in ONE call (no invoice/poll). Writes the `sk-` (0600) + binds the `node_url`, reports the probed balance. Refuses if `--key-out` already exists. | yes (synchronous) |
| `poll --key-out PATH` | LN only: poll the created invoice (invoice_id + node_url from the sidecar); on payment, write the `sk-` to `--key-out` (0600), bind the `node_url` beside it, and report the probed balance. | yes |
| `provision --amount-sats N --key-out PATH` | LN one-shot: `create` + emit the bolt11 early + `poll` + write. | yes |
| `topup --amount-sats N --key-path PATH` | LN: credit an EXISTING key's balance (authenticated with its `sk-`). | yes |
| `topup --from-token <cashu> --key-path PATH` | Ecash: credit an EXISTING key's balance from a Cashu token (POST, token in the body). | yes |
| `balance --key-path PATH` | Read an existing key's spendable balance. | no |

`create` and `topup` each take a funding SOURCE: `--amount-sats N` (Lightning) **or**
`--from-token <cashu>` (ecash). They are **mutually exclusive — pass exactly one**; both or
neither is a usage error (exit 9). Both sources share the same keyfile write, `node_url`
binding, JSON contract, and exit codes — only the "obtain the `sk-` / credit the balance" step
differs.

> **No `recover`.** Recovering a key from its `bolt11` is **deferred** (pending
> C7): a paid invoice's `bolt11` is public (it is handed to wallets / QR / NWC),
> so a bolt11-only recover would return bearer money to anyone who saw the
> invoice, and Routstr's recover-auth is unverified. The 0600 pending-invoice
> sidecar makes `create -> poll` crash-resumable (re-run `poll --key-out PATH`
> after a crash), so recover is rarely needed.

## The primary agent-native path: `create` -> pay -> `poll`

An agent with its own Lightning wallet does the split flow so it can pay in
between (the `sk-` only exists *after* payment):

```sh
# 1) Create the invoice (non-blocking). Returns the bolt11 to pay.
kirby-node fund-key create --amount-sats 2000 --key-out ./agent/brain.key
# -> {"status":"invoice-created","bolt11":"lnbc…","amount_sats":2000,"hint":"pay the bolt11, then run: fund-key poll --key-out ./agent/brain.key"}

# 2) Pay the bolt11 from your wallet (NWC, LNC, a QR for a human, …).
#    kirby does NOT build a payment rail -- paying the invoice is the creator's job.

# 3) Poll until the node mints the key. Writes ./agent/brain.key (0600) on payment.
kirby-node fund-key poll --key-out ./agent/brain.key --timeout-secs 1200
# -> {"status":"funded","key_path":"./agent/brain.key","balance_sats":2000}
```

The `create` output deliberately does **not** carry the `invoice_id` (it is
bearer-sensitive). `poll` reads the `invoice_id` **and** the `node_url` from the
0600 sidecar `create` wrote beside `--key-out`, so it always targets the node the
invoice was created against. (A `--node-url` on `poll` must match that bound
node_url unless you also pass `--allow-node-url-override`.) On a terminal
`expired`/`failed` status, or a timeout, `poll` exits non-zero and writes no key.

## The one-shot: `provision`

For a human (pay the QR) or a simple script -- create, pay, poll in one call.
The bolt11 is emitted as an **early JSONL line before it blocks** on poll, so a
driver can pay while it waits:

```sh
kirby-node fund-key provision --amount-sats 2000 --key-out ./agent/brain.key
# line 1 (immediately): {"status":"invoice-created","bolt11":"lnbc…","amount_sats":2000}
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

## Fund with ECASH: `create`/`topup --from-token`

A second, live-proven funding path runs **alongside** Lightning: fund a key from a
Cashu **ecash token** you already hold. It is a first-class source on `create` and
`topup` (via `--from-token <cashu>`), and it **routes around the current Routstr
LN-`create` outage** (see the caveat above) -- the ecash path is the live-smoke (C6)
path that works today.

```sh
# Create a NEW funded key from a token (ONE call, synchronous -- no invoice/poll):
kirby-node fund-key create --from-token cashuB... --key-out ./agent/brain.key
# -> {"status":"funded","key_path":"./agent/brain.key","balance_sats":2000}

# Credit an EXISTING key from a token:
kirby-node fund-key topup --from-token cashuB... --key-path ./agent/brain.key
# -> {"status":"funded","balance_sats":4000}
```

Ecash `create` redeems the token into a new key in a single call -- there is **no
invoice, no poll, and no pending-invoice sidecar** (the token redeems synchronously).
It runs the same hardened machinery as the LN `poll`: it writes the `sk-` to a 0600
keyfile, binds the `node_url` beside it, and reports the **probed** balance (the
token's redeemed value, minus any mint/routing rounding). Ecash `topup` POSTs the
token to `/v1/balance/topup` authenticated with the key, then confirms the balance
rose (the same balance-rise confirmation the LN topup uses).

### The creator brings the token (C5)

kirby does **not** build a mint or a payment rail -- the creator brings the funds, so
the creator mints the ecash token first. With [minibits](https://minibits.cash) (Routstr
accepts it, first in its mints list):

```
1) POST {minibits}/v1/mint/quote/bolt11 {amount_sats}  -> a bolt11 + a quote id
2) Pay that bolt11 from your Lightning wallet (NWC, LNC, a QR, ...).
3) Mint the ecash token against the paid quote (your Cashu wallet does this).
4) Redeem it: kirby-node fund-key create/topup --from-token <that token>
```

That is a complete "N sats -> funded key" loop **today**, even while Routstr's LN
`create` is failing on their end. (A future enhancement, E2, folds the minibits mint
flow into `fund-key` directly -- `--via ecash --amount N` -- for a one-command path.)

### Security: the create-token rides the URL (a log exposure)

Ecash **`create` is a GET with the token in the query string**
(`/v1/balance/create?initial_balance_token=<token>`). Routstr exposes **no POST
variant** for create-from-token, so the Cashu token (bearer money) can land in
server/proxy **access logs** -- unavoidable for `create`. Treat a create token as
**burned on use** (single-use, redeemed immediately, never reused). The token is
URL-encoded on the wire and never printed by kirby, but the server-side log exposure is
inherent to the GET.

**Prefer `topup --from-token`** when crediting an existing key: the topup **POST** puts
the token in the request **body**, so there is no URL/query-log exposure -- it is the
clean ecash primitive. (LN `create` carries no bearer secret on the request, so it has
no such exposure either.)

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
| 9 | `usage-error` | A bad argument caught before any network call (bad amount, node_url mismatch, a plaintext non-loopback node_url, an existing `--key-out`, no pending state, an empty `--from-token`, or not exactly one of `--amount-sats`/`--from-token`). |

On a failure the object is `{"status":"<tag>","error":"<message>"}`. The `sk-`
and `invoice_id` never appear in any JSON line, and no error message carries the
status URL (which would embed the `invoice_id`).

## Recover is deferred (C7)

There is intentionally **no `recover` command** in v1. Recovering a key from its
`bolt11` returns bearer money to anyone holding that `bolt11`:

> **The `bolt11` is public** (it is handed to wallets / QR / NWC). If the node
> mints the `sk-` from the `bolt11` alone, anyone who saw the invoice can steal
> the funded key -- and Routstr's recover-auth is **unverified (C7)**. Recover is
> deferred until C7 is resolved.

You rarely need it: the 0600 pending-invoice sidecar makes `create -> poll`
crash-resumable. If `poll` (or `provision`) is interrupted after payment but
before the key is written, just re-run `poll --key-out PATH` -- it reads the
invoice_id + node_url back from the sidecar and finishes the mint.

## The keyfile + its sidecars

`--key-out PATH` (the raw `sk-` on one line, 0600) is what `[brain] api_key_path`
loads; the loader trims the trailing newline. `fund-key` also writes, beside it:

- `PATH.invoice` (0600) -- the pending-invoice state (F2): JSON holding the
  `invoice_id` **and** the `node_url` the invoice was created against, so `poll`
  finds both and a crash between create and mint is recoverable. Bearer-sensitive
  (the invoice_id is a capability); never logged. It is cleared once the key is
  written. Even a pre-existing sidecar is forced to mode 0600 on write (never
  left world-readable), and a symlink at the path is refused (`O_NOFOLLOW`).
- `PATH.node_url` (0600) -- the bound node URL (F9), so `balance`/`topup` never
  send the key elsewhere. It is written **only after** the key lands (never a
  binding without a key beside it).

The key write is atomic and hardened (F8): `O_CREAT|O_EXCL|O_NOFOLLOW` + 0600, the
parent dir is created and `fsync`ed, and a partial file is removed if the write or
`fsync` fails (no empty/partial key ever lingers). Writing over an EXISTING key
fails unless its content fingerprint matches (an idempotent re-provision of the
same key succeeds; a DIFFERENT key is never silently clobbered). The
idempotent-read path opens the existing key `O_RDONLY|O_NOFOLLOW` and requires a
regular file mode 0600 -- it never follows a symlink or trusts a wrong-mode file.
