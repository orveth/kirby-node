---
name: fund-kirby-agent
description: Create and fund a new kirby agent (a sovereign Kirby) from this repo so it boots with starting money, or top up / check the balance of an existing one. Use when the user wants to create, spin up, provision, stand up, or fund a kirby agent; mint a funded Routstr key for an agent; give an agent starting sats; top up an agent's balance; or check what an agent is funded with. This is a thin wrapper over the `kirby-node fund-key` CLI — it invokes the CLI and lets the CLI own all funding policy.
---

# Funding a kirby agent

The user wants a kirby agent that has money to run. An agent's metabolism is play-money ecash held
behind a **Routstr key** (`sk-...` — a bearer credential). "Funding an agent" means minting or
topping up that key and pointing a kirby config at it. The `run-kirby-node` skill then runs the
agent on top of the funded key.

**This skill is a thin shim: it INVOKES `kirby-node fund-key` and nothing more.** It does not
implement, embed, or second-guess any funding policy — amount bounds, per-key caps, authentication,
faucet behavior, and the default node all live in the CLI. Your job is to drive the right
subcommand with the user's inputs and report what the CLI returns.

**Authoritative contract = the CLI's own help.** Before driving a flow, run
`kirby-node fund-key <cmd> --help` — it prints the current flags, defaults, and bounds. Trust that
over anything remembered. If a default or limit ever changes, `--help` reflects it and this skill
still works unchanged.

## In-repo vs installed

From a checkout, the binary is `cargo run -p kirby-node -- <args>` (do `nix develop` first — see
[`run-kirby-node`](../run-kirby-node/SKILL.md) for host setup). If `kirby-node` is on PATH, use it
directly. Examples below write `kirby-node`; substitute `cargo run -p kirby-node --` in a checkout.

## Every command speaks JSON + stable exit codes

Pass `--json` (the default) and read stdout as JSON. Most commands print a single JSON object, but
the LN-invoice blocking flows (`provision` and `topup --amount-sats`) print the `bolt11` as an
early `{"status":"invoice-created",...}` line and THEN a final result line — i.e. JSONL. Act on the
FINAL line plus the exit code; the exit code is the machine signal — branch on it, don't parse prose:

- `0` success · `2` unpaid-timeout · `3` expired · `4` failed-payment · `5` network-failure ·
  `6` auth-failure · `7` insufficient-balance · `8` key-write-failure · `9` usage-error

  `2`–`9` are the exact failure `status` tags the CLI emits in its JSON. Exit `0` is success, but
  its `status` varies by command: `invoice-created` (`create --amount-sats`), `funded`
  (`poll`/`provision`/`topup`/`create --from-token`), `ok` (`balance`). Branch on the exit code
  first; the `status` tag tells you which success shape you got.

The minted `sk-` is bearer money. The CLI writes it `0600` to your `--key-out` path and never prints
it. **Never** echo a key, put it in logs, commit it, or pass it on a command line where it lands in
shell history. Treat `--key-out` files as secrets.

## Pick the path

**One-shot (human pays a QR / simple script) — `provision`.** Creates the invoice, prints the
`bolt11` up front, blocks until paid, writes the funded key, and optionally emits a runnable config:

```sh
kirby-node fund-key provision --amount-sats <N> --key-out ./agent.key --emit-config ./kirby.toml
```

Show the user the `bolt11` to pay. On exit `0` you have `./agent.key` (funded) and `./kirby.toml`
(treasury `initial_sats` = the confirmed probed balance). Then run the agent:

```sh
kirby-node agent --config ./kirby.toml
```

**Agent-native async (a driving agent with its own LN wallet) — `create` then `poll`.** Split so
the agent can pay the returned `bolt11` programmatically and resume:

```sh
kirby-node fund-key create --amount-sats <N> --key-out ./agent.key   # → {status, bolt11, amount_sats}
# ... pay the bolt11 with your wallet ...
kirby-node fund-key poll --key-out ./agent.key                       # blocks → {status:"funded", key_path, balance_sats}
```

`create` persists a `0600` pending-invoice sidecar beside `--key-out`; `poll` reads it (no
`--invoice-id`). A crash mid-flow resumes with `poll` on the same `--key-out` — do not re-`create`
(that would overwrite and strand the pending invoice).

**Instant, no lightning — fund from an ecash token.** If the user already holds a Cashu token,
redeem it synchronously (no invoice, no poll):

```sh
kirby-node fund-key create --from-token <cashu...> --key-out ./agent.key   # → {status:"funded", ...}
```

Prefer `topup --from-token` over `create --from-token` when a key already exists — topup sends the
token in the request body, while create puts it in the URL (a bearer-in-logs exposure).

**Grow an existing key — `topup` (two sources, same shapes as `create`):**

```sh
# LN: mints a topup invoice, emits the bolt11 early, then BLOCKS until it is paid (real sats,
# human-gated) — same pay-then-confirm shape as create→poll, not an instant grow:
kirby-node fund-key topup --key-path ./agent.key --amount-sats <N>   # → prints bolt11, then blocks

# ecash: no invoice + no human pay step (token in the request body — no URL exposure), but it
# STILL blocks until the node confirms the balance rose (bounded by --timeout-secs):
kirby-node fund-key topup --key-path ./agent.key --from-token <cashu>
```

Surface the LN `bolt11` for the user to pay, exactly as with `create`; do not treat LN topup as
instant or it will hang until `--timeout-secs`. The `--from-token` path skips the invoice and the
human pay step but is not instant either — it blocks until the balance-rise is confirmed.

**Inspect a key — `balance`:**

```sh
kirby-node fund-key balance --key-path ./agent.key   # → {balance_sats} (probed from the bound node)
```

## Refusals are guardrails, not bugs

`create`/`provision` refuse if `--key-out` already exists — that protects a funded key from being
overwritten. Bounds and caps are enforced CLI-side; a `9` (usage) or `7` (insufficient) exit means
the CLI rejected the inputs against its policy. Report the CLI's message; do not work around it.

## When you finish

Report honestly, per the boundary in [`../../../AGENTS.md`](../../../AGENTS.md) and
[`../../../CLAUDE.md`](../../../CLAUDE.md): the money is play-money ecash (no on-chain Bitcoin), and
a funded key is a bearer credential the holder controls. State the funded balance the CLI probed,
where the key was written, and whether a config was emitted. Don't claim more than exit `0` proved.
