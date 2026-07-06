# Example: a user's agent creates + funds a kirby agent

A worked transcript of what the `fund-kirby-agent` skill drives when a user tells their personal
coding agent *"spin up a kirby agent with 21 sats and run it."* Commands are the in-repo form
(`cargo run -p kirby-node --`); with `kirby-node` on PATH, drop the prefix.

Outputs below are real (captured against `api.routstr.com`), except the paid steps — paying a
`bolt11` moves real sats and is gated to a human.

## 1. Confirm the host can run an agent (once)

```sh
cargo run -p kirby-node -- prereqs
```

## 2. Create the funding invoice (no money moves yet)

```sh
cargo run -p kirby-node -- fund-key create --amount-sats 21 --key-out ./agent.key
```
```json
{"status":"invoice-created","amount_sats":21,
 "bolt11":"lnbc210n1p4yhmjq...zrrs3hgpvgju5a",
 "hint":"pay the bolt11, then run: fund-key poll --key-out ./agent.key"}
```
The agent shows the `bolt11` to the user to pay. A `0600` sidecar `./agent.key.invoice` now holds
the invoice_id + node_url (bearer-sensitive — never printed).

## 3. User pays the bolt11, then poll until the key mints

*(pay step is human-gated — real sats)*

```sh
cargo run -p kirby-node -- fund-key poll --key-out ./agent.key
```
```json
{"status":"funded","key_path":"./agent.key","balance_sats":21}
```
On exit `0`, `./agent.key` holds the funded `sk-` (0600). The agent branches on the exit code, not
the prose.

## Turn the funded key into a runnable config

`create`/`poll` produce only the funded **key** — they do NOT write a config. To get a runnable
`./kirby.toml`, either:
- use `provision --emit-config ./kirby.toml` instead of `create`+`poll` (the one-shot variant below
  writes the key AND a correct minimal config in one call) — the simplest path, or
- build a config from `kirby.toml.example` + `docs/config.md`, pointing `[brain] api_key_path` at
  `./agent.key`. The [`run-kirby-node`](../run-kirby-node/SKILL.md) skill walks this. (Don't
  hand-assemble the routstr_key keys from memory — `--emit-config` writes the authoritative shape.)

## One-shot variant (human pays a QR)

`provision` collapses create+poll and can emit a runnable config in one call:

```sh
cargo run -p kirby-node -- fund-key provision --amount-sats 21 \
  --key-out ./agent.key --emit-config ./kirby.toml
```
It prints the `bolt11` early, blocks until paid, writes the funded key, and writes `./kirby.toml`
with treasury `initial_sats` = the confirmed probed balance.

## Instant variant (no lightning) — fund from an ecash token

If the user hands over a Cashu token, one synchronous call funds the key (no invoice, no poll):

```sh
cargo run -p kirby-node -- fund-key create --from-token <cashu...> --key-out ./agent.key
```
```json
{"status":"funded","key_path":"./agent.key","balance_sats":21}
```

## 4. Run the funded agent

```sh
cargo run -p kirby-node -- agent --config ./kirby.toml
```
(Handed off to the [`run-kirby-node`](../run-kirby-node/SKILL.md) skill.) Watch for
`published 9100 lifecycle event ... event=born` and `KIRBY-RUN ... reached_running=true born=true`.

## What the skill reports back

> Minted a 21-sat funding invoice and (after you paid) a funded key at `./agent.key`; the node
> probed a balance of 21 sats. Wrote a runnable config to `./kirby.toml`. The agent is booting —
> `born=true` confirmed. Money is play-money ecash; `./agent.key` is a bearer credential, keep it
> secret.
