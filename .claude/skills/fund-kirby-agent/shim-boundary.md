# Design note — the shim boundary (skill vs CLI)

The `fund-kirby-agent` skill is a **thin shim** over the `kirby-node fund-key` CLI. This note pins
down the boundary so it stays thin as funding policy evolves.

## The rule

> The skill INVOKES the CLI. It never reimplements the flow, and it never encodes funding policy.
> All policy lives CLI-side; the skill inherits it and passes user inputs through.

## What lives where

**CLI owns (in `crates/kirby-node/src/funding.rs` + `main.rs`):**
- Amount bounds (the accepted sats range) and the source rules (`--amount-sats` xor `--from-token`).
- The default Routstr node URL and node binding.
- Per-key caps / `balance_limit` semantics (the capped child-key concept).
- Authentication (Bearer key auth on topup/balance) and any faucet behavior.
- The stable JSON output shape and the exit-code contract (exit 0 = success — status
  `invoice-created`/`funded`/`ok` by command; 2–9 = distinct failure tags).
- Secret handling: `sk-` written `0600`, never printed/logged; the `0600` pending-invoice sidecar.

**Skill owns:** which subcommand fits the user's intent, threading the user's `--amount-sats` /
`--from-token` / `--key-out` through, surfacing the `bolt11` to pay, branching on the exit code, and
reporting honestly. Nothing else.

## Why thin

Funding policy is a moving target — e.g. the current direction (user self-funding uncapped,
capable-first defaults, limits only on shared infra) lands entirely in the CLI. If the skill
duplicated any of that, every policy ruling would force a skill edit and the two would drift (the
same drift that bit a verbatim-copied kernel elsewhere in this codebase). By deferring to the CLI —
and to `kirby-node fund-key <cmd> --help` as the authoritative flag/bounds reference — the skill
stays correct across rulings **with no edit**.

## The test that keeps it honest

The skill contains **zero** policy values: no hardcoded caps, no faucet amounts, no auth rules, no
node URL, no numeric bounds. Grep proves it. And a simulated CLI-side policy change (e.g. moving the
default node or an amount bound) leaves `SKILL.md` byte-identical — the wrapper does not move when
policy moves. That is the whole point of the boundary.
