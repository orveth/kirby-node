---
name: run-kirby-node
description: Set up and run a kirby node from this repo. Use when the user wants to run, start, launch, boot, or stand up a kirby node or sovereign agent, check whether their host (Linux or macOS) can host one, fill in kirby.toml, or build the genome image. Walks host prereqs, the Nix dev shell, the build, the config, and the `kirby-node agent` (one agent) and `kirby-node fleet` (the node) commands.
---

# Running a kirby node

The user wants a kirby node running. The authoritative runbook is [`AGENTS.md`](../../../AGENTS.md)
at the repo root. **Read it now** -- it has the exact requirements, config keys, commands, and
gotchas for both Linux and macOS. This skill is the interactive walkthrough on top of it.

## Set expectations first (say this up front)

- **node != agent.** A *node* joins the network (`kirby-node fleet --config kirby.toml`) and hosts
  agents; an *agent* is one sovereign Kirby that runs on top. `kirby-node agent --config kirby.toml`
  runs ONE agent end to end -- the fastest way to see the loop -- but the node you deploy is
  `kirby-node fleet`. (The actual command is `kirby-node agent`; the bare `kirby-node run` is a
  separate legacy boot demo, not the agent run.)
- **Sovereignty is real; the money is play-money ecash.** Each agent signs its public voice under a
  real 2-of-3 **FROST** key Q (the three shares are co-located on one host today; cross-machine
  distribution is the roadmap). The metabolism is ecash only -- no on-chain Bitcoin.
- It runs on **Linux** (Firecracker) and **Apple Silicon macOS** (Apple Virtualization);
  `backend = "auto"` in the config picks the right one.

## Walk the user through it

1. **Identify the platform.** Linux and Apple Silicon macOS are both supported; the prereqs and
   the genome-image step differ. macOS is aarch64 only.

2. **Enter the dev shell and build.**
   ```sh
   nix develop
   cargo build --workspace
   ```

3. **Prove the host** before anything else:
   ```sh
   cargo run -p kirby-node -- prereqs
   ```
   On Linux, a FAIL is almost always **jailer privilege** -- the daemon launches the Firecracker
   jailer through passwordless `sudo`. Fix it (passwordless sudoers rule, root, or `CAP_SYS_ADMIN`)
   and re-run. On macOS, expect `PASS (… 1 warn)`; the warn is the login-keychain note. Do not
   continue until prereqs passes.

4. **Get the genome image.** On Linux, build it:
   ```sh
   nix build --no-link --print-out-paths .#genome-image          # x86_64
   nix build --no-link --print-out-paths .#genome-image-aarch64  # arm64, for macOS
   ```
   On macOS you cannot build the Linux image; get the prebuilt aarch64 image and unpack it
   locally (see `AGENTS.md`).

5. **Fill in the config:**
   ```sh
   cp kirby.toml.example kirby.toml
   ```
   Help them edit the three fields that matter: `genome_image` (the image dir from step 4),
   `[identity] key_path`, and `[relay] url`. Leave `backend = "auto"`, `workload =
   "app-checkpoint"`, and `mode = "bootstrap"` (use `resume` only to restore an existing agent).

6. **Run it:**
   ```sh
   cargo run -p kirby-node -- agent --config kirby.toml
   ```

7. **Verify it's alive.** A single agent surfaces as a `9100` born log + live `31000` agent-state
   (under its npub), ending in a `9100` died -- watch the logs for `genome boot hello received`
   then `published 9100 lifecycle event ... event=born`, and the final `KIRBY-RUN ...
   reached_running=true born=true` line on stdout. Note a bare agent does NOT beacon node presence
   (`10100`), so `presence` will not show it -- that read path shows fleet *nodes*. Start a local
   relay for testing with `nix run .#relay`.

8. **To run a node (not just one agent):** `cargo run -p kirby-node -- fleet --config kirby.toml`
   joins the network (beacons `10100`), hosts agents, and runs the spawn control plane. Confirm it
   with `cargo run -p kirby-node -- presence --relay-url <url>` (a node DOES show up). Warn the user:
   an empty `[fleet.spawn] operators` allowlist means any signer may spawn on their node.

## When you finish

Report honestly against the boundary in `AGENTS.md` and [`../../../CLAUDE.md`](../../../CLAUDE.md):
the FROST custody is real but the three shares are co-located on one host today (so don't claim "a
key no human holds" yet), the metabolism is play-money ecash (no on-chain Bitcoin), and live
cross-node failover is roadmap (the lease/fence is wired, autonomous respawn-elsewhere is not).
Don't overclaim.
