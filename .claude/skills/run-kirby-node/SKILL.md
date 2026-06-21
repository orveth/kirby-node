---
name: run-kirby-node
description: Set up and run a kirby node from this repo. Use when the user wants to run, start, launch, boot, or stand up a kirby node or sovereign agent, check whether their host (Linux or macOS) can host one, fill in kirby.toml, or build the genome image. Walks host prereqs, the Nix dev shell, the build, the config, and the `kirby run` command.
---

# Running a kirby node

The user wants a kirby node running. The authoritative runbook is [`AGENTS.md`](../../../AGENTS.md)
at the repo root. **Read it now** -- it has the exact requirements, config keys, commands, and
gotchas for both Linux and macOS. This skill is the interactive walkthrough on top of it.

## Set expectations first (say this up front)

- kirby-node is a **play-money spike**, not a product. No real keys, no mainnet, no FROST.
- The run path is **one command**: `kirby-node agent --config kirby.toml` (`kirby run`). It runs
  one **sovereign** agent joined to a Nostr fleet, not a Raft cluster.
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

7. **Verify it's alive.** It publishes presence to the relay and emits a `9100` born event.
   Confirm with `cargo run -p kirby-node -- presence --relay-url <url>`. Start a local relay for
   testing with `nix run .#relay`.

## When you finish

Report honestly against the boundary in `AGENTS.md` ("What this spike does NOT prove"): it's
play-money, one sovereign node (multi-node failover is a showcase, not this command), no real
custody. Don't overclaim.
