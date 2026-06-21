# docs

The spec, the design records, and the macOS-backend plan for kirby-node.

## Start here

- [`../README.md`](../README.md) -- what kirby-node is (human-facing intro)
- [`../AGENTS.md`](../AGENTS.md) -- set up and run a node on Linux or macOS (the runbook)
- [`../kirby.toml.example`](../kirby.toml.example) -- the annotated `kirby run` config

## Reference (canonical)

- [`build-spec.md`](build-spec.md) -- the frozen build spec. Gates G1-G10, the decisions, the
  money-paths, and the honest boundary (what the spike does NOT prove). Everything else points here.

## Running on macOS

- [`mac-build-and-run.md`](mac-build-and-run.md) -- the verified clean-clone cold-boot
  walkthrough on Apple Silicon (Apple Virtualization backend).

## The macOS / VZ backend (design + plan)

- [`vz-build-sequence.md`](vz-build-sequence.md) -- the chunked work sequence for the VZ backend
  and its acceptance gate.
- [`vz-macos-backend-sketch.md`](vz-macos-backend-sketch.md) -- the CI verify-path options
  (self-hosted Mac runner) and the earlier work-item sketch.

## Design rationale (the why)

- [`cross-platform-sandbox.md`](cross-platform-sandbox.md) -- why a `SandboxBackend` trait, why
  Firecracker + VZ over the alternatives, why a hybrid resume strategy.
- [`vz-app-checkpoint-resume.md`](vz-app-checkpoint-resume.md) -- the portable app-checkpoint
  resume design and the two-hop liveness analysis.
