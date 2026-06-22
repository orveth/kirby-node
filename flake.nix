{
  description = "kirby-node: DKG-less Firecracker compute spike (node daemon + stub genome). Reproducible dev shell with the Rust toolchain, Firecracker plus jailer, nftables, and the host tooling the spike needs.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    # microvm.nix is the technique reference for the minimal kernel-plus-squashfs
    # microVM image the daemon boots (spec 3.6, D-7). It is pinned for
    # reproducibility; the genome image itself is built as a custom musl-init
    # squashfs (not a full NixOS guest), so this is referenced for provenance and
    # is available for later chunks that may reuse its runner helpers.
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, microvm }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Rust 1.90 stable (matches rust-toolchain.toml). 1.85+ is required by
        # the dependency tree (edition2024 in transitive deps). The musl target
        # is provisioned for the genome static build (C-2); the gnu target
        # builds the daemon.
        rustToolchain = pkgs.rust-bin.stable."1.90.0".default.override {
          targets = [ "x86_64-unknown-linux-gnu" "x86_64-unknown-linux-musl" ];
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };

        # The SAME pinned Rust 1.90 stable, but carrying the AARCH64 musl target
        # component, for the arm64 genome image (the FUTURE Apple
        # Virtualization.framework backend on Apple Silicon). The dev-shell
        # rustToolchain above only carries the x86 targets; the aarch64 image build
        # (nix/genome-image-aarch64.nix) cross-compiles the genome to
        # aarch64-unknown-linux-musl and needs that target's std, so it is supplied
        # here. The gnu build target is kept so the cross set's build-platform build
        # scripts and proc-macros compile on the host. Same toolchain version =
        # reproducible, and it does NOT change the dev shell or the x86 outputs.
        rustToolchainAarch64 = pkgs.rust-bin.stable."1.90.0".default.override {
          targets = [ "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-musl" ];
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };

        # NIGHTLY for the eBPF kernel program (C-5, spec 3.3 / D-7). The aya TC
        # egress classifier is built for the tier-3 bpfel-unknown-none target,
        # which needs build-std (nightly-only) and rust-src. The date matches
        # crates/kirby-ebpf/rust-toolchain.toml so the BPF object is reproducible
        # (gate G10). The daemon itself stays on stable 1.90; only the eBPF
        # subtree uses this, driven by the daemon's build.rs (aya-build) which
        # shells `cargo` under the nested nightly toolchain. It is on PATH in the
        # dev shell so that invocation resolves it.
        rustNightlyEbpf = pkgs.rust-bin.nightly."2025-09-01".default.override {
          # bpfel-unknown-none is a tier-3 target with no prebuilt std component;
          # it is produced by build-std (the .cargo/config.toml in the eBPF crate)
          # from rust-src, so only rust-src is required here (listing the target
          # would fail component resolution).
          extensions = [ "rust-src" ];
        };

        # The firecracker package ships firecracker, jailer, cpu-template-helper,
        # seccompiler-bin, snapshot-editor, rebase-snap in one derivation. The
        # jailer is the untrusted-genome boundary (chroot plus seccomp L2) and
        # is non-negotiable (spec D-7); it is on PATH here so no host install is
        # assumed. nftables is added the same way (the host ships only iptables).
        #
        # The STATIC (pkgsStatic) firecracker is used, not the default dynamic
        # one: the jailer chroots the firecracker binary into the jail and then
        # exec's it, so a dynamically linked firecracker fails with ENOENT (its
        # glibc loader and libs are outside the chroot). The official Firecracker
        # workflow requires a static binary for exactly this reason. The static
        # build keeps the jailer fully intact (the security boundary).
        #
        # SPLICE NOTE: a bare `pkgs.pkgsStatic.firecracker` placed directly into a
        # normal-stdenv `mkShell { packages = [...] }` is defeated by nixpkgs
        # cross-splicing: the splice machinery resolves the entry back to the
        # NATIVE (dynamic) firecracker for the shell's build platform, so a clean
        # `nix develop` would put the dynamic binary on PATH and the jailer
        # chroot-exec would fail with ENOENT. To stay splice-immune, the static
        # derivation is referenced by its build output (symlinkJoin reads it via
        # outPath, a plain store-path dependency that is never spliced) and the
        # resulting normal derivation is what goes on PATH. symlinkJoin also lands
        # firecracker, the jailer, AND snapshot-editor in ONE bin dir, which the
        # boot path needs: it resolves snapshot-editor as a sibling of the jailer.
        # Both firecracker and the jailer it execs are thus the static-musl
        # builds in the clean shell, with no manual PATH step.
        firecrackerStatic = pkgs.symlinkJoin {
          name = "firecracker-static-tools";
          paths = [ pkgs.pkgsStatic.firecracker ];
        };
        linuxHostTools = [
          firecrackerStatic
          pkgs.nftables
          pkgs.iproute2      # ip tuntap, for per-VM TAP devices (C-5)
          pkgs.util-linux    # unshare and friends, namespace inspection
          pkgs.iptables      # parity with the host; nftables is the enforcer
          pkgs.procps        # pkill, to reap the privileged eBPF meter child (C-5)
          pkgs.nostr-rs-relay # the "nerve" presence relay (slice 1); on PATH so the
                              # presence test (scripts/nerve-presence-test.sh) can run
                              # a local relay without a separate build
          pkgs.jq            # the presence test parses the `presence --json` output
        ];

        darwinHostTools = [
          pkgs.jq
        ];

        hostTools =
          if pkgs.stdenv.isLinux then linuxHostTools
          else if pkgs.stdenv.isDarwin then darwinHostTools
          else [];

        baseBuildTools = [
          rustToolchain
          pkgs.protobuf      # protoc, for tonic-build (the vsock gateway proto)
          pkgs.pkg-config
          pkgs.python3       # the cfg-gating lint (scripts/lint-macos-cfg.py), part
                             # of the Linux reference gate; stdlib-only, no deps
        ];

        linuxBuildTools = [
          # bpf-linker links the eBPF object the daemon's build.rs builds with the
          # nightly cargo (C-5, spec 3.3 / D-7). On PATH so the nightly cargo
          # invocation finds it. The nightly toolchain itself is NOT added to
          # buildTools (it would shadow the stable cargo/rustc the daemon uses);
          # build.rs invokes it by absolute path via KIRBY_EBPF_CARGO.
          pkgs.bpf-linker
        ];

        buildTools = baseBuildTools ++ pkgs.lib.optionals pkgs.stdenv.isLinux linuxBuildTools;

        # The genome image (spec 3.6): the musl-Rust genome in a read-only
        # squashfs plus the stripped 6.1 LTS guest kernel (VMGenID built-in),
        # built reproducibly so the hash is identical on every node (gate G10).
        genomeImage = import ./nix/genome-image.nix { inherit pkgs rustToolchain; };

        # The aarch64 sibling of the genome image, cross-built for the FUTURE
        # Apple Virtualization.framework (VZ) backend on Apple Silicon. Separate
        # outputs (the x86_64 Firecracker reference keeps using genomeImage). The
        # squashfs userspace is portable; only the kernel (PL011 console + GIC v3,
        # see nix/guest-kernel-aarch64.nix) and the host launcher differ, and this
        # image is BUILD-verified + reproducible here but BOOT-verified later on a
        # Mac (no VZ host on this Linux machine).
        genomeImageAarch64 = import ./nix/genome-image-aarch64.nix {
          inherit pkgs rustToolchainAarch64;
        };

        # The "nerve" (Nostr presence/discovery) relay deploy artifact (slice 1):
        # a packaged nostr-rs-relay plus an MVP config (arbitrary kinds, NIP-42
        # off) and a runner. It runs on its own box; for the local test, `nix run
        # .#relay` stands it up on 127.0.0.1:7777.
        nerveRelay = import ./nix/relay.nix { inherit pkgs; };
      in
      {
        packages = {
          genome-image = genomeImage;
          genome-kernel = genomeImage.passthru.kernel;
          genome-rootfs = genomeImage.passthru.rootfs;
          genome-bin = genomeImage.passthru.genomeBin;

          # arm64 (aarch64) variant, for the VZ backend. Mirrors the x86 output
          # set; builds and is reproducible here, boot-tested later on the Mac.
          genome-image-aarch64 = genomeImageAarch64;
          genome-kernel-aarch64 = genomeImageAarch64.passthru.kernel;
          genome-rootfs-aarch64 = genomeImageAarch64.passthru.rootfs;
          genome-bin-aarch64 = genomeImageAarch64.passthru.genomeBin;

          # The nerve presence relay (slice 1).
          relay = nerveRelay.runner;
          relay-bin = nerveRelay.relayBin;
        };

        apps.relay = {
          type = "app";
          program = "${nerveRelay.runner}/bin/kirby-relay";
        };

        devShells.default = pkgs.mkShell ({
          packages = buildTools ++ hostTools;

          # tonic-build needs protoc on PATH; make the location explicit so the
          # build does not depend on shell ordering.
          PROTOC = "${pkgs.protobuf}/bin/protoc";

          shellHook = ''
            echo "kirby-node dev shell"
            echo "  rust:        $(rustc --version)"
            if command -v firecracker >/dev/null 2>&1; then
              echo "  firecracker: $(firecracker --version 2>&1 | head -1)"
              echo "  jailer:      $(jailer --version 2>&1 | head -1)"
              echo "  nft:         $(nft --version 2>&1 | head -1)"
            fi
            echo "Run the host-prereqs gate:  cargo run -p kirby-node -- prereqs"
          '';
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # The eBPF kernel program (C-5) is built by the daemon's build.rs with
          # the nightly cargo on Linux only.
          KIRBY_EBPF_CARGO = "${rustNightlyEbpf}/bin/cargo";
          KIRBY_EBPF_BPF_LINKER_BIN = "${pkgs.bpf-linker}/bin/bpf-linker";
        });
      });
}
