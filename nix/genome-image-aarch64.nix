# The genome image, aarch64 variant (spec 3.6, gate G1, gate G10): the musl-Rust
# stub genome in a read-only squashfs plus the stripped Linux 6.1 LTS guest
# kernel, cross-built for aarch64 for the FUTURE Apple Virtualization.framework
# (VZ) backend on Apple Silicon. It is the arm64 sibling of
# nix/genome-image.nix (the x86_64 Firecracker image); the x86_64 outputs are
# untouched, so the Firecracker reference keeps using them.
#
# The image (squashfs root + static-musl /init genome) is PORTABLE across the two
# backends: the genome only ever talks to the gateway over vsock, so the same
# userspace boots under Firecracker (x86) and under VZ (arm64). Only the kernel
# (the console/interrupt devices) and the host-side launcher differ. See
# nix/guest-kernel-aarch64.nix for the arm64-vs-x86 console (PL011 not 8250) and
# interrupt (GIC v3) decisions and their boot-test caveats.
#
# The pieces (identical shape to the x86 image, retargeted to aarch64):
#   - genomeBin: the kirby-genome crate built as a static aarch64 musl binary
#     (no glibc, no interpreter), stripped. A pure function of the sources and the
#     pinned toolchain, so it is reproducible.
#   - rootfs.squashfs: a read-only squashfs whose only payload is the genome at
#     /init. Built with the SAME deterministic mksquashfs flags as x86 so the
#     bytes (and thus the hash) are stable.
#   - vmlinux: the arm64 guest kernel (nix/guest-kernel-aarch64.nix), VMGenID
#     built-in, stripped.
#   - the default output bundles vmlinux plus rootfs.squashfs plus a manifest.
#
# rustToolchainAarch64 is a rust-overlay toolchain that carries the
# aarch64-unknown-linux-musl target component (the dev-shell rustToolchain only
# carries the x86 targets); the flake provisions it and passes it in.
{ pkgs, rustToolchainAarch64 }:
let
  inherit (pkgs) lib;

  muslTarget = "aarch64-unknown-linux-musl";

  # The genome does NOT depend on the CDK ecash stack (that is the host daemon's
  # C-6 brokered rail). The cdk crates now come from the crates.io registry
  # (cashubtc/cdk 0.17.x); since the genome's closure is cdk-free, prune the
  # cdk/cashu packages (and their dangling references from the host-daemon package
  # block) from a build-time copy of the lock, matched by PACKAGE NAME (the
  # registry source string is shared by every crate). IDENTICAL logic to the x86
  # genome-image.nix prune (the workspace lock is shared); only the cdk-free genome
  # + kirby-proto subgraph is compiled here.
  prunedCargoLock = pkgs.runCommand "kirby-genome-pruned-cargo-aarch64.lock" { } ''
    ${pkgs.gawk}/bin/awk '
      BEGIN { RS = "\n\n"; ORS = "\n\n" }
      {
        # Drop every [[package]] block for a cdk/cashu crate (the ecash stack the
        # genome never uses): name = "cdk", "cdk-...", "cashu", or "cashu-...".
        if ($0 ~ /\nname = "(cdk|cashu)(-[a-z0-9-]+)?"\n/ || $0 ~ /^name = "(cdk|cashu)(-[a-z0-9-]+)?"\n/) next
        block = $0
        # In the kirby-node host-daemon block, drop the now-dangling cdk/cashu
        # dependency lines so the lock has no references to the pruned packages.
        if (block ~ /name = "kirby-node"/) {
          n = split(block, lines, "\n")
          block = ""
          for (i = 1; i <= n; i++) {
            if (lines[i] ~ /^ "(cdk|cashu)/) continue
            block = block (block == "" ? "" : "\n") lines[i]
          }
        }
        print block
      }
    ' ${../Cargo.lock} > "$out"
  '';

  # Cross-build the genome for static aarch64 musl. pkgsCross.aarch64-multiplatform-musl
  # sets buildPlatform = x86_64 gnu (so build scripts and proc-macros run on the
  # host with glibc, avoiding the static-build-script SIGSEGV) and hostPlatform =
  # aarch64 musl (so the genome binary itself is fully static, no glibc, no
  # interpreter, spec 3.6). This mirrors the x86 image's use of pkgsCross.musl64,
  # just retargeted to aarch64. The rust-overlay toolchain (pinned) supplies cargo
  # and rustc with the aarch64-musl target component, keeping the binary reproducible.
  muslPkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
  muslRustPlatform = muslPkgs.makeRustPlatform {
    cargo = rustToolchainAarch64;
    rustc = rustToolchainAarch64;
  };

  # The binutils for the aarch64 cross (the musl cross set, consistent with the
  # genome). The image-bundle below runs objcopy on the guest vmlinux, which is an
  # aarch64 ELF, so it MUST use the aarch64-targeting objcopy: the host (x86_64)
  # binutils objcopy is single-target and rejects an aarch64 ELF ("Unable to
  # recognise the format of the input file"). This is the one place the arm64 image
  # build needs a target-aware tool the x86 image got from the plain host binutils.
  aarch64Bintools = muslPkgs.stdenv.cc.bintools.bintools;
  # objcopy -O binary turns the vmlinux ELF into a raw arm64 `Image`: the PT_LOAD
  # segments laid out by paddr into a flat binary, dropping the non-loadable
  # debug/symbol sections. This is the exact transform the VZ backend used to do at
  # boot, moved to build time so the shipped image is ready-to-boot.
  aarch64Objcopy = "${aarch64Bintools}/bin/${muslPkgs.stdenv.cc.targetPrefix}objcopy";

  # The whole workspace is the source (the genome depends on kirby-proto). Filter
  # to the inputs that affect the build so unrelated edits do not change the
  # hash. The proto build needs protoc at build time. Identical to the x86 image.
  workspaceSrc = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let rel = lib.removePrefix (toString ../. + "/") (toString path);
      in
      rel == "Cargo.toml"
      || rel == "Cargo.lock"
      || rel == "crates"
      || lib.hasPrefix "crates/" rel;
  };

  genomeBin = muslRustPlatform.buildRustPackage {
    pname = "kirby-genome-aarch64";
    version = "0.1.0";
    src = workspaceSrc;
    # The cdk-free pruned lock (see prunedCargoLock above): the genome's closure has
    # no cdk deps, so the image builds against a lock with the CDK git packages
    # removed, sidestepping the importCargoLock bare-rev fetch limitation.
    cargoLock.lockFile = prunedCargoLock;
    # Swap in the pruned lock AND drop the host daemon (kirby-node) from the
    # workspace so cargo never tries to RESOLVE its cdk git deps (offline) when
    # building only the genome (the genome + kirby-proto are a cdk-free subgraph).
    postPatch = ''
      cp ${prunedCargoLock} Cargo.lock
      # Remove the kirby-node member line from the workspace members list.
      ${pkgs.gnused}/bin/sed -i '/"crates\/kirby-node",/d' Cargo.toml
      # Remove the cdk/cashu/bip39 workspace.dependencies lines (the host daemon's,
      # not the genome's) so cargo does not try to fetch them offline.
      ${pkgs.gnused}/bin/sed -i '/^cdk\( \|-\)/d;/^cashu /d' Cargo.toml
    '';

    # Build only the genome crate (the daemon is host-side, built by cargo, not
    # in the image).
    buildAndTestSubdir = "crates/kirby-genome";
    # The genome has no tests of its own and the integration tests need the host
    # target plus a vsock; the image build only needs the binary.
    doCheck = false;

    nativeBuildInputs = [ pkgs.protobuf ];
    PROTOC = "${pkgs.protobuf}/bin/protoc";

    # Force a FULLY static binary: +crt-static statically links the C runtime AND
    # libgcc, so the genome has NO dynamic dependencies (nixpkgs' cross-musl
    # otherwise dynamically links libgcc_s, which a microVM init off a read-only
    # root with no shared libraries could not load). Strip symbols for a smaller
    # image. Scoped to the AARCH64 musl target (note the env var name is the
    # aarch64 triple, not x86) so the host build platform is unaffected.
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static -C strip=symbols";

    # cargoBuildHook builds into the aarch64-musl target dir; install from there.
    installPhase = ''
      runHook preInstall
      install -Dm755 \
        "target/${muslTarget}/release/kirby-genome" \
        "$out/bin/kirby-genome"
      runHook postInstall
    '';

    meta.description = "kirby stub genome, static aarch64 musl, the microVM init (VZ backend)";
  };

  kernel = import ./guest-kernel-aarch64.nix { inherit pkgs; };

  # The read-only squashfs rootfs. The genome is /init (PID 1 off the read-only
  # root). mksquashfs is driven with the SAME deterministic flags as the x86
  # image so the image is content-addressed (gate G10):
  #   -all-root        every file owned by root:root (no build-user uid leak)
  #   -no-xattrs       no extended attributes (none are needed, and they vary)
  #   -comp xz         matches the kernel's built-in SQUASHFS_XZ decompressor
  # Timestamps are pinned by the nix-provided SOURCE_DATE_EPOCH (mksquashfs honors
  # it), so the explicit time flags are omitted (mksquashfs refuses both at once).
  # NOTE: the squashfs payload is the aarch64 genome binary, so the bytes (and the
  # hash) differ from the x86 rootfs; only the BUILD is deterministic/identical.
  rootfs = pkgs.runCommand "kirby-genome-rootfs-aarch64.squashfs"
    {
      nativeBuildInputs = [ pkgs.squashfsTools ];
    }
    ''
      root=$(mktemp -d)
      mkdir -p "$root"
      # The genome is the init process: install it at /init.
      install -Dm755 ${genomeBin}/bin/kirby-genome "$root/init"
      # Mount points the genome mounts as PID 1 (no init system in the image):
      # /proc and /sys are mounted by the genome, /dev is auto-mounted by the
      # kernel (CONFIG_DEVTMPFS_MOUNT). Empty dirs in the read-only squashfs.
      mkdir -p "$root/proc" "$root/sys" "$root/dev"

      mksquashfs "$root" "$out" \
        -all-root \
        -no-xattrs \
        -comp xz \
        -noappend \
        -no-progress
    '';

  # The source kernel is the uncompressed vmlinux ELF from the kernel's dev output
  # (nixpkgs installs it for every arch when CONFIG_MODULES=y, build.nix
  # `cp vmlinux $dev/`; module support stays enabled, see the kernel file, so this
  # path exists on aarch64 exactly as on x86). The image-bundle below does NOT ship
  # this ELF: VZLinuxBootLoader (and Firecracker-aarch64) boot a raw arm64 `Image`,
  # so the bundle runs objcopy -O binary to export the raw Image directly (which
  # also drops the debug/symbol sections, so the result is small). The bundle file
  # is still named `vmlinux` (the daemon reads that fixed filename), but its content
  # is now the raw Image, not the ELF, so the VZ backend's at-boot ELF-to-raw
  # conversion no-ops (the bytes are already raw).
  vmlinux = "${kernel.dev}/vmlinux";

in
pkgs.runCommand "kirby-genome-image-aarch64"
  {
    nativeBuildInputs = [ aarch64Bintools ];
    passthru = { inherit genomeBin rootfs kernel; vmlinuxPath = vmlinux; };
  }
  ''
    mkdir -p "$out"
    # Export the guest kernel as a raw arm64 `Image` (NOT the ELF): objcopy -O
    # binary lays the PT_LOAD segments out by paddr into a flat binary, dropping
    # non-loadable debug/symbol sections. The result is the bytes VZLinuxBootLoader
    # / Firecracker-aarch64 boot directly, so the daemon does no at-boot conversion.
    # The AARCH64 cross objcopy is used (the host x86_64 objcopy rejects an aarch64
    # ELF); it is provided on nativeBuildInputs above. The output file keeps the
    # name `vmlinux` (the daemon reads that fixed filename) though its content is
    # now the raw Image.
    ${aarch64Objcopy} -O binary ${vmlinux} "$out/vmlinux"
    cp ${rootfs} "$out/rootfs.squashfs"
    # The copy inherits the read-only mode of the nix-store source, so make it
    # writable for the pad below (nix re-seals the store path read-only afterward).
    chmod u+w "$out/rootfs.squashfs"
    # VZ's disk attachment requires the rootfs file size to be a multiple of the
    # 512-byte block size; pad it up here (squashfs records its real size in the
    # superblock and ignores the zero tail) so the daemon does no at-boot padding.
    truncate -s %512 "$out/rootfs.squashfs"

    # A manifest the daemon reads to locate the boot artifacts without hardcoding
    # nix store paths. Plain key=value lines, no timestamps, so it stays
    # reproducible. `arch` is added so the daemon/VZ launcher can assert it is
    # booting the arm64 image (the x86 manifest has no arch line; a consumer that
    # wants to distinguish keys off this).
    {
      echo "vmlinux=$out/vmlinux"
      echo "rootfs=$out/rootfs.squashfs"
      echo "kernel_version=${kernel.version}"
      echo "arch=aarch64"
    } > "$out/manifest.env"
  ''
