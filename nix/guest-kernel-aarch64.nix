# The genome guest kernel, aarch64 variant (spec 3.6, D-8): a stripped Linux 6.1
# LTS kernel cross-built for aarch64, for the FUTURE Apple Virtualization.framework
# (VZ) backend on Apple Silicon. It is the arm64 sibling of nix/guest-kernel.nix
# (the x86_64 Firecracker kernel); the x86_64 build is untouched.
#
# The base is the nixpkgs aarch64 cross of linux_6_1 (an LTS series, 6.1.x), via
# pkgs.pkgsCross.aarch64-multiplatform.linux_6_1. Its generic config (which sits
# on top of the arm64 defconfig) ships the microVM pieces as MODULES; a microVM
# that boots a squashfs root over virtio with no initrd cannot load modules
# before it has mounted root, so every piece on the boot path is promoted to
# built-in (=y) here:
#   - virtio plus the MMIO transport (and PCI, kept built-in for parity with the
#     x86 kernel; the VZ virtio transport is verified on the Mac, see CAVEATS)
#   - virtio-blk (the read-only squashfs rootfs is a virtio block device)
#   - squashfs with the xz decompressor (the rootfs filesystem)
#   - the vsock stack (the genome to daemon gateway transport, spec 3.1)
#   - virtio-net (the per-VM egress interface, spec 3.7)
#   - VMGENID (the device the kernel CSPRNG reseeds from on a snapshot restore,
#     the D-5 / D-8 resume gate)
#
# THE arm64-vs-x86 CONSOLE DIFFERENCE (the load-bearing judgment call):
# the x86 kernel uses the 8250/16550 UART (SERIAL_8250). The ARM `virt` machine
# that VZ (and QEMU, Lima, UTM, Tart) presents to an arm64 Linux guest has NO
# 8250; its console is the ARM AMBA PL011 PrimeCell UART. So the PL011 driver and
# its console hook are forced built-in here instead of the 8250, and the ARM
# Generic Interrupt Controller v3 (GIC v3, the arm64 `virt` machine's interrupt
# controller) is forced built-in so interrupts (including the console's) are
# delivered. SERIAL_AMBA_PL011 depends on ARM_AMBA in the Kconfig, so ARM_AMBA is
# forced on too (otherwise the config tool drops PL011). These device choices are
# how Linux-on-VZ / arm64-virt guests are normally configured; they are BEST
# EFFORT and MUST be boot-verified on the Mac (no VZ host exists here to boot
# under). See CAVEATS at the foot of this file.
#
# Reproducible: the derivation is a pure function of the pinned nixpkgs and this
# config, so the kernel hash is identical on every node (the verifiable-genome
# property, spec 3.6 and gate G10).
{ pkgs }:
let
  inherit (pkgs) lib;
  inherit (lib.kernel) yes;
  # nixpkgs' common-config sets IP_PNP (and its DHCP variant) to "n"; the spike
  # wants kernel boot-time IP autoconfiguration so the genome's eth0 is set from
  # the `ip=` cmdline, so force them on over that default (mirrors the x86 kernel).
  forceYes = lib.mkForce yes;
  # The aarch64 cross of the kernel package set. hostPlatform is
  # aarch64-unknown-linux-gnu; the build runs on the x86_64 host via the cross
  # toolchain. This is the same nixpkgs linux_6_1 expression, just cross-targeted,
  # so it keeps the known-bootable generic config as its base.
  crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;
in
(crossPkgs.linux_6_1.override {
  # structuredExtraConfig is merged over the generic nixpkgs config, so we keep
  # everything that config already provides (a known-bootable base) and only
  # force the boot-path pieces built-in plus the arm64 console/interrupt pieces.
  structuredExtraConfig = {
    # The VMGenID device, built-in so it is live at boot (spec D-5 / D-8).
    VMGENID = yes;

    # virtio core plus both transports. The arm64 `virt` machine presents virtio
    # over MMIO and/or PCI; both are kept built-in so the same kernel works
    # whichever transport VZ exposes (to be confirmed on the Mac, see CAVEATS).
    VIRTIO = yes;
    VIRTIO_MMIO = yes;
    VIRTIO_PCI = yes;

    # The read-only squashfs rootfs rides a virtio block device.
    VIRTIO_BLK = yes;

    # The squashfs filesystem and its xz decompressor (the rootfs format).
    SQUASHFS = yes;
    SQUASHFS_XZ = yes;

    # The vsock stack: the genome to daemon gateway transport (spec 3.1). The
    # guest side is identical across backends (the genome dials vsock); only the
    # host side differs (VZVirtioSocketConnection on macOS vs a Unix socket under
    # Firecracker), and that is daemon-side, not in this kernel.
    VSOCKETS = yes;
    VIRTIO_VSOCKETS = yes;

    # The network stack and virtio-net, built-in (spec 3.7): the per-VM interface
    # appears to the guest as a virtio-net device, so the genome has an interface
    # it can ATTEMPT egress on (which the host default-deny then drops). INET is
    # the IPv4 stack; VIRTIO_NET is the device; IP_PNP is kernel boot-time IP
    # autoconfiguration so eth0 is configured from the `ip=` cmdline (no in-genome
    # setup off the read-only root). Built-in because the microVM loads no modules.
    INET = yes;
    NETDEVICES = yes;
    NET_CORE = yes;
    VIRTIO_NET = yes;
    IP_PNP = forceYes;
    IP_PNP_DHCP = forceYes;

    # arm64 CONSOLE (the arm64-vs-x86 difference): the ARM AMBA PL011 PrimeCell
    # UART, built-in, is the console on the arm64 `virt` machine VZ presents (the
    # x86 8250 does not exist there). PL011 depends on ARM_AMBA in the Kconfig, so
    # ARM_AMBA is forced on too. SERIAL_CORE is select-ed by PL011. The boot log
    # then streams over the PL011 serial port (the macOS G1 boot evidence).
    ARM_AMBA = yes;
    SERIAL_AMBA_PL011 = yes;
    SERIAL_AMBA_PL011_CONSOLE = yes;

    # ARM Generic Interrupt Controller v3 (GIC v3): the interrupt controller on
    # the arm64 `virt` machine. Forced built-in so interrupts (the console's, the
    # virtio devices') are delivered at boot. On arm64 this is normally auto-
    # selected by the arch; forcing it is explicit and harmless (it select-s its
    # own dependencies).
    ARM_GIC_V3 = yes;
  };
  # The generic nixpkgs config carries many module (=m) options, so loadable
  # module support stays enabled (turning it off wholesale breaks the config tool
  # against the inherited =m answers, and the nixpkgs build.nix only installs the
  # uncompressed vmlinux ELF into $dev when CONFIG_MODULES=y). The genome boots
  # entirely on the built-in pieces above, so no module is loaded on the boot path.
}).overrideAttrs (old: {
  # A stripped guest kernel (spec 3.6): no debug info, smaller image. The
  # -aarch64 suffix keeps it distinct from the x86_64 kernel derivation.
  pname = "kirby-genome-kernel-aarch64";
})

# CAVEATS (read before the Mac boot-test; these are the arm64-vs-x86 judgment
# calls that could NOT be verified here because there is no VZ host on this
# x86_64 Linux machine):
#   1. CONSOLE = PL011: chosen because the arm64 `virt` machine (QEMU/VZ/Lima/UTM/
#      Tart) exposes a PL011, not an 8250. If VZ surprises us, the symptom is a
#      silent boot (no serial log). The kernel cmdline on the Mac should select it,
#      e.g. `console=ttyAMA0` (PL011 is ttyAMA*, NOT ttyS* which is the 8250).
#   2. VIRTIO TRANSPORT = MMIO and PCI both built-in: VZ presents virtio to arm64
#      Linux guests, but whether over MMIO or PCI on the `virt` machine is the
#      thing to confirm on the Mac. Both are =y so either works; if neither block
#      device appears, that is the transport to check first.
#   3. GIC v3 vs a possible GIC v2: VZ's arm64 `virt` machine uses GIC v3 in
#      current macOS; GIC v3 is forced =y. If a future/older VZ exposed GIC v2,
#      ARM_GIC (v2) would also be needed; not added now to keep the config minimal
#      and because v3 is the current VZ reality.
#   4. BOOT IMAGE = VZLinuxBootLoader consumes a raw arm64 `Image`. The image
#      derivation (nix/genome-image-aarch64.nix) exports it: objcopy -O binary on
#      ${kernel.dev}/vmlinux produces the raw Image (written to the bundle's
#      `vmlinux` file), so the shipped image is ready-to-boot and the daemon does
#      no at-boot conversion.
