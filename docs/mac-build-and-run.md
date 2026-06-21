# macOS Build And Run

This is the Mac half of the cold-boot milestone: build `kirby-node` from a clean
clone, point it at a prebuilt `aarch64-linux` genome image, and prove G1 on the
Apple Virtualization.framework backend.

The Linux image build and `kirby run` configuration wiring are owned separately by
keeper:kirby. Do not try to build the `aarch64-linux` genome image on a Mac unless
you have configured a Linux builder.

## Verified Host

This procedure was verified from a clean clone of public `main`
`a1e2fe4b9d2a72ca9926489f9b11f4b9a58a1f8d`.

Observed host and toolchain:

| Item | Observed value |
| --- | --- |
| Hardware | Apple M4 Max, arm64 |
| macOS | 26.2, build 25C56 |
| Xcode | 26.2, build 17C52 |
| Active developer dir | `/Applications/Xcode-26.2.0.app/Contents/Developer` |
| Swift | Apple Swift 6.2.3, target `arm64-apple-macosx26.0` |
| Clang | Apple clang 17.0.0 |
| Nix | 2.24.10 |
| Rust in `nix develop` | `rustc 1.90.0`, `cargo 1.90.0` |
| Protobuf in `nix develop` | `libprotoc 34.1` |
| pkg-config in `nix develop` | 0.29.2 |
| Git | 2.53.0 |
| GitHub CLI | 2.89.0 |

Not already present in the bare shell on the audit machine:

- `cargo`, `rustc`, and `rustup` were not available before entering `nix develop`.
- Homebrew was not installed and was not needed.
- `qemu-system-aarch64` was not installed and was not needed for VZ cold boot.

## Prerequisites

Install:

- Apple Silicon Mac. The current Mac MVP targets `aarch64` only.
- macOS with `Virtualization.framework`.
- Xcode or Xcode Command Line Tools that provide `xcrun`, `swiftc`, and `codesign`.
- Nix with flakes enabled.
- Git.

No Homebrew packages are required for the verified G1 path.

The Rust toolchain, `protoc`, `pkg-config`, and `jq` are provided by the repo dev
shell:

```bash
nix develop
```

Run the host gate:

```bash
nix develop -c cargo run -p kirby-node -- prereqs
```

Expected shape:

```text
RESULT: PASS (6 checks, 1 warn) host is spike-ready
```

The warning is currently the login keychain note. See "Machine-Specific
Assumptions And Open Items" below.

## Clone And Build

Clone the repo:

```bash
git clone https://github.com/orveth/kirby-node.git
cd kirby-node
```

Build the whole workspace:

```bash
nix develop -c cargo build --workspace
```

Verified result on the audit Mac:

```text
Finished `dev` profile [unoptimized + debuginfo] target(s)
```

## Obtain The Genome Image

The Mac VZ backend needs a prebuilt `aarch64-linux` genome image directory with:

```text
vmlinux
rootfs.squashfs
manifest.env
```

Placeholder until keeper:kirby publishes the artifact:

```text
prebuilt URL TBD from keeper:kirby
```

After download, unpack it somewhere local and export:

```bash
export KIRBY_GENOME_IMAGE=/absolute/path/to/kirby-genome-image-aarch64
```

Do not commit this path. It is machine-specific.

For the audit run, the image came from the prior VZ proof handoff:

```text
/Users/claude/.buzz/.scratch/q8daajcjf75k1ppgnimwdkjl0dhn3a77-kirby-genome-image-aarch64
```

That path is not portable and is listed only as evidence of what was tested.

## Run G1 Cold Boot

From the repo:

```bash
KIRBY_GENOME_IMAGE=/absolute/path/to/kirby-genome-image-aarch64 \
  nix develop -c cargo run -p kirby-node -- boot \
    --node-id mac-g1 \
    --task mac-g1 \
    --vsock-cid 61 \
    --vsock-port 5061 \
    --hello-timeout-secs 40
```

Expected evidence line:

```text
G1 PASS: VM Running=true ; GetSessionContext round-trip ; hello event detail="session=mac-g1" ; budget_sats=1000000
```

Verified audit command:

```bash
KIRBY_GENOME_IMAGE=/Users/claude/.buzz/.scratch/q8daajcjf75k1ppgnimwdkjl0dhn3a77-kirby-genome-image-aarch64 \
  nix develop -c cargo run -p kirby-node -- boot \
    --node-id mac-doc-g1-1782014735 \
    --task mac-doc-g1 \
    --vsock-cid 61 \
    --vsock-port 5061 \
    --hello-timeout-secs 40
```

Verified result:

```text
G1 PASS: VM Running=true ; GetSessionContext round-trip ; hello event detail="session=mac-doc-g1" ; budget_sats=1000000
```

The boot log also showed `backend="vz"`, `KIRBY_VZ_READY`, and a VZ helper exit
status of 0 after daemon-initiated halt.

## Machine-Specific Assumptions And Open Items

- **Apple Silicon only:** The Mac path currently requires `target_arch = aarch64`.
  Intel Macs are not supported for this milestone.
- **Xcode selection:** The build uses `/usr/bin/xcrun` to find `swiftc` and the
  matching macOS SDK. A teammate with multiple Xcodes must select a working Xcode
  with `xcode-select`.
- **Standard macOS tool paths:** `build.rs` invokes `/usr/bin/xcrun` and
  `/usr/bin/codesign`. These are standard macOS paths, not dev-box paths.
- **VZ helper signing:** The helper is ad-hoc signed at build time with
  `com.apple.security.virtualization` from
  `crates/kirby-node/src/vz_helper.entitlements`. No Developer ID certificate,
  provisioning profile, key, or secret is stored in the repo.
- **vmnet entitlement:** G1 cold boot and the current G5 no-NIC shape do not attach
  a guest network device, so they do not use the vmnet entitlement. Future G4
  egress lockdown with a bridged or raw vmnet attachment remains an open item for
  keeper:kirby. That work must decide whether to use managed NAT with less direct
  data-plane control, or vmnet/pf with the required entitlement/signing path.
- **Keychain behavior:** The prereq gate warns but does not probe the login
  keychain. If the helper fails with Security Server interaction errors, unlock the
  login keychain before running. This is documented from the macOS 15 class of
  failures; this audit booted successfully on macOS 26.2 without additional
  keychain steps.
- **macOS version:** The audited version is macOS 26.2. The code does not pin to
  macOS 26, but this document does not prove older macOS versions. Keep the
  prereq output in PR evidence for each Mac.
- **Genome image distribution:** The image path is intentionally external. The
  stable distribution URL, checksum, and unpack instructions are still owned by
  keeper:kirby.
- **Temporary files:** The VZ backend creates per-run sockets and converted kernel
  or padded rootfs files under `/tmp` with process, node, and port in the name.
  They are not user-specific and are removed on normal halt.
- **Metering service pid:** The VZ backend discovers Apple
  `com.apple.Virtualization.VirtualMachine` service pids for host-process metering.
  G1 does not depend on metering, but metered Mac runs fail closed if required pid
  discovery is unavailable.

## Linux Reference Gate

This doc-only Mac PR still comes from a shared repository. Before merge, run the
Linux reference gate on a Linux host:

```bash
cargo check -p kirby-node --lib && cargo check -p kirby-node --bin kirby-node \
 && cargo clippy -p kirby-node --all-targets -- -D warnings \
 && cargo test -p kirby-node --tests --no-run
```

If it cannot be run from the Mac authoring environment, leave the PR marked with
that fact so keeper:kirby can run it pre-merge.
