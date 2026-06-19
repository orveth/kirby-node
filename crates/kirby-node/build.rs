//! Build the kernel-side eBPF egress-byte classifier (C-5, spec 3.3, D-7).
//!
//! The daemon embeds a compiled BPF object (the `kirby-ebpf` crate, built for
//! bpfel-unknown-none) so the eBPF program travels inside the daemon binary and
//! is reproducible (gate G10). That crate needs a NIGHTLY toolchain (the BPF
//! target is tier 3 and needs build-std), while the daemon stays on stable. So
//! this build.rs invokes the nightly cargo by ABSOLUTE PATH (no rustup in nix):
//! the flake hands us `KIRBY_EBPF_CARGO` (the nightly cargo) and bpf-linker on
//! PATH. We build `kirby-ebpf` into OUT_DIR and the daemon `include_bytes!`s the
//! resulting object via `KIRBY_EGRESS_BPF_OBJECT` (set below).
//!
//! If `KIRBY_EBPF_CARGO` is unset (a non-nix build), we fall back to
//! `cargo +nightly-2025-09-01` (rustup), matching the eBPF crate's
//! rust-toolchain.toml. If neither is available the build fails LOUDLY with the
//! exact missing piece (the eBPF egress meter is part of the C-5 contract, so a
//! daemon that silently shipped without it would be wrong).

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        println!("cargo:rerun-if-env-changed=KIRBY_EBPF_CARGO");
        return;
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // crates/kirby-node -> crates/kirby-ebpf
    let ebpf_dir = manifest_dir
        .parent()
        .expect("crates dir")
        .join("kirby-ebpf");

    // Rebuild the embedded object if the eBPF source or its manifest changes.
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join(".cargo/config.toml").display()
    );
    println!("cargo:rerun-if-env-changed=KIRBY_EBPF_CARGO");

    // A per-crate target dir under OUT_DIR (cargo flocks its own target dir;
    // keeping the eBPF build separate avoids a self-flock against the daemon
    // build, the aya-build cargo#6412 workaround).
    let ebpf_target = out_dir.join("kirby-ebpf-target");

    let (cargo, rustc): (String, Option<String>) = match std::env::var("KIRBY_EBPF_CARGO") {
        Ok(nightly_cargo) => {
            // The sibling nightly rustc: cargo resolves rustc from PATH otherwise
            // (where stable is primary in the dev shell), so pin it explicitly.
            let rustc = Path::new(&nightly_cargo)
                .parent()
                .map(|d| d.join("rustc").display().to_string());
            (nightly_cargo, rustc)
        }
        Err(_) => {
            // Non-nix fallback: rustup's `cargo +<toolchain>`. The eBPF crate's
            // rust-toolchain.toml already selects the channel, so a plain `cargo`
            // run inside that dir would also pick nightly via rustup; we use the
            // explicit toolchain arg to be unambiguous.
            ("cargo".to_string(), None)
        }
    };

    let mut cmd = Command::new(&cargo);
    cmd.current_dir(&ebpf_dir);
    // Clear inherited cargo state that would otherwise force the daemon's
    // (stable) toolchain or wrapper onto the eBPF build.
    cmd.env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS");
    if std::env::var("KIRBY_EBPF_CARGO").is_err() {
        // rustup path: select the nightly toolchain explicitly.
        cmd.arg("+nightly-2025-09-01");
    }
    if let Some(rustc) = &rustc {
        cmd.env("RUSTC", rustc);
    }
    cmd.args(["build", "--release"]);
    cmd.arg("--target-dir").arg(&ebpf_target);

    let status = cmd.status().unwrap_or_else(|e| {
        panic!(
            "failed to invoke the eBPF build ({cargo}) for the egress meter (C-5): {e}. \
             Enter `nix develop` (it sets KIRBY_EBPF_CARGO + bpf-linker), or install rustup with \
             the nightly-2025-09-01 toolchain + rust-src + bpf-linker."
        )
    });
    assert!(
        status.success(),
        "the eBPF egress classifier (crates/kirby-ebpf) failed to build (C-5, spec 3.3). \
         The daemon needs this object embedded; refusing to build a daemon without its \
         egress meter. Check bpf-linker is on PATH and the nightly toolchain has rust-src."
    );

    let object = ebpf_target.join("bpfel-unknown-none/release/kirby-egress");
    assert!(
        object.is_file(),
        "the eBPF build reported success but produced no object at {} (C-5)",
        object.display()
    );

    // Hand the daemon the object path for include_bytes!.
    println!(
        "cargo:rustc-env=KIRBY_EGRESS_BPF_OBJECT={}",
        object.display()
    );
}
