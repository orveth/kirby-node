//! The host-prerequisites gate (spec 5 and 11, the C-1 definition-of-done).
//!
//! The spike needs a Linux host with KVM, cgroup v2, nftables, vsock
//! (/dev/vhost-vsock), and the ability to run the Firecracker jailer (root or a
//! documented privilege path). The verifier must reproduce these, so this gate
//! is a real probe that prints the values it found, not a static claim.
//!
//! Each check yields a Status. Hard requirements that FAIL make the gate fail
//! (non-zero exit). The jailer-privilege check is the load-bearing one: the
//! jailer is the untrusted-genome boundary (chroot plus seccomp L2), so the
//! gate reports exactly which privilege path is available and never suggests
//! disabling the jailer.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The outcome of a single probe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The requirement is met.
    Pass,
    /// The requirement is met for the spike but with a caveat the verifier
    /// should see (for example: nft comes from the dev shell, not the bare
    /// host).
    Warn,
    /// A hard requirement is unmet; the gate fails.
    Fail,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

/// One probe: a name, a status, the value found, and any detail or remediation.
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub found: String,
    pub detail: String,
}

impl Check {
    fn pass(name: &'static str, found: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name,
            status: Status::Pass,
            found: found.into(),
            detail: detail.into(),
        }
    }
    fn warn(name: &'static str, found: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name,
            status: Status::Warn,
            found: found.into(),
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, found: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name,
            status: Status::Fail,
            found: found.into(),
            detail: detail.into(),
        }
    }
}

/// The full prereqs report.
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    /// The gate passes when no check is FAIL. WARN does not fail the gate (it is
    /// a caveat the verifier reads, for example nft sourced from the dev shell).
    pub fn all_satisfied(&self) -> bool {
        self.checks.iter().all(|c| c.status != Status::Fail)
    }

    /// Human-readable report for the terminal and the build log.
    pub fn print_human(&self) {
        println!("kirby-node host-prereqs gate (spec section 5 and 11)");
        println!("{}", "=".repeat(60));
        for c in &self.checks {
            println!("[{}] {}", c.status.label(), c.name);
            println!("        found:  {}", c.found);
            if !c.detail.is_empty() {
                println!("        note:   {}", c.detail);
            }
        }
        println!("{}", "=".repeat(60));
        let fails = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count();
        let warns = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Warn)
            .count();
        if self.all_satisfied() {
            println!(
                "RESULT: PASS ({} checks, {} warn) host is spike-ready",
                self.checks.len(),
                warns
            );
        } else {
            println!("RESULT: FAIL ({} hard requirement(s) unmet)", fails);
        }
    }

    /// Machine-readable JSON (the producing-command evidence the verifier
    /// diffs). Hand-built so the daemon carries no serde derive just for this.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\n");
        let _ = writeln!(s, "  \"all_satisfied\": {},", self.all_satisfied());
        s.push_str("  \"checks\": [\n");
        for (i, c) in self.checks.iter().enumerate() {
            let comma = if i + 1 < self.checks.len() { "," } else { "" };
            let _ = writeln!(
                s,
                "    {{ \"name\": {}, \"status\": {}, \"found\": {}, \"detail\": {} }}{}",
                json_str(c.name),
                json_str(c.status.label()),
                json_str(&c.found),
                json_str(&c.detail),
                comma
            );
        }
        s.push_str("  ]\n}");
        s
    }
}

/// Minimal JSON string escaping (quotes, backslashes, control chars). The probe
/// values are paths and version strings, so this covers them.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Run every probe and assemble the report.
pub fn check() -> Report {
    if cfg!(target_os = "macos") {
        return check_macos_vz();
    }

    Report {
        checks: vec![
            check_os(),
            check_kvm(),
            check_vsock(),
            check_cgroup_v2(),
            check_cgroup_delegation(),
            check_nft(),
            check_firecracker(),
            check_jailer_binary(),
            check_jailer_privilege(),
        ],
    }
}

fn check_macos_vz() -> Report {
    Report {
        checks: vec![
            check_macos_os(),
            check_macos_arch(),
            check_virtualization_framework(),
            check_swiftc(),
            check_codesign(),
            check_login_keychain_note(),
        ],
    }
}

fn check_macos_os() -> Check {
    if cfg!(target_os = "macos") {
        let version = run_version("/usr/bin/sw_vers", &["-productVersion"]);
        Check::pass(
            "os: macos",
            version,
            "Apple Virtualization.framework backend target",
        )
    } else {
        Check::fail(
            "os: macos",
            std::env::consts::OS,
            "the VZ backend requires macOS",
        )
    }
}

fn check_macos_arch() -> Check {
    if cfg!(target_arch = "aarch64") {
        Check::pass(
            "arch: aarch64",
            std::env::consts::ARCH,
            "matches the staged aarch64 Linux genome image",
        )
    } else {
        Check::fail(
            "arch: aarch64",
            std::env::consts::ARCH,
            "the current Mac MVP targets Apple Silicon and the aarch64 genome image",
        )
    }
}

fn check_virtualization_framework() -> Check {
    let path = "/System/Library/Frameworks/Virtualization.framework";
    if Path::new(path).is_dir() {
        Check::pass(
            "Virtualization.framework",
            path,
            "runtime framework present for the VZ backend",
        )
    } else {
        Check::fail(
            "Virtualization.framework",
            "not found",
            "macOS Virtualization.framework is required to boot the Linux guest",
        )
    }
}

fn check_swiftc() -> Check {
    match which("swiftc") {
        Some(path) => Check::pass(
            "swiftc",
            format!("{path} ({})", run_version(&path, &["--version"])),
            "the planned VZ helper is a small Swift sidecar",
        ),
        None => Check::fail(
            "swiftc",
            "swiftc not on PATH",
            "install Xcode or command line tools so the VZ helper can be built",
        ),
    }
}

fn check_codesign() -> Check {
    match which("codesign") {
        Some(path) => Check::pass(
            "codesign",
            path,
            "the VZ helper will be ad-hoc signed with the virtualization entitlement",
        ),
        None => Check::fail(
            "codesign",
            "codesign not on PATH",
            "macOS requires signing for the virtualization entitlement",
        ),
    }
}

fn check_login_keychain_note() -> Check {
    Check::warn(
        "login keychain",
        "not probed",
        "unlock login.keychain before running the VZ helper if Security Server interaction is denied",
    )
}

/// Linux is required (KVM, cgroup v2, vsock are Linux-only).
fn check_os() -> Check {
    if cfg!(target_os = "linux") {
        let release = read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into());
        Check::pass("os: linux", format!("kernel {release}"), "")
    } else {
        Check::fail(
            "os: linux",
            std::env::consts::OS,
            "the spike requires a Linux host",
        )
    }
}

/// KVM: /dev/kvm must exist and be openable (the microVM needs hardware
/// virtualization).
fn check_kvm() -> Check {
    let path = "/dev/kvm";
    if !Path::new(path).exists() {
        return Check::fail(
            "kvm",
            "/dev/kvm absent",
            "no hardware virtualization; Firecracker cannot run",
        );
    }
    match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => Check::pass("kvm", "/dev/kvm rw", "hardware virtualization available"),
        Err(e) => Check::fail(
            "kvm",
            format!("/dev/kvm present but not openable: {e}"),
            "the daemon user needs rw on /dev/kvm (group kvm)",
        ),
    }
}

/// vsock: /dev/vhost-vsock must exist and be openable (the genome to daemon
/// gateway rides vsock, spec 3.1).
fn check_vsock() -> Check {
    let path = "/dev/vhost-vsock";
    if !Path::new(path).exists() {
        return Check::fail(
            "vsock",
            "/dev/vhost-vsock absent",
            "load the vhost_vsock kernel module; the gateway transport needs it",
        );
    }
    match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => Check::pass(
            "vsock",
            "/dev/vhost-vsock rw",
            "vsock gateway transport available",
        ),
        Err(e) => Check::fail(
            "vsock",
            format!("/dev/vhost-vsock present but not openable: {e}"),
            "the daemon user needs rw on /dev/vhost-vsock",
        ),
    }
}

/// cgroup v2: /sys/fs/cgroup must be a cgroup2 mount (unified hierarchy). The
/// presence of cgroup.controllers at the mount root is the cgroup v2 signal.
fn check_cgroup_v2() -> Check {
    let controllers_path = "/sys/fs/cgroup/cgroup.controllers";
    match read_trim(controllers_path) {
        Some(controllers) => {
            // Metering (C-4) needs cpu and memory controllers.
            let has_cpu = controllers.split_whitespace().any(|c| c == "cpu");
            let has_mem = controllers.split_whitespace().any(|c| c == "memory");
            if has_cpu && has_mem {
                Check::pass(
                    "cgroup v2",
                    format!("controllers: {controllers}"),
                    "unified hierarchy with cpu and memory",
                )
            } else {
                Check::fail(
                    "cgroup v2",
                    format!("controllers: {controllers}"),
                    "cpu and memory controllers are required for metering (spec 3.3)",
                )
            }
        }
        None => Check::fail(
            "cgroup v2",
            "no /sys/fs/cgroup/cgroup.controllers",
            "host is not on the cgroup v2 unified hierarchy",
        ),
    }
}

/// cgroup v2 delegation to the running user. If the user's own cgroup subtree
/// has cpu and memory delegated, metering (spec 3.3) can run without root by
/// placing the vCPU threads under a delegated sub-cgroup. This is informational:
/// it tells the next chunk whether rootless metering is on the table.
fn check_cgroup_delegation() -> Check {
    let uid = current_uid();
    let candidates = [
        format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers"),
        "/sys/fs/cgroup/user.slice/cgroup.controllers".to_string(),
    ];
    for path in candidates {
        if let Some(controllers) = read_trim(&path) {
            let has_cpu = controllers.split_whitespace().any(|c| c == "cpu");
            let has_mem = controllers.split_whitespace().any(|c| c == "memory");
            if has_cpu && has_mem {
                return Check::pass(
                    "cgroup v2 delegation",
                    format!("delegated to uid {uid}: {controllers}"),
                    "cpu and memory delegated; metering can run rootless under the user slice",
                );
            }
            return Check::warn(
                "cgroup v2 delegation",
                format!("delegated to uid {uid}: {controllers}"),
                "cpu or memory NOT delegated; metering may need root or a jailer-managed cgroup",
            );
        }
    }
    Check::warn(
        "cgroup v2 delegation",
        format!("no delegated user slice found for uid {uid}"),
        "metering will rely on the jailer-created cgroup under root",
    )
}

/// nftables: nft must be on PATH (spec 3.7 egress enforcement). The bare host
/// may ship only iptables; the dev shell provides nft. WARN (not PASS) when nft
/// resolves from a nix store dev-shell path so the verifier knows it is shell-
/// provided, not host-installed.
fn check_nft() -> Check {
    match which("nft") {
        Some(path) => {
            let version = run_version(&path, &["--version"]);
            let from_devshell = path.starts_with("/nix/store/");
            if from_devshell {
                Check::warn(
                    "nftables",
                    format!("{path} ({version})"),
                    "nft is provided by the nix dev shell (the bare host ships iptables only); run inside `nix develop`",
                )
            } else {
                Check::pass("nftables", format!("{path} ({version})"), "nft on PATH")
            }
        }
        None => Check::fail(
            "nftables",
            "nft not on PATH",
            "enter the dev shell (`nix develop`) which provides nftables, or install it on the host",
        ),
    }
}

/// Firecracker: the firecracker binary must be on PATH (the microVM monitor).
fn check_firecracker() -> Check {
    match which("firecracker") {
        Some(path) => {
            let version = run_version(&path, &["--version"]);
            Check::pass(
                "firecracker",
                format!("{path} ({version})"),
                "microVM monitor on PATH",
            )
        }
        None => Check::fail(
            "firecracker",
            "firecracker not on PATH",
            "enter the dev shell (`nix develop`) which provides the firecracker package",
        ),
    }
}

/// The jailer binary must be on PATH. The jailer is non-negotiable for the
/// untrusted genome (spec D-7 and section 11): it does the chroot plus seccomp
/// L2 plus the cgroup and namespace setup.
fn check_jailer_binary() -> Check {
    match which("jailer") {
        Some(path) => {
            let version = run_version(&path, &["--version"]);
            Check::pass(
                "jailer binary",
                format!("{path} ({version})"),
                "the untrusted-genome boundary is present",
            )
        }
        None => Check::fail(
            "jailer binary",
            "jailer not on PATH",
            "enter the dev shell (`nix develop`); the firecracker package ships the jailer",
        ),
    }
}

/// The jailer-privilege probe (the load-bearing C-1 check).
///
/// The jailer needs elevated privilege: it chroots, creates cgroups under the
/// cgroup root, enters namespaces, and applies the seccomp filter (a
/// CAP_SYS_ADMIN-class set of operations). The daemon runs as a normal user in
/// the spike, so this probe reports which privilege path is available, in
/// preference order, WITHOUT ever suggesting the jailer be disabled. If no path
/// is available it FAILs the gate and surfaces the exact blocker.
fn check_jailer_privilege() -> Check {
    let uid = current_uid();

    // Path 1: already root. Then the daemon can fork the jailer directly.
    if uid == 0 {
        return Check::pass(
            "jailer privilege",
            "running as uid 0 (root)",
            "the jailer can be launched directly",
        );
    }

    // Path 2: passwordless sudo for the running user. Detected with `sudo -n
    // true` against the NixOS setuid wrapper if present, else PATH sudo. This is
    // the spike's expected path on this host.
    if let Some((sudo_path, detail)) = sudo_nopasswd_available() {
        return Check::pass(
            "jailer privilege",
            format!("uid {uid}, passwordless sudo via {sudo_path}"),
            format!("{detail}; the daemon can launch the jailer with sudo (no jailer bypass, boundary intact)"),
        );
    }

    // Path 3: the running process carries CAP_SYS_ADMIN in its effective set
    // (for example via file capabilities on the daemon binary).
    if has_cap_sys_admin() {
        return Check::pass(
            "jailer privilege",
            format!("uid {uid}, CAP_SYS_ADMIN in effective set"),
            "the daemon holds the cap class the jailer needs",
        );
    }

    // No privilege path. FAIL and surface the options for the humans to choose
    // (the spec's hard rule: do not hack around the jailer).
    Check::fail(
        "jailer privilege",
        format!("uid {uid}, no root, no passwordless sudo, no CAP_SYS_ADMIN"),
        "the jailer needs elevated privilege and none is available; options: (A) a passwordless sudoers rule for the jailer binary, (B) file caps / a setuid wrapper on the jailer, (C) run the daemon under a privileged systemd unit. Do NOT disable the jailer (it is the untrusted-genome boundary).",
    )
}

// ---- helpers ----

/// Resolve a binary on PATH (does not run it). Returns the absolute path.
fn which(bin: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            // Best-effort: confirm it is executable by attempting metadata.
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Run `bin args...` and return the first line of combined stdout/stderr,
/// trimmed. Used for version strings. Returns "unknown" on any failure.
fn run_version(bin: &str, args: &[&str]) -> String {
    match Command::new(bin).args(args).output() {
        Ok(out) => {
            let text = if !out.stdout.is_empty() {
                String::from_utf8_lossy(&out.stdout).into_owned()
            } else {
                String::from_utf8_lossy(&out.stderr).into_owned()
            };
            text.lines().next().unwrap_or("").trim().to_string()
        }
        Err(_) => "unknown".to_string(),
    }
}

/// Read a file and return its trimmed contents, or None on any error.
fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// The current real user id, read from /proc/self/status (Uid line, first
/// field). Avoids a libc dependency for the C-1 skeleton.
fn current_uid() -> u32 {
    read_trim("/proc/self/status")
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|rest| rest.split_whitespace().next().map(str::to_string))
        })
        .and_then(|s| s.parse().ok())
        .unwrap_or(u32::MAX)
}

/// Resolve the path to a WORKING passwordless sudo for the running user, the
/// launch path for the jailer (the untrusted-genome boundary, D-7). Prefers the
/// NixOS setuid wrapper at /run/wrappers/bin/sudo (on NixOS the PATH sudo is the
/// non-setuid nix-store binary, which cannot elevate); otherwise falls back to
/// PATH sudo (/usr/bin/sudo on Ubuntu and others). The chosen candidate is
/// verified to actually elevate without a prompt (`sudo -n true` exits 0) before
/// it is returned, so the daemon launches the jailer through a real, working,
/// passwordless sudo on any Linux host with no symlink workaround.
///
/// FAILS LOUD when no working passwordless sudo exists: the jailer is never
/// silently skipped (the spec's hard rule, the boundary stays intact). The error
/// surfaces the same privilege options the prereqs gate reports.
///
/// This is the single source of truth for sudo discovery: the prereqs
/// jailer-privilege check and every jailer-launch call site share it, so the
/// gate and the launch never diverge.
pub fn resolve_sudo() -> anyhow::Result<PathBuf> {
    let candidates = [
        "/run/wrappers/bin/sudo".to_string(),
        which("sudo").unwrap_or_default(),
    ];
    for sudo in candidates {
        if sudo.is_empty() || !Path::new(&sudo).exists() {
            continue;
        }
        // `sudo -n true`: -n means non-interactive (never prompt). Exit 0 only
        // when a passwordless rule applies and the binary can actually elevate.
        match Command::new(&sudo).args(["-n", "true"]).output() {
            Ok(out) if out.status.success() => {
                return Ok(PathBuf::from(sudo));
            }
            _ => continue,
        }
    }
    anyhow::bail!(
        "no working passwordless sudo found (tried the NixOS setuid wrapper /run/wrappers/bin/sudo then PATH sudo, none elevated under `sudo -n true`); the jailer needs elevated privilege and none is available. Options: (A) a passwordless sudoers rule for the jailer/sudo, (B) file caps / a setuid wrapper, (C) run the daemon under a privileged systemd unit. Do NOT disable the jailer (it is the untrusted-genome boundary)."
    )
}

/// Detect passwordless sudo for the running user, in the prereqs check's
/// `(path, detail)` shape. A thin wrapper over [`resolve_sudo`] so the gate and
/// the jailer-launch call sites use the one discovery, never a divergent copy.
fn sudo_nopasswd_available() -> Option<(String, String)> {
    resolve_sudo().ok().map(|sudo| {
        (
            sudo.to_string_lossy().into_owned(),
            "verified with `sudo -n true`".to_string(),
        )
    })
}

/// Check whether the running process holds CAP_SYS_ADMIN in its effective set.
/// Reads CapEff from /proc/self/status and tests bit 21 (CAP_SYS_ADMIN).
fn has_cap_sys_admin() -> bool {
    const CAP_SYS_ADMIN_BIT: u64 = 21;
    read_trim("/proc/self/status")
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .map(|hex| hex.trim().to_string())
        })
        .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
        .map(|caps| (caps >> CAP_SYS_ADMIN_BIT) & 1 == 1)
        .unwrap_or(false)
}
