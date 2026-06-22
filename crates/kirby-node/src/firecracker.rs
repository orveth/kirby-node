//! The Firecracker sandbox backend (spec 5, D-7, gate G1): the first
//! [`crate::sandbox::SandboxBackend`] impl.
//!
//! This is the Linux/KVM backend behind the [`crate::sandbox`] seam. The daemon
//! drives Firecracker through fctools' VM layer, ALWAYS under the jailer (the
//! untrusted-genome boundary: chroot plus cgroup plus namespaces plus seccomp,
//! spec D-7 and section 11). The jailer can only run as root, so the daemon
//! launches it through the passwordless sudo wrapper (the locked decision: the
//! daemon shells `sudo jailer ...` via fctools' `SudoProcessSpawner`). Nothing in
//! the jailer is disabled or bypassed; the firecracker process it supervises is
//! dropped to the daemon's own uid/gid so the host daemon and the jailed VMM share
//! access to the vsock Unix socket.
//!
//! The image is the content-addressed genome image (spec 3.6, nix/genome-image
//! .nix): a stripped Linux 6.1 LTS kernel with VMGenID built in, plus a
//! read-only squashfs whose only payload is the musl genome at /init. The
//! squashfs is the root block device; the genome boots as PID 1 and pulls its
//! session context over vsock (spec 3.1).
//!
//! Firecracker's vsock is host-side a Unix socket, not an AF_VSOCK socket: when
//! the guest dials the host CID on port P, Firecracker connects to the host Unix
//! socket `<uds>_<P>`. So the daemon's gateway server listens on that path (the
//! `gateway::serve_firecracker_vsock` path), reported through the seam as
//! `GatewayTransport::FirecrackerVsockUds`.
//!
//! What is concrete HERE (the backend mechanics): boot the microVM, place it in
//! the dedicated cgroup the meter reads, install + wire the per-VM TAP and its
//! nftables lockdown, and the daemon-initiated halt. What stays AGNOSTIC and is
//! NOT in this module: the gateway service + authorize order, the treasury, the
//! rail, the meter burn math, and the genome (the genome talks only vsock, so it
//! is identical on every backend).

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sandbox::{
    BackendCapabilities, BackendKind, CpuClass, EgressControl, EgressDropCounter, GatewayTransport,
    GuestArch, GuestSpec, IsolationTier, MeterFidelity, MeterSource, RestoreSpec, SandboxBackend,
    SandboxInstance, SnapshotArtifact, SnapshotClass,
};

use fctools::process_spawner::SudoProcessSpawner;
use fctools::runtime::tokio::TokioRuntime;
use fctools::vm::api::VmApi;
use fctools::vm::configuration::{InitMethod, VmConfiguration, VmConfigurationData};
use fctools::vm::models::{
    BootSource, CpuTemplate, CreateSnapshot, Drive, LoadSnapshot, MachineConfiguration,
    MemoryBackend, MemoryBackendType, NetworkInterface, NetworkOverride, SnapshotType, VsockDevice,
};
use fctools::vm::shutdown::{VmShutdownAction, VmShutdownMethod};
use fctools::vm::{Vm, VmState};
use fctools::vmm::arguments::jailer::{JailerArguments, JailerCgroupVersion};
use fctools::vmm::arguments::{VmmApiSocket, VmmArguments};
use fctools::vmm::executor::jailed::{FlatVirtualPathResolver, JailedVmmExecutor};
use fctools::vmm::installation::VmmInstallation;
use fctools::vmm::ownership::VmmOwnershipModel;
use fctools::vmm::resource::system::ResourceSystem;
use fctools::vmm::resource::{MovedResourceType, ResourceType};

/// The env var pointing at a CUSTOM CPU template JSON file to apply at create (the
/// firecracker `CustomCpuTemplate` shape: `{kvm_capabilities, cpuid_modifiers,
/// msr_modifiers}`). Set this to the published Intel T2CL template for the two-host
/// cross-CPU bar (D-15); unset, the backend derives the host's own template via
/// `cpu-template-helper` (correct for the same-host bar, where the restore CPU is
/// identical). Either way a NON-EMPTY template is applied (the section 11
/// no-silent-no-op requirement).
const CPU_TEMPLATE_ENV: &str = "KIRBY_CPU_TEMPLATE";

/// The concrete VM type the daemon drives: a jailed executor, launched through
/// the sudo spawner, on the tokio runtime.
type GenomeVm = Vm<JailedVmmExecutor<FlatVirtualPathResolver>, SudoProcessSpawner, TokioRuntime>;

/// The Firecracker sandbox backend: the Linux/KVM impl of
/// [`SandboxBackend`]. It translates a backend-neutral [`GuestSpec`] into the
/// Firecracker launch (the per-VM TAP + nftables lockdown when egress is locked
/// down, then `boot` under the jailer) and hands the daemon a [`BootedVm`] as the
/// `SandboxInstance`. Stateless: the per-guest host state lives in the returned
/// instance. The daemon constructs ONE backend and boots many guests through it.
#[derive(Debug, Default, Clone, Copy)]
pub struct FirecrackerBackend;

impl FirecrackerBackend {
    pub fn new() -> Self {
        FirecrackerBackend
    }

    /// The resume class this backend produces and can restore (Firecracker x
    /// x86_64 x the Intel T2CL CPU class). A snapshot taken here is restorable only
    /// on another node reporting this exact class (`restore` re-checks it).
    pub fn snapshot_class() -> SnapshotClass {
        SnapshotClass {
            backend: BackendKind::Firecracker,
            guest_arch: GuestArch::X86_64,
            cpu_class: CpuClass::IntelT2CL,
        }
    }
}

/// The cross-CPU snapshot CPU template applied at VM create (D-8, gate G6), as the
/// fctools [`CpuTemplate::Untyped`] (the JSON serializes straight into the
/// machine-config `cpu_template` field). Firecracker 1.15 wants a full
/// `CustomCpuTemplate` object here (`{kvm_capabilities, cpuid_modifiers,
/// msr_modifiers}`), NOT a named static-template string, so this supplies one:
/// - if `KIRBY_CPU_TEMPLATE` points at a JSON file, load that (the published Intel
///   T2CL template for the two-host cross-CPU bar, D-15); else
/// - derive the HOST's own template via `cpu-template-helper template dump` (the
///   same-host bar, where the restore CPU is identical, so the host template applies
///   cleanly and a snapshot taken under it restores on the same host).
///
/// Either source yields a NON-EMPTY template, so the snapshot is demonstrably
/// CPU-template-normalized (not a silent no-op, the section 11 mitigation):
/// firecracker rejects a malformed template at boot, so a snapshot-capable VM that
/// reaches Running is the in-effect proof. The published T2CL is a drop-in via the
/// env var, mirroring the D-13 transfer seam's same-host-now / two-host-later shape.
fn cross_cpu_template() -> anyhow::Result<CpuTemplate> {
    let json = if let Some(path) = std::env::var_os(CPU_TEMPLATE_ENV) {
        let path = PathBuf::from(path);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read {CPU_TEMPLATE_ENV} {}: {e}", path.display()))?;
        serde_json::from_str::<serde_json::Value>(&text)
            .map_err(|e| anyhow::anyhow!("parse CPU template {}: {e}", path.display()))?
    } else {
        host_cpu_template()?
    };
    // Sanity: a usable template has at least one CPUID or MSR modifier (an empty one
    // would be a silent no-op). cpu-template-helper always emits a populated one.
    let nonempty = json
        .get("cpuid_modifiers")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty())
        || json
            .get("msr_modifiers")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
    if !nonempty {
        anyhow::bail!("CPU template is empty (no cpuid/msr modifiers); refusing a silent no-op template");
    }
    Ok(CpuTemplate::Untyped(json))
}

/// Derive THIS host's CPU template (a firecracker `CustomCpuTemplate`) via
/// `cpu-template-helper template dump`, which reads the host CPUID/MSRs and needs no
/// privilege and no running VM, then keep the MSR-modifier subset (the T2CL-class
/// feature masks: IA32_ARCH_CAPABILITIES 0x10a, IA32_PAT 0x277, and the rest). The
/// raw dump's CPUID modifiers re-set KVM-managed leaves (e.g. leaf 0xb extended
/// topology) that KVM refuses to take from a template, so the CPUID part is dropped;
/// the MSR masks ARE KVM-settable and are the meaningful, in-effect part of the
/// template (they normalize feature/security MSRs the same way T2CL does). On the
/// SAME-HOST bar this is correct (the restore CPU is identical, so the CPUID masking
/// T2CL would add is a no-op anyway, the section 11 point), and the template is
/// demonstrably non-empty / in effect (not a silent no-op). The full cross-CPU T2CL
/// (with its guest-safe CPUID masks) is supplied instead via `KIRBY_CPU_TEMPLATE`
/// for the two-host bar. The result is cached in the OS temp dir.
fn host_cpu_template() -> anyhow::Result<serde_json::Value> {
    let cache = std::env::temp_dir().join("kirby-host-cpu-template.json");
    if let Ok(text) = std::fs::read_to_string(&cache) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            return Ok(v);
        }
    }
    let helper = which("cpu-template-helper")?;
    let raw_path = std::env::temp_dir().join("kirby-host-cpu-template-raw.json");
    let output = std::process::Command::new(&helper)
        .args(["template", "dump", "-o"])
        .arg(&raw_path)
        .output()
        .map_err(|e| anyhow::anyhow!("run cpu-template-helper: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "cpu-template-helper template dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = std::fs::read_to_string(&raw_path)
        .map_err(|e| anyhow::anyhow!("read generated CPU template {}: {e}", raw_path.display()))?;
    let raw: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("parse generated CPU template: {e}"))?;

    // Keep ONLY the MSR modifiers (KVM-settable, the meaningful feature masks); drop
    // the CPUID modifiers (the raw host dump re-sets KVM-managed CPUID leaves that
    // KVM refuses from a template). The kvm_capabilities pass through.
    let msr_modifiers = raw.get("msr_modifiers").cloned().unwrap_or(serde_json::Value::Array(vec![]));
    let kvm_capabilities = raw
        .get("kvm_capabilities")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));
    let template = serde_json::json!({
        "kvm_capabilities": kvm_capabilities,
        "cpuid_modifiers": [],
        "msr_modifiers": msr_modifiers,
    });
    // Cache the FILTERED template (the one we actually apply).
    let _ = std::fs::write(&cache, serde_json::to_string_pretty(&template).unwrap_or_default());
    Ok(template)
}

#[async_trait::async_trait]
impl SandboxBackend for FirecrackerBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Firecracker,
            // The genome image is built for x86_64 (the spike host is Intel).
            guest_arch: GuestArch::X86_64,
            // The jailer cages an escaped guest (chroot + seccomp + namespaces +
            // uid-drop), so an escape is still confined (the plan's strongest tier).
            isolation: IsolationTier::HardwareVmJailed,
            // cgroups v2 (cpu.stat/memory.current) + the eBPF egress byte counter
            // are tick-accurate with a hard running memory bound.
            metering: MeterFidelity::CgroupExact,
            // VM-snapshot resume: a Firecracker/x86_64 snapshot taken under the
            // T2CL Intel template, restorable on another node of this same class
            // (G6). The scheduler matches this class to pick a same-class resume
            // node; a different backend (macOS VZ) is a different class and cannot
            // restore it.
            snapshot: Some(Self::snapshot_class()),
            // Firecracker runs the genome, so the portable app-checkpoint path is
            // also available to it (boot fresh + rehydrate). The spike does not
            // build that path (kirby-mac's VZ work); the flag lets the scheduler
            // fall back to it when no same-snapshot-class node exists.
            app_checkpoint: true,
        }
    }

    async fn boot(&self, spec: GuestSpec) -> anyhow::Result<Box<dyn SandboxInstance>> {
        // Resolve the binaries the prereqs gate already verified are present. The
        // jailer is the security boundary; it launches through a working
        // passwordless sudo (NOPASSWD, the same discovery the prereqs gate runs).
        let firecracker_bin = which("firecracker")?;
        let jailer_bin = which("jailer")?;
        // Discover the working passwordless sudo at runtime (the NixOS setuid
        // wrapper here, /usr/bin/sudo on Ubuntu) instead of hardcoding the NixOS
        // path, so the jailer launches on any Linux host; fails loud if none.
        let sudo_bin = crate::prereqs::resolve_sudo()?;

        let (uid, gid) = current_uid_gid();
        // A unique jail id per guest on this host: the (sanitized) instance id plus
        // this process's pid, so two node processes stay distinct.
        let jail_id = format!("{}-{}", sanitize(&spec.instance_id), std::process::id());

        // The per-VM TAP and its nftables default-deny egress lockdown (spec 3.7),
        // created before boot so the interface exists when firecracker wires it and
        // the lockdown is in force from the guest's first packet. Owned by the
        // returned instance so halt() tears it down. None => vsock-only guest.
        let tap = if spec.lockdown_egress {
            Some(crate::network::VmTap::create(&jail_id, uid, gid, sudo_bin.clone())?)
        } else {
            None
        };
        let tap_name = tap.as_ref().map(|t| t.name().to_string());

        // A SHORT chroot base, deliberately not under the (long) nix-shell TMPDIR:
        // the jailer relocates the vsock Unix socket under the jail root, and the
        // resulting path must fit the Unix-socket SUN_LEN limit (108 bytes). A short
        // fixed base plus the bare uds filename keeps it well within.
        let chroot_base_dir = PathBuf::from("/tmp/kj");
        // The dedicated cgroup parent for metering (C-4), under the daemon's
        // delegated user slice so the daemon reads the VM cgroup rootlessly.
        let parent_cgroup_rel = meter_cgroup_parent_rel(uid);

        let params = BootParams {
            vmlinux: spec.image.kernel.clone(),
            rootfs: spec.image.rootfs.clone(),
            firecracker_bin,
            jailer_bin,
            sudo_bin,
            guest_cid: spec.guest_cid,
            gateway_port: spec.gateway_port,
            workload: spec.workload.clone(),
            brain: spec.brain.clone(),
            vcpu_count: spec.vcpu_count,
            mem_size_mib: spec.mem_size_mib,
            jail_uid: uid,
            jail_gid: gid,
            chroot_base_dir,
            jail_id,
            parent_cgroup_rel,
            tap_name,
            snapshot_capable: spec.snapshot_capable,
        };

        let vm = boot(params, tap).await?;
        Ok(Box::new(vm))
    }

    async fn restore(
        &self,
        artifact: SnapshotArtifact,
        spec: RestoreSpec,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        restore(artifact, spec).await.map(|vm| Box::new(vm) as Box<dyn SandboxInstance>)
    }
}

/// The Firecracker-specific launch arguments for one genome microVM, derived from
/// a backend-neutral [`GuestSpec`] by `FirecrackerBackend::boot`. Backend-internal
/// (`pub(crate)`): the daemon speaks `GuestSpec`, not `BootParams`.
pub(crate) struct BootParams {
    /// The genome guest kernel image (vmlinux), from the content-addressed image.
    pub vmlinux: PathBuf,
    /// The read-only squashfs rootfs (the genome at /init), from the image.
    pub rootfs: PathBuf,
    /// Absolute paths to the firecracker and jailer binaries (dev shell provides
    /// them; the prereqs gate verified they are present).
    pub firecracker_bin: PathBuf,
    pub jailer_bin: PathBuf,
    /// The sudo binary the daemon launches the jailer through, discovered at
    /// runtime (the NixOS setuid wrapper or PATH sudo). NOPASSWD, so no password
    /// is supplied.
    pub sudo_bin: PathBuf,
    /// The guest CID for this VM's vsock (spec 3.1: one genome per CID, so two
    /// node processes on one host stay distinct). Firecracker requires CID >= 3.
    pub guest_cid: u32,
    /// The gateway vsock port the genome dials and the daemon serves on.
    pub gateway_port: u32,
    /// The genome workload the daemon requests on the kernel command line
    /// (`kirby.workload=<name>`). `Some("burn")` runs the C-4 metering workload
    /// (allocate memory + spin CPU, gate G2); `None` (the C-2 default) idles
    /// after the boot round-trip, so G1 is unaffected.
    pub workload: Option<String>,
    /// The `[brain]` knobs for the MIND workload (brain-stub). `Some` only for a
    /// `brain` guest: `model`, `max_cost_sats`, and `tick_secs` are written onto the
    /// kernel command line (`kirby.brain_*=`) so the genome's brain loop reads its
    /// config, exactly as `gateway_port` and `workload` already travel.
    pub brain: Option<crate::config::BrainConfig>,
    /// vCPU count and memory for the microVM. Small for the spike.
    pub vcpu_count: u8,
    pub mem_size_mib: usize,
    /// The uid/gid the jailer drops the firecracker process to. Set to the
    /// daemon's own uid/gid so the daemon can bind the vsock Unix socket inside
    /// the jail chroot that the jailed firecracker also reaches.
    pub jail_uid: u32,
    pub jail_gid: u32,
    /// The chroot base directory the jailer builds the jail under. A
    /// daemon-writable path keeps the spike off the default /srv/jailer (which a
    /// non-root daemon cannot manage); the jailer is otherwise fully intact.
    pub chroot_base_dir: PathBuf,
    /// A unique jail id for this VM (the jailer names the chroot after it).
    pub jail_id: String,
    /// The parent cgroup the jailer nests this VM's cgroup under, RELATIVE to the
    /// cgroup v2 mount root (`/sys/fs/cgroup`). The daemon pre-creates this under
    /// its OWN delegated user slice (cgroup2 is delegated to the daemon's uid,
    /// the C-1 finding) and enables the cpu and memory controllers in it, so the
    /// jailer (running as root via sudo) creates the VM cgroup at a deterministic
    /// path the daemon then reads ROOTLESSLY for metering (the cgroup files are
    /// world-readable within the daemon's own delegated subtree). The jailer
    /// stays fully intact; this only tells it WHERE to put the cgroup so metering
    /// (C-4) has a dedicated, readable cgroup instead of the launching shell's
    /// inherited one (the C-2-verifier flag). The VM cgroup's relative path is
    /// then `<parent_cgroup_rel>/<jail_id>` (the v1.15.1 jailer in v2 mode places
    /// the cgroup directly under the parent, named by the jail id).
    pub parent_cgroup_rel: PathBuf,
    /// The per-VM TAP device name to wire as the VM's network interface (C-5,
    /// spec 3.7), or `None` for a vsock-only VM (the C-2/C-4 default, no TAP).
    /// When set, the VM gets a `NetworkInterface` on this host TAP so it can
    /// ATTEMPT egress; the TAP itself (and its nftables default-deny lockdown) is
    /// created by the caller via `network::VmTap` before boot. The jailer runs in
    /// the HOST network namespace (no `--netns`), so the host TAP is directly
    /// usable, and the jailer mknods `/dev/net/tun` into the chroot by default.
    pub tap_name: Option<String>,
    /// Apply the cross-CPU snapshot template (T2CL) at create so this VM can be
    /// snapshotted and restored on a different Intel CPU (C-7, gate G6, D-8). The
    /// C-2..C-6 default is false (no template, no snapshot).
    pub snapshot_capable: bool,
}

/// A booted genome microVM plus the host-side facts the daemon needs: the base
/// vsock Unix socket path (the gateway binds `<uds_base>_<port>`) and the VM's
/// dedicated cgroup relative path (the meter reads `cpu.stat` + `memory.current`
/// there, C-4). This is the Firecracker backend's concrete instance; the daemon
/// drives it through the [`SandboxInstance`] trait, so it is `pub(crate)`.
pub(crate) struct BootedVm {
    vm: GenomeVm,
    uds_base: PathBuf,
    /// The gateway vsock port (reported back through `GatewayTransport` so the
    /// daemon binds `<uds_base>_<port>` and serves the agnostic gateway there).
    gateway_port: u32,
    cgroup_rel_path: PathBuf,
    /// The per-VM TAP and its nftables egress lockdown (C-5), if this VM has a
    /// network interface. Owned here so `halt()` tears it down with the VM (the
    /// TAP and the nftables table are host state that must not leak). `None` for
    /// a vsock-only VM.
    tap: Option<crate::network::VmTap>,
}

impl BootedVm {
    /// Stream the guest serial console (it rides firecracker stdout) to tracing,
    /// one line per `genome serial` log record, as supplementary G1 boot
    /// evidence. Spawns a background task that runs until the pipe closes (VM
    /// teardown). Best-effort: if the pipes are unavailable (already taken, or a
    /// daemonized launch), it logs that and returns.
    pub(crate) fn stream_serial_log(&mut self) {
        use futures::io::{AsyncBufReadExt, BufReader};
        use futures::stream::StreamExt;

        let pipes = match self.vm.take_pipes() {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, "serial pipes unavailable; boot log not streamed");
                return;
            }
        };
        // stdout carries the guest console (console=ttyS0 plus the genome's own
        // [genome] lines). Read it line by line on a background task.
        tokio::spawn(async move {
            let mut lines = BufReader::new(pipes.stdout).lines();
            while let Some(Ok(line)) = lines.next().await {
                tracing::info!(target: "genome_serial", "{line}");
            }
        });
    }

    /// Snapshot the running VM (gate G6): PAUSE it (firecracker requires a paused
    /// VM to snapshot), then write the Full snapshot (vmstate + guest-RAM mem file)
    /// inside the jail and return a backend-neutral [`SnapshotArtifact`]. The VM is
    /// left PAUSED so the caller can restore on the target node BEFORE halting this
    /// source VM (a clean restore exists before the source is destroyed). The CPU
    /// template applied at boot (T2CL, snapshot_capable) makes the pair restorable
    /// on a compatible different Intel CPU.
    ///
    /// The snapshot files are Produced resources created inside the jail; firecracker
    /// writes them and `upgrade_owner` (inside create_snapshot) makes them readable
    /// by the daemon, so the transfer seam can copy them out. The artifact carries
    /// the `VmConfigurationData` (the VM's config) as backend-private restore data so
    /// a fresh VMM can prepare from the files on the target node.
    pub(crate) async fn snapshot(&mut self) -> anyhow::Result<SnapshotArtifact> {
        // Firecracker can only snapshot a PAUSED VM (the API enforces it). Pause
        // freezes the vCPUs so the captured state is consistent.
        self.vm
            .pause()
            .await
            .map_err(|e| anyhow::anyhow!("pause VM before snapshot: {e}"))?;
        tracing::info!("VM paused for snapshot (gate G6)");

        // The snapshot output files, as Produced resources inside the jail. Short
        // bare names keep the in-jail path well under any limit; firecracker
        // resolves them to effective paths under the jail root.
        let resource_system = self.vm.get_resource_system_mut();
        let snapshot_resource = resource_system
            .create_resource(PathBuf::from("/snapshot.vmstate"), ResourceType::Produced)
            .map_err(|e| anyhow::anyhow!("register snapshot vmstate resource: {e}"))?;
        let mem_resource = resource_system
            .create_resource(PathBuf::from("/snapshot.mem"), ResourceType::Produced)
            .map_err(|e| anyhow::anyhow!("register snapshot mem resource: {e}"))?;

        // Create a FULL snapshot (not a diff; the spike moves a complete, self-
        // contained pair to the target node, D-8). create_snapshot writes the files,
        // upgrades their ownership to the daemon, and returns the effective paths +
        // the configuration data needed to restore.
        let vm_snapshot = self
            .vm
            .create_snapshot(CreateSnapshot {
                snapshot_type: Some(SnapshotType::Full),
                snapshot: snapshot_resource,
                mem_file: mem_resource,
            })
            .await
            .map_err(|e| anyhow::anyhow!("create VM snapshot: {e}"))?;

        tracing::info!(
            vmstate = %vm_snapshot.snapshot_path.display(),
            mem = %vm_snapshot.mem_file_path.display(),
            "VM snapshot created (mem+vmstate pair; CPU-template normalized)"
        );

        Ok(SnapshotArtifact {
            vmstate_path: vm_snapshot.snapshot_path.clone(),
            mem_path: vm_snapshot.mem_file_path.clone(),
            class: FirecrackerBackend::snapshot_class(),
            // Backend-private: the VM configuration data the restore needs (vCPU,
            // mem, devices). The restore reads it back via downcast. The file paths
            // travel in the artifact's vmstate_path/mem_path (the transfer rewrites
            // them), so restore uses those, not the paths frozen in here.
            restore_data: Box::new(vm_snapshot.configuration_data),
        })
    }

    /// Halt the VM: pause then kill, kill the actual VMM process via its cgroup,
    /// then clean the jail up. This is the daemon-initiated teardown (the
    /// spike-scale "death" the daemon controls; the metered budget-halt, C-4,
    /// calls this; the failover kill of the source node after a snapshot, C-7,
    /// calls this). Best-effort, so a teardown after a failed boot or of an
    /// already-paused snapshotted VM still cleans the jail.
    ///
    /// IMPORTANT: fctools launches the jailer through `sudo`, so the child it
    /// tracks (and `send_sigkill`s) is the SUDO process, not the firecracker it
    /// supervises. Killing sudo leaves firecracker orphaned and alive. So after
    /// the fctools shutdown we ALSO kill the firecracker process directly via the
    /// VM's cgroup: `cgroup.procs` lists its PIDs and the firecracker process was
    /// dropped to the daemon's own uid (so the daemon can SIGKILL it). The cgroup
    /// is the source of truth for which processes ARE this VM, so this is the
    /// reliable daemon-initiated kill the budget-death halt (G2) needs.
    pub(crate) async fn halt(mut self) {
        let actions = [
            VmShutdownAction {
                method: VmShutdownMethod::PauseThenKill,
                timeout: Some(Duration::from_secs(3)),
                graceful: false,
            },
            VmShutdownAction {
                method: VmShutdownMethod::Kill,
                timeout: Some(Duration::from_secs(3)),
                graceful: false,
            },
        ];
        if let Err(e) = self.vm.shutdown(actions).await {
            tracing::warn!(error = %e, "VM shutdown returned an error (continuing to kill via cgroup)");
        }
        // The reliable kill: terminate every process in the VM's cgroup (the
        // firecracker VMM, which fctools' sudo-tracked handle does not reach).
        kill_cgroup_processes(&self.cgroup_rel_path);
        if let Err(e) = self.vm.cleanup().await {
            tracing::warn!(error = %e, "VM jail cleanup returned an error");
        }
        // Tear down the per-VM TAP and its nftables egress lockdown (C-5) AFTER
        // the VMM is gone, so removing the TAP does not race a live firecracker.
        // Leaves no host network state behind.
        if let Some(tap) = self.tap.take() {
            tap.teardown();
        }
    }
}

/// The Firecracker microVM as a backend-neutral [`SandboxInstance`]: the daemon
/// drives the guest through this trait, never the concrete `BootedVm`. Each method
/// reports a backend-tagged descriptor (the vsock transport, the cgroup meter
/// source, the TAP egress control) the agnostic orchestration consumes; halt is
/// the daemon-initiated teardown.
#[async_trait::async_trait]
impl SandboxInstance for BootedVm {
    fn is_running(&mut self) -> bool {
        matches!(self.vm.get_state(), VmState::Running)
    }

    fn gateway_transport(&self) -> GatewayTransport {
        // Firecracker's host-side vsock is a Unix socket; the daemon binds
        // `<uds_base>_<port>` and serves the agnostic gateway there (spec 3.1).
        GatewayTransport::FirecrackerVsockUds {
            uds_base: self.uds_base.clone(),
            port: self.gateway_port,
        }
    }

    fn meter_source(&self) -> MeterSource {
        // The jailer placed the VM in this dedicated cgroup under the daemon's
        // delegated slice; the agnostic meter reads cpu.stat + memory.current here.
        MeterSource::CgroupV2 { rel_path: self.cgroup_rel_path.clone() }
    }

    fn egress_control(&self) -> Option<&dyn EgressControl> {
        self.tap.as_ref().map(|t| t as &dyn EgressControl)
    }

    fn stream_console(&mut self) {
        self.stream_serial_log();
    }

    async fn snapshot(&mut self) -> anyhow::Result<SnapshotArtifact> {
        BootedVm::snapshot(self).await
    }

    async fn halt(self: Box<Self>) {
        BootedVm::halt(*self).await;
    }
}

/// The per-VM TAP as the backend-neutral [`EgressControl`]: the orchestration asks
/// for the interface to meter and the host-kernel drop counter (the G4 evidence)
/// without naming the TAP/nftables mechanics.
impl EgressControl for crate::network::VmTap {
    fn iface_name(&self) -> &str {
        self.name()
    }

    fn drop_counter(&self) -> EgressDropCounter {
        let c = crate::network::VmTap::drop_counter(self);
        EgressDropCounter { packets: c.packets, bytes: c.bytes }
    }
}

/// SIGKILL every process in the VM's cgroup (the daemon-initiated VMM kill).
/// Reads `cgroup.procs` (world-readable in the jailer-created cgroup) and signals
/// each PID; the firecracker process was dropped to the daemon's uid, so the
/// daemon can kill it. Best-effort: a missing cgroup (already torn down) or an
/// already-dead PID is not an error. Tries `cgroup.kill` first (the v2 atomic
/// mass-kill) in case the daemon owns it, then falls back to per-PID SIGKILL.
fn kill_cgroup_processes(cgroup_rel_path: &Path) {
    let cgroup_abs = Path::new("/sys/fs/cgroup").join(cgroup_rel_path);
    if !cgroup_abs.is_dir() {
        return;
    }

    // v2 atomic mass-kill: write "1" to cgroup.kill. Works only if the daemon
    // owns the file (it does for daemon-created cgroups; the jailer-created one
    // is root-owned, so this is best-effort and the per-PID path below is the
    // real workhorse).
    let _ = std::fs::write(cgroup_abs.join("cgroup.kill"), "1");

    // Per-PID SIGKILL from cgroup.procs (the reliable path: the procs file is
    // world-readable and firecracker runs as the daemon's uid).
    if let Ok(procs) = std::fs::read_to_string(cgroup_abs.join("cgroup.procs")) {
        for line in procs.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                // SAFETY: kill(2) with SIGKILL on a pid the daemon may signal;
                // an invalid or already-dead pid returns ESRCH, which is fine.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                tracing::info!(pid, "SIGKILL to VM cgroup process (daemon-initiated VMM kill)");
            }
        }
    }

    // Remove the now-empty VM cgroup directory. The jailer (root) created it, so
    // it is root-owned, but the daemon owns the PARENT (its delegated `kirby`
    // slice) and rmdir permission is on the parent, so the daemon can clean its
    // own cgroup children. A short retry covers the brief window after SIGKILL
    // before the kernel empties the cgroup (rmdir fails EBUSY while a process is
    // still exiting). Best-effort: a non-empty or already-gone cgroup is fine.
    for _ in 0..20 {
        match std::fs::remove_dir(&cgroup_abs) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
}

/// Boot the genome microVM under the jailer (gate G1). Prepares the jail
/// (kernel and rootfs copied in by fctools), launches firecracker through
/// `sudo jailer`, and waits for the API socket. On success the VM is Running and
/// the genome is coming up; the caller serves the gateway on the returned vsock
/// Unix socket so the genome's boot round-trip lands. Backend-internal: the daemon
/// reaches it via `FirecrackerBackend::boot`, which builds `params` from a
/// `GuestSpec`.
///
/// `tap` is the per-VM TAP (C-5) whose name was set in `params.tap_name`, moved
/// in so the returned `BootedVm` owns it and `halt()` tears it down with the VM.
/// `None` for a vsock-only VM (no network interface).
pub(crate) async fn boot(
    params: BootParams,
    tap: Option<crate::network::VmTap>,
) -> anyhow::Result<BootedVm> {
    // The kernel command line: serial console for the boot log, the read-only
    // squashfs as the root device, the genome as init, and the gateway port the
    // genome dials (spec 3.6: session data enters via vsock, not a shared FS, so
    // only the non-secret port travels on the cmdline). pci=off keeps Firecracker
    // on the MMIO transport the guest kernel has built in.
    let mut boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/init kirby.gateway_port={}",
        params.gateway_port
    );
    // The workload selector (C-4): the genome runs the burn workload only when
    // the daemon asks for it, so a metered run drives the meter while a plain
    // boot (C-2) idles. Absent flag means idle.
    if let Some(workload) = &params.workload {
        boot_args.push_str(&format!(" kirby.workload={workload}"));
    }
    // The brain knobs for the MIND workload (brain-stub §4): the genome's brain loop
    // reads model/max_cost_sats/tick_secs from the cmdline, so the `[brain]` config
    // reaches it the same non-secret way the gateway port and workload do. Only the
    // genome-side knobs travel; the daemon's StubBrain cost knob (bytes_per_sat) stays
    // host-side. The model carries no spaces (a model id), so it needs no quoting.
    if let Some(brain) = &params.brain {
        boot_args.push_str(&format!(
            " kirby.brain_model={} kirby.brain_max_cost_sats={} kirby.brain_tick_secs={}",
            brain.model, brain.max_cost_sats, brain.tick_secs
        ));
    }

    // When a TAP is wired (C-5, spec 3.7), configure the guest eth0 from the
    // kernel `ip=` parameter (kernel IP autoconfig, CONFIG_IP_PNP) so the genome
    // has an address, a gateway (the host TAP end), and a route, and can ATTEMPT
    // egress without configuring the interface itself off the read-only root. The
    // gateway 172.16.0.1 is the host TAP; nftables default-deny on the TAP drops
    // anything the VM sends there (gate G4). Format:
    // ip=<client>:<server>:<gw>:<mask>:<host>:<dev>:<autoconf>.
    if params.tap_name.is_some() {
        boot_args.push_str(
            " ip=172.16.0.2::172.16.0.1:255.255.255.252:kirby-genome:eth0:off",
        );
    }

    // The jailer drops firecracker to the daemon's uid/gid so the host daemon and
    // the jailed VMM share the vsock Unix socket file. The jailer itself still
    // runs as root (it must) via sudo, and keeps chroot plus cgroup plus
    // namespaces plus seccomp fully intact.
    let ownership_model = VmmOwnershipModel::Downgraded { uid: params.jail_uid, gid: params.jail_gid };

    // The sudo spawner: NOPASSWD (no password supplied), the explicit NixOS sudo
    // wrapper path. fctools shells `sudo jailer ...` through it (the locked D-7
    // launch decision); the jailer is never bypassed.
    let spawner = SudoProcessSpawner::new(None, Some(params.sudo_bin.clone()));

    let installation = VmmInstallation::new(
        params.firecracker_bin.clone(),
        params.jailer_bin.clone(),
        // snapshot-editor: not used in C-2 (snapshots are C-7). The dev shell
        // ships it alongside firecracker; pass the same firecracker dir's
        // sibling so the installation is well-formed.
        params.jailer_bin.with_file_name("snapshot-editor"),
    );

    // The vsock device: the genome to daemon gateway transport (spec 3.1). The
    // uds is a Produced resource (Firecracker creates it inside the jail); after
    // start its effective path is the host-side base Unix socket.
    let mut resource_system = ResourceSystem::new(spawner, TokioRuntime, ownership_model);

    let kernel_resource = resource_system
        .create_resource(params.vmlinux.clone(), ResourceType::Moved(MovedResourceType::Copied))
        .map_err(|e| anyhow::anyhow!("register kernel resource: {e}"))?;
    let rootfs_resource = resource_system
        .create_resource(params.rootfs.clone(), ResourceType::Moved(MovedResourceType::Copied))
        .map_err(|e| anyhow::anyhow!("register rootfs resource: {e}"))?;
    // The vsock uds is a Produced resource (Firecracker creates it inside the
    // jail). Its initial path is a naming hint only (never created on the host);
    // the jailer relocates it to `<jail>/root/<jail_join(initial)>`, and the
    // daemon binds `<that>_<port>`. A bare short filename keeps that final path
    // well under the Unix-socket SUN_LEN limit (108 bytes), since the jail path
    // itself is already long.
    let vsock_uds_resource = resource_system
        .create_resource(PathBuf::from("/k.sock"), ResourceType::Produced)
        .map_err(|e| anyhow::anyhow!("register vsock uds resource: {e}"))?;

    // The VM's network interface (C-5, spec 3.7): the per-VM TAP, if one was
    // wired. The genome gets a deterministic guest MAC so it can configure the
    // link and ATTEMPT egress; the host TAP is locked down default-deny by
    // nftables (network::VmTap), so the attempt is dropped (gate G4). A vsock-only
    // VM (None) gets no interface, so it is already egress-isolated structurally.
    let network_interfaces = match &params.tap_name {
        Some(tap) => vec![NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: tap.clone(),
            guest_mac: Some(crate::network::GUEST_MAC.to_string()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        }],
        None => Vec::new(),
    };

    let configuration = VmConfiguration::New {
        init_method: InitMethod::ViaApiCalls,
        data: VmConfigurationData {
            boot_source: BootSource {
                kernel_image: kernel_resource,
                boot_args: Some(boot_args),
                initrd: None,
            },
            drives: vec![Drive {
                drive_id: "rootfs".to_string(),
                is_root_device: true,
                cache_type: None,
                partuuid: None,
                is_read_only: Some(true),
                block: Some(rootfs_resource),
                rate_limiter: None,
                io_engine: None,
                socket: None,
            }],
            pmem_devices: Vec::new(),
            machine_configuration: MachineConfiguration {
                vcpu_count: params.vcpu_count,
                mem_size_mib: params.mem_size_mib,
                smt: None,
                // track_dirty_pages is needed for incremental snapshots (C-7);
                // harmless to enable now and keeps the boot path identical.
                track_dirty_pages: Some(true),
                huge_pages: None,
            },
            // The cross-CPU snapshot template (D-8, gate G6): a snapshot-capable VM
            // boots under a CPU template so its snapshot restores on a compatible
            // different Intel CPU. A non-snapshot VM (C-2..C-6) boots with no template
            // (None), so those paths are byte-identical to before. Firecracker rejects
            // a malformed template at boot, so a snapshot-capable VM that reaches
            // Running proves the template is in effect (the section 11 no-silent-no-op
            // mitigation).
            cpu_template: if params.snapshot_capable {
                Some(cross_cpu_template()?)
            } else {
                None
            },
            network_interfaces,
            balloon_device: None,
            vsock_device: Some(VsockDevice { guest_cid: params.guest_cid, uds: vsock_uds_resource.clone() }),
            logger_system: None,
            metrics_system: None,
            memory_hotplug_configuration: None,
            mmds_configuration: None,
            entropy_device: None,
        },
    };

    // Prepare the dedicated cgroup parent the jailer nests the VM cgroup under
    // (C-4 metering placement). The daemon creates it under its OWN delegated
    // user slice and enables the cpu and memory controllers, so the root jailer
    // (via sudo) creates the VM cgroup at a deterministic, daemon-readable path.
    // This resolves the C-2-verifier flag (the jailer otherwise inherits the
    // launching shell's cgroup, leaving metering nothing clean to read).
    prepare_meter_cgroup_parent(&params.parent_cgroup_rel)?;
    let cgroup_rel_path = params.parent_cgroup_rel.join(&params.jail_id);

    // The jailer arguments: a unique jail id, cgroup v2 (the host is v2), a
    // daemon-writable chroot base, and the dedicated parent cgroup plus a cgroup
    // file so the jailer actually CREATES the v2 cgroup (with only
    // --cgroup-version 2 and no --cgroup the jailer leaves firecracker in the
    // launching process's cgroup; one --cgroup forces it to build the dedicated
    // hierarchy). cpu.max=max imposes no quota (the spike meters, it does not
    // throttle); it exists to trigger the cgroup creation under the parent. NOT
    // daemonized, so the firecracker stdout pipe (the guest serial console) is
    // capturable for the boot log.
    let jail_id = params
        .jail_id
        .clone()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid jail id {:?}: {e:?}", params.jail_id))?;
    let jailer_arguments = JailerArguments::new(jail_id)
        .cgroup_version(JailerCgroupVersion::V2)
        .parent_cgroup(params.parent_cgroup_rel.as_os_str())
        .cgroup("cpu.max", "max")
        .chroot_base_dir(params.chroot_base_dir.clone());

    let api_socket = PathBuf::from("firecracker.sock");
    let executor = JailedVmmExecutor::new(
        VmmArguments::new(VmmApiSocket::Enabled(api_socket)),
        jailer_arguments,
        FlatVirtualPathResolver,
    );

    tracing::info!(jail_id = %params.jail_id, "preparing jail (sudo: chown chroot, copy kernel and rootfs)");
    let mut vm = GenomeVm::prepare(executor, resource_system, installation, configuration)
        .await
        .map_err(|e| anyhow::anyhow!("prepare VM (jail setup, sudo jailer): {e}"))?;

    // Boot. fctools launches `sudo jailer ... -- firecracker ...`, waits for the
    // API socket, then issues the configure-and-InstanceStart API calls.
    tracing::info!("jail prepared; launching sudo jailer and starting the VM");
    vm.start(Duration::from_secs(20))
        .await
        .map_err(|e| anyhow::anyhow!("start VM under jailer: {e}"))?;

    // The vsock uds effective path is the host-side base Unix socket Firecracker
    // created inside the jail. The gateway binds `<base>_<port>`.
    let uds_base = vsock_uds_resource
        .get_effective_path()
        .ok_or_else(|| anyhow::anyhow!("vsock uds resource has no effective path after start"))?
        .to_path_buf();

    // The VM cgroup the jailer created exists now; confirm the path is present so
    // a metering attach later does not silently bill zero on a placement that
    // failed (the C-4 meter also re-checks, this is an early, clear signal).
    let cgroup_abs = std::path::Path::new("/sys/fs/cgroup").join(&cgroup_rel_path);
    if cgroup_abs.is_dir() {
        tracing::info!(path = %cgroup_abs.display(), "VM placed in dedicated cgroup (C-4 metering reads it here)");
    } else {
        tracing::warn!(
            path = %cgroup_abs.display(),
            "VM cgroup directory not found after start; metering attach will fail loudly"
        );
    }

    Ok(BootedVm { vm, uds_base, gateway_port: params.gateway_port, cgroup_rel_path, tap })
}

/// Restore a genome microVM from a transferred snapshot on THIS node (gate G6,
/// the cross-node resume). Boots a FRESH jailed VMM (the same D-7 boundary as a
/// cold boot: chroot + cgroup + namespaces + seccomp, launched via sudo), loads
/// the mem+vmstate pair, rebuilds the host plumbing the snapshot does not carry
/// (a fresh TAP + nftables lockdown if requested, a fresh vsock), and resumes the
/// guest to Running. Backend-internal: the daemon reaches it via
/// `FirecrackerBackend::restore`, which hands the artifact + `RestoreSpec`.
///
/// The snapshot moved only the mem+vmstate pair; the rootfs is pre-staged on this
/// node (D-8) and re-provisioned into the fresh jail from `spec.image`. This
/// mirrors fctools' `VmSnapshot::prepare_vm` recipe but takes the rootfs/kernel
/// from the pre-staged image (no source VM is present on the target node in a true
/// two-host run), so the restore depends ONLY on the transferred artifact + the
/// pre-staged image, not on the source VM.
pub(crate) async fn restore(
    artifact: SnapshotArtifact,
    spec: RestoreSpec,
) -> anyhow::Result<BootedVm> {
    // Re-check the resume class: this backend may only restore an artifact of its
    // own class (Firecracker x x86_64 x T2CL). The scheduler already picked a
    // same-class node; this refuses an incompatible artifact rather than loading
    // it. (A macOS VZ save is a different class and would fail here, the
    // non-interchangeable-artifact gap made enforceable.)
    let my_class = FirecrackerBackend::snapshot_class();
    if !artifact.class.restorable_on(&my_class) {
        anyhow::bail!(
            "snapshot class {:?} is not restorable on this backend (class {:?})",
            artifact.class,
            my_class
        );
    }

    // The backend-private restore data is the source VM's configuration (vCPU, mem,
    // devices). Downcast it back; a mismatch means a different backend produced the
    // artifact (already refused by the class check, this is defense-in-depth).
    let configuration_data: VmConfigurationData = *artifact
        .restore_data
        .downcast::<VmConfigurationData>()
        .map_err(|_| anyhow::anyhow!("snapshot restore_data is not a Firecracker VmConfigurationData"))?;

    let firecracker_bin = which("firecracker")?;
    let jailer_bin = which("jailer")?;
    let sudo_bin = crate::prereqs::resolve_sudo()?;
    let (uid, gid) = current_uid_gid();
    // A fresh jail id for the restored guest on THIS node (distinct from the source
    // jail, so the same-host harness keeps node 1 and node 2 separate).
    let jail_id = format!("{}-{}", sanitize(&spec.instance_id), std::process::id());

    // A fresh per-VM TAP + nftables lockdown on the target node (the TAP dropped on
    // the move, the plan's "network re-attach on resume"), so egress stays
    // default-deny after a resume too. None => vsock-only restored guest.
    let tap = if spec.lockdown_egress {
        Some(crate::network::VmTap::create(&jail_id, uid, gid, sudo_bin.clone())?)
    } else {
        None
    };
    // The restored snapshot's eth0 is overridden onto the fresh TAP (the snapshot
    // froze the source TAP's name; the restore re-points eth0 at this node's TAP).
    let network_overrides = match &tap {
        Some(tap) => vec![NetworkOverride {
            iface_id: "eth0".to_string(),
            host_dev_name: tap.name().to_string(),
        }],
        None => Vec::new(),
    };

    let chroot_base_dir = PathBuf::from("/tmp/kj");
    let parent_cgroup_rel = meter_cgroup_parent_rel(uid);
    prepare_meter_cgroup_parent(&parent_cgroup_rel)?;
    let cgroup_rel_path = parent_cgroup_rel.join(&jail_id);

    let ownership_model = VmmOwnershipModel::Downgraded { uid, gid };
    let spawner = SudoProcessSpawner::new(None, Some(sudo_bin.clone()));
    let installation = VmmInstallation::new(
        firecracker_bin,
        jailer_bin.clone(),
        jailer_bin.with_file_name("snapshot-editor"),
    );

    // The fresh resource system for the restored VMM. Register the transferred
    // mem+vmstate pair (copied into the jail) and re-provision the pre-staged
    // rootfs + kernel (the snapshot references the rootfs by host path; it must
    // exist in the fresh jail). The vmstate's recorded device model is otherwise
    // self-contained.
    let mut resource_system = ResourceSystem::new(spawner, TokioRuntime, ownership_model);
    let mem_resource = resource_system
        .create_resource(artifact.mem_path.clone(), ResourceType::Moved(MovedResourceType::Copied))
        .map_err(|e| anyhow::anyhow!("register restored mem resource: {e}"))?;
    let snapshot_resource = resource_system
        .create_resource(artifact.vmstate_path.clone(), ResourceType::Moved(MovedResourceType::Copied))
        .map_err(|e| anyhow::anyhow!("register restored vmstate resource: {e}"))?;
    // Re-provision the rootfs (and kernel, harmless) into the fresh jail from the
    // pre-staged image, so the restored block device backing exists on this node.
    let _kernel_resource = resource_system
        .create_resource(spec.image.kernel.clone(), ResourceType::Moved(MovedResourceType::Copied))
        .map_err(|e| anyhow::anyhow!("register restored kernel resource: {e}"))?;
    let _rootfs_resource = resource_system
        .create_resource(spec.image.rootfs.clone(), ResourceType::Moved(MovedResourceType::Copied))
        .map_err(|e| anyhow::anyhow!("register restored rootfs resource: {e}"))?;
    // A fresh vsock uds for the restored guest: the genome re-dials the host CID on
    // the gateway port and firecracker connects to `<base>_<port>` in THIS jail, so
    // the target daemon serves a fresh gateway there (the post-resume round-trip).
    let vsock_uds_resource = resource_system
        .create_resource(PathBuf::from("/k.sock"), ResourceType::Produced)
        .map_err(|e| anyhow::anyhow!("register restored vsock uds resource: {e}"))?;

    // The snapshot's frozen config carried the SOURCE vsock device (with the source
    // jail's uds). Re-point it at this node's fresh vsock uds so the restored guest's
    // host-side vsock binds in THIS jail (the genome re-dials and reaches the target
    // daemon's gateway). The guest CID is unchanged (the genome dials host CID 2).
    let mut configuration_data = configuration_data;
    if let Some(vsock) = configuration_data.vsock_device.as_mut() {
        vsock.uds = vsock_uds_resource.clone();
    }

    let load_snapshot = LoadSnapshot {
        // Match the source: dirty-page tracking stays on so a future incremental
        // snapshot of the restored VM is efficient (harmless for a full restore).
        track_dirty_pages: Some(true),
        mem_backend: MemoryBackend {
            backend_type: MemoryBackendType::File,
            backend: mem_resource,
        },
        snapshot: snapshot_resource,
        // Resume immediately: the restored guest runs (the genome's vCPUs continue
        // from the frozen state), so the post-resume round-trip can happen (G6).
        resume_vm: Some(true),
        network_overrides,
    };

    let configuration = VmConfiguration::RestoredFromSnapshot {
        load_snapshot,
        data: configuration_data,
    };

    // The fresh jail for the restored VMM: same shape as a cold boot (a unique jail
    // id, cgroup v2 under the daemon's delegated slice so metering can read it, a
    // daemon-writable chroot base). The jailer is fully intact (D-7), launched via
    // sudo, dropping firecracker to the daemon's uid so the daemon binds the vsock.
    let jail_id_arg = jail_id
        .clone()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid restored jail id {jail_id:?}: {e:?}"))?;
    let jailer_arguments = JailerArguments::new(jail_id_arg)
        .cgroup_version(JailerCgroupVersion::V2)
        .parent_cgroup(parent_cgroup_rel.as_os_str())
        .cgroup("cpu.max", "max")
        .chroot_base_dir(chroot_base_dir);

    let api_socket = PathBuf::from("firecracker.sock");
    let executor = JailedVmmExecutor::new(
        VmmArguments::new(VmmApiSocket::Enabled(api_socket)),
        jailer_arguments,
        FlatVirtualPathResolver,
    );

    tracing::info!(jail_id = %jail_id, "preparing fresh jail for snapshot restore (sudo jailer; rootfs pre-staged)");
    let mut vm = GenomeVm::prepare(executor, resource_system, installation, configuration)
        .await
        .map_err(|e| anyhow::anyhow!("prepare restored VM (fresh jail): {e}"))?;

    // Launch the fresh firecracker and load+resume the snapshot. After start the
    // guest is Running from the snapshot (the genome's frozen vCPUs resumed).
    tracing::info!("fresh jail prepared; launching sudo jailer and loading the snapshot");
    vm.start(Duration::from_secs(20))
        .await
        .map_err(|e| anyhow::anyhow!("start restored VM (snapshot load + resume): {e}"))?;

    let uds_base = vsock_uds_resource
        .get_effective_path()
        .ok_or_else(|| anyhow::anyhow!("restored vsock uds resource has no effective path after start"))?
        .to_path_buf();

    let cgroup_abs = std::path::Path::new("/sys/fs/cgroup").join(&cgroup_rel_path);
    if cgroup_abs.is_dir() {
        tracing::info!(path = %cgroup_abs.display(), "restored VM placed in dedicated cgroup (metering reads it here)");
    } else {
        tracing::warn!(path = %cgroup_abs.display(), "restored VM cgroup not found; metering attach would fail loudly");
    }

    tracing::info!("VM restored from snapshot and resumed to Running (gate G6)");
    Ok(BootedVm { vm, uds_base, gateway_port: spec.gateway_port, cgroup_rel_path, tap })
}

/// Create the parent cgroup the jailer nests the VM cgroup under, and enable the
/// cpu and memory controllers in its subtree so the child VM cgroup exposes
/// `cpu.stat` and `memory.current` (C-4 metering). This runs as the daemon's own
/// uid against its DELEGATED user-slice subtree (cgroup2 is delegated to the
/// daemon's uid, the C-1 finding), so it needs no root: the daemon owns this
/// subtree. The jailer (root, via sudo) then creates the VM cgroup one level
/// down, and its files are world-readable within this delegated subtree, so the
/// daemon reads them rootlessly.
///
/// In cgroup v2 a controller's interface files appear in a child only when that
/// controller is enabled in the PARENT's `cgroup.subtree_control`. So enabling
/// `+cpu +memory` here is what makes the jailer-created child carry `cpu.stat`
/// (with usage_usec) and `memory.current`. Idempotent: an existing parent and an
/// already-enabled controller are not errors.
fn prepare_meter_cgroup_parent(parent_rel: &Path) -> anyhow::Result<()> {
    let parent_abs = Path::new("/sys/fs/cgroup").join(parent_rel);

    // Create the parent (and any intervening daemon-owned levels). mkdir under a
    // delegated subtree is permitted for the delegatee without root.
    std::fs::create_dir_all(&parent_abs).map_err(|e| {
        anyhow::anyhow!(
            "create meter cgroup parent {}: {e} (is cgroup2 delegated to this uid? see the prereqs gate)",
            parent_abs.display()
        )
    })?;

    // Enable cpu and memory in the parent's subtree_control so the child VM
    // cgroup exposes their interface files. Writing the controllers it already
    // has is harmless; a controller not delegated to this subtree would error,
    // which is the honest signal that rootless metering is not available here.
    let subtree = parent_abs.join("cgroup.subtree_control");
    if let Err(e) = std::fs::write(&subtree, "+cpu +memory") {
        // Already-enabled writes can return EINVAL/EBUSY on some kernels; only
        // treat it as fatal if the controllers are genuinely absent afterwards.
        let current = std::fs::read_to_string(&subtree).unwrap_or_default();
        let has_cpu = current.split_whitespace().any(|c| c == "cpu");
        let has_mem = current.split_whitespace().any(|c| c == "memory");
        if !(has_cpu && has_mem) {
            return Err(anyhow::anyhow!(
                "enable cpu+memory in {}: {e} (delegated controllers: {current:?})",
                subtree.display()
            ));
        }
    }
    Ok(())
}

/// Resolve a binary on PATH to an absolute path (firecracker, jailer). The
/// prereqs gate (C-1) already verified these are present in the dev shell.
fn which(bin: &str) -> anyhow::Result<PathBuf> {
    let path_var = std::env::var_os("PATH").ok_or_else(|| anyhow::anyhow!("PATH unset"))?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("{bin} not found on PATH (enter the nix dev shell)")
}

/// The current real uid and gid, read from /proc/self/status. The jailer drops
/// firecracker to these so the daemon and the jailed VMM share the vsock socket.
fn current_uid_gid() -> (u32, u32) {
    let read_first = |prefix: &str| -> Option<u32> {
        std::fs::read_to_string("/proc/self/status").ok().and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix(prefix))
                .and_then(|rest| rest.split_whitespace().next().map(str::to_string))
                .and_then(|v| v.parse().ok())
        })
    };
    (read_first("Uid:").unwrap_or(1000), read_first("Gid:").unwrap_or(1000))
}

/// Sanitize an instance id into a jail-id-safe token (alphanumerics and dashes).
fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).collect()
}

/// The parent cgroup (relative to the cgroup v2 mount) the jailer nests a VM's
/// cgroup under, for C-4 metering. It lives under the daemon's DELEGATED
/// user-slice subtree (`user.slice/user-<uid>.slice/user@<uid>.service`, the C-1
/// finding that cgroup2 is delegated to the daemon's uid), so the daemon creates
/// it and reads the VM cgroup beneath it without root. The shared `kirby` parent
/// holds one child per jail; the VM cgroup is `<this>/<jail_id>` (the v1.15.1
/// jailer in v2 mode names the cgroup directly by the jail id).
fn meter_cgroup_parent_rel(uid: u32) -> PathBuf {
    PathBuf::from(format!(
        "user.slice/user-{uid}.slice/user@{uid}.service/kirby"
    ))
}
