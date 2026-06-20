//! The sandbox backend seam (spec 5, the cross-platform plan
//! `kirby-cross-platform-sandbox-20260617.md`).
//!
//! A node must run the genome inside a hardware-isolated guest. The MECHANICS of
//! that guest (boot it, expose the host-side vsock the gateway serves on, locate
//! it for CPU+memory metering, install and meter the egress lockdown, halt it)
//! are backend-specific: Linux uses Firecracker (KVM + the jailer; the only
//! backend built so far), and a macOS node would use Apple Virtualization.framework
//! (a future backend, built on a Mac, not here). This module is the interface the
//! daemon drives so a second backend can slot in without touching the
//! economic/gateway logic.
//!
//! WHAT IS BEHIND THIS SEAM (backend mechanics, one impl per platform):
//! - boot a guest microVM from the content-addressed image;
//! - the host-side vsock gateway transport the daemon serves `NodeGateway` over;
//! - the meter source for CPU+memory (Linux = the VM's dedicated cgroup v2);
//! - the egress lockdown + per-VM egress meter handle (Linux = TAP + nftables
//!   default-deny + the eBPF byte meter);
//! - halt (daemon-initiated kill + teardown of the VM and its egress plumbing).
//!
//! WHAT IS NOT behind this seam (identical on every backend, deliberately kept
//! out): the [`crate::gateway::NodeGateway`] service and its spec 3.2 authorize
//! order, the unforgeable [`crate::treasury`], the [`crate::rail`] (Rail/MockRail),
//! the meter BURN MATH ([`crate::meter::BurnRates`] and the treasury debit), and
//! the genome itself. The genome talks ONLY vsock to the gateway, never the host,
//! so it is portable across backends unchanged; that invariant is what makes one
//! interface honest (see the cross-platform plan, "the keystone").
//!
//! SCOPE: this seam captures the currently-built capabilities (boot,
//! host-vsock-gateway transport, meter source, egress lockdown+meter, halt) PLUS
//! snapshot/resume (C-7): [`SandboxInstance::snapshot`] pauses the guest and
//! produces a backend-tagged [`SnapshotArtifact`], and [`SandboxBackend::restore`]
//! boots a fresh guest from a transferred artifact whose [`SnapshotClass`] matches
//! this backend. Consensus (C-9) is NOT built yet and is not on the trait.
//!
//! THE TWO RESUME MECHANISMS (the cross-platform plan's hybrid). C-7 builds the
//! SAME-PLATFORM VM-snapshot path: pause the running guest, write its mem+vmstate
//! pair (CPU-template normalized so it restores on a compatible CPU), move that
//! pair to a target node, and restore the live guest there. That artifact is
//! tagged with a [`SnapshotClass`] (backend x guest-arch x CPU-class) and may
//! ONLY be restored on a node whose backend reports a MATCHING class, so the
//! scheduler picks the resume node by class match, never blindly. The PORTABLE
//! cross-backend path (an application-level checkpoint that boots a FRESH guest on
//! ANY backend and rehydrates logical state) is a SIBLING mechanism kirby-mac adds
//! for the macOS/VZ backend; it is NOT built here (a VZ Linux-guest save is
//! Mac-bound and unreliable, so macOS leans on the app checkpoint). The
//! [`BackendCapabilities`] carry both `snapshot: Option<SnapshotClass>` and
//! `app_checkpoint: bool` so the scheduler can choose the mechanism per backend
//! pair; see the app-checkpoint note on [`BackendCapabilities`] for exactly where
//! that sibling slots in WITHOUT reworking the VM-snapshot path built here.

use std::path::PathBuf;

/// Which sandbox backend an instance came from. The daemon stays backend-agnostic
/// for the economic/gateway logic, but a few decisions (the metering fidelity it
/// trusts, the resume mechanism it may use later) are backend-aware, so the
/// backend names itself here. Only `Firecracker` exists today; the cross-platform
/// plan adds `VirtualizationFramework` (macOS) as the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// Linux/KVM Firecracker under the jailer (the reference backend, built).
    Firecracker,
    /// macOS Apple Virtualization.framework. Built on Darwin only.
    #[cfg(target_os = "macos")]
    VirtualizationFramework,
}

/// Post-escape isolation strength of a backend (the cross-platform plan's
/// "isolation after escape" axis). Firecracker keeps an escaped guest inside the
/// jailer (chroot + seccomp + namespaces + uid-drop); a macOS VZ escape would land
/// in an unconfined host process, so the backend declares this so policy can
/// require a tier later (birth-cert `required_isolation`). Informational for the
/// spike; carried so the daemon does not bake in a Firecracker assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationTier {
    /// Hardware VM boundary PLUS an OS-level cage on escape (Firecracker: the
    /// jailer's chroot/seccomp/namespaces/uid-drop).
    HardwareVmJailed,
    /// Hardware VM boundary only. VZ has no jailer-equivalent post-escape cage,
    /// so policy can distinguish it from Firecracker.
    #[cfg(target_os = "macos")]
    HardwareVm,
}

/// How much the daemon should trust this backend's metering, and therefore how
/// wide a budget-halt margin it needs (the cross-platform plan's "meter fidelity"
/// axis). Linux cgroups+eBPF are tick-accurate with a hard memory bound; macOS
/// rusage/pf would be coarser with only a boot-time memory cap. The burn math is
/// identical; only the source fidelity differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterFidelity {
    /// Authoritative, tick-accurate, hard running memory bound (Linux cgroups v2
    /// `cpu.stat`/`memory.current` + the eBPF egress byte counter).
    CgroupExact,
    /// Coarser host-side accounting. macOS has no cgroup v2 equivalent; VZ uses
    /// boot-time memory caps and later Mach/rusage sampling.
    #[cfg(target_os = "macos")]
    HostCoarse,
}

/// What a backend can do, surfaced so the daemon can reason about it without
/// hardcoding Firecracker. The cross-platform plan's capability axes; the
/// scheduler reasons over these to admit an agent and to pick a resume mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub backend: BackendKind,
    /// The guest CPU architecture the backend boots (the genome image must match).
    pub guest_arch: GuestArch,
    pub isolation: IsolationTier,
    pub metering: MeterFidelity,
    /// The VM-snapshot resume class this backend produces and can restore, or
    /// `None` if the backend has no VM-snapshot support (e.g. libkrun). A snapshot
    /// artifact may only be restored on a backend whose `snapshot` class MATCHES
    /// the artifact's class (backend x arch x CPU-class), so the scheduler picks
    /// a same-class node for a fast VM-snapshot resume (G6) and never restores an
    /// incompatible artifact. Firecracker reports `Some(IntelT2CL-class)`.
    pub snapshot: Option<SnapshotClass>,
    /// Whether this backend can resume a genome from an APPLICATION-level checkpoint
    /// (boot a fresh guest on ANY backend/arch and rehydrate the genome's logical
    /// state). This is the PORTABLE cross-backend path, independent of VM-snapshot
    /// support: true for any backend that runs the genome. The spike does NOT build
    /// this path (it is kirby-mac's VZ work); the flag is carried so the scheduler
    /// can fall back to it when no same-`snapshot`-class node is available, and so
    /// the birth-cert portability stance (SameClassOnly vs CrossBackend) is a
    /// declared, admission-checked property. See the module header and the
    /// "where the app-checkpoint slots in" note in [`SandboxBackend`].
    pub app_checkpoint: bool,
}

/// The guest CPU architecture a backend boots. The genome image is built for one;
/// a backend on a different host arch needs a matching image (the plan's
/// SnapshotClass arch axis). Only x86_64 is built for the spike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArch {
    X86_64,
    /// AArch64 Linux guest, the Apple Silicon VZ image.
    #[cfg(target_os = "macos")]
    Aarch64,
}

/// The CPU-normalization class a VM snapshot is created under, so it restores on a
/// DIFFERENT CPU of the same family (the cross-platform plan's "same hypervisor +
/// same arch + different CPU needs a CPU template" axis). Firecracker applies a
/// named static CPU template at VM create (T2CL for Intel, T2A for AMD), masking
/// host-specific features so a snapshot taken on one CPU loads on another in the
/// class. The class is part of the [`SnapshotClass`] the scheduler matches on. The
/// spike host is Intel (vmx, the C-1 finding), so it uses the T2CL template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuClass {
    /// Intel CPUs under the Firecracker T2CL static template (the cross-CPU Intel
    /// baseline). Applied at create so the snapshot restores on any T2CL-compatible
    /// Intel CPU. (AMD's T2A class is the sibling; not used on this Intel host.)
    IntelT2CL,
}

/// The resume-compatibility class of a VM snapshot: a snapshot is only restorable
/// on a node whose backend reports a MATCHING class. It is the cross-platform
/// plan's non-interchangeable-artifact gap made into a value the scheduler matches
/// on (never a generic snapshot it blindly trusts): a Firecracker/x86/T2CL snapshot
/// restores only on another Firecracker/x86/T2CL node; a macOS VZ save (a different
/// backend) is a different class and cannot consume it. The class is `backend x
/// guest_arch x cpu_class`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotClass {
    pub backend: BackendKind,
    pub guest_arch: GuestArch,
    pub cpu_class: CpuClass,
}

impl SnapshotClass {
    /// Whether a snapshot of this class can be restored by a backend that produces
    /// `target` snapshots. The scheduler calls this to pick a same-class resume
    /// node (a fast VM-snapshot resume, G6); a mismatch means the VM-snapshot path
    /// is unavailable and the scheduler must fall back to the app-checkpoint path
    /// (kirby-mac's portable sibling, not built here).
    pub fn restorable_on(&self, target: &SnapshotClass) -> bool {
        self == target
    }
}

/// A produced VM snapshot: the mem+vmstate pair plus the backend-private data a
/// restore needs, tagged with its [`SnapshotClass`]. Backend-neutral so the
/// orchestration can transfer it (the D-13 seam) and hand it to a backend's
/// `restore` without naming a concrete VM type. The `restore_data` is opaque to
/// the agnostic layer (the Firecracker backend stuffs its `VmSnapshot`
/// configuration there); only the producing backend interprets it. The genome's
/// re-derive-on-resume invariant (G7) is enforced by the genome + gateway (it
/// re-fetches a fresh entropy nonce after the generation bumps), NOT by the
/// artifact, so no ephemeral secret is carried here.
pub struct SnapshotArtifact {
    /// The vmstate file: the microVM device + vCPU state Firecracker writes.
    pub vmstate_path: PathBuf,
    /// The guest-RAM memory file (the bulk of the snapshot).
    pub mem_path: PathBuf,
    /// The resume-compatibility class (backend x arch x CPU-class). A restore
    /// target's backend must report a matching `snapshot` class.
    pub class: SnapshotClass,
    /// Backend-private restore data, opaque to the agnostic layer. The producing
    /// backend downcasts it in `restore`. (Firecracker: the `VmSnapshot`
    /// configuration data so a fresh VMM can prepare from the files.)
    pub restore_data: Box<dyn std::any::Any + Send>,
}

impl std::fmt::Debug for SnapshotArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotArtifact")
            .field("vmstate_path", &self.vmstate_path)
            .field("mem_path", &self.mem_path)
            .field("class", &self.class)
            .field("restore_data", &"<backend-private>")
            .finish()
    }
}

impl SnapshotArtifact {
    /// The size of the mem+vmstate pair in bytes (the snapshot footprint that
    /// crosses the transfer seam). Best-effort: a missing file counts as 0.
    pub fn footprint_bytes(&self) -> u64 {
        let len = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        len(&self.vmstate_path) + len(&self.mem_path)
    }
}

/// The snapshot transfer seam (D-13, spec 5): move the mem+vmstate pair from the
/// source node to the target node. Behind a trait so the DEFAULT impl is a local
/// directory copy (the same-host harness: "node 1" and "node 2" are two processes
/// on one host, the snapshot moves over a local path) and a TWO-HOST impl (scp,
/// iroh-blobs) drops in later WITHOUT touching the snapshot/restore mechanics: the
/// same artifact, a different transfer. The rootfs is pre-staged on every node via
/// the Nix binary cache (D-8), so ONLY the mem+vmstate pair crosses here.
#[async_trait::async_trait]
pub trait SnapshotTransfer: Send + Sync {
    /// Move the artifact's mem+vmstate pair to the target node and return an
    /// artifact pointing at the moved files (its `class` and backend-private
    /// `restore_data` carry over unchanged; only the file paths change). The source
    /// files may remain (a copy) or be consumed (a move); the restore uses the
    /// returned artifact's paths.
    async fn transfer(&self, artifact: SnapshotArtifact) -> anyhow::Result<SnapshotArtifact>;
}

/// The same-host transfer (D-13 default): copy the mem+vmstate pair into a target
/// directory on the same machine, modeling "move from node 1 to node 2" over a
/// local path. This proves the transfer LOGIC; the two-host cross-CPU transfer
/// (real network, a real second box) is the later acceptance bar (D-15) and is a
/// drop-in [`SnapshotTransfer`] that does not change anything else.
pub struct LocalDirTransfer {
    /// The target directory the pair is copied into (node 2's snapshot inbox).
    pub target_dir: PathBuf,
}

#[async_trait::async_trait]
impl SnapshotTransfer for LocalDirTransfer {
    async fn transfer(&self, artifact: SnapshotArtifact) -> anyhow::Result<SnapshotArtifact> {
        std::fs::create_dir_all(&self.target_dir).map_err(|e| {
            anyhow::anyhow!(
                "create snapshot transfer target dir {}: {e}",
                self.target_dir.display()
            )
        })?;
        let copy_into = |src: &std::path::Path| -> anyhow::Result<PathBuf> {
            let name = src
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("snapshot file has no name: {}", src.display()))?;
            let dst = self.target_dir.join(name);
            std::fs::copy(src, &dst)
                .map_err(|e| anyhow::anyhow!("copy {} -> {}: {e}", src.display(), dst.display()))?;
            Ok(dst)
        };
        // The vmstate file is small; the mem file is the bulk. Both must land
        // before a restore on the target node.
        let vmstate_path = copy_into(&artifact.vmstate_path)?;
        let mem_path = copy_into(&artifact.mem_path)?;
        Ok(SnapshotArtifact {
            vmstate_path,
            mem_path,
            class: artifact.class,
            restore_data: artifact.restore_data,
        })
    }
}

/// Where to restore a snapshot: the target-node host facts the restored guest
/// needs that are NOT carried in the snapshot (the snapshot is the guest's frozen
/// RAM + device state; the host plumbing is rebuilt fresh on the target node). The
/// snapshot transfers the mem+vmstate pair; the ROOTFS is pre-staged on every node
/// (content-addressed via Nix), never transferred (D-8).
pub struct RestoreSpec {
    /// The genome image (kernel + rootfs), PRE-STAGED on the target node via the
    /// Nix binary cache (D-8): the rootfs block device the snapshot references must
    /// exist on the target node at restore (the snapshot moves only the mem+vmstate
    /// pair, not the rootfs). The restore re-provisions it into the fresh jail.
    pub image: GuestImage,
    /// A stable id for the restored guest on the TARGET host (its jail, cgroup,
    /// TAP, vsock uds all derive from it). Distinct from the source instance id so
    /// two node processes on one host (the D-13 same-host harness) stay separate.
    pub instance_id: String,
    /// The gateway vsock port the restored genome dials on the target node. The
    /// in-flight vsock drops across the move (the plan's "in-flight vsock loss on
    /// resume"); the genome re-dials, and the target daemon serves a fresh gateway
    /// on this port over the restored guest's new vsock transport.
    pub gateway_port: u32,
    /// Install the per-VM egress lockdown on the target node too (the TAP drops on
    /// restore, so node 2 wires a fresh TAP + nftables rules, the plan's "network
    /// re-attach on resume"), so egress stays default-deny after a resume. When
    /// false, the restored guest is vsock-only.
    pub lockdown_egress: bool,
}

/// The content-addressed genome image artifacts a boot needs (spec 3.6): the
/// guest kernel (vmlinux, with VMGenID built in) and the read-only squashfs whose
/// only payload is the musl genome at /init. Backend-neutral (the same image boots
/// on any Linux-guest backend; a macOS VZ backend consumes the same squashfs +
/// kernel via VZLinuxBootLoader).
#[derive(Clone)]
pub struct GuestImage {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
}

/// A backend-neutral request to boot one genome guest. The backend translates this
/// into its own launch arguments (the Firecracker backend builds `BootParams` and
/// a per-VM TAP from it). Everything here is intent-level and portable; nothing is
/// Firecracker-specific.
pub struct GuestSpec {
    /// The genome image (kernel + rootfs).
    pub image: GuestImage,
    /// A stable id for this guest on the host (distinguishes per-guest host state:
    /// the jail, the cgroup leaf, the TAP, the treasury). The backend derives its
    /// own resource names from it.
    pub instance_id: String,
    /// The guest CID for this guest's vsock (spec 3.1: one genome per CID, so two
    /// node processes on one host stay distinct). The gateway transport is keyed
    /// to it.
    pub guest_cid: u32,
    /// The gateway vsock port the genome dials and the daemon serves on.
    pub gateway_port: u32,
    /// vCPU count and memory for the guest. Small for the spike.
    pub vcpu_count: u8,
    pub mem_size_mib: usize,
    /// The genome workload the daemon requests on the guest boot parameters
    /// (`kirby.workload=<name>`). `None` idles after the boot round-trip (C-2/G1);
    /// `Some("burn")` runs the metering workload (C-4/G2); `Some("raw-egress")`
    /// runs the egress probe (C-5/G4).
    pub workload: Option<String>,
    /// Install the per-VM egress lockdown (default-deny on the guest's egress) and
    /// wire a metered network interface so the genome can ATTEMPT egress (spec 3.7,
    /// gate G4). When false, the guest is vsock-only (no network interface), which
    /// is egress-isolated structurally. The MECHANISM is the backend's (Linux =
    /// TAP + nftables + eBPF; macOS = vmnet + pf); the INTENT is portable.
    pub lockdown_egress: bool,
    /// Boot this guest so it can be SNAPSHOTTED later (C-7, gate G6): the backend
    /// applies its cross-CPU normalization (Firecracker = the T2CL/T2A CPU template
    /// at create) so a snapshot restores on a compatible different CPU. When false,
    /// the guest boots without the template (the C-2..C-6 default, no snapshot).
    /// Set true for a guest that will be snapshotted + resumed on another node.
    pub snapshot_capable: bool,
}

/// How the daemon's `NodeGateway` reaches THIS guest over vsock. The gateway
/// SERVICE is backend-agnostic (it serves the same four RPCs and the same
/// authorize order regardless); only the host-side listen mechanism differs by
/// backend, so the backend hands the daemon this transport descriptor and the
/// daemon serves the agnostic gateway over it.
///
/// The genome only ever sees the vsock gateway, never the host, so it is portable
/// across backends unchanged (the load-bearing invariant). This enum is that
/// invariant made concrete: a backend says "serve me here," nothing more.
#[derive(Debug, Clone)]
pub enum GatewayTransport {
    /// Firecracker's guest-to-host vsock is host-side a Unix socket: when the guest
    /// dials the host CID on port P, Firecracker connects to `<base>_<P>`. The
    /// daemon binds that path (see `gateway::serve_firecracker_vsock`). The value is
    /// the base path; the port is the guest's `gateway_port`.
    ///
    /// A macOS VZ backend would add a variant here (a `VZVirtioSocketConnection`
    /// host endpoint); the gateway service it serves is identical.
    FirecrackerVsockUds { uds_base: PathBuf, port: u32 },
    /// macOS VZ helper proxy socket. Virtualization.framework owns the virtio-vsock
    /// object; the helper bridges that stream to this Unix socket, where the daemon
    /// serves the same `NodeGateway` tonic service.
    #[cfg(target_os = "macos")]
    VzVsockProxyUds { uds_path: PathBuf, port: u32 },
}

/// Where the daemon reads host-authoritative CPU+memory consumption for THIS
/// guest. The meter BURN MATH ([`crate::meter::BurnRates`]) is backend-agnostic;
/// only the SOURCE it samples is backend-specific, so the backend hands the daemon
/// this descriptor and the agnostic meter samples it. Today only the Linux cgroup
/// source exists; a macOS backend would add a `HostThreads`/rusage variant and the
/// metered-run orchestration would gain a match arm, with the burn math untouched.
#[derive(Debug, Clone)]
pub enum MeterSource {
    /// The guest's dedicated cgroup v2, RELATIVE to the unified mount root
    /// (`/sys/fs/cgroup`). The jailer created it under the daemon's delegated user
    /// slice, so the daemon reads `cpu.stat usage_usec` + `memory.current` there
    /// rootlessly (C-4).
    CgroupV2 { rel_path: PathBuf },
    /// A macOS VZ process accounting source. CPU is read from the helper process
    /// plus the discovered launchd-owned VZ VM service pids; memory is billed
    /// against the VZ boot-time cap because macOS has no cgroup-style running
    /// memory ceiling.
    #[cfg(target_os = "macos")]
    HostProcess {
        root_pid: u32,
        service_pids: Vec<u32>,
        memory_mib: usize,
    },
}

/// A booted genome guest: the per-instance handle the daemon drives. The backend
/// produced it from a [`GuestSpec`]; it exposes exactly the backend-specific
/// surfaces the orchestration needs (the gateway transport to serve the agnostic
/// gateway over, the meter source to bill, the egress handle for the lockdown
/// meter + G4 evidence, the running/console signals, and halt). It does NOT expose
/// any gateway/treasury/rail logic; that is agnostic and lives outside the backend.
#[async_trait::async_trait]
pub trait SandboxInstance: Send {
    /// Whether the guest reached the running state after boot (the G1 boot
    /// evidence the daemon logs).
    fn is_running(&mut self) -> bool;

    /// The host-side vsock transport the daemon serves the agnostic `NodeGateway`
    /// over for this guest (spec 3.1). The genome dials the gateway over vsock; the
    /// daemon binds the returned transport and serves the same gateway service it
    /// serves on any backend.
    fn gateway_transport(&self) -> GatewayTransport;

    /// The host-authoritative CPU+memory meter source for this guest (spec 3.3).
    /// The agnostic meter samples it; the burn math is the same on every backend.
    fn meter_source(&self) -> MeterSource;

    /// The per-VM egress control for this guest, if it was booted with the egress
    /// lockdown (`GuestSpec::lockdown_egress`). Exposes the network-interface name
    /// the eBPF byte meter attaches to and the host-kernel drop counter (the G4
    /// evidence that the kernel dropped the guest's egress attempt). `None` for a
    /// vsock-only guest (no network interface; egress-isolated structurally).
    fn egress_control(&self) -> Option<&dyn EgressControl>;

    /// Stream the guest serial console (or the backend's equivalent boot log) to
    /// tracing as supplementary boot evidence. Best-effort.
    fn stream_console(&mut self);

    /// Snapshot the running guest: PAUSE it, then write its mem+vmstate pair (the
    /// CPU-template normalization applied at boot makes the pair restorable on a
    /// compatible CPU), returning a backend-tagged [`SnapshotArtifact`] (gate G6,
    /// the same-platform VM-snapshot resume path). The guest is left PAUSED (not
    /// killed): the caller transfers the artifact to a target node, restores there,
    /// THEN halts this (now superseded) source guest, so a clean restore exists
    /// before the source is destroyed. The artifact's [`SnapshotClass`] gates which
    /// nodes may restore it. The genome's ephemeral secrets are NOT in the artifact;
    /// the re-derive-on-resume invariant (G7) is enforced by the genome+gateway, so
    /// snapshotting carries no live secret across the move. Returns an error if the
    /// backend has no snapshot support (its `capabilities().snapshot` is `None`) or
    /// the pause/create fails.
    async fn snapshot(&mut self) -> anyhow::Result<SnapshotArtifact>;

    /// Halt the guest: daemon-initiated kill of the VMM PLUS teardown of the guest
    /// and its egress plumbing (the TAP and nftables lockdown on Linux). This is
    /// the daemon-controlled "death" (the budget-halt, C-4, calls it; the failover
    /// kill of the source node after a snapshot, C-7, calls it). Best-effort so a
    /// teardown after a failed boot, or of an already-paused snapshotted guest,
    /// still cleans up. Consumes the instance.
    async fn halt(self: Box<Self>);
}

/// The per-VM egress lockdown control surface (spec 3.7, gate G4). Backend-specific
/// mechanism (Linux = a TAP locked down by nftables, metered by eBPF; macOS would
/// be a vmnet interface locked down by pf), exposed to the orchestration as: the
/// interface name the byte meter attaches to, and the host-kernel drop counter that
/// proves the lockdown dropped the guest's egress attempt.
pub trait EgressControl: Send + Sync {
    /// The host network-interface name the guest's egress arrives on, which the
    /// eBPF byte meter attaches to (Linux: the TAP). The egress METER itself
    /// (per-byte billing against the treasury) is agnostic and lives in
    /// [`crate::meter_egress`]; the backend only says which interface to meter.
    fn iface_name(&self) -> &str;

    /// The host-kernel drop counter for this guest's egress lockdown (packets,
    /// bytes). After the genome's denied egress attempt this shows a non-zero drop
    /// (the host kernel dropped the guest's packets), the G4 evidence.
    fn drop_counter(&self) -> EgressDropCounter;
}

/// The host-kernel egress drop counter for a guest (the G4 evidence). Backend-
/// neutral (Linux fills it from the nftables `dropped_egress` counter).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EgressDropCounter {
    pub packets: u64,
    pub bytes: u64,
}

/// A sandbox backend: the factory the daemon asks to boot a genome guest, plus its
/// capability descriptor. One impl per platform; the daemon holds it as
/// `&dyn SandboxBackend` (or a concrete backend) and never names a concrete VM
/// type. This is the whole point of the seam: swap Firecracker for the macOS VZ
/// backend without touching the gateway/treasury/rail/meter-math/genome.
#[async_trait::async_trait]
pub trait SandboxBackend: Send + Sync {
    /// What this backend can do (so the daemon can reason about it without
    /// hardcoding Firecracker).
    fn capabilities(&self) -> BackendCapabilities;

    /// Boot one genome guest from the spec. On success the guest is running and the
    /// genome is coming up; the caller serves the agnostic gateway over the
    /// instance's [`GatewayTransport`] so the genome's boot round-trip lands. On a
    /// boot failure the backend cleans up any partial host state and returns the
    /// error.
    async fn boot(&self, spec: GuestSpec) -> anyhow::Result<Box<dyn SandboxInstance>>;

    /// Restore a guest from a transferred [`SnapshotArtifact`] on THIS node (gate
    /// G6, the same-platform VM-snapshot resume). The artifact's [`SnapshotClass`]
    /// MUST match this backend's `capabilities().snapshot` (the scheduler picked a
    /// same-class node; this re-checks and refuses a mismatch rather than loading
    /// an incompatible artifact). The backend boots a FRESH jailed VMM (under the
    /// jailer, the same D-7 boundary as a cold boot), loads the mem+vmstate pair,
    /// rebuilds the host plumbing the snapshot does not carry (a fresh TAP +
    /// nftables lockdown per [`RestoreSpec::lockdown_egress`], a fresh vsock the
    /// genome re-dials), and resumes the guest to Running. The genome's vsock dropped
    /// across the move, so it re-establishes the gateway connection and (the C-8
    /// gate) re-derives its entropy after the VMGenID generation bumps; the daemon
    /// bumps the gateway generation on restore (the orchestration calls
    /// `bump_generation`). On success the restored guest is Running and the genome
    /// is reconnecting; the caller serves a fresh gateway over the returned
    /// instance's transport so the post-resume round-trip lands.
    ///
    /// WHERE THE APP-CHECKPOINT SLOTS IN (kirby-mac, NOT built here): when the
    /// scheduler has no node whose `snapshot` class matches the artifact (e.g. the
    /// only healthy node is a macOS VZ backend, a different class), it instead uses
    /// the PORTABLE app-checkpoint path: a sibling restore that boots a fresh guest
    /// via [`SandboxBackend::boot`] (NOT this method) and hands the genome a
    /// `restore_from: CheckpointRef` so it rehydrates its logical state and
    /// re-derives ephemeral secrets (the SAME no-secret-survives-a-move invariant as
    /// G7, enforced on the checkpoint blob). That path uses the agnostic gateway's
    /// genome-pushed `SubmitCheckpoint(CheckpointBlob)` RPC and boot-time checkpoint
    /// metadata in `GetSessionContext`; it does NOT change this `restore` (the
    /// VM-snapshot path) or the five boot/transport/meter/egress/halt methods. The
    /// scheduler chooses between them by [`SnapshotClass::restorable_on`] over the
    /// source class and the target backend's `snapshot`/`app_checkpoint` caps, so
    /// adding the sibling is a new branch at the scheduler, not a rework here.
    async fn restore(
        &self,
        artifact: SnapshotArtifact,
        spec: RestoreSpec,
    ) -> anyhow::Result<Box<dyn SandboxInstance>>;
}
