//! The Apple Virtualization.framework sandbox backend scaffold.
//!
//! This is backend impl #2 behind [`crate::sandbox::SandboxBackend`]. The Mac
//! genome image handoff is complete, so the next blocker is no longer the image,
//! it is the VZ launch and host-side socket shim. This module names the Mac
//! backend in code, reports its honest capabilities, and gives Darwin builds a
//! backend selection target that does not instantiate Firecracker.
//!
//! The intended first real milestone is cold boot plus gateway transport:
//! a small Swift helper owns `VZVirtualMachine`, boots the aarch64 Linux kernel
//! and squashfs, and bridges the VZ virtio-socket stream to a Unix socket
//! where the Rust daemon serves the unchanged `NodeGateway` tonic service.
//! Snapshot/restore is intentionally unsupported here; macOS resume uses the
//! app-level checkpoint path described in `docs/vz-app-checkpoint-resume.md`.

use crate::sandbox::{
    BackendCapabilities, BackendKind, GuestArch, GuestSpec, IsolationTier, MeterFidelity,
    RestoreSpec, SandboxBackend, SandboxInstance, SnapshotArtifact,
};

/// Apple Virtualization.framework backend on macOS.
#[derive(Debug, Default, Clone, Copy)]
pub struct VzBackend;

impl VzBackend {
    pub fn new() -> Self {
        VzBackend
    }
}

#[async_trait::async_trait]
impl SandboxBackend for VzBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::VirtualizationFramework,
            guest_arch: GuestArch::Aarch64,
            isolation: IsolationTier::HardwareVm,
            metering: MeterFidelity::HostCoarse,
            snapshot: None,
            // This is a declared resume capability, not working machinery yet:
            // Track A must land CheckpointRef/CheckpointStore, SubmitCheckpoint,
            // restore_from boot state, and a checkpoint-aware genome before a
            // scheduler can rely on this flag for VZ-6.
            app_checkpoint: true,
        }
    }

    async fn boot(&self, spec: GuestSpec) -> anyhow::Result<Box<dyn SandboxInstance>> {
        validate_vz_boot_spec(&spec)?;
        anyhow::bail!(
            "macOS VZ backend selected and image is present, but cold boot is not implemented yet. \
             Next step: add the Swift VZ helper that boots vmlinux/rootfs.squashfs and bridges \
             VZ virtio-socket port {} to the daemon gateway Unix socket",
            spec.gateway_port
        )
    }

    async fn restore(
        &self,
        _artifact: SnapshotArtifact,
        _spec: RestoreSpec,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        anyhow::bail!(
            "VZ VM-snapshot restore is unsupported for Kirby Linux guests; use the app-checkpoint resume path"
        )
    }
}

fn validate_vz_boot_spec(spec: &GuestSpec) -> anyhow::Result<()> {
    if spec.snapshot_capable {
        anyhow::bail!(
            "VZ does not support Kirby VM-snapshot resume; boot with snapshot_capable=false and use app checkpoints"
        );
    }
    if spec.lockdown_egress {
        anyhow::bail!(
            "VZ egress lockdown is not implemented yet; first Mac milestone is vsock-only cold boot"
        );
    }
    if !spec.image.kernel.is_file() {
        anyhow::bail!(
            "VZ kernel image not found at {}",
            spec.image.kernel.display()
        );
    }
    if !spec.image.rootfs.is_file() {
        anyhow::bail!(
            "VZ rootfs image not found at {}",
            spec.image.rootfs.display()
        );
    }
    Ok(())
}
