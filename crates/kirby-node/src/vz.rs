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

use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use tokio::sync::oneshot;

use crate::sandbox::{
    BackendCapabilities, BackendKind, GatewayTransport, GuestArch, GuestSpec, IsolationTier,
    MeterFidelity, MeterSource, RestoreSpec, SandboxBackend, SandboxInstance, SnapshotArtifact,
};

const VZ_HELPER: &str = env!("KIRBY_VZ_HELPER");
const VZ_READY_TIMEOUT: Duration = Duration::from_secs(30);
const VZ_STOP_TIMEOUT: Duration = Duration::from_secs(5);

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
        let helper = PathBuf::from(VZ_HELPER);
        if !helper.is_file() {
            anyhow::bail!(
                "macOS VZ helper was not built at {}; run `cargo build -p kirby-node` in the dev shell",
                helper.display()
            );
        }

        let gateway_uds = vz_gateway_uds_path(&spec.instance_id, spec.gateway_port);
        if let Err(e) = tokio::fs::remove_file(&gateway_uds).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                anyhow::bail!("remove stale VZ gateway UDS {}: {e}", gateway_uds.display());
            }
        }

        let (vz_kernel, temp_kernel) =
            prepare_vz_kernel(&spec.image.kernel, &spec.instance_id, spec.gateway_port).await?;
        let (vz_rootfs, temp_rootfs) =
            prepare_vz_rootfs(&spec.image.rootfs, &spec.instance_id, spec.gateway_port).await?;
        let vz_service_pids_before = list_vz_virtual_machine_service_pids();

        let mut command = Command::new(&helper);
        command
            .arg("--kernel")
            .arg(&vz_kernel)
            .arg("--rootfs")
            .arg(&vz_rootfs)
            .arg("--gateway-uds")
            .arg(&gateway_uds)
            .arg("--gateway-port")
            .arg(spec.gateway_port.to_string())
            .arg("--cpus")
            .arg(spec.vcpu_count.to_string())
            .arg("--memory-mib")
            .arg(spec.mem_size_mib.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(workload) = &spec.workload {
            command.arg("--workload").arg(workload);
        }
        // Disabled by default. Used by the VERIFY-ON-MAC FIX-3 probe to stop the
        // VM while keeping the helper alive, so framework-fd death can be
        // distinguished from helper-process death.
        if let Ok(ms) = std::env::var("KIRBY_VZ_PROBE_STOP_VM_AFTER_READY_MS") {
            command.arg("--probe-stop-vm-after-ready-ms").arg(ms);
        }
        if let Ok(ms) = std::env::var("KIRBY_VZ_PROBE_PAUSE_VM_AFTER_READY_MS") {
            command.arg("--probe-pause-vm-after-ready-ms").arg(ms);
        }

        tracing::info!(
            helper = %helper.display(),
            kernel = %vz_kernel.display(),
            rootfs = %vz_rootfs.display(),
            gateway_uds = %gateway_uds.display(),
            gateway_port = spec.gateway_port,
            "launching macOS VZ helper"
        );

        let mut child = command
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn macOS VZ helper {}: {e}", helper.display()))?;
        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("spawned VZ helper has no pid"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("VZ helper stdout pipe missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("VZ helper stderr pipe missing"))?;

        stream_helper_stdout(stdout);
        let (ready_tx, ready_rx) = oneshot::channel();
        stream_helper_stderr(stderr, ready_tx);

        match tokio::time::timeout(VZ_READY_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => {
                tracing::info!(pid, "macOS VZ helper reported ready");
            }
            Ok(Ok(Err(e))) => {
                stop_helper_child(&mut child).await;
                return Err(e);
            }
            Ok(Err(_closed)) => {
                stop_helper_child(&mut child).await;
                anyhow::bail!("VZ helper readiness channel closed before READY");
            }
            Err(_elapsed) => {
                stop_helper_child(&mut child).await;
                anyhow::bail!(
                    "VZ helper did not report READY within {}s",
                    VZ_READY_TIMEOUT.as_secs()
                );
            }
        }
        let mut service_pids = list_vz_virtual_machine_service_pids();
        service_pids.retain(|pid| !vz_service_pids_before.contains(pid));
        if std::env::var_os("KIRBY_VZ_PROBE_DROP_SERVICE_PIDS").is_some() {
            tracing::warn!(
                pid,
                service_pids = ?service_pids,
                "KIRBY_VZ_PROBE_DROP_SERVICE_PIDS set; dropping discovered service pids before meter attach"
            );
            service_pids.clear();
        }
        if service_pids.is_empty() {
            tracing::warn!(
                pid,
                "could not identify VZ VirtualMachine service pid; metered macOS G2 runs will fail closed"
            );
        } else {
            tracing::info!(
                pid,
                service_pids = ?service_pids,
                "identified VZ VirtualMachine service pids for host-process metering"
            );
        }

        Ok(Box::new(BootedVzVm {
            child,
            pid,
            service_pids,
            memory_mib: spec.mem_size_mib,
            gateway_uds,
            gateway_port: spec.gateway_port,
            temp_kernel,
            temp_rootfs,
            exited: None,
        }))
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

/// A booted macOS VZ guest. The Swift helper owns VZVirtualMachine and the
/// framework-side vsock listener; Rust owns the helper process and the daemon
/// gateway socket it bridges to.
pub(crate) struct BootedVzVm {
    child: Child,
    pid: u32,
    service_pids: Vec<u32>,
    memory_mib: usize,
    gateway_uds: PathBuf,
    gateway_port: u32,
    temp_kernel: Option<PathBuf>,
    temp_rootfs: Option<PathBuf>,
    exited: Option<ExitStatus>,
}

#[async_trait::async_trait]
impl SandboxInstance for BootedVzVm {
    fn is_running(&mut self) -> bool {
        if self.exited.is_some() {
            return false;
        }
        match self.child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                self.exited = Some(status);
                false
            }
            Err(e) => {
                tracing::warn!(error = %e, pid = self.pid, "failed to poll VZ helper");
                false
            }
        }
    }

    fn gateway_transport(&self) -> GatewayTransport {
        GatewayTransport::VzVsockProxyUds {
            uds_path: self.gateway_uds.clone(),
            port: self.gateway_port,
        }
    }

    fn meter_source(&self) -> MeterSource {
        MeterSource::HostProcess {
            root_pid: self.pid,
            service_pids: self.service_pids.clone(),
            memory_mib: self.memory_mib,
        }
    }

    fn egress_control(&self) -> Option<&dyn crate::sandbox::EgressControl> {
        None
    }

    fn stream_console(&mut self) {
        tracing::debug!("VZ helper stdout/stderr are streamed from boot start");
    }

    async fn snapshot(&mut self) -> anyhow::Result<SnapshotArtifact> {
        anyhow::bail!("VZ VM-snapshot is unsupported for Kirby Linux guests; use app checkpointing")
    }

    async fn halt(mut self: Box<Self>) {
        stop_helper_child(&mut self.child).await;
        if let Err(e) = tokio::fs::remove_file(&self.gateway_uds).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    error = %e,
                    path = %self.gateway_uds.display(),
                    "failed to remove VZ gateway UDS"
                );
            }
        }
        if let Some(temp_rootfs) = &self.temp_rootfs {
            if let Err(e) = tokio::fs::remove_file(temp_rootfs).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        error = %e,
                        path = %temp_rootfs.display(),
                        "failed to remove padded VZ rootfs image"
                    );
                }
            }
        }
        if let Some(temp_kernel) = &self.temp_kernel {
            if let Err(e) = tokio::fs::remove_file(temp_kernel).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        error = %e,
                        path = %temp_kernel.display(),
                        "failed to remove converted VZ kernel image"
                    );
                }
            }
        }
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

fn list_vz_virtual_machine_service_pids() -> Vec<u32> {
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Vec::new();
    }

    let mut pids = vec![0 as libc::pid_t; count as usize];
    let bytes = match pids
        .len()
        .checked_mul(std::mem::size_of::<libc::pid_t>())
        .and_then(|n| i32::try_from(n).ok())
    {
        Some(bytes) => bytes,
        None => return Vec::new(),
    };
    let found = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<libc::c_void>(), bytes) };
    if found <= 0 {
        return Vec::new();
    }

    let found = (found as usize).min(pids.len());
    pids.truncate(found);
    pids.into_iter()
        .filter_map(|pid| {
            let pid = u32::try_from(pid).ok()?;
            let path = macos_process_path(pid)?;
            if path.contains("com.apple.Virtualization.VirtualMachine") {
                Some(pid)
            } else {
                None
            }
        })
        .collect()
}

fn macos_process_path(pid: u32) -> Option<String> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len() as u32,
        )
    };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn vz_gateway_uds_path(instance_id: &str, gateway_port: u32) -> PathBuf {
    PathBuf::from("/tmp").join(format!(
        "kirby-vz-{}-{}-{}.sock",
        std::process::id(),
        sanitize_instance_id(instance_id),
        gateway_port
    ))
}

async fn prepare_vz_kernel(
    kernel: &std::path::Path,
    instance_id: &str,
    gateway_port: u32,
) -> anyhow::Result<(PathBuf, Option<PathBuf>)> {
    let bytes = tokio::fs::read(kernel)
        .await
        .map_err(|e| anyhow::anyhow!("read VZ kernel {}: {e}", kernel.display()))?;
    let Some(image) = elf64_aarch64_to_raw_image(&bytes)? else {
        return Ok((kernel.to_path_buf(), None));
    };

    let temp = PathBuf::from("/tmp").join(format!(
        "kirby-vz-{}-{}-{}.Image",
        std::process::id(),
        sanitize_instance_id(instance_id),
        gateway_port
    ));
    if let Err(e) = tokio::fs::remove_file(&temp).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            anyhow::bail!("remove stale VZ kernel image {}: {e}", temp.display());
        }
    }
    tokio::fs::write(&temp, &image)
        .await
        .map_err(|e| anyhow::anyhow!("write converted VZ kernel image {}: {e}", temp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = tokio::fs::metadata(&temp)
            .await
            .map_err(|e| anyhow::anyhow!("stat converted VZ kernel image {}: {e}", temp.display()))?
            .permissions();
        permissions.set_mode(0o755);
        tokio::fs::set_permissions(&temp, permissions)
            .await
            .map_err(|e| {
                anyhow::anyhow!("chmod converted VZ kernel image {}: {e}", temp.display())
            })?;
    }
    tracing::info!(
        source = %kernel.display(),
        image = %temp.display(),
        image_len = image.len(),
        "converted ELF vmlinux to raw arm64 Image for VZLinuxBootLoader"
    );
    Ok((temp.clone(), Some(temp)))
}

async fn prepare_vz_rootfs(
    rootfs: &std::path::Path,
    instance_id: &str,
    gateway_port: u32,
) -> anyhow::Result<(PathBuf, Option<PathBuf>)> {
    let len = tokio::fs::metadata(rootfs)
        .await
        .map_err(|e| anyhow::anyhow!("stat VZ rootfs {}: {e}", rootfs.display()))?
        .len();
    if len % 512 == 0 {
        return Ok((rootfs.to_path_buf(), None));
    }

    // Virtualization.framework accepts only RAW disk images whose file size is a
    // multiple of the block size. The squashfs contents are still at byte 0; the
    // padded tail is ignored by the guest filesystem driver.
    let padded_len = len.next_multiple_of(512);
    let temp = PathBuf::from("/tmp").join(format!(
        "kirby-vz-{}-{}-{}.rootfs.raw",
        std::process::id(),
        sanitize_instance_id(instance_id),
        gateway_port
    ));
    if let Err(e) = tokio::fs::remove_file(&temp).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            anyhow::bail!("remove stale VZ rootfs image {}: {e}", temp.display());
        }
    }
    tokio::fs::copy(rootfs, &temp).await.map_err(|e| {
        anyhow::anyhow!(
            "copy VZ rootfs {} to {}: {e}",
            rootfs.display(),
            temp.display()
        )
    })?;
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&temp)
        .await
        .map_err(|e| anyhow::anyhow!("open padded VZ rootfs {}: {e}", temp.display()))?;
    file.set_len(padded_len).await.map_err(|e| {
        anyhow::anyhow!(
            "pad VZ rootfs {} to {padded_len} bytes: {e}",
            temp.display()
        )
    })?;
    tracing::info!(
        source = %rootfs.display(),
        padded = %temp.display(),
        original_len = len,
        padded_len,
        "created 512-byte-aligned VZ rootfs image"
    );
    Ok((temp.clone(), Some(temp)))
}

fn elf64_aarch64_to_raw_image(bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    if bytes.get(0..4) != Some(b"\x7fELF") {
        return Ok(None);
    }
    if bytes.get(4) != Some(&2) {
        anyhow::bail!("VZ kernel is ELF but not ELF64");
    }
    if bytes.get(5) != Some(&1) {
        anyhow::bail!("VZ kernel is ELF64 but not little-endian");
    }

    let machine = read_u16_le(bytes, 18)?;
    if machine != 183 {
        anyhow::bail!("VZ kernel ELF machine is {machine}, expected AArch64 (183)");
    }

    let phoff = read_u64_le(bytes, 32)? as usize;
    let phentsize = read_u16_le(bytes, 54)? as usize;
    let phnum = read_u16_le(bytes, 56)? as usize;
    if phentsize < 56 {
        anyhow::bail!("VZ kernel ELF program header size {phentsize} is too small");
    }

    #[derive(Debug)]
    struct LoadSegment {
        offset: usize,
        paddr: u64,
        filesz: usize,
    }

    let mut loads = Vec::new();
    for index in 0..phnum {
        let base =
            phoff
                .checked_add(index.checked_mul(phentsize).ok_or_else(|| {
                    anyhow::anyhow!("VZ kernel ELF program-header offset overflow")
                })?)
                .ok_or_else(|| anyhow::anyhow!("VZ kernel ELF program-header offset overflow"))?;
        let end = base
            .checked_add(phentsize)
            .ok_or_else(|| anyhow::anyhow!("VZ kernel ELF program-header end overflow"))?;
        if end > bytes.len() {
            anyhow::bail!("VZ kernel ELF program header {index} is past EOF");
        }

        let p_type = read_u32_le(bytes, base)?;
        if p_type != 1 {
            continue;
        }
        let offset = read_u64_le(bytes, base + 8)? as usize;
        let paddr = read_u64_le(bytes, base + 24)?;
        let filesz = read_u64_le(bytes, base + 32)? as usize;
        let file_end = offset
            .checked_add(filesz)
            .ok_or_else(|| anyhow::anyhow!("VZ kernel ELF LOAD file range overflow"))?;
        if file_end > bytes.len() {
            anyhow::bail!("VZ kernel ELF LOAD segment {index} is past EOF");
        }
        if filesz > 0 {
            loads.push(LoadSegment {
                offset,
                paddr,
                filesz,
            });
        }
    }
    if loads.is_empty() {
        anyhow::bail!("VZ kernel ELF contains no loadable segments");
    }

    let base_addr = loads.iter().map(|segment| segment.paddr).min().unwrap();
    let mut image_len = 0usize;
    for segment in &loads {
        let rel = segment
            .paddr
            .checked_sub(base_addr)
            .ok_or_else(|| anyhow::anyhow!("VZ kernel ELF LOAD address underflow"))?
            as usize;
        image_len = image_len.max(
            rel.checked_add(segment.filesz)
                .ok_or_else(|| anyhow::anyhow!("VZ kernel raw image size overflow"))?,
        );
    }

    let mut image = vec![0u8; image_len];
    for segment in &loads {
        let rel = segment
            .paddr
            .checked_sub(base_addr)
            .ok_or_else(|| anyhow::anyhow!("VZ kernel ELF LOAD address underflow"))?
            as usize;
        image[rel..rel + segment.filesz]
            .copy_from_slice(&bytes[segment.offset..segment.offset + segment.filesz]);
    }
    Ok(Some(image))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> anyhow::Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow::anyhow!("short ELF read at offset {offset}"))?
        .try_into()?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("short ELF read at offset {offset}"))?
        .try_into()?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> anyhow::Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow::anyhow!("short ELF read at offset {offset}"))?
        .try_into()?;
    Ok(u64::from_le_bytes(raw))
}

fn sanitize_instance_id(instance_id: &str) -> String {
    let mut out = String::with_capacity(instance_id.len().min(32));
    for ch in instance_id.chars().take(32) {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "node".to_string()
    } else {
        out
    }
}

fn stream_helper_stdout(stdout: ChildStdout) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => tracing::info!(target: "genome_serial", "{line}"),
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(error = %e, "VZ helper stdout stream ended with error");
                    break;
                }
            }
        }
    });
}

fn stream_helper_stderr(stderr: ChildStderr, ready_tx: oneshot::Sender<anyhow::Result<()>>) {
    tokio::spawn(async move {
        let mut ready_tx = Some(ready_tx);
        let mut lines = BufReader::new(stderr).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    tracing::info!(target: "vz_helper", "{line}");
                    if line.starts_with("KIRBY_VZ_READY ") {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(Ok(()));
                        }
                    } else if line.starts_with("KIRBY_VZ_ERROR ") {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(Err(anyhow::anyhow!("{line}")));
                        }
                    }
                }
                Ok(None) => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(anyhow::anyhow!(
                            "VZ helper exited before reporting READY"
                        )));
                    }
                    break;
                }
                Err(e) => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(anyhow::anyhow!(
                            "read VZ helper stderr before READY: {e}"
                        )));
                    }
                    break;
                }
            }
        }
    });
}

async fn stop_helper_child(child: &mut Child) {
    if let Ok(Some(status)) = child.try_wait() {
        tracing::info!(%status, "VZ helper already exited");
        return;
    }

    if let Some(pid) = child.id() {
        let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        if rc != 0 {
            tracing::warn!(
                pid,
                error = %std::io::Error::last_os_error(),
                "failed to send SIGTERM to VZ helper"
            );
        }
    }

    match tokio::time::timeout(VZ_STOP_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => tracing::info!(%status, "VZ helper exited after SIGTERM"),
        Ok(Err(e)) => tracing::warn!(error = %e, "waiting for VZ helper failed"),
        Err(_elapsed) => {
            tracing::warn!(
                timeout_secs = VZ_STOP_TIMEOUT.as_secs(),
                "VZ helper did not exit after SIGTERM; killing"
            );
            if let Err(e) = child.kill().await {
                tracing::warn!(error = %e, "SIGKILL VZ helper failed");
            }
        }
    }
}
