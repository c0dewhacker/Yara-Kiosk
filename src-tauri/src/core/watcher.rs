use tauri::{AppHandle, Emitter};

// ──────────────────────────────────────────────
// Linux implementation
// ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub async fn watch_mounts(app: AppHandle) {
    use std::collections::HashSet;

    let mut known: HashSet<String> = HashSet::new();

    // Seed with current mounts so we don't fire spurious events on first run.
    if let Ok(entries) = parse_mounts() {
        for (mount_point, _device, _fs_type) in &entries {
            known.insert(mount_point.clone());
        }
    }

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let current_entries = match parse_mounts() {
            Ok(e) => e,
            Err(e) => {
                log::warn!("Failed to parse /proc/self/mounts: {}", e);
                continue;
            }
        };

        let current_set: HashSet<String> = current_entries
            .iter()
            .map(|(mp, _, _)| mp.clone())
            .collect();

        // Detect new mounts.
        for (mount_point, device, _fs_type) in &current_entries {
            if !known.contains(mount_point) {
                known.insert(mount_point.clone());

                // Only care about removable devices.
                if !is_removable_device(device) {
                    continue;
                }

                let label = read_label(device).unwrap_or(None);
                let size_bytes = read_block_size(device).unwrap_or(0);

                log::info!("USB detected: {} ({})", mount_point, device);
                let _ = app.emit(
                    "usb-detected",
                    serde_json::json!({
                        "mountPoint": mount_point,
                        "label": label,
                        "sizeBytes": size_bytes,
                    }),
                );
            }
        }

        // Detect removed mounts.
        let removed: Vec<String> = known
            .iter()
            .filter(|mp| !current_set.contains(*mp))
            .cloned()
            .collect();
        for mount_point in removed {
            known.remove(&mount_point);
            log::info!("USB removed: {}", mount_point);
            let _ = app.emit(
                "usb-removed",
                serde_json::json!({ "mountPoint": mount_point }),
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_mounts() -> Result<Vec<(String, String, String)>, anyhow::Error> {
    let content = std::fs::read_to_string("/proc/self/mounts")?;
    let mut result = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            result.push((
                parts[1].to_string(), // mount_point
                parts[0].to_string(), // device
                parts[2].to_string(), // fs_type
            ));
        }
    }
    Ok(result)
}

/// Extract the base block device name from a device path.
/// e.g. `/dev/sdb1` → `sdb`, `/dev/sdb` → `sdb`
#[cfg(target_os = "linux")]
fn base_device_name(device: &str) -> &str {
    let dev_name = device.strip_prefix("/dev/").unwrap_or(device);
    let end = dev_name.find(|c: char| c.is_ascii_digit()).unwrap_or(dev_name.len());
    &dev_name[..end]
}

/// Determine if the device is a removable block device by reading
/// `/sys/block/<dev>/removable`.
#[cfg(target_os = "linux")]
fn is_removable_device(device: &str) -> bool {
    let base_dev = base_device_name(device);
    if base_dev.is_empty() { return false; }
    let removable_path = format!("/sys/block/{}/removable", base_dev);
    std::fs::read_to_string(&removable_path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Try to read the filesystem label from `/dev/disk/by-label/`.
#[cfg(target_os = "linux")]
fn read_label(device: &str) -> Result<Option<String>, anyhow::Error> {
    let label_dir = std::path::Path::new("/dev/disk/by-label");
    if !label_dir.exists() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(label_dir)?.flatten() {
        let link_target = std::fs::read_link(entry.path()).unwrap_or_default();
        // Resolve relative symlink.
        let resolved = if link_target.is_relative() {
            label_dir.join(&link_target)
        } else {
            link_target.clone()
        };
        if let Ok(canon) = std::fs::canonicalize(&resolved) {
            if canon == std::path::Path::new(device) {
                if let Some(label) = entry.file_name().to_str() {
                    return Ok(Some(label.to_string()));
                }
            }
        }
    }
    Ok(None)
}

/// Read block device size from `/sys/block/<dev>/size` (sectors × 512 bytes).
#[cfg(target_os = "linux")]
fn read_block_size(device: &str) -> Result<u64, anyhow::Error> {
    let base_dev = base_device_name(device);
    if base_dev.is_empty() { return Ok(0); }
    let size_path = format!("/sys/block/{}/size", base_dev);
    let sectors: u64 = std::fs::read_to_string(&size_path)?.trim().parse()?;
    Ok(sectors * 512)
}

// ──────────────────────────────────────────────
// Windows implementation
// ──────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub async fn watch_mounts(app: AppHandle) {
    use std::collections::HashSet;

    let mut known: HashSet<String> = HashSet::new();

    // Seed with current removable drives.
    for drive in enumerate_removable_drives() {
        known.insert(drive);
    }

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let current: HashSet<String> = enumerate_removable_drives().into_iter().collect();

        // New drives.
        for drive in current.difference(&known) {
            let size_bytes = get_drive_size(drive).unwrap_or(0);
            log::info!("USB detected: {}", drive);
            let _ = app.emit(
                "usb-detected",
                serde_json::json!({
                    "mountPoint": drive,
                    "label": Option::<String>::None,
                    "sizeBytes": size_bytes,
                }),
            );
        }

        // Removed drives.
        for drive in known.difference(&current) {
            log::info!("USB removed: {}", drive);
            let _ = app.emit(
                "usb-removed",
                serde_json::json!({ "mountPoint": drive }),
            );
        }

        known = current;
    }
}

#[cfg(target_os = "windows")]
fn enumerate_removable_drives() -> Vec<String> {
    use windows::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetLogicalDriveStringsW,
    };
    // DRIVE_REMOVABLE is not re-exported by the windows 0.58 crate under
    // Win32_Storage_FileSystem; use the raw value (2) from the Win32 SDK docs.
    const DRIVE_REMOVABLE: u32 = 2;

    // Buffer large enough for all possible drive strings.
    let mut buf = vec![0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) } as usize;
    if len == 0 || len > buf.len() {
        return Vec::new();
    }

    let mut drives = Vec::new();
    let mut start = 0usize;
    for i in 0..=len {
        let at_null = i == len || buf[i] == 0;
        if at_null {
            if i > start {
                let drive_str = String::from_utf16_lossy(&buf[start..i]);
                // Append null for PCWSTR.
                let drive_wstr: Vec<u16> =
                    drive_str.encode_utf16().chain(std::iter::once(0)).collect();
                let drive_type = unsafe {
                    GetDriveTypeW(windows::core::PCWSTR(drive_wstr.as_ptr()))
                };
                if drive_type == DRIVE_REMOVABLE {
                    drives.push(drive_str);
                }
            }
            start = i + 1;
        }
    }
    drives
}

#[cfg(target_os = "windows")]
fn get_drive_size(drive: &str) -> Result<u64, anyhow::Error> {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let path: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
    // Use u64 directly; the windows 0.58 crate exposes these as *mut u64.
    let mut free_caller: u64 = 0;
    let mut total: u64 = 0;
    let mut free_total: u64 = 0;
    unsafe {
        GetDiskFreeSpaceExW(
            windows::core::PCWSTR(path.as_ptr()),
            Some(&mut free_caller),
            Some(&mut total),
            Some(&mut free_total),
        )?;
    }
    Ok(total)
}

// ──────────────────────────────────────────────
// Fallback (macOS / other)
// ──────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub async fn watch_mounts(_app: AppHandle) {
    log::warn!("USB detection is not supported on this platform — USB events will not fire");
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
