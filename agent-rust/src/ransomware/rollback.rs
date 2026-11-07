//! Snapshot-based rollback orchestration — Phase R-E / Phase A
//!
//! Invokes platform snapshot restore mechanisms after a ransomware event:
//! - Windows: Volume Shadow Copy Service (VSS) enumeration and file recovery
//! - Linux: Btrfs subvolume snapshots or ZFS rollback
//! - macOS: Time Machine local snapshots (`tmutil`)
//!
//! All destructive operations are gated by `AEGIS_REAL_RECOVERY=1` or `RAM_REAL_RECOVERY=1`.
//! Without the gate, dry-run mode logs and returns planned commands without modifying files.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// The outcome of a restore attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestoreOutcome {
    /// Files successfully restored from snapshot into the recovery destination path.
    Restored(Vec<String>),
    /// The restore command or preparation failed.
    Failed(String),
    /// The host environment or filesystem does not support snapshots.
    Unsupported(String),
}

/// Errors from the rollback subsystem.
#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    #[error("IO error during rollback: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported platform for rollback: {0}")]
    UnsupportedPlatform(String),
}

/// Information about a parsed Windows VSS shadow copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssShadowCopy {
    pub shadow_id: String,
    pub original_volume: String,
    pub shadow_volume: String,
    pub creation_time: String,
}

/// Options controlling snapshot rollback execution.
#[derive(Debug, Clone)]
pub struct RollbackOptions {
    pub target_path: PathBuf,
    pub recovery_dir: Option<PathBuf>,
    pub confirm_volume_revert: bool,
}

impl RollbackOptions {
    pub fn new(target_path: impl Into<PathBuf>) -> Self {
        Self {
            target_path: target_path.into(),
            recovery_dir: None,
            confirm_volume_revert: false,
        }
    }
}

pub fn is_real_recovery_enabled() -> bool {
    let val = std::env::var("RAM_REAL_RECOVERY")
        .or_else(|_| std::env::var("AEGIS_REAL_RECOVERY"))
        .unwrap_or_default();
    val.trim() == "1"
}

// ---------------------------------------------------------------------------
// VSS (Windows) Parser & Command Planner
// ---------------------------------------------------------------------------

pub fn parse_vssadmin_shadows(output: &str) -> Vec<VssShadowCopy> {
    let mut shadows = Vec::new();
    let mut current_id = String::new();
    let mut current_orig = String::new();
    let mut current_vol = String::new();
    let mut current_time = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Shadow Copy ID:") {
            if !current_id.is_empty() && !current_vol.is_empty() {
                shadows.push(VssShadowCopy {
                    shadow_id: current_id.clone(),
                    original_volume: current_orig.clone(),
                    shadow_volume: current_vol.clone(),
                    creation_time: current_time.clone(),
                });
            }
            current_id = trimmed.trim_start_matches("Shadow Copy ID:").trim().to_string();
            current_orig.clear();
            current_vol.clear();
            current_time.clear();
        } else if trimmed.starts_with("Original Volume:") {
            current_orig = trimmed.trim_start_matches("Original Volume:").trim().to_string();
        } else if trimmed.starts_with("Shadow Copy Volume Name:") {
            current_vol = trimmed.trim_start_matches("Shadow Copy Volume Name:").trim().to_string();
        } else if trimmed.starts_with("Creation Time:") {
            current_time = trimmed.trim_start_matches("Creation Time:").trim().to_string();
        }
    }

    if !current_id.is_empty() && !current_vol.is_empty() {
        shadows.push(VssShadowCopy {
            shadow_id: current_id,
            original_volume: current_orig,
            shadow_volume: current_vol,
            creation_time: current_time,
        });
    }

    shadows
}

pub fn plan_windows_vss_restore(
    options: &RollbackOptions,
    vss_output: &str,
) -> Result<String, RestoreOutcome> {
    let shadows = parse_vssadmin_shadows(vss_output);
    if shadows.is_empty() {
        return Err(RestoreOutcome::Unsupported("No VSS shadow copies found on volume".to_string()));
    }

    // Select latest shadow copy (last in list)
    let latest = shadows.last().unwrap();
    let dest_dir = options.recovery_dir.clone().unwrap_or_else(|| {
        options.target_path
            .parent()
            .map(|p| p.join("recovered_from_snapshot"))
            .unwrap_or_else(|| PathBuf::from("C:\\recovered_from_snapshot"))
    });

    let filename = options.target_path.file_name().unwrap_or_default().to_string_lossy();
    let cmd = format!(
        "robocopy /E \"{}\" \"{}\" \"{}\"",
        latest.shadow_volume,
        dest_dir.to_string_lossy(),
        filename
    );
    Ok(cmd)
}

// ---------------------------------------------------------------------------
// Linux (Btrfs / ZFS) Parser & Command Planner
// ---------------------------------------------------------------------------

pub fn parse_btrfs_snapshots(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|l| l.contains("path "))
        .filter_map(|l| l.split("path ").nth(1))
        .map(|s| s.trim().to_string())
        .collect()
}

pub fn parse_zfs_snapshots(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|l| l.contains('@'))
        .map(|l| l.split_whitespace().next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn plan_linux_snapshot_restore(
    options: &RollbackOptions,
    btrfs_output: Option<&str>,
    zfs_output: Option<&str>,
) -> Result<String, RestoreOutcome> {
    if let Some(out) = btrfs_output {
        let snaps = parse_btrfs_snapshots(out);
        if let Some(latest) = snaps.last() {
            let dest = options.recovery_dir.clone().unwrap_or_else(|| {
                options.target_path.parent().unwrap_or(Path::new("/tmp")).join("recovered_from_snapshot")
            });
            return Ok(format!("btrfs subvolume snapshot {} {}", latest, dest.to_string_lossy()));
        }
    }

    if let Some(out) = zfs_output {
        let snaps = parse_zfs_snapshots(out);
        if let Some(latest) = snaps.last() {
            return Ok(format!("zfs rollback -r {}", latest));
        }
    }

    Err(RestoreOutcome::Unsupported(
        "filesystem does not support snapshots (neither btrfs nor zfs snapshots detected)".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// macOS (Time Machine) Parser & Command Planner
// ---------------------------------------------------------------------------

pub fn parse_tmutil_snapshots(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.starts_with("com.apple.TimeMachine."))
        .collect()
}

pub fn plan_macos_snapshot_restore(
    options: &RollbackOptions,
    tmutil_output: &str,
) -> Result<String, RestoreOutcome> {
    let snaps = parse_tmutil_snapshots(tmutil_output);
    if let Some(latest) = snaps.last() {
        let dest = options.recovery_dir.clone().unwrap_or_else(|| {
            options.target_path.parent().unwrap_or(Path::new("/tmp")).join("recovered_from_snapshot")
        });
        return Ok(format!(
            "tmutil restore -d / \"{}\" \"{}\"",
            latest,
            dest.to_string_lossy()
        ));
    }
    Err(RestoreOutcome::Unsupported("No Time Machine local snapshots found via tmutil".to_string()))
}

// ---------------------------------------------------------------------------
// Public Restore API
// ---------------------------------------------------------------------------

/// Attempt to restore `target_path` from the latest available platform snapshot.
///
/// If `AEGIS_REAL_RECOVERY=1` (or `RAM_REAL_RECOVERY=1`) is set, invokes the real platform command.
/// Otherwise, returns [`RestoreOutcome::Restored`] in dry-run mode with the planned command.
pub async fn restore(target_path: &Path) -> Result<RestoreOutcome, RollbackError> {
    restore_with_options(&RollbackOptions::new(target_path)).await
}

pub async fn restore_with_options(options: &RollbackOptions) -> Result<RestoreOutcome, RollbackError> {
    let real_recovery = is_real_recovery_enabled();

    #[cfg(target_os = "windows")]
    {
        // Query vssadmin list shadows
        let list_output = match tokio::process::Command::new("vssadmin")
            .args(["list", "shadows"])
            .output()
            .await
        {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(e) => return Ok(RestoreOutcome::Unsupported(format!("vssadmin query failed: {e}"))),
        };

        let planned_cmd = match plan_windows_vss_restore(options, &list_output) {
            Ok(cmd) => cmd,
            Err(outcome) => return Ok(outcome),
        };

        if !real_recovery {
            log::info!("[rollback] Dry-run mode: planned Windows VSS restore: {}", planned_cmd);
            return Ok(RestoreOutcome::Restored(vec![format!("DRY-RUN: {}", planned_cmd)]));
        }

        // Real execution
        let parts: Vec<&str> = planned_cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(RestoreOutcome::Failed("Empty command planned".into()));
        }
        let out = tokio::process::Command::new(parts[0])
            .args(&parts[1..])
            .output()
            .await?;

        if out.status.success() {
            Ok(RestoreOutcome::Restored(vec![options.target_path.to_string_lossy().to_string()]))
        } else {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            Ok(RestoreOutcome::Failed(err))
        }
    }

    #[cfg(target_os = "linux")]
    {
        let btrfs_out = tokio::process::Command::new("btrfs")
            .args(["subvolume", "list", "/"])
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

        let zfs_out = tokio::process::Command::new("zfs")
            .args(["list", "-t", "snapshot"])
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

        let planned_cmd = match plan_linux_snapshot_restore(
            options,
            btrfs_out.as_deref(),
            zfs_out.as_deref(),
        ) {
            Ok(cmd) => cmd,
            Err(outcome) => return Ok(outcome),
        };

        if !real_recovery {
            log::info!("[rollback] Dry-run mode: planned Linux snapshot restore: {}", planned_cmd);
            return Ok(RestoreOutcome::Restored(vec![format!("DRY-RUN: {}", planned_cmd)]));
        }

        let parts: Vec<&str> = planned_cmd.split_whitespace().collect();
        let out = tokio::process::Command::new(parts[0])
            .args(&parts[1..])
            .output()
            .await?;

        if out.status.success() {
            Ok(RestoreOutcome::Restored(vec![options.target_path.to_string_lossy().to_string()]))
        } else {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            Ok(RestoreOutcome::Failed(err))
        }
    }

    #[cfg(target_os = "macos")]
    {
        let tmutil_out = match tokio::process::Command::new("tmutil")
            .args(["listlocalsnapshots", "/"])
            .output()
            .await
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(e) => return Ok(RestoreOutcome::Unsupported(format!("tmutil failed: {e}"))),
        };

        let planned_cmd = match plan_macos_snapshot_restore(options, &tmutil_out) {
            Ok(cmd) => cmd,
            Err(outcome) => return Ok(outcome),
        };

        if !real_recovery {
            log::info!("[rollback] Dry-run mode: planned macOS Time Machine restore: {}", planned_cmd);
            return Ok(RestoreOutcome::Restored(vec![format!("DRY-RUN: {}", planned_cmd)]));
        }

        let parts: Vec<&str> = planned_cmd.split_whitespace().collect();
        let out = tokio::process::Command::new(parts[0])
            .args(&parts[1..])
            .output()
            .await?;

        if out.status.success() {
            Ok(RestoreOutcome::Restored(vec![options.target_path.to_string_lossy().to_string()]))
        } else {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            Ok(RestoreOutcome::Failed(err))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(RollbackError::UnsupportedPlatform("platform unsupported".into()))
    }
}

// ---------------------------------------------------------------------------
// Unit Tests (Mocked Command Outputs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_VSSADMIN_OUTPUT: &str = r#"
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {417e2978-508b-4b2a-89a7-8022d431c36a}
   Contained 1 shadow copies at creation time: 11/7/2026 10:00:00 AM
      Shadow Copy ID: {b20c9298-5c4d-45db-9080-692ab8cf896a}
         Original Volume: (C:)\\?\Volume{abc-123}\
         Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Creation Time: 11/7/2026 10:00:00 AM

Contents of shadow copy set ID: {528f3089-619c-5c3b-90b8-9133e542d47b}
   Contained 1 shadow copies at creation time: 11/7/2026 11:30:00 AM
      Shadow Copy ID: {c31da309-6d5e-56ec-0191-703bc9df907b}
         Original Volume: (C:)\\?\Volume{abc-123}\
         Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
         Creation Time: 11/7/2026 11:30:00 AM
"#;

    const SAMPLE_BTRFS_OUTPUT: &str = r#"
ID 256 gen 10 top level 5 path @
ID 257 gen 15 top level 5 path @home
ID 258 gen 18 top level 5 path .snapshots/1/snapshot
ID 259 gen 22 top level 5 path .snapshots/2/snapshot
"#;

    const SAMPLE_ZFS_OUTPUT: &str = r#"
NAME                     USED  AVAIL  REFER  MOUNTPOINT
rpool/data@snap-2026-01   10M      -   500M  -
rpool/data@snap-2026-02   12M      -   510M  -
"#;

    const SAMPLE_TMUTIL_OUTPUT: &str = r#"
Snapshots for volume group containing disk /:
com.apple.TimeMachine.2026-11-06-180000.local
com.apple.TimeMachine.2026-11-07-090000.local
"#;

    #[test]
    fn test_parse_vssadmin_shadows() {
        let shadows = parse_vssadmin_shadows(SAMPLE_VSSADMIN_OUTPUT);
        assert_eq!(shadows.len(), 2);
        assert_eq!(shadows[0].shadow_id, "{b20c9298-5c4d-45db-9080-692ab8cf896a}");
        assert_eq!(shadows[0].shadow_volume, r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1");
        assert_eq!(shadows[1].shadow_id, "{c31da309-6d5e-56ec-0191-703bc9df907b}");
        assert_eq!(shadows[1].shadow_volume, r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2");
    }

    #[test]
    fn test_plan_windows_vss_restore() {
        let opts = RollbackOptions::new("C:\\Users\\Victim\\Documents\\important.docx");
        let plan = plan_windows_vss_restore(&opts, SAMPLE_VSSADMIN_OUTPUT).unwrap();
        assert!(plan.contains(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2"));
        assert!(plan.contains("important.docx"));
        assert!(plan.contains("recovered_from_snapshot"));
    }

    #[test]
    fn test_plan_windows_vss_no_shadows() {
        let opts = RollbackOptions::new("C:\\Users\\Victim\\Documents\\important.docx");
        let res = plan_windows_vss_restore(&opts, "No items found that satisfy the query.");
        assert_eq!(
            res,
            Err(RestoreOutcome::Unsupported("No VSS shadow copies found on volume".to_string()))
        );
    }

    #[test]
    fn test_linux_btrfs_and_zfs_planning() {
        let opts = RollbackOptions::new("/home/user/data.csv");
        let plan_btrfs = plan_linux_snapshot_restore(&opts, Some(SAMPLE_BTRFS_OUTPUT), None).unwrap();
        assert!(plan_btrfs.contains("btrfs subvolume snapshot .snapshots/2/snapshot"));

        let plan_zfs = plan_linux_snapshot_restore(&opts, None, Some(SAMPLE_ZFS_OUTPUT)).unwrap();
        assert_eq!(plan_zfs, "zfs rollback -r rpool/data@snap-2026-02");

        let res_unsupported = plan_linux_snapshot_restore(&opts, None, None);
        assert_eq!(
            res_unsupported,
            Err(RestoreOutcome::Unsupported(
                "filesystem does not support snapshots (neither btrfs nor zfs snapshots detected)".to_string()
            ))
        );
    }

    #[test]
    fn test_macos_tmutil_planning() {
        let opts = RollbackOptions::new("/Users/victim/project.rs");
        let plan = plan_macos_snapshot_restore(&opts, SAMPLE_TMUTIL_OUTPUT).unwrap();
        assert!(plan.contains("tmutil restore"));
        assert!(plan.contains("com.apple.TimeMachine.2026-11-07-090000.local"));

        let empty = plan_macos_snapshot_restore(&opts, "No snapshots found");
        assert_eq!(
            empty,
            Err(RestoreOutcome::Unsupported("No Time Machine local snapshots found via tmutil".to_string()))
        );
    }

    #[tokio::test]
    async fn test_dry_run_mode_when_gate_unset() {
        std::env::remove_var("AEGIS_REAL_RECOVERY");
        std::env::remove_var("RAM_REAL_RECOVERY");
        let outcome = restore(Path::new("C:\\test\\file.txt")).await.unwrap();
        match outcome {
            RestoreOutcome::Restored(cmds) => {
                assert!(cmds[0].starts_with("DRY-RUN:"));
            }
            RestoreOutcome::Unsupported(_) => {
                // In environments without shadow copies, Unsupported is returned
            }
            other => panic!("Unexpected outcome in dry-run mode: {:?}", other),
        }
    }

    #[test]
    fn restore_outcome_serde_round_trip() {
        for variant in [
            RestoreOutcome::Restored(vec!["file1.txt".to_string(), "file2.txt".to_string()]),
            RestoreOutcome::Failed("Access denied".to_string()),
            RestoreOutcome::Unsupported("No VSS shadow copies found".to_string()),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: RestoreOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }
}
