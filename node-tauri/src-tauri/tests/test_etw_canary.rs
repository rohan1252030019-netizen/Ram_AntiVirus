// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canary PID correlation integration test for Windows ETW telemetry (Task B1).

#![cfg(target_os = "windows")]

#[cfg(feature = "ferrisetw")]
#[tokio::test]
async fn test_etw_canary_pid_correlation() {
    use aegis_node_lib::edr::{etw_windows, EdrEventKind, EdrState};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    let state = Arc::new(Mutex::new(EdrState::new(
        "https://localhost:8443".into(),
        Some("test-agent".into()),
    )));

    // Check if process has administrative elevation
    if !etw_windows::is_elevated() {
        eprintln!("[ETW TEST] Process is not running with administrative elevation.");
        // Test graceful degradation: run() must return Err, not panic, and tier2_active must be false
        let res = etw_windows::run(state.clone()).await;
        assert!(
            res.is_err(),
            "Expected error when running ETW without administrative rights"
        );
        let s = state.lock().await;
        assert!(
            !s.tier2_active,
            "tier2_active must be false when un-elevated"
        );
        println!(
            "[ETW TEST] Graceful degradation verified successfully on un-elevated host."
        );
        return;
    }

    // Elevated path (runs in GitHub Actions Windows runners with admin tokens)
    let state_etw = state.clone();
    tokio::spawn(async move {
        let _ = etw_windows::run(state_etw).await;
    });

    // Wait up to 3 seconds for the ETW trace session to start
    let start_wait = Instant::now();
    while start_wait.elapsed() < Duration::from_secs(3) {
        {
            let s = state.lock().await;
            if s.tier2_active {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Prepare canary file path in %TEMP%
    let canary_dir = std::env::temp_dir();
    let canary_id = uuid::Uuid::new_v4().to_string();
    let canary_file_name = format!("canary_{}.txt", canary_id);
    let canary_path = canary_dir.join(&canary_file_name);
    let canary_path_str = canary_path.to_string_lossy().to_string();

    // Spawn a child process to write the canary file
    let mut child = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Set-Content -Path '{}' -Value 'CanaryPayload123'", canary_path_str),
        ])
        .spawn()
        .expect("Failed to spawn canary process");

    let child_pid = child.id();
    let status = child.wait().expect("Canary process failed to complete");
    assert!(status.success(), "Canary process returned non-zero status");

    // Poll event buffer for up to 2 seconds for matching PID and canary target
    let poll_start = Instant::now();
    let mut matched_pid: Option<u32> = None;

    while poll_start.elapsed() < Duration::from_secs(2) {
        {
            let mut s = state.lock().await;
            let events = s.buffer.drain(1024);
            for ev in events {
                if (ev.kind == EdrEventKind::FileWrite || ev.kind == EdrEventKind::FileCreate)
                    && ev.target.as_ref().map_or(false, |t| t.contains(&canary_id))
                {
                    if let Some(pid) = ev.pid {
                        if pid == child_pid {
                            matched_pid = Some(pid);
                            break;
                        }
                    }
                }
            }
        }
        if matched_pid.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Cleanup canary file
    let _ = std::fs::remove_file(&canary_path);

    assert_eq!(
        matched_pid,
        Some(child_pid),
        "Expected ETW File event correlated with canary child PID {}",
        child_pid
    );
    println!(
        "[ETW TEST] Successfully correlated canary PID {} with ETW file event!",
        child_pid
    );
}
