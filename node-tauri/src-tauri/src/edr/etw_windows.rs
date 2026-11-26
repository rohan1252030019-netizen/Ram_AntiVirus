// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ETW-based telemetry collector (Task B1, Windows Tier 2)
//
// Subscribes to Microsoft-Windows-Kernel-* ETW providers via the
// `ferrisetw` crate. Requires admin; returns Err(...) on the first failure
// and the EDR module falls back to the Tier-1 poller.
//
// Providers subscribed:
//   - Microsoft-Windows-Kernel-Process   (22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716)
//   - Microsoft-Windows-Kernel-Network   (7dd42a49-5329-4832-8dfd-43d979153a88)
//   - Microsoft-Windows-Kernel-File      (edd08927-9cc4-4e65-b970-c2560fb5c289)
//   - Microsoft-Windows-Kernel-Registry  (70eb4f03-c1de-4f73-a051-33d13d5413bd)
// ---------------------------------------------------------------------------

#![cfg(target_os = "windows")]

use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::edr::{EdrEvent, EdrEventKind, EdrState};

/// Helper to check if current process is running with administrative elevation
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            let _ = windows::Win32::Foundation::CloseHandle(token);
            if ok.is_ok() && elevation.TokenIsElevated != 0 {
                return true;
            }
        }
    }
    false
}

/// Entry point. Runs as long as the process lives. Returns Err on setup
/// failure (e.g. not admin). The ferrisetw integration is compiled in when
/// the `ferrisetw` feature is enabled — otherwise this is a fallback that
/// returns an explicit error so the poller takes over.
pub async fn run(state: Arc<Mutex<EdrState>>) -> Result<(), String> {
    #[cfg(feature = "ferrisetw")]
    {
        use ferrisetw::parser::Parser;
        use ferrisetw::provider::Provider;
        use ferrisetw::trace::UserTrace;

        // Process Provider
        let state_cb = state.clone();
        let proc_provider = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
            .add_callback(move |record, schema_locator| {
                if let Ok(schema) = schema_locator.event_schema(record) {
                    let parser = Parser::create(record, &schema);
                    let opcode = record.opcode();
                    let kind = match opcode {
                        1 => EdrEventKind::ProcessStart,
                        2 => EdrEventKind::ProcessStop,
                        5 => EdrEventKind::ImageLoad,
                        _ => return,
                    };

                    let pid: Option<u32> = parser
                        .try_parse("ProcessID")
                        .ok()
                        .or_else(|| {
                            let p = record.process_id();
                            if p != 0 {
                                Some(p)
                            } else {
                                None
                            }
                        });
                    let ppid: Option<u32> = parser.try_parse("ParentProcessID").ok();
                    let image: Option<String> = parser.try_parse("ImageName").ok();
                    let cmdline: Option<String> = parser.try_parse("CommandLine").ok();

                    let ev = EdrEvent {
                        kind,
                        at: Utc::now(),
                        pid,
                        ppid,
                        process_name: image
                            .as_ref()
                            .and_then(|p| std::path::Path::new(p).file_name())
                            .and_then(|n| n.to_str())
                            .map(String::from),
                        process_path: image,
                        command_line: cmdline,
                        user: None,
                        target: None,
                        extra: serde_json::json!({"source": "etw_kernel_process"}),
                    };
                    let state_cb = state_cb.clone();
                    tokio::spawn(async move {
                        let mut s = state_cb.lock().await;
                        s.buffer.push(ev);
                    });
                }
            })
            .build();

        // Network Provider
        let state_cb = state.clone();
        let net_provider = Provider::by_guid("7dd42a49-5329-4832-8dfd-43d979153a88")
            .add_callback(move |record, schema_locator| {
                if let Ok(schema) = schema_locator.event_schema(record) {
                    let parser = Parser::create(record, &schema);
                    // opcode 12 = TcpIpConnect, 15 = TcpIpAccept
                    let kind = match record.opcode() {
                        12 => EdrEventKind::TcpConnect,
                        15 => EdrEventKind::TcpAccept,
                        _ => return,
                    };
                    let pid: Option<u32> = parser
                        .try_parse("PID")
                        .ok()
                        .or_else(|| {
                            let p = record.process_id();
                            if p != 0 {
                                Some(p)
                            } else {
                                None
                            }
                        });
                    let daddr: Option<String> = parser.try_parse("daddr").ok();
                    let dport: Option<u16> = parser.try_parse("dport").ok();

                    let target = match (daddr, dport) {
                        (Some(ip), Some(port)) => Some(format!("{}:{}", ip, port)),
                        (Some(ip), None) => Some(ip),
                        _ => None,
                    };
                    let ev = EdrEvent {
                        kind,
                        at: Utc::now(),
                        pid,
                        ppid: None,
                        process_name: None,
                        process_path: None,
                        command_line: None,
                        user: None,
                        target,
                        extra: serde_json::json!({"source": "etw_kernel_network"}),
                    };
                    let state_cb = state_cb.clone();
                    tokio::spawn(async move {
                        let mut s = state_cb.lock().await;
                        s.buffer.push(ev);
                    });
                }
            })
            .build();

        // File Provider
        let state_cb = state.clone();
        let file_provider = Provider::by_guid("edd08927-9cc4-4e65-b970-c2560fb5c289")
            .add_callback(move |record, schema_locator| {
                if let Ok(schema) = schema_locator.event_schema(record) {
                    let parser = Parser::create(record, &schema);
                    let kind = match record.opcode() {
                        12 | 64 => EdrEventKind::FileCreate,
                        27 | 67 => EdrEventKind::FileWrite,
                        26 | 66 => EdrEventKind::FileDelete,
                        _ => return,
                    };
                    let filename: Option<String> = parser
                        .try_parse("FileName")
                        .ok()
                        .or_else(|| parser.try_parse("OpenPath").ok());
                    let pid: Option<u32> = parser
                        .try_parse("IssuingThreadId")
                        .ok()
                        .or_else(|| {
                            let p = record.process_id();
                            if p != 0 {
                                Some(p)
                            } else {
                                None
                            }
                        });
                    let ev = EdrEvent {
                        kind,
                        at: Utc::now(),
                        pid,
                        ppid: None,
                        process_name: None,
                        process_path: None,
                        command_line: None,
                        user: None,
                        target: filename,
                        extra: serde_json::json!({"source": "etw_kernel_file"}),
                    };
                    let state_cb = state_cb.clone();
                    tokio::spawn(async move {
                        let mut s = state_cb.lock().await;
                        s.buffer.push(ev);
                    });
                }
            })
            .build();

        // Registry Provider
        let state_cb = state.clone();
        let reg_provider = Provider::by_guid("70eb4f03-c1de-4f73-a051-33d13d5413bd")
            .add_callback(move |record, schema_locator| {
                if let Ok(schema) = schema_locator.event_schema(record) {
                    let parser = Parser::create(record, &schema);
                    let kind = match record.opcode() {
                        11 => EdrEventKind::RegistrySet,
                        12 => EdrEventKind::RegistryDelete,
                        _ => return,
                    };
                    let key: Option<String> = parser.try_parse("KeyName").ok();
                    let value: Option<String> = parser.try_parse("ValueName").ok();
                    let pid = {
                        let p = record.process_id();
                        if p != 0 {
                            Some(p)
                        } else {
                            None
                        }
                    };
                    let ev = EdrEvent {
                        kind,
                        at: Utc::now(),
                        pid,
                        ppid: None,
                        process_name: None,
                        process_path: None,
                        command_line: None,
                        user: None,
                        target: key,
                        extra: serde_json::json!({
                            "source": "etw_kernel_registry",
                            "value": value,
                        }),
                    };
                    let state_cb = state_cb.clone();
                    tokio::spawn(async move {
                        let mut s = state_cb.lock().await;
                        s.buffer.push(ev);
                    });
                }
            })
            .build();

        // Build and start the session in a blocking thread — ferrisetw is sync-only
        let trace_result = tokio::task::spawn_blocking(move || {
            UserTrace::new()
                .named("RamAntivirusEDRTrace".into())
                .enable(proc_provider)
                .enable(net_provider)
                .enable(file_provider)
                .enable(reg_provider)
                .start_and_process()
        })
        .await
        .map_err(|e| format!("ETW task join error: {}", e))?;

        match trace_result {
            Ok(_trace) => {
                {
                    let mut s = state.lock().await;
                    s.tier2_active = true;
                }
                log::info!("[edr/etw] Tier 2 ETW collector active (Kernel-Process/Network/File/Registry)");
                // Keep the background worker alive
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
            }
            Err(e) => {
                {
                    let mut s = state.lock().await;
                    s.tier2_active = false;
                }
                log::warn!(
                    "[edr/etw] ETW trace start failed ({:?}); falling back to Tier-1 poller",
                    e
                );
                Err(format!("ETW trace start failed: {:?}", e))
            }
        }
    }

    #[cfg(not(feature = "ferrisetw"))]
    {
        let mut s = state.lock().await;
        s.tier2_active = false;
        log::warn!("[edr/etw] ferrisetw feature not enabled; falling back to Tier-1 poller");
        Err("ferrisetw feature not enabled — using Tier 1 poller".to_string())
    }
}
