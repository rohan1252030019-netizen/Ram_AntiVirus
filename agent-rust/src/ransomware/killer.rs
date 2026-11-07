//! Process killer with forensic chain capture — Phase R-E
//!
//! Terminates the offending process and its descendants (children, grandchildren,
//! etc.) with a cycle guard and a hard system/agent denylist. Before killing,
//! captures a [`ProcessChainSnapshot`] for forensic analysis.
//!
//! Open-files and network-connections fields are stubs — sysinfo does not
//! expose these at this abstraction level. They are reserved for future
//! platform-specific enrichment (lsof/netstat on Unix, NtQuerySystemInformation
//! on Windows).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessesToUpdate, System};
#[cfg(unix)]
use sysinfo::Signal;

/// Critical system and platform process names that must never be terminated.
pub const CRITICAL_PROCESS_NAMES: &[&str] = &[
    "system",
    "system idle process",
    "smss.exe",
    "smss",
    "csrss.exe",
    "csrss",
    "wininit.exe",
    "wininit",
    "services.exe",
    "services",
    "lsass.exe",
    "lsass",
    "winlogon.exe",
    "winlogon",
    "explorer.exe",
    "explorer",
    "svchost.exe",
    "svchost",
    "init",
    "systemd",
    "launchd",
    "kthreadd",
];

/// A lightweight process entry captured for forensics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub cmdline: Vec<String>,
}

/// Forensic snapshot of the process chain taken before killing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessChainSnapshot {
    /// All processes in the chain (target + descendants).
    pub tree: Vec<ProcessEntry>,
    /// Flat map pid -> command line (convenience accessor).
    pub command_lines: HashMap<u32, Vec<String>>,
    /// Open file handles — stub, populated when platform data is available.
    pub open_files: Vec<String>,
    /// Active network connections — stub, populated when platform data is available.
    pub network_connections: Vec<String>,
    /// UTC timestamp when the snapshot was captured.
    pub captured_at: u64,
}

/// Errors produced by the killer subsystem.
#[derive(Debug, thiserror::Error)]
pub enum KillerError {
    #[error("sysinfo refresh failed")]
    SysinfoRefresh,
    #[error("kill failed for pid {pid}: {reason}")]
    KillFailed { pid: u32, reason: String },
    #[error("refusing to kill denylisted pid {pid}: {reason}")]
    DenylistedPid { pid: u32, reason: String },
}

/// Abstract interface over process table queries and termination.
/// Allows unit testing without querying or terminating live OS processes.
pub trait ProcessTable {
    fn process_exists(&self, pid: u32) -> bool;
    fn parent_pid(&self, pid: u32) -> Option<u32>;
    fn process_name(&self, pid: u32) -> Option<String>;
    fn cmdline(&self, pid: u32) -> Vec<String>;
    fn all_pids(&self) -> Vec<u32>;
    fn kill(&mut self, pid: u32) -> Result<(), String>;
}

/// Real sysinfo-backed process table implementation.
pub struct SysinfoProcessTable<'a> {
    sys: &'a mut System,
}

impl<'a> SysinfoProcessTable<'a> {
    pub fn new(sys: &'a mut System) -> Self {
        Self { sys }
    }
}

impl<'a> ProcessTable for SysinfoProcessTable<'a> {
    fn process_exists(&self, pid: u32) -> bool {
        self.sys.process(Pid::from_u32(pid)).is_some()
    }

    fn parent_pid(&self, pid: u32) -> Option<u32> {
        self.sys
            .process(Pid::from_u32(pid))
            .and_then(|p| p.parent())
            .map(|p| p.as_u32())
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        self.sys
            .process(Pid::from_u32(pid))
            .map(|p| p.name().to_string_lossy().to_string())
    }

    fn cmdline(&self, pid: u32) -> Vec<String> {
        self.sys
            .process(Pid::from_u32(pid))
            .map(|p| p.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect())
            .unwrap_or_default()
    }

    fn all_pids(&self) -> Vec<u32> {
        self.sys.processes().keys().map(|p| p.as_u32()).collect()
    }

    fn kill(&mut self, pid: u32) -> Result<(), String> {
        if let Some(proc_) = self.sys.process(Pid::from_u32(pid)) {
            #[cfg(unix)]
            {
                let _ = proc_.kill_with(Signal::Kill);
            }
            #[cfg(windows)]
            {
                let _ = proc_.kill();
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = proc_.kill();
            }
        }
        Ok(())
    }
}

/// Evaluates whether a process is protected by the hard denylist.
pub fn is_denylisted(
    pid: u32,
    name: Option<&str>,
    agent_pid: u32,
    agent_ppid: Option<u32>,
) -> Option<&'static str> {
    if pid == 0 {
        return Some("PID 0 (idle/swapper)");
    }
    if pid == 1 {
        return Some("PID 1 (init/systemd/launchd)");
    }
    if pid == 4 {
        return Some("PID 4 (System)");
    }
    if pid == agent_pid {
        return Some("Agent self-PID");
    }
    if let Some(ppid) = agent_ppid {
        if pid == ppid {
            return Some("Agent parent PID");
        }
    }

    if let Some(n) = name {
        let n_lower = n.to_lowercase();
        if n_lower.starts_with('[') || n_lower.starts_with("kthread") {
            return Some("Kernel thread");
        }
        for &crit in CRITICAL_PROCESS_NAMES {
            if n_lower == crit {
                return Some("Critical system process name");
            }
        }
    }

    None
}

/// Collects ONLY the target PID and its descendants (children recursively)
/// with a cycle guard. Ancestor/parent processes are NEVER included.
pub fn collect_chain<T: ProcessTable + ?Sized>(
    table: &T,
    target_pid: u32,
    agent_pid: u32,
    agent_ppid: Option<u32>,
) -> Result<Vec<u32>, KillerError> {
    if !table.process_exists(target_pid) {
        return Ok(Vec::new());
    }

    let target_name = table.process_name(target_pid);
    if let Some(reason) = is_denylisted(target_pid, target_name.as_deref(), agent_pid, agent_ppid) {
        return Err(KillerError::DenylistedPid {
            pid: target_pid,
            reason: reason.to_string(),
        });
    }

    // Index all children by parent_pid to allow efficient breadth-first traversal
    let all = table.all_pids();
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in all {
        if let Some(parent) = table.parent_pid(p) {
            children_map.entry(parent).or_default().push(p);
        }
    }

    let mut collected = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    queue.push_back(target_pid);
    visited.insert(target_pid);

    while let Some(current) = queue.pop_front() {
        let name = table.process_name(current);
        if let Some(reason) = is_denylisted(current, name.as_deref(), agent_pid, agent_ppid) {
            log::warn!("[killer] skipping denylisted descendant PID {current}: {reason}");
            continue;
        }

        collected.push(current);

        if let Some(children) = children_map.get(&current) {
            for &child in children {
                // Cycle guard: only traverse unvisited children
                if visited.insert(child) {
                    queue.push_back(child);
                }
            }
        }
    }

    collected.sort_unstable();
    collected.dedup();
    Ok(collected)
}

/// Orchestrates forensic snapshot and safe process-tree termination on an arbitrary process table.
pub fn kill_chain_on_table<T: ProcessTable + ?Sized>(
    table: &mut T,
    target_pid: u32,
    capture_forensics: bool,
    agent_pid: u32,
    agent_ppid: Option<u32>,
) -> Result<ProcessChainSnapshot, KillerError> {
    let chain_pids = collect_chain(table, target_pid, agent_pid, agent_ppid)?;

    let snapshot = if capture_forensics {
        build_snapshot_from_table(table, &chain_pids)
    } else {
        empty_snapshot()
    };

    for &pid in &chain_pids {
        if let Err(reason) = table.kill(pid) {
            log::error!("[killer] failed to kill PID {pid}: {reason}");
        }
    }

    Ok(snapshot)
}

fn build_snapshot_from_table<T: ProcessTable + ?Sized>(table: &T, pids: &[u32]) -> ProcessChainSnapshot {
    let captured_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut tree = Vec::with_capacity(pids.len());
    let mut command_lines: HashMap<u32, Vec<String>> = HashMap::new();

    for &pid in pids {
        if table.process_exists(pid) {
            let cmdline = table.cmdline(pid);
            let entry = ProcessEntry {
                pid,
                parent_pid: table.parent_pid(pid),
                name: table.process_name(pid).unwrap_or_default(),
                cmdline: cmdline.clone(),
            };
            command_lines.insert(pid, cmdline);
            tree.push(entry);
        }
    }

    ProcessChainSnapshot {
        tree,
        command_lines,
        open_files: vec![],
        network_connections: vec![],
        captured_at,
    }
}

fn empty_snapshot() -> ProcessChainSnapshot {
    ProcessChainSnapshot {
        tree: vec![],
        command_lines: HashMap::new(),
        open_files: vec![],
        network_connections: vec![],
        captured_at: 0,
    }
}

/// Orchestrates forensic capture and process-chain termination.
pub struct Killer {
    capture_forensics: bool,
}

impl Killer {
    pub fn new(capture_forensics: bool) -> Self {
        Self { capture_forensics }
    }

    /// Capture forensics, then kill the process chain rooted at `target_pid`.
    /// Idempotent: if a PID is already dead, the call succeeds.
    pub async fn kill_chain(
        &self,
        target_pid: u32,
    ) -> Result<ProcessChainSnapshot, KillerError> {
        let capture = self.capture_forensics;
        tokio::task::spawn_blocking(move || kill_chain_sync(target_pid, capture))
            .await
            .map_err(|_| KillerError::SysinfoRefresh)?
    }
}

/// Synchronous (blocking) implementation — safe to call from spawn_blocking.
fn kill_chain_sync(
    target_pid: u32,
    capture_forensics: bool,
) -> Result<ProcessChainSnapshot, KillerError> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let agent_pid = std::process::id();
    let agent_ppid = sys
        .process(Pid::from_u32(agent_pid))
        .and_then(|p| p.parent())
        .map(|p| p.as_u32());

    let mut table = SysinfoProcessTable::new(&mut sys);
    kill_chain_on_table(&mut table, target_pid, capture_forensics, agent_pid, agent_ppid)
}

#[cfg(test)]
pub mod fake {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct FakeProcess {
        pub pid: u32,
        pub parent_pid: Option<u32>,
        pub name: String,
        pub cmdline: Vec<String>,
    }

    #[derive(Default)]
    pub struct FakeProcessTable {
        pub processes: HashMap<u32, FakeProcess>,
        pub killed_pids: Vec<u32>,
    }

    impl FakeProcessTable {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn add_process(&mut self, pid: u32, parent_pid: Option<u32>, name: &str, cmdline: &[&str]) {
            self.processes.insert(
                pid,
                FakeProcess {
                    pid,
                    parent_pid,
                    name: name.to_string(),
                    cmdline: cmdline.iter().map(|&s| s.to_string()).collect(),
                },
            );
        }
    }

    impl ProcessTable for FakeProcessTable {
        fn process_exists(&self, pid: u32) -> bool {
            self.processes.contains_key(&pid)
        }

        fn parent_pid(&self, pid: u32) -> Option<u32> {
            self.processes.get(&pid).and_then(|p| p.parent_pid)
        }

        fn process_name(&self, pid: u32) -> Option<String> {
            self.processes.get(&pid).map(|p| p.name.clone())
        }

        fn cmdline(&self, pid: u32) -> Vec<String> {
            self.processes.get(&pid).map(|p| p.cmdline.clone()).unwrap_or_default()
        }

        fn all_pids(&self) -> Vec<u32> {
            self.processes.keys().copied().collect()
        }

        fn kill(&mut self, pid: u32) -> Result<(), String> {
            if self.processes.contains_key(&pid) {
                self.killed_pids.push(pid);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    #[test]
    fn process_chain_snapshot_serde_round_trip() {
        let mut cmd_map = HashMap::new();
        cmd_map.insert(42u32, vec!["evil.exe".to_string(), "--encrypt".to_string()]);

        let snap = ProcessChainSnapshot {
            tree: vec![ProcessEntry {
                pid: 42,
                parent_pid: Some(1),
                name: "evil.exe".to_string(),
                cmdline: vec!["evil.exe".to_string(), "--encrypt".to_string()],
            }],
            command_lines: cmd_map,
            open_files: vec!["/tmp/victim.txt".to_string()],
            network_connections: vec!["192.0.2.1:443".to_string()],
            captured_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&snap).expect("serialize");
        let back: ProcessChainSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.tree.len(), 1);
        assert_eq!(back.tree[0].pid, 42);
        assert_eq!(back.tree[0].parent_pid, Some(1));
        assert_eq!(back.tree[0].name, "evil.exe");
        assert_eq!(back.command_lines[&42], vec!["evil.exe", "--encrypt"]);
        assert_eq!(back.open_files, vec!["/tmp/victim.txt"]);
        assert_eq!(back.network_connections, vec!["192.0.2.1:443"]);
        assert_eq!(back.captured_at, 1_700_000_000);
    }

    #[test]
    fn process_entry_serde_round_trip() {
        let entry = ProcessEntry {
            pid: 100,
            parent_pid: None,
            name: "init".to_string(),
            cmdline: vec!["/sbin/init".to_string()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProcessEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 100);
        assert!(back.parent_pid.is_none());
    }

    #[test]
    fn target_with_children_kills_target_and_children_only() {
        let mut table = FakeProcessTable::new();
        // Process hierarchy:
        // System (4) -> explorer.exe (1000) -> cmd.exe (2000) -> malware.exe (3000) -> child1.exe (3001) -> grandchild.exe (3002)
        table.add_process(4, None, "System", &["System"]);
        table.add_process(1000, Some(4), "explorer.exe", &["explorer.exe"]);
        table.add_process(2000, Some(1000), "cmd.exe", &["cmd.exe"]);
        table.add_process(3000, Some(2000), "malware.exe", &["malware.exe", "--encrypt"]);
        table.add_process(3001, Some(3000), "child1.exe", &["child1.exe"]);
        table.add_process(3002, Some(3001), "grandchild.exe", &["grandchild.exe"]);
        table.add_process(4000, Some(2000), "benign_sibling.exe", &["benign.exe"]);

        let res = kill_chain_on_table(&mut table, 3000, true, 9999, Some(1000));
        assert!(res.is_ok(), "kill_chain should succeed");

        // Assert killed PIDs are strictly target (3000) and its descendants (3001, 3002)
        let mut killed = table.killed_pids.clone();
        killed.sort_unstable();
        assert_eq!(killed, vec![3000, 3001, 3002]);

        // Ancestors (4, 1000, 2000) and sibling (4000) must NOT be killed
        assert!(!table.killed_pids.contains(&4));
        assert!(!table.killed_pids.contains(&1000));
        assert!(!table.killed_pids.contains(&2000));
        assert!(!table.killed_pids.contains(&4000));
    }

    #[test]
    fn parent_chain_is_untouched() {
        let mut table = FakeProcessTable::new();
        table.add_process(1, None, "init", &["/sbin/init"]);
        table.add_process(500, Some(1), "systemd", &["systemd"]);
        table.add_process(800, Some(500), "bash", &["/bin/bash"]);
        table.add_process(900, Some(800), "ransomware", &["./ransomware"]);

        let res = kill_chain_on_table(&mut table, 900, false, 9999, None);
        assert!(res.is_ok());

        assert_eq!(table.killed_pids, vec![900]);
        assert!(!table.killed_pids.contains(&800));
        assert!(!table.killed_pids.contains(&500));
        assert!(!table.killed_pids.contains(&1));
    }

    #[test]
    fn denylisted_pids_are_refused() {
        let mut table = FakeProcessTable::new();
        table.add_process(0, None, "System Idle Process", &[]);
        table.add_process(1, None, "init", &["/sbin/init"]);
        table.add_process(4, None, "System", &[]);
        table.add_process(100, None, "explorer.exe", &["explorer.exe"]);
        table.add_process(101, None, "svchost.exe", &["svchost.exe", "-k", "netsvcs"]);
        table.add_process(102, None, "csrss.exe", &["csrss.exe"]);
        table.add_process(103, None, "[kthreadd]", &[]);

        for &pid in &[0, 1, 4, 100, 101, 102, 103] {
            let res = kill_chain_on_table(&mut table, pid, false, 9999, None);
            assert!(
                matches!(res, Err(KillerError::DenylistedPid { .. })),
                "PID {pid} should be refused by denylist"
            );
        }
        assert!(table.killed_pids.is_empty(), "No denylisted PID should be killed");
    }

    #[test]
    fn cyclic_process_tree_does_not_infinite_loop() {
        let mut table = FakeProcessTable::new();
        // Cycle: 3000 -> 3001 -> 3002 -> 3000
        table.add_process(3000, Some(3002), "evil1", &[]);
        table.add_process(3001, Some(3000), "evil2", &[]);
        table.add_process(3002, Some(3001), "evil3", &[]);

        let res = kill_chain_on_table(&mut table, 3000, true, 9999, None);
        assert!(res.is_ok());

        let mut killed = table.killed_pids.clone();
        killed.sort_unstable();
        assert_eq!(killed, vec![3000, 3001, 3002]);
    }

    #[test]
    fn agent_self_pid_and_parent_are_refused() {
        let mut table = FakeProcessTable::new();
        let agent_pid = 7777;
        let agent_ppid = 7700;
        table.add_process(agent_pid, Some(agent_ppid), "aegis-agent-rust", &["aegis-agent-rust"]);
        table.add_process(agent_ppid, Some(1), "supervisor", &["supervisor"]);

        let res_self = kill_chain_on_table(&mut table, agent_pid, false, agent_pid, Some(agent_ppid));
        assert!(matches!(res_self, Err(KillerError::DenylistedPid { .. })));

        let res_parent = kill_chain_on_table(&mut table, agent_ppid, false, agent_pid, Some(agent_ppid));
        assert!(matches!(res_parent, Err(KillerError::DenylistedPid { .. })));

        assert!(table.killed_pids.is_empty());
    }
}
