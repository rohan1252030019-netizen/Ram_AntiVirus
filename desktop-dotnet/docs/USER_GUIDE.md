# Ram Antivirus Desktop Console — User Guide & Operator Manual

**Ram Antivirus Desktop** is the native Windows operator console for Ram Antivirus, providing security analysts and administrators with real-time detection, telemetry streaming, SOAR incident orchestration, and endpoint containment.

---

## 1. Role-Based Access Control (RBAC) Matrix

The backend enforces strict role-based access control. The desktop UI adapts its navigation menu dynamically according to the authenticated user's assigned role:

| Module / Screen | Viewer | Analyst | Admin | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| **Dashboard Overview** | ✅ | ✅ | ✅ | Fleet security posture, KPI statistics, and 7-day threat trendline |
| **Operator Guide** | ✅ | ✅ | ✅ | Incident response playbooks, triage procedures, and keyboard shortcuts |
| **Compliance Matrix** | ✅ | ✅ | ✅ | SOC 2, ISO 27001, and NIST CSF automated framework auditing |
| **Incident Queue (SOAR)** | ❌ | ✅ | ✅ | Real-time incident triage, severity filtering, and investigation |
| **Incident Detail & Remediation** | ❌ | ✅ | ✅ | Forensic timeline, indicators, and approved containment actions |
| **Ransomware Defense** | ❌ | ✅ | ✅ | Canary trap monitoring, RaaS group tracking, and snapshot recovery |
| **EDR Telemetry** | ❌ | ✅ | ✅ | Endpoint telemetry stream, process kill, and host isolation |
| **Antivirus Vault** | ❌ | ✅ | ✅ | Signature updates, quarantine management, and hash lookup |
| **Attack Surface Exposure** | ❌ | ✅ | ✅ | Asset inventory, CVSS vulnerability findings, and quick scans |
| **Threat Intel Hub** | ❌ | ✅ | ✅ | IOC search and ingestion (IP, domain, hash), TTP campaigns |
| **IP Investigation** | ❌ | ✅ | ✅ | Deep IP forensic lookup, geolocation, ASN, and abuse risk scoring |
| **DoS Shield** | ❌ | ✅ | ✅ | Volumetric L7 mitigation status, PPS throughput, and offender logs |
| **Quantum Lab** | ❌ | ✅ | ✅ | Renyi entropy calculation and post-quantum crypto readiness |
| **Phantom Honeygrid** | ❌ | ❌ | ✅ | High-interaction decoy deployment, listener rotation, and attackers |
| **Deception Campaigns** | ❌ | ❌ | ✅ | Honeytoken lures, breadcrumb deployment, and attacker traps |
| **Firewall Rules** | ❌ | ❌ | ✅ | Perimeter IP blocks, rule creation, and unblock execution |
| **Node Management** | ❌ | ❌ | ✅ | Endpoint fleet enrollment, tokens, and node removal |
| **Infrastructure Health** | ❌ | ❌ | ✅ | System CPU/RAM/Disk metrics, service daemons, and database latency |
| **Settings & Alerts** | ❌ | ❌ | ✅ | Client API settings, masked Telegram tokens, and webhook URLs |

---

## 2. Destructive Action Safety & Host Protection

To prevent accidental outages or catastrophic self-containment, all destructive operations require explicit operator confirmation:

1. **Host Isolation (`POST /api/v1/edr/hosts/{id}/isolate`)**:
   - Requires confirming dialog with reason and lease duration.
   - **Self-Protection Guard**: The desktop console blocks isolation if the target node matches the operator's current workstation or the server running the Ram Antivirus backend.
2. **Process Termination (`POST /api/v1/edr/kill-process`)**:
   - Requires explicit `confirm: true`.
   - Critical system PIDs (PID 0, PID 4, PID 1, own agent PID) are rejected by both client validation and backend safety checks.
3. **File Quarantine (`POST /api/v1/edr/quarantine-file`)**:
   - Obfuscates file on disk with XOR encryption; requires SHA-256 verification and explicit confirmation.
4. **Firewall Unblock (`DELETE /api/v1/firewall/blocked/{ip}`)**:
   - Requires operator confirmation before restoring traffic to a previously blocked IP.

---

## 3. Demo Scenario (Mock Mode)

To demo Ram Antivirus to stakeholders without a running backend:
1. On the login screen or in `appsettings.json`, ensure **Offline Demo Mode** is enabled.
2. Sign in with any credentials.
3. In the top navigation bar, click **⚡ Simulate Ransomware (Demo)**:
   - An alert toast pops up: *"CRITICAL: Ransomware LockBit 3.0 Canary Tripped on fin-srv-01!"*
   - Automatically opens the incident queue and displays the containment prompt.
   - Clicking **Approve Containment** isolates the endpoint and navigates to the Firewall screen showing the attacker's C2 IP blocked in real-time.
