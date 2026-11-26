# Ram Antivirus Desktop Console — Changelog

All notable changes to the Ram Antivirus Desktop Windows client are documented in this file.

---

## [1.0.0] - 2026-11-03

### Added
- **Native Windows WPF SOC Console**: Full MVVM implementation for Ram Antivirus using C# 12, .NET 8, and CommunityToolkit.Mvvm.
- **Complete Module Coverage**: 21 functional views covering Dashboard Overview, SOAR Incident Queue, Incident Detail, Ransomware Defense, EDR Telemetry, Antivirus Vault, Attack Surface, Phantom Honeygrid, Deception Campaigns, Threat Intel, IP Investigation, DoS Shield, Node Fleet Management, Quantum Lab, Compliance Matrix, Infrastructure Health, and Settings.
- **Strict Schema Integrity Engine**: Automated reflection test (`SchemaIntegrityTests.cs` and `RequestSchemaIntegrityTests.cs`) enforcing zero schema drift between C# DTOs and the backend's official OpenAPI 3.1 schema.
- **WebSocket Live Telemetry Service**: Real-time ClientWebSocket subscription engine with 10-second authentication frame (`auth_ok`), topic fan-out routing, 25-second ping/pong keepalive, and exponential backoff auto-reconnect.
- **Secrets Hygiene & Sanitization**:
  - All test fixtures scrubbed of live JWTs, API keys, Telegram bot tokens, and Slack webhooks (`SecretsSanitizationTests.cs`).
  - Serilog log masking with `SensitiveDataEnricher` and `RedactingTextFormatter`.
  - Settings and Login UI secret masking for tokens and API keys.
- **Packaging & Installer**:
  - `publish.ps1` producing a self-contained, single-file `RamAntivirus.exe` (82 MB) for win-x64 with embedded .NET 8 runtime.
  - Inno Setup script (`ram_antivirus_installer.iss`) supporting installation, Start Menu/Desktop shortcuts, and uninstaller option to purge `%LOCALAPPDATA%\RamAntivirus`.
  - GitHub Actions CI/CD workflow (`.github/workflows/desktop-ci.yml`) on `windows-latest`.
- **First-Run Connection & Mock Mode**:
  - First-run connection manager supporting custom server URL, live ping test, and instant Offline Demo Mode toggle.
  - Settings persisted to `%LOCALAPPDATA%\RamAntivirus\settings.json`.
- **Automated Demo Scenario**: One-click simulated ransomware canary trip to containment and firewall block in under 60 seconds.

### Changed
- Clarified endpoint architecture: removed legacy "kernel driver" claims; Ram Antivirus consistently uses a high-performance **Rust endpoint agent**.
- Aligned `RestoreRequest` to match backend Pydantic schema (`host_id`, `snapshot_id`, `target_path`).
- Replaced all hand-written test fixtures with live captures against the running FastAPI database.
- Standardized product identity and display branding exclusively to **Ram Antivirus**.
