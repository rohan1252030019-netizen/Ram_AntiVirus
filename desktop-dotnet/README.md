# Ram Antivirus Desktop Console (WPF / .NET 8)

Native Windows desktop security operations and EDR console for **Ram Antivirus** built with **C# 12, .NET 8, and the MVVM pattern**.

---

## 🏗️ Architecture

```
desktop-dotnet/
├── Aegis.Desktop.sln
│
├── Aegis.Core/                      # Domain DTOs, Enums, and Interfaces (No UI dependencies)
│   ├── Enums/                       # Severity, IncidentStatus, ActionStatus, ActionType, UserRole
│   ├── Models/                      # IncidentDto, RansomwareStatsDto, FirewallRuleDto, etc.
│   └── Interfaces/                  # IAegisApiClient, IAuthService, IAegisWebSocketService, etc.
│
├── Aegis.Services/                  # Business & Infrastructure Services
│   ├── AegisApiClient.cs            # Real typed HttpClient talking to FastAPI (/api/v1/*)
│   ├── MockAegisApiClient.cs        # Offline Demo / Mock mode provider
│   ├── AegisWebSocketService.cs     # Real-time ClientWebSocket with auto-reconnect & ping
│   ├── AuthService.cs               # DPAPI session encryption (ProtectedData + CurrentUser)
│   ├── NavigationService.cs         # Strict MVVM ViewModel-driven navigation
│   └── JsonOptions.cs               # System.Text.Json global snake_case & enum converters
│
├── Aegis.App/                       # Native WPF UI Layer (Ram Antivirus)
│   ├── Views/                       # XAML Views with Dark SOC security console theme
│   │   ├── MainWindow.xaml          # Shell with dynamic navigation sidebar & status bar
│   │   ├── LoginView.xaml           # DPAPI-backed credential sign-in & connection testing
│   │   ├── DashboardOverviewView.xaml # KPI metric cards & 7-day timeline
│   │   ├── IncidentQueueView.xaml   # Virtualized SOAR incident triage queue + CSV export
│   │   ├── IncidentDetailView.xaml  # Postmortem, evidence, and safe containment execution
│   │   ├── RansomwareDefenseView.xaml # Kill-chain counters, RaaS groups, snapshot rollback
│   │   ├── FirewallRulesView.xaml   # Active blocked IPs, provisional drops, unblock action
│   │   ├── InfrastructureHealthView.xaml # CPU/RAM/Disk gauges, PM2 daemons, agent nodes
│   │   └── SettingsView.xaml        # Safe-IPs whitelist, masked webhook & Telegram tokens
│   ├── ViewModels/                  # CommunityToolkit.Mvvm ObservableObject view models
│   ├── Converters/                  # SeverityToBrush, BooleanToVisibility, Inverse converters
│   ├── App.xaml / App.xaml.cs       # Microsoft.Extensions.Hosting DI & Serilog configuration
│   └── appsettings.json             # Configuration & Mock Mode toggle
│
└── Aegis.Tests/                     # xUnit & Moq Unit Test Suite (163 tests)
    ├── SchemaIntegrityTests.cs      # Reflection verification of response DTOs against openapi.json
    ├── RequestSchemaIntegrityTests.cs # Reflection verification of request DTOs against openapi.json
    ├── SecretsSanitizationTests.cs  # Ensures zero active secrets exist in fixtures
    ├── ContractDeserializationTests.cs # Real backend payload deserialization verification
    └── LiveBackendSmokeTests.cs     # Live end-to-end REST and WebSocket smoke tests
```

---

## 🚀 How to Run

### Prerequisites
- Windows 10/11 (x64)
- .NET 8.0 SDK (to build from source) or use the pre-built single-file executable `RamAntivirus.exe`.
- Ram Antivirus backend running at `http://localhost:8000` (optional if using Demo / Mock Mode).

### Build from Source
```powershell
# Restore dependencies
dotnet restore desktop-dotnet/Aegis.Desktop.sln

# Build with zero warnings tolerance
dotnet build desktop-dotnet/Aegis.Desktop.sln -warnaserror

# Run Ram Antivirus
dotnet run --project desktop-dotnet/Aegis.App/Aegis.App.csproj
```

### Run Tests & Code Coverage
```powershell
# Execute all 163 unit and schema tests
dotnet test desktop-dotnet/Aegis.Tests

# Collect code coverage
dotnet test desktop-dotnet/Aegis.Tests --collect:"XPlat Code Coverage"
```

### Packaging & Publishing Single-File Executable
```powershell
# Generate self-contained win-x64 binary and Inno Setup installer script
powershell -ExecutionPolicy Bypass -File desktop-dotnet/publish.ps1
```
The published binary is written to `desktop-dotnet/publish/RamAntivirus.exe` (~82 MB self-contained).

---

## 🛡️ Security Features
- **Local Credential Storage**: Windows Data Protection API (DPAPI) encrypted under `DataProtectionScope.CurrentUser` with application entropy.
- **Log Sanitization**: Serilog text formatter automatically redacts passwords, tokens, API keys, and webhook URLs.
- **Destructive Action Safety**: Process kill, host isolation, and quarantine release require multi-step confirmation with host self-protection guards.
- **Offline Demo Mode**: Immediate zero-backend simulation of ransomware detection, triage, and firewall containment.
