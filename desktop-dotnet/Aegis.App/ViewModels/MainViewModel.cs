using System.Collections.ObjectModel;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Toolkit.Uwp.Notifications;

namespace Aegis.App.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private readonly INavigationService _navigationService;
    private readonly IAuthService _authService;
    private readonly IAegisWebSocketService _wsService;
    private readonly INetworkStatusService _networkStatus;
    private readonly IDialogService? _dialogService;

    private readonly object _alertLock = new();
    private int _coalescedAlertCount = 0;
    private Timer? _coalesceTimer;
    private const int CoalesceWindowSeconds = 8;

    [ObservableProperty]
    private string _userName = "Operator";

    [ObservableProperty]
    private string _userRoleText = "Viewer";

    [ObservableProperty]
    private bool _isWsConnected;

    [ObservableProperty]
    private string _wsStatusText = "Connecting...";

    [ObservableProperty]
    private bool _isOffline;

    [ObservableProperty]
    private string _offlineMessage = string.Empty;

    public INavigationService Navigation => _navigationService;

    public ObservableCollection<NavigationItem> NavItems { get; } = new();

    public MainViewModel(
        INavigationService navigationService,
        IAuthService authService,
        IAegisWebSocketService wsService,
        INetworkStatusService networkStatus,
        IDialogService? dialogService = null)
    {
        _navigationService = navigationService;
        _authService = authService;
        _wsService = wsService;
        _networkStatus = networkStatus;
        _dialogService = dialogService;

        _wsService.ConnectionStateChanged += OnWsStateChanged;
        _wsService.Subscribe("incidents.new", OnIncidentAlertReceived);
        _wsService.Subscribe("ransomware.incident", OnRansomwareAlertReceived);
        _wsService.Subscribe("actions.new", OnActionExecutedReceived);

        _networkStatus.NetworkStatusChanged += OnNetworkStatusChanged;

        _navigationService.CurrentViewChanged += () => OnPropertyChanged(nameof(CurrentView));
    }

    public object? CurrentView => _navigationService.CurrentView;

    private void OnNetworkStatusChanged(object? sender, EventArgs e)
    {
        IsOffline = !_networkStatus.IsOnline;
        OfflineMessage = _networkStatus.LastError ?? "Backend network connection lost. Retrying...";
    }

    public void RefreshRoleVisibility()
    {
        UserName = _authService.CurrentUser?.Name ?? "Security Operator";
        UserRoleText = _authService.CurrentRole.ToString().ToUpperInvariant();

        NavItems.Clear();

        // Viewer+ items
        NavItems.Add(new NavigationItem("Dashboard", "Overview", typeof(DashboardOverviewViewModel), true));
        NavItems.Add(new NavigationItem("Operator Guide", "IR Playbooks & Keys", typeof(OperatorGuideViewModel), true));
        NavItems.Add(new NavigationItem("Compliance Matrix", "NIST / CIS Posture", typeof(ComplianceMatrixViewModel), true));

        // Analyst+ items
        var isAnalystOrHigher = _authService.HasRole(UserRole.Analyst);
        NavItems.Add(new NavigationItem("Incident Queue", "Response (SOAR)", typeof(IncidentQueueViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("Ransomware", "Ransomware Defense", typeof(RansomwareDefenseViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("EDR Telemetry", "Process & Host Isolate", typeof(EdrViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("Antivirus Vault", "Signatures & Quarantine", typeof(AntivirusViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("Attack Surface", "Exposure & Scans", typeof(AttackSurfaceViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("Threat Intel", "IOCs & Campaigns", typeof(ThreatIntelViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("IP Investigation", "Deep Forensics & ASN", typeof(IpInvestigationViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("DoS Shield", "L7 Volumetric Mitigations", typeof(DosShieldViewModel), isAnalystOrHigher));
        NavItems.Add(new NavigationItem("Quantum Lab", "Post-Quantum Cryptography", typeof(QuantumAnalyticsViewModel), isAnalystOrHigher));

        // Admin items
        var isAdmin = _authService.HasRole(UserRole.Admin);
        NavItems.Add(new NavigationItem("Phantom Honeygrid", "Decoy Traps & Attackers", typeof(PhantomViewModel), isAdmin));
        NavItems.Add(new NavigationItem("Deception", "Honeytokens & Lures", typeof(DeceptionViewModel), isAdmin));
        NavItems.Add(new NavigationItem("Firewall", "Firewall & Shield", typeof(FirewallRulesViewModel), isAdmin));
        NavItems.Add(new NavigationItem("Node Cluster", "Fleet Agents & Enrolling", typeof(NodeManagementViewModel), isAdmin));
        NavItems.Add(new NavigationItem("Infrastructure", "Health & Telemetry", typeof(InfrastructureHealthViewModel), isAdmin));
        NavItems.Add(new NavigationItem("Settings", "System Settings", typeof(SettingsViewModel), isAdmin));
    }

    private void OnWsStateChanged(bool connected)
    {
        IsWsConnected = connected;
        WsStatusText = connected ? "Live (Connected)" : "Offline (Reconnecting...)";
    }

    private void OnIncidentAlertReceived(object? payload)
    {
        if (payload is not string json) return;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var severity = root.TryGetProperty("severity", out var sProp) ? sProp.GetString() : null;

            // Only notify for critical incidents, with coalescing
            if (string.Equals(severity, "critical", StringComparison.OrdinalIgnoreCase))
            {
                var title = root.TryGetProperty("title", out var tProp) ? tProp.GetString() : "Critical Security Threat";
                EnqueueCriticalAlert(title ?? "Immediate SOC action required.");
            }
        }
        catch { /* best effort */ }
    }

    private void OnRansomwareAlertReceived(object? payload)
    {
        EnqueueCriticalAlert("Ransomware activity detected on endpoint (Canary / VSS trip)");
    }

    private void OnActionExecutedReceived(object? payload)
    {
        // Handled silently or status bar update
    }

    private void EnqueueCriticalAlert(string alertTitle)
    {
        lock (_alertLock)
        {
            if (_coalesceTimer == null)
            {
                // First critical alert in this window: fire immediate toast
                _coalescedAlertCount = 1;
                FireSingleToast("CRITICAL INCIDENT DETECTED", alertTitle);

                _coalesceTimer = new Timer(OnCoalesceTimerElapsed, null, TimeSpan.FromSeconds(CoalesceWindowSeconds), Timeout.InfiniteTimeSpan);
            }
            else
            {
                // Additional critical alert within window: coalesce
                _coalescedAlertCount++;
            }
        }
    }

    private void OnCoalesceTimerElapsed(object? state)
    {
        lock (_alertLock)
        {
            _coalesceTimer?.Dispose();
            _coalesceTimer = null;

            if (_coalescedAlertCount > 1)
            {
                var additional = _coalescedAlertCount - 1;
                FireSingleToast(
                    "MULTIPLE CRITICAL INCIDENTS",
                    $"{additional} additional critical incident(s) received in the last {CoalesceWindowSeconds}s. Review Incident Queue immediately.");
            }
            _coalescedAlertCount = 0;
        }
    }

    private void FireSingleToast(string title, string body)
    {
        try
        {
            new ToastContentBuilder()
                .AddText(title)
                .AddText(body)
                .Show();
        }
        catch { /* notifications best effort */ }
    }

    [RelayCommand]
    private void Navigate(Type? viewModelType)
    {
        if (viewModelType != null)
        {
            _navigationService.NavigateTo(viewModelType);
        }
    }

    [RelayCommand]
    private void Logout()
    {
        _authService.ClearCredentials();
        _ = _wsService.DisconnectAsync();
        _navigationService.NavigateTo<LoginViewModel>();
    }

    [RelayCommand]
    public async Task ShowAboutAsync()
    {
        if (_dialogService == null) return;
        await _dialogService.ShowMessageAsync(
            "About Ram Antivirus",
            "Ram Antivirus Desktop Security Console\n" +
            "Version 1.0.0 (Release)\n\n" +
            "Architecture: .NET 8 WPF / MVVM\n" +
            "Backend: Python FastAPI (Autonomous SOC & SOAR)\n" +
            "Endpoint Security: High-performance Rust endpoint agent\n" +
            "Live Bus: ClientWebSocket / Redis / Memory Event Bus\n" +
            "Cryptography: Post-quantum Renyi entropy & ML-KEM/Kyber ready\n\n" +
            "© 2026 Ram Antivirus Security Systems. All rights reserved."
        );
    }

    [RelayCommand]
    public async Task RunDemoScenarioAsync()
    {
        // 1. Toast & Banner Alert
        FireSingleToast("CRITICAL: Ransomware LockBit 3.0 Canary Tripped!", 
            "Canary file 'C:\\Shares\\Confidential\\budget_canary.xlsx' modified by unauthorized process 'vssadmin.exe' (PID 4812) on node 'fin-srv-01'.");

        // 2. Navigate to Incident Queue
        _navigationService.NavigateTo<IncidentQueueViewModel>();

        if (_dialogService == null) return;

        var proceed = await _dialogService.ShowConfirmationAsync(
            "Demo Scenario: Active Ransomware Incident",
            "A critical canary trip has been simulated on 'fin-srv-01'.\n\n" +
            "Incident ID: INC-LOCKBIT-9182\n" +
            "Threat Family: LockBit 3.0 / Ransomware\n" +
            "Attacker IP: 198.51.100.24\n\n" +
            "Do you want to dispatch emergency automated containment (Isolate Host + Block Attacker IP in Firewall)?",
            "Approve Containment",
            "Cancel");

        if (proceed)
        {
            // 3. Containment dispatched -> Navigate to Firewall
            _navigationService.NavigateTo<FirewallRulesViewModel>();
            FireSingleToast("CONTAINMENT EXECUTED", "Host 'fin-srv-01' isolated. Malicious IP 198.51.100.24 added to Firewall blocklist.");
            await _dialogService.ShowMessageAsync(
                "Containment Complete",
                "Host 'fin-srv-01' has been quarantined from the network.\n" +
                "Attacker IP '198.51.100.24' has been blocked at the network perimeter.\n" +
                "VSS Shadow Copy restore verification is standing by in the Ransomware Vault."
            );
        }
    }
}

public record NavigationItem(string Title, string Description, Type TargetType, bool IsVisible);

