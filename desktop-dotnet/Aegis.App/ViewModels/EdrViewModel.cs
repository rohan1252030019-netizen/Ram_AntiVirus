using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Exceptions;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.App.ViewModels;

public partial class EdrViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;
    private readonly ILogger<EdrViewModel> _logger;

    [ObservableProperty]
    private string _agentId = "host-monitor-local";

    [ObservableProperty]
    private string _targetHostname = "LOCAL-ENDPOINT";

    [ObservableProperty]
    private int _selectedPid = 0;

    [ObservableProperty]
    private string _targetFilePath = string.Empty;

    [ObservableProperty]
    private string _targetSha256 = string.Empty;

    [ObservableProperty]
    private string _isolationReason = "Suspicious lateral movement activity";

    [ObservableProperty]
    private bool _isHostIsolated;

    [ObservableProperty]
    private string? _statusNotice;

    public ObservableCollection<RecentEdrEventDto> Events { get; } = new();

    public EdrViewModel(
        IAegisApiClient apiClient,
        IDialogService dialogService,
        ILogger<EdrViewModel> logger)
    {
        _apiClient = apiClient;
        _dialogService = dialogService;
        _logger = logger;
    }

    public override async Task InitializeAsync()
    {
        await LoadEventsAsync();
    }

    [RelayCommand]
    public async Task LoadEventsAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;
        StatusNotice = null;

        try
        {
            var events = await _apiClient.GetRecentEdrEventsAsync(AgentId, minutes: 60, limit: 100);
            Events.Clear();
            foreach (var ev in events)
            {
                Events.Add(ev);
            }
            StatusNotice = $"Loaded {Events.Count} recent endpoint telemetry events.";
        }
        catch (AegisForbiddenException)
        {
            ErrorMessage = "Access Denied: EDR telemetry inspection is not permitted for your current role.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load EDR events");
            ErrorMessage = $"Failed to fetch EDR telemetry: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Checks whether the targeted PID is a protected system core or init process.
    /// NOTE: This is a client-side UX safeguard:
    /// - Windows targets: PID <= 4 (PID 0 = System Idle, PID 4 = System).
    /// - Linux/POSIX targets: PID <= 2 (PID 1 = init/systemd, PID 2 = kthreadd).
    /// The backend Rust node agent / EDR daemon remains the authoritative security enforcement point.
    /// </summary>
    private bool IsProtectedSystemPid(int pid)
    {
        if (pid <= 0) return true;

        if (OperatingSystem.IsLinux() || TargetHostname.Contains("linux", StringComparison.OrdinalIgnoreCase))
        {
            return pid <= 2; // init, kthreadd
        }

        // Windows client-side default: PID 0 (Idle) and PID 4 (System)
        return pid <= 4;
    }

    [RelayCommand]
    public async Task KillProcessAsync()
    {
        if (IsProtectedSystemPid(SelectedPid))
        {
            await _dialogService.ShowErrorAsync(
                "Protected System Process",
                $"Refusing to target protected operating system process (PID {SelectedPid}).\nClient-side safety guard prevented termination. The AEGIS Rust node agent remains the authoritative enforcement point.");
            return;
        }

        var confirmed = await _dialogService.ShowConfirmationAsync(
            "Confirm Kill Process",
            $"Are you sure you want to forcibly terminate process PID {SelectedPid} on endpoint '{TargetHostname}'?",
            "Terminate Process",
            "Cancel");

        if (!confirmed) return;

        IsBusy = true;
        try
        {
            var success = await _apiClient.KillProcessAsync(new KillProcessRequest(SelectedPid, Confirm: true));
            if (success)
            {
                await _dialogService.ShowMessageAsync("Process Terminated", $"Process PID {SelectedPid} was successfully killed.");
                await LoadEventsAsync();
            }
        }
        catch (AegisForbiddenException)
        {
            ErrorMessage = "Access Denied: Killing processes requires Administrator privileges.";
            await _dialogService.ShowErrorAsync("Access Denied", ErrorMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to kill process PID {Pid}", SelectedPid);
            ErrorMessage = $"Process termination failed: {ex.Message}";
            await _dialogService.ShowErrorAsync("Action Failed", ErrorMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    public async Task QuarantineFileAsync()
    {
        if (string.IsNullOrWhiteSpace(TargetFilePath) || string.IsNullOrWhiteSpace(TargetSha256))
        {
            await _dialogService.ShowErrorAsync("Missing Details", "Both Target File Path and Expected SHA-256 hash are required to quarantine a file.");
            return;
        }

        var confirmed = await _dialogService.ShowConfirmationAsync(
            "Confirm File Quarantine",
            $"Are you sure you want to move the following file into quarantine?\n\nPath: {TargetFilePath}\nExpected SHA256: {TargetSha256}",
            "Quarantine File",
            "Cancel");

        if (!confirmed) return;

        IsBusy = true;
        try
        {
            var success = await _apiClient.QuarantineFileAsync(new QuarantineFileRequest(TargetFilePath, TargetSha256, Confirm: true));
            if (success)
            {
                await _dialogService.ShowMessageAsync("File Quarantined", $"File '{TargetFilePath}' moved to secure quarantine vault.");
                TargetFilePath = string.Empty;
                TargetSha256 = string.Empty;
            }
        }
        catch (AegisForbiddenException)
        {
            ErrorMessage = "Access Denied: Quarantining files requires Analyst or Admin privileges.";
            await _dialogService.ShowErrorAsync("Access Denied", ErrorMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to quarantine file {Path}", TargetFilePath);
            ErrorMessage = $"Quarantine action failed: {ex.Message}";
            await _dialogService.ShowErrorAsync("Action Failed", ErrorMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    public async Task IsolateHostAsync()
    {
        // Enforce safety: typing hostname to confirm + blocking localhost without extra verification
        var confirmed = await _dialogService.ConfirmHostIsolationAsync(AgentId, TargetHostname);
        if (!confirmed)
        {
            StatusNotice = "Host isolation cancelled by operator.";
            return;
        }

        IsBusy = true;
        try
        {
            var req = new IsolateHostRequest(IsolationReason, LeaseSeconds: 3600, Confirm: true);
            var success = await _apiClient.IsolateHostAsync(AgentId, req);
            if (success)
            {
                IsHostIsolated = true;
                await _dialogService.ShowMessageAsync("Host Isolated", $"Endpoint '{TargetHostname}' is now isolated from the network.");
            }
        }
        catch (AegisForbiddenException)
        {
            ErrorMessage = "Access Denied: Host network isolation requires Administrator privileges.";
            await _dialogService.ShowErrorAsync("Access Denied", ErrorMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to isolate host {Host}", TargetHostname);
            ErrorMessage = $"Host isolation failed: {ex.Message}";
            await _dialogService.ShowErrorAsync("Isolation Failed", ErrorMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    public async Task UnisolateHostAsync()
    {
        var confirmed = await _dialogService.ShowConfirmationAsync(
            "Confirm Host Unisolation",
            $"Restore full network connectivity to endpoint '{TargetHostname}'?",
            "Unisolate Host",
            "Cancel");

        if (!confirmed) return;

        IsBusy = true;
        try
        {
            var req = new UnisolateHostRequest("Operator manual restoration");
            var success = await _apiClient.UnisolateHostAsync(AgentId, req);
            if (success)
            {
                IsHostIsolated = false;
                await _dialogService.ShowMessageAsync("Host Unisolated", $"Network access restored for '{TargetHostname}'.");
            }
        }
        catch (AegisForbiddenException)
        {
            ErrorMessage = "Access Denied: Unisolate host requires Administrator privileges.";
            await _dialogService.ShowErrorAsync("Access Denied", ErrorMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to unisolate host {Host}", TargetHostname);
            ErrorMessage = $"Unisolation failed: {ex.Message}";
            await _dialogService.ShowErrorAsync("Unisolation Failed", ErrorMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }
}
