using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;

namespace Aegis.App.ViewModels;

public partial class RansomwareDefenseViewModel : ViewModelBase
{
    private readonly IAegisApiClient _api;
    private readonly IDialogService _dialog;
    private readonly ILogger<RansomwareDefenseViewModel> _logger;

    [ObservableProperty]
    private int _canaryTrips;

    [ObservableProperty]
    private int _vssDeletions;

    [ObservableProperty]
    private int _activeAlerts;

    [ObservableProperty]
    private int _massEncryptionEvents;

    [ObservableProperty]
    private ISeries[]? _raasSeries;

    [ObservableProperty]
    private Axis[]? _raasXAxes;

    public ObservableCollection<RaaSGroupDto> RaasGroups { get; } = new();
    public ObservableCollection<SnapshotDto> Snapshots { get; } = new();
    public ObservableCollection<DecryptorDto> Decryptors { get; } = new();

    public RansomwareDefenseViewModel(
        IAegisApiClient api,
        IDialogService dialog,
        ILogger<RansomwareDefenseViewModel> logger)
    {
        _api = api;
        _dialog = dialog;
        _logger = logger;

        _ = LoadRansomwareDataAsync();
    }

    [RelayCommand]
    public async Task LoadRansomwareDataAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;

        try
        {
            var stats = await _api.GetRansomwareStatsAsync();
            CanaryTrips = stats.CanaryFilesTripped;
            VssDeletions = stats.ShadowCopiesDeleted;
            ActiveAlerts = stats.ActiveAlerts;
            MassEncryptionEvents = stats.MassEncryptionEvents;

            var groups = await _api.GetRaaSGroupsAsync();
            RaasGroups.Clear();
            foreach (var g in groups) RaasGroups.Add(g);

            if (groups.Count > 0)
            {
                var labels = groups.Select(g => g.Name.Length > 12 ? g.Name.Substring(0, 12) + ".." : g.Name).ToArray();
                var scores = groups.Select(g => (double)g.ActivityScore).ToArray();

                RaasSeries = new ISeries[]
                {
                    new ColumnSeries<double>
                    {
                        Name = "Activity Level",
                        Values = scores,
                        Fill = new SolidColorPaint(new SKColor(239, 68, 68)),
                        Rx = 4,
                        Ry = 4
                    }
                };

                RaasXAxes = new Axis[]
                {
                    new Axis
                    {
                        Labels = labels,
                        LabelsPaint = new SolidColorPaint(new SKColor(148, 163, 184)),
                        SeparatorsPaint = new SolidColorPaint(new SKColor(32, 36, 51))
                    }
                };
            }

            var recovery = await _api.GetRecoveryOptionsAsync("inc_001");
            Snapshots.Clear();
            Decryptors.Clear();
            if (recovery != null)
            {
                foreach (var s in recovery.Snapshots) Snapshots.Add(s);
                foreach (var d in recovery.Decryptors) Decryptors.Add(d);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load ransomware defense data");
            ErrorMessage = "Failed to load ransomware data: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RestoreSnapshotAsync(SnapshotDto? snapshot)
    {
        if (snapshot == null) return;

        var confirmed = await _dialog.ShowConfirmationAsync(
            "RESTORE SNAPSHOT (DESTRUCTIVE)",
            $"WARNING: This will roll back disk state on '{snapshot.Hostname}' to snapshot '{snapshot.SnapshotRef}'. Proceed?",
            "Restore Snapshot", "Cancel");

        if (!confirmed) return;

        try
        {
            var hostId = !string.IsNullOrWhiteSpace(snapshot.HostId) ? snapshot.HostId : (!string.IsNullOrWhiteSpace(snapshot.Hostname) ? snapshot.Hostname : "node-01");
            await _api.TriggerRestoreAsync(new RestoreRequest(hostId, snapshot.Id, "C:\\Restores"));
            await _dialog.ShowMessageAsync("Snapshot Restoration Triggered", $"Restoration job for {snapshot.SnapshotRef} has been dispatched.");
        }
        catch (Exception ex)
        {
            await _dialog.ShowErrorAsync("Restore Failed", ex.Message);
        }
    }
}
