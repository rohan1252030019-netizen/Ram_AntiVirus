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

public partial class DashboardOverviewViewModel : ViewModelBase
{
    private readonly IAegisApiClient _api;
    private readonly IAegisWebSocketService _ws;
    private readonly INavigationService _nav;
    private readonly ILogger<DashboardOverviewViewModel> _logger;

    [ObservableProperty]
    private int _activeThreats;

    [ObservableProperty]
    private int _incidentsToday;

    [ObservableProperty]
    private int _assetsProtected;

    [ObservableProperty]
    private int _blockedIpsCount;

    [ObservableProperty]
    private double _avgTriageTimeMs = 0.75;

    [ObservableProperty]
    private string _systemHealth = "Optimal";

    [ObservableProperty]
    private ISeries[]? _trendSeries;

    [ObservableProperty]
    private Axis[]? _xAxes;

    public ObservableCollection<TimelineEventDto> TimelineEvents { get; } = new();

    public DashboardOverviewViewModel(
        IAegisApiClient api,
        IAegisWebSocketService ws,
        INavigationService nav,
        ILogger<DashboardOverviewViewModel> logger)
    {
        _api = api;
        _ws = ws;
        _nav = nav;
        _logger = logger;

        _ws.Subscribe("incidents.new", _ =>
        {
            ActiveThreats++;
            IncidentsToday++;
        });

        _ = RefreshDataAsync();
    }

    [RelayCommand]
    public async Task RefreshDataAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;

        try
        {
            var overview = await _api.GetDashboardOverviewAsync();
            ActiveThreats = overview.ActiveThreats;
            IncidentsToday = overview.IncidentsToday;
            AssetsProtected = overview.AssetsProtected;
            BlockedIpsCount = overview.BlockedIpsCount;
            AvgTriageTimeMs = overview.AvgTriageTimeMs;
            SystemHealth = overview.SystemHealth;

            var timeline = await _api.GetTimelineAsync();
            TimelineEvents.Clear();
            foreach (var t in timeline) TimelineEvents.Add(t);

            if (timeline.Count > 0)
            {
                var labels = timeline.Select(t => t.Date.Length > 5 ? t.Date.Substring(5) : t.Date).ToArray();
                var incidents = timeline.Select(t => (double)t.IncidentCount).ToArray();
                var threats = timeline.Select(t => (double)t.ThreatCount).ToArray();

                TrendSeries = new ISeries[]
                {
                    new LineSeries<double>
                    {
                        Name = "Incidents",
                        Values = incidents,
                        Stroke = new SolidColorPaint(new SKColor(6, 182, 212), 2),
                        Fill = new SolidColorPaint(new SKColor(6, 182, 212, 35)),
                        GeometrySize = 6
                    },
                    new LineSeries<double>
                    {
                        Name = "Threats",
                        Values = threats,
                        Stroke = new SolidColorPaint(new SKColor(239, 68, 68), 2),
                        Fill = new SolidColorPaint(new SKColor(239, 68, 68, 25)),
                        GeometrySize = 6
                    }
                };

                XAxes = new Axis[]
                {
                    new Axis
                    {
                        Labels = labels,
                        LabelsPaint = new SolidColorPaint(new SKColor(148, 163, 184)),
                        SeparatorsPaint = new SolidColorPaint(new SKColor(32, 36, 51))
                    }
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load dashboard overview");
            ErrorMessage = "Failed to load overview: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void GoToIncidentQueue()
    {
        _nav.NavigateTo<IncidentQueueViewModel>();
    }

    [RelayCommand]
    private void GoToFirewall()
    {
        _nav.NavigateTo<FirewallRulesViewModel>();
    }
}
