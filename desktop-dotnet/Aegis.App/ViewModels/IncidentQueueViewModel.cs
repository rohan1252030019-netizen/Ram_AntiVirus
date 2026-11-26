using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.App.ViewModels;

public partial class IncidentQueueViewModel : ViewModelBase
{
    private readonly IAegisApiClient _api;
    private readonly INavigationService _nav;
    private readonly IDialogService _dialog;
    private readonly ILogger<IncidentQueueViewModel> _logger;

    private List<IncidentDto> _allIncidents = new();

    public ObservableCollection<IncidentDto> FilteredIncidents { get; } = new();

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private string _selectedSeverity = "All";

    [ObservableProperty]
    private string _selectedStatus = "All";

    [ObservableProperty]
    private IncidentDto? _selectedIncident;

    public IncidentQueueViewModel(
        IAegisApiClient api,
        INavigationService nav,
        IDialogService dialog,
        ILogger<IncidentQueueViewModel> logger)
    {
        _api = api;
        _nav = nav;
        _dialog = dialog;
        _logger = logger;

        _ = LoadIncidentsAsync();
    }

    [RelayCommand]
    public async Task LoadIncidentsAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;

        try
        {
            _allIncidents = await _api.GetIncidentsAsync();
            ApplyFilter();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch incidents");
            ErrorMessage = "Failed to load incidents: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    partial void OnSearchQueryChanged(string value) => ApplyFilter();
    partial void OnSelectedSeverityChanged(string value) => ApplyFilter();
    partial void OnSelectedStatusChanged(string value) => ApplyFilter();

    private void ApplyFilter()
    {
        var query = _allIncidents.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(SearchQuery))
        {
            query = query.Where(i =>
                i.Title.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                (i.SourceIp != null && i.SourceIp.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase)) ||
                (i.MitreTechnique != null && i.MitreTechnique.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase)));
        }

        if (SelectedSeverity != "All" && Enum.TryParse<Severity>(SelectedSeverity, true, out var sev))
        {
            query = query.Where(i => i.Severity == sev);
        }

        if (SelectedStatus != "All" && Enum.TryParse<IncidentStatus>(SelectedStatus, true, out var st))
        {
            query = query.Where(i => i.Status == st);
        }

        FilteredIncidents.Clear();
        foreach (var inc in query.OrderByDescending(i => i.CreatedAt))
        {
            FilteredIncidents.Add(inc);
        }
    }

    [RelayCommand]
    private void ViewDetail(IncidentDto? incident)
    {
        var target = incident ?? SelectedIncident;
        if (target != null)
        {
            _nav.NavigateTo<IncidentDetailViewModel>(vm => vm.LoadIncident(target.Id));
        }
    }

    [RelayCommand]
    private async Task ExportCsvAsync()
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Title,Severity,Status,SourceIP,MitreTechnique,CreatedAt,RiskScore");
            foreach (var inc in FilteredIncidents)
            {
                sb.AppendLine($"\"{inc.Id}\",\"{inc.Title}\",\"{inc.Severity}\",\"{inc.Status}\",\"{inc.SourceIp}\",\"{inc.MitreTechnique}\",\"{inc.CreatedAt:u}\",{inc.RiskScore}");
            }

            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Aegis_Incidents_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv");
            await File.WriteAllTextAsync(path, sb.ToString());
            await _dialog.ShowMessageAsync("Export Complete", $"Exported {FilteredIncidents.Count} incidents to:\n{path}");
        }
        catch (Exception ex)
        {
            await _dialog.ShowErrorAsync("Export Failed", ex.Message);
        }
    }
}
