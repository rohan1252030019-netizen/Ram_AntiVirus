using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.App.ViewModels;

public partial class IncidentDetailViewModel : ViewModelBase
{
    private readonly IAegisApiClient _api;
    private readonly INavigationService _nav;
    private readonly IDialogService _dialog;
    private readonly ILogger<IncidentDetailViewModel> _logger;

    [ObservableProperty]
    private IncidentDto? _incident;

    public ObservableCollection<ResponseActionDto> Actions { get; } = new();

    public IncidentDetailViewModel(
        IAegisApiClient api,
        INavigationService nav,
        IDialogService dialog,
        ILogger<IncidentDetailViewModel> logger)
    {
        _api = api;
        _nav = nav;
        _dialog = dialog;
        _logger = logger;
    }

    public async void LoadIncident(string incidentId)
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            Incident = await _api.GetIncidentDetailAsync(incidentId);
            Actions.Clear();
            if (Incident?.Actions != null)
            {
                foreach (var a in Incident.Actions) Actions.Add(a);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load incident details for {Id}", incidentId);
            ErrorMessage = "Failed to load details: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ApproveActionAsync(ResponseActionDto? action)
    {
        if (action == null) return;

        var confirmed = await _dialog.ShowConfirmationAsync(
            "Execute Containment Action",
            $"Are you sure you want to execute {action.ActionType} on target '{action.Target}'?",
            "Execute Now", "Cancel");

        if (!confirmed) return;

        try
        {
            await _api.ApproveActionAsync(action.Id);
            await _dialog.ShowMessageAsync("Action Executed", $"Containment {action.ActionType} executed successfully.");
            if (Incident != null) LoadIncident(Incident.Id);
        }
        catch (Exception ex)
        {
            await _dialog.ShowErrorAsync("Execution Failed", ex.Message);
        }
    }

    [RelayCommand]
    private async Task RejectActionAsync(ResponseActionDto? action)
    {
        if (action == null) return;

        var confirmed = await _dialog.ShowConfirmationAsync(
            "Dismiss Containment Action",
            $"Dismiss pending action {action.ActionType} on target '{action.Target}'?",
            "Dismiss", "Cancel");

        if (!confirmed) return;

        try
        {
            await _api.RejectActionAsync(action.Id, "Operator dismissed from desktop console");
            if (Incident != null) LoadIncident(Incident.Id);
        }
        catch (Exception ex)
        {
            await _dialog.ShowErrorAsync("Dismissal Failed", ex.Message);
        }
    }

    [RelayCommand]
    private void BackToQueue()
    {
        _nav.NavigateTo<IncidentQueueViewModel>();
    }
}
