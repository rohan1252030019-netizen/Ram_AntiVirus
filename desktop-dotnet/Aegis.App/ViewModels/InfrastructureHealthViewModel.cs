using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.App.ViewModels;

public partial class InfrastructureHealthViewModel : ViewModelBase
{
    private readonly IAegisApiClient _api;
    private readonly ILogger<InfrastructureHealthViewModel> _logger;

    public ObservableCollection<SystemInfoDto> Systems { get; } = new();

    public InfrastructureHealthViewModel(
        IAegisApiClient api,
        ILogger<InfrastructureHealthViewModel> logger)
    {
        _api = api;
        _logger = logger;

        _ = LoadSystemsAsync();
    }

    [RelayCommand]
    public async Task LoadSystemsAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;

        try
        {
            var res = await _api.GetSystemsAsync();
            Systems.Clear();
            foreach (var s in res.Systems) Systems.Add(s);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load systems infrastructure");
            ErrorMessage = "Failed to load infrastructure: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }
}
