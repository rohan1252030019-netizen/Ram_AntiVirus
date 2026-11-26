using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class DosShieldViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private DosStatusDto? _status;

    [ObservableProperty]
    private DosConfigDto? _config;

    [ObservableProperty]
    private ObservableCollection<DosOffenderDto> _offenders = new();

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    public DosShieldViewModel(IAegisApiClient apiClient, IDialogService dialogService)
    {
        _apiClient = apiClient;
        _dialogService = dialogService;
    }

    public override async Task InitializeAsync()
    {
        await LoadDataAsync();
    }

    [RelayCommand]
    public async Task LoadDataAsync()
    {
        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var statusTask = _apiClient.GetDosStatusAsync();
            var offTask = _apiClient.GetDosOffendersAsync();
            var cfgTask = _apiClient.GetDosConfigAsync();

            await Task.WhenAll(statusTask, offTask, cfgTask);

            Status = await statusTask;
            Offenders = new ObservableCollection<DosOffenderDto>(await offTask);
            Config = await cfgTask;
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: DoS Shield status not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load DoS shield data");
            ErrorMessage = "Failed to load DoS Shield: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
