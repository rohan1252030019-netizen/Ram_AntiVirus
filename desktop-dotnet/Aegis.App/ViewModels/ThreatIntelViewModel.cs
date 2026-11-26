using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class ThreatIntelViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private ObservableCollection<IOCOut> _iocs = new();

    [ObservableProperty]
    private ObservableCollection<TtpCampaignOut> _campaigns = new();

    [ObservableProperty]
    private string _newIocType = "ip";

    [ObservableProperty]
    private string _newIocValue = string.Empty;

    [ObservableProperty]
    private string _newIocSeverity = "high";

    [ObservableProperty]
    private string _newIocThreatType = "c2_server";

    [ObservableProperty]
    private string _newIocDescription = string.Empty;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _statusMessage;

    public ThreatIntelViewModel(IAegisApiClient apiClient, IDialogService dialogService)
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
            var iocTask = _apiClient.GetThreatIntelAsync();
            var campTask = _apiClient.GetTtpCampaignsAsync();

            await Task.WhenAll(iocTask, campTask);

            Iocs = new ObservableCollection<IOCOut>(await iocTask);
            Campaigns = new ObservableCollection<TtpCampaignOut>(await campTask);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Threat intelligence feeds not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load threat intel data");
            ErrorMessage = "Failed to load threat intel: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task AddIocAsync()
    {
        if (string.IsNullOrWhiteSpace(NewIocValue))
        {
            await _dialogService.ShowInfoAsync("Invalid IOC", "Please enter an IOC value (IP, domain, hash, or URL).");
            return;
        }

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var created = await _apiClient.CreateIOCAsync(new IOCCreate(
                NewIocType,
                NewIocValue.Trim(),
                NewIocThreatType,
                90.0,
                "analyst_console",
                new List<string> { "operator_ingest" }));

            StatusMessage = $"IOC '{created.IocValue}' added successfully.";
            NewIocValue = string.Empty;
            NewIocDescription = string.Empty;
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Creating IOCs not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to add IOC");
            ErrorMessage = "Add IOC failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
