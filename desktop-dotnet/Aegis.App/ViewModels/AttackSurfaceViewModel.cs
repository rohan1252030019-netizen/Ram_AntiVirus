using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class AttackSurfaceViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private ObservableCollection<AssetOut> _assets = new();

    [ObservableProperty]
    private ObservableCollection<VulnOut> _vulnerabilities = new();

    [ObservableProperty]
    private ObservableCollection<HardenChecklistItem> _recommendations = new();

    [ObservableProperty]
    private string _scanTarget = "192.168.1.0/24";

    [ObservableProperty]
    private string _scanType = "quick";

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _statusMessage;

    public AttackSurfaceViewModel(IAegisApiClient apiClient, IDialogService dialogService)
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
            var assetsTask = _apiClient.GetSurfaceAssetsAsync();
            var vulnsTask = _apiClient.GetSurfaceVulnerabilitiesAsync();
            var recsTask = _apiClient.GetHardenRecommendationsAsync();

            await Task.WhenAll(assetsTask, vulnsTask, recsTask);

            Assets = new ObservableCollection<AssetOut>(await assetsTask);
            Vulnerabilities = new ObservableCollection<VulnOut>(await vulnsTask);
            var recs = await recsTask;
            Recommendations = new ObservableCollection<HardenChecklistItem>(recs.Checklist);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Surface monitoring not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load attack surface data");
            ErrorMessage = "Failed to load surface data: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task TriggerScanAsync()
    {
        if (string.IsNullOrWhiteSpace(ScanTarget))
        {
            await _dialogService.ShowInfoAsync("Scan Error", "Please provide a valid target IP or CIDR range.");
            return;
        }

        var confirmed = await _dialogService.ConfirmAsync(
            "Trigger Attack Surface Scan",
            $"Initiate an active network scan against target:\nTarget: {ScanTarget}\nScan Type: {ScanType}\n\nProceed?");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var res = await _apiClient.StartSurfaceScanAsync(new ScanRequest(ScanTarget.Trim(), ScanType));
            StatusMessage = $"Scan started! Scan ID: {res.ScanId}, Status: {res.Status}";
            await _dialogService.ShowInfoAsync("Scan Dispatched", StatusMessage);
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Scan initiation not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to start surface scan");
            ErrorMessage = "Scan dispatch failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
