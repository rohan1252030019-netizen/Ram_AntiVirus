using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class IpInvestigationViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private string _targetIp = "185.220.101.42";

    [ObservableProperty]
    private bool _isDeep = true;

    [ObservableProperty]
    private IpIntelDto? _intel;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    public IpInvestigationViewModel(IAegisApiClient apiClient, IDialogService dialogService)
    {
        _apiClient = apiClient;
        _dialogService = dialogService;
    }

    public override async Task InitializeAsync()
    {
        if (!string.IsNullOrWhiteSpace(TargetIp))
        {
            await InvestigateIpAsync();
        }
    }

    [RelayCommand]
    public async Task InvestigateIpAsync()
    {
        if (string.IsNullOrWhiteSpace(TargetIp))
        {
            await _dialogService.ShowInfoAsync("Invalid IP", "Please enter a valid IPv4 or IPv6 address to investigate.");
            return;
        }

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            Intel = await _apiClient.LookupIpIntelAsync(TargetIp.Trim(), IsDeep);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: IP intelligence lookup not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to investigate IP {Ip}", TargetIp);
            ErrorMessage = "IP lookup failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
