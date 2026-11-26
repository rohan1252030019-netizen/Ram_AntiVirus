using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;
using System.Text;

namespace Aegis.App.ViewModels;

public partial class QuantumAnalyticsViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private QuantumReadinessDto? _readiness;

    [ObservableProperty]
    private string _payloadText = "The quick brown fox jumps over the lazy dog";

    [ObservableProperty]
    private EntropyAnalysisResult? _entropyResult;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    public QuantumAnalyticsViewModel(IAegisApiClient apiClient, IDialogService dialogService)
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
            Readiness = await _apiClient.GetQuantumReadinessAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Post-quantum crypto readiness not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load quantum analytics data");
            ErrorMessage = "Failed to load quantum analytics: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task TestEntropyAsync()
    {
        if (string.IsNullOrWhiteSpace(PayloadText))
        {
            await _dialogService.ShowInfoAsync("Invalid Payload", "Please enter payload text or base64 data to test.");
            return;
        }

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            // Convert to base64 if not already
            string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PayloadText));
            EntropyResult = await _apiClient.AnalyzeEntropyAsync(new EntropyRequest(b64));
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Entropy analysis not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to test entropy");
            ErrorMessage = "Entropy test failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
