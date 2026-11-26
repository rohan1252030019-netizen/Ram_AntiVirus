using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class DeceptionViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private ObservableCollection<CampaignOut> _campaigns = new();

    [ObservableProperty]
    private ObservableCollection<BreadcrumbHitOut> _breadcrumbHits = new();

    [ObservableProperty]
    private ObservableCollection<ThemeOut> _themes = new();

    [ObservableProperty]
    private CampaignOut? _selectedCampaign;

    [ObservableProperty]
    private string _newCampaignName = "Finance-Honeytoken-Q4";

    [ObservableProperty]
    private string _selectedTheme = "financial";

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _statusMessage;

    public DeceptionViewModel(IAegisApiClient apiClient, IDialogService dialogService)
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
            var campTask = _apiClient.GetDeceptionCampaignsAsync();
            var hitsTask = _apiClient.GetBreadcrumbHitsAsync();
            var themesTask = _apiClient.GetDeceptionThemesAsync();

            await Task.WhenAll(campTask, hitsTask, themesTask);

            Campaigns = new ObservableCollection<CampaignOut>(await campTask);
            BreadcrumbHits = new ObservableCollection<BreadcrumbHitOut>(await hitsTask);
            Themes = new ObservableCollection<ThemeOut>(await themesTask);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Deception management not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load deception data");
            ErrorMessage = "Failed to load deception data: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task CreateCampaignAsync()
    {
        if (string.IsNullOrWhiteSpace(NewCampaignName))
        {
            await _dialogService.ShowInfoAsync("Invalid Name", "Please enter a campaign name.");
            return;
        }

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var mix = new ServiceMixIn(2, 1, 1, 1);
            var req = new CampaignCreate(NewCampaignName.Trim(), SelectedTheme, 5, mix, 24);
            var created = await _apiClient.CreateDeceptionCampaignAsync(req);
            StatusMessage = $"Deception campaign '{created.Name}' created.";
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Campaign creation not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to create deception campaign");
            ErrorMessage = "Create failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task RotateCampaignAsync(CampaignOut? item)
    {
        var target = item ?? SelectedCampaign;
        if (target == null)
        {
            await _dialogService.ShowInfoAsync("Select Target", "Please select a campaign to rotate.");
            return;
        }

        var confirmed = await _dialogService.ConfirmAsync(
            "Rotate Deception Campaign",
            $"Rotate all breadcrumbs and lures for '{target.Name}' (ID: {target.Id})?\nPrevious lures will be invalidated.");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var rotated = await _apiClient.RotateDeceptionCampaignAsync(target.Id);
            StatusMessage = $"Campaign '{rotated.Name}' lures rotated.";
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Campaign rotation not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to rotate campaign {Id}", target.Id);
            ErrorMessage = "Rotation failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task DeleteCampaignAsync(CampaignOut? item)
    {
        var target = item ?? SelectedCampaign;
        if (target == null)
        {
            await _dialogService.ShowInfoAsync("Select Target", "Please select a campaign to delete.");
            return;
        }

        var confirmed = await _dialogService.ConfirmAsync(
            "Delete Deception Campaign",
            $"DANGER: Deleting deception campaign '{target.Name}' (ID: {target.Id}) will dismantle all deployed lures.\n\nConfirm deletion?");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            await _apiClient.DeleteDeceptionCampaignAsync(target.Id);
            StatusMessage = $"Campaign '{target.Name}' deleted.";
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Deletion not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to delete campaign {Id}", target.Id);
            ErrorMessage = "Delete failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
