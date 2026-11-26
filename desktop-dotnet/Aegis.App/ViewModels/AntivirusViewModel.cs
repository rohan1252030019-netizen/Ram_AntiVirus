using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class AntivirusViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private SignatureBundleDto? _signatures;

    [ObservableProperty]
    private ObservableCollection<QuarantineItemDto> _quarantineItems = new();

    [ObservableProperty]
    private QuarantineItemDto? _selectedQuarantineItem;

    [ObservableProperty]
    private string _hashToLookup = string.Empty;

    [ObservableProperty]
    private HashLookupDto? _hashResult;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _statusMessage;

    public AntivirusViewModel(IAegisApiClient apiClient, IDialogService dialogService)
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
            var sigTask = _apiClient.GetSignaturesAsync();
            var qTask = _apiClient.GetQuarantineListAsync();

            await Task.WhenAll(sigTask, qTask);

            Signatures = await sigTask;
            QuarantineItems = new ObservableCollection<QuarantineItemDto>(await qTask);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: You do not have permission to view Antivirus Quarantine.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load antivirus data");
            ErrorMessage = "Failed to load antivirus data: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task UpdateSignaturesAsync()
    {
        var confirmed = await _dialogService.ConfirmAsync(
            "Update Signatures",
            "Are you sure you want to trigger a signature database update from the threat feed?\nThis will refresh detection definitions.");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            Signatures = await _apiClient.UpdateSignaturesAsync();
            var count = Signatures.BadHashCount ?? Signatures.BadHashes?.Count ?? 0;
            StatusMessage = $"Signatures successfully updated to version {Signatures.Version} ({count} hashes).";
            await _dialogService.ShowInfoAsync("Success", StatusMessage);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: You do not have permission to update signatures.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to update antivirus signatures");
            ErrorMessage = "Signature update failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task ReleaseQuarantineAsync(QuarantineItemDto? item)
    {
        var target = item ?? SelectedQuarantineItem;
        if (target == null)
        {
            await _dialogService.ShowInfoAsync("Select Item", "Please select a quarantined item to release.");
            return;
        }

        var confirmed = await _dialogService.ConfirmAsync(
            "Release Quarantined File",
            $"WARNING: Releasing a quarantined file can restore malicious files to the filesystem!\n\nTarget Item ID: {target.Id}\nFile: {target.Path}\nRule: {target.Rule ?? target.Engine}\n\nDo you want to proceed?");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var res = await _apiClient.ReleaseQuarantineAsync(target.Id);
            StatusMessage = $"File released: {res.DetectionId}";
            await _dialogService.ShowInfoAsync("Released", StatusMessage);
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: You do not have permission to release quarantined items.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to release quarantine item {Id}", target.Id);
            ErrorMessage = "Quarantine release failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task LookupHashAsync()
    {
        if (string.IsNullOrWhiteSpace(HashToLookup))
        {
            await _dialogService.ShowInfoAsync("Hash Lookup", "Please enter a valid SHA256 or MD5 hash.");
            return;
        }

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            HashResult = await _apiClient.LookupHashAsync(HashToLookup.Trim());
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Hash lookup not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to lookup hash {Hash}", HashToLookup);
            ErrorMessage = "Hash lookup failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
