using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class PhantomViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private ObservableCollection<HoneypotOut> _honeypots = new();

    [ObservableProperty]
    private ObservableCollection<InteractionOut> _interactions = new();

    [ObservableProperty]
    private ObservableCollection<AttackerOut> _attackers = new();

    [ObservableProperty]
    private HoneypotOut? _selectedHoneypot;

    [ObservableProperty]
    private string _newHoneypotName = "decoy-ssh-01";

    [ObservableProperty]
    private string _newHoneypotService = "ssh";

    [ObservableProperty]
    private int _newHoneypotPort = 2222;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _statusMessage;

    public PhantomViewModel(IAegisApiClient apiClient, IDialogService dialogService)
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
            var hTask = _apiClient.GetHoneypotsAsync();
            var iTask = _apiClient.GetHoneypotInteractionsAsync();
            var aTask = _apiClient.GetAttackersAsync();

            await Task.WhenAll(hTask, iTask, aTask);

            Honeypots = new ObservableCollection<HoneypotOut>(await hTask);
            Interactions = new ObservableCollection<InteractionOut>(await iTask);
            Attackers = new ObservableCollection<AttackerOut>(await aTask);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Honeypot management not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load honeypot data");
            ErrorMessage = "Failed to load honeypot data: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task CreateHoneypotAsync()
    {
        if (string.IsNullOrWhiteSpace(NewHoneypotName))
        {
            await _dialogService.ShowInfoAsync("Invalid Name", "Please enter a valid honeypot name.");
            return;
        }

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var cfg = new Dictionary<string, object> { ["port"] = NewHoneypotPort };
            var created = await _apiClient.CreateHoneypotAsync(new HoneypotCreate(NewHoneypotName.Trim(), NewHoneypotService, cfg));
            StatusMessage = $"Honeypot '{created.Name}' created successfully.";
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Honeypot creation not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to create honeypot");
            ErrorMessage = "Create failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task RotateHoneypotAsync(HoneypotOut? item)
    {
        var target = item ?? SelectedHoneypot;
        if (target == null)
        {
            await _dialogService.ShowInfoAsync("Select Target", "Please select a honeypot to rotate.");
            return;
        }

        var confirmed = await _dialogService.ConfirmAsync(
            "Rotate Honeypot Decoy",
            $"Rotate honeypot '{target.Name}' (ID: {target.Id})?\nThis generates fresh credentials and resets telemetry.");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var rotated = await _apiClient.RotateHoneypotAsync(target.Id);
            StatusMessage = $"Honeypot '{rotated.Name}' rotated successfully.";
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Rotation not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to rotate honeypot {Id}", target.Id);
            ErrorMessage = "Rotation failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task DeleteHoneypotAsync(HoneypotOut? item)
    {
        var target = item ?? SelectedHoneypot;
        if (target == null)
        {
            await _dialogService.ShowInfoAsync("Select Target", "Please select a honeypot to delete.");
            return;
        }

        var confirmed = await _dialogService.ConfirmAsync(
            "Delete Honeypot Decoy",
            $"DANGER: Deleting honeypot '{target.Name}' (ID: {target.Id}) will permanently tear down the decoy service.\n\nConfirm deletion?");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            await _apiClient.DeleteHoneypotAsync(target.Id);
            StatusMessage = $"Honeypot '{target.Name}' deleted.";
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Deletion not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to delete honeypot {Id}", target.Id);
            ErrorMessage = "Delete failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
