using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class ComplianceMatrixViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private ComplianceOverview? _overview;

    [ObservableProperty]
    private ObservableCollection<FrameworkOut> _frameworks = new();

    [ObservableProperty]
    private FrameworkOut? _selectedFramework;

    [ObservableProperty]
    private ObservableCollection<ControlOut> _controls = new();

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    public ComplianceMatrixViewModel(IAegisApiClient apiClient, IDialogService dialogService)
    {
        _apiClient = apiClient;
        _dialogService = dialogService;
    }

    public override async Task InitializeAsync()
    {
        await LoadDataAsync();
    }

    partial void OnSelectedFrameworkChanged(FrameworkOut? value)
    {
        if (value?.Controls != null)
        {
            Controls = new ObservableCollection<ControlOut>(value.Controls);
        }
        else
        {
            Controls.Clear();
        }
    }

    [RelayCommand]
    public async Task LoadDataAsync()
    {
        IsLoading = true;
        ErrorMessage = null;
        try
        {
            Overview = await _apiClient.GetComplianceFrameworksAsync();
            Frameworks = new ObservableCollection<FrameworkOut>(Overview.Frameworks);
            if (Frameworks.Count > 0)
            {
                SelectedFramework = Frameworks[0];
            }
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Compliance matrix not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load compliance data");
            ErrorMessage = "Failed to load compliance matrix: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
