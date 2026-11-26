using System.Collections.ObjectModel;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Serilog;

namespace Aegis.App.ViewModels;

public partial class NodeManagementViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IDialogService _dialogService;

    [ObservableProperty]
    private ObservableCollection<NodeOut> _nodes = new();

    [ObservableProperty]
    private NodeOut? _selectedNode;

    [ObservableProperty]
    private string _enrollCode = string.Empty;

    [ObservableProperty]
    private string _enrollNodeType = "workspace";

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _statusMessage;

    public NodeManagementViewModel(IAegisApiClient apiClient, IDialogService dialogService)
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
            var nodesList = await _apiClient.GetNodesAsync();
            Nodes = new ObservableCollection<NodeOut>(nodesList);
            if (Nodes.Count > 0)
            {
                SelectedNode = Nodes[0];
            }
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Node cluster management not permitted for your role.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load node cluster data");
            ErrorMessage = "Failed to load nodes: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task EnrollNodeAsync()
    {
        if (string.IsNullOrWhiteSpace(EnrollCode))
        {
            await _dialogService.ShowInfoAsync("Invalid Code", "Please enter an enrollment token / invitation code.");
            return;
        }

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            var res = await _apiClient.EnrollNodeAsync(new EnrollRequest(EnrollCode.Trim(), EnrollNodeType));
            StatusMessage = $"Node enrolled successfully: {res.Hostname} ({res.NodeId})";
            await _dialogService.ShowInfoAsync("Enrollment Succeeded", StatusMessage);
            EnrollCode = string.Empty;
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Node enrollment not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to enroll node");
            ErrorMessage = "Node enrollment failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task DeleteNodeAsync(NodeOut? node)
    {
        var target = node ?? SelectedNode;
        if (target == null)
        {
            await _dialogService.ShowInfoAsync("Select Target", "Please select an endpoint node to remove.");
            return;
        }

        var confirmed = await _dialogService.ConfirmAsync(
            "Remove Endpoint Node",
            $"DANGER: Are you sure you want to unregister and disconnect endpoint node '{target.Hostname}' (ID: {target.Id})?\nThis node will lose telemetry connectivity.\n\nProceed?");

        if (!confirmed) return;

        IsLoading = true;
        ErrorMessage = null;
        try
        {
            await _apiClient.DeleteNodeAsync(target.Id);
            StatusMessage = $"Node '{target.Hostname}' removed.";
            await LoadDataAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ErrorMessage = "Access Denied: Node deletion not permitted.";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to delete node {Id}", target.Id);
            ErrorMessage = "Node removal failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }
}
