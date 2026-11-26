using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.App.ViewModels;

public partial class FirewallRulesViewModel : ViewModelBase
{
    private readonly IAegisApiClient _api;
    private readonly IDialogService _dialog;
    private readonly ILogger<FirewallRulesViewModel> _logger;

    public ObservableCollection<FirewallRuleDto> Rules { get; } = new();
    public ObservableCollection<BlockedIpDto> BlockedIps { get; } = new();

    public FirewallRulesViewModel(
        IAegisApiClient api,
        IDialogService dialog,
        ILogger<FirewallRulesViewModel> logger)
    {
        _api = api;
        _dialog = dialog;
        _logger = logger;

        _ = LoadFirewallDataAsync();
    }

    [RelayCommand]
    public async Task LoadFirewallDataAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;

        try
        {
            var rules = await _api.GetFirewallRulesAsync();
            Rules.Clear();
            foreach (var r in rules) Rules.Add(r);

            var blocked = await _api.GetBlockedIpsAsync();
            BlockedIps.Clear();
            foreach (var b in blocked.BlockedIps) BlockedIps.Add(b);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load firewall data");
            ErrorMessage = "Failed to load firewall: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task UnblockIpAsync(BlockedIpDto? blockedIp)
    {
        if (blockedIp == null) return;

        var confirmed = await _dialog.ShowConfirmationAsync(
            "Unblock IP Address",
            $"Are you sure you want to lift the firewall block on IP '{blockedIp.Ip}'?",
            "Unblock IP", "Cancel");

        if (!confirmed) return;

        try
        {
            await _api.UnblockIpAsync(blockedIp.Ip);
            BlockedIps.Remove(blockedIp);
            await _dialog.ShowMessageAsync("IP Unblocked", $"Traffic from {blockedIp.Ip} is now allowed.");
        }
        catch (Exception ex)
        {
            await _dialog.ShowErrorAsync("Unblock Failed", ex.Message);
        }
    }
}
