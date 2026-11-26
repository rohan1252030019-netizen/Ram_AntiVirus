using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.App.ViewModels;

public partial class SettingsViewModel : ViewModelBase
{
    private readonly IAegisApiClient _api;
    private readonly IDialogService _dialog;
    private readonly ILogger<SettingsViewModel> _logger;

    [ObservableProperty]
    private string _clientName = string.Empty;

    [ObservableProperty]
    private string _safeIpsText = string.Empty;

    [ObservableProperty]
    private string _telegramToken = string.Empty;

    [ObservableProperty]
    private string _telegramChatId = string.Empty;

    [ObservableProperty]
    private string _webhookUrl = string.Empty;

    [ObservableProperty]
    private bool _notificationsEnabled;

    [ObservableProperty]
    private bool _criticalOnly = true;

    private ClientSettingsDto? _originalSettings;
    private NotificationConfigDto? _originalNotifications;

    public SettingsViewModel(
        IAegisApiClient api,
        IDialogService dialog,
        ILogger<SettingsViewModel> logger)
    {
        _api = api;
        _dialog = dialog;
        _logger = logger;

        _ = LoadSettingsAsync();
    }

    [RelayCommand]
    public async Task LoadSettingsAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;

        try
        {
            _originalSettings = await _api.GetClientSettingsAsync();
            ClientName = _originalSettings.Name;
            SafeIpsText = string.Join(", ", _originalSettings.SafeIps);

            _originalNotifications = await _api.GetNotificationConfigAsync();
            TelegramToken = _originalNotifications.TelegramBotToken ?? string.Empty;
            TelegramChatId = _originalNotifications.TelegramChatId ?? string.Empty;
            WebhookUrl = _originalNotifications.WebhookUrl ?? string.Empty;
            NotificationsEnabled = _originalNotifications.Enabled;
            CriticalOnly = _originalNotifications.NotifyCriticalOnly;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load system settings");
            ErrorMessage = "Failed to load settings: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task SaveSettingsAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            var ips = SafeIpsText.Split(new[] { ',', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                                 .Select(s => s.Trim()).ToList();

            if (_originalSettings != null)
            {
                var updatedClient = _originalSettings with { Name = ClientName, SafeIps = ips };
                await _api.UpdateClientSettingsAsync(updatedClient);
            }

            var updatedNotif = new NotificationConfigDto(
                telegramBotToken: TelegramToken,
                telegramChatId: TelegramChatId,
                webhookUrl: WebhookUrl,
                notifyCriticalOnly: CriticalOnly,
                enabled: NotificationsEnabled
            );
            await _api.UpdateNotificationConfigAsync(updatedNotif);

            await _dialog.ShowMessageAsync("Settings Saved", "System security parameters successfully updated.");
        }
        catch (Exception ex)
        {
            await _dialog.ShowErrorAsync("Save Failed", ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task TestAlertAsync(string channel)
    {
        try
        {
            var res = await _api.TestNotificationAsync(channel);
            await _dialog.ShowMessageAsync("Test Alert", res.Message);
        }
        catch (Exception ex)
        {
            await _dialog.ShowErrorAsync("Test Failed", ex.Message);
        }
    }
}
