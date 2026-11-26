using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.App.ViewModels;

public partial class LoginViewModel : ViewModelBase
{
    private readonly IAegisApiClient _apiClient;
    private readonly IAuthService _authService;
    private readonly INavigationService _navigationService;
    private readonly IConnectionSettingsService? _connectionSettings;
    private readonly ILogger<LoginViewModel> _logger;

    [ObservableProperty]
    private string _serverUrl = "http://localhost:8000";

    [ObservableProperty]
    private bool _useMockData;

    [ObservableProperty]
    private bool _isTestingConnection;

    [ObservableProperty]
    private string? _connectionStatus;

    [ObservableProperty]
    private bool? _isConnectionSuccess;

    [ObservableProperty]
    private string _email = "admin@aegis.local";

    [ObservableProperty]
    private string _password = string.Empty;

    [ObservableProperty]
    private string _apiKey = string.Empty;

    [ObservableProperty]
    private bool _rememberMe = true;

    [ObservableProperty]
    private bool _isApiKeyMode;

    [ObservableProperty]
    private bool _isInsecureUrl;

    partial void OnServerUrlChanged(string value)
    {
        ValidateServerUrlSecurity(value);
    }

    private void ValidateServerUrlSecurity(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            IsInsecureUrl = false;
            return;
        }

        var isLocal = url.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
                      url.Contains("127.0.0.1") ||
                      url.Contains("::1");

        var isHttps = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        IsInsecureUrl = !isLocal && !isHttps;
    }

    public LoginViewModel(
        IAegisApiClient apiClient,
        IAuthService authService,
        INavigationService navigationService,
        ILogger<LoginViewModel> logger,
        IConnectionSettingsService? connectionSettings = null)
    {
        _apiClient = apiClient;
        _authService = authService;
        _navigationService = navigationService;
        _logger = logger;
        _connectionSettings = connectionSettings;

        if (_connectionSettings != null)
        {
            _serverUrl = _connectionSettings.CurrentSettings.BackendUrl;
            _useMockData = _connectionSettings.CurrentSettings.UseMockData;
        }
    }

    [RelayCommand]
    public async Task TestConnectionAsync()
    {
        if (_connectionSettings == null) return;
        IsTestingConnection = true;
        ConnectionStatus = "Connecting...";
        IsConnectionSuccess = null;

        try
        {
            var (success, msg) = await _connectionSettings.TestConnectionAsync(ServerUrl);
            IsConnectionSuccess = success;
            ConnectionStatus = msg;
        }
        catch (Exception ex)
        {
            IsConnectionSuccess = false;
            ConnectionStatus = ex.Message;
        }
        finally
        {
            IsTestingConnection = false;
        }
    }

    [RelayCommand]
    private void ToggleMode()
    {
        IsApiKeyMode = !IsApiKeyMode;
        ErrorMessage = null;
    }

    [RelayCommand]
    public async Task LoginAsync()
    {
        if (IsBusy) return;

        ErrorMessage = null;
        IsBusy = true;

        try
        {
            if (_connectionSettings != null)
            {
                await _connectionSettings.SaveSettingsAsync(new AppConnectionSettings(ServerUrl, UseMockData, true));
            }
            if (IsApiKeyMode)
            {
                if (string.IsNullOrWhiteSpace(ApiKey))
                {
                    ErrorMessage = "Please provide an API key.";
                    return;
                }

                var res = await _apiClient.LoginApiKeyAsync(ApiKey);
                var user = new UserDto(res.ClientId, "api-client@aegis.local", res.ClientName, UserRole.Admin, res.ClientId);
                await _authService.SaveCredentialsAsync(res.Token, user, RememberMe);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(Email) || string.IsNullOrWhiteSpace(Password))
                {
                    ErrorMessage = "Email and password are required.";
                    return;
                }

                var res = await _apiClient.LoginAsync(Email, Password);
                await _authService.SaveCredentialsAsync(res.Token, res.User, RememberMe);
            }

            _logger.LogInformation("Authentication successful for user: {Email}", Email);
            _navigationService.NavigateTo<DashboardOverviewViewModel>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed for {Email}", Email);
            ErrorMessage = "Authentication failed: " + (ex.Message.Contains("401") ? "Invalid email or password" : ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }
}
