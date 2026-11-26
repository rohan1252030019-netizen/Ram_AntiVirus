using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.Services;

public class AuthService : IAuthService
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Aegis-Desktop-Entropy-v1.6.5-Secure-Vault");
    private readonly string _vaultFilePath;
    private readonly ILogger<AuthService> _logger;

    public event EventHandler? SessionExpired;

    public UserDto? CurrentUser { get; private set; }
    public string? CurrentToken { get; private set; }
    public bool IsAuthenticated => !string.IsNullOrEmpty(CurrentToken);
    public UserRole CurrentRole => CurrentUser?.Role ?? UserRole.Viewer;

    public AuthService(ILogger<AuthService> logger)
    {
        _logger = logger;
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dir = Path.Combine(appData, "RamAntivirus");
        Directory.CreateDirectory(dir);
        _vaultFilePath = Path.Combine(dir, "session.dat");
    }

    public void NotifySessionExpired()
    {
        ClearCredentials();
        SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    public bool HasRole(UserRole minimumRole)
    {
        if (CurrentUser == null) return false;
        return CurrentUser.Role switch
        {
            UserRole.Admin => true,
            UserRole.Analyst => minimumRole != UserRole.Admin,
            UserRole.Viewer => minimumRole == UserRole.Viewer,
            _ => false
        };
    }

    public async Task SaveCredentialsAsync(string token, UserDto user, bool rememberMe)
    {
        CurrentToken = token;
        CurrentUser = user;

        if (!rememberMe)
        {
            try
            {
                if (File.Exists(_vaultFilePath))
                    File.Delete(_vaultFilePath);
            }
            catch { /* best-effort cleanup */ }
            return;
        }

        try
        {
            var payload = JsonSerializer.Serialize(new StoredSession(token, user), JsonOptions.Default);
            var plaintextBytes = Encoding.UTF8.GetBytes(payload);
            var encryptedBytes = ProtectedData.Protect(plaintextBytes, Entropy, DataProtectionScope.CurrentUser);
            await File.WriteAllBytesAsync(_vaultFilePath, encryptedBytes);
            _logger.LogInformation("Credentials securely encrypted and stored via DPAPI for user {UserId}", user.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist encrypted credentials to DPAPI vault");
        }
    }

    public async Task<(string? Token, UserDto? User)> LoadSavedCredentialsAsync()
    {
        if (!File.Exists(_vaultFilePath))
            return (null, null);

        try
        {
            var encryptedBytes = await File.ReadAllBytesAsync(_vaultFilePath);
            var plaintextBytes = ProtectedData.Unprotect(encryptedBytes, Entropy, DataProtectionScope.CurrentUser);
            var json = Encoding.UTF8.GetString(plaintextBytes);
            var session = JsonSerializer.Deserialize<StoredSession>(json, JsonOptions.Default);

            if (session != null)
            {
                CurrentToken = session.Token;
                CurrentUser = session.User;
                _logger.LogInformation("Restored active session for {UserEmail}", session.User.Email);
                return (session.Token, session.User);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to decrypt saved session. Clearing corrupted vault file.");
            ClearCredentials();
        }

        return (null, null);
    }

    public void ClearCredentials()
    {
        CurrentToken = null;
        CurrentUser = null;
        try
        {
            if (File.Exists(_vaultFilePath))
                File.Delete(_vaultFilePath);
        }
        catch { /* best-effort cleanup */ }
    }

    private record StoredSession(string Token, UserDto User);
}
