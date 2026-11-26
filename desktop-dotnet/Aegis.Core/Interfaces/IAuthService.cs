using Aegis.Core.Enums;
using Aegis.Core.Models;

namespace Aegis.Core.Interfaces;

public interface IAuthService
{
    UserDto? CurrentUser { get; }
    string? CurrentToken { get; }
    bool IsAuthenticated { get; }
    UserRole CurrentRole { get; }
    bool HasRole(UserRole minimumRole);

    event EventHandler? SessionExpired;
    void NotifySessionExpired();

    Task SaveCredentialsAsync(string token, UserDto user, bool rememberMe);
    Task<(string? Token, UserDto? User)> LoadSavedCredentialsAsync();
    void ClearCredentials();
}
