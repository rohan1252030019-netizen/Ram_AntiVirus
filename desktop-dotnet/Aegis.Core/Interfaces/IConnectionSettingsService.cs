using System.Threading.Tasks;

namespace Aegis.Core.Interfaces;

public record AppConnectionSettings(
    string BackendUrl = "http://localhost:8000",
    bool UseMockData = false,
    bool FirstRunCompleted = false
);

public interface IConnectionSettingsService
{
    AppConnectionSettings CurrentSettings { get; }
    Task<AppConnectionSettings> LoadSettingsAsync();
    Task SaveSettingsAsync(AppConnectionSettings settings);
    Task<(bool Success, string Message)> TestConnectionAsync(string url);
}
