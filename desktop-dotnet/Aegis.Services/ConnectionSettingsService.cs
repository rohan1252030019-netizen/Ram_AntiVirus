using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Aegis.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace Aegis.Services;

public class ConnectionSettingsService : IConnectionSettingsService
{
    private readonly HttpClient _http;
    private readonly ILogger<ConnectionSettingsService> _logger;
    private readonly string _settingsFilePath;
    private AppConnectionSettings _currentSettings;

    public AppConnectionSettings CurrentSettings => _currentSettings;

    public ConnectionSettingsService(HttpClient http, ILogger<ConnectionSettingsService> logger)
    {
        _http = http;
        _logger = logger;
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RamAntivirus");
        Directory.CreateDirectory(dir);
        _settingsFilePath = Path.Combine(dir, "settings.json");
        _currentSettings = new AppConnectionSettings();
    }

    public async Task<AppConnectionSettings> LoadSettingsAsync()
    {
        try
        {
            if (File.Exists(_settingsFilePath))
            {
                var json = await File.ReadAllTextAsync(_settingsFilePath);
                var loaded = JsonSerializer.Deserialize<AppConnectionSettings>(json, JsonOptions.Default);
                if (loaded != null)
                {
                    _currentSettings = loaded;
                    return _currentSettings;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load connection settings from {Path}. Using defaults.", _settingsFilePath);
        }

        return _currentSettings;
    }

    public async Task SaveSettingsAsync(AppConnectionSettings settings)
    {
        _currentSettings = settings;
        try
        {
            var json = JsonSerializer.Serialize(settings, JsonOptions.Default);
            await File.WriteAllTextAsync(_settingsFilePath, json);
            _logger.LogInformation("Connection settings persisted to {Path}", _settingsFilePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist connection settings to {Path}", _settingsFilePath);
            throw;
        }
    }

    public async Task<(bool Success, string Message)> TestConnectionAsync(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return (false, "URL cannot be empty");

        try
        {
            var uri = new Uri(url);
            using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(5));
            var resp = await _http.GetAsync(uri, cts.Token);
            if (resp.IsSuccessStatusCode)
            {
                return (true, $"Connected successfully (HTTP {(int)resp.StatusCode})");
            }
            return (false, $"Server returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}");
        }
        catch (Exception ex)
        {
            return (false, $"Connection failed: {ex.Message}");
        }
    }
}
