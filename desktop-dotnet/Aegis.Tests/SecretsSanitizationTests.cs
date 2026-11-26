using System;
using System.IO;
using System.Text.RegularExpressions;
using Xunit;

namespace Aegis.Tests;

public class SecretsSanitizationTests
{
    private static readonly Regex RealJwtPattern = new(
        @"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        RegexOptions.Compiled);

    private static readonly Regex LiveApiKeyPattern = new(
        @"\b(?:c6_|aegis_live_|sk_live_)[A-Za-z0-9_\-]{20,}\b",
        RegexOptions.Compiled);

    private static readonly Regex TelegramTokenPattern = new(
        @"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b",
        RegexOptions.Compiled);

    private static readonly Regex SlackWebhookPattern = new(
        @"https://hooks\.slack\.com/services/(?!PLACEHOLDER)[A-Za-z0-9/_\-]+",
        RegexOptions.Compiled);

    [Fact]
    public void AllFixtures_ContainNoLiveSecretsOrTokens()
    {
        var fixtureDir = Path.Combine(AppContext.BaseDirectory, "Fixtures");
        if (!Directory.Exists(fixtureDir))
        {
            fixtureDir = Path.Combine(Directory.GetCurrentDirectory(), "Fixtures");
        }
        if (!Directory.Exists(fixtureDir))
        {
            fixtureDir = Path.Combine(Directory.GetCurrentDirectory(), "..", "Aegis.Tests", "Fixtures");
        }
        Assert.True(Directory.Exists(fixtureDir), $"Fixtures directory not found at {fixtureDir}");

        var jsonFiles = Directory.GetFiles(fixtureDir, "*.json", SearchOption.AllDirectories);
        Assert.NotEmpty(jsonFiles);

        foreach (var file in jsonFiles)
        {
            var fileName = Path.GetFileName(file);
            // Skip the OpenAPI schema file and audit reports which contain property metadata definitions
            if (fileName.Equals("openapi.json", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains("audit", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var text = File.ReadAllText(file);

            Assert.False(RealJwtPattern.IsMatch(text),
                $"Fixture '{fileName}' contains a live JWT token pattern! Must use PLACEHOLDER.");

            Assert.False(LiveApiKeyPattern.IsMatch(text),
                $"Fixture '{fileName}' contains a live API key pattern! Must use PLACEHOLDER.");

            Assert.False(TelegramTokenPattern.IsMatch(text),
                $"Fixture '{fileName}' contains a live Telegram bot token! Must use PLACEHOLDER.");

            Assert.False(SlackWebhookPattern.IsMatch(text),
                $"Fixture '{fileName}' contains a live Slack webhook URL! Must use PLACEHOLDER.");
        }
    }
}
