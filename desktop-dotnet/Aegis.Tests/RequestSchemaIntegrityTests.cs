using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Aegis.Core.Models;
using Xunit;

namespace Aegis.Tests;

public class RequestSchemaIntegrityTests
{
    private static JsonDocument LoadOpenApiDocument()
    {
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "openapi.json");
        if (!File.Exists(fixturePath))
        {
            fixturePath = Path.Combine(Directory.GetCurrentDirectory(), "Fixtures", "openapi.json");
        }
        if (!File.Exists(fixturePath))
        {
            fixturePath = Path.Combine(Directory.GetCurrentDirectory(), "..", "Aegis.Tests", "Fixtures", "openapi.json");
        }
        Assert.True(File.Exists(fixturePath), $"openapi.json not found at {fixturePath}");

        var json = File.ReadAllText(fixturePath);
        return JsonDocument.Parse(json);
    }

    [Theory]
    [InlineData(typeof(UserLoginRequest), "UserLoginRequest")]
    [InlineData(typeof(ClientLoginRequest), "LoginRequest")]
    [InlineData(typeof(RejectActionRequest), "RejectActionRequest")]
    [InlineData(typeof(RestoreRequest), "RestoreRequest")]
    [InlineData(typeof(ClientSettingsUpdate), "ClientSettingsUpdate")]
    [InlineData(typeof(NotificationUpdate), "NotificationUpdate")]
    [InlineData(typeof(NotificationTestRequest), "NotificationTestRequest")]
    [InlineData(typeof(KillProcessRequest), "KillProcessRequest")]
    [InlineData(typeof(QuarantineFileRequest), "QuarantineFileRequest")]
    [InlineData(typeof(IsolateHostRequest), "IsolateHostRequest")]
    [InlineData(typeof(UnisolateHostRequest), "UnisolateHostRequest")]
    [InlineData(typeof(DetectionIn), "DetectionIn")]
    [InlineData(typeof(ScanRequest), "app__api__surface__ScanRequest")]
    [InlineData(typeof(VulnUpdate), "VulnUpdate")]
    [InlineData(typeof(HoneypotCreate), "HoneypotCreate")]
    [InlineData(typeof(CampaignCreate), "CampaignCreate")]
    [InlineData(typeof(IOCCreate), "IOCCreate")]
    [InlineData(typeof(EnrollRequest), "EnrollRequest")]
    [InlineData(typeof(EntropyRequest), "EntropyRequest")]
    public void RequestDtoProperties_MatchOpenApiSchemaProperties(Type requestDtoType, string schemaName)
    {
        using var doc = LoadOpenApiDocument();
        var schemas = doc.RootElement.GetProperty("components").GetProperty("schemas");

        Assert.True(schemas.TryGetProperty(schemaName, out var schemaElement),
            $"Schema '{schemaName}' not found in openapi.json components.schemas");

        var schemaProps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (schemaElement.TryGetProperty("properties", out var propsElement))
        {
            foreach (var prop in propsElement.EnumerateObject())
            {
                schemaProps.Add(prop.Name);
            }
        }

        var requiredProps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (schemaElement.TryGetProperty("required", out var requiredElement))
        {
            foreach (var req in requiredElement.EnumerateArray())
            {
                requiredProps.Add(req.GetString()!);
            }
        }

        // Inspect Request DTO properties that serialize to JSON
        var dtoPropsMap = requestDtoType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.GetCustomAttribute<JsonIgnoreAttribute>() == null)
            .ToDictionary(
                p => {
                    var attr = p.GetCustomAttribute<JsonPropertyNameAttribute>();
                    return attr != null ? attr.Name : ToSnakeCase(p.Name);
                },
                p => p,
                StringComparer.OrdinalIgnoreCase);

        // 1. Ensure every serialized DTO property exists in schema properties
        var extraInDto = dtoPropsMap.Keys.Where(p => !schemaProps.Contains(p)).ToList();
        Assert.Empty(extraInDto);

        // 2. Ensure every required schema property is present on the C# DTO
        var missingRequiredInDto = requiredProps.Where(req => !dtoPropsMap.ContainsKey(req)).ToList();
        Assert.Empty(missingRequiredInDto);
    }

    [Fact]
    public void DestructiveRequests_ContainConfirmFlag()
    {
        // Guard check: Destructive EDR actions must define 'confirm'
        var destructiveTypes = new[]
        {
            typeof(KillProcessRequest),
            typeof(QuarantineFileRequest),
            typeof(IsolateHostRequest)
        };

        foreach (var type in destructiveTypes)
        {
            var prop = type.GetProperty("Confirm", BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            Assert.NotNull(prop);
            Assert.Equal(typeof(bool), prop.PropertyType);
        }
    }

    private static string ToSnakeCase(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        var startUnderscores = Regex.Match(input, @"^_+");
        return startUnderscores + Regex.Replace(input, @"([a-z0-9])([A-Z])", "$1_$2").ToLowerInvariant();
    }
}
