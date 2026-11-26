using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Aegis.Core.Models;
using Xunit;

namespace Aegis.Tests;

public class SchemaIntegrityTests
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
    [InlineData(typeof(UserLoginResponse), "UserLoginResponse")]
    [InlineData(typeof(UserDto), "UserOut")]
    [InlineData(typeof(ClientLoginResponse), "LoginResponse")]
    [InlineData(typeof(DashboardOverviewDto), "OverviewStats")]
    [InlineData(typeof(TimelineEventDto), "TimelineEvent")]
    [InlineData(typeof(IncidentDto), "IncidentOut")]
    [InlineData(typeof(ResponseActionDto), "ActionOut")]
    [InlineData(typeof(RansomwareStatsDto), "RansomwareStatsOut")]
    [InlineData(typeof(RaaSGroupDto), "RaaSGroupOut")]
    [InlineData(typeof(RecoveryOptionsDto), "RecoveryOptionsOut")]
    [InlineData(typeof(SnapshotDto), "SnapshotOut")]
    [InlineData(typeof(DecryptorDto), "DecryptorOut")]
    [InlineData(typeof(FirewallRuleDto), "FirewallRuleOut")]
    [InlineData(typeof(BlockedIpsResponse), "BlockedIPsResponse")]
    [InlineData(typeof(ClientSettingsDto), "ClientSettings")]
    [InlineData(typeof(NotificationConfigDto), "NotificationConfig")]
    [InlineData(typeof(EdrEventsOut), "EdrEventsOut")]
    [InlineData(typeof(DetectionOut), "DetectionOut")]
    [InlineData(typeof(ScanResponse), "ScanResponse")]
    [InlineData(typeof(ScanDetail), "ScanDetail")]
    [InlineData(typeof(AssetOut), "AssetOut")]
    [InlineData(typeof(VulnOut), "VulnOut")]
    [InlineData(typeof(HardenResponse), "HardenResponse")]
    [InlineData(typeof(HoneypotOut), "HoneypotOut")]
    [InlineData(typeof(InteractionOut), "InteractionOut")]
    [InlineData(typeof(AttackerOut), "AttackerOut")]
    [InlineData(typeof(CampaignOut), "CampaignOut")]
    [InlineData(typeof(BreadcrumbHitOut), "BreadcrumbHitOut")]
    [InlineData(typeof(ThemeOut), "ThemeOut")]
    [InlineData(typeof(IOCOut), "IOCOut")]
    [InlineData(typeof(ThreatEventOut), "ThreatEventOut")]
    [InlineData(typeof(NodeOut), "NodeOut")]
    [InlineData(typeof(EnrollResponse), "EnrollResponse")]
    [InlineData(typeof(ComplianceOverview), "ComplianceOverview")]
    [InlineData(typeof(FrameworkOut), "FrameworkOut")]
    [InlineData(typeof(ControlOut), "ControlOut")]
    public void DtoProperties_MatchOpenApiSchemaProperties(Type dtoType, string schemaName)
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

        // Inspect DTO properties that serialize to JSON
        var dtoProps = dtoType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.GetCustomAttribute<JsonIgnoreAttribute>() == null)
            .Select(p =>
            {
                var attr = p.GetCustomAttribute<JsonPropertyNameAttribute>();
                return attr != null ? attr.Name : ToSnakeCase(p.Name);
            })
            .Distinct()
            .ToList();

        // Ensure every core serialized DTO property exists in schemaProps
        var missingInSchema = dtoProps.Where(p => !schemaProps.Contains(p)).ToList();

        Assert.Empty(missingInSchema);
    }

    private static string ToSnakeCase(string str)
    {
        return string.Concat(str.Select((x, i) => i > 0 && char.IsUpper(x) ? "_" + x.ToString() : x.ToString())).ToLower();
    }
}
