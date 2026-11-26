using System.IO;
using System.Text.Json;
using Aegis.Core.Enums;
using Aegis.Core.Models;
using Aegis.Services;
using Xunit;

namespace Aegis.Tests;

public class ContractDeserializationTests
{
    private static string LoadFixture(string filename)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", filename);
        if (!File.Exists(path))
        {
            path = Path.Combine(Directory.GetCurrentDirectory(), "Fixtures", filename);
        }
        return File.ReadAllText(path);
    }

    [Fact]
    public void UserLoginResponse_DeserializesCorrectly()
    {
        var json = LoadFixture("auth_user_login.json");
        var res = JsonSerializer.Deserialize<UserLoginResponse>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.False(string.IsNullOrWhiteSpace(res.Token));
        Assert.Equal("admin@aegis.local", res.User.Email);
        Assert.Equal(UserRole.Admin, res.User.Role);
    }

    [Fact]
    public void IncidentDto_DeserializesCorrectly()
    {
        var json = LoadFixture("incident_detail.json");
        var res = JsonSerializer.Deserialize<IncidentDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal("inc_001", res.Id);
        Assert.Equal(Severity.Critical, res.Severity);
        Assert.Equal(IncidentStatus.Open, res.Status);
        Assert.Equal("185.220.101.42", res.SourceIp);
        Assert.NotNull(res.Actions);
        Assert.Single(res.Actions);
        Assert.Equal(ActionType.BlockIp, res.Actions[0].ActionType);
    }

    [Fact]
    public void EdrEventsOut_DeserializesCorrectly()
    {
        var json = LoadFixture("edr_events_out.json");
        var res = JsonSerializer.Deserialize<EdrEventsOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal(15, res.Accepted);
        Assert.Equal(0, res.Dropped);
        Assert.Equal(1, res.ChainMatches);
    }

    [Fact]
    public void DetectionOut_DeserializesCorrectly()
    {
        var json = LoadFixture("av_detection_out.json");
        var res = JsonSerializer.Deserialize<DetectionOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal("det_01", res.Id);
        Assert.Equal("inc_001", res.IncidentId);
        Assert.True(res.Quarantined);
        Assert.Equal("yara", res.Engine);
    }

    [Fact]
    public void SignatureBundleDto_DeserializesCorrectly()
    {
        var json = LoadFixture("av_signatures.json");
        var res = JsonSerializer.Deserialize<SignatureBundleDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Version);
        Assert.NotNull(res.BadHashes);
        Assert.True(res.BadHashes.Count > 0);
    }

    [Fact]
    public void AssetOut_DeserializesCorrectly()
    {
        var json = LoadFixture("surface_asset_out.json");
        var res = JsonSerializer.Deserialize<AssetOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal("ast_01", res.Id);
        Assert.Equal("srv-app-01", res.Hostname);
        Assert.Equal(45.2, res.RiskScore);
        Assert.Equal(3, res.VulnerabilityCount);
    }

    [Fact]
    public void VulnOut_DeserializesCorrectly()
    {
        var json = LoadFixture("surface_vuln_out.json");
        var res = JsonSerializer.Deserialize<VulnOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
        Assert.NotEmpty(res.Title);
    }

    [Fact]
    public void HardenResponse_DeserializesCorrectly()
    {
        var json = LoadFixture("surface_harden.json");
        var res = JsonSerializer.Deserialize<HardenResponse>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotNull(res.Checklist);
        Assert.NotEmpty(res.Checklist);
    }

    [Fact]
    public void HoneypotOut_DeserializesCorrectly()
    {
        var json = LoadFixture("phantom_honeypot_out.json");
        var res = JsonSerializer.Deserialize<HoneypotOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal("hp_01", res.Id);
        Assert.Equal("ssh-trap", res.Name);
        Assert.Equal(42, res.InteractionsCount);
    }

    [Fact]
    public void AttackerOut_DeserializesCorrectly()
    {
        var json = LoadFixture("phantom_attacker_out.json");
        var res = JsonSerializer.Deserialize<AttackerOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
        Assert.True(res.TotalInteractions > 0);
    }

    [Fact]
    public void InteractionOut_DeserializesCorrectly()
    {
        var json = LoadFixture("phantom_interaction_out.json");
        var res = JsonSerializer.Deserialize<InteractionOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
        Assert.NotEmpty(res.HoneypotId);
    }

    [Fact]
    public void CampaignOut_DeserializesCorrectly()
    {
        var json = LoadFixture("deception_campaign_out.json");
        var res = JsonSerializer.Deserialize<CampaignOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
        Assert.NotEmpty(res.Name);
        Assert.True(res.DecoyCount > 0);
    }

    [Fact]
    public void BreadcrumbHitOut_DeserializesCorrectly()
    {
        var json = LoadFixture("deception_breadcrumb_hit.json");
        var res = JsonSerializer.Deserialize<BreadcrumbHitOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
        Assert.NotEmpty(res.CampaignId);
    }

    [Fact]
    public void ThemeOut_DeserializesCorrectly()
    {
        var json = LoadFixture("deception_theme_out.json");
        var res = JsonSerializer.Deserialize<ThemeOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Name);
        Assert.NotEmpty(res.Label);
    }

    [Fact]
    public void IOCOut_DeserializesCorrectly()
    {
        var json = LoadFixture("threat_ioc_out.json");
        var res = JsonSerializer.Deserialize<IOCOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal("ioc_01", res.Id);
        Assert.Equal("185.220.101.42", res.IocValue);
        Assert.Equal(0.95, res.Confidence);
        Assert.Contains("tor", res.Tags!);
    }

    [Fact]
    public void ThreatEventOut_DeserializesCorrectly()
    {
        var json = LoadFixture("threat_event_out.json");
        var res = JsonSerializer.Deserialize<ThreatEventOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
        Assert.NotEmpty(res.RuleName);
    }

    [Fact]
    public void TtpCampaignOut_DeserializesCorrectly()
    {
        var json = LoadFixture("threat_ttp_campaign.json");
        var res = JsonSerializer.Deserialize<TtpCampaignOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.ClusterId);
        Assert.True(res.IncidentCount > 0);
    }

    [Fact]
    public void IpIntelDto_DeserializesCorrectly()
    {
        var json = LoadFixture("ip_intel.json");
        var res = JsonSerializer.Deserialize<IpIntelDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Ip);
        Assert.True(res.RiskScore >= 0);
    }

    [Fact]
    public void DosStatusDto_DeserializesCorrectly()
    {
        var json = LoadFixture("dos_status.json");
        var res = JsonSerializer.Deserialize<DosStatusDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Mode);
        Assert.True(res.GlobalRps >= 0);
    }

    [Fact]
    public void DosConfigDto_DeserializesCorrectly()
    {
        var json = LoadFixture("dos_config.json");
        var res = JsonSerializer.Deserialize<DosConfigDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Mode);
    }

    [Fact]
    public void NodeOut_DeserializesCorrectly()
    {
        var json = LoadFixture("node_out.json");
        var res = JsonSerializer.Deserialize<NodeOut>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal("node-01", res.Id);
        Assert.Equal("WORKSTATION-01", res.Hostname);
        Assert.Equal(15.4, res.Cpu);
        Assert.Equal("online", res.Status);
    }

    [Fact]
    public void ComplianceOverview_DeserializesCorrectly()
    {
        var json = LoadFixture("compliance_overview.json");
        var res = JsonSerializer.Deserialize<ComplianceOverview>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal(80, res.OverallScore);
        Assert.Equal(3, res.Frameworks.Count);
        Assert.Equal("iso27001", res.Frameworks[0].Key);
        Assert.Equal("A.5", res.Frameworks[0].Controls[0].Id);
    }

    [Fact]
    public void QuantumReadinessDto_DeserializesCorrectly()
    {
        var json = LoadFixture("quantum_readiness.json");
        var res = JsonSerializer.Deserialize<QuantumReadinessDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.Equal(26.0, res.QuantumReadinessScore);
        Assert.Equal("D", res.Grade);
        Assert.Equal(25, res.Summary.TotalAlgorithmsTracked);
        Assert.Equal(26.0, res.Breakdown!.CryptoSafety);
    }

    [Fact]
    public void EntropyAnalysisResult_DeserializesCorrectly()
    {
        var json = LoadFixture("quantum_entropy.json");
        var res = JsonSerializer.Deserialize<EntropyAnalysisResult>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.True(res.ShannonEntropy > 0);
    }

    [Fact]
    public void BlockedIpsResponse_DeserializesCorrectly()
    {
        var json = LoadFixture("blocked_ips.json");
        var res = JsonSerializer.Deserialize<BlockedIpsResponse>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotNull(res.BlockedIps);
    }

    [Fact]
    public void FirewallRuleDto_DeserializesCorrectly()
    {
        var json = LoadFixture("firewall_rule.json");
        var res = JsonSerializer.Deserialize<FirewallRuleDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
    }

    [Fact]
    public void SystemsResponse_DeserializesCorrectly()
    {
        var json = LoadFixture("infra_systems.json");
        var res = JsonSerializer.Deserialize<SystemsResponse>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotNull(res.Systems);
    }

    [Fact]
    public void ClientSettingsDto_DeserializesCorrectly()
    {
        var json = LoadFixture("settings_client.json");
        var res = JsonSerializer.Deserialize<ClientSettingsDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
    }

    [Fact]
    public void NotificationConfigDto_DeserializesCorrectly()
    {
        var json = LoadFixture("settings_notifications.json");
        var res = JsonSerializer.Deserialize<NotificationConfigDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
    }

    [Fact]
    public void RansomwareStatsDto_DeserializesCorrectly()
    {
        var json = LoadFixture("ransomware_stats.json");
        var res = JsonSerializer.Deserialize<RansomwareStatsDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.True(res.ActiveIncidents >= 0);
    }

    [Fact]
    public void RaaSGroupDto_DeserializesCorrectly()
    {
        var json = LoadFixture("raas_group.json");
        var res = JsonSerializer.Deserialize<RaaSGroupDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Name);
    }

    [Fact]
    public void RecentEdrEventDto_DeserializesCorrectly()
    {
        var json = LoadFixture("recent_edr_event.json");
        var res = JsonSerializer.Deserialize<RecentEdrEventDto>(json, JsonOptions.Default);

        Assert.NotNull(res);
        Assert.NotEmpty(res.Id);
    }
}
