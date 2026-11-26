using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.Services;

public class AegisApiClient : IAegisApiClient
{
    private readonly HttpClient _http;
    private readonly IAuthService _auth;
    private readonly ILogger<AegisApiClient> _logger;

    public AegisApiClient(HttpClient http, IAuthService auth, ILogger<AegisApiClient> logger)
    {
        _http = http;
        _auth = auth;
        _logger = logger;
    }

    private void ApplyAuth(HttpRequestMessage request)
    {
        if (!string.IsNullOrEmpty(_auth.CurrentToken))
        {
            if (_auth.CurrentToken.StartsWith("c6_") || _auth.CurrentToken.StartsWith("aegis_") || _auth.CurrentToken.StartsWith("key_"))
                request.Headers.Add("X-API-Key", _auth.CurrentToken);
            else
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _auth.CurrentToken);
        }
    }

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(method, path);
        ApplyAuth(req);

        if (body != null)
        {
            req.Content = JsonContent.Create(body, options: JsonOptions.Default);
        }

        using var response = await _http.SendAsync(req, ct);

        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, ct);
        return result ?? throw new InvalidOperationException($"Empty response returned from {path}");
    }

    // --- Auth & Dashboard ---
    public async Task<UserLoginResponse> LoginAsync(string email, string password, CancellationToken ct = default) =>
        await SendAsync<UserLoginResponse>(HttpMethod.Post, "/api/v1/auth/user/login", new UserLoginRequest(email, password), ct);

    public async Task<ClientLoginResponse> LoginApiKeyAsync(string apiKey, CancellationToken ct = default) =>
        await SendAsync<ClientLoginResponse>(HttpMethod.Post, "/api/v1/auth/login", new ClientLoginRequest(apiKey), ct);

    public Task<DashboardOverviewDto> GetDashboardOverviewAsync(CancellationToken ct = default) =>
        SendAsync<DashboardOverviewDto>(HttpMethod.Get, "/api/v1/dashboard/overview", null, ct);

    public Task<List<TimelineEventDto>> GetTimelineAsync(CancellationToken ct = default) =>
        SendAsync<List<TimelineEventDto>>(HttpMethod.Get, "/api/v1/dashboard/timeline", null, ct);

    public Task<List<IncidentDto>> GetIncidentsAsync(string? status = null, Severity? severity = null, CancellationToken ct = default)
    {
        var url = "/api/v1/response/incidents";
        var query = new List<string>();
        if (!string.IsNullOrEmpty(status)) query.Add($"status={Uri.EscapeDataString(status)}");
        if (severity.HasValue) query.Add($"severity={severity.Value.ToString().ToLowerInvariant()}");
        if (query.Count > 0) url += "?" + string.Join("&", query);

        return SendAsync<List<IncidentDto>>(HttpMethod.Get, url, null, ct);
    }

    public Task<IncidentDto?> GetIncidentDetailAsync(string id, CancellationToken ct = default) =>
        SendAsync<IncidentDto?>(HttpMethod.Get, $"/api/v1/response/incidents/{id}", null, ct);

    public async Task<bool> ApproveActionAsync(string actionId, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Post, $"/api/v1/response/actions/{actionId}/approve", new { }, ct);
        return true;
    }

    public async Task<bool> RejectActionAsync(string actionId, string reason, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Post, $"/api/v1/response/actions/{actionId}/reject", new RejectActionRequest(reason), ct);
        return true;
    }

    // --- Ransomware ---
    public Task<RansomwareStatsDto> GetRansomwareStatsAsync(CancellationToken ct = default) =>
        SendAsync<RansomwareStatsDto>(HttpMethod.Get, "/api/v1/ransomware/stats", null, ct);

    public async Task<List<RaaSGroupDto>> GetRaaSGroupsAsync(CancellationToken ct = default)
    {
        var res = await SendAsync<RaaSGroupsOutDto>(HttpMethod.Get, "/api/v1/ransomware/raas-groups", null, ct);
        return res.Groups ?? new List<RaaSGroupDto>();
    }

    public Task<RecoveryOptionsDto?> GetRecoveryOptionsAsync(string eventId, CancellationToken ct = default) =>
        SendAsync<RecoveryOptionsDto?>(HttpMethod.Get, $"/api/v1/ransomware/recovery-options/{eventId}", null, ct);

    public async Task<bool> TriggerRestoreAsync(RestoreRequest request, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Post, "/api/v1/ransomware/restore", request, ct);
        return true;
    }

    // --- Firewall ---
    public Task<List<FirewallRuleDto>> GetFirewallRulesAsync(CancellationToken ct = default) =>
        SendAsync<List<FirewallRuleDto>>(HttpMethod.Get, "/api/v1/firewall/rules", null, ct);

    public Task<BlockedIpsResponse> GetBlockedIpsAsync(CancellationToken ct = default) =>
        SendAsync<BlockedIpsResponse>(HttpMethod.Get, "/api/v1/firewall/blocked", null, ct);

    public async Task<bool> UnblockIpAsync(string ip, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Delete, $"/api/v1/firewall/blocked/{Uri.EscapeDataString(ip)}", null, ct);
        return true;
    }

    // --- Systems & Settings ---
    public Task<SystemsResponse> GetSystemsAsync(CancellationToken ct = default) =>
        SendAsync<SystemsResponse>(HttpMethod.Get, "/api/v1/infra/systems", null, ct);

    public Task<ClientSettingsDto> GetClientSettingsAsync(CancellationToken ct = default) =>
        SendAsync<ClientSettingsDto>(HttpMethod.Get, "/api/v1/settings/client", null, ct);

    public async Task<bool> UpdateClientSettingsAsync(ClientSettingsDto settings, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Put, "/api/v1/settings/client", settings, ct);
        return true;
    }

    public Task<NotificationConfigDto> GetNotificationConfigAsync(CancellationToken ct = default) =>
        SendAsync<NotificationConfigDto>(HttpMethod.Get, "/api/v1/settings/notifications", null, ct);

    public async Task<bool> UpdateNotificationConfigAsync(NotificationConfigDto config, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Put, "/api/v1/settings/notifications", config, ct);
        return true;
    }

    public Task<NotificationTestResponse> TestNotificationAsync(string channel, CancellationToken ct = default) =>
        SendAsync<NotificationTestResponse>(HttpMethod.Post, "/api/v1/settings/notifications", new NotificationTestRequest(true, channel), ct);

    // --- EDR ---
    public Task<EdrEventsOut> SubmitEdrEventsAsync(EdrEventsIn eventsIn, CancellationToken ct = default) =>
        SendAsync<EdrEventsOut>(HttpMethod.Post, "/api/v1/edr/events", eventsIn, ct);

    public Task<List<RecentEdrEventDto>> GetRecentEdrEventsAsync(string agentId, int minutes = 15, int limit = 200, CancellationToken ct = default) =>
        SendAsync<List<RecentEdrEventDto>>(HttpMethod.Get, $"/api/v1/edr/events/recent?agent_id={Uri.EscapeDataString(agentId)}&minutes={minutes}&limit={limit}", null, ct);

    public async Task<bool> KillProcessAsync(KillProcessRequest request, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Post, "/api/v1/edr/kill-process", request, ct);
        return true;
    }

    public async Task<bool> QuarantineFileAsync(QuarantineFileRequest request, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Post, "/api/v1/edr/quarantine-file", request, ct);
        return true;
    }

    public async Task<bool> IsolateHostAsync(string agentId, IsolateHostRequest request, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Post, $"/api/v1/edr/hosts/{Uri.EscapeDataString(agentId)}/isolate", request, ct);
        return true;
    }

    public async Task<bool> UnisolateHostAsync(string agentId, UnisolateHostRequest request, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Post, $"/api/v1/edr/hosts/{Uri.EscapeDataString(agentId)}/unisolate", request, ct);
        return true;
    }

    // --- Antivirus ---
    public Task<SignatureBundleDto> GetSignaturesAsync(CancellationToken ct = default) =>
        SendAsync<SignatureBundleDto>(HttpMethod.Get, "/api/v1/antivirus/signatures", null, ct);

    public Task<SignatureBundleDto> UpdateSignaturesAsync(CancellationToken ct = default) =>
        SendAsync<SignatureBundleDto>(HttpMethod.Post, "/api/v1/antivirus/signatures/update", new { }, ct);

    public Task<DetectionOut> ReportDetectionAsync(DetectionIn detection, CancellationToken ct = default) =>
        SendAsync<DetectionOut>(HttpMethod.Post, "/api/v1/antivirus/detections", detection, ct);

    public Task<List<QuarantineItemDto>> GetQuarantineListAsync(int limit = 100, CancellationToken ct = default) =>
        SendAsync<List<QuarantineItemDto>>(HttpMethod.Get, $"/api/v1/antivirus/quarantine?limit={limit}", null, ct);

    public Task<ReleaseQuarantineResponse> ReleaseQuarantineAsync(string detectionId, CancellationToken ct = default) =>
        SendAsync<ReleaseQuarantineResponse>(HttpMethod.Post, $"/api/v1/antivirus/quarantine/{Uri.EscapeDataString(detectionId)}/release", new { }, ct);

    public Task<HashLookupDto> LookupHashAsync(string sha256, CancellationToken ct = default) =>
        SendAsync<HashLookupDto>(HttpMethod.Get, $"/api/v1/antivirus/hash/{Uri.EscapeDataString(sha256)}/lookup", null, ct);

    // --- Surface ---
    public Task<ScanResponse> StartSurfaceScanAsync(ScanRequest request, CancellationToken ct = default) =>
        SendAsync<ScanResponse>(HttpMethod.Post, "/api/v1/surface/scan", request, ct);

    public Task<List<ScanDetail>> GetSurfaceScansAsync(CancellationToken ct = default) =>
        SendAsync<List<ScanDetail>>(HttpMethod.Get, "/api/v1/surface/scans", null, ct);

    public Task<List<AssetOut>> GetSurfaceAssetsAsync(CancellationToken ct = default) =>
        SendAsync<List<AssetOut>>(HttpMethod.Get, "/api/v1/surface/assets", null, ct);

    public Task<List<VulnOut>> GetSurfaceVulnerabilitiesAsync(CancellationToken ct = default) =>
        SendAsync<List<VulnOut>>(HttpMethod.Get, "/api/v1/surface/vulnerabilities", null, ct);

    public Task<VulnOut> UpdateVulnerabilityStatusAsync(string vulnId, string status, CancellationToken ct = default) =>
        SendAsync<VulnOut>(HttpMethod.Patch, $"/api/v1/surface/vulnerabilities/{Uri.EscapeDataString(vulnId)}", new VulnUpdate(status), ct);

    public Task<HardenResponse> GetHardenRecommendationsAsync(CancellationToken ct = default) =>
        SendAsync<HardenResponse>(HttpMethod.Get, "/api/v1/surface/harden", null, ct);

    // --- Phantom ---
    public Task<List<HoneypotOut>> GetHoneypotsAsync(CancellationToken ct = default) =>
        SendAsync<List<HoneypotOut>>(HttpMethod.Get, "/api/v1/phantom/honeypots", null, ct);

    public Task<HoneypotOut> CreateHoneypotAsync(HoneypotCreate request, CancellationToken ct = default) =>
        SendAsync<HoneypotOut>(HttpMethod.Post, "/api/v1/phantom/honeypots", request, ct);

    public async Task<bool> DeleteHoneypotAsync(string honeypotId, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Delete, $"/api/v1/phantom/honeypots/{Uri.EscapeDataString(honeypotId)}", null, ct);
        return true;
    }

    public Task<HoneypotOut> RotateHoneypotAsync(string honeypotId, CancellationToken ct = default) =>
        SendAsync<HoneypotOut>(HttpMethod.Post, $"/api/v1/phantom/honeypots/{Uri.EscapeDataString(honeypotId)}/rotate", new { }, ct);

    public Task<List<InteractionOut>> GetHoneypotInteractionsAsync(CancellationToken ct = default) =>
        SendAsync<List<InteractionOut>>(HttpMethod.Get, "/api/v1/phantom/interactions", null, ct);

    public Task<List<AttackerOut>> GetAttackersAsync(CancellationToken ct = default) =>
        SendAsync<List<AttackerOut>>(HttpMethod.Get, "/api/v1/phantom/attackers", null, ct);

    // --- Deception ---
    public Task<List<CampaignOut>> GetDeceptionCampaignsAsync(CancellationToken ct = default) =>
        SendAsync<List<CampaignOut>>(HttpMethod.Get, "/api/v1/deception/campaigns", null, ct);

    public Task<CampaignOut> CreateDeceptionCampaignAsync(CampaignCreate request, CancellationToken ct = default) =>
        SendAsync<CampaignOut>(HttpMethod.Post, "/api/v1/deception/campaigns", request, ct);

    public Task<CampaignOut> RotateDeceptionCampaignAsync(string campaignId, CancellationToken ct = default) =>
        SendAsync<CampaignOut>(HttpMethod.Post, $"/api/v1/deception/campaigns/{Uri.EscapeDataString(campaignId)}/rotate", new { }, ct);

    public async Task<bool> DeleteDeceptionCampaignAsync(string campaignId, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Delete, $"/api/v1/deception/campaigns/{Uri.EscapeDataString(campaignId)}", null, ct);
        return true;
    }

    public Task<List<BreadcrumbHitOut>> GetBreadcrumbHitsAsync(CancellationToken ct = default) =>
        SendAsync<List<BreadcrumbHitOut>>(HttpMethod.Get, "/api/v1/deception/breadcrumb-hits", null, ct);

    public Task<List<ThemeOut>> GetDeceptionThemesAsync(CancellationToken ct = default) =>
        SendAsync<List<ThemeOut>>(HttpMethod.Get, "/api/v1/deception/themes", null, ct);

    // --- Threats & IP Intel ---
    public Task<List<IOCOut>> GetThreatIntelAsync(CancellationToken ct = default) =>
        SendAsync<List<IOCOut>>(HttpMethod.Get, "/api/v1/threats/intel", null, ct);

    public Task<IOCOut> CreateIOCAsync(IOCCreate request, CancellationToken ct = default) =>
        SendAsync<IOCOut>(HttpMethod.Post, "/api/v1/threats/intel", request, ct);

    public Task<List<ThreatEventOut>> GetThreatEventsAsync(CancellationToken ct = default) =>
        SendAsync<List<ThreatEventOut>>(HttpMethod.Get, "/api/v1/threats/events", null, ct);

    public Task<IpIntelDto> LookupIpIntelAsync(string ip, bool deep = false, CancellationToken ct = default) =>
        SendAsync<IpIntelDto>(HttpMethod.Get, $"/api/v1/intel/ip/{Uri.EscapeDataString(ip)}?deep={deep.ToString().ToLowerInvariant()}", null, ct);

    public async Task<List<TtpCampaignOut>> GetTtpCampaignsAsync(int limit = 20, int windowHours = 168, CancellationToken ct = default)
    {
        var res = await SendAsync<TtpCampaignsResponseDto>(HttpMethod.Get, $"/api/v1/threats/campaigns?limit={limit}&window_hours={windowHours}", null, ct);
        return res.Campaigns ?? new List<TtpCampaignOut>();
    }

    // --- DoS Shield ---
    public Task<DosStatusDto> GetDosStatusAsync(CancellationToken ct = default) =>
        SendAsync<DosStatusDto>(HttpMethod.Get, "/api/v1/dos/status", null, ct);

    public async Task<List<DosOffenderDto>> GetDosOffendersAsync(CancellationToken ct = default)
    {
        var dict = await SendAsync<Dictionary<string, List<DosOffenderDto>>>(HttpMethod.Get, "/api/v1/dos/offenders", null, ct);
        return dict.TryGetValue("offenders", out var list) ? list : new List<DosOffenderDto>();
    }

    public Task<DosConfigDto> GetDosConfigAsync(CancellationToken ct = default) =>
        SendAsync<DosConfigDto>(HttpMethod.Get, "/api/v1/dos/config", null, ct);

    // --- Nodes ---
    public Task<List<NodeOut>> GetNodesAsync(string? status = null, CancellationToken ct = default)
    {
        var url = "/api/v1/nodes";
        if (!string.IsNullOrEmpty(status)) url += $"?status={Uri.EscapeDataString(status)}";
        return SendAsync<List<NodeOut>>(HttpMethod.Get, url, null, ct);
    }

    public Task<NodeOut?> GetNodeAsync(string nodeId, CancellationToken ct = default) =>
        SendAsync<NodeOut?>(HttpMethod.Get, $"/api/v1/nodes/{Uri.EscapeDataString(nodeId)}", null, ct);

    public Task<EnrollResponse> EnrollNodeAsync(EnrollRequest request, CancellationToken ct = default) =>
        SendAsync<EnrollResponse>(HttpMethod.Post, "/api/v1/nodes/enroll", request, ct);

    public async Task<bool> DeleteNodeAsync(string nodeId, CancellationToken ct = default)
    {
        await SendAsync<object>(HttpMethod.Delete, $"/api/v1/nodes/{Uri.EscapeDataString(nodeId)}", null, ct);
        return true;
    }

    // --- Compliance ---
    public Task<ComplianceOverview> GetComplianceFrameworksAsync(CancellationToken ct = default) =>
        SendAsync<ComplianceOverview>(HttpMethod.Get, "/api/v1/compliance/frameworks", null, ct);

    // --- Quantum ---
    public Task<QuantumReadinessDto> GetQuantumReadinessAsync(CancellationToken ct = default) =>
        SendAsync<QuantumReadinessDto>(HttpMethod.Get, "/api/v1/quantum/readiness", null, ct);

    public Task<EntropyAnalysisResult> AnalyzeEntropyAsync(EntropyRequest request, CancellationToken ct = default) =>
        SendAsync<EntropyAnalysisResult>(HttpMethod.Post, "/api/v1/quantum/entropy", request, ct);
}
