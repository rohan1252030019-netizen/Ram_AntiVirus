using Aegis.Core.Enums;
using Aegis.Core.Models;

namespace Aegis.Core.Interfaces;

public interface IAegisApiClient
{
    // Auth & Dashboard
    Task<UserLoginResponse> LoginAsync(string email, string password, CancellationToken ct = default);
    Task<ClientLoginResponse> LoginApiKeyAsync(string apiKey, CancellationToken ct = default);
    Task<DashboardOverviewDto> GetDashboardOverviewAsync(CancellationToken ct = default);
    Task<List<TimelineEventDto>> GetTimelineAsync(CancellationToken ct = default);
    Task<List<IncidentDto>> GetIncidentsAsync(string? status = null, Severity? severity = null, CancellationToken ct = default);
    Task<IncidentDto?> GetIncidentDetailAsync(string id, CancellationToken ct = default);
    Task<bool> ApproveActionAsync(string actionId, CancellationToken ct = default);
    Task<bool> RejectActionAsync(string actionId, string reason, CancellationToken ct = default);
    
    // Ransomware
    Task<RansomwareStatsDto> GetRansomwareStatsAsync(CancellationToken ct = default);
    Task<List<RaaSGroupDto>> GetRaaSGroupsAsync(CancellationToken ct = default);
    Task<RecoveryOptionsDto?> GetRecoveryOptionsAsync(string eventId, CancellationToken ct = default);
    Task<bool> TriggerRestoreAsync(RestoreRequest request, CancellationToken ct = default);
    
    // Firewall
    Task<List<FirewallRuleDto>> GetFirewallRulesAsync(CancellationToken ct = default);
    Task<BlockedIpsResponse> GetBlockedIpsAsync(CancellationToken ct = default);
    Task<bool> UnblockIpAsync(string ip, CancellationToken ct = default);
    
    // Systems & Settings
    Task<SystemsResponse> GetSystemsAsync(CancellationToken ct = default);
    Task<ClientSettingsDto> GetClientSettingsAsync(CancellationToken ct = default);
    Task<bool> UpdateClientSettingsAsync(ClientSettingsDto settings, CancellationToken ct = default);
    Task<NotificationConfigDto> GetNotificationConfigAsync(CancellationToken ct = default);
    Task<bool> UpdateNotificationConfigAsync(NotificationConfigDto config, CancellationToken ct = default);
    Task<NotificationTestResponse> TestNotificationAsync(string channel, CancellationToken ct = default);

    // EDR
    Task<EdrEventsOut> SubmitEdrEventsAsync(EdrEventsIn eventsIn, CancellationToken ct = default);
    Task<List<RecentEdrEventDto>> GetRecentEdrEventsAsync(string agentId, int minutes = 15, int limit = 200, CancellationToken ct = default);
    Task<bool> KillProcessAsync(KillProcessRequest request, CancellationToken ct = default);
    Task<bool> QuarantineFileAsync(QuarantineFileRequest request, CancellationToken ct = default);
    Task<bool> IsolateHostAsync(string agentId, IsolateHostRequest request, CancellationToken ct = default);
    Task<bool> UnisolateHostAsync(string agentId, UnisolateHostRequest request, CancellationToken ct = default);

    // Antivirus
    Task<SignatureBundleDto> GetSignaturesAsync(CancellationToken ct = default);
    Task<SignatureBundleDto> UpdateSignaturesAsync(CancellationToken ct = default);
    Task<DetectionOut> ReportDetectionAsync(DetectionIn detection, CancellationToken ct = default);
    Task<List<QuarantineItemDto>> GetQuarantineListAsync(int limit = 100, CancellationToken ct = default);
    Task<ReleaseQuarantineResponse> ReleaseQuarantineAsync(string detectionId, CancellationToken ct = default);
    Task<HashLookupDto> LookupHashAsync(string sha256, CancellationToken ct = default);

    // Attack Surface
    Task<ScanResponse> StartSurfaceScanAsync(ScanRequest request, CancellationToken ct = default);
    Task<List<ScanDetail>> GetSurfaceScansAsync(CancellationToken ct = default);
    Task<List<AssetOut>> GetSurfaceAssetsAsync(CancellationToken ct = default);
    Task<List<VulnOut>> GetSurfaceVulnerabilitiesAsync(CancellationToken ct = default);
    Task<VulnOut> UpdateVulnerabilityStatusAsync(string vulnId, string status, CancellationToken ct = default);
    Task<HardenResponse> GetHardenRecommendationsAsync(CancellationToken ct = default);

    // Phantom & Deception
    Task<List<HoneypotOut>> GetHoneypotsAsync(CancellationToken ct = default);
    Task<HoneypotOut> CreateHoneypotAsync(HoneypotCreate request, CancellationToken ct = default);
    Task<bool> DeleteHoneypotAsync(string honeypotId, CancellationToken ct = default);
    Task<HoneypotOut> RotateHoneypotAsync(string honeypotId, CancellationToken ct = default);
    Task<List<InteractionOut>> GetHoneypotInteractionsAsync(CancellationToken ct = default);
    Task<List<AttackerOut>> GetAttackersAsync(CancellationToken ct = default);
    Task<List<CampaignOut>> GetDeceptionCampaignsAsync(CancellationToken ct = default);
    Task<CampaignOut> CreateDeceptionCampaignAsync(CampaignCreate request, CancellationToken ct = default);
    Task<CampaignOut> RotateDeceptionCampaignAsync(string campaignId, CancellationToken ct = default);
    Task<bool> DeleteDeceptionCampaignAsync(string campaignId, CancellationToken ct = default);
    Task<List<BreadcrumbHitOut>> GetBreadcrumbHitsAsync(CancellationToken ct = default);
    Task<List<ThemeOut>> GetDeceptionThemesAsync(CancellationToken ct = default);

    // Threats & IP Intel
    Task<List<IOCOut>> GetThreatIntelAsync(CancellationToken ct = default);
    Task<IOCOut> CreateIOCAsync(IOCCreate request, CancellationToken ct = default);
    Task<List<ThreatEventOut>> GetThreatEventsAsync(CancellationToken ct = default);
    Task<IpIntelDto> LookupIpIntelAsync(string ip, bool deep = false, CancellationToken ct = default);
    Task<List<TtpCampaignOut>> GetTtpCampaignsAsync(int limit = 20, int windowHours = 168, CancellationToken ct = default);

    // DoS Shield
    Task<DosStatusDto> GetDosStatusAsync(CancellationToken ct = default);
    Task<List<DosOffenderDto>> GetDosOffendersAsync(CancellationToken ct = default);
    Task<DosConfigDto> GetDosConfigAsync(CancellationToken ct = default);

    // Nodes
    Task<List<NodeOut>> GetNodesAsync(string? status = null, CancellationToken ct = default);
    Task<NodeOut?> GetNodeAsync(string nodeId, CancellationToken ct = default);
    Task<EnrollResponse> EnrollNodeAsync(EnrollRequest request, CancellationToken ct = default);
    Task<bool> DeleteNodeAsync(string nodeId, CancellationToken ct = default);

    // Compliance
    Task<ComplianceOverview> GetComplianceFrameworksAsync(CancellationToken ct = default);

    // Quantum
    Task<QuantumReadinessDto> GetQuantumReadinessAsync(CancellationToken ct = default);
    Task<EntropyAnalysisResult> AnalyzeEntropyAsync(EntropyRequest request, CancellationToken ct = default);
}
