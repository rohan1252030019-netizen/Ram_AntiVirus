using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record IOCCreate(
    string IocType,
    string IocValue,
    string? ThreatType,
    double Confidence,
    string Source,
    List<string> Tags);

public record IOCOut(
    string Id,
    string IocType,
    string IocValue,
    string? ThreatType,
    double? Confidence,
    string? Source,
    List<string>? Tags,
    string? FirstSeen,
    string? LastSeen);

public record ThreatEventOut(
    string Id,
    string RuleId,
    string RuleName,
    string Host,
    string Severity,
    string? TriggeredAt,
    string? Process,
    string? Details);

public record IpIntelDto(
    string Ip,
    string? Asn = null,
    string? Org = null,
    string? Country = null,
    string? City = null,
    string? Region = null,
    string? Hostname = null,
    bool IsTor = false,
    bool IsVpn = false,
    bool IsProxy = false,
    bool IsDatacenter = false,
    bool IsMobile = false,
    bool IsMalicious = false,
    bool IsScanner = false,
    bool IsKnownService = false,
    double RiskScore = 0.0,
    bool Internal = false);

public record TtpCampaignOut
{
    [JsonPropertyName("cluster_id")]
    public string ClusterId { get; init; } = "";

    [JsonPropertyName("mitre_tactic")]
    public string? MitreTactic { get; init; } = null;

    [JsonPropertyName("mitre_technique")]
    public string? MitreTechnique { get; init; } = null;

    [JsonPropertyName("ttp_fingerprint")]
    public string? TtpFingerprint { get; init; } = null;

    [JsonPropertyName("total_incidents")]
    public int TotalIncidents { get; init; } = 0;

    [JsonPropertyName("incident_count")]
    public int? LegacyIncidentCount { get; init; } = null;

    [JsonPropertyName("distinct_ips")]
    public int DistinctIps { get; init; } = 0;

    [JsonPropertyName("first_seen")]
    public string? FirstSeen { get; init; } = null;

    [JsonPropertyName("last_seen")]
    public string? LastSeen { get; init; } = null;

    [JsonPropertyName("sample_ips")]
    public List<string>? SampleIps { get; init; } = null;

    [JsonPropertyName("source_ips")]
    public List<string>? LegacySourceIps { get; init; } = null;

    [JsonConstructor]
    public TtpCampaignOut(
        string clusterId = "",
        string? mitreTactic = null,
        string? mitreTechnique = null,
        string? ttpFingerprint = null,
        int totalIncidents = 0,
        int? legacyIncidentCount = null,
        int distinctIps = 0,
        string? firstSeen = null,
        string? lastSeen = null,
        List<string>? sampleIps = null,
        List<string>? legacySourceIps = null)
    {
        ClusterId = clusterId;
        MitreTactic = mitreTactic;
        MitreTechnique = mitreTechnique;
        TtpFingerprint = ttpFingerprint;
        TotalIncidents = totalIncidents;
        LegacyIncidentCount = legacyIncidentCount;
        DistinctIps = distinctIps;
        FirstSeen = firstSeen;
        LastSeen = lastSeen;
        SampleIps = sampleIps;
        LegacySourceIps = legacySourceIps;
    }

    public TtpCampaignOut(
        string clusterId,
        string? tactic,
        string? technique,
        int incidentCount,
        string? firstSeen,
        string? lastSeen,
        List<string>? sourceIps)
        : this(clusterId, tactic, technique, null, incidentCount, incidentCount, 0, firstSeen, lastSeen, sourceIps, sourceIps)
    {
    }

    [JsonIgnore]
    public string? Tactic => MitreTactic;

    [JsonIgnore]
    public string? Technique => MitreTechnique;

    [JsonIgnore]
    public int IncidentCount => LegacyIncidentCount ?? TotalIncidents;

    [JsonIgnore]
    public List<string>? SourceIps => LegacySourceIps ?? SampleIps;
}

public record TtpCampaignsResponseDto(
    List<TtpCampaignOut>? Campaigns = null,
    int Count = 0,
    int WindowHours = 168
);
