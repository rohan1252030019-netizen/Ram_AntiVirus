using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record DashboardOverviewDto
{
    [JsonPropertyName("total_assets")]
    public int TotalAssets { get; init; } = 0;

    [JsonPropertyName("open_vulnerabilities")]
    public int OpenVulnerabilities { get; init; } = 0;

    [JsonPropertyName("critical_vulnerabilities")]
    public int CriticalVulnerabilities { get; init; } = 0;

    [JsonPropertyName("active_incidents")]
    public int ActiveIncidents { get; init; } = 0;

    [JsonPropertyName("honeypot_interactions")]
    public int HoneypotInteractions { get; init; } = 0;

    [JsonPropertyName("actions_taken")]
    public int ActionsTaken { get; init; } = 0;

    [JsonPropertyName("risk_level")]
    public string RiskLevel { get; init; } = "low";

    [JsonConstructor]
    public DashboardOverviewDto(
        int totalAssets = 0,
        int openVulnerabilities = 0,
        int criticalVulnerabilities = 0,
        int activeIncidents = 0,
        int honeypotInteractions = 0,
        int actionsTaken = 0,
        string riskLevel = "low")
    {
        TotalAssets = totalAssets;
        OpenVulnerabilities = openVulnerabilities;
        CriticalVulnerabilities = criticalVulnerabilities;
        ActiveIncidents = activeIncidents;
        HoneypotInteractions = honeypotInteractions;
        ActionsTaken = actionsTaken;
        RiskLevel = riskLevel;
    }

    public DashboardOverviewDto(
        int activeThreats,
        int incidentsToday,
        int assetsProtected,
        int blockedIpsCount,
        int honeypotInteractions24h = 0,
        double avgTriageTimeMs = 0.85,
        string systemHealth = "optimal")
        : this(assetsProtected, 0, 0, incidentsToday, honeypotInteractions24h, blockedIpsCount, systemHealth == "optimal" ? "low" : "high")
    {
    }

    // Convenience aliases for UI bindings
    [JsonIgnore] public int ActiveThreats => ActiveIncidents + CriticalVulnerabilities;
    [JsonIgnore] public int IncidentsToday => ActiveIncidents;
    [JsonIgnore] public int AssetsProtected => TotalAssets;
    [JsonIgnore] public int BlockedIpsCount => ActionsTaken;
    [JsonIgnore] public int HoneypotInteractions24h => HoneypotInteractions;
    [JsonIgnore] public double AvgTriageTimeMs => 0.85;
    [JsonIgnore] public string SystemHealth => (RiskLevel == "high" || RiskLevel == "critical") ? "degraded" : "optimal";
}

public record TimelineEventDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = "";

    [JsonPropertyName("type")]
    public string Type { get; init; } = "audit";

    [JsonPropertyName("title")]
    public string Title { get; init; } = "";

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; init; } = "";

    [JsonPropertyName("severity")]
    public string? Severity { get; init; } = null;

    [JsonPropertyName("description")]
    public string? Description { get; init; } = null;

    [JsonPropertyName("module")]
    public string? Module { get; init; } = null;

    [JsonPropertyName("decision")]
    public string? Decision { get; init; } = null;

    [JsonPropertyName("confidence")]
    public double? Confidence { get; init; } = null;

    [JsonPropertyName("model_used")]
    public string? ModelUsed { get; init; } = null;

    [JsonPropertyName("linked_incident_id")]
    public string? LinkedIncidentId { get; init; } = null;

    [JsonPropertyName("navigable")]
    public bool Navigable { get; init; } = false;

    [JsonConstructor]
    public TimelineEventDto(
        string id = "",
        string type = "audit",
        string title = "",
        string timestamp = "",
        string? severity = null,
        string? description = null,
        string? module = null,
        string? decision = null,
        double? confidence = null,
        string? modelUsed = null,
        string? linkedIncidentId = null,
        bool navigable = false)
    {
        Id = id;
        Type = type;
        Title = title;
        Timestamp = timestamp;
        Severity = severity;
        Description = description;
        Module = module;
        Decision = decision;
        Confidence = confidence;
        ModelUsed = modelUsed;
        LinkedIncidentId = linkedIncidentId;
        Navigable = navigable;
    }

    public TimelineEventDto(string date, int incidentCount, int threatCount)
        : this(Guid.NewGuid().ToString(), "incident", $"Incidents: {incidentCount}", date, threatCount > 0 ? "high" : "low", null, null, null, null, null, null, false)
    {
    }

    // UI convenience properties
    [JsonIgnore] public string Date => Timestamp;
    [JsonIgnore] public int IncidentCount => 1;
    [JsonIgnore] public int ThreatCount => (Severity is "critical" or "high") ? 1 : 0;
}

public record ThreatMapEntryDto(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("country")] string Country,
    [property: JsonPropertyName("latitude")] double Latitude,
    [property: JsonPropertyName("longitude")] double Longitude,
    [property: JsonPropertyName("threat_count")] int ThreatCount,
    [property: JsonPropertyName("threat_type")] string ThreatType
);

public record MonitoredAppDto(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("pid")] int Pid = 0,
    [property: JsonPropertyName("cpu")] double Cpu = 0,
    [property: JsonPropertyName("memory_mb")] double MemoryMb = 0,
    [property: JsonPropertyName("uptime_seconds")] long UptimeSeconds = 0
);
