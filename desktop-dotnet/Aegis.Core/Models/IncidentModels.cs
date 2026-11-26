using System.Text.Json.Serialization;
using Aegis.Core.Enums;

namespace Aegis.Core.Models;

public record ResponseActionDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = "";

    [JsonPropertyName("incident_id")]
    public string? IncidentId { get; init; } = null;

    [JsonPropertyName("action_type")]
    public ActionType ActionType { get; init; } = ActionType.BlockIp;

    [JsonPropertyName("target")]
    public string? Target { get; init; } = null;

    [JsonPropertyName("status")]
    public ActionStatus Status { get; init; } = ActionStatus.Pending;

    [JsonPropertyName("requires_approval")]
    public bool RequiresApproval { get; init; } = false;

    [JsonPropertyName("approved_by")]
    public string? ApprovedBy { get; init; } = null;

    [JsonPropertyName("ai_reasoning")]
    public string? AiReasoning { get; init; } = null;

    [JsonPropertyName("result")]
    public Dictionary<string, object>? Result { get; init; } = null;

    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; init; } = null;

    [JsonPropertyName("executed_at")]
    public string? ExecutedAt { get; init; } = null;

    [JsonConstructor]
    public ResponseActionDto(
        string id = "",
        string? incidentId = null,
        ActionType actionType = ActionType.BlockIp,
        string? target = null,
        ActionStatus status = ActionStatus.Pending,
        bool requiresApproval = false,
        string? approvedBy = null,
        string? aiReasoning = null,
        Dictionary<string, object>? result = null,
        string? createdAt = null,
        string? executedAt = null)
    {
        Id = id;
        IncidentId = incidentId;
        ActionType = actionType;
        Target = target;
        Status = status;
        RequiresApproval = requiresApproval;
        ApprovedBy = approvedBy;
        AiReasoning = aiReasoning;
        Result = result;
        CreatedAt = createdAt;
        ExecutedAt = executedAt;
    }

    public ResponseActionDto(
        string id,
        string? incidentId,
        ActionType actionType,
        string target,
        ActionStatus status,
        bool requiresApproval,
        DateTime createdAt,
        DateTime? executedAt = null,
        string? details = null)
        : this(id, incidentId, actionType, target, status, requiresApproval, null, details, null, createdAt.ToString("o"), executedAt?.ToString("o"))
    {
    }
}

public record IncidentDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = "";

    [JsonPropertyName("title")]
    public string Title { get; init; } = "";

    [JsonPropertyName("severity")]
    public Severity Severity { get; init; } = Severity.Medium;

    [JsonPropertyName("status")]
    public IncidentStatus Status { get; init; } = IncidentStatus.Open;

    [JsonPropertyName("source")]
    public string? Source { get; init; } = null;

    [JsonPropertyName("source_ip")]
    public string? SourceIp { get; init; } = null;

    [JsonPropertyName("mitre_technique")]
    public string? MitreTechnique { get; init; } = null;

    [JsonPropertyName("mitre_tactic")]
    public string? MitreTactic { get; init; } = null;

    [JsonPropertyName("description")]
    public string? Description { get; init; } = null;

    [JsonPropertyName("detected_at")]
    public string? DetectedAt { get; init; } = null;

    [JsonPropertyName("contained_at")]
    public string? ContainedAt { get; init; } = null;

    [JsonPropertyName("resolved_at")]
    public string? ResolvedAt { get; init; } = null;

    [JsonPropertyName("raw_alert")]
    public Dictionary<string, object>? RawAlert { get; init; } = null;

    [JsonPropertyName("ai_analysis")]
    public Dictionary<string, object>? AiAnalysis { get; init; } = null;

    [JsonPropertyName("actions")]
    public List<ResponseActionDto>? Actions { get; init; } = null;

    [JsonConstructor]
    public IncidentDto(
        string Id = "",
        string Title = "",
        Severity Severity = Severity.Medium,
        IncidentStatus Status = IncidentStatus.Open,
        string? Source = null,
        string? SourceIp = null,
        string? MitreTechnique = null,
        string? MitreTactic = null,
        string? Description = null,
        string? DetectedAt = null,
        string? ContainedAt = null,
        string? ResolvedAt = null,
        Dictionary<string, object>? RawAlert = null,
        Dictionary<string, object>? AiAnalysis = null,
        List<ResponseActionDto>? Actions = null)
    {
        this.Id = Id;
        this.Title = Title;
        this.Severity = Severity;
        this.Status = Status;
        this.Source = Source;
        this.SourceIp = SourceIp;
        this.MitreTechnique = MitreTechnique;
        this.MitreTactic = MitreTactic;
        this.Description = Description;
        this.DetectedAt = DetectedAt;
        this.ContainedAt = ContainedAt;
        this.ResolvedAt = ResolvedAt;
        this.RawAlert = RawAlert;
        this.AiAnalysis = AiAnalysis;
        this.Actions = Actions;
    }

    public IncidentDto(
        string id,
        string title,
        Severity severity,
        IncidentStatus status,
        string? sourceIp,
        string? mitreTechnique,
        DateTime createdAt,
        double riskScore = 0.0,
        string? description = null,
        string? rawLog = null,
        List<string>? tags = null,
        List<ResponseActionDto>? actions = null)
        : this(id, title, severity, status, "aegis-core", sourceIp, mitreTechnique, null, description, createdAt.ToString("o"), null, null, null, null, actions)
    {
    }

    [JsonIgnore]
    public DateTime CreatedAt => DateTime.TryParse(DetectedAt, out var dt) ? dt : DateTime.UtcNow;

    [JsonIgnore]
    public double RiskScore => Severity switch
    {
        Severity.Critical => 95.0,
        Severity.High => 80.0,
        Severity.Medium => 50.0,
        _ => 20.0
    };

    [JsonIgnore]
    public string? RawLog => RawAlert != null ? System.Text.Json.JsonSerializer.Serialize(RawAlert) : null;

    [JsonIgnore]
    public List<string>? Tags => MitreTechnique != null ? new List<string> { MitreTechnique } : null;
}

public record RejectActionRequest(
    [property: JsonPropertyName("reason")] string Reason
);

public record GuardrailConfigDto(
    [property: JsonPropertyName("auto_block_confirmed")] bool AutoBlockConfirmed,
    [property: JsonPropertyName("provisional_ttl_hours")] int ProvisionalTtlHours,
    [property: JsonPropertyName("safe_ips")] List<string> SafeIps
);
