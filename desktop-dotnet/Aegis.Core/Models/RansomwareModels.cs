using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record RansomwareStatsDto
{
    [JsonPropertyName("rules_active")]
    public int RulesActive { get; init; } = 15;

    [JsonPropertyName("raas_groups_tracked")]
    public int RaasGroupsTracked { get; init; } = 5;

    [JsonPropertyName("triggers_24h")]
    public int Triggers24H { get; init; } = 2;

    [JsonIgnore]
    public int TotalEvents { get; init; } = 0;

    [JsonIgnore]
    public int ActiveIncidents { get; init; } = 0;

    [JsonIgnore]
    public int CanaryFilesTripped { get; init; } = 0;

    [JsonIgnore]
    public int ShadowCopiesDeleted { get; init; } = 0;

    [JsonIgnore]
    public int MassEncryptionEvents { get; init; } = 0;

    [JsonIgnore]
    public int ActiveAlerts { get; init; } = 0;

    [JsonConstructor]
    public RansomwareStatsDto(
        int rulesActive = 15,
        int raasGroupsTracked = 5,
        int triggers24H = 2,
        int totalEvents = 0,
        int activeIncidents = 0,
        int canaryFilesTripped = 0,
        int shadowCopiesDeleted = 0,
        int massEncryptionEvents = 0,
        int activeAlerts = 0)
    {
        RulesActive = rulesActive;
        RaasGroupsTracked = raasGroupsTracked;
        Triggers24H = triggers24H;
        TotalEvents = totalEvents;
        ActiveIncidents = activeIncidents;
        CanaryFilesTripped = canaryFilesTripped;
        ShadowCopiesDeleted = shadowCopiesDeleted;
        MassEncryptionEvents = massEncryptionEvents;
        ActiveAlerts = activeAlerts;
    }
}

public record RaaSGroupDto
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("activity_score")]
    public int ActivityScore { get; init; } = 0;

    [JsonIgnore]
    public string? Color { get; init; } = null;

    [JsonIgnore]
    public string RansomNotePattern { get; init; } = "";

    [JsonIgnore]
    public List<string>? TargetExtensions { get; init; } = null;

    [JsonIgnore]
    public List<string>? C2Addresses { get; init; } = null;

    [JsonIgnore]
    public List<string>? KillChainSteps { get; init; } = null;

    [JsonConstructor]
    public RaaSGroupDto(string name = "", int activityScore = 0, string? color = null, string ransomNotePattern = "", List<string>? targetExtensions = null, List<string>? c2Addresses = null, List<string>? killChainSteps = null)
    {
        Name = name;
        ActivityScore = activityScore;
        Color = color;
        RansomNotePattern = ransomNotePattern;
        TargetExtensions = targetExtensions;
        C2Addresses = c2Addresses;
        KillChainSteps = killChainSteps;
    }

    public RaaSGroupDto(string name, string ransomNotePattern, List<string> targetExtensions, List<string> c2Addresses, List<string>? killChainSteps = null)
        : this(name, 0, null, ransomNotePattern, targetExtensions, c2Addresses, killChainSteps) { }
}

public record RaaSGroupsOutDto(
    [property: JsonPropertyName("timeline")] List<Dictionary<string, object>>? Timeline = null,
    [property: JsonPropertyName("groups")] List<RaaSGroupDto>? Groups = null
);

public record SnapshotDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = "";

    [JsonPropertyName("host_id")]
    public string? HostId { get; init; } = null;

    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; init; } = null;

    [JsonPropertyName("age_hours")]
    public double AgeHours { get; init; } = 0;

    [JsonPropertyName("label")]
    public string? Label { get; init; } = null;

    [JsonPropertyName("provider")]
    public string? Provider { get; init; } = null;

    [JsonIgnore]
    public string? Hostname { get; init; } = null;

    [JsonIgnore]
    public string? Mechanism { get; init; } = null;

    [JsonIgnore]
    public string? SnapshotRef { get; init; } = null;

    [JsonIgnore]
    public long SizeBytes { get; init; } = 0;

    [JsonConstructor]
    public SnapshotDto(string id = "", string? hostId = null, string? createdAt = null, double ageHours = 0, string? label = null, string? provider = null, string? hostname = null, string? mechanism = null, string? snapshotRef = null, long sizeBytes = 0)
    {
        Id = id;
        HostId = hostId;
        CreatedAt = createdAt;
        AgeHours = ageHours;
        Label = label;
        Provider = provider;
        Hostname = hostname;
        Mechanism = mechanism;
        SnapshotRef = snapshotRef;
        SizeBytes = sizeBytes;
    }

    public SnapshotDto(string id, string hostname, DateTime createdAt, string mechanism, string snapshotRef, long sizeBytes)
        : this(id, hostname, createdAt.ToString("o"), 0, null, mechanism, hostname, mechanism, snapshotRef, sizeBytes) { }
}

public record DecryptorDto(
    [property: JsonPropertyName("name")] string Name = "",
    [property: JsonPropertyName("source_url")] string SourceUrl = "",
    [property: JsonPropertyName("supported_groups")] List<string>? SupportedGroups = null,
    [property: JsonPropertyName("file_extensions")] List<string>? FileExtensions = null,
    [property: JsonPropertyName("ransom_notes")] List<string>? RansomNotes = null,
    [property: JsonIgnore] string MalwareFamily = "",
    [property: JsonIgnore] string DecryptorUrl = "",
    [property: JsonIgnore] string Author = "",
    [property: JsonIgnore] string Notes = "",
    [property: JsonIgnore] string Algorithm = "",
    [property: JsonIgnore] bool Verified = true
);

public record RecoveryOptionsDto(
    [property: JsonPropertyName("event_id")] string EventId,
    [property: JsonPropertyName("snapshots")] List<SnapshotDto> Snapshots,
    [property: JsonPropertyName("decryptors")] List<DecryptorDto> Decryptors,
    [property: JsonPropertyName("host_id")] string? HostId = null
);

public record RestoreRequest(
    [property: JsonPropertyName("host_id")] string HostId,
    [property: JsonPropertyName("snapshot_id")] string SnapshotId,
    [property: JsonPropertyName("target_path")] string TargetPath = "C:\\"
);

public record RestoreJobOut(
    [property: JsonPropertyName("job_id")] string JobId,
    [property: JsonPropertyName("host_id")] string HostId,
    [property: JsonPropertyName("snapshot_id")] string SnapshotId,
    [property: JsonPropertyName("target_path")] string TargetPath,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("started_at")] string StartedAt,
    [property: JsonPropertyName("error")] string? Error = null
);
