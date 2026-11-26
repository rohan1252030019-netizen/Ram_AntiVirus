using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record FirewallRuleDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = "";

    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    [JsonPropertyName("yaml_def")]
    public string YamlDef { get; init; } = "";

    [JsonPropertyName("priority")]
    public int Priority { get; init; } = 100;

    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; } = null;

    [JsonPropertyName("hits")]
    public int Hits { get; init; } = 0;

    [JsonPropertyName("last_hit_at")]
    public DateTime? LastHitAt { get; init; } = null;

    [JsonPropertyName("created_at")]
    public DateTime? CreatedAt { get; init; } = null;

    [JsonPropertyName("updated_at")]
    public DateTime? UpdatedAt { get; init; } = null;

    [JsonConstructor]
    public FirewallRuleDto(
        string id = "",
        string name = "",
        bool enabled = true,
        string yamlDef = "",
        int priority = 100,
        string? clientId = null,
        int hits = 0,
        DateTime? lastHitAt = null,
        DateTime? createdAt = null,
        DateTime? updatedAt = null)
    {
        Id = id;
        Name = name;
        Enabled = enabled;
        YamlDef = yamlDef;
        Priority = priority;
        ClientId = clientId;
        Hits = hits;
        LastHitAt = lastHitAt;
        CreatedAt = createdAt;
        UpdatedAt = updatedAt;
    }

    public FirewallRuleDto(
        string id,
        string name,
        bool enabled,
        int priority,
        string yamlDef,
        DateTime? createdAt = null)
        : this(id, name, enabled, yamlDef, priority, null, 0, null, createdAt, createdAt)
    {
    }
}

public record FirewallRuleCreateRequest(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("priority")] int Priority,
    [property: JsonPropertyName("yaml_def")] string YamlDef
);

public record BlockedIpItem(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("source")] string Source = "local",
    [property: JsonPropertyName("added_at")] DateTime? AddedAt = null
);

public record BlockedIpDto(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("reason")] string Reason = "blocked",
    [property: JsonPropertyName("blocked_at")] DateTime? BlockedAt = null,
    [property: JsonPropertyName("expires_at")] DateTime? ExpiresAt = null,
    [property: JsonPropertyName("is_provisional")] bool IsProvisional = false
)
{
    public BlockedIpDto() : this("") { }
}

public record BlockedIpsResponse
{
    [JsonPropertyName("items")]
    public List<BlockedIpItem>? Items { get; init; } = null;

    [JsonPropertyName("count")]
    public int Count { get; init; } = 0;

    [JsonPropertyName("pi_reachable")]
    public bool PiReachable { get; init; } = false;

    [JsonPropertyName("local_path")]
    public string? LocalPath { get; init; } = null;

    [JsonIgnore]
    public List<BlockedIpDto>? LegacyBlockedIps { get; init; } = null;

    [JsonIgnore]
    public int? LegacyTotal { get; init; } = null;

    [JsonConstructor]
    public BlockedIpsResponse(
        List<BlockedIpItem>? items = null,
        int count = 0,
        bool piReachable = false,
        string? localPath = null)
    {
        Items = items;
        Count = count;
        PiReachable = piReachable;
        LocalPath = localPath;
    }

    public BlockedIpsResponse(List<BlockedIpDto> blockedIps, int total)
        : this(null, total, false, null)
    {
        LegacyBlockedIps = blockedIps;
        LegacyTotal = total;
    }

    [JsonIgnore]
    public List<BlockedIpDto> BlockedIps =>
        LegacyBlockedIps ??
        (Items != null ? Items.Select(i => new BlockedIpDto(i.Ip, i.Source, i.AddedAt)).ToList() : new List<BlockedIpDto>());

    [JsonIgnore]
    public int Total => LegacyTotal ?? Count;
}

public record FirewallStatsDto(
    [property: JsonPropertyName("total_rules")] int TotalRules,
    [property: JsonPropertyName("active_rules")] int ActiveRules,
    [property: JsonPropertyName("blocked_ips_count")] int BlockedIpsCount,
    [property: JsonPropertyName("provisional_blocks_count")] int ProvisionalBlocksCount,
    [property: JsonPropertyName("packets_evaluated")] long PacketsEvaluated,
    [property: JsonPropertyName("drops_today")] int DropsToday
);
