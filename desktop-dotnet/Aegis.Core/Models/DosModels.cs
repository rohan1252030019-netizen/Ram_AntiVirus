using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record DosOffenderDto(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("rps")] double Rps,
    [property: JsonPropertyName("concurrency")] int Concurrency,
    [property: JsonPropertyName("last_reason")] string? LastReason);

public record DosStatusDto
{
    [JsonPropertyName("mode")]
    public string Mode { get; init; } = "monitor";

    [JsonPropertyName("under_attack")]
    public bool UnderAttack { get; init; } = false;

    [JsonPropertyName("global_rps")]
    public double GlobalRps { get; init; } = 0.0;

    [JsonPropertyName("global_window_s")]
    public int GlobalWindowS { get; init; } = 10;

    [JsonPropertyName("netshield_enabled")]
    public bool NetshieldEnabled { get; init; } = false;

    [JsonPropertyName("netshield_env_gate")]
    public bool NetshieldEnvGate { get; init; } = false;

    [JsonPropertyName("available")]
    public bool Available { get; init; } = true;

    [JsonPropertyName("thresholds")]
    public Dictionary<string, object>? Thresholds { get; init; } = null;

    [JsonPropertyName("counters")]
    public Dictionary<string, object>? Counters { get; init; } = null;

    [JsonPropertyName("top_offenders")]
    public List<DosOffenderDto>? TopOffenders { get; init; } = null;

    [JsonConstructor]
    public DosStatusDto(
        string mode = "monitor",
        bool underAttack = false,
        double globalRps = 0.0,
        int globalWindowS = 10,
        bool netshieldEnabled = false,
        bool netshieldEnvGate = false,
        bool available = true,
        Dictionary<string, object>? thresholds = null,
        Dictionary<string, object>? counters = null,
        List<DosOffenderDto>? topOffenders = null)
    {
        Mode = mode;
        UnderAttack = underAttack;
        GlobalRps = globalRps;
        GlobalWindowS = globalWindowS;
        NetshieldEnabled = netshieldEnabled;
        NetshieldEnvGate = netshieldEnvGate;
        Available = available;
        Thresholds = thresholds;
        Counters = counters;
        TopOffenders = topOffenders;
    }

    public DosStatusDto(
        string mode,
        bool underAttack,
        double globalRps,
        bool netshieldEnabled,
        bool available,
        List<DosOffenderDto>? topOffenders = null,
        Dictionary<string, object>? thresholds = null)
        : this(mode, underAttack, globalRps, 10, netshieldEnabled, false, available, thresholds, null, topOffenders)
    {
    }
}

public record DosConfigDto(
    [property: JsonPropertyName("thresholds")] Dictionary<string, object>? Thresholds,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("netshield_enabled")] bool NetshieldEnabled,
    [property: JsonPropertyName("netshield_env_gate")] bool NetshieldEnvGate,
    [property: JsonPropertyName("under_attack")] bool UnderAttack);
