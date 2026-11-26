using System.Text.Json.Serialization;
using Aegis.Core.Enums;

namespace Aegis.Core.Models;

public record TelemetryEventDto(
    [property: JsonPropertyName("event_id")] string EventId,
    [property: JsonPropertyName("event_type")] string EventType,
    [property: JsonPropertyName("hostname")] string Hostname,
    [property: JsonPropertyName("pid")] int Pid,
    [property: JsonPropertyName("process_name")] string ProcessName,
    [property: JsonPropertyName("command_line")] string CommandLine,
    [property: JsonPropertyName("user")] string User,
    [property: JsonPropertyName("timestamp")] DateTime Timestamp,
    [property: JsonPropertyName("severity")] Severity Severity = Severity.Low,
    [property: JsonPropertyName("is_threat")] bool IsThreat = false,
    [property: JsonPropertyName("rule_name")] string? RuleName = null,
    [property: JsonPropertyName("action_taken")] string? ActionTaken = null
);

public record WSMessage(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("topic")] string? Topic = null,
    [property: JsonPropertyName("data")] object? Data = null,
    [property: JsonPropertyName("timestamp")] string? Timestamp = null,
    [property: JsonPropertyName("severity")] string? Severity = null
);
