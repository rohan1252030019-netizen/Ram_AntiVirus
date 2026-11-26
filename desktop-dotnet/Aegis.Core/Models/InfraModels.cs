using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record PM2ProcessDto(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("cpu")] double Cpu = 0,
    [property: JsonPropertyName("mem")] string Mem = "0MB",
    [property: JsonPropertyName("uptime")] string Uptime = "—",
    [property: JsonPropertyName("restarts")] int Restarts = 0
);

public record SystemInfoDto(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("cpu")] double Cpu,
    [property: JsonPropertyName("mem")] double Mem,
    [property: JsonPropertyName("disk")] double Disk,
    [property: JsonPropertyName("uptime")] string Uptime,
    [property: JsonPropertyName("services")] List<string>? Services = null,
    [property: JsonPropertyName("pm2_processes")] List<PM2ProcessDto>? Pm2Processes = null,
    [property: JsonPropertyName("node_type")] string? NodeType = null,
    [property: JsonPropertyName("agent_id")] string? AgentId = null,
    [property: JsonPropertyName("os")] string? Os = null
);

public record SystemsResponse(
    [property: JsonPropertyName("systems")] List<SystemInfoDto> Systems
);
