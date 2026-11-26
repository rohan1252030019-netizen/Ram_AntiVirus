namespace Aegis.Core.Models;

public record EnrollRequest(
    string Code,
    string NodeType = "workspace");

public record EnrollResponse(
    string Status,
    string NodeId,
    string Hostname,
    string Message);

public record NodeOut(
    string Id,
    string Hostname,
    string? OsInfo,
    string? IpAddress,
    string AgentVersion,
    string Status,
    string? LastHeartbeat,
    string NodeType,
    List<string>? Tags,
    int AssetCount,
    string? CreatedAt,
    double Cpu,
    double Mem,
    double Disk,
    int Processes);

public record NodeGenerateResponse(
    string Code,
    int ExpiresInMinutes);
