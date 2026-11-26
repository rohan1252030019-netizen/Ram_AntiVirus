namespace Aegis.Core.Models;

public record HoneypotCreate(
    string Name,
    string HoneypotType,
    Dictionary<string, object> Config);

public record HoneypotOut(
    string Id,
    string Name,
    string HoneypotType,
    Dictionary<string, object> Config,
    string Status,
    string? IpAddress,
    int? Port,
    string? LastRotation,
    int InteractionsCount,
    string? CreatedAt);

public record InteractionOut(
    string Id,
    string HoneypotId,
    string SourceIp,
    int? SourcePort,
    string? Protocol,
    List<string>? Commands,
    List<string>? CredentialsTried,
    int? SessionDuration,
    string? AttackerProfileId,
    string? Timestamp);

public record AttackerOut(
    string Id,
    string? SourceIp,
    List<string>? KnownIps,
    List<string>? ToolsUsed,
    List<string>? Techniques,
    string? Sophistication,
    int TotalInteractions,
    string? FirstSeen,
    string? LastSeen,
    string? AiAssessment);
