namespace Aegis.Core.Models;

public record ControlOut(
    string Id,
    string Name,
    string Module,
    string Status,
    string Evidence);

public record FrameworkOut(
    string Key,
    string Name,
    string ShortName,
    string Description,
    int Score,
    int Met,
    int Partial,
    int NotMet,
    List<ControlOut> Controls);

public record ComplianceOverview(
    List<FrameworkOut> Frameworks,
    int OverallScore,
    int TotalControls,
    int TotalMet,
    int TotalPartial,
    int TotalNotMet,
    List<Dictionary<string, object>>? Gaps,
    string AssessedAt,
    string Note);
