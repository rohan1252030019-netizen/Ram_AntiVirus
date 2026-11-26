namespace Aegis.Core.Models;

public record ServiceMixIn(
    int Web,
    int Db,
    int Files,
    int Admin);

public record CampaignCreate(
    string Name,
    string Theme,
    int DecoyCount,
    ServiceMixIn ServiceMix,
    int RotationHours);

public record CampaignOut(
    string Id,
    string Name,
    string Theme,
    int DecoyCount,
    Dictionary<string, int>? ServiceMix,
    int RotationHours,
    string Status,
    string CreatedAt,
    string? DeployedAt,
    string? LastRotatedAt,
    string? StoppedAt,
    int HoneypotCount,
    int BreadcrumbCount,
    string? Error);

public record BreadcrumbHitOut(
    string Id,
    string CampaignId,
    string BreadcrumbUuid,
    string PlantedIn,
    string BaitKind,
    int HitCount,
    string? LastHitAt,
    string? LastHitSource,
    string PlantedAt);

public record ThemeOut(
    string Name,
    string Label,
    string Description,
    string Industry,
    List<string> BaitKinds);
