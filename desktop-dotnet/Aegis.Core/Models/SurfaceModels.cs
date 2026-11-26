namespace Aegis.Core.Models;

public record ScanRequest(
    string Target,
    string ScanType = "full");

public record ScanResponse(
    string ScanId,
    string Target,
    string Status,
    string Message);

public record ScanDetail(
    string Id,
    string Target,
    string Type,
    string Status,
    string? StartedAt,
    string? CompletedAt,
    Dictionary<string, object>? Results,
    int AssetsFound,
    double Progress);

public record AssetOut(
    string Id,
    string? Hostname,
    string? IpAddress,
    string? AssetType,
    List<int>? Ports,
    List<string>? Technologies,
    string Status,
    double RiskScore,
    string? LastScanAt,
    int VulnerabilityCount,
    string? RiskBand = null,
    string? RiskMethod = null,
    bool RiskAiUsed = false,
    string? Exposure = null,
    double ExposureMultiplier = 1.0,
    double BaseScore = 0.0,
    double VulnTerm = 0.0,
    List<string>? RiskDrivers = null,
    List<string>? ServiceClasses = null,
    int HostWideCount = 0,
    int OwnedCount = 0);

public record VulnOut(
    string Id,
    string AssetId,
    string Title,
    string? Description,
    string Severity,
    double? CvssScore,
    string? CveId,
    string Status,
    double? AiRiskScore,
    string? Remediation,
    string? FoundAt);

public record VulnUpdate(
    string Status);

public record HardenChecklistItem(
    string Item,
    string Priority,
    string Category);

public record HardenResponse(
    string Target,
    string AssetType,
    Dictionary<string, object>? AiRecommendations,
    List<HardenChecklistItem> Checklist);
