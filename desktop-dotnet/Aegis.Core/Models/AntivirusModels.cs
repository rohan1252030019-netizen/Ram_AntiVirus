namespace Aegis.Core.Models;

public record DetectionIn(
    string AgentId,
    string Path,
    string Sha256,
    string? Rule = null,
    string Engine = "yara",
    bool Quarantined = false,
    string DetectedAt = "",
    int? FileSize = null);

public record DetectionOut(
    string Id,
    string? IncidentId,
    string Path,
    string Sha256,
    string? Rule,
    string Engine,
    bool Quarantined,
    string DetectedAt);

public record QuarantineItemDto(
    string Id,
    string AgentId,
    string Path,
    string Sha256,
    string? Rule,
    string Engine,
    int? FileSize,
    string? DetectedAt);

public record SignatureBundleDto(
    string Version,
    List<string> BadHashes,
    string? GeneratedAt = null,
    int? BadHashCount = null);

public record HashLookupDto(
    string Sha256,
    bool KnownBad,
    int LocalDetections,
    string? LastDetection);

public record ReleaseQuarantineResponse(
    bool Released,
    string DetectionId,
    string Sha256);
