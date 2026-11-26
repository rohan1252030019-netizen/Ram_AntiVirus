using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record QuantumReadinessSummary(
    [property: JsonPropertyName("total_algorithms_tracked")] int TotalAlgorithmsTracked,
    [property: JsonPropertyName("quantum_safe")] int QuantumSafe,
    [property: JsonPropertyName("already_vulnerable")] int AlreadyVulnerable,
    [property: JsonPropertyName("upcoming_vulnerabilities")] int UpcomingVulnerabilities,
    [property: JsonPropertyName("monitoring_active")] bool MonitoringActive,
    [property: JsonPropertyName("urgent_migrations")] int UrgentMigrations);

public record QuantumReadinessBreakdown(
    [property: JsonPropertyName("crypto_safety")] double CryptoSafety,
    [property: JsonPropertyName("urgency_penalty")] double UrgencyPenalty,
    [property: JsonPropertyName("adversarial_monitoring")] double AdversarialMonitoring,
    [property: JsonPropertyName("post_quantum_adoption")] double PostQuantumAdoption);

public record QuantumReadinessDto(
    [property: JsonPropertyName("quantum_readiness_score")] double QuantumReadinessScore,
    [property: JsonPropertyName("grade")] string Grade,
    [property: JsonPropertyName("summary")] QuantumReadinessSummary Summary,
    [property: JsonPropertyName("breakdown")] QuantumReadinessBreakdown? Breakdown,
    [property: JsonPropertyName("assessed_at")] string AssessedAt);

public record EntropyRequest(
    [property: JsonPropertyName("data_base64")] string DataBase64,
    [property: JsonPropertyName("alpha_orders")] List<double>? AlphaOrders = null);

public record RenyiEntropyDetail(
    [property: JsonPropertyName("value")] double Value,
    [property: JsonPropertyName("max_possible")] double MaxPossible = 8.0,
    [property: JsonPropertyName("normalized")] double Normalized = 0.0,
    [property: JsonPropertyName("label")] string Label = "");

public record EntropyAnalysisResult
{
    [JsonPropertyName("entropies")]
    public Dictionary<string, RenyiEntropyDetail>? Entropies { get; init; } = null;

    [JsonPropertyName("data_size_bytes")]
    public int DataSizeBytes { get; init; } = 0;

    [JsonPropertyName("unique_byte_values")]
    public int UniqueByteValues { get; init; } = 0;

    [JsonPropertyName("max_byte_values")]
    public int MaxByteValues { get; init; } = 256;

    [JsonPropertyName("byte_utilization")]
    public double ByteUtilization { get; init; } = 0.0;

    [JsonPropertyName("shannon_entropy")]
    public double? LegacyShannon { get; init; } = null;

    [JsonPropertyName("min_entropy")]
    public double? LegacyMin { get; init; } = null;

    [JsonPropertyName("classification")]
    public string? Classification { get; init; } = null;

    [JsonConstructor]
    public EntropyAnalysisResult(
        Dictionary<string, RenyiEntropyDetail>? entropies = null,
        int dataSizeBytes = 0,
        int uniqueByteValues = 0,
        int maxByteValues = 256,
        double byteUtilization = 0.0,
        double? legacyShannon = null,
        double? legacyMin = null,
        string? classification = null)
    {
        Entropies = entropies;
        DataSizeBytes = dataSizeBytes;
        UniqueByteValues = uniqueByteValues;
        MaxByteValues = maxByteValues;
        ByteUtilization = byteUtilization;
        LegacyShannon = legacyShannon;
        LegacyMin = legacyMin;
        Classification = classification;
    }

    public EntropyAnalysisResult(
        double shannonEntropy,
        double minEntropy,
        Dictionary<string, double>? renyiOrders = null,
        string? classification = null)
        : this(null, 0, 0, 256, 0.0, shannonEntropy, minEntropy, classification)
    {
    }

    [JsonIgnore]
    public double ShannonEntropy => LegacyShannon ?? (Entropies != null && Entropies.TryGetValue("1.0", out var s) ? s.Value : 0.0);

    [JsonIgnore]
    public double MinEntropy => LegacyMin ?? (Entropies != null && Entropies.TryGetValue("inf", out var m) ? m.Value : 0.0);
}
