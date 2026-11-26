namespace Aegis.Core.Models;

public record EdrEventIn(
    string Kind,
    string At,
    int? Pid = null,
    int? Ppid = null,
    string? ProcessName = null,
    string? ProcessPath = null,
    string? CommandLine = null,
    string? User = null,
    string? Target = null,
    Dictionary<string, object>? Extra = null);

public record EdrEventsIn(
    string AgentId,
    int EventsDroppedTotal,
    List<EdrEventIn> Events);

public record EdrEventsOut(
    int Accepted,
    int Dropped,
    int ChainMatches);

public record KillProcessRequest(
    int Pid,
    bool Confirm = false);

public record QuarantineFileRequest(
    string Path,
    string ExpectedSha256,
    bool Confirm = false);

public record IsolateHostRequest(
    string Reason,
    int LeaseSeconds = 3600,
    bool Confirm = false);

public record UnisolateHostRequest(
    string Reason);

public record ProcessTreeNode(
    int Pid,
    int Ppid,
    string? Name,
    string? CommandLine,
    string? Path,
    string? User,
    List<ProcessTreeNode>? Children = null);

public record RecentEdrEventDto(
    string Id,
    string? Category,
    string? Severity,
    string Title,
    Dictionary<string, object>? Details,
    string? Timestamp);
