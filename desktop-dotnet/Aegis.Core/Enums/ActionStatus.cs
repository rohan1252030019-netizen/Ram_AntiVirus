namespace Aegis.Core.Enums;

public enum ActionStatus
{
    Pending,
    Approved,
    Rejected,
    Executed,
    Failed,
    Skipped
}

public enum ActionType
{
    BlockIp,
    IsolateHost,
    KillProcess,
    QuarantineFile,
    SnapshotRestore,
    Custom
}
