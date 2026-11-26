namespace Aegis.Core.Interfaces;

public interface INetworkStatusService
{
    bool IsOnline { get; }
    string? LastError { get; }
    event EventHandler? NetworkStatusChanged;
    void SetOnline();
    void SetOffline(string error);
}
