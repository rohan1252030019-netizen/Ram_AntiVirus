using Aegis.Core.Interfaces;

namespace Aegis.Services;

public class NetworkStatusService : INetworkStatusService
{
    public bool IsOnline { get; private set; } = true;
    public string? LastError { get; private set; }

    public event EventHandler? NetworkStatusChanged;

    public void SetOnline()
    {
        if (!IsOnline || LastError != null)
        {
            IsOnline = true;
            LastError = null;
            NetworkStatusChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public void SetOffline(string error)
    {
        if (IsOnline || LastError != error)
        {
            IsOnline = false;
            LastError = error;
            NetworkStatusChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}
