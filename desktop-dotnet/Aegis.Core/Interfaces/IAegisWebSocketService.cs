using Aegis.Core.Models;

namespace Aegis.Core.Interfaces;

public interface IAegisWebSocketService : IDisposable
{
    bool IsConnected { get; }
    event Action<bool>? ConnectionStateChanged;
    event Action<string, object?>? EventReceived;

    Task ConnectAsync(string serverUrl, string token, CancellationToken ct = default);
    Task DisconnectAsync();
    void Subscribe(string topic, Action<object?> handler);
    void Unsubscribe(string topic, Action<object?> handler);
}
