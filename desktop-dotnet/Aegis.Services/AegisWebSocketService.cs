using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;

namespace Aegis.Services;

public class AegisWebSocketService : IAegisWebSocketService
{
    private readonly ILogger<AegisWebSocketService> _logger;
    private readonly Dictionary<string, List<Action<object?>>> _topicHandlers = new();
    private readonly SynchronizationContext? _syncContext;
    private ClientWebSocket? _socket;
    private CancellationTokenSource? _cts;
    private bool _isDisposed;
    private string _currentUrl = string.Empty;
    private string _currentToken = string.Empty;

    public bool IsConnected => _socket?.State == WebSocketState.Open;
    public event Action<bool>? ConnectionStateChanged;
    public event Action<string, object?>? EventReceived;

    public AegisWebSocketService(ILogger<AegisWebSocketService> logger)
    {
        _logger = logger;
        _syncContext = SynchronizationContext.Current;
    }

    public Task ConnectAsync(string serverUrl, string token, CancellationToken ct = default)
    {
        _currentUrl = serverUrl;
        _currentToken = token;

        var wsUrl = serverUrl.TrimEnd('/');
        if (wsUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            wsUrl = "ws://" + wsUrl[7..];
        else if (wsUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            wsUrl = "wss://" + wsUrl[8..];
        if (!wsUrl.EndsWith("/ws", StringComparison.OrdinalIgnoreCase))
            wsUrl += "/ws";

        _cts?.Cancel();
        _cts = new CancellationTokenSource();

        _ = Task.Run(() => ConnectAndListenLoopAsync(wsUrl, token, _cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    private async Task ConnectAndListenLoopAsync(string wsUrl, string token, CancellationToken ct)
    {
        int attempt = 0;
        while (!ct.IsCancellationRequested && !_isDisposed)
        {
            try
            {
                _socket?.Dispose();
                _socket = new ClientWebSocket();
                _logger.LogInformation("Connecting to AEGIS WebSocket: {WsUrl}...", wsUrl);

                await _socket.ConnectAsync(new Uri(wsUrl), ct);

                // Step 1: Send authentication frame within 10s
                var authFrame = JsonSerializer.Serialize(new { type = "auth", token }, JsonOptions.Default);
                var authBytes = Encoding.UTF8.GetBytes(authFrame);
                await _socket.SendAsync(new ArraySegment<byte>(authBytes), WebSocketMessageType.Text, true, ct);

                // Wait for auth response with 10-second timeout
                using var authTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                authTimeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

                var authBuffer = new byte[4096];
                var authResult = await _socket.ReceiveAsync(new ArraySegment<byte>(authBuffer), authTimeoutCts.Token);
                var authResponseJson = Encoding.UTF8.GetString(authBuffer, 0, authResult.Count);

                using var authDoc = JsonDocument.Parse(authResponseJson);
                var authType = authDoc.RootElement.TryGetProperty("type", out var atProp) ? atProp.GetString() : string.Empty;

                if (authType == "auth_error")
                {
                    _logger.LogError("WebSocket authentication failed: received auth_error from backend.");
                    DispatchConnectionState(false);
                    await DisconnectAsync();
                    return; // Stop reconnect loop on invalid credentials
                }

                _logger.LogInformation("WebSocket authentication verified (auth_ok).");
                DispatchConnectionState(true);
                attempt = 0;

                // Step 2: Send subscription frame for core topics
                var subFrame = JsonSerializer.Serialize(new
                {
                    type = "subscribe",
                    topics = new[]
                    {
                        "incidents.new", "actions.new", "ransomware.incident",
                        "edr.events", "antivirus.detection", "honeypot.interactions",
                        "honeypot.status", "scans.completed", "nodes.status",
                        "threats.new", "threats.ioc", "dos.events"
                    }
                }, JsonOptions.Default);
                var subBytes = Encoding.UTF8.GetBytes(subFrame);
                await _socket.SendAsync(new ArraySegment<byte>(subBytes), WebSocketMessageType.Text, true, ct);

                // Step 3: Start ping loop (ping every 25s, expect pong)
                using var loopCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                _ = Task.Run(() => PingLoopAsync(_socket, loopCts.Token), loopCts.Token);

                // Step 4: Listen loop
                var buffer = new byte[32768];
                while (_socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var result = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        break;
                    }

                    if (result.MessageType == WebSocketMessageType.Text)
                    {
                        var json = Encoding.UTF8.GetString(buffer, 0, result.Count);
                        HandleIncomingMessage(json);
                    }
                }

                loopCts.Cancel();
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogWarning("WebSocket connection lost: {Message}. Reconnecting...", ex.Message);
            }

            DispatchConnectionState(false);

            if (!ct.IsCancellationRequested && !_isDisposed)
            {
                // Exponential backoff capped at 30 seconds
                var delayMs = Math.Min(30000, 1000 * (int)Math.Pow(2, Math.Min(attempt++, 5)));
                _logger.LogInformation("WebSocket reconnect in {DelayMs} ms (attempt {Attempt})...", delayMs, attempt);
                try
                {
                    await Task.Delay(delayMs, ct);
                }
                catch (TaskCanceledException) { break; }
            }
        }
    }

    private async Task PingLoopAsync(ClientWebSocket socket, CancellationToken ct)
    {
        var pingBytes = Encoding.UTF8.GetBytes("{\"type\":\"ping\"}");
        while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(25000, ct);
                if (socket.State == WebSocketState.Open)
                {
                    await socket.SendAsync(new ArraySegment<byte>(pingBytes), WebSocketMessageType.Text, true, ct);
                }
            }
            catch { break; }
        }
    }

    private void HandleIncomingMessage(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var type = root.TryGetProperty("type", out var tProp) ? tProp.GetString() : string.Empty;
            var topic = root.TryGetProperty("topic", out var topProp) ? topProp.GetString() : type;

            if (type is "auth_ok" or "pong") return;

            DispatchToUi(() =>
            {
                EventReceived?.Invoke(topic ?? "event", json);

                lock (_topicHandlers)
                {
                    if (topic != null && _topicHandlers.TryGetValue(topic, out var handlers))
                    {
                        foreach (var h in handlers.ToList())
                        {
                            try { h(json); } catch (Exception ex) { _logger.LogError(ex, "Topic handler error"); }
                        }
                    }
                    if (_topicHandlers.TryGetValue("*", out var allHandlers))
                    {
                        foreach (var h in allHandlers.ToList())
                        {
                            try { h(json); } catch (Exception ex) { _logger.LogError(ex, "Wildcard topic handler error"); }
                        }
                    }
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse incoming WS message: {Json}", json);
        }
    }

    private void DispatchConnectionState(bool isConnected)
    {
        DispatchToUi(() => ConnectionStateChanged?.Invoke(isConnected));
    }

    private void DispatchToUi(Action action)
    {
        if (_syncContext != null && _syncContext != SynchronizationContext.Current)
        {
            _syncContext.Post(_ => action(), null);
        }
        else
        {
            action();
        }
    }

    public void Subscribe(string topic, Action<object?> handler)
    {
        lock (_topicHandlers)
        {
            if (!_topicHandlers.TryGetValue(topic, out var list))
            {
                list = new List<Action<object?>>();
                _topicHandlers[topic] = list;
            }
            list.Add(handler);
        }
    }

    public void Unsubscribe(string topic, Action<object?> handler)
    {
        lock (_topicHandlers)
        {
            if (_topicHandlers.TryGetValue(topic, out var list))
            {
                list.Remove(handler);
            }
        }
    }

    public async Task DisconnectAsync()
    {
        _cts?.Cancel();
        if (_socket != null && _socket.State == WebSocketState.Open)
        {
            try
            {
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client disconnecting", CancellationToken.None);
            }
            catch { /* best effort */ }
        }
        DispatchConnectionState(false);
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        _cts?.Cancel();
        _socket?.Dispose();
        _cts?.Dispose();
    }
}
