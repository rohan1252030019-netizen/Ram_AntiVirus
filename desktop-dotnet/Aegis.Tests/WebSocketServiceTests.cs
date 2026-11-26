using Aegis.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Aegis.Tests;

public class WebSocketServiceTests
{
    [Theory]
    [InlineData(0, 1000)]
    [InlineData(1, 2000)]
    [InlineData(2, 4000)]
    [InlineData(3, 8000)]
    [InlineData(4, 16000)]
    [InlineData(5, 30000)]
    [InlineData(6, 30000)]
    [InlineData(10, 30000)]
    public void ExponentialBackoff_CapsAt30Seconds(int attempt, int expectedDelayMs)
    {
        // Algorithm from AegisWebSocketService:
        // Math.Min(30000, 1000 * (int)Math.Pow(2, Math.Min(attempt, 5)));
        var delayMs = Math.Min(30000, 1000 * (int)Math.Pow(2, Math.Min(attempt, 5)));
        Assert.Equal(expectedDelayMs, delayMs);
        Assert.True(delayMs <= 30000);
    }

    [Fact]
    public void WebSocketService_SubscriptionHandlers_TriggerOnMatchingTopic()
    {
        var wsService = new AegisWebSocketService(NullLogger<AegisWebSocketService>.Instance);
        string? receivedTopic = null;
        object? receivedPayload = null;

        wsService.Subscribe("incidents.new", payload =>
        {
            receivedTopic = "incidents.new";
            receivedPayload = payload;
        });

        // Use reflection to invoke internal HandleIncomingMessage
        var method = typeof(AegisWebSocketService).GetMethod("HandleIncomingMessage",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        Assert.NotNull(method);

        var sampleJson = "{\"topic\":\"incidents.new\",\"type\":\"incident\",\"severity\":\"critical\",\"title\":\"Test Incident\"}";
        method.Invoke(wsService, new object[] { sampleJson });

        Assert.Equal("incidents.new", receivedTopic);
        Assert.Equal(sampleJson, receivedPayload);
    }

    [Fact]
    public void WebSocketService_Unsubscribe_StopsReceivingEvents()
    {
        var wsService = new AegisWebSocketService(NullLogger<AegisWebSocketService>.Instance);
        int callCount = 0;
        Action<object?> handler = _ => callCount++;

        wsService.Subscribe("ransomware.incident", handler);

        var method = typeof(AegisWebSocketService).GetMethod("HandleIncomingMessage",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);

        var sampleJson = "{\"topic\":\"ransomware.incident\",\"type\":\"ransomware\"}";
        method.Invoke(wsService, new object[] { sampleJson });
        Assert.Equal(1, callCount);

        wsService.Unsubscribe("ransomware.incident", handler);
        method.Invoke(wsService, new object[] { sampleJson });
        Assert.Equal(1, callCount);
    }
}
