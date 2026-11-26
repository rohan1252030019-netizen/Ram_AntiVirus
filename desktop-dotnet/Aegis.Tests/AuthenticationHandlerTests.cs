using System.Net;
using System.Net.Http;
using Aegis.Core.Exceptions;
using Aegis.Core.Interfaces;
using Aegis.Services;
using Aegis.Services.Handlers;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Aegis.Tests;

public class AuthenticationHandlerTests
{
    private class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
        public int CallCount { get; private set; }

        public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(_handler(request));
        }
    }

    [Fact]
    public async Task SendAsync_On401Unauthorized_NotifiesSessionExpired_AndThrowsAegisUnauthorizedException()
    {
        // Arrange
        var mockAuth = new Mock<IAuthService>();
        mockAuth.SetupGet(a => a.CurrentToken).Returns("test_token_123");

        var mockNetwork = new Mock<INetworkStatusService>();

        var innerHandler = new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));

        var authHandler = new AegisAuthenticationHandler(mockAuth.Object, mockNetwork.Object, NullLogger<AegisAuthenticationHandler>.Instance)
        {
            InnerHandler = innerHandler
        };

        using var client = new HttpClient(authHandler) { BaseAddress = new Uri("http://localhost:8000") };

        // Act & Assert
        await Assert.ThrowsAsync<AegisUnauthorizedException>(() => client.GetAsync("/api/v1/dashboard/overview"));
        mockAuth.Verify(a => a.NotifySessionExpired(), Times.Once);
    }

    [Fact]
    public async Task SendAsync_On403Forbidden_ThrowsAegisForbiddenException()
    {
        // Arrange
        var mockAuth = new Mock<IAuthService>();
        mockAuth.SetupGet(a => a.CurrentToken).Returns("test_token_123");

        var mockNetwork = new Mock<INetworkStatusService>();

        var innerHandler = new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden));

        var authHandler = new AegisAuthenticationHandler(mockAuth.Object, mockNetwork.Object, NullLogger<AegisAuthenticationHandler>.Instance)
        {
            InnerHandler = innerHandler
        };

        using var client = new HttpClient(authHandler) { BaseAddress = new Uri("http://localhost:8000") };

        // Act & Assert
        await Assert.ThrowsAsync<AegisForbiddenException>(() => client.PostAsync("/api/v1/edr/kill-process", new StringContent("{}")));
        mockAuth.Verify(a => a.NotifySessionExpired(), Times.Never);
    }

    [Fact]
    public async Task SendAsync_OnGet503_RetriesUpToMaxAttempts()
    {
        // Arrange
        var mockAuth = new Mock<IAuthService>();
        var mockNetwork = new Mock<INetworkStatusService>();

        int attempts = 0;
        var innerHandler = new MockHttpMessageHandler(_ =>
        {
            attempts++;
            if (attempts < 3)
            {
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
        });

        var authHandler = new AegisAuthenticationHandler(mockAuth.Object, mockNetwork.Object, NullLogger<AegisAuthenticationHandler>.Instance)
        {
            InnerHandler = innerHandler
        };

        using var client = new HttpClient(authHandler) { BaseAddress = new Uri("http://localhost:8000") };

        // Act
        var response = await client.GetAsync("/api/v1/dashboard/overview");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, innerHandler.CallCount);
    }

    [Fact]
    public async Task SendAsync_OnPost503_NeverRetries()
    {
        // Arrange
        var mockAuth = new Mock<IAuthService>();
        var mockNetwork = new Mock<INetworkStatusService>();

        var innerHandler = new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        var authHandler = new AegisAuthenticationHandler(mockAuth.Object, mockNetwork.Object, NullLogger<AegisAuthenticationHandler>.Instance)
        {
            InnerHandler = innerHandler
        };

        using var client = new HttpClient(authHandler) { BaseAddress = new Uri("http://localhost:8000") };

        // Act
        var response = await client.PostAsync("/api/v1/ransomware/restore", new StringContent("{}"));

        // Assert: POST is non-idempotent, must only execute once
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, innerHandler.CallCount);
    }
}
