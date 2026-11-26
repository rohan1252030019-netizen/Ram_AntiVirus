using System.Net;
using System.Net.Http.Headers;
using Aegis.Core.Exceptions;
using Aegis.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace Aegis.Services.Handlers;

public class AegisAuthenticationHandler : DelegatingHandler
{
    private readonly IAuthService _authService;
    private readonly INetworkStatusService _networkStatus;
    private readonly ILogger<AegisAuthenticationHandler> _logger;
    private const int MaxGetRetries = 2;

    public AegisAuthenticationHandler(
        IAuthService authService,
        INetworkStatusService networkStatus,
        ILogger<AegisAuthenticationHandler> logger)
    {
        _authService = authService;
        _networkStatus = networkStatus;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // 1. Attach authorization header if available and not already set
        if (!string.IsNullOrEmpty(_authService.CurrentToken) && request.Headers.Authorization == null)
        {
            if (_authService.CurrentToken.StartsWith("aegis_") || _authService.CurrentToken.StartsWith("key_"))
            {
                if (!request.Headers.Contains("X-API-Key"))
                    request.Headers.Add("X-API-Key", _authService.CurrentToken);
            }
            else
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _authService.CurrentToken);
            }
        }

        bool isIdempotentGet = request.Method == HttpMethod.Get;
        int attempts = 0;

        while (true)
        {
            attempts++;
            try
            {
                var response = await base.SendAsync(request, cancellationToken);
                _networkStatus.SetOnline();

                // 2. Centralized 401 handling
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    _logger.LogWarning("HTTP 401 Unauthorized received. Session expired or invalid. Navigating to LoginView.");
                    _authService.NotifySessionExpired();
                    throw new AegisUnauthorizedException("Session expired or invalid. Please log in again.");
                }

                // 3. Centralized 403 handling
                if (response.StatusCode == HttpStatusCode.Forbidden)
                {
                    _logger.LogWarning("HTTP 403 Forbidden received for path {Path}. Role unauthorized.", request.RequestUri?.AbsolutePath);
                    throw new AegisForbiddenException("Access denied: your role is not permitted to perform this action.");
                }

                // Retry for idempotent GET on 502/503/504
                if (isIdempotentGet && attempts <= MaxGetRetries &&
                    (response.StatusCode == HttpStatusCode.BadGateway ||
                     response.StatusCode == HttpStatusCode.ServiceUnavailable ||
                     response.StatusCode == HttpStatusCode.GatewayTimeout))
                {
                    _logger.LogWarning("Transient {StatusCode} on GET {Uri}. Retry attempt {Attempt} of {Max}",
                        response.StatusCode, request.RequestUri, attempts, MaxGetRetries);
                    await Task.Delay(250 * attempts, cancellationToken);
                    continue;
                }

                return response;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogWarning(ex, "HttpRequestException on {Method} {Uri} (attempt {Attempt})",
                    request.Method, request.RequestUri, attempts);

                if (isIdempotentGet && attempts <= MaxGetRetries)
                {
                    await Task.Delay(250 * attempts, cancellationToken);
                    continue;
                }

                _networkStatus.SetOffline(ex.Message);
                throw new AegisNetworkException($"Network connection failed while calling {request.RequestUri?.AbsolutePath}: {ex.Message}", ex);
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                // Timeout
                _logger.LogWarning(ex, "Timeout on {Method} {Uri} (attempt {Attempt})", request.Method, request.RequestUri, attempts);

                if (isIdempotentGet && attempts <= MaxGetRetries)
                {
                    await Task.Delay(250 * attempts, cancellationToken);
                    continue;
                }

                _networkStatus.SetOffline("Request timed out");
                throw new AegisNetworkException($"Request to {request.RequestUri?.AbsolutePath} timed out.", ex);
            }
        }
    }
}
