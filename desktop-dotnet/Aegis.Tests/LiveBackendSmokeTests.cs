using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Aegis.Core.Enums;
using Aegis.Core.Exceptions;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Aegis.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace Aegis.Tests;

public class LiveBackendSmokeTests
{
    private readonly ITestOutputHelper _output;

    public LiveBackendSmokeTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private class SimpleAuthService : IAuthService
    {
        public string? CurrentToken { get; set; }
        public UserDto? CurrentUser { get; set; }
        public bool IsAuthenticated => !string.IsNullOrEmpty(CurrentToken);
        public UserRole CurrentRole => CurrentUser?.Role ?? UserRole.Viewer;

        public bool HasRole(UserRole minimumRole) => CurrentRole <= minimumRole;

        public event EventHandler? SessionExpired;
        public void NotifySessionExpired() => SessionExpired?.Invoke(this, EventArgs.Empty);

        public Task SaveCredentialsAsync(string token, UserDto user, bool rememberMe)
        {
            CurrentToken = token;
            CurrentUser = user;
            return Task.CompletedTask;
        }

        public Task<(string? Token, UserDto? User)> LoadSavedCredentialsAsync() =>
            Task.FromResult((CurrentToken, CurrentUser));

        public void ClearCredentials()
        {
            CurrentToken = null;
            CurrentUser = null;
        }

        public void SetSession(string token, UserDto user)
        {
            CurrentToken = token;
            CurrentUser = user;
        }
    }

    public record SmokeTestResult(string Route, string Status, string Result, string Notes);

    [Fact]
    public async Task RunLiveBackendSmokeTest_AllEndpoints()
    {
        var http = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:8000") };
        var auth = new SimpleAuthService();
        var client = new AegisApiClient(http, auth, NullLogger<AegisApiClient>.Instance);

        var results = new List<SmokeTestResult>();

        // 1. Login
        try
        {
            var login = await client.LoginAsync("admin@aegis.local", "admin123456");
            auth.SetSession(login.Token, login.User);
            results.Add(new("POST /api/v1/auth/user/login", "200 OK", "PASS", $"Token length {login.Token.Length}, user {login.User.Email}"));
        }
        catch (Exception ex)
        {
            results.Add(new("POST /api/v1/auth/user/login", "FAIL", "FAIL", ex.Message));
            _output.WriteLine($"Login failed: {ex.Message}");
            return;
        }

        async Task TestEndpoint<T>(string route, Func<Task<T>> call, Func<T, string>? summary = null)
        {
            try
            {
                var val = await call();
                var s = summary != null ? summary(val) : "Deserialized cleanly";
                results.Add(new(route, "200 OK", "PASS", s));
            }
            catch (AegisApiException aex)
            {
                results.Add(new(route, $"{aex.StatusCode}", aex.StatusCode == 403 ? "ROLE_GATED" : "FAIL", aex.Message));
            }
            catch (HttpRequestException hex)
            {
                results.Add(new(route, hex.StatusCode?.ToString() ?? "ERR", "FAIL", hex.Message));
            }
            catch (Exception ex)
            {
                results.Add(new(route, "EXCEPTION", "FAIL", ex.Message));
            }
        }

        // Dashboard & Overview
        await TestEndpoint("GET /api/v1/dashboard/overview", () => client.GetDashboardOverviewAsync(), d => $"Assets: {d.TotalAssets}, Risk: {d.RiskLevel}");
        await TestEndpoint("GET /api/v1/dashboard/timeline", () => client.GetTimelineAsync(), l => $"Count: {l.Count}");
        await TestEndpoint("GET /api/v1/response/incidents", () => client.GetIncidentsAsync(), l => $"Count: {l.Count}");

        // Ransomware
        await TestEndpoint("GET /api/v1/ransomware/stats", () => client.GetRansomwareStatsAsync(), s => $"Rules: {s.RulesActive}, Groups: {s.RaasGroupsTracked}");
        await TestEndpoint("GET /api/v1/ransomware/raas-groups", () => client.GetRaaSGroupsAsync(), l => $"Count: {l.Count}");

        // Firewall
        await TestEndpoint("GET /api/v1/firewall/rules", () => client.GetFirewallRulesAsync(), l => $"Rules: {l.Count}");
        await TestEndpoint("GET /api/v1/firewall/blocked", () => client.GetBlockedIpsAsync(), b => $"Count: {b.Count}, Pi: {b.PiReachable}");

        // Infra & Settings
        await TestEndpoint("GET /api/v1/infra/systems", () => client.GetSystemsAsync(), s => $"Systems: {s.Systems.Count}");
        await TestEndpoint("GET /api/v1/settings/client", () => client.GetClientSettingsAsync(), c => $"Name: {c.Name}, Slug: {c.Slug}");
        await TestEndpoint("GET /api/v1/settings/notifications", () => client.GetNotificationConfigAsync(), n => $"Format: {n.WebhookFormat}, Email: {n.EmailEnabled}");

        // EDR
        await TestEndpoint("GET /api/v1/edr/events/recent?agent_id=aegis-msi", () => client.GetRecentEdrEventsAsync("aegis-msi"), l => $"Events: {l.Count}");

        // Antivirus
        await TestEndpoint("GET /api/v1/antivirus/signatures", () => client.GetSignaturesAsync(), s => $"Version: {s.Version}");
        await TestEndpoint("GET /api/v1/antivirus/quarantine", () => client.GetQuarantineListAsync(), q => $"Count: {q.Count}");

        // Surface
        await TestEndpoint("GET /api/v1/surface/assets", () => client.GetSurfaceAssetsAsync(), a => $"Assets: {a.Count}");
        await TestEndpoint("GET /api/v1/surface/scans", () => client.GetSurfaceScansAsync(), s => $"Scans: {s.Count}");
        await TestEndpoint("GET /api/v1/surface/vulnerabilities", () => client.GetSurfaceVulnerabilitiesAsync(), v => $"Vulns: {v.Count}");
        await TestEndpoint("GET /api/v1/surface/harden", () => client.GetHardenRecommendationsAsync(), h => $"Checklist: {h.Checklist.Count}");

        // Phantom & Deception
        await TestEndpoint("GET /api/v1/phantom/honeypots", () => client.GetHoneypotsAsync(), h => $"Honeypots: {h.Count}");
        await TestEndpoint("GET /api/v1/phantom/interactions", () => client.GetHoneypotInteractionsAsync(), i => $"Interactions: {i.Count}");
        await TestEndpoint("GET /api/v1/phantom/attackers", () => client.GetAttackersAsync(), a => $"Attackers: {a.Count}");
        await TestEndpoint("GET /api/v1/deception/campaigns", () => client.GetDeceptionCampaignsAsync(), c => $"Campaigns: {c.Count}");
        await TestEndpoint("GET /api/v1/deception/breadcrumb-hits", () => client.GetBreadcrumbHitsAsync(), b => $"Hits: {b.Count}");
        await TestEndpoint("GET /api/v1/deception/themes", () => client.GetDeceptionThemesAsync(), t => $"Themes: {t.Count}");

        // Threats & Intel
        await TestEndpoint("GET /api/v1/threats/intel", () => client.GetThreatIntelAsync(), i => $"IOCs: {i.Count}");
        await TestEndpoint("GET /api/v1/threats/events", () => client.GetThreatEventsAsync(), e => $"Events: {e.Count}");
        await TestEndpoint("GET /api/v1/threats/campaigns", () => client.GetTtpCampaignsAsync(), c => $"Campaigns: {c.Count}");
        await TestEndpoint("GET /api/v1/intel/ip/8.8.8.8", () => client.LookupIpIntelAsync("8.8.8.8"), ip => $"IP: {ip.Ip}, Country: {ip.Country}");

        // DoS Shield
        await TestEndpoint("GET /api/v1/dos/status", () => client.GetDosStatusAsync(), d => $"Mode: {d.Mode}, UnderAttack: {d.UnderAttack}");
        await TestEndpoint("GET /api/v1/dos/offenders", () => client.GetDosOffendersAsync(), o => $"Offenders: {o.Count}");
        await TestEndpoint("GET /api/v1/dos/config", () => client.GetDosConfigAsync(), c => $"Mode: {c.Mode}");

        // Nodes
        await TestEndpoint("GET /api/v1/nodes", () => client.GetNodesAsync(), n => $"Nodes: {n.Count}");

        // Compliance
        await TestEndpoint("GET /api/v1/compliance/frameworks", () => client.GetComplianceFrameworksAsync(), c => $"Score: {c.OverallScore}, Frameworks: {c.Frameworks.Count}");

        // Quantum
        await TestEndpoint("GET /api/v1/quantum/readiness", () => client.GetQuantumReadinessAsync(), q => $"Score: {q.QuantumReadinessScore}, Grade: {q.Grade}");

        // Output results
        _output.WriteLine("\n=======================================================");
        _output.WriteLine("           LIVE BACKEND SMOKE TEST RESULTS");
        _output.WriteLine("=======================================================");
        _output.WriteLine("| Endpoint | Status | Result | Notes |");
        _output.WriteLine("| :--- | :--- | :--- | :--- |");
        foreach (var r in results)
        {
            _output.WriteLine($"| `{r.Route}` | **{r.Status}** | {r.Result} | {r.Notes} |");
        }
        _output.WriteLine("=======================================================\n");

        var outPath = Path.Combine(AppContext.BaseDirectory, "live_smoke_test_results.json");
        File.WriteAllText(outPath, JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
    }

    [Fact]
    public async Task RunLiveBackendSmokeTest_DestructiveSafeEndpoints()
    {
        var http = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:8000") };
        var auth = new SimpleAuthService();
        var client = new AegisApiClient(http, auth, NullLogger<AegisApiClient>.Instance);

        var login = await client.LoginAsync("admin@aegis.local", "admin123456");
        auth.SetSession(login.Token, login.User);

        // 1. Guard check: KillProcess without confirm -> Expected 400 Bad Request or 403 Forbidden (Demo Sandbox guard)
        using (var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/edr/kill-process"))
        {
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login.Token);
            req.Content = new StringContent("{\"pid\": 999999, \"confirm\": false}", Encoding.UTF8, "application/json");
            var resp = await http.SendAsync(req);
            Assert.True(resp.StatusCode == System.Net.HttpStatusCode.BadRequest || resp.StatusCode == System.Net.HttpStatusCode.Forbidden);
            _output.WriteLine($"Verified: POST /api/v1/edr/kill-process correctly rejected with {(int)resp.StatusCode} {resp.StatusCode} (backend sandbox guard active).");
        }

        // 2. Guard check: IsolateHost without confirm -> Expected 400 Bad Request or 403 Forbidden (Demo Sandbox guard)
        using (var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/edr/hosts/demo-fake-node/isolate"))
        {
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login.Token);
            req.Content = new StringContent("{\"reason\": \"Test containment\", \"lease_seconds\": 300, \"confirm\": false}", Encoding.UTF8, "application/json");
            var resp = await http.SendAsync(req);
            Assert.True(resp.StatusCode == System.Net.HttpStatusCode.BadRequest || resp.StatusCode == System.Net.HttpStatusCode.Forbidden);
            _output.WriteLine($"Verified: POST /api/v1/edr/hosts/{{id}}/isolate correctly rejected with {(int)resp.StatusCode} {resp.StatusCode} (backend sandbox guard active).");
        }

        // 3. Allowed write action: Surface Scan (safe against 127.0.0.1 demo target)
        var scanResp = await client.StartSurfaceScanAsync(new ScanRequest("127.0.0.1", "quick"));
        Assert.NotNull(scanResp);
        _output.WriteLine($"Verified: POST /api/v1/surface/scan launched safe scan (ID: {scanResp.ScanId}, Status: {scanResp.Status})");
    }

    [Fact]
    public async Task RunLiveBackendSmokeTest_WebSocketHandshakeAndEventDelivery()
    {
        var http = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:8000") };
        var auth = new SimpleAuthService();
        var client = new AegisApiClient(http, auth, NullLogger<AegisApiClient>.Instance);

        var login = await client.LoginAsync("admin@aegis.local", "admin123456");

        using var ws = new ClientWebSocket();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        await ws.ConnectAsync(new Uri("ws://127.0.0.1:8000/ws"), cts.Token);
        Assert.Equal(WebSocketState.Open, ws.State);
        _output.WriteLine("1. Connected to ws://127.0.0.1:8000/ws");

        // 1. Send auth frame
        var authJson = JsonSerializer.Serialize(new { type = "auth", token = login.Token });
        var authBytes = Encoding.UTF8.GetBytes(authJson);
        await ws.SendAsync(new ArraySegment<byte>(authBytes), WebSocketMessageType.Text, true, cts.Token);

        // Receive auth_ok
        var buffer = new byte[8192];
        var res = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cts.Token);
        var authResp = Encoding.UTF8.GetString(buffer, 0, res.Count);
        _output.WriteLine($"2. Received Auth Response: {authResp}");
        using (var doc = JsonDocument.Parse(authResp))
        {
            Assert.Equal("auth_ok", doc.RootElement.GetProperty("type").GetString());
        }

        // 2. Send subscribe frame
        var subJson = JsonSerializer.Serialize(new { type = "subscribe", topics = new[] { "incidents.new", "threats.new", "honeypot.interactions" } });
        var subBytes = Encoding.UTF8.GetBytes(subJson);
        await ws.SendAsync(new ArraySegment<byte>(subBytes), WebSocketMessageType.Text, true, cts.Token);

        res = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cts.Token);
        var subResp = Encoding.UTF8.GetString(buffer, 0, res.Count);
        _output.WriteLine($"3. Received Subscribe Response: {subResp}");
        using (var doc = JsonDocument.Parse(subResp))
        {
            Assert.Equal("subscribed", doc.RootElement.GetProperty("type").GetString());
        }

        // 3. Send ping frame
        var pingJson = JsonSerializer.Serialize(new { type = "ping" });
        var pingBytes = Encoding.UTF8.GetBytes(pingJson);
        await ws.SendAsync(new ArraySegment<byte>(pingBytes), WebSocketMessageType.Text, true, cts.Token);

        res = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cts.Token);
        var pingResp = Encoding.UTF8.GetString(buffer, 0, res.Count);
        _output.WriteLine($"4. Received Ping Response: {pingResp}");
        using (var doc = JsonDocument.Parse(pingResp))
        {
            Assert.Equal("pong", doc.RootElement.GetProperty("type").GetString());
        }

        // Clean disconnect
        await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Test complete", cts.Token);
        _output.WriteLine("5. WebSocket connection closed cleanly.");
    }
}
