using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;

namespace Aegis.Services;

public class MockAegisApiClient : IAegisApiClient
{
    private readonly List<IncidentDto> _incidents = new();
    private readonly List<FirewallRuleDto> _rules = new();
    private readonly List<BlockedIpDto> _blockedIps = new();
    private readonly List<QuarantineItemDto> _quarantine = new();
    private readonly List<HoneypotOut> _honeypots = new();
    private readonly List<CampaignOut> _campaigns = new();
    private readonly List<IOCOut> _iocs = new();
    private readonly List<NodeOut> _nodes = new();
    private ClientSettingsDto _clientSettings;
    private NotificationConfigDto _notificationConfig;

    public MockAegisApiClient()
    {
        _clientSettings = new ClientSettingsDto(
            clientId: "client_demo_001",
            name: "AEGIS Homelab Defense",
            slug: "demo",
            safeIps: new List<string> { "127.0.0.1", "192.168.1.1", "10.0.0.0/24" },
            riskThreshold: 75.0,
            aiMode: "local"
        );

        _notificationConfig = new NotificationConfigDto(
            telegramBotToken: "7123456789:AAHxxxxxx_masked_token",
            telegramChatId: "-100123456789",
            webhookUrl: "https://discord.com/api/webhooks/xxxx/masked",
            notifyCriticalOnly: true,
            enabled: true
        );

        // Seed realistic incidents
        _incidents.AddRange(new[]
        {
            new IncidentDto(
                Id: "inc_001",
                Title: "Ransomware Shadow Copy Inhibition (T1490)",
                Severity: Severity.Critical,
                Status: IncidentStatus.Open,
                SourceIp: "185.220.101.42",
                MitreTechnique: "T1490 - Inhibit System Recovery",
                DetectedAt: DateTime.UtcNow.AddMinutes(-12).ToString("o"),
                Description: "Execution of shadow copy inhibition detected on endpoint WORKSTATION-04 via spawned powershell.exe",
                Actions: new List<ResponseActionDto>
                {
                    new("act_1", "inc_001", ActionType.BlockIp, "185.220.101.42", ActionStatus.Pending, true, DateTime.UtcNow.AddMinutes(-10)),
                    new("act_2", "inc_001", ActionType.KillProcess, "PID: 4820", ActionStatus.Pending, true, DateTime.UtcNow.AddMinutes(-10))
                }
            ),
            new IncidentDto(
                Id: "inc_002",
                Title: "SSH Brute-Force Authentication Spike (T1110)",
                Severity: Severity.High,
                Status: IncidentStatus.Investigating,
                SourceIp: "45.142.120.18",
                MitreTechnique: "T1110 - Brute Force",
                DetectedAt: DateTime.UtcNow.AddHours(-1).ToString("o"),
                Description: "Over 450 failed authentication attempts on port 22 in 60 seconds from external IP 45.142.120.18",
                Actions: new List<ResponseActionDto>
                {
                    new("act_3", "inc_002", ActionType.BlockIp, "45.142.120.18", ActionStatus.Executed, false, DateTime.UtcNow.AddMinutes(-50))
                }
            ),
            new IncidentDto(
                Id: "inc_003",
                Title: "Suspicious DLL Injection Attempt (T1055)",
                Severity: Severity.Medium,
                Status: IncidentStatus.Contained,
                SourceIp: "10.0.0.15",
                MitreTechnique: "T1055 - Process Injection",
                DetectedAt: DateTime.UtcNow.AddHours(-3).ToString("o"),
                Description: "Remote thread injection detected from unknown process into svchost.exe memory space",
                Actions: new List<ResponseActionDto>()
            )
        });

        // Seed firewall rules
        _rules.AddRange(new[]
        {
            new FirewallRuleDto("fw_01", "Block Known C2 Cluster", true, 10, "action: block\nsource: 185.220.101.0/24", DateTime.UtcNow.AddDays(-2)),
            new FirewallRuleDto("fw_02", "Allow Management VPN", true, 20, "action: allow\nsource: 10.8.0.0/24", DateTime.UtcNow.AddDays(-10)),
            new FirewallRuleDto("fw_03", "Rate-limit HTTP Public", true, 30, "action: ratelimit\nsource: 0.0.0.0/0", DateTime.UtcNow.AddDays(-5))
        });

        _blockedIps.AddRange(new[]
        {
            new BlockedIpDto("185.220.101.42", "Ransomware C2 Beacon", DateTime.UtcNow.AddMinutes(-10), DateTime.UtcNow.AddDays(7), false),
            new BlockedIpDto("45.142.120.18", "SSH Brute Force", DateTime.UtcNow.AddMinutes(-50), DateTime.UtcNow.AddHours(23), false),
            new BlockedIpDto("194.26.29.112", "Mirai Scanner Hit", DateTime.UtcNow.AddHours(-4), DateTime.UtcNow.AddDays(1), true)
        });

        _quarantine.AddRange(new[]
        {
            new QuarantineItemDto("q_01", "agent_win10_01", "C:\\Users\\Admin\\Downloads\\invoice.exe", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Win.Ransomware.SampleA", "yara", 1048576, DateTime.UtcNow.AddHours(-2).ToString("o")),
            new QuarantineItemDto("q_02", "agent_win10_02", "C:\\Temp\\sample_artifact.exe", "a6b1c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b866", "SecTest.Win32.DumpTool", "clamav", 819200, DateTime.UtcNow.AddDays(-1).ToString("o"))
        });

        _honeypots.AddRange(new[]
        {
            new HoneypotOut("hp_01", "SSH-Decoy-01", "ssh", new Dictionary<string, object> { ["port"] = 2222 }, "active", "10.0.0.50", 2222, DateTime.UtcNow.AddDays(-1).ToString("o"), 342, DateTime.UtcNow.AddDays(-10).ToString("o")),
            new HoneypotOut("hp_02", "SMB-Trap-Finance", "smb", new Dictionary<string, object> { ["share"] = "Accounting$" }, "active", "10.0.0.51", 445, DateTime.UtcNow.AddDays(-2).ToString("o"), 89, DateTime.UtcNow.AddDays(-8).ToString("o"))
        });

        _campaigns.AddRange(new[]
        {
            new CampaignOut("cmp_01", "Finance Decoy 2026", "finance", 4, new Dictionary<string, int> { ["web"] = 1, ["db"] = 1, ["files"] = 2, ["admin"] = 0 }, 24, "active", DateTime.UtcNow.AddDays(-5).ToString("o"), DateTime.UtcNow.AddDays(-5).ToString("o"), DateTime.UtcNow.AddDays(-1).ToString("o"), null, 2, 8, null)
        });

        _iocs.AddRange(new[]
        {
            new IOCOut("ioc_01", "ip", "185.220.101.42", "c2", 0.95, "honeypot", new List<string> { "ransomware", "tor" }, DateTime.UtcNow.AddDays(-3).ToString("o"), DateTime.UtcNow.ToString("o")),
            new IOCOut("ioc_02", "hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "malware", 1.0, "av_detection", new List<string> { "sample_threat" }, DateTime.UtcNow.AddDays(-1).ToString("o"), DateTime.UtcNow.ToString("o"))
        });

        _nodes.AddRange(new[]
        {
            new NodeOut("node-win-01", "WORKSTATION-01", "Windows 11 Pro 23H2", "192.168.1.101", "1.6.4", "online", DateTime.UtcNow.ToString("o"), "workspace", new List<string> { "executive", "finance" }, 14, DateTime.UtcNow.AddDays(-30).ToString("o"), 12.5, 45.0, 38.2, 142),
            new NodeOut("node-srv-01", "DC-PRIMARY", "Windows Server 2022", "192.168.1.10", "1.6.4", "online", DateTime.UtcNow.ToString("o"), "server", new List<string> { "domain-controller", "tier0" }, 32, DateTime.UtcNow.AddDays(-60).ToString("o"), 22.1, 68.4, 52.0, 210)
        });
    }

    public Task<UserLoginResponse> LoginAsync(string email, string password, CancellationToken ct = default)
    {
        var role = email.Contains("admin") ? UserRole.Admin : email.Contains("analyst") ? UserRole.Analyst : UserRole.Viewer;
        var user = new UserDto("usr_demo_001", email, "Demo Analyst", role, "client_demo_001", true);
        return Task.FromResult(new UserLoginResponse("mock_jwt_token_demo_mode_secure_payload", user));
    }

    public Task<ClientLoginResponse> LoginApiKeyAsync(string apiKey, CancellationToken ct = default)
    {
        return Task.FromResult(new ClientLoginResponse(apiKey, "client_demo_001", "AEGIS Homelab Defense"));
    }

    public Task<DashboardOverviewDto> GetDashboardOverviewAsync(CancellationToken ct = default)
    {
        var overview = new DashboardOverviewDto(
            totalAssets: 42,
            openVulnerabilities: 6,
            criticalVulnerabilities: 1,
            activeIncidents: _incidents.Count(i => i.Status == IncidentStatus.Open),
            honeypotInteractions: 18,
            actionsTaken: _blockedIps.Count,
            riskLevel: "medium"
        );
        return Task.FromResult(overview);
    }

    public Task<List<TimelineEventDto>> GetTimelineAsync(CancellationToken ct = default)
    {
        var list = new List<TimelineEventDto>
        {
            new(DateTime.UtcNow.AddDays(-2).ToString("yyyy-MM-dd"), 12, 18),
            new(DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-dd"), 8, 14),
            new(DateTime.UtcNow.ToString("yyyy-MM-dd"), 15, 22)
        };
        return Task.FromResult(list);
    }

    public Task<List<IncidentDto>> GetIncidentsAsync(string? status = null, Severity? severity = null, CancellationToken ct = default)
    {
        var result = _incidents.AsEnumerable();
        if (!string.IsNullOrEmpty(status) && Enum.TryParse<IncidentStatus>(status, true, out var st))
            result = result.Where(i => i.Status == st);
        if (severity.HasValue)
            result = result.Where(i => i.Severity == severity.Value);

        return Task.FromResult(result.ToList());
    }

    public Task<IncidentDto?> GetIncidentDetailAsync(string id, CancellationToken ct = default) =>
        Task.FromResult(_incidents.FirstOrDefault(i => i.Id == id));

    public Task<bool> ApproveActionAsync(string actionId, CancellationToken ct = default)
    {
        foreach (var inc in _incidents)
        {
            var act = inc.Actions?.FirstOrDefault(a => a.Id == actionId);
            if (act != null && inc.Actions != null)
            {
                var idx = inc.Actions.IndexOf(act);
                inc.Actions[idx] = act with { Status = ActionStatus.Executed };
                return Task.FromResult(true);
            }
        }
        return Task.FromResult(true);
    }

    public Task<bool> RejectActionAsync(string actionId, string reason, CancellationToken ct = default)
    {
        foreach (var inc in _incidents)
        {
            var act = inc.Actions?.FirstOrDefault(a => a.Id == actionId);
            if (act != null && inc.Actions != null)
            {
                var idx = inc.Actions.IndexOf(act);
                inc.Actions[idx] = act with { Status = ActionStatus.Rejected };
                return Task.FromResult(true);
            }
        }
        return Task.FromResult(true);
    }

    public Task<RansomwareStatsDto> GetRansomwareStatsAsync(CancellationToken ct = default)
    {
        var stats = new RansomwareStatsDto(
            totalEvents: 38,
            activeIncidents: 1,
            canaryFilesTripped: 0,
            shadowCopiesDeleted: 1,
            massEncryptionEvents: 0,
            activeAlerts: 2
        );
        return Task.FromResult(stats);
    }

    public Task<List<RaaSGroupDto>> GetRaaSGroupsAsync(CancellationToken ct = default)
    {
        var list = new List<RaaSGroupDto>
        {
            new("AlphaLocker 3.0", "Restore-My-Files.txt", new List<string> { ".locked", ".docx", ".pdf" }, new List<string> { "185.220.101.42" }, new List<string> { "Recon", "Execution", "Impact" }),
            new("ShadowCat (Variant-A)", "RECOVER-FILES.txt", new List<string> { ".crypt", ".vmdk" }, new List<string> { "45.142.120.18" }, new List<string> { "Initial Access", "Lateral Movement", "Exfiltration" }),
            new("CipherX", "readme_decrypt.txt", new List<string> { ".cipher", ".sql" }, new List<string> { "194.26.29.112" }, new List<string> { "Credential Access", "Defense Evasion", "Impact" })
        };
        return Task.FromResult(list);
    }

    public Task<RecoveryOptionsDto?> GetRecoveryOptionsAsync(string eventId, CancellationToken ct = default)
    {
        var options = new RecoveryOptionsDto(
            EventId: eventId,
            Snapshots: new List<SnapshotDto>
            {
                new("snap_01", "WORKSTATION-04", DateTime.UtcNow.AddMinutes(-30), "VSS", "VSS_WORKSTATION_04_AUTO", 4294967296)
            },
            Decryptors: new List<DecryptorDto>()
        );
        return Task.FromResult<RecoveryOptionsDto?>(options);
    }

    public Task<bool> TriggerRestoreAsync(RestoreRequest request, CancellationToken ct = default) =>
        Task.FromResult(true);

    public Task<List<FirewallRuleDto>> GetFirewallRulesAsync(CancellationToken ct = default) =>
        Task.FromResult(_rules.ToList());

    public Task<BlockedIpsResponse> GetBlockedIpsAsync(CancellationToken ct = default) =>
        Task.FromResult(new BlockedIpsResponse(_blockedIps.ToList(), _blockedIps.Count));

    public Task<bool> UnblockIpAsync(string ip, CancellationToken ct = default)
    {
        _blockedIps.RemoveAll(b => b.Ip == ip);
        return Task.FromResult(true);
    }

    public Task<SystemsResponse> GetSystemsAsync(CancellationToken ct = default)
    {
        var systems = new List<SystemInfoDto>
        {
            new("AEGIS Core Controller", "10.0.0.1", "Control Plane", "Online", 28.4, 42.1, 55.0, "24d 12h", new List<string> { "api", "auth", "broker" }, null, "server", "srv_01", "Ubuntu 22.04 LTS"),
            new("Phantom Decoy Gateway", "10.0.0.50", "Deception Node", "Online", 14.2, 22.8, 30.1, "18d 04h", new List<string> { "honeypot", "ssh-decoy" }, null, "gateway", "srv_02", "Debian 12"),
            new("EDR Telemetry Ingest", "10.0.0.2", "Data Pipeline", "Online", 64.8, 71.5, 48.0, "12d 19h", new List<string> { "telemetry-worker" }, null, "worker", "srv_03", "Windows Server 2022")
        };
        return Task.FromResult(new SystemsResponse(systems));
    }

    public Task<ClientSettingsDto> GetClientSettingsAsync(CancellationToken ct = default) =>
        Task.FromResult(_clientSettings);

    public Task<bool> UpdateClientSettingsAsync(ClientSettingsDto settings, CancellationToken ct = default)
    {
        _clientSettings = settings;
        return Task.FromResult(true);
    }

    public Task<NotificationConfigDto> GetNotificationConfigAsync(CancellationToken ct = default) =>
        Task.FromResult(_notificationConfig);

    public Task<bool> UpdateNotificationConfigAsync(NotificationConfigDto config, CancellationToken ct = default)
    {
        _notificationConfig = config;
        return Task.FromResult(true);
    }

    public Task<NotificationTestResponse> TestNotificationAsync(string channel, CancellationToken ct = default) =>
        Task.FromResult(new NotificationTestResponse(true, $"Test dispatch to {channel} simulated successfully."));

    // --- EDR ---
    public Task<EdrEventsOut> SubmitEdrEventsAsync(EdrEventsIn eventsIn, CancellationToken ct = default) =>
        Task.FromResult(new EdrEventsOut(eventsIn.Events.Count, 0, 1));

    public Task<List<RecentEdrEventDto>> GetRecentEdrEventsAsync(string agentId, int minutes = 15, int limit = 200, CancellationToken ct = default)
    {
        var events = new List<RecentEdrEventDto>
        {
            new("edr_ev_1", "process", "critical", "Suspicious child process spawned: powershell.exe", new Dictionary<string, object> { ["pid"] = 4820, ["user"] = "SYSTEM" }, DateTime.UtcNow.AddMinutes(-5).ToString("o")),
            new("edr_ev_2", "network", "high", "Outbound connection to known C2 port 8443", new Dictionary<string, object> { ["target"] = "185.220.101.42:8443" }, DateTime.UtcNow.AddMinutes(-8).ToString("o"))
        };
        return Task.FromResult(events);
    }

    public Task<bool> KillProcessAsync(KillProcessRequest request, CancellationToken ct = default) => Task.FromResult(true);
    public Task<bool> QuarantineFileAsync(QuarantineFileRequest request, CancellationToken ct = default) => Task.FromResult(true);
    public Task<bool> IsolateHostAsync(string agentId, IsolateHostRequest request, CancellationToken ct = default) => Task.FromResult(true);
    public Task<bool> UnisolateHostAsync(string agentId, UnisolateHostRequest request, CancellationToken ct = default) => Task.FromResult(true);

    // --- Antivirus ---
    public Task<SignatureBundleDto> GetSignaturesAsync(CancellationToken ct = default) =>
        Task.FromResult(new SignatureBundleDto("2026.11.03.01", new List<string> { "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }, DateTime.UtcNow.ToString("o"), 14205));

    public Task<SignatureBundleDto> UpdateSignaturesAsync(CancellationToken ct = default) =>
        Task.FromResult(new SignatureBundleDto("2026.11.03.02", new List<string> { "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }, DateTime.UtcNow.ToString("o"), 14250));

    public Task<DetectionOut> ReportDetectionAsync(DetectionIn detection, CancellationToken ct = default) =>
        Task.FromResult(new DetectionOut("det_01", "inc_001", detection.Path, detection.Sha256, detection.Rule, detection.Engine, detection.Quarantined, DateTime.UtcNow.ToString("o")));

    public Task<List<QuarantineItemDto>> GetQuarantineListAsync(int limit = 100, CancellationToken ct = default) =>
        Task.FromResult(_quarantine.ToList());

    public Task<ReleaseQuarantineResponse> ReleaseQuarantineAsync(string detectionId, CancellationToken ct = default)
    {
        _quarantine.RemoveAll(q => q.Id == detectionId);
        return Task.FromResult(new ReleaseQuarantineResponse(true, detectionId, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }

    public Task<HashLookupDto> LookupHashAsync(string sha256, CancellationToken ct = default) =>
        Task.FromResult(new HashLookupDto(sha256, sha256.StartsWith("e3b0"), 2, DateTime.UtcNow.AddDays(-1).ToString("o")));

    // --- Surface ---
    public Task<ScanResponse> StartSurfaceScanAsync(ScanRequest request, CancellationToken ct = default) =>
        Task.FromResult(new ScanResponse("scan_01", request.Target, "queued", "Surface vulnerability scan initiated"));

    public Task<List<ScanDetail>> GetSurfaceScansAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<ScanDetail>
        {
            new("scan_01", "192.168.1.0/24", "full", "completed", DateTime.UtcNow.AddHours(-1).ToString("o"), DateTime.UtcNow.ToString("o"), new(), 18, 1.0)
        });

    public Task<List<AssetOut>> GetSurfaceAssetsAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<AssetOut>
        {
            new("ast_01", "primary-dc.corp", "192.168.1.10", "server", new List<int> { 88, 389, 445, 3389 }, new List<string> { "Active Directory", "SMBv3" }, "active", 42.5, DateTime.UtcNow.ToString("o"), 2)
        });

    public Task<List<VulnOut>> GetSurfaceVulnerabilitiesAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<VulnOut>
        {
            new("vuln_01", "ast_01", "SMBv1 Dialect Supported", "Legacy SMBv1 protocol dialect is enabled on domain controller", "high", 7.5, "CVE-2017-0144", "open", 8.0, "Disable SMBv1 via PowerShell registry command", DateTime.UtcNow.AddDays(-2).ToString("o"))
        });

    public Task<VulnOut> UpdateVulnerabilityStatusAsync(string vulnId, string status, CancellationToken ct = default) =>
        Task.FromResult(new VulnOut(vulnId, "ast_01", "SMBv1 Dialect Supported", "Legacy SMBv1 protocol dialect", "high", 7.5, "CVE-2017-0144", status, 8.0, "Disable SMBv1", DateTime.UtcNow.ToString("o")));

    public Task<HardenResponse> GetHardenRecommendationsAsync(CancellationToken ct = default) =>
        Task.FromResult(new HardenResponse("primary-dc.corp", "server", new(), new List<HardenChecklistItem>
        {
            new("Disable LLMNR and NBT-NS protocols", "high", "network"),
            new("Enable Windows Defender Credential Guard", "critical", "os")
        }));

    // --- Phantom & Deception ---
    public Task<List<HoneypotOut>> GetHoneypotsAsync(CancellationToken ct = default) =>
        Task.FromResult(_honeypots.ToList());

    public Task<HoneypotOut> CreateHoneypotAsync(HoneypotCreate request, CancellationToken ct = default)
    {
        var hp = new HoneypotOut($"hp_{Guid.NewGuid():N}", request.Name, request.HoneypotType, request.Config, "active", "10.0.0.52", 80, null, 0, DateTime.UtcNow.ToString("o"));
        _honeypots.Add(hp);
        return Task.FromResult(hp);
    }

    public Task<bool> DeleteHoneypotAsync(string honeypotId, CancellationToken ct = default)
    {
        _honeypots.RemoveAll(h => h.Id == honeypotId);
        return Task.FromResult(true);
    }

    public Task<HoneypotOut> RotateHoneypotAsync(string honeypotId, CancellationToken ct = default)
    {
        var existing = _honeypots.FirstOrDefault(h => h.Id == honeypotId);
        if (existing != null)
        {
            var idx = _honeypots.IndexOf(existing);
            var updated = existing with { LastRotation = DateTime.UtcNow.ToString("o") };
            _honeypots[idx] = updated;
            return Task.FromResult(updated);
        }
        return Task.FromResult(new HoneypotOut(honeypotId, "Rotated", "ssh", new(), "active", null, null, DateTime.UtcNow.ToString("o"), 0, null));
    }

    public Task<List<InteractionOut>> GetHoneypotInteractionsAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<InteractionOut>
        {
            new("int_01", "hp_01", "185.220.101.42", 51234, "ssh", new List<string> { "uname -a", "cat /etc/passwd" }, new List<string> { "root:root", "admin:123456" }, 45, "atk_01", DateTime.UtcNow.AddMinutes(-30).ToString("o"))
        });

    public Task<List<AttackerOut>> GetAttackersAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<AttackerOut>
        {
            new("atk_01", "185.220.101.42", new List<string> { "185.220.101.42", "185.220.101.43" }, new List<string> { "hydra", "nmap" }, new List<string> { "T1110", "T1046" }, "advanced", 48, DateTime.UtcNow.AddDays(-7).ToString("o"), DateTime.UtcNow.ToString("o"), "Automated scanner targeting lateral movement")
        });

    public Task<List<CampaignOut>> GetDeceptionCampaignsAsync(CancellationToken ct = default) =>
        Task.FromResult(_campaigns.ToList());

    public Task<CampaignOut> CreateDeceptionCampaignAsync(CampaignCreate request, CancellationToken ct = default)
    {
        var cmp = new CampaignOut($"cmp_{Guid.NewGuid():N}", request.Name, request.Theme, request.DecoyCount, new() { ["web"] = request.ServiceMix.Web, ["db"] = request.ServiceMix.Db, ["files"] = request.ServiceMix.Files, ["admin"] = request.ServiceMix.Admin }, request.RotationHours, "active", DateTime.UtcNow.ToString("o"), DateTime.UtcNow.ToString("o"), null, null, 2, 6, null);
        _campaigns.Add(cmp);
        return Task.FromResult(cmp);
    }

    public Task<CampaignOut> RotateDeceptionCampaignAsync(string campaignId, CancellationToken ct = default)
    {
        var existing = _campaigns.FirstOrDefault(c => c.Id == campaignId);
        if (existing != null)
        {
            var idx = _campaigns.IndexOf(existing);
            var updated = existing with { LastRotatedAt = DateTime.UtcNow.ToString("o") };
            _campaigns[idx] = updated;
            return Task.FromResult(updated);
        }
        return Task.FromResult(new CampaignOut(campaignId, "Rotated", "finance", 4, new(), 24, "active", DateTime.UtcNow.ToString("o"), null, DateTime.UtcNow.ToString("o"), null, 0, 0, null));
    }

    public Task<bool> DeleteDeceptionCampaignAsync(string campaignId, CancellationToken ct = default)
    {
        _campaigns.RemoveAll(c => c.Id == campaignId);
        return Task.FromResult(true);
    }

    public Task<List<BreadcrumbHitOut>> GetBreadcrumbHitsAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<BreadcrumbHitOut>
        {
            new("hit_01", "cmp_01", "bc_token_01", "C:\\Users\\Admin\\.aws\\credentials", "aws_key", 3, DateTime.UtcNow.AddHours(-1).ToString("o"), "185.220.101.42", DateTime.UtcNow.AddDays(-5).ToString("o"))
        });

    public Task<List<ThemeOut>> GetDeceptionThemesAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<ThemeOut>
        {
            new("finance", "Financial Services", "Decoys mimicking banking APIs, accounting spreadsheets, and payment gateways", "banking", new List<string> { "aws_key", "db_creds", "invoice_file" }),
            new("healthcare", "Healthcare & HIPAA", "Decoys mimicking patient records (EHR/EMR) and HL7 endpoints", "medical", new List<string> { "patient_db", "vpn_config" })
        });

    // --- Threats & IP Intel ---
    public Task<List<IOCOut>> GetThreatIntelAsync(CancellationToken ct = default) =>
        Task.FromResult(_iocs.ToList());

    public Task<IOCOut> CreateIOCAsync(IOCCreate request, CancellationToken ct = default)
    {
        var ioc = new IOCOut($"ioc_{Guid.NewGuid():N}", request.IocType, request.IocValue, request.ThreatType, request.Confidence, request.Source, request.Tags, DateTime.UtcNow.ToString("o"), DateTime.UtcNow.ToString("o"));
        _iocs.Add(ioc);
        return Task.FromResult(ioc);
    }

    public Task<List<ThreatEventOut>> GetThreatEventsAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<ThreatEventOut>
        {
            new("te_01", "rule_credential_access", "Memory Dump Heuristic Signature", "WORKSTATION-01", "critical", DateTime.UtcNow.AddMinutes(-20).ToString("o"), "procdump.exe", "Attempted memory dump inspection")
        });

    public Task<IpIntelDto> LookupIpIntelAsync(string ip, bool deep = false, CancellationToken ct = default) =>
        Task.FromResult(new IpIntelDto(
            Ip: ip,
            Asn: "AS13335",
            Org: "Cloudflare, Inc.",
            Country: "US",
            City: "San Francisco",
            Region: "California",
            Hostname: "one.one.one.one",
            IsTor: ip.StartsWith("185.220."),
            IsVpn: false,
            IsProxy: false,
            IsDatacenter: true,
            IsMobile: false,
            IsMalicious: ip.StartsWith("185.220.") || ip.StartsWith("45.142."),
            IsScanner: true,
            IsKnownService: false,
            RiskScore: ip.StartsWith("185.220.") ? 98.0 : 15.0,
            Internal: ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip == "127.0.0.1"
        ));

    public Task<List<TtpCampaignOut>> GetTtpCampaignsAsync(int limit = 20, int windowHours = 168, CancellationToken ct = default) =>
        Task.FromResult(new List<TtpCampaignOut>
        {
            new("cluster_t1490", "Impact", "T1490 - Inhibit System Recovery", 8, DateTime.UtcNow.AddDays(-3).ToString("o"), DateTime.UtcNow.ToString("o"), new List<string> { "185.220.101.42", "185.220.101.45" })
        });

    // --- DoS Shield ---
    public Task<DosStatusDto> GetDosStatusAsync(CancellationToken ct = default) =>
        Task.FromResult(new DosStatusDto("monitor", false, 14.8, true, true, new List<DosOffenderDto>
        {
            new("45.142.120.18", 32.5, 8, "Per-IP rate limit burst")
        }, new Dictionary<string, object> { ["global_max_rps"] = 500, ["per_ip_max_rps"] = 30 }));

    public Task<List<DosOffenderDto>> GetDosOffendersAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<DosOffenderDto>
        {
            new("45.142.120.18", 32.5, 8, "Per-IP rate limit burst"),
            new("194.26.29.112", 21.0, 4, "SYN flood burst")
        });

    public Task<DosConfigDto> GetDosConfigAsync(CancellationToken ct = default) =>
        Task.FromResult(new DosConfigDto(new Dictionary<string, object> { ["global_max_rps"] = 500 }, "monitor", true, false, false));

    // --- Nodes ---
    public Task<List<NodeOut>> GetNodesAsync(string? status = null, CancellationToken ct = default) =>
        Task.FromResult(_nodes.ToList());

    public Task<NodeOut?> GetNodeAsync(string nodeId, CancellationToken ct = default) =>
        Task.FromResult(_nodes.FirstOrDefault(n => n.Id == nodeId));

    public Task<EnrollResponse> EnrollNodeAsync(EnrollRequest request, CancellationToken ct = default)
    {
        var node = new NodeOut($"node-{Guid.NewGuid():N}", "ENROLLED-HOST", "Windows 11", "192.168.1.150", "1.6.4", "online", DateTime.UtcNow.ToString("o"), request.NodeType, new List<string> { "newly-enrolled" }, 0, DateTime.UtcNow.ToString("o"), 5.0, 30.0, 25.0, 95);
        _nodes.Add(node);
        return Task.FromResult(new EnrollResponse("enrolled", node.Id, node.Hostname, "Node enrolled successfully."));
    }

    public Task<bool> DeleteNodeAsync(string nodeId, CancellationToken ct = default)
    {
        _nodes.RemoveAll(n => n.Id == nodeId);
        return Task.FromResult(true);
    }

    // --- Compliance ---
    public Task<ComplianceOverview> GetComplianceFrameworksAsync(CancellationToken ct = default) =>
        Task.FromResult(new ComplianceOverview(
            new List<FrameworkOut>
            {
                new("nist_csf", "NIST Cybersecurity Framework", "NIST CSF", "Standard for critical infrastructure cybersecurity", 88, 22, 4, 1, new List<ControlOut>
                {
                    new("DE.CM-1", "Network Monitoring", "dos_shield", "met", "DoS Shield active in real-time monitor mode"),
                    new("PR.IP-1", "Baseline Configuration", "antivirus", "met", "Local signature bundle up to date")
                }),
                new("cis_controls", "CIS Critical Security Controls v8", "CIS v8", "Prioritized set of actions to protect enterprise", 82, 18, 5, 2, new List<ControlOut>
                {
                    new("CIS-8", "Audit Log Management", "edr", "met", "EDR event stream active with tamper protection")
                })
            },
            OverallScore: 85,
            TotalControls: 52,
            TotalMet: 40,
            TotalPartial: 9,
            TotalNotMet: 3,
            Gaps: new(),
            AssessedAt: DateTime.UtcNow.ToString("o"),
            Note: "AEGIS continuous assessment active across all deployed telemetry modules."
        ));

    // --- Quantum ---
    public Task<QuantumReadinessDto> GetQuantumReadinessAsync(CancellationToken ct = default) =>
        Task.FromResult(new QuantumReadinessDto(
            QuantumReadinessScore: 78.5,
            Grade: "B",
            Summary: new QuantumReadinessSummary(18, 12, 2, 4, true, 2),
            Breakdown: new QuantumReadinessBreakdown(35.0, -10.0, 28.5, 15.0),
            AssessedAt: DateTime.UtcNow.ToString("o")
        ));

    public Task<EntropyAnalysisResult> AnalyzeEntropyAsync(EntropyRequest request, CancellationToken ct = default) =>
        Task.FromResult(new EntropyAnalysisResult(7.85, 6.92, new Dictionary<string, double> { ["order_0.5"] = 7.95, ["order_1.0"] = 7.85, ["order_2.0"] = 7.60 }, "Encrypted / Packed payload detected"));
}
