using System.Net;
using System.Net.Http;
using Aegis.App.ViewModels;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Moq;
using Xunit;

namespace Aegis.Tests;

public class RemainingViewModelsTests
{
    private readonly Mock<IAegisApiClient> _mockApi = new();
    private readonly Mock<IDialogService> _mockDialog = new();

    // =========================================================================
    // 1. AttackSurfaceViewModel Tests
    // =========================================================================

    [Fact]
    public async Task AttackSurfaceViewModel_LoadData_Success()
    {
        _mockApi.Setup(a => a.GetSurfaceAssetsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<AssetOut> { new("ast_1", "srv-1", "10.0.0.1", "server", null, null, "active", 40.0, null, 1) });
        _mockApi.Setup(a => a.GetSurfaceVulnerabilitiesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<VulnOut> { new("vuln_1", "ast_1", "Open Port", null, "low", 3.0, null, "open", null, null, null) });
        _mockApi.Setup(a => a.GetHardenRecommendationsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new HardenResponse("srv-1", "server", null, new List<HardenChecklistItem>()));

        var vm = new AttackSurfaceViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.Single(vm.Assets);
        Assert.Single(vm.Vulnerabilities);
        Assert.Null(vm.ErrorMessage);
        Assert.False(vm.IsLoading);
    }

    [Fact]
    public async Task AttackSurfaceViewModel_LoadData_ApiError()
    {
        _mockApi.Setup(a => a.GetSurfaceAssetsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Timeout"));

        var vm = new AttackSurfaceViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Failed to load surface data", vm.ErrorMessage);
    }

    [Fact]
    public async Task AttackSurfaceViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetSurfaceAssetsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new AttackSurfaceViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    [Fact]
    public async Task AttackSurfaceViewModel_TriggerScan_WhenConfirmed_DispatchesScan()
    {
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(true);
        _mockApi.Setup(a => a.StartSurfaceScanAsync(It.IsAny<ScanRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ScanResponse("scan_1", "10.0.0.1", "running", "Started"));
        _mockApi.Setup(a => a.GetSurfaceAssetsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<AssetOut>());
        _mockApi.Setup(a => a.GetSurfaceVulnerabilitiesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<VulnOut>());
        _mockApi.Setup(a => a.GetHardenRecommendationsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new HardenResponse("target", "server", null, new List<HardenChecklistItem>()));

        var vm = new AttackSurfaceViewModel(_mockApi.Object, _mockDialog.Object)
        {
            ScanTarget = "10.0.0.1"
        };
        await vm.TriggerScanAsync();

        _mockApi.Verify(a => a.StartSurfaceScanAsync(It.Is<ScanRequest>(r => r.Target == "10.0.0.1"), It.IsAny<CancellationToken>()), Times.Once);
        Assert.Contains("scan_1", vm.StatusMessage);
    }

    [Fact]
    public async Task AttackSurfaceViewModel_TriggerScan_WhenCancelled_DoesNotCallApi()
    {
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(false);

        var vm = new AttackSurfaceViewModel(_mockApi.Object, _mockDialog.Object)
        {
            ScanTarget = "10.0.0.1"
        };
        await vm.TriggerScanAsync();

        _mockApi.Verify(a => a.StartSurfaceScanAsync(It.IsAny<ScanRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // =========================================================================
    // 2. PhantomViewModel Tests
    // =========================================================================

    [Fact]
    public async Task PhantomViewModel_LoadData_Success()
    {
        _mockApi.Setup(a => a.GetHoneypotsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<HoneypotOut> { new("hp_1", "ssh-trap", "ssh", new Dictionary<string, object>(), "active", "10.0.0.2", 2222, null, 10, null) });
        _mockApi.Setup(a => a.GetHoneypotInteractionsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<InteractionOut>());
        _mockApi.Setup(a => a.GetAttackersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<AttackerOut>());

        var vm = new PhantomViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.Single(vm.Honeypots);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task PhantomViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetHoneypotsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new PhantomViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    [Fact]
    public async Task PhantomViewModel_RotateHoneypot_WhenConfirmed_CallsApi()
    {
        var hp = new HoneypotOut("hp_1", "trap-01", "ssh", new Dictionary<string, object>(), "active", "127.0.0.1", 2222, null, 0, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.RotateHoneypotAsync("hp_1", It.IsAny<CancellationToken>())).ReturnsAsync(hp);
        _mockApi.Setup(a => a.GetHoneypotsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<HoneypotOut>());
        _mockApi.Setup(a => a.GetHoneypotInteractionsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<InteractionOut>());
        _mockApi.Setup(a => a.GetAttackersAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<AttackerOut>());

        var vm = new PhantomViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.RotateHoneypotAsync(hp);

        _mockApi.Verify(a => a.RotateHoneypotAsync("hp_1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task PhantomViewModel_RotateHoneypot_WhenCancelled_DoesNotCallApi()
    {
        var hp = new HoneypotOut("hp_1", "trap-01", "ssh", new Dictionary<string, object>(), "active", "127.0.0.1", 2222, null, 0, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(false);

        var vm = new PhantomViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.RotateHoneypotAsync(hp);

        _mockApi.Verify(a => a.RotateHoneypotAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task PhantomViewModel_DeleteHoneypot_WhenConfirmed_CallsApi()
    {
        var hp = new HoneypotOut("hp_1", "trap-01", "ssh", new Dictionary<string, object>(), "active", "127.0.0.1", 2222, null, 0, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.DeleteHoneypotAsync("hp_1", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.GetHoneypotsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<HoneypotOut>());
        _mockApi.Setup(a => a.GetHoneypotInteractionsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<InteractionOut>());
        _mockApi.Setup(a => a.GetAttackersAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<AttackerOut>());

        var vm = new PhantomViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.DeleteHoneypotAsync(hp);

        _mockApi.Verify(a => a.DeleteHoneypotAsync("hp_1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task PhantomViewModel_DeleteHoneypot_WhenCancelled_DoesNotCallApi()
    {
        var hp = new HoneypotOut("hp_1", "trap-01", "ssh", new Dictionary<string, object>(), "active", "127.0.0.1", 2222, null, 0, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(false);

        var vm = new PhantomViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.DeleteHoneypotAsync(hp);

        _mockApi.Verify(a => a.DeleteHoneypotAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // =========================================================================
    // 3. DeceptionViewModel Tests
    // =========================================================================

    [Fact]
    public async Task DeceptionViewModel_LoadData_Success()
    {
        _mockApi.Setup(a => a.GetDeceptionCampaignsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<CampaignOut>());
        _mockApi.Setup(a => a.GetBreadcrumbHitsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<BreadcrumbHitOut>());
        _mockApi.Setup(a => a.GetDeceptionThemesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ThemeOut>());

        var vm = new DeceptionViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.Campaigns);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task DeceptionViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetDeceptionCampaignsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new DeceptionViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    [Fact]
    public async Task DeceptionViewModel_RotateCampaign_WhenConfirmed_CallsApi()
    {
        var campaign = new CampaignOut("camp_1", "Theme-Fin", "finance", 5, null, 24, "active", "2026", null, null, null, 2, 3, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.RotateDeceptionCampaignAsync("camp_1", It.IsAny<CancellationToken>())).ReturnsAsync(campaign);
        _mockApi.Setup(a => a.GetDeceptionCampaignsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<CampaignOut>());
        _mockApi.Setup(a => a.GetBreadcrumbHitsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<BreadcrumbHitOut>());
        _mockApi.Setup(a => a.GetDeceptionThemesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ThemeOut>());

        var vm = new DeceptionViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.RotateCampaignAsync(campaign);

        _mockApi.Verify(a => a.RotateDeceptionCampaignAsync("camp_1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DeceptionViewModel_RotateCampaign_WhenCancelled_DoesNotCallApi()
    {
        var campaign = new CampaignOut("camp_1", "Theme-Fin", "finance", 5, null, 24, "active", "2026", null, null, null, 2, 3, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(false);

        var vm = new DeceptionViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.RotateCampaignAsync(campaign);

        _mockApi.Verify(a => a.RotateDeceptionCampaignAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DeceptionViewModel_DeleteCampaign_WhenConfirmed_CallsApi()
    {
        var campaign = new CampaignOut("camp_1", "Theme-Fin", "finance", 5, null, 24, "active", "2026", null, null, null, 2, 3, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.DeleteDeceptionCampaignAsync("camp_1", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.GetDeceptionCampaignsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<CampaignOut>());
        _mockApi.Setup(a => a.GetBreadcrumbHitsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<BreadcrumbHitOut>());
        _mockApi.Setup(a => a.GetDeceptionThemesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ThemeOut>());

        var vm = new DeceptionViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.DeleteCampaignAsync(campaign);

        _mockApi.Verify(a => a.DeleteDeceptionCampaignAsync("camp_1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DeceptionViewModel_DeleteCampaign_WhenCancelled_DoesNotCallApi()
    {
        var campaign = new CampaignOut("camp_1", "Theme-Fin", "finance", 5, null, 24, "active", "2026", null, null, null, 2, 3, null);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(false);

        var vm = new DeceptionViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.DeleteCampaignAsync(campaign);

        _mockApi.Verify(a => a.DeleteDeceptionCampaignAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // =========================================================================
    // 4. ThreatIntelViewModel Tests
    // =========================================================================

    [Fact]
    public async Task ThreatIntelViewModel_LoadData_Success()
    {
        _mockApi.Setup(a => a.GetThreatIntelAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<IOCOut>());
        _mockApi.Setup(a => a.GetTtpCampaignsAsync(20, 168, It.IsAny<CancellationToken>())).ReturnsAsync(new List<TtpCampaignOut>());

        var vm = new ThreatIntelViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.Iocs);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task ThreatIntelViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetThreatIntelAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new ThreatIntelViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    [Fact]
    public async Task ThreatIntelViewModel_AddIoc_CallsApi()
    {
        _mockApi.Setup(a => a.CreateIOCAsync(It.IsAny<IOCCreate>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new IOCOut("ioc_1", "ip", "1.2.3.4", "c2", 90.0, "analyst", null, null, null));
        _mockApi.Setup(a => a.GetThreatIntelAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<IOCOut>());
        _mockApi.Setup(a => a.GetTtpCampaignsAsync(20, 168, It.IsAny<CancellationToken>())).ReturnsAsync(new List<TtpCampaignOut>());

        var vm = new ThreatIntelViewModel(_mockApi.Object, _mockDialog.Object)
        {
            NewIocType = "ip",
            NewIocValue = "1.2.3.4"
        };
        await vm.AddIocAsync();

        _mockApi.Verify(a => a.CreateIOCAsync(It.Is<IOCCreate>(i => i.IocValue == "1.2.3.4"), It.IsAny<CancellationToken>()), Times.Once);
    }

    // =========================================================================
    // 5. IpInvestigationViewModel Tests
    // =========================================================================

    [Fact]
    public async Task IpInvestigationViewModel_LookupIp_Success()
    {
        _mockApi.Setup(a => a.LookupIpIntelAsync("8.8.8.8", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new IpIntelDto("8.8.8.8", "AS15169", "Google LLC", "US", "Mountain View", "CA", "dns.google", false, false, false, false, false, false, false, false, 0.0, false));

        var vm = new IpInvestigationViewModel(_mockApi.Object, _mockDialog.Object)
        {
            TargetIp = "8.8.8.8",
            IsDeep = true
        };
        await vm.InvestigateIpAsync();

        _mockApi.Verify(a => a.LookupIpIntelAsync("8.8.8.8", true, It.IsAny<CancellationToken>()), Times.Once);
        Assert.NotNull(vm.Intel);
        Assert.Equal("Google LLC", vm.Intel.Org);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task IpInvestigationViewModel_LookupIp_403Forbidden()
    {
        _mockApi.Setup(a => a.LookupIpIntelAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new IpInvestigationViewModel(_mockApi.Object, _mockDialog.Object)
        {
            TargetIp = "1.1.1.1"
        };
        await vm.InvestigateIpAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    // =========================================================================
    // 6. DosShieldViewModel Tests
    // =========================================================================

    [Fact]
    public async Task DosShieldViewModel_LoadData_Success()
    {
        _mockApi.Setup(a => a.GetDosStatusAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DosStatusDto("active", false, 150.0, true, true));
        _mockApi.Setup(a => a.GetDosOffendersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<DosOffenderDto> { new("1.1.1.1", 50.0, 10, "Per-IP limit") });
        _mockApi.Setup(a => a.GetDosConfigAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DosConfigDto(null, "active", true, true, false));

        var vm = new DosShieldViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.Status);
        Assert.Equal(150.0, vm.Status.GlobalRps);
        Assert.Single(vm.Offenders);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task DosShieldViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetDosStatusAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new DosShieldViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    // =========================================================================
    // 7. ComplianceMatrixViewModel Tests
    // =========================================================================

    [Fact]
    public async Task ComplianceMatrixViewModel_LoadData_Success()
    {
        var fw = new FrameworkOut("nist", "NIST CSF", "NIST", "National Institute", 92, 10, 2, 0, new List<ControlOut>());
        var overview = new ComplianceOverview(new List<FrameworkOut> { fw }, 92, 12, 10, 2, 0, null, "2026", "OK");

        _mockApi.Setup(a => a.GetComplianceFrameworksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(overview);

        var vm = new ComplianceMatrixViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.Overview);
        Assert.Equal(fw, vm.SelectedFramework);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task ComplianceMatrixViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetComplianceFrameworksAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new ComplianceMatrixViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    // =========================================================================
    // 8. QuantumAnalyticsViewModel Tests
    // =========================================================================

    [Fact]
    public async Task QuantumAnalyticsViewModel_LoadData_Success()
    {
        var readiness = new QuantumReadinessDto(85.0, "A", new QuantumReadinessSummary(10, 8, 1, 1, true, 0), null, "2026-11-03");
        _mockApi.Setup(a => a.GetQuantumReadinessAsync(It.IsAny<CancellationToken>())).ReturnsAsync(readiness);

        var vm = new QuantumAnalyticsViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.Readiness);
        Assert.Equal("A", vm.Readiness.Grade);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task QuantumAnalyticsViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetQuantumReadinessAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new QuantumAnalyticsViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    [Fact]
    public async Task QuantumAnalyticsViewModel_EntropyAnalysis_CallsApi()
    {
        _mockApi.Setup(a => a.AnalyzeEntropyAsync(It.IsAny<EntropyRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new EntropyAnalysisResult(7.95, 7.8, null, "encrypted"));

        var vm = new QuantumAnalyticsViewModel(_mockApi.Object, _mockDialog.Object)
        {
            PayloadText = "secret payload bytes"
        };
        await vm.TestEntropyAsync();

        _mockApi.Verify(a => a.AnalyzeEntropyAsync(It.IsAny<EntropyRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        Assert.NotNull(vm.EntropyResult);
        Assert.Equal(7.95, vm.EntropyResult.ShannonEntropy);
    }

    // =========================================================================
    // 9. NodeManagementViewModel Tests
    // =========================================================================

    [Fact]
    public async Task NodeManagementViewModel_LoadData_Success()
    {
        var node = new NodeOut("node_1", "srv-db", "Linux", "10.0.0.5", "1.6", "online", "now", "server", null, 1, "2026", 10.0, 20.0, 30.0, 50);
        _mockApi.Setup(a => a.GetNodesAsync(null, It.IsAny<CancellationToken>())).ReturnsAsync(new List<NodeOut> { node });

        var vm = new NodeManagementViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.Single(vm.Nodes);
        Assert.Equal(node, vm.SelectedNode);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task NodeManagementViewModel_LoadData_403Forbidden()
    {
        _mockApi.Setup(a => a.GetNodesAsync(null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new NodeManagementViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
    }

    [Fact]
    public async Task NodeManagementViewModel_EnrollNode_CallsApi()
    {
        _mockApi.Setup(a => a.EnrollNodeAsync(It.IsAny<EnrollRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new EnrollResponse("success", "node_100", "srv-test", "Enrolled"));
        _mockApi.Setup(a => a.GetNodesAsync(null, It.IsAny<CancellationToken>())).ReturnsAsync(new List<NodeOut>());

        var vm = new NodeManagementViewModel(_mockApi.Object, _mockDialog.Object)
        {
            EnrollCode = "token_abc123"
        };
        await vm.EnrollNodeAsync();

        _mockApi.Verify(a => a.EnrollNodeAsync(It.Is<EnrollRequest>(r => r.Code == "token_abc123"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task NodeManagementViewModel_DeleteNode_WhenConfirmed_CallsApi()
    {
        var node = new NodeOut("node_1", "srv-db", "Linux", "10.0.0.5", "1.6", "online", "now", "server", null, 1, "2026", 10.0, 20.0, 30.0, 50);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.DeleteNodeAsync("node_1", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        _mockApi.Setup(a => a.GetNodesAsync(null, It.IsAny<CancellationToken>())).ReturnsAsync(new List<NodeOut>());

        var vm = new NodeManagementViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.DeleteNodeAsync(node);

        _mockApi.Verify(a => a.DeleteNodeAsync("node_1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task NodeManagementViewModel_DeleteNode_WhenCancelled_DoesNotCallApi()
    {
        var node = new NodeOut("node_1", "srv-db", "Linux", "10.0.0.5", "1.6", "online", "now", "server", null, 1, "2026", 10.0, 20.0, 30.0, 50);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(false);

        var vm = new NodeManagementViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.DeleteNodeAsync(node);

        _mockApi.Verify(a => a.DeleteNodeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // =========================================================================
    // 10. OperatorGuideViewModel Tests
    // =========================================================================

    [Fact]
    public void OperatorGuideViewModel_InitializesStaticPlaybooksAndShortcuts()
    {
        var vm = new OperatorGuideViewModel();

        Assert.NotEmpty(vm.PlaybookSteps);
        Assert.NotEmpty(vm.Shortcuts);
        Assert.Contains(vm.PlaybookSteps, p => p.Code == "IR-101");
        Assert.Contains(vm.Shortcuts, s => s.Shortcut == "Ctrl + 1");
    }
}
