using System.Net;
using System.Net.Http;
using Aegis.App.ViewModels;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Moq;
using Xunit;

namespace Aegis.Tests;

public class AntivirusViewModelTests
{
    private readonly Mock<IAegisApiClient> _mockApi = new();
    private readonly Mock<IDialogService> _mockDialog = new();

    [Fact]
    public async Task LoadData_PopulatesSignaturesAndQuarantine()
    {
        var sigs = new SignatureBundleDto("1.0.4", new List<string> { "hash1", "hash2" }, "2026-11-03", 2);
        var qList = new List<QuarantineItemDto>
        {
            new("det_1", "agent_1", "C:\\temp\\malware.exe", "abcd1234", "Trojan.Dropper", "yara", 1024, "2026-11-03")
        };

        _mockApi.Setup(a => a.GetSignaturesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(sigs);
        _mockApi.Setup(a => a.GetQuarantineListAsync(100, It.IsAny<CancellationToken>())).ReturnsAsync(qList);

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.Signatures);
        Assert.Equal("1.0.4", vm.Signatures.Version);
        Assert.Single(vm.QuarantineItems);
        Assert.Equal("C:\\temp\\malware.exe", vm.QuarantineItems[0].Path);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task LoadData_OnApiError_SetsErrorMessage_NoCrash()
    {
        _mockApi.Setup(a => a.GetSignaturesAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Server error 500"));

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Failed to load antivirus data", vm.ErrorMessage);
        Assert.False(vm.IsLoading);
    }

    [Fact]
    public async Task LoadData_On403_SetsAccessDenied_NoCrash()
    {
        _mockApi.Setup(a => a.GetSignaturesAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Forbidden", null, HttpStatusCode.Forbidden));

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.LoadDataAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
        Assert.False(vm.IsLoading);
    }

    [Fact]
    public async Task UpdateSignatures_WhenConfirmed_CallsApi()
    {
        var updated = new SignatureBundleDto("1.0.5", new List<string> { "hash1", "hash2", "hash3" }, "2026-11-03", 3);
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(true);
        _mockApi.Setup(a => a.UpdateSignaturesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(updated);

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.UpdateSignaturesAsync();

        _mockApi.Verify(a => a.UpdateSignaturesAsync(It.IsAny<CancellationToken>()), Times.Once);
        Assert.Equal("1.0.5", vm.Signatures?.Version);
    }

    [Fact]
    public async Task UpdateSignatures_WhenCancelled_DoesNotCallApi()
    {
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(false);

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.UpdateSignaturesAsync();

        _mockApi.Verify(a => a.UpdateSignaturesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ReleaseQuarantine_WhenConfirmed_ReleasesFile()
    {
        var item = new QuarantineItemDto("det_1", "agent_1", "C:\\malware.bin", "hash", "Rule", "Engine", 512, "2026");
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(true);
        _mockApi.Setup(a => a.ReleaseQuarantineAsync("det_1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReleaseQuarantineResponse(true, "det_1", "hash"));
        _mockApi.Setup(a => a.GetSignaturesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SignatureBundleDto("1.0", new List<string>()));
        _mockApi.Setup(a => a.GetQuarantineListAsync(100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<QuarantineItemDto>());

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.ReleaseQuarantineAsync(item);

        _mockApi.Verify(a => a.ReleaseQuarantineAsync("det_1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ReleaseQuarantine_WhenCancelled_DoesNotCallApi()
    {
        var item = new QuarantineItemDto("det_1", "agent_1", "C:\\malware.bin", "hash", "Rule", "Engine", 512, "2026");
        _mockDialog.Setup(d => d.ConfirmAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(false);

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object);
        await vm.ReleaseQuarantineAsync(item);

        _mockApi.Verify(a => a.ReleaseQuarantineAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task LookupHash_ReturnsResult()
    {
        _mockApi.Setup(a => a.LookupHashAsync("abcd", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new HashLookupDto("abcd", true, 5, "2026-11-03"));

        var vm = new AntivirusViewModel(_mockApi.Object, _mockDialog.Object)
        {
            HashToLookup = "abcd"
        };
        await vm.LookupHashAsync();

        Assert.NotNull(vm.HashResult);
        Assert.True(vm.HashResult.KnownBad);
        Assert.Equal(5, vm.HashResult.LocalDetections);
    }
}
