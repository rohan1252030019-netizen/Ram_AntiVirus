using System.Net.Http;
using Aegis.App.ViewModels;
using Aegis.Core.Exceptions;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Aegis.Tests;

public class EdrViewModelTests
{
    private readonly Mock<IAegisApiClient> _mockApi = new();
    private readonly Mock<IDialogService> _mockDialog = new();
    private readonly ILogger<EdrViewModel> _logger = Mock.Of<ILogger<EdrViewModel>>();

    [Fact]
    public async Task LoadEvents_PopulatesEventsList()
    {
        var sampleEvents = new List<RecentEdrEventDto>
        {
            new("ev_1", "process", "high", "powershell.exe executed", null, "2026-11-03")
        };
        _mockApi.Setup(a => a.GetRecentEdrEventsAsync("host-monitor-local", 60, 100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(sampleEvents);

        var vm = new EdrViewModel(_mockApi.Object, _mockDialog.Object, _logger);
        await vm.LoadEventsAsync();

        Assert.Single(vm.Events);
        Assert.Equal("powershell.exe executed", vm.Events[0].Title);
        Assert.False(vm.IsBusy);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task LoadEvents_OnApiError_SetsErrorMessage_NoCrash()
    {
        _mockApi.Setup(a => a.GetRecentEdrEventsAsync(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Connection reset by peer"));

        var vm = new EdrViewModel(_mockApi.Object, _mockDialog.Object, _logger);
        await vm.LoadEventsAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Failed to fetch EDR telemetry", vm.ErrorMessage);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task LoadEvents_On403_SetsAccessDenied_NoCrash()
    {
        _mockApi.Setup(a => a.GetRecentEdrEventsAsync(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new AegisForbiddenException("Forbidden"));

        var vm = new EdrViewModel(_mockApi.Object, _mockDialog.Object, _logger);
        await vm.LoadEventsAsync();

        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Access Denied", vm.ErrorMessage);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task KillProcess_WhenConfirmed_CallsApi()
    {
        var vm = new EdrViewModel(_mockApi.Object, _mockDialog.Object, _logger)
        {
            SelectedPid = 1234
        };

        _mockDialog.Setup(d => d.ShowConfirmationAsync(It.IsAny<string>(), It.IsAny<string>(), "Terminate Process", "Cancel"))
            .ReturnsAsync(true);
        _mockApi.Setup(a => a.KillProcessAsync(It.Is<KillProcessRequest>(r => r.Pid == 1234 && r.Confirm == true), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _mockApi.Setup(a => a.GetRecentEdrEventsAsync(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<RecentEdrEventDto>());

        await vm.KillProcessAsync();

        _mockApi.Verify(a => a.KillProcessAsync(It.Is<KillProcessRequest>(r => r.Pid == 1234 && r.Confirm == true), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task KillProcess_WhenCancelled_DoesNotCallApi()
    {
        var vm = new EdrViewModel(_mockApi.Object, _mockDialog.Object, _logger)
        {
            SelectedPid = 1234
        };

        _mockDialog.Setup(d => d.ShowConfirmationAsync(It.IsAny<string>(), It.IsAny<string>(), "Terminate Process", "Cancel"))
            .ReturnsAsync(false);

        await vm.KillProcessAsync();

        _mockApi.Verify(a => a.KillProcessAsync(It.IsAny<KillProcessRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IsolateHost_WhenHostnameMatches_CallsApiWithConfirmTrue()
    {
        var vm = new EdrViewModel(_mockApi.Object, _mockDialog.Object, _logger)
        {
            AgentId = "target-node-99",
            TargetHostname = "target-node-99"
        };

        _mockDialog.Setup(d => d.ConfirmHostIsolationAsync("target-node-99", "target-node-99"))
            .ReturnsAsync(true);
        _mockApi.Setup(a => a.IsolateHostAsync("target-node-99", It.Is<IsolateHostRequest>(r => r.Confirm == true), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        await vm.IsolateHostAsync();

        _mockApi.Verify(a => a.IsolateHostAsync("target-node-99", It.Is<IsolateHostRequest>(r => r.Confirm == true), It.IsAny<CancellationToken>()), Times.Once);
        Assert.True(vm.IsHostIsolated);
    }

    [Fact]
    public async Task IsolateHost_WhenCancelled_DoesNotCallApi()
    {
        var vm = new EdrViewModel(_mockApi.Object, _mockDialog.Object, _logger)
        {
            AgentId = "target-node-99",
            TargetHostname = "target-node-99"
        };

        _mockDialog.Setup(d => d.ConfirmHostIsolationAsync("target-node-99", "target-node-99"))
            .ReturnsAsync(false);

        await vm.IsolateHostAsync();

        _mockApi.Verify(a => a.IsolateHostAsync(It.IsAny<string>(), It.IsAny<IsolateHostRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.False(vm.IsHostIsolated);
    }
}
