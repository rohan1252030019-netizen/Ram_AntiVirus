using Aegis.App.ViewModels;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Moq;
using Xunit;

namespace Aegis.Tests;

public class WebSocketViewModelIntegrationTests
{
    [Fact]
    public void MainViewModel_UpdatesConnectionState_WhenWebSocketStateChanges()
    {
        // Arrange
        var mockNav = new Mock<INavigationService>();
        var mockAuth = new Mock<IAuthService>();
        var mockWs = new Mock<IAegisWebSocketService>();
        var mockNetwork = new Mock<INetworkStatusService>();

        var vm = new MainViewModel(mockNav.Object, mockAuth.Object, mockWs.Object, mockNetwork.Object);

        // Act - Simulate WS connected
        mockWs.Raise(w => w.ConnectionStateChanged += null, true);

        // Assert
        Assert.True(vm.IsWsConnected);
        Assert.Equal("Live (Connected)", vm.WsStatusText);

        // Act - Simulate WS disconnected
        mockWs.Raise(w => w.ConnectionStateChanged += null, false);

        // Assert
        Assert.False(vm.IsWsConnected);
        Assert.Equal("Offline (Reconnecting...)", vm.WsStatusText);
    }

    [Fact]
    public void MainViewModel_UpdatesOfflineBanner_WhenNetworkStatusChanges()
    {
        // Arrange
        var mockNav = new Mock<INavigationService>();
        var mockAuth = new Mock<IAuthService>();
        var mockWs = new Mock<IAegisWebSocketService>();
        var mockNetwork = new Mock<INetworkStatusService>();

        mockNetwork.SetupGet(n => n.IsOnline).Returns(true);

        var vm = new MainViewModel(mockNav.Object, mockAuth.Object, mockWs.Object, mockNetwork.Object);
        Assert.False(vm.IsOffline);

        // Act - network goes offline
        mockNetwork.SetupGet(n => n.IsOnline).Returns(false);
        mockNetwork.SetupGet(n => n.LastError).Returns("Failed to reach http://localhost:8000");
        mockNetwork.Raise(n => n.NetworkStatusChanged += null, EventArgs.Empty);

        // Assert
        Assert.True(vm.IsOffline);
        Assert.Equal("Failed to reach http://localhost:8000", vm.OfflineMessage);
    }

    [Fact]
    public void MainViewModel_SubscribesToExpectedTopics_OnConstruction()
    {
        // Arrange
        var mockNav = new Mock<INavigationService>();
        var mockAuth = new Mock<IAuthService>();
        var mockWs = new Mock<IAegisWebSocketService>();
        var mockNetwork = new Mock<INetworkStatusService>();

        // Act
        var vm = new MainViewModel(mockNav.Object, mockAuth.Object, mockWs.Object, mockNetwork.Object);

        // Assert
        mockWs.Verify(w => w.Subscribe("incidents.new", It.IsAny<Action<object?>>()), Times.Once);
        mockWs.Verify(w => w.Subscribe("ransomware.incident", It.IsAny<Action<object?>>()), Times.Once);
        mockWs.Verify(w => w.Subscribe("actions.new", It.IsAny<Action<object?>>()), Times.Once);
    }
}
