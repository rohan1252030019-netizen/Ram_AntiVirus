using Aegis.App.ViewModels;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Moq;
using Xunit;

namespace Aegis.Tests;

public class MainViewModelRoleTests
{
    private readonly Mock<INavigationService> _mockNav = new();
    private readonly Mock<IAuthService> _mockAuth = new();
    private readonly Mock<IAegisWebSocketService> _mockWs = new();
    private readonly Mock<INetworkStatusService> _mockNetwork = new();

    [Fact]
    public void RefreshRoleVisibility_ViewerRole_HidesAdminAndAnalystModules()
    {
        // Arrange
        var viewer = new UserDto("usr_viewer", "viewer@aegis.local", "Read-Only Auditor", UserRole.Viewer);
        _mockAuth.SetupGet(x => x.CurrentUser).Returns(viewer);
        _mockAuth.SetupGet(x => x.CurrentRole).Returns(UserRole.Viewer);
        _mockAuth.Setup(x => x.HasRole(UserRole.Analyst)).Returns(false);
        _mockAuth.Setup(x => x.HasRole(UserRole.Admin)).Returns(false);

        var vm = new MainViewModel(_mockNav.Object, _mockAuth.Object, _mockWs.Object, _mockNetwork.Object);

        // Act
        vm.RefreshRoleVisibility();

        // Assert
        var dashboardItem = vm.NavItems.First(i => i.Title == "Dashboard");
        Assert.True(dashboardItem.IsVisible);

        var incidentItem = vm.NavItems.First(i => i.Title == "Incident Queue");
        Assert.False(incidentItem.IsVisible);

        var firewallItem = vm.NavItems.First(i => i.Title == "Firewall");
        Assert.False(firewallItem.IsVisible);
    }

    [Fact]
    public void RefreshRoleVisibility_AdminRole_ExposesAllModules()
    {
        // Arrange
        var admin = new UserDto("usr_admin", "admin@aegis.local", "System Admin", UserRole.Admin);
        _mockAuth.SetupGet(x => x.CurrentUser).Returns(admin);
        _mockAuth.SetupGet(x => x.CurrentRole).Returns(UserRole.Admin);
        _mockAuth.Setup(x => x.HasRole(It.IsAny<UserRole>())).Returns(true);

        var vm = new MainViewModel(_mockNav.Object, _mockAuth.Object, _mockWs.Object, _mockNetwork.Object);

        // Act
        vm.RefreshRoleVisibility();

        // Assert
        Assert.All(vm.NavItems, item => Assert.True(item.IsVisible));
    }
}
