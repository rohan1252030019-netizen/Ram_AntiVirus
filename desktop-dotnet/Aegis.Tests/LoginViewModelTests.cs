using System.Net.Http;
using Aegis.App.ViewModels;
using Aegis.Core.Enums;
using Aegis.Core.Interfaces;
using Aegis.Core.Models;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Aegis.Tests;

public class LoginViewModelTests
{
    private readonly Mock<IAegisApiClient> _mockApi;
    private readonly Mock<IAuthService> _mockAuth;
    private readonly Mock<INavigationService> _mockNav;
    private readonly Mock<ILogger<LoginViewModel>> _mockLogger;

    public LoginViewModelTests()
    {
        _mockApi = new Mock<IAegisApiClient>();
        _mockAuth = new Mock<IAuthService>();
        _mockNav = new Mock<INavigationService>();
        _mockLogger = new Mock<ILogger<LoginViewModel>>();
    }

    [Fact]
    public async Task LoginAsync_ValidCredentials_PersistsSessionAndNavigatesToDashboard()
    {
        // Arrange
        var user = new UserDto("usr_1", "admin@aegis.local", "Admin User", UserRole.Admin);
        var loginResponse = new UserLoginResponse("valid_jwt_token_12345", user);

        _mockApi.Setup(x => x.LoginAsync("admin@aegis.local", "secret123", It.IsAny<CancellationToken>()))
                .ReturnsAsync(loginResponse);

        var vm = new LoginViewModel(_mockApi.Object, _mockAuth.Object, _mockNav.Object, _mockLogger.Object)
        {
            Email = "admin@aegis.local",
            Password = "secret123",
            RememberMe = true
        };

        // Act
        await vm.LoginAsync();

        // Assert
        Assert.Null(vm.ErrorMessage);
        Assert.False(vm.IsBusy);
        _mockAuth.Verify(x => x.SaveCredentialsAsync("valid_jwt_token_12345", user, true), Times.Once);
        _mockNav.Verify(x => x.NavigateTo<DashboardOverviewViewModel>(), Times.Once);
    }

    [Fact]
    public async Task LoginAsync_InvalidCredentials_SetsErrorMessageAndDoesNotNavigate()
    {
        // Arrange
        _mockApi.Setup(x => x.LoginAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new HttpRequestException("401 Unauthorized"));

        var vm = new LoginViewModel(_mockApi.Object, _mockAuth.Object, _mockNav.Object, _mockLogger.Object)
        {
            Email = "attacker@evil.com",
            Password = "wrong"
        };

        // Act
        await vm.LoginAsync();

        // Assert
        Assert.NotNull(vm.ErrorMessage);
        Assert.Contains("Invalid email or password", vm.ErrorMessage);
        _mockNav.Verify(x => x.NavigateTo<DashboardOverviewViewModel>(), Times.Never);
    }
}
