using System.IO;
using System.Windows;
using Aegis.App.Services;
using Aegis.App.ViewModels;
using Aegis.App.Views;
using Aegis.Core.Interfaces;
using Aegis.Services;
using Aegis.Services.Handlers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;

namespace Aegis.App;

public partial class App : Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        this.DispatcherUnhandledException += (s, args) =>
        {
            Log.Error(args.Exception, "Unhandled UI Exception caught by Global Dispatcher Handler: {Message}", args.Exception.Message);
            args.Handled = true;
            MessageBox.Show(
                $"An unexpected application error occurred:\n\n{args.Exception.Message}\n\nThe event has been securely recorded to the console audit log.",
                "Ram Antivirus Error",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        };

        var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RamAntivirus", "logs");
        Directory.CreateDirectory(logDir);
        var logPath = Path.Combine(logDir, "ramantivirus-.log");

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Enrich.With<SensitiveDataEnricher>()
            .WriteTo.File(new RedactingTextFormatter(), logPath, rollingInterval: RollingInterval.Day, retainedFileCountLimit: 7)
            .CreateLogger();

        Log.Information("Starting Ram Antivirus Desktop Console v1.0.0...");

        _host = Host.CreateDefaultBuilder()
            .ConfigureAppConfiguration((ctx, config) =>
            {
                config.SetBasePath(AppDomain.CurrentDomain.BaseDirectory);
                config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
            })
            .ConfigureServices((ctx, services) =>
            {
                var cfg = ctx.Configuration;
                var backendUrl = cfg["RamAntivirus:BackendUrl"] ?? cfg["Aegis:BackendUrl"] ?? "http://localhost:8000";
                var useMock = cfg.GetValue<bool>("RamAntivirus:UseMockData") || cfg.GetValue<bool>("Aegis:UseMockData");

                // Core Services
                services.AddSingleton<IAuthService, AuthService>();
                services.AddSingleton<INavigationService, NavigationService>();
                services.AddSingleton<IDialogService, WpfDialogService>();
                services.AddSingleton<INetworkStatusService, NetworkStatusService>();
                services.AddSingleton<IAegisWebSocketService, AegisWebSocketService>();
                services.AddSingleton<IConnectionSettingsService, ConnectionSettingsService>();

                // HTTP & Handlers
                services.AddTransient<AegisAuthenticationHandler>();
                services.AddHttpClient<AegisApiClient>(c =>
                {
                    c.BaseAddress = new Uri(backendUrl);
                    c.Timeout = TimeSpan.FromSeconds(15);
                })
                .AddHttpMessageHandler<AegisAuthenticationHandler>();

                if (useMock)
                {
                    Log.Information("Ram Antivirus Running in DEMO / MOCK Mode (backend optional)");
                    services.AddSingleton<IAegisApiClient, MockAegisApiClient>();
                }
                else
                {
                    services.AddTransient<IAegisApiClient, AegisApiClient>();
                }

                // ViewModels
                services.AddSingleton<MainViewModel>();
                services.AddTransient<LoginViewModel>();
                services.AddTransient<DashboardOverviewViewModel>();
                services.AddTransient<IncidentQueueViewModel>();
                services.AddTransient<IncidentDetailViewModel>();
                services.AddTransient<RansomwareDefenseViewModel>();
                services.AddTransient<FirewallRulesViewModel>();
                services.AddTransient<InfrastructureHealthViewModel>();
                services.AddTransient<SettingsViewModel>();
                services.AddTransient<EdrViewModel>();
                services.AddTransient<AntivirusViewModel>();
                services.AddTransient<AttackSurfaceViewModel>();
                services.AddTransient<PhantomViewModel>();
                services.AddTransient<DeceptionViewModel>();
                services.AddTransient<ThreatIntelViewModel>();
                services.AddTransient<IpInvestigationViewModel>();
                services.AddTransient<DosShieldViewModel>();
                services.AddTransient<ComplianceMatrixViewModel>();
                services.AddTransient<QuantumAnalyticsViewModel>();
                services.AddTransient<NodeManagementViewModel>();
                services.AddTransient<OperatorGuideViewModel>();

                // Windows
                services.AddSingleton<MainWindow>();
            })
            .UseSerilog()
            .Build();

        await _host.StartAsync();

        var mainWindow = _host.Services.GetRequiredService<MainWindow>();
        var mainVm = _host.Services.GetRequiredService<MainViewModel>();
        var authService = _host.Services.GetRequiredService<IAuthService>();
        var navService = _host.Services.GetRequiredService<INavigationService>();

        // Central session expiration handling -> Return to LoginView
        authService.SessionExpired += (s, args) =>
        {
            Dispatcher.Invoke(() =>
            {
                Log.Warning("Session expired event triggered. Returning to LoginView.");
                navService.NavigateTo<LoginViewModel>();
            });
        };

        mainWindow.DataContext = mainVm;
        mainWindow.Show();

        // Attempt silent login via DPAPI saved credentials
        var (savedToken, savedUser) = await authService.LoadSavedCredentialsAsync();
        if (!string.IsNullOrEmpty(savedToken) && savedUser != null)
        {
            mainVm.RefreshRoleVisibility();
            navService.NavigateTo<DashboardOverviewViewModel>();
        }
        else
        {
            navService.NavigateTo<LoginViewModel>();
        }
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host != null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
        Log.CloseAndFlush();
        base.OnExit(e);
    }
}
