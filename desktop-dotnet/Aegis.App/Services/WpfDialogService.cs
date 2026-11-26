using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Aegis.Core.Interfaces;
using Microsoft.Extensions.Configuration;

namespace Aegis.App.Services;

public class WpfDialogService : IDialogService
{
    private readonly IConfiguration? _configuration;

    public WpfDialogService(IConfiguration? configuration = null)
    {
        _configuration = configuration;
    }
    public Task ShowMessageAsync(string title, string message)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
        });
        return Task.CompletedTask;
    }

    public Task ShowErrorAsync(string title, string message)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
        });
        return Task.CompletedTask;
    }

    public Task<bool> ShowConfirmationAsync(string title, string message, string confirmText = "Confirm", string cancelText = "Cancel")
    {
        var result = false;
        Application.Current?.Dispatcher.Invoke(() =>
        {
            var res = MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning);
            result = res == MessageBoxResult.Yes;
        });
        return Task.FromResult(result);
    }

    public Task<string?> ShowPromptAsync(string title, string message, string defaultText = "")
    {
        string? result = null;
        Application.Current?.Dispatcher.Invoke(() =>
        {
            var win = new Window
            {
                Title = title,
                Width = 460,
                Height = 220,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                Background = new SolidColorBrush(Color.FromRgb(15, 23, 42)),
                Foreground = Brushes.White,
                ResizeMode = ResizeMode.NoResize,
                WindowStyle = WindowStyle.ToolWindow
            };

            var stack = new StackPanel { Margin = new Thickness(20) };
            var msgBlock = new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 15),
                Foreground = new SolidColorBrush(Color.FromRgb(226, 232, 240)),
                FontSize = 13
            };
            stack.Children.Add(msgBlock);

            var textBox = new TextBox
            {
                Text = defaultText,
                Margin = new Thickness(0, 0, 0, 20),
                Background = new SolidColorBrush(Color.FromRgb(30, 41, 59)),
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(Color.FromRgb(51, 65, 85)),
                Padding = new Thickness(8, 6, 8, 6),
                FontSize = 13
            };
            stack.Children.Add(textBox);

            var btnPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var cancelBtn = new Button
            {
                Content = "Cancel",
                Width = 80,
                Height = 30,
                Margin = new Thickness(0, 0, 10, 0),
                Background = Brushes.Transparent,
                Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184))
            };
            cancelBtn.Click += (_, _) => win.Close();
            btnPanel.Children.Add(cancelBtn);

            var okBtn = new Button
            {
                Content = "OK",
                Width = 80,
                Height = 30,
                Background = new SolidColorBrush(Color.FromRgb(6, 182, 212)),
                Foreground = new SolidColorBrush(Color.FromRgb(15, 23, 42)),
                FontWeight = FontWeights.Bold
            };
            okBtn.Click += (_, _) =>
            {
                result = textBox.Text;
                win.Close();
            };
            btnPanel.Children.Add(okBtn);

            stack.Children.Add(btnPanel);
            win.Content = stack;
            textBox.Focus();
            win.ShowDialog();
        });

        return Task.FromResult(result);
    }

    public async Task<bool> ConfirmHostIsolationAsync(string agentId, string hostname)
    {
        var localMachine = Environment.MachineName;
        var backendUrl = _configuration?["Aegis:BackendUrl"] ?? "http://localhost:8000";
        string? backendHost = null;
        if (Uri.TryCreate(backendUrl, UriKind.Absolute, out var uri))
        {
            backendHost = uri.Host;
        }

        bool isLocalOrServer = string.Equals(hostname, localMachine, StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(hostname, "localhost", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(agentId, "host-monitor-local", StringComparison.OrdinalIgnoreCase) ||
                               hostname.Contains("127.0.0.1") ||
                               (!string.IsNullOrEmpty(backendHost) && (
                                   string.Equals(hostname, backendHost, StringComparison.OrdinalIgnoreCase) ||
                                   string.Equals(agentId, backendHost, StringComparison.OrdinalIgnoreCase) ||
                                   hostname.Contains(backendHost, StringComparison.OrdinalIgnoreCase)
                               ));

        if (isLocalOrServer)
        {
            var warningRes = await ShowConfirmationAsync(
                "CRITICAL WARNING: CONSOLE OR SERVER HOST DETECTED",
                $"Target '{hostname}' (Agent: '{agentId}') matches the local operator station or configured AEGIS backend server ({backendHost ?? backendUrl}).\n\n" +
                "Isolating this host will sever communication to the AEGIS control plane, disconnect remote nodes, and terminate your active session.\n\n" +
                "Are you absolutely certain you want to proceed?");

            if (!warningRes) return false;
        }

        var typed = await ShowPromptAsync(
            "Host Network Isolation Confirmation",
            $"This action will sever all network traffic for host '{hostname}', allowing only AEGIS management traffic.\n\n" +
            $"Type the exact hostname '{hostname}' to confirm isolation:",
            "");

        if (string.IsNullOrEmpty(typed))
            return false;

        return string.Equals(typed.Trim(), hostname.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
