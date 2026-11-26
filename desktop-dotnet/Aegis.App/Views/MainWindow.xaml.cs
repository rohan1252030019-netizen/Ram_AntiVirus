using System.IO;
using System.Text.Json;
using System.Windows;

namespace Aegis.App.Views;

public partial class MainWindow : Window
{
    private static readonly string StatePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AegisDesktop",
        "window_state.json");

    public MainWindow()
    {
        InitializeComponent();
        RestoreWindowState();
        Closing += (_, _) => SaveWindowState();
    }

    private void RestoreWindowState()
    {
        try
        {
            if (!File.Exists(StatePath)) return;

            var json = File.ReadAllText(StatePath);
            var state = JsonSerializer.Deserialize<WindowPlacementState>(json);
            if (state == null) return;

            // Ensure window is within virtual screen bounds
            if (state.Left >= SystemParameters.VirtualScreenLeft &&
                state.Top >= SystemParameters.VirtualScreenTop &&
                state.Left + state.Width <= SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth &&
                state.Top + state.Height <= SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight)
            {
                WindowStartupLocation = WindowStartupLocation.Manual;
                Left = state.Left;
                Top = state.Top;
                Width = Math.Max(MinWidth, state.Width);
                Height = Math.Max(MinHeight, state.Height);
            }

            if (state.IsMaximized)
            {
                WindowState = WindowState.Maximized;
            }
        }
        catch
        {
            // Fallback to default CenterScreen if corrupt
        }
    }

    private void SaveWindowState()
    {
        try
        {
            var dir = Path.GetDirectoryName(StatePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var state = new WindowPlacementState
            {
                Left = RestoreBounds.Left,
                Top = RestoreBounds.Top,
                Width = RestoreBounds.Width,
                Height = RestoreBounds.Height,
                IsMaximized = WindowState == WindowState.Maximized
            };

            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(StatePath, json);
        }
        catch
        {
            // Persistence best-effort
        }
    }

    private class WindowPlacementState
    {
        public double Left { get; set; }
        public double Top { get; set; }
        public double Width { get; set; }
        public double Height { get; set; }
        public bool IsMaximized { get; set; }
    }
}
