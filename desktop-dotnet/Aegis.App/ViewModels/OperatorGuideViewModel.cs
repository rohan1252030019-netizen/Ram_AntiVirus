using CommunityToolkit.Mvvm.ComponentModel;
using System.Collections.ObjectModel;

namespace Aegis.App.ViewModels;

public record PlaybookStep(string Code, string Name, string Description, string ActionCommand);
public record ShortcutGuide(string Shortcut, string Action);

public partial class OperatorGuideViewModel : ViewModelBase
{
    [ObservableProperty]
    private ObservableCollection<PlaybookStep> _playbookSteps = new()
    {
        new("IR-101", "Ransomware Spread Containment", "Instantly isolate infected host endpoints via EDR panel and invoke volume shadow snapshot rollback.", "Ram Antivirus: Ransomware > Recovery"),
        new("IR-102", "DDoS Volumetric Mitigation", "Enable L7 rate-limiting shield and auto-jail abusive CIDRs exceeding burst allowances.", "Ram Antivirus: DoS Shield"),
        new("IR-103", "Compromised Credential Rotation", "Trigger deception honeynet lure rotation and invalidate leaked API keys across all registered nodes.", "Ram Antivirus: Deception > Rotate"),
        new("IR-104", "Active Malicious Process Termination", "Locate target PID in EDR live telemetry, verify parent process tree, and dispatch termination command to the Rust endpoint agent.", "Ram Antivirus: EDR > Kill PID"),
        new("IR-105", "Malware Artifact Vault Isolation", "Ingest file SHA-256 into AV quarantine vault and dispatch global hash blacklisting.", "Ram Antivirus: Antivirus > Quarantine")
    };

    [ObservableProperty]
    private ObservableCollection<ShortcutGuide> _shortcuts = new()
    {
        new("Ctrl + 1", "Navigate to Dashboard Overview"),
        new("Ctrl + 2", "Navigate to Incident Triage Queue"),
        new("Ctrl + 3", "Navigate to Ransomware Defense"),
        new("Ctrl + 4", "Navigate to EDR Telemetry & Isolation"),
        new("Ctrl + 5", "Navigate to Antivirus Vault"),
        new("Ctrl + 6", "Navigate to Attack Surface Exposure"),
        new("Ctrl + 7", "Navigate to Phantom Deception"),
        new("Ctrl + 8", "Navigate to Threat Intelligence"),
        new("Ctrl + 9", "Navigate to DoS Shield"),
        new("Ctrl + 0", "Navigate to Settings"),
        new("F5", "Force refresh active view telemetry")
    };
}
