namespace Aegis.Core.Interfaces;

public interface IDialogService
{
    Task ShowMessageAsync(string title, string message);
    Task ShowErrorAsync(string title, string message);
    Task<bool> ShowConfirmationAsync(string title, string message, string confirmText = "Confirm", string cancelText = "Cancel");
    Task<string?> ShowPromptAsync(string title, string message, string defaultText = "");
    Task<bool> ConfirmHostIsolationAsync(string agentId, string hostname);

    Task<bool> ConfirmAsync(string title, string message) => ShowConfirmationAsync(title, message);
    Task ShowInfoAsync(string title, string message) => ShowMessageAsync(title, message);
}
