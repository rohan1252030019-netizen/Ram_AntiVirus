using System.Text.Json.Serialization;

namespace Aegis.Core.Models;

public record ClientSettingsDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = "";

    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("slug")]
    public string Slug { get; init; } = "";

    [JsonPropertyName("api_key")]
    public string ApiKey { get; init; } = "";

    [JsonPropertyName("settings")]
    public Dictionary<string, object>? Settings { get; init; } = null;

    [JsonIgnore]
    public List<string> SafeIps { get; init; } = new();

    [JsonIgnore]
    public double RiskThreshold { get; init; } = 75.0;

    [JsonIgnore]
    public string AiMode { get; init; } = "local";

    [JsonIgnore]
    public string ClientId => Id;

    [JsonConstructor]
    public ClientSettingsDto(
        string id = "",
        string name = "",
        string slug = "",
        string apiKey = "",
        Dictionary<string, object>? settings = null)
    {
        Id = id;
        Name = name;
        Slug = slug;
        ApiKey = apiKey;
        Settings = settings;
    }

    public ClientSettingsDto(
        string clientId,
        string name,
        string slug,
        List<string> safeIps,
        double riskThreshold = 75.0,
        string aiMode = "local")
        : this(clientId, name, slug, "", null)
    {
        SafeIps = safeIps;
        RiskThreshold = riskThreshold;
        AiMode = aiMode;
    }
}

public record NotificationConfigDto
{
    [JsonPropertyName("webhook_url")]
    public string? WebhookUrl { get; init; } = null;

    [JsonPropertyName("webhook_format")]
    public string WebhookFormat { get; init; } = "generic";

    [JsonPropertyName("email_enabled")]
    public bool EmailEnabled { get; init; } = false;

    [JsonPropertyName("email_recipients")]
    public List<string>? EmailRecipients { get; init; } = null;

    [JsonPropertyName("notify_on_critical")]
    public bool NotifyOnCritical { get; init; } = true;

    [JsonPropertyName("notify_on_high")]
    public bool NotifyOnHigh { get; init; } = true;

    [JsonPropertyName("notify_on_actions")]
    public bool NotifyOnActions { get; init; } = true;

    [JsonPropertyName("notify_on_scan_completed")]
    public bool NotifyOnScanCompleted { get; init; } = false;

    [JsonPropertyName("channels")]
    public List<string>? Channels { get; init; } = null;

    [JsonPropertyName("telegram_enabled")]
    public bool TelegramEnabled { get; init; } = false;

    [JsonPropertyName("telegram_bot_token")]
    public string? TelegramBotToken { get; init; } = null;

    [JsonPropertyName("telegram_chat_id")]
    public string? TelegramChatId { get; init; } = null;

    [JsonPropertyName("telegram_connected")]
    public bool TelegramConnected { get; init; } = false;

    [JsonIgnore]
    public bool NotifyCriticalOnly { get; init; } = true;

    [JsonIgnore]
    public bool Enabled { get; init; } = true;

    [JsonConstructor]
    public NotificationConfigDto(
        string? webhookUrl = null,
        string webhookFormat = "generic",
        bool emailEnabled = false,
        List<string>? emailRecipients = null,
        bool notifyOnCritical = true,
        bool notifyOnHigh = true,
        bool notifyOnActions = true,
        bool notifyOnScanCompleted = false,
        List<string>? channels = null,
        bool telegramEnabled = false,
        string? telegramBotToken = null,
        string? telegramChatId = null,
        bool telegramConnected = false)
    {
        WebhookUrl = webhookUrl;
        WebhookFormat = webhookFormat;
        EmailEnabled = emailEnabled;
        EmailRecipients = emailRecipients;
        NotifyOnCritical = notifyOnCritical;
        NotifyOnHigh = notifyOnHigh;
        NotifyOnActions = notifyOnActions;
        NotifyOnScanCompleted = notifyOnScanCompleted;
        Channels = channels;
        TelegramEnabled = telegramEnabled;
        TelegramBotToken = telegramBotToken;
        TelegramChatId = telegramChatId;
        TelegramConnected = telegramConnected;
        NotifyCriticalOnly = notifyOnCritical && !notifyOnHigh;
        Enabled = telegramEnabled || emailEnabled || (channels != null && channels.Count > 0);
    }

    public NotificationConfigDto(
        string? telegramBotToken = null,
        string? telegramChatId = null,
        string? webhookUrl = null,
        bool notifyCriticalOnly = true,
        bool enabled = false)
        : this(webhookUrl, "generic", false, null, notifyCriticalOnly, !notifyCriticalOnly, true, false, null, enabled, telegramBotToken, telegramChatId, false)
    {
    }
}

public record NotificationTestResponse(
    [property: JsonPropertyName("success")] bool Success = true,
    [property: JsonPropertyName("message")] string Message = "Notification sent successfully"
);

public record ClientSettingsUpdate(
    [property: JsonPropertyName("name")] string? Name = null,
    [property: JsonPropertyName("settings")] Dictionary<string, object>? Settings = null
);

public record NotificationUpdate(
    [property: JsonPropertyName("webhook_url")] string? WebhookUrl = null,
    [property: JsonPropertyName("webhook_format")] string? WebhookFormat = null,
    [property: JsonPropertyName("email_enabled")] bool? EmailEnabled = null,
    [property: JsonPropertyName("email_recipients")] List<string>? EmailRecipients = null,
    [property: JsonPropertyName("notify_on_critical")] bool? NotifyOnCritical = null,
    [property: JsonPropertyName("notify_on_high")] bool? NotifyOnHigh = null,
    [property: JsonPropertyName("notify_on_actions")] bool? NotifyOnActions = null,
    [property: JsonPropertyName("notify_on_scan_completed")] bool? NotifyOnScanCompleted = null,
    [property: JsonPropertyName("channels")] List<string>? Channels = null,
    [property: JsonPropertyName("telegram_enabled")] bool? TelegramEnabled = null,
    [property: JsonPropertyName("telegram_bot_token")] string? TelegramBotToken = null,
    [property: JsonPropertyName("telegram_chat_id")] string? TelegramChatId = null
);

public record NotificationTestRequest(
    [property: JsonPropertyName("test")] bool Test = true,
    [property: JsonPropertyName("channel")] string Channel = "webhook"
);

public record IntelSharingStatusDto(
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("mode")] string Mode = "community",
    [property: JsonPropertyName("hub_url")] string? HubUrl = null,
    [property: JsonPropertyName("min_confidence")] double MinConfidence = 0.7
);
