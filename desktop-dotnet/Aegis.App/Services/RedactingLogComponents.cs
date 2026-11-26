using System.IO;
using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Display;

namespace Aegis.App.Services;

public class SensitiveDataEnricher : ILogEventEnricher
{
    private static readonly string[] SensitiveKeys = { "password", "token", "apikey", "api_key", "secret", "auth", "webhook", "bot_token", "chat_id" };

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        foreach (var prop in logEvent.Properties.ToList())
        {
            if (SensitiveKeys.Any(k => prop.Key.Contains(k, StringComparison.OrdinalIgnoreCase)))
            {
                logEvent.AddOrUpdateProperty(new LogEventProperty(prop.Key, new ScalarValue("[REDACTED]")));
            }
        }
    }
}

public class RedactingTextFormatter : ITextFormatter
{
    private readonly MessageTemplateTextFormatter _innerFormatter;
    private static readonly Regex SensitiveRegex = new(
        "(?i)(?<=(?:password|token|api_key|apikey|secret|authorization|webhook|webhook_url|bot_token|chat_id)\\s*[:=]\\s*[\"']?)[^\\s\"',;}\\]]+",
        RegexOptions.Compiled);

    public RedactingTextFormatter(string outputTemplate = "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    {
        _innerFormatter = new MessageTemplateTextFormatter(outputTemplate);
    }

    public void Format(LogEvent logEvent, TextWriter output)
    {
        using var sw = new StringWriter();
        _innerFormatter.Format(logEvent, sw);
        var formatted = sw.ToString();
        var redacted = SensitiveRegex.Replace(formatted, "[REDACTED]");
        output.Write(redacted);
    }
}
