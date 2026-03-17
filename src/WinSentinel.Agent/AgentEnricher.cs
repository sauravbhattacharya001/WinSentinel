using Serilog.Core;
using Serilog.Events;
using System.Reflection;

namespace WinSentinel.Agent;

/// <summary>
/// Serilog enricher that attaches agent metadata to every log event.
/// Adds AgentVersion, MachineName, and OSVersion properties automatically.
/// </summary>
public class AgentEnricher : ILogEventEnricher
{
    private static readonly string AgentVersion =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";

    private static readonly string OsVersion =
        $"{Environment.OSVersion.Platform} {Environment.OSVersion.Version}";

    private static readonly string Machine = Environment.MachineName;

    /// <inheritdoc />
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("AgentVersion", AgentVersion));
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("OSVersion", OsVersion));

        // Default module context when not set via LogContext.PushProperty
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("Module", "Agent"));
    }
}
