using Serilog.Core;
using Serilog.Events;

namespace WinSentinel.Agent;

/// <summary>
/// Serilog enricher that attaches agent-specific context to every log entry.
/// Properties added: MachineName, OSVersion, AgentVersion, RiskTolerance.
/// </summary>
public sealed class AgentEnricher : ILogEventEnricher
{
    private readonly AgentConfig _config;

    private static readonly string AgentVersion =
        typeof(AgentEnricher).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    public AgentEnricher(AgentConfig config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("MachineName", Environment.MachineName));
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("OSVersion", Environment.OSVersion.ToString()));
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("AgentVersion", AgentVersion));
        logEvent.AddPropertyIfAbsent(
            propertyFactory.CreateProperty("RiskTolerance", _config.RiskTolerance.ToString()));
    }
}
