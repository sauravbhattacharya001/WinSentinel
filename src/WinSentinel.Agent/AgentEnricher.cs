using Serilog.Core;
using Serilog.Events;

namespace WinSentinel.Agent;

/// <summary>
/// Serilog enricher that attaches agent-specific context to every log entry.
/// Properties added: MachineName, OSVersion, AgentVersion, RiskTolerance.
/// </summary>
/// <remarks>
/// MachineName, OSVersion, and AgentVersion are constant for the lifetime of the
/// process, so their LogEventProperty instances are pre-built once and reused on
/// every Enrich() call. This eliminates three string→property allocations per log
/// event — significant when the agent emits thousands of structured log entries
/// during active monitoring.
/// </remarks>
public sealed class AgentEnricher : ILogEventEnricher
{
    private readonly AgentConfig _config;

    private static readonly string AgentVersion =
        typeof(AgentEnricher).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    // Pre-built immutable properties — reused on every Enrich() call.
    private static readonly LogEventProperty MachineNameProp =
        new("MachineName", new ScalarValue(Environment.MachineName));
    private static readonly LogEventProperty OsVersionProp =
        new("OSVersion", new ScalarValue(Environment.OSVersion.ToString()));
    private static readonly LogEventProperty AgentVersionProp =
        new("AgentVersion", new ScalarValue(AgentVersion));

    // Cached per-instance: only changes if AgentConfig.RiskTolerance changes.
    private volatile LogEventProperty? _riskToleranceProp;
    private string? _lastRiskTolerance;

    public AgentEnricher(AgentConfig config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        logEvent.AddPropertyIfAbsent(MachineNameProp);
        logEvent.AddPropertyIfAbsent(OsVersionProp);
        logEvent.AddPropertyIfAbsent(AgentVersionProp);

        // RiskTolerance can change at runtime, so cache and invalidate on change.
        var currentRisk = _config.RiskTolerance.ToString();
        var cached = _riskToleranceProp;
        if (cached == null || _lastRiskTolerance != currentRisk)
        {
            cached = new LogEventProperty("RiskTolerance", new ScalarValue(currentRisk));
            _riskToleranceProp = cached;
            _lastRiskTolerance = currentRisk;
        }
        logEvent.AddPropertyIfAbsent(cached);
    }
}
