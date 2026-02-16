using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Services;

/// <summary>
/// The central decision-making engine for the WinSentinel agent.
/// Receives ThreatEvents from all monitor modules, evaluates them against policies,
/// correlates across modules, decides on response actions, and executes them.
/// </summary>
public class AgentBrain
{
    private readonly ILogger<AgentBrain> _logger;
    private readonly ResponsePolicy _policy;
    private readonly ThreatCorrelator _correlator;
    private readonly AutoRemediator _remediator;
    private readonly AgentJournal _journal;
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;

    /// <summary>Event fired when a decision is made (for IPC notification).</summary>
    public event Action<ThreatEvent, PolicyDecision>? DecisionMade;

    /// <summary>Event fired when a remediation is executed.</summary>
    public event Action<RemediationRecord>? RemediationExecuted;

    /// <summary>Event fired when a correlation is detected.</summary>
    public event Action<CorrelatedThreat>? CorrelationDetected;

    public AgentBrain(
        ILogger<AgentBrain> logger,
        ResponsePolicy policy,
        ThreatCorrelator correlator,
        AutoRemediator remediator,
        AgentJournal journal,
        ThreatLog threatLog,
        AgentConfig config)
    {
        _logger = logger;
        _policy = policy;
        _correlator = correlator;
        _remediator = remediator;
        _journal = journal;
        _threatLog = threatLog;
        _config = config;

        // Wire up correlation events
        _correlator.CorrelationDetected += OnCorrelationDetected;
    }

    /// <summary>
    /// Initialize the brain — subscribe to the threat log for incoming events.
    /// </summary>
    public void Initialize()
    {
        _threatLog.ThreatDetected += OnThreatDetected;

        // Load policy from disk
        _policy.Load();
        _policy.RiskTolerance = _config.RiskTolerance;

        // Record agent start
        _journal.Record(new JournalEntry
        {
            EntryType = JournalEntryType.AgentStarted,
            Source = "AgentBrain",
            Summary = "Agent brain initialized",
            Details = $"Risk tolerance: {_config.RiskTolerance}. " +
                      $"Custom rules: {_policy.Rules.Count}. " +
                      $"User overrides: {_policy.UserOverrides.Count}."
        });

        // Backup hosts file if clean
        _remediator.BackupHostsFile();

        _logger.LogInformation("AgentBrain initialized. Risk tolerance: {Risk}", _config.RiskTolerance);
    }

    /// <summary>
    /// Shut down the brain — unsubscribe from events.
    /// </summary>
    public void Shutdown()
    {
        _threatLog.ThreatDetected -= OnThreatDetected;
        _correlator.CorrelationDetected -= OnCorrelationDetected;

        _journal.Record(new JournalEntry
        {
            EntryType = JournalEntryType.AgentStopped,
            Source = "AgentBrain",
            Summary = "Agent brain shut down"
        });

        _logger.LogInformation("AgentBrain shut down");
    }

    /// <summary>
    /// Process a single threat event through the decision pipeline.
    /// This is the core logic: evaluate → correlate → decide → act → record.
    /// </summary>
    public PolicyDecision ProcessThreat(ThreatEvent threat)
    {
        // 1. Evaluate against policy
        var decision = _policy.Evaluate(threat);

        _logger.LogDebug(
            "Policy decision for '{Title}' [{Severity}]: {Action} (rule: {Rule})",
            threat.Title, threat.Severity, decision.Action, decision.MatchedRule);

        // 2. Run through correlator (may elevate severity)
        var correlations = _correlator.ProcessEvent(threat);
        if (correlations.Count > 0)
        {
            // Re-evaluate at elevated severity
            var highestCorrelation = correlations.OrderByDescending(c => c.ThreatScore).First();
            if (highestCorrelation.CombinedSeverity > threat.Severity)
            {
                _logger.LogWarning(
                    "Correlation elevated '{Title}' from {Old} to {New}",
                    threat.Title, threat.Severity, highestCorrelation.CombinedSeverity);

                // Create an elevated threat event for the correlation
                var correlatedThreat = new ThreatEvent
                {
                    Source = "ThreatCorrelator",
                    Severity = highestCorrelation.CombinedSeverity,
                    Title = $"Correlated: {highestCorrelation.RuleName}",
                    Description = highestCorrelation.ChainDescription,
                    AutoFixable = threat.AutoFixable,
                    FixCommand = threat.FixCommand
                };

                // Re-evaluate the correlated threat
                decision = _policy.Evaluate(correlatedThreat);
                _threatLog.Add(correlatedThreat);
            }
        }

        // 3. Record the decision
        _journal.RecordThreat(threat, decision);

        // 4. Execute response
        ExecuteDecision(threat, decision);

        // 5. Notify listeners
        DecisionMade?.Invoke(threat, decision);

        return decision;
    }

    /// <summary>
    /// Handle user feedback on a threat (for learning).
    /// </summary>
    public void HandleUserFeedback(string threatEventId, string feedback, bool createOverride = false)
    {
        _journal.RecordUserFeedback(threatEventId, feedback);

        if (createOverride)
        {
            // Find the original threat
            var threats = _threatLog.GetAll();
            var threat = threats.FirstOrDefault(t => t.Id == threatEventId);

            if (threat != null)
            {
                var overrideAction = feedback.ToLowerInvariant() switch
                {
                    "ignore" or "dismiss" or "false_positive" => UserOverrideAction.AlwaysIgnore,
                    "autofix" or "auto_fix" or "always_fix" => UserOverrideAction.AlwaysAutoFix,
                    "alert" or "always_alert" => UserOverrideAction.AlwaysAlert,
                    _ => (UserOverrideAction?)null
                };

                if (overrideAction.HasValue)
                {
                    _policy.AddUserOverride(threat.Title, overrideAction.Value, threat.Source);
                    _logger.LogInformation(
                        "User override created: {Action} for '{Title}' from {Source}",
                        overrideAction.Value, threat.Title, threat.Source);
                }
            }
        }
    }

    /// <summary>
    /// Undo a previous remediation action.
    /// </summary>
    public RemediationRecord UndoRemediation(string remediationId)
    {
        var result = _remediator.Undo(remediationId);
        _journal.RecordRemediation(result);
        return result;
    }

    /// <summary>Get the response policy (for UI display/editing).</summary>
    public ResponsePolicy Policy => _policy;

    /// <summary>Get the journal (for UI queries).</summary>
    public AgentJournal Journal => _journal;

    /// <summary>Get the remediator (for history display).</summary>
    public AutoRemediator Remediator => _remediator;

    /// <summary>Get the correlator (for window inspection).</summary>
    public ThreatCorrelator Correlator => _correlator;

    // ══════════════════════════════════════════
    //  Private Handlers
    // ══════════════════════════════════════════

    private void OnThreatDetected(ThreatEvent threat)
    {
        // Skip events from the brain itself to avoid recursion
        if (threat.Source == "Agent" || threat.Source == "ThreatCorrelator")
        {
            // Still record in journal, but don't process through the pipeline
            _journal.RecordThreat(threat);
            return;
        }

        try
        {
            ProcessThreat(threat);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing threat: {Title}", threat.Title);
        }
    }

    private void OnCorrelationDetected(CorrelatedThreat correlation)
    {
        _journal.RecordCorrelation(correlation);
        CorrelationDetected?.Invoke(correlation);
    }

    private void ExecuteDecision(ThreatEvent threat, PolicyDecision decision)
    {
        switch (decision.Action)
        {
            case ResponseAction.Log:
                // Already recorded in journal — nothing more to do
                threat.ResponseTaken = "Logged";
                break;

            case ResponseAction.Alert:
                threat.ResponseTaken = "Alert sent to UI";
                // IPC notification happens via DecisionMade event
                break;

            case ResponseAction.Escalate:
                threat.ResponseTaken = "Escalated — immediate attention required";
                // IPC notification happens via DecisionMade event with escalation flag
                break;

            case ResponseAction.AutoFix:
                if (decision.AutoFixAllowed && threat.AutoFixable)
                {
                    var remediation = ExecuteAutoFix(threat);
                    threat.ResponseTaken = remediation.Success
                        ? $"Auto-fixed: {remediation.Description}"
                        : $"Auto-fix failed: {remediation.ErrorMessage}";
                }
                else
                {
                    threat.ResponseTaken = "Auto-fix not available — alerting instead";
                    decision.Action = ResponseAction.Alert;
                }
                break;
        }
    }

    /// <summary>
    /// Execute automatic remediation based on the threat type.
    /// </summary>
    private RemediationRecord ExecuteAutoFix(ThreatEvent threat)
    {
        RemediationRecord record;

        // Determine the best remediation action based on the threat
        if (threat.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
            threat.Title.Contains("Disabled", StringComparison.OrdinalIgnoreCase))
        {
            record = _remediator.ReEnableDefender(threat.Id);
        }
        else if (threat.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase))
        {
            record = _remediator.RestoreHostsFile(threat.Id);
        }
        else if (threat.Source == "ProcessMonitor" && ExtractPid(threat.Description) is int pid)
        {
            var processName = ExtractProcessName(threat.Description) ?? "unknown";
            record = _remediator.KillProcess(pid, processName, threat.Id);
        }
        else if (threat.Source == "FileSystemMonitor" && ExtractFilePath(threat.Description) is string filePath)
        {
            record = _remediator.QuarantineFile(filePath, threat.Id);
        }
        else if (ExtractIpAddress(threat.Description) is string ip)
        {
            record = _remediator.BlockIp(ip, threat.Title, threat.Id);
        }
        else if (!string.IsNullOrEmpty(threat.FixCommand))
        {
            record = _remediator.ExecuteFixCommand(threat);
        }
        else
        {
            record = new RemediationRecord
            {
                ActionType = RemediationAction.Custom,
                Target = threat.Title,
                ThreatEventId = threat.Id,
                Success = false,
                ErrorMessage = "No suitable remediation strategy found",
                Description = "Auto-fix was requested but no remediation could be determined"
            };
        }

        _journal.RecordRemediation(record);
        RemediationExecuted?.Invoke(record);

        return record;
    }

    // ══════════════════════════════════════════
    //  Extraction Helpers
    // ══════════════════════════════════════════

    /// <summary>Extract a PID from a threat description like "PID 1234".</summary>
    internal static int? ExtractPid(string description)
    {
        var match = Regex.Match(description, @"PID\s+(\d+)", RegexOptions.IgnoreCase);
        return match.Success && int.TryParse(match.Groups[1].Value, out var pid) ? pid : null;
    }

    /// <summary>Extract a process name from a threat description.</summary>
    internal static string? ExtractProcessName(string description)
    {
        // Pattern: 'processname.exe' or "processname.exe"
        var match = Regex.Match(description, @"['""]([^'""]+\.exe)['""]", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>Extract a file path from a threat description.</summary>
    internal static string? ExtractFilePath(string description)
    {
        // Pattern: Path: C:\something\file.ext
        var match = Regex.Match(description, @"Path:\s*([A-Za-z]:\\[^\s,\.\n]+\.\w+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>Extract an IP address from a threat description.</summary>
    internal static string? ExtractIpAddress(string description)
    {
        var match = Regex.Match(description, @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
        return match.Success ? match.Groups[1].Value : null;
    }
}
