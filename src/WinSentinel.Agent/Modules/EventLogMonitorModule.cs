using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Modules;

/// <summary>
/// Real-time Windows Event Log monitoring module.
/// Subscribes to Security, System, Defender, PowerShell, and Sysmon logs
/// using EventLogWatcher with XPath queries for efficient, filtered monitoring.
/// Includes a correlation engine for multi-event threat detection:
///   - Brute force detection (>5 failed logons in 5 min from same source)
///   - Kill chain detection (failed logon → success → privilege escalation)
///   - Defender bypass (real-time protection disabled + new service installed)
/// </summary>
public class EventLogMonitorModule : IAgentModule
{
    public string Name => "EventLogMonitor";
    public bool IsActive { get; private set; }

    private readonly ILogger<EventLogMonitorModule> _logger;
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private readonly List<EventLogWatcher> _watchers = new();
    private CancellationTokenSource? _cts;

    // ── Correlation state ──

    /// <summary>Failed logon attempts: source → list of timestamps (sliding window).</summary>
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _failedLogons = new();

    /// <summary>Successful logons after failed attempts: source → timestamp.</summary>
    private readonly ConcurrentDictionary<string, DateTimeOffset> _successfulLogonsAfterFailure = new();

    /// <summary>Recent privilege escalations within correlation window.</summary>
    private readonly ConcurrentQueue<(string Account, DateTimeOffset Timestamp)> _privilegeEscalations = new();

    /// <summary>Whether Defender real-time protection was recently disabled.</summary>
    private volatile bool _defenderRtpDisabled;
    private DateTimeOffset _defenderRtpDisabledTime;

    /// <summary>Rate-limit: recent alert keys with timestamps.</summary>
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentAlerts = new();

    // ── Constants ──

    /// <summary>Sliding window for brute force and correlation detection.</summary>
    internal static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(5);

    /// <summary>Threshold for brute force detection (failed logons from same source).</summary>
    internal const int BruteForceThreshold = 5;

    /// <summary>Rate-limit: minimum seconds between identical alerts.</summary>
    private const int RateLimitSeconds = 60;

    /// <summary>How often to purge correlation caches (minutes).</summary>
    private const int CachePurgeIntervalMinutes = 10;

    // ── Event Log Channel Definitions ──

    /// <summary>
    /// Defines all monitored event log subscriptions.
    /// Each entry specifies the log channel, an XPath filter, and the handler method.
    /// </summary>
    private List<EventSubscription> GetSubscriptions() => new()
    {
        // Security log events
        new EventSubscription
        {
            LogName = "Security",
            XPathQuery = "*[System[(EventID=4625 or EventID=4648 or EventID=4672 or EventID=4720 or EventID=4732 or EventID=4740 or EventID=1102)]]",
            Handler = OnSecurityEvent
        },
        // System log events
        new EventSubscription
        {
            LogName = "System",
            XPathQuery = "*[System[(EventID=7045 or EventID=7040 or EventID=1074 or EventID=6006 or EventID=6008)]]",
            Handler = OnSystemEvent
        },
        // Windows Defender operational log
        new EventSubscription
        {
            LogName = "Microsoft-Windows-Windows Defender/Operational",
            XPathQuery = "*[System[(EventID=1116 or EventID=1117 or EventID=5001)]]",
            Handler = OnDefenderEvent
        },
        // PowerShell script block logging
        new EventSubscription
        {
            LogName = "Microsoft-Windows-PowerShell/Operational",
            XPathQuery = "*[System[(EventID=4104)]]",
            Handler = OnPowerShellEvent
        },
        // Sysmon (optional — only if installed)
        new EventSubscription
        {
            LogName = "Microsoft-Windows-Sysmon/Operational",
            XPathQuery = "*[System[(EventID=1 or EventID=3 or EventID=11)]]",
            Handler = OnSysmonEvent,
            Optional = true
        }
    };

    public EventLogMonitorModule(
        ILogger<EventLogMonitorModule> logger,
        ThreatLog threatLog,
        AgentConfig config)
    {
        _logger = logger;
        _threatLog = threatLog;
        _config = config;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("EventLogMonitor starting — setting up event log watchers...");
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        foreach (var sub in GetSubscriptions())
        {
            try
            {
                var query = new EventLogQuery(sub.LogName, PathType.LogName, sub.XPathQuery);
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += (sender, args) =>
                {
                    if (args.EventRecord != null)
                    {
                        try
                        {
                            sub.Handler(args.EventRecord);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "Error processing event from {Log}", sub.LogName);
                        }
                    }
                };
                watcher.Enabled = true;
                _watchers.Add(watcher);
                _logger.LogInformation("Subscribed to {Log}", sub.LogName);
            }
            catch (EventLogNotFoundException)
            {
                if (sub.Optional)
                {
                    _logger.LogInformation("Optional log {Log} not found — skipping (not installed)", sub.LogName);
                }
                else
                {
                    _logger.LogWarning("Event log {Log} not found", sub.LogName);
                }
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogWarning("Access denied to {Log} — run as Administrator for full monitoring", sub.LogName);
            }
            catch (Exception ex)
            {
                if (sub.Optional)
                {
                    _logger.LogDebug(ex, "Optional log {Log} not available", sub.LogName);
                }
                else
                {
                    _logger.LogWarning(ex, "Failed to subscribe to {Log}", sub.LogName);
                }
            }
        }

        // Start correlation cache cleanup
        _ = Task.Run(() => CorrelationCleanupLoopAsync(_cts.Token), _cts.Token);

        IsActive = true;
        _logger.LogInformation("EventLogMonitor active with {Count} watchers", _watchers.Count);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("EventLogMonitor stopping...");
        IsActive = false;
        _cts?.Cancel();

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.Enabled = false;
                watcher.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error disposing event log watcher");
            }
        }

        _watchers.Clear();
        _failedLogons.Clear();
        _successfulLogonsAfterFailure.Clear();
        _recentAlerts.Clear();
        _defenderRtpDisabled = false;

        return Task.CompletedTask;
    }

    // ══════════════════════════════════════════
    //  Security Log Event Handlers
    // ══════════════════════════════════════════

    /// <summary>
    /// Process security log events. Made internal for testability via ProcessSecurityEventData.
    /// </summary>
    private void OnSecurityEvent(EventRecord record)
    {
        var eventId = record.Id;
        var timeCreated = record.TimeCreated ?? DateTime.UtcNow;

        switch (eventId)
        {
            case 4625: // Failed logon
                HandleFailedLogon(record, timeCreated);
                break;

            case 4648: // Explicit credential logon
                HandleExplicitCredentialLogon(record, timeCreated);
                break;

            case 4672: // Special privileges assigned
                HandlePrivilegeAssigned(record, timeCreated);
                break;

            case 4720: // User account created
                HandleAccountCreated(record, timeCreated);
                break;

            case 4732: // Member added to security-enabled local group
                HandleGroupMemberAdded(record, timeCreated);
                break;

            case 4740: // Account lockout
                HandleAccountLockout(record, timeCreated);
                break;

            case 1102: // Audit log cleared
                HandleAuditLogCleared(record, timeCreated);
                break;
        }
    }

    private void HandleFailedLogon(EventRecord record, DateTime timeCreated)
    {
        var source = GetEventDataValue(record, "IpAddress") ?? GetEventDataValue(record, "WorkstationName") ?? "unknown";
        var targetUser = GetEventDataValue(record, "TargetUserName") ?? "unknown";
        var logonType = GetEventDataValue(record, "LogonType") ?? "";
        var failureReason = GetEventDataValue(record, "FailureReason") ?? "";
        var status = GetEventDataValue(record, "Status") ?? "";

        var now = DateTimeOffset.UtcNow;

        // Track for brute force correlation
        var failedList = _failedLogons.GetOrAdd(source, _ => new List<DateTimeOffset>());
        lock (failedList)
        {
            failedList.Add(now);
            // Trim old entries outside correlation window
            failedList.RemoveAll(t => (now - t) > CorrelationWindow);
        }

        // Check brute force threshold
        int failCount;
        lock (failedList)
        {
            failCount = failedList.Count;
        }

        if (failCount >= BruteForceThreshold)
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Brute Force Attack Detected",
                Description = $"Over {failCount} failed logon attempts from '{source}' within {CorrelationWindow.TotalMinutes} minutes. " +
                              $"Target account: '{targetUser}'. Logon type: {logonType}. " +
                              $"This may indicate a brute force or password spraying attack.",
                AutoFixable = true,
                FixCommand = $"netsh advfirewall firewall add rule name=\"Block {source}\" dir=in action=block remoteip={source}"
            });
        }
        else
        {
            // Individual failed logon — lower severity
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Low,
                Title = "Failed Logon Attempt",
                Description = $"Failed logon for '{targetUser}' from '{source}'. " +
                              $"Logon type: {logonType}. Status: {status}. ({failCount} in window)"
            });
        }
    }

    private void HandleExplicitCredentialLogon(EventRecord record, DateTime timeCreated)
    {
        var subjectUser = GetEventDataValue(record, "SubjectUserName") ?? "unknown";
        var targetUser = GetEventDataValue(record, "TargetUserName") ?? "unknown";
        var targetServer = GetEventDataValue(record, "TargetServerName") ?? "unknown";
        var processName = GetEventDataValue(record, "ProcessName") ?? "";

        // Track as potential successful logon (for kill chain correlation)
        var source = subjectUser;
        if (_failedLogons.ContainsKey(source))
        {
            _successfulLogonsAfterFailure[source] = DateTimeOffset.UtcNow;
        }

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Explicit Credential Logon",
            Description = $"User '{subjectUser}' used explicit credentials to log on as '{targetUser}' " +
                          $"to server '{targetServer}'. Process: {processName}. " +
                          $"This may indicate lateral movement."
        });
    }

    private void HandlePrivilegeAssigned(EventRecord record, DateTime timeCreated)
    {
        var subjectUser = GetEventDataValue(record, "SubjectUserName") ?? "unknown";
        var privileges = GetEventDataValue(record, "PrivilegeList") ?? "";

        // Track for kill chain correlation
        _privilegeEscalations.Enqueue((subjectUser, DateTimeOffset.UtcNow));

        // Check kill chain: failed logon → successful logon → privilege escalation
        CheckKillChainCorrelation(subjectUser);

        // Sensitive privileges (SeTakeOwnership, SeDebugPrivilege, etc.)
        var severity = ThreatSeverity.Low;
        if (privileges.Contains("SeDebugPrivilege", StringComparison.OrdinalIgnoreCase) ||
            privileges.Contains("SeTakeOwnershipPrivilege", StringComparison.OrdinalIgnoreCase) ||
            privileges.Contains("SeLoadDriverPrivilege", StringComparison.OrdinalIgnoreCase) ||
            privileges.Contains("SeBackupPrivilege", StringComparison.OrdinalIgnoreCase) ||
            privileges.Contains("SeRestorePrivilege", StringComparison.OrdinalIgnoreCase) ||
            privileges.Contains("SeImpersonatePrivilege", StringComparison.OrdinalIgnoreCase))
        {
            severity = ThreatSeverity.High;
        }

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = "Special Privileges Assigned",
            Description = $"Special privileges assigned to '{subjectUser}': {TruncateString(privileges, 200)}. " +
                          $"This may indicate privilege escalation."
        });
    }

    private void HandleAccountCreated(EventRecord record, DateTime timeCreated)
    {
        var subjectUser = GetEventDataValue(record, "SubjectUserName") ?? "unknown";
        var newAccountName = GetEventDataValue(record, "TargetUserName") ?? "unknown";

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.High,
            Title = "User Account Created",
            Description = $"New user account '{newAccountName}' created by '{subjectUser}'. " +
                          $"Unauthorized account creation may indicate compromise.",
            AutoFixable = true,
            FixCommand = $"net user \"{newAccountName}\" /delete"
        });
    }

    private void HandleGroupMemberAdded(EventRecord record, DateTime timeCreated)
    {
        var subjectUser = GetEventDataValue(record, "SubjectUserName") ?? "unknown";
        var memberName = GetEventDataValue(record, "MemberName") ?? GetEventDataValue(record, "MemberSid") ?? "unknown";
        var groupName = GetEventDataValue(record, "TargetUserName") ?? "unknown";

        // Administrators group is especially critical
        var severity = groupName.Contains("Admin", StringComparison.OrdinalIgnoreCase)
            ? ThreatSeverity.Critical
            : ThreatSeverity.High;

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = "Member Added to Security Group",
            Description = $"'{subjectUser}' added '{memberName}' to security group '{groupName}'. " +
                          (severity == ThreatSeverity.Critical
                              ? "Adding members to the Administrators group is a critical security event."
                              : "Review whether this group membership change is authorized."),
            AutoFixable = severity == ThreatSeverity.Critical,
            FixCommand = severity == ThreatSeverity.Critical
                ? $"net localgroup Administrators \"{memberName}\" /delete"
                : null
        });
    }

    private void HandleAccountLockout(EventRecord record, DateTime timeCreated)
    {
        var targetUser = GetEventDataValue(record, "TargetUserName") ?? "unknown";
        var callerComputer = GetEventDataValue(record, "SubjectUserName") ?? "unknown";

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Account Lockout",
            Description = $"Account '{targetUser}' was locked out. Source: '{callerComputer}'. " +
                          $"This may indicate a brute force attack.",
            AutoFixable = true,
            FixCommand = $"net user \"{targetUser}\" /active:yes"
        });
    }

    private void HandleAuditLogCleared(EventRecord record, DateTime timeCreated)
    {
        var subjectUser = GetEventDataValue(record, "SubjectUserName") ?? "unknown";

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Audit Log Cleared",
            Description = $"The Security audit log was cleared by '{subjectUser}'. " +
                          $"This is a strong indicator of evidence destruction by an attacker. " +
                          $"Investigate immediately.",
            AutoFixable = false
        }, forceEmit: true); // Always emit — never rate-limit this
    }

    // ══════════════════════════════════════════
    //  System Log Event Handlers
    // ══════════════════════════════════════════

    private void OnSystemEvent(EventRecord record)
    {
        var eventId = record.Id;
        var timeCreated = record.TimeCreated ?? DateTime.UtcNow;

        switch (eventId)
        {
            case 7045: // New service installed
                HandleNewServiceInstalled(record, timeCreated);
                break;

            case 7040: // Service start type changed
                HandleServiceStartTypeChanged(record, timeCreated);
                break;

            case 1074: // Planned shutdown/restart
            case 6006: // Clean shutdown
            case 6008: // Unexpected shutdown
                HandleShutdownEvent(record, eventId, timeCreated);
                break;
        }
    }

    private void HandleNewServiceInstalled(EventRecord record, DateTime timeCreated)
    {
        var serviceName = GetEventDataValue(record, "ServiceName") ?? "unknown";
        var imagePath = GetEventDataValue(record, "ImagePath") ?? "unknown";
        var serviceType = GetEventDataValue(record, "ServiceType") ?? "";
        var startType = GetEventDataValue(record, "StartType") ?? "";
        var accountName = GetEventDataValue(record, "AccountName") ?? "";

        // Check Defender bypass correlation
        if (_defenderRtpDisabled && (DateTimeOffset.UtcNow - _defenderRtpDisabledTime) < CorrelationWindow)
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Defender Bypass — Service Installed After RTP Disabled",
                Description = $"New service '{serviceName}' installed shortly after Windows Defender " +
                              $"real-time protection was disabled. Image: {imagePath}. " +
                              $"This combination strongly suggests an attacker bypassing defenses to install malware.",
                AutoFixable = true,
                FixCommand = $"sc delete \"{serviceName}\""
            }, forceEmit: true);
        }

        // Suspicious service paths
        var severity = ThreatSeverity.Medium;
        var imagePathLower = imagePath.ToLowerInvariant();
        if (imagePathLower.Contains(@"\temp\") ||
            imagePathLower.Contains(@"\appdata\") ||
            imagePathLower.Contains(@"\downloads\") ||
            imagePathLower.Contains(@"$recycle.bin") ||
            imagePathLower.Contains("cmd.exe") ||
            imagePathLower.Contains("powershell") ||
            imagePathLower.Contains("mshta"))
        {
            severity = ThreatSeverity.Critical;
        }

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = "New Service Installed",
            Description = $"Service '{serviceName}' installed. Image: {imagePath}. " +
                          $"Type: {serviceType}. Start: {startType}. Account: {accountName}. " +
                          $"New services can be used for persistence.",
            AutoFixable = severity >= ThreatSeverity.High,
            FixCommand = severity >= ThreatSeverity.High ? $"sc delete \"{serviceName}\"" : null
        });
    }

    private void HandleServiceStartTypeChanged(EventRecord record, DateTime timeCreated)
    {
        var serviceName = GetEventDataValue(record, "param1") ?? "unknown";
        var oldStartType = GetEventDataValue(record, "param2") ?? "";
        var newStartType = GetEventDataValue(record, "param3") ?? "";

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Low,
            Title = "Service Start Type Changed",
            Description = $"Service '{serviceName}' start type changed from '{oldStartType}' to '{newStartType}'. " +
                          $"Attackers may change service configurations for persistence."
        });
    }

    private void HandleShutdownEvent(EventRecord record, int eventId, DateTime timeCreated)
    {
        var (title, severity, description) = eventId switch
        {
            1074 => ("System Shutdown/Restart", ThreatSeverity.Info,
                $"Planned shutdown initiated. Reason: {record.FormatDescription() ?? "N/A"}"),
            6006 => ("System Clean Shutdown", ThreatSeverity.Info,
                "The Event Log service was stopped cleanly."),
            6008 => ("Unexpected System Shutdown", ThreatSeverity.High,
                $"The system shut down unexpectedly at {timeCreated:u}. " +
                $"This may indicate a crash, BSOD, or forced restart by malware."),
            _ => ("Shutdown Event", ThreatSeverity.Info, "")
        };

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = title,
            Description = description
        });
    }

    // ══════════════════════════════════════════
    //  Windows Defender Event Handlers
    // ══════════════════════════════════════════

    private void OnDefenderEvent(EventRecord record)
    {
        var eventId = record.Id;

        switch (eventId)
        {
            case 1116: // Malware detected
                HandleMalwareDetected(record);
                break;

            case 1117: // Malware action taken
                HandleMalwareActionTaken(record);
                break;

            case 5001: // Real-time protection disabled
                HandleRtpDisabled(record);
                break;
        }
    }

    private void HandleMalwareDetected(EventRecord record)
    {
        var threatName = GetEventDataValue(record, "Threat Name") ?? GetIndexedEventData(record, 7) ?? "unknown";
        var path = GetEventDataValue(record, "Path") ?? GetIndexedEventData(record, 17) ?? "";
        var severity = GetEventDataValue(record, "Severity Name") ?? GetIndexedEventData(record, 9) ?? "";

        var threatSeverity = severity.ToLowerInvariant() switch
        {
            "severe" or "high" => ThreatSeverity.Critical,
            "medium" => ThreatSeverity.High,
            _ => ThreatSeverity.Medium
        };

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = threatSeverity,
            Title = "Malware Detected",
            Description = $"Windows Defender detected malware: '{threatName}'. " +
                          $"Path: {path}. Severity: {severity}."
        }, forceEmit: true);
    }

    private void HandleMalwareActionTaken(EventRecord record)
    {
        var threatName = GetEventDataValue(record, "Threat Name") ?? GetIndexedEventData(record, 7) ?? "unknown";
        var action = GetEventDataValue(record, "Action Name") ?? GetIndexedEventData(record, 5) ?? "unknown";

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Malware Action Taken",
            Description = $"Windows Defender took action '{action}' on threat '{threatName}'."
        });
    }

    private void HandleRtpDisabled(EventRecord record)
    {
        // Set correlation flag
        _defenderRtpDisabled = true;
        _defenderRtpDisabledTime = DateTimeOffset.UtcNow;

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Defender Real-Time Protection Disabled",
            Description = "Windows Defender real-time protection has been disabled. " +
                          "This is a critical security event — attackers often disable Defender before deploying payloads. " +
                          "Investigate immediately and re-enable protection.",
            AutoFixable = true,
            FixCommand = "Set-MpPreference -DisableRealtimeMonitoring $false"
        }, forceEmit: true);
    }

    // ══════════════════════════════════════════
    //  PowerShell Event Handlers
    // ══════════════════════════════════════════

    private void OnPowerShellEvent(EventRecord record)
    {
        if (record.Id == 4104)
        {
            HandleScriptBlockLogging(record);
        }
    }

    private void HandleScriptBlockLogging(EventRecord record)
    {
        var scriptBlock = GetEventDataValue(record, "ScriptBlockText") ?? GetIndexedEventData(record, 2) ?? "";
        if (string.IsNullOrWhiteSpace(scriptBlock))
            return;

        var scriptLower = scriptBlock.ToLowerInvariant();

        // Check for suspicious patterns
        var (isSuspicious, reason, severity) = AnalyzeScriptBlock(scriptLower);
        if (!isSuspicious)
            return;

        var scriptId = GetEventDataValue(record, "ScriptBlockId") ?? "";
        var path = GetEventDataValue(record, "Path") ?? "";

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = "Suspicious PowerShell Script Block",
            Description = $"PowerShell script block contains suspicious content: {reason}. " +
                          (!string.IsNullOrEmpty(path) ? $"Script: {path}. " : "") +
                          $"Content preview: {TruncateString(scriptBlock, 300)}"
        });
    }

    /// <summary>
    /// Analyze a PowerShell script block for suspicious patterns.
    /// Made internal for testability.
    /// </summary>
    internal static (bool IsSuspicious, string Reason, ThreatSeverity Severity) AnalyzeScriptBlock(string scriptLower)
    {
        // Encoded commands / obfuscation
        if (scriptLower.Contains("frombase64string") || scriptLower.Contains("[convert]::frombase64"))
            return (true, "Base64 decoding detected — possible encoded payload", ThreatSeverity.High);

        if (scriptLower.Contains("-encodedcommand") || scriptLower.Contains("-enc "))
            return (true, "Encoded command execution", ThreatSeverity.Critical);

        // Download cradles
        if (scriptLower.Contains("downloadstring") || scriptLower.Contains("downloadfile") ||
            scriptLower.Contains("downloaddata"))
            return (true, "Download cradle detected — remote payload download", ThreatSeverity.Critical);

        if (scriptLower.Contains("invoke-webrequest") && (scriptLower.Contains("-outfile") || scriptLower.Contains("| iex")))
            return (true, "Web download with execution", ThreatSeverity.High);

        if (scriptLower.Contains("start-bitstransfer"))
            return (true, "BITS transfer — alternative download method", ThreatSeverity.Medium);

        // Invoke-Expression and variants
        if (scriptLower.Contains("invoke-expression") || scriptLower.Contains("iex(") || scriptLower.Contains("iex ("))
            return (true, "Invoke-Expression detected — dynamic code execution", ThreatSeverity.High);

        // Credential access
        if (scriptLower.Contains("mimikatz") || scriptLower.Contains("invoke-mimikatz"))
            return (true, "Mimikatz credential theft tool detected", ThreatSeverity.Critical);

        if (scriptLower.Contains("get-credential") && scriptLower.Contains("net."))
            return (true, "Credential harvesting pattern", ThreatSeverity.High);

        if (scriptLower.Contains("sekurlsa") || scriptLower.Contains("lsadump"))
            return (true, "LSASS credential dump patterns detected", ThreatSeverity.Critical);

        // Persistence
        if (scriptLower.Contains("new-scheduledtask") || scriptLower.Contains("register-scheduledtask"))
            return (true, "Scheduled task creation — persistence mechanism", ThreatSeverity.Medium);

        if (scriptLower.Contains("new-service") || scriptLower.Contains("sc.exe create"))
            return (true, "Service creation — persistence mechanism", ThreatSeverity.Medium);

        // Defense evasion
        if (scriptLower.Contains("set-mppreference") && scriptLower.Contains("disablerealtimemonitoring"))
            return (true, "Attempting to disable Windows Defender", ThreatSeverity.Critical);

        if (scriptLower.Contains("amsiutils") || scriptLower.Contains("amsiinitfailed") || scriptLower.Contains("amsi.dll"))
            return (true, "AMSI bypass attempt detected", ThreatSeverity.Critical);

        if (scriptLower.Contains("-executionpolicy") && scriptLower.Contains("bypass"))
            return (true, "Execution policy bypass", ThreatSeverity.Medium);

        // Reflection / memory manipulation
        if (scriptLower.Contains("reflection.assembly") && scriptLower.Contains("load"))
            return (true, "Reflective assembly loading — fileless malware technique", ThreatSeverity.High);

        if (scriptLower.Contains("virtualalloc") || scriptLower.Contains("virtualprotect"))
            return (true, "Memory allocation via P/Invoke — possible shellcode injection", ThreatSeverity.Critical);

        // Reconnaissance
        if (scriptLower.Contains("get-adcomputer") || scriptLower.Contains("get-aduser") ||
            scriptLower.Contains("get-adgroup"))
            return (true, "Active Directory reconnaissance", ThreatSeverity.Medium);

        return (false, "", ThreatSeverity.Info);
    }

    // ══════════════════════════════════════════
    //  Sysmon Event Handlers
    // ══════════════════════════════════════════

    private void OnSysmonEvent(EventRecord record)
    {
        switch (record.Id)
        {
            case 1: // Process creation
                HandleSysmonProcessCreation(record);
                break;

            case 3: // Network connection
                HandleSysmonNetworkConnection(record);
                break;

            case 11: // File creation
                HandleSysmonFileCreation(record);
                break;
        }
    }

    private void HandleSysmonProcessCreation(EventRecord record)
    {
        var image = GetEventDataValue(record, "Image") ?? "";
        var commandLine = GetEventDataValue(record, "CommandLine") ?? "";
        var parentImage = GetEventDataValue(record, "ParentImage") ?? "";
        var user = GetEventDataValue(record, "User") ?? "";
        var hash = GetEventDataValue(record, "Hashes") ?? "";

        // Only log if command line looks suspicious — Sysmon process events are very verbose
        var cmdLower = commandLine.ToLowerInvariant();
        if (IsSuspiciousCommandLine(cmdLower))
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Medium,
                Title = "Suspicious Process (Sysmon)",
                Description = $"Process: {image}. Command: {TruncateString(commandLine, 200)}. " +
                              $"Parent: {parentImage}. User: {user}. Hash: {hash}"
            });
        }
    }

    private void HandleSysmonNetworkConnection(EventRecord record)
    {
        var image = GetEventDataValue(record, "Image") ?? "";
        var destIp = GetEventDataValue(record, "DestinationIp") ?? "";
        var destPort = GetEventDataValue(record, "DestinationPort") ?? "";
        var user = GetEventDataValue(record, "User") ?? "";
        var protocol = GetEventDataValue(record, "Protocol") ?? "";

        // Only alert on suspicious ports or processes
        if (IsSuspiciousNetworkActivity(image, destPort))
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Medium,
                Title = "Suspicious Network Connection (Sysmon)",
                Description = $"Process '{Path.GetFileName(image)}' connected to {destIp}:{destPort} ({protocol}). User: {user}."
            });
        }
    }

    private void HandleSysmonFileCreation(EventRecord record)
    {
        var image = GetEventDataValue(record, "Image") ?? "";
        var targetFilename = GetEventDataValue(record, "TargetFilename") ?? "";

        // Only alert on executable file creation in sensitive locations
        var ext = Path.GetExtension(targetFilename);
        var targetLower = targetFilename.ToLowerInvariant();

        if (IsExecutableExtension(ext) &&
            (targetLower.Contains(@"\startup\") ||
             targetLower.Contains(@"\system32\") ||
             targetLower.Contains(@"\tasks\") ||
             targetLower.Contains(@"\temp\")))
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.High,
                Title = "Executable File Created (Sysmon)",
                Description = $"Process '{Path.GetFileName(image)}' created executable '{targetFilename}'."
            });
        }
    }

    // ══════════════════════════════════════════
    //  Correlation Engine
    // ══════════════════════════════════════════

    /// <summary>
    /// Kill chain correlation: Failed logon → successful logon → privilege escalation = Critical.
    /// </summary>
    private void CheckKillChainCorrelation(string account)
    {
        var now = DateTimeOffset.UtcNow;

        // Check if this account (or any account) had a recent successful logon after failed attempts
        foreach (var kvp in _successfulLogonsAfterFailure)
        {
            if ((now - kvp.Value) > CorrelationWindow)
                continue;

            // We have: failed logons + successful logon + now privilege escalation
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Kill Chain Detected — Logon → Escalation",
                Description = $"Potential attack chain detected: Failed logon attempts from '{kvp.Key}' " +
                              $"followed by successful logon, now followed by privilege escalation for '{account}'. " +
                              $"This pattern (credential brute force → access → escalation) is a classic attack chain.",
                AutoFixable = false
            }, forceEmit: true);
        }
    }

    // ══════════════════════════════════════════
    //  Testable Event Processing Methods
    // ══════════════════════════════════════════

    /// <summary>
    /// Process a security event from parsed data (for unit testing without real EventRecord).
    /// </summary>
    internal void ProcessSecurityEventData(int eventId, Dictionary<string, string> eventData)
    {
        var timeCreated = DateTime.UtcNow;

        switch (eventId)
        {
            case 4625:
                ProcessFailedLogonData(eventData);
                break;
            case 4648:
                ProcessExplicitCredentialData(eventData);
                break;
            case 4672:
                ProcessPrivilegeAssignedData(eventData);
                break;
            case 4720:
                ProcessAccountCreatedData(eventData);
                break;
            case 4732:
                ProcessGroupMemberAddedData(eventData);
                break;
            case 4740:
                ProcessAccountLockoutData(eventData);
                break;
            case 1102:
                ProcessAuditLogClearedData(eventData);
                break;
        }
    }

    /// <summary>
    /// Process a system event from parsed data (for unit testing).
    /// </summary>
    internal void ProcessSystemEventData(int eventId, Dictionary<string, string> eventData)
    {
        switch (eventId)
        {
            case 7045:
                ProcessNewServiceData(eventData);
                break;
            case 7040:
                ProcessServiceStartTypeData(eventData);
                break;
            case 6008:
                EmitThreat(new ThreatEvent
                {
                    Source = "EventLogMonitor",
                    Severity = ThreatSeverity.High,
                    Title = "Unexpected System Shutdown",
                    Description = "The system shut down unexpectedly. This may indicate a crash or forced restart."
                });
                break;
        }
    }

    /// <summary>
    /// Process a Defender event from parsed data (for unit testing).
    /// </summary>
    internal void ProcessDefenderEventData(int eventId, Dictionary<string, string> eventData)
    {
        switch (eventId)
        {
            case 1116:
                EmitThreat(new ThreatEvent
                {
                    Source = "EventLogMonitor",
                    Severity = ThreatSeverity.High,
                    Title = "Malware Detected",
                    Description = $"Windows Defender detected malware: '{eventData.GetValueOrDefault("ThreatName", "unknown")}'. " +
                                  $"Path: {eventData.GetValueOrDefault("Path", "")}."
                }, forceEmit: true);
                break;
            case 5001:
                _defenderRtpDisabled = true;
                _defenderRtpDisabledTime = DateTimeOffset.UtcNow;
                EmitThreat(new ThreatEvent
                {
                    Source = "EventLogMonitor",
                    Severity = ThreatSeverity.Critical,
                    Title = "Defender Real-Time Protection Disabled",
                    Description = "Windows Defender real-time protection has been disabled.",
                    AutoFixable = true,
                    FixCommand = "Set-MpPreference -DisableRealtimeMonitoring $false"
                }, forceEmit: true);
                break;
        }
    }

    // ── Testable data processing helpers ──

    private void ProcessFailedLogonData(Dictionary<string, string> data)
    {
        var source = data.GetValueOrDefault("IpAddress") ?? data.GetValueOrDefault("WorkstationName") ?? "unknown";
        var targetUser = data.GetValueOrDefault("TargetUserName", "unknown");
        var logonType = data.GetValueOrDefault("LogonType", "");
        var now = DateTimeOffset.UtcNow;

        var failedList = _failedLogons.GetOrAdd(source, _ => new List<DateTimeOffset>());
        lock (failedList)
        {
            failedList.Add(now);
            failedList.RemoveAll(t => (now - t) > CorrelationWindow);
        }

        int failCount;
        lock (failedList) { failCount = failedList.Count; }

        if (failCount >= BruteForceThreshold)
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Brute Force Attack Detected",
                Description = $"Over {failCount} failed logon attempts from '{source}' within " +
                              $"{CorrelationWindow.TotalMinutes} minutes. Target: '{targetUser}'.",
                AutoFixable = true,
                FixCommand = $"netsh advfirewall firewall add rule name=\"Block {source}\" dir=in action=block remoteip={source}"
            });
        }
        else
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Low,
                Title = "Failed Logon Attempt",
                Description = $"Failed logon for '{targetUser}' from '{source}'. ({failCount} in window)"
            });
        }
    }

    private void ProcessExplicitCredentialData(Dictionary<string, string> data)
    {
        var subjectUser = data.GetValueOrDefault("SubjectUserName", "unknown");
        var targetUser = data.GetValueOrDefault("TargetUserName", "unknown");
        var targetServer = data.GetValueOrDefault("TargetServerName", "unknown");

        if (_failedLogons.ContainsKey(subjectUser))
            _successfulLogonsAfterFailure[subjectUser] = DateTimeOffset.UtcNow;

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Explicit Credential Logon",
            Description = $"User '{subjectUser}' used explicit credentials as '{targetUser}' to '{targetServer}'."
        });
    }

    private void ProcessPrivilegeAssignedData(Dictionary<string, string> data)
    {
        var subjectUser = data.GetValueOrDefault("SubjectUserName", "unknown");
        var privileges = data.GetValueOrDefault("PrivilegeList", "");

        _privilegeEscalations.Enqueue((subjectUser, DateTimeOffset.UtcNow));
        CheckKillChainCorrelation(subjectUser);

        var severity = ThreatSeverity.Low;
        if (privileges.Contains("SeDebugPrivilege", StringComparison.OrdinalIgnoreCase) ||
            privileges.Contains("SeTakeOwnershipPrivilege", StringComparison.OrdinalIgnoreCase))
            severity = ThreatSeverity.High;

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = "Special Privileges Assigned",
            Description = $"Special privileges assigned to '{subjectUser}': {TruncateString(privileges, 200)}."
        });
    }

    private void ProcessAccountCreatedData(Dictionary<string, string> data)
    {
        var subjectUser = data.GetValueOrDefault("SubjectUserName", "unknown");
        var newAccount = data.GetValueOrDefault("TargetUserName", "unknown");

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.High,
            Title = "User Account Created",
            Description = $"New user account '{newAccount}' created by '{subjectUser}'.",
            AutoFixable = true,
            FixCommand = $"net user \"{newAccount}\" /delete"
        });
    }

    private void ProcessGroupMemberAddedData(Dictionary<string, string> data)
    {
        var subjectUser = data.GetValueOrDefault("SubjectUserName", "unknown");
        var memberName = data.GetValueOrDefault("MemberName", "unknown");
        var groupName = data.GetValueOrDefault("TargetUserName", "unknown");

        var severity = groupName.Contains("Admin", StringComparison.OrdinalIgnoreCase)
            ? ThreatSeverity.Critical : ThreatSeverity.High;

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = "Member Added to Security Group",
            Description = $"'{subjectUser}' added '{memberName}' to group '{groupName}'."
        });
    }

    private void ProcessAccountLockoutData(Dictionary<string, string> data)
    {
        var targetUser = data.GetValueOrDefault("TargetUserName", "unknown");

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Account Lockout",
            Description = $"Account '{targetUser}' was locked out."
        });
    }

    private void ProcessAuditLogClearedData(Dictionary<string, string> data)
    {
        var subjectUser = data.GetValueOrDefault("SubjectUserName", "unknown");

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Audit Log Cleared",
            Description = $"Security audit log cleared by '{subjectUser}'. Evidence destruction suspected."
        }, forceEmit: true);
    }

    private void ProcessNewServiceData(Dictionary<string, string> data)
    {
        var serviceName = data.GetValueOrDefault("ServiceName", "unknown");
        var imagePath = data.GetValueOrDefault("ImagePath", "unknown");

        if (_defenderRtpDisabled && (DateTimeOffset.UtcNow - _defenderRtpDisabledTime) < CorrelationWindow)
        {
            EmitThreat(new ThreatEvent
            {
                Source = "EventLogMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Defender Bypass — Service Installed After RTP Disabled",
                Description = $"New service '{serviceName}' installed after Defender was disabled. Image: {imagePath}."
            }, forceEmit: true);
        }

        var severity = ThreatSeverity.Medium;
        var imagePathLower = imagePath.ToLowerInvariant();
        if (imagePathLower.Contains(@"\temp\") || imagePathLower.Contains(@"\appdata\") ||
            imagePathLower.Contains("powershell") || imagePathLower.Contains("cmd.exe"))
            severity = ThreatSeverity.Critical;

        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = severity,
            Title = "New Service Installed",
            Description = $"Service '{serviceName}' installed. Image: {imagePath}."
        });
    }

    private void ProcessServiceStartTypeData(Dictionary<string, string> data)
    {
        var serviceName = data.GetValueOrDefault("param1", "unknown");
        EmitThreat(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Low,
            Title = "Service Start Type Changed",
            Description = $"Service '{serviceName}' start type was changed."
        });
    }

    /// <summary>Expose Defender RTP disabled flag for testing.</summary>
    internal bool IsDefenderRtpDisabled => _defenderRtpDisabled;

    /// <summary>Get failed logon count for a source (for testing).</summary>
    internal int GetFailedLogonCount(string source)
    {
        if (_failedLogons.TryGetValue(source, out var list))
        {
            lock (list) return list.Count;
        }
        return 0;
    }

    // ══════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════

    /// <summary>
    /// Extract a named data value from an EventRecord's properties.
    /// Event log properties are positional; named lookups fall back to XML parsing.
    /// </summary>
    private static string? GetEventDataValue(EventRecord record, string name)
    {
        try
        {
            var xml = record.ToXml();
            // Quick XML extraction — avoid full XML parsing for performance
            var dataTag = $"Name='{name}'>";
            var idx = xml.IndexOf(dataTag, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                dataTag = $"Name=\"{name}\">";
                idx = xml.IndexOf(dataTag, StringComparison.OrdinalIgnoreCase);
            }
            if (idx < 0) return null;

            var start = idx + dataTag.Length;
            var end = xml.IndexOf("</Data>", start, StringComparison.OrdinalIgnoreCase);
            if (end < 0) return null;

            var value = xml[start..end].Trim();
            return string.IsNullOrEmpty(value) ? null : value;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Get event data by positional index (for logs that don't use named data elements).
    /// </summary>
    private static string? GetIndexedEventData(EventRecord record, int index)
    {
        try
        {
            if (record.Properties != null && index < record.Properties.Count)
            {
                return record.Properties[index]?.Value?.ToString();
            }
        }
        catch { }
        return null;
    }

    /// <summary>Emit a threat event with rate limiting.</summary>
    private void EmitThreat(ThreatEvent threat, bool forceEmit = false)
    {
        if (!forceEmit && ShouldRateLimit(threat))
            return;

        _threatLog.Add(threat);
        _logger.LogWarning("[{Severity}] {Title}: {Desc}", threat.Severity, threat.Title, threat.Description);
    }

    /// <summary>Rate-limit by threat content.</summary>
    private bool ShouldRateLimit(ThreatEvent threat)
    {
        var key = $"{threat.Source}|{threat.Title}|{threat.Description?[..Math.Min(threat.Description?.Length ?? 0, 60)]}";

        if (_recentAlerts.TryGetValue(key, out var lastAlert))
        {
            if ((DateTimeOffset.UtcNow - lastAlert).TotalSeconds < RateLimitSeconds)
                return true;
        }

        _recentAlerts[key] = DateTimeOffset.UtcNow;
        return false;
    }

    private static string TruncateString(string? s, int maxLength)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length > maxLength ? s[..maxLength] + "..." : s;
    }

    private static bool IsSuspiciousCommandLine(string cmdLower)
    {
        return cmdLower.Contains("-enc ") ||
               cmdLower.Contains("-encodedcommand") ||
               cmdLower.Contains("downloadstring") ||
               cmdLower.Contains("invoke-expression") ||
               cmdLower.Contains("frombase64string") ||
               cmdLower.Contains("net user ") ||
               cmdLower.Contains("net localgroup") ||
               cmdLower.Contains("mimikatz") ||
               cmdLower.Contains("whoami /priv") ||
               cmdLower.Contains("certutil -urlcache") ||
               cmdLower.Contains("bitsadmin /transfer") ||
               cmdLower.Contains("reg save hklm\\sam") ||
               cmdLower.Contains("reg save hklm\\system") ||
               cmdLower.Contains("vssadmin delete shadows");
    }

    private static bool IsSuspiciousNetworkActivity(string processImage, string destPort)
    {
        var processName = Path.GetFileName(processImage).ToLowerInvariant();

        // Known suspicious: scripts making network connections
        var suspiciousProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe"
        };

        if (suspiciousProcesses.Contains(processName))
            return true;

        // Uncommon ports
        if (int.TryParse(destPort, out var port))
        {
            // Reverse shells, C2 common ports
            if (port == 4444 || port == 5555 || port == 8888 || port == 1337 ||
                port == 6666 || port == 9999 || port == 31337)
                return true;
        }

        return false;
    }

    private static bool IsExecutableExtension(string? ext)
    {
        if (string.IsNullOrEmpty(ext)) return false;
        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Periodically clean up stale correlation data.</summary>
    private async Task CorrelationCleanupLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(CachePurgeIntervalMinutes), ct);
            }
            catch (OperationCanceledException) { return; }

            var cutoff = DateTimeOffset.UtcNow - CorrelationWindow;

            // Purge old failed logon entries
            foreach (var kvp in _failedLogons)
            {
                lock (kvp.Value)
                {
                    kvp.Value.RemoveAll(t => t < cutoff);
                }
                if (kvp.Value.Count == 0)
                    _failedLogons.TryRemove(kvp.Key, out _);
            }

            // Purge old successful logon tracking
            foreach (var key in _successfulLogonsAfterFailure.Keys.ToList())
            {
                if (_successfulLogonsAfterFailure.TryGetValue(key, out var ts) && ts < cutoff)
                    _successfulLogonsAfterFailure.TryRemove(key, out _);
            }

            // Purge old privilege escalation records
            while (_privilegeEscalations.TryPeek(out var item) && item.Timestamp < cutoff)
                _privilegeEscalations.TryDequeue(out _);

            // Reset Defender RTP flag if it's old
            if (_defenderRtpDisabled && _defenderRtpDisabledTime < cutoff)
                _defenderRtpDisabled = false;

            // Purge rate-limit entries
            var alertCutoff = DateTimeOffset.UtcNow.AddSeconds(-RateLimitSeconds * 2);
            foreach (var key in _recentAlerts.Keys.ToList())
            {
                if (_recentAlerts.TryGetValue(key, out var ts) && ts < alertCutoff)
                    _recentAlerts.TryRemove(key, out _);
            }

            _logger.LogDebug("EventLogMonitor correlation cleanup complete");
        }
    }
}

// ── Supporting Types ──

/// <summary>Defines an event log subscription.</summary>
internal class EventSubscription
{
    public string LogName { get; set; } = "";
    public string XPathQuery { get; set; } = "";
    public Action<EventRecord> Handler { get; set; } = _ => { };
    public bool Optional { get; set; }
}
