using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Event Logs for security-relevant events: failed logins,
/// account lockouts, privilege escalation, suspicious PowerShell activity,
/// service installations, Defender detections, audit policy gaps, and more.
/// </summary>
public class EventLogAudit : IAuditModule
{
    public string Name => "Event Log Analysis";
    public string Category => "Event Logs";
    public string Description => "Analyzes Windows Event Logs for failed logins, account lockouts, privilege escalation, suspicious activity, audit policy gaps, service installations, and security events.";

    /// <summary>Timeout per individual event log query.</summary>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Lock guarding <see cref="AuditResult.Findings"/> additions from
    /// concurrent check tasks (see <see cref="RunAuditAsync"/>).
    /// </summary>
    private readonly object _findingsLock = new();

    /// <summary>Thread-safe helper to add a finding to the result.</summary>
    private void AddFinding(AuditResult result, Finding finding)
    {
        lock (_findingsLock)
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>Thread-safe helper to add multiple findings to the result.</summary>
    private void AddFindings(AuditResult result, IEnumerable<Finding> findings)
    {
        lock (_findingsLock)
        {
            foreach (var finding in findings)
            {
                result.Findings.Add(finding);
            }
        }
    }

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            // First check the Event Log service — if it's not running, no point
            // in running the other checks.
            await CheckEventLogServiceRunning(result, cancellationToken);

            // Run all independent event-log checks concurrently. Each check
            // queries a different log / event ID, so there is no ordering
            // dependency. Running them in parallel cuts total wall-clock time
            // from the sum of all timeouts to the duration of the slowest
            // individual check (up to ~11× faster on a cold Security log).
            await Task.WhenAll(
                CheckFailedLogins(result, cancellationToken),
                CheckAccountLockouts(result, cancellationToken),
                CheckPrivilegeEscalation(result, cancellationToken),
                CheckAuditPolicyGaps(result, cancellationToken),
                CheckServiceInstallations(result, cancellationToken),
                CheckSuspiciousPowerShell(result, cancellationToken),
                CheckDefenderDetections(result, cancellationToken),
                CheckDefenderTampering(result, cancellationToken),
                CheckSystemErrors(result, cancellationToken),
                CheckSecurityLogSize(result, cancellationToken),
                CheckLogCleared(result, cancellationToken),
                CheckRemoteLogons(result, cancellationToken));
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    #region Event Log Service

    /// <summary>Check that the Windows Event Log service is running.</summary>
    private Task CheckEventLogServiceRunning(AuditResult result, CancellationToken ct)
    {
        try
        {
            using var sc = new ServiceController("EventLog");
            if (sc.Status == ServiceControllerStatus.Running)
            {
                AddFinding(result, Finding.Pass(
                    "Event Log Service Running",
                    "The Windows Event Log service is running. Event logging is active.",
                    Category));
            }
            else
            {
                AddFinding(result, Finding.Critical(
                    "Event Log Service Not Running",
                    $"The Windows Event Log service is in state '{sc.Status}'. Security events are NOT being recorded. This is a severe security gap.",
                    Category,
                    "Start the Windows Event Log service immediately: net start EventLog",
                    "powershell -Command \"Start-Service EventLog\""));
            }
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Event Log Service Check Error",
                $"Could not check Event Log service status: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator to check service status."));
        }

        return Task.CompletedTask;
    }

    #endregion

    #region Failed Logins (Event ID 4625)

    /// <summary>Check Security log for failed logon attempts (Event ID 4625) in the last 24 hours.</summary>
    private async Task CheckFailedLogins(AuditResult result, CancellationToken ct)
    {
        try
        {
            // XPath query targeting only Event ID 4625 with time filter (last 24h)
            var query = $"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";

            var events = await QueryEventLogAsync("Security", query, ct);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Failed Login Check — Access Denied",
                    "Could not read the Security event log. Administrator privileges are required to access Security events.",
                    Category,
                    "Run WinSentinel as Administrator to check failed login attempts."));
                return;
            }

            int count = events.Count;
            var usernames = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var sourceIPs = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var evt in events)
            {
                // Extract TargetUserName (index 5) and IpAddress (index 19) from event properties
                try
                {
                    if (evt.Properties.Count > 5)
                    {
                        var user = evt.Properties[5]?.Value?.ToString();
                        if (EventLogAnalyzer.IsMeaningfulUser(user))
                        {
                            usernames[user!] = usernames.GetValueOrDefault(user!) + 1;
                        }
                    }

                    if (evt.Properties.Count > 19)
                    {
                        var ip = evt.Properties[19]?.Value?.ToString();
                        if (EventLogAnalyzer.IsMeaningfulSourceIp(ip))
                        {
                            sourceIPs[ip!] = sourceIPs.GetValueOrDefault(ip!) + 1;
                        }
                    }
                }
                catch
                {
                    // Skip malformed events
                }
            }

            AddFinding(result, EventLogAnalyzer.BuildFailedLoginFinding(
                count,
                EventLogAnalyzer.RankTopCounts(usernames),
                EventLogAnalyzer.RankTopCounts(sourceIPs)));
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Failed Login Check Error",
                $"Could not check failed logins: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator to access Security event log."));
        }
    }

    #endregion

    #region Account Lockouts (Event ID 4740)

    /// <summary>Check for account lockout events (Event ID 4740) in the last 7 days.</summary>
    private async Task CheckAccountLockouts(AuditResult result, CancellationToken ct)
    {
        try
        {
            // 7 days in milliseconds = 604800000
            var query = "*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";

            var events = await QueryEventLogAsync("Security", query, ct);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Account Lockout Check — Access Denied",
                    "Could not read Security event log for lockout events. Administrator privileges required.",
                    Category,
                    "Run WinSentinel as Administrator."));
                return;
            }

            int count = events.Count;
            var lockedAccounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var evt in events)
            {
                try
                {
                    if (evt.Properties.Count > 0)
                    {
                        var user = evt.Properties[0]?.Value?.ToString();
                        if (!string.IsNullOrWhiteSpace(user))
                        {
                            lockedAccounts[user] = lockedAccounts.GetValueOrDefault(user) + 1;
                        }
                    }
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
            }

            AddFinding(result, EventLogAnalyzer.BuildAccountLockoutFinding(
                count,
                EventLogAnalyzer.RankTopCounts(lockedAccounts)));
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Account Lockout Check Error",
                $"Could not check account lockouts: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator."));
        }
    }

    #endregion

    #region Privilege Escalation (Event IDs 4672, 4673)

    /// <summary>Check for unusual privilege escalation events in the last 24 hours.</summary>
    private async Task CheckPrivilegeEscalation(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Event 4672: special privileges assigned to new logon
            // Event 4673: privileged service was called
            // Only look at last 24h and count — high volume is suspicious
            var query = "*[System[(EventID=4672 or EventID=4673) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";

            var events = await QueryEventLogAsync("Security", query, ct, maxEvents: 500);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Privilege Escalation Check — Access Denied",
                    "Could not read Security event log for privilege escalation events. Administrator privileges required.",
                    Category,
                    "Run WinSentinel as Administrator."));
                return;
            }

            int event4672Count = 0;
            int event4673Count = 0;
            var privilegedUsers = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var evt in events)
            {
                try
                {
                    if (evt.Id == 4672) event4672Count++;
                    else if (evt.Id == 4673) event4673Count++;

                    // Property index 1 = SubjectUserName for 4672
                    if (evt.Properties.Count > 1)
                    {
                        var user = evt.Properties[1]?.Value?.ToString();
                        if (EventLogAnalyzer.IsMeaningfulUser(user) && !EventLogAnalyzer.IsSystemAccount(user))
                        {
                            privilegedUsers[user!] = privilegedUsers.GetValueOrDefault(user!) + 1;
                        }
                    }
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
            }

            AddFinding(result, EventLogAnalyzer.BuildPrivilegeEscalationFinding(
                event4672Count,
                event4673Count,
                EventLogAnalyzer.RankTopCounts(privilegedUsers),
                privilegedUsers.Count));
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Privilege Escalation Check Error",
                $"Could not check privilege escalation events: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator."));
        }
    }

    #endregion

    #region Audit Policy Gaps

    /// <summary>Check if key Windows audit policies are enabled using auditpol.</summary>
    private async Task CheckAuditPolicyGaps(AuditResult result, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunCmdAsync("auditpol /get /category:*", QueryTimeout, ct);

            var auditScan = EventLogAnalyzer.ParseAuditPolicy(output);
            if (auditScan == null)
            {
                AddFinding(result, Finding.Info(
                    "Audit Policy Check — Access Denied",
                    "Could not read audit policies. Administrator privileges are required to run 'auditpol /get /category:*'.",
                    Category,
                    "Run WinSentinel as Administrator to check audit policies."));
                return;
            }

            AddFinding(result, EventLogAnalyzer.BuildAuditPolicyFinding(auditScan));
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Audit Policy Check Error",
                $"Could not check audit policies: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator."));
        }
    }

    #endregion

    #region Service Installations (Event ID 7045)

    /// <summary>Check for new service installations (Event ID 7045) in the last 7 days.</summary>
    private async Task CheckServiceInstallations(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Event 7045 in System log = new service was installed
            var query = "*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";

            var events = await QueryEventLogAsync("System", query, ct);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Service Installation Check — Error",
                    "Could not read the System event log for service installation events.",
                    Category,
                    "Run WinSentinel as Administrator."));
                return;
            }

            int count = events.Count;

            var serviceDetails = new List<string>();
            foreach (var evt in events)
            {
                try
                {
                    // Properties: 0=ServiceName, 1=ImagePath, 2=ServiceType, 3=StartType, 4=AccountName
                    string serviceName = evt.Properties.Count > 0 ? evt.Properties[0]?.Value?.ToString() ?? "Unknown" : "Unknown";
                    string imagePath = evt.Properties.Count > 1 ? evt.Properties[1]?.Value?.ToString() ?? "Unknown" : "Unknown";

                    serviceDetails.Add($"• {serviceName} — {imagePath} ({evt.TimeCreated:yyyy-MM-dd HH:mm})");
                }
                catch
                {
                    serviceDetails.Add($"• (malformed event at {evt.TimeCreated:yyyy-MM-dd HH:mm})");
                }
            }

            AddFinding(result, EventLogAnalyzer.BuildServiceInstallFinding(count, serviceDetails));
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Service Installation Check Error",
                $"Could not check service installations: {ex.Message}",
                Category));
        }
    }

    #endregion

    #region Suspicious PowerShell (Event ID 4104)

    /// <summary>Check PowerShell script block logging (Event ID 4104) for suspicious patterns.</summary>
    private async Task CheckSuspiciousPowerShell(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Event 4104 is in Microsoft-Windows-PowerShell/Operational
            // Check last 7 days
            var query = "*[System[(EventID=4104) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";

            var events = await QueryEventLogAsync("Microsoft-Windows-PowerShell/Operational", query, ct, maxEvents: 200);

            if (events == null)
            {
                // Check if script block logging is even enabled
                var scriptBlockLogging = RegistryHelper.GetValue<int>(
                    RegistryHive.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                    "EnableScriptBlockLogging", -1);

                AddFinding(result, scriptBlockLogging != 1
                    ? EventLogAnalyzer.BuildScriptBlockLoggingDisabledFinding()
                    : Finding.Info(
                        "PowerShell Activity Check — No Events",
                        "Script Block Logging is enabled but could not read events. Run as Administrator.",
                        Category));
                return;
            }

            int suspiciousCount = 0;
            var suspiciousCommands = new List<string>();

            foreach (var evt in events)
            {
                try
                {
                    // Property 2 = ScriptBlockText for Event 4104
                    var scriptBlock = evt.Properties.Count > 2
                        ? evt.Properties[2]?.Value?.ToString() ?? ""
                        : evt.FormatDescription() ?? "";

                    if (string.IsNullOrWhiteSpace(scriptBlock)) continue;

                    if (EventLogAnalyzer.IsSuspiciousPowerShell(scriptBlock))
                    {
                        suspiciousCount++;

                        // Truncate to keep report readable
                        var snippet = EventLogAnalyzer.Truncate(scriptBlock, 150);
                        snippet = snippet.Replace("\r", " ").Replace("\n", " ");

                        if (suspiciousCommands.Count < 5)
                            suspiciousCommands.Add($"• [{evt.TimeCreated:MM-dd HH:mm}] {snippet}");
                    }
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
            }

            if (suspiciousCount == 0 && events.Count == 0)
            {
                // Check if Script Block Logging is enabled
                var scriptBlockLogging = RegistryHelper.GetValue<int>(
                    RegistryHive.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                    "EnableScriptBlockLogging", -1);

                AddFinding(result, scriptBlockLogging != 1
                    ? EventLogAnalyzer.BuildScriptBlockLoggingDisabledFinding()
                    : Finding.Pass(
                        "No Suspicious PowerShell Activity",
                        "PowerShell Script Block Logging is enabled and no suspicious patterns detected in the last 7 days.",
                        Category));
            }
            else
            {
                AddFinding(result, EventLogAnalyzer.BuildSuspiciousPowerShellFinding(
                    suspiciousCount, events.Count, suspiciousCommands));
            }
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "PowerShell Activity Check Error",
                $"Could not check PowerShell activity: {ex.Message}",
                Category));
        }
    }

    #endregion

    #region Windows Defender Detections (Event IDs 1116, 1117)

    /// <summary>Check Windows Defender logs for threat detections in the last 7 days.</summary>
    private async Task CheckDefenderDetections(AuditResult result, CancellationToken ct)
    {
        try
        {
            // 1116 = threat detected, 1117 = action taken on threat
            var query = "*[System[(EventID=1116 or EventID=1117) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";

            var events = await QueryEventLogAsync("Microsoft-Windows-Windows Defender/Operational", query, ct);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Defender Detection Check — Log Unavailable",
                    "Could not read Windows Defender operational log. Defender may not be installed or the log may be inaccessible.",
                    Category,
                    "Ensure Windows Defender is installed and running."));
                return;
            }

            int detections = events.Count(e => e.Id == 1116);
            int actions = events.Count(e => e.Id == 1117);
            var threatNames = new List<string>();

            foreach (var evt in events.Where(e => e.Id == 1116))
            {
                try
                {
                    var desc = evt.FormatDescription();
                    if (!string.IsNullOrEmpty(desc))
                    {
                        // Try to extract threat name from description
                        var nameMatch = Regex.Match(desc, @"Name:\s*(.+?)[\r\n]");
                        if (nameMatch.Success && threatNames.Count < 5)
                            threatNames.Add(nameMatch.Groups[1].Value.Trim());
                    }

                    // Also try properties — threat name is typically in early properties
                    if (threatNames.Count < 5 && evt.Properties.Count > 7)
                    {
                        var threatName = evt.Properties[7]?.Value?.ToString();
                        if (!string.IsNullOrWhiteSpace(threatName) && !threatNames.Contains(threatName))
                            threatNames.Add(threatName);
                    }
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
            }

            if (detections == 0)
            {
                AddFinding(result, Finding.Pass(
                    "No Defender Threat Detections",
                    "Windows Defender has not detected any threats (Event IDs 1116/1117) in the last 7 days.",
                    Category));
            }
            else
            {
                AddFinding(result, EventLogAnalyzer.BuildDefenderDetectionFinding(
                    detections, actions, threatNames));
            }
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Defender Detection Check Error",
                $"Could not check Defender detections: {ex.Message}",
                Category));
        }
    }

    /// <summary>
    /// Check the Windows Defender operational log for "protection turned off"
    /// events over the last 7 days: 5001 (real-time protection disabled), 5010
    /// (anti-malware/anti-spyware scanning disabled), 5012 (antivirus scanning
    /// disabled). Distinct from <see cref="CheckDefenderDetections"/> (which flags
    /// threats Defender <i>caught</i>); this flags Defender being <i>switched
    /// off</i>, a classic attacker precursor to dropping a payload.
    /// </summary>
    private async Task CheckDefenderTampering(AuditResult result, CancellationToken ct)
    {
        try
        {
            // 5001 = real-time protection disabled, 5010 = anti-malware scanning
            // disabled, 5012 = antivirus scanning disabled. Last 7 days.
            var query = "*[System[(EventID=5001 or EventID=5010 or EventID=5012) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";

            var events = await QueryEventLogAsync("Microsoft-Windows-Windows Defender/Operational", query, ct);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Defender Tamper Check — Log Unavailable",
                    "Could not read Windows Defender operational log. Defender may not be installed or the log may be inaccessible.",
                    Category,
                    "Ensure Windows Defender is installed and running."));
                return;
            }

            if (events.Count == 0)
            {
                AddFinding(result, EventLogAnalyzer.BuildDefenderTamperingFinding(0));
                return;
            }

            var eventLines = new List<string>();
            foreach (var evt in events.OrderByDescending(e => e.TimeCreated))
            {
                if (eventLines.Count >= 10) break;
                var what = evt.Id switch
                {
                    5001 => "Real-time protection disabled",
                    5010 => "Anti-malware/anti-spyware scanning disabled",
                    5012 => "Antivirus scanning disabled",
                    _ => $"Protection disabled (event {evt.Id})",
                };
                eventLines.Add($"• {evt.TimeCreated:yyyy-MM-dd HH:mm} — {what}");
            }

            AddFinding(result, EventLogAnalyzer.BuildDefenderTamperingFinding(events.Count, eventLines));
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Defender Tamper Check Error",
                $"Could not check Defender tampering: {ex.Message}",
                Category));
        }
    }

    #endregion

    #region System Errors

    /// <summary>Check for Critical and Error events in the System log in the last 24 hours.</summary>
    private async Task CheckSystemErrors(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Level 1 = Critical, Level 2 = Error
            var query = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";

            var events = await QueryEventLogAsync("System", query, ct, maxEvents: 100);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "System Error Check — Error",
                    "Could not read the System event log for error events.",
                    Category));
                return;
            }

            int criticalCount = events.Count(e =>
            {
                try { return e.Level == 1; } catch { return false; }
            });
            int errorCount = events.Count(e =>
            {
                try { return e.Level == 2; } catch { return false; }
            });

            int total = criticalCount + errorCount;

            if (total == 0)
            {
                AddFinding(result, Finding.Pass(
                    "No System Errors",
                    "No critical or error events in the System log in the last 24 hours. System stability appears good.",
                    Category));
            }
            else
            {
                // Summarize top event sources
                var sources = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                var samples = new List<string>();

                foreach (var evt in events)
                {
                    try
                    {
                        var source = evt.ProviderName ?? "Unknown";
                        sources[source] = sources.GetValueOrDefault(source) + 1;

                        if (samples.Count < 5)
                        {
                            var desc = evt.FormatDescription();
                            var shortDesc = EventLogAnalyzer.Truncate(desc ?? "No description", 100);
                            shortDesc = shortDesc.Replace("\r", " ").Replace("\n", " ");
                            samples.Add($"• [{evt.TimeCreated:HH:mm}] {source} (ID {evt.Id}): {shortDesc}");
                        }
                    }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
                }

                AddFinding(result, EventLogAnalyzer.BuildSystemErrorFinding(
                    criticalCount, errorCount,
                    EventLogAnalyzer.RankTopCounts(sources),
                    samples));
            }
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "System Error Check Error",
                $"Could not check system errors: {ex.Message}",
                Category));
        }
    }

    #endregion

    #region Security Log Size

    /// <summary>Check if the Security event log is adequately sized (>= 128 MB) and configured properly.</summary>
    private async Task CheckSecurityLogSize(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Read from registry where log configuration is stored
            var logSizeBytes = RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "MaxSize", 0);

            // Also check the retention/overwrite setting
            var retention = RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "Retention", 0);

            // Retention: 0 = Overwrite as needed, -1 = Do not overwrite (archive), >0 = Overwrite older than N days

            if (logSizeBytes == 0)
            {
                // Try PowerShell as fallback
                try
                {
                    var psOutput = await ShellHelper.RunPowerShellAsync(
                        "(Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue) | Select-Object -Property MaximumSizeInBytes,LogMode | Format-List", ct);

                    if (!string.IsNullOrWhiteSpace(psOutput))
                    {
                        var parsedSize = EventLogAnalyzer.ParseMaxSizeFromPowerShell(psOutput);
                        if (parsedSize > 0)
                            logSizeBytes = (int)Math.Min(parsedSize, int.MaxValue);

                        retention = EventLogAnalyzer.ParseRetentionFromLogMode(psOutput, retention);
                    }
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
            }

            long maxSizeBytes = logSizeBytes > 0 ? logSizeBytes : EventLogAnalyzer.SecurityLogDefaultBytes;

            AddFinding(result, EventLogAnalyzer.BuildSecurityLogSizeFinding(maxSizeBytes, retention));

            // Warn if set to "do not overwrite" — can cause event loss if log fills up
            var doNotOverwrite = EventLogAnalyzer.BuildDoNotOverwriteFinding(retention);
            if (doNotOverwrite != null)
                AddFinding(result, doNotOverwrite);
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Security Log Size Check Error",
                $"Could not check Security log size: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator."));
        }
    }

    #endregion

    #region Log Cleared (Event ID 1102)

    /// <summary>Check for audit log cleared events (Event ID 1102) — someone may have wiped evidence.</summary>
    private async Task CheckLogCleared(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Event ID 1102 in Security log = "The audit log was cleared"
            // Check last 30 days — this is a rare and significant event
            var query = "*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]";

            var events = await QueryEventLogAsync("Security", query, ct);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Log Cleared Check — Access Denied",
                    "Could not check for log-cleared events. Administrator privileges required.",
                    Category,
                    "Run WinSentinel as Administrator."));
                return;
            }

            if (events.Count == 0)
            {
                AddFinding(result, EventLogAnalyzer.BuildLogClearedFinding(0));
            }
            else
            {
                var clearDetails = new List<string>();
                foreach (var evt in events)
                {
                    try
                    {
                        string who = "Unknown";
                        if (evt.Properties.Count > 1)
                        {
                            var domain = evt.Properties[1]?.Value?.ToString() ?? "";
                            var user = evt.Properties[2]?.Value?.ToString() ?? "";
                            who = !string.IsNullOrEmpty(domain) ? $"{domain}\\{user}" : user;
                        }

                        clearDetails.Add($"• {evt.TimeCreated:yyyy-MM-dd HH:mm} by {who}");
                    }
                    catch
                    {
                        clearDetails.Add($"• {evt.TimeCreated:yyyy-MM-dd HH:mm} by Unknown");
                    }
                }

                AddFinding(result, EventLogAnalyzer.BuildLogClearedFinding(events.Count, clearDetails));
            }
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Log Cleared Check Error",
                $"Could not check for log-cleared events: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator."));
        }
    }

    #endregion

    #region Remote Logons (Event ID 4624, LogonType 3/10)

    /// <summary>
    /// Check the Security log for SUCCESSFUL remote logons (Event ID 4624) that came
    /// from external (public-internet) source IPs in the last 24 hours - RDP
    /// (LogonType 10) and network (LogonType 3). Complements <see
    /// cref="CheckFailedLogins"/> (4625): a successful remote logon from outside the
    /// LAN, especially RDP, is the point at which a brute force turns into a breach.
    /// </summary>
    private async Task CheckRemoteLogons(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Event 4624 = successful logon. Filter to the two remotely-reachable
            // logon types (3 network, 10 RemoteInteractive/RDP) in the last 24h.
            // EventData/Data[@Name='LogonType'] narrows at the log layer so we don't
            // pull every interactive/service logon on the box.
            var query = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 86400000]]]" +
                        "[EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']]";

            var events = await QueryEventLogAsync("Security", query, ct, maxEvents: 1000);

            if (events == null)
            {
                AddFinding(result, Finding.Info(
                    "Remote Logon Check - Access Denied",
                    "Could not read the Security event log for successful remote logons (Event ID 4624). Administrator privileges are required.",
                    Category,
                    "Run WinSentinel as Administrator to check remote logon activity."));
                return;
            }

            int externalRdp = 0;
            int externalNetwork = 0;
            var sources = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var evt in events)
            {
                try
                {
                    // 4624 property layout: 5 = TargetUserName, 8 = LogonType, 18 = IpAddress.
                    int logonType = -1;
                    if (evt.Properties.Count > 8 &&
                        int.TryParse(evt.Properties[8]?.Value?.ToString(), out var lt))
                    {
                        logonType = lt;
                    }

                    var ip = evt.Properties.Count > 18 ? evt.Properties[18]?.Value?.ToString() : null;

                    // Only external (public) source IPs are the risk signal - LAN
                    // remote logons are expected. IsExternalSourceIp also drops
                    // blank/"-"/loopback.
                    if (!EventLogAnalyzer.IsExternalSourceIp(ip)) continue;

                    var user = evt.Properties.Count > 5 ? evt.Properties[5]?.Value?.ToString() : null;
                    if (EventLogAnalyzer.IsSystemAccount(user)) continue; // ignore machine/system network auth noise

                    if (logonType == EventLogAnalyzer.LogonTypeRemoteInteractive) externalRdp++;
                    else if (logonType == EventLogAnalyzer.LogonTypeNetwork) externalNetwork++;
                    else continue;

                    var who = EventLogAnalyzer.IsMeaningfulUser(user) ? user! : "?";
                    var key = $"{who}@{ip} [{EventLogAnalyzer.DescribeLogonType(logonType)}]";
                    sources[key] = sources.GetValueOrDefault(key) + 1;
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
            }

            AddFinding(result, EventLogAnalyzer.BuildRemoteLogonFinding(
                externalRdp, externalNetwork,
                EventLogAnalyzer.RankTopCounts(sources)));
        }
        catch (Exception ex)
        {
            AddFinding(result, Finding.Info(
                "Remote Logon Check Error",
                $"Could not check remote logons: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator."));
        }
    }

    #endregion

    #region Helpers

    /// <summary>
    /// Query an event log using XPath with timeout protection.
    /// Returns null if the log is inaccessible, empty list if no matching events.
    /// </summary>
    private async Task<List<EventLogRecord>?> QueryEventLogAsync(
        string logName, string xpathQuery, CancellationToken ct, int maxEvents = 1000)
    {
        return await Task.Run(() =>
        {
            try
            {
                var records = new List<EventLogRecord>();
                var query = new EventLogQuery(logName, PathType.LogName, xpathQuery);

                using var reader = new EventLogReader(query);
                EventRecord? record;
                int count = 0;

                while ((record = reader.ReadEvent()) != null && count < maxEvents)
                {
                    ct.ThrowIfCancellationRequested();

                    if (record is EventLogRecord logRecord)
                    {
                        records.Add(logRecord);
                        count++;
                    }
                    else
                    {
                        record.Dispose();
                    }
                }

                return records;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            catch (EventLogNotFoundException)
            {
                return null;
            }
            catch (EventLogException ex) when (
                ex.Message.Contains("access", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("denied", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            catch (EventLogException)
            {
                // Log not found or other issue — return null to handle gracefully
                return null;
            }
        }, ct);
    }

    #endregion
}
