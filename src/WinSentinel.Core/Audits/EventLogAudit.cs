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

    /// <summary>Suspicious PowerShell patterns (case-insensitive).</summary>
    private static readonly Regex SuspiciousPowerShellPattern = new(
        @"(?i)(Invoke-Expression|IEX\s*\(|Invoke-WebRequest|DownloadString|DownloadFile|" +
        @"Net\.WebClient|Start-BitsTransfer|Invoke-Mimikatz|Invoke-Shellcode|" +
        @"-enc\s|EncodedCommand|FromBase64String|bypass|hidden|" +
        @"Add-MpPreference\s+-ExclusionPath|Set-MpPreference\s+-DisableRealtimeMonitoring|" +
        @"New-Object\s+System\.Net\.Sockets\.TCPClient|Invoke-Command\s+-ComputerName)",
        RegexOptions.Compiled);

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
            // Run all checks — each is isolated so one failure doesn't block others
            await CheckEventLogServiceRunning(result, cancellationToken);
            await CheckFailedLogins(result, cancellationToken);
            await CheckAccountLockouts(result, cancellationToken);
            await CheckPrivilegeEscalation(result, cancellationToken);
            await CheckAuditPolicyGaps(result, cancellationToken);
            await CheckServiceInstallations(result, cancellationToken);
            await CheckSuspiciousPowerShell(result, cancellationToken);
            await CheckDefenderDetections(result, cancellationToken);
            await CheckSystemErrors(result, cancellationToken);
            await CheckSecurityLogSize(result, cancellationToken);
            await CheckLogCleared(result, cancellationToken);
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
                result.Findings.Add(Finding.Pass(
                    "Event Log Service Running",
                    "The Windows Event Log service is running. Event logging is active.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Critical(
                    "Event Log Service Not Running",
                    $"The Windows Event Log service is in state '{sc.Status}'. Security events are NOT being recorded. This is a severe security gap.",
                    Category,
                    "Start the Windows Event Log service immediately: net start EventLog",
                    "powershell -Command \"Start-Service EventLog\""));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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
            var since = DateTime.UtcNow.AddHours(-24);
            var timeFilter = ToSystemTimeXml(since);

            // XPath query targeting only Event ID 4625 with time filter
            var query = $"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";

            var events = await QueryEventLogAsync("Security", query, ct);

            if (events == null)
            {
                result.Findings.Add(Finding.Info(
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
                        if (!string.IsNullOrWhiteSpace(user) && user != "-")
                        {
                            usernames[user] = usernames.GetValueOrDefault(user) + 1;
                        }
                    }

                    if (evt.Properties.Count > 19)
                    {
                        var ip = evt.Properties[19]?.Value?.ToString();
                        if (!string.IsNullOrWhiteSpace(ip) && ip != "-" && ip != "::1" && ip != "127.0.0.1")
                        {
                            sourceIPs[ip] = sourceIPs.GetValueOrDefault(ip) + 1;
                        }
                    }
                }
                catch
                {
                    // Skip malformed events
                }
            }

            if (count == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "No Failed Login Attempts",
                    "No failed login attempts (Event ID 4625) detected in the last 24 hours.",
                    Category));
            }
            else
            {
                var details = new List<string> { $"Total failed logins: {count}" };

                if (usernames.Count > 0)
                {
                    var topUsers = usernames.OrderByDescending(kv => kv.Value).Take(5)
                        .Select(kv => $"{kv.Key} ({kv.Value}x)");
                    details.Add($"Targeted accounts: {string.Join(", ", topUsers)}");
                }

                if (sourceIPs.Count > 0)
                {
                    var topIPs = sourceIPs.OrderByDescending(kv => kv.Value).Take(5)
                        .Select(kv => $"{kv.Key} ({kv.Value}x)");
                    details.Add($"Source IPs: {string.Join(", ", topIPs)}");
                }

                var description = string.Join(". ", details) + ".";

                if (count > 20)
                {
                    result.Findings.Add(Finding.Critical(
                        $"High Failed Login Rate — {count} in 24h",
                        $"{description} This may indicate a brute-force attack or credential stuffing attempt.",
                        Category,
                        "Investigate the source IPs. Consider enabling account lockout policies, IP blocking, or MFA. Check if any accounts were compromised.",
                        "powershell -Command \"auditpol /set /subcategory:'Logon' /failure:enable\""));
                }
                else if (count > 5)
                {
                    result.Findings.Add(Finding.Warning(
                        $"Failed Login Attempts — {count} in 24h",
                        $"{description} Multiple failed login attempts detected — monitor for patterns.",
                        Category,
                        "Review the failed login sources. Ensure account lockout policies are configured. Consider enabling MFA."));
                }
                else
                {
                    result.Findings.Add(Finding.Info(
                        $"Failed Login Attempts — {count} in 24h",
                        $"{description} A small number of failed logins is normal (mistyped passwords, etc.).",
                        Category));
                }
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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
                result.Findings.Add(Finding.Info(
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
                catch { }
            }

            if (count == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "No Account Lockouts",
                    "No account lockout events (Event ID 4740) in the last 7 days.",
                    Category));
            }
            else
            {
                var accountsList = lockedAccounts.OrderByDescending(kv => kv.Value)
                    .Take(5).Select(kv => $"{kv.Key} ({kv.Value}x)");

                result.Findings.Add(count > 5
                    ? Finding.Warning(
                        $"Account Lockouts — {count} in 7 Days",
                        $"Detected {count} account lockout event(s). Affected accounts: {string.Join(", ", accountsList)}. Frequent lockouts may indicate brute-force attacks.",
                        Category,
                        "Investigate whether lockouts are from legitimate users mistyping passwords or from an attacker. Review account lockout policies.")
                    : Finding.Info(
                        $"Account Lockouts — {count} in 7 Days",
                        $"Detected {count} account lockout event(s). Affected accounts: {string.Join(", ", accountsList)}. Occasional lockouts are normal.",
                        Category));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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
                result.Findings.Add(Finding.Info(
                    "Privilege Escalation Check — Access Denied",
                    "Could not read Security event log for privilege escalation events. Administrator privileges required.",
                    Category,
                    "Run WinSentinel as Administrator."));
                return;
            }

            int event4672Count = 0;
            int event4673Count = 0;
            var privilegedUsers = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            // Well-known system accounts that normally have elevated privileges
            var systemAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "DWM-3",
                "UMFD-0", "UMFD-1", "UMFD-2", "UMFD-3",
                "ANONYMOUS LOGON", "Window Manager"
            };

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
                        if (!string.IsNullOrWhiteSpace(user) && !systemAccounts.Contains(user) &&
                            !user.EndsWith("$", StringComparison.Ordinal)) // Skip machine accounts
                        {
                            privilegedUsers[user] = privilegedUsers.GetValueOrDefault(user) + 1;
                        }
                    }
                }
                catch { }
            }

            int total = event4672Count + event4673Count;

            if (total == 0)
            {
                result.Findings.Add(Finding.Info(
                    "No Privilege Escalation Events",
                    "No privilege escalation events (4672/4673) detected in the last 24 hours. Note: this may mean audit policies are not enabled for privilege use.",
                    Category,
                    "Enable 'Privilege Use' auditing: auditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable /failure:enable"));
            }
            else
            {
                var userList = privilegedUsers.OrderByDescending(kv => kv.Value).Take(5)
                    .Select(kv => $"{kv.Key} ({kv.Value}x)");
                var details = $"Detected {event4672Count} special privilege logon(s) and {event4673Count} privileged service call(s) in 24h.";

                if (privilegedUsers.Count > 0)
                    details += $" Non-system users with elevated privileges: {string.Join(", ", userList)}.";

                if (privilegedUsers.Count > 10 || event4673Count > 50)
                {
                    result.Findings.Add(Finding.Warning(
                        "Unusual Privilege Activity",
                        details + " High volume of privilege usage from non-system accounts may indicate compromise or misconfiguration.",
                        Category,
                        "Review which accounts are being granted elevated privileges. Verify that only authorized administrators have these permissions."));
                }
                else
                {
                    result.Findings.Add(Finding.Pass(
                        "Privilege Escalation Events — Normal",
                        details + " Volume appears normal for this system.",
                        Category));
                }
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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

            if (string.IsNullOrWhiteSpace(output) ||
                output.Contains("Access is denied", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Info(
                    "Audit Policy Check — Access Denied",
                    "Could not read audit policies. Administrator privileges are required to run 'auditpol /get /category:*'.",
                    Category,
                    "Run WinSentinel as Administrator to check audit policies."));
                return;
            }

            // Key audit subcategories and whether they should have Success/Failure enabled
            var requiredPolicies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "Logon", "Logon/Logoff" },
                { "Logoff", "Logon/Logoff" },
                { "Account Lockout", "Logon/Logoff" },
                { "Special Logon", "Logon/Logoff" },
                { "File System", "Object Access" },
                { "Registry", "Object Access" },
                { "Sensitive Privilege Use", "Privilege Use" },
                { "Authentication Policy Change", "Policy Change" },
                { "Audit Policy Change", "Policy Change" },
                { "User Account Management", "Account Management" },
                { "Security Group Management", "Account Management" },
                { "Computer Account Management", "Account Management" },
            };

            var lines = output.Split('\n', StringSplitOptions.TrimEntries);
            var gaps = new List<string>();
            var enabled = new List<string>();

            foreach (var kvp in requiredPolicies)
            {
                var subcategory = kvp.Key;
                var parentCategory = kvp.Value;

                // Find the line for this subcategory
                var line = lines.FirstOrDefault(l =>
                    l.Contains(subcategory, StringComparison.OrdinalIgnoreCase) &&
                    !l.StartsWith("Category", StringComparison.OrdinalIgnoreCase));

                if (line == null) continue;

                bool hasNoAuditing = line.Contains("No Auditing", StringComparison.OrdinalIgnoreCase);

                if (hasNoAuditing)
                {
                    gaps.Add($"{subcategory} ({parentCategory})");
                }
                else
                {
                    enabled.Add(subcategory);
                }
            }

            if (gaps.Count == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "Audit Policies Configured",
                    $"All key audit policies are enabled ({enabled.Count} subcategories checked). Security events are being logged for logon/logoff, object access, privilege use, policy changes, and account management.",
                    Category));
            }
            else if (gaps.Count <= 3)
            {
                result.Findings.Add(Finding.Warning(
                    $"Audit Policy Gaps — {gaps.Count} Missing",
                    $"Some audit policies are not enabled: {string.Join(", ", gaps)}. Missing audit policies create blind spots where malicious activity goes unrecorded.",
                    Category,
                    $"Enable missing audit policies using: auditpol /set /subcategory:\"<name>\" /success:enable /failure:enable",
                    $"powershell -Command \"{string.Join("; ", gaps.Select(g => $"auditpol /set /subcategory:\\\"{g.Split('(')[0].Trim()}\\\" /success:enable /failure:enable"))}\""));
            }
            else
            {
                result.Findings.Add(Finding.Critical(
                    $"Major Audit Policy Gaps — {gaps.Count} Missing",
                    $"Many critical audit policies are disabled: {string.Join(", ", gaps.Take(8))}. The system is not recording important security events, making incident investigation extremely difficult.",
                    Category,
                    "Enable comprehensive audit policies immediately. Use: auditpol /set /category:* /success:enable /failure:enable — or apply a security baseline via Group Policy.",
                    "powershell -Command \"auditpol /set /category:* /success:enable /failure:enable\""));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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
                result.Findings.Add(Finding.Info(
                    "Service Installation Check — Error",
                    "Could not read the System event log for service installation events.",
                    Category,
                    "Run WinSentinel as Administrator."));
                return;
            }

            int count = events.Count;

            if (count == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "No New Services Installed",
                    "No new service installations (Event ID 7045) detected in the last 7 days.",
                    Category));
            }
            else
            {
                var serviceDetails = new List<string>();

                foreach (var evt in events)
                {
                    try
                    {
                        // Properties: 0=ServiceName, 1=ImagePath, 2=ServiceType, 3=StartType, 4=AccountName
                        string serviceName = evt.Properties.Count > 0 ? evt.Properties[0]?.Value?.ToString() ?? "Unknown" : "Unknown";
                        string imagePath = evt.Properties.Count > 1 ? evt.Properties[1]?.Value?.ToString() ?? "Unknown" : "Unknown";
                        string startType = evt.Properties.Count > 3 ? evt.Properties[3]?.Value?.ToString() ?? "" : "";

                        serviceDetails.Add($"• {serviceName} — {imagePath} ({evt.TimeCreated:yyyy-MM-dd HH:mm})");
                    }
                    catch
                    {
                        serviceDetails.Add($"• (malformed event at {evt.TimeCreated:yyyy-MM-dd HH:mm})");
                    }
                }

                var description = $"{count} new service(s) installed in the last 7 days. Service installations can be used for malware persistence.\n{string.Join("\n", serviceDetails.Take(10))}";

                if (count > 10)
                    description += $"\n... and {count - 10} more.";

                if (count > 5)
                {
                    result.Findings.Add(Finding.Warning(
                        $"New Services Installed — {count} in 7 Days",
                        description,
                        Category,
                        "Review installed services to ensure they are legitimate. Malware often persists by installing services. Check service binary paths for suspicious locations (temp folders, AppData, etc.)."));
                }
                else
                {
                    result.Findings.Add(Finding.Info(
                        $"New Services Installed — {count} in 7 Days",
                        description,
                        Category,
                        "Review installed services to ensure they are expected."));
                }
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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

                if (scriptBlockLogging != 1)
                {
                    result.Findings.Add(Finding.Warning(
                        "PowerShell Script Block Logging Not Enabled",
                        "PowerShell Script Block Logging is not enabled. Malicious PowerShell commands will not be recorded in event logs, making it difficult to detect living-off-the-land attacks.",
                        Category,
                        "Enable Script Block Logging via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging.",
                        "powershell -Command \"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord\""));
                }
                else
                {
                    result.Findings.Add(Finding.Info(
                        "PowerShell Activity Check — No Events",
                        "Script Block Logging is enabled but could not read events. Run as Administrator.",
                        Category));
                }
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

                    if (SuspiciousPowerShellPattern.IsMatch(scriptBlock))
                    {
                        suspiciousCount++;

                        // Truncate to keep report readable
                        var snippet = scriptBlock.Length > 150
                            ? scriptBlock[..150] + "..."
                            : scriptBlock;
                        snippet = snippet.Replace("\r", " ").Replace("\n", " ");

                        if (suspiciousCommands.Count < 5)
                            suspiciousCommands.Add($"• [{evt.TimeCreated:MM-dd HH:mm}] {snippet}");
                    }
                }
                catch { }
            }

            if (suspiciousCount == 0 && events.Count == 0)
            {
                // Check if Script Block Logging is enabled
                var scriptBlockLogging = RegistryHelper.GetValue<int>(
                    RegistryHive.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                    "EnableScriptBlockLogging", -1);

                if (scriptBlockLogging != 1)
                {
                    result.Findings.Add(Finding.Warning(
                        "PowerShell Script Block Logging Not Enabled",
                        "PowerShell Script Block Logging is not enabled. Malicious PowerShell commands will not be recorded, making detection of attacks difficult.",
                        Category,
                        "Enable Script Block Logging via Group Policy or registry.",
                        "powershell -Command \"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord\""));
                }
                else
                {
                    result.Findings.Add(Finding.Pass(
                        "No Suspicious PowerShell Activity",
                        "PowerShell Script Block Logging is enabled and no suspicious patterns detected in the last 7 days.",
                        Category));
                }
            }
            else if (suspiciousCount == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "No Suspicious PowerShell Activity",
                    $"Analyzed {events.Count} PowerShell script block event(s) from the last 7 days. No suspicious patterns (encoded commands, download cradles, bypass techniques) detected.",
                    Category));
            }
            else
            {
                var description = $"Detected {suspiciousCount} suspicious PowerShell script block(s) in the last 7 days out of {events.Count} total. Suspicious patterns include encoded commands, download cradles, and security bypass techniques.";

                if (suspiciousCommands.Count > 0)
                    description += "\n\nExamples:\n" + string.Join("\n", suspiciousCommands);

                result.Findings.Add(suspiciousCount > 5
                    ? Finding.Critical(
                        $"Suspicious PowerShell Activity — {suspiciousCount} Events",
                        description,
                        Category,
                        "Investigate the PowerShell commands immediately. Check which user account ran them. Look for indicators of compromise. Consider blocking PowerShell for non-admin users via AppLocker.")
                    : Finding.Warning(
                        $"Suspicious PowerShell Activity — {suspiciousCount} Events",
                        description,
                        Category,
                        "Review the flagged PowerShell commands. Some may be legitimate admin scripts, but encoded commands and download cradles are common attack techniques."));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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
                result.Findings.Add(Finding.Info(
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
                catch { }
            }

            if (detections == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "No Defender Threat Detections",
                    "Windows Defender has not detected any threats (Event IDs 1116/1117) in the last 7 days.",
                    Category));
            }
            else
            {
                var description = $"Windows Defender detected {detections} threat(s) in the last 7 days, with {actions} remediation action(s) taken.";

                if (threatNames.Count > 0)
                    description += $" Threats: {string.Join(", ", threatNames)}.";

                if (detections > actions)
                {
                    result.Findings.Add(Finding.Critical(
                        $"Defender Threats Detected — {detections} ({detections - actions} Unresolved)",
                        description + " Some threats may not have been remediated.",
                        Category,
                        "Open Windows Security → Virus & threat protection → Protection history. Review and resolve any remaining threats. Run a full system scan.",
                        "powershell -Command \"Start-MpScan -ScanType FullScan\""));
                }
                else
                {
                    result.Findings.Add(Finding.Warning(
                        $"Defender Threats Detected — {detections} (All Remediated)",
                        description + " All detected threats were remediated.",
                        Category,
                        "Review Windows Security → Protection history to understand what was detected. Consider running a full scan to ensure no threats remain.",
                        "powershell -Command \"Start-MpScan -ScanType FullScan\""));
                }
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "Defender Detection Check Error",
                $"Could not check Defender detections: {ex.Message}",
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
                result.Findings.Add(Finding.Info(
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
                result.Findings.Add(Finding.Pass(
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
                            var shortDesc = desc != null && desc.Length > 100 ? desc[..100] + "..." : desc ?? "No description";
                            shortDesc = shortDesc.Replace("\r", " ").Replace("\n", " ");
                            samples.Add($"• [{evt.TimeCreated:HH:mm}] {source} (ID {evt.Id}): {shortDesc}");
                        }
                    }
                    catch { }
                }

                var topSources = sources.OrderByDescending(kv => kv.Value).Take(5)
                    .Select(kv => $"{kv.Key} ({kv.Value}x)");

                var description = $"Detected {criticalCount} critical and {errorCount} error event(s) in the System log in the last 24 hours. " +
                                  $"Top sources: {string.Join(", ", topSources)}.";

                if (samples.Count > 0)
                    description += "\n\nRecent events:\n" + string.Join("\n", samples);

                if (criticalCount > 0)
                {
                    result.Findings.Add(Finding.Warning(
                        $"System Critical Errors — {criticalCount} Critical, {errorCount} Errors",
                        description,
                        Category,
                        "Investigate critical events immediately. Check for bugcheck dumps (BSOD), driver failures, or hardware issues. Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth' to repair system files.",
                        "powershell -Command \"sfc /scannow\""));
                }
                else if (errorCount > 20)
                {
                    result.Findings.Add(Finding.Warning(
                        $"High System Error Rate — {errorCount} Errors in 24h",
                        description,
                        Category,
                        "Investigate recurring error sources. High error rates may indicate driver issues, hardware failure, or misconfigurations."));
                }
                else
                {
                    result.Findings.Add(Finding.Info(
                        $"System Errors — {errorCount} in 24h",
                        description,
                        Category,
                        "Review error sources if any seem unusual. A small number of errors is common."));
                }
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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
            const long recommendedSize = 128L * 1024 * 1024; // 128 MB
            const long minimumSize = 64L * 1024 * 1024; // 64 MB

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
                        var sizeMatch = Regex.Match(psOutput, @"MaximumSizeInBytes\s*:\s*(\d+)");
                        if (sizeMatch.Success)
                            logSizeBytes = int.Parse(sizeMatch.Groups[1].Value);

                        var modeMatch = Regex.Match(psOutput, @"LogMode\s*:\s*(\w+)");
                        if (modeMatch.Success)
                        {
                            var mode = modeMatch.Groups[1].Value;
                            if (mode.Equals("Retain", StringComparison.OrdinalIgnoreCase))
                                retention = -1;
                            else if (mode.Equals("Circular", StringComparison.OrdinalIgnoreCase))
                                retention = 0;
                        }
                    }
                }
                catch { }
            }

            long maxSizeBytes = logSizeBytes > 0 ? logSizeBytes : 20L * 1024 * 1024; // Default is usually 20 MB
            double maxSizeMB = maxSizeBytes / (1024.0 * 1024.0);

            // Check overwrite mode
            string overwriteMode = retention switch
            {
                0 => "Overwrite as needed (default)",
                -1 => "Do not overwrite (archive/manual clear)",
                _ => $"Overwrite events older than {retention} days"
            };

            if (maxSizeBytes < minimumSize)
            {
                result.Findings.Add(Finding.Critical(
                    $"Security Log Too Small — {maxSizeMB:F0} MB",
                    $"The Security event log maximum size is only {maxSizeMB:F0} MB. Recommended minimum is 128 MB. Small log sizes cause events to be overwritten quickly, potentially destroying forensic evidence. Overwrite mode: {overwriteMode}.",
                    Category,
                    "Increase Security log size to at least 128 MB: Event Viewer → Windows Logs → Security → Properties → Maximum log size.",
                    $"powershell -Command \"wevtutil sl Security /ms:{recommendedSize}\""));
            }
            else if (maxSizeBytes < recommendedSize)
            {
                result.Findings.Add(Finding.Warning(
                    $"Security Log Size — {maxSizeMB:F0} MB",
                    $"The Security event log is {maxSizeMB:F0} MB. Recommended size is >= 128 MB for adequate forensic retention. Overwrite mode: {overwriteMode}.",
                    Category,
                    "Increase Security log size to 128 MB or more.",
                    $"powershell -Command \"wevtutil sl Security /ms:{recommendedSize}\""));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    $"Security Log Size — {maxSizeMB:F0} MB",
                    $"The Security event log is adequately sized at {maxSizeMB:F0} MB (recommended >= 128 MB). Overwrite mode: {overwriteMode}.",
                    Category));
            }

            // Warn if set to "do not overwrite" — can cause event loss if log fills up
            if (retention == -1)
            {
                result.Findings.Add(Finding.Warning(
                    "Security Log — Do Not Overwrite Mode",
                    "The Security event log is configured to NOT overwrite events. When the log fills up, new events will be silently dropped. This can cause a denial-of-logging attack.",
                    Category,
                    "Change to 'Overwrite as needed' or implement automated log archiving to prevent event loss.",
                    "powershell -Command \"wevtutil sl Security /rt:false\""));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
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
                result.Findings.Add(Finding.Info(
                    "Log Cleared Check — Access Denied",
                    "Could not check for log-cleared events. Administrator privileges required.",
                    Category,
                    "Run WinSentinel as Administrator."));
                return;
            }

            if (events.Count == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "No Audit Log Clears",
                    "No audit log clear events (Event ID 1102) detected in the last 30 days. Log integrity appears intact.",
                    Category));
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

                result.Findings.Add(Finding.Critical(
                    $"Audit Log Cleared — {events.Count} Time(s)",
                    $"The Security audit log was cleared {events.Count} time(s) in the last 30 days. This destroys forensic evidence and may indicate an attacker covering their tracks.\n\nClear events:\n{string.Join("\n", clearDetails)}",
                    Category,
                    "Investigate who cleared the logs and why. Implement log forwarding to a SIEM or remote log collector to prevent evidence destruction. Consider restricting 'Manage auditing and security log' privilege."));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "Log Cleared Check Error",
                $"Could not check for log-cleared events: {ex.Message}",
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

    /// <summary>
    /// Convert a DateTime to the XPath SystemTime XML format for event log queries.
    /// </summary>
    private static string ToSystemTimeXml(DateTime utcTime)
    {
        return utcTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
    }

    #endregion
}
