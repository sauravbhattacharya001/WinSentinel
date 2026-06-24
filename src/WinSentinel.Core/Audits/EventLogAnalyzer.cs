using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="EventLogAudit"/> module.
///
/// Everything here is deterministic and side-effect free (no Event Log reader,
/// no <c>auditpol</c>, no registry, no clock, no <c>Console</c>) so the actual
/// security decisions — brute-force thresholds, audit-policy gap detection,
/// suspicious-PowerShell matching, log-tamper detection, and Security-log sizing
/// — can be unit tested. The audit module owns the Windows Event Log / shell /
/// registry collection and delegates every classification to this analyzer.
///
/// Mirrors the structure of <see cref="ProcessLineageAnalyzer"/>.
/// </summary>
public static class EventLogAnalyzer
{
    /// <summary>Category label shared with <see cref="EventLogAudit"/>.</summary>
    public const string Category = "Event Logs";

    // ──────────────────────────────────────────────────────────────────────
    // Thresholds (kept here so they're documented + testable in one place)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Failed-login count above which the finding is Critical (likely brute force).</summary>
    public const int FailedLoginCriticalThreshold = 20;

    /// <summary>Failed-login count above which the finding is a Warning.</summary>
    public const int FailedLoginWarningThreshold = 5;

    /// <summary>Account-lockout count above which the finding is a Warning.</summary>
    public const int AccountLockoutWarningThreshold = 5;

    /// <summary>New-service-install count above which the finding is a Warning.</summary>
    public const int ServiceInstallWarningThreshold = 5;

    /// <summary>Distinct non-system privileged users above which privilege activity is unusual.</summary>
    public const int PrivilegedUserWarningThreshold = 10;

    /// <summary>Privileged service-call (4673) count above which privilege activity is unusual.</summary>
    public const int PrivilegedServiceCallWarningThreshold = 50;

    /// <summary>System error count (24h) above which a high-error-rate warning fires.</summary>
    public const int SystemErrorWarningThreshold = 20;

    /// <summary>Suspicious-PowerShell event count above which the finding is Critical.</summary>
    public const int SuspiciousPowerShellCriticalThreshold = 5;

    /// <summary>Recommended Security log size (128 MB).</summary>
    public const long SecurityLogRecommendedBytes = 128L * 1024 * 1024;

    /// <summary>Minimum acceptable Security log size (64 MB); below this is Critical.</summary>
    public const long SecurityLogMinimumBytes = 64L * 1024 * 1024;

    /// <summary>Default Security log size assumed when none is configured (20 MB).</summary>
    public const long SecurityLogDefaultBytes = 20L * 1024 * 1024;

    /// <summary>
    /// Suspicious PowerShell patterns (case-insensitive). Shared with <see cref="EventLogAudit"/>
    /// so the live module and the unit tests evaluate exactly the same regex.
    /// </summary>
    public static readonly Regex SuspiciousPowerShellPattern = new(
        @"(?i)(Invoke-Expression|IEX\s*\(|Invoke-WebRequest|DownloadString|DownloadFile|" +
        @"Net\.WebClient|Start-BitsTransfer|Invoke-Mimikatz|Invoke-Shellcode|" +
        @"-enc\s|EncodedCommand|FromBase64String|" +
        // -ExecutionPolicy Bypass / -ep:bypass / -exec bypass and -WindowStyle Hidden /
        // -w hidden are the malware launch flags we care about. Match them only in that
        // switch context ([-/] prefix + the ExecutionPolicy/WindowStyle switch), NOT as bare
        // substrings: a script that merely contains the words "bypass" or "hidden" (a comment,
        // a path, or the legitimate `Get-ChildItem -Hidden` switch) is not suspicious and was
        // previously a guaranteed false positive.
        @"[-/](?:ep|exec\w*)\b\s*:?\s*bypass|[-/](?:w|win\w*)\b\s*:?\s*hidden|" +
        @"Add-MpPreference\s+-ExclusionPath|Set-MpPreference\s+-DisableRealtimeMonitoring|" +
        @"New-Object\s+System\.Net\.Sockets\.TCPClient|Invoke-Command\s+-ComputerName)",
        RegexOptions.Compiled);

    /// <summary>
    /// Well-known system accounts that normally hold elevated privileges and should
    /// not count toward the "non-system privileged user" tally for 4672/4673.
    /// </summary>
    public static readonly IReadOnlySet<string> SystemAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "DWM-3",
        "UMFD-0", "UMFD-1", "UMFD-2", "UMFD-3",
        "ANONYMOUS LOGON", "Window Manager"
    };

    /// <summary>
    /// Key audit subcategories that should be enabled, mapped to their parent category.
    /// A "No Auditing" line for any of these is reported as a gap.
    /// </summary>
    public static readonly IReadOnlyList<KeyValuePair<string, string>> RequiredAuditPolicies = new List<KeyValuePair<string, string>>
    {
        new("Logon", "Logon/Logoff"),
        new("Logoff", "Logon/Logoff"),
        new("Account Lockout", "Logon/Logoff"),
        new("Special Logon", "Logon/Logoff"),
        new("File System", "Object Access"),
        new("Registry", "Object Access"),
        new("Sensitive Privilege Use", "Privilege Use"),
        new("Authentication Policy Change", "Policy Change"),
        new("Audit Policy Change", "Policy Change"),
        new("User Account Management", "Account Management"),
        new("Security Group Management", "Account Management"),
        new("Computer Account Management", "Account Management"),
    };

    // ──────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>True when the account is a well-known system/machine account (machine = ends with '$').</summary>
    public static bool IsSystemAccount(string? account)
    {
        if (string.IsNullOrWhiteSpace(account)) return true;
        if (SystemAccounts.Contains(account)) return true;
        return account.EndsWith("$", StringComparison.Ordinal);
    }

    /// <summary>True when the username is a real, attributable account ("-" / blank are skipped).</summary>
    public static bool IsMeaningfulUser(string? user)
        => !string.IsNullOrWhiteSpace(user) && user != "-";

    /// <summary>
    /// True when an IPv4/IPv6 source address is "real" — i.e. not blank, "-", or loopback.
    /// Loopback failed logons are noise from local services and are excluded from source-IP tallies.
    /// </summary>
    public static bool IsMeaningfulSourceIp(string? ip)
        => !string.IsNullOrWhiteSpace(ip) && ip != "-" && ip != "::1" && ip != "127.0.0.1";

    /// <summary>Truncate a string to <paramref name="maxLength"/>, appending an ellipsis when cut.</summary>
    public static string Truncate(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return value ?? string.Empty;
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }

    /// <summary>True when a script-block body matches a known suspicious PowerShell pattern.</summary>
    public static bool IsSuspiciousPowerShell(string? scriptBlock)
        => !string.IsNullOrWhiteSpace(scriptBlock) && SuspiciousPowerShellPattern.IsMatch(scriptBlock);

    /// <summary>
    /// Rank a name→count tally into the top <paramref name="take"/> "name (Nx)" fragments,
    /// ordered by descending count. Used for top targeted users / source IPs / lockout accounts.
    ///
    /// Ties are broken by ascending key (ordinal) so the output is fully deterministic.
    /// A bare <c>OrderByDescending(kv =&gt; kv.Value)</c> is a <em>stable</em> sort, but the
    /// input is an <see cref="IReadOnlyDictionary{TKey,TValue}"/> whose enumeration order is
    /// not defined — it depends on insertion order, hash-bucket layout and any prior removals.
    /// Without a secondary key, two scans of <em>identical</em> event data could surface a
    /// different set of equally-frequent users/IPs at the <paramref name="take"/> cut-off (or
    /// the same set in a different order), producing phantom diffs in score history /
    /// <c>winsentinel diff</c>. The ordinal key tie-break removes that non-determinism.
    /// </summary>
    public static IReadOnlyList<string> RankTopCounts(IReadOnlyDictionary<string, int> counts, int take = 5)
    {
        if (counts is null || counts.Count == 0) return Array.Empty<string>();
        return counts.OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.Ordinal)
            .Take(take)
            .Select(kv => $"{kv.Key} ({kv.Value}x)")
            .ToList();
    }

    // ──────────────────────────────────────────────────────────────────────
    // Failed logins (Event ID 4625)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Classify a failed-login tally into a Finding. <paramref name="topUsers"/> /
    /// <paramref name="topSourceIps"/> are pre-ranked "name (Nx)" fragments (caller controls ranking).
    /// &gt;20 → Critical, &gt;5 → Warning, 1–5 → Info, 0 → Pass.
    /// </summary>
    public static Finding BuildFailedLoginFinding(int count,
        IReadOnlyList<string>? topUsers = null, IReadOnlyList<string>? topSourceIps = null)
    {
        if (count <= 0)
        {
            return Finding.Pass(
                "No Failed Login Attempts",
                "No failed login attempts (Event ID 4625) detected in the last 24 hours.",
                Category);
        }

        var details = new List<string> { $"Total failed logins: {count}" };
        if (topUsers is { Count: > 0 })
            details.Add($"Targeted accounts: {string.Join(", ", topUsers)}");
        if (topSourceIps is { Count: > 0 })
            details.Add($"Source IPs: {string.Join(", ", topSourceIps)}");
        var description = string.Join(". ", details) + ".";

        if (count > FailedLoginCriticalThreshold)
        {
            return Finding.Critical(
                $"High Failed Login Rate — {count} in 24h",
                $"{description} This may indicate a brute-force attack or credential stuffing attempt.",
                Category,
                "Investigate the source IPs. Consider enabling account lockout policies, IP blocking, or MFA. Check if any accounts were compromised.",
                "powershell -Command \"auditpol /set /subcategory:'Logon' /failure:enable\"");
        }

        if (count > FailedLoginWarningThreshold)
        {
            return Finding.Warning(
                $"Failed Login Attempts — {count} in 24h",
                $"{description} Multiple failed login attempts detected — monitor for patterns.",
                Category,
                "Review the failed login sources. Ensure account lockout policies are configured. Consider enabling MFA.");
        }

        return Finding.Info(
            $"Failed Login Attempts — {count} in 24h",
            $"{description} A small number of failed logins is normal (mistyped passwords, etc.).",
            Category);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Account lockouts (Event ID 4740)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Classify account-lockout events. &gt;5 → Warning, 1–5 → Info, 0 → Pass.
    /// <paramref name="topAccounts"/> are pre-ranked "name (Nx)" fragments.
    /// </summary>
    public static Finding BuildAccountLockoutFinding(int count, IReadOnlyList<string>? topAccounts = null)
    {
        if (count <= 0)
        {
            return Finding.Pass(
                "No Account Lockouts",
                "No account lockout events (Event ID 4740) in the last 7 days.",
                Category);
        }

        var accountsList = topAccounts is { Count: > 0 } ? string.Join(", ", topAccounts) : "unknown";

        return count > AccountLockoutWarningThreshold
            ? Finding.Warning(
                $"Account Lockouts — {count} in 7 Days",
                $"Detected {count} account lockout event(s). Affected accounts: {accountsList}. Frequent lockouts may indicate brute-force attacks.",
                Category,
                "Investigate whether lockouts are from legitimate users mistyping passwords or from an attacker. Review account lockout policies.")
            : Finding.Info(
                $"Account Lockouts — {count} in 7 Days",
                $"Detected {count} account lockout event(s). Affected accounts: {accountsList}. Occasional lockouts are normal.",
                Category);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Privilege escalation (Event IDs 4672, 4673)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Classify privilege-use volume. Unusual when distinct non-system privileged users &gt; 10
    /// OR privileged service calls (4673) &gt; 50. Zero events → Info (audit policy may be off).
    /// </summary>
    public static Finding BuildPrivilegeEscalationFinding(int event4672Count, int event4673Count,
        IReadOnlyList<string>? topPrivilegedUsers = null, int distinctPrivilegedUsers = 0)
    {
        int total = event4672Count + event4673Count;

        if (total == 0)
        {
            return Finding.Info(
                "No Privilege Escalation Events",
                "No privilege escalation events (4672/4673) detected in the last 24 hours. Note: this may mean audit policies are not enabled for privilege use.",
                Category,
                "Enable 'Privilege Use' auditing: auditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable /failure:enable");
        }

        var details = $"Detected {event4672Count} special privilege logon(s) and {event4673Count} privileged service call(s) in 24h.";
        if (topPrivilegedUsers is { Count: > 0 })
            details += $" Non-system users with elevated privileges: {string.Join(", ", topPrivilegedUsers)}.";

        if (distinctPrivilegedUsers > PrivilegedUserWarningThreshold || event4673Count > PrivilegedServiceCallWarningThreshold)
        {
            return Finding.Warning(
                "Unusual Privilege Activity",
                details + " High volume of privilege usage from non-system accounts may indicate compromise or misconfiguration.",
                Category,
                "Review which accounts are being granted elevated privileges. Verify that only authorized administrators have these permissions.");
        }

        return Finding.Pass(
            "Privilege Escalation Events — Normal",
            details + " Volume appears normal for this system.",
            Category);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Audit policy gaps (auditpol /get /category:*)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Result of parsing <c>auditpol</c> output against <see cref="RequiredAuditPolicies"/>.</summary>
    public sealed record AuditPolicyScan(IReadOnlyList<string> Gaps, IReadOnlyList<string> Enabled);

    /// <summary>
    /// Parse <c>auditpol /get /category:*</c> output, classifying each required subcategory as a
    /// gap ("No Auditing") or enabled. Subcategories not present in the output are skipped.
    /// Returns <c>null</c> when the output is empty or access was denied — the audit treats that
    /// as an "Access Denied" Info finding instead of a real result.
    /// </summary>
    public static AuditPolicyScan? ParseAuditPolicy(string? auditpolOutput)
    {
        if (string.IsNullOrWhiteSpace(auditpolOutput)) return null;
        if (auditpolOutput.Contains("Access is denied", StringComparison.OrdinalIgnoreCase)) return null;

        var lines = auditpolOutput.Split('\n', StringSplitOptions.TrimEntries);
        var gaps = new List<string>();
        var enabled = new List<string>();

        foreach (var kvp in RequiredAuditPolicies)
        {
            var subcategory = kvp.Key;
            var parentCategory = kvp.Value;

            // Match the subcategory as a leading token on the (already TrimEntries'd)
            // line, NOT a free substring anywhere on it. A loose Contains lets the
            // shorter "Logon" subcategory match a "Special Logon" line (substring
            // collision), which — depending on auditpol output ordering — misreports
            // "Logon" using "Special Logon"'s setting (e.g. a false gap, or a duplicate
            // when both share the same wording). Anchoring to the start with a
            // whitespace/end boundary keeps each required subcategory bound to its
            // own line. Category headers are still excluded.
            var line = lines.FirstOrDefault(l =>
                LineStartsWithSubcategory(l, subcategory) &&
                !l.StartsWith("Category", StringComparison.OrdinalIgnoreCase));

            if (line == null) continue;

            if (line.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
                gaps.Add($"{subcategory} ({parentCategory})");
            else
                enabled.Add(subcategory);
        }

        return new AuditPolicyScan(gaps, enabled);
    }

    /// <summary>
    /// True when a (whitespace-trimmed) auditpol line names exactly
    /// <paramref name="subcategory"/> as its leading subcategory token — i.e. the
    /// line starts with the name and the name is bounded by whitespace or end of
    /// line. This avoids the substring collision where "Logon" would otherwise
    /// match a "Special Logon" line. Case-insensitive; the line is expected to be
    /// pre-trimmed (the caller splits with <see cref="StringSplitOptions.TrimEntries"/>).
    /// </summary>
    internal static bool LineStartsWithSubcategory(string? line, string subcategory)
    {
        if (string.IsNullOrEmpty(line) || string.IsNullOrEmpty(subcategory)) return false;
        if (!line.StartsWith(subcategory, StringComparison.OrdinalIgnoreCase)) return false;
        // Exact length → whole line is the name; otherwise the next char must be a
        // separator (auditpol pads subcategory → setting with spaces/tabs), so
        // "Logon" does not match "Logon/Logoff" or a longer name either.
        if (line.Length == subcategory.Length) return true;
        return char.IsWhiteSpace(line[subcategory.Length]);
    }

    /// <summary>
    /// Classify an audit-policy scan. 0 gaps → Pass, 1–3 → Warning, &gt;3 → Critical.
    /// The Warning fix command rebuilds <c>auditpol</c> set lines from the gap names.
    /// </summary>
    public static Finding BuildAuditPolicyFinding(AuditPolicyScan scan)
    {
        var gaps = scan.Gaps;
        var enabled = scan.Enabled;

        if (gaps.Count == 0)
        {
            return Finding.Pass(
                "Audit Policies Configured",
                $"All key audit policies are enabled ({enabled.Count} subcategories checked). Security events are being logged for logon/logoff, object access, privilege use, policy changes, and account management.",
                Category);
        }

        if (gaps.Count <= 3)
        {
            var fix = "powershell -Command \"" + string.Join("; ", gaps.Select(g =>
                $"auditpol /set /subcategory:\\\"{g.Split('(')[0].Trim()}\\\" /success:enable /failure:enable")) + "\"";
            return Finding.Warning(
                $"Audit Policy Gaps — {gaps.Count} Missing",
                $"Some audit policies are not enabled: {string.Join(", ", gaps)}. Missing audit policies create blind spots where malicious activity goes unrecorded.",
                Category,
                "Enable missing audit policies using: auditpol /set /subcategory:\"<name>\" /success:enable /failure:enable",
                fix);
        }

        return Finding.Critical(
            $"Major Audit Policy Gaps — {gaps.Count} Missing",
            $"Many critical audit policies are disabled: {string.Join(", ", gaps.Take(8))}. The system is not recording important security events, making incident investigation extremely difficult.",
            Category,
            "Enable comprehensive audit policies immediately. Use: auditpol /set /category:* /success:enable /failure:enable — or apply a security baseline via Group Policy.",
            "powershell -Command \"auditpol /set /category:* /success:enable /failure:enable\"");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Service installations (Event ID 7045)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Classify new-service-install events. &gt;5 → Warning, 1–5 → Info, 0 → Pass.
    /// <paramref name="serviceLines"/> are pre-formatted "• name — path (date)" fragments.
    /// </summary>
    public static Finding BuildServiceInstallFinding(int count, IReadOnlyList<string>? serviceLines = null)
    {
        if (count <= 0)
        {
            return Finding.Pass(
                "No New Services Installed",
                "No new service installations (Event ID 7045) detected in the last 7 days.",
                Category);
        }

        var lines = serviceLines ?? Array.Empty<string>();
        var description = $"{count} new service(s) installed in the last 7 days. Service installations can be used for malware persistence.\n{string.Join("\n", lines.Take(10))}";
        if (count > 10)
            description += $"\n... and {count - 10} more.";

        return count > ServiceInstallWarningThreshold
            ? Finding.Warning(
                $"New Services Installed — {count} in 7 Days",
                description,
                Category,
                "Review installed services to ensure they are legitimate. Malware often persists by installing services. Check service binary paths for suspicious locations (temp folders, AppData, etc.).")
            : Finding.Info(
                $"New Services Installed — {count} in 7 Days",
                description,
                Category,
                "Review installed services to ensure they are expected.");
    }

    // === Suspicious PowerShell (Event ID 4104) ===

    /// <summary>
    /// Build the "Script Block Logging not enabled" warning, shared by the two call sites in the audit.
    /// </summary>
    public static Finding BuildScriptBlockLoggingDisabledFinding()
        => Finding.Warning(
            "PowerShell Script Block Logging Not Enabled",
            "PowerShell Script Block Logging is not enabled. Malicious PowerShell commands will not be recorded in event logs, making it difficult to detect living-off-the-land attacks.",
            Category,
            "Enable Script Block Logging via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging.",
            "powershell -Command \"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord\"");

    /// <summary>
    /// Classify suspicious-PowerShell analysis. &gt;5 =&gt; Critical, 1-5 =&gt; Warning, 0 with events =&gt; Pass.
    /// <paramref name="examples"/> are pre-formatted fragments.
    /// </summary>
    public static Finding BuildSuspiciousPowerShellFinding(int suspiciousCount, int totalEvents,
        IReadOnlyList<string>? examples = null)
    {
        if (suspiciousCount <= 0)
        {
            return Finding.Pass(
                "No Suspicious PowerShell Activity",
                $"Analyzed {totalEvents} PowerShell script block event(s) from the last 7 days. No suspicious patterns (encoded commands, download cradles, bypass techniques) detected.",
                Category);
        }

        var description = $"Detected {suspiciousCount} suspicious PowerShell script block(s) in the last 7 days out of {totalEvents} total. Suspicious patterns include encoded commands, download cradles, and security bypass techniques.";
        if (examples is { Count: > 0 })
            description += "\n\nExamples:\n" + string.Join("\n", examples);

        return suspiciousCount > SuspiciousPowerShellCriticalThreshold
            ? Finding.Critical(
                $"Suspicious PowerShell Activity — {suspiciousCount} Events",
                description,
                Category,
                "Investigate the PowerShell commands immediately. Check which user account ran them. Look for indicators of compromise. Consider blocking PowerShell for non-admin users via AppLocker.")
            : Finding.Warning(
                $"Suspicious PowerShell Activity — {suspiciousCount} Events",
                description,
                Category,
                "Review the flagged PowerShell commands. Some may be legitimate admin scripts, but encoded commands and download cradles are common attack techniques.");
    }

    // === Windows Defender detections (Event IDs 1116, 1117) ===

    /// <summary>
    /// Classify Windows Defender threat detections. Unresolved (detections &gt; actions) =&gt; Critical;
    /// all-remediated =&gt; Warning; none =&gt; Pass.
    /// </summary>
    public static Finding BuildDefenderDetectionFinding(int detections, int actions,
        IReadOnlyList<string>? threatNames = null)
    {
        if (detections <= 0)
        {
            return Finding.Pass(
                "No Defender Threat Detections",
                "Windows Defender has not detected any threats (Event IDs 1116/1117) in the last 7 days.",
                Category);
        }

        var description = $"Windows Defender detected {detections} threat(s) in the last 7 days, with {actions} remediation action(s) taken.";
        if (threatNames is { Count: > 0 })
            description += $" Threats: {string.Join(", ", threatNames)}.";

        if (detections > actions)
        {
            return Finding.Critical(
                $"Defender Threats Detected — {detections} ({detections - actions} Unresolved)",
                description + " Some threats may not have been remediated.",
                Category,
                "Open Windows Security → Virus & threat protection → Protection history. Review and resolve any remaining threats. Run a full system scan.",
                "powershell -Command \"Start-MpScan -ScanType FullScan\"");
        }

        return Finding.Warning(
            $"Defender Threats Detected — {detections} (All Remediated)",
            description + " All detected threats were remediated.",
            Category,
            "Review Windows Security → Protection history to understand what was detected. Consider running a full scan to ensure no threats remain.",
            "powershell -Command \"Start-MpScan -ScanType FullScan\"");
    }

    // === System errors (System log, Level 1/2) ===

    /// <summary>
    /// Classify System-log error volume (24h). Any Critical (Level 1) =&gt; Warning; else &gt;20 errors
    /// =&gt; Warning (high rate); 1-20 =&gt; Info; 0 =&gt; Pass.
    /// </summary>
    public static Finding BuildSystemErrorFinding(int criticalCount, int errorCount,
        IReadOnlyList<string>? topSources = null, IReadOnlyList<string>? samples = null)
    {
        int total = criticalCount + errorCount;

        if (total == 0)
        {
            return Finding.Pass(
                "No System Errors",
                "No critical or error events in the System log in the last 24 hours. System stability appears good.",
                Category);
        }

        var sourcesText = topSources is { Count: > 0 } ? string.Join(", ", topSources) : "various";
        var description = $"Detected {criticalCount} critical and {errorCount} error event(s) in the System log in the last 24 hours. Top sources: {sourcesText}.";
        if (samples is { Count: > 0 })
            description += "\n\nRecent events:\n" + string.Join("\n", samples);

        if (criticalCount > 0)
        {
            return Finding.Warning(
                $"System Critical Errors — {criticalCount} Critical, {errorCount} Errors",
                description,
                Category,
                "Investigate critical events immediately. Check for bugcheck dumps (BSOD), driver failures, or hardware issues. Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth' to repair system files.",
                "powershell -Command \"sfc /scannow\"");
        }

        if (errorCount > SystemErrorWarningThreshold)
        {
            return Finding.Warning(
                $"High System Error Rate — {errorCount} Errors in 24h",
                description,
                Category,
                "Investigate recurring error sources. High error rates may indicate driver issues, hardware failure, or misconfigurations.");
        }

        return Finding.Info(
            $"System Errors — {errorCount} in 24h",
            description,
            Category,
            "Review error sources if any seem unusual. A small number of errors is common.");
    }

    // === Security log size + retention ===

    /// <summary>
    /// Human label for a Security-log retention value:
    /// 0 = overwrite as needed, -1 = do not overwrite (archive/manual), &gt;0 = overwrite older than N days.
    /// </summary>
    public static string DescribeRetentionMode(int retention) => retention switch
    {
        0 => "Overwrite as needed (default)",
        -1 => "Do not overwrite (archive/manual clear)",
        _ => $"Overwrite events older than {retention} days"
    };

    /// <summary>
    /// Classify the Security event-log size. <paramref name="configuredBytes"/> is the raw configured
    /// MaxSize (0 = unknown =&gt; assume 20 MB default). &lt;64 MB =&gt; Critical, &lt;128 MB =&gt; Warning, else Pass.
    /// </summary>
    public static Finding BuildSecurityLogSizeFinding(long configuredBytes, int retention)
    {
        long maxSizeBytes = configuredBytes > 0 ? configuredBytes : SecurityLogDefaultBytes;
        double maxSizeMB = maxSizeBytes / (1024.0 * 1024.0);
        string overwriteMode = DescribeRetentionMode(retention);

        if (maxSizeBytes < SecurityLogMinimumBytes)
        {
            return Finding.Critical(
                $"Security Log Too Small — {maxSizeMB:F0} MB",
                $"The Security event log maximum size is only {maxSizeMB:F0} MB. Recommended minimum is 128 MB. Small log sizes cause events to be overwritten quickly, potentially destroying forensic evidence. Overwrite mode: {overwriteMode}.",
                Category,
                "Increase Security log size to at least 128 MB: Event Viewer → Windows Logs → Security → Properties → Maximum log size.",
                $"powershell -Command \"wevtutil sl Security /ms:{SecurityLogRecommendedBytes}\"");
        }

        if (maxSizeBytes < SecurityLogRecommendedBytes)
        {
            return Finding.Warning(
                $"Security Log Size — {maxSizeMB:F0} MB",
                $"The Security event log is {maxSizeMB:F0} MB. Recommended size is >= 128 MB for adequate forensic retention. Overwrite mode: {overwriteMode}.",
                Category,
                "Increase Security log size to 128 MB or more.",
                $"powershell -Command \"wevtutil sl Security /ms:{SecurityLogRecommendedBytes}\"");
        }

        return Finding.Pass(
            $"Security Log Size — {maxSizeMB:F0} MB",
            $"The Security event log is adequately sized at {maxSizeMB:F0} MB (recommended >= 128 MB). Overwrite mode: {overwriteMode}.",
            Category);
    }

    /// <summary>
    /// Build the "do not overwrite" denial-of-logging warning when retention == -1, else <c>null</c>.
    /// </summary>
    public static Finding? BuildDoNotOverwriteFinding(int retention)
    {
        if (retention != -1) return null;
        return Finding.Warning(
            "Security Log — Do Not Overwrite Mode",
            "The Security event log is configured to NOT overwrite events. When the log fills up, new events will be silently dropped. This can cause a denial-of-logging attack.",
            Category,
            "Change to 'Overwrite as needed' or implement automated log archiving to prevent event loss.",
            "powershell -Command \"wevtutil sl Security /rt:false\"");
    }

    /// <summary>
    /// Extract <c>MaximumSizeInBytes</c> from <c>Get-WinEvent -ListLog</c> output (a <c>Format-List</c>
    /// block of <c>Property : Value</c> lines). Returns 0 when not found.
    /// </summary>
    /// <remarks>
    /// The property name is anchored to the start of a line (after optional indentation) with a
    /// trailing word boundary, so a longer-named property that merely <em>ends with</em>
    /// <c>MaximumSizeInBytes</c> (e.g. a hypothetical <c>OwningProviderMaximumSizeInBytes</c>), or the
    /// literal substring appearing inside another property's <em>value</em>, cannot be mistaken for the
    /// real <c>MaximumSizeInBytes</c> line and bind a bogus size. Without the anchor the unbounded
    /// match grabbed whichever <c>...MaximumSizeInBytes : N</c> appeared first, which could be the wrong
    /// value entirely (same substring-collision class as <c>ParseAuditPolicy</c>).
    /// </remarks>
    public static long ParseMaxSizeFromPowerShell(string? psOutput)
    {
        if (string.IsNullOrWhiteSpace(psOutput)) return 0;
        // ^...\b in multiline mode: the token must be a whole property name at line start, not a suffix.
        var m = Regex.Match(psOutput, @"^\s*MaximumSizeInBytes\b\s*:\s*(\d+)", RegexOptions.Multiline);
        return m.Success && long.TryParse(m.Groups[1].Value, out var bytes) ? bytes : 0;
    }

    /// <summary>
    /// Map a <c>LogMode</c> string to a retention sentinel. <c>LogMode</c> comes from
    /// <see cref="!:System.Diagnostics.Eventing.Reader.EventLogMode"/>, whose only three
    /// members are <c>Circular</c>, <c>Retain</c>, and <c>AutoBackup</c>:
    /// <list type="bullet">
    ///   <item><c>Circular</c> — overwrite the oldest events when full =&gt; <c>0</c> (overwrite as needed).</item>
    ///   <item><c>Retain</c> — keep all events, stop logging when full =&gt; <c>-1</c> (do not overwrite).</item>
    ///   <item><c>AutoBackup</c> — archive the log when full and start a fresh one; events are
    ///         <em>never overwritten</em> =&gt; <c>-1</c> (do not overwrite / archive). This is the
    ///         "Archive the log when full" radio button in Event Viewer's log properties.</item>
    /// </list>
    /// Both <c>Retain</c> and <c>AutoBackup</c> mean the log will not overwrite events, so both map
    /// to <c>-1</c> — that is what trips the denial-of-logging warning and the
    /// "do not overwrite" retention label. Anything unrecognised returns the <paramref name="fallback"/>.
    /// </summary>
    public static int ParseRetentionFromLogMode(string? psOutput, int fallback = 0)
    {
        if (string.IsNullOrWhiteSpace(psOutput)) return fallback;
        var m = Regex.Match(psOutput, @"LogMode\s*:\s*(\w+)");
        if (!m.Success) return fallback;
        var mode = m.Groups[1].Value;
        // Retain and AutoBackup both stop the log from overwriting events (archive vs. block),
        // so both surface as -1 "do not overwrite"; Circular is the normal overwrite-as-needed mode.
        if (mode.Equals("Retain", StringComparison.OrdinalIgnoreCase)) return -1;
        if (mode.Equals("AutoBackup", StringComparison.OrdinalIgnoreCase)) return -1;
        if (mode.Equals("Circular", StringComparison.OrdinalIgnoreCase)) return 0;
        return fallback;
    }

    // === Audit log cleared (Event ID 1102) ===

    /// <summary>
    /// Classify audit-log-cleared events. Any clear =&gt; Critical (evidence destruction); 0 =&gt; Pass.
    /// <paramref name="clearLines"/> are pre-formatted "who/when" fragments.
    /// </summary>
    public static Finding BuildLogClearedFinding(int count, IReadOnlyList<string>? clearLines = null)
    {
        if (count <= 0)
        {
            return Finding.Pass(
                "No Audit Log Clears",
                "No audit log clear events (Event ID 1102) detected in the last 30 days. Log integrity appears intact.",
                Category);
        }

        var lines = clearLines is { Count: > 0 } ? string.Join("\n", clearLines) : "(details unavailable)";
        return Finding.Critical(
            $"Audit Log Cleared — {count} Time(s)",
            $"The Security audit log was cleared {count} time(s) in the last 30 days. This destroys forensic evidence and may indicate an attacker covering their tracks.\n\nClear events:\n{lines}",
            Category,
            "Investigate who cleared the logs and why. Implement log forwarding to a SIEM or remote log collector to prevent evidence destruction. Consider restricting 'Manage auditing and security log' privilege.");
    }
}
