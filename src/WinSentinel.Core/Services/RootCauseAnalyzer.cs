using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Clusters findings by inferred root cause so users can fix one underlying
/// issue and resolve multiple findings at once.
/// </summary>
public class RootCauseAnalyzer
{
    /// <summary>A root-cause cluster grouping related findings.</summary>
    public record RootCause(
        string Id,
        string Name,
        string Description,
        string Category,
        List<Finding> Findings,
        Severity WorstSeverity,
        string SuggestedFix,
        string? FixCommand
    )
    {
        /// <summary>Number of findings this root cause accounts for.</summary>
        public int ImpactCount => Findings.Count;

        /// <summary>Weighted impact score (critical=20, warning=5, info=1).</summary>
        public int ImpactScore => Findings.Sum(f => f.Severity switch
        {
            Severity.Critical => 20,
            Severity.Warning => 5,
            Severity.Info => 1,
            _ => 0
        });
    }

    /// <summary>Full root-cause analysis report.</summary>
    public record RootCauseReport(
        int TotalFindings,
        int RootCausesIdentified,
        int FindingsCovered,
        int UngroupedFindings,
        List<RootCause> RootCauses,
        List<Finding> Ungrouped,
        List<string> TopActions
    )
    {
        /// <summary>Percentage of findings covered by root causes.</summary>
        public double CoveragePercent => TotalFindings == 0
            ? 100.0
            : Math.Round(100.0 * FindingsCovered / TotalFindings, 1);
    }

    /// <summary>A pattern rule that maps findings to a root cause.</summary>
    public record CausePattern(
        string CauseId,
        string CauseName,
        string Description,
        string Category,
        string[] TitlePatterns,
        string SuggestedFix,
        string? FixCommand = null
    );

    private readonly List<CausePattern> _patterns = new();

    public RootCauseAnalyzer()
    {
        RegisterBuiltInPatterns();
    }

    /// <summary>Register a custom cause pattern.</summary>
    public void AddPattern(CausePattern pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        _patterns.Add(pattern);
    }

    /// <summary>Get all registered patterns.</summary>
    public IReadOnlyList<CausePattern> Patterns => _patterns.AsReadOnly();

    /// <summary>Analyze a security report for root causes.</summary>
    public RootCauseReport Analyze(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity > Severity.Pass)
            .ToList();

        var assigned = new HashSet<Finding>(ReferenceEqualityComparer.Instance);
        var rootCauses = new List<RootCause>();

        foreach (var pattern in _patterns)
        {
            var matched = allFindings
                .Where(f => !assigned.Contains(f))
                .Where(f => pattern.TitlePatterns.Any(p =>
                    f.Title.Contains(p, StringComparison.OrdinalIgnoreCase) ||
                    f.Description.Contains(p, StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (matched.Count < 2) continue; // need 2+ findings to form a cluster

            var worst = matched.Max(f => f.Severity);
            var cause = new RootCause(
                pattern.CauseId,
                pattern.CauseName,
                pattern.Description,
                pattern.Category,
                matched,
                worst,
                pattern.SuggestedFix,
                pattern.FixCommand
            );

            rootCauses.Add(cause);
            foreach (var f in matched) assigned.Add(f);
        }

        // Sort by impact score descending
        rootCauses.Sort((a, b) => b.ImpactScore.CompareTo(a.ImpactScore));

        var ungrouped = allFindings.Where(f => !assigned.Contains(f)).ToList();

        var topActions = rootCauses
            .Take(5)
            .Select(rc => $"[{rc.WorstSeverity}] {rc.Name}: {rc.SuggestedFix} (resolves {rc.ImpactCount} findings)")
            .ToList();

        return new RootCauseReport(
            TotalFindings: allFindings.Count,
            RootCausesIdentified: rootCauses.Count,
            FindingsCovered: assigned.Count,
            UngroupedFindings: ungrouped.Count,
            RootCauses: rootCauses,
            Ungrouped: ungrouped,
            TopActions: topActions
        );
    }

    /// <summary>Analyze a list of audit results directly.</summary>
    public RootCauseReport Analyze(IEnumerable<AuditResult> results)
    {
        var report = new SecurityReport { Results = results.ToList() };
        return Analyze(report);
    }

    private void RegisterBuiltInPatterns()
    {
        _patterns.AddRange(new[]
        {
            new CausePattern(
                "RC-UPDATE", "Windows Update Disabled",
                "Multiple findings stem from Windows Update being disabled or misconfigured",
                "System",
                new[] { "update", "patch", "outdated", "end of life", "unsupported version", "KB" },
                "Enable Windows Update and install all pending patches",
                "Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv; Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install -AcceptAll"
            ),
            new CausePattern(
                "RC-FIREWALL", "Firewall Misconfiguration",
                "Multiple findings relate to Windows Firewall rules or configuration",
                "Network",
                new[] { "firewall", "inbound rule", "outbound rule", "open port", "exposed port" },
                "Review and tighten Windows Firewall rules; block unnecessary inbound connections",
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
            ),
            new CausePattern(
                "RC-DEFENDER", "Windows Defender Gaps",
                "Multiple findings indicate Windows Defender is not fully configured",
                "Antivirus",
                new[] { "defender", "real-time protection", "virus definition", "antivirus", "malware", "tamper protection" },
                "Enable all Windows Defender protection features and update definitions",
                "Set-MpPreference -DisableRealtimeMonitoring $false; Update-MpSignature"
            ),
            new CausePattern(
                "RC-ENCRYPTION", "Encryption Not Enabled",
                "Multiple findings stem from lack of disk or data encryption",
                "Encryption",
                new[] { "bitlocker", "encryption", "encrypted", "unencrypted", "plain text" },
                "Enable BitLocker on all drives and enforce encryption policies",
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly"
            ),
            new CausePattern(
                "RC-ACCOUNT", "Weak Account Policies",
                "Multiple findings point to weak user account or password policies",
                "Account",
                new[] { "password", "account lockout", "guest account", "admin account", "privilege", "UAC", "user account control" },
                "Enforce strong password policies, disable guest accounts, configure UAC",
                null
            ),
            new CausePattern(
                "RC-REMOTE", "Unnecessary Remote Access",
                "Multiple findings indicate remote access services are unnecessarily enabled",
                "Remote Access",
                new[] { "remote desktop", "RDP", "SSH", "WinRM", "remote management", "remote access", "telnet" },
                "Disable unused remote access services; restrict RDP to VPN-only access",
                null
            ),
            new CausePattern(
                "RC-PRIVACY", "Privacy Settings Weak",
                "Multiple findings relate to Windows telemetry and privacy settings",
                "Privacy",
                new[] { "telemetry", "privacy", "tracking", "diagnostic data", "advertising", "location services" },
                "Configure Windows privacy settings to minimize data collection",
                null
            ),
            new CausePattern(
                "RC-NETWORK", "Insecure Network Configuration",
                "Multiple findings stem from insecure network protocol or sharing settings",
                "Network",
                new[] { "SMB", "NetBIOS", "LLMNR", "mDNS", "network share", "open share", "anonymous" },
                "Disable legacy network protocols (SMBv1, NetBIOS, LLMNR) and restrict shares",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
            ),
            new CausePattern(
                "RC-AUDIT-LOG", "Insufficient Audit Logging",
                "Multiple findings indicate audit and event logging is incomplete",
                "Logging",
                new[] { "audit policy", "event log", "logging", "log size", "log retention", "security log" },
                "Enable comprehensive audit policies and increase log retention sizes",
                null
            ),
            new CausePattern(
                "RC-BROWSER", "Browser Security Gaps",
                "Multiple findings relate to web browser security configuration",
                "Browser",
                new[] { "browser", "extension", "chrome", "edge", "firefox", "password manager" },
                "Review browser extensions, enable built-in security features, use a password manager",
                null
            ),
            new CausePattern(
                "RC-SERVICE", "Unnecessary Services Running",
                "Multiple findings indicate unnecessary or risky Windows services are enabled",
                "Services",
                new[] { "service", "startup", "auto-start", "unnecessary service", "running service" },
                "Disable unnecessary services to reduce attack surface",
                null
            ),
            new CausePattern(
                "RC-CERT", "Certificate Issues",
                "Multiple findings relate to certificate validation or expiration",
                "Certificates",
                new[] { "certificate", "cert", "expired", "self-signed", "root CA", "trust" },
                "Review certificate store, remove expired/untrusted certificates",
                null
            ),
            new CausePattern(
                "RC-WIFI", "Wi-Fi Security Weak",
                "Multiple findings relate to wireless network security",
                "Wi-Fi",
                new[] { "Wi-Fi", "WiFi", "wireless", "WPA", "WEP", "open network", "saved network" },
                "Use WPA3/WPA2-Enterprise, remove saved open networks, disable auto-connect",
                null
            ),
            new CausePattern(
                "RC-BACKUP", "No Backup Strategy",
                "Multiple findings indicate lack of backup or recovery capability",
                "Backup",
                new[] { "backup", "restore point", "system restore", "recovery", "shadow copy" },
                "Configure regular backups and verify restore capability",
                null
            ),
        });
    }
}
