using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="ProcessLineageAudit"/> module.
/// Parses raw <c>Win32_Process</c> pipe-delimited output and turns it into
/// matched lineage records, orphan/deep-nesting records, and the corresponding
/// <see cref="Finding"/> objects.
///
/// Everything here is deterministic and side-effect free (no shell, no WMI, no
/// clock, no <c>Console</c>) so the suspicious-lineage detection — the actual
/// security value of the module — can be unit tested. The audit module itself
/// only owns the PowerShell/WMI collection and delegates all decisions here.
/// </summary>
public static class ProcessLineageAnalyzer
{
    /// <summary>Category label shared with <see cref="ProcessLineageAudit"/>.</summary>
    public const string Category = "Processes";

    /// <summary>
    /// Rules defining suspicious parent → child process spawning patterns.
    /// Each rule has a parent pattern, child pattern, severity, and explanation.
    /// </summary>
    public static readonly IReadOnlyList<LineageRule> Rules = new List<LineageRule>
    {
        // Office apps spawning command interpreters
        new("winword|excel|powerpnt|outlook|msaccess|mspub|onenote", "cmd|powershell|pwsh|wscript|cscript|mshta", Severity.Critical,
            "Office Application Spawning Script Engine",
            "Office applications should not spawn command interpreters. This is a classic indicator of macro-based malware or phishing payload execution.",
            "MITRE ATT&CK T1204.002 (User Execution: Malicious File)"),

        // Browsers spawning command interpreters
        new("chrome|msedge|firefox|iexplore|brave", "cmd|powershell|pwsh|wscript|cscript|mshta", Severity.Critical,
            "Browser Spawning Script Engine",
            "Browsers should not directly spawn command interpreters. This may indicate exploitation of a browser vulnerability or malicious download execution.",
            "MITRE ATT&CK T1189 (Drive-by Compromise)"),

        // Script engines spawning network utilities
        new("wscript|cscript|mshta|powershell|pwsh", "certutil|bitsadmin|curl|wget|Invoke-WebRequest", Severity.Critical,
            "Script Engine Downloading Content",
            "Script engines using download utilities may indicate staged payload retrieval.",
            "MITRE ATT&CK T1105 (Ingress Tool Transfer)"),

        // LOLBin abuse: certutil used for decoding
        new("cmd|powershell|pwsh", "certutil", Severity.Warning,
            "Potential LOLBin Abuse: certutil",
            "certutil can be abused to download or decode payloads. Verify the command-line arguments.",
            "MITRE ATT&CK T1140 (Deobfuscate/Decode Files)"),

        // LOLBin abuse: mshta executing content
        new("explorer|cmd|powershell|pwsh|svchost", "mshta", Severity.Warning,
            "Potential LOLBin Abuse: mshta",
            "mshta.exe can execute arbitrary HTA content including scripts. Often used to bypass application controls.",
            "MITRE ATT&CK T1218.005 (System Binary Proxy Execution: Mshta)"),

        // LOLBin abuse: rundll32 with unusual parent
        new("cmd|powershell|pwsh|wscript|cscript|mshta|wmiprvse", "rundll32", Severity.Warning,
            "Potential LOLBin Abuse: rundll32",
            "rundll32 spawned from script engines or WMI may indicate proxy execution of malicious DLLs.",
            "MITRE ATT&CK T1218.011 (System Binary Proxy Execution: Rundll32)"),

        // WMI spawning processes (lateral movement indicator)
        new("wmiprvse|WmiPrvSE", "cmd|powershell|pwsh|mshta|rundll32|regsvr32", Severity.Critical,
            "WMI Spawning Execution Engine",
            "WMI provider host spawning command interpreters is a strong indicator of lateral movement or persistence via WMI.",
            "MITRE ATT&CK T1047 (Windows Management Instrumentation)"),

        // Services spawning unexpected children
        new("services", "cmd|powershell|pwsh|wscript|cscript|mshta", Severity.Warning,
            "Service Control Manager Spawning Script Engine",
            "SCM spawning script engines outside normal service startup may indicate a malicious service installation.",
            "MITRE ATT&CK T1543.003 (Create or Modify System Process: Windows Service)"),

        // Task scheduler spawning unusual binaries
        new("svchost|taskeng|taskhostw", "powershell|pwsh|cmd|wscript|cscript|mshta|certutil|bitsadmin", Severity.Warning,
            "Scheduled Task Spawning Script Engine",
            "Scheduled tasks launching script engines may indicate persistence via task scheduler. Verify task legitimacy.",
            "MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task)"),

        // regsvr32 proxy execution
        new("cmd|powershell|pwsh|explorer|wscript|cscript", "regsvr32", Severity.Warning,
            "Potential LOLBin Abuse: regsvr32",
            "regsvr32 can be used to execute scripts via COM scriptlets, bypassing application controls.",
            "MITRE ATT&CK T1218.010 (System Binary Proxy Execution: Regsvr32)"),

        // cmd spawning PowerShell (possible obfuscation chain)
        new("cmd", "powershell|pwsh", Severity.Info,
            "Command Prompt Spawning PowerShell",
            "While often legitimate, cmd→powershell chains can indicate obfuscation layers. Review if unexpected.",
            "MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)"),

        // Explorer spawning command interpreters directly (unusual)
        new("explorer", "cmd|powershell|pwsh", Severity.Info,
            "Explorer Spawning Command Interpreter",
            "While user-initiated shell access is normal, automated or unexpected explorer→shell spawns may warrant review.",
            "MITRE ATT&CK T1059 (Command and Scripting Interpreter)"),
    };

    /// <summary>
    /// Known-safe parent|child combinations (case-insensitive) to reduce false positives.
    /// </summary>
    public static readonly IReadOnlySet<string> SafeExclusions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "svchost|taskhostw",  // Normal task scheduling
        "services|svchost",   // Normal service startup
        "explorer|cmd",       // User right-click → Open command window (very common)
    };

    // ──────────────────────────────────────────────────────────────────────
    // Parsing
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parse a single <c>name|pid|parentName|parentPid|commandLine</c> line emitted by the
    /// lineage WMI query. Returns <c>null</c> when the line is malformed, lacks a parent/child
    /// name, or carries unparseable PIDs — exactly the rows the audit skips.
    /// </summary>
    public static ProcessRecord? ParseProcessLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        var parts = line.Split('|', 5);
        if (parts.Length < 4) return null;

        var childName = parts[0].Trim();
        var parentName = parts[2].Trim();
        if (string.IsNullOrEmpty(parentName) || string.IsNullOrEmpty(childName)) return null;

        if (!int.TryParse(parts[1].Trim(), out int childPid)) return null;
        if (!int.TryParse(parts[3].Trim(), out int parentPid)) return null;

        var commandLine = parts.Length >= 5 ? parts[4].Trim() : string.Empty;
        return new ProcessRecord(childName, childPid, parentName, parentPid, commandLine);
    }

    /// <summary>
    /// Parse the full lineage query output into records, dropping malformed lines.
    /// Accepts <c>\n</c>- or <c>\r\n</c>-separated text.
    /// </summary>
    public static IReadOnlyList<ProcessRecord> ParseProcessLines(string? output)
    {
        if (string.IsNullOrEmpty(output)) return Array.Empty<ProcessRecord>();
        var records = new List<ProcessRecord>();
        foreach (var line in SplitLines(output))
        {
            var record = ParseProcessLine(line);
            if (record is not null) records.Add(record);
        }
        return records;
    }

    /// <summary>
    /// Parse a single <c>name|pid|parentPid</c> orphan line. Returns <c>null</c> when malformed.
    /// </summary>
    public static OrphanRecord? ParseOrphanLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        var parts = line.Split('|');
        if (parts.Length < 3) return null;

        var name = parts[0].Trim();
        if (string.IsNullOrEmpty(name)) return null;
        if (!int.TryParse(parts[1].Trim(), out int pid)) return null;
        if (!int.TryParse(parts[2].Trim(), out int parentPid)) return null;

        return new OrphanRecord(name, pid, parentPid);
    }

    /// <summary>Parse the orphan query output into records, dropping malformed lines.</summary>
    public static IReadOnlyList<OrphanRecord> ParseOrphanLines(string? output)
    {
        if (string.IsNullOrEmpty(output)) return Array.Empty<OrphanRecord>();
        var records = new List<OrphanRecord>();
        foreach (var line in SplitLines(output))
        {
            var record = ParseOrphanLine(line);
            if (record is not null) records.Add(record);
        }
        return records;
    }

    /// <summary>
    /// Parse a single <c>name|pid|depth</c> deep-nesting line. Returns <c>null</c> when malformed.
    /// </summary>
    public static DeepNestRecord? ParseDeepNestLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        var parts = line.Split('|');
        if (parts.Length < 3) return null;

        var name = parts[0].Trim();
        if (string.IsNullOrEmpty(name)) return null;
        if (!int.TryParse(parts[1].Trim(), out int pid)) return null;
        if (!int.TryParse(parts[2].Trim(), out int depth)) return null;

        return new DeepNestRecord(name, pid, depth);
    }

    /// <summary>Parse the deep-nesting query output into records, dropping malformed lines.</summary>
    public static IReadOnlyList<DeepNestRecord> ParseDeepNestLines(string? output)
    {
        if (string.IsNullOrEmpty(output)) return Array.Empty<DeepNestRecord>();
        var records = new List<DeepNestRecord>();
        foreach (var line in SplitLines(output))
        {
            var record = ParseDeepNestLine(line);
            if (record is not null) records.Add(record);
        }
        return records;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Matching
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns <c>true</c> when the parent|child pair is on the known-safe allow-list.
    /// </summary>
    public static bool IsSafeExclusion(string parentName, string childName)
        => SafeExclusions.Contains($"{parentName}|{childName}");

    /// <summary>
    /// Match a single record against the rule set, honouring safe exclusions and the
    /// "first matching rule wins" semantics. Returns <c>null</c> when nothing matches
    /// or the pair is excluded.
    /// </summary>
    public static LineageMatch? MatchRecord(ProcessRecord record)
    {
        if (record is null) return null;
        if (IsSafeExclusion(record.ParentName, record.ChildName)) return null;

        foreach (var rule in Rules)
        {
            if (rule.MatchesParent(record.ParentName) && rule.MatchesChild(record.ChildName))
            {
                return new LineageMatch(rule, record);
            }
        }
        return null;
    }

    /// <summary>
    /// Match every record against the rule set, returning the matches in input order.
    /// </summary>
    public static IReadOnlyList<LineageMatch> MatchRecords(IEnumerable<ProcessRecord> records)
    {
        var matches = new List<LineageMatch>();
        if (records is null) return matches;
        foreach (var record in records)
        {
            var match = MatchRecord(record);
            if (match is not null) matches.Add(match);
        }
        return matches;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Finding generation
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Build the lineage findings from a set of matches: a single Pass when none matched,
    /// or grouped Critical/Warning/Info findings (one per non-empty severity bucket).
    /// </summary>
    public static IReadOnlyList<Finding> BuildLineageFindings(IReadOnlyList<LineageMatch> matches)
    {
        var findings = new List<Finding>();

        if (matches is null || matches.Count == 0)
        {
            findings.Add(Finding.Pass(
                "Process Lineage Clean",
                "No suspicious parent-child process relationships detected.",
                Category));
            return findings;
        }

        var critical = matches.Where(m => m.Rule.Severity == Severity.Critical).ToList();
        var warning = matches.Where(m => m.Rule.Severity == Severity.Warning).ToList();
        var info = matches.Where(m => m.Rule.Severity == Severity.Info).ToList();

        if (critical.Count > 0)
        {
            var details = string.Join("\n", critical.Select(m =>
                $"  • {m.ParentName} (PID {m.ParentPid}) → {m.ChildName} (PID {m.ChildPid}): {m.Rule.Title} [{m.Rule.MitreId}]"));
            var cmdDetails = string.Join("\n", critical
                .Where(m => !string.IsNullOrWhiteSpace(m.CommandLine))
                .Take(5)
                .Select(m => $"  [{m.ChildName}] {Truncate(m.CommandLine, 120)}"));

            findings.Add(Finding.Critical(
                $"Critical Process Lineage Violations ({critical.Count})",
                $"Detected {critical.Count} critical suspicious parent-child process chains:\n{details}" +
                (cmdDetails.Length > 0 ? $"\n\nSample command lines:\n{cmdDetails}" : ""),
                Category,
                "Investigate these process chains immediately. Terminate suspicious processes and check for malware. Review MITRE ATT&CK references for context.",
                $"# Terminate suspicious children:\n{string.Join("\n", critical.Take(3).Select(m => $"Stop-Process -Id {m.ChildPid} -Force  # {m.ChildName} spawned by {m.ParentName}"))}"));
        }

        if (warning.Count > 0)
        {
            var details = string.Join("\n", warning.Select(m =>
                $"  • {m.ParentName} → {m.ChildName} (PID {m.ChildPid}): {m.Rule.Title} [{m.Rule.MitreId}]"));

            findings.Add(Finding.Warning(
                $"Suspicious Process Lineage Patterns ({warning.Count})",
                $"Detected {warning.Count} potentially suspicious parent-child chains:\n{details}",
                Category,
                "Review these process chains. While some may be legitimate, they match patterns commonly used by attackers for LOLBin abuse or persistence."));
        }

        if (info.Count > 0)
        {
            findings.Add(Finding.Info(
                $"Noteworthy Process Chains ({info.Count})",
                $"Detected {info.Count} process chains worth monitoring: " +
                string.Join(", ", info.Take(5).Select(m => $"{m.ParentName}→{m.ChildName}")),
                Category,
                "These are often legitimate but can be part of attack chains. Monitor for unusual frequency or timing."));
        }

        return findings;
    }

    /// <summary>
    /// Build the single orphaned-process finding for the given orphan records.
    /// &gt;10 → Warning, 1–10 → Info, 0 → Pass — matching the audit's thresholds.
    /// </summary>
    public static Finding BuildOrphanFinding(IReadOnlyList<OrphanRecord> orphaned)
    {
        var count = orphaned?.Count ?? 0;

        if (count > 10)
        {
            var sample = string.Join(", ", orphaned!.Take(8).Select(o => $"{o.Name} (PID {o.Pid})"));
            return Finding.Warning(
                $"Orphaned Processes Detected ({count})",
                $"Found {count} processes whose parent process no longer exists. Sample: {sample}. " +
                "While some orphaning is normal (parent exits first), a high count can indicate process injection or parent-PID spoofing.",
                Category,
                "Review orphaned processes, especially those running from unusual locations. Process injection often results in orphaned suspicious processes.");
        }

        if (count > 0)
        {
            return Finding.Info(
                $"Orphaned Processes ({count})",
                $"Found {count} processes with non-existent parent PIDs — normal in most cases.",
                Category);
        }

        return Finding.Pass(
            "No Orphaned Processes",
            "All running processes have valid parent process references.",
            Category);
    }

    /// <summary>
    /// Build the single deep-nesting finding. Any chains → Warning, none → Pass.
    /// </summary>
    public static Finding BuildDeepNestFinding(IReadOnlyList<DeepNestRecord> deepChains)
    {
        var count = deepChains?.Count ?? 0;

        if (count > 0)
        {
            var details = string.Join(", ", deepChains!.Take(5).Select(d => $"{d.Name} (PID {d.Pid}, depth {d.Depth})"));
            return Finding.Warning(
                $"Deeply Nested Interpreter Chains ({count})",
                $"Found {count} processes with 3+ levels of nested command interpreters: {details}. " +
                "Deep nesting of shells/script engines is an obfuscation technique used to evade detection.",
                Category,
                "Review the deepest chains. Legitimate automation rarely nests more than 2 levels of interpreters. Check for encoded commands or obfuscated scripts.",
                "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'cmd|powershell|pwsh' } | Select-Object ProcessId, ParentProcessId, CommandLine | Format-Table");
        }

        return Finding.Pass(
            "No Deep Interpreter Nesting",
            "No processes found with excessive command interpreter nesting.",
            Category);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Truncate a string to <paramref name="maxLength"/>, appending an ellipsis when cut.</summary>
    public static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return value ?? string.Empty;
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }

    private static IEnumerable<string> SplitLines(string output)
        => output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // ──────────────────────────────────────────────────────────────────────
    // Records / types
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>A parsed parent/child process pair from the lineage query.</summary>
    public sealed record ProcessRecord(string ChildName, int ChildPid, string ParentName, int ParentPid, string CommandLine);

    /// <summary>A parsed orphaned-process row (parent PID no longer exists).</summary>
    public sealed record OrphanRecord(string Name, int Pid, int ParentPid);

    /// <summary>A parsed deep-nesting row (interpreter-chain depth).</summary>
    public sealed record DeepNestRecord(string Name, int Pid, int Depth);

    /// <summary>A record that matched a <see cref="LineageRule"/>.</summary>
    public sealed class LineageMatch
    {
        public LineageRule Rule { get; }
        public ProcessRecord Record { get; }

        public LineageMatch(LineageRule rule, ProcessRecord record)
        {
            Rule = rule;
            Record = record;
        }

        public string ChildName => Record.ChildName;
        public int ChildPid => Record.ChildPid;
        public string ParentName => Record.ParentName;
        public int ParentPid => Record.ParentPid;
        public string CommandLine => Record.CommandLine;
    }

    /// <summary>
    /// Defines a suspicious parent→child process relationship pattern.
    /// </summary>
    public sealed class LineageRule
    {
        private readonly string[] _parentPatterns;
        private readonly string[] _childPatterns;

        public Severity Severity { get; }
        public string Title { get; }
        public string Description { get; }
        public string MitreId { get; }

        public LineageRule(string parentPattern, string childPattern,
            Severity severity, string title, string description, string mitreId)
        {
            _parentPatterns = (parentPattern ?? string.Empty).Split('|', StringSplitOptions.RemoveEmptyEntries);
            _childPatterns = (childPattern ?? string.Empty).Split('|', StringSplitOptions.RemoveEmptyEntries);
            Severity = severity;
            Title = title;
            Description = description;
            MitreId = mitreId;
        }

        /// <summary>True when the process name contains any parent pattern (case-insensitive substring).</summary>
        public bool MatchesParent(string processName)
            => !string.IsNullOrEmpty(processName)
               && _parentPatterns.Any(p => processName.Contains(p, StringComparison.OrdinalIgnoreCase));

        /// <summary>True when the process name equals or contains any child pattern (case-insensitive).</summary>
        public bool MatchesChild(string processName)
            => !string.IsNullOrEmpty(processName)
               && _childPatterns.Any(p => processName.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                                          processName.Contains(p, StringComparison.OrdinalIgnoreCase));
    }
}