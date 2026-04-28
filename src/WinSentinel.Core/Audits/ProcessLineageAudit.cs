using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits process parent-child relationships to detect suspicious lineage chains.
/// Identifies LOLBin abuse, Office macro execution, shell injection, and living-off-the-land techniques.
/// </summary>
public class ProcessLineageAudit : AuditModuleBase
{
    public override string Name => "Process Lineage Audit";
    public override string Category => "Processes";
    public override string Description => "Analyzes parent-child process relationships to detect suspicious execution chains, LOLBin abuse, and living-off-the-land techniques.";

    /// <summary>
    /// Rules defining suspicious parent → child process spawning patterns.
    /// Each rule has a parent pattern, child pattern, severity, and explanation.
    /// </summary>
    private static readonly List<LineageRule> Rules = new()
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
    /// Known-safe parent-child combinations to reduce false positives.
    /// </summary>
    private static readonly HashSet<string> SafeExclusions = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost|taskhostw",  // Normal task scheduling
        "services|svchost",  // Normal service startup
        "explorer|cmd",      // User right-click → Open command window (very common)
    };

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        await CheckProcessLineage(result, cancellationToken);
        await CheckOrphanedProcesses(result, cancellationToken);
        await CheckDeepNesting(result, cancellationToken);
    }

    private async Task CheckProcessLineage(AuditResult result, CancellationToken ct)
    {
        // Get process tree with parent info via WMI
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
              Where-Object { $_.ProcessId -ne 0 } |
              ForEach-Object { 
                  $parentName = ''
                  if ($_.ParentProcessId) {
                      $parent = Get-CimInstance Win32_Process -Filter ""ProcessId = $($_.ParentProcessId)"" -EA SilentlyContinue
                      if ($parent) { $parentName = $parent.Name -replace '\.exe$','' }
                  }
                  '{0}|{1}|{2}|{3}|{4}' -f ($_.Name -replace '\.exe$',''), $_.ProcessId, $parentName, $_.ParentProcessId, ($_.CommandLine -replace '\|','_' -replace '\r?\n',' ')
              }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var matchedRules = new List<(LineageRule Rule, string ChildProcess, int ChildPid, string ParentProcess, int ParentPid, string CommandLine)>();

        foreach (var line in lines)
        {
            var parts = line.Split('|', 5);
            if (parts.Length < 4) continue;

            var childName = parts[0].Trim();
            var parentName = parts[2].Trim();

            if (string.IsNullOrEmpty(parentName) || string.IsNullOrEmpty(childName)) continue;
            if (!int.TryParse(parts[1], out int childPid)) continue;
            if (!int.TryParse(parts[3], out int parentPid)) continue;

            var commandLine = parts.Length >= 5 ? parts[4].Trim() : "";

            // Check safe exclusions
            var pairKey = $"{parentName}|{childName}";
            if (SafeExclusions.Contains(pairKey)) continue;

            // Match against lineage rules
            foreach (var rule in Rules)
            {
                if (rule.MatchesParent(parentName) && rule.MatchesChild(childName))
                {
                    matchedRules.Add((rule, childName, childPid, parentName, parentPid, commandLine));
                    break; // One match per process pair
                }
            }
        }

        if (matchedRules.Count == 0)
        {
            result.Findings.Add(Finding.Pass(
                "Process Lineage Clean",
                "No suspicious parent-child process relationships detected.",
                Category));
            return;
        }

        // Group by severity and report
        var criticalMatches = matchedRules.Where(m => m.Rule.Severity == Severity.Critical).ToList();
        var warningMatches = matchedRules.Where(m => m.Rule.Severity == Severity.Warning).ToList();
        var infoMatches = matchedRules.Where(m => m.Rule.Severity == Severity.Info).ToList();

        if (criticalMatches.Count > 0)
        {
            var details = string.Join("\n", criticalMatches.Select(m =>
                $"  • {m.ParentProcess} (PID {m.ParentPid}) → {m.ChildProcess} (PID {m.ChildPid}): {m.Rule.Title} [{m.Rule.MitreId}]"));
            var cmdDetails = string.Join("\n", criticalMatches
                .Where(m => !string.IsNullOrWhiteSpace(m.CommandLine))
                .Take(5)
                .Select(m => $"  [{m.ChildProcess}] {Truncate(m.CommandLine, 120)}"));

            result.Findings.Add(Finding.Critical(
                $"Critical Process Lineage Violations ({criticalMatches.Count})",
                $"Detected {criticalMatches.Count} critical suspicious parent-child process chains:\n{details}" +
                (cmdDetails.Length > 0 ? $"\n\nSample command lines:\n{cmdDetails}" : ""),
                Category,
                "Investigate these process chains immediately. Terminate suspicious processes and check for malware. Review MITRE ATT&CK references for context.",
                $"# Terminate suspicious children:\n{string.Join("\n", criticalMatches.Take(3).Select(m => $"Stop-Process -Id {m.ChildPid} -Force  # {m.ChildProcess} spawned by {m.ParentProcess}"))}"));
        }

        if (warningMatches.Count > 0)
        {
            var details = string.Join("\n", warningMatches.Select(m =>
                $"  • {m.ParentProcess} → {m.ChildProcess} (PID {m.ChildPid}): {m.Rule.Title} [{m.Rule.MitreId}]"));

            result.Findings.Add(Finding.Warning(
                $"Suspicious Process Lineage Patterns ({warningMatches.Count})",
                $"Detected {warningMatches.Count} potentially suspicious parent-child chains:\n{details}",
                Category,
                "Review these process chains. While some may be legitimate, they match patterns commonly used by attackers for LOLBin abuse or persistence."));
        }

        if (infoMatches.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Noteworthy Process Chains ({infoMatches.Count})",
                $"Detected {infoMatches.Count} process chains worth monitoring: " +
                string.Join(", ", infoMatches.Take(5).Select(m => $"{m.ParentProcess}→{m.ChildProcess}")),
                Category,
                "These are often legitimate but can be part of attack chains. Monitor for unusual frequency or timing."));
        }
    }

    private async Task CheckOrphanedProcesses(AuditResult result, CancellationToken ct)
    {
        // Find processes whose parent PID doesn't exist (orphaned/reparented)
        var output = await ShellHelper.RunPowerShellAsync(
            @"$allPids = (Get-CimInstance Win32_Process -EA SilentlyContinue).ProcessId
              Get-CimInstance Win32_Process -EA SilentlyContinue | 
              Where-Object { $_.ParentProcessId -ne 0 -and $_.ProcessId -ne 4 -and $allPids -notcontains $_.ParentProcessId } |
              Where-Object { $_.Name -notin @('System','Registry','Memory Compression','svchost.exe','csrss.exe','wininit.exe','winlogon.exe','services.exe','smss.exe','lsass.exe') } |
              Select-Object -First 20 |
              ForEach-Object { '{0}|{1}|{2}' -f ($_.Name -replace '\.exe$',''), $_.ProcessId, $_.ParentProcessId }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var orphaned = lines.Where(l => l.Contains('|') && l.Split('|').Length >= 3).ToList();

        if (orphaned.Count > 10)
        {
            var sample = string.Join(", ", orphaned.Take(8).Select(l =>
            {
                var p = l.Split('|');
                return $"{p[0]} (PID {p[1]})";
            }));

            result.Findings.Add(Finding.Warning(
                $"Orphaned Processes Detected ({orphaned.Count})",
                $"Found {orphaned.Count} processes whose parent process no longer exists. Sample: {sample}. " +
                "While some orphaning is normal (parent exits first), a high count can indicate process injection or parent-PID spoofing.",
                Category,
                "Review orphaned processes, especially those running from unusual locations. Process injection often results in orphaned suspicious processes."));
        }
        else if (orphaned.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Orphaned Processes ({orphaned.Count})",
                $"Found {orphaned.Count} processes with non-existent parent PIDs — normal in most cases.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Orphaned Processes",
                "All running processes have valid parent process references.",
                Category));
        }
    }

    private async Task CheckDeepNesting(AuditResult result, CancellationToken ct)
    {
        // Detect deeply nested process chains (>4 levels of cmd/powershell)
        var output = await ShellHelper.RunPowerShellAsync(
            @"function Get-ProcessDepth {
                  param([int]$Pid, [int]$MaxDepth = 8, [hashtable]$ProcMap)
                  $depth = 0; $current = $Pid
                  $interpreters = @('cmd','powershell','pwsh','wscript','cscript')
                  $chainNames = @()
                  while ($depth -lt $MaxDepth -and $ProcMap.ContainsKey($current)) {
                      $info = $ProcMap[$current]
                      $name = $info.Name -replace '\.exe$',''
                      if ($name -in $interpreters) { $chainNames += $name }
                      $current = $info.ParentId
                      $depth++
                  }
                  return $chainNames.Count
              }
              $procs = Get-CimInstance Win32_Process -EA SilentlyContinue
              $map = @{}
              foreach ($p in $procs) { $map[$p.ProcessId] = @{ Name=$p.Name; ParentId=$p.ParentProcessId } }
              $deep = foreach ($p in $procs) {
                  $d = Get-ProcessDepth -Pid $p.ProcessId -ProcMap $map
                  if ($d -ge 3) { '{0}|{1}|{2}' -f ($p.Name -replace '\.exe$',''), $p.ProcessId, $d }
              }
              $deep | Select-Object -First 10", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var deepChains = lines.Where(l => l.Contains('|')).ToList();

        if (deepChains.Count > 0)
        {
            var details = string.Join(", ", deepChains.Take(5).Select(l =>
            {
                var p = l.Split('|');
                return p.Length >= 3 ? $"{p[0]} (PID {p[1]}, depth {p[2]})" : l;
            }));

            result.Findings.Add(Finding.Warning(
                $"Deeply Nested Interpreter Chains ({deepChains.Count})",
                $"Found {deepChains.Count} processes with 3+ levels of nested command interpreters: {details}. " +
                "Deep nesting of shells/script engines is an obfuscation technique used to evade detection.",
                Category,
                "Review the deepest chains. Legitimate automation rarely nests more than 2 levels of interpreters. Check for encoded commands or obfuscated scripts.",
                "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'cmd|powershell|pwsh' } | Select-Object ProcessId, ParentProcessId, CommandLine | Format-Table"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Deep Interpreter Nesting",
                "No processes found with excessive command interpreter nesting.",
                Category));
        }
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength] + "...";

    /// <summary>
    /// Defines a suspicious parent→child process relationship pattern.
    /// </summary>
    private class LineageRule
    {
        private readonly string[] _parentPatterns;
        private readonly string[] _childPatterns;

        public Severity Severity { get; }
        public string Title { get; }
        public string Description { get; }
        public string MitreId { get; }

        public LineageRule(string parentPattern, string childPattern, Severity severity, string title, string description, string mitreId)
        {
            _parentPatterns = parentPattern.Split('|', StringSplitOptions.RemoveEmptyEntries);
            _childPatterns = childPattern.Split('|', StringSplitOptions.RemoveEmptyEntries);
            Severity = severity;
            Title = title;
            Description = description;
            MitreId = mitreId;
        }

        public bool MatchesParent(string processName)
            => _parentPatterns.Any(p => processName.Contains(p, StringComparison.OrdinalIgnoreCase));

        public bool MatchesChild(string processName)
            => _childPatterns.Any(p => processName.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                                       processName.Contains(p, StringComparison.OrdinalIgnoreCase));
    }
}
