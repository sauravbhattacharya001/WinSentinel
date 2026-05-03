namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Execution Detector — autonomous detection of techniques adversaries use to run
/// malicious code on local or remote systems after gaining initial access.
/// Identifies command/scripting interpreter abuse, inter-process communication,
/// exploitation for execution, and other code execution techniques.
///
/// MITRE ATT&amp;CK: TA0002 (Execution)
/// Techniques: T1059 (Command and Scripting Interpreter), T1059.001 (PowerShell),
/// T1059.003 (Windows Command Shell), T1059.005 (Visual Basic), T1059.006 (Python),
/// T1059.007 (JavaScript), T1047 (Windows Management Instrumentation),
/// T1053.005 (Scheduled Task), T1569.002 (Service Execution),
/// T1203 (Exploitation for Client Execution), T1204.001 (Malicious Link),
/// T1204.002 (Malicious File), T1559.001 (Component Object Model / DCOM)
/// </summary>
public sealed class ExecutionDetector
{
    private readonly AuditHistoryService _history;

    private static readonly List<ExecutionSignature> Signatures = new()
    {
        new("PowerShell", "T1059.001",
            new[] { "powershell", "pwsh", "invoke-expression", "iex(", "invoke-command",
                    "encodedcommand", "bypass", "hidden", "-enc ", "-nop ", "downloadstring",
                    "invoke-webrequest", "new-object net.webclient", "powershell.exe",
                    "script block logging", "scriptblock" },
            0.80, "Scripting"),
        new("Windows Command Shell", "T1059.003",
            new[] { "cmd.exe", "cmd /c", "command shell", "cmd /k", "batch file",
                    "command prompt", "cmd execution", ".bat execution", ".cmd execution",
                    "command interpreter", "comspec" },
            0.70, "Scripting"),
        new("Visual Basic", "T1059.005",
            new[] { "vbscript", "wscript", "cscript", "visual basic", "vbs execution",
                    "wscript.exe", "cscript.exe", ".vbs", "macro execution", "vba macro",
                    "office macro", "auto_open", "document_open" },
            0.80, "Scripting"),
        new("Python", "T1059.006",
            new[] { "python.exe", "python3.exe", "python execution", "python script",
                    "python -c", "python payload", "py execution", "ironpython" },
            0.75, "Scripting"),
        new("JavaScript", "T1059.007",
            new[] { "jscript", "javascript execution", ".js execution", "wscript.exe",
                    "node.exe malicious", "javascript payload", "jscript.encode",
                    "activexobject", "wshell" },
            0.75, "Scripting"),
        new("Windows Management Instrumentation", "T1047",
            new[] { "wmi", "wmic", "win32_process", "invoke-wmimethod", "wmi execution",
                    "wmiprvse", "wbemtest", "get-wmiobject", "gwmi", "invoke-cimmethod",
                    "winmgmt", "wmi process create", "win32_scheduledJob" },
            0.85, "WMI"),
        new("Scheduled Task/Job", "T1053.005",
            new[] { "schtasks", "scheduled task", "task scheduler", "at.exe",
                    "new-scheduledtask", "register-scheduledtask", "task creation",
                    "schtasks /create", "schtasks /run", "taskschd.msc" },
            0.80, "ScheduledTask"),
        new("System Services: Service Execution", "T1569.002",
            new[] { "service execution", "sc create", "sc start", "new-service",
                    "service creation", "services.exe", "binpath", "service start type",
                    "psexec", "remote service", "sc.exe" },
            0.85, "Service"),
        new("Exploitation for Client Execution", "T1203",
            new[] { "exploit", "client execution", "vulnerability exploit", "buffer overflow",
                    "memory corruption", "use-after-free", "heap spray", "rop chain",
                    "exploit kit", "drive-by exploit", "browser exploit", "office exploit" },
            0.90, "Exploit"),
        new("User Execution: Malicious Link", "T1204.001",
            new[] { "malicious link", "phishing link", "click link", "url execution",
                    "suspicious url", "drive-by download", "compromised link",
                    "link click", "redirect chain" },
            0.70, "UserExecution"),
        new("User Execution: Malicious File", "T1204.002",
            new[] { "malicious file", "suspicious attachment", "double extension",
                    "file execution", "exe attachment", "malicious document",
                    "weaponized document", "trojanized file", "dropper", "payload delivery" },
            0.75, "UserExecution"),
        new("Inter-Process Communication: DCOM", "T1559.001",
            new[] { "dcom", "distributed com", "component object model", "com object",
                    "dcomlaunch", "ole automation", "mmc20.application", "shellbrowserwindow",
                    "shellwindows", "excel.application", "outlook.application" },
            0.80, "IPC"),
        new("Shared Modules", "T1129",
            new[] { "dll loading", "loadlibrary", "shared module", "dll injection",
                    "side-loading", "dll execution", "regsvr32", "rundll32",
                    "rundll32.exe", "regsvr32.exe", "reflective dll" },
            0.80, "DLLExecution"),
    };

    /// <summary>Indicators of automated/scripted execution (higher urgency).</summary>
    private static readonly string[] AutomationIndicators =
        { "automated", "script", "bot", "mass", "bulk", "framework", "batch", "scheduled", "recurring" };

    /// <summary>Known execution tool/framework names for enhanced detection.</summary>
    private static readonly string[] KnownTools =
        { "psexec", "cobalt strike", "meterpreter", "empire", "covenant",
          "sliver", "mimikatz", "impacket", "crackmapexec", "wmiexec",
          "smbexec", "atexec", "dcomexec", "evil-winrm", "metasploit",
          "powersploit", "sharpshooter", "unicorn", "nishang" };

    /// <summary>Execution method risk ordering (low index = lower risk).</summary>
    private static readonly string[] MethodRiskLevels =
        { "UserExecution", "Scripting", "ScheduledTask", "DLLExecution", "IPC", "Service", "WMI", "Exploit" };

    public ExecutionDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run execution detection against the current security report.</summary>
    public ExecutionReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new ExecutionReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var events = new List<ExecutionEvent>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectExecutions(finding, module);
            events.AddRange(detected);
        }

        // Scan historical findings
        foreach (var run in runs)
        {
            foreach (var fr in run.Findings)
            {
                var finding = new Finding
                {
                    Title = fr.Title,
                    Description = fr.Description,
                    Category = fr.ModuleName
                };
                var detected = DetectExecutions(finding, fr.ModuleName);
                events.AddRange(detected);
            }
        }

        // Deduplicate by technique + evidence
        events = DeduplicateEvents(events);

        result.Executions = events;
        result.ExecutionsDetected = events.Count;
        result.HighSeverityExecutions = events.Count(e => e.Severity is ExecutionSeverity.High or ExecutionSeverity.Critical);
        result.MediumSeverityExecutions = events.Count(e => e.Severity == ExecutionSeverity.Medium);
        result.LowSeverityExecutions = events.Count(e => e.Severity == ExecutionSeverity.Low);

        // Build campaigns
        result.Campaigns = BuildCampaigns(events);

        // Compute stats
        result.Stats = ComputeStats(events);

        // Score threat
        result.ThreatScore = ComputeThreatScore(events, result.Campaigns);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(events, result.Campaigns, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<ExecutionEvent> DetectExecutions(Finding finding, string module)
    {
        var results = new List<ExecutionEvent>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            var isAutomated = AutomationIndicators.Any(a => text.Contains(a));
            var confidence = isAutomated ? Math.Min(sig.BaseConfidence + 0.05, 1.0) : sig.BaseConfidence;

            var toolFound = KnownTools.FirstOrDefault(t => text.Contains(t));
            if (toolFound != null)
                confidence = Math.Min(confidence + 0.05, 1.0);

            var evt = new ExecutionEvent
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                TargetAsset = ExtractAsset(text),
                ExecutionMethod = sig.Category,
                SourceTool = toolFound,
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                ProcessName = ExtractProcess(text),
                IsAutomated = isAutomated,
                Indicators = new List<string>()
            };

            if (isAutomated)
                evt.Indicators.Add("Automated/scripted execution activity detected");

            if (toolFound != null)
                evt.Indicators.Add($"Known attack tool/framework referenced: {toolFound}");

            // Check for encoded/obfuscated commands
            if (text.Contains("encod") || text.Contains("obfuscat") || text.Contains("base64") || text.Contains("-enc "))
                evt.Indicators.Add("Encoded or obfuscated command execution detected — may indicate evasion");

            // Check for download + execute pattern
            if ((text.Contains("download") || text.Contains("invoke-webrequest") || text.Contains("webclient"))
                && (text.Contains("execute") || text.Contains("invoke") || text.Contains("iex") || text.Contains("start-process")))
                evt.Indicators.Add("Download-and-execute pattern detected — classic malware delivery chain");

            // Check for fileless/in-memory execution
            if (text.Contains("fileless") || text.Contains("in-memory") || text.Contains("reflective") || text.Contains("amsi bypass"))
                evt.Indicators.Add("Fileless/in-memory execution technique detected — difficult to forensically analyze");

            // Check for persistence combo
            if (text.Contains("persist") || text.Contains("startup") || text.Contains("autorun") || text.Contains("registry run"))
                evt.Indicators.Add("Execution combined with persistence mechanism — adversary establishing foothold");

            // Check for lateral movement combo
            if (text.Contains("remote") || text.Contains("lateral") || text.Contains("pivot"))
                evt.Indicators.Add("Remote execution may indicate lateral movement");

            // Check for privilege escalation combo
            if (text.Contains("elevat") || text.Contains("admin") || text.Contains("system") || text.Contains("privilege"))
                evt.Indicators.Add("Execution in elevated context — possible privilege escalation");

            // Severity classification
            evt.Severity = ClassifySeverity(evt);

            results.Add(evt);
            break; // One technique per finding
        }

        return results;
    }

    private ExecutionSeverity ClassifySeverity(ExecutionEvent evt)
    {
        // Critical: exploit-based execution with tool, fileless execution
        if (evt.MitreTechnique == "T1203" && evt.SourceTool != null)
            return ExecutionSeverity.Critical;
        if (evt.Indicators.Any(i => i.Contains("Fileless")))
            return ExecutionSeverity.Critical;
        if (evt.Indicators.Any(i => i.Contains("Download-and-execute")))
            return ExecutionSeverity.Critical;

        // High: WMI execution, service execution, exploit, DCOM
        if (evt.MitreTechnique == "T1047")
            return ExecutionSeverity.High;
        if (evt.MitreTechnique == "T1569.002")
            return ExecutionSeverity.High;
        if (evt.MitreTechnique == "T1203")
            return ExecutionSeverity.High;
        if (evt.MitreTechnique == "T1559.001")
            return ExecutionSeverity.High;
        if (evt.MitreTechnique == "T1129")
            return ExecutionSeverity.High;

        // Medium: PowerShell (encoded), VBScript, scheduled tasks, Python, JS
        if (evt.MitreTechnique == "T1059.001" && evt.Indicators.Any(i => i.Contains("Encoded")))
            return ExecutionSeverity.High;
        if (evt.ExecutionMethod is "Scripting" or "ScheduledTask")
            return ExecutionSeverity.Medium;

        // Low: user execution (link/file)
        if (evt.ExecutionMethod == "UserExecution")
            return ExecutionSeverity.Low;

        return ExecutionSeverity.Medium;
    }

    // ── Campaign Detection ──────────────────────────────────────────

    private List<ExecutionCampaign> BuildCampaigns(List<ExecutionEvent> events)
    {
        if (events.Count < 2) return new();

        var campaigns = new List<ExecutionCampaign>();

        // Sort by time
        var sorted = events.OrderBy(e => e.DetectedAt).ToList();

        // Group by target asset
        var byAsset = sorted
            .Where(e => e.TargetAsset != null)
            .GroupBy(e => e.TargetAsset!)
            .Where(g => g.Count() >= 2);

        foreach (var group in byAsset)
        {
            var steps = group.OrderBy(e => e.DetectedAt).ToList();
            var campaign = new ExecutionCampaign
            {
                Steps = steps,
                PrimaryMethod = steps
                    .GroupBy(s => s.ExecutionMethod)
                    .OrderByDescending(g => g.Count())
                    .First().Key ?? "unknown",
                TargetSummary = group.Key,
                MethodCount = steps.Select(s => s.ExecutionMethod).Distinct().Count(),
                Duration = steps.Last().DetectedAt - steps.First().DetectedAt,
                CompoundConfidence = steps.Aggregate(1.0, (acc, e) => acc * e.Confidence)
            };
            campaign.Verdict = campaign.MethodCount >= 3
                ? $"CRITICAL: Multi-method execution campaign against {campaign.TargetSummary} using {campaign.MethodCount} execution methods"
                : $"Multi-stage execution against {campaign.TargetSummary} ({campaign.Steps.Count} events)";
            campaigns.Add(campaign);
        }

        // Multi-method campaigns
        if (!campaigns.Any() && sorted.Count >= 2)
        {
            var methods = sorted.Select(e => e.ExecutionMethod).Distinct().Count();
            if (methods >= 2)
            {
                var campaign = new ExecutionCampaign
                {
                    Steps = sorted,
                    PrimaryMethod = sorted
                        .GroupBy(s => s.ExecutionMethod)
                        .OrderByDescending(g => g.Count())
                        .First().Key ?? "unknown",
                    TargetSummary = "Multiple assets",
                    MethodCount = methods,
                    Duration = sorted.Last().DetectedAt - sorted.First().DetectedAt,
                    CompoundConfidence = sorted.Aggregate(1.0, (acc, e) => acc * e.Confidence)
                };
                campaign.Verdict = $"Multi-method execution campaign ({methods} methods, {sorted.Count} events)";
                campaigns.Add(campaign);
            }
        }

        return campaigns;
    }

    // ── Statistics ───────────────────────────────────────────────────

    private ExecutionStats ComputeStats(List<ExecutionEvent> events)
    {
        if (events.Count == 0)
            return new ExecutionStats();

        var techniques = events.Select(e => e.Technique).Distinct().ToList();
        var assets = events.Where(e => e.TargetAsset != null).Select(e => e.TargetAsset!).Distinct().ToList();
        var methods = events.Where(e => e.ExecutionMethod != null).Select(e => e.ExecutionMethod!).Distinct().ToList();
        var mostCommon = events
            .GroupBy(e => e.Technique)
            .OrderByDescending(g => g.Count())
            .First();

        var timeSpan = events.Max(e => e.DetectedAt) - events.Min(e => e.DetectedAt);
        var days = Math.Max(timeSpan.TotalDays, 1);

        return new ExecutionStats
        {
            TotalTechniquesUsed = techniques.Count,
            UniqueAssetsTargeted = assets.Count,
            MostCommonTechnique = mostCommon.Key,
            AverageConfidence = Math.Round(events.Average(e => e.Confidence), 3),
            AutomatedExecutions = events.Count(e => e.IsAutomated),
            ManualExecutions = events.Count(e => !e.IsAutomated),
            ExecutionVelocity = Math.Round(events.Count / days, 2),
            ExecutionMethodsUsed = methods.Count
        };
    }

    // ── Scoring ─────────────────────────────────────────────────────

    private int ComputeThreatScore(List<ExecutionEvent> events, List<ExecutionCampaign> campaigns)
    {
        if (events.Count == 0) return 0;

        double score = 0;

        // Base score from event count and severity
        score += events.Count(e => e.Severity == ExecutionSeverity.Critical) * 25;
        score += events.Count(e => e.Severity == ExecutionSeverity.High) * 15;
        score += events.Count(e => e.Severity == ExecutionSeverity.Medium) * 8;
        score += events.Count(e => e.Severity == ExecutionSeverity.Low) * 3;

        // Campaign bonus
        score += campaigns.Count * 10;
        if (campaigns.Any(c => c.MethodCount >= 3))
            score += 20;

        // Known tool bonus
        if (events.Any(e => e.SourceTool != null))
            score += 15;

        // Automated execution bonus
        if (events.Any(e => e.IsAutomated))
            score += 10;

        // Diversity bonus (more techniques = more sophisticated)
        var uniqueTechniques = events.Select(e => e.Technique).Distinct().Count();
        if (uniqueTechniques >= 3) score += 10;
        if (uniqueTechniques >= 5) score += 10;

        // Method diversity bonus
        var uniqueMethods = events.Select(e => e.ExecutionMethod).Distinct().Count();
        if (uniqueMethods >= 3) score += 5;

        return (int)Math.Min(score, 100);
    }

    private string ClassifyThreatLevel(int score) => score switch
    {
        >= 80 => "Critical",
        >= 60 => "Elevated",
        >= 40 => "Moderate",
        >= 20 => "Low",
        _ => "Minimal"
    };

    // ── Recommendations ─────────────────────────────────────────────

    private List<string> GenerateRecommendations(List<ExecutionEvent> events,
        List<ExecutionCampaign> campaigns, ExecutionStats stats)
    {
        var recs = new List<string>();

        if (events.Count == 0)
        {
            recs.Add("No execution indicators detected. Continue monitoring.");
            return recs;
        }

        var techniques = events.Select(e => e.Technique).Distinct().ToHashSet();

        if (techniques.Contains("PowerShell"))
            recs.Add("Enable PowerShell Script Block Logging (Event ID 4104) and Module Logging; enforce Constrained Language Mode; deploy AMSI for runtime inspection; block encoded commands via AppLocker policy; consider disabling PowerShell v2 which bypasses logging.");

        if (techniques.Contains("Windows Command Shell"))
            recs.Add("Enable command-line auditing via Event ID 4688 with process creation arguments; restrict cmd.exe access for non-admin users via AppLocker; monitor for suspicious batch file execution in temp directories.");

        if (techniques.Contains("Visual Basic"))
            recs.Add("CRITICAL: Block Office macro execution via Group Policy (disable VBA for all Office apps); enforce Attack Surface Reduction (ASR) rules for Office child process creation; disable Windows Script Host (wscript/cscript) for non-admin users.");

        if (techniques.Contains("Python"))
            recs.Add("Monitor for unauthorized Python installations; restrict Python execution via AppLocker to approved directories; audit python.exe process creation events; consider application whitelisting to prevent interpreter abuse.");

        if (techniques.Contains("JavaScript"))
            recs.Add("Disable Windows Script Host for non-admin users via registry; block .js/.jse file execution via AppLocker; enforce ASR rules for JavaScript/VBScript launching executables; monitor for jscript/wscript process creation.");

        if (techniques.Contains("Windows Management Instrumentation"))
            recs.Add("CRITICAL: WMI-based execution detected — restrict WMI access via DCOM permissions; enable WMI activity logging (Event ID 5857-5861); monitor wmiprvse.exe child processes; disable remote WMI for non-admin accounts; block lateral WMI execution via firewall rules.");

        if (techniques.Contains("Scheduled Task/Job"))
            recs.Add("Monitor for suspicious schtasks /create commands; audit Task Scheduler events (Event IDs 4698-4702); restrict task creation to admin accounts; review all scheduled tasks for unauthorized entries; enable ASR rule to block process creation from scheduled tasks.");

        if (techniques.Contains("System Services: Service Execution"))
            recs.Add("CRITICAL: Service-based execution detected — restrict service creation (sc create) to admin accounts; monitor Event ID 7045 (new service installed); audit binpath parameters for suspicious executables; block PsExec via AppLocker; review all services for unsigned binaries.");

        if (techniques.Contains("Exploitation for Client Execution"))
            recs.Add("CRITICAL: Exploit-based execution detected — ensure all client applications are patched; enable Exploit Protection (Windows Defender); deploy ASR rules; monitor for unusual application crashes (potential exploit attempts); isolate affected endpoint for investigation.");

        if (techniques.Contains("User Execution: Malicious Link"))
            recs.Add("Deploy URL filtering and web proxy inspection; train users on phishing awareness; enable SmartScreen for URL reputation checking; monitor for unusual browser-launched processes; implement email link rewriting/sandboxing.");

        if (techniques.Contains("User Execution: Malicious File"))
            recs.Add("Block execution of files from internet zones via Mark-of-the-Web enforcement; deploy ASR rules for double-extension files; restrict executable downloads to approved sources; enable SmartScreen and Windows Defender real-time protection; audit temp/download directory execution.");

        if (techniques.Contains("Inter-Process Communication: DCOM"))
            recs.Add("CRITICAL: DCOM-based execution detected — restrict DCOM permissions via Component Services; disable remote DCOM activation for non-admin users; monitor for unusual COM object instantiation (MMC20, ShellBrowserWindow); audit DCOM configuration changes.");

        if (techniques.Contains("Shared Modules"))
            recs.Add("Monitor for DLL loading from suspicious paths (temp/downloads); enable DLL search order hardening; deploy ASR rules for DLL side-loading; audit regsvr32/rundll32 execution; block unsigned DLL loading via code integrity policies.");

        // Campaign-level recommendations
        if (campaigns.Any(c => c.MethodCount >= 3))
            recs.Add("CRITICAL: Multi-method execution campaign detected — adversary is using diverse execution techniques to evade detection; activate incident response; assume compromise and begin containment; check for persistence mechanisms and lateral movement.");

        if (stats.AutomatedExecutions > 0)
            recs.Add("Automated execution activity detected — investigate for active attack framework (Cobalt Strike, Metasploit, Empire); review endpoint for C2 beaconing; check for post-exploitation tooling.");

        if (stats.ExecutionVelocity > 5)
            recs.Add("High execution activity velocity indicates active adversary operations — increase monitoring posture; consider network isolation of affected assets; activate threat hunting.");

        if (stats.ExecutionMethodsUsed >= 3)
            recs.Add("Multiple execution methods in use — sophisticated adversary employing technique diversity; review all execution surfaces (scripting, WMI, services, scheduled tasks); ensure defense-in-depth across all execution vectors.");

        // General
        recs.Add("Enable Windows Event ID 4688 (process creation) with command-line logging; deploy Sysmon for enhanced process telemetry; enable Attack Surface Reduction (ASR) rules; review AppLocker/WDAC policies for execution control gaps.");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private List<ExecutionEvent> DeduplicateEvents(List<ExecutionEvent> events)
    {
        return events
            .GroupBy(e => $"{e.Technique}|{e.Evidence}")
            .Select(g => g.First())
            .ToList();
    }

    private static string? ExtractAsset(string text)
    {
        var patterns = new[] { "server:", "host:", "target:", "system:", "endpoint:", "asset:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 40, text.Length);
            var asset = text[start..end].Trim();
            if (asset.Length > 0) return asset;
        }
        return null;
    }

    private static string? ExtractProcess(string text)
    {
        var patterns = new[] { "process:", "executable:", "binary:", "program:", "tool:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 60, text.Length);
            var proc = text[start..end].Trim();
            if (proc.Length > 0) return proc;
        }
        return null;
    }

    // ── Internal Types ──────────────────────────────────────────────

    private sealed record ExecutionSignature(
        string Name, string MitreId, string[] Keywords, double BaseConfidence, string Category);
}
