namespace WinSentinel.Core.Services;

using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

/// <summary>
/// Privilege Escalation Detector — autonomous detection of privilege escalation patterns
/// across security findings. Identifies token manipulation, UAC bypass, DLL hijacking,
/// service creation, scheduled task abuse, process injection, and more.
/// Builds escalation chains and recommends containment actions.
///
/// MITRE ATT&amp;CK: TA0004 (Privilege Escalation)
/// Techniques: T1134 (Access Token Manipulation), T1068 (Exploitation for Priv Esc),
/// T1078.003 (Valid Accounts: Local), T1053.005 (Scheduled Task/Job),
/// T1543.003 (Windows Service), T1548.002 (Bypass UAC), T1547.001 (Autostart),
/// T1546.015 (COM Hijacking), T1055 (Process Injection), T1574.001 (DLL Hijacking)
/// </summary>
public sealed class PrivilegeEscalationDetector
{
    private readonly AuditHistoryService _history;

    private static readonly List<EscTechniqueSignature> Signatures = new()
    {
        new("Access Token Manipulation", "T1134",
            new[] { "token", "impersonate", "sedebugprivilege", "duplicatetoken", "adjusttokenprivileges", "setokenassignprimary" }, 0.85, "SYSTEM"),
        new("Exploitation for Privilege Escalation", "T1068",
            new[] { "exploit", "cve-", "overflow", "elevation of privilege", "eop", "lpe", "local privilege" }, 0.9, "SYSTEM"),
        new("Valid Accounts: Local Admin", "T1078.003",
            new[] { "local admin", "administrator", "builtin\\\\administrators", "net localgroup administrators", "add to admin" }, 0.75, "Administrator"),
        new("Scheduled Task as SYSTEM", "T1053.005",
            new[] { "schtasks /create", "schtasks.*system", "task scheduler.*system", "at.exe" }, 0.8, "SYSTEM"),
        new("Windows Service Creation", "T1543.003",
            new[] { "sc create", "new-service", "service.*localsystem", "sc config.*start=", "createservice" }, 0.85, "SYSTEM"),
        new("UAC Bypass", "T1548.002",
            new[] { "uac bypass", "eventvwr", "fodhelper", "sdclt", "cmstp", "computerdefaults", "silentcleanup", "auto-elevat" }, 0.9, "High Integrity"),
        new("Boot/Logon Autostart", "T1547.001",
            new[] { "autorun", "startup folder", "run key", "currentversion\\\\run", "winlogon", "userinit" }, 0.7, "Persistent"),
        new("COM Hijacking", "T1546.015",
            new[] { "com hijack", "clsid", "inprocserver", "localserver32", "treatas", "com object" }, 0.8, "Medium-High"),
        new("Process Injection", "T1055",
            new[] { "inject", "hollowing", "createremotethread", "ntcreatethreadex", "reflective load", "process injection", "writeprocessmemory" }, 0.9, "Target Process"),
        new("DLL Search Order Hijacking", "T1574.001",
            new[] { "dll hijack", "search order", "path interception", "phantom dll", "dll side-load", "dll proxying" }, 0.8, "Application"),
    };

    /// <summary>Indicators of automated/scripted escalation (higher urgency).</summary>
    private static readonly string[] AutomationIndicators = { "script", "powershell", "batch", "automated", "scheduled", "tool", "framework", "metasploit", "cobalt" };

    /// <summary>Privilege levels for chain ordering (low index = low privilege).</summary>
    private static readonly string[] PrivilegeLevels = { "standard-user", "Application", "Persistent", "Medium-High", "High Integrity", "Administrator", "SYSTEM", "Target Process" };

    public PrivilegeEscalationDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run privilege escalation detection against the current security report.</summary>
    public PrivilegeEscalationReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new PrivilegeEscalationReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var escalations = new List<PrivilegeEscalation>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectEscalations(finding, module);
            escalations.AddRange(detected);
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
                var detected = DetectEscalations(finding, fr.ModuleName);
                escalations.AddRange(detected);
            }
        }

        // Deduplicate by technique + evidence within same time window
        escalations = DeduplicateEscalations(escalations);

        result.Escalations = escalations;
        result.EscalationsDetected = escalations.Count;
        result.HighSeverityEscalations = escalations.Count(e => e.Severity is PrivEscSeverity.High or PrivEscSeverity.Critical);
        result.MediumSeverityEscalations = escalations.Count(e => e.Severity == PrivEscSeverity.Medium);
        result.LowSeverityEscalations = escalations.Count(e => e.Severity == PrivEscSeverity.Low);

        // Build escalation chains
        result.Chains = BuildChains(escalations);

        // Compute stats
        result.Stats = ComputeStats(escalations);

        // Score threat
        result.ThreatScore = ComputeThreatScore(escalations, result.Chains);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(escalations, result.Chains, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<PrivilegeEscalation> DetectEscalations(Finding finding, string module)
    {
        var results = new List<PrivilegeEscalation>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => ContainsKeyword(text, k)))
                continue;

            var isAutomated = AutomationIndicators.Any(a => text.Contains(a));
            var confidence = isAutomated ? Math.Min(sig.BaseConfidence + 0.1, 1.0) : sig.BaseConfidence;

            var escalation = new PrivilegeEscalation
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                AccountUsed = ExtractAccount(text),
                TargetPrivilege = sig.TargetPrivilege,
                SourcePrivilege = "standard-user",
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                ProcessName = ExtractProcess(text),
                IsAutomated = isAutomated,
                Indicators = new List<string>()
            };

            if (isAutomated)
                escalation.Indicators.Add("Automated/scripted escalation detected");

            // Check for known exploit frameworks
            if (text.Contains("metasploit") || text.Contains("cobalt"))
                escalation.Indicators.Add("Known attack framework referenced");

            // Severity classification
            escalation.Severity = ClassifySeverity(escalation);

            results.Add(escalation);
            break; // One technique per finding
        }

        return results;
    }

    private PrivEscSeverity ClassifySeverity(PrivilegeEscalation esc)
    {
        // Critical: automated + targets SYSTEM or uses known exploit
        if (esc.IsAutomated && esc.TargetPrivilege == "SYSTEM")
            return PrivEscSeverity.Critical;
        if (esc.Indicators.Any(i => i.Contains("attack framework")))
            return PrivEscSeverity.Critical;

        // High: targets SYSTEM/Administrator or process injection
        if (esc.TargetPrivilege is "SYSTEM" or "Administrator" or "Target Process")
            return PrivEscSeverity.High;

        // Medium: UAC bypass, COM hijacking, DLL hijacking
        if (esc.TargetPrivilege is "High Integrity" or "Medium-High" or "Application")
            return PrivEscSeverity.Medium;

        return PrivEscSeverity.Low;
    }

    // ── Chain Detection ──────────────────────────────────────────────

    private List<EscalationChain> BuildChains(List<PrivilegeEscalation> escalations)
    {
        if (escalations.Count < 2) return new();

        var chains = new List<EscalationChain>();

        // Sort by time to find sequences
        var sorted = escalations.OrderBy(e => e.DetectedAt).ToList();

        // Group by account to find per-user chains
        var byAccount = sorted
            .Where(e => e.AccountUsed != null)
            .GroupBy(e => e.AccountUsed!)
            .Where(g => g.Count() >= 2);

        foreach (var group in byAccount)
        {
            var steps = group.OrderBy(e => e.DetectedAt).ToList();
            var chain = new EscalationChain
            {
                Steps = steps,
                StartPrivilege = steps.First().SourcePrivilege ?? "standard-user",
                EndPrivilege = steps.Last().TargetPrivilege ?? "unknown",
                HopCount = steps.Count,
                Duration = steps.Last().DetectedAt - steps.First().DetectedAt,
                CompoundConfidence = steps.Aggregate(1.0, (acc, e) => acc * e.Confidence)
            };
            chain.Verdict = chain.EndPrivilege == "SYSTEM"
                ? "CRITICAL: Full privilege escalation chain to SYSTEM detected"
                : $"Escalation chain reaching {chain.EndPrivilege} privilege";
            chains.Add(chain);
        }

        // Also detect technique-progression chains (different techniques in sequence)
        if (sorted.Count >= 2 && !chains.Any())
        {
            // Order by privilege level
            var ordered = sorted
                .OrderBy(e => Array.IndexOf(PrivilegeLevels, e.TargetPrivilege ?? ""))
                .ToList();

            if (ordered.Count >= 2)
            {
                var chain = new EscalationChain
                {
                    Steps = ordered,
                    StartPrivilege = ordered.First().SourcePrivilege ?? "standard-user",
                    EndPrivilege = ordered.Last().TargetPrivilege ?? "unknown",
                    HopCount = ordered.Count,
                    Duration = ordered.Last().DetectedAt - ordered.First().DetectedAt,
                    CompoundConfidence = ordered.Aggregate(1.0, (acc, e) => acc * e.Confidence)
                };
                chain.Verdict = $"Multi-technique escalation path detected ({chain.HopCount} steps)";
                chains.Add(chain);
            }
        }

        return chains;
    }

    // ── Statistics ───────────────────────────────────────────────────

    private PrivEscStats ComputeStats(List<PrivilegeEscalation> escalations)
    {
        if (escalations.Count == 0)
            return new PrivEscStats();

        var techniques = escalations.Select(e => e.Technique).Distinct().ToList();
        var accounts = escalations.Where(e => e.AccountUsed != null).Select(e => e.AccountUsed!).Distinct().ToList();
        var mostCommon = escalations
            .GroupBy(e => e.Technique)
            .OrderByDescending(g => g.Count())
            .First();

        // Velocity: escalations per day
        var timeSpan = escalations.Max(e => e.DetectedAt) - escalations.Min(e => e.DetectedAt);
        var days = Math.Max(timeSpan.TotalDays, 1);

        return new PrivEscStats
        {
            TotalTechniquesUsed = techniques.Count,
            UniqueAccountsInvolved = accounts.Count,
            MostCommonTechnique = mostCommon.Key,
            AverageConfidence = Math.Round(escalations.Average(e => e.Confidence), 3),
            AutomatedAttempts = escalations.Count(e => e.IsAutomated),
            ManualAttempts = escalations.Count(e => !e.IsAutomated),
            EscalationVelocity = Math.Round(escalations.Count / days, 2)
        };
    }

    // ── Scoring ─────────────────────────────────────────────────────

    private int ComputeThreatScore(List<PrivilegeEscalation> escalations, List<EscalationChain> chains)
    {
        if (escalations.Count == 0) return 0;

        double score = 0;

        // Base score from escalation count and severity
        score += escalations.Count(e => e.Severity == PrivEscSeverity.Critical) * 25;
        score += escalations.Count(e => e.Severity == PrivEscSeverity.High) * 15;
        score += escalations.Count(e => e.Severity == PrivEscSeverity.Medium) * 8;
        score += escalations.Count(e => e.Severity == PrivEscSeverity.Low) * 3;

        // Chain bonus
        score += chains.Count * 10;
        if (chains.Any(c => c.EndPrivilege == "SYSTEM"))
            score += 20;

        // Automated escalation bonus
        if (escalations.Any(e => e.IsAutomated))
            score += 10;

        // Diversity bonus (more techniques = more sophisticated)
        var uniqueTechniques = escalations.Select(e => e.Technique).Distinct().Count();
        if (uniqueTechniques >= 3) score += 10;
        if (uniqueTechniques >= 5) score += 10;

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

    private List<string> GenerateRecommendations(List<PrivilegeEscalation> escalations,
        List<EscalationChain> chains, PrivEscStats stats)
    {
        var recs = new List<string>();

        if (escalations.Count == 0)
        {
            recs.Add("No privilege escalation indicators detected. Continue monitoring.");
            return recs;
        }

        // Technique-specific recommendations
        var techniques = escalations.Select(e => e.Technique).Distinct().ToHashSet();

        if (techniques.Contains("UAC Bypass"))
            recs.Add("Enforce 'Always notify' UAC policy; deploy WDAC to block known bypass tools (fodhelper, eventvwr abuse).");

        if (techniques.Contains("Access Token Manipulation"))
            recs.Add("Restrict SeDebugPrivilege to necessary accounts only; enable Credential Guard.");

        if (techniques.Contains("Process Injection"))
            recs.Add("Enable Attack Surface Reduction (ASR) rules for process injection; deploy EDR with memory protection.");

        if (techniques.Contains("Windows Service Creation"))
            recs.Add("Restrict service creation to authorized administrators; monitor sc.exe and New-Service usage.");

        if (techniques.Contains("DLL Search Order Hijacking"))
            recs.Add("Enable SafeDllSearchMode; audit application directories for writable paths; use DLL signing.");

        if (techniques.Contains("Scheduled Task as SYSTEM"))
            recs.Add("Restrict SYSTEM-level scheduled task creation; audit schtasks.exe usage via command-line logging.");

        if (techniques.Contains("COM Hijacking"))
            recs.Add("Monitor registry changes to CLSID/InprocServer32 keys; baseline legitimate COM objects.");

        if (techniques.Contains("Boot/Logon Autostart"))
            recs.Add("Monitor Run/RunOnce registry keys and Startup folders; use AppLocker to restrict autostart entries.");

        if (techniques.Contains("Valid Accounts: Local Admin"))
            recs.Add("Implement Local Administrator Password Solution (LAPS); minimize local admin group membership.");

        if (techniques.Contains("Exploitation for Privilege Escalation"))
            recs.Add("Prioritize patching for known EoP vulnerabilities; enable exploit protection (EMET/Windows Defender EG).");

        // Chain-level recommendations
        if (chains.Any(c => c.EndPrivilege == "SYSTEM"))
            recs.Add("CRITICAL: Full SYSTEM escalation chain detected — immediate incident response recommended.");

        if (stats.AutomatedAttempts > 0)
            recs.Add("Automated escalation tools detected — investigate for active adversary presence.");

        if (stats.EscalationVelocity > 5)
            recs.Add("High escalation velocity indicates active attack — consider network isolation.");

        // General
        recs.Add("Enable Windows Event Forwarding for Security events 4672, 4673, 4674 (privilege use).");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Match a signature keyword against `text` (already lower-cased).
    /// Multi-word keywords (containing spaces) use substring matching.
    /// Single-token keywords use a word-boundary check so short acronyms like
    /// "lpe" or "eop" don't false-match inside unrelated words (e.g. "fodhelper").
    /// Keywords containing regex metacharacters (e.g. "schtasks.*system")
    /// are treated as already-anchored regex fragments.
    /// </summary>
    private static bool ContainsKeyword(string text, string keyword)
    {
        if (string.IsNullOrEmpty(keyword)) return false;

        // Regex-style keyword (contains an unescaped wildcard)
        if (keyword.Contains(".*") || keyword.Contains("\\"))
        {
            try { return Regex.IsMatch(text, keyword); }
            catch { return false; }
        }

        // Multi-word keyword: substring is fine (the spaces act as boundaries).
        if (keyword.Contains(' ') || keyword.Contains('-'))
            return text.Contains(keyword);

        // Single-token keyword: require word boundaries to avoid intra-word hits.
        return Regex.IsMatch(text, $"\\b{Regex.Escape(keyword)}\\b");
    }

    private List<PrivilegeEscalation> DeduplicateEscalations(List<PrivilegeEscalation> escalations)
    {
        return escalations
            .GroupBy(e => $"{e.Technique}|{e.Evidence}")
            .Select(g => g.First())
            .ToList();
    }

    private static string? ExtractAccount(string text)
    {
        var patterns = new[] { "user:", "account:", "username:", "identity:", "logon:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 40, text.Length);
            var acct = text[start..end].Trim();
            if (acct.Length > 0) return acct;
        }
        return null;
    }

    private static string? ExtractProcess(string text)
    {
        var patterns = new[] { "process:", "executable:", "binary:", "program:" };
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

    private sealed record EscTechniqueSignature(
        string Name, string MitreId, string[] Keywords, double BaseConfidence, string TargetPrivilege);
}
