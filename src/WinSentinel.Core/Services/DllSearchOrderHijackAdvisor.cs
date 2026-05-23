using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic DLL search-order / sideloading hijack advisor.
/// <para>
/// Scores per-process module-load snapshots for the classic
/// MITRE ATT&amp;CK T1574.001 (DLL Search Order Hijacking) and
/// T1574.002 (DLL Side-Loading) vectors. Detects unsigned modules
/// loaded out of writable application directories, name collisions
/// with System32 DLLs, well-known hijack targets (version.dll,
/// msimg32.dll, winhttp.dll, etc.), current-directory side-loads,
/// phantom DLLs satisfied from a writable parent, and high-privilege
/// processes loading risky binaries.
/// </para>
/// <para>
/// Tenth sibling in the agentic services suite alongside
/// <see cref="WmiSubscriptionAbuseAdvisor"/>,
/// <see cref="ScheduledTaskAbuseAdvisor"/>, and
/// <see cref="ServiceTamperingAdvisor"/> — focusing on in-process
/// module-load hygiene rather than persistence surfaces. Answers
/// <em>which running processes are loading hijackable DLLs, and
/// which fixes should ship first?</em>
/// </para>
/// <para>
/// Pure / deterministic — no I/O, no live module enumeration.
/// Caller passes snapshots gathered by their own collector (e.g.
/// ProcessExplorer, Sysmon EventID 7, ETW). Inject time via
/// <see cref="AdvisorContext.NowOverride"/> for reproducible tests.
/// Never mutates inputs.
/// </para>
/// </summary>
public class DllSearchOrderHijackAdvisor
{
    // ── Public model ─────────────────────────────────────────────

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ModuleSource
    {
        Unknown,
        ApplicationDir,
        System32,
        SysWow64,
        Path,
        CurrentDirectory,
        SxS,
        Custom,
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ProcessVerdict
    {
        QuarantineProcess,
        RestrictAndPatch,
        MonitorAndReview,
        Healthy,
    }

    /// <summary>One loaded module observed in a process snapshot.</summary>
    public record ModuleLoad(
        string ModuleName,
        string? FullPath,
        ModuleSource Source,
        bool IsSigned,
        bool SignerTrusted,
        bool ParentDirWritableByNonAdmin,
        bool ShadowsSystem32Name,
        bool AppDirSatisfiedPhantom);

    /// <summary>One process snapshot.</summary>
    public record ProcessSnapshot(
        string ProcessName,
        int Pid,
        string? ImagePath,
        bool RunsAsHighPrivilege,
        bool AutoStart,
        IReadOnlyList<ModuleLoad> LoadedModules);

    public class AdvisorContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;
        public DateTime? NowOverride { get; set; }

        /// <summary>Additional module names treated as well-known hijack targets.</summary>
        public IReadOnlyList<string> ExtraHijackTargets { get; set; } = Array.Empty<string>();
    }

    public record ModuleFinding(
        string ModuleName,
        string? FullPath,
        ModuleSource Source,
        int Severity,
        IReadOnlyList<string> Reasons);

    public record ProcessAssessment(
        string ProcessName,
        int Pid,
        bool RunsAsHighPrivilege,
        bool AutoStart,
        int RiskScore,
        ProcessVerdict Verdict,
        ActionPriority Priority,
        IReadOnlyList<ModuleFinding> ModuleFindings,
        IReadOnlyList<string> Reasons);

    public record PlaybookAction(
        string Id,
        ActionPriority Priority,
        string Label,
        string Owner,
        int BlastRadius,
        string Reversibility,
        string Reason,
        IReadOnlyList<string> RelatedProcessIds);

    public record DllSearchOrderHijackReport(
        DateTime GeneratedAt,
        int TotalProcesses,
        int QuarantineCount,
        int RestrictCount,
        int MonitorCount,
        double MeanRiskScore,
        double MaxRiskScore,
        string Verdict,
        string Grade,
        IReadOnlyList<ProcessAssessment> Assessments,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights);

    // ── Public API ───────────────────────────────────────────────

    public DllSearchOrderHijackReport Analyze(
        IEnumerable<ProcessSnapshot> processes,
        AdvisorContext? ctx = null)
    {
        if (processes is null) throw new ArgumentNullException(nameof(processes));
        ctx ??= new AdvisorContext();
        var list = processes.ToList();
        var now = ctx.NowOverride ?? DateTime.UtcNow;
        double sevMult = ctx.Risk switch
        {
            RiskAppetite.Cautious => 1.15,
            RiskAppetite.Aggressive => 0.85,
            _ => 1.0,
        };

        var extraTargets = new HashSet<string>(
            ctx.ExtraHijackTargets?.Select(s => (s ?? string.Empty).Trim().ToLowerInvariant())
                ?? Array.Empty<string>(),
            StringComparer.Ordinal);

        var assessments = new List<ProcessAssessment>();

        var writableLoaders = new List<string>();
        var unsignedHighPriv = new List<string>();
        var nameCollisions = new List<string>();
        var currentDirSideloads = new List<string>();
        var knownTargets = new List<string>();
        var phantomSatisfied = new List<string>();
        var autoStartHijacks = new List<string>();
        var untrustedSigner = new List<string>();

        bool forceF = false;

        foreach (var p in list)
        {
            var modules = p.LoadedModules ?? (IReadOnlyList<ModuleLoad>)Array.Empty<ModuleLoad>();
            var findings = new List<ModuleFinding>();
            var procReasons = new List<string>();
            var procSevHits = new List<int>();
            string procId = $"{p.ProcessName}#{p.Pid}";

            foreach (var m in modules)
            {
                var reasons = new List<string>();
                var sevHits = new List<int>();

                bool wellKnown = IsWellKnownHijackTarget(m.ModuleName, extraTargets);

                // LOAD_FROM_WRITABLE_PARENT — module loaded from a directory
                // that a non-admin can write to. Textbook DLL planting setup.
                if (m.ParentDirWritableByNonAdmin)
                {
                    sevHits.Add(p.RunsAsHighPrivilege ? 80 : 55);
                    reasons.Add("LOAD_FROM_WRITABLE_PARENT");
                    writableLoaders.Add(procId);
                    if (p.RunsAsHighPrivilege) forceF = true;
                }

                // UNSIGNED_DLL_IN_PRIVILEGED_PROCESS
                if (!m.IsSigned && p.RunsAsHighPrivilege)
                {
                    sevHits.Add(65);
                    reasons.Add("UNSIGNED_DLL_IN_PRIVILEGED_PROCESS");
                    unsignedHighPriv.Add(procId);
                }
                else if (!m.IsSigned)
                {
                    sevHits.Add(30);
                    reasons.Add("UNSIGNED_DLL");
                }

                // UNTRUSTED_SIGNER — signed, but signer not on the trust list.
                if (m.IsSigned && !m.SignerTrusted)
                {
                    sevHits.Add(p.RunsAsHighPrivilege ? 45 : 25);
                    reasons.Add("UNTRUSTED_SIGNER");
                    untrustedSigner.Add(procId);
                }

                // SHADOWS_SYSTEM32_NAME — a non-system file using a System32 DLL
                // name, loaded from the application directory before System32 was
                // consulted. Classic search-order hijack.
                if (m.ShadowsSystem32Name && m.Source == ModuleSource.ApplicationDir)
                {
                    sevHits.Add(p.RunsAsHighPrivilege ? 85 : 60);
                    reasons.Add("SHADOWS_SYSTEM32_NAME");
                    nameCollisions.Add(procId);
                    forceF = true;
                }

                // SIDELOAD_FROM_CURRENT_DIRECTORY — caller resolved the module
                // from the working directory rather than the image directory.
                if (m.Source == ModuleSource.CurrentDirectory)
                {
                    sevHits.Add(p.RunsAsHighPrivilege ? 70 : 45);
                    reasons.Add("SIDELOAD_FROM_CURRENT_DIRECTORY");
                    currentDirSideloads.Add(procId);
                }

                // KNOWN_HIJACK_TARGET — module is on the well-known sideload
                // shortlist (version.dll, msimg32.dll, winhttp.dll, etc.).
                if (wellKnown && m.Source != ModuleSource.System32 && m.Source != ModuleSource.SysWow64)
                {
                    sevHits.Add(p.RunsAsHighPrivilege ? 60 : 40);
                    reasons.Add("KNOWN_HIJACK_TARGET");
                    knownTargets.Add(procId);
                }

                // PHANTOM_DLL_SATISFIED_FROM_APPDIR — DLL referenced but not
                // present in System32; resolved from a writable app dir instead.
                if (m.AppDirSatisfiedPhantom)
                {
                    sevHits.Add(p.RunsAsHighPrivilege ? 75 : 50);
                    reasons.Add("PHANTOM_DLL_SATISFIED_FROM_APPDIR");
                    phantomSatisfied.Add(procId);
                    if (p.RunsAsHighPrivilege) forceF = true;
                }

                // AUTO_START_HIJACK_RISK — process is an auto-start program and
                // has any of the higher-severity reasons above.
                if (p.AutoStart && (m.ParentDirWritableByNonAdmin || m.ShadowsSystem32Name
                                    || m.AppDirSatisfiedPhantom))
                {
                    sevHits.Add(35);
                    reasons.Add("AUTO_START_HIJACK_RISK");
                    autoStartHijacks.Add(procId);
                }

                if (sevHits.Count > 0)
                {
                    sevHits.Sort((a, b) => b.CompareTo(a));
                    int top = sevHits[0];
                    int rest = sevHits.Skip(1).Sum();
                    int restCapped = Math.Min(rest, 50);
                    int sev = (int)Math.Round(Math.Clamp((top + 0.4 * restCapped) * sevMult, 0, 100));
                    findings.Add(new ModuleFinding(m.ModuleName, m.FullPath, m.Source, sev, reasons));
                    procSevHits.Add(sev);
                    foreach (var r in reasons)
                        if (!procReasons.Contains(r)) procReasons.Add(r);
                }
            }

            int risk;
            if (procSevHits.Count == 0)
            {
                risk = 0;
                procReasons.Add("HEALTHY");
            }
            else
            {
                procSevHits.Sort((a, b) => b.CompareTo(a));
                int top = procSevHits[0];
                int rest = procSevHits.Skip(1).Sum();
                int restCapped = Math.Min(rest, 60);
                risk = (int)Math.Round(Math.Clamp(top + 0.4 * restCapped, 0, 100));
            }

            ProcessVerdict verdict;
            ActionPriority priority;
            if (risk >= 75)
            {
                verdict = ProcessVerdict.QuarantineProcess;
                priority = ActionPriority.P0;
            }
            else if (risk >= 50)
            {
                verdict = ProcessVerdict.RestrictAndPatch;
                priority = ActionPriority.P1;
            }
            else if (risk >= 25)
            {
                verdict = ProcessVerdict.MonitorAndReview;
                priority = ActionPriority.P2;
            }
            else
            {
                verdict = ProcessVerdict.Healthy;
                priority = ActionPriority.P3;
            }

            // Stable per-process finding sort: severity desc, module name asc.
            findings.Sort((a, b) =>
            {
                int s = b.Severity.CompareTo(a.Severity);
                if (s != 0) return s;
                return string.CompareOrdinal(a.ModuleName, b.ModuleName);
            });

            assessments.Add(new ProcessAssessment(
                p.ProcessName, p.Pid, p.RunsAsHighPrivilege, p.AutoStart,
                risk, verdict, priority, findings, procReasons));
        }

        assessments.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            int r = b.RiskScore.CompareTo(a.RiskScore);
            if (r != 0) return r;
            int n = string.CompareOrdinal(a.ProcessName, b.ProcessName);
            if (n != 0) return n;
            return a.Pid.CompareTo(b.Pid);
        });

        int total = list.Count;
        int qCount = assessments.Count(a => a.Verdict == ProcessVerdict.QuarantineProcess);
        int rCount = assessments.Count(a => a.Verdict == ProcessVerdict.RestrictAndPatch);
        int mCount = assessments.Count(a => a.Verdict == ProcessVerdict.MonitorAndReview);
        double meanRisk = assessments.Count == 0 ? 0 : assessments.Average(a => a.RiskScore);
        double maxRisk = assessments.Count == 0 ? 0 : assessments.Max(a => a.RiskScore);

        string verdictStr;
        string grade;
        if (total == 0)
        {
            verdictStr = "NO_DATA";
            grade = "A";
        }
        else if (qCount > 0 || forceF)
        {
            verdictStr = "DLL_HIJACK_ABUSE_SUSPECTED";
            grade = "F";
        }
        else if (rCount > 0 || maxRisk >= 50)
        {
            verdictStr = "DEGRADED_LOAD_HYGIENE";
            grade = maxRisk >= 65 ? "D" : "C";
        }
        else if (mCount > 0 || maxRisk >= 25)
        {
            verdictStr = "MINOR_DRIFT";
            grade = "B";
        }
        else
        {
            verdictStr = "HEALTHY";
            grade = "A";
        }

        var playbook = BuildPlaybook(
            ctx.Risk, grade,
            writableLoaders.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            unsignedHighPriv.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            nameCollisions.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            currentDirSideloads.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            knownTargets.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            phantomSatisfied.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            autoStartHijacks.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            untrustedSigner.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
            total);

        var insights = new List<string>();
        if (nameCollisions.Count > 0)
            insights.Add($"SYSTEM32_NAME_COLLISIONS:{nameCollisions.Distinct().Count()}");
        if (phantomSatisfied.Count > 0)
            insights.Add($"PHANTOM_DLLS_RESOLVED_FROM_APPDIR:{phantomSatisfied.Distinct().Count()}");
        if (writableLoaders.Count >= 2)
            insights.Add($"WRITABLE_LOAD_PATH_CLUSTER:{writableLoaders.Distinct().Count()}");
        if (unsignedHighPriv.Count > 0)
            insights.Add($"UNSIGNED_IN_PRIVILEGED_PROCESSES:{unsignedHighPriv.Distinct().Count()}");
        if (knownTargets.Count > 0)
            insights.Add($"KNOWN_HIJACK_TARGETS_LOADED:{knownTargets.Distinct().Count()}");
        if (currentDirSideloads.Count > 0)
            insights.Add($"CURRENT_DIRECTORY_SIDELOADS:{currentDirSideloads.Distinct().Count()}");
        if (autoStartHijacks.Count > 0)
            insights.Add($"AUTO_START_HIJACK_EXPOSURE:{autoStartHijacks.Distinct().Count()}");
        if (untrustedSigner.Count >= 2)
            insights.Add($"UNTRUSTED_SIGNER_CLUSTER:{untrustedSigner.Distinct().Count()}");
        if (total > 0 && qCount == 0 && rCount == 0 && mCount == 0)
            insights.Add("ALL_PROCESSES_HEALTHY");

        return new DllSearchOrderHijackReport(
            GeneratedAt: now,
            TotalProcesses: total,
            QuarantineCount: qCount,
            RestrictCount: rCount,
            MonitorCount: mCount,
            MeanRiskScore: Math.Round(meanRisk, 2),
            MaxRiskScore: Math.Round(maxRisk, 2),
            Verdict: verdictStr,
            Grade: grade,
            Assessments: assessments,
            Playbook: playbook,
            Insights: insights);
    }

    public string ToMarkdown(DllSearchOrderHijackReport report)
    {
        if (report is null) throw new ArgumentNullException(nameof(report));
        var sb = new StringBuilder();
        sb.AppendLine("# DLL Search Order Hijack Report");
        sb.AppendLine();
        sb.AppendLine($"- Generated: {report.GeneratedAt:O}");
        sb.AppendLine($"- Total processes: {report.TotalProcesses}");
        sb.AppendLine($"- Quarantine: {report.QuarantineCount} | Restrict: {report.RestrictCount} | Monitor: {report.MonitorCount}");
        sb.AppendLine($"- Mean risk: {report.MeanRiskScore:F2} | Max risk: {report.MaxRiskScore:F2}");
        sb.AppendLine($"- Verdict: **{report.Verdict}** | Grade: **{report.Grade}**");
        sb.AppendLine();

        sb.AppendLine("## Processes");
        if (report.Assessments.Count == 0)
        {
            sb.AppendLine("_(no processes analyzed)_");
        }
        else
        {
            sb.AppendLine("| Process | PID | Priv | AutoStart | Risk | Verdict | Priority | Top modules |");
            sb.AppendLine("|---|---:|---|---|---:|---|---|---|");
            foreach (var a in report.Assessments)
            {
                string topMods = string.Join(", ", a.ModuleFindings.Take(3).Select(m => $"{m.ModuleName} ({m.Severity})"));
                sb.AppendLine($"| {a.ProcessName} | {a.Pid} | {(a.RunsAsHighPrivilege ? "high" : "user")} | {(a.AutoStart ? "yes" : "no")} | {a.RiskScore} | {a.Verdict} | {a.Priority} | {topMods} |");
            }
        }
        sb.AppendLine();

        sb.AppendLine("## Playbook");
        if (report.Playbook.Count == 0)
        {
            sb.AppendLine("_(no actions)_");
        }
        else
        {
            sb.AppendLine("| Priority | Action | Owner | Blast | Reversibility | Processes |");
            sb.AppendLine("|---|---|---|---:|---|---|");
            foreach (var p in report.Playbook)
            {
                sb.AppendLine($"| {p.Priority} | {p.Label} ({p.Id}) | {p.Owner} | {p.BlastRadius} | {p.Reversibility} | {string.Join(", ", p.RelatedProcessIds)} |");
            }
        }
        sb.AppendLine();

        sb.AppendLine("## Insights");
        if (report.Insights.Count == 0)
        {
            sb.AppendLine("- (none)");
        }
        else
        {
            foreach (var i in report.Insights) sb.AppendLine($"- {i}");
        }
        return sb.ToString();
    }

    public string ToJson(DllSearchOrderHijackReport report)
    {
        if (report is null) throw new ArgumentNullException(nameof(report));
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        };
        return JsonSerializer.Serialize(report, opts);
    }

    // ── Internals ────────────────────────────────────────────────

    // Module names historically abused as DLL sideload / search-order targets.
    // Source: public threat-intel writeups, MITRE T1574.001 / T1574.002 catalog.
    private static readonly HashSet<string> WellKnownHijackTargets = new(StringComparer.Ordinal)
    {
        "version.dll",
        "msimg32.dll",
        "winhttp.dll",
        "winmm.dll",
        "dwmapi.dll",
        "uxtheme.dll",
        "secur32.dll",
        "wlbsctrl.dll",
        "wbemcomn.dll",
        "iertutil.dll",
        "cryptbase.dll",
        "ntmarta.dll",
        "fxsst.dll",
        "vssapi.dll",
        "schannel.dll",
        "dbghelp.dll",
        "comctl32.dll",
        "rsaenh.dll",
        "wlanapi.dll",
    };

    private static bool IsWellKnownHijackTarget(string moduleName, HashSet<string> extra)
    {
        if (string.IsNullOrWhiteSpace(moduleName)) return false;
        var key = moduleName.Trim().ToLowerInvariant();
        if (!key.EndsWith(".dll", StringComparison.Ordinal)) key += ".dll";
        return WellKnownHijackTargets.Contains(key) || extra.Contains(key);
    }

    private static List<PlaybookAction> BuildPlaybook(
        RiskAppetite risk,
        string grade,
        List<string> writableLoaders,
        List<string> unsignedHighPriv,
        List<string> nameCollisions,
        List<string> currentDirSideloads,
        List<string> knownTargets,
        List<string> phantomSatisfied,
        List<string> autoStartHijacks,
        List<string> untrustedSigner,
        int total)
    {
        var actions = new List<PlaybookAction>();

        if (nameCollisions.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "QUARANTINE_SYSTEM32_NAME_COLLISIONS",
                ActionPriority.P0,
                "Quarantine processes loading non-system files that shadow System32 DLL names",
                "incident_response",
                BlastRadius: 5,
                Reversibility: "low",
                Reason: "A non-system DLL with a System32 name loaded from the application directory is a textbook DLL search-order hijack (MITRE T1574.001).",
                RelatedProcessIds: nameCollisions));
        }

        if (phantomSatisfied.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "REMOVE_PHANTOM_DLL_HIJACKS",
                ActionPriority.P0,
                "Remove phantom DLLs satisfied from writable application directories",
                "incident_response",
                BlastRadius: 4,
                Reversibility: "medium",
                Reason: "Phantom DLLs (referenced but missing from System32) resolved out of a writable app directory let an attacker plant code that always wins the search.",
                RelatedProcessIds: phantomSatisfied));
        }

        if (writableLoaders.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "TIGHTEN_WRITABLE_APPLICATION_DIRECTORIES",
                ActionPriority.P0,
                "Tighten ACLs on writable application directories used by privileged processes",
                "platform_admin",
                BlastRadius: 3,
                Reversibility: "high",
                Reason: "Non-admin-writable parent directories are the precondition for every DLL planting attack.",
                RelatedProcessIds: writableLoaders));
        }

        if (currentDirSideloads.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "DISABLE_CURRENT_DIRECTORY_SEARCH",
                ActionPriority.P1,
                "Force SetDefaultDllDirectories / safe DLL search mode for affected processes",
                "platform_admin",
                BlastRadius: 3,
                Reversibility: "high",
                Reason: "Modules resolved from the working directory bypass System32 — enable LOAD_LIBRARY_SEARCH_SYSTEM32 / SafeDllSearchMode to fix.",
                RelatedProcessIds: currentDirSideloads));
        }

        if (unsignedHighPriv.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "BLOCK_UNSIGNED_IN_PRIVILEGED_PROCESSES",
                ActionPriority.P1,
                "Block unsigned DLL loads in privileged processes via WDAC / mitigation policy",
                "platform_admin",
                BlastRadius: 3,
                Reversibility: "medium",
                Reason: "Privileged processes loading unsigned modules expand the kernel-adjacent attack surface; enforce signature gating.",
                RelatedProcessIds: unsignedHighPriv));
        }

        if (knownTargets.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "REPLACE_KNOWN_HIJACK_TARGETS",
                ActionPriority.P1,
                "Replace well-known sideload targets (version.dll, msimg32.dll, winhttp.dll, ...) with signed system copies",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "These DLL names are repeatedly abused as sideload anchors in real intrusions and should always come from System32.",
                RelatedProcessIds: knownTargets));
        }

        if (autoStartHijacks.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "AUDIT_AUTO_START_DLL_LOADS",
                ActionPriority.P1,
                "Audit auto-starting processes with hijackable DLL loads",
                "platform_admin",
                BlastRadius: 3,
                Reversibility: "high",
                Reason: "Auto-start + hijackable load surface = automatic persistence on every boot if an attacker plants a DLL once.",
                RelatedProcessIds: autoStartHijacks));
        }

        if (untrustedSigner.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "REVIEW_UNTRUSTED_SIGNERS",
                ActionPriority.P2,
                "Review DLLs signed by publishers not on the trust list",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Signed-but-untrusted modules often indicate bundled third-party software or stolen-cert sideloads worth attribution.",
                RelatedProcessIds: untrustedSigner));
        }

        // Cautious adds an audit sweep when grade is poor.
        if (risk == RiskAppetite.Cautious && (grade == "C" || grade == "D" || grade == "F"))
        {
            actions.Add(new PlaybookAction(
                "SCHEDULE_DLL_LOAD_AUDIT",
                ActionPriority.P2,
                "Schedule a fleet-wide module-load audit",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: "Grade indicates posture drift; a planned sweep catches what we missed.",
                RelatedProcessIds: new List<string>()));
        }

        if (actions.Count == 0)
        {
            actions.Add(new PlaybookAction(
                "ALL_PROCESSES_HEALTHY",
                ActionPriority.P3,
                "Maintain DLL load monitoring",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: total == 0
                    ? "No processes were provided; keep the collector running."
                    : "No hijack indicators detected; continue routine monitoring.",
                RelatedProcessIds: new List<string>()));
        }

        if (risk == RiskAppetite.Aggressive && actions.Count > 1)
        {
            actions = actions.Where(a => a.Priority != ActionPriority.P3).ToList();
        }

        actions.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            return string.CompareOrdinal(a.Id, b.Id);
        });
        return actions;
    }
}
