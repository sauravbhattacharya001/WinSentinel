using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic fix-execution planner. Given a set of selected findings (or a full report),
/// it produces a safe, ordered, multi-phase playbook that answers
/// "in what order do I actually run these fixes, and what do I need to be careful about?"
///
/// Complements existing services:
///   <see cref="RemediationCostEstimator"/> answers "how much will it cost?"
///   <see cref="FindingDependencyAnalyzer"/> answers "which fixes cascade-resolve others?"
///   <see cref="HardenScriptGenerator"/> answers "what commands do I run?"
///   <c>FixOrchestrationPlanner</c> answers "in what order, batched how, with what guard-rails?"
///
/// The planner is intentionally heuristic-driven and offline (no LLM): it classifies each
/// fix into one of six execution phases, batches reboot-requiring fixes together,
/// flags business-hours risk windows, and emits rollback hints — all from the
/// finding text + auto-fix command shape. Output is renderable as text, markdown, or JSON.
/// </summary>
public sealed class FixOrchestrationPlanner
{
    // ── Phases (ordered: lower number runs first) ────────────────────

    /// <summary>Logical phases of a fix playbook. Lower index runs first.</summary>
    public enum Phase
    {
        /// <summary>Preconditions: snapshots, restore points, elevation, baselining.</summary>
        Preconditions = 0,
        /// <summary>Foundation: turn protective controls back on (Defender, Firewall, Updates, UAC).</summary>
        Foundation = 1,
        /// <summary>Hardening: account/registry/service/policy tightening that doesn't move data.</summary>
        Hardening = 2,
        /// <summary>Containment: kill processes, quarantine files, block IPs, disable accounts.</summary>
        Containment = 3,
        /// <summary>Cleanup: uninstall outdated apps, remove startup entries, prune scheduled tasks.</summary>
        Cleanup = 4,
        /// <summary>Verification: re-run impacted audits / smoke checks to confirm the fix landed.</summary>
        Verification = 5,
    }

    // ── Result models ────────────────────────────────────────────────

    /// <summary>A single planned fix step.</summary>
    public sealed class PlannedStep
    {
        public int Order { get; set; }
        public Phase Phase { get; set; }
        public required string Title { get; set; }
        public required string Category { get; set; }
        public Severity Severity { get; set; }
        public bool HasAutoFix { get; set; }
        public string? FixCommand { get; set; }
        public string? Remediation { get; set; }

        /// <summary>True if applying this fix typically requires (or benefits from) a reboot.</summary>
        public bool RequiresReboot { get; set; }

        /// <summary>True if this fix can disrupt user-facing services (block IP, disable account, kill process).</summary>
        public bool DisruptsUsers { get; set; }

        /// <summary>True if this fix is hard to roll back automatically.</summary>
        public bool DestructiveOrIrreversible { get; set; }

        /// <summary>Estimated blast radius: 1 (local registry tweak) → 5 (kicks users off network).</summary>
        public int BlastRadius { get; set; }

        /// <summary>Index of the reboot batch this step belongs to (0 = no reboot, 1+ = batch number).</summary>
        public int RebootBatch { get; set; }

        /// <summary>Suggested rollback action (human-readable).</summary>
        public string? RollbackHint { get; set; }

        /// <summary>Why the planner placed this step here.</summary>
        public string Rationale { get; set; } = string.Empty;
    }

    /// <summary>A reboot grouping (so the user reboots once for several fixes).</summary>
    public sealed class RebootBatch
    {
        public int BatchNumber { get; set; }
        public List<int> StepOrders { get; set; } = new();
        public string Reason { get; set; } = string.Empty;
    }

    /// <summary>Top-level orchestration plan.</summary>
    public sealed class OrchestrationPlan
    {
        public DateTimeOffset GeneratedAt { get; set; }
        public int TotalSteps { get; set; }
        public int AutoFixableSteps { get; set; }
        public int DestructiveSteps { get; set; }
        public int DisruptiveSteps { get; set; }
        public int RebootBatchCount { get; set; }
        public List<PlannedStep> Steps { get; set; } = new();
        public List<RebootBatch> RebootBatches { get; set; } = new();
        public List<string> RiskWindowWarnings { get; set; } = new();
        public List<string> PreflightChecklist { get; set; } = new();
        public List<string> Notes { get; set; } = new();
    }

    /// <summary>Optional planner inputs.</summary>
    public sealed class PlanOptions
    {
        /// <summary>If true, planner flags disruptive steps as "avoid during business hours".</summary>
        public bool RespectBusinessHours { get; set; } = true;

        /// <summary>If true, planner inserts a "create system restore point" Preconditions step.</summary>
        public bool IncludeRestorePoint { get; set; } = true;

        /// <summary>If true, planner appends a Verification phase that re-runs impacted modules.</summary>
        public bool IncludeVerification { get; set; } = true;

        /// <summary>If &gt; 0, only the top N findings (by severity, then category) are planned.</summary>
        public int MaxSteps { get; set; } = 0;
    }

    // ── Public API ───────────────────────────────────────────────────

    /// <summary>Plan execution for every actionable finding in a full security report.</summary>
    public OrchestrationPlan Plan(SecurityReport report, PlanOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        var findings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity is not Severity.Pass)
            .ToList();
        return Plan(findings, options);
    }

    /// <summary>Plan execution for an explicit list of findings (e.g. user-selected from a UI).</summary>
    public OrchestrationPlan Plan(IEnumerable<Finding> findings, PlanOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(findings);
        options ??= new PlanOptions();

        var actionable = findings
            .Where(f => f is not null && f.Severity is not Severity.Pass)
            .ToList();

        if (options.MaxSteps > 0 && actionable.Count > options.MaxSteps)
        {
            actionable = actionable
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Category)
                .Take(options.MaxSteps)
                .ToList();
        }

        var steps = new List<PlannedStep>();

        // 1) Preconditions phase
        if (options.IncludeRestorePoint && actionable.Count > 0)
        {
            steps.Add(new PlannedStep
            {
                Phase = Phase.Preconditions,
                Title = "Create System Restore Point",
                Category = "Preflight",
                Severity = Severity.Info,
                HasAutoFix = true,
                FixCommand = "Checkpoint-Computer -Description 'WinSentinel pre-remediation' -RestorePointType MODIFY_SETTINGS",
                Remediation = "Take a system restore point before applying remediations so the entire batch can be reverted.",
                RequiresReboot = false,
                DisruptsUsers = false,
                DestructiveOrIrreversible = false,
                BlastRadius = 1,
                RollbackHint = "Restore points can be removed via System Properties → System Protection.",
                Rationale = "Insurance against any destructive step further down the plan.",
            });
        }

        // 2) Classify every finding into a phase + risk profile
        foreach (var f in actionable)
        {
            steps.Add(Classify(f));
        }

        // 3) Optional Verification phase (one step per impacted module)
        if (options.IncludeVerification && actionable.Count > 0)
        {
            var impactedCategories = actionable
                .Select(f => string.IsNullOrWhiteSpace(f.Category) ? "General" : f.Category)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(c => c, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var cat in impactedCategories)
            {
                steps.Add(new PlannedStep
                {
                    Phase = Phase.Verification,
                    Title = $"Re-audit {cat} module",
                    Category = cat,
                    Severity = Severity.Info,
                    HasAutoFix = true,
                    FixCommand = $"winsentinel audit --module \"{cat}\"",
                    Remediation = $"Re-run the {cat} audit to confirm the previously-flagged findings are resolved.",
                    RequiresReboot = false,
                    DisruptsUsers = false,
                    DestructiveOrIrreversible = false,
                    BlastRadius = 1,
                    RollbackHint = null,
                    Rationale = "Verifies that the remediation actually landed and no regressions were introduced.",
                });
            }
        }

        // 4) Stable order: by Phase, then severity DESC, then category, then title
        steps = steps
            .OrderBy(s => (int)s.Phase)
            .ThenByDescending(s => (int)s.Severity)
            .ThenBy(s => s.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 5) Reboot batching: group every reboot-requiring step inside the same phase into a single batch
        var rebootBatches = new List<RebootBatch>();
        int batchCounter = 0;
        Phase? currentPhase = null;
        RebootBatch? openBatch = null;

        for (int i = 0; i < steps.Count; i++)
        {
            var s = steps[i];
            s.Order = i + 1;

            if (!s.RequiresReboot)
            {
                continue;
            }

            if (openBatch is null || currentPhase != s.Phase)
            {
                batchCounter++;
                currentPhase = s.Phase;
                openBatch = new RebootBatch
                {
                    BatchNumber = batchCounter,
                    Reason = $"Reboot batch for {s.Phase} phase",
                };
                rebootBatches.Add(openBatch);
            }

            s.RebootBatch = openBatch.BatchNumber;
            openBatch.StepOrders.Add(s.Order);
        }

        // 6) Risk-window warnings
        var warnings = new List<string>();
        if (options.RespectBusinessHours)
        {
            var disruptive = steps
                .Where(s => s.DisruptsUsers)
                .GroupBy(s => s.Category, StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase);

            foreach (var g in disruptive)
            {
                warnings.Add($"{g.Count()} disruptive step(s) in {g.Key} — schedule outside business hours (e.g. 22:00–05:00).");
            }

            if (rebootBatches.Count > 0)
            {
                warnings.Add($"{rebootBatches.Count} reboot batch(es) planned — coordinate maintenance windows accordingly.");
            }
        }

        // 7) Preflight checklist
        var preflight = new List<string>
        {
            "Run PowerShell as Administrator.",
            "Close any non-essential applications.",
            "Have console / out-of-band access ready (in case a network-related fix locks you out).",
        };
        if (options.IncludeRestorePoint) preflight.Add("Confirm system restore point was created successfully.");
        if (steps.Any(s => s.DestructiveOrIrreversible))
            preflight.Add("Review every step flagged ⚠ DESTRUCTIVE — these cannot be auto-rolled-back.");

        // 8) Build plan
        return new OrchestrationPlan
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            TotalSteps = steps.Count,
            AutoFixableSteps = steps.Count(s => s.HasAutoFix),
            DestructiveSteps = steps.Count(s => s.DestructiveOrIrreversible),
            DisruptiveSteps = steps.Count(s => s.DisruptsUsers),
            RebootBatchCount = rebootBatches.Count,
            Steps = steps,
            RebootBatches = rebootBatches,
            RiskWindowWarnings = warnings,
            PreflightChecklist = preflight,
            Notes = BuildNotes(steps, rebootBatches),
        };
    }

    // ── Classification heuristics ────────────────────────────────────

    private static PlannedStep Classify(Finding f)
    {
        var title = f.Title ?? string.Empty;
        var category = string.IsNullOrWhiteSpace(f.Category) ? "General" : f.Category;
        var rem = f.Remediation ?? string.Empty;
        var fix = f.FixCommand ?? string.Empty;
        var hay = $"{title} {category} {rem} {fix}".ToLowerInvariant();

        var phase = ChoosePhase(hay, category);
        var requiresReboot = NeedsReboot(hay);
        var disrupts = IsDisruptive(hay);
        var destructive = IsDestructive(hay);
        var blast = EstimateBlastRadius(hay, f.Severity);

        return new PlannedStep
        {
            Phase = phase,
            Title = string.IsNullOrWhiteSpace(title) ? "(unnamed finding)" : title,
            Category = category,
            Severity = f.Severity,
            HasAutoFix = !string.IsNullOrWhiteSpace(f.FixCommand),
            FixCommand = f.FixCommand,
            Remediation = f.Remediation,
            RequiresReboot = requiresReboot,
            DisruptsUsers = disrupts,
            DestructiveOrIrreversible = destructive,
            BlastRadius = blast,
            RollbackHint = SuggestRollback(phase, hay),
            Rationale = ExplainPhase(phase),
        };
    }

    private static Phase ChoosePhase(string hay, string category)
    {
        // Foundation: re-enable protective controls
        if (Contains(hay, "firewall", "defender", "real-time protection", "tamper protection",
                    "windows update", "automatic update", "uac", "user account control",
                    "smartscreen", "secure boot", "bitlocker"))
            return Phase.Foundation;

        // Containment: active threats / disruption
        if (Contains(hay, "kill process", "quarantine", "block ip", "disable account",
                    "isolate", "suspend", "terminate", "revoke session"))
            return Phase.Containment;

        // Cleanup: uninstall / remove
        if (Contains(hay, "uninstall", "remove startup", "remove scheduled task",
                    "remove run key", "delete shortcut", "outdated software", "end of life",
                    " eol"))
            return Phase.Cleanup;

        // Hardening: registry, policy, account, service tightening
        if (Contains(hay, "registry", "policy", "audit policy", "password policy",
                    "permissions", "acl", "harden", "disable service", "disable feature",
                    "smb1", "llmnr", "netbios", "telnet", "guest account"))
            return Phase.Hardening;

        // Category-based fallback
        if (category.Equals("Firewall", StringComparison.OrdinalIgnoreCase)
            || category.Equals("Defender", StringComparison.OrdinalIgnoreCase)
            || category.Equals("Windows Update", StringComparison.OrdinalIgnoreCase))
            return Phase.Foundation;

        if (category.Equals("Processes", StringComparison.OrdinalIgnoreCase)
            || category.Equals("Network", StringComparison.OrdinalIgnoreCase))
            return Phase.Containment;

        if (category.Equals("Software Inventory", StringComparison.OrdinalIgnoreCase)
            || category.Equals("App Security", StringComparison.OrdinalIgnoreCase))
            return Phase.Cleanup;

        return Phase.Hardening;
    }

    private static bool NeedsReboot(string hay) => Contains(hay,
        "reboot", "restart required", "requires restart", "secure boot",
        "bitlocker", "kernel", "driver", "boot configuration", "bcdedit",
        "feature install", "feature uninstall", "dism", "windows update install");

    private static bool IsDisruptive(string hay) => Contains(hay,
        "block ip", "disable account", "kill process", "terminate", "disable service",
        "stop service", "isolate", "revoke session", "lockdown", "network disable");

    private static bool IsDestructive(string hay) => Contains(hay,
        "uninstall", "delete", "wipe", "remove user", "remove account",
        "format", "reset password", "purge", "revoke certificate");

    private static int EstimateBlastRadius(string hay, Severity sev)
    {
        int radius = sev switch
        {
            Severity.Critical => 3,
            Severity.Warning => 2,
            Severity.Info => 1,
            _ => 1,
        };
        if (Contains(hay, "block ip", "isolate", "network disable", "firewall disable all")) radius += 2;
        else if (Contains(hay, "disable account", "kill process", "stop service")) radius += 1;
        return Math.Clamp(radius, 1, 5);
    }

    private static string? SuggestRollback(Phase phase, string hay) => phase switch
    {
        Phase.Preconditions => null,
        Phase.Foundation when Contains(hay, "firewall") =>
            "Re-disable via Set-NetFirewallProfile -Profile <name> -Enabled False (not recommended).",
        Phase.Foundation when Contains(hay, "defender") =>
            "Disable RTP via Set-MpPreference -DisableRealtimeMonitoring $true (not recommended).",
        Phase.Containment when Contains(hay, "block ip") =>
            "Remove-NetFirewallRule -DisplayName <rule-name>",
        Phase.Containment when Contains(hay, "disable account") =>
            "Enable-LocalUser -Name <user>",
        Phase.Containment when Contains(hay, "kill process") =>
            "Process termination is irreversible; restart the application if needed.",
        Phase.Cleanup when Contains(hay, "uninstall") =>
            "Reinstall the package from its original installer / vendor source.",
        Phase.Hardening when Contains(hay, "registry") =>
            "Restore previous registry value (consider importing a pre-fix .reg export).",
        _ => "Restore from system restore point taken in Preconditions phase.",
    };

    private static string ExplainPhase(Phase phase) => phase switch
    {
        Phase.Preconditions => "Snapshot/preflight step; must run before any mutating fix.",
        Phase.Foundation => "Re-enables protective controls so all later fixes execute under a hardened baseline.",
        Phase.Hardening => "Tightens policy/registry/account configuration; safe to batch.",
        Phase.Containment => "Actively responds to live threats; can disrupt users — schedule carefully.",
        Phase.Cleanup => "Removes outdated/unused surface area after foundation and hardening are in place.",
        Phase.Verification => "Confirms remediation success via a re-audit of impacted modules.",
        _ => string.Empty,
    };

    private static List<string> BuildNotes(List<PlannedStep> steps, List<RebootBatch> batches)
    {
        var notes = new List<string>();
        if (steps.Count == 0) return notes;

        var byPhase = steps.GroupBy(s => s.Phase).OrderBy(g => (int)g.Key);
        foreach (var g in byPhase)
        {
            notes.Add($"{g.Key}: {g.Count()} step(s)");
        }

        if (batches.Count > 0)
        {
            notes.Add($"Reboot batches consolidate {batches.Sum(b => b.StepOrders.Count)} reboot-requiring step(s) into {batches.Count} reboot(s).");
        }

        var manual = steps.Count(s => !s.HasAutoFix);
        if (manual > 0)
        {
            notes.Add($"{manual} step(s) have no auto-fix command and require manual execution.");
        }

        return notes;
    }

    private static bool Contains(string hay, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (!string.IsNullOrEmpty(n) && hay.Contains(n, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // ── Formatters ───────────────────────────────────────────────────

    /// <summary>Render the plan as a human-readable text playbook.</summary>
    public static string RenderText(OrchestrationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine("  ╔══════════════════════════════════════════════════╗");
        sb.AppendLine("  ║   🛠   Fix Orchestration Plan                    ║");
        sb.AppendLine("  ╚══════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"  Generated:        {plan.GeneratedAt:u}");
        sb.AppendLine($"  Total steps:      {plan.TotalSteps}");
        sb.AppendLine($"  Auto-fixable:     {plan.AutoFixableSteps}");
        sb.AppendLine($"  Disruptive:       {plan.DisruptiveSteps}");
        sb.AppendLine($"  Destructive:      {plan.DestructiveSteps}");
        sb.AppendLine($"  Reboot batches:   {plan.RebootBatchCount}");
        sb.AppendLine();

        if (plan.PreflightChecklist.Count > 0)
        {
            sb.AppendLine("  PREFLIGHT CHECKLIST");
            sb.AppendLine("  ──────────────────────────────────────────────────");
            foreach (var p in plan.PreflightChecklist) sb.AppendLine($"   [ ] {p}");
            sb.AppendLine();
        }

        if (plan.RiskWindowWarnings.Count > 0)
        {
            sb.AppendLine("  ⚠  RISK-WINDOW WARNINGS");
            sb.AppendLine("  ──────────────────────────────────────────────────");
            foreach (var w in plan.RiskWindowWarnings) sb.AppendLine($"   - {w}");
            sb.AppendLine();
        }

        Phase? lastPhase = null;
        foreach (var s in plan.Steps)
        {
            if (lastPhase != s.Phase)
            {
                sb.AppendLine();
                sb.AppendLine($"  ── PHASE: {s.Phase.ToString().ToUpperInvariant()} ──");
                lastPhase = s.Phase;
            }

            var tags = new List<string>();
            if (s.HasAutoFix) tags.Add("⚡auto");
            if (s.RequiresReboot) tags.Add($"⟳reboot#{s.RebootBatch}");
            if (s.DisruptsUsers) tags.Add("👥disruptive");
            if (s.DestructiveOrIrreversible) tags.Add("⚠destructive");
            var tagStr = tags.Count > 0 ? $" [{string.Join(' ', tags)}]" : string.Empty;

            sb.AppendLine($"  {s.Order,3}. [{s.Severity}] {s.Title}{tagStr}");
            sb.AppendLine($"        category={s.Category}  blast-radius={s.BlastRadius}/5");
            if (!string.IsNullOrWhiteSpace(s.Rationale))
                sb.AppendLine($"        why:      {s.Rationale}");
            if (!string.IsNullOrWhiteSpace(s.FixCommand))
                sb.AppendLine($"        fix:      {s.FixCommand}");
            if (!string.IsNullOrWhiteSpace(s.RollbackHint))
                sb.AppendLine($"        rollback: {s.RollbackHint}");
        }

        if (plan.RebootBatches.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("  REBOOT BATCHES");
            sb.AppendLine("  ──────────────────────────────────────────────────");
            foreach (var b in plan.RebootBatches)
            {
                sb.AppendLine($"   Batch #{b.BatchNumber}: steps {string.Join(", ", b.StepOrders)}  ({b.Reason})");
            }
        }

        if (plan.Notes.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("  NOTES");
            sb.AppendLine("  ──────────────────────────────────────────────────");
            foreach (var n in plan.Notes) sb.AppendLine($"   - {n}");
        }

        sb.AppendLine();
        return sb.ToString();
    }

    /// <summary>Render the plan as Markdown (suitable for runbooks / PRs).</summary>
    public static string RenderMarkdown(OrchestrationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var sb = new StringBuilder();
        sb.AppendLine("# 🛠 Fix Orchestration Plan");
        sb.AppendLine();
        sb.AppendLine($"_Generated {plan.GeneratedAt:u}_");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|---|---:|");
        sb.AppendLine($"| Total steps | {plan.TotalSteps} |");
        sb.AppendLine($"| Auto-fixable | {plan.AutoFixableSteps} |");
        sb.AppendLine($"| Disruptive | {plan.DisruptiveSteps} |");
        sb.AppendLine($"| Destructive | {plan.DestructiveSteps} |");
        sb.AppendLine($"| Reboot batches | {plan.RebootBatchCount} |");
        sb.AppendLine();

        if (plan.PreflightChecklist.Count > 0)
        {
            sb.AppendLine("## Preflight");
            foreach (var p in plan.PreflightChecklist) sb.AppendLine($"- [ ] {p}");
            sb.AppendLine();
        }

        if (plan.RiskWindowWarnings.Count > 0)
        {
            sb.AppendLine("## ⚠ Risk-window warnings");
            foreach (var w in plan.RiskWindowWarnings) sb.AppendLine($"- {w}");
            sb.AppendLine();
        }

        var phases = plan.Steps.GroupBy(s => s.Phase).OrderBy(g => (int)g.Key);
        foreach (var g in phases)
        {
            sb.AppendLine($"## Phase: {g.Key}");
            sb.AppendLine();
            sb.AppendLine("| # | Severity | Title | Category | Auto | Reboot | Risk | Blast |");
            sb.AppendLine("|---:|---|---|---|:-:|:-:|:-:|:-:|");
            foreach (var s in g)
            {
                var auto = s.HasAutoFix ? "⚡" : "";
                var reboot = s.RequiresReboot ? $"#{s.RebootBatch}" : "";
                var risk = s.DestructiveOrIrreversible ? "⚠" : (s.DisruptsUsers ? "👥" : "");
                sb.AppendLine($"| {s.Order} | {s.Severity} | {Escape(s.Title)} | {Escape(s.Category)} | {auto} | {reboot} | {risk} | {s.BlastRadius}/5 |");
            }
            sb.AppendLine();
        }

        if (plan.RebootBatches.Count > 0)
        {
            sb.AppendLine("## Reboot batches");
            foreach (var b in plan.RebootBatches)
                sb.AppendLine($"- **Batch #{b.BatchNumber}** — steps {string.Join(", ", b.StepOrders)} ({b.Reason})");
            sb.AppendLine();
        }

        if (plan.Notes.Count > 0)
        {
            sb.AppendLine("## Notes");
            foreach (var n in plan.Notes) sb.AppendLine($"- {n}");
        }

        return sb.ToString();
    }

    /// <summary>Render the plan as JSON (machine-readable / pipeline-friendly).</summary>
    public static string RenderJson(OrchestrationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return JsonSerializer.Serialize(plan, JsonOpts);
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    private static string Escape(string s)
        => string.IsNullOrEmpty(s) ? string.Empty : s.Replace("|", "\\|");
}
