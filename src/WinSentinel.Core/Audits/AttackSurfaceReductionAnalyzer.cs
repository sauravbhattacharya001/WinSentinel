using System.Globalization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the Defender <b>Attack Surface Reduction (ASR)</b>
/// posture checks consumed by <see cref="DefenderAudit"/>.
///
/// ASR rules are Microsoft Defender's behavioural blocking controls (block
/// Office child-process creation, credential theft from LSASS, executable
/// content from email, etc.). Each rule is identified by a GUID and carries an
/// action state: <c>0</c> = not configured / disabled, <c>1</c> = Block,
/// <c>2</c> = Audit (log only), <c>6</c> = Warn. The recommended hardened
/// posture is <b>Block</b> for the standard rule set; Audit/Warn/Disabled leave
/// the corresponding attack technique unmitigated.
///
/// This class parses the two parallel arrays that
/// <c>Get-MpPreference</c> emits — <c>AttackSurfaceReductionRules_Ids</c> and
/// <c>AttackSurfaceReductionRules_Actions</c> — pairs them up by index, and
/// classifies the fleet of recommended rules into a single rolled-up
/// <see cref="Finding"/>. Like the rest of <see cref="DefenderAnalyzer"/>'s
/// siblings, nothing here runs PowerShell, touches the registry, or reads the
/// clock; the audit module owns collection and delegates every decision here so
/// the boundaries are deterministically unit-testable.
///
/// The emitted remediation is a single non-chained <c>Set-MpPreference</c>
/// invocation (no semicolons / pipes / sub-expressions) so it survives
/// <c>InputSanitizer.CheckDangerousCommand</c> and is a real one-click Fix
/// rather than a dead button — see
/// <c>AuditFixCommandSanitizerCoverageTests</c>.
/// </summary>
public static class AttackSurfaceReductionAnalyzer
{
    /// <summary>Category label shared with <see cref="DefenderAudit"/>.</summary>
    public const string Category = "Defender";

    /// <summary>Action value meaning the rule blocks the behaviour (hardened).</summary>
    public const int ActionBlock = 1;

    /// <summary>Action value meaning the rule only audits (logs, does not block).</summary>
    public const int ActionAudit = 2;

    /// <summary>Action value meaning the rule warns the user but can be bypassed.</summary>
    public const int ActionWarn = 6;

    /// <summary>Action value meaning the rule is disabled / not configured.</summary>
    public const int ActionDisabled = 0;

    /// <summary>
    /// A single recommended ASR rule: its GUID, a short human label, and the
    /// MITRE-flavoured behaviour it blocks. The label/description drive the
    /// finding text; the GUID drives both matching and the fix command.
    /// </summary>
    public sealed record AsrRule(string Id, string Name);

    /// <summary>
    /// The Microsoft-recommended "standard protection" ASR rule set that should
    /// be in Block mode on a hardened endpoint. GUIDs are the stable, public
    /// rule identifiers from Microsoft's ASR documentation (lower-cased here so
    /// matching is case-insensitive and order-independent).
    /// </summary>
    public static readonly IReadOnlyList<AsrRule> RecommendedRules = new[]
    {
        new AsrRule("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
        new AsrRule("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes"),
        new AsrRule("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes"),
        new AsrRule("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows LSASS subsystem"),
        new AsrRule("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail"),
        new AsrRule("01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files unless they meet prevalence/age/trusted-list criteria"),
        new AsrRule("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts"),
        new AsrRule("d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content"),
        new AsrRule("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content"),
        new AsrRule("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes"),
        new AsrRule("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes"),
        new AsrRule("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
        new AsrRule("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands"),
        new AsrRule("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB"),
        new AsrRule("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros"),
        new AsrRule("c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware"),
    };

    /// <summary>
    /// A recommended rule paired with the action it is currently configured with
    /// (or <c>null</c> when it is not present in the policy at all).
    /// </summary>
    public sealed record RuleStatus(AsrRule Rule, int? Action)
    {
        /// <summary>True when the rule actively blocks (Action == 1).</summary>
        public bool IsBlocking => Action == ActionBlock;

        /// <summary>
        /// Short human label for the rule's current configured state, used to
        /// annotate the finding sample so an admin can tell an audit-only rule
        /// (logs but doesn't stop the technique) apart from a fully disabled one
        /// at a glance.
        /// </summary>
        public string StateLabel => StateLabelFor(Action);
    }

    /// <summary>
    /// Map an ASR action code to a short human state label. <c>null</c> means the
    /// rule is absent from the policy ("not configured"); an unrecognized code
    /// falls back to its numeric value so nothing is silently swallowed.
    /// </summary>
    public static string StateLabelFor(int? action) => action switch
    {
        null => "not configured",
        ActionBlock => "block",
        ActionAudit => "audit",
        ActionWarn => "warn",
        ActionDisabled => "disabled",
        _ => $"action {action}",
    };

    /// <summary>
    /// Parse the two parallel CSV strings Get-MpPreference produces into a map of
    /// <c>guid -&gt; action</c>. Ids and actions are matched positionally; a row
    /// is skipped if either side is blank or the action is not an integer. GUID
    /// keys are lower-cased and trimmed so lookups are case-insensitive. Returns
    /// an empty map when no ASR rules are configured.
    /// </summary>
    public static IReadOnlyDictionary<string, int> ParseConfiguredRules(string? idsCsv, string? actionsCsv)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var ids = SplitList(idsCsv);
        var actions = SplitList(actionsCsv);
        var count = Math.Min(ids.Count, actions.Count);
        for (var i = 0; i < count; i++)
        {
            var id = ids[i].Trim().ToLowerInvariant();
            if (id.Length == 0) continue;
            if (!int.TryParse(actions[i].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var action))
                continue;
            map[id] = action; // last write wins on duplicate id
        }
        return map;
    }

    /// <summary>
    /// Split a Get-MpPreference list value on commas and/or newlines. PowerShell
    /// renders an array either comma-joined (when we ask for it via
    /// <c>-join ','</c>) or newline-separated (default <c>ToString</c>), so we
    /// tolerate both. Empty entries are dropped.
    /// </summary>
    private static List<string> SplitList(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return new List<string>();
        return value
            .Split(new[] { ',', '\r', '\n', ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();
    }

    /// <summary>
    /// Cross-reference the configured-rule map against
    /// <see cref="RecommendedRules"/>, returning one <see cref="RuleStatus"/> per
    /// recommended rule (in declaration order) with its current action, or
    /// <c>null</c> action when the rule is absent from the policy.
    /// </summary>
    public static IReadOnlyList<RuleStatus> EvaluateRules(IReadOnlyDictionary<string, int> configured)
    {
        var list = new List<RuleStatus>(RecommendedRules.Count);
        foreach (var rule in RecommendedRules)
        {
            list.Add(configured.TryGetValue(rule.Id, out var action)
                ? new RuleStatus(rule, action)
                : new RuleStatus(rule, null));
        }
        return list;
    }

    /// <summary>
    /// Build the rolled-up ASR finding from the raw Get-MpPreference output.
    /// Returns <c>null</c> only when Defender management itself is indeterminate
    /// — represented here by <paramref name="defenderManaged"/> being false (e.g.
    /// a third-party AV owns protection), matching the audit's "stay silent when
    /// we can't tell" convention. Otherwise always returns a finding.
    /// </summary>
    public static Finding? BuildAsrFinding(string? idsCsv, string? actionsCsv, bool defenderManaged = true)
    {
        if (!defenderManaged) return null;
        var configured = ParseConfiguredRules(idsCsv, actionsCsv);
        return BuildAsrFinding(EvaluateRules(configured));
    }

    /// <inheritdoc cref="BuildAsrFinding(string?, string?, bool)"/>
    public static Finding BuildAsrFinding(IReadOnlyList<RuleStatus> statuses)
    {
        var total = statuses.Count;
        var blocking = statuses.Where(s => s.IsBlocking).ToList();
        var notBlocking = statuses.Where(s => !s.IsBlocking).ToList();

        // All recommended rules already block → Pass.
        if (notBlocking.Count == 0)
        {
            return Finding.Pass(
                "Attack Surface Reduction Rules Enabled",
                $"All {total} recommended Microsoft Defender ASR rules are configured in Block mode.",
                Category);
        }

        // Fix: enable every recommended rule in Block mode in one call. Comma-
        // joined GUID/action lists, no command chaining → sanitizer-safe.
        var fix = BuildEnableAllFixCommand();

        var disabled = notBlocking.Where(s => s.Action is null || s.Action == ActionDisabled).ToList();
        var auditOrWarn = notBlocking.Where(s => s.Action == ActionAudit || s.Action == ActionWarn).ToList();

        // Sample a few rule names so the description is actionable without dumping all 16.
        // Annotate each with its current state so audit-only (logs, doesn't stop
        // the technique) is visibly distinct from fully disabled.
        var sample = string.Join("; ", notBlocking.Take(3).Select(s => $"{s.Rule.Name} ({s.StateLabel})"));
        if (notBlocking.Count > 3) sample += $"; +{notBlocking.Count - 3} more";

        // None of the recommended rules block at all → Critical (ASR effectively off).
        if (blocking.Count == 0)
        {
            return Finding.Critical(
                "Attack Surface Reduction Rules Disabled",
                $"None of the {total} recommended Defender ASR rules are in Block mode " +
                $"({disabled.Count} disabled/unset, {auditOrWarn.Count} audit/warn-only). " +
                $"Attack techniques such as: {sample} are not being blocked.",
                Category,
                "Enable the recommended ASR rules in Block mode.",
                fix);
        }

        // Some rules block, some don't → Warning (partial coverage).
        return Finding.Warning(
            "Attack Surface Reduction Rules Incomplete",
            $"{blocking.Count} of {total} recommended Defender ASR rules block; " +
            $"{notBlocking.Count} do not ({disabled.Count} disabled/unset, " +
            $"{auditOrWarn.Count} audit/warn-only). Not blocking: {sample}.",
            Category,
            "Switch the remaining recommended ASR rules to Block mode.",
            fix);
    }

    /// <summary>
    /// Build the single-call remediation that sets every recommended rule to
    /// Block. Deliberately a lone <c>Set-MpPreference</c> with comma-separated
    /// argument lists — no <c>;</c>, <c>|</c>, <c>$( )</c>, backticks or
    /// <c>Start-Process</c> — so it passes the FixEngine sanitizer.
    /// </summary>
    public static string BuildEnableAllFixCommand()
    {
        var ids = string.Join(",", RecommendedRules.Select(r => r.Id));
        var actions = string.Join(",", RecommendedRules.Select(_ => "Enabled"));
        return $"Set-MpPreference -AttackSurfaceReductionRules_Ids {ids} -AttackSurfaceReductionRules_Actions {actions}";
    }
}
