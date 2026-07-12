using System.Linq;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;
using Xunit;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Unit tests for <see cref="AttackSurfaceReductionAnalyzer"/> — the pure,
/// I/O-free logic behind the new Defender Attack Surface Reduction (ASR) posture
/// check in <see cref="DefenderAudit"/>.
///
/// ASR rules are GUID-identified behavioural blocking controls (block Office
/// child processes, block LSASS credential theft, …) each carrying an action
/// state: 0 disabled/unset, 1 Block, 2 Audit, 6 Warn. The hardened posture is
/// Block for the standard recommended set; anything else leaves the technique
/// unmitigated. These tests pin the parser (positional pairing of the two
/// parallel Get-MpPreference arrays, comma + newline tolerance, malformed-row
/// skipping, case-insensitive GUID matching), the per-rule evaluation, all three
/// roll-up tiers (Pass when every recommended rule blocks, Warning on partial
/// coverage, Critical when nothing blocks), the "stay silent when Defender isn't
/// managed" convention, and — critically — that the emitted one-click
/// <c>FixCommand</c> survives the FixEngine sanitizer (so it is not a dead Fix
/// button). No shell, no registry, no clock.
/// </summary>
public class AttackSurfaceReductionAnalyzerTests
{
    private const string Cat = "Defender";

    private static string IdAt(int i) => AttackSurfaceReductionAnalyzer.RecommendedRules[i].Id;
    private static int RuleCount => AttackSurfaceReductionAnalyzer.RecommendedRules.Count;

    // Build a comma-joined ids/actions pair that sets the first `blockCount`
    // recommended rules to Block (1) and leaves the rest at `restAction`.
    private static (string ids, string actions) Policy(int blockCount, int restAction)
    {
        var rules = AttackSurfaceReductionAnalyzer.RecommendedRules;
        var ids = string.Join(",", rules.Select(r => r.Id));
        var actions = string.Join(",", rules.Select((_, i) => (i < blockCount ? 1 : restAction).ToString()));
        return (ids, actions);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Recommended-rule set sanity
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void RecommendedRules_AreNonEmpty_WithUniqueLowercaseGuids()
    {
        var rules = AttackSurfaceReductionAnalyzer.RecommendedRules;
        Assert.NotEmpty(rules);
        // GUIDs are stored lower-cased so matching is case-insensitive & stable.
        Assert.All(rules, r => Assert.Equal(r.Id, r.Id.ToLowerInvariant()));
        Assert.All(rules, r => Assert.True(System.Guid.TryParse(r.Id, out _), $"not a GUID: {r.Id}"));
        Assert.All(rules, r => Assert.False(string.IsNullOrWhiteSpace(r.Name)));
        // No duplicate rule IDs.
        Assert.Equal(rules.Count, rules.Select(r => r.Id).Distinct().Count());
    }

    // ──────────────────────────────────────────────────────────────────────
    // ParseConfiguredRules
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void ParseConfiguredRules_PairsIdsAndActionsPositionally()
    {
        var map = AttackSurfaceReductionAnalyzer.ParseConfiguredRules(
            $"{IdAt(0)},{IdAt(1)}", "1,2");
        Assert.Equal(2, map.Count);
        Assert.Equal(1, map[IdAt(0)]);
        Assert.Equal(2, map[IdAt(1)]);
    }

    [Fact]
    public void ParseConfiguredRules_ToleratesNewlineSeparatedLists()
    {
        // PowerShell's default array ToString is newline-separated; we accept it.
        var map = AttackSurfaceReductionAnalyzer.ParseConfiguredRules(
            $"{IdAt(0)}\r\n{IdAt(1)}", "1\r\n0");
        Assert.Equal(1, map[IdAt(0)]);
        Assert.Equal(0, map[IdAt(1)]);
    }

    [Fact]
    public void ParseConfiguredRules_IsCaseInsensitiveOnGuid()
    {
        var map = AttackSurfaceReductionAnalyzer.ParseConfiguredRules(
            IdAt(0).ToUpperInvariant(), "1");
        // Lookup with the canonical lower-case GUID still hits.
        Assert.True(map.ContainsKey(IdAt(0)));
        Assert.Equal(1, map[IdAt(0)]);
    }

    [Fact]
    public void ParseConfiguredRules_SkipsRowsWithNonIntegerAction()
    {
        var map = AttackSurfaceReductionAnalyzer.ParseConfiguredRules(
            $"{IdAt(0)},{IdAt(1)}", "1,notanumber");
        Assert.Single(map);
        Assert.True(map.ContainsKey(IdAt(0)));
        Assert.False(map.ContainsKey(IdAt(1)));
    }

    [Fact]
    public void ParseConfiguredRules_StopsAtShorterList()
    {
        // More ids than actions: only the paired prefix is taken.
        var map = AttackSurfaceReductionAnalyzer.ParseConfiguredRules(
            $"{IdAt(0)},{IdAt(1)},{IdAt(2)}", "1");
        Assert.Single(map);
        Assert.Equal(1, map[IdAt(0)]);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    public void ParseConfiguredRules_EmptyInputs_YieldEmptyMap(string? ids, string? actions)
    {
        var map = AttackSurfaceReductionAnalyzer.ParseConfiguredRules(ids, actions);
        Assert.Empty(map);
    }

    // ──────────────────────────────────────────────────────────────────────
    // EvaluateRules
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void EvaluateRules_ReturnsOneStatusPerRecommendedRule_InOrder()
    {
        var map = AttackSurfaceReductionAnalyzer.ParseConfiguredRules(IdAt(0), "1");
        var statuses = AttackSurfaceReductionAnalyzer.EvaluateRules(map);
        Assert.Equal(RuleCount, statuses.Count);
        // First rule was configured to Block; it should report blocking.
        Assert.True(statuses[0].IsBlocking);
        Assert.Equal(1, statuses[0].Action);
        // A rule absent from the policy has null action and is not blocking.
        Assert.Null(statuses[1].Action);
        Assert.False(statuses[1].IsBlocking);
    }

    // ──────────────────────────────────────────────────────────────────────
    // BuildAsrFinding — three tiers
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void BuildAsrFinding_AllRulesBlock_IsPass()
    {
        var (ids, actions) = Policy(blockCount: RuleCount, restAction: 1);
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(ids, actions);
        Assert.NotNull(finding);
        Assert.Equal(Severity.Pass, finding!.Severity);
        Assert.Equal(Cat, finding.Category);
        // A Pass needs no fix.
        Assert.True(string.IsNullOrEmpty(finding.FixCommand));
    }

    [Fact]
    public void BuildAsrFinding_NoRulesConfigured_IsCriticalWithFix()
    {
        // Empty policy: every recommended rule is unset.
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(null, null);
        Assert.NotNull(finding);
        Assert.Equal(Severity.Critical, finding!.Severity);
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("Set-MpPreference", finding.FixCommand);
    }

    [Fact]
    public void BuildAsrFinding_AllAuditOnly_IsCritical_NotBlocking()
    {
        // Every rule present but only in Audit (2) mode → nothing actually blocks.
        var (ids, actions) = Policy(blockCount: 0, restAction: AttackSurfaceReductionAnalyzer.ActionAudit);
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(ids, actions);
        Assert.NotNull(finding);
        Assert.Equal(Severity.Critical, finding!.Severity);
        Assert.Contains("audit", finding.Description.ToLowerInvariant());
    }

    [Fact]
    public void BuildAsrFinding_PartialCoverage_IsWarningWithFix()
    {
        // Half the rules block, the rest are disabled.
        var (ids, actions) = Policy(blockCount: RuleCount / 2, restAction: 0);
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(ids, actions);
        Assert.NotNull(finding);
        Assert.Equal(Severity.Warning, finding!.Severity);
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("Set-MpPreference", finding.FixCommand);
    }

    // ──────────────────────────────────────────────────────────────────────
    // StateLabel / StateLabelFor
    // ──────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, "not configured")]
    [InlineData(0, "disabled")]
    [InlineData(1, "block")]
    [InlineData(2, "audit")]
    [InlineData(6, "warn")]
    [InlineData(99, "action 99")]
    public void StateLabelFor_MapsActionCodeToHumanLabel(int? action, string expected)
    {
        Assert.Equal(expected, AttackSurfaceReductionAnalyzer.StateLabelFor(action));
    }

    [Fact]
    public void RuleStatus_StateLabel_ReflectsAction()
    {
        var rule = AttackSurfaceReductionAnalyzer.RecommendedRules[0];
        Assert.Equal("audit", new AttackSurfaceReductionAnalyzer.RuleStatus(rule, 2).StateLabel);
        Assert.Equal("not configured", new AttackSurfaceReductionAnalyzer.RuleStatus(rule, null).StateLabel);
    }

    [Fact]
    public void BuildAsrFinding_PartialCoverage_SampleAnnotatesStateOfNonBlockingRules()
    {
        // First rule blocks; the rest are audit-only. The sample must call out
        // "(audit)" so an admin sees the technique is logged but not stopped.
        var (ids, actions) = Policy(blockCount: 1, restAction: AttackSurfaceReductionAnalyzer.ActionAudit);
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(ids, actions);
        Assert.NotNull(finding);
        Assert.Equal(Severity.Warning, finding!.Severity);
        Assert.Contains("(audit)", finding.Description);
    }

    [Fact]
    public void BuildAsrFinding_NotDefenderManaged_ReturnsNull()
    {
        // Third-party AV owns protection → stay silent, like the other Defender checks.
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(null, null, defenderManaged: false);
        Assert.Null(finding);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Fix command safety — must NOT be a dead Fix button
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void BuildEnableAllFixCommand_SurvivesSanitizer()
    {
        var fix = AttackSurfaceReductionAnalyzer.BuildEnableAllFixCommand();
        var reason = InputSanitizer.CheckDangerousCommand(fix);
        Assert.True(reason is null,
            $"ASR enable-all fix is rejected by the sanitizer and would be a dead Fix button: " +
            $"\"{fix}\" — blocked because: {reason}");
        // Sanity: it references every recommended rule GUID and uses Enabled actions.
        Assert.Contains("-AttackSurfaceReductionRules_Ids", fix);
        Assert.Contains("-AttackSurfaceReductionRules_Actions", fix);
        Assert.All(AttackSurfaceReductionAnalyzer.RecommendedRules, r => Assert.Contains(r.Id, fix));
        Assert.DoesNotContain(";", fix);
        Assert.DoesNotContain("|", fix);
    }

    [Fact]
    public void BuildAsrFinding_EmittedFixCommand_SurvivesSanitizer()
    {
        // The fix attached to a real (Critical) finding must also pass the sanitizer.
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(null, null);
        Assert.NotNull(finding!.FixCommand);
        Assert.Null(InputSanitizer.CheckDangerousCommand(finding.FixCommand));
    }
}
