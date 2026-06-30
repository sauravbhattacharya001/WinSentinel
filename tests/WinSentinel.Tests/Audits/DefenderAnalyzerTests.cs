using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Unit tests for <see cref="DefenderAnalyzer"/> — the pure, I/O-free Windows
/// Defender posture decision logic behind the <see cref="DefenderAudit"/> module.
/// Previously these thresholds and parsers lived inline inside the
/// <c>Get-MpPreference</c> / <c>Get-MpComputerStatus</c> collection methods and
/// could only be exercised by an integration test that asserted "a finding
/// exists" — never the actual classification or the staleness boundaries.
///
/// These tests pin every security-relevant boundary directly with synthetic
/// input: real-time protection on/off/unknown (with the DisableRealtimeMonitoring
/// inversion), Tamper Protection on/off/unknown, MAPS cloud-protection level,
/// antivirus-definition freshness at the exact 24h/72h thresholds, and quick-scan
/// recency at the 14-day threshold. Every time-relative check takes an injected
/// "now" so the boundaries are deterministic — no shell, no clock.
/// </summary>
public class DefenderAnalyzerTests
{
    private const string Cat = "Defender";

    // A fixed reference time used by all time-relative tests.
    private static readonly DateTime Now = new(2026, 6, 14, 12, 0, 0, DateTimeKind.Local);

    // ──────────────────────────────────────────────────────────────────────
    // ParseBool
    // ──────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("True", DefenderAnalyzer.BoolState.True)]
    [InlineData("true", DefenderAnalyzer.BoolState.True)]
    [InlineData("  TRUE  ", DefenderAnalyzer.BoolState.True)]
    [InlineData("False", DefenderAnalyzer.BoolState.False)]
    [InlineData("false", DefenderAnalyzer.BoolState.False)]
    [InlineData("  FALSE\r\n", DefenderAnalyzer.BoolState.False)]
    [InlineData("", DefenderAnalyzer.BoolState.Unknown)]
    [InlineData("   ", DefenderAnalyzer.BoolState.Unknown)]
    [InlineData(null, DefenderAnalyzer.BoolState.Unknown)]
    [InlineData("Get-MpPreference : The term is not recognized", DefenderAnalyzer.BoolState.Unknown)]
    [InlineData("1", DefenderAnalyzer.BoolState.Unknown)]
    public void ParseBool_Classifies(string? output, DefenderAnalyzer.BoolState expected)
    {
        Assert.Equal(expected, DefenderAnalyzer.ParseBool(output));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Real-time protection — DisableRealtimeMonitoring is INVERTED.
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Realtime_DisableTrue_IsCritical()
    {
        // DisableRealtimeMonitoring == True  => protection OFF => Critical.
        var f = DefenderAnalyzer.BuildRealtimeProtectionFinding("True");
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Disabled", f.Title);
        Assert.Equal(Cat, f.Category);
        Assert.Equal("Set-MpPreference -DisableRealtimeMonitoring $false", f.FixCommand);
    }

    [Fact]
    public void Realtime_DisableFalse_IsPass()
    {
        // DisableRealtimeMonitoring == False => protection ON => Pass.
        var f = DefenderAnalyzer.BuildRealtimeProtectionFinding("False");
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Enabled", f.Title);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("garbage")]
    public void Realtime_Unknown_IsInfo(string? output)
    {
        var f = DefenderAnalyzer.BuildRealtimeProtectionFinding(output);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Unknown", f.Title);
    }

    [Fact]
    public void Realtime_StateOverload_MatchesStringOverload()
    {
        Assert.Equal(
            DefenderAnalyzer.BuildRealtimeProtectionFinding("True").Severity,
            DefenderAnalyzer.BuildRealtimeProtectionFinding(DefenderAnalyzer.BoolState.True).Severity);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Tamper protection — True == Pass, False == Warning, unknown == null.
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Tamper_False_IsWarning()
    {
        var f = DefenderAnalyzer.BuildTamperProtectionFinding("False");
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("Tamper Protection", f.Title);
        Assert.Contains("Disabled", f.Title);
    }

    [Fact]
    public void Tamper_True_IsPass()
    {
        var f = DefenderAnalyzer.BuildTamperProtectionFinding("True");
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("Enabled", f.Title);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-bool")]
    public void Tamper_Unknown_EmitsNoFinding(string? output)
    {
        Assert.Null(DefenderAnalyzer.BuildTamperProtectionFinding(output));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ParseMapsReporting + cloud protection
    // ──────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("0", 0)]
    [InlineData("1", 1)]
    [InlineData("2", 2)]
    [InlineData("  2 ", 2)]
    public void ParseMaps_ParsesInts(string output, int expected)
    {
        Assert.Equal(expected, DefenderAnalyzer.ParseMapsReporting(output));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("Advanced")]
    [InlineData("2.5")]
    public void ParseMaps_NonInt_IsNull(string? output)
    {
        Assert.Null(DefenderAnalyzer.ParseMapsReporting(output));
    }

    [Fact]
    public void Cloud_Zero_IsWarning()
    {
        var f = DefenderAnalyzer.BuildCloudProtectionFinding("0");
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("Cloud Protection Disabled", f.Title);
        Assert.Equal("Set-MpPreference -MAPSReporting Advanced", f.FixCommand);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    public void Cloud_NonZero_IsPass(string output)
    {
        var f = DefenderAnalyzer.BuildCloudProtectionFinding(output);
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("Enabled", f.Title);
        Assert.Contains($"level: {output}", f.Description);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("xyz")]
    public void Cloud_Unparseable_EmitsNoFinding(string? output)
    {
        Assert.Null(DefenderAnalyzer.BuildCloudProtectionFinding(output));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ParseTimestamp
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void ParseTimestamp_ExactFormat()
    {
        var ts = DefenderAnalyzer.ParseTimestamp("2026-06-14 09:30:00");
        Assert.NotNull(ts);
        Assert.Equal(new DateTime(2026, 6, 14, 9, 30, 0), ts!.Value);
    }

    [Fact]
    public void ParseTimestamp_TrimsWhitespace()
    {
        Assert.NotNull(DefenderAnalyzer.ParseTimestamp("  2026-06-14 09:30:00 \r\n"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("not a date")]
    [InlineData("Get-MpComputerStatus : not recognized")]
    public void ParseTimestamp_Unparseable_IsNull(string? output)
    {
        Assert.Null(DefenderAnalyzer.ParseTimestamp(output));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Definition freshness — 24h / 72h boundaries (measured in hours).
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Definitions_Fresh_IsPass()
    {
        // 1 hour old.
        var f = DefenderAnalyzer.BuildDefinitionFreshnessFinding(Now.AddHours(-1), Now);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Current", f.Title);
    }

    [Fact]
    public void Definitions_ExactlyWarningThreshold_IsStillPass()
    {
        // > 24 triggers Warning; exactly 24h is NOT greater than 24 => Pass.
        var f = DefenderAnalyzer.BuildDefinitionFreshnessFinding(Now.AddHours(-24), Now);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Definitions_JustOverWarningThreshold_IsWarning()
    {
        var f = DefenderAnalyzer.BuildDefinitionFreshnessFinding(Now.AddHours(-24).AddMinutes(-1), Now);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Outdated", f.Title);
        Assert.Equal("Update-MpSignature", f.FixCommand);
    }

    [Fact]
    public void Definitions_ExactlyCriticalThreshold_IsStillWarning()
    {
        // > 72 triggers Critical; exactly 72h is NOT greater than 72 => Warning.
        var f = DefenderAnalyzer.BuildDefinitionFreshnessFinding(Now.AddHours(-72), Now);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void Definitions_JustOverCriticalThreshold_IsCritical()
    {
        var f = DefenderAnalyzer.BuildDefinitionFreshnessFinding(Now.AddHours(-72).AddMinutes(-1), Now);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Severely Outdated", f.Title);
    }

    [Fact]
    public void Definitions_FromString_ParsesAndClassifies()
    {
        var output = Now.AddHours(-100).ToString(DefenderAnalyzer.TimestampFormat);
        var f = DefenderAnalyzer.BuildDefinitionFreshnessFinding(output, Now);
        Assert.NotNull(f);
        Assert.Equal(Severity.Critical, f!.Severity);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("garbage")]
    public void Definitions_UnparseableTimestamp_EmitsNoFinding(string? output)
    {
        Assert.Null(DefenderAnalyzer.BuildDefinitionFreshnessFinding(output, Now));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Quick-scan recency — 14-day boundary (whole days, int-truncating).
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void QuickScan_Recent_IsPass()
    {
        var f = DefenderAnalyzer.BuildQuickScanFinding(Now.AddDays(-3), Now);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Recent Scan", f.Title);
    }

    [Fact]
    public void QuickScan_Exactly14Days_IsStillPass()
    {
        // > 14 triggers Warning; exactly 14 whole days is not greater than 14.
        var f = DefenderAnalyzer.BuildQuickScanFinding(Now.AddDays(-14), Now);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void QuickScan_FourteenDaysAndChange_IsStillPass_DueToWholeDayTruncation()
    {
        // 14 days 23h -> .Days == 14 (truncated) -> not > 14 -> Pass.
        // This pins the original (DateTime.Now - lastScan).Days semantics.
        var f = DefenderAnalyzer.BuildQuickScanFinding(Now.AddDays(-14).AddHours(-23), Now);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void QuickScan_FifteenDays_IsWarning()
    {
        var f = DefenderAnalyzer.BuildQuickScanFinding(Now.AddDays(-15), Now);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("No Recent Quick Scan", f.Title);
        Assert.Equal("Start-MpScan -ScanType QuickScan", f.FixCommand);
    }

    [Fact]
    public void QuickScan_FromString_ParsesAndClassifies()
    {
        var output = Now.AddDays(-30).ToString(DefenderAnalyzer.TimestampFormat);
        var f = DefenderAnalyzer.BuildQuickScanFinding(output, Now);
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-timestamp")]
    public void QuickScan_UnparseableTimestamp_EmitsNoFinding(string? output)
    {
        Assert.Null(DefenderAnalyzer.BuildQuickScanFinding(output, Now));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Cross-cutting: every emitted finding carries the Defender category.
    // ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void AllBuilders_TagFindingsWithDefenderCategory()
    {
        var findings = new List<Finding?>
        {
            DefenderAnalyzer.BuildRealtimeProtectionFinding("True"),
            DefenderAnalyzer.BuildRealtimeProtectionFinding("False"),
            DefenderAnalyzer.BuildRealtimeProtectionFinding(""),
            DefenderAnalyzer.BuildTamperProtectionFinding("True"),
            DefenderAnalyzer.BuildTamperProtectionFinding("False"),
            DefenderAnalyzer.BuildCloudProtectionFinding("0"),
            DefenderAnalyzer.BuildCloudProtectionFinding("2"),
            DefenderAnalyzer.BuildDefinitionFreshnessFinding(Now.AddHours(-100), Now),
            DefenderAnalyzer.BuildDefinitionFreshnessFinding(Now.AddHours(-1), Now),
            DefenderAnalyzer.BuildQuickScanFinding(Now.AddDays(-30), Now),
            DefenderAnalyzer.BuildQuickScanFinding(Now.AddDays(-1), Now),
        };

        foreach (var f in findings)
        {
            Assert.NotNull(f);
            Assert.Equal(Cat, f!.Category);
            Assert.False(string.IsNullOrWhiteSpace(f.Title));
            Assert.False(string.IsNullOrWhiteSpace(f.Description));
        }
    }

    // ───────────────────────────────────────────────────────
    // Controlled Folder Access (EnableControlledFolderAccess)
    // ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("1", DefenderAnalyzer.CfaBlock)]
    [InlineData("0", DefenderAnalyzer.CfaDisabled)]
    [InlineData("2", DefenderAnalyzer.CfaAudit)]
    [InlineData("3", DefenderAnalyzer.CfaBlockDiskOnly)]
    [InlineData("4", DefenderAnalyzer.CfaAuditDiskOnly)]
    [InlineData("  1  ", DefenderAnalyzer.CfaBlock)]
    [InlineData("Enabled", DefenderAnalyzer.CfaBlock)]
    [InlineData("Block", DefenderAnalyzer.CfaBlock)]
    [InlineData("Disabled", DefenderAnalyzer.CfaDisabled)]
    [InlineData("AuditMode", DefenderAnalyzer.CfaAudit)]
    [InlineData("audit", DefenderAnalyzer.CfaAudit)]
    [InlineData("BlockDiskModificationOnly", DefenderAnalyzer.CfaBlockDiskOnly)]
    [InlineData("AuditDiskModificationOnly", DefenderAnalyzer.CfaAuditDiskOnly)]
    public void ParseControlledFolderAccess_ParsesNumericAndNamedStates(string raw, int expected)
    {
        Assert.Equal(expected, DefenderAnalyzer.ParseControlledFolderAccess(raw));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Yes")]
    [InlineData("on")]
    [InlineData(null)]
    public void ParseControlledFolderAccess_ReturnsNullForUnparseable(string? raw)
    {
        Assert.Null(DefenderAnalyzer.ParseControlledFolderAccess(raw));
    }

    [Fact]
    public void ControlledFolderAccess_Block_IsPass_WithNoFix()
    {
        var f = DefenderAnalyzer.BuildControlledFolderAccessFinding("1");
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Equal(Cat, f.Category);
        // A Pass needs no remediation.
        Assert.True(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void ControlledFolderAccess_Disabled_IsWarning_WithEnableFix()
    {
        var f = DefenderAnalyzer.BuildControlledFolderAccessFinding("0");
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("Disabled", f.Title);
        Assert.Equal("Set-MpPreference -EnableControlledFolderAccess Enabled", f.FixCommand);
    }

    [Theory]
    [InlineData(DefenderAnalyzer.CfaAudit)]
    [InlineData(DefenderAnalyzer.CfaAuditDiskOnly)]
    public void ControlledFolderAccess_AuditModes_AreWarning_WithEnableFix(int state)
    {
        var f = DefenderAnalyzer.BuildControlledFolderAccessFinding(state);
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Equal("Set-MpPreference -EnableControlledFolderAccess Enabled", f.FixCommand);
    }

    [Fact]
    public void ControlledFolderAccess_BlockDiskOnly_IsWarning_WithEnableFix()
    {
        var f = DefenderAnalyzer.BuildControlledFolderAccessFinding(DefenderAnalyzer.CfaBlockDiskOnly);
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Equal("Set-MpPreference -EnableControlledFolderAccess Enabled", f.FixCommand);
    }

    [Fact]
    public void ControlledFolderAccess_Unparseable_EmitsNoFinding()
    {
        // Mirrors the MAPS/Tamper "stay silent when indeterminate" convention.
        Assert.Null(DefenderAnalyzer.BuildControlledFolderAccessFinding(""));
        Assert.Null(DefenderAnalyzer.BuildControlledFolderAccessFinding("third-party-av"));
        Assert.Null(DefenderAnalyzer.BuildControlledFolderAccessFinding((int?)null));
    }

    [Fact]
    public void ControlledFolderAccess_UnknownPositiveState_IsWarning_NotMislabeledPass()
    {
        // A future/unrecognized positive enum value must not be reported as Block/Pass.
        var f = DefenderAnalyzer.BuildControlledFolderAccessFinding(99);
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Equal("Set-MpPreference -EnableControlledFolderAccess Enabled", f.FixCommand);
    }

    // ─────────────────────────────────────────────
    // PUA protection (PUAProtection)
    // ─────────────────────────────────────────────

    [Theory]
    [InlineData("1", DefenderAnalyzer.PuaBlock)]
    [InlineData("0", DefenderAnalyzer.PuaDisabled)]
    [InlineData("2", DefenderAnalyzer.PuaAudit)]
    [InlineData("  1  ", DefenderAnalyzer.PuaBlock)]
    [InlineData("Enabled", DefenderAnalyzer.PuaBlock)]
    [InlineData("Block", DefenderAnalyzer.PuaBlock)]
    [InlineData("on", DefenderAnalyzer.PuaBlock)]
    [InlineData("Disabled", DefenderAnalyzer.PuaDisabled)]
    [InlineData("off", DefenderAnalyzer.PuaDisabled)]
    [InlineData("AuditMode", DefenderAnalyzer.PuaAudit)]
    [InlineData("audit", DefenderAnalyzer.PuaAudit)]
    public void ParsePuaProtection_ParsesNumericAndNamedStates(string raw, int expected)
    {
        Assert.Equal(expected, DefenderAnalyzer.ParsePuaProtection(raw));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Yes")]
    [InlineData("enable")]
    [InlineData(null)]
    public void ParsePuaProtection_ReturnsNullForUnparseable(string? raw)
    {
        Assert.Null(DefenderAnalyzer.ParsePuaProtection(raw));
    }

    [Fact]
    public void PuaProtection_Block_IsPass_WithNoFix()
    {
        var f = DefenderAnalyzer.BuildPuaProtectionFinding("1");
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Equal(Cat, f.Category);
        Assert.Contains("Enabled", f.Title);
        // A Pass needs no remediation.
        Assert.True(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void PuaProtection_Disabled_IsWarning_WithEnableFix()
    {
        var f = DefenderAnalyzer.BuildPuaProtectionFinding("0");
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("Disabled", f.Title);
        Assert.Equal("Set-MpPreference -PUAProtection Enabled", f.FixCommand);
    }

    [Fact]
    public void PuaProtection_AuditMode_IsWarning_WithEnableFix()
    {
        var f = DefenderAnalyzer.BuildPuaProtectionFinding(DefenderAnalyzer.PuaAudit);
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("Audit", f.Title);
        Assert.Equal("Set-MpPreference -PUAProtection Enabled", f.FixCommand);
    }

    [Fact]
    public void PuaProtection_Unparseable_EmitsNoFinding()
    {
        // Mirrors the MAPS/CFA "stay silent when indeterminate" convention.
        Assert.Null(DefenderAnalyzer.BuildPuaProtectionFinding(""));
        Assert.Null(DefenderAnalyzer.BuildPuaProtectionFinding("third-party-av"));
        Assert.Null(DefenderAnalyzer.BuildPuaProtectionFinding((int?)null));
    }

    [Fact]
    public void PuaProtection_UnknownPositiveState_IsWarning_NotMislabeledPass()
    {
        // A future/unrecognized positive enum value must not be reported as Block/Pass.
        var f = DefenderAnalyzer.BuildPuaProtectionFinding(99);
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Equal("Set-MpPreference -PUAProtection Enabled", f.FixCommand);
    }
}
