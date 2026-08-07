using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.AttachmentManagerAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="AttachmentManagerAnalyzer"/> -
/// the single-machine Attachment Manager / Mark-of-the-Web policy checks
/// (SaveZoneInformation, HideZoneInfoOnProperties, ScanWithAntiVirus,
/// DefaultFileTypeRisk, LowRiskFileTypes). Every rule is exercised directly
/// against a synthetic <see cref="AttachmentManagerState"/>; no registry or I/O
/// is touched.
/// </summary>
public class AttachmentManagerAnalyzerTests
{
    /// <summary>A fully-hardened state: every check should Pass.</summary>
    private static AttachmentManagerState HardenedState() => new()
    {
        SaveZoneInformation = 2,
        HideZoneInfoOnProperties = 0,
        ScanWithAntiVirus = 3,
        DefaultFileTypeRisk = RiskHigh,
        LowRiskFileTypes = null,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_HardenedState_IsAllPass()
    {
        var findings = Analyze(HardenedState());
        Assert.Equal(5, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Attachment Manager", f.Category));
    }

    [Fact]
    public void Analyze_AllAbsent_IsAllPass()
    {
        // A machine with none of these policy values set should be treated as the
        // safe OS default across the board.
        var findings = Analyze(new AttachmentManagerState());
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    // ── SaveZoneInformation ──────────────────────────────────────────

    [Fact]
    public void SaveZoneInformation_StripsMotw_IsCritical_WithFix()
    {
        var f = AnalyzeSaveZoneInformation(HardenedState() with { SaveZoneInformation = 1 });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("SaveZoneInformation", f.FixCommand);
    }

    [Fact]
    public void SaveZoneInformation_PreserveOrAbsent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeSaveZoneInformation(HardenedState() with { SaveZoneInformation = 2 }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeSaveZoneInformation(HardenedState() with { SaveZoneInformation = null }).Severity);
    }

    // ── HideZoneInfoOnProperties ─────────────────────────────────────

    [Fact]
    public void HideZoneInfo_On_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeHideZoneInfo(HardenedState() with { HideZoneInfoOnProperties = 1 }).Severity);
    }

    [Fact]
    public void HideZoneInfo_OffOrAbsent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeHideZoneInfo(HardenedState() with { HideZoneInfoOnProperties = 0 }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeHideZoneInfo(HardenedState() with { HideZoneInfoOnProperties = null }).Severity);
    }

    // ── ScanWithAntiVirus ────────────────────────────────────────────

    [Theory]
    [InlineData(ScanOff, Severity.Critical)]
    [InlineData(ScanOptional, Severity.Pass)]
    [InlineData(ScanAlways, Severity.Pass)]
    public void ScanWithAntiVirus_Values(int value, Severity expected)
    {
        var f = AnalyzeScanWithAntiVirus(HardenedState() with { ScanWithAntiVirus = value });
        Assert.Equal(expected, f.Severity);
        if (expected == Severity.Critical)
        {
            Assert.Contains("ScanWithAntiVirus", f.FixCommand);
        }
    }

    [Fact]
    public void ScanWithAntiVirus_Absent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeScanWithAntiVirus(HardenedState() with { ScanWithAntiVirus = null }).Severity);
    }

    // ── DefaultFileTypeRisk ──────────────────────────────────────────

    [Theory]
    [InlineData(RiskHigh, Severity.Pass)]
    [InlineData(RiskModerate, Severity.Warning)]
    [InlineData(RiskLow, Severity.Critical)]
    public void DefaultFileTypeRisk_Values(int value, Severity expected)
    {
        var f = AnalyzeDefaultFileTypeRisk(HardenedState() with { DefaultFileTypeRisk = value });
        Assert.Equal(expected, f.Severity);
    }

    [Fact]
    public void DefaultFileTypeRisk_Absent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeDefaultFileTypeRisk(HardenedState() with { DefaultFileTypeRisk = null }).Severity);
    }

    [Fact]
    public void DefaultFileTypeRisk_Low_HasFix()
    {
        var f = AnalyzeDefaultFileTypeRisk(HardenedState() with { DefaultFileTypeRisk = RiskLow });
        Assert.Contains("DefaultFileTypeRisk", f.FixCommand);
    }

    // ── LowRiskFileTypes ─────────────────────────────────────────────

    [Fact]
    public void LowRiskFileTypes_EmptyOrAbsent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeLowRiskFileTypes(HardenedState() with { LowRiskFileTypes = null }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeLowRiskFileTypes(HardenedState() with { LowRiskFileTypes = "" }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeLowRiskFileTypes(HardenedState() with { LowRiskFileTypes = "   " }).Severity);
    }

    [Fact]
    public void LowRiskFileTypes_WithExecutable_IsCritical()
    {
        var f = AnalyzeLowRiskFileTypes(HardenedState() with { LowRiskFileTypes = ".txt;.exe;.pdf" });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains(".exe", f.Description);
    }

    [Fact]
    public void LowRiskFileTypes_ExecutableWithoutLeadingDot_IsCritical()
    {
        // Extensions supplied without a leading dot should still be normalised.
        var f = AnalyzeLowRiskFileTypes(HardenedState() with { LowRiskFileTypes = "ps1;js" });
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void LowRiskFileTypes_BenignOnly_Warns()
    {
        var f = AnalyzeLowRiskFileTypes(HardenedState() with { LowRiskFileTypes = ".txt;.pdf;.png" });
        Assert.Equal(Severity.Warning, f.Severity);
    }
}
