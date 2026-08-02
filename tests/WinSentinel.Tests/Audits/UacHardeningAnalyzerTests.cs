using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.UacHardeningAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="UacHardeningAnalyzer"/> - the
/// single-machine User Account Control (UAC) hardening checks: the master UAC switch
/// (EnableLUA), the admin-approval-mode consent prompt (ConsentPromptBehaviorAdmin),
/// secure-desktop prompting (PromptOnSecureDesktop), Admin Approval Mode for the built-in
/// Administrator (FilterAdministratorToken), installer detection (EnableInstallerDetection),
/// and the remote UAC token-filtering override (LocalAccountTokenFilterPolicy) that enables
/// Pass-the-Hash. Every rule is exercised directly against a synthetic
/// <see cref="UacHardeningState"/>; no registry I/O is touched.
/// </summary>
public class UacHardeningAnalyzerTests
{
    private static UacHardeningState HardenedState() => new()
    {
        EnableLua = true,
        ConsentPromptBehaviorAdmin = 2,
        PromptOnSecureDesktop = true,
        FilterAdministratorToken = true,
        EnableInstallerDetection = true,
        LocalAccountTokenFilterPolicyEnabled = false,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => UacHardeningAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Fully_Hardened_Is_All_Pass()
    {
        var findings = UacHardeningAnalyzer.Analyze(HardenedState());
        Assert.Equal(6, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var state = HardenedState();
        var a = UacHardeningAnalyzer.Analyze(state).Select(f => f.Title).ToArray();
        var b = UacHardeningAnalyzer.Analyze(state).Select(f => f.Title).ToArray();
        Assert.Equal(a, b);
    }

    [Fact]
    public void EnableLua_Off_Is_Critical()
    {
        var f = AnalyzeEnableLua(HardenedState() with { EnableLua = false });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("UAC is disabled", f.Title);
        Assert.Contains("EnableLUA", f.FixCommand);
    }

    [Fact]
    public void EnableLua_On_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzeEnableLua(HardenedState()).Severity);
    }

    [Fact]
    public void ConsentPromptBehaviorAdmin_Zero_Is_Critical()
    {
        var f = AnalyzeConsentPromptBehaviorAdmin(HardenedState() with { ConsentPromptBehaviorAdmin = 0 });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("without prompting", f.Title);
        Assert.Contains("ConsentPromptBehaviorAdmin", f.FixCommand);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    public void ConsentPromptBehaviorAdmin_Prompting_Values_Are_Pass(int value)
    {
        var f = AnalyzeConsentPromptBehaviorAdmin(HardenedState() with { ConsentPromptBehaviorAdmin = value });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void PromptOnSecureDesktop_Off_Is_Warning()
    {
        var f = AnalyzePromptOnSecureDesktop(HardenedState() with { PromptOnSecureDesktop = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("secure desktop", f.Title);
        Assert.Contains("PromptOnSecureDesktop", f.FixCommand);
    }

    [Fact]
    public void PromptOnSecureDesktop_On_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzePromptOnSecureDesktop(HardenedState()).Severity);
    }

    [Fact]
    public void FilterAdministratorToken_Off_Is_Warning()
    {
        var f = AnalyzeFilterAdministratorToken(HardenedState() with { FilterAdministratorToken = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Administrator", f.Title);
        Assert.Contains("FilterAdministratorToken", f.FixCommand);
    }

    [Fact]
    public void FilterAdministratorToken_On_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzeFilterAdministratorToken(HardenedState()).Severity);
    }

    [Fact]
    public void InstallerDetection_Off_Is_Info_Not_Failure()
    {
        // Installer detection is advisory (usability/robustness), so its absence is Info,
        // not a hard Warning/Critical.
        var f = AnalyzeInstallerDetection(HardenedState() with { EnableInstallerDetection = false });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void InstallerDetection_On_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzeInstallerDetection(HardenedState()).Severity);
    }

    [Fact]
    public void LocalAccountTokenFilterPolicy_Enabled_Is_Critical()
    {
        var f = AnalyzeLocalAccountTokenFilterPolicy(HardenedState() with { LocalAccountTokenFilterPolicyEnabled = true });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("token filtering is disabled", f.Title);
        Assert.Contains("LocalAccountTokenFilterPolicy", f.FixCommand);
    }

    [Fact]
    public void LocalAccountTokenFilterPolicy_Disabled_Is_Pass()
    {
        var f = AnalyzeLocalAccountTokenFilterPolicy(HardenedState());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("token filtering is intact", f.Title);
    }

    [Fact]
    public void Defaults_Are_Secure_So_Empty_State_Is_All_Pass()
    {
        // A default-constructed state models an unreadable registry: every value must fall to
        // the SECURE posture so a missing key never false-positives the dangerous state.
        var findings = UacHardeningAnalyzer.Analyze(new UacHardeningState());
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    [Fact]
    public void Worst_Case_State_Flags_Three_Critical()
    {
        var worst = new UacHardeningState
        {
            EnableLua = false,
            ConsentPromptBehaviorAdmin = 0,
            PromptOnSecureDesktop = false,
            FilterAdministratorToken = false,
            EnableInstallerDetection = false,
            LocalAccountTokenFilterPolicyEnabled = true,
        };
        var findings = UacHardeningAnalyzer.Analyze(worst);
        var criticals = findings.Count(f => f.Severity == Severity.Critical);
        Assert.Equal(3, criticals); // UAC off, silent elevation, remote token filtering disabled
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
    }
}
