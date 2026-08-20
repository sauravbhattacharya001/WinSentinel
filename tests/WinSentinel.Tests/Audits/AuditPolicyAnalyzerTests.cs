using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.AuditPolicyAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="AuditPolicyAnalyzer"/> - the
/// single-machine advanced-audit-policy checks (Logon, Credential Validation,
/// Process Creation, Audit Policy Change, User Account Management) plus the
/// <c>auditpol /get /category:* /r</c> CSV parser. Every rule is exercised directly
/// against a synthetic <see cref="AuditPolicyState"/> (or parsed CSV text); no
/// process or I/O is touched.
/// </summary>
public class AuditPolicyAnalyzerTests
{
    private static AuditPolicyState StateOf(params (string name, bool success, bool failure)[] rows)
    {
        var map = new Dictionary<string, SubcategorySetting>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, s, f) in rows)
        {
            map[name] = new SubcategorySetting(s, f);
        }
        return new AuditPolicyState(map);
    }

    private static AuditPolicyState FullyHardened() => StateOf(
        ("Logon", true, true),
        ("Credential Validation", true, true),
        ("Process Creation", true, false),
        ("Audit Policy Change", true, true),
        ("User Account Management", true, false));

    // --- Analyze() shape -------------------------------------------------------

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_HardenedState_IsAllPass()
    {
        var findings = Analyze(FullyHardened());
        Assert.Equal(5, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    [Fact]
    public void Analyze_EmptyState_IsAllWarning()
    {
        var findings = Analyze(new AuditPolicyState(new Dictionary<string, SubcategorySetting>()));
        Assert.Equal(5, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Warning, f.Severity));
    }

    [Fact]
    public void Analyze_EveryFinding_UsesTheAuditPolicyCategory()
    {
        var findings = Analyze(FullyHardened());
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    // --- Success+Failure subcategories -----------------------------------------

    [Theory]
    [InlineData(true, true, Severity.Pass)]
    [InlineData(true, false, Severity.Warning)]
    [InlineData(false, true, Severity.Warning)]
    [InlineData(false, false, Severity.Warning)]
    public void Logon_RequiresSuccessAndFailure(bool success, bool failure, Severity expected)
    {
        var f = AnalyzeLogon(StateOf(("Logon", success, failure)));
        Assert.Equal(expected, f.Severity);
    }

    [Theory]
    [InlineData(true, true, Severity.Pass)]
    [InlineData(true, false, Severity.Warning)]
    [InlineData(false, false, Severity.Warning)]
    public void CredentialValidation_RequiresSuccessAndFailure(bool success, bool failure, Severity expected)
    {
        var f = AnalyzeCredentialValidation(StateOf(("Credential Validation", success, failure)));
        Assert.Equal(expected, f.Severity);
    }

    [Theory]
    [InlineData(true, true, Severity.Pass)]
    [InlineData(false, true, Severity.Warning)]
    public void AuditPolicyChange_RequiresSuccessAndFailure(bool success, bool failure, Severity expected)
    {
        var f = AnalyzeAuditPolicyChange(StateOf(("Audit Policy Change", success, failure)));
        Assert.Equal(expected, f.Severity);
    }

    // --- Success-only subcategories --------------------------------------------

    [Theory]
    [InlineData(true, Severity.Pass)]
    [InlineData(false, Severity.Warning)]
    public void ProcessCreation_RequiresSuccess(bool success, Severity expected)
    {
        var f = AnalyzeProcessCreation(StateOf(("Process Creation", success, false)));
        Assert.Equal(expected, f.Severity);
    }

    [Theory]
    [InlineData(true, Severity.Pass)]
    [InlineData(false, Severity.Warning)]
    public void AccountManagement_RequiresSuccess(bool success, Severity expected)
    {
        var f = AnalyzeAccountManagement(StateOf(("User Account Management", success, false)));
        Assert.Equal(expected, f.Severity);
    }

    [Fact]
    public void MissingSubcategory_Warns_NotFalsePass()
    {
        // Empty state -> subcategory absent -> must warn, and mention it wasn't reported.
        var f = AnalyzeProcessCreation(new AuditPolicyState(new Dictionary<string, SubcategorySetting>()));
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("not reported", f.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WarningFindings_CarryFixCommand()
    {
        var f = AnalyzeLogon(StateOf(("Logon", false, false)));
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
        Assert.Contains("auditpol", f.FixCommand!, StringComparison.OrdinalIgnoreCase);
    }

    // --- SubcategorySetting semantics ------------------------------------------

    [Theory]
    [InlineData(true, true, "Success and Failure")]
    [InlineData(true, false, "Success")]
    [InlineData(false, true, "Failure")]
    [InlineData(false, false, "No Auditing")]
    public void SubcategorySetting_Describe(bool s, bool f, string expected)
    {
        Assert.Equal(expected, new SubcategorySetting(s, f).Describe());
    }

    [Fact]
    public void SubcategorySetting_IsNoAuditing()
    {
        Assert.True(new SubcategorySetting(false, false).IsNoAuditing);
        Assert.False(new SubcategorySetting(true, false).IsNoAuditing);
    }

    // --- CSV parser ------------------------------------------------------------

    private const string SampleCsv =
        "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
        "WORKSTATION,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\r\n" +
        "WORKSTATION,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,\r\n" +
        "WORKSTATION,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},No Auditing,\r\n";

    [Fact]
    public void ParseCsv_ReadsSubcategoriesAndSettings()
    {
        var state = ParseAuditpolCsv(SampleCsv);
        Assert.Equal(3, state.Count);

        var logon = state.Get("Logon");
        Assert.NotNull(logon);
        Assert.True(logon!.Success);
        Assert.True(logon.Failure);

        var proc = state.Get("Process Creation");
        Assert.NotNull(proc);
        Assert.True(proc!.Success);
        Assert.False(proc.Failure);

        var cred = state.Get("Credential Validation");
        Assert.NotNull(cred);
        Assert.True(cred!.IsNoAuditing);
    }

    [Fact]
    public void ParseCsv_ThenAnalyze_ProducesExpectedSeverities()
    {
        var state = ParseAuditpolCsv(SampleCsv);
        Assert.Equal(Severity.Pass, AnalyzeLogon(state).Severity);            // Success and Failure
        Assert.Equal(Severity.Pass, AnalyzeProcessCreation(state).Severity);  // Success
        Assert.Equal(Severity.Warning, AnalyzeCredentialValidation(state).Severity); // No Auditing
    }

    [Fact]
    public void ParseCsv_HandlesLfOnlyLineEndings()
    {
        var lf = SampleCsv.Replace("\r\n", "\n");
        var state = ParseAuditpolCsv(lf);
        Assert.Equal(3, state.Count);
        Assert.True(state.Get("Logon")!.Success);
    }

    [Fact]
    public void ParseCsv_NoHeader_UsesFixedColumnLayout()
    {
        // Some hosts/locales omit the header row; fall back to fixed auditpol columns.
        var noHeader =
            "WORKSTATION,System,Logon,{GUID},Success and Failure,\n" +
            "WORKSTATION,System,User Account Management,{GUID},Success,\n";
        var state = ParseAuditpolCsv(noHeader);
        Assert.Equal(2, state.Count);
        Assert.True(state.Get("Logon")!.Failure);
        Assert.True(state.Get("User Account Management")!.Success);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ParseCsv_EmptyInput_YieldsEmptyState(string? csv)
    {
        var state = ParseAuditpolCsv(csv);
        Assert.Equal(0, state.Count);
        // And the analyzer then warns on everything rather than false-passing.
        Assert.All(Analyze(state), f => Assert.Equal(Severity.Warning, f.Severity));
    }

    [Fact]
    public void ParseCsv_IgnoresBlankLines()
    {
        var withBlanks = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting\n\nWS,System,Logon,{G},Success and Failure\n\n";
        var state = ParseAuditpolCsv(withBlanks);
        Assert.Equal(1, state.Count);
        Assert.True(state.Get("Logon")!.Success);
    }
}
