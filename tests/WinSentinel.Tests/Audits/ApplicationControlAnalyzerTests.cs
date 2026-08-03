using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.ApplicationControlAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="ApplicationControlAnalyzer"/> - the
/// single-machine application-allowlisting checks: AppLocker rule-collection enforcement
/// (Exe/Msi/Script/Dll/Appx), the Application Identity enforcement service, WDAC/Code
/// Integrity policy state, and Smart App Control. Every rule is exercised directly against a
/// synthetic <see cref="ApplicationControlState"/>; no registry/service I/O is touched.
/// </summary>
public class ApplicationControlAnalyzerTests
{
    private static Dictionary<string, AppLockerEnforcementMode> AllEnforced() => new()
    {
        ["Exe"] = AppLockerEnforcementMode.Enabled,
        ["Msi"] = AppLockerEnforcementMode.Enabled,
        ["Script"] = AppLockerEnforcementMode.Enabled,
        ["Dll"] = AppLockerEnforcementMode.Enabled,
        ["Appx"] = AppLockerEnforcementMode.Enabled,
    };

    private static ApplicationControlState EnforcedState() => new()
    {
        AppLockerCollections = AllEnforced(),
        AppIdServiceRunning = true,
        WdacEnforced = false,
        WdacAuditOnly = false,
        SmartAppControlState = -1,
    };

    // Expected finding count: overall + AppIDSvc + 5 collections + WDAC + SmartAppControl = 9.
    private const int ExpectedCount = 9;

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => ApplicationControlAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Returns_Stable_Count()
    {
        Assert.Equal(ExpectedCount, ApplicationControlAnalyzer.Analyze(EnforcedState()).Count);
        Assert.Equal(ExpectedCount, ApplicationControlAnalyzer.Analyze(new ApplicationControlState()).Count);
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var state = EnforcedState();
        var a = ApplicationControlAnalyzer.Analyze(state).Select(f => f.Title).ToArray();
        var b = ApplicationControlAnalyzer.Analyze(state).Select(f => f.Title).ToArray();
        Assert.Equal(a, b);
    }

    [Fact]
    public void Analyze_All_Findings_Carry_Category()
    {
        Assert.All(ApplicationControlAnalyzer.Analyze(EnforcedState()),
            f => Assert.Equal(Category, f.Category));
    }

    // ---- Overall posture ----

    [Fact]
    public void Overall_Enforcing_AppLocker_Passes()
    {
        var f = ApplicationControlAnalyzer.AnalyzeAppLockerOverall(EnforcedState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Overall_Enforcing_Requires_Running_Service()
    {
        var state = EnforcedState() with { AppIdServiceRunning = false };
        var f = ApplicationControlAnalyzer.AnalyzeAppLockerOverall(state);
        // Enforced rules but stopped service => not actually enforcing.
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void Overall_Wdac_Alone_Enforces()
    {
        var state = new ApplicationControlState { WdacEnforced = true };
        var f = ApplicationControlAnalyzer.AnalyzeAppLockerOverall(state);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Overall_SmartAppControl_On_Enforces()
    {
        var state = new ApplicationControlState { SmartAppControlState = 1 };
        var f = ApplicationControlAnalyzer.AnalyzeAppLockerOverall(state);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Overall_AuditOnly_Is_Warning()
    {
        var audited = new Dictionary<string, AppLockerEnforcementMode>
        {
            ["Exe"] = AppLockerEnforcementMode.AuditOnly,
        };
        var state = new ApplicationControlState { AppLockerCollections = audited };
        var f = ApplicationControlAnalyzer.AnalyzeAppLockerOverall(state);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("not enforcing", f.Title);
    }

    [Fact]
    public void Overall_Nothing_Configured_Is_Warning()
    {
        var f = ApplicationControlAnalyzer.AnalyzeAppLockerOverall(new ApplicationControlState());
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("No application allowlisting", f.Title);
    }

    // ---- AppIDSvc enforcement service ----

    [Fact]
    public void AppIdService_NotNeeded_When_No_Enforcement()
    {
        var f = ApplicationControlAnalyzer.AnalyzeAppIdService(new ApplicationControlState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void AppIdService_Running_With_Enforcement_Passes()
    {
        var f = ApplicationControlAnalyzer.AnalyzeAppIdService(EnforcedState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void AppIdService_Stopped_With_Enforcement_Is_Critical()
    {
        var state = EnforcedState() with { AppIdServiceRunning = false };
        var f = ApplicationControlAnalyzer.AnalyzeAppIdService(state);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.NotNull(f.FixCommand);
    }

    // ---- Per-collection ----

    [Fact]
    public void Collection_Enabled_Passes()
    {
        var f = ApplicationControlAnalyzer.AnalyzeCollection(EnforcedState(), "Exe", "executables", core: true);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Collection_AuditOnly_Is_Warning()
    {
        var state = new ApplicationControlState
        {
            AppLockerCollections = new Dictionary<string, AppLockerEnforcementMode>
            {
                ["Exe"] = AppLockerEnforcementMode.AuditOnly,
            },
        };
        var f = ApplicationControlAnalyzer.AnalyzeCollection(state, "Exe", "executables", core: true);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void Collection_Core_NotConfigured_Is_Warning()
    {
        var f = ApplicationControlAnalyzer.AnalyzeCollection(new ApplicationControlState(), "Exe", "executables", core: true);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void Collection_NonCore_NotConfigured_Is_Info()
    {
        var f = ApplicationControlAnalyzer.AnalyzeCollection(new ApplicationControlState(), "Dll", "DLLs", core: false);
        Assert.Equal(Severity.Info, f.Severity);
    }

    // ---- WDAC ----

    [Fact]
    public void Wdac_Enforced_Passes()
    {
        var f = ApplicationControlAnalyzer.AnalyzeWdac(new ApplicationControlState { WdacEnforced = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Wdac_AuditOnly_Is_Info()
    {
        var f = ApplicationControlAnalyzer.AnalyzeWdac(new ApplicationControlState { WdacAuditOnly = true });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void Wdac_Absent_Is_Info()
    {
        var f = ApplicationControlAnalyzer.AnalyzeWdac(new ApplicationControlState());
        Assert.Equal(Severity.Info, f.Severity);
    }

    // ---- Smart App Control ----

    [Theory]
    [InlineData(1, Severity.Pass)]
    [InlineData(2, Severity.Info)]
    [InlineData(0, Severity.Info)]
    [InlineData(-1, Severity.Info)]
    public void SmartAppControl_States(int sac, Severity expected)
    {
        var f = ApplicationControlAnalyzer.AnalyzeSmartAppControl(new ApplicationControlState { SmartAppControlState = sac });
        Assert.Equal(expected, f.Severity);
    }

    // ---- State helpers ----

    [Fact]
    public void GetCollectionMode_Defaults_NotConfigured()
    {
        Assert.Equal(AppLockerEnforcementMode.NotConfigured, new ApplicationControlState().GetCollectionMode("Exe"));
    }

    [Fact]
    public void AnyAppLockerConfigured_And_Enforcing_Flags()
    {
        var audited = new ApplicationControlState
        {
            AppLockerCollections = new Dictionary<string, AppLockerEnforcementMode>
            {
                ["Exe"] = AppLockerEnforcementMode.AuditOnly,
            },
        };
        Assert.True(audited.AnyAppLockerConfigured);
        Assert.False(audited.AnyAppLockerEnforcing);

        Assert.True(EnforcedState().AnyAppLockerEnforcing);
        Assert.False(new ApplicationControlState().AnyAppLockerConfigured);
    }
}
