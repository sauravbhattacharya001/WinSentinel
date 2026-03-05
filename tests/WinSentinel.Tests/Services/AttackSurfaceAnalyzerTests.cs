using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.AttackSurfaceAnalyzer;

namespace WinSentinel.Tests.Services;

public class AttackSurfaceAnalyzerTests
{
    private readonly AttackSurfaceAnalyzer _sut = new();

    private static Finding MakeFinding(Severity severity, string category,
        string title = "Test Finding", string? remediation = null) => new()
    {
        Title = title,
        Description = $"Test finding: {title}",
        Severity = severity,
        Category = category,
        Remediation = remediation
    };

    private static AuditResult MakeResult(string module, string category, params Finding[] findings) => new()
    {
        ModuleName = module,
        Category = category,
        Findings = findings.ToList(),
        StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
        EndTime = DateTimeOffset.UtcNow
    };

    private static SecurityReport MakeReport(params AuditResult[] results) => new()
    {
        Results = results.ToList(),
        SecurityScore = 50
    };

    // ── Analyze: Empty report ──

    [Fact]
    public void Analyze_EmptyReport_ScoreIsZero()
    {
        var report = MakeReport();
        var result = _sut.Analyze(report);
        Assert.Equal(0, result.OverallScore);
        Assert.Equal("A", result.OverallGrade);
        Assert.Equal(0, result.TotalFindings);
    }

    [Fact]
    public void Analyze_EmptyReport_AllVectorsPresent()
    {
        var report = MakeReport();
        var result = _sut.Analyze(report);
        Assert.Equal(Enum.GetValues<SurfaceVector>().Length, result.Vectors.Count);
    }

    // ── Vector mapping ──

    [Fact]
    public void Analyze_FirewallCategory_MapsToNetwork()
    {
        var report = MakeReport(MakeResult("Firewall Audit", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Open port detected")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(1, network.TotalFindings);
        Assert.Equal(1, network.WarningCount);
    }

    [Fact]
    public void Analyze_AccountsCategory_MapsToAuthentication()
    {
        var report = MakeReport(MakeResult("Account Audit", "Accounts",
            MakeFinding(Severity.Critical, "Accounts", "Guest account enabled")));
        var result = _sut.Analyze(report);
        var auth = result.Vectors.First(v => v.Vector == SurfaceVector.Authentication);
        Assert.Equal(1, auth.CriticalCount);
    }

    [Fact]
    public void Analyze_RemoteAccessCategory_MapsCorrectly()
    {
        var report = MakeReport(MakeResult("Remote Access Audit", "RemoteAccess",
            MakeFinding(Severity.Warning, "RemoteAccess", "RDP exposed")));
        var result = _sut.Analyze(report);
        var ra = result.Vectors.First(v => v.Vector == SurfaceVector.RemoteAccess);
        Assert.Equal(1, ra.WarningCount);
    }

    [Fact]
    public void Analyze_BluetoothCategory_MapsToPhysicalAccess()
    {
        var report = MakeReport(MakeResult("Bluetooth Audit", "Bluetooth",
            MakeFinding(Severity.Warning, "Bluetooth", "Discoverable")));
        var result = _sut.Analyze(report);
        var phys = result.Vectors.First(v => v.Vector == SurfaceVector.PhysicalAccess);
        Assert.Equal(1, phys.TotalFindings);
    }

    [Fact]
    public void Analyze_EncryptionCategory_MapsToDataExposure()
    {
        var report = MakeReport(MakeResult("Encryption Audit", "Encryption",
            MakeFinding(Severity.Critical, "Encryption", "BitLocker disabled")));
        var result = _sut.Analyze(report);
        var data = result.Vectors.First(v => v.Vector == SurfaceVector.DataExposure);
        Assert.Equal(1, data.CriticalCount);
    }

    [Fact]
    public void Analyze_RegistryCategory_MapsToConfiguration()
    {
        var report = MakeReport(MakeResult("Registry Audit", "Registry",
            MakeFinding(Severity.Warning, "Registry", "UAC disabled")));
        var result = _sut.Analyze(report);
        var config = result.Vectors.First(v => v.Vector == SurfaceVector.Configuration);
        Assert.Equal(1, config.TotalFindings);
    }

    [Fact]
    public void Analyze_ProcessCategory_MapsToPrivilege()
    {
        var report = MakeReport(MakeResult("Process Audit", "Process",
            MakeFinding(Severity.Warning, "Process", "Elevated process")));
        var result = _sut.Analyze(report);
        var priv = result.Vectors.First(v => v.Vector == SurfaceVector.Privilege);
        Assert.Equal(1, priv.TotalFindings);
    }

    [Fact]
    public void Analyze_SoftwareCategory_MapsToSoftware()
    {
        var report = MakeReport(MakeResult("Software Audit", "Software",
            MakeFinding(Severity.Warning, "Software", "Outdated app")));
        var result = _sut.Analyze(report);
        var sw = result.Vectors.First(v => v.Vector == SurfaceVector.Software);
        Assert.Equal(1, sw.TotalFindings);
    }

    // ── Keyword fallback mapping ──

    [Fact]
    public void Analyze_UnknownCategory_FallsBackToKeyword_Password()
    {
        var report = MakeReport(MakeResult("Custom", "Unknown",
            MakeFinding(Severity.Warning, "Unknown", "Weak password policy")));
        var result = _sut.Analyze(report);
        var auth = result.Vectors.First(v => v.Vector == SurfaceVector.Authentication);
        Assert.Equal(1, auth.TotalFindings);
    }

    [Fact]
    public void Analyze_UnknownCategory_FallsBackToKeyword_Firewall()
    {
        var report = MakeReport(MakeResult("Custom", "Unknown",
            MakeFinding(Severity.Warning, "Unknown", "Firewall rule issue")));
        var result = _sut.Analyze(report);
        var net = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(1, net.TotalFindings);
    }

    [Fact]
    public void Analyze_UnknownCategory_FallsBackToConfiguration()
    {
        var report = MakeReport(MakeResult("Custom", "Unknown",
            MakeFinding(Severity.Warning, "Unknown", "Something misconfigured")));
        var result = _sut.Analyze(report);
        var config = result.Vectors.First(v => v.Vector == SurfaceVector.Configuration);
        Assert.True(config.TotalFindings > 0);
    }

    // ── Exposure scoring ──

    [Fact]
    public void Analyze_CriticalFinding_Scores15Points()
    {
        var report = MakeReport(MakeResult("Test", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "Critical issue")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(15.0, network.ExposureScore);
    }

    [Fact]
    public void Analyze_WarningFinding_Scores5Points()
    {
        var report = MakeReport(MakeResult("Test", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Warning issue")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(5.0, network.ExposureScore);
    }

    [Fact]
    public void Analyze_InfoFinding_Scores1Point()
    {
        var report = MakeReport(MakeResult("Test", "Firewall",
            MakeFinding(Severity.Info, "Firewall", "Info item")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(1.0, network.ExposureScore);
    }

    [Fact]
    public void Analyze_PassFinding_ScoresZero()
    {
        var report = MakeReport(MakeResult("Test", "Firewall",
            MakeFinding(Severity.Pass, "Firewall", "All good")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(0.0, network.ExposureScore);
    }

    [Fact]
    public void Analyze_ExposureScoreCappedAt100()
    {
        // 7 critical = 105, but should cap at 100
        var findings = Enumerable.Range(0, 7)
            .Select(i => MakeFinding(Severity.Critical, "Firewall", $"Critical {i}"))
            .ToArray();
        var report = MakeReport(MakeResult("Test", "Firewall", findings));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(100.0, network.ExposureScore);
    }

    [Fact]
    public void Analyze_MixedSeverities_SumsCorrectly()
    {
        // 1 critical (15) + 2 warnings (10) + 3 info (3) = 28
        var report = MakeReport(MakeResult("Test", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "Crit"),
            MakeFinding(Severity.Warning, "Firewall", "Warn1"),
            MakeFinding(Severity.Warning, "Firewall", "Warn2"),
            MakeFinding(Severity.Info, "Firewall", "Info1"),
            MakeFinding(Severity.Info, "Firewall", "Info2"),
            MakeFinding(Severity.Info, "Firewall", "Info3")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(28.0, network.ExposureScore);
    }

    // ── Grading ──

    [Fact]
    public void Analyze_LowExposure_GradeA()
    {
        var report = MakeReport(MakeResult("Test", "Firewall",
            MakeFinding(Severity.Pass, "Firewall", "Good")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal("A", network.Grade);
    }

    [Fact]
    public void Analyze_ModerateExposure_GradeC()
    {
        // 6 warnings = 30 points -> C
        var findings = Enumerable.Range(0, 6)
            .Select(i => MakeFinding(Severity.Warning, "Firewall", $"Warn {i}"))
            .ToArray();
        var report = MakeReport(MakeResult("Test", "Firewall", findings));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal("C", network.Grade);
    }

    [Fact]
    public void Analyze_HighExposure_GradeF()
    {
        // 5 critical = 75 points -> F
        var findings = Enumerable.Range(0, 5)
            .Select(i => MakeFinding(Severity.Critical, "Firewall", $"Crit {i}"))
            .ToArray();
        var report = MakeReport(MakeResult("Test", "Firewall", findings));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal("F", network.Grade);
    }

    // ── Overall score ──

    [Fact]
    public void Analyze_SingleVector_OverallEqualsVector()
    {
        var report = MakeReport(MakeResult("Test", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Issue")));
        var result = _sut.Analyze(report);
        Assert.Equal(5.0, result.OverallScore);
    }

    [Fact]
    public void Analyze_MultipleVectors_OverallIsAverage()
    {
        // Network: 15 (critical), Auth: 5 (warning) -> avg = 10
        var report = MakeReport(
            MakeResult("Test1", "Firewall", MakeFinding(Severity.Critical, "Firewall", "Crit")),
            MakeResult("Test2", "Accounts", MakeFinding(Severity.Warning, "Accounts", "Warn")));
        var result = _sut.Analyze(report);
        Assert.Equal(10.0, result.OverallScore);
    }

    // ── Most/Least exposed ──

    [Fact]
    public void Analyze_MostExposedVector_Correct()
    {
        var report = MakeReport(
            MakeResult("T1", "Firewall", MakeFinding(Severity.Critical, "Firewall", "C1")),
            MakeResult("T2", "Accounts", MakeFinding(Severity.Warning, "Accounts", "W1")));
        var result = _sut.Analyze(report);
        Assert.Equal(SurfaceVector.Network, result.MostExposedVector);
    }

    [Fact]
    public void Analyze_LeastExposedVector_Correct()
    {
        var report = MakeReport(
            MakeResult("T1", "Firewall", MakeFinding(Severity.Critical, "Firewall", "C1")),
            MakeResult("T2", "Accounts", MakeFinding(Severity.Warning, "Accounts", "W1")));
        var result = _sut.Analyze(report);
        Assert.Equal(SurfaceVector.Authentication, result.LeastExposedVector);
    }

    [Fact]
    public void Analyze_NoFindings_MostExposedIsNull()
    {
        var report = MakeReport();
        var result = _sut.Analyze(report);
        Assert.Null(result.MostExposedVector);
    }

    // ── Totals ──

    [Fact]
    public void Analyze_TotalCritical_CountsCorrectly()
    {
        var report = MakeReport(
            MakeResult("T1", "Firewall",
                MakeFinding(Severity.Critical, "Firewall", "C1"),
                MakeFinding(Severity.Critical, "Firewall", "C2")),
            MakeResult("T2", "Accounts",
                MakeFinding(Severity.Critical, "Accounts", "C3")));
        var result = _sut.Analyze(report);
        Assert.Equal(3, result.TotalCritical);
    }

    [Fact]
    public void Analyze_TotalWarnings_CountsCorrectly()
    {
        var report = MakeReport(
            MakeResult("T1", "Firewall",
                MakeFinding(Severity.Warning, "Firewall", "W1")),
            MakeResult("T2", "Accounts",
                MakeFinding(Severity.Warning, "Accounts", "W2"),
                MakeFinding(Severity.Warning, "Accounts", "W3")));
        var result = _sut.Analyze(report);
        Assert.Equal(3, result.TotalWarnings);
    }

    [Fact]
    public void Analyze_TotalFindings_CountsAll()
    {
        var report = MakeReport(
            MakeResult("T1", "Firewall",
                MakeFinding(Severity.Critical, "Firewall", "C1"),
                MakeFinding(Severity.Pass, "Firewall", "P1")));
        var result = _sut.Analyze(report);
        Assert.Equal(2, result.TotalFindings);
    }

    // ── Reduction actions ──

    [Fact]
    public void Analyze_ReductionActions_SkipsPassAndInfo()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Pass, "Firewall", "Good"),
            MakeFinding(Severity.Info, "Firewall", "Info")));
        var result = _sut.Analyze(report);
        Assert.Empty(result.TopActions);
    }

    [Fact]
    public void Analyze_ReductionActions_IncludesWarnings()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Warn", "Fix this")));
        var result = _sut.Analyze(report);
        Assert.Single(result.TopActions);
        Assert.Equal("Fix this", result.TopActions[0].Action);
    }

    [Fact]
    public void Analyze_ReductionActions_CriticalHasHigherReduction()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "Crit"),
            MakeFinding(Severity.Warning, "Firewall", "Warn")));
        var result = _sut.Analyze(report);
        Assert.Equal(2, result.TopActions.Count);
        Assert.Equal(15.0, result.TopActions[0].EstimatedReduction);
    }

    [Fact]
    public void Analyze_ReductionActions_UsesRemediationText()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Issue", "Enable firewall")));
        var result = _sut.Analyze(report);
        Assert.Equal("Enable firewall", result.TopActions[0].Action);
    }

    [Fact]
    public void Analyze_ReductionActions_FallsBackToTitle()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Open port 8080")));
        var result = _sut.Analyze(report);
        Assert.Contains("Open port 8080", result.TopActions[0].Action);
    }

    [Fact]
    public void Analyze_ReductionActions_CappedAt15()
    {
        var findings = Enumerable.Range(0, 20)
            .Select(i => MakeFinding(Severity.Warning, "Firewall", $"Warn {i}"))
            .ToArray();
        var report = MakeReport(MakeResult("T1", "Firewall", findings));
        var result = _sut.Analyze(report);
        Assert.True(result.TopActions.Count <= 15);
    }

    // ── Recommendations ──

    [Fact]
    public void Analyze_NetworkVector_HasRecommendations()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "Issue")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.NotEmpty(network.Recommendations);
    }

    [Fact]
    public void Analyze_AuthVector_HasRecommendations()
    {
        var report = MakeReport(MakeResult("T1", "Accounts",
            MakeFinding(Severity.Critical, "Accounts", "Issue")));
        var result = _sut.Analyze(report);
        var auth = result.Vectors.First(v => v.Vector == SurfaceVector.Authentication);
        Assert.NotEmpty(auth.Recommendations);
    }

    [Fact]
    public void Analyze_PassOnlyVector_NoRecommendations()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Pass, "Firewall", "Good")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Empty(network.Recommendations);
    }

    // ── Contributing modules ──

    [Fact]
    public void Analyze_ContributingModules_TracksDistinctModules()
    {
        var report = MakeReport(
            MakeResult("Firewall Audit", "Firewall",
                MakeFinding(Severity.Warning, "Firewall", "W1")),
            MakeResult("DNS Audit", "DNS",
                MakeFinding(Severity.Warning, "DNS", "W2")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(2, network.ContributingModules.Count);
        Assert.Contains("Firewall Audit", network.ContributingModules);
        Assert.Contains("DNS Audit", network.ContributingModules);
    }

    // ── Comparison ──

    [Fact]
    public void AnalyzeWithComparison_ScoreDelta_Calculated()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "C1")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.NotNull(result.Comparison);
        Assert.Equal(10.0, result.Comparison.ScoreDelta); // 15 - 5
    }

    [Fact]
    public void AnalyzeWithComparison_Direction_Worsened()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "C1"),
            MakeFinding(Severity.Critical, "Firewall", "C2")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.Equal("Worsened", result.Comparison!.Direction);
    }

    [Fact]
    public void AnalyzeWithComparison_Direction_Improved()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "C1"),
            MakeFinding(Severity.Critical, "Firewall", "C2")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.Equal("Improved", result.Comparison!.Direction);
    }

    [Fact]
    public void AnalyzeWithComparison_Direction_Unchanged()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.Equal("Unchanged", result.Comparison!.Direction);
    }

    [Fact]
    public void AnalyzeWithComparison_NewFindings_Counted()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Old")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Old"),
            MakeFinding(Severity.Warning, "Firewall", "New")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.Equal(1, result.Comparison!.NewFindings);
    }

    [Fact]
    public void AnalyzeWithComparison_ResolvedFindings_Counted()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Fixed"),
            MakeFinding(Severity.Warning, "Firewall", "Remaining")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Remaining")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.Equal(1, result.Comparison!.ResolvedFindings);
    }

    [Fact]
    public void AnalyzeWithComparison_VectorDeltas_Present()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "C1")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.NotEmpty(result.Comparison!.VectorDeltas);
        var networkDelta = result.Comparison.VectorDeltas.First(d => d.Vector == SurfaceVector.Network);
        Assert.Equal(10.0, networkDelta.ScoreDelta);
    }

    // ── GetVectorPriorities ──

    [Fact]
    public void GetVectorPriorities_SortedByExposure()
    {
        var report = MakeReport(
            MakeResult("T1", "Firewall", MakeFinding(Severity.Critical, "Firewall", "C1")),
            MakeResult("T2", "Accounts", MakeFinding(Severity.Warning, "Accounts", "W1")));
        var priorities = _sut.GetVectorPriorities(report);
        Assert.Equal(SurfaceVector.Network, priorities[0].Vector);
        Assert.Equal(SurfaceVector.Authentication, priorities[1].Vector);
    }

    [Fact]
    public void GetVectorPriorities_ExcludesEmptyVectors()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var priorities = _sut.GetVectorPriorities(report);
        Assert.Single(priorities);
    }

    // ── Summary ──

    [Fact]
    public void Analyze_Summary_ContainsKey()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "Issue")));
        var result = _sut.Analyze(report);
        Assert.Contains("ATTACK SURFACE ANALYSIS", result.Summary);
        Assert.Contains("Grade:", result.Summary);
        Assert.Contains("Network", result.Summary);
    }

    [Fact]
    public void Analyze_Summary_ContainsReductionActions()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Issue", "Fix it")));
        var result = _sut.Analyze(report);
        Assert.Contains("Reduction Actions", result.Summary);
    }

    [Fact]
    public void AnalyzeWithComparison_Summary_ContainsComparison()
    {
        var prev = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "W1")));
        var curr = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "C1")));
        var result = _sut.AnalyzeWithComparison(curr, prev);
        Assert.Contains("Comparison", result.Summary);
        Assert.Contains("Score change", result.Summary);
    }

    // ── Null input ──

    [Fact]
    public void Analyze_NullReport_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.Analyze(null!));
    }

    // ── Multi-module same vector ──

    [Fact]
    public void Analyze_MultipleModulesSameVector_Aggregated()
    {
        var report = MakeReport(
            MakeResult("Firewall Audit", "Firewall",
                MakeFinding(Severity.Critical, "Firewall", "FW issue")),
            MakeResult("DNS Audit", "DNS",
                MakeFinding(Severity.Warning, "DNS", "DNS issue")),
            MakeResult("WiFi Audit", "WiFi",
                MakeFinding(Severity.Warning, "WiFi", "WiFi issue")));
        var result = _sut.Analyze(report);
        var network = result.Vectors.First(v => v.Vector == SurfaceVector.Network);
        Assert.Equal(3, network.TotalFindings);
        Assert.Equal(25.0, network.ExposureScore); // 15 + 5 + 5
    }

    // ── Edge: all pass findings ──

    [Fact]
    public void Analyze_AllPassFindings_ZeroOverall()
    {
        var report = MakeReport(
            MakeResult("T1", "Firewall", MakeFinding(Severity.Pass, "Firewall", "OK")),
            MakeResult("T2", "Accounts", MakeFinding(Severity.Pass, "Accounts", "OK")));
        var result = _sut.Analyze(report);
        // Vectors have findings but 0 exposure, so average of 0s
        Assert.Equal(0, result.OverallScore);
    }

    // ── Large report ──

    [Fact]
    public void Analyze_LargeReport_HandlesGracefully()
    {
        var results = Enumerable.Range(0, 50).Select(i =>
            MakeResult($"Module{i}", "Firewall",
                MakeFinding(Severity.Warning, "Firewall", $"Finding {i}"))).ToArray();
        var report = MakeReport(results);
        var result = _sut.Analyze(report);
        Assert.Equal(50, result.TotalFindings);
        Assert.True(result.OverallScore > 0);
    }

    // ── Action priority ──

    [Fact]
    public void Analyze_CriticalFinding_ActionPriorityCritical()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Critical, "Firewall", "Crit")));
        var result = _sut.Analyze(report);
        Assert.Equal(ActionPriority.Critical, result.TopActions[0].Priority);
    }

    [Fact]
    public void Analyze_WarningFinding_ActionPriorityMedium()
    {
        var report = MakeReport(MakeResult("T1", "Firewall",
            MakeFinding(Severity.Warning, "Firewall", "Warn")));
        var result = _sut.Analyze(report);
        Assert.Equal(ActionPriority.Medium, result.TopActions[0].Priority);
    }

    // ── Vector-specific recommendation content ──

    [Fact]
    public void Analyze_RemoteAccessCritical_MentionsDisable()
    {
        var report = MakeReport(MakeResult("T1", "RemoteAccess",
            MakeFinding(Severity.Critical, "RemoteAccess", "RDP open")));
        var result = _sut.Analyze(report);
        var ra = result.Vectors.First(v => v.Vector == SurfaceVector.RemoteAccess);
        Assert.Contains(ra.Recommendations, r => r.Contains("Disable", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_SoftwareCritical_MentionsUpdates()
    {
        var report = MakeReport(MakeResult("T1", "Updates",
            MakeFinding(Severity.Critical, "Updates", "Missing patches")));
        var result = _sut.Analyze(report);
        var sw = result.Vectors.First(v => v.Vector == SurfaceVector.Software);
        Assert.Contains(sw.Recommendations, r => r.Contains("update", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_DataExposureCritical_MentionsEncryption()
    {
        var report = MakeReport(MakeResult("T1", "Encryption",
            MakeFinding(Severity.Critical, "Encryption", "No encryption")));
        var result = _sut.Analyze(report);
        var de = result.Vectors.First(v => v.Vector == SurfaceVector.DataExposure);
        Assert.Contains(de.Recommendations, r => r.Contains("encrypt", StringComparison.OrdinalIgnoreCase));
    }
}
