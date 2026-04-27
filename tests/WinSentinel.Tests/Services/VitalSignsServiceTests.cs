using Microsoft.Data.Sqlite;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for VitalSignsService — maps security metrics to medical vital signs.
/// Uses an in-memory SQLite AuditHistoryService to inject controlled audit data.
/// </summary>
public class VitalSignsServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;
    private readonly VitalSignsService _svc;

    public VitalSignsServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"vitals_test_{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _history.EnsureDatabase();
        _svc = new VitalSignsService(_history);
    }

    public void Dispose()
    {
        _svc.Dispose();
        _history.Dispose();
        SqliteConnection.ClearAllPools();
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
    }

    // ── Helper ──────────────────────────────────────────────────

    /// <summary>
    /// Insert a run with zero findings (empty AuditResult).
    /// TotalFindings=0, PassCount=0 → Oxygen coverage=100%, Temperature normal.
    /// </summary>
    private void InsertRunRaw(int score, DateTimeOffset ts)
    {
        var report = new SecurityReport
        {
            GeneratedAt = ts.DateTime,
            SecurityScore = score,
            Results = new List<AuditResult>
            {
                new() { ModuleName = "TestModule", Category = "Security", Findings = new List<Finding>() }
            }
        };
        _history.SaveAuditResult(report);
    }

    /// <summary>
    /// Build a SecurityReport with properly-typed findings so that
    /// TotalFindings/TotalCritical/TotalWarnings/TotalInfo/TotalPass compute correctly.
    /// Note: TotalFindings includes ALL findings (including Pass), which affects
    /// oxygen coverage calculation: coverage = PassCount / (TotalFindings + PassCount).
    /// </summary>
    private void InsertRun(int score, DateTimeOffset ts, int criticals = 0, int warnings = 0,
        int info = 0, int pass = 50, int extraFindings = 0)
    {
        var findings = new List<Finding>();
        for (int i = 0; i < criticals; i++)
            findings.Add(new Finding { Title = $"Critical-{i}", Severity = Severity.Critical, Description = "crit" });
        for (int i = 0; i < warnings; i++)
            findings.Add(new Finding { Title = $"Warning-{i}", Severity = Severity.Warning, Description = "warn" });
        for (int i = 0; i < info; i++)
            findings.Add(new Finding { Title = $"Info-{i}", Severity = Severity.Info, Description = "info" });
        for (int i = 0; i < pass; i++)
            findings.Add(new Finding { Title = $"Pass-{i}", Severity = Severity.Pass, Description = "pass" });
        for (int i = 0; i < extraFindings; i++)
            findings.Add(new Finding { Title = $"Extra-{i}", Severity = Severity.Warning, Description = "extra" });

        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Security",
            Findings = findings
        };

        var report = new SecurityReport
        {
            GeneratedAt = ts.DateTime,
            SecurityScore = score,
            Results = new List<AuditResult> { result }
        };
        _history.SaveAuditResult(report);
    }

    // ── No Data ─────────────────────────────────────────────────

    [Fact]
    public void Assess_NoRuns_AllVitalsAbnormal()
    {
        var result = _svc.Assess();

        Assert.Equal(VitalStatus.Critical, result.Heartbeat.Status);
        Assert.Equal(VitalStatus.Critical, result.BloodPressure.Status);
        Assert.Equal(VitalStatus.Critical, result.Oxygen.Status);
        Assert.Equal(VitalStatus.Critical, result.Consciousness.Status);
        Assert.Equal("CRITICAL", result.OverallStatus);
        Assert.Equal("BLACK", result.TriageLevel);
    }

    // ── Heartbeat ───────────────────────────────────────────────

    [Fact]
    public void Assess_FrequentScans_HeartbeatNormal()
    {
        for (int i = 10; i >= 0; i--)
            InsertRun(80, DateTimeOffset.UtcNow.AddHours(-i * 2));

        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Normal, result.Heartbeat.Status);
        Assert.True(result.Heartbeat.Bpm >= 55);
    }

    [Fact]
    public void Assess_InfrequentScans_HeartbeatLowBpm()
    {
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-20));
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-10));
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-1));

        var result = _svc.Assess();
        Assert.True(result.Heartbeat.Bpm <= 55);
    }

    [Fact]
    public void Assess_SingleRun_HeartbeatCritical()
    {
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-1));
        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Critical, result.Heartbeat.Status);
        Assert.Equal(0, result.Heartbeat.Bpm);
    }

    // ── Blood Pressure (Score) ──────────────────────────────────

    [Fact]
    public void Assess_HighScore_BPNormal()
    {
        for (int i = 3; i >= 0; i--)
            InsertRun(85, DateTimeOffset.UtcNow.AddHours(-i * 6));

        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Normal, result.BloodPressure.Status);
        Assert.Equal(85, result.BloodPressure.Systolic);
    }

    [Fact]
    public void Assess_LowScore_BPCritical()
    {
        for (int i = 3; i >= 0; i--)
            InsertRun(30, DateTimeOffset.UtcNow.AddHours(-i * 6));

        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Critical, result.BloodPressure.Status);
    }

    [Fact]
    public void Assess_VolatileScores_BPElevated()
    {
        InsertRun(40, DateTimeOffset.UtcNow.AddHours(-12));
        InsertRun(95, DateTimeOffset.UtcNow.AddHours(-8));
        InsertRun(45, DateTimeOffset.UtcNow.AddHours(-4));
        InsertRun(90, DateTimeOffset.UtcNow.AddHours(-1));

        var result = _svc.Assess();
        Assert.True(result.BloodPressure.Volatility > 15);
        Assert.Equal(VitalStatus.Elevated, result.BloodPressure.Status);
    }

    [Fact]
    public void Assess_ImprovingScores_BPTrendImproving()
    {
        InsertRun(60, DateTimeOffset.UtcNow.AddHours(-12));
        InsertRun(65, DateTimeOffset.UtcNow.AddHours(-8));
        InsertRun(70, DateTimeOffset.UtcNow.AddHours(-4));
        InsertRun(75, DateTimeOffset.UtcNow.AddHours(-1));

        var result = _svc.Assess();
        Assert.Contains("Improving", result.BloodPressure.Trend);
    }

    [Fact]
    public void Assess_DecliningScores_BPTrendDeclining()
    {
        InsertRun(85, DateTimeOffset.UtcNow.AddHours(-12));
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-8));
        InsertRun(75, DateTimeOffset.UtcNow.AddHours(-4));
        InsertRun(70, DateTimeOffset.UtcNow.AddHours(-1));

        var result = _svc.Assess();
        Assert.Contains("Declining", result.BloodPressure.Trend);
    }

    // ── Temperature (Threats) ───────────────────────────────────

    [Fact]
    public void Assess_NoThreats_TempNormal()
    {
        InsertRun(90, DateTimeOffset.UtcNow.AddHours(-2), criticals: 0, warnings: 0, pass: 90);
        InsertRun(90, DateTimeOffset.UtcNow.AddHours(-1), criticals: 0, warnings: 0, pass: 90);

        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Normal, result.Temperature.Status);
        Assert.True(result.Temperature.TemperatureF <= 100.4);
    }

    [Fact]
    public void Assess_ManyThreats_TempElevated()
    {
        InsertRun(50, DateTimeOffset.UtcNow.AddHours(-2), criticals: 5, warnings: 10);
        InsertRun(50, DateTimeOffset.UtcNow.AddHours(-1), criticals: 5, warnings: 10);

        var result = _svc.Assess();
        // 15 active threats * 0.3 + 97 = 101.5 → elevated
        Assert.True(result.Temperature.TemperatureF > 100.4);
        Assert.True(result.Temperature.Status == VitalStatus.Elevated || result.Temperature.Status == VitalStatus.Critical);
    }

    [Fact]
    public void Assess_MassiveThreats_TempCritical()
    {
        InsertRun(10, DateTimeOffset.UtcNow.AddHours(-2), criticals: 10, warnings: 15);
        InsertRun(10, DateTimeOffset.UtcNow.AddHours(-1), criticals: 10, warnings: 15);

        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Critical, result.Temperature.Status);
    }

    [Fact]
    public void Assess_Temperature_CappedAt106()
    {
        InsertRun(5, DateTimeOffset.UtcNow.AddHours(-2), criticals: 50, warnings: 50);
        InsertRun(5, DateTimeOffset.UtcNow.AddHours(-1), criticals: 50, warnings: 50);

        var result = _svc.Assess();
        Assert.True(result.Temperature.TemperatureF <= 106.0);
    }

    // ── Respiration (Remediation Rate) ──────────────────────────

    [Fact]
    public void Assess_FindingsDecreasing_RespirationGood()
    {
        // Decreasing non-pass findings = good remediation
        InsertRun(70, DateTimeOffset.UtcNow.AddDays(-6), warnings: 20, pass: 30);
        InsertRun(75, DateTimeOffset.UtcNow.AddDays(-5), warnings: 18, pass: 32);
        InsertRun(80, DateTimeOffset.UtcNow.AddDays(-4), warnings: 15, pass: 35);
        InsertRun(85, DateTimeOffset.UtcNow.AddDays(-3), warnings: 12, pass: 38);
        InsertRun(88, DateTimeOffset.UtcNow.AddDays(-2), warnings: 10, pass: 40);
        InsertRun(90, DateTimeOffset.UtcNow.AddDays(-1), warnings: 8, pass: 42);
        InsertRun(92, DateTimeOffset.UtcNow.AddHours(-1), warnings: 5, pass: 45);

        var result = _svc.Assess();
        Assert.True(result.Respiration.Rpm >= 12);
        Assert.Equal(VitalStatus.Normal, result.Respiration.Status);
    }

    [Fact]
    public void Assess_FindingsIncreasing_RespirationPoor()
    {
        // TotalFindings must actually increase across runs (all findings count)
        InsertRun(80, DateTimeOffset.UtcNow.AddDays(-6), warnings: 5);
        InsertRun(70, DateTimeOffset.UtcNow.AddDays(-3), warnings: 15);
        InsertRun(60, DateTimeOffset.UtcNow.AddDays(-2), warnings: 25);
        InsertRun(50, DateTimeOffset.UtcNow.AddDays(-1), warnings: 35);
        InsertRun(40, DateTimeOffset.UtcNow.AddHours(-1), warnings: 45);

        var result = _svc.Assess();
        Assert.True(result.Respiration.Rpm < 12);
    }

    [Fact]
    public void Assess_SingleRun_RespirationElevated()
    {
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-1));
        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Elevated, result.Respiration.Status);
    }

    // ── Oxygen (Coverage) ───────────────────────────────────────

    [Fact]
    public void Assess_NoFindings_OxygenNormal()
    {
        // With no findings at all, TotalFindings=0, PassCount=0 → coverage=100%
        InsertRunRaw(90, DateTimeOffset.UtcNow.AddHours(-2));
        InsertRunRaw(90, DateTimeOffset.UtcNow.AddHours(-1));

        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Normal, result.Oxygen.Status);
        Assert.True(result.Oxygen.SpO2Percent >= 93);
    }

    [Fact]
    public void Assess_LowPassCount_OxygenCritical()
    {
        InsertRun(30, DateTimeOffset.UtcNow.AddHours(-2), warnings: 80, pass: 10);
        InsertRun(30, DateTimeOffset.UtcNow.AddHours(-1), warnings: 80, pass: 10);

        var result = _svc.Assess();
        Assert.Equal(VitalStatus.Critical, result.Oxygen.Status);
    }

    // ── Consciousness (Awareness) ───────────────────────────────

    [Fact]
    public void Assess_LowInfoCount_ConsciousnessAlert()
    {
        InsertRun(85, DateTimeOffset.UtcNow.AddHours(-2), info: 2, pass: 50, warnings: 3);
        InsertRun(85, DateTimeOffset.UtcNow.AddHours(-1), info: 2, pass: 50, warnings: 3);

        var result = _svc.Assess();
        Assert.Equal("Alert", result.Consciousness.Level);
        Assert.Equal(VitalStatus.Normal, result.Consciousness.Status);
    }

    [Fact]
    public void Assess_HighInfoCount_ConsciousnessLow()
    {
        InsertRun(60, DateTimeOffset.UtcNow.AddHours(-2), info: 30, pass: 20, warnings: 10);
        InsertRun(60, DateTimeOffset.UtcNow.AddHours(-1), info: 30, pass: 20, warnings: 10);

        var result = _svc.Assess();
        Assert.True(result.Consciousness.Level == "Drowsy" || result.Consciousness.Level == "Unconscious");
    }

    // ── Overall Triage Levels ───────────────────────────────────

    [Fact]
    public void Assess_HealthySystem_TriageGreen()
    {
        // No findings at all → all vitals normal
        for (int i = 10; i >= 0; i--)
            InsertRunRaw(92, DateTimeOffset.UtcNow.AddHours(-i * 2));

        var result = _svc.Assess();
        Assert.Equal("GREEN", result.TriageLevel);
        Assert.Equal("STABLE", result.OverallStatus);
    }

    [Fact]
    public void Assess_SeverelyCompromised_TriageRedOrBlack()
    {
        InsertRun(25, DateTimeOffset.UtcNow.AddDays(-3), criticals: 15, warnings: 20, pass: 5);
        InsertRun(20, DateTimeOffset.UtcNow.AddHours(-1), criticals: 20, warnings: 25, pass: 5);

        var result = _svc.Assess();
        Assert.True(result.TriageLevel == "RED" || result.TriageLevel == "BLACK");
        Assert.True(result.OverallStatus == "SERIOUS" || result.OverallStatus == "CRITICAL");
    }

    // ── Prescriptions ───────────────────────────────────────────

    [Fact]
    public void Assess_AllNormal_NominalPrescription()
    {
        for (int i = 10; i >= 0; i--)
            InsertRunRaw(95, DateTimeOffset.UtcNow.AddHours(-i * 2));

        var result = _svc.Assess();
        Assert.Contains(result.Prescriptions, p => p.Contains("nominal"));
    }

    [Fact]
    public void Assess_HighThreats_PrescriptionMentionsThreats()
    {
        InsertRun(40, DateTimeOffset.UtcNow.AddHours(-6), criticals: 10, warnings: 15, pass: 20);
        InsertRun(35, DateTimeOffset.UtcNow.AddHours(-1), criticals: 12, warnings: 18, pass: 15);

        var result = _svc.Assess();
        if (result.Temperature.Status != VitalStatus.Normal)
            Assert.Contains(result.Prescriptions, p => p.Contains("threats", StringComparison.OrdinalIgnoreCase));
    }

    // ── Concerns ────────────────────────────────────────────────

    [Fact]
    public void Assess_Healthy_NoConcerns()
    {
        for (int i = 10; i >= 0; i--)
            InsertRunRaw(95, DateTimeOffset.UtcNow.AddHours(-i * 2));

        var result = _svc.Assess();
        Assert.Empty(result.Concerns);
    }

    [Fact]
    public void Assess_MultipleBadVitals_MultipleConcerns()
    {
        InsertRun(30, DateTimeOffset.UtcNow.AddHours(-1), criticals: 15, warnings: 10, info: 20, pass: 5);

        var result = _svc.Assess();
        Assert.True(result.Concerns.Count >= 2);
    }

    // ── Custom History Window ───────────────────────────────────

    [Fact]
    public void Assess_CustomDays_FiltersCorrectly()
    {
        InsertRun(90, DateTimeOffset.UtcNow.AddDays(-60), pass: 90, warnings: 5);
        InsertRun(40, DateTimeOffset.UtcNow.AddHours(-1), criticals: 10, warnings: 10, pass: 10);

        var result = _svc.Assess(historyDays: 7);
        Assert.Equal(40, result.BloodPressure.Systolic);
    }

    // ── Dispose Safety ──────────────────────────────────────────

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        var tempDb = Path.Combine(Path.GetTempPath(), $"vitals_dispose_{Guid.NewGuid():N}.db");
        var history = new AuditHistoryService(tempDb);
        var svc = new VitalSignsService(history);
        svc.Dispose();
        history.Dispose();
        SqliteConnection.ClearAllPools();
        try { if (File.Exists(tempDb)) File.Delete(tempDb); } catch { }
    }

    [Fact]
    public void OwnsHistory_Constructor_Works()
    {
        using var svc2 = new VitalSignsService();
        var result = svc2.Assess(1);
        Assert.NotNull(result);
    }
}
