using System.Text.Json;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.ThreatHorizonForecastAdvisor;

namespace WinSentinel.Tests;

public class ThreatHorizonForecastAdvisorTests
{
    private static readonly DateTime Now = new DateTime(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);

    private static ForecastContext Ctx(
        RiskAppetite risk = RiskAppetite.Balanced,
        int horizon = 7,
        int lookback = 14) =>
        new ForecastContext { Risk = risk, NowOverride = Now, HorizonDays = horizon, LookbackDays = lookback };

    private static PostureContext CalmPosture() => new PostureContext(
        OpenCriticalFindings: 0,
        OpenHighFindings: 0,
        AttackSurfaceSize: 5,
        ExposedAssetCount: 0,
        DaysSinceLastRegression: 60,
        RecentlyRevokedExceptionCount: 0);

    private static ReconSignal Sig(
        string id,
        ReconSignalType type,
        double ageHours = 1,
        string source = "1.2.3.4",
        double confidence = 0.7,
        string detail = "test")
    {
        return new ReconSignal(
            Id: id,
            Type: type,
            ObservedAt: Now.AddHours(-Math.Abs(ageHours)),
            Source: source,
            Confidence: confidence,
            Detail: detail);
    }

    [Fact]
    public void Empty_signals_and_calm_posture_returns_calm_verdict_grade_A()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var r = advisor.Analyze(Array.Empty<ReconSignal>(), CalmPosture(), Ctx());

        Assert.Equal(HorizonVerdict.Calm, r.Verdict);
        Assert.Equal("A", r.Grade);
        Assert.Equal(0, r.PressureScore);
        Assert.Empty(r.Contributions);
        Assert.Single(r.Playbook);
        Assert.Equal("WATCH_AND_WAIT", r.Playbook[0].Id);
        Assert.Contains("LOW_SIGNAL_ENVIRONMENT", r.Insights);
        Assert.Equal(7, r.Forecast.Count);
    }

    [Fact]
    public void HighConfidence_ioc_match_drives_p0_block_action()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[]
        {
            Sig("s1", ReconSignalType.IocMatch, ageHours: 2, confidence: 0.95),
        };

        var r = advisor.Analyze(sigs, CalmPosture(), Ctx());

        Assert.Contains(r.Contributions, c => c.Code == "IOC_MATCH_FRESH" && c.Weight == 60);
        Assert.Contains(r.Playbook, p => p.Id == "BLOCK_KNOWN_IOCS" && p.Priority == ActionPriority.P0);
        // 60 + 0 shift > 50 ⇒ Imminent or UnderPressure
        Assert.True(r.Verdict == HorizonVerdict.Imminent || r.Verdict == HorizonVerdict.UnderPressure);
    }

    [Fact]
    public void Brute_force_velocity_only_counts_last_24h()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[]
        {
            // 12 recent brute force events ⇒ weight 40
            Sig("b1",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b2",  ReconSignalType.BruteForce, ageHours: 2),
            Sig("b3",  ReconSignalType.BruteForce, ageHours: 3),
            Sig("b4",  ReconSignalType.BruteForce, ageHours: 4),
            Sig("b5",  ReconSignalType.BruteForce, ageHours: 5),
            Sig("b6",  ReconSignalType.BruteForce, ageHours: 6),
            Sig("b7",  ReconSignalType.BruteForce, ageHours: 7),
            Sig("b8",  ReconSignalType.BruteForce, ageHours: 8),
            Sig("b9",  ReconSignalType.CredentialStuffing, ageHours: 9),
            Sig("b10", ReconSignalType.CredentialStuffing, ageHours: 10),
            Sig("b11", ReconSignalType.BruteForce, ageHours: 11),
            Sig("b12", ReconSignalType.BruteForce, ageHours: 12),
            // older than 24h ⇒ excluded from velocity bucket
            Sig("b13", ReconSignalType.BruteForce, ageHours: 48),
        };

        var r = advisor.Analyze(sigs, CalmPosture(), Ctx());
        var bf = r.Contributions.Single(c => c.Code == "BRUTE_FORCE_VELOCITY");
        Assert.Equal(12, bf.Count);
        Assert.Equal(40, bf.Weight);
        Assert.Contains(r.Playbook, p => p.Id == "RATE_LIMIT_AUTH" && p.Priority == ActionPriority.P0);
        Assert.Contains("HEAT_CONCENTRATED_AUTH", r.Insights);
    }

    [Fact]
    public void Port_scan_distinct_sources_drive_burst_signal()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[]
        {
            Sig("p1", ReconSignalType.PortScan, ageHours: 1, source: "10.0.0.1"),
            Sig("p2", ReconSignalType.PortScan, ageHours: 1, source: "10.0.0.1"), // dup source
            Sig("p3", ReconSignalType.PortScan, ageHours: 1, source: "10.0.0.2"),
            Sig("p4", ReconSignalType.PortScan, ageHours: 1, source: "10.0.0.3"),
        };

        var r = advisor.Analyze(sigs, CalmPosture(), Ctx());
        var ps = r.Contributions.Single(c => c.Code == "PORT_SCAN_BURST");
        Assert.Equal(3, ps.Count);
        Assert.Equal(15, ps.Weight);
    }

    [Fact]
    public void Defender_overhang_alone_contributes_to_pressure()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var posture = new PostureContext(
            OpenCriticalFindings: 3,
            OpenHighFindings: 5,
            AttackSurfaceSize: 150,
            ExposedAssetCount: 12,
            DaysSinceLastRegression: 3,
            RecentlyRevokedExceptionCount: 2);

        var r = advisor.Analyze(Array.Empty<ReconSignal>(), posture, Ctx());

        Assert.Contains(r.Contributions, c => c.Code == "OPEN_CRITICAL_OVERHANG");
        Assert.Contains(r.Contributions, c => c.Code == "LARGE_ATTACK_SURFACE");
        Assert.Contains(r.Contributions, c => c.Code == "RECENT_REGRESSION");
        Assert.Contains(r.Contributions, c => c.Code == "EXPOSED_ASSETS");
        Assert.Contains(r.Contributions, c => c.Code == "EXCEPTION_THAW");
        Assert.True(r.PressureScore > 0);
        Assert.NotEqual(HorizonVerdict.Calm, r.Verdict);
    }

    [Fact]
    public void Compound_pressure_insight_when_attacker_and_defender_signals_both_present()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var posture = new PostureContext(
            OpenCriticalFindings: 1, OpenHighFindings: 0,
            AttackSurfaceSize: 5, ExposedAssetCount: 0,
            DaysSinceLastRegression: 30, RecentlyRevokedExceptionCount: 0);
        var sigs = new[] { Sig("s1", ReconSignalType.IocMatch, ageHours: 1, confidence: 0.5) };

        var r = advisor.Analyze(sigs, posture, Ctx());
        Assert.Contains("COMPOUND_PRESSURE_INTERNAL_AND_EXTERNAL", r.Insights);
    }

    [Fact]
    public void Port_scan_plus_large_surface_yields_harden_perimeter_p0()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var posture = new PostureContext(0, 0, 120, 0, 30, 0);
        var sigs = new[]
        {
            Sig("p1", ReconSignalType.PortScan, ageHours: 1, source: "10.0.0.1"),
            Sig("p2", ReconSignalType.PortScan, ageHours: 1, source: "10.0.0.2"),
            Sig("p3", ReconSignalType.PortScan, ageHours: 1, source: "10.0.0.3"),
        };

        var r = advisor.Analyze(sigs, posture, Ctx());
        Assert.Contains(r.Playbook, p => p.Id == "HARDEN_PERIMETER" && p.Priority == ActionPriority.P0);
        Assert.DoesNotContain(r.Playbook, p => p.Id == "AUDIT_EXPOSED_PORTS");
    }

    [Fact]
    public void Two_p0_actions_convene_war_room()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[]
        {
            Sig("i1", ReconSignalType.IocMatch, ageHours: 1, confidence: 0.95),
            // 12 brute hits ⇒ weight 40 ⇒ RATE_LIMIT_AUTH P0
            Sig("b1",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b2",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b3",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b4",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b5",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b6",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b7",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b8",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b9",  ReconSignalType.BruteForce, ageHours: 1),
            Sig("b10", ReconSignalType.BruteForce, ageHours: 1),
            Sig("b11", ReconSignalType.BruteForce, ageHours: 1),
            Sig("b12", ReconSignalType.BruteForce, ageHours: 1),
        };

        var r = advisor.Analyze(sigs, CalmPosture(), Ctx());
        Assert.Contains(r.Playbook, p => p.Id == "CONVENE_THREAT_WAR_ROOM" && p.Priority == ActionPriority.P0);
        Assert.Equal(HorizonVerdict.UnderPressure, r.Verdict);
        Assert.Contains(r.Playbook, p => p.Id == "ACTIVATE_HIGH_ALERT");
    }

    [Fact]
    public void Aggressive_appetite_trims_p2_and_p3_when_p0_present()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[]
        {
            Sig("i1", ReconSignalType.IocMatch, ageHours: 1, confidence: 0.95), // P0
            Sig("d1", ReconSignalType.RogueDns, ageHours: 1), // P2 normally
        };

        var r = advisor.Analyze(sigs, CalmPosture(), Ctx(risk: RiskAppetite.Aggressive));
        Assert.DoesNotContain(r.Playbook, p => p.Priority == ActionPriority.P2);
        Assert.DoesNotContain(r.Playbook, p => p.Priority == ActionPriority.P3);
        Assert.Contains(r.Playbook, p => p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Cautious_appetite_shifts_pressure_up_by_five()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[] { Sig("i1", ReconSignalType.IocMatch, ageHours: 1, confidence: 0.5) };

        var balanced = advisor.Analyze(sigs, CalmPosture(), Ctx(risk: RiskAppetite.Balanced));
        var cautious = advisor.Analyze(sigs, CalmPosture(), Ctx(risk: RiskAppetite.Cautious));
        var aggressive = advisor.Analyze(sigs, CalmPosture(), Ctx(risk: RiskAppetite.Aggressive));

        Assert.Equal(balanced.PressureScore + 5, cautious.PressureScore);
        Assert.Equal(balanced.PressureScore - 5, aggressive.PressureScore);
    }

    [Fact]
    public void Lookback_window_filters_old_signals()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[]
        {
            Sig("s1", ReconSignalType.PhishingLanding, ageHours: 24 * 30), // 30d old, outside default 14d
        };

        var r = advisor.Analyze(sigs, CalmPosture(), Ctx(lookback: 14));
        Assert.DoesNotContain(r.Contributions, c => c.Code == "PHISHING_LANDING_HITS");
    }

    [Fact]
    public void Forecast_curve_has_horizon_days_entries_and_decays()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var sigs = new[] { Sig("i1", ReconSignalType.IocMatch, ageHours: 1, confidence: 0.95) };

        var r = advisor.Analyze(sigs, CalmPosture(), Ctx(horizon: 5));
        Assert.Equal(5, r.Forecast.Count);
        Assert.True(r.Forecast[0].Pressure >= r.Forecast[^1].Pressure,
            $"day1={r.Forecast[0].Pressure} dayN={r.Forecast[^1].Pressure}");
        Assert.All(r.Forecast, f => Assert.InRange(f.Pressure, 0, 100));
    }

    [Fact]
    public void NowOverride_is_returned_as_generated_at()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var pinned = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var r = advisor.Analyze(Array.Empty<ReconSignal>(), CalmPosture(),
            new ForecastContext { NowOverride = pinned });

        Assert.Equal(pinned, r.GeneratedAt);
    }

    [Fact]
    public void RenderJson_round_trips_as_valid_json()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var r = advisor.Analyze(
            new[] { Sig("i1", ReconSignalType.IocMatch, ageHours: 1, confidence: 0.95) },
            CalmPosture(),
            Ctx());

        string json = ThreatHorizonForecastAdvisor.RenderJson(r);
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("Verdict", out _));
        Assert.True(doc.RootElement.TryGetProperty("Forecast", out var forecast));
        Assert.Equal(JsonValueKind.Array, forecast.ValueKind);
    }

    [Fact]
    public void RenderMarkdown_contains_expected_sections()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        var r = advisor.Analyze(
            new[] { Sig("i1", ReconSignalType.IocMatch, ageHours: 1, confidence: 0.95) },
            CalmPosture(),
            Ctx());

        string md = ThreatHorizonForecastAdvisor.RenderMarkdown(r);
        Assert.Contains("## Summary", md);
        Assert.Contains("## Contributions", md);
        Assert.Contains("## Daily forecast", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
    }

    [Fact]
    public void Null_signals_throws()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        Assert.Throws<ArgumentNullException>(() =>
            advisor.Analyze(null!, CalmPosture(), Ctx()));
    }

    [Fact]
    public void Null_posture_throws()
    {
        var advisor = new ThreatHorizonForecastAdvisor();
        Assert.Throws<ArgumentNullException>(() =>
            advisor.Analyze(Array.Empty<ReconSignal>(), null!, Ctx()));
    }
}
