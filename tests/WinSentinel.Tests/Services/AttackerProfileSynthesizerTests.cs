using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.AttackerProfileSynthesizer;

namespace WinSentinel.Tests.Services;

public class AttackerProfileSynthesizerTests
{
    private readonly AttackerProfileSynthesizer _sut = new();

    private static readonly DateTimeOffset Now =
        new(2026, 5, 13, 14, 0, 0, TimeSpan.Zero);

    private static AttackerSignal S(string id, Tactic tactic, string source = "detector",
        int sev = 70, int conf = 80, IReadOnlyList<string>? tags = null,
        DateTimeOffset? at = null)
        => new(id, tactic, source, sev, conf, at ?? Now, tags);

    private static ProfileContext Ctx() => new() { NowOverride = Now };

    [Fact]
    public void EmptyBatch_ReturnsUnknownGradeA()
    {
        var p = _sut.Synthesize(Array.Empty<AttackerSignal>(), Ctx());
        Assert.Equal(AttackerArchetype.Unknown, p.PrimaryArchetype);
        Assert.Equal("A", p.Grade);
        Assert.Empty(p.Hunts);
        Assert.Empty(p.Containments);
    }

    [Fact]
    public void RansomwareSignals_PickRansomwareOperator()
    {
        var signals = new[]
        {
            S("T1486", Tactic.Impact, sev: 95, conf: 90, tags: new[] { "encryption", "ransom" }),
            S("T1021", Tactic.LateralMovement, sev: 80),
            S("T1003", Tactic.CredentialAccess, sev: 75),
            S("T1490", Tactic.DefenseEvasion, sev: 70, source: "DefenseEvasionDetector"),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Equal(AttackerArchetype.RansomwareOperator, p.PrimaryArchetype);
        Assert.True(p.PrimaryConfidence >= 25);
        Assert.Contains(p.Hunts, h => h.Code == "HUNT_VSS_DELETION");
        Assert.Contains(p.Containments, a => a.Code == "ISOLATE_AFFECTED_HOSTS" && a.Priority == ActionPriority.P0);
    }

    [Fact]
    public void ScannerSignals_PickAutomatedScanner()
    {
        var signals = new[]
        {
            S("T1595", Tactic.Reconnaissance, sev: 60, tags: new[] { "scanner", "portscan" }),
            S("T1190", Tactic.InitialAccess, sev: 50),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Equal(AttackerArchetype.AutomatedScanner, p.PrimaryArchetype);
        Assert.Contains(p.Hunts, h => h.Code == "HUNT_PORT_SWEEP");
        Assert.Contains(p.Containments, a => a.Code == "RATE_LIMIT_INGRESS");
    }

    [Fact]
    public void InsiderSignals_PickInsiderThreat()
    {
        var signals = new[]
        {
            S("T1005", Tactic.Collection, sev: 80, tags: new[] { "insider", "legit_credentials" }),
            S("T1041", Tactic.Exfiltration, sev: 90),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Equal(AttackerArchetype.InsiderThreat, p.PrimaryArchetype);
        Assert.Contains(p.Hunts, h => h.Code == "HUNT_DATA_EGRESS");
        Assert.Contains(p.Containments, a => a.Code == "HR_LEGAL_LOOP");
    }

    [Fact]
    public void MinerSignals_PickCryptoMiner()
    {
        var signals = new[]
        {
            S("T1496", Tactic.Impact, sev: 60, tags: new[] { "mining", "xmrig" }),
            S("T1059", Tactic.Execution, sev: 70),
            S("T1547", Tactic.Persistence, sev: 65),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Equal(AttackerArchetype.CryptoMiner, p.PrimaryArchetype);
        Assert.Contains(p.Hunts, h => h.Code == "HUNT_STRATUM");
    }

    [Fact]
    public void AptSignals_PickAptArchetype()
    {
        var signals = new[]
        {
            S("T1071", Tactic.CommandAndControl, sev: 75, tags: new[] { "apt", "low_and_slow" }),
            S("T1003", Tactic.CredentialAccess, sev: 80),
            S("T1547", Tactic.Persistence, sev: 70),
            S("T1027", Tactic.DefenseEvasion, sev: 85),
            S("T1083", Tactic.Discovery, sev: 65),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Equal(AttackerArchetype.AptNationState, p.PrimaryArchetype);
        Assert.Contains(p.Containments, a => a.Code == "COLLECT_FORENSICS_FIRST" && a.Priority == ActionPriority.P0);
    }

    [Fact]
    public void RedTeamWindow_BoostsRedTeam()
    {
        var ctx = Ctx();
        ctx.ActiveRedTeamWindow = true;
        var signals = new[]
        {
            S("T1190", Tactic.InitialAccess, sev: 60),
            S("T1059", Tactic.Execution, sev: 60),
            S("T1083", Tactic.Discovery, sev: 60),
        };
        var p = _sut.Synthesize(signals, ctx);
        Assert.Equal(AttackerArchetype.RedTeam, p.PrimaryArchetype);
        Assert.Contains(p.Insights, i => i.Code != "REDTEAM_WINDOW_MISMATCH");
        // No mismatch insight when primary IS RedTeam.
        Assert.DoesNotContain(p.Insights, i => i.Code == "REDTEAM_WINDOW_MISMATCH");
    }

    [Fact]
    public void KillChainProgression_FlagsDeepInsight()
    {
        var signals = new[]
        {
            S("T1190", Tactic.InitialAccess),
            S("T1059", Tactic.Execution),
            S("T1547", Tactic.Persistence),
            S("T1003", Tactic.CredentialAccess),
            S("T1021", Tactic.LateralMovement),
            S("T1005", Tactic.Collection),
            S("T1041", Tactic.Exfiltration),
            S("T1486", Tactic.Impact),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.True(p.KillChainProgressionPct >= 90);
        Assert.Contains(p.Insights, i => i.Code == "DEEP_KILL_CHAIN");
        Assert.Equal("F", p.Grade);
    }

    [Fact]
    public void HighTempo_FlagsTempoInsight()
    {
        var sigs = Enumerable.Range(0, 12)
            .Select(i => S($"T{i}", Tactic.Execution, sev: 60, conf: 70, at: Now.AddMinutes(-i)))
            .ToArray();
        var p = _sut.Synthesize(sigs, Ctx());
        Assert.True(p.TempoSignalsPerHour >= 10);
        Assert.Contains(p.Insights, i => i.Code == "HIGH_TEMPO");
    }

    [Fact]
    public void MultiDetectorFan_FlagsCorroboration()
    {
        var signals = new[]
        {
            S("a", Tactic.Execution, source: "ExecutionDetector"),
            S("b", Tactic.Persistence, source: "PersistenceScanner"),
            S("c", Tactic.CommandAndControl, source: "BeaconDetectionService"),
            S("d", Tactic.DefenseEvasion, source: "DefenseEvasionDetector"),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Contains(p.Insights, i => i.Code == "MULTI_DETECTOR_FAN");
    }

    [Fact]
    public void SensitiveData_AddsRegulatoryClock()
    {
        var ctx = Ctx();
        ctx.ContainsSensitiveData = true;
        var signals = new[]
        {
            S("T1486", Tactic.Impact, sev: 90, tags: new[] { "ransom" }),
            S("T1021", Tactic.LateralMovement, sev: 70),
        };
        var p = _sut.Synthesize(signals, ctx);
        Assert.Equal(AttackerArchetype.RansomwareOperator, p.PrimaryArchetype);
        Assert.Contains(p.Insights, i => i.Code == "REGULATORY_CLOCK");
        Assert.Contains(p.Containments, a => a.Code == "ENGAGE_DATA_OWNER");
    }

    [Fact]
    public void PreLateralHunt_FiresOnCredAccessWithoutLateral()
    {
        var signals = new[]
        {
            S("T1003", Tactic.CredentialAccess, sev: 80),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Contains(p.Hunts, h => h.Code == "HUNT_PRE_LATERAL");
    }

    [Fact]
    public void PreExfilHunt_FiresOnCollectionWithoutExfil()
    {
        var signals = new[]
        {
            S("T1005", Tactic.Collection, sev: 70, tags: new[] { "insider" }),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Contains(p.Hunts, h => h.Code == "HUNT_PRE_EXFIL");
    }

    [Fact]
    public void AggressiveRisk_TrimsP2Hunts()
    {
        var ctx = Ctx();
        ctx.Risk = RiskAppetite.Aggressive;
        var signals = new[]
        {
            S("T1190", Tactic.InitialAccess, sev: 50),
            S("T1059", Tactic.Execution, sev: 50),
        };
        var pAgg = _sut.Synthesize(signals, ctx);
        Assert.DoesNotContain(pAgg.Hunts, h => h.Priority == ActionPriority.P2);
        Assert.DoesNotContain(pAgg.Containments, a => a.Priority == ActionPriority.P2);
    }

    [Fact]
    public void ActiveRedTeam_SuppressesHighBlastContainment_ForNonRedTeam()
    {
        var ctx = Ctx();
        ctx.ActiveRedTeamWindow = true;
        // Strong ransomware signal but red-team window says don't act destructively.
        var signals = new[]
        {
            S("T1486", Tactic.Impact, sev: 95, conf: 95, tags: new[] { "ransom" }),
            S("T1490", Tactic.DefenseEvasion, sev: 95, conf: 95),
            S("T1021", Tactic.LateralMovement, sev: 95, conf: 95),
            S("T1003", Tactic.CredentialAccess, sev: 95, conf: 95),
            S("T1486b", Tactic.Impact, sev: 95, conf: 95, tags: new[] { "encryption" }),
        };
        var p = _sut.Synthesize(signals, ctx);
        if (p.PrimaryArchetype != AttackerArchetype.RedTeam)
        {
            Assert.DoesNotContain(p.Containments,
                a => a.BlastRadius >= 3 && a.Owner != "leadership");
            Assert.Contains(p.Insights, i => i.Code == "REDTEAM_WINDOW_MISMATCH");
        }
    }

    [Fact]
    public void Formatters_Produce_NonEmptyText_Markdown_Json()
    {
        var signals = new[]
        {
            S("T1486", Tactic.Impact, sev: 90, tags: new[] { "ransom" }),
            S("T1021", Tactic.LateralMovement, sev: 80),
            S("T1003", Tactic.CredentialAccess, sev: 75),
        };
        var p = _sut.Synthesize(signals, Ctx());
        var text = _sut.FormatText(p);
        var md = _sut.FormatMarkdown(p);
        var json = _sut.FormatJson(p);
        Assert.Contains("ATTACKER PROFILE", text);
        Assert.Contains("# Attacker Profile", md);
        Assert.Contains("\"PrimaryArchetype\"", json);
        Assert.Contains("RansomwareOperator", json);
    }

    [Fact]
    public void CommodityMalware_DefaultPath()
    {
        var signals = new[]
        {
            S("T1547", Tactic.Persistence, sev: 70),
            S("T1071", Tactic.CommandAndControl, sev: 60),
            S("T1059", Tactic.Execution, sev: 60),
        };
        var p = _sut.Synthesize(signals, Ctx());
        Assert.Equal(AttackerArchetype.CommodityMalware, p.PrimaryArchetype);
        Assert.Contains(p.Hunts, h => h.Code == "HUNT_AUTORUN");
        Assert.Contains(p.Containments, a => a.Code == "QUARANTINE_HOST");
    }

    [Fact]
    public void Candidates_AreOrderedByConfidence()
    {
        var signals = new[]
        {
            S("T1486", Tactic.Impact, sev: 90, tags: new[] { "ransom" }),
            S("T1021", Tactic.LateralMovement, sev: 80),
        };
        var p = _sut.Synthesize(signals, Ctx());
        for (int i = 1; i < p.Candidates.Count; i++)
            Assert.True(p.Candidates[i - 1].Score >= p.Candidates[i].Score);
    }

    [Fact]
    public void CautiousRisk_PromotesIsolationP1ToP0()
    {
        var ctx = Ctx();
        ctx.Risk = RiskAppetite.Cautious;
        var signals = new[]
        {
            S("T1486", Tactic.Impact, sev: 90, tags: new[] { "ransom" }),
            S("T1021", Tactic.LateralMovement, sev: 80),
        };
        var p = _sut.Synthesize(signals, ctx);
        // The base ransomware path already has ISOLATE_AFFECTED_HOSTS at P0 - sanity-check it stays present.
        Assert.Contains(p.Containments, a => a.Code == "ISOLATE_AFFECTED_HOSTS" && a.Priority == ActionPriority.P0);
    }
}
