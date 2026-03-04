using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.FirewallRuleAnalyzer;

namespace WinSentinel.Tests.Services;

public class FirewallRuleAnalyzerTests
{
    private readonly FirewallRuleAnalyzer _analyzer;

    public FirewallRuleAnalyzerTests()
    {
        _analyzer = new FirewallRuleAnalyzer();
    }

    private static FirewallRuleState EmptyState() => new() { Rules = new() };

    private static FirewallRule MakeRule(
        string name = "TestRule",
        bool enabled = true,
        string direction = "In",
        string action = "Allow",
        string protocol = "TCP",
        string localPort = "80",
        string remoteAddress = "Any",
        string program = "Any",
        string profile = "Any",
        string remotePort = "Any",
        string localAddress = "Any") => new()
    {
        Name = name,
        Enabled = enabled,
        Direction = direction,
        Action = action,
        Protocol = protocol,
        LocalPort = localPort,
        RemoteAddress = remoteAddress,
        Program = program,
        Profile = profile,
        RemotePort = remotePort,
        LocalAddress = localAddress,
    };

    // ===================== Empty State =====================

    [Fact]
    public void EmptyState_ProducesOnlySummaryFinding()
    {
        var findings = _analyzer.Analyze(EmptyState());
        Assert.Single(findings); // summary only
        Assert.Contains("Total: 0 rules", findings[0].Description);
    }

    [Fact]
    public void EmptyState_ReportZeroCounts()
    {
        var report = _analyzer.BuildReport(EmptyState());
        Assert.Equal(0, report.TotalRules);
        Assert.Equal(0, report.EnabledRules);
        Assert.Equal(0, report.InboundAllowRules);
        Assert.Equal(0.0, report.RiskScore);
    }

    // ===================== Basic Counting =====================

    [Fact]
    public void CountsEnabledAndDisabledRules()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "R1", enabled: true),
                MakeRule(name: "R2", enabled: true),
                MakeRule(name: "R3", enabled: false),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(3, report.TotalRules);
        Assert.Equal(2, report.EnabledRules);
        Assert.Equal(1, report.DisabledRules);
    }

    [Fact]
    public void CountsInboundAllowRules()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Allow1", direction: "In", action: "Allow"),
                MakeRule(name: "Block1", direction: "In", action: "Block"),
                MakeRule(name: "OutAllow", direction: "Out", action: "Allow"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.InboundAllowRules);
    }

    [Fact]
    public void CountsOutboundBlockRules()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "OutBlock", direction: "Out", action: "Block"),
                MakeRule(name: "OutAllow", direction: "Out", action: "Allow"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.OutboundBlockRules);
    }

    [Fact]
    public void DisabledRulesNotAnalyzed()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Disabled", enabled: false, protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Empty(report.RiskyRules);
    }

    // ===================== Overly Permissive Rules =====================

    [Fact]
    public void FullyOpenRule_FlaggedCritical()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "WideOpen", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.OverlyPermissiveCount);
        var risk = Assert.Single(report.RiskyRules.Where(r => r.Rule.Name == "WideOpen" && r.Severity == Severity.Critical));
        Assert.Contains("ALL inbound traffic", risk.RiskReason);
    }

    [Fact]
    public void AllTcpPortsFromAny_FlaggedWarning()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "AllTCP", protocol: "TCP", localPort: "Any", remoteAddress: "Any", program: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.OverlyPermissiveCount);
        Assert.Contains(report.RiskyRules, r => r.Severity == Severity.Warning && r.RiskReason.Contains("ALL ports"));
    }

    [Fact]
    public void AllUdpPortsFromAny_FlaggedWarning()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "AllUDP", protocol: "UDP", localPort: "Any", remoteAddress: "Any", program: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.OverlyPermissiveCount);
    }

    [Fact]
    public void SpecificPortRule_NotOverlyPermissive()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Web", protocol: "TCP", localPort: "443"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.OverlyPermissiveCount);
    }

    [Fact]
    public void RestrictedRemoteAddress_NotOverlyPermissive()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "LocalOnly", protocol: "TCP", localPort: "Any", remoteAddress: "192.168.1.0/24", program: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.OverlyPermissiveCount);
    }

    [Fact]
    public void SpecificProgram_NotOverlyPermissive()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "AppRule", protocol: "TCP", localPort: "Any", remoteAddress: "Any", program: @"C:\myapp.exe"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.OverlyPermissiveCount);
    }

    // ===================== Dangerous Ports =====================

    [Theory]
    [InlineData(21, "FTP")]
    [InlineData(23, "Telnet")]
    [InlineData(445, "SMB")]
    [InlineData(3389, "RDP")]
    [InlineData(5900, "VNC")]
    public void DangerousPort_AnyRemote_FlaggedCritical(int port, string keyword)
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: $"Port{port}", localPort: port.ToString(), remoteAddress: "Any") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.DangerousPortCount);
        var risk = report.RiskyRules.First(r => r.RiskReason.Contains(port.ToString()));
        Assert.Equal(Severity.Critical, risk.Severity);
    }

    [Fact]
    public void DangerousPort_RestrictedRemote_FlaggedWarning()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "RDP-LAN", localPort: "3389", remoteAddress: "10.0.0.0/8") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.DangerousPortCount);
        var risk = report.RiskyRules.First(r => r.RiskReason.Contains("3389"));
        Assert.Equal(Severity.Warning, risk.Severity);
    }

    [Fact]
    public void SafePort_NotFlagged()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "HTTPS", localPort: "443") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.DangerousPortCount);
    }

    [Fact]
    public void MultiplePortsWithDangerous_AllFlagged()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "Multi", localPort: "80,445,443") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.DangerousPortCount); // Only 445 is dangerous
    }

    [Fact]
    public void PortRange_IncludesDangerous()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "Range", localPort: "135-139") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.True(report.DangerousPortCount >= 1); // 135 and 139 are endpoints
    }

    [Fact]
    public void BlockRules_NotFlaggedForDangerousPorts()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "BlockSMB", localPort: "445", action: "Block") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.DangerousPortCount);
    }

    [Fact]
    public void OutboundRules_NotFlaggedForDangerousPorts()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "OutSMB", localPort: "445", direction: "Out") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.DangerousPortCount);
    }

    // ===================== Public Profile Exposure =====================

    [Fact]
    public void PublicProfile_AnyRemote_Flagged()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "PubRule", profile: "Public", remoteAddress: "Any") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.True(report.PublicProfileExposureCount > 0);
    }

    [Fact]
    public void AnyProfile_AnyRemote_Flagged()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "AnyProf", profile: "Any", remoteAddress: "Any") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.True(report.PublicProfileExposureCount > 0);
    }

    [Fact]
    public void DomainOnlyProfile_NotFlaggedPublicExposure()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "DomOnly", profile: "Domain", remoteAddress: "Any") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.PublicProfileExposureCount);
    }

    [Fact]
    public void PublicProfile_RestrictedRemote_NotFlagged()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "PubLAN", profile: "Public", remoteAddress: "192.168.1.0/24") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.PublicProfileExposureCount);
    }

    // ===================== Programless Rules =====================

    [Fact]
    public void PortSpecificNoProgramRule_FlaggedInfo()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "NoApp", localPort: "8080", program: "Any") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Contains(report.RiskyRules, r => r.Severity == Severity.Info && r.RiskReason.Contains("program"));
    }

    [Fact]
    public void PortSpecificWithProgram_NotFlagged()
    {
        var state = new FirewallRuleState
        {
            Rules = new() { MakeRule(name: "WithApp", localPort: "8080", program: @"C:\app.exe") }
        };
        var report = _analyzer.BuildReport(state);
        Assert.DoesNotContain(report.RiskyRules, r => r.RiskReason.Contains("program"));
    }

    // ===================== Duplicates =====================

    [Fact]
    public void DuplicateRules_Detected()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "R1", protocol: "TCP", localPort: "80"),
                MakeRule(name: "R2", protocol: "TCP", localPort: "80"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Single(report.DuplicateGroups);
        Assert.Equal(2, report.DuplicateGroups[0].RuleNames.Count);
    }

    [Fact]
    public void DifferentPortRules_NoDuplicate()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "R1", localPort: "80"),
                MakeRule(name: "R2", localPort: "443"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Empty(report.DuplicateGroups);
    }

    [Fact]
    public void ThreeDuplicates_SingleGroup()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "A", protocol: "TCP", localPort: "22"),
                MakeRule(name: "B", protocol: "TCP", localPort: "22"),
                MakeRule(name: "C", protocol: "TCP", localPort: "22"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Single(report.DuplicateGroups);
        Assert.Equal(3, report.DuplicateGroups[0].RuleNames.Count);
    }

    // ===================== Shadowed Rules =====================

    [Fact]
    public void NarrowRuleShadowedByBroad()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Broad", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
                MakeRule(name: "Narrow", protocol: "TCP", localPort: "80", remoteAddress: "Any", program: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Contains(report.ShadowedRules, s => s.RuleName == "Narrow" && s.ShadowedBy == "Broad");
    }

    [Fact]
    public void EqualRules_NotShadowed()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "A", protocol: "TCP", localPort: "80"),
                MakeRule(name: "B", protocol: "TCP", localPort: "80"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Empty(report.ShadowedRules); // They're duplicates, not shadowed
    }

    [Fact]
    public void UnrelatedRules_NotShadowed()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "A", protocol: "TCP", localPort: "80"),
                MakeRule(name: "B", protocol: "UDP", localPort: "53"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Empty(report.ShadowedRules);
    }

    [Fact]
    public void ProgramBroad_ShadowsProgramSpecific()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "AnyApp", protocol: "TCP", localPort: "80", program: "Any"),
                MakeRule(name: "SpecificApp", protocol: "TCP", localPort: "80", program: @"C:\app.exe"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Contains(report.ShadowedRules, s => s.RuleName == "SpecificApp");
    }

    // ===================== IsBroaderThan =====================

    [Fact]
    public void IsBroaderThan_AnyCoversSpecific()
    {
        var broad = MakeRule(protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any");
        var narrow = MakeRule(protocol: "TCP", localPort: "80", remoteAddress: "10.0.0.1", program: @"C:\a.exe");
        Assert.True(FirewallRuleAnalyzer.IsBroaderThan(broad, narrow));
    }

    [Fact]
    public void IsBroaderThan_SameNotBroader()
    {
        var a = MakeRule(protocol: "TCP", localPort: "80");
        var b = MakeRule(protocol: "TCP", localPort: "80");
        Assert.False(FirewallRuleAnalyzer.IsBroaderThan(a, b));
    }

    [Fact]
    public void IsBroaderThan_NarrowNotBroaderThanBroad()
    {
        var narrow = MakeRule(protocol: "TCP", localPort: "80");
        var broad = MakeRule(protocol: "Any", localPort: "Any");
        Assert.False(FirewallRuleAnalyzer.IsBroaderThan(narrow, broad));
    }

    // ===================== ParsePorts =====================

    [Fact]
    public void ParsePorts_Any_ReturnsEmpty()
    {
        Assert.Empty(FirewallRuleAnalyzer.ParsePorts("Any"));
    }

    [Fact]
    public void ParsePorts_SinglePort()
    {
        var result = FirewallRuleAnalyzer.ParsePorts("80");
        Assert.Single(result);
        Assert.Equal(80, result[0]);
    }

    [Fact]
    public void ParsePorts_MultiplePorts()
    {
        var result = FirewallRuleAnalyzer.ParsePorts("80,443,8080");
        Assert.Equal(3, result.Count);
        Assert.Contains(result, p => p == 443);
    }

    [Fact]
    public void ParsePorts_Range()
    {
        var result = FirewallRuleAnalyzer.ParsePorts("100-200");
        Assert.Contains(result, p => p == 100);
        Assert.Contains(result, p => p == 200);
    }

    [Fact]
    public void ParsePorts_Null_ReturnsEmpty()
    {
        Assert.Empty(FirewallRuleAnalyzer.ParsePorts(null!));
    }

    [Fact]
    public void ParsePorts_Empty_ReturnsEmpty()
    {
        Assert.Empty(FirewallRuleAnalyzer.ParsePorts(""));
    }

    // ===================== Risk Score =====================

    [Fact]
    public void RiskScore_EmptyState_IsZero()
    {
        var report = _analyzer.BuildReport(EmptyState());
        Assert.Equal(0, report.RiskScore);
    }

    [Fact]
    public void RiskScore_CriticalRule_IncreasesSignificantly()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "WideOpen", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.True(report.RiskScore >= 15);
    }

    [Fact]
    public void RiskScore_CappedAt100()
    {
        var rules = new List<FirewallRule>();
        for (int i = 0; i < 20; i++)
        {
            rules.Add(MakeRule(name: $"Open{i}", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"));
        }
        var report = _analyzer.BuildReport(new FirewallRuleState { Rules = rules });
        Assert.Equal(100, report.RiskScore);
    }

    [Fact]
    public void RiskScore_SafeRules_LowScore()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "HTTPS", localPort: "443", program: @"C:\nginx.exe", remoteAddress: "10.0.0.0/8"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.True(report.RiskScore < 10);
    }

    // ===================== Analyze Findings =====================

    [Fact]
    public void Analyze_HighRiskScore_ProducesCriticalFinding()
    {
        var rules = new List<FirewallRule>();
        for (int i = 0; i < 10; i++)
        {
            rules.Add(MakeRule(name: $"Open{i}", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"));
        }
        var findings = _analyzer.Analyze(new FirewallRuleState { Rules = rules });
        Assert.Contains(findings, f => f.Title == "High Firewall Risk Score" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_ModerateRisk_ProducesWarningFinding()
    {
        // 3 critical rules = 45 risk score
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "O1", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
                MakeRule(name: "O2", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
                MakeRule(name: "O3", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
            }
        };
        var findings = _analyzer.Analyze(state);
        Assert.Contains(findings, f => f.Title.Contains("Firewall Risk Score") && f.Severity >= Severity.Warning);
    }

    [Fact]
    public void Analyze_LowRisk_ProducesPassFinding()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Safe", localPort: "8080", program: "Any"), // Only info-level
            }
        };
        var findings = _analyzer.Analyze(state);
        Assert.Contains(findings, f => f.Title.Contains("Firewall Risk Score") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_DuplicateRules_ProducesInfoFinding()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "A", localPort: "80"),
                MakeRule(name: "B", localPort: "80"),
            }
        };
        var findings = _analyzer.Analyze(state);
        Assert.Contains(findings, f => f.Title == "Duplicate Firewall Rules");
    }

    [Fact]
    public void Analyze_ShadowedRule_ProducesWarningFinding()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Broad", protocol: "Any", localPort: "Any", remoteAddress: "Any", program: "Any"),
                MakeRule(name: "Narrow", protocol: "TCP", localPort: "80"),
            }
        };
        var findings = _analyzer.Analyze(state);
        Assert.Contains(findings, f => f.Title.Contains("Shadowed Rule"));
    }

    // ===================== Profile Coverage =====================

    [Fact]
    public void ProfileCovers_CommaProfileSupersetCoversSubset()
    {
        var broad = MakeRule(protocol: "TCP", localPort: "80", profile: "Domain, Private, Public", program: "Any", remoteAddress: "Any");
        var narrow = MakeRule(protocol: "TCP", localPort: "80", profile: "Private", program: "Any", remoteAddress: "Any");
        // Broad has Any-like coverage via profile but needs strictly broader in another dimension
        // These have same protocol/port/remote/program so IsBroaderThan requires one dim strictly broader
        Assert.False(FirewallRuleAnalyzer.IsBroaderThan(broad, narrow));
        // But if broad has Any program and narrow has specific...
        narrow.Program = @"C:\a.exe";
        Assert.True(FirewallRuleAnalyzer.IsBroaderThan(broad, narrow));
    }

    // ===================== Edge Cases =====================

    [Fact]
    public void OnlyBlockRules_NoRisks()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Block1", action: "Block", localPort: "445"),
                MakeRule(name: "Block2", action: "Block", localPort: "3389"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Empty(report.RiskyRules);
        Assert.Equal(0, report.OverlyPermissiveCount);
        Assert.Equal(0, report.DangerousPortCount);
    }

    [Fact]
    public void OnlyOutboundRules_NoInboundRisks()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "Out1", direction: "Out", protocol: "Any", localPort: "Any"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(0, report.OverlyPermissiveCount);
        Assert.Equal(0, report.DangerousPortCount);
        Assert.Equal(0, report.PublicProfileExposureCount);
    }

    [Fact]
    public void MixedRules_OnlyInboundAllowAnalyzed()
    {
        var state = new FirewallRuleState
        {
            Rules = new()
            {
                MakeRule(name: "InAllow", direction: "In", action: "Allow", localPort: "445"),
                MakeRule(name: "InBlock", direction: "In", action: "Block", localPort: "445"),
                MakeRule(name: "OutAllow", direction: "Out", action: "Allow", localPort: "445"),
            }
        };
        var report = _analyzer.BuildReport(state);
        Assert.Equal(1, report.DangerousPortCount);
    }

    [Fact]
    public void DangerousPortsMap_ContainsExpectedEntries()
    {
        Assert.True(FirewallRuleAnalyzer.DangerousPorts.ContainsKey(21));
        Assert.True(FirewallRuleAnalyzer.DangerousPorts.ContainsKey(23));
        Assert.True(FirewallRuleAnalyzer.DangerousPorts.ContainsKey(135));
        Assert.True(FirewallRuleAnalyzer.DangerousPorts.ContainsKey(139));
        Assert.True(FirewallRuleAnalyzer.DangerousPorts.ContainsKey(445));
        Assert.True(FirewallRuleAnalyzer.DangerousPorts.ContainsKey(3389));
        Assert.True(FirewallRuleAnalyzer.DangerousPorts.ContainsKey(27017));
        Assert.Equal(13, FirewallRuleAnalyzer.DangerousPorts.Count);
    }

    [Fact]
    public void LargeRuleSet_CompletesWithoutError()
    {
        var rules = new List<FirewallRule>();
        for (int i = 0; i < 500; i++)
        {
            rules.Add(MakeRule(name: $"Rule{i}", localPort: (i % 65535 + 1).ToString()));
        }
        var report = _analyzer.BuildReport(new FirewallRuleState { Rules = rules });
        Assert.Equal(500, report.TotalRules);
    }
}
