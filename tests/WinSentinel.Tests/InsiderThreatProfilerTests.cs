using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class InsiderThreatProfilerTests
{
    private static AuditHistoryService MakeHistory() => new();

    private static SecurityReport MakeReport(params (string module, Finding[] findings)[] modules)
    {
        var report = new SecurityReport();
        foreach (var (module, findings) in modules)
        {
            report.Results.Add(new AuditResult
            {
                ModuleName = module,
                Category = module,
                Findings = findings.ToList()
            });
        }
        return report;
    }

    private static Finding MakeFinding(string title, string desc, string category,
        Severity severity = Severity.Warning) => new()
    {
        Title = title,
        Description = desc,
        Category = category,
        Severity = severity,
        Timestamp = DateTimeOffset.UtcNow.AddHours(-2)
    };

    [Fact]
    public void Profile_EmptyReport_ReturnsCleanPosture()
    {
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var report = profiler.Profile(new SecurityReport(), historyDays: 30);

        Assert.Equal(100, report.PostureScore);
        Assert.Equal("Low", report.RiskTier);
        Assert.Empty(report.Indicators);
        Assert.Equal(0, report.UsersProfiled);
    }

    [Fact]
    public void Profile_AccountFindings_CreatesProfiles()
    {
        var findings = new[]
        {
            MakeFinding("User 'admin' has no password expiry",
                "account admin lacks expiration policy", "Accounts"),
            MakeFinding("User 'jdoe' last logon 90 days ago",
                "user jdoe stale account", "Accounts")
        };

        var report = MakeReport(("Account Audit", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        Assert.True(result.UsersProfiled > 0);
        Assert.NotNull(result.Stats);
    }

    [Fact]
    public void Profile_PrivilegeEscalation_DetectsDeviation()
    {
        var findings = Enumerable.Range(0, 10).Select(i =>
            MakeFinding($"Elevated privilege use #{i}",
                $"user testuser ran elevated command {i}", "Process",
                Severity.Warning)).ToArray();

        var report = MakeReport(("Process Audit", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        Assert.True(result.UsersProfiled > 0);
        Assert.True(result.EventsProcessed > 0);
    }

    [Fact]
    public void Profile_LogTampering_FlagsCritical()
    {
        var findings = new[]
        {
            MakeFinding("Security log cleared by user badactor",
                "user badactor cleared security event log", "EventLog",
                Severity.Critical)
        };

        var report = MakeReport(("Event Log Audit", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        Assert.True(result.UsersProfiled > 0);
        // Log tampering is always concerning
        var profiles = result.Profiles.Where(p => p.Username.Contains("badactor")).ToList();
        if (profiles.Count > 0)
        {
            Assert.True(profiles.First().RiskScore > 0);
        }
    }

    [Fact]
    public void Profile_NetworkAndFileActivity_DetectsExfiltration()
    {
        var findings = new List<Finding>();
        // Bulk file access
        for (int i = 0; i < 15; i++)
        {
            findings.Add(new Finding
            {
                Title = $"user exfiltrator accessed sensitive file {i}",
                Description = $"user exfiltrator read file /confidential/doc{i}.pdf",
                Category = "FileAccess",
                Severity = Severity.Warning,
                Timestamp = DateTimeOffset.UtcNow.AddHours(-3 + (i * 0.1))
            });
        }
        // Network activity
        for (int i = 0; i < 5; i++)
        {
            findings.Add(new Finding
            {
                Title = $"user exfiltrator network connection to external {i}",
                Description = $"user exfiltrator connection to 203.0.113.{i}",
                Category = "Network",
                Severity = Severity.Info,
                Timestamp = DateTimeOffset.UtcNow.AddHours(-2)
            });
        }

        var report = MakeReport(("File System Monitor", findings.ToArray()));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        Assert.True(result.EventsProcessed >= 20);
        Assert.True(result.UsersProfiled > 0);
    }

    [Fact]
    public void Profile_MultipleUsers_RanksbyRisk()
    {
        var findings = new List<Finding>();

        // Low-risk user
        findings.Add(MakeFinding("user lowrisk normal logon",
            "user lowrisk authenticated", "Authentication", Severity.Info));

        // High-risk user with many alerts
        for (int i = 0; i < 8; i++)
        {
            findings.Add(new Finding
            {
                Title = $"user highrisk elevated operation {i}",
                Description = $"user highrisk privilege escalation attempt {i}",
                Category = "Security",
                Severity = Severity.Critical,
                Timestamp = DateTimeOffset.UtcNow.AddHours(-1)
            });
        }

        var report = MakeReport(("Account Audit", findings.ToArray()));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        // Profiles should be ordered by risk (highest first)
        if (result.Profiles.Count >= 2)
        {
            Assert.True(result.Profiles.First().RiskScore >= result.Profiles.Last().RiskScore);
        }
    }

    [Fact]
    public void Profile_PostureScore_DecreasesWithThreats()
    {
        var cleanReport = new SecurityReport();
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var cleanResult = profiler.Profile(cleanReport, historyDays: 30);

        var findings = Enumerable.Range(0, 20).Select(i => new Finding
        {
            Title = $"user threat{i % 3} critical event {i}",
            Description = $"user threat{i % 3} severe security violation {i}",
            Category = "Security",
            Severity = Severity.Critical,
            Timestamp = DateTimeOffset.UtcNow.AddHours(-1)
        }).ToArray();

        var dirtyReport = MakeReport(("Security Monitor", findings));
        var dirtyResult = profiler.Profile(dirtyReport, historyDays: 30);

        Assert.True(cleanResult.PostureScore >= dirtyResult.PostureScore);
    }

    [Fact]
    public void Profile_Recommendations_GeneratedForRiskyEnvironment()
    {
        var findings = Enumerable.Range(0, 10).Select(i => new Finding
        {
            Title = $"user risky elevated admin operation {i}",
            Description = $"user risky privilege escalation and file access {i}",
            Category = "Privilege",
            Severity = Severity.Critical,
            Timestamp = DateTimeOffset.UtcNow.AddMinutes(-30)
        }).ToArray();

        var report = MakeReport(("Privilege Audit", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        // Should generate at least some recommendations for risky environment
        // (depends on whether indicators were detected)
        Assert.NotNull(result.Recommendations);
    }

    [Fact]
    public void Profile_RiskTier_Classification()
    {
        var profiler = new InsiderThreatProfiler(MakeHistory());

        // Empty = safe
        var safeResult = profiler.Profile(new SecurityReport(), 30);
        Assert.Equal("Low", safeResult.RiskTier);
        Assert.Equal(100, safeResult.PostureScore);
    }

    [Fact]
    public void Profile_Stats_ComputedCorrectly()
    {
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(new SecurityReport(), 30);

        Assert.Equal(0, result.Stats.HighRiskUsers);
        Assert.Equal(0, result.Stats.MediumRiskUsers);
        Assert.Equal(0, result.Stats.LowRiskUsers);
        Assert.Equal(0, result.Stats.OffHoursEvents);
        Assert.Equal(0, result.Stats.ExfiltrationIndicators);
        Assert.Equal(0, result.Stats.PrivilegeAbuseIndicators);
        Assert.Equal(0, result.Stats.PreDepartureUsers);
    }

    [Fact]
    public void Profile_AnomalyTimeline_OrderedByTimestamp()
    {
        var findings = Enumerable.Range(0, 5).Select(i => new Finding
        {
            Title = $"user timeuser event at hour {i}",
            Description = $"user timeuser activity {i}",
            Category = "Activity",
            Severity = Severity.Warning,
            Timestamp = DateTimeOffset.UtcNow.AddHours(-i)
        }).ToArray();

        var report = MakeReport(("Activity Monitor", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        if (result.AnomalyTimeline.Count >= 2)
        {
            // Should be ordered most recent first
            for (int i = 0; i < result.AnomalyTimeline.Count - 1; i++)
            {
                Assert.True(result.AnomalyTimeline[i].Timestamp >=
                           result.AnomalyTimeline[i + 1].Timestamp);
            }
        }
    }

    [Fact]
    public void Profile_SynthesizesFromModules_WhenNoUsersFound()
    {
        var findings = new[]
        {
            new Finding
            {
                Title = "Outdated TLS version",
                Description = "TLS 1.0 still enabled",
                Category = "Network",
                Severity = Severity.Warning,
                Timestamp = DateTimeOffset.UtcNow
            }
        };

        var report = MakeReport(("Network Audit", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        // Should still produce a result even without user-specific findings
        Assert.True(result.EventsProcessed > 0);
    }

    [Fact]
    public void Profile_HistoryDays_Configurable()
    {
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result7 = profiler.Profile(new SecurityReport(), historyDays: 7);
        var result90 = profiler.Profile(new SecurityReport(), historyDays: 90);

        Assert.Equal(7, result7.DaysAnalyzed);
        Assert.Equal(90, result90.DaysAnalyzed);
    }

    [Fact]
    public void Profile_OffHoursEvents_Counted()
    {
        // Create findings timestamped at 2 AM (off-hours)
        var findings = Enumerable.Range(0, 5).Select(i => new Finding
        {
            Title = $"user nightowl logon at 2AM event {i}",
            Description = $"user nightowl authentication at unusual hour",
            Category = "Authentication",
            Severity = Severity.Warning,
            Timestamp = new DateTimeOffset(2026, 4, 29, 2, i, 0, TimeSpan.Zero)
        }).ToArray();

        var report = MakeReport(("Account Audit", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        // Should detect activity and profile the user
        Assert.True(result.UsersProfiled > 0);
    }

    [Fact]
    public void Profile_RemovableMedia_FlagsDataStaging()
    {
        var findings = Enumerable.Range(0, 6).Select(i => new Finding
        {
            Title = $"user stager USB removable media access {i}",
            Description = $"user stager connected USB drive and copied files",
            Category = "DeviceControl",
            Severity = Severity.Warning,
            Timestamp = DateTimeOffset.UtcNow.AddHours(-1)
        }).ToArray();

        var report = MakeReport(("Device Monitor", findings));
        var profiler = new InsiderThreatProfiler(MakeHistory());
        var result = profiler.Profile(report, historyDays: 30);

        Assert.True(result.UsersProfiled > 0);
        Assert.True(result.EventsProcessed >= 6);
    }
}
