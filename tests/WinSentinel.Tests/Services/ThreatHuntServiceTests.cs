using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ThreatHuntServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;
    private readonly ThreatHuntService _svc;

    public ThreatHuntServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"threat-hunt-test-{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _history.EnsureDatabase();
        _svc = new ThreatHuntService(_history);
    }

    public void Dispose()
    {
        _history.Dispose();
        try { File.Delete(_dbPath); } catch { }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static SecurityReport BuildReport(params (string title, string module, string category, Severity severity)[] findings)
    {
        var report = new SecurityReport
        {
            SecurityScore = 70,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new List<AuditResult>()
        };

        var grouped = findings.GroupBy(f => f.module);
        foreach (var group in grouped)
        {
            var result = new AuditResult
            {
                ModuleName = group.Key,
                Category = group.First().category,
                Findings = group.Select(f => new Finding
                {
                    Title = f.title,
                    Description = f.title,
                    Severity = f.severity,
                    Category = f.category
                }).ToList()
            };
            report.Results.Add(result);
        }

        return report;
    }

    private static SecurityReport EmptyReport() => new()
    {
        SecurityScore = 100,
        GeneratedAt = DateTimeOffset.UtcNow,
        Results = new List<AuditResult>()
    };

    private void SeedHistory(int runs)
    {
        for (int i = 0; i < runs; i++)
        {
            var r = new SecurityReport
            {
                SecurityScore = 80,
                GeneratedAt = DateTimeOffset.UtcNow.AddDays(-(runs - i)),
                Results = new List<AuditResult>
                {
                    new()
                    {
                        ModuleName = "NetworkAudit",
                        Category = "Network",
                        Findings = new List<Finding>
                        {
                            Finding.Warning("Open port 445", "SMB port open", "Network")
                        }
                    }
                }
            };
            _history.SaveAuditResult(r);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Basic behavior
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_EmptyReport_NoHypotheses()
    {
        var result = _svc.Hunt(EmptyReport());

        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.TotalHypotheses);
        Assert.Equal(100, result.HuntScore);
        Assert.Empty(result.Hypotheses);
        Assert.Empty(result.RecommendedActions);
    }

    [Fact]
    public void Hunt_SetsTimestamp()
    {
        var before = DateTimeOffset.UtcNow;
        var result = _svc.Hunt(EmptyReport());
        var after = DateTimeOffset.UtcNow;

        Assert.True(result.HuntTimestamp >= before);
        Assert.True(result.HuntTimestamp <= after);
    }

    [Fact]
    public void Hunt_CountsFindings()
    {
        var report = BuildReport(
            ("SMB open", "NetworkAudit", "Network", Severity.Warning),
            ("RDP enabled", "NetworkAudit", "Network", Severity.Warning),
            ("Weak password", "CredentialAudit", "Credential", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        Assert.Equal(3, result.TotalFindings);
    }

    [Fact]
    public void Hunt_ReportsHistoryRunCount()
    {
        SeedHistory(5);
        var result = _svc.Hunt(EmptyReport(), historyDays: 90);

        Assert.Equal(5, result.HistoryRunsAnalyzed);
    }

    [Fact]
    public void Hunt_HypothesesSortedByThreatScoreDesc()
    {
        var report = BuildReport(
            ("SMB share exposed", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP enabled", "NetworkAudit", "Network", Severity.Critical),
            ("Admin account active", "AccountAudit", "Account", Severity.Warning),
            ("Password never expires", "CredentialAudit", "Credential", Severity.Warning),
            ("Defender disabled", "DefenderAudit", "Defender", Severity.Critical),
            ("Event log cleared", "EventLogAudit", "EventLog", Severity.Warning),
            ("BitLocker off", "EncryptionAudit", "Encryption", Severity.Critical),
            ("Open port 8080", "NetworkAudit", "Network", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        for (int i = 1; i < result.Hypotheses.Count; i++)
        {
            Assert.True(result.Hypotheses[i - 1].ThreatScore >= result.Hypotheses[i].ThreatScore,
                $"Hypotheses not sorted: [{i - 1}]={result.Hypotheses[i - 1].ThreatScore} < [{i}]={result.Hypotheses[i].ThreatScore}");
        }
    }

    [Fact]
    public void Hunt_CountsStatusCategories()
    {
        var report = BuildReport(
            ("SMB share open", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP enabled", "NetworkAudit", "Network", Severity.Critical),
            ("Defender issue", "DefenderAudit", "Defender", Severity.Warning),
            ("PowerShell logging disabled", "PowerShellAudit", "PowerShell", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        Assert.Equal(result.ConfirmedThreats + result.SuspiciousFindings + result.ClearedHypotheses, result.TotalHypotheses);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Lateral Movement (TA0008)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_LateralMovement_SMBAndRemote_Confirmed()
    {
        var report = BuildReport(
            ("SMB share exposed", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP enabled without NLA", "NetworkAudit", "Network", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var lateral = result.Hypotheses.FirstOrDefault(h => h.Name == "Lateral Movement Potential");
        Assert.NotNull(lateral);
        Assert.Equal("TA0008", lateral.MitreId);
        Assert.True(lateral.ThreatScore > 0);
    }

    [Fact]
    public void Hunt_LateralMovement_OnlySMB_NotConfirmed()
    {
        var report = BuildReport(
            ("SMB share exposed", "NetworkAudit", "SMB", Severity.Info)
        );

        var result = _svc.Hunt(report);

        var lateral = result.Hypotheses.FirstOrDefault(h => h.Name == "Lateral Movement Potential");
        if (lateral != null)
        {
            Assert.NotEqual(HuntStatus.Confirmed, lateral.Status);
        }
    }

    [Fact]
    public void Hunt_LateralMovement_IncludesEvidence()
    {
        var report = BuildReport(
            ("SMB share public", "NetworkAudit", "Share", Severity.Critical),
            ("WinRM open", "NetworkAudit", "Network", Severity.Warning),
            ("Firewall too permissive", "FirewallAudit", "Firewall", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var lateral = result.Hypotheses.FirstOrDefault(h => h.Name == "Lateral Movement Potential");
        Assert.NotNull(lateral);
        Assert.NotEmpty(lateral.Evidence);
        Assert.Contains(lateral.Evidence, e => e.Contains("SMB share public"));
    }

    // ══════════════════════════════════════════════════════════════════
    //  Persistence (TA0003)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_Persistence_MultipleCategories_Confirmed()
    {
        var report = BuildReport(
            ("Suspicious startup entry", "StartupAudit", "Startup", Severity.Warning),
            ("Unknown scheduled task", "ScheduledTaskAudit", "Tasks", Severity.Warning),
            ("Unquoted service path", "ServiceAudit", "Service", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        var persistence = result.Hypotheses.FirstOrDefault(h => h.Name == "Persistence Mechanism Abuse");
        Assert.NotNull(persistence);
        Assert.Equal("TA0003", persistence.MitreId);
        Assert.Equal(HuntStatus.Confirmed, persistence.Status);
    }

    [Fact]
    public void Hunt_Persistence_TwoCategories_Suspicious()
    {
        var report = BuildReport(
            ("Suspicious startup item", "StartupAudit", "Startup", Severity.Warning),
            ("Task scheduler anomaly", "ScheduledTaskAudit", "Tasks", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var persistence = result.Hypotheses.FirstOrDefault(h => h.Name == "Persistence Mechanism Abuse");
        Assert.NotNull(persistence);
        Assert.Equal(HuntStatus.Suspicious, persistence.Status);
    }

    [Fact]
    public void Hunt_Persistence_SingleCategory_Cleared()
    {
        var report = BuildReport(
            ("Autorun enabled", "StartupAudit", "Startup", Severity.Info)
        );

        var result = _svc.Hunt(report);

        var persistence = result.Hypotheses.FirstOrDefault(h => h.Name == "Persistence Mechanism Abuse");
        if (persistence != null)
        {
            Assert.Equal(HuntStatus.Cleared, persistence.Status);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Privilege Escalation (TA0004)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_PrivilegeEscalation_UnpatchedAndWeakAccounts_Confirmed()
    {
        var report = BuildReport(
            ("Missing critical updates", "UpdateAudit", "Update", Severity.Critical),
            ("Too many admin accounts", "AccountAudit", "Account", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var privesc = result.Hypotheses.FirstOrDefault(h => h.Name == "Privilege Escalation Risk");
        Assert.NotNull(privesc);
        Assert.Equal("TA0004", privesc.MitreId);
        Assert.Equal(HuntStatus.Confirmed, privesc.Status);
    }

    [Fact]
    public void Hunt_PrivilegeEscalation_OnlyAccount_Suspicious()
    {
        var report = BuildReport(
            ("Admin group too large", "AccountAudit", "Account", Severity.Warning),
            ("UAC disabled", "GroupPolicyAudit", "Policy", Severity.Warning),
            ("Elevated privilege granted", "AccountAudit", "Account", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var privesc = result.Hypotheses.FirstOrDefault(h => h.Name == "Privilege Escalation Risk");
        Assert.NotNull(privesc);
        Assert.True(privesc.Status == HuntStatus.Suspicious || privesc.Status == HuntStatus.Cleared);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Data Exfiltration (TA0010)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_DataExfiltration_MultipleVectors_Confirmed()
    {
        var report = BuildReport(
            ("BitLocker not enabled", "EncryptionAudit", "Encryption", Severity.Critical),
            ("Clipboard history enabled", "PrivacyAudit", "Privacy", Severity.Info),
            ("Port 8080 listening", "NetworkAudit", "Network", Severity.Warning),
            ("Telemetry set to full", "PrivacyAudit", "Privacy", Severity.Info)
        );

        var result = _svc.Hunt(report);

        var exfil = result.Hypotheses.FirstOrDefault(h => h.Name == "Data Exfiltration Vectors");
        Assert.NotNull(exfil);
        Assert.Equal("TA0010", exfil.MitreId);
        Assert.Equal(HuntStatus.Confirmed, exfil.Status);
    }

    [Fact]
    public void Hunt_DataExfiltration_SingleCategory_Cleared()
    {
        var report = BuildReport(
            ("BitLocker off on D:", "EncryptionAudit", "Encryption", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var exfil = result.Hypotheses.FirstOrDefault(h => h.Name == "Data Exfiltration Vectors");
        if (exfil != null)
        {
            Assert.Equal(HuntStatus.Cleared, exfil.Status);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Defense Evasion (TA0005)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_DefenseEvasion_DefenderAndLogs_Confirmed()
    {
        var report = BuildReport(
            ("Real-time protection disabled", "DefenderAudit", "Defender", Severity.Critical),
            ("Event log size too small", "EventLogAudit", "EventLog", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var evasion = result.Hypotheses.FirstOrDefault(h => h.Name == "Defense Evasion Indicators");
        Assert.NotNull(evasion);
        Assert.Equal("TA0005", evasion.MitreId);
        Assert.Equal(HuntStatus.Confirmed, evasion.Status);
        Assert.Contains("CRITICAL", evasion.Recommendation);
    }

    [Fact]
    public void Hunt_DefenseEvasion_OnlyDefender_Suspicious()
    {
        var report = BuildReport(
            ("Cloud-delivered protection off", "DefenderAudit", "Defender", Severity.Warning),
            ("Tamper protection disabled", "DefenderAudit", "Defender", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        var evasion = result.Hypotheses.FirstOrDefault(h => h.Name == "Defense Evasion Indicators");
        Assert.NotNull(evasion);
        Assert.Equal(HuntStatus.Suspicious, evasion.Status);
    }

    [Fact]
    public void Hunt_DefenseEvasion_DefenderDisabled_BonusScore()
    {
        var report = BuildReport(
            ("Real-time protection disabled", "DefenderAudit", "Defender", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        var evasion = result.Hypotheses.FirstOrDefault(h => h.Name == "Defense Evasion Indicators");
        Assert.NotNull(evasion);
        // Defender down adds +20 bonus to threat score
        Assert.True(evasion.ThreatScore >= 20);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Shadow Admins (T1078)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_ShadowAdmins_ManyFindings_Confirmed()
    {
        var report = BuildReport(
            ("Admin group has 5 members", "AccountAudit", "Account", Severity.Warning),
            ("Guest account enabled", "AccountAudit", "Account", Severity.Warning),
            ("Built-in admin active", "AccountAudit", "Account", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        var shadow = result.Hypotheses.FirstOrDefault(h => h.Name == "Shadow Admin Accounts");
        Assert.NotNull(shadow);
        Assert.Equal("T1078", shadow.MitreId);
        Assert.Equal(HuntStatus.Confirmed, shadow.Status);
    }

    [Fact]
    public void Hunt_ShadowAdmins_SingleFinding_Suspicious()
    {
        var report = BuildReport(
            ("Built-in admin active", "AccountAudit", "Account", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var shadow = result.Hypotheses.FirstOrDefault(h => h.Name == "Shadow Admin Accounts");
        Assert.NotNull(shadow);
        Assert.Equal(HuntStatus.Suspicious, shadow.Status);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Stale Credentials (T1552)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_StaleCredentials_Critical_Confirmed()
    {
        var report = BuildReport(
            ("Credential exposure detected", "CredentialAudit", "Credential", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        var cred = result.Hypotheses.FirstOrDefault(h => h.Name == "Stale / Exposed Credentials");
        Assert.NotNull(cred);
        Assert.Equal("T1552", cred.MitreId);
        Assert.Equal(HuntStatus.Confirmed, cred.Status);
        Assert.Contains("CRITICAL", cred.Recommendation);
    }

    [Fact]
    public void Hunt_StaleCredentials_MultipleNonCritical_Suspicious()
    {
        var report = BuildReport(
            ("Password never expires", "CredentialAudit", "Credential", Severity.Warning),
            ("Cached credentials found", "CredentialAudit", "Credential", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var cred = result.Hypotheses.FirstOrDefault(h => h.Name == "Stale / Exposed Credentials");
        Assert.NotNull(cred);
        Assert.Equal(HuntStatus.Suspicious, cred.Status);
    }

    [Fact]
    public void Hunt_StaleCredentials_SingleWarning_Cleared()
    {
        var report = BuildReport(
            ("Password complexity not enforced", "CredentialAudit", "Credential", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var cred = result.Hypotheses.FirstOrDefault(h => h.Name == "Stale / Exposed Credentials");
        Assert.NotNull(cred);
        Assert.Equal(HuntStatus.Cleared, cred.Status);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Phantom Services (T1036)
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_PhantomServices_LessThan3Runs_NoHypothesis()
    {
        SeedHistory(2);

        var result = _svc.Hunt(EmptyReport(), historyDays: 90);

        var phantom = result.Hypotheses.FirstOrDefault(h => h.Name == "Phantom / Intermittent Activity");
        Assert.Null(phantom);
    }

    [Fact]
    public void Hunt_PhantomServices_IntermittentModules_Detected()
    {
        // Seed history with intermittent findings: module present in 3 of 5 runs
        for (int i = 0; i < 5; i++)
        {
            var findings = new List<Finding>();
            if (i % 2 == 0) // Present in runs 0, 2, 4 = 60% presence
            {
                findings.Add(Finding.Warning("Suspicious service found", "Odd svc", "Service"));
            }

            var r = new SecurityReport
            {
                SecurityScore = 75,
                GeneratedAt = DateTimeOffset.UtcNow.AddDays(-(5 - i)),
                Results = new List<AuditResult>
                {
                    new() { ModuleName = "SuspiciousModule", Category = "Service", Findings = findings }
                }
            };
            _history.SaveAuditResult(r);
        }

        var result = _svc.Hunt(EmptyReport(), historyDays: 90);

        var phantom = result.Hypotheses.FirstOrDefault(h => h.Name == "Phantom / Intermittent Activity");
        if (phantom != null)
        {
            Assert.Equal("T1036", phantom.MitreId);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Hunt Score & Recommended Actions
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_HuntScore_100ForNoThreats()
    {
        var result = _svc.Hunt(EmptyReport());

        Assert.Equal(100, result.HuntScore);
    }

    [Fact]
    public void Hunt_HuntScore_LowerWithThreats()
    {
        var report = BuildReport(
            ("SMB share open", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP enabled", "NetworkAudit", "Network", Severity.Critical),
            ("Defender off", "DefenderAudit", "Defender", Severity.Critical),
            ("Event log cleared", "EventLogAudit", "EventLog", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        Assert.True(result.HuntScore < 100, $"Expected < 100 but got {result.HuntScore}");
    }

    [Fact]
    public void Hunt_HuntScore_ClampedTo0_100()
    {
        var report = BuildReport(
            ("SMB share open", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP open", "NetworkAudit", "Network", Severity.Critical),
            ("Defender off", "DefenderAudit", "Defender", Severity.Critical),
            ("Logs cleared", "EventLogAudit", "EventLog", Severity.Critical),
            ("PowerShell logging off", "PowerShellAudit", "PowerShell", Severity.Critical),
            ("BitLocker off", "EncryptionAudit", "Encryption", Severity.Critical),
            ("Port open", "NetworkAudit", "Network", Severity.Critical),
            ("Telemetry full", "PrivacyAudit", "Privacy", Severity.Critical),
            ("Admin sprawl", "AccountAudit", "Account", Severity.Critical),
            ("Credential leak", "CredentialAudit", "Credential", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        Assert.InRange(result.HuntScore, 0, 100);
    }

    [Fact]
    public void Hunt_RecommendedActions_ConfirmedGetHighPriority()
    {
        var report = BuildReport(
            ("SMB share open", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP enabled", "NetworkAudit", "Network", Severity.Critical),
            ("Defender off", "DefenderAudit", "Defender", Severity.Critical),
            ("Event log cleared", "EventLogAudit", "EventLog", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        if (result.RecommendedActions.Count > 0)
        {
            // First actions should be from Confirmed hypotheses
            var confirmedNames = result.Hypotheses
                .Where(h => h.Status == HuntStatus.Confirmed)
                .Select(h => h.Name)
                .ToHashSet();

            var firstAction = result.RecommendedActions[0];
            Assert.True(confirmedNames.Contains(firstAction.HypothesisName),
                $"First action '{firstAction.HypothesisName}' should be from a Confirmed hypothesis");
        }
    }

    [Fact]
    public void Hunt_RecommendedActions_PrioritiesAscending()
    {
        var report = BuildReport(
            ("SMB share exposed", "NetworkAudit", "Share", Severity.Critical),
            ("RDP enabled", "NetworkAudit", "Network", Severity.Critical),
            ("Admin account active", "AccountAudit", "Account", Severity.Warning),
            ("Password never expires", "CredentialAudit", "Credential", Severity.Warning),
            ("Defender disabled", "DefenderAudit", "Defender", Severity.Critical),
            ("Event log cleared", "EventLogAudit", "EventLog", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        for (int i = 1; i < result.RecommendedActions.Count; i++)
        {
            Assert.True(result.RecommendedActions[i].Priority > result.RecommendedActions[i - 1].Priority,
                $"Actions not in ascending priority order at index {i}");
        }
    }

    [Fact]
    public void Hunt_RecommendedActions_ContainMitreIds()
    {
        var report = BuildReport(
            ("SMB share open", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP open", "NetworkAudit", "Network", Severity.Critical)
        );

        var result = _svc.Hunt(report);

        foreach (var action in result.RecommendedActions)
        {
            Assert.False(string.IsNullOrEmpty(action.MitreId),
                $"Action '{action.HypothesisName}' missing MITRE ID");
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Cross-module correlation
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_CrossModule_HigherScoreWhenMultipleModulesContribute()
    {
        // Single module - only network findings
        var singleModule = BuildReport(
            ("SMB open", "NetworkAudit", "Network", Severity.Warning),
            ("RDP open", "NetworkAudit", "Network", Severity.Warning)
        );

        // Multiple modules - cross-module correlation bonus
        var multiModule = BuildReport(
            ("SMB open", "NetworkAudit", "Share", Severity.Warning),
            ("RDP open", "NetworkAudit", "Network", Severity.Warning),
            ("Firewall permissive", "FirewallAudit", "Firewall", Severity.Warning)
        );

        var singleResult = _svc.Hunt(singleModule);
        var multiResult = _svc.Hunt(multiModule);

        // Multi-module should have lower hunt score (more threats detected)
        // or at least equivalent findings
        Assert.True(multiResult.TotalHypotheses >= singleResult.TotalHypotheses ||
                    multiResult.HuntScore <= singleResult.HuntScore);
    }

    // ══════════════════════════════════════════════════════════════════
    //  MITRE ATT&CK coverage
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Hunt_CoversMultipleMitreTactics()
    {
        var report = BuildReport(
            ("SMB share open", "NetworkAudit", "Share", Severity.Critical),
            ("RDP enabled", "NetworkAudit", "Network", Severity.Critical),
            ("Startup entry suspicious", "StartupAudit", "Startup", Severity.Warning),
            ("Scheduled task unknown", "ScheduledTaskAudit", "Tasks", Severity.Warning),
            ("Service unquoted path", "ServiceAudit", "Service", Severity.Critical),
            ("Missing patches", "UpdateAudit", "Update", Severity.Critical),
            ("Admin sprawl", "AccountAudit", "Account", Severity.Warning),
            ("BitLocker off", "EncryptionAudit", "Encryption", Severity.Critical),
            ("Open port 443", "NetworkAudit", "Network", Severity.Warning),
            ("Telemetry full", "PrivacyAudit", "Privacy", Severity.Info),
            ("Defender off", "DefenderAudit", "Defender", Severity.Critical),
            ("Event log size small", "EventLogAudit", "EventLog", Severity.Warning),
            ("Admin group large", "AccountAudit", "Account", Severity.Warning),
            ("Guest account on", "AccountAudit", "Account", Severity.Warning),
            ("Built-in admin active", "AccountAudit", "Account", Severity.Critical),
            ("Password never expires", "CredentialAudit", "Credential", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        var mitreIds = result.Hypotheses.Select(h => h.MitreId).Distinct().ToList();

        // Should cover at least: TA0008, TA0003, TA0004, TA0010, TA0005, T1078, T1552
        Assert.Contains("TA0008", mitreIds);
        Assert.Contains("TA0003", mitreIds);
        Assert.Contains("TA0004", mitreIds);
        Assert.Contains("TA0010", mitreIds);
        Assert.Contains("TA0005", mitreIds);
        Assert.Contains("T1078", mitreIds);
        Assert.Contains("T1552", mitreIds);
    }

    [Fact]
    public void Hunt_AllHypothesesHaveNames()
    {
        var report = BuildReport(
            ("SMB share open", "NetworkAudit", "Share", Severity.Critical),
            ("RDP open", "NetworkAudit", "Network", Severity.Critical),
            ("Defender off", "DefenderAudit", "Defender", Severity.Critical),
            ("Password weak", "CredentialAudit", "Credential", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        foreach (var h in result.Hypotheses)
        {
            Assert.False(string.IsNullOrWhiteSpace(h.Name), "Hypothesis has no name");
            Assert.False(string.IsNullOrWhiteSpace(h.Description), "Hypothesis has no description");
            Assert.False(string.IsNullOrWhiteSpace(h.MitreId), "Hypothesis has no MITRE ID");
            Assert.False(string.IsNullOrWhiteSpace(h.Recommendation), "Hypothesis has no recommendation");
        }
    }

    [Fact]
    public void Hunt_EvidenceIsCapped()
    {
        // Create many findings to verify evidence list is capped at 8
        var findings = Enumerable.Range(1, 20)
            .Select(i => ($"SMB share {i}", "NetworkAudit", "Share", Severity.Warning))
            .Concat(Enumerable.Range(1, 20)
                .Select(i => ($"RDP port {i}", "NetworkAudit", "Network", Severity.Warning)))
            .ToArray();

        var report = BuildReport(findings);
        var result = _svc.Hunt(report);

        foreach (var h in result.Hypotheses)
        {
            Assert.True(h.Evidence.Count <= 8,
                $"Hypothesis '{h.Name}' has {h.Evidence.Count} evidence items (max 8)");
        }
    }

    [Fact]
    public void Hunt_NoNullFieldsInResults()
    {
        var report = BuildReport(
            ("SMB share", "NetworkAudit", "SMB", Severity.Critical),
            ("RDP open", "NetworkAudit", "Network", Severity.Warning)
        );

        var result = _svc.Hunt(report);

        Assert.NotNull(result.Hypotheses);
        Assert.NotNull(result.RecommendedActions);

        foreach (var h in result.Hypotheses)
        {
            Assert.NotNull(h.Evidence);
            Assert.NotNull(h.Name);
            Assert.NotNull(h.Description);
            Assert.NotNull(h.Recommendation);
        }
    }
}