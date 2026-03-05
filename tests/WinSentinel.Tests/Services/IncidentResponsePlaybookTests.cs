using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.IncidentResponsePlaybook;

namespace WinSentinel.Tests.Services;

public class IncidentResponsePlaybookTests
{
    // ── Helpers ──────────────────────────────────────────────────────

    private static IncidentResponsePlaybook CreatePlaybook() => new();

    private static Finding MakeFinding(Severity severity, string title,
        string description, string category) =>
        new()
        {
            Title = title,
            Description = description,
            Severity = severity,
            Category = category
        };

    private static SecurityReport MakeReport(params Finding[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            Findings = findings.ToList(),
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow,
            Success = true
        };
        return new SecurityReport
        {
            Results = new List<AuditResult> { result },
            SecurityScore = 50,
            GeneratedAt = DateTimeOffset.UtcNow
        };
    }

    private static SecurityReport MakeMultiModuleReport(
        params (string module, string category, Finding[] findings)[] modules)
    {
        return new SecurityReport
        {
            Results = modules.Select(m => new AuditResult
            {
                ModuleName = m.module,
                Category = m.category,
                Findings = m.findings.ToList(),
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow,
                Success = true
            }).ToList(),
            SecurityScore = 50,
            GeneratedAt = DateTimeOffset.UtcNow
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Built-in playbooks registration
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void Constructor_Registers12BuiltInPlaybooks()
    {
        var pb = CreatePlaybook();
        Assert.Equal(12, pb.PlaybookIds.Count);
    }

    [Theory]
    [InlineData("malware")]
    [InlineData("credential-compromise")]
    [InlineData("network-intrusion")]
    [InlineData("ransomware")]
    [InlineData("unauthorized-access")]
    [InlineData("data-exfiltration")]
    [InlineData("privilege-escalation")]
    [InlineData("insecure-config")]
    [InlineData("certificate-compromise")]
    [InlineData("wireless-threat")]
    [InlineData("supply-chain")]
    [InlineData("insider-threat")]
    public void GetPlaybook_BuiltIn_ReturnsPlaybook(string id)
    {
        var pb = CreatePlaybook();
        var playbook = pb.GetPlaybook(id);
        Assert.NotNull(playbook);
        Assert.Equal(id, playbook!.Id);
        Assert.False(string.IsNullOrWhiteSpace(playbook.Name));
        Assert.False(string.IsNullOrWhiteSpace(playbook.Description));
        Assert.NotEmpty(playbook.TriggerCategories);
        Assert.NotEmpty(playbook.TriggerKeywords);
        Assert.NotEmpty(playbook.Steps);
        Assert.NotEmpty(playbook.References);
    }

    [Fact]
    public void GetPlaybook_Unknown_ReturnsNull()
    {
        var pb = CreatePlaybook();
        Assert.Null(pb.GetPlaybook("nonexistent"));
    }

    [Fact]
    public void AllPlaybooks_ReturnsAll()
    {
        var pb = CreatePlaybook();
        Assert.Equal(12, pb.AllPlaybooks.Count);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Playbook structure validation
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void AllPlaybooks_HaveAllFivePhases()
    {
        var pb = CreatePlaybook();
        foreach (var playbook in pb.AllPlaybooks)
        {
            var phases = playbook.Steps.Select(s => s.Phase).Distinct().ToHashSet();
            Assert.Contains(ResponsePhase.Identification, phases);
            Assert.Contains(ResponsePhase.Containment, phases);
            Assert.Contains(ResponsePhase.Eradication, phases);
            Assert.Contains(ResponsePhase.Recovery, phases);
            Assert.Contains(ResponsePhase.LessonsLearned, phases);
        }
    }

    [Fact]
    public void AllPlaybooks_StepsHavePositiveOrder()
    {
        var pb = CreatePlaybook();
        foreach (var playbook in pb.AllPlaybooks)
        {
            Assert.All(playbook.Steps, step =>
            {
                Assert.True(step.Order > 0, $"Step '{step.Action}' in {playbook.Name} has non-positive order");
                Assert.False(string.IsNullOrWhiteSpace(step.Action));
                Assert.False(string.IsNullOrWhiteSpace(step.Details));
            });
        }
    }

    [Fact]
    public void StepsForPhase_ReturnsFilteredSteps()
    {
        var pb = CreatePlaybook();
        var malware = pb.GetPlaybook("malware")!;

        var identification = malware.StepsForPhase(ResponsePhase.Identification);
        Assert.True(identification.Count >= 1);
        Assert.All(identification, s => Assert.Equal(ResponsePhase.Identification, s.Phase));

        var containment = malware.StepsForPhase(ResponsePhase.Containment);
        Assert.True(containment.Count >= 1);
        Assert.All(containment, s => Assert.Equal(ResponsePhase.Containment, s.Phase));
    }

    [Fact]
    public void StepsForPhase_ReturnsOrderedSteps()
    {
        var pb = CreatePlaybook();
        foreach (var playbook in pb.AllPlaybooks)
        {
            foreach (var phase in Enum.GetValues<ResponsePhase>())
            {
                var steps = playbook.StepsForPhase(phase);
                for (int i = 1; i < steps.Count; i++)
                {
                    Assert.True(steps[i].Order >= steps[i - 1].Order,
                        $"Steps out of order in {playbook.Name}/{phase}");
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  Custom playbook registration
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void RegisterPlaybook_AddsCustomPlaybook()
    {
        var pb = CreatePlaybook();
        var custom = new Playbook(
            "custom-test", "Test Playbook", "A custom test playbook.",
            new[] { "Test" }, new[] { "test" }, Priority.P3_Medium,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Identify", "Identify the issue.", false),
                new(ResponsePhase.Containment, 1, "Contain", "Contain it.", false),
                new(ResponsePhase.Eradication, 1, "Remove", "Remove it.", false),
                new(ResponsePhase.Recovery, 1, "Recover", "Recover.", false),
                new(ResponsePhase.LessonsLearned, 1, "Learn", "Learn from it.", false),
            },
            new[] { "None" });

        pb.RegisterPlaybook(custom);
        Assert.Equal(13, pb.PlaybookIds.Count);
        Assert.NotNull(pb.GetPlaybook("custom-test"));
    }

    [Fact]
    public void RegisterPlaybook_NullThrows()
    {
        var pb = CreatePlaybook();
        Assert.Throws<ArgumentNullException>(() => pb.RegisterPlaybook(null!));
    }

    [Fact]
    public void RegisterPlaybook_EmptyIdThrows()
    {
        var pb = CreatePlaybook();
        var bad = new Playbook("", "Bad", "No ID.", Array.Empty<string>(),
            Array.Empty<string>(), Priority.P4_Low, Array.Empty<ResponseStep>(),
            Array.Empty<string>());
        Assert.Throws<ArgumentException>(() => pb.RegisterPlaybook(bad));
    }

    [Fact]
    public void RegisterPlaybook_OverwritesExisting()
    {
        var pb = CreatePlaybook();
        var replacement = new Playbook(
            "malware", "Replaced Malware", "Custom malware playbook.",
            new[] { "Process" }, new[] { "malware" }, Priority.P1_Critical,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Custom step", "Custom.", false),
                new(ResponsePhase.Containment, 1, "Contain", "Contain.", false),
                new(ResponsePhase.Eradication, 1, "Remove", "Remove.", false),
                new(ResponsePhase.Recovery, 1, "Recover", "Recover.", false),
                new(ResponsePhase.LessonsLearned, 1, "Learn", "Learn.", false),
            },
            Array.Empty<string>());

        pb.RegisterPlaybook(replacement);
        Assert.Equal("Replaced Malware", pb.GetPlaybook("malware")!.Name);
        Assert.Equal(12, pb.PlaybookIds.Count);
    }

    [Fact]
    public void RemovePlaybook_RemovesAndReturnsTrue()
    {
        var pb = CreatePlaybook();
        Assert.True(pb.RemovePlaybook("malware"));
        Assert.Equal(11, pb.PlaybookIds.Count);
        Assert.Null(pb.GetPlaybook("malware"));
    }

    [Fact]
    public void RemovePlaybook_UnknownReturnsFalse()
    {
        var pb = CreatePlaybook();
        Assert.False(pb.RemovePlaybook("nonexistent"));
    }

    // ═══════════════════════════════════════════════════════════════
    //  Single finding matching
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void MatchFinding_MalwareFinding_MatchesMalwarePlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Critical, "Suspicious Process Detected",
            "Unsigned executable running from temp directory with malware-like behavior.",
            "Process");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "malware");
    }

    [Fact]
    public void MatchFinding_CredentialFinding_MatchesCredentialPlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Critical, "WDigest Cleartext Credentials",
            "WDigest is storing cleartext passwords in LSASS memory.",
            "Credential");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "credential-compromise");
    }

    [Fact]
    public void MatchFinding_NetworkFinding_MatchesNetworkPlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Warning, "LLMNR Enabled",
            "LLMNR is enabled, allowing name resolution poisoning attacks.",
            "Network");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "network-intrusion");
    }

    [Fact]
    public void MatchFinding_CertificateFinding_MatchesCertificatePlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Warning, "Expired Certificate",
            "Certificate 'MyServer' in LocalMachine\\My expired 30 days ago.",
            "Certificate");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "certificate-compromise");
    }

    [Fact]
    public void MatchFinding_WiFiFinding_MatchesWirelessPlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Warning, "WEP Network Saved",
            "Saved WiFi profile 'CoffeeShop' uses WEP encryption which is easily crackable.",
            "WiFi");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "wireless-threat");
    }

    [Fact]
    public void MatchFinding_DriverFinding_MatchesSupplyChainPlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Critical, "Vulnerable Driver Loaded",
            "Known BYOVD vulnerable driver detected: unsigned driver in system32.",
            "Driver");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "supply-chain");
    }

    [Fact]
    public void MatchFinding_UnquotedPathFinding_MatchesPrivEscPlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Warning, "Unquoted Service Path",
            "Service 'MyService' has an unquoted path allowing DLL hijack or privilege escalation.",
            "Service");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "privilege-escalation");
    }

    [Fact]
    public void MatchFinding_ScheduledTaskFinding_MatchesInsiderThreatPlaybook()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Critical, "Encoded Command in Scheduled Task",
            "Task 'UpdateCheck' runs an encoded command, potential persistence mechanism.",
            "ScheduledTask");

        var matches = pb.MatchFinding(finding);
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Playbook.Id == "insider-threat");
    }

    [Fact]
    public void MatchFinding_NoMatch_ReturnsEmpty()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Info, "Screen Resolution",
            "Display is set to 1920x1080.",
            "Display");

        var matches = pb.MatchFinding(finding);
        Assert.Empty(matches);
    }

    [Fact]
    public void MatchFinding_NullThrows()
    {
        var pb = CreatePlaybook();
        Assert.Throws<ArgumentNullException>(() => pb.MatchFinding(null!));
    }

    [Fact]
    public void MatchFinding_OrderedByConfidenceThenPriority()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Critical, "Malicious Process with Network Intrusion",
            "Suspicious malware process making unauthorized network connections via open port.",
            "Process");

        var matches = pb.MatchFinding(finding);
        Assert.True(matches.Count >= 2);

        for (int i = 1; i < matches.Count; i++)
        {
            Assert.True(
                matches[i - 1].ConfidenceScore >= matches[i].ConfidenceScore ||
                (matches[i - 1].ConfidenceScore == matches[i].ConfidenceScore &&
                 (int)matches[i - 1].AdjustedPriority <= (int)matches[i].AdjustedPriority),
                "Matches should be ordered by confidence desc, then priority asc");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  Priority adjustment
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void MatchFinding_CriticalSeverity_EscalatesPriority()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Critical, "LLMNR Enabled",
            "LLMNR enables poisoning attacks on the network.",
            "Network");

        var matches = pb.MatchFinding(finding);
        var networkMatch = matches.FirstOrDefault(m => m.Playbook.Id == "network-intrusion");
        Assert.NotNull(networkMatch);
        Assert.Equal(Priority.P1_Critical, networkMatch!.AdjustedPriority);
    }

    [Fact]
    public void MatchFinding_InfoSeverity_DeescalatesPriority()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Info, "System Configuration Note",
            "System is not configured with latest baseline settings.",
            "System");

        var matches = pb.MatchFinding(finding);
        var configMatch = matches.FirstOrDefault(m => m.Playbook.Id == "insecure-config");
        Assert.NotNull(configMatch);
        Assert.Equal(Priority.P4_Low, configMatch!.AdjustedPriority);
    }

    [Fact]
    public void MatchFinding_CriticalOnP1_StaysP1()
    {
        var pb = CreatePlaybook();
        var finding = MakeFinding(Severity.Critical, "Trojan Detected",
            "Known trojan malware signature detected in running process.",
            "Process");

        var matches = pb.MatchFinding(finding);
        var malwareMatch = matches.FirstOrDefault(m => m.Playbook.Id == "malware");
        Assert.NotNull(malwareMatch);
        Assert.Equal(Priority.P1_Critical, malwareMatch!.AdjustedPriority);
    }

    [Fact]
    public void MatchFinding_InfoOnP4_StaysP4()
    {
        var pb = CreatePlaybook();
        var p4 = new Playbook("p4-test", "P4 Test", "Test",
            new[] { "TestCat" }, new[] { "testword" },
            Priority.P4_Low,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Id", "Id.", false),
                new(ResponsePhase.Containment, 1, "C", "C.", false),
                new(ResponsePhase.Eradication, 1, "E", "E.", false),
                new(ResponsePhase.Recovery, 1, "R", "R.", false),
                new(ResponsePhase.LessonsLearned, 1, "L", "L.", false),
            },
            Array.Empty<string>());
        pb.RegisterPlaybook(p4);

        var finding = MakeFinding(Severity.Info, "Test Info Finding",
            "Some testword info finding.", "TestCat");

        var matches = pb.MatchFinding(finding);
        var match = matches.FirstOrDefault(m => m.Playbook.Id == "p4-test");
        Assert.NotNull(match);
        Assert.Equal(Priority.P4_Low, match!.AdjustedPriority);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Plan generation
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void GeneratePlan_EmptyReport_ReturnsCleanPlan()
    {
        var pb = CreatePlaybook();
        var report = MakeReport();

        var plan = pb.GeneratePlan(report);
        Assert.Equal(0, plan.TotalFindings);
        Assert.Equal(0, plan.MatchedPlaybooks);
        Assert.Equal(Priority.P4_Low, plan.OverallPriority);
        Assert.Single(plan.ImmediateActions);
        Assert.Contains("clean", plan.ImmediateActions[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GeneratePlan_PassOnlyReport_ReturnsCleanPlan()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            Finding.Pass("All Good", "Everything is fine.", "Network"));

        var plan = pb.GeneratePlan(report);
        Assert.Equal(0, plan.TotalFindings);
        Assert.Equal(0, plan.MatchedPlaybooks);
    }

    [Fact]
    public void GeneratePlan_NullThrows()
    {
        var pb = CreatePlaybook();
        Assert.Throws<ArgumentNullException>(() => pb.GeneratePlan(null!));
    }

    [Fact]
    public void GeneratePlan_CriticalMalware_HasP1Priority()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "Trojan Detected",
                "Known trojan malware detected in process list.", "Process"));

        var plan = pb.GeneratePlan(report);
        Assert.Equal(Priority.P1_Critical, plan.OverallPriority);
        Assert.True(plan.MatchedPlaybooks > 0);
        Assert.True(plan.TotalFindings > 0);
    }

    [Fact]
    public void GeneratePlan_MultipleFindings_GroupsByPlaybook()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "LLMNR Enabled", "Network poisoning.", "Network"),
            MakeFinding(Severity.Warning, "SMB Signing Disabled", "SMB relay attacks possible.", "Network"),
            MakeFinding(Severity.Warning, "Open Port 445", "SMB port exposed to network.", "Network"));

        var plan = pb.GeneratePlan(report);
        var networkMatch = plan.Matches.FirstOrDefault(m => m.Playbook.Id == "network-intrusion");
        Assert.NotNull(networkMatch);
        Assert.True(networkMatch!.TriggeringFindings.Count >= 2);
    }

    [Fact]
    public void GeneratePlan_MixedCategories_MatchesMultiplePlaybooks()
    {
        var pb = CreatePlaybook();
        var report = MakeMultiModuleReport(
            ("Network", "Network", new[]
            {
                MakeFinding(Severity.Warning, "LLMNR Enabled", "LLMNR poisoning risk.", "Network")
            }),
            ("Credential", "Credential", new[]
            {
                MakeFinding(Severity.Critical, "WDigest Enabled", "Cleartext credential exposure.", "Credential")
            }));

        var plan = pb.GeneratePlan(report);
        Assert.True(plan.MatchedPlaybooks >= 2);
        Assert.Contains(plan.Matches, m => m.Playbook.Id == "network-intrusion");
        Assert.Contains(plan.Matches, m => m.Playbook.Id == "credential-compromise");
    }

    [Fact]
    public void GeneratePlan_OverallPriority_IsWorstMatch()
    {
        var pb = CreatePlaybook();
        var report = MakeMultiModuleReport(
            ("Network", "Network", new[]
            {
                MakeFinding(Severity.Warning, "Open Port", "Port 3389 is open.", "Network")
            }),
            ("Certificate", "Certificate", new[]
            {
                MakeFinding(Severity.Info, "Certificate Info", "Certificate expiring soon.", "Certificate")
            }));

        var plan = pb.GeneratePlan(report);
        Assert.True((int)plan.OverallPriority <= (int)Priority.P2_High);
    }

    [Fact]
    public void GeneratePlan_ImmediateActions_IncludesP1Alert()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "Ransomware Indicator",
                "Shadow copy deletion and file encrypt activity detected.", "Process"));

        var plan = pb.GeneratePlan(report);
        Assert.Contains(plan.ImmediateActions,
            a => a.Contains("CRITICAL", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void GeneratePlan_LowSeverityOnly_SuggestsMaintenanceWindow()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Info, "System not configured",
                "System baseline not configured with latest settings.", "System"));

        var plan = pb.GeneratePlan(report);
        Assert.Contains(plan.ImmediateActions,
            a => a.Contains("maintenance", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void GeneratePlan_EstimatedResponseTime_IsPositive()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "Malware Found",
                "Malicious software detected via signature match.", "Process"));

        var plan = pb.GeneratePlan(report);
        Assert.True(plan.EstimatedResponseTime > TimeSpan.Zero);
    }

    [Fact]
    public void GeneratePlan_Summary_ContainsCounts()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Warning, "LLMNR Enabled", "Network poisoning risk.", "Network"));

        var plan = pb.GeneratePlan(report);
        Assert.False(string.IsNullOrWhiteSpace(plan.Summary));
        Assert.Contains("playbook", plan.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GeneratePlan_MatchesOrderedByPriorityThenConfidence()
    {
        var pb = CreatePlaybook();
        var report = MakeMultiModuleReport(
            ("Process", "Process", new[]
            {
                MakeFinding(Severity.Critical, "Malware", "Trojan malware detected.", "Process")
            }),
            ("WiFi", "WiFi", new[]
            {
                MakeFinding(Severity.Info, "WiFi Info", "Auto-connect enabled for public WiFi.", "WiFi")
            }));

        var plan = pb.GeneratePlan(report);
        if (plan.Matches.Count >= 2)
        {
            Assert.True((int)plan.Matches[0].AdjustedPriority <= (int)plan.Matches[1].AdjustedPriority);
        }
    }

    [Fact]
    public void GeneratePlan_ConfidenceBoostedByMultipleFindings()
    {
        var pb = CreatePlaybook();
        var singleReport = MakeReport(
            MakeFinding(Severity.Warning, "LLMNR Enabled", "LLMNR poisoning.", "Network"));
        var singlePlan = pb.GeneratePlan(singleReport);
        var singleMatch = singlePlan.Matches.FirstOrDefault(m => m.Playbook.Id == "network-intrusion");

        var multiReport = MakeReport(
            MakeFinding(Severity.Warning, "LLMNR Enabled", "LLMNR poisoning.", "Network"),
            MakeFinding(Severity.Warning, "SMB Exposed", "SMB relay attack possible.", "Network"),
            MakeFinding(Severity.Warning, "Open Port", "Open port 3389 exposed.", "Network"));
        var multiPlan = pb.GeneratePlan(multiReport);
        var multiMatch = multiPlan.Matches.FirstOrDefault(m => m.Playbook.Id == "network-intrusion");

        Assert.NotNull(singleMatch);
        Assert.NotNull(multiMatch);
        Assert.True(multiMatch!.ConfidenceScore >= singleMatch!.ConfidenceScore);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Checklist generation
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void GenerateChecklist_ReturnsOrderedSteps()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "Malware Detected",
                "Suspicious process malware in temp directory.", "Process"));

        var plan = pb.GeneratePlan(report);
        var checklist = pb.GenerateChecklist(plan);

        Assert.NotEmpty(checklist);
        for (int i = 1; i < checklist.Count; i++)
        {
            var prev = checklist[i - 1];
            var curr = checklist[i];
            Assert.True(
                (int)prev.Priority < (int)curr.Priority ||
                ((int)prev.Priority == (int)curr.Priority && (int)prev.Step.Phase <= (int)curr.Step.Phase),
                "Checklist should be ordered by priority, then phase");
        }
    }

    [Fact]
    public void GenerateChecklist_EmptyPlan_ReturnsEmpty()
    {
        var pb = CreatePlaybook();
        var report = MakeReport();
        var plan = pb.GeneratePlan(report);
        var checklist = pb.GenerateChecklist(plan);
        Assert.Empty(checklist);
    }

    [Fact]
    public void GenerateChecklist_NullThrows()
    {
        var pb = CreatePlaybook();
        Assert.Throws<ArgumentNullException>(() => pb.GenerateChecklist(null!));
    }

    [Fact]
    public void GenerateChecklist_IncludesPlaybookName()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "Trojan Found",
                "Known trojan malware detected.", "Process"));

        var plan = pb.GeneratePlan(report);
        var checklist = pb.GenerateChecklist(plan);
        Assert.All(checklist, item =>
        {
            Assert.False(string.IsNullOrWhiteSpace(item.PlaybookName));
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  Text report generation
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void GenerateTextReport_ContainsHeaderAndSummary()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Warning, "LLMNR Enabled", "Network poisoning risk.", "Network"));
        var plan = pb.GeneratePlan(report);

        var text = pb.GenerateTextReport(plan);
        Assert.Contains("INCIDENT RESPONSE PLAN", text);
        Assert.Contains("SUMMARY", text);
        Assert.Contains("Overall Priority", text);
    }

    [Fact]
    public void GenerateTextReport_IncludesPlaybookDetails()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "Malware Process",
                "Suspicious malware process detected.", "Process"));
        var plan = pb.GeneratePlan(report);

        var text = pb.GenerateTextReport(plan);
        Assert.Contains("MALWARE DETECTED", text);
        Assert.Contains("Confidence", text);
    }

    [Fact]
    public void GenerateTextReport_ShowsImmediateActions()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "Ransomware Indicator",
                "Encrypt activity and shadow copy deletion detected.", "Process"));
        var plan = pb.GeneratePlan(report);

        var text = pb.GenerateTextReport(plan);
        Assert.Contains("IMMEDIATE ACTIONS", text);
    }

    [Fact]
    public void GenerateTextReport_NullThrows()
    {
        var pb = CreatePlaybook();
        Assert.Throws<ArgumentNullException>(() => pb.GenerateTextReport(null!));
    }

    [Fact]
    public void GenerateTextReport_EmptyPlan_StillGenerates()
    {
        var pb = CreatePlaybook();
        var report = MakeReport();
        var plan = pb.GeneratePlan(report);

        var text = pb.GenerateTextReport(plan);
        Assert.Contains("INCIDENT RESPONSE PLAN", text);
    }

    [Fact]
    public void GenerateTextReport_ShowsCommands()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Critical, "WDigest Credential Exposure",
                "WDigest cleartext password storage in LSASS memory.", "Credential"));
        var plan = pb.GeneratePlan(report);

        var text = pb.GenerateTextReport(plan);
        Assert.Contains(">", text);
    }

    [Fact]
    public void GenerateTextReport_ShowsEstimatedDuration()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Warning, "Open Port Exposed",
                "Port 3389 open for unauthorized network intrusion.", "Network"));
        var plan = pb.GeneratePlan(report);

        var text = pb.GenerateTextReport(plan);
        Assert.Contains("Estimated Response Time", text);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Plan comparison
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void ComparePlans_IdenticalPlans_NoChanges()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Warning, "LLMNR Enabled", "Network poisoning.", "Network"));

        var plan1 = pb.GeneratePlan(report);
        var plan2 = pb.GeneratePlan(report);

        var comparison = pb.ComparePlans(plan1, plan2);
        Assert.Empty(comparison.ResolvedIncidents);
        Assert.Empty(comparison.NewIncidents);
        Assert.True(comparison.OngoingIncidents.Count > 0);
        Assert.Equal(0, comparison.NetResolved);
    }

    [Fact]
    public void ComparePlans_ResolvedIncident_DetectsResolution()
    {
        var pb = CreatePlaybook();
        var olderReport = MakeReport(
            MakeFinding(Severity.Warning, "LLMNR Enabled", "Network poisoning.", "Network"));
        var newerReport = MakeReport();

        var older = pb.GeneratePlan(olderReport);
        var newer = pb.GeneratePlan(newerReport);

        var comparison = pb.ComparePlans(older, newer);
        Assert.True(comparison.ResolvedIncidents.Count > 0);
        Assert.Empty(comparison.NewIncidents);
        Assert.True(comparison.NetResolved > 0);
    }

    [Fact]
    public void ComparePlans_NewIncident_DetectsNew()
    {
        var pb = CreatePlaybook();
        var olderReport = MakeReport();
        var newerReport = MakeReport(
            MakeFinding(Severity.Critical, "Malware Found",
                "Malware process detected.", "Process"));

        var older = pb.GeneratePlan(olderReport);
        var newer = pb.GeneratePlan(newerReport);

        var comparison = pb.ComparePlans(older, newer);
        Assert.Empty(comparison.ResolvedIncidents);
        Assert.True(comparison.NewIncidents.Count > 0);
        Assert.True(comparison.NetResolved < 0);
    }

    [Fact]
    public void ComparePlans_NullOlderThrows()
    {
        var pb = CreatePlaybook();
        var newer = pb.GeneratePlan(MakeReport());
        Assert.Throws<ArgumentNullException>(() => pb.ComparePlans(null!, newer));
    }

    [Fact]
    public void ComparePlans_NullNewerThrows()
    {
        var pb = CreatePlaybook();
        var older = pb.GeneratePlan(MakeReport());
        Assert.Throws<ArgumentNullException>(() => pb.ComparePlans(older, null!));
    }

    [Fact]
    public void ComparePlans_FindingsDelta_Computed()
    {
        var pb = CreatePlaybook();
        var olderReport = MakeReport(
            MakeFinding(Severity.Warning, "A", "A desc.", "Network"),
            MakeFinding(Severity.Warning, "B", "B desc.", "Network"),
            MakeFinding(Severity.Warning, "C", "C desc.", "Network"));
        var newerReport = MakeReport(
            MakeFinding(Severity.Warning, "A", "A desc.", "Network"));

        var older = pb.GeneratePlan(olderReport);
        var newer = pb.GeneratePlan(newerReport);

        var comparison = pb.ComparePlans(older, newer);
        Assert.Equal(2, comparison.FindingsDelta);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Edge cases & stress tests
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public void GeneratePlan_ManyFindings_HandlesGracefully()
    {
        var pb = CreatePlaybook();
        var findings = Enumerable.Range(0, 100)
            .Select(i => MakeFinding(
                i % 3 == 0 ? Severity.Critical : Severity.Warning,
                $"Finding {i}",
                $"Description with malware and network and credential keywords {i}.",
                i % 2 == 0 ? "Process" : "Network"))
            .ToArray();

        var report = MakeReport(findings);
        var plan = pb.GeneratePlan(report);

        Assert.Equal(100, plan.TotalFindings);
        Assert.True(plan.MatchedPlaybooks > 0);
        Assert.NotNull(plan.Summary);
    }

    [Fact]
    public void GeneratePlan_AllInfoFindings_NoP1Matches()
    {
        var pb = CreatePlaybook();
        var report = MakeReport(
            MakeFinding(Severity.Info, "Info 1", "System info about network config.", "Network"),
            MakeFinding(Severity.Info, "Info 2", "Certificate info note.", "Certificate"));

        var plan = pb.GeneratePlan(report);
        Assert.DoesNotContain(plan.Matches,
            m => m.AdjustedPriority == Priority.P1_Critical);
    }

    [Fact]
    public void Playbook_DefaultPriority_IsReasonable()
    {
        var pb = CreatePlaybook();
        foreach (var playbook in pb.AllPlaybooks)
        {
            var priority = playbook.DefaultPriority;
            Assert.True(
                priority >= Priority.P1_Critical && priority <= Priority.P4_Low,
                $"Playbook {playbook.Id} has unreasonable priority: {priority}");
        }
    }

    [Fact]
    public void Playbook_AllStepsHaveNonEmptyAction()
    {
        var pb = CreatePlaybook();
        foreach (var playbook in pb.AllPlaybooks)
        {
            foreach (var step in playbook.Steps)
            {
                Assert.False(string.IsNullOrWhiteSpace(step.Action),
                    $"Empty action in {playbook.Id} phase {step.Phase}");
            }
        }
    }

    [Fact]
    public void Playbook_CommandsAreOptional()
    {
        var pb = CreatePlaybook();
        var hasCommand = pb.AllPlaybooks
            .SelectMany(p => p.Steps)
            .Any(s => s.Command != null);
        var hasNoCommand = pb.AllPlaybooks
            .SelectMany(p => p.Steps)
            .Any(s => s.Command == null);

        Assert.True(hasCommand, "Some steps should have commands");
        Assert.True(hasNoCommand, "Some steps should not have commands");
    }

    [Fact]
    public void Playbook_EstimatedDurations_AreReasonable()
    {
        var pb = CreatePlaybook();
        foreach (var playbook in pb.AllPlaybooks)
        {
            foreach (var step in playbook.Steps)
            {
                if (step.EstimatedDuration.HasValue)
                {
                    Assert.True(step.EstimatedDuration.Value > TimeSpan.Zero,
                        $"Duration should be positive in {playbook.Id}: {step.Action}");
                    Assert.True(step.EstimatedDuration.Value <= TimeSpan.FromHours(4),
                        $"Duration seems too long in {playbook.Id}: {step.Action}");
                }
            }
        }
    }

    [Fact]
    public void Playbook_References_AreNonEmpty()
    {
        var pb = CreatePlaybook();
        foreach (var playbook in pb.AllPlaybooks)
        {
            Assert.NotEmpty(playbook.References);
            Assert.All(playbook.References, r =>
                Assert.False(string.IsNullOrWhiteSpace(r)));
        }
    }
}
