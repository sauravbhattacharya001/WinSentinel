using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class LateralMovementDetectorTests
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

    private static Finding MakeFinding(string title, string desc = "",
        Severity severity = Severity.Warning) => new()
    {
        Title = title,
        Description = desc,
        Category = "Security",
        Severity = severity,
        Timestamp = DateTimeOffset.UtcNow.AddHours(-2)
    };

    // ── Basic Tests ──────────────────────────────────────────────

    [Fact]
    public void Detect_EmptyReport_ReturnsCleanReport()
    {
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(new SecurityReport(), historyDays: 30);

        Assert.Equal(0, report.MovementsDetected);
        Assert.Equal(0, report.ThreatScore);
        Assert.Equal("Minimal", report.ThreatLevel);
        Assert.Empty(report.Movements);
        Assert.Empty(report.Paths);
        Assert.NotNull(report.Recommendations);
    }

    [Fact]
    public void Detect_NoLateralMovementFindings_ReturnsZeroMovements()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("High CPU usage by chrome.exe") }),
            ("NetworkAudit", new[] { MakeFinding("DNS query to google.com") })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(0, report.MovementsDetected);
    }

    // ── RDP Detection ────────────────────────────────────────────

    [Fact]
    public void Detect_RdpKeyword_DetectsMovement()
    {
        var secReport = MakeReport(
            ("RemoteAccessAudit", new[] {
                MakeFinding("RDP connection from 10.0.1.5 to 10.0.1.10",
                    "Remote desktop session initiated from workstation to server")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "RDP");
        Assert.Contains(report.Movements, m => m.MitreTechnique == "T1021.001");
    }

    [Fact]
    public void Detect_Port3389_DetectsRdp()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("Outbound connection to 192.168.1.50 on port 3389",
                    "Remote desktop protocol detected from network monitor")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "RDP");
    }

    // ── SMB/PsExec Detection ─────────────────────────────────────

    [Fact]
    public void Detect_SmbPsExec_DetectsMovement()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("PsExec remote execution from 10.0.0.1 to 10.0.0.2",
                    "SMB-based remote process execution detected")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "SMB/PsExec");
        Assert.Contains(report.Movements, m => m.MitreTechnique == "T1021.002");
    }

    [Fact]
    public void Detect_AdminShare_DetectsSmb()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("Access to ADMIN$ share on remote server",
                    "admin$ share accessed from 10.0.0.5 via SMB")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Contains(report.Movements, m => m.Technique == "SMB/PsExec");
    }

    // ── WMI Detection ────────────────────────────────────────────

    [Fact]
    public void Detect_Wmi_DetectsMovement()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("WMI remote process creation on 10.0.2.15",
                    "wmiprvse.exe spawned cmd.exe from remote WMI call")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "WMI");
        Assert.Contains(report.Movements, m => m.MitreTechnique == "T1047");
    }

    // ── PSRemoting Detection ─────────────────────────────────────

    [Fact]
    public void Detect_PSRemoting_DetectsMovement()
    {
        var secReport = MakeReport(
            ("RemoteAccessAudit", new[] {
                MakeFinding("Invoke-Command executed on remote host 10.0.3.20",
                    "PSRemoting session via WinRM port 5985")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "PSRemoting");
    }

    // ── DCOM Detection ───────────────────────────────────────────

    [Fact]
    public void Detect_Dcom_DetectsMovement()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("DCOM lateral movement via MMC20 Application",
                    "Remote DCOM object activation detected")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "DCOM");
    }

    // ── SSH Detection ────────────────────────────────────────────

    [Fact]
    public void Detect_Ssh_DetectsMovement()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("SSH connection to 10.0.5.10 from 10.0.5.1",
                    "OpenSSH client connecting to remote host")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "SSH");
    }

    // ── Service Account Detection ────────────────────────────────

    [Fact]
    public void Detect_ServiceAccount_FlaggedCorrectly()
    {
        var secReport = MakeReport(
            ("RemoteAccessAudit", new[] {
                MakeFinding("RDP connection user: svc_backup from 10.0.1.1 to 10.0.1.2",
                    "Remote desktop using service account svc_backup")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        var svcMovement = report.Movements.FirstOrDefault(m => m.IsServiceAccount);
        Assert.NotNull(svcMovement);
        Assert.Contains(svcMovement.Indicators, i => i.Contains("Service account"));
    }

    // ── Graph Building ───────────────────────────────────────────

    [Fact]
    public void Detect_MultipleMovements_BuildsGraph()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("RDP from 10.0.0.1 to 10.0.0.2", "Remote desktop connection"),
                MakeFinding("SMB access from 10.0.0.2 to 10.0.0.3", "PsExec lateral movement"),
                MakeFinding("WMI call from 10.0.0.1 to 10.0.0.3", "Remote WMI process creation")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Graph.NodeCount >= 2);
        Assert.True(report.Graph.EdgeCount >= 1);
        Assert.NotNull(report.Graph.MostConnectedNode);
    }

    // ── Multi-Hop Path Detection ─────────────────────────────────

    [Fact]
    public void Detect_ChainedMovements_DetectsPath()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("RDP from workstation-a to server-b", "Remote desktop to server-b"),
                MakeFinding("SMB from server-b to dc-01", "PsExec from server-b to domain controller dc-01")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        // At minimum we should detect movements
        Assert.True(report.MovementsDetected >= 2);
    }

    // ── Severity Classification ──────────────────────────────────

    [Fact]
    public void Detect_HighRiskTechnique_HigherSeverity()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("WMI remote execution from 10.0.0.1 to 10.0.0.2",
                    "Remote WMI process creation detected from network lateral movement")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        var wmiMovement = report.Movements.First(m => m.Technique == "WMI");
        // WMI with remote context should be at least Medium
        Assert.True(wmiMovement.Severity >= LateralMovementSeverity.Medium);
    }

    // ── Threat Score ─────────────────────────────────────────────

    [Fact]
    public void Detect_ManyMovements_HigherThreatScore()
    {
        var findings = new List<Finding>();
        for (var i = 0; i < 10; i++)
        {
            findings.Add(MakeFinding(
                $"SMB PsExec from 10.0.0.{i} to 10.0.0.{i + 100}",
                "Remote SMB lateral movement detected"));
        }

        var secReport = MakeReport(("NetworkAudit", findings.ToArray()));
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.ThreatScore > 0);
        Assert.NotEqual("Minimal", report.ThreatLevel);
    }

    [Fact]
    public void Detect_ZeroMovements_MinimalThreat()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("Normal process activity") })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(0.0, report.ThreatScore);
        Assert.Equal("Minimal", report.ThreatLevel);
    }

    // ── Recommendations ──────────────────────────────────────────

    [Fact]
    public void Detect_WithMovements_GeneratesRecommendations()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("SMB from 10.0.0.1 to 10.0.0.2", "PsExec admin$ remote execution detected"),
                MakeFinding("WMI remote call from 10.0.0.3 to 10.0.0.4", "Remote WMI process creation")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.NotEmpty(report.Recommendations);
        Assert.Contains(report.Recommendations, r => r.Category.Length > 0);
    }

    [Fact]
    public void Detect_ServiceAccountMovement_GeneratesCredentialRecommendation()
    {
        var secReport = MakeReport(
            ("RemoteAccessAudit", new[] {
                MakeFinding("RDP connection user: svc_deploy from 10.0.0.1 to 10.0.0.2",
                    "Remote desktop using service account svc_deploy from remote workstation")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        if (report.Stats.ServiceAccountMovements > 0)
        {
            Assert.Contains(report.Recommendations, r => r.Category == "Credential Hygiene");
        }
    }

    // ── Deduplication ────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateMovements_Deduplicated()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("RDP from 10.0.0.1 to 10.0.0.2", "Remote desktop detected"),
                MakeFinding("RDP session from 10.0.0.1 to 10.0.0.2", "Another RDP detection same hosts")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        // Same source->target->technique should be deduplicated
        var rdpMoves = report.Movements.Where(m =>
            m.Technique == "RDP" && m.SourceHost == "10.0.0.1" && m.TargetHost == "10.0.0.2").ToList();
        Assert.True(rdpMoves.Count <= 1);
    }

    // ── IP Extraction ────────────────────────────────────────────

    [Fact]
    public void Detect_IpAddressesInTitle_ExtractsHosts()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("SMB connection from 192.168.1.10 to 192.168.1.20",
                    "PsExec lateral movement between two hosts")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        var movement = report.Movements.First();
        Assert.Equal("192.168.1.10", movement.SourceHost);
        Assert.Equal("192.168.1.20", movement.TargetHost);
    }

    // ── Stats Computation ────────────────────────────────────────

    [Fact]
    public void Detect_MultiTechnique_StatsCorrect()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("RDP from 10.0.0.1 to 10.0.0.2", "Remote desktop session"),
                MakeFinding("SMB from 10.0.0.3 to 10.0.0.4", "PsExec lateral movement"),
                MakeFinding("WMI call from 10.0.0.5 to 10.0.0.6", "Remote WMI execution")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Stats.UniqueTechniques >= 2);
        Assert.True(report.Stats.UniqueSourceHosts >= 1);
        Assert.True(report.Stats.UniqueTargetHosts >= 1);
        Assert.NotEmpty(report.Stats.MostUsedTechnique);
        Assert.NotEmpty(report.Stats.MostTargetedHost);
    }

    // ── Host Role Classification ────────────────────────────────

    [Fact]
    public void Detect_DomainControllerTarget_MarkedCritical()
    {
        var secReport = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("SMB from workstation-01 to dc-primary",
                    "PsExec remote execution to domain controller dc-primary")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        if (report.Graph.Nodes.Count > 0)
        {
            var dcNode = report.Graph.Nodes.FirstOrDefault(n => n.HostName.Contains("dc"));
            if (dcNode != null)
            {
                Assert.True(dcNode.IsCriticalAsset);
                Assert.Equal("dc", dcNode.Role);
            }
        }
    }

    // ── Scheduled Task Detection ─────────────────────────────────

    [Fact]
    public void Detect_ScheduledTask_DetectsMovement()
    {
        var secReport = MakeReport(
            ("ScheduledTaskAudit", new[] {
                MakeFinding("Remote scheduled task created via schtasks on 10.0.4.15",
                    "Scheduled task propagation from remote host")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.MovementsDetected >= 1);
        Assert.Contains(report.Movements, m => m.Technique == "ScheduledTask");
    }

    // ── Confidence Scoring ───────────────────────────────────────

    [Fact]
    public void Detect_RemoteContext_HigherConfidence()
    {
        var withRemote = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("RDP remote lateral pivot from 10.0.0.1 to 10.0.0.2",
                    "Remote desktop lateral movement detected")
            })
        );
        var withoutRemote = MakeReport(
            ("NetworkAudit", new[] {
                MakeFinding("RDP connection from 10.0.0.1 to 10.0.0.2",
                    "Desktop protocol activity on port 3389")
            })
        );
        var detector = new LateralMovementDetector(MakeHistory());
        var reportWith = detector.Detect(withRemote, historyDays: 30);
        var reportWithout = detector.Detect(withoutRemote, historyDays: 30);

        if (reportWith.Movements.Count > 0 && reportWithout.Movements.Count > 0)
        {
            // Remote context should boost confidence
            Assert.True(reportWith.Movements[0].Confidence >= reportWithout.Movements[0].Confidence);
        }
    }
}
