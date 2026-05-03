using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class InitialAccessDetectorTests
{
    private static AuditHistoryService CreateHistory() => new();

    private static SecurityReport MakeReport(params (string title, string desc)[] findings)
    {
        var report = new SecurityReport();
        var result = new AuditResult { ModuleName = "TestModule", Category = "TestModule" };
        foreach (var (title, desc) in findings)
            result.Findings.Add(new Finding { Title = title, Description = desc });
        report.Results.Add(result);
        return report;
    }

    // ── Basic Behavior ──────────────────────────────────────────────

    [Fact]
    public void Detect_EmptyReport_ReturnsCleanReport()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.AttemptsDetected);
        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Attempts);
        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void Detect_NoInitialAccessFindings_ReturnsZeroAttempts()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Firewall enabled", "Windows firewall is active and configured"));
        var result = detector.Detect(report);

        Assert.Equal(0, result.AttemptsDetected);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    // ── Technique Detection ─────────────────────────────────────────

    [Fact]
    public void Detect_PhishingAttachment_DetectsSpearphishAttachment()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Suspicious email attachment", "Malicious attachment detected with macro-enabled document"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Spearphishing Attachment", result.Attempts[0].Technique);
        Assert.Equal("T1566.001", result.Attempts[0].MitreTechnique);
        Assert.Equal("Email", result.Attempts[0].AccessVector);
    }

    [Fact]
    public void Detect_PhishingLink_DetectsSpearphishLink()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Credential harvest page", "Phishing link redirecting to fake login page"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Spearphishing Link", result.Attempts[0].Technique);
        Assert.Equal("T1566.002", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_DriveByCompromise_DetectsWebExploit()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Browser exploit detected", "Drive-by compromise via malicious redirect on compromised website"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Drive-by Compromise", result.Attempts[0].Technique);
        Assert.Equal("T1189", result.Attempts[0].MitreTechnique);
        Assert.Equal("Web", result.Attempts[0].AccessVector);
    }

    [Fact]
    public void Detect_ExploitPublicFacing_DetectsAppExploit()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Web server compromise", "Remote code execution exploit against public-facing web server via SQL injection"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Exploit Public-Facing Application", result.Attempts[0].Technique);
        Assert.Equal("T1190", result.Attempts[0].MitreTechnique);
        Assert.Equal("Network", result.Attempts[0].AccessVector);
    }

    [Fact]
    public void Detect_ExternalRemoteServices_DetectsRDP()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Exposed RDP service", "RDP exposed to internet with brute force attempts detected"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("External Remote Services", result.Attempts[0].Technique);
        Assert.Equal("T1133", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ValidAccounts_DetectsCredentialAbuse()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Account compromise", "Stolen credential used for credential stuffing attack"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Valid Accounts", result.Attempts[0].Technique);
        Assert.Equal("T1078", result.Attempts[0].MitreTechnique);
        Assert.Equal("Credential", result.Attempts[0].AccessVector);
    }

    [Fact]
    public void Detect_DefaultAccounts_DetectsDefaultCreds()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Default credentials", "System using default password for admin account"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Default Accounts", result.Attempts[0].Technique);
        Assert.Equal("T1078.001", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_SupplyChain_DetectsCompromise()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Trojanized update", "Supply chain compromise via trojanized software update from vendor"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Supply Chain Compromise", result.Attempts[0].Technique);
        Assert.Equal("T1195", result.Attempts[0].MitreTechnique);
        Assert.Equal("Supply Chain", result.Attempts[0].AccessVector);
    }

    [Fact]
    public void Detect_TrustedRelationship_DetectsPartnerCompromise()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Third-party breach", "Managed service provider compromise leading to access via trusted relationship"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Trusted Relationship", result.Attempts[0].Technique);
        Assert.Equal("T1199", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_RemovableMedia_DetectsUSBAttack()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("USB threat", "Infected USB drive connected with autorun malware"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Replication Through Removable Media", result.Attempts[0].Technique);
        Assert.Equal("T1091", result.Attempts[0].MitreTechnique);
        Assert.Equal("Physical", result.Attempts[0].AccessVector);
    }

    [Fact]
    public void Detect_HardwareAdditions_DetectsRogueDevice()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Network intrusion", "Rogue device detected on network segment, possible hardware implant"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Hardware Additions", result.Attempts[0].Technique);
        Assert.Equal("T1200", result.Attempts[0].MitreTechnique);
    }

    // ── Tool Detection ──────────────────────────────────────────────

    [Fact]
    public void Detect_CobaltStrike_DetectsToolAndBoostsConfidence()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Phishing campaign", "Phishing attachment with cobalt strike beacon delivered via email"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.True(result.Attempts[0].IsAutomated);
        Assert.Equal("cobalt strike", result.Attempts[0].SourceTool);
        Assert.Contains(result.Attempts[0].Indicators, i => i.Contains("attack tool"));
    }

    [Fact]
    public void Detect_Metasploit_DetectsFramework()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Web exploit", "Exploit of public-facing application using metasploit framework"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("metasploit", result.Attempts[0].SourceTool);
        Assert.True(result.Attempts[0].IsAutomated);
    }

    // ── Severity Classification ─────────────────────────────────────

    [Fact]
    public void Detect_SupplyChain_IsCriticalSeverity()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Supply chain attack", "Supply chain compromise detected in vendor update mechanism"));
        var result = detector.Detect(report);

        Assert.Equal(InitialAccessSeverity.Critical, result.Attempts[0].Severity);
    }

    [Fact]
    public void Detect_ExploitPublicFacing_IsHighSeverity()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Server exploit", "SQL injection on public-facing web application"));
        var result = detector.Detect(report);

        Assert.Equal(InitialAccessSeverity.High, result.Attempts[0].Severity);
    }

    [Fact]
    public void Detect_PhishingAttachment_IsMediumSeverity()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Email attack", "Malicious attachment in phishing email"));
        var result = detector.Detect(report);

        Assert.Equal(InitialAccessSeverity.Medium, result.Attempts[0].Severity);
    }

    [Fact]
    public void Detect_RemovableMedia_IsLowSeverity()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("USB threat", "Removable media with suspicious autorun detected"));
        var result = detector.Detect(report);

        Assert.Equal(InitialAccessSeverity.Low, result.Attempts[0].Severity);
    }

    // ── Campaign Detection ──────────────────────────────────────────

    [Fact]
    public void Detect_MultipleVectors_BuildsCampaign()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("Phishing attempt", "Phishing link targeting user credentials"),
            ("Exposed service", "RDP exposed to internet with brute force attempts"),
            ("USB baiting", "Infected USB drive left in parking lot")
        );
        var result = detector.Detect(report);

        Assert.Equal(3, result.AttemptsDetected);
        Assert.True(result.Campaigns.Count >= 1);
    }

    [Fact]
    public void Detect_MultipleVectors_CampaignHasMultipleVectorCount()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("Email phishing", "Phishing attachment delivered via email campaign"),
            ("Web exploit", "Drive-by compromise via watering hole site")
        );
        var result = detector.Detect(report);

        Assert.Equal(2, result.AttemptsDetected);
        if (result.Campaigns.Count > 0)
            Assert.True(result.Campaigns[0].VectorCount >= 2);
    }

    // ── Indicator Detection ─────────────────────────────────────────

    [Fact]
    public void Detect_CampaignIndicator_FlagsMassTargeting()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Mass phishing campaign", "Widespread phishing link targeting multiple users"));
        var result = detector.Detect(report);

        Assert.Contains(result.Attempts[0].Indicators, i => i.Contains("Campaign-level"));
    }

    [Fact]
    public void Detect_PersistenceIndicator_FlagsBackdoor()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Exploit with persistence", "Drive-by compromise installed backdoor and persist mechanism"));
        var result = detector.Detect(report);

        Assert.Contains(result.Attempts[0].Indicators, i => i.Contains("Persistence"));
    }

    [Fact]
    public void Detect_LateralMovementIndicator_FlagsPivot()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Initial compromise", "Stolen credential used to pivot laterally through internal network"));
        var result = detector.Detect(report);

        Assert.Contains(result.Attempts[0].Indicators, i => i.Contains("lateral movement"));
    }

    // ── Scoring ─────────────────────────────────────────────────────

    [Fact]
    public void Detect_CriticalAttempts_HighThreatScore()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("Supply chain", "Supply chain compromise via trojanized software"),
            ("Web exploit", "Remote code execution on public-facing server via cobalt strike"),
            ("Phishing", "Malicious attachment phishing campaign")
        );
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 40);
    }

    [Fact]
    public void Detect_SingleLowSeverity_LowScore()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("USB device", "Removable media autorun detected on workstation"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore <= 20);
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Detect_Phishing_RecommendsEmailSandboxing()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Email threat", "Phishing attachment with office macro detected"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("email attachment sandboxing") || r.Contains("macro"));
    }

    [Fact]
    public void Detect_ExploitPublicFacing_RecommendsPatch()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Server exploit", "SQL injection exploit on public-facing web application"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Patch") || r.Contains("WAF"));
    }

    [Fact]
    public void Detect_ExternalRDP_RecommendsMFA()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Exposed RDP", "Exposed RDP service accessible from internet"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("MFA") || r.Contains("remote access"));
    }

    [Fact]
    public void Detect_SupplyChain_RecommendsSoftwareIntegrity()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Vendor compromise", "Supply chain compromise through compromised vendor update"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("integrity") || r.Contains("checksums"));
    }

    [Fact]
    public void Detect_DefaultAccounts_RecommendsAudit()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Weak configuration", "System using default password for administrator"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("default") || r.Contains("vendor credentials"));
    }

    // ── Statistics ───────────────────────────────────────────────────

    [Fact]
    public void Detect_MultipleFindings_ComputesCorrectStats()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("Phishing email", "Phishing attachment detected in email"),
            ("Web exploit", "Drive-by compromise via browser exploit"),
            ("USB threat", "Removable media with malware autorun")
        );
        var result = detector.Detect(report);

        Assert.Equal(3, result.Stats.TotalTechniquesUsed);
        Assert.True(result.Stats.AccessVectorsUsed >= 2);
        Assert.True(result.Stats.AverageConfidence > 0);
    }

    [Fact]
    public void Detect_AutomatedAttack_StatsReflectAutomation()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Automated phishing", "Automated phishing attachment from gophish framework"));
        var result = detector.Detect(report);

        Assert.True(result.Stats.AutomatedAttempts >= 1);
    }

    // ── Deduplication ───────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateFindings_Deduplicates()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = new SecurityReport();
        var result1 = new AuditResult { ModuleName = "Mod1", Category = "Mod1" };
        result1.Findings.Add(new Finding { Title = "Phishing attack", Description = "Phishing link detected" });
        var result2 = new AuditResult { ModuleName = "Mod2", Category = "Mod2" };
        result2.Findings.Add(new Finding { Title = "Phishing attack", Description = "Phishing link detected" });
        report.Results.Add(result1);
        report.Results.Add(result2);

        var iaReport = detector.Detect(report);
        Assert.Equal(1, iaReport.AttemptsDetected);
    }

    // ── Threat Level Classification ─────────────────────────────────

    [Fact]
    public void ThreatLevel_MinimalForZero()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    // ── Asset Extraction ────────────────────────────────────────────

    [Fact]
    public void Detect_AssetInDescription_ExtractsTarget()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("RDP exploit", "Exposed RDP on host:webserver01 accessible from internet"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.NotNull(result.Attempts[0].TargetAsset);
        Assert.Equal("webserver01", result.Attempts[0].TargetAsset);
    }

    // ── General Phishing Detection ──────────────────────────────────

    [Fact]
    public void Detect_BEC_DetectsGenericPhishing()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("BEC attempt", "Business email compromise targeting finance department"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Phishing General", result.Attempts[0].Technique);
        Assert.Equal("T1566", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ZeroDay_DetectsPublicFacingExploit()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Critical vulnerability", "Zero-day exploit targeting public-facing application server"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Exploit Public-Facing Application", result.Attempts[0].Technique);
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    [Fact]
    public void Detect_CaseInsensitive_MatchesUpperCase()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("PHISHING ATTACHMENT", "MALICIOUS ATTACHMENT DETECTED IN EMAIL"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
    }

    [Fact]
    public void Detect_EmptyFindings_HandlesGracefully()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = new SecurityReport();
        report.Results.Add(new AuditResult { ModuleName = "Empty", Category = "Empty" });
        var result = detector.Detect(report);

        Assert.Equal(0, result.AttemptsDetected);
    }

    [Fact]
    public void Detect_AlwaysIncludesGeneralRecommendation()
    {
        var detector = new InitialAccessDetector(CreateHistory());
        var report = MakeReport(("Phishing", "Phishing link detected"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Event Forwarding") || r.Contains("perimeter"));
    }
}
