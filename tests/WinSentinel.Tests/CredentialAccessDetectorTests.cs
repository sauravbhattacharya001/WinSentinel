using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class CredentialAccessDetectorTests
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
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.AttemptsDetected);
        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Attempts);
        Assert.Empty(result.Chains);
    }

    [Fact]
    public void Detect_NoCredentialFindings_ReturnsZeroAttempts()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Firewall enabled", "Windows firewall is active"));
        var result = detector.Detect(report);

        Assert.Equal(0, result.AttemptsDetected);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    // ── Technique Detection ─────────────────────────────────────────

    [Fact]
    public void Detect_LsassKeyword_DetectsMemoryDump()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("LSASS memory access", "Process lsass.exe memory was accessed by suspicious process"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("LSASS Memory Dump", result.Attempts[0].Technique);
        Assert.Equal("T1003.001", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_Mimikatz_DetectsWithToolReference()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Credential dumping", "mimikatz was detected accessing lsass.exe"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.True(result.Attempts[0].IsAutomated);
        Assert.Equal("mimikatz", result.Attempts[0].SourceTool);
        Assert.Contains(result.Attempts[0].Indicators, i => i.Contains("credential theft tool"));
    }

    [Fact]
    public void Detect_SamDatabase_DetectsAccess()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Registry export", "reg save HKLM\\SAM database to file"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("SAM Database Access", result.Attempts[0].Technique);
        Assert.Equal("T1003.002", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_NtdsDit_DetectsDomainCredentialExtraction()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("NTDS extraction", "ntdsutil snapshot of ntds.dit for domain credential dump"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("NTDS.dit Extraction", result.Attempts[0].Technique);
        Assert.Equal("T1003.003", result.Attempts[0].MitreTechnique);
        Assert.Equal(CredAccessSeverity.Critical, result.Attempts[0].Severity);
    }

    [Fact]
    public void Detect_Kerberoasting_DetectsServiceTicketAttack()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Kerberos attack", "Invoke-Kerberoast SPN scan detected requesting service ticket"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Kerberoasting", result.Attempts[0].Technique);
        Assert.Equal("T1558.003", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_BruteForce_DetectsFailedLogons()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Authentication failure", "Multiple failed logon attempts detected, account lockout triggered, event 4625"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Brute Force", result.Attempts[0].Technique);
        Assert.Equal("T1110", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_PasswordSpraying_DetectsDistributedAttack()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Distributed auth failure", "Password spray attack with single password against multiple accounts"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Password Spraying", result.Attempts[0].Technique);
        Assert.Equal("T1110.003", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_BrowserPasswords_DetectsCredentialStoreAccess()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Browser credential access", "Process accessed chrome login data credential store"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Credentials from Password Stores", result.Attempts[0].Technique);
        Assert.Equal("T1555", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_Keylogging_DetectsInputCapture()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Input monitoring", "Keylogging hook installed via SetWindowsHookEx for keystroke capture"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Keylogging", result.Attempts[0].Technique);
        Assert.Equal("T1056.001", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_CredentialsInFiles_DetectsPlaintextPasswords()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Config scan", "Found hardcoded password in .env file with credentials in plain text"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Credentials In Files", result.Attempts[0].Technique);
        Assert.Equal("T1552.001", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_MitmAttack_DetectsNetworkCredentialTheft()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Network attack", "LLMNR responder detected performing NTLM relay attack on network"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Adversary-in-the-Middle", result.Attempts[0].Technique);
        Assert.Equal("T1557", result.Attempts[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ForcedAuthentication_DetectsNtlmCapture()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Auth capture", "SCF file placed for forced auth to capture NTLM hashes via URL file over SMB"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("Forced Authentication", result.Attempts[0].Technique);
        Assert.Equal("T1187", result.Attempts[0].MitreTechnique);
    }

    // ── Severity Classification ─────────────────────────────────────

    [Fact]
    public void Detect_DomainCredentials_CriticalSeverity()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("DCSync detected", "ntds.dit extraction via dcsync domain replication"));
        var result = detector.Detect(report);

        Assert.True(result.Attempts.All(a => a.Severity == CredAccessSeverity.Critical));
    }

    [Fact]
    public void Detect_LsassWithTool_CriticalSeverity()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Credential dump", "mimikatz sekurlsa::logonpasswords on lsass"));
        var result = detector.Detect(report);

        Assert.Equal(CredAccessSeverity.Critical, result.Attempts[0].Severity);
    }

    [Fact]
    public void Detect_BruteForce_LowSeverity()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Failed logins", "Brute force login attempt detected event 4625"));
        var result = detector.Detect(report);

        Assert.Equal(CredAccessSeverity.Low, result.Attempts[0].Severity);
    }

    // ── Chain Detection ─────────────────────────────────────────────

    [Fact]
    public void Detect_MultipleAttempts_BuildsChain()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("Credential scan", "Brute force failed logon for user: admin account lockout"),
            ("LSASS dump", "mimikatz accessed lsass.exe memory for user: admin"),
            ("Domain dump", "dcsync ntds.dit extraction targeting user: admin domain replication")
        );
        var result = detector.Detect(report);

        Assert.True(result.AttemptsDetected >= 2);
    }

    [Fact]
    public void Detect_MultipleTechniques_IncreasesScore()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("LSASS access", "Process accessed lsass.exe memory"),
            ("Kerberos attack", "Kerberoast SPN scan for service ticket"),
            ("Password spray", "Password spray attack against multiple accounts")
        );
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore > 20);
        Assert.True(result.Stats.TotalTechniquesUsed >= 3);
    }

    // ── Scoring ─────────────────────────────────────────────────────

    [Fact]
    public void Detect_CriticalFinding_HighThreatScore()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Domain dump", "ntds.dit DCSync domain replication attack using mimikatz"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 40);
        Assert.NotEqual("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void Detect_KnownTool_BoostsScore()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Tool detected", "mimikatz process accessing lsass.exe"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 30);
    }

    // ── Statistics ──────────────────────────────────────────────────

    [Fact]
    public void Stats_CorrectCounts()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("LSASS dump", "Process accessed lsass memory"),
            ("Browser creds", "Chrome login data credential store access")
        );
        var result = detector.Detect(report);

        Assert.True(result.Stats.TotalTechniquesUsed >= 1);
    }

    [Fact]
    public void Stats_AutomatedDetection()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Automated dump", "PowerShell script accessing lsass memory with mimikatz framework"));
        var result = detector.Detect(report);

        Assert.True(result.Stats.AutomatedAttempts >= 1);
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Recommendations_LsassDetected_RecommendsCredentialGuard()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("LSASS access", "Process lsass.exe memory accessed"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Credential Guard"));
    }

    [Fact]
    public void Recommendations_Kerberoasting_RecommendsStrongPasswords()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("Kerberos attack", "Kerberoast service ticket attack with SPN scan"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("service account") || r.Contains("gMSA"));
    }

    [Fact]
    public void Recommendations_EmptyReport_SuggestsContinueMonitoring()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Continue monitoring"));
    }

    // ── Deduplication ───────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateFindings_Deduplicated()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(
            ("LSASS dump detected", "Process accessed lsass.exe memory"),
            ("LSASS dump detected", "Process accessed lsass.exe memory")
        );
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
    }

    // ── Threat Level Classification ─────────────────────────────────

    [Fact]
    public void ThreatLevel_NoFindings_Minimal()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void Detect_DomainIndicator_FlaggedInIndicators()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("AD attack", "LSASS access targeting active directory domain credentials"));
        var result = detector.Detect(report);

        Assert.Contains(result.Attempts[0].Indicators, i => i.Contains("Domain-level"));
    }

    [Fact]
    public void Detect_LsaSecrets_DetectsServiceCredentials()
    {
        var detector = new CredentialAccessDetector(CreateHistory());
        var report = MakeReport(("LSA dump", "lsadump of lsa secret for service account dpapi"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.AttemptsDetected);
        Assert.Equal("LSA Secrets", result.Attempts[0].Technique);
        Assert.Equal("T1003.004", result.Attempts[0].MitreTechnique);
    }
}
