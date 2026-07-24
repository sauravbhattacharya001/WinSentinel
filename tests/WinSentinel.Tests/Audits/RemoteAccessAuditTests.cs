using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.RemoteAccessAudit;

namespace WinSentinel.Tests.Audits;

public class RemoteAccessAuditTests
{
    private readonly RemoteAccessAudit _audit;

    public RemoteAccessAuditTests()
    {
        _audit = new RemoteAccessAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Remote Access Security Audit",
        Category = "Remote Access"
    };

    private static RemoteAccessState MakeSecureState() => new()
    {
        RdpEnabled = false,
        SshServerInstalled = false,
        SshServerRunning = false,
        RunningRemoteTools = new(),
        InstalledRemoteTools = new(),
        WinRmRunning = false,
        RemoteRegistryRunning = false,
        RemoteRegistryStartType = "Disabled",
        RemoteAssistanceEnabled = false,
        TelnetServerRunning = false,
    };

    private static RemoteAccessState MakeInsecureState() => new()
    {
        RdpEnabled = true,
        RdpNlaEnabled = false,
        RdpPort = 3389,
        RdpEncryptionLevel = 1,
        RdpSecurityLayer = 0,
        RdpIdleTimeoutConfigured = false,
        RdpSingleSessionPerUser = false,
        RemoteDesktopUsers = new() { "DOMAIN\\User1", "DOMAIN\\User2", "DOMAIN\\User3",
            "DOMAIN\\User4", "DOMAIN\\User5", "DOMAIN\\User6" },
        SshServerInstalled = true,
        SshServerRunning = true,
        SshPort = 22,
        SshPasswordAuthEnabled = true,
        SshRootLoginEnabled = true,
        RunningRemoteTools = new() { "tvnserver", "ammyy_admin", "TeamViewer" },
        InstalledRemoteTools = new() { "tvnserver", "ammyy_admin", "TeamViewer", "AnyDesk" },
        WinRmRunning = true,
        WinRmAllowUnencrypted = true,
        WinRmBasicAuthEnabled = true,
        WinRmHttpListenerEnabled = true,
        WinRmHttpsListenerEnabled = false,
        RemoteRegistryRunning = true,
        RemoteRegistryStartType = "Automatic",
        RemoteAssistanceEnabled = true,
        TelnetServerRunning = true,
    };

    // --- Module metadata ---

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("Remote Access Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsExpected()
    {
        Assert.Equal("Remote Access", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // --- Secure state ---

    [Fact]
    public void SecureState_AllPass()
    {
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(MakeSecureState(), result);
        Assert.True(result.Findings.Count > 0);
        Assert.All(result.Findings, f => Assert.True(f.Severity <= Severity.Info,
            $"Expected Pass/Info but got {f.Severity}: {f.Title}"));
        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.WarningCount);
    }

    [Fact]
    public void InsecureState_HasCriticalFindings()
    {
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(MakeInsecureState(), result);
        Assert.True(result.CriticalCount > 0);
        Assert.True(result.WarningCount > 0);
    }

    // --- RDP checks ---

    [Fact]
    public void RdpDisabled_PassFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "RDP Disabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RdpEnabled_WarningFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        state.RdpIdleTimeoutMinutes = 15;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "RDP Enabled" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpNlaDisabled_CriticalFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = false;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Network Level Authentication Disabled") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void RdpNlaEnabled_PassFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("NLA Enabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RdpDefaultPort_InfoFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpPort = 3389;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Default Port") && f.Severity == Severity.Info);
    }

    [Fact]
    public void SshTcpForwardingEnabled_WarningFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshTcpForwardingEnabled = true;
        state.SshGatewayPortsEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("TCP Port Forwarding Enabled") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void SshTcpForwardingDisabled_PassFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshTcpForwardingEnabled = false;
        state.SshGatewayPortsEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("TCP Port Forwarding Disabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void SshGatewayPortsEnabled_WarningFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshTcpForwardingEnabled = false;
        state.SshGatewayPortsEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("GatewayPorts Enabled") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void SshGatewayPortsDisabled_NoGatewayFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshTcpForwardingEnabled = false;
        state.SshGatewayPortsEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("GatewayPorts"));
    }

    [Fact]
    public void RdpWeakEncryption_WarningFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 1;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Weak Encryption") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpStrongEncryption_PassFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 4;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Strong Encryption") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RdpNativeSecurityLayer_WarningFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 0;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Native RDP Security") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpTlsSecurityLayer_PassFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("TLS Security Layer") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RdpNoIdleTimeout_WarningFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No Idle Timeout") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpIdleTimeoutConfigured_PassFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        state.RdpIdleTimeoutMinutes = 30;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Idle Timeout Configured") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RdpMultipleSessionsAllowed_InfoFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        state.RdpSingleSessionPerUser = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Multiple Sessions") && f.Severity == Severity.Info);
    }

    [Fact]
    public void RdpLargeUserGroup_WarningFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        state.RemoteDesktopUsers = Enumerable.Range(1, 8).Select(i => $"User{i}").ToList();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Large Remote Desktop Users") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpSmallUserGroup_InfoFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        state.RemoteDesktopUsers = new() { "Admin" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Remote Desktop Users") && f.Severity == Severity.Info);
    }

    // --- RDP device redirection (drive / clipboard) ---

    // A fully-hardened RDP baseline so the ONLY thing under test is the redirection setting.
    private static RemoteAccessState RdpSecureBaseline()
    {
        var s = MakeSecureState();
        s.RdpEnabled = true;
        s.RdpNlaEnabled = true;
        s.RdpEncryptionLevel = 3;
        s.RdpSecurityLayer = 2;
        s.RdpIdleTimeoutConfigured = true;
        s.RdpSingleSessionPerUser = true;
        return s;
    }

    [Fact]
    public void RdpDriveRedirectionAllowed_WarningFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpDriveRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Drive Redirection Allowed") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpDriveRedirectionAllowed_HasFixCommand()
    {
        var state = RdpSecureBaseline();
        state.RdpDriveRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Drive Redirection Allowed"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("fDisableCdm", finding.FixCommand);
    }

    [Fact]
    public void RdpDriveRedirectionDisabled_PassFinding()
    {
        var state = RdpSecureBaseline(); // redirection flags default false = disabled
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Drive Redirection Disabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RdpClipboardRedirectionAllowed_InfoFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpClipboardRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Clipboard Redirection Allowed") && f.Severity == Severity.Info);
    }

    [Fact]
    public void RdpClipboardRedirectionAllowed_HasFixCommand()
    {
        var state = RdpSecureBaseline();
        state.RdpClipboardRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Clipboard Redirection Allowed"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("fDisableClip", finding.FixCommand);
    }

    [Fact]
    public void RdpClipboardRedirectionDisabled_NoFinding()
    {
        var state = RdpSecureBaseline(); // clipboard flag default false = disabled
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Clipboard Redirection Allowed"));
    }

    [Fact]
    public void RdpPrinterRedirectionAllowed_InfoFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpPrinterRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Printer Redirection Allowed") && f.Severity == Severity.Info);
    }

    [Fact]
    public void RdpPrinterRedirectionAllowed_HasFixCommand()
    {
        var state = RdpSecureBaseline();
        state.RdpPrinterRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Printer Redirection Allowed"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("fDisableCpm", finding.FixCommand);
    }

    [Fact]
    public void RdpPrinterRedirectionDisabled_NoFinding()
    {
        var state = RdpSecureBaseline(); // printer flag default false = disabled
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Printer Redirection Allowed"));
    }

    [Fact]
    public void RdpPortRedirectionAllowed_InfoFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpPortRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Port Redirection Allowed") && f.Severity == Severity.Info);
    }

    [Fact]
    public void RdpPortRedirectionAllowed_HasFixCommand()
    {
        var state = RdpSecureBaseline();
        state.RdpPortRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Port Redirection Allowed"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("fDisableLPT", finding.FixCommand);
    }

    [Fact]
    public void RdpPortRedirectionDisabled_NoFinding()
    {
        var state = RdpSecureBaseline(); // port flag default false = disabled
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Port Redirection Allowed"));
    }

    [Fact]
    public void RdpPnpRedirectionAllowed_InfoFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpPnpRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Plug-and-Play Device Redirection Allowed") && f.Severity == Severity.Info);
    }

    [Fact]
    public void RdpPnpRedirectionAllowed_HasFixCommand()
    {
        var state = RdpSecureBaseline();
        state.RdpPnpRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Plug-and-Play Device Redirection Allowed"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("fDisablePNPRedir", finding.FixCommand);
    }

    [Fact]
    public void RdpPnpRedirectionDisabled_NoFinding()
    {
        var state = RdpSecureBaseline(); // PnP flag default false = disabled
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Plug-and-Play Device Redirection Allowed"));
    }

    [Fact]
    public void RdpRedirection_NotEvaluatedWhenRdpDisabled()
    {
        // Redirection findings live inside the RDP-enabled branch; with RDP off they must not fire
        // even if the (stale) redirection flags say "allowed". This keeps a non-RDP host clean.
        var state = MakeSecureState();
        state.RdpEnabled = false;
        state.RdpDriveRedirectionAllowed = true;
        state.RdpClipboardRedirectionAllowed = true;
        state.RdpPrinterRedirectionAllowed = true;
        state.RdpPortRedirectionAllowed = true;
        state.RdpPnpRedirectionAllowed = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Redirection"));
    }

    // --- RDP session shadowing (Shadow policy) ---

    [Fact]
    public void RdpShadowFullControlNoConsent_WarningFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpShadowConfigured = true;
        state.RdpShadowMode = 2; // full control WITHOUT consent
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title == "RDP: Session Shadowing Without User Consent" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpShadowViewNoConsent_WarningFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpShadowConfigured = true;
        state.RdpShadowMode = 4; // view WITHOUT consent
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title == "RDP: Session Shadowing Without User Consent" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpShadowNoConsent_HasFixCommand()
    {
        var state = RdpSecureBaseline();
        state.RdpShadowConfigured = true;
        state.RdpShadowMode = 2;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.Single(f => f.Title == "RDP: Session Shadowing Without User Consent");
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("Shadow", finding.FixCommand);
    }

    [Fact]
    public void RdpShadowDisabled_PassFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpShadowConfigured = true;
        state.RdpShadowMode = 0; // no remote control
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title == "RDP: Session Shadowing Requires Consent" && f.Severity == Severity.Pass);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Without User Consent"));
    }

    [Fact]
    public void RdpShadowWithConsent_PassFinding()
    {
        var state = RdpSecureBaseline();
        state.RdpShadowConfigured = true;
        state.RdpShadowMode = 1; // full control WITH consent
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title == "RDP: Session Shadowing Requires Consent" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RdpShadowUnconfigured_NoShadowFinding()
    {
        // Policy absent => OS default; we raise no shadow-specific finding at all.
        var state = RdpSecureBaseline();
        state.RdpShadowConfigured = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Session Shadowing"));
    }

    [Fact]
    public void RdpShadow_NotEvaluatedWhenRdpDisabled()
    {
        // Shadowing lives inside the RDP-enabled branch; with RDP off a no-consent mode must not fire.
        var state = MakeSecureState();
        state.RdpEnabled = false;
        state.RdpShadowConfigured = true;
        state.RdpShadowMode = 2;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Session Shadowing"));
    }

    // --- RDP always-prompt-for-password (fPromptForPassword policy) ---

    [Fact]
    public void RdpPromptForPasswordDisabled_WarningFinding()
    {
        // Policy explicitly 0 => saved/delegated creds open a session with no prompt.
        var state = RdpSecureBaseline();
        state.RdpPromptForPasswordConfigured = true;
        state.RdpAlwaysPromptForPassword = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title == "RDP: Password Prompt On Connect Disabled" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpPromptForPasswordDisabled_HasFixCommand()
    {
        var state = RdpSecureBaseline();
        state.RdpPromptForPasswordConfigured = true;
        state.RdpAlwaysPromptForPassword = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.Single(f => f.Title == "RDP: Password Prompt On Connect Disabled");
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.Contains("fPromptForPassword", finding.FixCommand);
    }

    [Fact]
    public void RdpPromptForPasswordEnabled_PassFinding()
    {
        // Policy explicitly 1 => a password is required on every connection.
        var state = RdpSecureBaseline();
        state.RdpPromptForPasswordConfigured = true;
        state.RdpAlwaysPromptForPassword = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title == "RDP: Password Prompt On Connect Required" && f.Severity == Severity.Pass);
        Assert.DoesNotContain(result.Findings, f => f.Title == "RDP: Password Prompt On Connect Disabled");
    }

    [Fact]
    public void RdpPromptForPasswordUnconfigured_NoFinding()
    {
        // Policy absent => OS default; no prompt-for-password finding of either polarity.
        var state = RdpSecureBaseline();
        state.RdpPromptForPasswordConfigured = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Password Prompt On Connect"));
    }

    [Fact]
    public void RdpPromptForPassword_NotEvaluatedWhenRdpDisabled()
    {
        // The check lives inside the RDP-enabled branch; with RDP off, a disabled policy must not fire.
        var state = MakeSecureState();
        state.RdpEnabled = false;
        state.RdpPromptForPasswordConfigured = true;
        state.RdpAlwaysPromptForPassword = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Password Prompt On Connect"));
    }

    // --- SSH checks ---

    [Fact]
    public void SshNotInstalled_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("SSH Server Not Installed") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void SshInstalledNotRunning_InfoFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Installed but Not Running") && f.Severity == Severity.Info);
    }

    [Fact]
    public void SshRunning_InfoFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshPasswordAuthEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "SSH Server Running" && f.Severity == Severity.Info);
    }

    [Fact]
    public void SshPasswordAuth_WarningFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshPasswordAuthEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Password Authentication Enabled") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void SshPasswordAuthDisabled_PassFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshPasswordAuthEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Password Authentication Disabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void SshRootLogin_CriticalFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshRootLoginEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Root/Admin Login") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void SshDefaultPort_InfoFinding()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshPort = 22;
        state.SshPasswordAuthEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Default Port (22)") && f.Severity == Severity.Info);
    }

    // --- Remote tools ---

    [Fact]
    public void NoRemoteTools_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No Third-Party Remote Tools") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void HighRiskToolRunning_CriticalFinding()
    {
        var state = MakeSecureState();
        state.RunningRemoteTools = new() { "ammyy_admin" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Ammyy Admin") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void MediumRiskToolRunning_WarningFinding()
    {
        var state = MakeSecureState();
        state.RunningRemoteTools = new() { "TeamViewer" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("TeamViewer") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void LowRiskToolRunning_InfoFinding()
    {
        var state = MakeSecureState();
        state.RunningRemoteTools = new() { "rustdesk" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("RustDesk") && f.Severity == Severity.Info);
    }

    [Fact]
    public void InstalledButNotRunning_InfoFinding()
    {
        var state = MakeSecureState();
        state.InstalledRemoteTools = new() { "AnyDesk" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Installed (Not Running)") && f.Severity == Severity.Info);
    }

    [Fact]
    public void MultipleToolsRunning_WarningFinding()
    {
        var state = MakeSecureState();
        state.RunningRemoteTools = new() { "TeamViewer", "AnyDesk", "rustdesk" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Multiple Remote Access Tools") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void UnknownRemoteTool_InfoFinding()
    {
        var state = MakeSecureState();
        state.RunningRemoteTools = new() { "mysterytool" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Unknown Remote Tool") && f.Severity == Severity.Info);
    }

    // --- WinRM checks ---

    [Fact]
    public void WinRmNotRunning_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("WinRM Not Running") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void WinRmRunning_InfoFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "WinRM Running" && f.Severity == Severity.Info);
    }

    [Fact]
    public void WinRmUnencrypted_CriticalFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmAllowUnencrypted = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Unencrypted Traffic") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void WinRmEncrypted_PassFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmAllowUnencrypted = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Encrypted Traffic Required") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void WinRmBasicAuth_WarningFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmBasicAuthEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Basic Authentication") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WinRmHttpOnly_WarningFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmHttpListenerEnabled = true;
        state.WinRmHttpsListenerEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("HTTP-Only") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WinRmHttpsConfigured_PassFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmHttpsListenerEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("HTTPS Listener") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void WinRmListenerUnrestricted_WarningFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmHttpListenerEnabled = true;
        state.WinRmListenerUnrestricted = true;
        state.WinRmListenerIpv4Filter = "*";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Accepts Connections From Any IP") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WinRmListenerScopedFilter_NoUnrestrictedFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmHttpsListenerEnabled = true;
        state.WinRmListenerUnrestricted = false;            // scoped, e.g. "10.0.0.0-10.0.0.255"
        state.WinRmListenerIpv4Filter = "10.0.0.0-10.0.0.255";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Accepts Connections From Any IP"));
    }

    [Fact]
    public void WinRmListenerUnrestrictedButNoListener_NoFinding()
    {
        // Filter parsed as unrestricted but no listener actually enabled => no exposure, no finding.
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmHttpListenerEnabled = false;
        state.WinRmHttpsListenerEnabled = false;
        state.WinRmListenerUnrestricted = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Accepts Connections From Any IP"));
    }

    // --- Remote Registry ---

    [Fact]
    public void RemoteRegistryRunning_WarningFinding()
    {
        var state = MakeSecureState();
        state.RemoteRegistryRunning = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Remote Registry Service Running") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RemoteRegistryManual_InfoFinding()
    {
        var state = MakeSecureState();
        state.RemoteRegistryRunning = false;
        state.RemoteRegistryStartType = "Manual";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Remote Registry Not Disabled") && f.Severity == Severity.Info);
    }

    [Fact]
    public void RemoteRegistryDisabled_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Remote Registry Disabled") && f.Severity == Severity.Pass);
    }

    // --- Remote Assistance ---

    [Fact]
    public void RemoteAssistanceEnabled_InfoFinding()
    {
        var state = MakeSecureState();
        state.RemoteAssistanceEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Remote Assistance Enabled") && f.Severity == Severity.Info);
    }

    [Fact]
    public void RemoteAssistanceDisabled_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Remote Assistance Disabled") && f.Severity == Severity.Pass);
    }

    // --- Unsolicited Remote Assistance ("Offer Remote Assistance") ---

    [Fact]
    public void RemoteAssistanceUnsolicited_WarningFinding()
    {
        var state = MakeSecureState();
        state.RemoteAssistanceUnsolicitedEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Unsolicited Offers Allowed") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RemoteAssistanceUnsolicited_HasFixCommand()
    {
        var state = MakeSecureState();
        state.RemoteAssistanceUnsolicitedEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Unsolicited Offers Allowed"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void RemoteAssistanceUnsolicitedFullControl_MentionedInMessage()
    {
        var state = MakeSecureState();
        state.RemoteAssistanceUnsolicitedEnabled = true;
        state.RemoteAssistanceUnsolicitedFullControl = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Unsolicited Offers Allowed"));
        Assert.Contains("full control", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RemoteAssistanceUnsolicitedViewOnly_MentionedInMessage()
    {
        var state = MakeSecureState();
        state.RemoteAssistanceUnsolicitedEnabled = true;
        state.RemoteAssistanceUnsolicitedFullControl = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Unsolicited Offers Allowed"));
        Assert.Contains("view-only", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RemoteAssistanceUnsolicitedDisabled_NoFinding()
    {
        var state = MakeSecureState(); // unsolicited flags default false
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Unsolicited Offers Allowed"));
    }

    [Fact]
    public void RemoteAssistanceUnsolicited_IndependentOfSolicited()
    {
        // Unsolicited can be enabled even when solicited "Ask for Help" (fAllowToGetHelp) is off;
        // the two findings are evaluated independently.
        var state = MakeSecureState();
        state.RemoteAssistanceEnabled = false;
        state.RemoteAssistanceUnsolicitedEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Remote Assistance Disabled") && f.Severity == Severity.Pass);
        Assert.Contains(result.Findings, f => f.Title.Contains("Unsolicited Offers Allowed") && f.Severity == Severity.Warning);
    }

    // --- Telnet ---

    [Fact]
    public void TelnetRunning_CriticalFinding()
    {
        var state = MakeSecureState();
        state.TelnetServerRunning = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Telnet Server Running") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void TelnetNotRunning_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Telnet Server Not Running") && f.Severity == Severity.Pass);
    }

    // --- Overall exposure ---

    [Fact]
    public void NoRemoteVectors_MinimalExposure()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Minimal Remote Access Exposure") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void SingleVector_InfoFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Single Remote Access Vector") && f.Severity == Severity.Info);
    }

    [Fact]
    public void TwoVectors_WarningFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        state.WinRmRunning = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Multiple Remote Access Vectors") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void FourPlusVectors_CriticalFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        state.SshServerRunning = true;
        state.SshServerInstalled = true;
        state.SshPasswordAuthEnabled = false;
        state.WinRmRunning = true;
        state.RemoteRegistryRunning = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Excessive Remote Access Exposure") && f.Severity == Severity.Critical);
    }

    // --- Static data ---

    [Fact]
    public void KnownRemoteTools_ContainsExpectedTools()
    {
        Assert.True(KnownRemoteTools.ContainsKey("TeamViewer"));
        Assert.True(KnownRemoteTools.ContainsKey("AnyDesk"));
        Assert.True(KnownRemoteTools.ContainsKey("tvnserver"));
        Assert.True(KnownRemoteTools.ContainsKey("ammyy_admin"));
        Assert.True(KnownRemoteTools.ContainsKey("sshd"));
        Assert.True(KnownRemoteTools.ContainsKey("rustdesk"));
    }

    [Fact]
    public void DefaultPorts_ContainsExpected()
    {
        Assert.Equal(3389, DefaultPorts["RDP"]);
        Assert.Equal(22, DefaultPorts["SSH"]);
        Assert.Equal(5900, DefaultPorts["VNC"]);
        Assert.Equal(23, DefaultPorts["Telnet"]);
    }

    [Fact]
    public void TotalRemoteVectors_CalculatesCorrectly()
    {
        var state = new RemoteAccessState
        {
            RdpEnabled = true,
            SshServerRunning = true,
            RunningRemoteTools = new() { "TeamViewer" },
            WinRmRunning = true,
            RemoteRegistryRunning = false,
            TelnetServerRunning = true,
        };
        Assert.Equal(5, state.TotalRemoteVectors);
    }

    [Fact]
    public void TotalRemoteVectors_ZeroWhenAllDisabled()
    {
        var state = MakeSecureState();
        Assert.Equal(0, state.TotalRemoteVectors);
    }

    // --- VNC high risk ---

    [Fact]
    public void VncRunning_CriticalFinding()
    {
        var state = MakeSecureState();
        state.RunningRemoteTools = new() { "tvnserver" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("TightVNC") && f.Severity == Severity.Critical);
    }

    // --- Remediation commands present ---

    [Fact]
    public void RdpNlaDisabled_HasFixCommand()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = false;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var nlaFinding = result.Findings.First(f => f.Title.Contains("Network Level Authentication Disabled"));
        Assert.False(string.IsNullOrWhiteSpace(nlaFinding.FixCommand));
    }

    [Fact]
    public void RemoteRegistryRunning_HasFixCommand()
    {
        var state = MakeSecureState();
        state.RemoteRegistryRunning = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Remote Registry Service Running"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void TelnetRunning_HasFixCommand()
    {
        var state = MakeSecureState();
        state.TelnetServerRunning = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Telnet Server Running"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    // --- Edge cases ---

    [Fact]
    public void RdpEncryptionLevel2_WarningFinding()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 2;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Weak Encryption") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RdpSecurityLayerNegotiate_NoWarning()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 1; // Negotiate
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        // Negotiate (1) doesn't trigger the native RDP layer warning nor the TLS pass
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Native RDP Security"));
    }

    [Fact]
    public void SshCustomPort_NoDefaultPortInfo()
    {
        var state = MakeSecureState();
        state.SshServerInstalled = true;
        state.SshServerRunning = true;
        state.SshPort = 2222;
        state.SshPasswordAuthEnabled = false;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Default Port (22)"));
    }

    [Fact]
    public void RdpCustomPort_NoDefaultPortInfo()
    {
        var state = MakeSecureState();
        state.RdpEnabled = true;
        state.RdpNlaEnabled = true;
        state.RdpPort = 13389;
        state.RdpEncryptionLevel = 3;
        state.RdpSecurityLayer = 2;
        state.RdpIdleTimeoutConfigured = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Default Port"));
    }

    [Fact]
    public void InstalledToolAlsoRunning_NotDuplicated()
    {
        var state = MakeSecureState();
        state.RunningRemoteTools = new() { "TeamViewer" };
        state.InstalledRemoteTools = new() { "TeamViewer", "AnyDesk" };
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        // TeamViewer should appear only as running, not also as installed-not-running
        var tvFindings = result.Findings.Where(f => f.Title.Contains("TeamViewer")).ToList();
        Assert.Single(tvFindings);
        // AnyDesk should appear as installed-not-running
        Assert.Contains(result.Findings, f => f.Title.Contains("AnyDesk") && f.Title.Contains("Not Running"));
    }

    [Fact]
    public void RemoteAssistanceEnabled_HasRemediation()
    {
        var state = MakeSecureState();
        state.RemoteAssistanceEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Remote Assistance Enabled"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void WinRmUnencrypted_HasRemediation()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmAllowUnencrypted = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Unencrypted Traffic"));
        Assert.False(string.IsNullOrWhiteSpace(finding.Remediation));
    }

    // --- WinRM CredSSP + TrustedHosts ---

    [Fact]
    public void WinRmServiceCredSsp_WarningFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmServiceCredSspEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("CredSSP Authentication Accepted (Service)") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WinRmClientCredSsp_WarningFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmClientCredSspEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("CredSSP Authentication Enabled (Client)") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WinRmServiceCredSsp_HasRemediation()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmServiceCredSspEnabled = true;
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("CredSSP Authentication Accepted (Service)"));
        Assert.False(string.IsNullOrWhiteSpace(finding.Remediation));
    }

    [Fact]
    public void WinRmCredSsp_NotFlaggedWhenDisabled()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true; // running but no CredSSP
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("CredSSP"));
    }

    [Fact]
    public void WinRmCredSsp_NotEvaluatedWhenWinRmStopped()
    {
        // CredSSP/TrustedHosts checks live inside the WinRM-running branch; if WinRM is not
        // running they should never fire even if the (stale) state flags are set.
        var state = MakeSecureState();
        state.WinRmRunning = false;
        state.WinRmServiceCredSspEnabled = true;
        state.WinRmClientCredSspEnabled = true;
        state.WinRmTrustedHosts = "*";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("CredSSP") || f.Title.Contains("TrustedHosts"));
    }

    // --- WinRM channel binding (CbtHardeningLevel) ---

    [Fact]
    public void WinRmCbtHardeningNone_WarningFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmCbtHardeningLevel = "None";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Channel Binding Disabled") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WinRmCbtHardeningNone_HasRemediation()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmCbtHardeningLevel = "none"; // case-insensitive
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("Channel Binding Disabled"));
        Assert.False(string.IsNullOrWhiteSpace(finding.Remediation));
    }

    [Fact]
    public void WinRmCbtHardeningStrict_PassFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmCbtHardeningLevel = "Strict";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Channel Binding Enforced") && f.Severity == Severity.Pass);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Channel Binding Disabled"));
    }

    [Fact]
    public void WinRmCbtHardeningRelaxed_NoFinding()
    {
        // "Relaxed" is the OS default; it is neither flagged as a gap nor asserted as a hardened pass.
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmCbtHardeningLevel = "Relaxed";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Channel Binding"));
    }

    [Fact]
    public void WinRmCbtHardeningNone_NotEvaluatedWhenWinRmStopped()
    {
        // The CbtHardeningLevel check lives inside the WinRM-running branch; a stale None value
        // on a stopped service must not raise a finding.
        var state = MakeSecureState();
        state.WinRmRunning = false;
        state.WinRmCbtHardeningLevel = "None";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Channel Binding"));
    }

    [Fact]
    public void WinRmTrustedHostsWildcard_WarningFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmTrustedHosts = "*";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("TrustedHosts Set to Wildcard") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WinRmTrustedHostsScoped_InfoFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmTrustedHosts = "server01,server02";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings,
            f => f.Title.Contains("TrustedHosts Configured") && f.Severity == Severity.Info);
    }

    [Fact]
    public void WinRmTrustedHostsEmpty_NoFinding()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmTrustedHosts = "";
        var result = MakeResult();
        RemoteAccessAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("TrustedHosts"));
    }
}
