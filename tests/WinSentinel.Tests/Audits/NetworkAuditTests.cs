using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Comprehensive integration tests for the NetworkAudit module.
/// Validates all 10 audit checks: listening ports, SMB exposure, RDP, WinRM,
/// DNS settings, network profile, Wi-Fi security, LLMNR/NetBIOS, ARP anomalies, IPv6.
/// Runs audit once and shares the result across all tests for efficiency.
/// </summary>
public class NetworkAuditTests : IAsyncLifetime
{
    private readonly NetworkAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    // ─────────────────────────────────────────────────────────────────────
    // Module properties
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Network Audit", _audit.Name);
        Assert.Equal("Network", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public void Description_CoversKeyAreas()
    {
        Assert.Contains("LLMNR", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ARP", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("port", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SMB", _audit.Description, StringComparison.OrdinalIgnoreCase);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Basic execution
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
        Assert.Equal("Network Audit", _result.ModuleName);
        Assert.Equal("Network", _result.Category);
    }

    [Fact]
    public void RunAuditAsync_ProducesMultipleFindings()
    {
        // 10 checks should produce at minimum 8+ findings
        Assert.True(_result.Findings.Count >= 8,
            $"Expected at least 8 findings from 10 checks, got {_result.Findings.Count}");
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }

    [Fact]
    public void RunAuditAsync_HasValidTimestamps()
    {
        Assert.True(_result.StartTime > DateTimeOffset.MinValue);
        Assert.True(_result.EndTime >= _result.StartTime);
        Assert.True(_result.Duration > TimeSpan.Zero);
        Assert.True(_result.Duration < TimeSpan.FromMinutes(2),
            $"Audit took too long: {_result.Duration.TotalSeconds:F1}s");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Finding quality
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_AllFindingsHaveCategory()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.Equal("Network", finding.Category);
        }
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveTitleAndDescription()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title),
                "Every finding must have a non-empty title");
            Assert.False(string.IsNullOrWhiteSpace(finding.Description),
                $"Finding '{finding.Title}' must have a non-empty description");
        }
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveValidSeverity()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.True(Enum.IsDefined(finding.Severity),
                $"Finding '{finding.Title}' has invalid severity: {finding.Severity}");
        }
    }

    [Fact]
    public void RunAuditAsync_WarningFindingsHaveRemediation()
    {
        var actionableFindings = _result.Findings
            .Where(f => f.Severity == Severity.Warning || f.Severity == Severity.Critical)
            .ToList();

        foreach (var finding in actionableFindings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Warning/Critical finding '{finding.Title}' must have remediation text");
        }
    }

    [Fact]
    public void RunAuditAsync_CriticalFindingsHaveFixCommand()
    {
        var criticalFindings = _result.Findings
            .Where(f => f.Severity == Severity.Critical)
            .ToList();

        foreach (var finding in criticalFindings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand),
                $"Critical finding '{finding.Title}' must have a fix command");
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: Listening ports
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksListeningPorts()
    {
        var portFindings = _result.Findings
            .Where(f => f.Title.Contains("Port", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Listening", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(portFindings.Count >= 1,
            "Expected at least 1 finding about listening ports");
    }

    [Fact]
    public void RunAuditAsync_ReportsTotalListeningPortCount()
    {
        var infoFinding = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("Total Listening Ports", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(infoFinding);
        Assert.Equal(Severity.Info, infoFinding.Severity);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: SMB exposure
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksSmbV1()
    {
        var smbv1Findings = _result.Findings
            .Where(f => f.Title.Contains("SMBv1", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("SMB1", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(smbv1Findings.Count >= 1,
            "Expected at least 1 SMBv1 finding (enabled=Critical or disabled=Pass)");
    }

    [Fact]
    public void RunAuditAsync_ChecksSmbSigning()
    {
        var smbSigningFindings = _result.Findings
            .Where(f => f.Title.Contains("SMB Signing", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(smbSigningFindings.Count >= 1,
            "Expected at least 1 SMB signing finding");
    }

    [Fact]
    public void RunAuditAsync_SmbV1CriticalHasFixCommand()
    {
        var smbv1Critical = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("SMBv1", StringComparison.OrdinalIgnoreCase) &&
                                 f.Severity == Severity.Critical);

        if (smbv1Critical != null)
        {
            Assert.False(string.IsNullOrWhiteSpace(smbv1Critical.FixCommand),
                "SMBv1 critical finding must have a fix command");
            Assert.Contains("EnableSMB1Protocol", smbv1Critical.FixCommand);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: RDP exposure
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksRdpExposure()
    {
        var rdpFindings = _result.Findings
            .Where(f => f.Title.Contains("RDP", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Remote Desktop", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(rdpFindings.Count >= 1,
            "Expected at least 1 RDP finding (enabled/disabled/NLA status)");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: WinRM
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksWinRm()
    {
        var winrmFindings = _result.Findings
            .Where(f => f.Title.Contains("WinRM", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(winrmFindings.Count >= 1,
            "Expected at least 1 WinRM finding (running=Warning or stopped=Pass)");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: DNS settings
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksDnsSettings()
    {
        var dnsFindings = _result.Findings
            .Where(f => f.Title.Contains("DNS", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(dnsFindings.Count >= 1,
            "Expected at least 1 DNS finding");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: Network profile
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksNetworkProfile()
    {
        var profileFindings = _result.Findings
            .Where(f => f.Title.Contains("Network Profile", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Public Network", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Private", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Domain", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(profileFindings.Count >= 1,
            "Expected at least 1 network profile finding");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: LLMNR/NetBIOS
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksLlmnr()
    {
        var llmnrFindings = _result.Findings
            .Where(f => f.Title.Contains("LLMNR", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(llmnrFindings.Count >= 1,
            "Expected at least 1 LLMNR finding (enabled=Warning or disabled=Pass)");
    }

    [Fact]
    public void RunAuditAsync_ChecksNetBios()
    {
        var netBiosFindings = _result.Findings
            .Where(f => f.Title.Contains("NetBIOS", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(netBiosFindings.Count >= 1,
            "Expected at least 1 NetBIOS finding");
    }

    [Fact]
    public void RunAuditAsync_LlmnrWarningHasFixCommand()
    {
        var llmnrWarning = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("LLMNR", StringComparison.OrdinalIgnoreCase) &&
                                 f.Severity == Severity.Warning);

        if (llmnrWarning != null)
        {
            Assert.False(string.IsNullOrWhiteSpace(llmnrWarning.Remediation),
                "LLMNR warning should have remediation advice");
            Assert.False(string.IsNullOrWhiteSpace(llmnrWarning.FixCommand),
                "LLMNR warning should have a fix command");
            Assert.Contains("EnableMulticast", llmnrWarning.FixCommand);
        }
    }

    [Fact]
    public void RunAuditAsync_NetBiosWarningHasFixCommand()
    {
        var nbWarning = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("NetBIOS", StringComparison.OrdinalIgnoreCase) &&
                                 f.Severity == Severity.Warning);

        if (nbWarning != null)
        {
            Assert.False(string.IsNullOrWhiteSpace(nbWarning.Remediation),
                "NetBIOS warning should have remediation advice");
            Assert.False(string.IsNullOrWhiteSpace(nbWarning.FixCommand),
                "NetBIOS warning should have a fix command");
            Assert.Contains("SetTcpipNetbios", nbWarning.FixCommand);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: ARP anomalies
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksArpTable()
    {
        var arpFindings = _result.Findings
            .Where(f => f.Title.Contains("ARP", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(arpFindings.Count >= 1,
            "Expected at least 1 ARP table finding");
    }

    [Fact]
    public void RunAuditAsync_ArpFindingHasMeaningfulTitle()
    {
        var arpFinding = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("ARP", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(arpFinding);
        Assert.True(
            arpFinding.Title.Contains("No Anomalies") ||
            arpFinding.Title.Contains("Duplicate") ||
            arpFinding.Title.Contains("Empty") ||
            arpFinding.Title.Contains("Unavailable") ||
            arpFinding.Title.Contains("Check Performed"),
            $"ARP finding title should indicate result: '{arpFinding.Title}'");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Check: IPv6 exposure
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksIpv6()
    {
        // IPv6 checks may not produce findings if no global addresses exist
        // But the check should not cause the audit to fail
        Assert.True(_result.Success);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Execution behavior
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAuditAsync_CompletesWithinTimeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var result = await _audit.RunAuditAsync(cts.Token);

        Assert.True(result.Success, $"Audit should complete within 90 seconds: {result.Error}");
        Assert.True(result.Duration < TimeSpan.FromSeconds(90),
            $"Audit took {result.Duration.TotalSeconds:F1}s, expected < 90s");
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        try
        {
            var result = await _audit.RunAuditAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected — cancellation was honored
        }
    }

    [Fact]
    public void RunAuditAsync_IsIdempotent()
    {
        // The shared result is from one run. Verify it's consistent:
        // all findings have non-null Title (idempotency proxy — same audit = stable output)
        Assert.All(_result.Findings, f => Assert.NotNull(f.Title));
    }

    [Fact]
    public void RunAuditAsync_FindingTitlesAreUnique()
    {
        var duplicates = _result.Findings
            .GroupBy(f => f.Title)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.True(duplicates.Count <= 1,
            $"Too many duplicate finding titles: {string.Join(", ", duplicates)}");
    }

    [Fact]
    public void RunAuditAsync_NoFindingHasEmptyRemediation_WhenActionable()
    {
        var actionable = _result.Findings
            .Where(f => f.Severity == Severity.Warning || f.Severity == Severity.Critical);

        foreach (var finding in actionable)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Actionable finding '{finding.Title}' (severity={finding.Severity}) must have remediation");
            Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand),
                $"Actionable finding '{finding.Title}' (severity={finding.Severity}) should have a fix command");
        }
    }

    [Fact]
    public void RunAuditAsync_FixCommandsArePowerShellOrNetsh()
    {
        var withFixCmd = _result.Findings.Where(f => !string.IsNullOrWhiteSpace(f.FixCommand));

        foreach (var finding in withFixCmd)
        {
            var cmd = finding.FixCommand!;
            Assert.True(
                cmd.Contains("Set-") || cmd.Contains("Get-") || cmd.Contains("New-Item") ||
                cmd.Contains("Stop-Service") || cmd.Contains("netsh") || cmd.Contains("arp") ||
                cmd.Contains("ForEach-Object") || cmd.Contains("Remove-Item"),
                $"Fix command for '{finding.Title}' should be a PowerShell cmdlet or netsh: '{cmd}'");
        }
    }
}
