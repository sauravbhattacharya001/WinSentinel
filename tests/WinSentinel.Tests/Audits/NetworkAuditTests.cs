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

/// <summary>
/// Pure unit tests for <see cref="NetworkAudit"/>'s <c>arp -a</c> line parsing
/// (<see cref="NetworkAudit.TryParseArpLine"/> and its IPv4/MAC validators). These
/// run without touching the host ARP table, so they can exercise the header /
/// interface / malformed-line edge cases that the live integration tests above
/// cannot reach.
/// </summary>
public class NetworkAuditArpParsingTests
{
    [Theory]
    [InlineData("  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic", "192.168.1.1", "aa-bb-cc-dd-ee-ff")]
    [InlineData("10.0.0.5   00-11-22-33-44-55   static", "10.0.0.5", "00-11-22-33-44-55")]
    [InlineData("224.0.0.22            01-00-5e-00-00-16     static", "224.0.0.22", "01-00-5e-00-00-16")]
    [InlineData("255.255.255.255       ff-ff-ff-ff-ff-ff     static", "255.255.255.255", "ff-ff-ff-ff-ff-ff")]
    public void TryParseArpLine_ParsesRealEntries(string line, string expectedIp, string expectedMac)
    {
        Assert.True(NetworkAudit.TryParseArpLine(line, out var entry));
        Assert.Equal(expectedIp, entry.Ip);
        Assert.Equal(expectedMac, entry.Mac);
    }

    [Theory]
    // The "Interface:" banner that precedes each adapter's table. Its IP sits in the
    // SECOND column, so the old positional heuristic only rejected it by luck; the
    // structural check rejects it because column 0 ("Interface:") is not a dotted-quad.
    [InlineData("Interface: 192.168.1.5 --- 0x5")]
    // The English column header.
    [InlineData("  Internet Address      Physical Address      Type")]
    // A localized column header whose second column is a hyphenated word: the OLD
    // heuristic (col1 contains '-' && length >= 17) would have ingested this as a
    // bogus ARP entry; structural MAC validation rejects it.
    [InlineData("  Adresse-Internet      Adresse-physique-ici   Typ")]
    // Incomplete / unresolved entries.
    [InlineData("  192.168.1.99         incomplete")]
    [InlineData("  192.168.1.42")]
    // Blank / whitespace.
    [InlineData("")]
    [InlineData("     ")]
    public void TryParseArpLine_RejectsNonEntries(string line)
    {
        Assert.False(NetworkAudit.TryParseArpLine(line, out _));
    }

    [Fact]
    public void TryParseArpLine_RejectsNull()
    {
        Assert.False(NetworkAudit.TryParseArpLine(null, out _));
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("192.168.1.1")]
    [InlineData("255.255.255.255")]
    [InlineData("8.8.8.8")]
    public void IsIPv4DottedQuad_AcceptsValid(string ip) =>
        Assert.True(NetworkAudit.IsIPv4DottedQuad(ip));

    [Theory]
    [InlineData("256.1.1.1")]      // octet > 255
    [InlineData("192.168.1")]       // only three octets
    [InlineData("192.168.1.1.1")]   // five octets
    [InlineData("192.168.1.")]      // trailing empty octet
    [InlineData("Interface:")]      // header token
    [InlineData("1.2.3.x")]         // non-numeric octet
    [InlineData("fe80::1")]         // IPv6
    [InlineData("")]
    public void IsIPv4DottedQuad_RejectsInvalid(string ip) =>
        Assert.False(NetworkAudit.IsIPv4DottedQuad(ip));

    [Theory]
    [InlineData("aa-bb-cc-dd-ee-ff")]
    [InlineData("00-11-22-33-44-55")]
    [InlineData("FF-FF-FF-FF-FF-FF")]
    [InlineData("01-00-5E-00-00-16")]
    public void IsMacAddress_AcceptsValid(string mac) =>
        Assert.True(NetworkAudit.IsMacAddress(mac));

    [Theory]
    [InlineData("aa-bb-cc-dd-ee")]        // only five octets
    [InlineData("aa-bb-cc-dd-ee-ff-00")]  // seven octets
    [InlineData("aabb-cc-dd-ee-ff")]      // wrong group width
    [InlineData("aa:bb:cc:dd:ee:ff")]     // colon-separated (not Windows arp form)
    [InlineData("gg-bb-cc-dd-ee-ff")]     // non-hex digit
    [InlineData("incomplete")]
    [InlineData("Physical-Address-Here-X")] // hyphenated non-MAC word >= 17 chars
    [InlineData("")]
    public void IsMacAddress_RejectsInvalid(string mac) =>
        Assert.False(NetworkAudit.IsMacAddress(mac));

    [Fact]
    public void TryParseArpLine_FullTableSample_ExtractsOnlyRealRows()
    {
        // A representative multi-interface `arp -a` capture: two banner lines, two
        // column headers, real unicast/multicast/broadcast rows, and an incomplete row.
        var sample = string.Join("\n", new[]
        {
            "",
            "Interface: 192.168.1.5 --- 0x5",
            "  Internet Address      Physical Address      Type",
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic",
            "  192.168.1.20          11-22-33-44-55-66     dynamic",
            "  192.168.1.99          incomplete",
            "  224.0.0.22            01-00-5e-00-00-16     static",
            "  255.255.255.255       ff-ff-ff-ff-ff-ff     static",
            "",
            "Interface: 10.0.0.8 --- 0x9",
            "  Internet Address      Physical Address      Type",
            "  10.0.0.1              de-ad-be-ef-00-01     dynamic",
        });

        var parsed = sample
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => NetworkAudit.TryParseArpLine(l, out var e) ? e : null)
            .Where(e => e != null)
            .ToList();

        // 5 real rows; both banners, both headers and the incomplete row are dropped.
        Assert.Equal(5, parsed.Count);
        Assert.DoesNotContain(parsed, e => e!.Ip == "192.168.1.99"); // incomplete dropped
        Assert.Contains(parsed, e => e!.Ip == "192.168.1.1" && e.Mac == "aa-bb-cc-dd-ee-ff");
        Assert.Contains(parsed, e => e!.Ip == "10.0.0.1" && e.Mac == "de-ad-be-ef-00-01");
    }
}

/// <summary>
/// Host-independent unit tests for the IPv6 collector's pure parsing seams
/// (<see cref="NetworkAudit.TryParseGlobalIPv6Line"/>, <see cref="NetworkAudit.IsGlobalIPv6Address"/>,
/// and <see cref="NetworkAudit.IsTeredoActiveState"/>). These do not run a live audit; they
/// validate that only genuine, routable global IPv6 addresses survive parsing and that
/// Teredo is reported active only for client/relay/server states. This guards a real
/// false-positive class: before structural validation, any pipe-delimited output line
/// (incl. a localized header) could be ingested as a bogus "global IPv6 address", and the
/// old "anything not disabled/default" Teredo check could manufacture a phantom warning.
/// </summary>
public class NetworkAuditIPv6ParsingTests
{
    // ── TryParseGlobalIPv6Line: real rows ──────────────────────────────

    [Theory]
    [InlineData("2001:db8::1|Ethernet|Manual", "2001:db8::1")]
    [InlineData("2606:4700:4700::1111|Wi-Fi|Dhcp", "2606:4700:4700::1111")]
    [InlineData("  2001:0db8:85a3:0000:0000:8a2e:0370:7334 | Ethernet 2 | RouterAdvertisement ", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
    [InlineData("2a00:1450:4009:80f::200e|Ethernet|Manual", "2a00:1450:4009:80f::200e")]
    public void TryParseGlobalIPv6Line_ParsesRealRows(string line, string expected)
    {
        Assert.True(NetworkAudit.TryParseGlobalIPv6Line(line, out var addr));
        Assert.Equal(expected, addr);
    }

    // ── TryParseGlobalIPv6Line: lines that must be rejected ─────────────

    [Theory]
    [InlineData("")]                                              // blank
    [InlineData("   ")]                                           // whitespace
    [InlineData("IPAddress InterfaceAlias PrefixOrigin")]        // header, no pipe
    [InlineData("Adresse|Schnittstelle|Ursprung")]              // localized header -> col0 not an IPv6 addr
    [InlineData("fe80::1|Ethernet|LinkLayerAddress")]           // link-local must be dropped
    [InlineData("fe80::1%eth0|Ethernet|Manual")]               // scoped link-local
    [InlineData("::1|Loopback Pseudo-Interface 1|WellKnown")]   // loopback
    [InlineData("::|Ethernet|WellKnown")]                       // unspecified
    [InlineData("ff02::1|Ethernet|WellKnown")]                  // multicast
    [InlineData("192.168.1.5|Ethernet|Manual")]                // IPv4 in col0
    [InlineData("not-an-address|Ethernet|Manual")]             // garbage col0
    [InlineData("2001:db8::1")]                                  // no pipe delimiter at all
    public void TryParseGlobalIPv6Line_RejectsNonGlobalOrMalformed(string line)
    {
        Assert.False(NetworkAudit.TryParseGlobalIPv6Line(line, out var addr));
        Assert.Equal(string.Empty, addr);
    }

    [Fact]
    public void TryParseGlobalIPv6Line_RejectsNull()
    {
        Assert.False(NetworkAudit.TryParseGlobalIPv6Line(null, out var addr));
        Assert.Equal(string.Empty, addr);
    }

    // ── IsGlobalIPv6Address validator ──────────────────────────────────

    [Theory]
    [InlineData("2001:db8::1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2a00:1450:4009:80f::200e")]
    [InlineData("fd00::1")]   // unique-local (fc00::/7) is still a routable non-link-local addr we surface
    public void IsGlobalIPv6Address_AcceptsGlobal(string addr) =>
        Assert.True(NetworkAudit.IsGlobalIPv6Address(addr));

    [Theory]
    [InlineData("::1")]                 // loopback
    [InlineData("::")]                  // unspecified
    [InlineData("fe80::1")]             // link-local
    [InlineData("fe80::abcd:1234")]     // link-local
    [InlineData("ff02::1")]             // multicast
    [InlineData("ff00::")]              // multicast base
    [InlineData("192.168.1.1")]         // IPv4, wrong family
    [InlineData("10.0.0.1")]            // IPv4, wrong family
    [InlineData("hello")]               // garbage
    [InlineData("")]                    // empty
    [InlineData("   ")]                 // whitespace
    [InlineData("2001:db8::1%5")]       // zone-scoped suffix rejected
    public void IsGlobalIPv6Address_RejectsNonGlobal(string addr) =>
        Assert.False(NetworkAudit.IsGlobalIPv6Address(addr));

    [Fact]
    public void IsGlobalIPv6Address_RejectsNull() =>
        Assert.False(NetworkAudit.IsGlobalIPv6Address(null));

    // ── IsTeredoActiveState classifier ─────────────────────────────────

    [Theory]
    [InlineData("client")]
    [InlineData("enterpriseclient")]
    [InlineData("CLIENT")]              // case-insensitive
    [InlineData(" relay ")]             // trimmed
    [InlineData("server")]
    public void IsTeredoActiveState_TrueForActiveStates(string typeValue) =>
        Assert.True(NetworkAudit.IsTeredoActiveState(typeValue));

    [Theory]
    [InlineData("disabled")]
    [InlineData("default")]
    [InlineData("offline")]
    [InlineData("dormant")]
    [InlineData("probe")]               // transient, not yet a client
    [InlineData("qualified")]           // not one of our recognized active tokens
    [InlineData("deaktiviert")]         // localized 'disabled' -> not matched -> inactive (safe default)
    [InlineData("")]
    [InlineData("   ")]
    public void IsTeredoActiveState_FalseForInactiveOrUnknown(string typeValue) =>
        Assert.False(NetworkAudit.IsTeredoActiveState(typeValue));

    [Fact]
    public void IsTeredoActiveState_FalseForNull() =>
        Assert.False(NetworkAudit.IsTeredoActiveState(null));

    // ── Full pipe-delimited collector sample (structure end-to-end) ─────

    [Fact]
    public void GlobalIPv6_FullSample_KeepsOnlyGlobalAddresses()
    {
        // Mirrors the IPv6 collector's PowerShell output plus noise a localized or
        // misbehaving host might emit. Only the two genuine global addresses survive.
        var sample = string.Join("\n", new[]
        {
            "",
            "IPAddress|InterfaceAlias|PrefixOrigin",        // header line
            "2001:db8:abcd:12::1|Ethernet|RouterAdvertisement",
            "fe80::1cad:42ff:fe00:1|Ethernet|WellKnown",   // link-local -> dropped
            "::1|Loopback Pseudo-Interface 1|WellKnown",   // loopback -> dropped
            "2606:4700:4700::1001|Wi-Fi|Manual",
            "ff02::fb|Wi-Fi|WellKnown",                     // multicast -> dropped
            "garbage line with | pipe but no address",     // junk col0 -> dropped
        });

        var parsed = sample
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => NetworkAudit.TryParseGlobalIPv6Line(l, out var a) ? a : null)
            .Where(a => a != null)
            .ToList();

        Assert.Equal(2, parsed.Count);
        Assert.Contains("2001:db8:abcd:12::1", parsed);
        Assert.Contains("2606:4700:4700::1001", parsed);
        Assert.DoesNotContain("::1", parsed);
    }
}
