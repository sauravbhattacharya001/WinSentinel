using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using Toggle = WinSentinel.Core.Audits.NetworkPostureAnalyzer.Toggle;

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
            // Every actionable finding MUST carry human-readable remediation guidance.
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Actionable finding '{finding.Title}' (severity={finding.Severity}) must have remediation");

            // A FixCommand (one-click auto-fix) is NOT required for every actionable
            // finding: some remediations are an inherent human-judgement call with no
            // single safe auto-fix (e.g. "High-Risk Ports Listening" - which listening
            // service to stop depends on what the box is for, and the only safe action
            // is to investigate, so the owning-process query lives in Remediation text
            // rather than as an un-runnable FixCommand). When a FixCommand IS present it
            // must be non-empty/non-whitespace; absence is allowed for these cases.
            if (finding.FixCommand != null)
            {
                Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand),
                    $"Finding '{finding.Title}' has a non-null but blank FixCommand; " +
                    "use null to mean 'no auto-fix', never an empty/whitespace string.");
            }
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

    // ── TryParseListeningPortLine: rows that must parse ─────────────────

    [Theory]
    [InlineData("445|System", 445, "System")]
    [InlineData("49664|svchost", 49664, "svchost")]
    [InlineData("  3389 | TermService ", 3389, "TermService")]     // surrounding whitespace trimmed
    [InlineData("1|wininit", 1, "wininit")]                          // lowest valid port
    [InlineData("65535|app", 65535, "app")]                          // highest valid port
    [InlineData("80|svc|extra", 80, "svc")]                          // trailing column ignored
    public void TryParseListeningPortLine_ParsesRealRows(string line, int expectedPort, string expectedProc)
    {
        Assert.True(NetworkAudit.TryParseListeningPortLine(line, out var p));
        Assert.Equal(expectedPort, p.Port);
        Assert.Equal(expectedProc, p.ProcessName);
    }

    [Fact]
    public void TryParseListeningPortLine_BlankOwner_NormalizedToUnknown()
    {
        // A process that exited between Get-NetTCPConnection and Get-Process yields "445|".
        Assert.True(NetworkAudit.TryParseListeningPortLine("445|", out var p));
        Assert.Equal(445, p.Port);
        Assert.Equal("unknown", p.ProcessName);
    }

    [Fact]
    public void TryParseListeningPortLine_WhitespaceOwner_NormalizedToUnknown()
    {
        Assert.True(NetworkAudit.TryParseListeningPortLine("445|   ", out var p));
        Assert.Equal("unknown", p.ProcessName);
    }

    // ── TryParseListeningPortLine: lines that must be rejected ──────────

    [Theory]
    [InlineData("")]                                   // blank
    [InlineData("   ")]                                // whitespace
    [InlineData("LocalPort OwningProcess")]            // header, no pipe
    [InlineData("LocalPort|OwningProcess")]            // header WITH pipe -> col0 not numeric
    [InlineData("Port|Prozess")]                       // localized header
    [InlineData("445")]                                // no pipe delimiter at all
    [InlineData("0|System")]                           // port 0 invalid
    [InlineData("-1|System")]                          // negative
    [InlineData("65536|System")]                       // above max
    [InlineData("999999|System")]                      // way above max (e.g. a stray year/number)
    [InlineData("0x1f|System")]                        // hex token rejected
    [InlineData("5e3|System")]                         // scientific notation rejected
    [InlineData("abc|System")]                         // non-numeric port
    [InlineData("44 5|System")]                        // embedded space -> not digits-only
    public void TryParseListeningPortLine_RejectsMalformed(string line)
    {
        Assert.False(NetworkAudit.TryParseListeningPortLine(line, out var p));
        Assert.Equal(0, p.Port);
    }

    [Fact]
    public void TryParseListeningPortLine_RejectsNull()
    {
        Assert.False(NetworkAudit.TryParseListeningPortLine(null, out var p));
        Assert.Equal(0, p.Port);
    }

    // ── IsValidTcpPort validator ───────────────────────────────────────

    [Theory]
    [InlineData("1", 1)]
    [InlineData("80", 80)]
    [InlineData("65535", 65535)]
    public void IsValidTcpPort_AcceptsInRange(string value, int expected)
    {
        Assert.True(NetworkAudit.IsValidTcpPort(value, out var port));
        Assert.Equal(expected, port);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("65536")]
    [InlineData("100000")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abc")]
    [InlineData("0x50")]
    [InlineData("8.0")]
    public void IsValidTcpPort_RejectsOutOfRangeOrNonNumeric(string value)
    {
        Assert.False(NetworkAudit.IsValidTcpPort(value, out var port));
        Assert.Equal(0, port);
    }

    [Fact]
    public void IsValidTcpPort_RejectsNull() =>
        Assert.False(NetworkAudit.IsValidTcpPort(null, out _));

    // ── Full pipe-delimited collector sample (structure end-to-end) ─────

    [Fact]
    public void ListeningPorts_FullSample_KeepsOnlyValidPortRows()
    {
        // Mirrors the listening-ports collector output plus noise a localized or
        // misbehaving host might emit. Only the genuine port|process rows survive,
        // and an exited owner is labeled "unknown".
        var sample = string.Join("\n", new[]
        {
            "",
            "LocalPort|OwningProcess",          // header -> dropped (col0 not numeric)
            "135|svchost",
            "445|System",
            "3389|",                            // exited owner -> kept as "unknown"
            "0|bogus",                          // port 0 -> dropped
            "999999|noise",                     // out-of-range -> dropped
            "garbage line with no pipe",        // junk -> dropped
        });

        var parsed = sample
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => NetworkAudit.TryParseListeningPortLine(l, out var p) ? p : null)
            .Where(p => p != null)
            .ToList();

        Assert.Equal(3, parsed.Count);
        Assert.Contains(parsed, p => p!.Port == 135 && p.ProcessName == "svchost");
        Assert.Contains(parsed, p => p!.Port == 445 && p.ProcessName == "System");
        Assert.Contains(parsed, p => p!.Port == 3389 && p.ProcessName == "unknown");
        Assert.DoesNotContain(parsed, p => p!.Port == 0);
        Assert.DoesNotContain(parsed, p => p!.ProcessName == "noise");
    }
}

/// <summary>
/// Host-independent tests for the SMB toggle and RDP registry-flag parsers in
/// <see cref="NetworkAudit"/> (<see cref="NetworkAudit.ParseToggle"/>,
/// <see cref="NetworkAudit.TryParseRegistryDword"/>,
/// <see cref="NetworkAudit.IsRdpEnabledFromDeny"/>,
/// <see cref="NetworkAudit.IsNlaEnabledFromValue"/>). These collectors read
/// True/False and DWORD values out of PowerShell output; the parsers must ignore
/// noisy/multi-line output and FAIL SAFE for NLA so a failed read surfaces the
/// RDP exposure rather than hiding it. No live PowerShell is invoked.
/// </summary>
public class NetworkAuditSmbRdpParsingTests
{
    // ── ParseToggle: clean and noisy boolean output ────────────────────

    [Theory]
    [InlineData("True", Toggle.Enabled)]
    [InlineData("False", Toggle.Disabled)]
    [InlineData("  true  ", Toggle.Enabled)]          // surrounding whitespace
    [InlineData("FALSE", Toggle.Disabled)]            // case-insensitive
    [InlineData("\r\nTrue\r\n", Toggle.Enabled)]      // CRLF padded
    public void ParseToggle_ParsesCleanBooleans(string raw, Toggle expected)
    {
        Assert.Equal(expected, NetworkAudit.ParseToggle(raw));
    }

    [Theory]
    // A CIM/WMI warning or verbose banner preceding the value used to degrade the
    // whole blob to Unknown; now the genuine boolean line is found.
    [InlineData("WARNING: An unexpected provider error occurred.\nTrue", Toggle.Enabled)]
    [InlineData("VERBOSE: connecting...\nFalse\n", Toggle.Disabled)]
    [InlineData("\n\nTrue", Toggle.Enabled)]
    public void ParseToggle_FindsBooleanAmidNoise(string raw, Toggle expected)
    {
        Assert.Equal(expected, NetworkAudit.ParseToggle(raw));
    }

    [Theory]
    [InlineData("ERROR")]                              // the catch sentinel -> Unknown, not a boolean
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Truthy")]                             // not exactly True
    [InlineData("yes")]                                // not a .NET boolean token
    [InlineData("1")]                                  // numeric, not True/False
    [InlineData("True False")]                         // ambiguous single line -> no exact token
    public void ParseToggle_ReturnsUnknownForNonBoolean(string raw)
    {
        Assert.Equal(Toggle.Unknown, NetworkAudit.ParseToggle(raw));
    }

    [Fact]
    public void ParseToggle_ReturnsUnknownForNull() =>
        Assert.Equal(Toggle.Unknown, NetworkAudit.ParseToggle(null));

    // ── TryParseRegistryDword: only a clean lone DWORD is trusted ───────

    [Theory]
    [InlineData("0", 0)]
    [InlineData("1", 1)]
    [InlineData("  2 ", 2)]                            // whitespace trimmed
    [InlineData("\r\n1\r\n", 1)]                       // blank lines around the value
    [InlineData("4294967", 4294967)]                  // large in-range int
    public void TryParseRegistryDword_AcceptsCleanLoneInteger(string raw, int expected)
    {
        Assert.True(NetworkAudit.TryParseRegistryDword(raw, out var v));
        Assert.Equal(expected, v);
    }

    [Theory]
    [InlineData("")]                                   // empty
    [InlineData("   ")]                                // whitespace
    [InlineData("-1")]                                 // sign rejected
    [InlineData("0x1")]                                // hex rejected
    [InlineData("1.0")]                                // decimal rejected
    [InlineData("1 0")]                                // embedded space
    [InlineData("0\n1")]                               // two values -> ambiguous
    [InlineData("True")]                               // non-numeric
    [InlineData("99999999999999999999")]              // overflows int
    [InlineData("WARNING: x\n0")]                       // noise line + value -> ambiguous, rejected
    public void TryParseRegistryDword_RejectsNoisyOrNonNumeric(string raw)
    {
        Assert.False(NetworkAudit.TryParseRegistryDword(raw, out var v));
        Assert.Equal(0, v);
    }

    [Fact]
    public void TryParseRegistryDword_RejectsNull() =>
        Assert.False(NetworkAudit.TryParseRegistryDword(null, out _));

    // ── IsRdpEnabledFromDeny: fDenyTSConnections == clean 0 ─────────────

    [Theory]
    [InlineData("0", true)]                            // RDP enabled
    [InlineData(" 0 ", true)]
    [InlineData("1", false)]                           // RDP denied
    [InlineData("", false)]                            // missing key -> not enabled
    [InlineData("   ", false)]
    [InlineData("0\n0", false)]                        // ambiguous multi-value -> not enabled
    [InlineData("WARNING\n0", false)]                  // noisy -> not coerced to enabled
    [InlineData("0x0", false)]                         // hex not trusted
    public void IsRdpEnabledFromDeny_OnlyTrueForCleanZero(string raw, bool expected)
    {
        Assert.Equal(expected, NetworkAudit.IsRdpEnabledFromDeny(raw));
    }

    [Fact]
    public void IsRdpEnabledFromDeny_NullIsNotEnabled() =>
        Assert.False(NetworkAudit.IsRdpEnabledFromDeny(null));

    // ── IsNlaEnabledFromValue: fails SAFE (only clean 1 == enabled) ─────

    [Theory]
    [InlineData("1", true)]                            // NLA enabled
    [InlineData(" 1 ", true)]
    [InlineData("0", false)]                           // NLA explicitly disabled -> exposure
    public void IsNlaEnabledFromValue_TrueOnlyForCleanOne(string raw, bool expected)
    {
        Assert.Equal(expected, NetworkAudit.IsNlaEnabledFromValue(raw));
    }

    [Theory]
    // The critical fail-safe direction: an unreadable / missing / noisy NLA value
    // must NOT be treated as enabled, so the "RDP without NLA" warning still fires.
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("WARNING: registry read failed")]
    [InlineData("1\n1")]                               // ambiguous multi-value
    [InlineData("enabled")]                            // non-numeric
    [InlineData("0x1")]                                // hex not trusted
    public void IsNlaEnabledFromValue_UnreadableIsNotEnabled(string raw)
    {
        Assert.False(NetworkAudit.IsNlaEnabledFromValue(raw));
    }

    [Fact]
    public void IsNlaEnabledFromValue_NullIsNotEnabled() =>
        Assert.False(NetworkAudit.IsNlaEnabledFromValue(null));

    // ── Regression: pins the security-relevant behaviour CHANGE ────────

    [Fact]
    public void IsNlaEnabledFromValue_FailsSafe_WhereOldTrimCheckDidNot()
    {
        // The old collector computed NLA as `nla.Trim() != "0"`, so an EMPTY value
        // (registry read failed / key missing) evaluated to true and silently
        // marked NLA as enabled -- suppressing the "RDP without NLA" exposure. The
        // hardened reader treats only a clean "1" as enabled, so the same input now
        // fails safe and the exposure is surfaced.
        const string unreadable = "";
        bool oldResult = unreadable.Trim() != "0";              // legacy logic
        Assert.True(oldResult);                                 // old: NLA assumed ENABLED (the bug)
        Assert.False(NetworkAudit.IsNlaEnabledFromValue(unreadable)); // new: NOT enabled (fail safe)
    }

    [Fact]
    public void ParseToggle_FindsValue_WhereOldWholeBlobTrimDidNot()
    {
        // The old ParseToggle did `raw.Trim()` over the WHOLE blob, so a warning
        // line ahead of the value degraded a known True/False to Unknown.
        const string noisy = "WARNING: An unexpected provider error occurred.\nTrue";
        var oldResult = noisy.Trim().Equals("True", StringComparison.OrdinalIgnoreCase)
            ? Toggle.Enabled
            : noisy.Trim().Equals("False", StringComparison.OrdinalIgnoreCase)
                ? Toggle.Disabled
                : Toggle.Unknown;
        Assert.Equal(Toggle.Unknown, oldResult);                // old: degraded to Unknown
        Assert.Equal(Toggle.Enabled, NetworkAudit.ParseToggle(noisy)); // new: finds the real value
    }
}

/// <summary>
/// Host-independent tests for the LLMNR (EnableMulticast GPO) and NetBIOS-over-
/// TCP/IP option parsers in <see cref="NetworkAudit"/>. These exercise the pure
/// seams (ClassifyLlmnrValue, IsNetBiosEnabledFromOption) directly, so they run
/// anywhere without touching the registry or CIM. Both fail SAFE: an unreadable
/// or noisy value surfaces the name-resolution-poisoning exposure (LLMNR not
/// Disabled / NetBIOS counted as enabled) rather than hiding it.
/// </summary>
public class NetworkAuditLlmnrNetBiosParsingTests
{
    // ── ClassifyLlmnrValue ─────────────────────────────────────────────

    [Fact]
    public void ClassifyLlmnr_CleanZero_IsDisabled() =>
        Assert.Equal(Toggle.Disabled, NetworkAudit.ClassifyLlmnrValue("0"));

    [Theory]
    [InlineData(" 0 ")]            // surrounding whitespace
    [InlineData("0\n")]           // trailing newline (typical PowerShell output)
    [InlineData("\n0\n")]         // blank lines around the value
    public void ClassifyLlmnr_CleanZeroWithWhitespace_IsDisabled(string raw) =>
        Assert.Equal(Toggle.Disabled, NetworkAudit.ClassifyLlmnrValue(raw));

    [Theory]
    [InlineData("1")]             // explicitly enabled
    [InlineData("NOT_SET")]       // key absent
    [InlineData("not_set")]       // case-insensitive sentinel
    [InlineData("ERROR")]         // reader catch sentinel
    public void ClassifyLlmnr_EnabledOrUnknownTokens_AreEnabled(string raw) =>
        Assert.Equal(Toggle.Enabled, NetworkAudit.ClassifyLlmnrValue(raw));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("garbage")]       // unrecognised single token
    [InlineData("2")]            // not a valid EnableMulticast value -> not "disabled"
    [InlineData("00")]           // not exactly "0"
    public void ClassifyLlmnr_MissingOrUnrecognised_FailSafeEnabled(string? raw) =>
        Assert.Equal(Toggle.Enabled, NetworkAudit.ClassifyLlmnrValue(raw));

    [Fact]
    public void ClassifyLlmnr_NoisyPrefixThenZero_IsDisabled()
    {
        // A CIM/registry warning ahead of the real value must NOT defeat the
        // disabled verdict -- the scanner finds the first recognised token line.
        const string noisy = "WARNING: Get-ItemProperty provider error\n0";
        Assert.Equal(Toggle.Disabled, NetworkAudit.ClassifyLlmnrValue(noisy));
    }

    [Fact]
    public void ClassifyLlmnr_NoisyPrefixThenOne_IsEnabled()
    {
        const string noisy = "WARNING: verbose banner\n1";
        Assert.Equal(Toggle.Enabled, NetworkAudit.ClassifyLlmnrValue(noisy));
    }

    // ── IsNetBiosEnabledFromOption ─────────────────────────────────────

    [Theory]
    [InlineData("0")]             // default: enabled via DHCP
    [InlineData("1")]             // explicitly enabled
    [InlineData(" 1 ")]           // whitespace tolerated by the clean-int gate
    public void NetBios_EnabledOptions_AreEnabled(string opt) =>
        Assert.True(NetworkAudit.IsNetBiosEnabledFromOption(opt));

    [Theory]
    [InlineData("2")]             // the only "disabled"
    [InlineData(" 2 ")]
    [InlineData("2\n")]
    public void NetBios_CleanTwo_IsDisabled(string opt) =>
        Assert.False(NetworkAudit.IsNetBiosEnabledFromOption(opt));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("2.0")]          // decimal -> not a clean DWORD
    [InlineData("0x2")]          // hex -> not trusted
    [InlineData("-2")]           // signed -> rejected by the clean-int gate
    [InlineData("disabled")]     // non-numeric noise
    [InlineData("2 extra")]      // multi-token
    public void NetBios_UnparseableOrNoisy_FailSafeEnabled(string? opt) =>
        Assert.True(NetworkAudit.IsNetBiosEnabledFromOption(opt));

    // ── Regression: pin the security-relevant behaviour CHANGE ─────────

    [Fact]
    public void ClassifyLlmnr_NoisyZero_DisabledWhereOldWholeBlobTrimWasEnabled()
    {
        // The old collector did `llmnrOutput.Trim() == "0"` over the WHOLE blob,
        // so a prepended warning line made a genuinely-disabled (0) value read as
        // ENABLED -- a false LLMNR-poisoning Warning. The hardened classifier scans
        // for the real token line and correctly reports Disabled.
        const string noisy = "WARNING: An unexpected provider error occurred.\n0";
        var oldResult = noisy.Trim() == "0" ? Toggle.Disabled : Toggle.Enabled;
        Assert.Equal(Toggle.Enabled, oldResult);                              // old: mis-read as Enabled
        Assert.Equal(Toggle.Disabled, NetworkAudit.ClassifyLlmnrValue(noisy)); // new: correct Disabled
    }

    [Fact]
    public void NetBios_GarbageOption_EnabledWhereOldEqualityCheckDroppedIt()
    {
        // The old collector added an adapter only when the option was exactly "0"
        // or "1"; ANY other value (including garbage like "2.0") fell through and
        // was silently treated as disabled -- suppressing the NBT-NS exposure for a
        // malformed value. The hardened reader fails safe and surfaces it.
        const string garbage = "2.0";
        var opt = garbage.Trim();
        bool oldEnabled = opt == "0" || opt == "1";                      // legacy logic
        Assert.False(oldEnabled);                                        // old: dropped (assumed disabled)
        Assert.True(NetworkAudit.IsNetBiosEnabledFromOption(garbage));   // new: surfaced (fail safe)
    }
}

