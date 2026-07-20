using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.FirewallAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="FirewallAnalyzer"/>.
///
/// <see cref="FirewallAuditTests"/> already exercises the module end-to-end against
/// the live system; this suite targets the analyzer's own surface directly with
/// synthetic <see cref="FirewallState"/> instances so every classification threshold
/// (a disabled profile is Critical, the >100 inbound-allow count, the >5 any-TCP-port
/// heuristic, the default-inbound-Allow Critical, and the wide-open "any program /
/// any remote IP / any port" inbound-rule detection) plus the netsh rule-block parser
/// are pinned without touching netsh, PowerShell, cmd, WMI, or the registry.
/// </summary>
public class FirewallAnalyzerTests
{
    // ── helpers ───────────────────────────────────────────────────────────────

    private static FirewallProfile Prof(string name, Toggle state) => new(name, state);

    private static FirewallRule Rule(
        string name = "r",
        bool enabled = true,
        string action = "Allow",
        string protocol = "TCP",
        string localPort = "443",
        string remoteIp = "Any",
        string program = @"C:\app.exe") => new()
    {
        Name = name,
        Enabled = enabled,
        Action = action,
        Protocol = protocol,
        LocalPort = localPort,
        RemoteIp = remoteIp,
        Program = program,
    };

    private static FirewallState SecureState() => new()
    {
        Profiles = new()
        {
            new FirewallProfile("Domain", Toggle.Enabled, Toggle.Enabled),
            new FirewallProfile("Private", Toggle.Enabled, Toggle.Enabled),
            new FirewallProfile("Public", Toggle.Enabled, Toggle.Enabled),
        },
        InboundRules = new() { Rule(localPort: "443"), Rule(localPort: "80") },
        RulesQueried = true,
        DefaultInboundBlock = Toggle.Enabled,
        CurrentProfileName = "Public",
    };

    private static bool Has(IEnumerable<Finding> f, Severity sev, string titleContains) =>
        f.Any(x => x.Severity == sev && x.Title.Contains(titleContains, StringComparison.OrdinalIgnoreCase));

    // ── Analyze (aggregate) ─────────────────────────────────────────────────────

    [Fact]
    public void Analyze_NullState_Throws() =>
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));

    [Fact]
    public void Analyze_SecureState_HasNoCriticalsOrWarnings()
    {
        var f = Analyze(SecureState());
        Assert.DoesNotContain(f, x => x.Severity == Severity.Critical);
        Assert.DoesNotContain(f, x => x.Severity == Severity.Warning);
        Assert.NotEmpty(f);
    }

    [Fact]
    public void Analyze_EveryFinding_HasCategoryTitleDescription()
    {
        foreach (var find in Analyze(SecureState()))
        {
            Assert.Equal(Category, find.Category);
            Assert.False(string.IsNullOrWhiteSpace(find.Title));
            Assert.False(string.IsNullOrWhiteSpace(find.Description));
        }
    }

    [Fact]
    public void Analyze_CriticalFindings_CarryRemediationAndFix()
    {
        var state = SecureState();
        state.Profiles = new() { Prof("Public", Toggle.Disabled) };
        state.DefaultInboundBlock = Toggle.Disabled;

        foreach (var c in Analyze(state).Where(x => x.Severity == Severity.Critical))
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Remediation), $"'{c.Title}' needs remediation");
            Assert.False(string.IsNullOrWhiteSpace(c.FixCommand), $"'{c.Title}' needs a fix command");
        }
    }

    // ── Profiles ────────────────────────────────────────────────────────────────

    [Fact]
    public void Profiles_Enabled_Passes()
    {
        var f = CheckProfiles(new FirewallState { Profiles = new() { Prof("Domain", Toggle.Enabled) } });
        Assert.True(Has(f, Severity.Pass, "Domain Firewall Enabled"));
    }

    [Fact]
    public void Profiles_Disabled_IsCriticalWithProfileScopedFix()
    {
        var f = CheckProfiles(new FirewallState { Profiles = new() { Prof("Public", Toggle.Disabled) } });
        var crit = Assert.Single(f);
        Assert.Equal(Severity.Critical, crit.Severity);
        Assert.Contains("Public Firewall Disabled", crit.Title);
        Assert.Equal("netsh advfirewall set publicprofile state on", crit.FixCommand);
    }

    [Fact]
    public void Profiles_Unknown_EmitsNothing()
    {
        var f = CheckProfiles(new FirewallState { Profiles = new() { Prof("Domain", Toggle.Unknown) } });
        Assert.Empty(f);
    }

    [Fact]
    public void Profiles_AllThree_ProduceThreeFindings()
    {
        var f = CheckProfiles(SecureState());
        Assert.Equal(3, f.Count);
        Assert.All(f, x => Assert.Equal(Severity.Pass, x.Severity));
    }

    // ── Rule counts ───────────────────────────────────────────────────────────────

    [Fact]
    public void Rules_NotQueried_EmitsSkipInfo()
    {
        var f = CheckRules(new FirewallState { RulesQueried = false });
        Assert.True(Has(f, Severity.Info, "Firewall Rules Check Skipped"));
    }

    [Fact]
    public void Rules_FewAllows_Passes()
    {
        var f = CheckRules(new FirewallState
        {
            InboundRules = new() { Rule(), Rule(), Rule(enabled: false) },
        });
        Assert.True(Has(f, Severity.Pass, "Inbound Rules Count Acceptable"));
        // "2 enabled inbound allow rules" — the disabled one must not count.
        Assert.Contains(f, x => x.Description.Contains("2 enabled inbound allow rules"));
    }

    [Fact]
    public void Rules_ManyAllows_Warns()
    {
        var many = Enumerable.Range(0, InboundAllowRuleWarnThreshold + 1)
            .Select(i => Rule(name: $"r{i}"))
            .ToList();
        var f = CheckRules(new FirewallState { InboundRules = many });
        Assert.True(Has(f, Severity.Warning, "High Number of Inbound Allow Rules"));
    }

    [Fact]
    public void Rules_BlockRulesAndDisabled_DoNotCount()
    {
        var f = CheckRules(new FirewallState
        {
            InboundRules = new()
            {
                Rule(action: "Block"),                 // not an allow
                Rule(enabled: false),                  // not enabled
                Rule(name: "keep", localPort: "22"),   // the only counted allow
            },
        });
        Assert.Contains(f, x => x.Description.Contains("1 enabled inbound allow rules"));
    }

    [Fact]
    public void Rules_ManyAnyTcpPort_Warns()
    {
        var rules = Enumerable.Range(0, AnyTcpPortRuleWarnThreshold + 1)
            .Select(i => Rule(name: $"any{i}", localPort: "Any"))
            .ToList();
        var f = CheckRules(new FirewallState { InboundRules = rules });
        Assert.True(Has(f, Severity.Warning, "Rules Allowing All TCP Ports"));
    }

    [Fact]
    public void Rules_AnyPortOnUdp_DoesNotTriggerTcpWarning()
    {
        var rules = Enumerable.Range(0, AnyTcpPortRuleWarnThreshold + 2)
            .Select(i => Rule(name: $"u{i}", protocol: "UDP", localPort: "Any"))
            .ToList();
        var f = CheckRules(new FirewallState { InboundRules = rules });
        Assert.False(Has(f, Severity.Warning, "Rules Allowing All TCP Ports"));
    }

    // ── Wide-open inbound rules (net-new) ─────────────────────────────────────────

    [Fact]
    public void WideOpen_AnyPortAnyIpAnyProgram_Warns()
    {
        var f = CheckWideOpenInboundRules(new FirewallState
        {
            InboundRules = new() { Rule(name: "OpenHole", localPort: "Any", remoteIp: "Any", program: "Any") },
            CurrentProfileName = "Public",
        });
        Assert.True(Has(f, Severity.Warning, "Wide-Open Inbound Allow Rule"));
        Assert.Contains(f, x => x.Description.Contains("OpenHole"));
        Assert.Contains(f, x => x.Description.Contains("current profile: Public"));
    }

    [Fact]
    public void WideOpen_BlankScopeFields_TreatedAsAny()
    {
        // netsh omits an unset scope field entirely → blank must count as "Any".
        var f = CheckWideOpenInboundRules(new FirewallState
        {
            InboundRules = new() { Rule(name: "Blanks", localPort: "", remoteIp: "", program: "") },
        });
        Assert.True(Has(f, Severity.Warning, "Wide-Open Inbound Allow Rule"));
    }

    [Fact]
    public void WideOpen_ScopedRule_NotFlagged()
    {
        // Any port + any IP, but scoped to a specific program ⇒ not wide open.
        var f = CheckWideOpenInboundRules(new FirewallState
        {
            InboundRules = new() { Rule(localPort: "Any", remoteIp: "Any", program: @"C:\nginx.exe") },
        });
        Assert.Empty(f);
    }

    [Fact]
    public void WideOpen_ScopedRemoteIp_NotFlagged()
    {
        var f = CheckWideOpenInboundRules(new FirewallState
        {
            InboundRules = new() { Rule(localPort: "Any", remoteIp: "10.0.0.0/8", program: "Any") },
        });
        Assert.Empty(f);
    }

    [Fact]
    public void WideOpen_DisabledOrBlockRule_NotFlagged()
    {
        var f = CheckWideOpenInboundRules(new FirewallState
        {
            InboundRules = new()
            {
                Rule(name: "off", enabled: false, localPort: "Any", remoteIp: "Any", program: "Any"),
                Rule(name: "block", action: "Block", localPort: "Any", remoteIp: "Any", program: "Any"),
            },
        });
        Assert.Empty(f);
    }

    [Fact]
    public void WideOpen_NotQueried_EmitsNothing()
    {
        var f = CheckWideOpenInboundRules(new FirewallState { RulesQueried = false });
        Assert.Empty(f);
    }

    [Fact]
    public void WideOpen_CountAndSampleCappedAtThree()
    {
        var rules = Enumerable.Range(0, 5)
            .Select(i => Rule(name: $"hole{i}", localPort: "Any", remoteIp: "Any", program: "Any"))
            .ToList();
        var f = CheckWideOpenInboundRules(new FirewallState { InboundRules = rules });
        var warn = Assert.Single(f);
        Assert.Contains("(5)", warn.Title);       // full count in the title
        Assert.Contains("hole0", warn.Description); // first few named
        Assert.DoesNotContain("hole4", warn.Description); // capped at three
    }

    // ── Default inbound policy ────────────────────────────────────────────────────

    [Fact]
    public void DefaultInbound_Block_Passes()
    {
        var f = CheckInboundDefault(new FirewallState { DefaultInboundBlock = Toggle.Enabled });
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
    }

    [Fact]
    public void DefaultInbound_Allow_IsCritical()
    {
        var f = CheckInboundDefault(new FirewallState { DefaultInboundBlock = Toggle.Disabled });
        Assert.NotNull(f);
        Assert.Equal(Severity.Critical, f!.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void DefaultInbound_Unknown_ReturnsNull() =>
        Assert.Null(CheckInboundDefault(new FirewallState { DefaultInboundBlock = Toggle.Unknown }));

    // ── netsh parsing ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("State                                 ON", Toggle.Enabled)]
    [InlineData("State                                 OFF", Toggle.Disabled)]
    [InlineData("", Toggle.Unknown)]
    [InlineData(null, Toggle.Unknown)]
    public void ParseProfileState_Classifies(string? input, Toggle expected) =>
        Assert.Equal(expected, ParseProfileState(input));

    [Theory]
    [InlineData("BlockInbound,AllowOutbound", Toggle.Enabled)]
    [InlineData("AllowInbound,AllowOutbound", Toggle.Disabled)]
    [InlineData("", Toggle.Unknown)]
    [InlineData(null, Toggle.Unknown)]
    public void ParseDefaultInbound_Classifies(string? input, Toggle expected) =>
        Assert.Equal(expected, ParseDefaultInbound(input));

    [Fact]
    public void ParseNetshRuleBlock_ExtractsKeyValuePairs()
    {
        var block =
            "Rule Name:                            Allow Web\r\n" +
            "----------------------------------------\r\n" +
            "Enabled:                              Yes\r\n" +
            "Action:                               Allow\r\n" +
            "Protocol:                             TCP\r\n" +
            "LocalPort:                            443\r\n";
        var fields = ParseNetshRuleBlock(block);
        Assert.Equal("Allow Web", fields["Rule Name"]);
        Assert.Equal("Yes", fields["Enabled"]);
        Assert.Equal("443", fields["LocalPort"]);
        // separator line must not become a field
        Assert.False(fields.ContainsKey("---"));
    }

    [Fact]
    public void ParseNetshRuleBlock_KeysAreCaseInsensitive()
    {
        var fields = ParseNetshRuleBlock("Action:                               Allow");
        Assert.Equal("Allow", fields["action"]);
        Assert.Equal("Allow", fields["ACTION"]);
    }

    [Fact]
    public void ParseRules_ParsesMultipleRuleBlocks()
    {
        var dump =
            "Rule Name:                            Web\r\n" +
            "Enabled:                              Yes\r\n" +
            "Action:                               Allow\r\n" +
            "Protocol:                             TCP\r\n" +
            "LocalPort:                            443\r\n" +
            "RemoteIP:                             Any\r\n" +
            "Program:                              C:\\web.exe\r\n" +
            "\r\n" +
            "Rule Name:                            Hole\r\n" +
            "Enabled:                              Yes\r\n" +
            "Action:                               Allow\r\n" +
            "Protocol:                             TCP\r\n" +
            "LocalPort:                            Any\r\n" +
            "RemoteIP:                             Any\r\n" +
            "Program:                              Any\r\n";

        var rules = ParseRules(dump);
        Assert.Equal(2, rules.Count);

        var web = rules[0];
        Assert.Equal("Web", web.Name);
        Assert.True(web.IsEnabledAllow);
        Assert.False(web.IsWideOpenInboundAllow);   // scoped to a program

        var hole = rules[1];
        Assert.True(hole.IsWideOpenInboundAllow);    // scopes nothing
    }

    [Fact]
    public void ParseRules_SkipsBlocksWithoutRuleName()
    {
        // A banner block with no "Rule Name:" must not become a rule.
        var dump =
            "Windows Defender Firewall Rules\r\n" +
            "-------------------------------\r\n" +
            "\r\n" +
            "Rule Name:                            Real\r\n" +
            "Enabled:                              Yes\r\n" +
            "Action:                               Allow\r\n";
        var rules = ParseRules(dump);
        var only = Assert.Single(rules);
        Assert.Equal("Real", only.Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void ParseRules_EmptyInput_ReturnsEmpty(string? input) =>
        Assert.Empty(ParseRules(input));

    // ── FirewallRule scope semantics ──────────────────────────────────────────────

    [Fact]
    public void FirewallRule_WideOpen_RequiresEnabledAllow()
    {
        Assert.False(new FirewallRule
        {
            Enabled = false, Action = "Allow", LocalPort = "Any", RemoteIp = "Any", Program = "Any",
        }.IsWideOpenInboundAllow);

        Assert.True(new FirewallRule
        {
            Enabled = true, Action = "allow", LocalPort = "any", RemoteIp = "ANY", Program = "Any",
        }.IsWideOpenInboundAllow);
    }

    // ── Dropped-packet logging (CIS L1) ─────────────────────────────────────

    [Fact]
    public void CheckLoggingDroppedPackets_Enabled_Passes()
    {
        var state = new FirewallState
        {
            Profiles = new() { new FirewallProfile("Public", Toggle.Enabled, Toggle.Enabled) },
        };
        var f = CheckLoggingDroppedPackets(state);
        Assert.True(Has(f, Severity.Pass, "Logs Dropped Packets"));
        Assert.DoesNotContain(f, x => x.Severity == Severity.Warning);
    }

    [Fact]
    public void CheckLoggingDroppedPackets_Disabled_WarnsWithFix()
    {
        var state = new FirewallState
        {
            Profiles = new() { new FirewallProfile("Public", Toggle.Enabled, Toggle.Disabled) },
        };
        var f = CheckLoggingDroppedPackets(state);
        var warn = Assert.Single(f);
        Assert.Equal(Severity.Warning, warn.Severity);
        Assert.Contains("Not Logging Dropped Packets", warn.Title);
        Assert.False(string.IsNullOrWhiteSpace(warn.Remediation));
        Assert.Contains("logging droppedconnections enable", warn.FixCommand ?? "");
        Assert.Contains("publicprofile", warn.FixCommand ?? "");
    }

    [Fact]
    public void CheckLoggingDroppedPackets_Unknown_EmitsNothing()
    {
        var state = new FirewallState
        {
            Profiles = new() { new FirewallProfile("Public", Toggle.Enabled, Toggle.Unknown) },
        };
        Assert.Empty(CheckLoggingDroppedPackets(state));
    }

    [Fact]
    public void Analyze_ProfileWithLoggingDisabled_SurfacesWarning()
    {
        var state = SecureState();
        state.Profiles = new()
        {
            new FirewallProfile("Domain", Toggle.Enabled, Toggle.Enabled),
            new FirewallProfile("Private", Toggle.Enabled, Toggle.Enabled),
            new FirewallProfile("Public", Toggle.Enabled, Toggle.Disabled),
        };
        Assert.True(Has(Analyze(state), Severity.Warning, "Not Logging Dropped Packets"));
    }

    [Theory]
    [InlineData("LogDroppedConnections                  Enable", true)]
    [InlineData("LogDroppedConnections   Enable\r\nLogAllowedConnections   Disable", true)]
    [InlineData("LogDroppedConnections                  Disable", false)]
    public void ParseLogDroppedConnections_ReadsValue(string dump, bool expectEnabled)
    {
        var expected = expectEnabled ? Toggle.Enabled : Toggle.Disabled;
        Assert.Equal(expected, ParseLogDroppedConnections(dump));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("LogAllowedConnections   Enable")]
    public void ParseLogDroppedConnections_MissingOrEmpty_IsUnknown(string? dump) =>
        Assert.Equal(Toggle.Unknown, ParseLogDroppedConnections(dump));
}
