using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using System.Text.Json;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for <see cref="SarifExporter"/> — SARIF v2.1.0 report generation.
/// </summary>
public class SarifExporterTests
{
    private readonly SarifExporter _exporter = new();

    // ──────────── Helpers ────────────

    private static SecurityReport CreateReport(params AuditResult[] results)
    {
        var report = new SecurityReport
        {
            Results = results.ToList(),
            GeneratedAt = new DateTimeOffset(2026, 2, 22, 12, 0, 0, TimeSpan.Zero),
            SecurityScore = 75
        };
        return report;
    }

    private static AuditResult CreateAuditResult(string moduleName, string category,
        params Finding[] findings)
    {
        return new AuditResult
        {
            ModuleName = moduleName,
            Category = category,
            Findings = findings.ToList(),
            Success = true,
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-1),
            EndTime = DateTimeOffset.UtcNow
        };
    }

    private static AuditResult CreateFailedAuditResult(string moduleName, string category, string error)
    {
        return new AuditResult
        {
            ModuleName = moduleName,
            Category = category,
            Findings = new List<Finding>(),
            Success = false,
            Error = error,
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-1),
            EndTime = DateTimeOffset.UtcNow
        };
    }

    private static JsonElement ParseJson(string json)
    {
        return JsonDocument.Parse(json).RootElement;
    }

    // ──────────── Basic structure ────────────

    [Fact]
    public void GenerateSarif_EmptyReport_ProducesValidStructure()
    {
        var report = CreateReport();
        var sarif = _exporter.GenerateSarif(report);
        var doc = ParseJson(sarif);

        Assert.Equal("2.1.0", doc.GetProperty("version").GetString());
        Assert.True(doc.TryGetProperty("$schema", out var schema));
        Assert.Contains("sarif-schema-2.1.0", schema.GetString());
        Assert.Equal(1, doc.GetProperty("runs").GetArrayLength());
    }

    [Fact]
    public void GenerateSarif_NullReport_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => _exporter.GenerateSarif(null!));
    }

    [Fact]
    public void GenerateSarif_EmptyReport_HasToolInfo()
    {
        var report = CreateReport();
        var doc = ParseJson(_exporter.GenerateSarif(report));
        var driver = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver");

        Assert.Equal("WinSentinel", driver.GetProperty("name").GetString());
        Assert.Equal("1.1.0", driver.GetProperty("version").GetString());
        Assert.Contains("WinSentinel", driver.GetProperty("informationUri").GetString()!);
    }

    [Fact]
    public void GenerateSarif_EmptyReport_HasSecurityScoreProperty()
    {
        var report = CreateReport();
        report.SecurityScore = 85;
        var doc = ParseJson(_exporter.GenerateSarif(report));
        var driver = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver");
        var props = driver.GetProperty("properties");

        Assert.Equal(85, props.GetProperty("securityScore").GetInt32());
        Assert.Equal("B", props.GetProperty("grade").GetString());
    }

    [Fact]
    public void GenerateSarif_EmptyReport_HasEmptyResults()
    {
        var report = CreateReport();
        var doc = ParseJson(_exporter.GenerateSarif(report));
        var results = doc.GetProperty("runs")[0].GetProperty("results");

        Assert.Equal(0, results.GetArrayLength());
    }

    // ──────────── Results ────────────

    [Fact]
    public void GenerateSarif_CriticalFinding_MapsToError()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Critical("Firewall Disabled", "Windows Firewall is off", "Firewall",
                    remediation: "Enable firewall", fixCommand: "netsh advfirewall set allprofiles state on")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var result = doc.GetProperty("runs")[0].GetProperty("results")[0];

        Assert.Equal("error", result.GetProperty("level").GetString());
        Assert.StartsWith("WSFW/", result.GetProperty("ruleId").GetString());
        Assert.Contains("firewall-disabled", result.GetProperty("ruleId").GetString());
        Assert.Equal("Windows Firewall is off", result.GetProperty("message").GetProperty("text").GetString());
    }

    [Fact]
    public void GenerateSarif_WarningFinding_MapsToWarning()
    {
        var report = CreateReport(
            CreateAuditResult("UpdateAudit", "Windows Update",
                Finding.Warning("Updates Pending", "3 updates available", "Updates")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var result = doc.GetProperty("runs")[0].GetProperty("results")[0];

        Assert.Equal("warning", result.GetProperty("level").GetString());
    }

    [Fact]
    public void GenerateSarif_InfoFinding_MapsToNote()
    {
        var report = CreateReport(
            CreateAuditResult("SystemAudit", "System",
                Finding.Info("OS Version", "Windows 11 23H2", "System")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var result = doc.GetProperty("runs")[0].GetProperty("results")[0];

        Assert.Equal("note", result.GetProperty("level").GetString());
    }

    [Fact]
    public void GenerateSarif_PassFinding_ExcludedByDefault()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Pass("Firewall Enabled", "Firewall is active", "Firewall"),
                Finding.Warning("Rule Gap", "Outbound not filtered", "Firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var results = doc.GetProperty("runs")[0].GetProperty("results");

        Assert.Equal(1, results.GetArrayLength());
        Assert.Equal("warning", results[0].GetProperty("level").GetString());
    }

    [Fact]
    public void GenerateSarif_PassFinding_IncludedWhenRequested()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Pass("Firewall Enabled", "Firewall is active", "Firewall"),
                Finding.Warning("Rule Gap", "Outbound not filtered", "Firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report, includePassFindings: true));
        var results = doc.GetProperty("runs")[0].GetProperty("results");

        Assert.Equal(2, results.GetArrayLength());
    }

    // ──────────── Rules ────────────

    [Fact]
    public void GenerateSarif_CreatesDedupedRules()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Warning("Open Port", "Port 22 open", "Firewall"),
                Finding.Warning("Open Port", "Port 80 open", "Firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var rules = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules");

        // Same title → same rule ID → deduped to 1 rule
        Assert.Equal(1, rules.GetArrayLength());
        // But 2 results still
        Assert.Equal(2, doc.GetProperty("runs")[0].GetProperty("results").GetArrayLength());
    }

    [Fact]
    public void GenerateSarif_RuleHasFullDescription()
    {
        var report = CreateReport(
            CreateAuditResult("DefenderAudit", "Windows Defender",
                Finding.Critical("Defender Disabled", "Real-time protection is off", "Defender",
                    remediation: "Enable real-time protection")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var rule = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0];

        Assert.Equal("Defender Disabled", rule.GetProperty("name").GetString());
        Assert.Equal("Defender Disabled", rule.GetProperty("shortDescription").GetProperty("text").GetString());
        Assert.Equal("Real-time protection is off", rule.GetProperty("fullDescription").GetProperty("text").GetString());
    }

    [Fact]
    public void GenerateSarif_RuleHasHelp_WhenRemediationPresent()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Critical("FW Off", "Firewall disabled", "Firewall",
                    remediation: "Turn on the firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var rule = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0];

        Assert.True(rule.TryGetProperty("help", out var help));
        Assert.Equal("Turn on the firewall", help.GetProperty("text").GetString());
        Assert.Contains("Remediation", help.GetProperty("markdown").GetString()!);
    }

    [Fact]
    public void GenerateSarif_RuleHasNoHelp_WhenNoRemediation()
    {
        var report = CreateReport(
            CreateAuditResult("SystemAudit", "System",
                Finding.Info("OS Info", "Windows 11", "System")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var rule = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0];

        Assert.False(rule.TryGetProperty("help", out _));
    }

    // ──────────── Locations ────────────

    [Fact]
    public void GenerateSarif_ResultHasLogicalLocation()
    {
        var report = CreateReport(
            CreateAuditResult("NetworkAudit", "Network Security",
                Finding.Warning("Open Port", "Port 445 open", "Network")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var location = doc.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("locations")[0].GetProperty("logicalLocations")[0];

        Assert.Equal("Network Security", location.GetProperty("name").GetString());
        Assert.Equal("module", location.GetProperty("kind").GetString());
        Assert.Equal("WinSentinel/NetworkAudit", location.GetProperty("fullyQualifiedName").GetString());
    }

    // ──────────── Fixes ────────────

    [Fact]
    public void GenerateSarif_ResultHasFix_WhenRemediationPresent()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Critical("FW Off", "Firewall disabled", "Firewall",
                    remediation: "Enable it", fixCommand: "netsh advfirewall set allprofiles state on")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var result = doc.GetProperty("runs")[0].GetProperty("results")[0];
        var fix = result.GetProperty("fixes")[0];

        Assert.Contains("Enable it", fix.GetProperty("description").GetProperty("text").GetString()!);
        Assert.Contains("netsh", fix.GetProperty("description").GetProperty("text").GetString()!);
    }

    [Fact]
    public void GenerateSarif_ResultHasNoFix_WhenNoRemediation()
    {
        var report = CreateReport(
            CreateAuditResult("SystemAudit", "System",
                Finding.Info("OS Version", "Windows 11", "System")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var result = doc.GetProperty("runs")[0].GetProperty("results")[0];

        Assert.False(result.TryGetProperty("fixes", out _));
    }

    // ──────────── Invocations ────────────

    [Fact]
    public void GenerateSarif_SuccessfulInvocation()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Pass("FW OK", "Firewall is on", "Firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var invocation = doc.GetProperty("runs")[0].GetProperty("invocations")[0];

        Assert.True(invocation.GetProperty("executionSuccessful").GetBoolean());
        Assert.True(invocation.TryGetProperty("startTimeUtc", out _));
        Assert.True(invocation.TryGetProperty("endTimeUtc", out _));
    }

    [Fact]
    public void GenerateSarif_FailedModule_ReportsNotifications()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Pass("FW OK", "Active", "Firewall")),
            CreateFailedAuditResult("DefenderAudit", "Windows Defender", "Access denied"));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var invocation = doc.GetProperty("runs")[0].GetProperty("invocations")[0];

        Assert.False(invocation.GetProperty("executionSuccessful").GetBoolean());
        var notifications = invocation.GetProperty("toolExecutionNotifications");
        Assert.Equal(1, notifications.GetArrayLength());
        Assert.Contains("Access denied", notifications[0].GetProperty("message").GetProperty("text").GetString()!);
        Assert.Equal("error", notifications[0].GetProperty("level").GetString());
    }

    [Fact]
    public void GenerateSarif_AllModulesSucceed_NoNotifications()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Pass("FW OK", "Active", "Firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var invocation = doc.GetProperty("runs")[0].GetProperty("invocations")[0];

        Assert.False(invocation.TryGetProperty("toolExecutionNotifications", out _));
    }

    [Fact]
    public void GenerateSarif_InvocationHasMetadata()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Critical("FW Off", "Disabled", "Firewall"),
                Finding.Warning("Gap", "Outbound open", "Firewall"),
                Finding.Info("Ver", "v2", "Firewall"),
                Finding.Pass("Rules", "OK", "Firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var props = doc.GetProperty("runs")[0].GetProperty("invocations")[0].GetProperty("properties");

        Assert.Equal(1, props.GetProperty("totalModules").GetInt32());
        Assert.Equal(4, props.GetProperty("totalFindings").GetInt32());
        Assert.Equal(1, props.GetProperty("criticalCount").GetInt32());
        Assert.Equal(1, props.GetProperty("warningCount").GetInt32());
        Assert.Equal(1, props.GetProperty("infoCount").GetInt32());
        Assert.Equal(1, props.GetProperty("passCount").GetInt32());
    }

    // ──────────── AutomationDetails ────────────

    [Fact]
    public void GenerateSarif_HasAutomationDetails()
    {
        var report = CreateReport();
        var doc = ParseJson(_exporter.GenerateSarif(report));
        var automation = doc.GetProperty("runs")[0].GetProperty("automationDetails");

        Assert.True(automation.TryGetProperty("id", out var id));
        Assert.Contains("WinSentinel/", id.GetString());
        Assert.True(automation.TryGetProperty("description", out _));
    }

    // ──────────── Rule ID generation ────────────

    [Fact]
    public void GenerateRuleId_ProducesConsistentIds()
    {
        var id1 = SarifExporter.GenerateRuleId("Firewall", "Firewall Disabled");
        var id2 = SarifExporter.GenerateRuleId("Firewall", "Firewall Disabled");
        Assert.Equal(id1, id2);
    }

    [Fact]
    public void GenerateRuleId_DifferentCategories_DifferentIds()
    {
        var id1 = SarifExporter.GenerateRuleId("Firewall", "Something");
        var id2 = SarifExporter.GenerateRuleId("Network", "Something");
        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void GenerateRuleId_ContainsCategoryCode()
    {
        var id = SarifExporter.GenerateRuleId("Firewall", "Test Finding");
        Assert.StartsWith("WSFW/", id);
    }

    [Fact]
    public void GenerateRuleId_NormalizesTitle()
    {
        var id = SarifExporter.GenerateRuleId("Firewall", "Windows Firewall Is Disabled!");
        Assert.Equal("WSFW/windows-firewall-is-disabled", id);
    }

    // ──────────── Category codes ────────────

    [Theory]
    [InlineData("Firewall", "FW")]
    [InlineData("Windows Defender", "DF")]
    [InlineData("Defender", "DF")]
    [InlineData("Windows Update", "UP")]
    [InlineData("Updates", "UP")]
    [InlineData("User Accounts", "UA")]
    [InlineData("Accounts", "UA")]
    [InlineData("Encryption", "EN")]
    [InlineData("Network", "NW")]
    [InlineData("Network Security", "NW")]
    [InlineData("Browser Security", "BR")]
    [InlineData("Browser", "BR")]
    [InlineData("Privacy", "PV")]
    [InlineData("Process Security", "PS")]
    [InlineData("Processes", "PS")]
    [InlineData("Startup Programs", "ST")]
    [InlineData("Startup", "ST")]
    [InlineData("System Configuration", "SY")]
    [InlineData("System", "SY")]
    [InlineData("Event Log", "EL")]
    [InlineData("Event Logging", "EL")]
    [InlineData("Application Security", "AP")]
    [InlineData("Applications", "AP")]
    public void GetCategoryCode_MapsKnownCategories(string category, string expected)
    {
        Assert.Equal(expected, SarifExporter.GetCategoryCode(category));
    }

    [Fact]
    public void GetCategoryCode_UnknownCategory_UsesTwoChars()
    {
        Assert.Equal("CU", SarifExporter.GetCategoryCode("Custom Module"));
    }

    [Fact]
    public void GetCategoryCode_SingleCharCategory()
    {
        Assert.Equal("X", SarifExporter.GetCategoryCode("X"));
    }

    // ──────────── NormalizeForId ────────────

    [Fact]
    public void NormalizeForId_ConvertsToLowercase()
    {
        Assert.Equal("hello-world", SarifExporter.NormalizeForId("Hello World"));
    }

    [Fact]
    public void NormalizeForId_ReplacesSpecialChars()
    {
        Assert.Equal("test-finding-v2", SarifExporter.NormalizeForId("Test Finding (v2)"));
    }

    [Fact]
    public void NormalizeForId_CollapsesHyphens()
    {
        Assert.Equal("a-b", SarifExporter.NormalizeForId("a---b"));
    }

    [Fact]
    public void NormalizeForId_TrimsTrailingHyphen()
    {
        Assert.Equal("test", SarifExporter.NormalizeForId("test!"));
    }

    [Fact]
    public void NormalizeForId_EmptyString_ReturnsUnknown()
    {
        Assert.Equal("unknown", SarifExporter.NormalizeForId(""));
    }

    [Fact]
    public void NormalizeForId_NullString_ReturnsUnknown()
    {
        Assert.Equal("unknown", SarifExporter.NormalizeForId(null!));
    }

    [Fact]
    public void NormalizeForId_LongTitle_TruncatesAt60()
    {
        var longTitle = new string('a', 100);
        var result = SarifExporter.NormalizeForId(longTitle);
        Assert.Equal(60, result.Length);
    }

    // ──────────── Severity mapping ────────────

    [Theory]
    [InlineData(Severity.Critical, "error")]
    [InlineData(Severity.Warning, "warning")]
    [InlineData(Severity.Info, "note")]
    [InlineData(Severity.Pass, "none")]
    public void MapSeverityToLevel_CorrectMapping(Severity severity, string expected)
    {
        Assert.Equal(expected, SarifExporter.MapSeverityToLevel(severity));
    }

    // ──────────── Multiple modules ────────────

    [Fact]
    public void GenerateSarif_MultipleModules_AllIncluded()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Critical("FW Off", "Disabled", "Firewall")),
            CreateAuditResult("DefenderAudit", "Windows Defender",
                Finding.Warning("Scan Old", "Last scan >7d ago", "Defender")),
            CreateAuditResult("UpdateAudit", "Windows Update",
                Finding.Info("Up to date", "All updates installed", "Updates")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var results = doc.GetProperty("runs")[0].GetProperty("results");

        Assert.Equal(3, results.GetArrayLength());
    }

    [Fact]
    public void GenerateSarif_MultipleModules_DistinctRules()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Critical("FW Off", "Disabled", "Firewall")),
            CreateAuditResult("DefenderAudit", "Windows Defender",
                Finding.Critical("Defender Off", "Disabled", "Defender")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var rules = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules");

        Assert.Equal(2, rules.GetArrayLength());
        var ruleIds = new HashSet<string>();
        for (int i = 0; i < rules.GetArrayLength(); i++)
            ruleIds.Add(rules[i].GetProperty("id").GetString()!);
        Assert.Equal(2, ruleIds.Count);
    }

    // ──────────── Properties ────────────

    [Fact]
    public void GenerateSarif_ResultHasModuleProperty()
    {
        var report = CreateReport(
            CreateAuditResult("EncryptionAudit", "Encryption",
                Finding.Warning("BitLocker Off", "Drive not encrypted", "Encryption")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var props = doc.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("properties");

        Assert.Equal("EncryptionAudit", props.GetProperty("module").GetString());
        Assert.Equal("Encryption", props.GetProperty("category").GetString());
    }

    [Fact]
    public void GenerateSarif_RuleHasCategoryProperty()
    {
        var report = CreateReport(
            CreateAuditResult("NetworkAudit", "Network Security",
                Finding.Warning("Open Port", "Port 22", "Network")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var rule = doc.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0];
        var props = rule.GetProperty("properties");

        Assert.Equal("Network Security", props.GetProperty("category").GetString());
    }

    // ──────────── JSON validity ────────────

    [Fact]
    public void GenerateSarif_OutputIsValidJson()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Critical("Test <script>alert('xss')</script>",
                    "Description with \"quotes\" and\nnewlines", "Firewall")));

        var sarif = _exporter.GenerateSarif(report);

        // Should not throw
        var doc = JsonDocument.Parse(sarif);
        Assert.NotNull(doc);
    }

    [Fact]
    public void GenerateSarif_SpecialCharsInTitles_SanitizedInRuleIds()
    {
        var report = CreateReport(
            CreateAuditResult("BrowserAudit", "Browser Security",
                Finding.Warning("Chrome Extension: \"Unsafe\" v1.2.3",
                    "Potentially dangerous extension", "Browser")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var ruleId = doc.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("ruleId").GetString();

        // Rule ID should not contain special chars
        Assert.DoesNotContain("\"", ruleId);
        Assert.DoesNotContain(":", ruleId);
        Assert.StartsWith("WSBR/", ruleId);
    }

    // ──────────── Edge cases ────────────

    [Fact]
    public void GenerateSarif_OnlyPassFindings_EmptyResultsDefault()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall",
                Finding.Pass("FW On", "Active", "Firewall"),
                Finding.Pass("Rules OK", "Configured", "Firewall")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        Assert.Equal(0, doc.GetProperty("runs")[0].GetProperty("results").GetArrayLength());
    }

    [Fact]
    public void GenerateSarif_NoFindings_EmptyResults()
    {
        var report = CreateReport(
            new AuditResult { ModuleName = "Test", Category = "Test", Success = true });

        var doc = ParseJson(_exporter.GenerateSarif(report));
        Assert.Equal(0, doc.GetProperty("runs")[0].GetProperty("results").GetArrayLength());
    }

    [Fact]
    public void GenerateSarif_MixedSeverities_CorrectCounts()
    {
        var report = CreateReport(
            CreateAuditResult("Test", "Test",
                Finding.Critical("C1", "Critical 1", "Test"),
                Finding.Critical("C2", "Critical 2", "Test"),
                Finding.Warning("W1", "Warning 1", "Test"),
                Finding.Info("I1", "Info 1", "Test"),
                Finding.Pass("P1", "Pass 1", "Test")));

        // Without pass
        var doc = ParseJson(_exporter.GenerateSarif(report, includePassFindings: false));
        Assert.Equal(4, doc.GetProperty("runs")[0].GetProperty("results").GetArrayLength());

        // With pass
        doc = ParseJson(_exporter.GenerateSarif(report, includePassFindings: true));
        Assert.Equal(5, doc.GetProperty("runs")[0].GetProperty("results").GetArrayLength());
    }

    [Fact]
    public void GenerateSarif_LargeReport_HandlesGracefully()
    {
        var findings = Enumerable.Range(1, 100)
            .Select(i => Finding.Warning($"Finding {i}", $"Description {i}", "Test"))
            .ToArray();

        var report = CreateReport(CreateAuditResult("BigModule", "Test", findings));
        var sarif = _exporter.GenerateSarif(report);
        var doc = ParseJson(sarif);

        Assert.Equal(100, doc.GetProperty("runs")[0].GetProperty("results").GetArrayLength());
    }

    [Fact]
    public void GenerateSarif_RuleIndex_MatchesResultRuleIndex()
    {
        var report = CreateReport(
            CreateAuditResult("Module1", "Cat1",
                Finding.Warning("A", "Desc A", "Cat1")),
            CreateAuditResult("Module2", "Cat2",
                Finding.Critical("B", "Desc B", "Cat2")));

        var doc = ParseJson(_exporter.GenerateSarif(report));
        var run = doc.GetProperty("runs")[0];
        var rules = run.GetProperty("tool").GetProperty("driver").GetProperty("rules");
        var results = run.GetProperty("results");

        for (int i = 0; i < results.GetArrayLength(); i++)
        {
            var ruleIndex = results[i].GetProperty("ruleIndex").GetInt32();
            var ruleId = results[i].GetProperty("ruleId").GetString();
            Assert.Equal(ruleId, rules[ruleIndex].GetProperty("id").GetString());
        }
    }
}
