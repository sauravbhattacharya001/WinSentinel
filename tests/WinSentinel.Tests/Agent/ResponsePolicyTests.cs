using WinSentinel.Agent;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

public class ResponsePolicyTests
{
    private static ResponsePolicy CreatePolicy(RiskTolerance risk = RiskTolerance.Medium)
    {
        return ResponsePolicy.CreateDefault(risk);
    }

    // ── Default severity-based policy tests ──

    [Theory]
    [InlineData(ThreatSeverity.Critical, RiskTolerance.Low, ResponseAction.AutoFix)]
    [InlineData(ThreatSeverity.Critical, RiskTolerance.Medium, ResponseAction.Alert)]
    [InlineData(ThreatSeverity.Critical, RiskTolerance.High, ResponseAction.Alert)]
    [InlineData(ThreatSeverity.High, RiskTolerance.Low, ResponseAction.Alert)]
    [InlineData(ThreatSeverity.High, RiskTolerance.Medium, ResponseAction.Alert)]
    [InlineData(ThreatSeverity.High, RiskTolerance.High, ResponseAction.Log)]
    [InlineData(ThreatSeverity.Medium, RiskTolerance.Medium, ResponseAction.Log)]
    [InlineData(ThreatSeverity.Low, RiskTolerance.Medium, ResponseAction.Log)]
    [InlineData(ThreatSeverity.Info, RiskTolerance.Medium, ResponseAction.Log)]
    public void DefaultPolicy_ReturnsCorrectAction(ThreatSeverity severity, RiskTolerance risk, ResponseAction expected)
    {
        var policy = CreatePolicy(risk);
        var threat = new ThreatEvent
        {
            Source = "TestModule",
            Severity = severity,
            Title = "Test Threat",
            AutoFixable = true
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(expected, decision.Action);
    }

    [Fact]
    public void DefaultPolicy_AutoFixAllowed_OnlyWhenThreatIsAutoFixable()
    {
        var policy = CreatePolicy(RiskTolerance.Low);
        var threat = new ThreatEvent
        {
            Source = "TestModule",
            Severity = ThreatSeverity.Critical,
            Title = "Test Threat",
            AutoFixable = false // Not fixable!
        };

        var decision = policy.Evaluate(threat);
        // Even though policy says AutoFix, the threat isn't fixable
        Assert.False(decision.AutoFixAllowed);
    }

    // ── Correlation category escalation ──

    [Fact]
    public void CorrelationCategory_AlwaysEscalated()
    {
        var policy = CreatePolicy();
        var threat = new ThreatEvent
        {
            Source = "ThreatCorrelator",
            Severity = ThreatSeverity.Medium,
            Title = "Correlated Threat"
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(ResponseAction.Escalate, decision.Action);
    }

    // ── Custom rules ──

    [Fact]
    public void CustomRule_OverridesDefault()
    {
        var policy = CreatePolicy();
        policy.Rules.Add(new PolicyRule
        {
            Category = ThreatCategory.Process,
            Severity = ThreatSeverity.Medium,
            Action = ResponseAction.Alert,
            Priority = 50
        });

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Process"
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(ResponseAction.Alert, decision.Action);
    }

    [Fact]
    public void CustomRule_HigherPriorityWins()
    {
        var policy = CreatePolicy();
        policy.Rules.Add(new PolicyRule
        {
            Category = ThreatCategory.Process,
            Action = ResponseAction.Log,
            Priority = 10
        });
        policy.Rules.Add(new PolicyRule
        {
            Category = ThreatCategory.Process,
            Action = ResponseAction.Escalate,
            Priority = 50
        });

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Test"
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(ResponseAction.Escalate, decision.Action);
    }

    [Fact]
    public void CustomRule_TitlePattern_MatchesContains()
    {
        var policy = CreatePolicy();
        policy.Rules.Add(new PolicyRule
        {
            TitlePattern = "Encoded PowerShell",
            Action = ResponseAction.AutoFix,
            AllowAutoFix = true,
            Priority = 50
        });

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Encoded PowerShell Command",
            AutoFixable = true
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(ResponseAction.AutoFix, decision.Action);
        Assert.True(decision.AutoFixAllowed);
    }

    // ── User overrides ──

    [Fact]
    public void UserOverride_AlwaysIgnore_ReturnsLog()
    {
        var policy = CreatePolicy();
        policy.AddUserOverride("LOLBin Execution Detected", UserOverrideAction.AlwaysIgnore);

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.High,
            Title = "LOLBin Execution Detected"
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(ResponseAction.Log, decision.Action);
        Assert.True(decision.UserOverrideApplied);
    }

    [Fact]
    public void UserOverride_AlwaysAutoFix_ReturnsAutoFix()
    {
        var policy = CreatePolicy();
        policy.AddUserOverride("Suspicious Script Created", UserOverrideAction.AlwaysAutoFix, "FileSystemMonitor");

        var threat = new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Script Created",
            AutoFixable = true
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(ResponseAction.AutoFix, decision.Action);
        Assert.True(decision.UserOverrideApplied);
    }

    [Fact]
    public void UserOverride_SourceMismatch_NotApplied()
    {
        var policy = CreatePolicy();
        policy.AddUserOverride("Test Threat", UserOverrideAction.AlwaysIgnore, "ProcessMonitor");

        var threat = new ThreatEvent
        {
            Source = "FileSystemMonitor", // Different source
            Severity = ThreatSeverity.High,
            Title = "Test Threat"
        };

        var decision = policy.Evaluate(threat);
        Assert.False(decision.UserOverrideApplied); // Override should NOT apply
    }

    [Fact]
    public void UserOverride_NoSource_MatchesAll()
    {
        var policy = CreatePolicy();
        policy.AddUserOverride("Test Threat", UserOverrideAction.AlwaysIgnore); // No source = match all

        var threat = new ThreatEvent
        {
            Source = "AnyModule",
            Severity = ThreatSeverity.High,
            Title = "Test Threat"
        };

        var decision = policy.Evaluate(threat);
        Assert.True(decision.UserOverrideApplied);
    }

    [Fact]
    public void RemoveUserOverride_Works()
    {
        var policy = CreatePolicy();
        policy.AddUserOverride("Test", UserOverrideAction.AlwaysIgnore);
        Assert.Single(policy.UserOverrides);

        var removed = policy.RemoveUserOverride("Test");
        Assert.True(removed);
        Assert.Empty(policy.UserOverrides);
    }

    // ── Category classification ──

    [Theory]
    [InlineData("ProcessMonitor", ThreatCategory.Process)]
    [InlineData("FileSystemMonitor", ThreatCategory.File)]
    [InlineData("EventLogMonitor", ThreatCategory.EventLog)]
    [InlineData("ThreatCorrelator", ThreatCategory.Correlation)]
    [InlineData("NetworkMonitor", ThreatCategory.Network)]
    [InlineData("SomeRandomThing", ThreatCategory.Unknown)]
    public void ClassifyCategory_ReturnsCorrectCategory(string source, ThreatCategory expected)
    {
        Assert.Equal(expected, ResponsePolicy.ClassifyCategory(source));
    }

    // ── Audit log cleared always escalates ──

    [Fact]
    public void AuditLogCleared_AlwaysEscalated()
    {
        var policy = CreatePolicy(RiskTolerance.High);
        var threat = new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Audit Log Cleared"
        };

        var decision = policy.Evaluate(threat);
        Assert.Equal(ResponseAction.Escalate, decision.Action);
    }
}
