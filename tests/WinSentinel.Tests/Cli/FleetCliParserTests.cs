using Xunit;
using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Parser coverage for the <c>fleet</c> command surface (Pro-only fleet orchestration).
/// </summary>
public class FleetCliParserTests
{
    [Fact]
    public void Bare_Fleet_Defaults_To_Help()
    {
        var opts = CliParser.Parse(new[] { "fleet" });
        Assert.Null(opts.Error);
        Assert.Equal(CliCommand.Fleet, opts.Command);
        Assert.Equal(FleetAction.Help, opts.FleetAction);
    }

    [Theory]
    [InlineData("status", FleetAction.Status)]
    [InlineData("scan-all", FleetAction.ScanAll)]
    [InlineData("scan", FleetAction.ScanAll)]
    [InlineData("push-policy", FleetAction.PushPolicy)]
    [InlineData("nodes", FleetAction.Nodes)]
    [InlineData("commands", FleetAction.Commands)]
    [InlineData("history", FleetAction.Commands)]
    [InlineData("help", FleetAction.Help)]
    public void Fleet_Subcommands_Map_Correctly(string sub, FleetAction expected)
    {
        var opts = CliParser.Parse(new[] { "fleet", sub });
        Assert.Null(opts.Error);
        Assert.Equal(CliCommand.Fleet, opts.Command);
        Assert.Equal(expected, opts.FleetAction);
    }

    [Fact]
    public void Fleet_Endpoint_Option_Parsed()
    {
        var opts = CliParser.Parse(new[] { "fleet", "status", "--fleet-endpoint", "https://custom.example.com/fleet" });
        Assert.Equal(CliCommand.Fleet, opts.Command);
        Assert.Equal(FleetAction.Status, opts.FleetAction);
        Assert.Equal("https://custom.example.com/fleet", opts.FleetEndpoint);
    }

    [Fact]
    public void Fleet_Nodes_Option_Parsed()
    {
        var opts = CliParser.Parse(new[] { "fleet", "scan-all", "--nodes", "node-01,node-02" });
        Assert.Equal(FleetAction.ScanAll, opts.FleetAction);
        Assert.Equal("node-01,node-02", opts.FleetTargetNodes);
    }

    [Fact]
    public void Fleet_PushPolicy_File_Option_Parsed()
    {
        var opts = CliParser.Parse(new[] { "fleet", "push-policy", "--file", "policy.json" });
        Assert.Equal(FleetAction.PushPolicy, opts.FleetAction);
        Assert.Equal("policy.json", opts.FleetPolicyFile);
    }

    [Fact]
    public void Fleet_Json_Output_Flag()
    {
        var opts = CliParser.Parse(new[] { "fleet", "nodes", "--json" });
        Assert.Equal(CliCommand.Fleet, opts.Command);
        Assert.Equal(FleetAction.Nodes, opts.FleetAction);
        Assert.True(opts.Json);
    }

    [Fact]
    public void Fleet_With_License_Key()
    {
        var opts = CliParser.Parse(new[] { "fleet", "status", "--license", "WSP-AAAA-BBBB-CCCC" });
        Assert.Equal(CliCommand.Fleet, opts.Command);
        Assert.Equal("WSP-AAAA-BBBB-CCCC", opts.TransientLicenseKey);
    }

    // ─── commands / history view ─────────────────────────────────────

    [Fact]
    public void Fleet_Commands_Status_Filter_Parsed()
    {
        var opts = CliParser.Parse(new[] { "fleet", "commands", "--fleet-status", "failed" });
        Assert.Null(opts.Error);
        Assert.Equal(FleetAction.Commands, opts.FleetAction);
        Assert.Equal("failed", opts.FleetStatusFilter);
    }

    [Fact]
    public void Fleet_Commands_Status_Filter_Alias_Parsed()
    {
        var opts = CliParser.Parse(new[] { "fleet", "commands", "--command-status", "completed" });
        Assert.Equal("completed", opts.FleetStatusFilter);
    }

    [Fact]
    public void Fleet_Commands_Limit_Parsed_And_Routes_To_FleetLimit()
    {
        // Inside a fleet command, --limit fills FleetLimit (not HistoryLimit) and allows up to 200.
        var opts = CliParser.Parse(new[] { "fleet", "commands", "--limit", "150" });
        Assert.Null(opts.Error);
        Assert.Equal(FleetAction.Commands, opts.FleetAction);
        Assert.Equal(150, opts.FleetLimit);
        // HistoryLimit keeps its default; the fleet redirect must not touch it.
        Assert.Equal(20, opts.HistoryLimit);
    }

    [Fact]
    public void Fleet_Commands_Limit_Rejects_Above_200()
    {
        var opts = CliParser.Parse(new[] { "fleet", "commands", "--limit", "500" });
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void Fleet_Commands_Node_And_Json_And_Status_Combined()
    {
        var opts = CliParser.Parse(new[]
        {
            "fleet", "commands", "--nodes", "node-01", "--fleet-status", "completed", "--limit", "20", "--json"
        });
        Assert.Null(opts.Error);
        Assert.Equal(FleetAction.Commands, opts.FleetAction);
        Assert.Equal("node-01", opts.FleetTargetNodes);
        Assert.Equal("completed", opts.FleetStatusFilter);
        Assert.Equal(20, opts.FleetLimit);
        Assert.True(opts.Json);
    }

    [Fact]
    public void NonFleet_Limit_Still_Routes_To_HistoryLimit()
    {
        // Regression guard: the fleet-scoped --limit redirect must not affect other commands.
        var opts = CliParser.Parse(new[] { "--history", "--limit", "25" });
        Assert.Null(opts.Error);
        Assert.Equal(CliCommand.History, opts.Command);
        Assert.Equal(25, opts.HistoryLimit);
        Assert.Null(opts.FleetLimit);
    }
}
