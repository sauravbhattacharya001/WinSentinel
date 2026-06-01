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
}
