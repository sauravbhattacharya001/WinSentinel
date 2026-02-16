using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class FixEngineTests
{
    private readonly FixEngine _engine = new();

    [Fact]
    public async Task ExecuteFixAsync_NoFixCommand_ReturnsNoFixAvailable()
    {
        var finding = new Finding
        {
            Title = "Test Finding",
            Description = "No fix available",
            Severity = Severity.Warning,
            FixCommand = null
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.False(result.Success);
        Assert.Contains("No fix command", result.Error);
        Assert.Equal("Test Finding", result.FindingTitle);
    }

    [Fact]
    public async Task ExecuteFixAsync_EmptyFixCommand_ReturnsNoFixAvailable()
    {
        var finding = new Finding
        {
            Title = "Test Finding",
            Description = "Empty fix",
            Severity = Severity.Warning,
            FixCommand = ""
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.False(result.Success);
        Assert.Contains("No fix command", result.Error);
    }

    [Fact]
    public async Task ExecuteFixAsync_WhitespaceFixCommand_ReturnsNoFixAvailable()
    {
        var finding = new Finding
        {
            Title = "Test Finding",
            Description = "Whitespace fix",
            Severity = Severity.Warning,
            FixCommand = "   "
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task ExecuteFixAsync_DryRun_DoesNotExecute()
    {
        var finding = new Finding
        {
            Title = "Test Finding",
            Description = "Dry run test",
            Severity = Severity.Warning,
            FixCommand = "Write-Output 'This should not execute'"
        };

        var result = await _engine.ExecuteFixAsync(finding, dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.Contains("DRY RUN", result.Output);
        Assert.Contains(finding.FixCommand, result.Output);
        Assert.Equal("Test Finding", result.FindingTitle);
    }

    [Fact]
    public async Task ExecuteFixAsync_SimpleCommand_Succeeds()
    {
        var finding = new Finding
        {
            Title = "Echo Test",
            Description = "Simple echo",
            Severity = Severity.Warning,
            FixCommand = "Write-Output 'Hello from FixEngine'"
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.True(result.Success);
        Assert.Contains("Hello from FixEngine", result.Output);
        Assert.Equal(0, result.ExitCode);
        Assert.False(result.DryRun);
        Assert.Equal("Echo Test", result.FindingTitle);
    }

    [Fact]
    public async Task ExecuteFixAsync_FailingCommand_ReturnsFailure()
    {
        var finding = new Finding
        {
            Title = "Fail Test",
            Description = "This should fail",
            Severity = Severity.Critical,
            FixCommand = "exit 1"
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
    }

    [Fact]
    public async Task ExecuteFixAsync_Cancellation_ReturnsCancelled()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        var finding = new Finding
        {
            Title = "Cancel Test",
            Description = "Should be cancelled",
            Severity = Severity.Warning,
            FixCommand = "Start-Sleep 60"
        };

        var result = await _engine.ExecuteFixAsync(finding, cancellationToken: cts.Token);

        Assert.False(result.Success);
        Assert.Contains("cancelled", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExecuteFixAsync_Timeout_ReturnsTimeout()
    {
        var engine = new FixEngine { DefaultTimeout = TimeSpan.FromSeconds(2) };

        var finding = new Finding
        {
            Title = "Timeout Test",
            Description = "Should timeout",
            Severity = Severity.Warning,
            FixCommand = "Start-Sleep 30"
        };

        var result = await engine.ExecuteFixAsync(finding);

        Assert.False(result.Success);
        Assert.Contains("timed out", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExecuteCommandAsync_Works()
    {
        var result = await _engine.ExecuteCommandAsync("Write-Output 'direct command'");

        Assert.True(result.Success);
        Assert.Contains("direct command", result.Output);
    }

    [Fact]
    public async Task ExecuteCommandAsync_DryRun_Works()
    {
        var result = await _engine.ExecuteCommandAsync("dangerous-command", dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.Contains("dangerous-command", result.Output);
    }

    [Theory]
    [InlineData("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Test' -Name 'Value' -Value 1", true)]
    [InlineData("Set-MpPreference -DisableRealtimeMonitoring $false", true)]
    [InlineData("Update-MpSignature", true)]
    [InlineData("Disable-LocalUser -Name 'Guest'", true)]
    [InlineData("net accounts /minpwlen:8", true)]
    [InlineData("netsh advfirewall set currentprofile state on", true)]
    [InlineData("Stop-Service WinRM", true)]
    [InlineData("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", true)]
    [InlineData("manage-bde -on C:", true)]
    [InlineData("shutdown /r /t 60", true)]
    [InlineData("Write-Output 'hello'", false)]
    [InlineData("Get-Process | Format-Table", false)]
    [InlineData("Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Test' -Name 'Value' -Value 0", false)]
    [InlineData("explorer.exe shell:startup", false)]
    [InlineData("Start-Process ms-settings:windowsupdate", false)]
    [InlineData("", false)]
    public void RequiresElevation_CorrectlyDetects(string command, bool expected)
    {
        Assert.Equal(expected, FixEngine.RequiresElevation(command));
    }

    [Fact]
    public void IsElevated_ReturnsBoolean()
    {
        // Just verify it doesn't throw — actual value depends on test runner context
        var result = FixEngine.IsElevated();
        Assert.IsType<bool>(result);
    }

    [Fact]
    public void FixResult_StaticFactories_Work()
    {
        var succeeded = FixResult.Succeeded("cmd", "output", TimeSpan.FromSeconds(1), "title");
        Assert.True(succeeded.Success);
        Assert.Equal("cmd", succeeded.Command);
        Assert.Equal("output", succeeded.Output);
        Assert.Equal("title", succeeded.FindingTitle);

        var failed = FixResult.Failed("cmd", "error", TimeSpan.FromSeconds(2), 42, "title2");
        Assert.False(failed.Success);
        Assert.Equal("error", failed.Error);
        Assert.Equal(42, failed.ExitCode);
        Assert.Equal("title2", failed.FindingTitle);

        var dryRun = FixResult.DryRunResult("cmd", "title3");
        Assert.True(dryRun.Success);
        Assert.True(dryRun.DryRun);
        Assert.Contains("DRY RUN", dryRun.Output);
        Assert.Equal("title3", dryRun.FindingTitle);

        var noFix = FixResult.NoFixAvailable("title4");
        Assert.False(noFix.Success);
        Assert.Contains("No fix command", noFix.Error);
        Assert.Equal("title4", noFix.FindingTitle);
    }

    [Fact]
    public void FixResult_ToString_FormatsCorrectly()
    {
        var dryRun = FixResult.DryRunResult("test-cmd");
        Assert.Contains("DRY RUN", dryRun.ToString());

        var success = FixResult.Succeeded("cmd", "output", TimeSpan.Zero, "Fix Title");
        Assert.Contains("OK", success.ToString());

        var fail = FixResult.Failed("cmd", "err", TimeSpan.Zero, findingTitle: "Fail Title");
        Assert.Contains("FAIL", fail.ToString());
    }

    [Fact]
    public async Task ExecuteFixAsync_MultiLineOutput_CapturesAll()
    {
        var finding = new Finding
        {
            Title = "Multi-line Test",
            Description = "Multiple lines",
            Severity = Severity.Warning,
            FixCommand = "Write-Output 'Line1'; Write-Output 'Line2'; Write-Output 'Line3'"
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.True(result.Success);
        Assert.Contains("Line1", result.Output);
        Assert.Contains("Line2", result.Output);
        Assert.Contains("Line3", result.Output);
    }

    [Fact]
    public async Task ExecuteFixAsync_CommandWithQuotes_HandlesCorrectly()
    {
        var finding = new Finding
        {
            Title = "Quotes Test",
            Description = "Command with quotes",
            Severity = Severity.Warning,
            FixCommand = "Write-Output 'It works!'"
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.True(result.Success);
        Assert.Contains("It works!", result.Output);
    }

    [Fact]
    public async Task ExecuteFixAsync_RecordsDuration()
    {
        var finding = new Finding
        {
            Title = "Duration Test",
            Description = "Check duration tracking",
            Severity = Severity.Warning,
            FixCommand = "Write-Output 'quick'"
        };

        var result = await _engine.ExecuteFixAsync(finding);

        Assert.True(result.Duration > TimeSpan.Zero);
    }
}
