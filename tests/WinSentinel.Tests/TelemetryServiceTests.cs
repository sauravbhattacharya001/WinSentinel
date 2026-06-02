using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class TelemetryServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _configPath;

    public TelemetryServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"ws-telemetry-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _configPath = Path.Combine(_tempDir, "telemetry.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    [Fact]
    public void DefaultState_IsDisabled()
    {
        var svc = new TelemetryService(_configPath);
        Assert.False(svc.IsEnabled);
    }

    [Fact]
    public void Enable_PersistsToConfig()
    {
        var svc = new TelemetryService(_configPath);
        svc.Enable();
        Assert.True(svc.IsEnabled);

        // Reload from disk
        var svc2 = new TelemetryService(_configPath);
        Assert.True(svc2.IsEnabled);
    }

    [Fact]
    public void Disable_PersistsToConfig()
    {
        var svc = new TelemetryService(_configPath);
        svc.Enable();
        svc.Disable();
        Assert.False(svc.IsEnabled);

        var svc2 = new TelemetryService(_configPath);
        Assert.False(svc2.IsEnabled);
    }

    [Fact]
    public void InstallId_IsStableAcrossReloads()
    {
        var svc = new TelemetryService(_configPath);
        svc.Enable();
        var id = svc.InstallId;

        var svc2 = new TelemetryService(_configPath);
        Assert.Equal(id, svc2.InstallId);
    }

    [Fact]
    public void Disable_WithClearId_GeneratesNewId()
    {
        var svc = new TelemetryService(_configPath);
        svc.Enable();
        var id1 = svc.InstallId;
        svc.Disable(clearId: true);

        var svc2 = new TelemetryService(_configPath);
        Assert.NotEqual(id1, svc2.InstallId);
    }

    [Fact]
    public void GetStatus_ReturnsCorrectInfo()
    {
        var svc = new TelemetryService(_configPath);
        svc.Enable();
        var status = svc.GetStatus();

        Assert.True(status.Enabled);
        Assert.NotEmpty(status.InstallId);
        Assert.Contains("winsentinel.ai", status.Endpoint);
        Assert.Equal(_configPath, status.ConfigPath);
    }

    [Fact]
    public async Task ReportErrorAsync_WhenDisabled_DoesNotThrow()
    {
        var svc = new TelemetryService(_configPath);
        // Disabled by default — should silently no-op
        await svc.ReportErrorAsync("audit", new InvalidOperationException("test"));
    }
}
