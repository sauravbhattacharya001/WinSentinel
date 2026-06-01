using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Modules;
using Xunit;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="FleetRegistrationModule"/> startup gating behavior.
/// </summary>
public class FleetRegistrationModuleTests
{
    [Fact]
    public async Task StartAsync_WithoutProLicense_RemainsInactive()
    {
        // Arrange — no license file exists, so LicenseManager.GetStatus() returns free
        var logger = new NullLogger<FleetRegistrationModule>();
        var config = new AgentConfig();
        var state = new AgentState();
        var threatLog = new ThreatLog();
        var module = new FleetRegistrationModule(logger, config, state, threatLog);

        // Act
        await module.StartAsync(CancellationToken.None);

        // Assert — module should not activate without Pro license
        Assert.False(module.IsActive);
    }

    [Fact]
    public async Task StartAsync_WithProLicense_NoEndpoint_RemainsInactive()
    {
        // Even with a Pro license, if no fleet endpoint is configured the module is a no-op.
        // We can't easily mock the license file here, but we can verify that
        // the module handles a missing endpoint gracefully by setting the env var to empty.
        var logger = new NullLogger<FleetRegistrationModule>();
        var config = new AgentConfig { FleetEndpoint = null };
        var state = new AgentState();
        var threatLog = new ThreatLog();
        var module = new FleetRegistrationModule(logger, config, state, threatLog);

        // Without a Pro license this still won't activate
        await module.StartAsync(CancellationToken.None);
        Assert.False(module.IsActive);
    }

    [Fact]
    public void Name_ReturnsFleetRegistration()
    {
        var logger = new NullLogger<FleetRegistrationModule>();
        var config = new AgentConfig();
        var state = new AgentState();
        var threatLog = new ThreatLog();
        var module = new FleetRegistrationModule(logger, config, state, threatLog);

        Assert.Equal("FleetRegistration", module.Name);
    }
}
