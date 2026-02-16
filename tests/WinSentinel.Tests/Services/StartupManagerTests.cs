using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class StartupManagerTests
{
    [Fact]
    public void IsRegistered_ReturnsBoolean()
    {
        // Just verify it doesn't throw
        var result = StartupManager.IsRegistered();
        Assert.IsType<bool>(result);
    }

    [Fact]
    public void Register_And_Unregister_WorksRoundTrip()
    {
        // Use a fake path to avoid registering the actual app
        var testExePath = @"C:\NonExistent\WinSentinel.exe";

        try
        {
            // Register
            var registered = StartupManager.Register(testExePath);
            Assert.True(registered);
            Assert.True(StartupManager.IsRegistered());

            // Unregister
            var unregistered = StartupManager.Unregister();
            Assert.True(unregistered);
            Assert.False(StartupManager.IsRegistered());
        }
        finally
        {
            // Cleanup: ensure we remove the test entry
            StartupManager.Unregister();
        }
    }

    [Fact]
    public void SetStartup_EnableAndDisable()
    {
        var testExePath = @"C:\NonExistent\WinSentinel.exe";

        try
        {
            // Enable
            var result = StartupManager.SetStartup(true, testExePath);
            Assert.True(result);
            Assert.True(StartupManager.IsRegistered());

            // Disable
            result = StartupManager.SetStartup(false);
            Assert.True(result);
            Assert.False(StartupManager.IsRegistered());
        }
        finally
        {
            StartupManager.Unregister();
        }
    }

    [Fact]
    public void Unregister_WhenNotRegistered_Succeeds()
    {
        // Ensure not registered
        StartupManager.Unregister();

        // Unregister again — should succeed silently
        var result = StartupManager.Unregister();
        Assert.True(result);
    }
}
