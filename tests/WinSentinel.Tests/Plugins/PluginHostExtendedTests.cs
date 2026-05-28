using System;
using System.IO;
using System.Security.Cryptography;
using System.Reflection;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

/// <summary>
/// Tests machine-wide plugin directory support (#202) and naughty plugin
/// behavior (#205).
/// </summary>
public sealed class PluginHostExtendedTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly string _userDir;
    private readonly string _machineDir;

    public PluginHostExtendedTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "ws-ext-" + Guid.NewGuid().ToString("N"));
        _userDir = Path.Combine(_tempRoot, "user-plugins");
        _machineDir = Path.Combine(_tempRoot, "machine-plugins");
        Directory.CreateDirectory(_userDir);
        Directory.CreateDirectory(_machineDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, true); } catch { }
    }

    private static string TestPluginDllPath()
    {
        var here = Path.GetDirectoryName(typeof(PluginHostExtendedTests).Assembly.Location)!;
        var candidate = Path.Combine(here, "WinSentinel.TestPlugin.dll");
        if (File.Exists(candidate)) return candidate;
        var found = Directory.GetFiles(here, "WinSentinel.TestPlugin.dll", SearchOption.AllDirectories);
        if (found.Length == 0) throw new FileNotFoundException("WinSentinel.TestPlugin.dll not found.");
        return found[0];
    }

    private static string NaughtyPluginDllPath()
    {
        var here = Path.GetDirectoryName(typeof(PluginHostExtendedTests).Assembly.Location)!;
        var candidate = Path.Combine(here, "WinSentinel.NaughtyTestPlugin.dll");
        if (File.Exists(candidate)) return candidate;
        var found = Directory.GetFiles(here, "WinSentinel.NaughtyTestPlugin.dll", SearchOption.AllDirectories);
        if (found.Length == 0) throw new FileNotFoundException("WinSentinel.NaughtyTestPlugin.dll not found.");
        return found[0];
    }

    // --- #202: Machine-wide plugin directory ---

    [Fact]
    public void Machine_Dir_Plugins_Are_Loaded()
    {
        var src = TestPluginDllPath();
        File.Copy(src, Path.Combine(_machineDir, "WinSentinel.TestPlugin.dll"));

        var host = new PluginHost(
            new TrustedPublisherConfig { AllowUnsigned = true },
            _userDir,
            _machineDir,
            _ => true,
            log: (_, _) => { },
            reportProvider: null);
        host.LoadAll();

        Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.Loaded, host.LoadResults[0].Status);
    }

    [Fact]
    public void User_Dir_Overrides_Machine_Dir_Same_Filename()
    {
        var src = TestPluginDllPath();
        // Put plugin in both dirs
        File.Copy(src, Path.Combine(_machineDir, "WinSentinel.TestPlugin.dll"));
        File.Copy(src, Path.Combine(_userDir, "WinSentinel.TestPlugin.dll"));

        var host = new PluginHost(
            new TrustedPublisherConfig { AllowUnsigned = true },
            _userDir,
            _machineDir,
            _ => true,
            log: (_, _) => { },
            reportProvider: null);
        host.LoadAll();

        // Should only load once (user-dir wins).
        Assert.Single(host.LoadResults);
        Assert.Contains(_userDir, host.LoadResults[0].DllPath);
    }

    // --- #205: Naughty plugin test fixtures ---

    [Fact]
    public void Plugin_Throwing_In_Initialize_Is_Skipped_Gracefully()
    {
        var src = NaughtyPluginDllPath();
        File.Copy(src, Path.Combine(_userDir, "WinSentinel.NaughtyTestPlugin.dll"));

        var errors = new System.Collections.Generic.List<string>();
        var host = new PluginHost(
            new TrustedPublisherConfig { AllowUnsigned = true },
            _userDir,
            null,
            _ => true,
            log: (msg, level) => { if (level == PluginLogLevel.Error) errors.Add(msg); },
            reportProvider: null);
        host.LoadAll();

        // The naughty plugin has one type that throws — recorded as SkippedInitFailed,
        // then a SkippedNoTypes since no types successfully instantiated.
        Assert.True(host.LoadResults.Count >= 1);
        Assert.Equal(PluginLoadStatus.SkippedInitFailed, host.LoadResults[0].Status);
        Assert.Contains("Intentional explosion", host.LoadResults[0].Message);
        Assert.NotEmpty(errors);
    }
}
