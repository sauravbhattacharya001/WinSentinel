using System;
using System.IO;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

public sealed class PluginLoadAuditLogTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _logPath;

    public PluginLoadAuditLogTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ws-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _logPath = Path.Combine(_tempDir, "plugin-load.log");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    [Fact]
    public void Append_Creates_Log_File_With_Expected_Fields()
    {
        var result = new PluginLoadResult(
            @"C:\plugins\test.dll",
            PluginLoadStatus.Loaded,
            "pdf-report",
            "1.0.0",
            "Acme",
            "ABCDEFGH12345678ABCDEFGH12345678ABCDEFGH123=",
            "loaded 1 type(s)");

        PluginLoadAuditLog.Append(result, _logPath);

        Assert.True(File.Exists(_logPath));
        var line = File.ReadAllText(_logPath).Trim();
        Assert.Contains("pdf-report", line);
        Assert.Contains("loaded", line);
        Assert.Contains("ABCDEFGH", line);
    }

    [Fact]
    public void Append_Handles_Null_FeatureId()
    {
        var result = new PluginLoadResult(
            "bad.dll", PluginLoadStatus.SkippedNoManifest,
            null, null, null, null, "missing manifest");

        PluginLoadAuditLog.Append(result, _logPath);

        var line = File.ReadAllText(_logPath).Trim();
        Assert.Contains("(unknown)", line);
        Assert.Contains("skipped", line);
    }

    [Fact]
    public void AppendAll_Writes_Multiple_Lines()
    {
        var pluginDir = Path.Combine(_tempDir, "plugins");
        Directory.CreateDirectory(pluginDir);
        File.WriteAllBytes(Path.Combine(pluginDir, "junk.dll"), new byte[] { 0, 1, 2 });
        File.WriteAllBytes(Path.Combine(pluginDir, "junk2.dll"), new byte[] { 3, 4, 5 });

        var host = new PluginHost(
            new TrustedPublisherConfig(),
            pluginDir,
            _ => true,
            log: (_, _) => { },
            reportProvider: null);
        host.LoadAll();

        PluginLoadAuditLog.AppendAll(host, _logPath);

        var lines = File.ReadAllLines(_logPath);
        Assert.True(lines.Length >= 2);
    }
}
