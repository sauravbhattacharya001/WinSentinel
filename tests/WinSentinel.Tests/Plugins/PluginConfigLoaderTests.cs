using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

public sealed class PluginConfigLoaderTests : IDisposable
{
    private readonly string _tempDir;

    public PluginConfigLoaderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ws-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    [Fact]
    public void Load_Returns_Empty_When_No_Config_Exists()
    {
        var cfg = PluginConfigLoader.Load("nonexistent-plugin", _tempDir);
        Assert.Empty(cfg);
    }

    [Fact]
    public void Load_Reads_Json_File()
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["apiKey"] = "secret123",
            ["outputDir"] = @"C:\Reports"
        });
        File.WriteAllText(Path.Combine(_tempDir, "pdf-report.json"), json);

        var cfg = PluginConfigLoader.Load("pdf-report", _tempDir);

        Assert.Equal("secret123", cfg["apiKey"]);
        Assert.Equal(@"C:\Reports", cfg["outputDir"]);
    }

    [Fact]
    public void Load_Handles_Malformed_Json_Gracefully()
    {
        File.WriteAllText(Path.Combine(_tempDir, "bad-plugin.json"), "not valid json{{{");

        var cfg = PluginConfigLoader.Load("bad-plugin", _tempDir);
        // Should not throw, returns empty (or env-var entries only).
        Assert.NotNull(cfg);
    }

    [Fact]
    public void Load_Is_Case_Insensitive_On_Keys()
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, string> { ["ApiKey"] = "val" });
        File.WriteAllText(Path.Combine(_tempDir, "my-plugin.json"), json);

        var cfg = PluginConfigLoader.Load("my-plugin", _tempDir);
        Assert.Equal("val", cfg["apikey"]);
        Assert.Equal("val", cfg["APIKEY"]);
    }
}
