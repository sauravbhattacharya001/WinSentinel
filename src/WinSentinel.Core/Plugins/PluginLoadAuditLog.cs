using System;
using System.IO;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Appends plugin load/skip/reject events to a persistent audit log file
/// at <c>%LOCALAPPDATA%\WinSentinel\plugin-load.log</c>. Each line is a
/// tab-separated record: timestamp, featureId, publisher fingerprint,
/// outcome, reason.
/// </summary>
public static class PluginLoadAuditLog
{
    private static readonly string DefaultLogPath = GetDefaultLogPath();

    private static string GetDefaultLogPath()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(local)) local = Path.GetTempPath();
        return Path.Combine(local, "WinSentinel", "plugin-load.log");
    }

    /// <summary>
    /// Appends a single load result to the audit log. Thread-safe via
    /// append-mode file IO. Swallows all exceptions — audit logging must
    /// never crash the host.
    /// </summary>
    public static void Append(PluginLoadResult result, string? logPath = null)
    {
        try
        {
            var path = logPath ?? DefaultLogPath;
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var outcome = result.Status == PluginLoadStatus.Loaded ? "loaded"
                : result.Status.ToString().StartsWith("Skipped") ? "skipped"
                : "rejected";

            var fingerprint = string.IsNullOrEmpty(result.PublisherKey)
                ? "(none)"
                : TruncateFingerprint(result.PublisherKey);

            var line = $"{DateTime.UtcNow:O}\t{result.FeatureId ?? "(unknown)"}\t{fingerprint}\t{outcome}\t{result.Message}";
            File.AppendAllText(path, line + Environment.NewLine);
        }
        catch
        {
            // Never crash the host for audit logging failures.
        }
    }

    /// <summary>Writes all load results from a PluginHost to the audit log.</summary>
    public static void AppendAll(PluginHost host, string? logPath = null)
    {
        foreach (var r in host.LoadResults)
            Append(r, logPath);
    }

    private static string TruncateFingerprint(string key)
    {
        if (key.Length <= 12) return key;
        return key[..8] + "..." + key[^4..];
    }
}
