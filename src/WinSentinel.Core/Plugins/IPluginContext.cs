using System;
using System.Collections.Generic;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Severity for plugin log messages. Intentionally narrow — plugins should
/// not take a hard dependency on Microsoft.Extensions.Logging.
/// </summary>
public enum PluginLogLevel
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
}

/// <summary>
/// Minimal callback surface handed to a loaded plugin. Deliberately narrow:
/// the public Core API of WinSentinel is large and we do NOT want plugins
/// reaching into arbitrary services. Anything a plugin needs that is not on
/// this surface should be requested explicitly and code-reviewed first.
/// </summary>
public interface IPluginContext
{
    /// <summary>Structured logger. Plugins use this instead of <c>Console.WriteLine</c>.</summary>
    Action<string, PluginLogLevel> Log { get; }

    /// <summary>
    /// Most recent audit report visible to the host, or <c>null</c> if no scan has run
    /// in this process yet. Read-only snapshot — plugins must not mutate.
    /// </summary>
    SecurityReport? CurrentReport { get; }

    /// <summary>
    /// Read-only configuration dictionary. Currently sourced from environment
    /// variables prefixed <c>WINSENTINEL_PLUGIN_</c>. Reserved for a future
    /// per-plugin config file.
    /// </summary>
    IReadOnlyDictionary<string, string> Config { get; }
}
