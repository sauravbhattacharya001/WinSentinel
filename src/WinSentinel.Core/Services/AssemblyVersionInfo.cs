// SPDX-License-Identifier: Apache-2.0
using System.Reflection;

namespace WinSentinel.Core.Services;

/// <summary>
/// Resolves the running WinSentinel.Core assembly version for embedding in
/// generated artifacts (SARIF reports, etc.).
///
/// <para>
/// Prefers <see cref="AssemblyInformationalVersionAttribute"/> (the semver that
/// flows from the git tag via MinVer), then the assembly file version, then the
/// plain assembly version. This mirrors the CLI's version resolver and exists so
/// exporters in Core never hard-code a version string that drifts out of date.
/// </para>
///
/// <para>
/// See issue #192: <c>AssemblyVersion</c> is intentionally pinned to a stable
/// binding surface (often "1.0.0.0") and must NOT be used as the reported
/// product version. The SARIF exporter previously hard-coded "1.1.0", which was
/// stale by many releases — GitHub Code Scanning surfaces this string as the
/// tool version, so a wrong value misleads consumers.
/// </para>
/// </summary>
public static class AssemblyVersionInfo
{
    /// <summary>
    /// The resolved semantic version of WinSentinel.Core (e.g. "1.19.0").
    /// Any build-metadata suffix (after a '+', from SourceLink) is stripped.
    /// Falls back to "0.0.0" only if no version attribute is present at all.
    /// </summary>
    public static string CoreVersion { get; } = Resolve();

    private static string Resolve()
    {
        var asm = typeof(AssemblyVersionInfo).Assembly;

        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            // Strip SourceLink build metadata, e.g. "1.19.0+abc123" -> "1.19.0".
            var plus = info.IndexOf('+');
            return plus >= 0 ? info.Substring(0, plus) : info;
        }

        var fileVersion = asm.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
        if (!string.IsNullOrWhiteSpace(fileVersion))
        {
            return fileVersion!;
        }

        var version = asm.GetName().Version;
        return version is null
            ? "0.0.0"
            : $"{version.Major}.{version.Minor}.{version.Build}";
    }
}
