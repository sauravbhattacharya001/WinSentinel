using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for Windows Script Host (WSH) hardening on a single
/// machine. WSH (<c>wscript.exe</c> / <c>cscript.exe</c>) is the built-in engine
/// that runs <c>.vbs</c>, <c>.js</c>, <c>.wsf</c> and other script files. It is a
/// long-standing "living off the land" execution surface: phishing payloads and
/// commodity malware routinely ship a double-clickable <c>.vbs</c>/<c>.js</c>
/// dropper because WSH is enabled by default and runs the script with the user's
/// full token, no compiler, and no SmartScreen the way an <c>.exe</c> would get.
///
/// The checks (all local registry state):
///   * <b>WSH Enabled</b> - HKLM\...\Windows Script Host\Settings\Enabled. When 0,
///     wscript/cscript refuse to run any script at all, removing the surface
///     entirely. Absent/1 = WSH is on (the default). On endpoints that never run
///     legitimate scripts, disabling WSH is a cheap, high-value hardening.
///   * <b>Remote script execution</b> - ...\Settings\Remote. When 1, WSH will run
///     scripts fetched from a remote (UNC / network) path; combined with a lure
///     this widens the delivery surface. 0/absent = local only.
///   * <b>TrustPolicy (Authenticode enforcement)</b> - ...\Settings\TrustPolicy.
///     2 = only run digitally-signed scripts from trusted publishers, 1 = prompt,
///     0/absent = run anything. 2 is the hardened state; anything else means
///     unsigned scripts run without a signature check.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// registry state only. Nothing multi-machine, nothing license-gated. All rules
/// operate on a synthetic <see cref="WindowsScriptHostState"/> so they can be unit
/// tested directly, mirroring the established <see cref="PrintSpoolerAnalyzer"/> /
/// <see cref="LsaHardeningAnalyzer"/> pattern (collector owns I/O, analyzer owns
/// decisions).
/// </summary>
public static class WindowsScriptHostAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Windows Script Host";

    /// <summary>
    /// Evaluate the collected Windows Script Host state and return one finding per
    /// check (a Pass when the setting is already safe, otherwise Info/Warning).
    /// Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(WindowsScriptHostState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeEnabled(state),
            AnalyzeRemote(state),
            AnalyzeTrustPolicy(state),
        };
    }

    /// <summary>WSH Enabled=0 removes the wscript/cscript execution surface entirely.</summary>
    public static Finding AnalyzeEnabled(WindowsScriptHostState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // Absent (null) means the value is not set, which is the Windows default:
        // WSH is ENABLED. Only an explicit 0 disables it.
        if (state.Enabled == 0)
        {
            return Finding.Pass(
                "Windows Script Host is disabled",
                "The Windows Script Host Enabled value is 0, so wscript.exe and cscript.exe " +
                "refuse to run .vbs/.js/.wsf scripts. This removes a common living-off-the-" +
                "land execution surface used by script-based malware and phishing droppers.",
                Category);
        }

        return Finding.Info(
            "Windows Script Host is enabled",
            "Windows Script Host is enabled (the default), so wscript.exe/cscript.exe will " +
            "run .vbs, .js and .wsf scripts with the user's full token. This is a recurring " +
            "delivery/execution vector for script-based malware. On endpoints that never " +
            "run legitimate scripts, disabling WSH is a cheap, high-value hardening.",
            Category,
            remediation: "If scripts are not needed, set HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\" +
                         "Settings\\Enabled = 0 (DWORD) to disable WSH machine-wide.",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name Enabled -Type DWord -Value 0");
    }

    /// <summary>Remote=1 lets WSH run scripts from remote/UNC paths, widening delivery.</summary>
    public static Finding AnalyzeRemote(WindowsScriptHostState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.Remote == 1)
        {
            return Finding.Warning(
                "Windows Script Host runs remote scripts",
                "The Windows Script Host Remote value is 1, so WSH will execute scripts loaded " +
                "from remote (UNC / network) locations. Combined with a lure or a compromised " +
                "share, this widens the script delivery surface beyond local files.",
                Category,
                remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Remote = 0 (DWORD) " +
                             "to restrict WSH to local scripts.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name Remote -Type DWord -Value 0");
        }

        return Finding.Pass(
            "Windows Script Host does not run remote scripts",
            "The Windows Script Host Remote value is 0 or absent, so WSH does not execute " +
            "scripts from remote locations.",
            Category);
    }

    /// <summary>TrustPolicy=2 enforces Authenticode-signed scripts only.</summary>
    public static Finding AnalyzeTrustPolicy(WindowsScriptHostState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // 2 = run only signed scripts from trusted publishers (hardened).
        // 1 = prompt the user for unsigned scripts.
        // 0 / absent = run anything unsigned without a check (default).
        switch (state.TrustPolicy)
        {
            case 2:
                return Finding.Pass(
                    "Windows Script Host requires signed scripts",
                    "The Windows Script Host TrustPolicy value is 2, so WSH only runs scripts " +
                    "that are Authenticode-signed by a trusted publisher. Unsigned scripts are " +
                    "blocked.",
                    Category);
            case 1:
                return Finding.Info(
                    "Windows Script Host prompts before running unsigned scripts",
                    "The Windows Script Host TrustPolicy value is 1, so WSH prompts the user " +
                    "before running an unsigned script. This relies on the user to make the " +
                    "right call; enforcing signed-only (2) is stronger.",
                    Category,
                    remediation: "For stronger enforcement set HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\" +
                                 "Settings\\TrustPolicy = 2 (DWORD) to allow only signed scripts.",
                    fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name TrustPolicy -Type DWord -Value 2");
            default:
                return Finding.Info(
                    "Windows Script Host runs unsigned scripts without checking a signature",
                    "The Windows Script Host TrustPolicy value is 0 or absent, so WSH runs any " +
                    "script regardless of whether it is digitally signed. Signature enforcement " +
                    "would block unsigned script-based payloads.",
                    Category,
                    remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\TrustPolicy = 2 " +
                                 "(DWORD) to run only signed scripts, or 1 to prompt.",
                    fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Force | Out-Null; " +
                                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name TrustPolicy -Type DWord -Value 2");
        }
    }
}

/// <summary>
/// Raw, collector-supplied Windows Script Host state. Populated by the audit
/// module's I/O layer and handed to <see cref="WindowsScriptHostAnalyzer"/> for a
/// pure decision. Null fields mean "value absent / not readable"; the analyzer
/// treats absence as the Windows default (WSH enabled, no remote/signing
/// enforcement) so a missing key is never silently reported as hardened.
/// </summary>
public sealed record WindowsScriptHostState
{
    /// <summary>Settings\Enabled (DWORD). 0 = WSH disabled; absent/1 = enabled (default).</summary>
    public int? Enabled { get; init; }

    /// <summary>Settings\Remote (DWORD). 1 = allow remote scripts; 0/absent = local only.</summary>
    public int? Remote { get; init; }

    /// <summary>Settings\TrustPolicy (DWORD). 2 = signed only; 1 = prompt; 0/absent = run anything.</summary>
    public int? TrustPolicy { get; init; }
}
