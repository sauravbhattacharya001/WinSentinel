using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing the integrity of the local <c>hosts</c>
/// file (<c>%SystemRoot%\System32\drivers\etc\hosts</c>) on a single machine.
///
/// <para>The hosts file overrides DNS for the whole machine, so it is a classic,
/// low-effort tampering target: malware and adware routinely add entries there to
/// (a) <b>blackhole security/update domains</b> - pointing anti-virus, Windows
/// Update, or telemetry endpoints at <c>0.0.0.0</c>/loopback so the machine can no
/// longer patch or get definitions - and (b) <b>hijack traffic</b> - pointing a
/// bank/login/vendor domain at an attacker-controlled public IP for phishing or a
/// man-in-the-middle. Neither of these needs admin persistence beyond a single
/// file write, and both are invisible unless something actually reads the file.</para>
///
/// <para>This analyzer is single-machine and therefore FREE / OSS: it reasons only
/// about the parsed contents of the local hosts file. The audit module owns the
/// file read (I/O); this class owns every pass/fail decision, mirroring the
/// established collector-owns-I/O / analyzer-owns-decisions split used across the
/// audit suite (see <see cref="WindowsRecallAnalyzer"/>).</para>
/// </summary>
public static class HostsFileAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Network";

    /// <summary>
    /// Well-known domains that legitimate software effectively never wants a user
    /// to blackhole in the hosts file: blocking them silently breaks security
    /// updates / AV definitions. A hosts entry redirecting any of these to a
    /// non-routable address is a strong tamper signal. Matched as a suffix so
    /// sub-domains (e.g. <c>definitionupdates.microsoft.com</c>) are covered.
    /// </summary>
    private static readonly string[] SecuritySensitiveSuffixes =
    {
        "windowsupdate.com",
        "update.microsoft.com",
        "windowsupdate.microsoft.com",
        "wustat.windows.com",
        "sls.microsoft.com",
        "download.windowsupdate.com",
        "definitionupdates.microsoft.com",
        "wdcp.microsoft.com",
        "wdcpalt.microsoft.com",
        "wd.microsoft.com",
        "mrs.microsoft.com",
        "spynet2.microsoft.com",
        "clamav.net",
        "sophosxl.net",
        "avast.com",
        "avg.com",
        "mcafee.com",
        "symantec.com",
        "sophos.com",
        "kaspersky.com",
        "malwarebytes.com",
        "bitdefender.com",
    };

    /// <summary>
    /// Evaluate the parsed hosts-file state and return one finding per check.
    /// Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(HostsFileState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var findings = new List<Finding>
        {
            AnalyzeReadable(state),
            AnalyzeBlackholedSecurityDomains(state),
            AnalyzePublicRedirects(state),
            AnalyzeEntryCount(state),
        };
        return findings;
    }

    /// <summary>
    /// If the hosts file could not be read the audit cannot vouch for its
    /// integrity - report an Info so the run is honest rather than a false pass.
    /// A missing hosts file is normal on a fresh install and treated as a Pass by
    /// the other checks (they see zero entries).
    /// </summary>
    public static Finding AnalyzeReadable(HostsFileState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.Readable)
        {
            return Finding.Pass(
                "Hosts file is readable and was parsed",
                state.FileExists
                    ? $"The hosts file at {state.Path} was read and parsed ({state.Entries.Count} host mapping(s))."
                    : $"No hosts file is present at {state.Path}; DNS is resolved entirely via the network resolver.",
                Category);
        }

        return Finding.Info(
            "Hosts file could not be read",
            $"The hosts file at {state.Path} exists but could not be read for inspection, so its " +
            "integrity could not be verified this run. This is usually a permissions issue; re-run elevated.",
            Category,
            remediation: "Run the audit from an elevated prompt so the hosts file can be read and checked for tampering.");
    }

    /// <summary>
    /// Any hosts entry that points a security/update domain at a non-routable
    /// address (0.0.0.0 / loopback) blackholes patching or AV - a strong tamper
    /// signal - so it is Critical.
    /// </summary>
    public static Finding AnalyzeBlackholedSecurityDomains(HostsFileState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var blackholed = state.Entries
            .Where(e => IsNonRoutable(e.Address) && MatchesSecurityDomain(e.Hostname))
            .Select(e => e.Hostname)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (blackholed.Count == 0)
        {
            return Finding.Pass(
                "No security or update domains are blackholed in the hosts file",
                "No hosts entry redirects a Windows Update, Microsoft Defender or third-party AV " +
                "domain to a non-routable address.",
                Category);
        }

        var sample = string.Join(", ", blackholed.Take(8));
        return Finding.Critical(
            "Security/update domains are blackholed in the hosts file",
            $"{blackholed.Count} security-relevant domain(s) are redirected to a non-routable address in the " +
            $"hosts file ({sample}{(blackholed.Count > 8 ? ", ..." : string.Empty)}). This silently blocks Windows " +
            "Update and/or anti-virus definition updates and is a common malware tactic to keep a machine " +
            "unpatched and undefended.",
            Category,
            remediation: "Inspect the hosts file, remove the entries that redirect update/AV domains, and confirm " +
                         "the machine can reach Windows Update and Defender again.",
            fixCommand: "notepad $env:SystemRoot\\System32\\drivers\\etc\\hosts");
    }

    /// <summary>
    /// A hosts entry that maps a hostname to a routable public IP (not loopback,
    /// not private RFC1918, not link-local) is a potential traffic-hijack /
    /// phishing redirect - Warning, since some legitimate setups do this.
    /// </summary>
    public static Finding AnalyzePublicRedirects(HostsFileState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var redirects = state.Entries
            .Where(e => IsRoutablePublic(e.Address))
            .Select(e => $"{e.Hostname} -> {e.Address}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (redirects.Count == 0)
        {
            return Finding.Pass(
                "No hosts entries redirect a hostname to a public IP",
                "Every hosts mapping targets loopback, a private, or a non-routable address - none point a " +
                "hostname at a routable public IP that could hijack traffic.",
                Category);
        }

        var sample = string.Join("; ", redirects.Take(6));
        return Finding.Warning(
            "Hosts entries redirect hostnames to public IP addresses",
            $"{redirects.Count} hosts mapping(s) point a hostname at a routable public IP ({sample}" +
            $"{(redirects.Count > 6 ? "; ..." : string.Empty)}). This overrides DNS for the whole machine and can " +
            "be used to route a bank, login or vendor domain to an attacker-controlled server. Confirm each of " +
            "these is an intentional, trusted override.",
            Category,
            remediation: "Review each public-IP hosts mapping; remove any you did not add deliberately.");
    }

    /// <summary>
    /// A hosts file that has grown to thousands of entries is usually a bulk
    /// ad/tracker blocklist (benign) but can also hide malicious entries in the
    /// noise - Info so the operator is aware of an unusually large file.
    /// </summary>
    public static Finding AnalyzeEntryCount(HostsFileState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        const int LargeThreshold = 1000;
        if (state.Entries.Count < LargeThreshold)
        {
            return Finding.Pass(
                "Hosts file size is within a normal range",
                $"The hosts file contains {state.Entries.Count} host mapping(s), a normal number for a " +
                "single machine.",
                Category);
        }

        return Finding.Info(
            "Hosts file is unusually large",
            $"The hosts file contains {state.Entries.Count} host mappings. Large hosts files are usually bulk " +
            "ad/tracker blocklists (benign), but the size makes it easy for a malicious entry to hide in the " +
            "noise. Confirm the source of this blocklist is trusted.",
            Category,
            remediation: "Verify the large hosts file came from a trusted blocklist source and scan it for " +
                         "unexpected public-IP redirects.");
    }

    /// <summary>0.0.0.0, any 127.x loopback, or the IPv6 unspecified/loopback address.</summary>
    private static bool IsNonRoutable(string address)
    {
        if (string.IsNullOrWhiteSpace(address)) return false;
        var a = address.Trim();
        return a == "0.0.0.0"
            || a.StartsWith("127.", StringComparison.Ordinal)
            || a == "::"
            || a == "::1";
    }

    /// <summary>
    /// A routable, public IPv4/IPv6 target: parseable as an IP, not loopback,
    /// not private/link-local/unspecified. Non-IP targets are ignored (never a
    /// public-redirect signal).
    /// </summary>
    private static bool IsRoutablePublic(string address)
    {
        if (string.IsNullOrWhiteSpace(address)) return false;
        var a = address.Trim();
        if (IsNonRoutable(a)) return false;

        // IPv4 dotted quad only for the private-range checks; other parseable
        // addresses (public IPv6) are treated as routable-public too.
        var parts = a.Split('.');
        if (parts.Length == 4 && parts.All(p => int.TryParse(p, out var n) && n is >= 0 and <= 255))
        {
            var o0 = int.Parse(parts[0]);
            var o1 = int.Parse(parts[1]);
            if (o0 == 10) return false;                       // 10.0.0.0/8
            if (o0 == 172 && o1 is >= 16 and <= 31) return false; // 172.16.0.0/12
            if (o0 == 192 && o1 == 168) return false;         // 192.168.0.0/16
            if (o0 == 169 && o1 == 254) return false;         // link-local
            if (o0 == 100 && o1 is >= 64 and <= 127) return false; // CGNAT 100.64/10
            if (o0 == 0) return false;                        // 0.x
            return true;
        }

        // Anything with a ':' that we did not classify as non-routable above is a
        // public/ULA IPv6 target; treat fc00::/7 (ULA) and fe80::/10 (link-local)
        // as non-public.
        if (a.Contains(':'))
        {
            var lower = a.ToLowerInvariant();
            if (lower.StartsWith("fc", StringComparison.Ordinal) ||
                lower.StartsWith("fd", StringComparison.Ordinal) ||
                lower.StartsWith("fe8", StringComparison.Ordinal) ||
                lower.StartsWith("fe9", StringComparison.Ordinal) ||
                lower.StartsWith("fea", StringComparison.Ordinal) ||
                lower.StartsWith("feb", StringComparison.Ordinal))
            {
                return false;
            }
            return true;
        }

        return false;
    }

    private static bool MatchesSecurityDomain(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname)) return false;
        var h = hostname.Trim().TrimEnd('.').ToLowerInvariant();
        return SecuritySensitiveSuffixes.Any(s =>
            h.Equals(s, StringComparison.Ordinal) || h.EndsWith("." + s, StringComparison.Ordinal));
    }

    /// <summary>
    /// Parse raw hosts-file text into normalized <see cref="HostMapping"/> mappings.
    /// Comments (<c>#</c>), blank lines and malformed rows are skipped; a single
    /// line may map several hostnames to one address, and each becomes its own
    /// entry. This is pure and used by both the module and the tests.
    /// </summary>
    public static IReadOnlyList<HostMapping> ParseHosts(string? content)
    {
        var entries = new List<HostMapping>();
        if (string.IsNullOrEmpty(content)) return entries;

        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line.Substring(0, hash);
            line = line.Trim();
            if (line.Length == 0) continue;

            var tokens = Regex.Split(line, "\\s+").Where(t => t.Length > 0).ToArray();
            if (tokens.Length < 2) continue;

            var address = tokens[0];
            for (var i = 1; i < tokens.Length; i++)
            {
                entries.Add(new HostMapping(address, tokens[i]));
            }
        }

        return entries;
    }
}

/// <summary>A single normalized hosts-file mapping: one address to one hostname.</summary>
public sealed record HostMapping(string Address, string Hostname);

/// <summary>
/// Raw, collector-supplied hosts-file state handed to <see cref="HostsFileAnalyzer"/>
/// for a pure decision. The audit module owns reading the file and parsing it into
/// <see cref="Entries"/>; the analyzer never touches disk.
/// </summary>
public sealed record HostsFileState
{
    /// <summary>Absolute path of the hosts file that was inspected.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Whether the hosts file exists on disk.</summary>
    public bool FileExists { get; init; }

    /// <summary>
    /// Whether the file was successfully read. A missing file counts as readable
    /// (there is simply nothing to read); only an existing-but-unreadable file is
    /// <c>false</c>.
    /// </summary>
    public bool Readable { get; init; } = true;

    /// <summary>Parsed host mappings (address to hostname).</summary>
    public IReadOnlyList<HostMapping> Entries { get; init; } = new List<HostMapping>();
}
