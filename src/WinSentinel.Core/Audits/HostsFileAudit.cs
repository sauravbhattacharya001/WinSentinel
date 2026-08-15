using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that verifies the integrity of the local Windows <c>hosts</c>
/// file (<c>%SystemRoot%\System32\drivers\etc\hosts</c>) in a live
/// <c>--audit</c> run. Because the hosts file overrides DNS for the entire
/// machine with a single unprivileged-looking file write, it is a favourite
/// tampering target: malware blackholes Windows Update / anti-virus domains to
/// keep a box unpatched, and phishing kits redirect bank/login domains to
/// attacker IPs. This module surfaces both.
///
/// <para>It is the thin I/O layer for <see cref="HostsFileAnalyzer"/>: it owns
/// locating and reading the hosts file and parsing it into
/// <see cref="HostMapping"/> mappings, and delegates every pass/fail decision to
/// the pure, unit-tested analyzer (collector owns I/O, analyzer owns decisions -
/// the same split as <see cref="WindowsRecallAudit"/> /
/// <see cref="WindowsRecallAnalyzer"/>). It reads only the local machine's hosts
/// file, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class HostsFileAudit : AuditModuleBase
{
    public override string Name => "Hosts File Integrity Audit";
    public override string Category => HostsFileAnalyzer.Category;
    public override string Description =>
        "Checks the local hosts file for tampering - security/update domains blackholed to a non-routable " +
        "address (blocks Windows Update and AV), hostnames redirected to public IPs (traffic hijack / phishing), " +
        "and unusually large blocklists - to catch a common, low-effort DNS-override attack on a single machine.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in HostsFileAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Locate and read the local hosts file into a pure <see cref="HostsFileState"/>.
    /// A missing file is a normal, safe state (readable = true, zero entries); only
    /// an existing-but-unreadable file (permissions) is reported as not readable so
    /// the analyzer can emit an honest Info rather than a false pass. Never throws.
    /// </summary>
    internal static HostsFileState CollectState()
    {
        var path = ResolveHostsPath();

        bool exists;
        try
        {
            exists = File.Exists(path);
        }
        catch
        {
            exists = false;
        }

        if (!exists)
        {
            return new HostsFileState
            {
                Path = path,
                FileExists = false,
                Readable = true,
                Entries = new List<HostMapping>(),
            };
        }

        string? content = null;
        try
        {
            content = File.ReadAllText(path);
        }
        catch
        {
            content = null;
        }

        if (content is null)
        {
            return new HostsFileState
            {
                Path = path,
                FileExists = true,
                Readable = false,
                Entries = new List<HostMapping>(),
            };
        }

        return new HostsFileState
        {
            Path = path,
            FileExists = true,
            Readable = true,
            Entries = HostsFileAnalyzer.ParseHosts(content),
        };
    }

    /// <summary>
    /// Resolve the hosts file path from the live system root, falling back to the
    /// canonical location if the environment variable is unavailable.
    /// </summary>
    private static string ResolveHostsPath()
    {
        string systemRoot;
        try
        {
            systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(systemRoot))
            {
                systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows";
            }
        }
        catch
        {
            systemRoot = "C:\\Windows";
        }

        return Path.Combine(systemRoot, "System32", "drivers", "etc", "hosts");
    }
}
