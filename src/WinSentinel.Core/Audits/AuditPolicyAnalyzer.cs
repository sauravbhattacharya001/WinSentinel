using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the single-machine Windows <b>Advanced Audit Policy</b>
/// configuration - the per-subcategory success/failure auditing that decides whether
/// this box actually records the security events an investigation depends on. A host
/// can be perfectly hardened yet be forensically blind: if the relevant audit
/// subcategories are set to "No Auditing", the Security event log never gets the
/// Logon, Account-Logon, Process-Creation, Policy-Change and Object-Access records
/// that <see cref="EventLogAnalyzer"/> (and any DFIR responder) later looks for.
///
///   * <b>Logon</b> (subcategory "Logon") - Success+Failure records interactive /
///       network logons (4624/4625). Failure auditing is the source of brute-force
///       and password-spray detection.
///   * <b>Account Logon / Credential Validation</b> - Success+Failure records
///       authentication at the authority (4776/4768/4769); the primary signal for
///       Kerberoasting, AS-REP roasting and offline-credential abuse.
///   * <b>Process Creation</b> (subcategory "Process Creation") - Success records
///       4688, the backbone of process-lineage and living-off-the-land detection
///       (pairs with <see cref="ProcessLineageAnalyzer"/>).
///   * <b>Audit Policy Change</b> - Success+Failure records 4719, so an attacker who
///       disables auditing to go dark leaves a trace of having done so.
///   * <b>Account Management / User Account Management</b> - Success records user /
///       group / privilege changes (4720/4728/4732): local-admin sprawl and
///       persistence via new accounts.
///
/// This is single-machine and therefore FREE / OSS: it inspects the local audit
/// policy of this host only, reported by <c>auditpol /get</c>. Nothing multi-machine,
/// nothing license-gated. All rules operate on a parsed
/// <see cref="AuditPolicyState"/> so they can be unit tested directly, mirroring the
/// established <see cref="DiagnosticsHardeningAnalyzer"/> / <see cref="LsaHardeningAnalyzer"/>
/// pattern (collector owns I/O, the analyzer owns decisions).
/// </summary>
public static class AuditPolicyAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Audit Policy";

    /// <summary>
    /// Effective auditing configured for a single advanced-audit subcategory.
    /// Mirrors the flags <c>auditpol</c> reports: whether Success and/or Failure
    /// events are recorded.
    /// </summary>
    public sealed record SubcategorySetting(bool Success, bool Failure)
    {
        /// <summary>True when neither Success nor Failure auditing is enabled ("No Auditing").</summary>
        public bool IsNoAuditing => !Success && !Failure;

        /// <summary>Human label matching auditpol's own wording.</summary>
        public string Describe()
        {
            if (Success && Failure) return "Success and Failure";
            if (Success) return "Success";
            if (Failure) return "Failure";
            return "No Auditing";
        }
    }

    /// <summary>
    /// Evaluate the collected audit-policy state and return one finding per checked
    /// subcategory (a Pass when the required auditing is present, a Warning when it
    /// is missing). Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(AuditPolicyState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeLogon(state),
            AnalyzeCredentialValidation(state),
            AnalyzeProcessCreation(state),
            AnalyzeAuditPolicyChange(state),
            AnalyzeAccountManagement(state),
        };
    }

    /// <summary>Logon subcategory should audit both Success and Failure (4624/4625).</summary>
    public static Finding AnalyzeLogon(AuditPolicyState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return RequireSuccessAndFailure(
            state, "Logon",
            passTitle: "Logon auditing records success and failure",
            passDetail: "The Logon subcategory audits both Success and Failure, so interactive and network " +
                        "logons (4624) and failed logons (4625) are recorded - the source data for brute-force and " +
                        "password-spray detection.",
            warnTitle: "Logon auditing is incomplete",
            warnDetail: "The Logon subcategory is not auditing both Success and Failure. Without Failure auditing " +
                        "this host records no 4625 events, so brute-force and password-spray attempts are invisible in the Security log.",
            auditpolSubcategory: "Logon");
    }

    /// <summary>Credential Validation (Account Logon) should audit Success and Failure (4776/4768/4769).</summary>
    public static Finding AnalyzeCredentialValidation(AuditPolicyState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return RequireSuccessAndFailure(
            state, "Credential Validation",
            passTitle: "Credential validation auditing records success and failure",
            passDetail: "The Credential Validation subcategory audits both Success and Failure, capturing " +
                        "authentication at the authority (4776/4768/4769) - the primary signal for Kerberoasting, " +
                        "AS-REP roasting and offline credential abuse.",
            warnTitle: "Credential validation auditing is incomplete",
            warnDetail: "The Credential Validation subcategory is not auditing both Success and Failure, so " +
                        "authentication events used to detect credential-abuse (Kerberoasting, AS-REP roasting, spray) may not be recorded.",
            auditpolSubcategory: "Credential Validation");
    }

    /// <summary>Process Creation should audit Success (4688) for process-lineage / LOLBin detection.</summary>
    public static Finding AnalyzeProcessCreation(AuditPolicyState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var s = state.Get("Process Creation");
        if (s is { Success: true })
        {
            return Finding.Pass(
                "Process creation auditing is enabled",
                "The Process Creation subcategory audits Success, so 4688 process-creation events are recorded - " +
                "the backbone of process-lineage and living-off-the-land (LOLBin) detection.",
                Category);
        }

        return Finding.Warning(
            "Process creation auditing is disabled",
            "The Process Creation subcategory is not auditing Success" +
            (s is null ? " (subcategory not reported by auditpol)" : $" (currently: {s.Describe()})") +
            ", so no 4688 events are recorded. Process-lineage and living-off-the-land detection have no source data on this host.",
            Category,
            remediation: "Enable Success auditing for Advanced Audit Policy > Detailed Tracking > Audit Process Creation " +
                         "(also enable 'Include command line in process creation events' for full value).",
            fixCommand: "auditpol /set /subcategory:\"Process Creation\" /success:enable");
    }

    /// <summary>Audit Policy Change should audit Success and Failure (4719) to catch audit tampering.</summary>
    public static Finding AnalyzeAuditPolicyChange(AuditPolicyState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return RequireSuccessAndFailure(
            state, "Audit Policy Change",
            passTitle: "Audit policy change auditing is enabled",
            passDetail: "The Audit Policy Change subcategory audits Success and Failure, so 4719 events fire when " +
                        "auditing is modified - an attacker who disables auditing to go dark leaves a trace of doing so.",
            warnTitle: "Audit policy change auditing is incomplete",
            warnDetail: "The Audit Policy Change subcategory is not auditing both Success and Failure, so an " +
                        "attacker can weaken or disable auditing (to erase their own visibility) without a reliable 4719 record.",
            auditpolSubcategory: "Audit Policy Change");
    }

    /// <summary>User Account Management should audit Success (4720/4728/4732) for account persistence.</summary>
    public static Finding AnalyzeAccountManagement(AuditPolicyState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var s = state.Get("User Account Management");
        if (s is { Success: true })
        {
            return Finding.Pass(
                "Account management auditing is enabled",
                "The User Account Management subcategory audits Success, so account and group changes " +
                "(4720 account created, 4728/4732 added to privileged group) are recorded - the signal for local-admin " +
                "sprawl and new-account persistence.",
                Category);
        }

        return Finding.Warning(
            "Account management auditing is disabled",
            "The User Account Management subcategory is not auditing Success" +
            (s is null ? " (subcategory not reported by auditpol)" : $" (currently: {s.Describe()})") +
            ", so new local accounts and additions to privileged groups are not recorded - a common persistence path goes unlogged.",
            Category,
            remediation: "Enable Success auditing for Advanced Audit Policy > Account Management > Audit User Account Management.",
            fixCommand: "auditpol /set /subcategory:\"User Account Management\" /success:enable");
    }

    /// <summary>
    /// Shared helper for subcategories that should record both Success and Failure.
    /// Emits a Pass only when both flags are set; otherwise a Warning that names the
    /// current effective setting.
    /// </summary>
    private static Finding RequireSuccessAndFailure(
        AuditPolicyState state,
        string subcategory,
        string passTitle,
        string passDetail,
        string warnTitle,
        string warnDetail,
        string auditpolSubcategory)
    {
        var s = state.Get(subcategory);
        if (s is { Success: true, Failure: true })
        {
            return Finding.Pass(passTitle, passDetail, Category);
        }

        string current = s is null ? "not reported by auditpol" : s.Describe();
        return Finding.Warning(
            warnTitle,
            warnDetail + $" (currently: {current})",
            Category,
            remediation: $"Enable Success and Failure auditing for the '{auditpolSubcategory}' subcategory via " +
                         "Advanced Audit Policy Configuration (or auditpol).",
            fixCommand: $"auditpol /set /subcategory:\"{auditpolSubcategory}\" /success:enable /failure:enable");
    }

    /// <summary>
    /// Parse the CSV emitted by <c>auditpol /get /category:* /r</c> into an
    /// <see cref="AuditPolicyState"/>. The report is a header row followed by one row
    /// per subcategory; the columns of interest are "Subcategory" and "Inclusion
    /// Setting" ("No Auditing" / "Success" / "Failure" / "Success and Failure").
    /// Robust to CRLF/LF, quoted fields, and localized whitespace; unknown / empty
    /// input yields an empty state (every check then warns, never false-passes).
    /// </summary>
    public static AuditPolicyState ParseAuditpolCsv(string? csv)
    {
        var map = new Dictionary<string, SubcategorySetting>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(csv))
        {
            return new AuditPolicyState(map);
        }

        var lines = csv.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        int subcatIdx = -1, settingIdx = -1;
        bool headerParsed = false;

        foreach (var raw in lines)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var cols = SplitCsvLine(raw);
            if (!headerParsed)
            {
                for (int i = 0; i < cols.Count; i++)
                {
                    var h = cols[i].Trim();
                    if (h.Equals("Subcategory", StringComparison.OrdinalIgnoreCase)) subcatIdx = i;
                    else if (h.Equals("Inclusion Setting", StringComparison.OrdinalIgnoreCase)) settingIdx = i;
                }
                if (subcatIdx >= 0 && settingIdx >= 0) { headerParsed = true; continue; }
                // Some locales/machines omit a header; fall back to fixed auditpol column layout
                // (Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, ...).
                if (cols.Count >= 5)
                {
                    subcatIdx = 2; settingIdx = 4; headerParsed = true;
                    // fallthrough to process this same row as data
                }
                else
                {
                    continue;
                }
            }

            if (subcatIdx < 0 || settingIdx < 0) continue;
            if (cols.Count <= Math.Max(subcatIdx, settingIdx)) continue;

            var name = cols[subcatIdx].Trim();
            var setting = cols[settingIdx].Trim();
            if (string.IsNullOrEmpty(name)) continue;
            // Skip the header row if it slipped through the fixed-layout fallback.
            if (name.Equals("Subcategory", StringComparison.OrdinalIgnoreCase)) continue;

            map[name] = ParseSetting(setting);
        }

        return new AuditPolicyState(map);
    }

    private static SubcategorySetting ParseSetting(string setting)
    {
        bool success = setting.Contains("Success", StringComparison.OrdinalIgnoreCase);
        bool failure = setting.Contains("Failure", StringComparison.OrdinalIgnoreCase);
        return new SubcategorySetting(success, failure);
    }

    private static List<string> SplitCsvLine(string line)
    {
        var fields = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else inQuotes = !inQuotes;
            }
            else if (c == ',' && !inQuotes)
            {
                fields.Add(sb.ToString());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }
        fields.Add(sb.ToString());
        return fields;
    }
}

/// <summary>
/// Parsed, collector-supplied Windows advanced-audit-policy state - a map of
/// subcategory name to its effective Success/Failure setting, produced from
/// <c>auditpol /get</c> by <see cref="AuditPolicyAudit"/> and handed to
/// <see cref="AuditPolicyAnalyzer"/> for a pure decision. A subcategory absent from
/// the map means "not reported"; the analyzer treats absence as not-audited, so a
/// missing subcategory never becomes a false pass.
/// </summary>
public sealed class AuditPolicyState
{
    private readonly IReadOnlyDictionary<string, AuditPolicyAnalyzer.SubcategorySetting> _subcategories;

    public AuditPolicyState(IReadOnlyDictionary<string, AuditPolicyAnalyzer.SubcategorySetting> subcategories)
    {
        _subcategories = subcategories ?? throw new ArgumentNullException(nameof(subcategories));
    }

    /// <summary>Effective setting for a subcategory, or null when auditpol did not report it.</summary>
    public AuditPolicyAnalyzer.SubcategorySetting? Get(string subcategory)
        => _subcategories.TryGetValue(subcategory, out var s) ? s : null;

    /// <summary>Number of subcategories parsed (0 when auditpol output was empty / unreadable).</summary>
    public int Count => _subcategories.Count;
}
