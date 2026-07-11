using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="IdentityCredentialAudit"/> module.
///
/// All credential-hygiene <em>decisions</em> live here — the thresholds and
/// classification rules that turn a collected <see cref="IdentityState"/> into
/// <see cref="Finding"/> objects:
/// <list type="bullet">
///   <item>which password-never-expires accounts are risky vs. well-known,</item>
///   <item>when the local Administrators group counts as "sprawl",</item>
///   <item>how a cached-logon count maps to pass/warn/info,</item>
///   <item>LSA Protection (RunAsPPL) and Credential Guard / VBS posture,</item>
///   <item>LAPS posture for domain-joined vs. standalone machines.</item>
/// </list>
///
/// Nothing here touches the registry, PowerShell, WMI, the clock, or the
/// console, so the security-relevant thresholds can be unit tested directly
/// with synthetic state. The audit module owns only the collection of the raw
/// <see cref="IdentityState"/> and delegates every decision to this class.
///
/// Mirrors the established <see cref="ProcessLineageAnalyzer"/> pattern.
/// </summary>
public static class IdentityCredentialAnalyzer
{
    /// <summary>Category label shared with <see cref="IdentityCredentialAudit"/>.</summary>
    public const string Category = "Identity";

    /// <summary>
    /// Well-known local accounts that legitimately have "password never expires"
    /// set by Windows and should not be flagged. Case-insensitive.
    /// </summary>
    public static readonly IReadOnlySet<string> WellKnownNeverExpireAccounts =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "DefaultAccount", "WDAGUtilityAccount", "Guest"
        };

    /// <summary>
    /// Number of stale/idle days after which a local account is considered stale.
    /// Matches the collection query (<c>-90</c> days).
    /// </summary>
    public const int StaleAccountThresholdDays = 90;

    /// <summary>
    /// Member count above which the local Administrators group is flagged as sprawl.
    /// (Built-in Administrator + one human admin + one break-glass = 3 is tolerated.)
    /// </summary>
    public const int AdminSprawlThreshold = 3;

    /// <summary>
    /// Cached domain logon count above which we warn. CIS recommends ≤4 for
    /// workstations; 1–2 for high-security environments.
    /// </summary>
    public const int MaxAcceptableCachedLogons = 4;

    /// <summary>The Windows default cached-logon count when the value is unset.</summary>
    public const int DefaultCachedLogons = 10;

    // ──────────────────────────────────────────────────────────────────────
    // Pure JSON name extraction (shared with collection, but side-effect free)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Extract every <c>"Name":"…"</c> value from a (compressed) JSON fragment
    /// produced by <c>ConvertTo-Json</c>, in document order. Handles both a JSON
    /// array of objects and a single object. Returns an empty list for null/blank
    /// input or the literal <c>null</c>. This is the parsing the audit previously
    /// did inline and could not test.
    /// </summary>
    public static IReadOnlyList<string> ExtractJsonNames(string? json)
    {
        var names = new List<string>();
        if (string.IsNullOrWhiteSpace(json)) return names;

        var trimmed = json.Trim();
        if (string.Equals(trimmed, "null", StringComparison.OrdinalIgnoreCase)) return names;

        const string marker = "\"Name\":";
        int idx = 0;
        while (true)
        {
            int found = trimmed.IndexOf(marker, idx, StringComparison.OrdinalIgnoreCase);
            if (found < 0) break;

            int valueStart = found + marker.Length;
            var name = ReadJsonStringValue(trimmed, valueStart);
            if (!string.IsNullOrEmpty(name)) names.Add(name!);

            idx = valueStart;
        }

        return names;
    }

    /// <summary>
    /// Read a JSON string value starting at or after <paramref name="from"/>
    /// (skips whitespace, expects an opening quote). Returns the unescaped-enough
    /// inner text up to the next unescaped quote, or <c>null</c> if there is no
    /// quoted string.
    /// </summary>
    private static string? ReadJsonStringValue(string json, int from)
    {
        int i = from;
        while (i < json.Length && char.IsWhiteSpace(json[i])) i++;
        if (i >= json.Length || json[i] != '"') return null;

        int start = i + 1;
        var chars = new System.Text.StringBuilder();
        for (int j = start; j < json.Length; j++)
        {
            char c = json[j];
            if (c == '\\' && j + 1 < json.Length)
            {
                // Keep the escaped char as-is (names rarely contain escapes; we
                // only need to not terminate early on an escaped quote).
                chars.Append(json[j + 1]);
                j++;
                continue;
            }
            if (c == '"') return chars.ToString();
            chars.Append(c);
        }
        return null; // unterminated
    }

    /// <summary>
    /// From a set of enabled-account names that never expire, return only the
    /// ones that are NOT well-known system accounts (i.e. the risky ones).
    /// Order and case are preserved; null entries are dropped.
    /// </summary>
    public static IReadOnlyList<string> FilterRiskyNeverExpireAccounts(IEnumerable<string>? names)
    {
        var flagged = new List<string>();
        if (names is null) return flagged;
        foreach (var n in names)
        {
            if (string.IsNullOrWhiteSpace(n)) continue;
            if (!WellKnownNeverExpireAccounts.Contains(n.Trim())) flagged.Add(n.Trim());
        }
        return flagged;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Finding generation (one method per check; all pure)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Password-never-expires finding. When collection failed, emit the
    /// informational "skipped" finding. Otherwise: risky accounts → Warning,
    /// only well-known (or none) → Pass.
    /// </summary>
    public static Finding BuildPasswordNeverExpiresFinding(IdentityState state)
    {
        if (state.PasswordExpiryCheckFailed)
        {
            return Finding.Info(
                "Password Expiry Check Skipped",
                "Unable to query local user password expiration status.",
                Category);
        }

        var flagged = FilterRiskyNeverExpireAccounts(state.NeverExpireAccountNames);

        if (flagged.Count == 0)
        {
            // Distinguish "no candidates at all" from "only well-known ones".
            bool hadWellKnownOnly = (state.NeverExpireAccountNames?.Count ?? 0) > 0;
            return hadWellKnownOnly
                ? Finding.Pass(
                    "No Risky Password-Never-Expires Accounts",
                    "Only well-known system accounts have password-never-expires set.",
                    Category)
                : Finding.Pass(
                    "No Password-Never-Expires Accounts",
                    "All enabled local accounts have password expiration configured.",
                    Category);
        }

        return Finding.Warning(
            $"Password Never Expires ({flagged.Count} account{(flagged.Count > 1 ? "s" : "")})",
            $"Accounts with password-never-expires: {string.Join(", ", flagged)}. " +
            "Passwords that never expire increase risk of credential compromise over time.",
            Category,
            "Configure password expiration for these accounts or move to managed service accounts.",
            $"Set-LocalUser -Name '{flagged[0]}' -PasswordNeverExpires $false");
    }

    /// <summary>
    /// Stale-account finding. Collection failure → Info "skipped"; any stale
    /// accounts → Warning; none → Pass.
    /// </summary>
    public static Finding BuildStaleAccountsFinding(IdentityState state)
    {
        if (state.StaleAccountCheckFailed)
        {
            return Finding.Info(
                "Stale Account Check Skipped",
                "Unable to query last logon dates for local accounts.",
                Category);
        }

        var stale = (state.StaleAccountNames ?? new List<string>())
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Select(n => n.Trim())
            .ToList();

        if (stale.Count == 0)
        {
            return Finding.Pass(
                "No Stale Local Accounts",
                $"All enabled accounts have logged in within the last {StaleAccountThresholdDays} days.",
                Category);
        }

        return Finding.Warning(
            $"Stale Local Accounts ({stale.Count})",
            $"Accounts not used in {StaleAccountThresholdDays}+ days: {string.Join(", ", stale)}. " +
            "Stale accounts are attractive targets for attackers.",
            Category,
            "Disable or remove accounts that are no longer needed.",
            $"Disable-LocalUser -Name '{stale[0]}'");
    }

    /// <summary>
    /// Local-admin-sprawl findings (zero, one, or two): a Warning when the
    /// member count exceeds <see cref="AdminSprawlThreshold"/>, plus an Info when
    /// nested groups are present. When admin membership could not be read, returns
    /// an empty list (the audit stays quiet, as before).
    /// </summary>
    public static IReadOnlyList<Finding> BuildAdminSprawlFindings(IdentityState state)
    {
        var findings = new List<Finding>();
        if (!state.AdminGroupReadable) return findings;

        if (state.AdminMemberCount > AdminSprawlThreshold)
        {
            findings.Add(Finding.Warning(
                $"Local Admin Sprawl ({state.AdminMemberCount} members)",
                $"The Administrators group has {state.AdminMemberCount} members. " +
                "Excessive admin accounts increase the attack surface. " +
                "Apply principle of least privilege.",
                Category,
                "Remove unnecessary members from the local Administrators group. Use JIT/JEA where possible.",
                "Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass"));
        }

        if (state.AdminGroupHasNestedGroups)
        {
            findings.Add(Finding.Info(
                "Nested Groups in Administrators",
                "One or more groups are members of the local Administrators group. " +
                "This creates indirect admin access that may be hard to audit.",
                Category));
        }

        return findings;
    }

    /// <summary>
    /// LAPS posture finding, driven entirely by the collected state:
    /// not domain-joined → Info (N/A); Windows LAPS active → Pass;
    /// legacy LAPS installed → Pass; check failed → Info (skipped);
    /// otherwise (domain-joined, no LAPS) → Warning.
    /// </summary>
    public static Finding BuildLapsFinding(IdentityState state)
    {
        if (state.LapsCheckFailed)
        {
            return Finding.Info(
                "LAPS Check Skipped",
                "Unable to determine LAPS deployment status.",
                Category);
        }

        if (!state.IsDomainJoined)
        {
            return Finding.Info(
                "LAPS Not Applicable (Standalone)",
                "This machine is not domain-joined. LAPS is an Active Directory feature.",
                Category);
        }

        if (state.WindowsLapsActive)
        {
            return Finding.Pass(
                "Windows LAPS Active",
                "Windows LAPS is managing the local administrator password on this domain-joined machine.",
                Category);
        }

        if (state.LegacyLapsInstalled)
        {
            return Finding.Pass(
                "Legacy LAPS Installed",
                "Microsoft LAPS client-side extension is installed on this domain-joined machine.",
                Category);
        }

        return Finding.Warning(
            "LAPS Not Deployed",
            "This domain-joined machine does not have LAPS (Local Administrator Password Solution) " +
            "installed. Without LAPS, the local admin password is likely static across the environment, " +
            "enabling lateral movement after a single credential compromise.",
            Category,
            "Deploy Windows LAPS (preferred) or legacy Microsoft LAPS to randomize local admin passwords.",
            "Get-WindowsCapability -Online | Where-Object Name -like '*LAPS*'");
    }

    /// <summary>
    /// Cached-credentials finding. Not configured → Info (default 10);
    /// &gt; <see cref="MaxAcceptableCachedLogons"/> → Warning; otherwise Pass.
    /// </summary>
    public static Finding BuildCachedCredentialsFinding(IdentityState state)
    {
        if (!state.CachedLogonsConfigured)
        {
            return Finding.Info(
                $"Cached Credentials at Default ({DefaultCachedLogons})",
                $"CachedLogonsCount is not explicitly configured; Windows defaults to {DefaultCachedLogons}. " +
                "Consider reducing to limit credential exposure.",
                Category);
        }

        int cached = state.CachedLogonsCount;
        if (cached > MaxAcceptableCachedLogons)
        {
            return Finding.Warning(
                $"High Cached Credentials Count ({cached})",
                $"Windows caches {cached} domain logon credentials. " +
                "Cached credentials can be extracted by tools like Mimikatz on compromised machines. " +
                $"CIS recommends \u2264{MaxAcceptableCachedLogons} for workstations, 1-2 for high-security environments.",
                Category,
                "Reduce CachedLogonsCount to 2 (or 0 for always-connected machines).",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '2'");
        }

        return Finding.Pass(
            $"Cached Credentials: {cached}",
            $"Cached logon count is {cached} (\u2264{MaxAcceptableCachedLogons} is acceptable).",
            Category);
    }

    /// <summary>
    /// LSA Protection (RunAsPPL) finding. Enabled → Pass; otherwise Warning.
    /// When the LSA key is unreadable the audit emits nothing, so this returns
    /// <c>null</c> in that case.
    /// </summary>
    public static Finding? BuildLsaProtectionFinding(IdentityState state)
    {
        if (!state.LsaKeyReadable) return null;

        if (state.RunAsPplEnabled)
        {
            if (state.RunAsPplUefiLocked)
            {
                return Finding.Pass(
                    "LSA Protection Enabled (UEFI-Locked)",
                    "LSASS is running as a Protected Process Light (PPL) with a UEFI lock (RunAsPPL = 1). " +
                    "The setting is stored in a UEFI variable and cannot be silently removed by malware with admin rights.",
                    Category);
            }

            return Finding.Pass(
                "LSA Protection Enabled",
                "LSASS is running as a Protected Process Light (PPL), protecting against credential dumping tools. " +
                "Consider enabling the UEFI lock (RunAsPPL = 1) so the protection cannot be turned off by simply removing the registry value.",
                Category,
                "Enable the UEFI lock for LSA Protection to make it tamper-resistant.",
                @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1");
        }

        return Finding.Warning(
            "LSA Protection Not Enabled",
            "LSASS is not running as a Protected Process. Credential dumping tools like Mimikatz " +
            "can extract passwords and hashes from memory.",
            Category,
            "Enable LSA Protection (RunAsPPL) to harden against credential theft.",
            @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1");
    }

    /// <summary>
    /// Credential Guard finding. No Device Guard key → Info (not configured);
    /// VBS + Credential Guard (LsaCfgFlags ≥ 1) → Pass; VBS only → Info
    /// (partially configured); neither → Info (not enabled).
    /// </summary>
    public static Finding BuildCredentialGuardFinding(IdentityState state)
    {
        if (!state.DeviceGuardKeyPresent)
        {
            return Finding.Info(
                "Credential Guard Not Configured",
                "Device Guard / Credential Guard is not configured on this system. " +
                "Credential Guard uses virtualization to isolate secrets from the OS.",
                Category);
        }

        if (state.VbsEnabled && state.LsaCfgFlags >= 1)
        {
            return Finding.Pass(
                "Credential Guard Enabled",
                "Windows Credential Guard is enabled, providing virtualization-based isolation of credentials.",
                Category);
        }

        if (state.VbsEnabled)
        {
            return Finding.Info(
                "VBS Enabled, Credential Guard Not Fully Configured",
                "Virtualization-Based Security is enabled but Credential Guard (LsaCfgFlags) is not configured.",
                Category);
        }

        return Finding.Info(
            "Credential Guard Not Enabled",
            "Credential Guard is not enabled. On supported hardware, it provides strong protection against credential theft.",
            Category);
    }

    /// <summary>
    /// Build the full set of findings for a collected <see cref="IdentityState"/>,
    /// in the same order the audit produces them. This is the single entry point
    /// the audit module calls after collection.
    /// </summary>
    public static IReadOnlyList<Finding> BuildFindings(IdentityState state)
    {
        var findings = new List<Finding>
        {
            BuildPasswordNeverExpiresFinding(state),
            BuildStaleAccountsFinding(state)
        };

        findings.AddRange(BuildAdminSprawlFindings(state));
        findings.Add(BuildLapsFinding(state));
        findings.Add(BuildCachedCredentialsFinding(state));

        var lsa = BuildLsaProtectionFinding(state);
        if (lsa is not null) findings.Add(lsa);

        findings.Add(BuildCredentialGuardFinding(state));

        return findings;
    }

    // ──────────────────────────────────────────────────────────────────────
    // State DTO
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Snapshot of the identity / credential posture collected from the system.
    /// The audit module fills this in via registry + PowerShell; the analyzer
    /// reads it and only it. Defaults represent a clean, fully-collected machine.
    /// </summary>
    public sealed class IdentityState
    {
        // Password never expires
        /// <summary>Names of enabled local accounts whose password never expires (pre-filter).</summary>
        public List<string> NeverExpireAccountNames { get; set; } = new();
        /// <summary>True when the password-expiry query threw / could not run.</summary>
        public bool PasswordExpiryCheckFailed { get; set; }

        // Stale accounts
        /// <summary>Names of enabled local accounts idle ≥ <see cref="StaleAccountThresholdDays"/> days.</summary>
        public List<string> StaleAccountNames { get; set; } = new();
        /// <summary>True when the stale-account query threw / could not run.</summary>
        public bool StaleAccountCheckFailed { get; set; }

        // Local admin sprawl
        /// <summary>True when the Administrators group membership could be read.</summary>
        public bool AdminGroupReadable { get; set; }
        /// <summary>Count of members in the local Administrators group.</summary>
        public int AdminMemberCount { get; set; }
        /// <summary>True when at least one member of Administrators is itself a group.</summary>
        public bool AdminGroupHasNestedGroups { get; set; }

        // LAPS
        /// <summary>True when the machine is joined to an Active Directory domain.</summary>
        public bool IsDomainJoined { get; set; }
        /// <summary>True when Windows LAPS is actively managing the local admin password.</summary>
        public bool WindowsLapsActive { get; set; }
        /// <summary>True when the legacy Microsoft LAPS CSE is installed.</summary>
        public bool LegacyLapsInstalled { get; set; }
        /// <summary>True when the LAPS check threw / could not run.</summary>
        public bool LapsCheckFailed { get; set; }

        // Cached credentials
        /// <summary>True when CachedLogonsCount is explicitly set in the registry.</summary>
        public bool CachedLogonsConfigured { get; set; }
        /// <summary>The configured cached-logon count (valid only when configured).</summary>
        public int CachedLogonsCount { get; set; }

        // LSA protection
        /// <summary>True when the LSA registry key could be opened.</summary>
        public bool LsaKeyReadable { get; set; }
        /// <summary>True when RunAsPPL = 1 or 2 (LSASS as Protected Process Light).</summary>
        public bool RunAsPplEnabled { get; set; }
        /// <summary>True when RunAsPPL = 1 (PPL enforced WITH a UEFI lock, tamper-resistant).</summary>
        public bool RunAsPplUefiLocked { get; set; }

        // Credential Guard
        /// <summary>True when the DeviceGuard registry key is present.</summary>
        public bool DeviceGuardKeyPresent { get; set; }
        /// <summary>True when EnableVirtualizationBasedSecurity = 1.</summary>
        public bool VbsEnabled { get; set; }
        /// <summary>Value of LsaCfgFlags (0 = off, 1 = with UEFI lock, 2 = without lock).</summary>
        public int LsaCfgFlags { get; set; }
    }
}
