using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="FirewallAudit"/> module.
///
/// Every Windows Firewall decision lives here - the rules that turn collected raw
/// state (each profile's on/off state, the parsed inbound rule set, and the current
/// profile's default inbound/outbound policy) into <see cref="Finding"/> objects, plus
/// the fiddly netsh rule-block parser those checks depend on.
///
/// Nothing here touches netsh, PowerShell, cmd, WMI, the registry, the clock or the
/// console, so every threshold (a disabled profile is Critical, the >100 inbound-allow
/// count, the >5 any-TCP-port heuristic, the default-inbound-Allow Critical, and the
/// wide-open "any program / any remote IP / any port" inbound-rule detection) can be
/// unit-tested directly with synthetic <see cref="FirewallState"/> instances.
/// <see cref="FirewallAudit"/> owns only the collection of raw netsh output and delegates
/// every decision - including parsing - to this class.
///
/// Mirrors the established <see cref="NetworkPostureAnalyzer"/> /
/// <see cref="PowerShellSecurityAnalyzer"/> / <see cref="EncryptionAnalyzer"/> /
/// <see cref="IdentityCredentialAnalyzer"/> pattern.
/// </summary>
public static class FirewallAnalyzer
{
    /// <summary>Category label shared with <see cref="FirewallAudit"/>.</summary>
    public const string Category = "Firewall";

    /// <summary>Inbound allow-rule count above which the surface is worth reviewing.</summary>
    public const int InboundAllowRuleWarnThreshold = 100;

    /// <summary>Number of "any TCP port" inbound rules above which to warn.</summary>
    public const int AnyTcpPortRuleWarnThreshold = 5;

    // ──────────────────────────────────────────────────────────────────────
    // State DTO
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Tri-state for a value that may be unknown / unreadable.</summary>
    public enum Toggle { Unknown = 0, Enabled, Disabled }

    /// <summary>One firewall profile (Domain / Private / Public) and whether it is on.</summary>
    public sealed class FirewallProfile
    {
        public string Name { get; set; } = "";
        public Toggle State { get; set; } = Toggle.Unknown;

        public FirewallProfile() { }
        public FirewallProfile(string name, Toggle state)
        {
            Name = name ?? "";
            State = state;
        }
    }

    /// <summary>
    /// A single parsed inbound firewall rule. Only the fields the analyzer reasons
    /// about are modelled; everything else in the netsh block is ignored.
    /// </summary>
    public sealed class FirewallRule
    {
        public string Name { get; set; } = "";
        public bool Enabled { get; set; }
        /// <summary>"Allow" or "Block" (case-insensitive as collected).</summary>
        public string Action { get; set; } = "";
        /// <summary>e.g. "TCP", "UDP", "Any".</summary>
        public string Protocol { get; set; } = "";
        /// <summary>e.g. "Any", "445", "80,443".</summary>
        public string LocalPort { get; set; } = "";
        /// <summary>e.g. "Any", "192.168.1.0/24".</summary>
        public string RemoteIp { get; set; } = "";
        /// <summary>Owning program path, or "Any" when the rule is not app-scoped.</summary>
        public string Program { get; set; } = "";

        public bool IsEnabledAllow =>
            Enabled && Action.Equals("Allow", StringComparison.OrdinalIgnoreCase);

        private static bool IsAny(string? v) =>
            string.IsNullOrWhiteSpace(v) || v.Equals("Any", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// True when this rule allows inbound connections on any local port from any
        /// remote address for any program - i.e. it scopes nothing. Such a rule is a
        /// blanket "accept anything" hole rather than a targeted allowance. A blank
        /// field is treated as "Any" because netsh omits an unset scope.
        /// </summary>
        public bool IsWideOpenInboundAllow =>
            IsEnabledAllow && IsAny(LocalPort) && IsAny(RemoteIp) && IsAny(Program);
    }

    /// <summary>
    /// Data transfer object for the firewall environment. All checks operate on this
    /// record so they can be unit-tested without running real netsh commands.
    /// </summary>
    public sealed class FirewallState
    {
        /// <summary>Domain / Private / Public profile states, in collection order.</summary>
        public List<FirewallProfile> Profiles { get; set; } = new();

        /// <summary>
        /// All inbound rules parsed from netsh, or empty if the rule dump could not be
        /// read. <see cref="RulesQueried"/> distinguishes "read, none matched" from
        /// "could not read".
        /// </summary>
        public List<FirewallRule> InboundRules { get; set; } = new();

        /// <summary>False when the inbound rule dump was empty/unavailable.</summary>
        public bool RulesQueried { get; set; } = true;

        /// <summary>Default inbound policy of the current profile.</summary>
        public Toggle DefaultInboundBlock { get; set; } = Toggle.Unknown;

        /// <summary>
        /// Name of the profile the wide-open inbound rules are evaluated against
        /// (typically the active/current profile). Used only to sharpen the finding
        /// text; may be empty.
        /// </summary>
        public string CurrentProfileName { get; set; } = "";
    }

    // ──────────────────────────────────────────────────────────────────────
    // Aggregate entry point
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs every firewall check against <paramref name="state"/> and returns the
    /// findings in a stable order. Pure - no I/O.
    /// </summary>
    public static List<Finding> Analyze(FirewallState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<Finding>();
        findings.AddRange(CheckProfiles(state));
        findings.AddRange(CheckRules(state));
        findings.AddRange(CheckWideOpenInboundRules(state));
        var def = CheckInboundDefault(state);
        if (def != null) findings.Add(def);
        return findings;
    }

    // ── Profiles ──────────────────────────────────────────────────────────────

    /// <summary>
    /// One finding per profile: Pass when enabled, Critical when disabled. Unknown
    /// (unreadable) profiles emit nothing so a probe failure never invents a Pass.
    /// </summary>
    public static List<Finding> CheckProfiles(FirewallState state)
    {
        var findings = new List<Finding>();
        foreach (var profile in state.Profiles)
        {
            if (profile.State == Toggle.Enabled)
            {
                findings.Add(Finding.Pass(
                    $"{profile.Name} Firewall Enabled",
                    $"Windows Firewall {profile.Name} profile is enabled.",
                    Category));
            }
            else if (profile.State == Toggle.Disabled)
            {
                var key = profile.Name.ToLowerInvariant() + "profile";
                findings.Add(Finding.Critical(
                    $"{profile.Name} Firewall Disabled",
                    $"Windows Firewall {profile.Name} profile is DISABLED. Your system is exposed to network attacks.",
                    Category,
                    $"Enable the {profile.Name} firewall profile immediately.",
                    $"netsh advfirewall set {key} state on"));
            }
        }
        return findings;
    }

    // ── Rule counts ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates the enabled inbound allow-rule count and the number of rules that
    /// allow any TCP port. Emits an Info skip when the rule dump was unavailable.
    /// </summary>
    public static List<Finding> CheckRules(FirewallState state)
    {
        var findings = new List<Finding>();

        if (!state.RulesQueried)
        {
            findings.Add(Finding.Info(
                "Firewall Rules Check Skipped",
                "Could not retrieve firewall rules via netsh.",
                Category));
            return findings;
        }

        var allow = state.InboundRules.Where(r => r.IsEnabledAllow).ToList();
        int allowCount = allow.Count;
        int anyTcp = allow.Count(r =>
            r.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) &&
            r.LocalPort.Equals("Any", StringComparison.OrdinalIgnoreCase));

        if (allowCount > InboundAllowRuleWarnThreshold)
        {
            findings.Add(Finding.Warning(
                "High Number of Inbound Allow Rules",
                $"There are {allowCount} enabled inbound allow rules. Consider reviewing and removing unnecessary rules.",
                Category,
                "Review inbound firewall rules and disable any that are no longer needed.",
                "netsh advfirewall firewall show rule name=all dir=in"));
        }
        else
        {
            findings.Add(Finding.Pass(
                "Inbound Rules Count Acceptable",
                $"There are {allowCount} enabled inbound allow rules.",
                Category));
        }

        if (anyTcp > AnyTcpPortRuleWarnThreshold)
        {
            findings.Add(Finding.Warning(
                "Rules Allowing All TCP Ports",
                $"{anyTcp} inbound rules allow connections on any TCP port. This increases attack surface.",
                Category,
                "Review rules that allow all ports and restrict to specific ports where possible.",
                "netsh advfirewall firewall show rule name=all dir=in | findstr /i \"LocalPort\""));
        }

        return findings;
    }

    // ── Wide-open inbound rules (net-new) ────────────────────────────────────────

    /// <summary>
    /// Flags enabled inbound <c>Allow</c> rules that scope <em>nothing</em> - any
    /// local port, from any remote address, for any program. Unlike the raw
    /// allow-rule count (which treats a tightly-scoped "TCP/443 from 10.0.0.0/8 for
    /// nginx.exe" rule the same as a blanket hole), such a rule lets every process on
    /// the machine accept unsolicited inbound traffic from the entire internet on
    /// every port - exactly the misconfiguration that turns one listening service
    /// (or a future one) into remote exposure. netsh omits an unset scope field, so a
    /// blank Program/RemoteIP/LocalPort is treated as "Any".
    ///
    /// <para>Returns a Warning naming up to three offending rules when any exist, and
    /// nothing otherwise (the benign case is already reported by the rule-count Pass).
    /// The finding is not auto-fixable - which specific rule to tighten or delete is a
    /// human judgement call - so the investigative command lives in the remediation
    /// text rather than as a guaranteed-to-fail FixCommand.</para>
    /// </summary>
    public static List<Finding> CheckWideOpenInboundRules(FirewallState state)
    {
        var findings = new List<Finding>();
        if (!state.RulesQueried) return findings;

        var wideOpen = state.InboundRules.Where(r => r.IsWideOpenInboundAllow).ToList();
        if (wideOpen.Count == 0) return findings;

        var named = wideOpen
            .Select(r => string.IsNullOrWhiteSpace(r.Name) ? "(unnamed)" : r.Name)
            .Take(3)
            .ToList();
        var sample = string.Join("; ", named);
        var profileNote = string.IsNullOrWhiteSpace(state.CurrentProfileName)
            ? ""
            : $" (current profile: {state.CurrentProfileName})";

        findings.Add(Finding.Warning(
            $"Wide-Open Inbound Allow Rule(s) ({wideOpen.Count})",
            $"{wideOpen.Count} enabled inbound allow rule(s) permit any program to accept " +
            $"connections on any port from any remote address{profileNote}: {sample}. " +
            "A rule that scopes neither the program, the local port nor the remote address is a " +
            "blanket hole: every current and future listening service is reachable from the entire " +
            "network. Attackers routinely rely on such catch-all rules to reach services that were " +
            "never meant to be exposed.",
            Category,
            "Review each wide-open rule and scope it to the specific program, port and/or remote " +
            "address range it needs - or delete it if it is not required. List the rules and their " +
            "scope with: netsh advfirewall firewall show rule name=all dir=in verbose"));

        return findings;
    }

    // ── Default inbound policy ───────────────────────────────────────────────────

    /// <summary>
    /// Classifies the current profile's default inbound policy: Pass when it blocks,
    /// Critical when it allows. Returns <c>null</c> when the policy could not be read.
    /// </summary>
    public static Finding? CheckInboundDefault(FirewallState state)
    {
        if (state.DefaultInboundBlock == Toggle.Enabled)
        {
            return Finding.Pass(
                "Default Inbound Policy: Block",
                "The default inbound firewall policy is set to block, which is the recommended configuration.",
                Category);
        }

        if (state.DefaultInboundBlock == Toggle.Disabled)
        {
            return Finding.Critical(
                "Default Inbound Policy: Allow",
                "The default inbound firewall policy is set to ALLOW. All incoming connections are permitted by default.",
                Category,
                "Change the default inbound policy to Block.",
                "netsh advfirewall set currentprofile firewallpolicy blockinbound,allowoutbound");
        }

        return null;
    }

    // ──────────────────────────────────────────────────────────────────────
    // netsh parsing (pure)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads the on/off state out of a <c>netsh advfirewall show &lt;profile&gt; state</c>
    /// dump. Returns <see cref="Toggle.Enabled"/> when "ON" appears, else Disabled.
    /// A null/empty dump is Unknown so an unreadable probe does not masquerade as a
    /// disabled profile.
    /// </summary>
    public static Toggle ParseProfileState(string? netshStateOutput)
    {
        if (string.IsNullOrWhiteSpace(netshStateOutput)) return Toggle.Unknown;
        return netshStateOutput.Contains("ON", StringComparison.OrdinalIgnoreCase)
            ? Toggle.Enabled
            : Toggle.Disabled;
    }

    /// <summary>
    /// Reads the default inbound policy out of a
    /// <c>netsh advfirewall show currentprofile firewallpolicy</c> dump. The policy is
    /// reported as "&lt;inbound&gt;,&lt;outbound&gt;" (e.g. "BlockInbound,AllowOutbound").
    /// Returns Enabled (blocks) when the inbound half says Block, Disabled when it says
    /// Allow, Unknown when neither can be found.
    /// </summary>
    public static Toggle ParseDefaultInbound(string? firewallPolicyOutput)
    {
        if (string.IsNullOrWhiteSpace(firewallPolicyOutput)) return Toggle.Unknown;
        // Order matters: match the explicit inbound tokens first, then fall back to a
        // bare "Block"/"Allow" so older netsh phrasings still classify.
        if (firewallPolicyOutput.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase))
            return Toggle.Enabled;
        if (firewallPolicyOutput.Contains("AllowInbound", StringComparison.OrdinalIgnoreCase))
            return Toggle.Disabled;
        if (firewallPolicyOutput.Contains("Block", StringComparison.OrdinalIgnoreCase))
            return Toggle.Enabled;
        if (firewallPolicyOutput.Contains("Allow", StringComparison.OrdinalIgnoreCase))
            return Toggle.Disabled;
        return Toggle.Unknown;
    }

    /// <summary>
    /// Parses the full <c>netsh advfirewall firewall show rule name=all dir=in verbose</c>
    /// dump into <see cref="FirewallRule"/> objects. Rules are separated by blank lines;
    /// each field is a "Key: Value" line. Unknown keys are ignored. Blocks that carry no
    /// recognisable field become no rule.
    /// </summary>
    public static List<FirewallRule> ParseRules(string? netshRuleOutput)
    {
        var rules = new List<FirewallRule>();
        if (string.IsNullOrWhiteSpace(netshRuleOutput)) return rules;

        var blocks = netshRuleOutput.Split(
            new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var block in blocks)
        {
            var fields = ParseNetshRuleBlock(block);
            if (fields.Count == 0) continue;

            // A block must at least name a rule to be a rule (netsh emits a header
            // banner block with no "Rule Name" that we want to skip).
            if (!fields.ContainsKey("Rule Name")) continue;

            var rule = new FirewallRule
            {
                Name = fields.GetValueOrDefault("Rule Name", ""),
                Enabled = fields.GetValueOrDefault("Enabled", "")
                    .Equals("Yes", StringComparison.OrdinalIgnoreCase),
                Action = fields.GetValueOrDefault("Action", ""),
                Protocol = fields.GetValueOrDefault("Protocol", ""),
                LocalPort = fields.GetValueOrDefault("LocalPort", ""),
                RemoteIp = fields.GetValueOrDefault("RemoteIP", ""),
                Program = fields.GetValueOrDefault("Program", ""),
            };
            rules.Add(rule);
        }

        return rules;
    }

    /// <summary>
    /// Parses one netsh rule block into case-insensitive key/value pairs. Each line is
    /// "Key:                Value"; separator ("---") lines and lines without a colon
    /// are skipped.
    /// </summary>
    public static Dictionary<string, string> ParseNetshRuleBlock(string block)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(block)) return fields;

        var lines = block.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            if (line.StartsWith("---")) continue;

            var colonIdx = line.IndexOf(':');
            if (colonIdx <= 0) continue;

            var key = line.Substring(0, colonIdx).Trim();
            var value = line.Substring(colonIdx + 1).Trim();
            fields[key] = value;
        }
        return fields;
    }
}
