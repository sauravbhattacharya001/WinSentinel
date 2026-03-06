using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Built-in security knowledge base that enriches audit findings with contextual
/// intelligence: CWE IDs, MITRE ATT&amp;CK techniques, detailed explanations,
/// impact assessments, and best practice references.
/// 
/// Provides lookup by finding title pattern, category, or CWE/ATT&amp;CK ID.
/// Supports enriching entire SecurityReports with cross-referenced metadata.
/// </summary>
public class SecurityKnowledgeBase
{
    private readonly List<KnowledgeEntry> _entries = new();
    private readonly Dictionary<string, KnowledgeEntry> _byCwe = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, KnowledgeEntry> _byAttack = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<KnowledgeEntry>> _byCategory = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>All registered knowledge entries.</summary>
    public IReadOnlyList<KnowledgeEntry> Entries => _entries;

    public SecurityKnowledgeBase()
    {
        LoadBuiltInEntries();
    }

    /// <summary>
    /// Look up a knowledge entry by CWE ID (e.g., "CWE-284").
    /// </summary>
    public KnowledgeEntry? LookupByCwe(string cweId) =>
        _byCwe.TryGetValue(NormalizeCwe(cweId), out var entry) ? entry : null;

    /// <summary>
    /// Look up a knowledge entry by MITRE ATT&amp;CK technique ID (e.g., "T1053.005").
    /// </summary>
    public KnowledgeEntry? LookupByAttackId(string attackId) =>
        _byAttack.TryGetValue(attackId.Trim(), out var entry) ? entry : null;

    /// <summary>
    /// Get all knowledge entries for a given audit category.
    /// </summary>
    public IReadOnlyList<KnowledgeEntry> GetByCategory(string category) =>
        _byCategory.TryGetValue(category, out var list) ? list : Array.Empty<KnowledgeEntry>();

    /// <summary>
    /// Find the best-matching knowledge entry for a finding based on title pattern matching.
    /// Returns null if no match found.
    /// </summary>
    public KnowledgeEntry? MatchFinding(Finding finding)
    {
        // Try exact title match first
        var exact = _entries.FirstOrDefault(e =>
            e.TitlePatterns.Any(p => string.Equals(p, finding.Title, StringComparison.OrdinalIgnoreCase)));
        if (exact != null) return exact;

        // Try substring match on title patterns
        var substring = _entries.FirstOrDefault(e =>
            e.TitlePatterns.Any(p => finding.Title.Contains(p, StringComparison.OrdinalIgnoreCase)));
        if (substring != null) return substring;

        // Try keyword match (at least 2 keywords must match)
        var keywordMatch = _entries
            .Select(e => new
            {
                Entry = e,
                Matches = e.Keywords.Count(k =>
                    finding.Title.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                    finding.Description.Contains(k, StringComparison.OrdinalIgnoreCase))
            })
            .Where(x => x.Matches >= 2)
            .OrderByDescending(x => x.Matches)
            .FirstOrDefault();

        return keywordMatch?.Entry;
    }

    /// <summary>
    /// Enrich a single finding with knowledge base context.
    /// Returns an EnrichedFinding with additional metadata.
    /// </summary>
    public EnrichedFinding Enrich(Finding finding)
    {
        var entry = MatchFinding(finding);
        return new EnrichedFinding
        {
            Finding = finding,
            KnowledgeEntry = entry,
            CweId = entry?.CweId,
            AttackTechniqueId = entry?.AttackTechniqueId,
            AttackTechniqueName = entry?.AttackTechniqueName,
            ImpactRating = entry?.ImpactRating ?? ImpactRating.Unknown,
            Explanation = entry?.Explanation,
            BestPractices = entry?.BestPractices ?? Array.Empty<string>(),
            References = entry?.References ?? Array.Empty<string>(),
            RelatedCwes = entry?.RelatedCwes ?? Array.Empty<string>()
        };
    }

    /// <summary>
    /// Enrich an entire security report. Returns enrichment results
    /// with per-finding metadata and aggregate statistics.
    /// </summary>
    public EnrichmentReport EnrichReport(SecurityReport report)
    {
        var enriched = new List<EnrichedFinding>();

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                enriched.Add(Enrich(finding));
            }
        }

        var matched = enriched.Where(e => e.KnowledgeEntry != null).ToList();
        var unmatched = enriched.Where(e => e.KnowledgeEntry == null).ToList();

        // CWE distribution
        var cweDistribution = matched
            .Where(e => e.CweId != null)
            .GroupBy(e => e.CweId!)
            .ToDictionary(g => g.Key, g => g.Count());

        // ATT&CK technique distribution
        var attackDistribution = matched
            .Where(e => e.AttackTechniqueId != null)
            .GroupBy(e => e.AttackTechniqueId!)
            .ToDictionary(g => g.Key, g => g.Count());

        // Impact distribution
        var impactDistribution = matched
            .GroupBy(e => e.ImpactRating)
            .ToDictionary(g => g.Key, g => g.Count());

        // Category coverage
        var categories = report.Results.Select(r => r.Category).Distinct().ToList();
        var coveredCategories = matched
            .Select(e => e.Finding.Category)
            .Distinct()
            .ToList();

        return new EnrichmentReport
        {
            EnrichedFindings = enriched,
            TotalFindings = enriched.Count,
            MatchedCount = matched.Count,
            UnmatchedCount = unmatched.Count,
            CoveragePercent = enriched.Count > 0
                ? Math.Round(100.0 * matched.Count / enriched.Count, 1)
                : 100.0,
            CweDistribution = cweDistribution,
            AttackDistribution = attackDistribution,
            ImpactDistribution = impactDistribution,
            TotalCategories = categories.Count,
            CoveredCategories = coveredCategories.Count,
            TopCwes = cweDistribution
                .OrderByDescending(kv => kv.Value)
                .Take(5)
                .Select(kv => new CweFrequency { CweId = kv.Key, Count = kv.Value,
                    Name = LookupByCwe(kv.Key)?.Title ?? "" })
                .ToList(),
            TopAttackTechniques = attackDistribution
                .OrderByDescending(kv => kv.Value)
                .Take(5)
                .Select(kv => new AttackFrequency { TechniqueId = kv.Key, Count = kv.Value,
                    Name = LookupByAttackId(kv.Key)?.AttackTechniqueName ?? "" })
                .ToList()
        };
    }

    /// <summary>
    /// Search the knowledge base by keyword across all fields.
    /// </summary>
    public IReadOnlyList<KnowledgeEntry> Search(string query)
    {
        if (string.IsNullOrWhiteSpace(query)) return Array.Empty<KnowledgeEntry>();
        var q = query.Trim();
        return _entries.Where(e =>
            e.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            (e.CweId != null && e.CweId.Contains(q, StringComparison.OrdinalIgnoreCase)) ||
            (e.AttackTechniqueId != null && e.AttackTechniqueId.Contains(q, StringComparison.OrdinalIgnoreCase)) ||
            (e.AttackTechniqueName != null && e.AttackTechniqueName.Contains(q, StringComparison.OrdinalIgnoreCase)) ||
            (e.Explanation != null && e.Explanation.Contains(q, StringComparison.OrdinalIgnoreCase)) ||
            e.Keywords.Any(k => k.Contains(q, StringComparison.OrdinalIgnoreCase)) ||
            e.Categories.Any(c => c.Contains(q, StringComparison.OrdinalIgnoreCase))
        ).ToList();
    }

    /// <summary>
    /// Get all unique CWE IDs in the knowledge base.
    /// </summary>
    public IReadOnlyList<string> GetAllCweIds() =>
        _entries.Where(e => e.CweId != null).Select(e => e.CweId!).Distinct().OrderBy(x => x).ToList();

    /// <summary>
    /// Get all unique MITRE ATT&amp;CK technique IDs in the knowledge base.
    /// </summary>
    public IReadOnlyList<string> GetAllAttackIds() =>
        _entries.Where(e => e.AttackTechniqueId != null).Select(e => e.AttackTechniqueId!).Distinct().OrderBy(x => x).ToList();

    /// <summary>
    /// Generate a text summary of the enrichment report.
    /// </summary>
    public string GenerateTextReport(EnrichmentReport report)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("═══════════════════════════════════════════════════");
        sb.AppendLine("         Security Knowledge Base Report           ");
        sb.AppendLine("═══════════════════════════════════════════════════");
        sb.AppendLine();

        sb.AppendLine($"  Total Findings:      {report.TotalFindings}");
        sb.AppendLine($"  KB Matched:          {report.MatchedCount}");
        sb.AppendLine($"  Unmatched:           {report.UnmatchedCount}");
        sb.AppendLine($"  Coverage:            {report.CoveragePercent}%");
        sb.AppendLine($"  Category Coverage:   {report.CoveredCategories}/{report.TotalCategories}");
        sb.AppendLine();

        if (report.TopCwes.Count > 0)
        {
            sb.AppendLine("  Top CWE Weaknesses:");
            foreach (var cwe in report.TopCwes)
            {
                sb.AppendLine($"    {cwe.CweId,-10} ({cwe.Count}x) {cwe.Name}");
            }
            sb.AppendLine();
        }

        if (report.TopAttackTechniques.Count > 0)
        {
            sb.AppendLine("  Top MITRE ATT&CK Techniques:");
            foreach (var t in report.TopAttackTechniques)
            {
                sb.AppendLine($"    {t.TechniqueId,-12} ({t.Count}x) {t.Name}");
            }
            sb.AppendLine();
        }

        if (report.ImpactDistribution.Count > 0)
        {
            sb.AppendLine("  Impact Distribution:");
            foreach (var (impact, count) in report.ImpactDistribution.OrderByDescending(kv => kv.Value))
            {
                sb.AppendLine($"    {impact,-15} {count}");
            }
            sb.AppendLine();
        }

        // List findings with critical/high impact that matched
        var highImpact = report.EnrichedFindings
            .Where(e => e.ImpactRating is ImpactRating.Critical or ImpactRating.High && e.KnowledgeEntry != null)
            .ToList();

        if (highImpact.Count > 0)
        {
            sb.AppendLine("  High/Critical Impact Findings:");
            foreach (var ef in highImpact.Take(10))
            {
                sb.AppendLine($"    [{ef.ImpactRating}] {ef.Finding.Title}");
                if (ef.CweId != null) sb.AppendLine($"           CWE: {ef.CweId}");
                if (ef.AttackTechniqueId != null) sb.AppendLine($"           ATT&CK: {ef.AttackTechniqueId} ({ef.AttackTechniqueName})");
                if (ef.BestPractices.Count > 0)
                    sb.AppendLine($"           Action: {ef.BestPractices[0]}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("═══════════════════════════════════════════════════");
        return sb.ToString();
    }

    /// <summary>
    /// Register a custom knowledge entry.
    /// </summary>
    public void Register(KnowledgeEntry entry)
    {
        _entries.Add(entry);
        IndexEntry(entry);
    }

    private void IndexEntry(KnowledgeEntry entry)
    {
        if (entry.CweId != null)
            _byCwe[NormalizeCwe(entry.CweId)] = entry;
        if (entry.AttackTechniqueId != null)
            _byAttack[entry.AttackTechniqueId.Trim()] = entry;
        foreach (var cat in entry.Categories)
        {
            if (!_byCategory.ContainsKey(cat))
                _byCategory[cat] = new List<KnowledgeEntry>();
            _byCategory[cat].Add(entry);
        }
    }

    private static string NormalizeCwe(string cweId)
    {
        var trimmed = cweId.Trim();
        if (!trimmed.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase))
            return "CWE-" + trimmed;
        return trimmed.ToUpperInvariant();
    }

    private void LoadBuiltInEntries()
    {
        // ── Firewall / Network ──
        Register(new KnowledgeEntry
        {
            Title = "Firewall Disabled",
            CweId = "CWE-284",
            AttackTechniqueId = "T1562.004",
            AttackTechniqueName = "Impair Defenses: Disable or Modify System Firewall",
            ImpactRating = ImpactRating.Critical,
            Explanation = "A disabled firewall removes the primary network perimeter defense, " +
                "allowing unrestricted inbound and outbound connections. Attackers can establish " +
                "C2 channels, exfiltrate data, and pivot laterally without triggering network-level " +
                "blocks. On shared or public networks, the machine becomes directly accessible to " +
                "any host on the same segment.",
            Categories = new[] { "Firewall", "Network" },
            TitlePatterns = new[] { "Firewall Disabled", "firewall is disabled", "Windows Firewall" },
            Keywords = new[] { "firewall", "disabled", "network", "defense" },
            BestPractices = new[]
            {
                "Enable Windows Firewall on all profiles (Domain, Private, Public)",
                "Configure default deny-inbound policy",
                "Allow only necessary applications through firewall rules",
                "Use Windows Firewall with Advanced Security for granular control"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §9.1 - Windows Firewall",
                "NIST SP 800-41 Rev 1 - Guidelines on Firewalls and Firewall Policy"
            },
            RelatedCwes = new[] { "CWE-668", "CWE-1188" }
        });

        Register(new KnowledgeEntry
        {
            Title = "Overly Permissive Firewall Rule",
            CweId = "CWE-668",
            AttackTechniqueId = "T1562.004",
            AttackTechniqueName = "Impair Defenses: Disable or Modify System Firewall",
            ImpactRating = ImpactRating.High,
            Explanation = "Firewall rules that allow all ports, all addresses, or use overly broad " +
                "wildcards create unnecessary attack surface. Each open port is a potential entry " +
                "point for exploitation, especially on public-facing network profiles.",
            Categories = new[] { "Firewall" },
            TitlePatterns = new[] { "Overly Permissive", "permissive rule", "allow all" },
            Keywords = new[] { "permissive", "firewall", "rule", "open port" },
            BestPractices = new[]
            {
                "Follow principle of least privilege for firewall rules",
                "Restrict rules to specific ports and IP ranges",
                "Audit firewall rules quarterly and remove unused entries",
                "Block inbound on Public profile by default"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §9.3 - Firewall Rules"
            },
            RelatedCwes = new[] { "CWE-284", "CWE-1188" }
        });

        // ── SMB ──
        Register(new KnowledgeEntry
        {
            Title = "SMBv1 Enabled",
            CweId = "CWE-327",
            AttackTechniqueId = "T1210",
            AttackTechniqueName = "Exploitation of Remote Services",
            ImpactRating = ImpactRating.Critical,
            Explanation = "SMBv1 is a legacy protocol with critical vulnerabilities including " +
                "EternalBlue (MS17-010), which enabled the WannaCry and NotPetya attacks. " +
                "It transmits data with weak or no encryption and has been deprecated by Microsoft.",
            Categories = new[] { "SMB", "Network" },
            TitlePatterns = new[] { "SMBv1", "SMB v1", "SMB1" },
            Keywords = new[] { "SMBv1", "SMB", "EternalBlue", "legacy protocol" },
            BestPractices = new[]
            {
                "Disable SMBv1 via PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                "Use SMBv3 which supports encryption and signing",
                "Audit SMB shares for unnecessary exposure",
                "Enable SMB signing on all connections"
            },
            References = new[]
            {
                "MS17-010 - EternalBlue",
                "CIS Benchmark Windows 11 §18.6.14 - SMBv1"
            },
            RelatedCwes = new[] { "CWE-757" }
        });

        // ── Encryption ──
        Register(new KnowledgeEntry
        {
            Title = "BitLocker Not Enabled",
            CweId = "CWE-311",
            AttackTechniqueId = "T1005",
            AttackTechniqueName = "Data from Local System",
            ImpactRating = ImpactRating.High,
            Explanation = "Without full-disk encryption, anyone with physical access to the machine " +
                "can remove the drive and read all data, including credentials, personal files, " +
                "and sensitive business documents. This is particularly dangerous for laptops and " +
                "portable devices.",
            Categories = new[] { "Encryption" },
            TitlePatterns = new[] { "BitLocker", "not encrypted", "disk encryption" },
            Keywords = new[] { "BitLocker", "encryption", "disk", "full-disk" },
            BestPractices = new[]
            {
                "Enable BitLocker on all fixed and removable drives",
                "Store recovery keys in Azure AD or Active Directory",
                "Use TPM 2.0 for key protection where available",
                "Enable pre-boot authentication for high-security environments"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §18.9.12 - BitLocker",
                "NIST SP 800-111 - Guide to Storage Encryption Technologies"
            },
            RelatedCwes = new[] { "CWE-312", "CWE-922" }
        });

        // ── Accounts ──
        Register(new KnowledgeEntry
        {
            Title = "Guest Account Enabled",
            CweId = "CWE-287",
            AttackTechniqueId = "T1078.001",
            AttackTechniqueName = "Valid Accounts: Default Accounts",
            ImpactRating = ImpactRating.High,
            Explanation = "The Guest account provides unauthenticated access to the system. " +
                "Attackers can use it to gain initial foothold without needing credentials, " +
                "then escalate privileges through local exploits.",
            Categories = new[] { "Accounts" },
            TitlePatterns = new[] { "Guest Account", "guest account enabled" },
            Keywords = new[] { "guest", "account", "unauthenticated", "default" },
            BestPractices = new[]
            {
                "Disable the Guest account (net user Guest /active:no)",
                "Audit all local accounts regularly",
                "Implement account lockout policies",
                "Use Microsoft Entra ID for centralized identity management"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §1.1.3 - Guest Account Status"
            },
            RelatedCwes = new[] { "CWE-798", "CWE-1392" }
        });

        Register(new KnowledgeEntry
        {
            Title = "Weak Password Policy",
            CweId = "CWE-521",
            AttackTechniqueId = "T1110",
            AttackTechniqueName = "Brute Force",
            ImpactRating = ImpactRating.High,
            Explanation = "Weak password requirements allow users to set easily guessable passwords. " +
                "Modern GPU-based cracking can test billions of combinations per second. Without " +
                "complexity and length requirements, common passwords like 'Password1' provide " +
                "trivial initial access.",
            Categories = new[] { "Accounts" },
            TitlePatterns = new[] { "Weak Password", "password policy", "password length" },
            Keywords = new[] { "password", "policy", "weak", "complexity", "brute force" },
            BestPractices = new[]
            {
                "Set minimum password length to 14+ characters",
                "Enable password complexity requirements",
                "Implement account lockout after 5 failed attempts",
                "Consider using passphrase policies instead of complexity rules"
            },
            References = new[]
            {
                "NIST SP 800-63B - Digital Identity Guidelines",
                "CIS Benchmark Windows 11 §1.1.1 - Password Policy"
            },
            RelatedCwes = new[] { "CWE-262", "CWE-263" }
        });

        // ── Remote Access ──
        Register(new KnowledgeEntry
        {
            Title = "RDP Without NLA",
            CweId = "CWE-306",
            AttackTechniqueId = "T1021.001",
            AttackTechniqueName = "Remote Services: Remote Desktop Protocol",
            ImpactRating = ImpactRating.Critical,
            Explanation = "Without Network Level Authentication (NLA), RDP establishes a full " +
                "graphical session before requiring credentials. This exposes the login screen to " +
                "unauthenticated users, enabling brute-force attacks, denial of service, and " +
                "exploitation of pre-auth vulnerabilities like BlueKeep (CVE-2019-0708).",
            Categories = new[] { "RemoteAccess" },
            TitlePatterns = new[] { "NLA", "Network Level Authentication", "RDP" },
            Keywords = new[] { "RDP", "NLA", "remote desktop", "BlueKeep" },
            BestPractices = new[]
            {
                "Enable NLA for all RDP connections",
                "Use RD Gateway for internet-facing access",
                "Restrict RDP to specific user groups and IP ranges",
                "Implement multi-factor authentication for RDP"
            },
            References = new[]
            {
                "CVE-2019-0708 - BlueKeep",
                "CIS Benchmark Windows 11 §18.9.65 - Remote Desktop Services"
            },
            RelatedCwes = new[] { "CWE-287" }
        });

        Register(new KnowledgeEntry
        {
            Title = "Third-Party Remote Access Tool",
            CweId = "CWE-829",
            AttackTechniqueId = "T1219",
            AttackTechniqueName = "Remote Access Software",
            ImpactRating = ImpactRating.Medium,
            Explanation = "Third-party remote access tools (TeamViewer, AnyDesk, etc.) bypass " +
                "standard Windows authentication and auditing. Attackers frequently abuse these " +
                "tools for persistent access and lateral movement, as they blend in with legitimate " +
                "administrative use.",
            Categories = new[] { "RemoteAccess" },
            TitlePatterns = new[] { "TeamViewer", "AnyDesk", "remote access tool", "VNC" },
            Keywords = new[] { "remote access", "TeamViewer", "AnyDesk", "VNC", "third-party" },
            BestPractices = new[]
            {
                "Inventory all remote access tools and remove unauthorized ones",
                "Configure unattended access only with strong passwords",
                "Monitor for unexpected remote access connections",
                "Prefer built-in RDP with NLA over third-party tools"
            },
            References = new[]
            {
                "CISA Advisory - Remote Access Software Threats"
            },
            RelatedCwes = new[] { "CWE-284" }
        });

        // ── Windows Defender ──
        Register(new KnowledgeEntry
        {
            Title = "Windows Defender Disabled",
            CweId = "CWE-693",
            AttackTechniqueId = "T1562.001",
            AttackTechniqueName = "Impair Defenses: Disable or Modify Tools",
            ImpactRating = ImpactRating.Critical,
            Explanation = "Disabling Windows Defender removes real-time malware protection, " +
                "leaving the system vulnerable to known malware, ransomware, and exploits. " +
                "Attackers frequently disable security tools as a first step after gaining access.",
            Categories = new[] { "Defender", "Antivirus" },
            TitlePatterns = new[] { "Defender Disabled", "real-time protection", "antivirus" },
            Keywords = new[] { "Defender", "disabled", "antivirus", "malware protection" },
            BestPractices = new[]
            {
                "Enable Windows Defender real-time protection",
                "Enable cloud-delivered protection for latest threat intelligence",
                "Enable tamper protection to prevent unauthorized changes",
                "Configure scheduled full scans weekly"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §18.9.47 - Windows Defender"
            },
            RelatedCwes = new[] { "CWE-778" }
        });

        // ── Updates ──
        Register(new KnowledgeEntry
        {
            Title = "Pending Security Updates",
            CweId = "CWE-1104",
            AttackTechniqueId = "T1190",
            AttackTechniqueName = "Exploit Public-Facing Application",
            ImpactRating = ImpactRating.High,
            Explanation = "Missing security patches leave known vulnerabilities exploitable. " +
                "Public exploit code is often available within days of patch release, and automated " +
                "scanning tools actively search for unpatched systems. The window between patch " +
                "release and exploitation is shrinking rapidly.",
            Categories = new[] { "Updates" },
            TitlePatterns = new[] { "pending update", "security update", "missing patch", "outdated" },
            Keywords = new[] { "update", "patch", "vulnerability", "outdated", "pending" },
            BestPractices = new[]
            {
                "Enable automatic Windows Update installation",
                "Review and install security updates within 48 hours of release",
                "Monitor CISA Known Exploited Vulnerabilities catalog",
                "Test critical updates in staging environment when possible"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §18.9.103 - Windows Update"
            },
            RelatedCwes = new[] { "CWE-1395" }
        });

        // ── Privacy ──
        Register(new KnowledgeEntry
        {
            Title = "Telemetry Level Too High",
            CweId = "CWE-359",
            AttackTechniqueId = "T1119",
            AttackTechniqueName = "Automated Collection",
            ImpactRating = ImpactRating.Low,
            Explanation = "High telemetry levels send detailed usage and diagnostic data to Microsoft, " +
                "which may include application usage patterns, browsing data, and device identifiers. " +
                "While not a direct security vulnerability, excessive telemetry increases the data " +
                "exposure surface and may violate organizational data minimization policies.",
            Categories = new[] { "Privacy" },
            TitlePatterns = new[] { "Telemetry", "diagnostic data", "privacy" },
            Keywords = new[] { "telemetry", "privacy", "diagnostic", "data collection" },
            BestPractices = new[]
            {
                "Set telemetry to 'Required' (minimum) level",
                "Review and disable unnecessary data collection features",
                "Configure diagnostic data viewer to audit what's being sent",
                "Consider Enterprise editions for granular telemetry control"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §18.9.17 - Data Collection"
            },
            RelatedCwes = new[] { "CWE-200" }
        });

        // ── Registry ──
        Register(new KnowledgeEntry
        {
            Title = "UAC Disabled or Weakened",
            CweId = "CWE-250",
            AttackTechniqueId = "T1548.002",
            AttackTechniqueName = "Abuse Elevation Control Mechanism: Bypass User Account Control",
            ImpactRating = ImpactRating.Critical,
            Explanation = "Disabling or weakening User Account Control removes the elevation prompt " +
                "that prevents unauthorized privilege escalation. Without UAC, any process running as " +
                "a standard user can silently gain administrator privileges, making privilege " +
                "escalation attacks trivial.",
            Categories = new[] { "Registry", "Configuration" },
            TitlePatterns = new[] { "UAC", "User Account Control" },
            Keywords = new[] { "UAC", "elevation", "privilege", "admin" },
            BestPractices = new[]
            {
                "Set UAC to 'Always Notify' level",
                "Enable secure desktop for UAC prompts",
                "Do not auto-elevate built-in administrator",
                "Use standard user accounts for daily work"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §2.3.17 - UAC"
            },
            RelatedCwes = new[] { "CWE-269" }
        });

        // ── PowerShell ──
        Register(new KnowledgeEntry
        {
            Title = "PowerShell Script Block Logging Disabled",
            CweId = "CWE-778",
            AttackTechniqueId = "T1059.001",
            AttackTechniqueName = "Command and Scripting Interpreter: PowerShell",
            ImpactRating = ImpactRating.High,
            Explanation = "Without script block logging, PowerShell commands executed by attackers " +
                "leave no trace. Fileless malware, living-off-the-land attacks, and post-exploitation " +
                "tools commonly use PowerShell, making logging essential for detection and forensics.",
            Categories = new[] { "PowerShell" },
            TitlePatterns = new[] { "Script Block Logging", "PowerShell logging" },
            Keywords = new[] { "PowerShell", "logging", "script block", "fileless" },
            BestPractices = new[]
            {
                "Enable PowerShell Script Block Logging",
                "Enable Module Logging for all modules",
                "Enable Transcription logging to a secure path",
                "Forward PowerShell logs to a SIEM",
                "Disable PowerShell v2 engine to prevent downgrade attacks"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §18.9.100 - PowerShell Logging",
                "MITRE ATT&CK T1059.001 - PowerShell"
            },
            RelatedCwes = new[] { "CWE-223" }
        });

        // ── Scheduled Tasks ──
        Register(new KnowledgeEntry
        {
            Title = "Suspicious Scheduled Task",
            CweId = "CWE-829",
            AttackTechniqueId = "T1053.005",
            AttackTechniqueName = "Scheduled Task/Job: Scheduled Task",
            ImpactRating = ImpactRating.High,
            Explanation = "Attackers frequently create scheduled tasks for persistence, executing " +
                "malicious payloads at login, startup, or on a timer. Tasks running from temporary " +
                "directories, user-writable locations, or using encoded PowerShell commands are " +
                "strong indicators of compromise.",
            Categories = new[] { "ScheduledTasks" },
            TitlePatterns = new[] { "Suspicious Scheduled Task", "scheduled task", "persistence" },
            Keywords = new[] { "scheduled task", "persistence", "encoded", "temp directory" },
            BestPractices = new[]
            {
                "Audit scheduled tasks regularly for unauthorized entries",
                "Monitor task creation events (Event ID 4698)",
                "Restrict task creation to administrators only",
                "Review tasks running from non-standard locations"
            },
            References = new[]
            {
                "MITRE ATT&CK T1053.005 - Scheduled Task/Job"
            },
            RelatedCwes = new[] { "CWE-284" }
        });

        // ── Services ──
        Register(new KnowledgeEntry
        {
            Title = "Unquoted Service Path",
            CweId = "CWE-428",
            AttackTechniqueId = "T1574.009",
            AttackTechniqueName = "Hijack Execution Flow: Path Interception by Unquoted Path",
            ImpactRating = ImpactRating.High,
            Explanation = "When a Windows service path contains spaces and is not quoted, Windows " +
                "tries multiple path interpretations. An attacker who can write to the ambiguous " +
                "path location can place a malicious executable that runs with the service's " +
                "privileges (often SYSTEM).",
            Categories = new[] { "Services" },
            TitlePatterns = new[] { "Unquoted Service Path", "unquoted path" },
            Keywords = new[] { "unquoted", "service path", "hijack", "space in path" },
            BestPractices = new[]
            {
                "Quote all service binary paths containing spaces",
                "Use sc qc to audit service configurations",
                "Restrict write access to directories in service paths",
                "Monitor service modifications (Event ID 7045)"
            },
            References = new[]
            {
                "CWE-428 - Unquoted Search Path or Element",
                "MITRE ATT&CK T1574.009 - Unquoted Path"
            },
            RelatedCwes = new[] { "CWE-426" }
        });

        // ── Drivers ──
        Register(new KnowledgeEntry
        {
            Title = "Unsigned Driver",
            CweId = "CWE-829",
            AttackTechniqueId = "T1014",
            AttackTechniqueName = "Rootkit",
            ImpactRating = ImpactRating.High,
            Explanation = "Unsigned drivers execute in kernel space without verification of their " +
                "origin or integrity. Rootkits and kernel-level malware use unsigned drivers to " +
                "hide processes, intercept system calls, and maintain persistent, undetectable access.",
            Categories = new[] { "Drivers" },
            TitlePatterns = new[] { "Unsigned Driver", "unsigned kernel driver" },
            Keywords = new[] { "unsigned", "driver", "kernel", "rootkit" },
            BestPractices = new[]
            {
                "Enable Secure Boot to prevent unsigned driver loading",
                "Enable HVCI (Memory Integrity) for driver signature enforcement",
                "Remove or update unsigned drivers",
                "Disable test signing mode in production"
            },
            References = new[]
            {
                "Microsoft - Kernel-mode code signing requirements",
                "LOLDrivers project - loldrivers.io"
            },
            RelatedCwes = new[] { "CWE-494" }
        });

        Register(new KnowledgeEntry
        {
            Title = "Vulnerable BYOVD Driver",
            CweId = "CWE-749",
            AttackTechniqueId = "T1068",
            AttackTechniqueName = "Exploitation for Privilege Escalation",
            ImpactRating = ImpactRating.Critical,
            Explanation = "Bring Your Own Vulnerable Driver (BYOVD) attacks use legitimate but " +
                "vulnerable signed drivers to gain kernel-level access. Attackers load a known-vulnerable " +
                "driver, exploit it to execute arbitrary kernel code, then use that access to disable " +
                "security tools, install rootkits, or escalate privileges.",
            Categories = new[] { "Drivers" },
            TitlePatterns = new[] { "BYOVD", "vulnerable driver", "known vulnerable" },
            Keywords = new[] { "BYOVD", "vulnerable driver", "privilege escalation", "kernel" },
            BestPractices = new[]
            {
                "Enable HVCI (Memory Integrity) to block known vulnerable drivers",
                "Keep the Microsoft Vulnerable Driver Blocklist updated",
                "Monitor driver load events (Sysmon Event ID 6)",
                "Use application control policies to restrict driver loading"
            },
            References = new[]
            {
                "LOLDrivers project - loldrivers.io",
                "Microsoft - Vulnerable Driver Blocklist"
            },
            RelatedCwes = new[] { "CWE-829" }
        });

        // ── DNS ──
        Register(new KnowledgeEntry
        {
            Title = "LLMNR/NetBIOS Enabled",
            CweId = "CWE-350",
            AttackTechniqueId = "T1557.001",
            AttackTechniqueName = "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ImpactRating = ImpactRating.High,
            Explanation = "LLMNR and NetBIOS Name Service respond to name queries on the local " +
                "network when DNS fails. Attackers on the same network can poison these responses " +
                "to capture NTLMv2 hashes, relay authentication, and gain unauthorized access to " +
                "network resources.",
            Categories = new[] { "DNS", "Network" },
            TitlePatterns = new[] { "LLMNR", "NetBIOS", "name resolution" },
            Keywords = new[] { "LLMNR", "NetBIOS", "poisoning", "NTLM", "relay" },
            BestPractices = new[]
            {
                "Disable LLMNR via Group Policy",
                "Disable NetBIOS over TCP/IP on all network adapters",
                "Configure DNS as the sole name resolution method",
                "Monitor for LLMNR/NBT-NS traffic with a NIDS"
            },
            References = new[]
            {
                "MITRE ATT&CK T1557.001 - LLMNR/NBT-NS Poisoning",
                "Responder tool documentation"
            },
            RelatedCwes = new[] { "CWE-290" }
        });

        // ── Credentials ──
        Register(new KnowledgeEntry
        {
            Title = "Stored Credentials Exposed",
            CweId = "CWE-522",
            AttackTechniqueId = "T1555",
            AttackTechniqueName = "Credentials from Password Stores",
            ImpactRating = ImpactRating.High,
            Explanation = "Credentials stored in plaintext files, Git configs, browser stores, or " +
                "weakly protected credential managers can be harvested by attackers or malware. " +
                "Tools like Mimikatz, LaZagne, and browser credential dumpers automate this process.",
            Categories = new[] { "Credentials" },
            TitlePatterns = new[] { "stored credential", "plaintext password", "credential exposure" },
            Keywords = new[] { "credential", "password", "plaintext", "stored", "exposed" },
            BestPractices = new[]
            {
                "Use Windows Credential Manager with DPAPI protection",
                "Never store credentials in plaintext files",
                "Use SSH keys instead of stored passwords",
                "Enable LSASS protection (RunAsPPL)",
                "Use Git Credential Manager with secure storage"
            },
            References = new[]
            {
                "MITRE ATT&CK T1555 - Credentials from Password Stores",
                "CIS Benchmark - Credential Protection"
            },
            RelatedCwes = new[] { "CWE-256", "CWE-312" }
        });

        // ── WiFi ──
        Register(new KnowledgeEntry
        {
            Title = "Weak WiFi Encryption",
            CweId = "CWE-326",
            AttackTechniqueId = "T1040",
            AttackTechniqueName = "Network Sniffing",
            ImpactRating = ImpactRating.High,
            Explanation = "WiFi profiles using WEP or WPA-TKIP provide insufficient encryption. " +
                "WEP can be cracked in minutes with aircrack-ng. WPA-TKIP has known vulnerabilities " +
                "allowing packet injection and partial decryption. All traffic on these networks " +
                "should be considered interceptable.",
            Categories = new[] { "WiFi", "Network" },
            TitlePatterns = new[] { "WEP", "WPA-TKIP", "weak encryption", "WiFi encryption" },
            Keywords = new[] { "WiFi", "WEP", "WPA", "TKIP", "encryption", "wireless" },
            BestPractices = new[]
            {
                "Use WPA3 (or WPA2-AES minimum) for all wireless connections",
                "Remove saved profiles for networks with weak encryption",
                "Disable auto-connect to open or weakly-encrypted networks",
                "Use a VPN when connecting to any wireless network"
            },
            References = new[]
            {
                "CIS Benchmark - Wireless Network Configuration",
                "NIST SP 800-153 - Guidelines for Securing Wireless LANs"
            },
            RelatedCwes = new[] { "CWE-327" }
        });

        // ── Bluetooth ──
        Register(new KnowledgeEntry
        {
            Title = "Bluetooth Discoverable",
            CweId = "CWE-284",
            AttackTechniqueId = "T1011",
            AttackTechniqueName = "Exfiltration Over Other Network Medium",
            ImpactRating = ImpactRating.Medium,
            Explanation = "A discoverable Bluetooth adapter broadcasts its presence to nearby devices, " +
                "enabling reconnaissance, pairing attacks, and BlueBorne-style exploitation. " +
                "Bluetooth vulnerabilities can allow remote code execution without user interaction.",
            Categories = new[] { "Bluetooth" },
            TitlePatterns = new[] { "Bluetooth Discoverable", "discoverable mode" },
            Keywords = new[] { "Bluetooth", "discoverable", "pairing", "BlueBorne" },
            BestPractices = new[]
            {
                "Disable Bluetooth discoverability when not pairing",
                "Remove stale paired devices",
                "Keep Bluetooth drivers updated",
                "Disable Bluetooth entirely when not in use"
            },
            References = new[]
            {
                "BlueBorne vulnerability disclosure",
                "CIS Benchmark - Bluetooth Configuration"
            },
            RelatedCwes = new[] { "CWE-668" }
        });

        // ── Environment ──
        Register(new KnowledgeEntry
        {
            Title = "PATH Hijacking Risk",
            CweId = "CWE-426",
            AttackTechniqueId = "T1574.007",
            AttackTechniqueName = "Hijack Execution Flow: Path Interception by PATH Environment Variable",
            ImpactRating = ImpactRating.High,
            Explanation = "Writable directories in the system PATH allow attackers to place malicious " +
                "executables that shadow legitimate system commands. When a user or service runs a " +
                "command, Windows searches PATH directories in order — a malicious file placed earlier " +
                "in the path takes precedence.",
            Categories = new[] { "Environment" },
            TitlePatterns = new[] { "PATH hijacking", "writable PATH", "DLL search order" },
            Keywords = new[] { "PATH", "hijacking", "writable", "search order" },
            BestPractices = new[]
            {
                "Remove writable user directories from the system PATH",
                "Ensure PATH directories are only writable by administrators",
                "Use full paths in scripts and service configurations",
                "Audit PATH changes regularly"
            },
            References = new[]
            {
                "CWE-426 - Untrusted Search Path",
                "MITRE ATT&CK T1574.007 - PATH Interception"
            },
            RelatedCwes = new[] { "CWE-427", "CWE-428" }
        });

        // ── Browser ──
        Register(new KnowledgeEntry
        {
            Title = "Risky Browser Extension",
            CweId = "CWE-829",
            AttackTechniqueId = "T1176",
            AttackTechniqueName = "Browser Extensions",
            ImpactRating = ImpactRating.Medium,
            Explanation = "Browser extensions with excessive permissions can read all web content, " +
                "intercept authentication tokens, modify banking pages, and exfiltrate browsing data. " +
                "Malicious or compromised extensions have been used in supply-chain attacks targeting " +
                "millions of users.",
            Categories = new[] { "Browser" },
            TitlePatterns = new[] { "browser extension", "extension permission", "risky extension" },
            Keywords = new[] { "browser", "extension", "permission", "addon" },
            BestPractices = new[]
            {
                "Review extension permissions before installing",
                "Remove extensions you no longer use",
                "Prefer extensions from verified publishers",
                "Use browser policies to restrict extension installation"
            },
            References = new[]
            {
                "MITRE ATT&CK T1176 - Browser Extensions"
            },
            RelatedCwes = new[] { "CWE-284" }
        });

        // ── Virtualization ──
        Register(new KnowledgeEntry
        {
            Title = "Container Escape Risk",
            CweId = "CWE-265",
            AttackTechniqueId = "T1611",
            AttackTechniqueName = "Escape to Host",
            ImpactRating = ImpactRating.Critical,
            Explanation = "Containers running in privileged mode, with host filesystem mounts, or " +
                "without user namespace isolation can escape to the host system. A container escape " +
                "gives the attacker full access to the host and all other containers.",
            Categories = new[] { "Virtualization" },
            TitlePatterns = new[] { "privileged container", "container escape", "Docker" },
            Keywords = new[] { "container", "Docker", "privileged", "escape", "isolation" },
            BestPractices = new[]
            {
                "Never run containers in privileged mode in production",
                "Enable user namespace remapping",
                "Use read-only filesystem mounts where possible",
                "Enable Docker Content Trust for image verification"
            },
            References = new[]
            {
                "CIS Docker Benchmark",
                "MITRE ATT&CK T1611 - Escape to Host"
            },
            RelatedCwes = new[] { "CWE-250" }
        });

        // ── Certificate ──
        Register(new KnowledgeEntry
        {
            Title = "Expired Certificate",
            CweId = "CWE-298",
            AttackTechniqueId = "T1588.004",
            AttackTechniqueName = "Obtain Capabilities: Digital Certificates",
            ImpactRating = ImpactRating.Medium,
            Explanation = "Expired certificates in trusted stores can cause authentication failures, " +
                "broken TLS connections, and may indicate neglected certificate management. In some " +
                "cases, applications may fall back to insecure connections when certificates expire.",
            Categories = new[] { "Certificate" },
            TitlePatterns = new[] { "Expired Certificate", "certificate expired", "cert expiry" },
            Keywords = new[] { "certificate", "expired", "TLS", "trust store" },
            BestPractices = new[]
            {
                "Implement automated certificate lifecycle management",
                "Set up expiration alerts at 30, 14, and 7 days before expiry",
                "Remove expired certificates from trust stores",
                "Use Let's Encrypt or ACME protocol for automatic renewal"
            },
            References = new[]
            {
                "NIST SP 800-52 Rev 2 - TLS Configuration",
                "CIS Benchmark - Certificate Management"
            },
            RelatedCwes = new[] { "CWE-295" }
        });

        // ── Application Security ──
        Register(new KnowledgeEntry
        {
            Title = "AutoRun Enabled",
            CweId = "CWE-1188",
            AttackTechniqueId = "T1091",
            AttackTechniqueName = "Replication Through Removable Media",
            ImpactRating = ImpactRating.High,
            Explanation = "AutoRun/AutoPlay automatically executes programs from removable media " +
                "(USB drives, CDs) when connected. This is the primary vector for USB-based malware " +
                "like Stuxnet. An attacker who drops a USB drive in a parking lot relies on AutoRun " +
                "to execute their payload.",
            Categories = new[] { "Registry", "Configuration" },
            TitlePatterns = new[] { "AutoRun", "AutoPlay", "auto run" },
            Keywords = new[] { "AutoRun", "AutoPlay", "USB", "removable media" },
            BestPractices = new[]
            {
                "Disable AutoRun for all drive types via Group Policy",
                "Disable AutoPlay in Windows Settings",
                "Use endpoint protection with USB device control",
                "Educate users about USB-based attack vectors"
            },
            References = new[]
            {
                "CIS Benchmark Windows 11 §18.9.7 - AutoPlay/AutoRun",
                "MITRE ATT&CK T1091 - Removable Media"
            },
            RelatedCwes = new[] { "CWE-250" }
        });
    }
}

// ─── Models ─────────────────────────────────────────────────

/// <summary>
/// A knowledge base entry mapping security concepts to findings.
/// </summary>
public class KnowledgeEntry
{
    /// <summary>Human-readable title for this knowledge entry.</summary>
    public required string Title { get; set; }

    /// <summary>CWE identifier (e.g., "CWE-284").</summary>
    public string? CweId { get; set; }

    /// <summary>MITRE ATT&amp;CK technique ID (e.g., "T1562.004").</summary>
    public string? AttackTechniqueId { get; set; }

    /// <summary>MITRE ATT&amp;CK technique name.</summary>
    public string? AttackTechniqueName { get; set; }

    /// <summary>Impact rating for this type of finding.</summary>
    public ImpactRating ImpactRating { get; set; }

    /// <summary>Detailed explanation of why this matters.</summary>
    public string? Explanation { get; set; }

    /// <summary>Categories this entry applies to.</summary>
    public string[] Categories { get; set; } = Array.Empty<string>();

    /// <summary>Title patterns used for matching findings.</summary>
    public string[] TitlePatterns { get; set; } = Array.Empty<string>();

    /// <summary>Keywords used for fallback matching.</summary>
    public string[] Keywords { get; set; } = Array.Empty<string>();

    /// <summary>Recommended best practices.</summary>
    public string[] BestPractices { get; set; } = Array.Empty<string>();

    /// <summary>External references (standards, benchmarks, CVEs).</summary>
    public string[] References { get; set; } = Array.Empty<string>();

    /// <summary>Related CWE IDs.</summary>
    public string[] RelatedCwes { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Impact rating levels for knowledge entries.
/// </summary>
public enum ImpactRating
{
    Unknown,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// A finding enriched with knowledge base context.
/// </summary>
public class EnrichedFinding
{
    public required Finding Finding { get; set; }
    public KnowledgeEntry? KnowledgeEntry { get; set; }
    public string? CweId { get; set; }
    public string? AttackTechniqueId { get; set; }
    public string? AttackTechniqueName { get; set; }
    public ImpactRating ImpactRating { get; set; }
    public string? Explanation { get; set; }
    public IReadOnlyList<string> BestPractices { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> RelatedCwes { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Result of enriching an entire security report.
/// </summary>
public class EnrichmentReport
{
    public List<EnrichedFinding> EnrichedFindings { get; set; } = new();
    public int TotalFindings { get; set; }
    public int MatchedCount { get; set; }
    public int UnmatchedCount { get; set; }
    public double CoveragePercent { get; set; }
    public Dictionary<string, int> CweDistribution { get; set; } = new();
    public Dictionary<string, int> AttackDistribution { get; set; } = new();
    public Dictionary<ImpactRating, int> ImpactDistribution { get; set; } = new();
    public int TotalCategories { get; set; }
    public int CoveredCategories { get; set; }
    public List<CweFrequency> TopCwes { get; set; } = new();
    public List<AttackFrequency> TopAttackTechniques { get; set; } = new();
}

/// <summary>CWE occurrence frequency.</summary>
public class CweFrequency
{
    public required string CweId { get; set; }
    public int Count { get; set; }
    public string Name { get; set; } = "";
}

/// <summary>ATT&amp;CK technique occurrence frequency.</summary>
public class AttackFrequency
{
    public required string TechniqueId { get; set; }
    public int Count { get; set; }
    public string Name { get; set; } = "";
}
