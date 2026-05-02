namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Credential Access Detector — autonomous detection of credential theft and harvesting
/// patterns across security findings. Identifies LSASS dumping, credential file access,
/// Kerberoasting, brute-force attacks, keylogging, password spraying, and more.
/// Builds harvest chains and recommends containment actions.
///
/// MITRE ATT&CK: TA0006 (Credential Access)
/// Techniques: T1003 (OS Credential Dumping), T1003.001 (LSASS Memory),
/// T1003.002 (SAM), T1003.003 (NTDS), T1003.004 (LSA Secrets),
/// T1558.003 (Kerberoasting), T1110 (Brute Force), T1110.003 (Password Spraying),
/// T1555 (Credentials from Password Stores), T1056.001 (Keylogging),
/// T1552.001 (Credentials In Files), T1557 (Adversary-in-the-Middle)
/// </summary>
public sealed class CredentialAccessDetector
{
    private readonly AuditHistoryService _history;

    private static readonly List<CredAccessSignature> Signatures = new()
    {
        new("LSASS Memory Dump", "T1003.001",
            new[] { "lsass", "procdump", "mimikatz", "sekurlsa", "lsass.dmp", "comsvcs.dll", "minidump", "task manager.*lsass" },
            0.95, "NTLM Hashes/Tickets"),
        new("SAM Database Access", "T1003.002",
            new[] { "sam database", "sam hive", "reg save.*sam", "shadow copy.*sam", "vssadmin.*sam", "sam dump" },
            0.9, "Local Password Hashes"),
        new("NTDS.dit Extraction", "T1003.003",
            new[] { "ntds.dit", "ntdsutil", "dcsync", "drsuapi", "domain replication", "ntds dump" },
            0.95, "Domain Credentials"),
        new("LSA Secrets", "T1003.004",
            new[] { "lsa secret", "lsadump", "dpapi", "policy.*secrets", "reg save.*security" },
            0.85, "Service Account Credentials"),
        new("Kerberoasting", "T1558.003",
            new[] { "kerberoast", "spn scan", "service ticket", "tgsrepcrack", "invoke-kerberoast", "getuserspn", "rc4-hmac" },
            0.9, "Service Account Hashes"),
        new("Brute Force", "T1110",
            new[] { "brute force", "failed logon", "account lockout", "4625", "password guess", "login attempt", "authentication fail" },
            0.75, "Password"),
        new("Password Spraying", "T1110.003",
            new[] { "password spray", "spray attack", "single password.*multiple", "distributed logon", "low-and-slow" },
            0.85, "Multiple Account Passwords"),
        new("Credentials from Password Stores", "T1555",
            new[] { "credential manager", "vaultcmd", "browser password", "chrome.*login data", "firefox.*logins.json", "credential store", "windows vault" },
            0.8, "Stored Passwords"),
        new("Keylogging", "T1056.001",
            new[] { "keylog", "keystroke", "getasynckeystate", "setwindowshook", "keyboard hook", "input capture", "key capture" },
            0.85, "Typed Credentials"),
        new("Credentials In Files", "T1552.001",
            new[] { "password.*file", "credentials.*plain", "hardcoded.*password", ".env file", "config.*password", "unattend.xml", "web.config.*password", "password.*txt" },
            0.7, "Plaintext Passwords"),
        new("Adversary-in-the-Middle", "T1557",
            new[] { "mitm", "man-in-the-middle", "arp poison", "arp spoof", "llmnr", "nbt-ns", "responder", "relay attack", "ntlm relay" },
            0.9, "Network Credentials"),
        new("Forced Authentication", "T1187",
            new[] { "forced auth", "scf file", "url file.*smb", "webdav.*ntlm", "\\\\attacker", "responder.*capture", "ntlm capture" },
            0.85, "NTLM Hashes"),
    };

    /// <summary>Indicators of automated/scripted credential access (higher urgency).</summary>
    private static readonly string[] AutomationIndicators =
        { "script", "powershell", "automated", "tool", "framework", "mimikatz", "impacket", "crackmapexec", "rubeus", "hashcat", "john" };

    /// <summary>Known credential theft tool names for enhanced detection.</summary>
    private static readonly string[] KnownTools =
        { "mimikatz", "rubeus", "impacket", "crackmapexec", "hashcat", "john", "responder", "bloodhound", "lazagne", "procdump", "secretsdump", "pypykatz" };

    /// <summary>Credential value ordering (low index = low value target).</summary>
    private static readonly string[] CredentialValueLevels =
        { "Plaintext Passwords", "Typed Credentials", "Stored Passwords", "Password", "Multiple Account Passwords",
          "NTLM Hashes", "Network Credentials", "Local Password Hashes",
          "NTLM Hashes/Tickets", "Service Account Credentials", "Service Account Hashes", "Domain Credentials" };

    public CredentialAccessDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run credential access detection against the current security report.</summary>
    public CredentialAccessReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new CredentialAccessReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var attempts = new List<CredentialAccessAttempt>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectAttempts(finding, module);
            attempts.AddRange(detected);
        }

        // Scan historical findings
        foreach (var run in runs)
        {
            foreach (var fr in run.Findings)
            {
                var finding = new Finding
                {
                    Title = fr.Title,
                    Description = fr.Description,
                    Category = fr.ModuleName
                };
                var detected = DetectAttempts(finding, fr.ModuleName);
                attempts.AddRange(detected);
            }
        }

        // Deduplicate by technique + evidence within same time window
        attempts = DeduplicateAttempts(attempts);

        result.Attempts = attempts;
        result.AttemptsDetected = attempts.Count;
        result.HighSeverityAttempts = attempts.Count(a => a.Severity is CredAccessSeverity.High or CredAccessSeverity.Critical);
        result.MediumSeverityAttempts = attempts.Count(a => a.Severity == CredAccessSeverity.Medium);
        result.LowSeverityAttempts = attempts.Count(a => a.Severity == CredAccessSeverity.Low);

        // Build harvest chains
        result.Chains = BuildChains(attempts);

        // Compute stats
        result.Stats = ComputeStats(attempts);

        // Score threat
        result.ThreatScore = ComputeThreatScore(attempts, result.Chains);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(attempts, result.Chains, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<CredentialAccessAttempt> DetectAttempts(Finding finding, string module)
    {
        var results = new List<CredentialAccessAttempt>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            var isAutomated = AutomationIndicators.Any(a => text.Contains(a));
            var confidence = isAutomated ? Math.Min(sig.BaseConfidence + 0.05, 1.0) : sig.BaseConfidence;

            // Boost confidence if a known tool is referenced
            var toolFound = KnownTools.FirstOrDefault(t => text.Contains(t));
            if (toolFound != null)
                confidence = Math.Min(confidence + 0.05, 1.0);

            var attempt = new CredentialAccessAttempt
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                AccountTargeted = ExtractAccount(text),
                CredentialType = sig.CredentialType,
                SourceTool = toolFound,
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                ProcessName = ExtractProcess(text),
                IsAutomated = isAutomated,
                Indicators = new List<string>()
            };

            if (isAutomated)
                attempt.Indicators.Add("Automated/scripted credential access detected");

            if (toolFound != null)
                attempt.Indicators.Add($"Known credential theft tool referenced: {toolFound}");

            // Check for domain-level targeting
            if (text.Contains("domain") || text.Contains("ntds") || text.Contains("dcsync") || text.Contains("active directory"))
                attempt.Indicators.Add("Domain-level credential targeting detected");

            // Check for lateral movement correlation
            if (text.Contains("remote") || text.Contains("lateral") || text.Contains("pivot"))
                attempt.Indicators.Add("Possible credential access for lateral movement");

            // Severity classification
            attempt.Severity = ClassifySeverity(attempt);

            results.Add(attempt);
            break; // One technique per finding
        }

        return results;
    }

    private CredAccessSeverity ClassifySeverity(CredentialAccessAttempt attempt)
    {
        // Critical: domain credentials or LSASS with known tool
        if (attempt.CredentialType == "Domain Credentials")
            return CredAccessSeverity.Critical;
        if (attempt.MitreTechnique == "T1003.001" && attempt.SourceTool != null)
            return CredAccessSeverity.Critical;
        if (attempt.Indicators.Any(i => i.Contains("Domain-level")))
            return CredAccessSeverity.Critical;

        // High: LSASS, SAM, Kerberoasting, MITM
        if (attempt.CredentialType is "NTLM Hashes/Tickets" or "Local Password Hashes"
            or "Service Account Hashes" or "Network Credentials" or "NTLM Hashes")
            return CredAccessSeverity.High;

        // Medium: password stores, keylogging, password spraying
        if (attempt.CredentialType is "Stored Passwords" or "Typed Credentials"
            or "Multiple Account Passwords" or "Service Account Credentials")
            return CredAccessSeverity.Medium;

        // Low: brute force, credentials in files
        return CredAccessSeverity.Low;
    }

    // ── Chain Detection ──────────────────────────────────────────────

    private List<CredentialHarvestChain> BuildChains(List<CredentialAccessAttempt> attempts)
    {
        if (attempts.Count < 2) return new();

        var chains = new List<CredentialHarvestChain>();

        // Sort by time to find sequences
        var sorted = attempts.OrderBy(a => a.DetectedAt).ToList();

        // Group by target account to find per-target chains
        var byAccount = sorted
            .Where(a => a.AccountTargeted != null)
            .GroupBy(a => a.AccountTargeted!)
            .Where(g => g.Count() >= 2);

        foreach (var group in byAccount)
        {
            var steps = group.OrderBy(a => a.DetectedAt).ToList();
            var chain = new CredentialHarvestChain
            {
                Steps = steps,
                InitialVector = steps.First().Technique,
                FinalAccess = steps.Last().CredentialType ?? "unknown",
                StepCount = steps.Count,
                Duration = steps.Last().DetectedAt - steps.First().DetectedAt,
                CompoundConfidence = steps.Aggregate(1.0, (acc, a) => acc * a.Confidence)
            };
            chain.Verdict = chain.FinalAccess == "Domain Credentials"
                ? "CRITICAL: Credential harvest chain targeting domain credentials"
                : $"Multi-step credential harvest targeting {chain.FinalAccess}";
            chains.Add(chain);
        }

        // Also detect technique-progression chains (escalating credential value)
        if (sorted.Count >= 2 && !chains.Any())
        {
            var ordered = sorted
                .OrderBy(a => Array.IndexOf(CredentialValueLevels, a.CredentialType ?? ""))
                .ToList();

            if (ordered.Count >= 2)
            {
                var chain = new CredentialHarvestChain
                {
                    Steps = ordered,
                    InitialVector = ordered.First().Technique,
                    FinalAccess = ordered.Last().CredentialType ?? "unknown",
                    StepCount = ordered.Count,
                    Duration = ordered.Last().DetectedAt - ordered.First().DetectedAt,
                    CompoundConfidence = ordered.Aggregate(1.0, (acc, a) => acc * a.Confidence)
                };
                chain.Verdict = $"Multi-technique credential harvest ({chain.StepCount} steps, escalating value)";
                chains.Add(chain);
            }
        }

        return chains;
    }

    // ── Statistics ───────────────────────────────────────────────────

    private CredAccessStats ComputeStats(List<CredentialAccessAttempt> attempts)
    {
        if (attempts.Count == 0)
            return new CredAccessStats();

        var techniques = attempts.Select(a => a.Technique).Distinct().ToList();
        var accounts = attempts.Where(a => a.AccountTargeted != null).Select(a => a.AccountTargeted!).Distinct().ToList();
        var credTypes = attempts.Where(a => a.CredentialType != null).Select(a => a.CredentialType!).Distinct().ToList();
        var mostCommon = attempts
            .GroupBy(a => a.Technique)
            .OrderByDescending(g => g.Count())
            .First();

        var timeSpan = attempts.Max(a => a.DetectedAt) - attempts.Min(a => a.DetectedAt);
        var days = Math.Max(timeSpan.TotalDays, 1);

        return new CredAccessStats
        {
            TotalTechniquesUsed = techniques.Count,
            UniqueAccountsTargeted = accounts.Count,
            MostCommonTechnique = mostCommon.Key,
            AverageConfidence = Math.Round(attempts.Average(a => a.Confidence), 3),
            AutomatedAttempts = attempts.Count(a => a.IsAutomated),
            ManualAttempts = attempts.Count(a => !a.IsAutomated),
            AttackVelocity = Math.Round(attempts.Count / days, 2),
            CredentialTypesTargeted = credTypes.Count
        };
    }

    // ── Scoring ─────────────────────────────────────────────────────

    private int ComputeThreatScore(List<CredentialAccessAttempt> attempts, List<CredentialHarvestChain> chains)
    {
        if (attempts.Count == 0) return 0;

        double score = 0;

        // Base score from attempt count and severity
        score += attempts.Count(a => a.Severity == CredAccessSeverity.Critical) * 25;
        score += attempts.Count(a => a.Severity == CredAccessSeverity.High) * 15;
        score += attempts.Count(a => a.Severity == CredAccessSeverity.Medium) * 8;
        score += attempts.Count(a => a.Severity == CredAccessSeverity.Low) * 3;

        // Chain bonus
        score += chains.Count * 10;
        if (chains.Any(c => c.FinalAccess == "Domain Credentials"))
            score += 20;

        // Known tool bonus
        if (attempts.Any(a => a.SourceTool != null))
            score += 15;

        // Automated attack bonus
        if (attempts.Any(a => a.IsAutomated))
            score += 10;

        // Diversity bonus (more techniques = more sophisticated)
        var uniqueTechniques = attempts.Select(a => a.Technique).Distinct().Count();
        if (uniqueTechniques >= 3) score += 10;
        if (uniqueTechniques >= 5) score += 10;

        // Credential type diversity bonus
        var uniqueCredTypes = attempts.Select(a => a.CredentialType).Distinct().Count();
        if (uniqueCredTypes >= 3) score += 5;

        return (int)Math.Min(score, 100);
    }

    private string ClassifyThreatLevel(int score) => score switch
    {
        >= 80 => "Critical",
        >= 60 => "Elevated",
        >= 40 => "Moderate",
        >= 20 => "Low",
        _ => "Minimal"
    };

    // ── Recommendations ─────────────────────────────────────────────

    private List<string> GenerateRecommendations(List<CredentialAccessAttempt> attempts,
        List<CredentialHarvestChain> chains, CredAccessStats stats)
    {
        var recs = new List<string>();

        if (attempts.Count == 0)
        {
            recs.Add("No credential access indicators detected. Continue monitoring.");
            return recs;
        }

        var techniques = attempts.Select(a => a.Technique).Distinct().ToHashSet();

        if (techniques.Contains("LSASS Memory Dump"))
            recs.Add("Enable Credential Guard to protect LSASS; configure ASR rules to block credential stealing from lsass.exe.");

        if (techniques.Contains("SAM Database Access"))
            recs.Add("Restrict access to SAM/SECURITY/SYSTEM registry hives; monitor reg.exe and vssadmin usage.");

        if (techniques.Contains("NTDS.dit Extraction"))
            recs.Add("CRITICAL: Monitor DCSync and ntdsutil usage; restrict domain replication permissions to authorized DCs only.");

        if (techniques.Contains("LSA Secrets"))
            recs.Add("Enable DPAPI protection; audit services running with plaintext passwords; rotate service account credentials.");

        if (techniques.Contains("Kerberoasting"))
            recs.Add("Use strong passwords (25+ chars) for service accounts with SPNs; implement gMSA; monitor TGS requests for RC4 encryption.");

        if (techniques.Contains("Brute Force"))
            recs.Add("Enforce account lockout policies; implement MFA; monitor Event ID 4625 for failed logon patterns.");

        if (techniques.Contains("Password Spraying"))
            recs.Add("Implement smart lockout with Azure AD; monitor for distributed authentication failures; ban common passwords.");

        if (techniques.Contains("Credentials from Password Stores"))
            recs.Add("Deploy browser password restrictions via GPO; audit Windows Credential Manager access; use enterprise password vaults.");

        if (techniques.Contains("Keylogging"))
            recs.Add("Enable ASR rules for keylogging prevention; deploy EDR with API hook monitoring; audit SetWindowsHookEx calls.");

        if (techniques.Contains("Credentials In Files"))
            recs.Add("Scan for plaintext credentials in files/configs; implement secrets management (Azure Key Vault, HashiCorp Vault); audit .env and config files.");

        if (techniques.Contains("Adversary-in-the-Middle"))
            recs.Add("Disable LLMNR and NBT-NS via GPO; require SMB signing; implement EPA for NTLM; deploy 802.1X.");

        if (techniques.Contains("Forced Authentication"))
            recs.Add("Block outbound SMB (port 445) to untrusted networks; disable NTLM where possible; implement NTLM auditing.");

        // Chain-level recommendations
        if (chains.Any(c => c.FinalAccess == "Domain Credentials"))
            recs.Add("CRITICAL: Domain credential harvest chain detected — immediate domain-wide password reset recommended.");

        if (stats.AutomatedAttempts > 0)
            recs.Add("Automated credential theft tools detected — investigate for active adversary presence and check for persistence mechanisms.");

        if (stats.AttackVelocity > 5)
            recs.Add("High credential attack velocity indicates active campaign — consider immediate network isolation and credential rotation.");

        if (stats.CredentialTypesTargeted >= 3)
            recs.Add("Multiple credential types targeted — adversary likely conducting comprehensive credential harvesting for maximum access.");

        // General
        recs.Add("Enable Windows Event Forwarding for Security events 4648 (explicit logon), 4768/4769 (Kerberos), and 4776 (NTLM validation).");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private List<CredentialAccessAttempt> DeduplicateAttempts(List<CredentialAccessAttempt> attempts)
    {
        return attempts
            .GroupBy(a => $"{a.Technique}|{a.Evidence}")
            .Select(g => g.First())
            .ToList();
    }

    private static string? ExtractAccount(string text)
    {
        var patterns = new[] { "user:", "account:", "username:", "identity:", "logon:", "target:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 40, text.Length);
            var acct = text[start..end].Trim();
            if (acct.Length > 0) return acct;
        }
        return null;
    }

    private static string? ExtractProcess(string text)
    {
        var patterns = new[] { "process:", "executable:", "binary:", "program:", "tool:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 60, text.Length);
            var proc = text[start..end].Trim();
            if (proc.Length > 0) return proc;
        }
        return null;
    }

    // ── Internal Types ──────────────────────────────────────────────

    private sealed record CredAccessSignature(
        string Name, string MitreId, string[] Keywords, double BaseConfidence, string CredentialType);
}
