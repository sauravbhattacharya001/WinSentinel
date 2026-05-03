namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Initial Access Detector — autonomous detection of techniques adversaries use to gain
/// their first foothold inside a network. Identifies phishing, drive-by compromise,
/// exploited public-facing applications, valid accounts abuse, supply chain compromise,
/// trusted relationships abuse, external remote services, and more.
///
/// MITRE ATT&CK: TA0001 (Initial Access)
/// Techniques: T1566 (Phishing), T1566.001 (Spearphishing Attachment),
/// T1566.002 (Spearphishing Link), T1189 (Drive-by Compromise),
/// T1190 (Exploit Public-Facing Application), T1133 (External Remote Services),
/// T1078 (Valid Accounts), T1078.001 (Default Accounts),
/// T1195 (Supply Chain Compromise), T1199 (Trusted Relationship),
/// T1091 (Replication Through Removable Media), T1200 (Hardware Additions)
/// </summary>
public sealed class InitialAccessDetector
{
    private readonly AuditHistoryService _history;

    private static readonly List<InitialAccessSignature> Signatures = new()
    {
        new("Spearphishing Attachment", "T1566.001",
            new[] { "phishing attachment", "malicious attachment", "macro-enabled", "suspicious email attachment",
                    "office macro", "vba macro", "email attachment.*executable", ".docm", ".xlsm",
                    "suspicious document", "weaponized document", "maldoc" },
            0.85, "Email"),
        new("Spearphishing Link", "T1566.002",
            new[] { "phishing link", "malicious url", "suspicious email link", "credential harvesting",
                    "phishing url", "fake login", "lookalike domain", "typosquat",
                    "email.*malicious link", "spearphish" },
            0.8, "Email"),
        new("Drive-by Compromise", "T1189",
            new[] { "drive-by", "watering hole", "browser exploit", "exploit kit",
                    "malicious redirect", "iframe injection", "malvertising",
                    "browser vulnerability", "web exploit", "compromised website" },
            0.85, "Web"),
        new("Exploit Public-Facing Application", "T1190",
            new[] { "exploit.*public", "web application exploit", "sql injection", "rce.*web",
                    "remote code execution.*server", "cve.*exploit", "web shell",
                    "vulnerable service", "exposed service", "public-facing.*exploit",
                    "application vulnerability", "server exploit", "0-day", "zero-day" },
            0.9, "Network"),
        new("External Remote Services", "T1133",
            new[] { "rdp.*external", "vpn.*compromise", "ssh.*brute", "exposed rdp",
                    "remote desktop.*internet", "citrix.*exploit", "vpn.*vulnerability",
                    "remote service.*exposed", "external.*ssh", "exposed.*remote",
                    "rdp.*internet", "open rdp" },
            0.85, "Network"),
        new("Valid Accounts", "T1078",
            new[] { "stolen credential", "compromised account", "valid account.*abuse",
                    "credential stuffing", "account takeover", "leaked password",
                    "credential reuse", "dark web.*credential", "breached credential",
                    "pass-the-hash", "compromised password" },
            0.8, "Credential"),
        new("Default Accounts", "T1078.001",
            new[] { "default password", "default credential", "default account",
                    "factory password", "unchanged password", "vendor default",
                    "admin.*default", "default.*admin", "out-of-box credential" },
            0.75, "Credential"),
        new("Supply Chain Compromise", "T1195",
            new[] { "supply chain", "compromised update", "malicious package",
                    "trojanized software", "software supply chain", "dependency confusion",
                    "compromised vendor", "backdoored update", "solarwinds",
                    "package hijack", "typosquatting.*package" },
            0.9, "Supply Chain"),
        new("Trusted Relationship", "T1199",
            new[] { "trusted relationship", "partner compromise", "vendor access",
                    "third-party.*compromise", "msp.*compromise", "trusted third",
                    "managed service provider", "contractor.*access", "vendor.*breach" },
            0.85, "Trust"),
        new("Replication Through Removable Media", "T1091",
            new[] { "usb.*malware", "removable media", "usb.*autorun", "infected usb",
                    "usb drop", "baiting.*usb", "thumb drive.*malicious",
                    "external media.*infection", "autoplay.*usb" },
            0.75, "Physical"),
        new("Hardware Additions", "T1200",
            new[] { "rogue device", "hardware implant", "usb.*implant", "network tap",
                    "keylogger.*hardware", "rubber ducky", "bash bunny", "lan turtle",
                    "unauthorized device", "rogue access point", "evil twin" },
            0.8, "Physical"),
        new("Phishing General", "T1566",
            new[] { "phishing", "social engineering.*email", "pretexting.*email",
                    "business email compromise", "bec", "whaling",
                    "vishing", "smishing", "qr.*phishing" },
            0.75, "Email"),
    };

    /// <summary>Indicators of automated/scripted initial access (higher urgency).</summary>
    private static readonly string[] AutomationIndicators =
        { "automated", "script", "bot", "scanner", "exploit kit", "framework",
          "cobalt strike", "metasploit", "empire", "covenant", "sliver" };

    /// <summary>Known initial access tool names for enhanced detection.</summary>
    private static readonly string[] KnownTools =
        { "cobalt strike", "metasploit", "empire", "gophish", "evilginx",
          "modlishka", "king phisher", "social engineering toolkit", "set",
          "beef", "sliver", "covenant", "caldera" };

    /// <summary>Access vector risk ordering (low index = lower risk).</summary>
    private static readonly string[] AccessVectorRiskLevels =
        { "Physical", "Email", "Credential", "Web", "Trust", "Network", "Supply Chain" };

    public InitialAccessDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run initial access detection against the current security report.</summary>
    public InitialAccessReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new InitialAccessReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var attempts = new List<InitialAccessAttempt>();

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

        // Deduplicate by technique + evidence
        attempts = DeduplicateAttempts(attempts);

        result.Attempts = attempts;
        result.AttemptsDetected = attempts.Count;
        result.HighSeverityAttempts = attempts.Count(a => a.Severity is InitialAccessSeverity.High or InitialAccessSeverity.Critical);
        result.MediumSeverityAttempts = attempts.Count(a => a.Severity == InitialAccessSeverity.Medium);
        result.LowSeverityAttempts = attempts.Count(a => a.Severity == InitialAccessSeverity.Low);

        // Build campaigns
        result.Campaigns = BuildCampaigns(attempts);

        // Compute stats
        result.Stats = ComputeStats(attempts);

        // Score threat
        result.ThreatScore = ComputeThreatScore(attempts, result.Campaigns);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(attempts, result.Campaigns, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<InitialAccessAttempt> DetectAttempts(Finding finding, string module)
    {
        var results = new List<InitialAccessAttempt>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            var isAutomated = AutomationIndicators.Any(a => text.Contains(a));
            var confidence = isAutomated ? Math.Min(sig.BaseConfidence + 0.05, 1.0) : sig.BaseConfidence;

            var toolFound = KnownTools.FirstOrDefault(t => text.Contains(t));
            if (toolFound != null)
                confidence = Math.Min(confidence + 0.05, 1.0);

            var attempt = new InitialAccessAttempt
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                TargetAsset = ExtractAsset(text),
                AccessVector = sig.AccessVector,
                SourceTool = toolFound,
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                ProcessName = ExtractProcess(text),
                IsAutomated = isAutomated,
                Indicators = new List<string>()
            };

            if (isAutomated)
                attempt.Indicators.Add("Automated/scripted initial access detected");

            if (toolFound != null)
                attempt.Indicators.Add($"Known attack tool referenced: {toolFound}");

            // Check for lateral movement correlation
            if (text.Contains("pivot") || text.Contains("lateral") || text.Contains("internal"))
                attempt.Indicators.Add("Initial access may have led to lateral movement");

            // Check for persistence indicators
            if (text.Contains("persist") || text.Contains("backdoor") || text.Contains("implant"))
                attempt.Indicators.Add("Persistence indicators detected alongside initial access");

            // Check for multiple targets
            if (text.Contains("campaign") || text.Contains("mass") || text.Contains("widespread"))
                attempt.Indicators.Add("Campaign-level targeting detected");

            // Severity classification
            attempt.Severity = ClassifySeverity(attempt);

            results.Add(attempt);
            break; // One technique per finding
        }

        return results;
    }

    private InitialAccessSeverity ClassifySeverity(InitialAccessAttempt attempt)
    {
        // Critical: supply chain, exploit of public-facing app with tool, zero-day
        if (attempt.AccessVector == "Supply Chain")
            return InitialAccessSeverity.Critical;
        if (attempt.MitreTechnique == "T1190" && attempt.SourceTool != null)
            return InitialAccessSeverity.Critical;
        if (attempt.Indicators.Any(i => i.Contains("Campaign-level")))
            return InitialAccessSeverity.Critical;

        // High: public-facing exploits, external services, drive-by
        if (attempt.AccessVector is "Network" or "Trust")
            return InitialAccessSeverity.High;
        if (attempt.MitreTechnique == "T1189")
            return InitialAccessSeverity.High;

        // Medium: phishing, valid accounts
        if (attempt.AccessVector is "Email" or "Credential")
            return InitialAccessSeverity.Medium;

        // Low: physical, default accounts
        return InitialAccessSeverity.Low;
    }

    // ── Campaign Detection ──────────────────────────────────────────

    private List<InitialAccessCampaign> BuildCampaigns(List<InitialAccessAttempt> attempts)
    {
        if (attempts.Count < 2) return new();

        var campaigns = new List<InitialAccessCampaign>();

        // Sort by time to find sequences
        var sorted = attempts.OrderBy(a => a.DetectedAt).ToList();

        // Group by target asset to find per-target campaigns
        var byAsset = sorted
            .Where(a => a.TargetAsset != null)
            .GroupBy(a => a.TargetAsset!)
            .Where(g => g.Count() >= 2);

        foreach (var group in byAsset)
        {
            var steps = group.OrderBy(a => a.DetectedAt).ToList();
            var campaign = new InitialAccessCampaign
            {
                Steps = steps,
                PrimaryVector = steps
                    .GroupBy(s => s.AccessVector)
                    .OrderByDescending(g => g.Count())
                    .First().Key ?? "unknown",
                TargetSummary = group.Key,
                VectorCount = steps.Select(s => s.AccessVector).Distinct().Count(),
                Duration = steps.Last().DetectedAt - steps.First().DetectedAt,
                CompoundConfidence = steps.Aggregate(1.0, (acc, a) => acc * a.Confidence)
            };
            campaign.Verdict = campaign.VectorCount >= 3
                ? $"CRITICAL: Multi-vector campaign against {campaign.TargetSummary} using {campaign.VectorCount} access vectors"
                : $"Multi-attempt campaign against {campaign.TargetSummary} ({campaign.Steps.Count} attempts)";
            campaigns.Add(campaign);
        }

        // Also detect multi-vector campaigns (different vectors in short time window)
        if (!campaigns.Any() && sorted.Count >= 2)
        {
            var vectors = sorted.Select(a => a.AccessVector).Distinct().Count();
            if (vectors >= 2)
            {
                var campaign = new InitialAccessCampaign
                {
                    Steps = sorted,
                    PrimaryVector = sorted
                        .GroupBy(s => s.AccessVector)
                        .OrderByDescending(g => g.Count())
                        .First().Key ?? "unknown",
                    TargetSummary = "Multiple assets",
                    VectorCount = vectors,
                    Duration = sorted.Last().DetectedAt - sorted.First().DetectedAt,
                    CompoundConfidence = sorted.Aggregate(1.0, (acc, a) => acc * a.Confidence)
                };
                campaign.Verdict = $"Multi-vector initial access campaign ({vectors} vectors, {sorted.Count} attempts)";
                campaigns.Add(campaign);
            }
        }

        return campaigns;
    }

    // ── Statistics ───────────────────────────────────────────────────

    private InitialAccessStats ComputeStats(List<InitialAccessAttempt> attempts)
    {
        if (attempts.Count == 0)
            return new InitialAccessStats();

        var techniques = attempts.Select(a => a.Technique).Distinct().ToList();
        var assets = attempts.Where(a => a.TargetAsset != null).Select(a => a.TargetAsset!).Distinct().ToList();
        var vectors = attempts.Where(a => a.AccessVector != null).Select(a => a.AccessVector!).Distinct().ToList();
        var mostCommon = attempts
            .GroupBy(a => a.Technique)
            .OrderByDescending(g => g.Count())
            .First();

        var timeSpan = attempts.Max(a => a.DetectedAt) - attempts.Min(a => a.DetectedAt);
        var days = Math.Max(timeSpan.TotalDays, 1);

        return new InitialAccessStats
        {
            TotalTechniquesUsed = techniques.Count,
            UniqueAssetsTargeted = assets.Count,
            MostCommonTechnique = mostCommon.Key,
            AverageConfidence = Math.Round(attempts.Average(a => a.Confidence), 3),
            AutomatedAttempts = attempts.Count(a => a.IsAutomated),
            ManualAttempts = attempts.Count(a => !a.IsAutomated),
            AttackVelocity = Math.Round(attempts.Count / days, 2),
            AccessVectorsUsed = vectors.Count
        };
    }

    // ── Scoring ─────────────────────────────────────────────────────

    private int ComputeThreatScore(List<InitialAccessAttempt> attempts, List<InitialAccessCampaign> campaigns)
    {
        if (attempts.Count == 0) return 0;

        double score = 0;

        // Base score from attempt count and severity
        score += attempts.Count(a => a.Severity == InitialAccessSeverity.Critical) * 25;
        score += attempts.Count(a => a.Severity == InitialAccessSeverity.High) * 15;
        score += attempts.Count(a => a.Severity == InitialAccessSeverity.Medium) * 8;
        score += attempts.Count(a => a.Severity == InitialAccessSeverity.Low) * 3;

        // Campaign bonus
        score += campaigns.Count * 10;
        if (campaigns.Any(c => c.VectorCount >= 3))
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

        // Access vector diversity bonus
        var uniqueVectors = attempts.Select(a => a.AccessVector).Distinct().Count();
        if (uniqueVectors >= 3) score += 5;

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

    private List<string> GenerateRecommendations(List<InitialAccessAttempt> attempts,
        List<InitialAccessCampaign> campaigns, InitialAccessStats stats)
    {
        var recs = new List<string>();

        if (attempts.Count == 0)
        {
            recs.Add("No initial access indicators detected. Continue monitoring.");
            return recs;
        }

        var techniques = attempts.Select(a => a.Technique).Distinct().ToHashSet();

        if (techniques.Contains("Spearphishing Attachment") || techniques.Contains("Phishing General"))
            recs.Add("Deploy email attachment sandboxing; enable macro execution policies (Block macros in files from the Internet); train staff on phishing recognition.");

        if (techniques.Contains("Spearphishing Link"))
            recs.Add("Implement URL rewriting/detonation for inbound email links; deploy browser isolation for suspicious URLs; enable Safe Links if using Microsoft 365.");

        if (techniques.Contains("Drive-by Compromise"))
            recs.Add("Keep browsers and plugins updated; deploy web content filtering; enable exploit protection (EMET/Exploit Guard); consider browser isolation for risky sites.");

        if (techniques.Contains("Exploit Public-Facing Application"))
            recs.Add("CRITICAL: Patch or mitigate the exploited vulnerability immediately; deploy WAF rules; review public-facing application inventory; implement network segmentation to limit blast radius.");

        if (techniques.Contains("External Remote Services"))
            recs.Add("Restrict RDP/SSH/VPN access to authorized IPs; enforce MFA on all remote access; audit exposed remote services; deploy network-level authentication (NLA) for RDP.");

        if (techniques.Contains("Valid Accounts"))
            recs.Add("Enforce MFA on all accounts; monitor for credential stuffing (Event ID 4625 patterns); check credentials against known breach databases; implement conditional access policies.");

        if (techniques.Contains("Default Accounts"))
            recs.Add("Audit all systems for default/vendor credentials; enforce password change on first login; disable unnecessary default accounts; implement account inventory management.");

        if (techniques.Contains("Supply Chain Compromise"))
            recs.Add("CRITICAL: Validate software integrity via checksums/signatures; implement software allowlisting; audit vendor update mechanisms; segment vendor-managed systems from crown jewels.");

        if (techniques.Contains("Trusted Relationship"))
            recs.Add("Review and restrict third-party access privileges; implement zero-trust for vendor connections; audit MSP and contractor access; require MFA for all partner/vendor accounts.");

        if (techniques.Contains("Replication Through Removable Media"))
            recs.Add("Disable USB autorun/autoplay via GPO; implement device control policies; deploy endpoint DLP for removable media; consider USB port blocking on sensitive systems.");

        if (techniques.Contains("Hardware Additions"))
            recs.Add("Implement 802.1X network access control; conduct physical security audits; deploy rogue device detection (NAC); restrict USB ports on sensitive systems.");

        // Campaign-level recommendations
        if (campaigns.Any(c => c.VectorCount >= 3))
            recs.Add("CRITICAL: Multi-vector campaign detected — activate incident response; assume breach and begin threat hunting across all attack surfaces.");

        if (stats.AutomatedAttempts > 0)
            recs.Add("Automated attack tooling detected — investigate for active adversary; check for post-exploitation and persistence mechanisms.");

        if (stats.AttackVelocity > 5)
            recs.Add("High initial access attempt velocity indicates active targeting — consider threat intelligence enrichment and increased monitoring posture.");

        if (stats.AccessVectorsUsed >= 3)
            recs.Add("Multiple access vectors in use — adversary is probing multiple entry points; review security controls across all vectors (email, network, physical).");

        // General
        recs.Add("Enable Windows Event Forwarding for Security events 4624/4625 (logon), 4648 (explicit logon), and 1102 (audit log cleared); review perimeter security controls.");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private List<InitialAccessAttempt> DeduplicateAttempts(List<InitialAccessAttempt> attempts)
    {
        return attempts
            .GroupBy(a => $"{a.Technique}|{a.Evidence}")
            .Select(g => g.First())
            .ToList();
    }

    private static string? ExtractAsset(string text)
    {
        var patterns = new[] { "server:", "host:", "target:", "system:", "endpoint:", "asset:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 40, text.Length);
            var asset = text[start..end].Trim();
            if (asset.Length > 0) return asset;
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

    private sealed record InitialAccessSignature(
        string Name, string MitreId, string[] Keywords, double BaseConfidence, string AccessVector);
}
