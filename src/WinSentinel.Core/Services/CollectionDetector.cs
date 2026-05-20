namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Collection Detector — autonomous detection of data collection patterns
/// across security findings. Identifies screen capture, clipboard access,
/// keylogging, input capture, data staging, email collection, automated
/// collection, and archive creation for exfiltration preparation.
///
/// MITRE ATT&amp;CK: TA0009 (Collection)
/// Techniques: T1113, T1115, T1056.001, T1056.002, T1056.003, T1056.004,
/// T1074.001, T1074.002, T1114.001, T1114.002, T1119, T1560.001
/// </summary>
public sealed class CollectionDetector
{
    private readonly AuditHistoryService _history;

    private const int OffHoursStart = 22;
    private const int OffHoursEnd = 6;

    private sealed record TechniqueSignature(
        string Name, string TechniqueId, string[] Keywords, double BaseConfidence);

    private static readonly List<TechniqueSignature> Signatures = new()
    {
        new("Screen Capture", "T1113",
            new[] { "screenshot", "screen capture", "printscreen", "screen grab", "display capture", "snipping", "screen record", "bitblt capture" }, 0.80),
        new("Clipboard Data", "T1115",
            new[] { "clipboard", "paste data", "clipboard monitor", "clipboard capture", "copy paste intercept", "clipboard hook", "getclipboarddata" }, 0.75),
        new("Keylogging", "T1056.001",
            new[] { "keylog", "keystroke", "key capture", "input capture", "keyboard hook", "key monitor", "setwindowshookex", "rawinput keyboard", "getkeystate" }, 0.85),
        new("GUI Input Capture", "T1056.002",
            new[] { "gui capture", "input box", "credential dialog", "fake prompt", "gui hook", "fake login", "phishing dialog", "credential popup" }, 0.80),
        new("Web Portal Capture", "T1056.003",
            new[] { "web portal", "form capture", "browser credential", "form grab", "web input", "browser hook", "form inject", "web keylog" }, 0.75),
        new("Credential API Hooking", "T1056.004",
            new[] { "credential api", "lsass hook", "api hook credential", "sspi hook", "credentialprovider", "credential intercept", "auth hook" }, 0.90),
        new("Local Data Staging", "T1074.001",
            new[] { "local staging", "staged data", "temp archive", "staging folder", "data collection folder", "staging directory", "local collect" }, 0.70),
        new("Remote Data Staging", "T1074.002",
            new[] { "remote staging", "network share staging", "smb staging", "shared drive staging", "remote collect", "unc staging", "network stage" }, 0.75),
        new("Local Email Collection", "T1114.001",
            new[] { "local email", "pst file", "ost file", "email archive", "mailbox export", "outlook data", "email dump", "mail spool" }, 0.80),
        new("Remote Email Collection", "T1114.002",
            new[] { "remote email", "exchange harvest", "owa scrape", "email forward rule", "mailbox access", "exchange impersonation", "email intercept" }, 0.85),
        new("Automated Collection", "T1119",
            new[] { "automated collection", "scripted harvest", "bulk collect", "mass data gather", "auto-scrape", "scheduled collect", "auto harvest", "systematic collection" }, 0.80),
        new("Archive via Utility", "T1560.001",
            new[] { "archive collected", "7zip", "winrar", "compress data", "zip before exfil", "tar archive", "rar archive", "makecab", "compact archive" }, 0.75),
    };

    /// <summary>Known collection tools.</summary>
    private static readonly string[] KnownTools =
    {
        "lazagne", "mimikatz", "keyscan", "hooker", "powersploit", "empire",
        "meterpreter", "cobaltstrike", "rubeus", "sharpweb", "seatbelt",
        "snaffler", "sharphound", "bloodhound", "mailsniper", "ruler",
        "pspy", "screen capture tool", "keylogger"
    };

    /// <summary>Sensitive data target indicators.</summary>
    private static readonly string[] SensitiveTargets =
    {
        "email", "credential", "password", "financial", "bank", "ssn",
        "credit card", "personal", "confidential", "secret", "private key",
        "certificate", "token", "api key", "database", "patient", "hipaa"
    };

    /// <summary>High volume indicators.</summary>
    private static readonly string[] VolumeIndicators =
    {
        "bulk", "mass", "large", "all files", "entire", "complete",
        "recursive", "sweep", "comprehensive", "full scan", "gigabyte"
    };

    /// <summary>Automation indicators.</summary>
    private static readonly string[] AutomationIndicators =
    {
        "script", "scheduled", "automated", "cron", "task scheduler",
        "powershell", "batch", "loop", "interval", "periodic", "recurring"
    };

    public CollectionDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run collection activity detection against the current security report.</summary>
    public CollectionReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new CollectionReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var events = new List<CollectionEvent>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectCollection(finding, module);
            events.AddRange(detected);
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
                var detected = DetectCollection(finding, fr.ModuleName);
                events.AddRange(detected);
            }
        }

        result.Events = events
            .OrderByDescending(e => e.Confidence)
            .ThenByDescending(e => e.Timestamp)
            .ToList();

        result.CollectionActivitiesDetected = events.Count;
        result.HighSeverityCount = events.Count(e => e.Severity == "High" || e.Severity == "Critical");
        result.MediumSeverityCount = events.Count(e => e.Severity == "Medium");
        result.LowSeverityCount = events.Count(e => e.Severity == "Low");

        // Aggregate techniques
        result.Techniques = events
            .GroupBy(e => e.TechniqueId)
            .Select(g => new CollectionTechnique
            {
                TechniqueName = g.First().Technique,
                TechniqueId = g.Key,
                EventCount = g.Count(),
                FirstSeen = g.Min(e => e.Timestamp),
                LastSeen = g.Max(e => e.Timestamp),
                Severity = g.Any(e => e.Severity == "Critical") ? "Critical" :
                           g.Any(e => e.Severity == "High") ? "High" :
                           g.Any(e => e.Severity == "Medium") ? "Medium" : "Low"
            })
            .OrderByDescending(t => t.EventCount)
            .ToList();

        // Detect campaigns (3+ techniques from same source process)
        result.Campaigns = DetectCampaigns(events);

        // Calculate stats
        result.Stats = CalculateStats(events);

        // Calculate threat score
        result.ThreatScore = CalculateThreatScore(events, result.Campaigns);
        result.ThreatLevel = result.ThreatScore switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 40 => "Moderate",
            >= 20 => "Low",
            _ => "Minimal"
        };

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(events, result.Techniques);

        return result;
    }

    private List<CollectionEvent> DetectCollection(Finding finding, string module)
    {
        var events = new List<CollectionEvent>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            var matchedKeywords = sig.Keywords
                .Where(k => text.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedKeywords.Count == 0) continue;

            var confidence = sig.BaseConfidence;
            var riskFactors = new List<string>();
            var contextIndicators = new List<string>(matchedKeywords);

            // Check for known tools
            var toolMatch = KnownTools.FirstOrDefault(t =>
                text.Contains(t, StringComparison.OrdinalIgnoreCase));
            if (toolMatch != null)
            {
                confidence = Math.Min(1.0, confidence + 0.15);
                riskFactors.Add($"Known tool: {toolMatch}");
            }

            // Check for sensitive targets
            var sensitiveMatch = SensitiveTargets
                .Where(s => text.Contains(s, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (sensitiveMatch.Count > 0)
            {
                confidence = Math.Min(1.0, confidence + 0.05 * sensitiveMatch.Count);
                riskFactors.Add($"Sensitive target: {string.Join(", ", sensitiveMatch)}");
            }

            // Check for high volume
            var volumeMatch = VolumeIndicators
                .Any(v => text.Contains(v, StringComparison.OrdinalIgnoreCase));
            if (volumeMatch)
            {
                confidence = Math.Min(1.0, confidence + 0.05);
                riskFactors.Add("High volume indicators");
            }

            // Check for automation
            var autoMatch = AutomationIndicators
                .Any(a => text.Contains(a, StringComparison.OrdinalIgnoreCase));
            if (autoMatch)
            {
                confidence = Math.Min(1.0, confidence + 0.05);
                riskFactors.Add("Automation indicators");
            }

            // Off-hours detection
            var hour = DateTimeOffset.UtcNow.Hour;
            var isOffHours = hour >= OffHoursStart || hour < OffHoursEnd;
            if (isOffHours)
            {
                confidence = Math.Min(1.0, confidence + 0.05);
                riskFactors.Add("Off-hours activity");
            }

            // Determine severity based on confidence + risk factors
            var severity = confidence switch
            {
                >= 0.90 => riskFactors.Count >= 2 ? "Critical" : "High",
                >= 0.75 => riskFactors.Count >= 2 ? "High" : "Medium",
                >= 0.60 => "Medium",
                _ => "Low"
            };

            // Extract source process hint
            var sourceProcess = ExtractProcessHint(text) ?? module;

            // Extract target data hint
            var targetData = ExtractTargetHint(text, sig.Name);

            events.Add(new CollectionEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                Technique = sig.Name,
                TechniqueId = sig.TechniqueId,
                Description = finding.Title,
                SourceProcess = sourceProcess,
                TargetData = targetData,
                Severity = severity,
                Confidence = Math.Round(confidence, 3),
                ContextIndicators = contextIndicators,
                RiskFactors = riskFactors
            });
        }

        return events;
    }

    private static string? ExtractProcessHint(string text)
    {
        var processPatterns = new[] { "process:", "exe:", "binary:", "program:", "via " };
        foreach (var pattern in processPatterns)
        {
            var idx = text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var start = idx + pattern.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n' }, start);
            if (end < 0) end = Math.Min(text.Length, start + 40);
            var value = text[start..end].Trim();
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        return null;
    }

    private static string ExtractTargetHint(string text, string technique)
    {
        var targetPatterns = new[] { "target:", "collecting:", "data:", "file:", "from:" };
        foreach (var pattern in targetPatterns)
        {
            var idx = text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var start = idx + pattern.Length;
            var end = text.IndexOfAny(new[] { ',', ';', '\n' }, start);
            if (end < 0) end = Math.Min(text.Length, start + 60);
            var value = text[start..end].Trim();
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }

        // Default target based on technique
        return technique switch
        {
            "Screen Capture" => "Display/screen content",
            "Clipboard Data" => "Clipboard buffer",
            "Keylogging" => "Keyboard input",
            "GUI Input Capture" => "GUI credentials",
            "Web Portal Capture" => "Web form data",
            "Credential API Hooking" => "Authentication credentials",
            "Local Data Staging" => "Local files",
            "Remote Data Staging" => "Remote files",
            "Local Email Collection" => "Local email data",
            "Remote Email Collection" => "Remote mailbox data",
            "Automated Collection" => "Bulk data",
            "Archive via Utility" => "Compressed archives",
            _ => "Unknown data"
        };
    }

    private static List<CollectionCampaign> DetectCampaigns(List<CollectionEvent> events)
    {
        var campaigns = new List<CollectionCampaign>();
        var byProcess = events
            .GroupBy(e => e.SourceProcess.ToLowerInvariant())
            .Where(g => !string.IsNullOrWhiteSpace(g.Key));

        var campaignId = 0;
        foreach (var group in byProcess)
        {
            var techniques = group.Select(e => e.TechniqueId).Distinct().ToList();
            if (techniques.Count < 3) continue;

            campaignId++;
            campaigns.Add(new CollectionCampaign
            {
                CampaignId = $"CAMP-{campaignId:D4}",
                SourceProcess = group.Key,
                TechniquesUsed = techniques,
                EventCount = group.Count(),
                Severity = techniques.Count >= 5 ? "Critical" : "High",
                Confidence = Math.Min(1.0, 0.7 + techniques.Count * 0.05)
            });
        }

        return campaigns.OrderByDescending(c => c.TechniquesUsed.Count).ToList();
    }

    private static CollectionStats CalculateStats(List<CollectionEvent> events)
    {
        return new CollectionStats
        {
            TotalTechniquesDetected = events.Select(e => e.TechniqueId).Distinct().Count(),
            UniqueProcesses = events.Select(e => e.SourceProcess).Distinct().Count(),
            OffHoursActivities = events.Count(e => e.RiskFactors.Any(r => r.Contains("Off-hours"))),
            HighVolumeCollections = events.Count(e => e.RiskFactors.Any(r => r.Contains("High volume"))),
            AutomatedCollectionCount = events.Count(e => e.RiskFactors.Any(r => r.Contains("Automation"))),
            SensitiveDataTargets = events.Count(e => e.RiskFactors.Any(r => r.Contains("Sensitive")))
        };
    }

    private static double CalculateThreatScore(List<CollectionEvent> events, List<CollectionCampaign> campaigns)
    {
        if (events.Count == 0) return 0;

        // Base score from event count and severity
        var severityScore = events.Sum(e => e.Severity switch
        {
            "Critical" => 15.0,
            "High" => 10.0,
            "Medium" => 5.0,
            _ => 2.0
        });

        // Technique diversity bonus
        var techniqueCount = events.Select(e => e.TechniqueId).Distinct().Count();
        var diversityBonus = techniqueCount * 5.0;

        // Campaign bonus
        var campaignBonus = campaigns.Sum(c => c.TechniquesUsed.Count * 5.0);

        // Known tool bonus
        var toolBonus = events.Count(e => e.RiskFactors.Any(r => r.StartsWith("Known tool"))) * 8.0;

        var rawScore = severityScore + diversityBonus + campaignBonus + toolBonus;
        return Math.Min(100, Math.Round(rawScore, 1));
    }

    private static List<CollectionRecommendation> GenerateRecommendations(
        List<CollectionEvent> events, List<CollectionTechnique> techniques)
    {
        var recommendations = new List<CollectionRecommendation>();
        var priority = 0;

        if (techniques.Any(t => t.TechniqueId == "T1056.001"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "Input Protection",
                Title = "Deploy anti-keylogging protection",
                Description = "Implement kernel-level input protection to prevent unauthorized keystroke capture. Consider credential guard and protected process light.",
                MitreTechnique = "T1056.001"
            });
        }

        if (techniques.Any(t => t.TechniqueId == "T1115"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "Clipboard Security",
                Title = "Monitor and restrict clipboard access",
                Description = "Audit clipboard access by non-standard processes. Implement clipboard clearing for sensitive operations.",
                MitreTechnique = "T1115"
            });
        }

        if (techniques.Any(t => t.TechniqueId is "T1114.001" or "T1114.002"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "Email Protection",
                Title = "Secure email storage and access",
                Description = "Encrypt email archives, monitor mailbox access patterns, audit email forwarding rules, and restrict PST/OST file access.",
                MitreTechnique = "T1114"
            });
        }

        if (techniques.Any(t => t.TechniqueId == "T1113"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "Screen Protection",
                Title = "Restrict screen capture capabilities",
                Description = "Monitor screen capture API usage (BitBlt, PrintWindow), restrict unnecessary screen recording software.",
                MitreTechnique = "T1113"
            });
        }

        if (techniques.Any(t => t.TechniqueId is "T1074.001" or "T1074.002"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "Data Staging",
                Title = "Monitor data staging locations",
                Description = "Watch for unusual file accumulation in temp directories, network shares, and non-standard locations. Alert on bulk file copies.",
                MitreTechnique = "T1074"
            });
        }

        if (techniques.Any(t => t.TechniqueId == "T1560.001"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "Archive Control",
                Title = "Monitor archive creation tools",
                Description = "Alert on unexpected usage of compression utilities (7zip, WinRAR, tar). Monitor for large archive creation outside normal workflows.",
                MitreTechnique = "T1560.001"
            });
        }

        if (techniques.Any(t => t.TechniqueId == "T1119"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "Automation Defense",
                Title = "Detect automated collection scripts",
                Description = "Monitor for scripted data harvesting patterns including bulk file enumeration, recursive directory scanning, and scheduled collection tasks.",
                MitreTechnique = "T1119"
            });
        }

        if (techniques.Any(t => t.TechniqueId == "T1056.004"))
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "API Protection",
                Title = "Protect credential APIs from hooking",
                Description = "Enable Credential Guard, monitor LSASS access, implement Protected Process Light for sensitive authentication services.",
                MitreTechnique = "T1056.004"
            });
        }

        // General recommendation if any events
        if (events.Count > 0 && recommendations.Count < 3)
        {
            recommendations.Add(new CollectionRecommendation
            {
                Priority = ++priority,
                Category = "General",
                Title = "Enable comprehensive DLP monitoring",
                Description = "Deploy Data Loss Prevention (DLP) sensors to detect and prevent unauthorized data collection activities across endpoints.",
                MitreTechnique = "TA0009"
            });
        }

        return recommendations;
    }
}
