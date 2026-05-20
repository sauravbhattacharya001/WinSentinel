namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Data Exfiltration Detector — autonomous detection of data exfiltration patterns
/// across security findings. Identifies cloud storage uploads, USB transfers, C2 channels,
/// code repository pushes, webhook exfiltration, scheduled/chunked transfers, and
/// alternative protocol abuse.
///
/// MITRE ATT&amp;CK: TA0010 (Exfiltration)
/// Techniques: T1048.001, T1048.002, T1048.003, T1041, T1567.001, T1567.002,
/// T1567.004, T1052.001, T1029, T1030
/// </summary>
public sealed class DataExfiltrationDetector
{
    private readonly AuditHistoryService _history;

    private const int OffHoursStart = 22;
    private const int OffHoursEnd = 6;

    private sealed record TechniqueSignature(
        string Name, string TechniqueId, string[] Keywords, double BaseConfidence);

    private static readonly List<TechniqueSignature> Signatures = new()
    {
        new("Symmetric Encrypted Non-C2", "T1048.001",
            new[] { "encrypted transfer", "aes upload", "symmetric encrypt", "tls non-standard", "custom encryption", "obfuscated payload" }, 0.75),
        new("Asymmetric Encrypted Non-C2", "T1048.002",
            new[] { "rsa upload", "asymmetric encrypt", "pgp transfer", "gpg encrypt", "public key exfil" }, 0.75),
        new("Unencrypted Non-C2 Protocol", "T1048.003",
            new[] { "ftp upload", "tftp", "dns tunnel", "icmp tunnel", "dns exfil", "dns txt record", "icmp exfiltration", "raw socket" }, 0.8),
        new("Exfiltration Over C2", "T1041",
            new[] { "c2 channel", "command and control", "beacon upload", "c2 exfil", "reverse shell upload", "staged data" }, 0.85),
        new("Exfiltration to Code Repository", "T1567.001",
            new[] { "git push", "github upload", "gitlab push", "bitbucket", "code repository", "repo push", "git remote" }, 0.8),
        new("Exfiltration to Cloud Storage", "T1567.002",
            new[] { "onedrive upload", "google drive", "dropbox upload", "s3 upload", "azure blob", "cloud storage", "mega upload", "box.com", "icloud" }, 0.85),
        new("Exfiltration Over Webhook", "T1567.004",
            new[] { "webhook", "slack webhook", "discord webhook", "teams webhook", "http post exfil", "webhook upload" }, 0.8),
        new("USB Exfiltration", "T1052.001",
            new[] { "usb", "removable media", "thumb drive", "flash drive", "external drive", "removable storage", "mass storage device" }, 0.9),
        new("Scheduled Transfer", "T1029",
            new[] { "scheduled transfer", "timed upload", "periodic exfil", "cron upload", "scheduled task upload", "batch transfer" }, 0.7),
        new("Chunked Transfer", "T1030",
            new[] { "chunked", "split file", "data chunk", "fragmented transfer", "size limit", "segmented upload", "partial transfer" }, 0.7),
    };

    /// <summary>Indicators of high data volume.</summary>
    private static readonly string[] VolumeIndicators =
        { "large", "bulk", "massive", "gigabyte", "terabyte", "high volume", "large file", "archive", "compressed", "zip", "7z", "rar" };

    /// <summary>Indicators of encrypted channels.</summary>
    private static readonly string[] EncryptionIndicators =
        { "encrypt", "ssl", "tls", "pgp", "gpg", "aes", "rsa", "obfuscat", "encoded", "base64" };

    /// <summary>Indicators suggesting unusual protocols.</summary>
    private static readonly string[] UnusualProtocolIndicators =
        { "dns tunnel", "icmp", "raw socket", "covert channel", "steganograph", "non-standard port", "protocol abuse" };

    /// <summary>Destination extraction patterns.</summary>
    private static readonly string[] DestinationPatterns =
        { "to ", "dest:", "destination:", "target:", "upload to", "server:", "endpoint:", "url:" };

    public DataExfiltrationDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run data exfiltration detection against the current security report.</summary>
    public DataExfiltrationReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new DataExfiltrationReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var events = new List<ExfiltrationEvent>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectExfiltration(finding, module);
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
                var detected = DetectExfiltration(finding, fr.ModuleName);
                events.AddRange(detected);
            }
            result.EventsProcessed += run.Findings.Count;
        }

        result.Events = events;
        result.ExfiltrationsDetected = events.Count;

        // Classify severity counts
        result.HighSeverityCount = events.Count(e => e.Severity == "High" || e.Severity == "Critical");
        result.MediumSeverityCount = events.Count(e => e.Severity == "Medium");
        result.LowSeverityCount = events.Count(e => e.Severity == "Low");

        // Compute threat score
        result.ThreatScore = ComputeThreatScore(events);
        result.ThreatLevel = result.ThreatScore switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 40 => "Medium",
            >= 20 => "Low",
            _ => "Minimal"
        };

        // Build channels
        result.Channels = BuildChannels(events);

        // Compute stats
        result.Stats = ComputeStats(events);

        // Build graph
        result.Graph = BuildGraph(events);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(events);

        return result;
    }

    private List<ExfiltrationEvent> DetectExfiltration(Finding finding, string module)
    {
        var events = new List<ExfiltrationEvent>();
        var text = $"{finding.Title} {finding.Description} {finding.Category}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            var matchedKeywords = sig.Keywords.Where(k => text.Contains(k)).ToList();
            if (matchedKeywords.Count == 0) continue;

            var confidence = sig.BaseConfidence;
            var riskFactors = new List<string>();
            var contextIndicators = new List<string>(matchedKeywords);

            // Off-hours boost
            var hour = DateTimeOffset.UtcNow.Hour;
            if (hour >= OffHoursStart || hour < OffHoursEnd)
            {
                confidence = Math.Min(1.0, confidence + 0.1);
                riskFactors.Add("Off-hours activity");
            }

            // Volume boost
            if (VolumeIndicators.Any(v => text.Contains(v)))
            {
                confidence = Math.Min(1.0, confidence + 0.1);
                riskFactors.Add("High data volume indicators");
            }

            // Encryption boost
            if (EncryptionIndicators.Any(e => text.Contains(e)))
            {
                confidence = Math.Min(1.0, confidence + 0.05);
                riskFactors.Add("Encrypted channel");
            }

            // Unusual protocol boost
            if (UnusualProtocolIndicators.Any(u => text.Contains(u)))
            {
                confidence = Math.Min(1.0, confidence + 0.1);
                riskFactors.Add("Unusual protocol");
            }

            // Multiple keyword matches boost
            if (matchedKeywords.Count >= 3)
            {
                confidence = Math.Min(1.0, confidence + 0.1);
                riskFactors.Add("Multiple indicators");
            }

            var severity = confidence switch
            {
                >= 0.9 => "Critical",
                >= 0.8 => "High",
                >= 0.6 => "Medium",
                _ => "Low"
            };

            var destination = ExtractDestination(text);
            var volume = EstimateVolume(text);

            events.Add(new ExfiltrationEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                Technique = sig.Name,
                TechniqueId = sig.TechniqueId,
                Description = finding.Title,
                SourceProcess = module,
                DestinationAddress = destination,
                DataVolume = volume,
                Severity = severity,
                Confidence = Math.Round(confidence, 2),
                ContextIndicators = contextIndicators,
                RiskFactors = riskFactors
            });
        }

        return events;
    }

    private static string ExtractDestination(string text)
    {
        foreach (var pattern in DestinationPatterns)
        {
            var idx = text.IndexOf(pattern, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + pattern.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 50, text.Length);
            var dest = text[start..end].Trim();
            if (dest.Length > 0) return dest;
        }
        return "Unknown";
    }

    private static long EstimateVolume(string text)
    {
        if (text.Contains("terabyte") || text.Contains("tb")) return 1_099_511_627_776;
        if (text.Contains("gigabyte") || text.Contains("gb")) return 1_073_741_824;
        if (text.Contains("megabyte") || text.Contains("mb")) return 1_048_576;
        if (text.Contains("large") || text.Contains("bulk") || text.Contains("massive")) return 104_857_600;
        if (text.Contains("archive") || text.Contains("zip") || text.Contains("compressed")) return 52_428_800;
        return 0;
    }

    private static double ComputeThreatScore(List<ExfiltrationEvent> events)
    {
        if (events.Count == 0) return 0;

        double score = 0;
        foreach (var e in events)
        {
            score += e.Severity switch
            {
                "Critical" => 25,
                "High" => 15,
                "Medium" => 8,
                _ => 3
            };
        }

        return Math.Min(100, score);
    }

    private static List<ExfiltrationChannel> BuildChannels(List<ExfiltrationEvent> events)
    {
        return events
            .GroupBy(e => e.TechniqueId)
            .Select(g => new ExfiltrationChannel
            {
                ChannelType = g.First().Technique ?? string.Empty,
                TechniqueId = g.Key,
                EventCount = g.Count(),
                TotalVolumeEstimate = g.Sum(e => e.DataVolume),
                FirstSeen = g.Min(e => e.Timestamp),
                LastSeen = g.Max(e => e.Timestamp),
                Severity = g.Max(e => e.Severity) ?? "Medium"
            })
            .OrderByDescending(c => c.EventCount)
            .ToList();
    }

    private static DataExfiltrationStats ComputeStats(List<ExfiltrationEvent> events)
    {
        var destinations = events.Select(e => e.DestinationAddress).Where(d => d != "Unknown").Distinct().ToList();
        return new DataExfiltrationStats
        {
            TotalChannelsDetected = events.Select(e => e.TechniqueId).Distinct().Count(),
            UniqueDestinations = destinations.Count,
            OffHoursExfiltrations = events.Count(e => e.RiskFactors.Contains("Off-hours activity")),
            HighVolumeTransfers = events.Count(e => e.RiskFactors.Contains("High data volume indicators")),
            EncryptedChannelCount = events.Count(e => e.RiskFactors.Contains("Encrypted channel")),
            UnusualProtocolCount = events.Count(e => e.RiskFactors.Contains("Unusual protocol"))
        };
    }

    private static ExfiltrationGraph BuildGraph(List<ExfiltrationEvent> events)
    {
        var graph = new ExfiltrationGraph();
        var nodeSet = new HashSet<string>();

        foreach (var e in events)
        {
            var srcId = $"proc:{e.SourceProcess}";
            var channelId = $"channel:{e.TechniqueId}";
            var destId = $"dest:{e.DestinationAddress}";

            if (nodeSet.Add(srcId))
                graph.Nodes.Add(new ExfilNode { Id = srcId, Label = e.SourceProcess, Type = "process" });
            if (nodeSet.Add(channelId))
                graph.Nodes.Add(new ExfilNode { Id = channelId, Label = e.Technique, Type = "channel" });
            if (nodeSet.Add(destId))
                graph.Nodes.Add(new ExfilNode { Id = destId, Label = e.DestinationAddress, Type = "destination" });

            graph.Edges.Add(new ExfilEdge { Source = srcId, Target = channelId, Label = "uses", Weight = e.Confidence });
            graph.Edges.Add(new ExfilEdge { Source = channelId, Target = destId, Label = "exfils to", Weight = e.Confidence });
        }

        return graph;
    }

    private static List<DataExfiltrationRecommendation> GenerateRecommendations(List<ExfiltrationEvent> events)
    {
        var recs = new List<DataExfiltrationRecommendation>();
        var techniques = events.Select(e => e.TechniqueId).Distinct().ToHashSet();
        int priority = 1;

        if (techniques.Contains("T1567.002"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "DLP",
                Title = "Block unauthorized cloud storage uploads",
                Description = "Implement Data Loss Prevention (DLP) policies to monitor and block uploads to unauthorized cloud storage services (OneDrive, Dropbox, Google Drive, etc.).",
                MitreTechnique = "T1567.002"
            });

        if (techniques.Contains("T1052.001"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "Endpoint",
                Title = "Restrict removable media access",
                Description = "Enforce device control policies to block or audit USB/removable media writes. Use BitLocker To Go for authorized devices.",
                MitreTechnique = "T1052.001"
            });

        if (techniques.Contains("T1048.003") || techniques.Contains("T1048.001") || techniques.Contains("T1048.002"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "Network",
                Title = "Monitor and restrict non-standard protocols",
                Description = "Deploy network monitoring to detect DNS tunneling, ICMP exfiltration, and non-standard protocol usage. Block outbound traffic on unauthorized ports.",
                MitreTechnique = "T1048"
            });

        if (techniques.Contains("T1041"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "Network",
                Title = "Detect and block C2 exfiltration channels",
                Description = "Implement network traffic analysis to detect beaconing patterns and data staging over C2 channels. Use SSL/TLS inspection for encrypted C2.",
                MitreTechnique = "T1041"
            });

        if (techniques.Contains("T1567.001"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "DLP",
                Title = "Audit code repository access",
                Description = "Monitor git push operations and block pushes to unauthorized repositories. Review access tokens and SSH keys regularly.",
                MitreTechnique = "T1567.001"
            });

        if (techniques.Contains("T1567.004"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "Network",
                Title = "Control webhook and API endpoint access",
                Description = "Restrict outbound HTTP POST requests to approved webhook URLs. Monitor for data exfiltration through messaging platform webhooks.",
                MitreTechnique = "T1567.004"
            });

        if (techniques.Contains("T1029"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "Monitoring",
                Title = "Detect scheduled data transfers",
                Description = "Monitor scheduled tasks and cron jobs for periodic data transfer patterns. Alert on new scheduled tasks that access sensitive data.",
                MitreTechnique = "T1029"
            });

        if (techniques.Contains("T1030"))
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = priority++,
                Category = "Monitoring",
                Title = "Detect chunked data exfiltration",
                Description = "Monitor for repeated small-sized transfers to the same destination that may indicate data being exfiltrated in chunks to avoid detection.",
                MitreTechnique = "T1030"
            });

        if (recs.Count == 0)
            recs.Add(new DataExfiltrationRecommendation
            {
                Priority = 1,
                Category = "General",
                Title = "Maintain DLP monitoring",
                Description = "No active exfiltration detected. Continue monitoring data flows and maintain DLP policies.",
                MitreTechnique = "TA0010"
            });

        return recs;
    }
}
