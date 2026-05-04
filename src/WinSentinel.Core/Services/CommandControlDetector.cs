namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Command and Control Detector — autonomous detection of C2 infrastructure and
/// communication channels adversaries use to maintain contact with compromised systems.
/// Identifies web protocol abuse, DNS tunneling, protocol tunneling, encrypted channels,
/// multi-stage C2, fallback channels, and ingress tool transfer.
///
/// MITRE ATT&amp;CK: TA0011 (Command and Control)
/// Techniques: T1071.001 (Web Protocols), T1071.002 (File Transfer Protocols),
/// T1071.003 (Mail Protocols), T1071.004 (DNS), T1132.001 (Standard Encoding),
/// T1132.002 (Non-Standard Encoding), T1573.001 (Symmetric Cryptography),
/// T1573.002 (Asymmetric Cryptography), T1008 (Fallback Channels),
/// T1104 (Multi-Stage Channels), T1105 (Ingress Tool Transfer),
/// T1572 (Protocol Tunneling)
/// </summary>
public sealed class CommandControlDetector
{
    private readonly AuditHistoryService _history;

    private sealed record C2Signature(
        string Name, string TechniqueId, string[] Keywords, double BaseConfidence, string Category);

    private static readonly List<C2Signature> Signatures = new()
    {
        new("Web Protocols", "T1071.001",
            new[] { "http c2", "https c2", "http beacon", "https beacon", "web callback",
                    "http post", "http get", "web shell", "reverse proxy", "domain fronting",
                    "cdn fronting", "http tunnel", "web c2", "http channel", "web traffic c2",
                    "malleable profile", "c2 profile" },
            0.80, "WebProtocol"),
        new("File Transfer Protocols", "T1071.002",
            new[] { "ftp c2", "sftp c2", "ftp channel", "ftp beacon", "file transfer c2",
                    "ftp command", "ftp upload", "ftp download", "ftp exfil", "tftp c2" },
            0.75, "FileTransfer"),
        new("Mail Protocols", "T1071.003",
            new[] { "smtp c2", "imap c2", "email c2", "email beacon", "mail channel",
                    "smtp beacon", "email command", "pop3 c2", "email exfil",
                    "email tunnel", "mail exfil" },
            0.75, "MailProtocol"),
        new("DNS", "T1071.004",
            new[] { "dns c2", "dns tunnel", "dns beacon", "dns exfil", "dns channel",
                    "dns txt record", "dns query c2", "dnscat", "iodine", "dns covert",
                    "subdomain encoding", "dns over https", "doh c2" },
            0.85, "DNS"),
        new("Standard Encoding", "T1132.001",
            new[] { "base64 c2", "base64 beacon", "base64 encoded command", "url encoding c2",
                    "hex encoding c2", "standard encoding", "encoded payload", "base64 channel" },
            0.65, "Encoding"),
        new("Non-Standard Encoding", "T1132.002",
            new[] { "custom encoding", "custom cipher", "xor encoding", "rot13 c2",
                    "custom obfuscation", "proprietary encoding", "non-standard encoding",
                    "steganography", "steganographic c2" },
            0.70, "Encoding"),
        new("Symmetric Cryptography", "T1573.001",
            new[] { "aes c2", "symmetric encrypt", "aes beacon", "rc4 c2", "blowfish c2",
                    "chacha20 c2", "symmetric key exchange", "encrypted c2 channel",
                    "encrypted beacon" },
            0.80, "EncryptedChannel"),
        new("Asymmetric Cryptography", "T1573.002",
            new[] { "rsa c2", "asymmetric encrypt", "rsa beacon", "ecdh c2", "tls c2",
                    "ssl c2", "certificate pinning c2", "public key c2",
                    "asymmetric key exchange", "encrypted command channel" },
            0.80, "EncryptedChannel"),
        new("Fallback Channels", "T1008",
            new[] { "fallback c2", "backup channel", "failover c2", "alternate c2",
                    "redundant channel", "secondary beacon", "dead drop resolver",
                    "backup c2", "c2 failover", "domain rotation" },
            0.85, "Fallback"),
        new("Multi-Stage Channels", "T1104",
            new[] { "multi-stage c2", "staged payload", "stage download", "stager",
                    "dropper", "staged beacon", "multi-stage channel", "payload staging",
                    "second stage", "stage two", "loader" },
            0.85, "MultiStage"),
        new("Ingress Tool Transfer", "T1105",
            new[] { "tool transfer", "ingress tool", "certutil download", "bitsadmin transfer",
                    "curl download", "wget download", "powershell download", "tool download",
                    "payload download", "binary transfer", "implant download",
                    "remote tool fetch" },
            0.75, "ToolTransfer"),
        new("Protocol Tunneling", "T1572",
            new[] { "protocol tunnel", "ssh tunnel", "vpn tunnel", "icmp tunnel",
                    "protocol encapsulation", "socks proxy", "port forwarding",
                    "reverse tunnel", "ngrok", "chisel", "cloudflared tunnel",
                    "wireguard tunnel", "tor c2" },
            0.85, "Tunneling"),
    };

    /// <summary>Known C2 frameworks for enhanced detection.</summary>
    private static readonly string[] KnownFrameworks =
        { "cobalt strike", "meterpreter", "metasploit", "empire", "sliver", "covenant",
          "havoc", "mythic", "brute ratel", "poshc2", "silent trinity", "merlin",
          "deimosc2", "koadic", "villain", "nighthawk", "manjusaka" };

    /// <summary>Indicators of encrypted communication.</summary>
    private static readonly string[] EncryptionIndicators =
        { "encrypt", "ssl", "tls", "aes", "rsa", "ecdh", "certificate", "cipher",
          "obfuscat", "encoded", "pgp", "gpg", "chacha", "rc4" };

    /// <summary>Indicators of automated/scripted C2 activity.</summary>
    private static readonly string[] AutomationIndicators =
        { "automated", "scheduled", "periodic", "beacon", "heartbeat", "callback",
          "interval", "jitter", "polling", "recurring" };

    /// <summary>Indicators of evasion techniques in C2 traffic.</summary>
    private static readonly string[] EvasionIndicators =
        { "domain fronting", "cdn", "cloudflare", "fastly", "akamai", "jitter",
          "sleep", "malleable", "profile", "user-agent spoof", "mimick",
          "legitimate traffic" };

    /// <summary>Protocol risk ordering (low index = lower risk).</summary>
    private static readonly string[] ProtocolRiskLevels =
        { "Encoding", "ToolTransfer", "FileTransfer", "MailProtocol", "WebProtocol",
          "EncryptedChannel", "Fallback", "MultiStage", "DNS", "Tunneling" };

    public CommandControlDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run C2 detection against the current security report.</summary>
    public CommandControlReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new CommandControlReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var events = new List<C2Event>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectC2Events(finding, module);
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
                var detected = DetectC2Events(finding, fr.ModuleName);
                events.AddRange(detected);
            }
        }

        // Deduplicate
        events = DeduplicateEvents(events);

        result.Detections = events;
        result.C2DetectionsCount = events.Count;
        result.HighSeverityC2 = events.Count(e => e.Severity is C2Severity.High or C2Severity.Critical);
        result.MediumSeverityC2 = events.Count(e => e.Severity == C2Severity.Medium);
        result.LowSeverityC2 = events.Count(e => e.Severity == C2Severity.Low);

        result.Campaigns = BuildCampaigns(events);
        result.Stats = ComputeStats(events);
        result.ThreatScore = ComputeThreatScore(events, result.Campaigns);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);
        result.Recommendations = GenerateRecommendations(events, result.Campaigns, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<C2Event> DetectC2Events(Finding finding, string module)
    {
        var results = new List<C2Event>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            var isAutomated = AutomationIndicators.Any(a => text.Contains(a));
            var confidence = isAutomated ? Math.Min(sig.BaseConfidence + 0.05, 1.0) : sig.BaseConfidence;

            var frameworkFound = KnownFrameworks.FirstOrDefault(f => text.Contains(f));
            if (frameworkFound != null)
                confidence = Math.Min(confidence + 0.10, 1.0);

            var isEncrypted = EncryptionIndicators.Any(e => text.Contains(e));
            if (isEncrypted)
                confidence = Math.Min(confidence + 0.05, 1.0);

            var evt = new C2Event
            {
                Technique = sig.Name,
                MitreTechnique = sig.TechniqueId,
                TargetAsset = ExtractAsset(text),
                ChannelType = sig.Category,
                KnownFramework = frameworkFound,
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                Protocol = ExtractProtocol(text),
                IsEncrypted = isEncrypted || sig.Category == "EncryptedChannel",
                Indicators = new List<string>()
            };

            if (isAutomated)
                evt.Indicators.Add("Automated/periodic C2 beacon activity detected");

            if (frameworkFound != null)
                evt.Indicators.Add($"Known C2 framework detected: {frameworkFound}");

            if (isEncrypted)
                evt.Indicators.Add("Encrypted C2 communication channel detected");

            // Check for evasion
            if (EvasionIndicators.Any(e => text.Contains(e)))
                evt.Indicators.Add("C2 traffic evasion technique detected — may bypass network monitoring");

            // Check for domain fronting
            if (text.Contains("domain fronting") || text.Contains("cdn fronting"))
                evt.Indicators.Add("Domain fronting detected — C2 traffic masquerading behind legitimate CDN");

            // Check for DNS tunneling
            if (text.Contains("dns tunnel") || text.Contains("dnscat") || text.Contains("iodine"))
                evt.Indicators.Add("DNS tunneling detected — covert C2 channel via DNS queries");

            // Check for multi-stage
            if (text.Contains("stager") || text.Contains("staged") || text.Contains("dropper") || text.Contains("loader"))
                evt.Indicators.Add("Multi-stage payload delivery detected — adversary establishing persistent foothold");

            // Check for fallback/redundancy
            if (text.Contains("fallback") || text.Contains("backup channel") || text.Contains("failover") || text.Contains("rotation"))
                evt.Indicators.Add("Fallback/redundant C2 channels detected — resilient adversary infrastructure");

            // Check for lateral movement integration
            if (text.Contains("lateral") || text.Contains("pivot") || text.Contains("proxy"))
                evt.Indicators.Add("C2 channel may support lateral movement — internal pivoting capability");

            // Check for data exfiltration integration
            if (text.Contains("exfil") || text.Contains("upload") || text.Contains("steal"))
                evt.Indicators.Add("C2 channel potentially used for data exfiltration");

            evt.Severity = ClassifySeverity(evt);
            results.Add(evt);
            break; // One technique per finding
        }

        return results;
    }

    private C2Severity ClassifySeverity(C2Event evt)
    {
        // Critical: known framework + encrypted, or DNS tunneling with framework
        if (evt.KnownFramework != null && evt.IsEncrypted)
            return C2Severity.Critical;
        if (evt.MitreTechnique == "T1071.004" && evt.KnownFramework != null)
            return C2Severity.Critical;

        // High: DNS tunneling, protocol tunneling, multi-stage, fallback
        if (evt.MitreTechnique is "T1071.004" or "T1572" or "T1104" or "T1008")
            return C2Severity.High;
        if (evt.KnownFramework != null)
            return C2Severity.High;

        // Medium: web protocols, mail protocols, encrypted channels, tool transfer
        if (evt.ChannelType is "WebProtocol" or "MailProtocol" or "EncryptedChannel" or "ToolTransfer" or "FileTransfer")
            return C2Severity.Medium;

        // Low: encoding only
        if (evt.ChannelType == "Encoding")
            return C2Severity.Low;

        return C2Severity.Medium;
    }

    private static List<C2Event> DeduplicateEvents(List<C2Event> events)
    {
        var seen = new HashSet<string>();
        var deduped = new List<C2Event>();
        foreach (var evt in events)
        {
            var key = $"{evt.MitreTechnique}|{evt.Evidence}";
            if (seen.Add(key))
                deduped.Add(evt);
        }
        return deduped;
    }

    private static List<C2Campaign> BuildCampaigns(List<C2Event> events)
    {
        if (events.Count < 2) return new();

        var sorted = events.OrderBy(e => e.DetectedAt).ToList();
        var campaigns = new List<C2Campaign>();
        var used = new HashSet<int>();

        for (var i = 0; i < sorted.Count; i++)
        {
            if (used.Contains(i)) continue;
            var group = new List<C2Event> { sorted[i] };
            used.Add(i);

            for (var j = i + 1; j < sorted.Count; j++)
            {
                if (used.Contains(j)) continue;
                var diff = sorted[j].DetectedAt - sorted[i].DetectedAt;
                if (diff.TotalHours <= 24)
                {
                    group.Add(sorted[j]);
                    used.Add(j);
                }
            }

            var distinctTechniques = group.Select(e => e.MitreTechnique).Distinct().Count();
            if (distinctTechniques < 2) continue;

            var protocolCounts = group.GroupBy(e => e.ChannelType ?? "unknown")
                .OrderByDescending(g => g.Count()).First();

            var assets = group.Where(e => e.TargetAsset != null).Select(e => e.TargetAsset!)
                .Distinct().ToList();

            var first = group.Min(e => e.DetectedAt);
            var last = group.Max(e => e.DetectedAt);
            var compound = 1.0 - group.Aggregate(1.0, (acc, e) => acc * (1.0 - e.Confidence));

            campaigns.Add(new C2Campaign
            {
                Channels = group,
                PrimaryProtocol = protocolCounts.Key,
                TargetSummary = assets.Count > 0 ? string.Join(", ", assets.Take(3)) : "unknown",
                ChannelCount = distinctTechniques,
                CompoundConfidence = Math.Round(compound, 3),
                Duration = last - first,
                Verdict = distinctTechniques >= 4
                    ? "Advanced multi-channel C2 infrastructure — likely APT activity"
                    : distinctTechniques >= 3
                        ? "Coordinated C2 deployment — multiple channel types in use"
                        : "Related C2 activity — possible redundant channels"
            });
        }

        return campaigns;
    }

    private static C2Stats ComputeStats(List<C2Event> events)
    {
        if (events.Count == 0)
            return new C2Stats();

        var techniques = events.Select(e => e.MitreTechnique).Distinct().ToList();
        var protocols = events.Select(e => e.Protocol).Where(p => p != null).Distinct().ToList();
        var frameworks = events.Where(e => e.KnownFramework != null)
            .Select(e => e.KnownFramework!).Distinct().ToList();

        var most = events.GroupBy(e => e.Technique)
            .OrderByDescending(g => g.Count()).First();

        var sortedTimes = events.Select(e => e.DetectedAt).OrderBy(t => t).ToList();
        double velocity = 0;
        if (sortedTimes.Count > 1)
        {
            var span = (sortedTimes.Last() - sortedTimes.First()).TotalDays;
            velocity = span > 0 ? Math.Round(events.Count / span, 2) : events.Count;
        }

        return new C2Stats
        {
            TotalTechniquesUsed = techniques.Count,
            UniqueProtocols = protocols.Count,
            MostCommonTechnique = most.Key,
            AverageConfidence = Math.Round(events.Average(e => e.Confidence), 3),
            EncryptedChannels = events.Count(e => e.IsEncrypted),
            ClearTextChannels = events.Count(e => !e.IsEncrypted),
            C2Velocity = velocity,
            FrameworksDetected = frameworks.Count
        };
    }

    private static int ComputeThreatScore(List<C2Event> events, List<C2Campaign> campaigns)
    {
        if (events.Count == 0) return 0;

        double score = 0;
        foreach (var evt in events)
        {
            score += evt.Severity switch
            {
                C2Severity.Critical => 25,
                C2Severity.High => 15,
                C2Severity.Medium => 8,
                C2Severity.Low => 3,
                _ => 0
            };
        }

        // Campaign bonus: coordinated C2 is worse
        foreach (var campaign in campaigns)
        {
            score += campaign.ChannelCount * 5;
        }

        return (int)Math.Min(score, 100);
    }

    private static string ClassifyThreatLevel(int score) => score switch
    {
        >= 80 => "Critical",
        >= 60 => "Severe",
        >= 40 => "Significant",
        >= 20 => "Moderate",
        > 0 => "Low",
        _ => "Minimal"
    };

    private static List<string> GenerateRecommendations(
        List<C2Event> events, List<C2Campaign> campaigns, C2Stats stats)
    {
        var recs = new List<string>();

        if (events.Count == 0)
        {
            recs.Add("No C2 activity detected — maintain network monitoring and DNS inspection");
            return recs;
        }

        if (events.Any(e => e.MitreTechnique == "T1071.004"))
            recs.Add("DNS C2 detected — enable DNS query logging, deploy DNS sinkholing, and monitor for high-entropy subdomain queries");

        if (events.Any(e => e.MitreTechnique == "T1572"))
            recs.Add("Protocol tunneling detected — inspect SSH/VPN connections for anomalous patterns, restrict outbound tunnel protocols");

        if (events.Any(e => e.MitreTechnique is "T1071.001"))
            recs.Add("Web-based C2 detected — deploy SSL/TLS inspection, monitor for beaconing patterns in HTTP(S) traffic");

        if (events.Any(e => e.KnownFramework != null))
        {
            var frameworks = events.Where(e => e.KnownFramework != null)
                .Select(e => e.KnownFramework!).Distinct().ToList();
            recs.Add($"Known C2 frameworks detected ({string.Join(", ", frameworks)}) — update IDS/IPS signatures, scan for related IoCs");
        }

        if (stats.EncryptedChannels > 0)
            recs.Add("Encrypted C2 channels detected — deploy TLS inspection at egress points, monitor for certificate anomalies");

        if (events.Any(e => e.MitreTechnique == "T1008"))
            recs.Add("Fallback C2 channels detected — identify and block all known C2 domains/IPs simultaneously");

        if (events.Any(e => e.MitreTechnique == "T1104"))
            recs.Add("Multi-stage C2 detected — monitor for staged payload downloads, inspect intermediate staging servers");

        if (events.Any(e => e.MitreTechnique == "T1105"))
            recs.Add("Ingress tool transfer detected — restrict certutil/bitsadmin/curl usage via AppLocker, monitor download activity");

        if (events.Any(e => e.Indicators.Any(i => i.Contains("Domain fronting"))))
            recs.Add("Domain fronting detected — configure TLS inspection to detect SNI/Host mismatches");

        if (campaigns.Count > 0)
            recs.Add($"{campaigns.Count} coordinated C2 campaign(s) detected — engage incident response, isolate affected hosts");

        if (events.Any(e => e.MitreTechnique is "T1071.003"))
            recs.Add("Mail-based C2 detected — inspect SMTP/IMAP traffic for encoded commands, restrict external mail relay");

        if (events.Any(e => e.MitreTechnique is "T1132.001" or "T1132.002"))
            recs.Add("Encoded C2 data detected — deploy deep packet inspection to decode and inspect payload content");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static string? ExtractAsset(string text)
    {
        var markers = new[] { "on ", "target ", "host ", "server ", "endpoint ", "machine ", "system " };
        foreach (var m in markers)
        {
            var idx = text.IndexOf(m, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + m.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', '.', ';', ')', '\n' }, start);
            if (end < 0) end = Math.Min(start + 40, text.Length);
            var asset = text[start..end].Trim();
            if (asset.Length > 2) return asset;
        }
        return null;
    }

    private static string? ExtractProtocol(string text)
    {
        var protocols = new[]
        {
            "https", "http", "dns", "smtp", "imap", "pop3", "ftp", "sftp", "ssh",
            "icmp", "socks", "vpn", "wireguard", "tor", "websocket"
        };
        return protocols.FirstOrDefault(p => text.Contains(p));
    }
}
