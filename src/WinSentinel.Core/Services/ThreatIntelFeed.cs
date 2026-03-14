using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Types of threat intelligence indicators.
/// </summary>
public enum IndicatorType
{
    /// <summary>IPv4 or IPv6 address.</summary>
    IpAddress,

    /// <summary>Domain name.</summary>
    Domain,

    /// <summary>File hash (MD5, SHA1, SHA256).</summary>
    FileHash,

    /// <summary>Executable or process name.</summary>
    ProcessName,

    /// <summary>Windows registry key or value.</summary>
    RegistryKey,

    /// <summary>URL or URI pattern.</summary>
    Url,

    /// <summary>Network port number.</summary>
    Port,

    /// <summary>User-Agent string pattern.</summary>
    UserAgent,

    /// <summary>Email address (phishing source).</summary>
    Email,

    /// <summary>YARA rule or signature name.</summary>
    Signature,

    /// <summary>Certificate thumbprint.</summary>
    CertificateHash,

    /// <summary>Service name.</summary>
    ServiceName,
}

/// <summary>
/// Confidence level for an indicator.
/// </summary>
public enum IndicatorConfidence
{
    /// <summary>Unverified or crowd-sourced.</summary>
    Low = 1,

    /// <summary>Correlated from multiple sources.</summary>
    Medium = 2,

    /// <summary>Verified by analysis or trusted feed.</summary>
    High = 3,

    /// <summary>Confirmed active threat.</summary>
    Confirmed = 4,
}

/// <summary>
/// Threat classification for an indicator.
/// </summary>
public enum ThreatClassification
{
    Malware,
    Ransomware,
    Phishing,
    C2Server,
    Botnet,
    Cryptominer,
    Exploit,
    DataExfiltration,
    BruteForce,
    Reconnaissance,
    LateralMovement,
    PrivilegeEscalation,
    DefenseEvasion,
    PersistenceMechanism,
    Suspicious,
}

/// <summary>
/// A single threat intelligence indicator (IoC).
/// </summary>
public class ThreatIndicator
{
    /// <summary>Unique identifier for this indicator.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    /// <summary>The indicator value (IP, hash, domain, etc.).</summary>
    public string Value { get; set; } = "";

    /// <summary>Type of indicator.</summary>
    public IndicatorType Type { get; set; }

    /// <summary>Threat classification.</summary>
    public ThreatClassification Classification { get; set; }

    /// <summary>Confidence level.</summary>
    public IndicatorConfidence Confidence { get; set; } = IndicatorConfidence.Medium;

    /// <summary>Associated severity.</summary>
    public Severity Severity { get; set; } = Severity.Warning;

    /// <summary>Human-readable description of the threat.</summary>
    public string Description { get; set; } = "";

    /// <summary>Source feed or analyst who reported this.</summary>
    public string Source { get; set; } = "built-in";

    /// <summary>When this indicator was first seen.</summary>
    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>When this indicator was last updated.</summary>
    public DateTimeOffset LastUpdated { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>When this indicator expires (null = never).</summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>Tags for grouping and filtering.</summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>MITRE ATT&amp;CK technique IDs.</summary>
    public List<string> MitreAttackIds { get; set; } = new();

    /// <summary>Whether this indicator is currently active.</summary>
    public bool Active { get; set; } = true;

    /// <summary>Number of times this indicator was matched.</summary>
    public int HitCount { get; set; }

    /// <summary>When this indicator was last matched.</summary>
    public DateTimeOffset? LastHit { get; set; }

    /// <summary>Check if this indicator has expired.</summary>
    public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTimeOffset.UtcNow;

    /// <summary>Check if this indicator is effectively active (active and not expired).</summary>
    public bool IsEffectivelyActive => Active && !IsExpired;
}

/// <summary>
/// Result of checking a value against the threat intel feed.
/// </summary>
public class ThreatMatch
{
    /// <summary>The matched indicator.</summary>
    public ThreatIndicator Indicator { get; set; } = null!;

    /// <summary>The value that was checked.</summary>
    public string CheckedValue { get; set; } = "";

    /// <summary>How the match was made.</summary>
    public MatchType MatchType { get; set; }

    /// <summary>When the match occurred.</summary>
    public DateTimeOffset MatchedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// How a threat match was determined.
/// </summary>
public enum MatchType
{
    /// <summary>Exact string match.</summary>
    Exact,

    /// <summary>Case-insensitive match.</summary>
    CaseInsensitive,

    /// <summary>Substring or pattern match.</summary>
    Pattern,

    /// <summary>IP in CIDR range.</summary>
    CidrRange,
}

/// <summary>
/// Statistics about the threat intel feed.
/// </summary>
public class FeedStatistics
{
    public int TotalIndicators { get; set; }
    public int ActiveIndicators { get; set; }
    public int ExpiredIndicators { get; set; }
    public int TotalHits { get; set; }
    public Dictionary<IndicatorType, int> ByType { get; set; } = new();
    public Dictionary<ThreatClassification, int> ByClassification { get; set; } = new();
    public Dictionary<IndicatorConfidence, int> ByConfidence { get; set; } = new();
    public Dictionary<string, int> BySource { get; set; } = new();
    public DateTimeOffset? OldestIndicator { get; set; }
    public DateTimeOffset? NewestIndicator { get; set; }
}

/// <summary>
/// Curated threat intelligence feed for matching observed system activity
/// against known indicators of compromise (IoCs).
///
/// Provides:
/// - Built-in indicator database (known-bad IPs, domains, hashes, process names)
/// - Custom indicator management (add/remove/update)
/// - Fast lookup by type with case-insensitive matching
/// - Hit tracking and statistics
/// - JSON import/export for sharing and backup
/// - Text report generation
/// - Expiration and lifecycle management
///
/// Usage:
///   var feed = new ThreatIntelFeed();
///   feed.LoadBuiltInIndicators();
///
///   // Check an IP
///   var match = feed.CheckIp("185.220.101.1");
///   if (match != null) { /* known threat */ }
///
///   // Check a process name
///   var matches = feed.CheckProcess("mimikatz.exe");
///
///   // Add custom indicator
///   feed.AddIndicator(new ThreatIndicator {
///       Value = "evil.example.com",
///       Type = IndicatorType.Domain,
///       Classification = ThreatClassification.C2Server,
///   });
///
///   // Export/Import
///   feed.ExportJson("threat-intel.json");
///   feed.ImportJson("shared-indicators.json");
/// </summary>
public class ThreatIntelFeed
{
    private readonly List<ThreatIndicator> _indicators = new();
    private readonly Dictionary<IndicatorType, Dictionary<string, ThreatIndicator>> _index = new();
    private readonly object _lock = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>All indicators in the feed.</summary>
    public IReadOnlyList<ThreatIndicator> Indicators
    {
        get { lock (_lock) return _indicators.ToList(); }
    }

    /// <summary>Number of indicators in the feed.</summary>
    public int Count
    {
        get { lock (_lock) return _indicators.Count; }
    }

    // ── Indicator Management ─────────────────────────────────────

    /// <summary>
    /// Add an indicator to the feed. Returns false if a duplicate
    /// (same type + value) already exists.
    /// </summary>
    public bool AddIndicator(ThreatIndicator indicator)
    {
        if (indicator == null) throw new ArgumentNullException(nameof(indicator));
        if (string.IsNullOrWhiteSpace(indicator.Value))
            throw new ArgumentException("Indicator value cannot be empty.", nameof(indicator));

        var key = NormalizeValue(indicator.Value, indicator.Type);

        lock (_lock)
        {
            if (!_index.TryGetValue(indicator.Type, out var typeIndex))
            {
                typeIndex = new Dictionary<string, ThreatIndicator>(StringComparer.OrdinalIgnoreCase);
                _index[indicator.Type] = typeIndex;
            }

            if (typeIndex.ContainsKey(key))
                return false;

            typeIndex[key] = indicator;
            _indicators.Add(indicator);
            return true;
        }
    }

    /// <summary>
    /// Remove an indicator by its ID.
    /// </summary>
    public bool RemoveIndicator(string indicatorId)
    {
        lock (_lock)
        {
            var indicator = _indicators.Find(i => i.Id == indicatorId);
            if (indicator == null) return false;

            var key = NormalizeValue(indicator.Value, indicator.Type);
            if (_index.TryGetValue(indicator.Type, out var typeIndex))
                typeIndex.Remove(key);

            _indicators.Remove(indicator);
            return true;
        }
    }

    /// <summary>
    /// Deactivate an indicator by ID (soft-delete).
    /// </summary>
    public bool DeactivateIndicator(string indicatorId)
    {
        lock (_lock)
        {
            var indicator = _indicators.Find(i => i.Id == indicatorId);
            if (indicator == null) return false;
            indicator.Active = false;
            return true;
        }
    }

    /// <summary>
    /// Remove all expired indicators from the feed.
    /// Returns the number of indicators purged.
    /// </summary>
    public int PurgeExpired()
    {
        lock (_lock)
        {
            var expired = _indicators.Where(i => i.IsExpired).ToList();
            foreach (var ind in expired)
            {
                var key = NormalizeValue(ind.Value, ind.Type);
                if (_index.TryGetValue(ind.Type, out var typeIndex))
                    typeIndex.Remove(key);
                _indicators.Remove(ind);
            }
            return expired.Count;
        }
    }

    // ── Lookups ──────────────────────────────────────────────────

    /// <summary>
    /// Check an IP address against the feed.
    /// </summary>
    public ThreatMatch? CheckIp(string ipAddress)
    {
        return CheckValue(ipAddress, IndicatorType.IpAddress);
    }

    /// <summary>
    /// Check a domain name against the feed.
    /// </summary>
    public ThreatMatch? CheckDomain(string domain)
    {
        return CheckValue(domain, IndicatorType.Domain);
    }

    /// <summary>
    /// Check a file hash against the feed.
    /// </summary>
    public ThreatMatch? CheckHash(string hash)
    {
        return CheckValue(hash, IndicatorType.FileHash);
    }

    /// <summary>
    /// Check a process name against the feed.
    /// </summary>
    public ThreatMatch? CheckProcess(string processName)
    {
        return CheckValue(processName, IndicatorType.ProcessName);
    }

    /// <summary>
    /// Check a URL against the feed.
    /// </summary>
    public ThreatMatch? CheckUrl(string url)
    {
        return CheckValue(url, IndicatorType.Url);
    }

    /// <summary>
    /// Check any value against a specific indicator type.
    /// </summary>
    public ThreatMatch? CheckValue(string value, IndicatorType type)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var key = NormalizeValue(value, type);

        lock (_lock)
        {
            if (!_index.TryGetValue(type, out var typeIndex))
                return null;

            if (typeIndex.TryGetValue(key, out var indicator) && indicator.IsEffectivelyActive)
            {
                indicator.HitCount++;
                indicator.LastHit = DateTimeOffset.UtcNow;
                return new ThreatMatch
                {
                    Indicator = indicator,
                    CheckedValue = value,
                    MatchType = MatchType.CaseInsensitive,
                };
            }
        }

        return null;
    }

    /// <summary>
    /// Check a value against all indicator types.
    /// Returns all matches found.
    /// </summary>
    public List<ThreatMatch> CheckAll(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return new List<ThreatMatch>();

        var matches = new List<ThreatMatch>();
        foreach (IndicatorType type in Enum.GetValues<IndicatorType>())
        {
            var match = CheckValue(value, type);
            if (match != null) matches.Add(match);
        }
        return matches;
    }

    /// <summary>
    /// Get all indicators matching a filter.
    /// </summary>
    public List<ThreatIndicator> Search(
        IndicatorType? type = null,
        ThreatClassification? classification = null,
        IndicatorConfidence? minConfidence = null,
        string? source = null,
        string? tag = null,
        bool activeOnly = true)
    {
        lock (_lock)
        {
            IEnumerable<ThreatIndicator> query = _indicators;

            if (activeOnly)
                query = query.Where(i => i.IsEffectivelyActive);
            if (type.HasValue)
                query = query.Where(i => i.Type == type.Value);
            if (classification.HasValue)
                query = query.Where(i => i.Classification == classification.Value);
            if (minConfidence.HasValue)
                query = query.Where(i => i.Confidence >= minConfidence.Value);
            if (!string.IsNullOrEmpty(source))
                query = query.Where(i => i.Source.Equals(source, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(tag))
                query = query.Where(i => i.Tags.Contains(tag, StringComparer.OrdinalIgnoreCase));

            return query.ToList();
        }
    }

    // ── Statistics ────────────────────────────────────────────────

    /// <summary>
    /// Get comprehensive feed statistics.
    /// </summary>
    public FeedStatistics GetStatistics()
    {
        lock (_lock)
        {
            var stats = new FeedStatistics
            {
                TotalIndicators = _indicators.Count,
                ActiveIndicators = _indicators.Count(i => i.IsEffectivelyActive),
                ExpiredIndicators = _indicators.Count(i => i.IsExpired),
                TotalHits = _indicators.Sum(i => i.HitCount),
            };

            foreach (var ind in _indicators)
            {
                // By type
                stats.ByType.TryGetValue(ind.Type, out int tc);
                stats.ByType[ind.Type] = tc + 1;

                // By classification
                stats.ByClassification.TryGetValue(ind.Classification, out int cc);
                stats.ByClassification[ind.Classification] = cc + 1;

                // By confidence
                stats.ByConfidence.TryGetValue(ind.Confidence, out int confc);
                stats.ByConfidence[ind.Confidence] = confc + 1;

                // By source
                stats.BySource.TryGetValue(ind.Source, out int sc);
                stats.BySource[ind.Source] = sc + 1;
            }

            if (_indicators.Count > 0)
            {
                stats.OldestIndicator = _indicators.Min(i => i.FirstSeen);
                stats.NewestIndicator = _indicators.Max(i => i.FirstSeen);
            }

            return stats;
        }
    }

    // ── Import / Export ──────────────────────────────────────────

    /// <summary>
    /// Export all indicators to JSON.
    /// </summary>
    public string ExportJson(string? filePath = null)
    {
        string json;
        lock (_lock)
        {
            json = JsonSerializer.Serialize(_indicators, JsonOpts);
        }

        if (!string.IsNullOrEmpty(filePath))
        {
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        return json;
    }

    /// <summary>
    /// Import indicators from JSON. Duplicates (same type+value) are skipped.
    /// Returns the number of indicators imported.
    /// </summary>
    public int ImportJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("JSON content cannot be empty.", nameof(json));

        var indicators = JsonSerializer.Deserialize<List<ThreatIndicator>>(json, JsonOpts)
            ?? throw new JsonException("Failed to deserialize indicators.");

        int imported = 0;
        foreach (var ind in indicators)
        {
            if (AddIndicator(ind)) imported++;
        }
        return imported;
    }

    /// <summary>
    /// Import indicators from a JSON file.
    /// </summary>
    public int ImportJsonFile(string filePath)
    {
        var json = File.ReadAllText(filePath, Encoding.UTF8);
        return ImportJson(json);
    }

    // ── Text Report ──────────────────────────────────────────────

    /// <summary>
    /// Generate a human-readable text report of the feed.
    /// </summary>
    public string GenerateTextReport(bool includeInactive = false)
    {
        var sb = new StringBuilder();
        var stats = GetStatistics();

        sb.AppendLine("╔══════════════════════════════════════════════╗");
        sb.AppendLine("║       Threat Intelligence Feed Report        ║");
        sb.AppendLine("╚══════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"  Total indicators: {stats.TotalIndicators}");
        sb.AppendLine($"  Active:           {stats.ActiveIndicators}");
        sb.AppendLine($"  Expired:          {stats.ExpiredIndicators}");
        sb.AppendLine($"  Total hits:       {stats.TotalHits}");
        sb.AppendLine();

        // By type
        sb.AppendLine("  ── By Type ──────────────────────────────────");
        foreach (var (type, count) in stats.ByType.OrderByDescending(kv => kv.Value))
            sb.AppendLine($"    {type,-22} {count,5}");
        sb.AppendLine();

        // By classification
        sb.AppendLine("  ── By Classification ────────────────────────");
        foreach (var (cls, count) in stats.ByClassification.OrderByDescending(kv => kv.Value))
            sb.AppendLine($"    {cls,-22} {count,5}");
        sb.AppendLine();

        // By source
        sb.AppendLine("  ── By Source ─────────────────────────────────");
        foreach (var (src, count) in stats.BySource.OrderByDescending(kv => kv.Value))
            sb.AppendLine($"    {src,-22} {count,5}");
        sb.AppendLine();

        // Top hits
        List<ThreatIndicator> topHits;
        lock (_lock)
        {
            topHits = _indicators.Where(i => i.HitCount > 0)
                .OrderByDescending(i => i.HitCount)
                .Take(10)
                .ToList();
        }

        if (topHits.Count > 0)
        {
            sb.AppendLine("  ── Top 10 Hits ──────────────────────────────");
            foreach (var ind in topHits)
                sb.AppendLine($"    {ind.HitCount,5}× {ind.Type,-14} {ind.Value,-30} ({ind.Classification})");
            sb.AppendLine();
        }

        // Recent indicators
        List<ThreatIndicator> recent;
        lock (_lock)
        {
            var query = includeInactive ? _indicators.AsEnumerable()
                : _indicators.Where(i => i.IsEffectivelyActive);
            recent = query.OrderByDescending(i => i.LastUpdated).Take(20).ToList();
        }

        sb.AppendLine("  ── Recent Indicators (20) ────────────────────");
        sb.AppendLine($"    {"Type",-14} {"Value",-30} {"Classification",-22} {"Confidence",-10} {"Severity"}");
        sb.AppendLine($"    {new string('─', 14)} {new string('─', 30)} {new string('─', 22)} {new string('─', 10)} {new string('─', 8)}");
        foreach (var ind in recent)
        {
            var status = ind.IsEffectivelyActive ? " " : "✗";
            sb.AppendLine($"  {status} {ind.Type,-14} {ind.Value,-30} {ind.Classification,-22} {ind.Confidence,-10} {ind.Severity}");
        }

        return sb.ToString();
    }

    // ── Built-in Indicators ──────────────────────────────────────

    /// <summary>
    /// Load built-in curated threat indicators.
    /// These are well-known IoCs that represent common threats.
    /// </summary>
    public void LoadBuiltInIndicators()
    {
        // ── Known malicious / suspicious process names ────────
        AddBuiltIn(IndicatorType.ProcessName, "mimikatz.exe",
            ThreatClassification.PrivilegeEscalation, IndicatorConfidence.Confirmed,
            Severity.Critical, "Credential dumping tool",
            new[] { "T1003", "T1003.001" });

        AddBuiltIn(IndicatorType.ProcessName, "lazagne.exe",
            ThreatClassification.PrivilegeEscalation, IndicatorConfidence.Confirmed,
            Severity.Critical, "Multi-protocol credential recovery tool",
            new[] { "T1003", "T1555" });

        AddBuiltIn(IndicatorType.ProcessName, "procdump.exe",
            ThreatClassification.PrivilegeEscalation, IndicatorConfidence.Medium,
            Severity.Warning, "Sysinternals tool, often abused for LSASS dumping",
            new[] { "T1003.001" });

        AddBuiltIn(IndicatorType.ProcessName, "psexec.exe",
            ThreatClassification.LateralMovement, IndicatorConfidence.Medium,
            Severity.Warning, "Sysinternals remote execution, frequently used in attacks",
            new[] { "T1021.002", "T1570" });

        AddBuiltIn(IndicatorType.ProcessName, "cobaltstrike.exe",
            ThreatClassification.C2Server, IndicatorConfidence.Confirmed,
            Severity.Critical, "Commercial red-team tool heavily used by APTs",
            new[] { "T1071", "T1095" });

        AddBuiltIn(IndicatorType.ProcessName, "nc.exe",
            ThreatClassification.C2Server, IndicatorConfidence.Medium,
            Severity.Warning, "Netcat - network utility often used as backdoor",
            new[] { "T1095" });

        AddBuiltIn(IndicatorType.ProcessName, "ncat.exe",
            ThreatClassification.C2Server, IndicatorConfidence.Medium,
            Severity.Warning, "Nmap Netcat variant, network backdoor capability",
            new[] { "T1095" });

        AddBuiltIn(IndicatorType.ProcessName, "xmrig.exe",
            ThreatClassification.Cryptominer, IndicatorConfidence.Confirmed,
            Severity.Critical, "Popular cryptocurrency miner, often deployed by malware",
            new[] { "T1496" });

        AddBuiltIn(IndicatorType.ProcessName, "minergate.exe",
            ThreatClassification.Cryptominer, IndicatorConfidence.Confirmed,
            Severity.Critical, "Cryptocurrency mining client",
            new[] { "T1496" });

        AddBuiltIn(IndicatorType.ProcessName, "rubeus.exe",
            ThreatClassification.PrivilegeEscalation, IndicatorConfidence.Confirmed,
            Severity.Critical, "Kerberos attack toolkit",
            new[] { "T1558", "T1558.003" });

        AddBuiltIn(IndicatorType.ProcessName, "sharphound.exe",
            ThreatClassification.Reconnaissance, IndicatorConfidence.Confirmed,
            Severity.Critical, "BloodHound data collector for Active Directory enumeration",
            new[] { "T1087", "T1069" });

        AddBuiltIn(IndicatorType.ProcessName, "certutil.exe",
            ThreatClassification.DefenseEvasion, IndicatorConfidence.Low,
            Severity.Info, "Legitimate Windows tool, often abused for file download",
            new[] { "T1105", "T1140" });

        AddBuiltIn(IndicatorType.ProcessName, "bitsadmin.exe",
            ThreatClassification.DefenseEvasion, IndicatorConfidence.Low,
            Severity.Info, "Legitimate Windows tool, abused for stealthy file transfers",
            new[] { "T1197", "T1105" });

        // ── Known malicious domains ──────────────────────────
        AddBuiltIn(IndicatorType.Domain, "malware-c2.example.com",
            ThreatClassification.C2Server, IndicatorConfidence.Confirmed,
            Severity.Critical, "Example C2 server domain",
            new[] { "T1071.001" });

        AddBuiltIn(IndicatorType.Domain, "evil-updates.example.com",
            ThreatClassification.Malware, IndicatorConfidence.Confirmed,
            Severity.Critical, "Fake update distribution domain",
            new[] { "T1189" });

        // ── Known suspicious ports ───────────────────────────
        AddBuiltIn(IndicatorType.Port, "4444",
            ThreatClassification.C2Server, IndicatorConfidence.Medium,
            Severity.Warning, "Default Metasploit/Meterpreter listener port",
            new[] { "T1095" });

        AddBuiltIn(IndicatorType.Port, "5555",
            ThreatClassification.C2Server, IndicatorConfidence.Medium,
            Severity.Warning, "Common reverse shell port",
            new[] { "T1095" });

        AddBuiltIn(IndicatorType.Port, "6666",
            ThreatClassification.Botnet, IndicatorConfidence.Medium,
            Severity.Warning, "Common IRC botnet port",
            new[] { "T1071.001" });

        AddBuiltIn(IndicatorType.Port, "6667",
            ThreatClassification.Botnet, IndicatorConfidence.Medium,
            Severity.Warning, "Standard IRC port, frequently used by botnets",
            new[] { "T1071.001" });

        AddBuiltIn(IndicatorType.Port, "8443",
            ThreatClassification.C2Server, IndicatorConfidence.Low,
            Severity.Info, "Alternative HTTPS port, sometimes used by C2 frameworks",
            new[] { "T1071.001" });

        AddBuiltIn(IndicatorType.Port, "9001",
            ThreatClassification.C2Server, IndicatorConfidence.Medium,
            Severity.Warning, "Common Tor hidden service / C2 port",
            new[] { "T1090.003" });

        AddBuiltIn(IndicatorType.Port, "31337",
            ThreatClassification.C2Server, IndicatorConfidence.High,
            Severity.Warning, "Classic backdoor port ('elite')",
            new[] { "T1095" });

        // ── Known suspicious registry keys ───────────────────
        AddBuiltIn(IndicatorType.RegistryKey,
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ThreatClassification.PersistenceMechanism, IndicatorConfidence.Low,
            Severity.Info, "Autorun persistence key — verify entries are legitimate",
            new[] { "T1547.001" });

        AddBuiltIn(IndicatorType.RegistryKey,
            @"HKLM\SYSTEM\CurrentControlSet\Services",
            ThreatClassification.PersistenceMechanism, IndicatorConfidence.Low,
            Severity.Info, "Service persistence — verify new services are legitimate",
            new[] { "T1543.003" });

        // ── Known suspicious service names ───────────────────
        AddBuiltIn(IndicatorType.ServiceName, "WinDefend_disabled",
            ThreatClassification.DefenseEvasion, IndicatorConfidence.High,
            Severity.Critical, "Indicates Windows Defender was manually disabled as a service",
            new[] { "T1562.001" });

        AddBuiltIn(IndicatorType.ServiceName, "kprocesshacker",
            ThreatClassification.DefenseEvasion, IndicatorConfidence.High,
            Severity.Warning, "Process Hacker kernel driver — can be used to kill security software",
            new[] { "T1562.001" });
    }

    private void AddBuiltIn(IndicatorType type, string value,
        ThreatClassification classification, IndicatorConfidence confidence,
        Severity severity, string description, string[] mitreIds)
    {
        AddIndicator(new ThreatIndicator
        {
            Value = value,
            Type = type,
            Classification = classification,
            Confidence = confidence,
            Severity = severity,
            Description = description,
            Source = "built-in",
            MitreAttackIds = mitreIds.ToList(),
            Tags = new List<string> { classification.ToString().ToLowerInvariant() },
        });
    }

    // ── Helpers ───────────────────────────────────────────────────

    private static string NormalizeValue(string value, IndicatorType type)
    {
        return type switch
        {
            IndicatorType.FileHash => value.Trim().ToUpperInvariant(),
            IndicatorType.Domain => value.Trim().ToLowerInvariant(),
            IndicatorType.Email => value.Trim().ToLowerInvariant(),
            IndicatorType.ProcessName => value.Trim().ToLowerInvariant(),
            IndicatorType.IpAddress => value.Trim(),
            _ => value.Trim(),
        };
    }

    /// <summary>
    /// Compute SHA256 hash of a file for checking against the feed.
    /// </summary>
    public static string ComputeFileHash(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash);
    }
}
