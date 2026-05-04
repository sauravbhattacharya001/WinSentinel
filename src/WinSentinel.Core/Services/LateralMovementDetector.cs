namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Lateral Movement Detector — autonomous detection of lateral movement patterns
/// across security findings. Identifies RDP abuse, SMB pivoting, WMI/PSRemoting,
/// credential reuse, service account spreading, and scheduled task propagation.
/// Builds movement graphs and recommends containment actions.
///
/// MITRE ATT&amp;CK: TA0008 (Lateral Movement)
/// Techniques: T1021.001 (RDP), T1021.002 (SMB/Admin Shares), T1021.003 (DCOM),
/// T1021.004 (SSH), T1021.006 (WinRM), T1047 (WMI), T1053.005 (Scheduled Task),
/// T1570 (Lateral Tool Transfer)
/// </summary>
public sealed class LateralMovementDetector
{
    private readonly AuditHistoryService _history;

    private const int OffHoursStart = 22;
    private const int OffHoursEnd = 6;

    private static readonly List<TechniqueSignature> Signatures = new()
    {
        new("RDP", "T1021.001", new[] { "rdp", "remote desktop", "3389", "mstsc", "termsrv" }, 0.8),
        new("SMB/PsExec", "T1021.002", new[] { "smb", "admin$", "c$", "psexec", "445", "ipc$", "smbclient", "net use" }, 0.85),
        new("WMI", "T1047", new[] { "wmi", "wmiprvse", "wmic", "win32_process" }, 0.9),
        new("PSRemoting", "T1021.006", new[] { "psremoting", "winrm", "5985", "5986", "invoke-command", "enter-pssession", "new-pssession" }, 0.9),
        new("DCOM", "T1021.003", new[] { "dcom", "mmc20", "shellwindows", "shellbrowserwindow" }, 0.85),
        new("SSH", "T1021.004", new[] { "ssh", "openssh", "putty", "sshd", "22/tcp" }, 0.7),
        new("ScheduledTask", "T1053.005", new[] { "schtasks", "scheduled task", "at.exe", "task scheduler" }, 0.75),
        new("ToolTransfer", "T1570", new[] { "bitsadmin", "certutil -urlcache", "robocopy", "xcopy" }, 0.65),
    };

    /// <summary>Patterns indicating remote/network context (boosts confidence).</summary>
    private static readonly string[] RemoteIndicators = { "remote", "network", "\\\\", "//", "lateral", "pivot", "hop" };

    /// <summary>Patterns for extracting host references.</summary>
    private static readonly string[] HostPatterns = { "from ", "to ", "target:", "source:", "host:", "server:", "dest:", "destination:" };

    public LateralMovementDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run lateral movement detection against the current security report.</summary>
    public LateralMovementReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new LateralMovementReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        // Detect movements from current findings
        var movements = new List<LateralMovement>();
        foreach (var (finding, module) in findings)
        {
            var detected = DetectMovements(finding, module);
            movements.AddRange(detected);
        }

        // Also scan historical findings
        foreach (var run in runs)
        {
            foreach (var fr in run.Findings)
            {
                // Convert FindingRecord to Finding for detection
                var finding = new Finding
                {
                    Title = fr.Title,
                    Description = fr.Description,
                    Category = fr.ModuleName
                };
                var detected = DetectMovements(finding, fr.ModuleName);
                movements.AddRange(detected);
            }
        }

        // Deduplicate by source+target+technique within a time window
        movements = DeduplicateMovements(movements);

        result.Movements = movements;
        result.MovementsDetected = movements.Count;
        result.HighSeverityMovements = movements.Count(m => m.Severity is LateralMovementSeverity.High or LateralMovementSeverity.Critical);
        result.MediumSeverityMovements = movements.Count(m => m.Severity == LateralMovementSeverity.Medium);
        result.LowSeverityMovements = movements.Count(m => m.Severity == LateralMovementSeverity.Low);

        // Build movement graph
        result.Graph = BuildGraph(movements);

        // Detect multi-hop paths
        result.Paths = DetectPaths(movements, result.Graph);

        // Compute stats
        result.Stats = ComputeStats(movements, result.Paths);

        // Score threat
        result.ThreatScore = ComputeThreatScore(movements, result.Paths);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(movements, result.Paths, result.Stats);

        return result;
    }

    // ── Detection Engines ────────────────────────────────────────────

    private List<LateralMovement> DetectMovements(Finding finding, string module)
    {
        var results = new List<LateralMovement>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            // Check for remote context indicators to boost confidence
            var hasRemoteContext = RemoteIndicators.Any(r => text.Contains(r));
            var confidence = hasRemoteContext ? sig.BaseConfidence : sig.BaseConfidence * 0.7;

            // Extract source/target hosts
            var (source, target) = ExtractHosts(text, finding);

            var movement = new LateralMovement
            {
                SourceHost = source,
                TargetHost = target,
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                AccountUsed = ExtractAccount(text),
                DetectedAt = DateTimeOffset.UtcNow,
                Confidence = Math.Min(confidence, 1.0),
                Evidence = finding.Title,
                ProcessName = ExtractProcess(text),
                Indicators = new List<string>()
            };

            // Service account detection
            if (movement.AccountUsed != null)
            {
                var acctLower = movement.AccountUsed.ToLowerInvariant();
                movement.IsServiceAccount = acctLower.Contains("svc") ||
                                           acctLower.Contains("service") ||
                                           acctLower.EndsWith("$") ||
                                           acctLower.Contains("system") ||
                                           acctLower.Contains("admin");
                if (movement.IsServiceAccount)
                    movement.Indicators.Add("Service account used for lateral movement");
            }

            // Off-hours detection
            var hour = movement.DetectedAt.Hour;
            var isOffHours = hour >= OffHoursStart || hour < OffHoursEnd;
            if (isOffHours)
                movement.Indicators.Add("Off-hours activity detected");

            // Classify severity
            movement.Severity = ClassifySeverity(movement, isOffHours, hasRemoteContext);

            results.Add(movement);
            break; // One technique match per finding
        }

        return results;
    }

    private (string source, string target) ExtractHosts(string text, Finding finding)
    {
        var source = "unknown-source";
        var target = "unknown-target";

        // Try to extract from common patterns
        foreach (var pattern in HostPatterns)
        {
            var idx = text.IndexOf(pattern, StringComparison.Ordinal);
            if (idx < 0) continue;
            var afterPattern = text[(idx + pattern.Length)..];
            var host = ExtractHostToken(afterPattern);
            if (string.IsNullOrEmpty(host)) continue;

            if (pattern.Contains("from") || pattern.Contains("source"))
                source = host;
            else
                target = host;
        }

        // Try IP extraction as fallback
        var ips = ExtractIpAddresses(text);
        if (ips.Count >= 2)
        {
            source = ips[0];
            target = ips[1];
        }
        else if (ips.Count == 1)
        {
            target = ips[0];
        }

        // Use module context for source if still unknown
        if (source == "unknown-source")
            source = Environment.MachineName.ToLowerInvariant();

        return (source, target);
    }

    private static string ExtractHostToken(string text)
    {
        var token = new string(text.TakeWhile(c => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_').ToArray());
        return token.Length >= 2 ? token : "";
    }

    private static List<string> ExtractIpAddresses(string text)
    {
        var ips = new List<string>();
        var parts = text.Split(' ', ',', ';', '(', ')', '[', ']');
        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (trimmed.Count(c => c == '.') == 3 && trimmed.All(c => char.IsDigit(c) || c == '.'))
            {
                var octets = trimmed.Split('.');
                if (octets.Length == 4 && octets.All(o => int.TryParse(o, out var v) && v >= 0 && v <= 255))
                    ips.Add(trimmed);
            }
        }
        return ips;
    }

    private static string? ExtractAccount(string text)
    {
        // Look for "user:", "account:", "as ", "credentials:" patterns
        string[] accountPatterns = { "user:", "account:", "as ", "credentials:", "logon:" };
        foreach (var p in accountPatterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var after = text[(idx + p.Length)..].TrimStart();
            var acct = new string(after.TakeWhile(c => char.IsLetterOrDigit(c) || c == '\\' || c == '_' || c == '-' || c == '$' || c == '.').ToArray());
            if (acct.Length >= 2) return acct;
        }
        return null;
    }

    private static string? ExtractProcess(string text)
    {
        string[] processPatterns = { "process:", "proc:", "exe:" };
        foreach (var p in processPatterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var after = text[(idx + p.Length)..].TrimStart();
            var proc = new string(after.TakeWhile(c => char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-').ToArray());
            if (proc.Length >= 2) return proc;
        }
        return null;
    }

    private static LateralMovementSeverity ClassifySeverity(LateralMovement m, bool isOffHours, bool hasRemoteContext)
    {
        var score = 0;

        // High-risk techniques
        if (m.Technique is "WMI" or "PSRemoting" or "DCOM") score += 3;
        else if (m.Technique is "SMB/PsExec") score += 2;
        else score += 1;

        // Confidence boost
        if (m.Confidence >= 0.8) score += 2;
        else if (m.Confidence >= 0.6) score += 1;

        // Context
        if (isOffHours) score += 2;
        if (m.IsServiceAccount) score += 2;
        if (hasRemoteContext) score += 1;

        return score switch
        {
            >= 8 => LateralMovementSeverity.Critical,
            >= 6 => LateralMovementSeverity.High,
            >= 4 => LateralMovementSeverity.Medium,
            _ => LateralMovementSeverity.Low
        };
    }

    // ── Graph Building ───────────────────────────────────────────────

    private static MovementGraph BuildGraph(List<LateralMovement> movements)
    {
        var graph = new MovementGraph();
        var nodeMap = new Dictionary<string, GraphNode>();
        var edgeMap = new Dictionary<string, GraphEdge>();

        foreach (var m in movements)
        {
            // Add/update source node
            if (!nodeMap.ContainsKey(m.SourceHost))
                nodeMap[m.SourceHost] = new GraphNode { HostName = m.SourceHost, Role = ClassifyHostRole(m.SourceHost) };
            nodeMap[m.SourceHost].OutDegree++;

            // Add/update target node
            if (!nodeMap.ContainsKey(m.TargetHost))
                nodeMap[m.TargetHost] = new GraphNode { HostName = m.TargetHost, Role = ClassifyHostRole(m.TargetHost) };
            nodeMap[m.TargetHost].InDegree++;

            // Mark critical assets
            if (nodeMap[m.TargetHost].Role is "dc" or "server")
                nodeMap[m.TargetHost].IsCriticalAsset = true;

            // Add/update edge
            var edgeKey = $"{m.SourceHost}->{m.TargetHost}:{m.Technique}";
            if (!edgeMap.ContainsKey(edgeKey))
                edgeMap[edgeKey] = new GraphEdge { Source = m.SourceHost, Target = m.TargetHost, Technique = m.Technique };
            edgeMap[edgeKey].Count++;
            edgeMap[edgeKey].LastSeen = m.DetectedAt;
        }

        graph.Nodes = nodeMap.Values.ToList();
        graph.Edges = edgeMap.Values.ToList();
        graph.NodeCount = graph.Nodes.Count;
        graph.EdgeCount = graph.Edges.Count;

        if (graph.Nodes.Count > 0)
        {
            var mostConnected = graph.Nodes.OrderByDescending(n => n.InDegree + n.OutDegree).First();
            graph.MostConnectedNode = mostConnected.HostName;
        }

        return graph;
    }

    private static string ClassifyHostRole(string hostname)
    {
        var lower = hostname.ToLowerInvariant();
        if (lower.Contains("dc") || lower.Contains("domain")) return "dc";
        if (lower.Contains("srv") || lower.Contains("server")) return "server";
        if (lower.Contains("jump") || lower.Contains("bastion")) return "jump-box";
        return "workstation";
    }

    // ── Path Detection (BFS) ─────────────────────────────────────────

    private static List<MovementPath> DetectPaths(List<LateralMovement> movements, MovementGraph graph)
    {
        var paths = new List<MovementPath>();
        if (movements.Count == 0) return paths;

        // Build adjacency list
        var adjacency = new Dictionary<string, List<(string target, string technique, DateTimeOffset time)>>();
        foreach (var m in movements.OrderBy(m => m.DetectedAt))
        {
            if (!adjacency.ContainsKey(m.SourceHost))
                adjacency[m.SourceHost] = new();
            adjacency[m.SourceHost].Add((m.TargetHost, m.Technique, m.DetectedAt));
        }

        // Find all paths starting from each source using DFS with depth limit
        var visited = new HashSet<string>();
        foreach (var startNode in adjacency.Keys)
        {
            var pathsFromNode = FindPathsDfs(startNode, adjacency, graph, maxDepth: 6);
            paths.AddRange(pathsFromNode);
        }

        // Keep only paths with 2+ hops
        paths = paths.Where(p => p.HopCount >= 2).OrderByDescending(p => p.PathRisk).Take(20).ToList();

        if (paths.Count > 0)
            graph.MaxPathLength = paths.Max(p => p.HopCount);

        return paths;
    }

    private static List<MovementPath> FindPathsDfs(
        string start,
        Dictionary<string, List<(string target, string technique, DateTimeOffset time)>> adjacency,
        MovementGraph graph,
        int maxDepth)
    {
        var results = new List<MovementPath>();
        var stack = new Stack<(string node, List<string> hops, List<string> techniques, HashSet<string> visited)>();
        stack.Push((start, new List<string> { start }, new List<string>(), new HashSet<string> { start }));

        while (stack.Count > 0)
        {
            var (current, hops, techniques, visitedSet) = stack.Pop();

            if (hops.Count > maxDepth) continue;

            if (!adjacency.TryGetValue(current, out var neighbors)) continue;

            foreach (var (target, technique, _) in neighbors)
            {
                if (visitedSet.Contains(target)) continue;

                var newHops = new List<string>(hops) { target };
                var newTechniques = new List<string>(techniques) { technique };
                var newVisited = new HashSet<string>(visitedSet) { target };

                // Record path if 2+ hops
                if (newHops.Count >= 3) // 3 nodes = 2 hops
                {
                    var targetNode = graph.Nodes.FirstOrDefault(n => n.HostName == target);
                    var path = new MovementPath
                    {
                        Hops = newHops,
                        Techniques = newTechniques,
                        HopCount = newHops.Count - 1,
                        OriginHost = start,
                        TerminalHost = target,
                        ReachesCriticalAsset = targetNode?.IsCriticalAsset ?? false,
                        PathRisk = ComputePathRisk(newTechniques, targetNode?.IsCriticalAsset ?? false)
                    };
                    results.Add(path);
                }

                stack.Push((target, newHops, newTechniques, newVisited));
            }
        }

        return results;
    }

    private static double ComputePathRisk(List<string> techniques, bool reachesCritical)
    {
        var risk = 0.0;
        foreach (var t in techniques)
        {
            risk += t switch
            {
                "WMI" or "PSRemoting" or "DCOM" => 25,
                "SMB/PsExec" => 20,
                "RDP" => 15,
                "SSH" => 12,
                "ScheduledTask" => 18,
                "ToolTransfer" => 10,
                _ => 8
            };
        }
        if (reachesCritical) risk *= 1.5;
        return Math.Min(risk, 100);
    }

    // ── Statistics ───────────────────────────────────────────────────

    private static LateralMovementStats ComputeStats(List<LateralMovement> movements, List<MovementPath> paths)
    {
        if (movements.Count == 0)
            return new LateralMovementStats();

        var stats = new LateralMovementStats
        {
            UniqueSourceHosts = movements.Select(m => m.SourceHost).Distinct().Count(),
            UniqueTargetHosts = movements.Select(m => m.TargetHost).Distinct().Count(),
            UniqueTechniques = movements.Select(m => m.Technique).Distinct().Count(),
            UniqueAccounts = movements.Where(m => m.AccountUsed != null).Select(m => m.AccountUsed!).Distinct().Count(),
            ServiceAccountMovements = movements.Count(m => m.IsServiceAccount),
            OffHoursMovements = movements.Count(m => m.Indicators.Any(i => i.Contains("Off-hours")))
        };

        var techniqueGroups = movements.GroupBy(m => m.Technique).OrderByDescending(g => g.Count());
        stats.MostUsedTechnique = techniqueGroups.First().Key;

        var targetGroups = movements.GroupBy(m => m.TargetHost).OrderByDescending(g => g.Count());
        stats.MostTargetedHost = targetGroups.First().Key;

        var accountMovements = movements.Where(m => m.AccountUsed != null).ToList();
        if (accountMovements.Count > 0)
            stats.MostActiveAccount = accountMovements.GroupBy(m => m.AccountUsed!).OrderByDescending(g => g.Count()).First().Key;

        stats.AverageHopsPerPath = paths.Count > 0 ? paths.Average(p => p.HopCount) : 0;

        return stats;
    }

    // ── Threat Scoring ───────────────────────────────────────────────

    private static double ComputeThreatScore(List<LateralMovement> movements, List<MovementPath> paths)
    {
        if (movements.Count == 0) return 0;

        var score = 0.0;

        // Base score from movement count (diminishing returns)
        score += Math.Min(movements.Count * 5, 30);

        // Severity weighting
        score += movements.Count(m => m.Severity == LateralMovementSeverity.Critical) * 10;
        score += movements.Count(m => m.Severity == LateralMovementSeverity.High) * 6;
        score += movements.Count(m => m.Severity == LateralMovementSeverity.Medium) * 3;

        // Multi-hop paths are very concerning
        score += paths.Count * 8;
        score += paths.Count(p => p.ReachesCriticalAsset) * 15;

        // Service account abuse
        score += movements.Count(m => m.IsServiceAccount) * 4;

        return Math.Min(score, 100);
    }

    private static string ClassifyThreatLevel(double score) => score switch
    {
        >= 80 => "Critical",
        >= 60 => "High",
        >= 40 => "Medium",
        >= 20 => "Low",
        _ => "Minimal"
    };

    // ── Recommendations ──────────────────────────────────────────────

    private static List<LateralMovementRecommendation> GenerateRecommendations(
        List<LateralMovement> movements, List<MovementPath> paths, LateralMovementStats stats)
    {
        var recs = new List<LateralMovementRecommendation>();

        if (movements.Count == 0)
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "Low",
                Category = "Posture",
                Title = "No lateral movement detected",
                Description = "Current scan found no lateral movement indicators. Continue monitoring.",
            });
            return recs;
        }

        // Service account recommendations
        if (stats.ServiceAccountMovements > 0)
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "Critical",
                Category = "Credential Hygiene",
                Title = "Restrict service account lateral movement",
                Description = $"{stats.ServiceAccountMovements} movements used service accounts. Implement tiered admin model and restrict service account logon types.",
                MitreMitigation = "M1026 — Privileged Account Management"
            });
        }

        // Off-hours recommendations
        if (stats.OffHoursMovements > 0)
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "High",
                Category = "Access Control",
                Title = "Investigate off-hours lateral movement",
                Description = $"{stats.OffHoursMovements} movements occurred during off-hours (22:00-06:00). Consider time-based access policies.",
                MitreMitigation = "M1035 — Limit Access to Resource Over Network"
            });
        }

        // Multi-hop path recommendations
        if (paths.Count > 0)
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "Critical",
                Category = "Network Segmentation",
                Title = "Break multi-hop movement chains",
                Description = $"{paths.Count} multi-hop paths detected (avg {stats.AverageHopsPerPath:F1} hops). Implement network segmentation and jump-box requirements.",
                MitreMitigation = "M1030 — Network Segmentation"
            });
        }

        // Critical asset recommendations
        if (paths.Any(p => p.ReachesCriticalAsset))
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "Critical",
                Category = "Asset Protection",
                Title = "Harden critical asset access paths",
                Description = "Movement paths reach critical assets (DCs, servers). Enforce MFA for privileged access and implement PAW/PAM.",
                MitreMitigation = "M1032 — Multi-factor Authentication"
            });
        }

        // Technique-specific recommendations
        if (movements.Any(m => m.Technique == "SMB/PsExec"))
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "High",
                Category = "Protocol Hardening",
                Title = "Restrict SMB lateral access",
                Description = "Disable admin shares (ADMIN$, C$) where not needed. Block SMB (445) between workstations via host firewall.",
                MitreMitigation = "M1037 — Filter Network Traffic"
            });
        }

        if (movements.Any(m => m.Technique == "WMI"))
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "High",
                Category = "Protocol Hardening",
                Title = "Restrict WMI remote access",
                Description = "Limit WMI namespace permissions. Monitor wmiprvse.exe process creation for remote origins.",
                MitreMitigation = "M1026 — Privileged Account Management"
            });
        }

        if (movements.Any(m => m.Technique == "RDP"))
        {
            recs.Add(new LateralMovementRecommendation
            {
                Priority = "Medium",
                Category = "Access Control",
                Title = "Tighten RDP access controls",
                Description = "Restrict RDP to jump-boxes only. Enable NLA and restrict Remote Desktop Users group membership.",
                MitreMitigation = "M1042 — Disable or Remove Feature or Program"
            });
        }

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static List<LateralMovement> DeduplicateMovements(List<LateralMovement> movements)
    {
        var seen = new HashSet<string>();
        var deduped = new List<LateralMovement>();
        foreach (var m in movements.OrderByDescending(x => x.Confidence))
        {
            var key = $"{m.SourceHost}|{m.TargetHost}|{m.Technique}";
            if (seen.Add(key))
                deduped.Add(m);
        }
        return deduped;
    }

    // ── Internal types ───────────────────────────────────────────────

    private sealed record TechniqueSignature(string Name, string MitreId, string[] Keywords, double BaseConfidence);
}
