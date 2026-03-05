using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes the total attack surface by categorizing security findings into
/// exposure vectors, computing per-vector and overall attack surface scores,
/// and recommending surface reduction actions.
/// </summary>
public class AttackSurfaceAnalyzer
{
    /// <summary>
    /// Attack surface vector categories.
    /// </summary>
    public enum SurfaceVector
    {
        Network,
        Authentication,
        RemoteAccess,
        Software,
        DataExposure,
        PhysicalAccess,
        Configuration,
        Privilege
    }

    /// <summary>
    /// Mapping rules: audit category → surface vector.
    /// </summary>
    private static readonly Dictionary<string, SurfaceVector> CategoryVectorMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Firewall"] = SurfaceVector.Network,
        ["Network"] = SurfaceVector.Network,
        ["DNS"] = SurfaceVector.Network,
        ["SMB"] = SurfaceVector.Network,
        ["WiFi"] = SurfaceVector.Network,
        ["Accounts"] = SurfaceVector.Authentication,
        ["Credentials"] = SurfaceVector.Authentication,
        ["Certificate"] = SurfaceVector.Authentication,
        ["RemoteAccess"] = SurfaceVector.RemoteAccess,
        ["RDP"] = SurfaceVector.RemoteAccess,
        ["SSH"] = SurfaceVector.RemoteAccess,
        ["WinRM"] = SurfaceVector.RemoteAccess,
        ["Software"] = SurfaceVector.Software,
        ["Browser"] = SurfaceVector.Software,
        ["Application"] = SurfaceVector.Software,
        ["Updates"] = SurfaceVector.Software,
        ["Drivers"] = SurfaceVector.Software,
        ["Privacy"] = SurfaceVector.DataExposure,
        ["Encryption"] = SurfaceVector.DataExposure,
        ["Clipboard"] = SurfaceVector.DataExposure,
        ["Backup"] = SurfaceVector.DataExposure,
        ["Bluetooth"] = SurfaceVector.PhysicalAccess,
        ["USB"] = SurfaceVector.PhysicalAccess,
        ["Startup"] = SurfaceVector.Configuration,
        ["Registry"] = SurfaceVector.Configuration,
        ["GroupPolicy"] = SurfaceVector.Configuration,
        ["Environment"] = SurfaceVector.Configuration,
        ["PowerShell"] = SurfaceVector.Configuration,
        ["ScheduledTasks"] = SurfaceVector.Configuration,
        ["Services"] = SurfaceVector.Configuration,
        ["Defender"] = SurfaceVector.Configuration,
        ["Virtualization"] = SurfaceVector.Configuration,
        ["Process"] = SurfaceVector.Privilege,
        ["EventLog"] = SurfaceVector.Privilege,
        ["FileIntegrity"] = SurfaceVector.Privilege,
    };

    /// <summary>
    /// Per-vector analysis result.
    /// </summary>
    public class VectorAnalysis
    {
        public SurfaceVector Vector { get; init; }
        public string DisplayName => Vector.ToString();

        /// <summary>Number of findings mapped to this vector.</summary>
        public int TotalFindings { get; init; }

        /// <summary>Critical findings count.</summary>
        public int CriticalCount { get; init; }

        /// <summary>Warning findings count.</summary>
        public int WarningCount { get; init; }

        /// <summary>Info findings count.</summary>
        public int InfoCount { get; init; }

        /// <summary>Pass findings count.</summary>
        public int PassCount { get; init; }

        /// <summary>Exposure score 0-100 (higher = more exposed).</summary>
        public double ExposureScore { get; init; }

        /// <summary>Risk grade A-F.</summary>
        public string Grade { get; init; } = "A";

        /// <summary>Contributing audit modules.</summary>
        public List<string> ContributingModules { get; init; } = new();

        /// <summary>Top reduction recommendations for this vector.</summary>
        public List<string> Recommendations { get; init; } = new();
    }

    /// <summary>
    /// Overall attack surface report.
    /// </summary>
    public class AttackSurfaceReport
    {
        /// <summary>Overall attack surface score 0-100 (higher = more exposed).</summary>
        public double OverallScore { get; init; }

        /// <summary>Overall grade.</summary>
        public string OverallGrade { get; init; } = "A";

        /// <summary>Per-vector analysis.</summary>
        public List<VectorAnalysis> Vectors { get; init; } = new();

        /// <summary>Total findings analyzed.</summary>
        public int TotalFindings { get; init; }

        /// <summary>Total critical findings.</summary>
        public int TotalCritical { get; init; }

        /// <summary>Total warning findings.</summary>
        public int TotalWarnings { get; init; }

        /// <summary>Most exposed vector.</summary>
        public SurfaceVector? MostExposedVector { get; init; }

        /// <summary>Least exposed vector.</summary>
        public SurfaceVector? LeastExposedVector { get; init; }

        /// <summary>Top priority reduction actions across all vectors.</summary>
        public List<ReductionAction> TopActions { get; init; } = new();

        /// <summary>Comparison with a previous report (if provided).</summary>
        public SurfaceComparison? Comparison { get; init; }

        /// <summary>Text summary.</summary>
        public string Summary => GenerateSummary();

        private string GenerateSummary()
        {
            var lines = new List<string>
            {
                "=== ATTACK SURFACE ANALYSIS ===",
                $"Overall Exposure Score: {OverallScore:F1}/100 (Grade: {OverallGrade})",
                $"Total Findings: {TotalFindings} ({TotalCritical} critical, {TotalWarnings} warnings)",
                ""
            };

            if (MostExposedVector.HasValue)
                lines.Add($"Most Exposed: {MostExposedVector.Value}");
            if (LeastExposedVector.HasValue)
                lines.Add($"Least Exposed: {LeastExposedVector.Value}");

            lines.Add("");
            lines.Add("--- Vector Breakdown ---");
            foreach (var v in Vectors.OrderByDescending(x => x.ExposureScore))
            {
                lines.Add($"  {v.DisplayName}: {v.ExposureScore:F1}/100 ({v.Grade}) — {v.CriticalCount}C/{v.WarningCount}W/{v.InfoCount}I/{v.PassCount}P");
            }

            if (TopActions.Count > 0)
            {
                lines.Add("");
                lines.Add("--- Top Reduction Actions ---");
                for (int i = 0; i < Math.Min(TopActions.Count, 10); i++)
                {
                    var a = TopActions[i];
                    lines.Add($"  {i + 1}. [{a.Priority}] {a.Action} (reduces ~{a.EstimatedReduction:F1} points on {a.Vector})");
                }
            }

            if (Comparison != null)
            {
                lines.Add("");
                lines.Add("--- Comparison ---");
                lines.Add($"  Score change: {Comparison.ScoreDelta:+0.0;-0.0;0.0}");
                lines.Add($"  New findings: {Comparison.NewFindings}, Resolved: {Comparison.ResolvedFindings}");
                lines.Add($"  Direction: {Comparison.Direction}");
            }

            return string.Join(Environment.NewLine, lines);
        }
    }

    /// <summary>
    /// A recommended action to reduce attack surface.
    /// </summary>
    public class ReductionAction
    {
        public required string Action { get; init; }
        public SurfaceVector Vector { get; init; }
        public ActionPriority Priority { get; init; }
        public double EstimatedReduction { get; init; }
        public string? RelatedFindingTitle { get; init; }
    }

    public enum ActionPriority { Low, Medium, High, Critical }

    /// <summary>
    /// Comparison between two attack surface reports.
    /// </summary>
    public class SurfaceComparison
    {
        public double ScoreDelta { get; init; }
        public int NewFindings { get; init; }
        public int ResolvedFindings { get; init; }
        public string Direction { get; init; } = "Unchanged";
        public List<VectorDelta> VectorDeltas { get; init; } = new();
    }

    public class VectorDelta
    {
        public SurfaceVector Vector { get; init; }
        public double ScoreDelta { get; init; }
        public int FindingDelta { get; init; }
    }

    /// <summary>
    /// Analyze a security report and produce an attack surface analysis.
    /// </summary>
    public AttackSurfaceReport Analyze(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var allFindings = new List<(string Module, string Category, Finding Finding)>();
        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                allFindings.Add((result.ModuleName, result.Category, finding));
            }
        }

        // Group findings by vector
        var vectorGroups = new Dictionary<SurfaceVector, List<(string Module, Finding Finding)>>();
        foreach (var (module, category, finding) in allFindings)
        {
            var vector = MapToVector(category, finding);
            if (!vectorGroups.ContainsKey(vector))
                vectorGroups[vector] = new();
            vectorGroups[vector].Add((module, finding));
        }

        // Analyze each vector
        var vectors = new List<VectorAnalysis>();
        foreach (SurfaceVector sv in Enum.GetValues<SurfaceVector>())
        {
            var group = vectorGroups.GetValueOrDefault(sv, new());
            vectors.Add(AnalyzeVector(sv, group));
        }

        // Overall score: weighted average by finding count, or simple average if no findings
        double overallScore;
        if (allFindings.Count == 0)
        {
            overallScore = 0;
        }
        else
        {
            // Weight by severity impact per vector
            var activeVectors = vectors.Where(v => v.TotalFindings > 0).ToList();
            if (activeVectors.Count == 0)
                overallScore = 0;
            else
                overallScore = activeVectors.Average(v => v.ExposureScore);
        }

        var sortedVectors = vectors.Where(v => v.TotalFindings > 0).OrderByDescending(v => v.ExposureScore).ToList();

        // Generate reduction actions
        var actions = GenerateReductionActions(allFindings, vectors);

        int totalCritical = allFindings.Count(f => f.Finding.Severity == Severity.Critical);
        int totalWarnings = allFindings.Count(f => f.Finding.Severity == Severity.Warning);

        return new AttackSurfaceReport
        {
            OverallScore = Math.Round(overallScore, 1),
            OverallGrade = ScoreToGrade(overallScore),
            Vectors = vectors,
            TotalFindings = allFindings.Count,
            TotalCritical = totalCritical,
            TotalWarnings = totalWarnings,
            MostExposedVector = sortedVectors.FirstOrDefault()?.Vector,
            LeastExposedVector = sortedVectors.LastOrDefault()?.Vector,
            TopActions = actions.OrderByDescending(a => a.EstimatedReduction)
                .ThenByDescending(a => a.Priority)
                .Take(15).ToList()
        };
    }

    /// <summary>
    /// Compare two reports to show attack surface changes over time.
    /// </summary>
    public AttackSurfaceReport AnalyzeWithComparison(SecurityReport current, SecurityReport previous)
    {
        var currentReport = Analyze(current);
        var previousReport = Analyze(previous);

        double delta = currentReport.OverallScore - previousReport.OverallScore;
        string direction = delta > 1 ? "Worsened" : delta < -1 ? "Improved" : "Unchanged";

        var currentTitles = new HashSet<string>(
            current.Results.SelectMany(r => r.Findings).Select(f => f.Title));
        var previousTitles = new HashSet<string>(
            previous.Results.SelectMany(r => r.Findings).Select(f => f.Title));

        int newFindings = currentTitles.Except(previousTitles).Count();
        int resolved = previousTitles.Except(currentTitles).Count();

        var vectorDeltas = new List<VectorDelta>();
        foreach (var cv in currentReport.Vectors)
        {
            var pv = previousReport.Vectors.FirstOrDefault(v => v.Vector == cv.Vector);
            if (pv != null)
            {
                vectorDeltas.Add(new VectorDelta
                {
                    Vector = cv.Vector,
                    ScoreDelta = Math.Round(cv.ExposureScore - pv.ExposureScore, 1),
                    FindingDelta = cv.TotalFindings - pv.TotalFindings
                });
            }
        }

        // Return a new report with comparison attached
        return new AttackSurfaceReport
        {
            OverallScore = currentReport.OverallScore,
            OverallGrade = currentReport.OverallGrade,
            Vectors = currentReport.Vectors,
            TotalFindings = currentReport.TotalFindings,
            TotalCritical = currentReport.TotalCritical,
            TotalWarnings = currentReport.TotalWarnings,
            MostExposedVector = currentReport.MostExposedVector,
            LeastExposedVector = currentReport.LeastExposedVector,
            TopActions = currentReport.TopActions,
            Comparison = new SurfaceComparison
            {
                ScoreDelta = Math.Round(delta, 1),
                NewFindings = newFindings,
                ResolvedFindings = resolved,
                Direction = direction,
                VectorDeltas = vectorDeltas
            }
        };
    }

    /// <summary>
    /// Get a quick summary of which vectors need the most attention.
    /// </summary>
    public List<(SurfaceVector Vector, string Grade, double Score)> GetVectorPriorities(SecurityReport report)
    {
        var analysis = Analyze(report);
        return analysis.Vectors
            .Where(v => v.TotalFindings > 0)
            .OrderByDescending(v => v.ExposureScore)
            .Select(v => (v.Vector, v.Grade, v.ExposureScore))
            .ToList();
    }

    private VectorAnalysis AnalyzeVector(SurfaceVector vector, List<(string Module, Finding Finding)> findings)
    {
        int critical = findings.Count(f => f.Finding.Severity == Severity.Critical);
        int warning = findings.Count(f => f.Finding.Severity == Severity.Warning);
        int info = findings.Count(f => f.Finding.Severity == Severity.Info);
        int pass = findings.Count(f => f.Finding.Severity == Severity.Pass);

        // Exposure score: weighted sum of non-pass findings, capped at 100
        // Critical = 15 points, Warning = 5 points, Info = 1 point
        double rawScore = critical * 15.0 + warning * 5.0 + info * 1.0;
        double exposure = Math.Min(100.0, rawScore);

        var modules = findings.Select(f => f.Module).Distinct().ToList();
        var recommendations = GenerateVectorRecommendations(vector, critical, warning);

        return new VectorAnalysis
        {
            Vector = vector,
            TotalFindings = findings.Count,
            CriticalCount = critical,
            WarningCount = warning,
            InfoCount = info,
            PassCount = pass,
            ExposureScore = Math.Round(exposure, 1),
            Grade = ScoreToGrade(exposure),
            ContributingModules = modules,
            Recommendations = recommendations
        };
    }

    private static SurfaceVector MapToVector(string category, Finding finding)
    {
        // Direct category mapping
        if (CategoryVectorMap.TryGetValue(category, out var vector))
            return vector;

        // Fallback: try matching on finding category
        if (!string.IsNullOrEmpty(finding.Category) && CategoryVectorMap.TryGetValue(finding.Category, out var fv))
            return fv;

        // Keyword-based fallback
        var titleLower = finding.Title.ToLowerInvariant();
        if (titleLower.Contains("firewall") || titleLower.Contains("port") || titleLower.Contains("network"))
            return SurfaceVector.Network;
        if (titleLower.Contains("password") || titleLower.Contains("credential") || titleLower.Contains("account"))
            return SurfaceVector.Authentication;
        if (titleLower.Contains("remote") || titleLower.Contains("rdp") || titleLower.Contains("ssh"))
            return SurfaceVector.RemoteAccess;
        if (titleLower.Contains("software") || titleLower.Contains("update") || titleLower.Contains("browser"))
            return SurfaceVector.Software;
        if (titleLower.Contains("encrypt") || titleLower.Contains("privacy") || titleLower.Contains("data"))
            return SurfaceVector.DataExposure;
        if (titleLower.Contains("usb") || titleLower.Contains("bluetooth"))
            return SurfaceVector.PhysicalAccess;
        if (titleLower.Contains("privilege") || titleLower.Contains("admin") || titleLower.Contains("escalat"))
            return SurfaceVector.Privilege;

        return SurfaceVector.Configuration; // default
    }

    private static List<string> GenerateVectorRecommendations(SurfaceVector vector, int criticalCount, int warningCount)
    {
        var recs = new List<string>();

        if (criticalCount == 0 && warningCount == 0)
            return recs;

        switch (vector)
        {
            case SurfaceVector.Network:
                if (criticalCount > 0) recs.Add("Review and restrict firewall rules to minimize open ports");
                if (warningCount > 0) recs.Add("Audit network services and disable unnecessary protocols");
                recs.Add("Enable DNS-over-HTTPS and disable LLMNR/NetBIOS");
                break;
            case SurfaceVector.Authentication:
                if (criticalCount > 0) recs.Add("Disable guest/default accounts and enforce strong password policies");
                recs.Add("Enable multi-factor authentication where supported");
                recs.Add("Rotate credentials and remove stale accounts");
                break;
            case SurfaceVector.RemoteAccess:
                if (criticalCount > 0) recs.Add("Disable unnecessary remote access services (RDP, WinRM, Telnet)");
                recs.Add("Enforce NLA and encryption for any required remote access");
                recs.Add("Remove third-party remote access tools not actively used");
                break;
            case SurfaceVector.Software:
                if (criticalCount > 0) recs.Add("Apply all pending security updates immediately");
                recs.Add("Remove unused software and browser extensions");
                recs.Add("Keep all applications updated to latest versions");
                break;
            case SurfaceVector.DataExposure:
                if (criticalCount > 0) recs.Add("Enable full-disk encryption (BitLocker) on all drives");
                recs.Add("Review privacy settings and restrict data collection");
                recs.Add("Implement secure backup with encryption");
                break;
            case SurfaceVector.PhysicalAccess:
                if (criticalCount > 0) recs.Add("Restrict USB device access with allowlisting");
                recs.Add("Disable Bluetooth discoverability when not in use");
                recs.Add("Enable device lock policies");
                break;
            case SurfaceVector.Configuration:
                if (criticalCount > 0) recs.Add("Review and harden system configuration settings");
                recs.Add("Enable security-critical services (Defender, logging)");
                recs.Add("Audit startup items and scheduled tasks for persistence threats");
                break;
            case SurfaceVector.Privilege:
                if (criticalCount > 0) recs.Add("Review processes running with elevated privileges");
                recs.Add("Enable audit logging for privilege escalation events");
                recs.Add("Apply principle of least privilege to all accounts");
                break;
        }

        return recs;
    }

    private List<ReductionAction> GenerateReductionActions(
        List<(string Module, string Category, Finding Finding)> findings,
        List<VectorAnalysis> vectors)
    {
        var actions = new List<ReductionAction>();

        foreach (var (module, category, finding) in findings)
        {
            if (finding.Severity == Severity.Pass || finding.Severity == Severity.Info)
                continue;

            var vector = MapToVector(category, finding);
            var priority = finding.Severity == Severity.Critical ? ActionPriority.Critical : ActionPriority.Medium;
            double reduction = finding.Severity == Severity.Critical ? 15.0 : 5.0;

            string action = !string.IsNullOrEmpty(finding.Remediation)
                ? finding.Remediation
                : $"Address: {finding.Title}";

            actions.Add(new ReductionAction
            {
                Action = action,
                Vector = vector,
                Priority = priority,
                EstimatedReduction = reduction,
                RelatedFindingTitle = finding.Title
            });
        }

        return actions;
    }

    private static string ScoreToGrade(double score)
    {
        return score switch
        {
            <= 10 => "A",
            <= 25 => "B",
            <= 45 => "C",
            <= 65 => "D",
            _ => "F"
        };
    }
}
