using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Builds a comparison matrix showing module scores across multiple historical
/// audit runs. Useful for spotting per-module regressions and improvements at
/// a glance. Each row is a module; each column is a scan (newest → oldest or
/// chronological depending on options).
/// </summary>
public class ScanMatrixService
{
    // ── Result types ─────────────────────────────────────────────────

    /// <summary>A single cell in the matrix (one module × one scan).</summary>
    public record MatrixCell(
        int Score,
        int FindingCount,
        int CriticalCount,
        int WarningCount);

    /// <summary>One row of the matrix representing a single module across scans.</summary>
    public record MatrixRow(
        string ModuleName,
        string Category,
        List<MatrixCell?> Cells,
        int NetChange,
        string Trend);

    /// <summary>One column header representing a single scan.</summary>
    public record MatrixColumn(
        long RunId,
        DateTimeOffset Timestamp,
        int OverallScore,
        string Grade);

    /// <summary>Summary statistics for the matrix.</summary>
    public record MatrixSummary(
        int TotalScans,
        int TotalModules,
        int ImprovingModules,
        int DecliningModules,
        int StableModules,
        int BestOverallScore,
        int WorstOverallScore,
        DateTimeOffset OldestScan,
        DateTimeOffset NewestScan);

    /// <summary>Full matrix report.</summary>
    public record MatrixReport(
        List<MatrixColumn> Columns,
        List<MatrixRow> Rows,
        MatrixSummary Summary);

    // ── Options ──────────────────────────────────────────────────────

    public class MatrixOptions
    {
        /// <summary>Max number of scans (columns) to include. Default 5.</summary>
        public int MaxScans { get; set; } = 5;
        public string? ModuleFilter { get; set; }
        public bool SortByName { get; set; }
    }

    // ── Build ────────────────────────────────────────────────────────

    /// <summary>
    /// Build a comparison matrix from audit run records that include
    /// <see cref="AuditRunRecord.ModuleScores"/>.
    /// Runs should be provided newest-first (as returned by history service).
    /// </summary>
    public MatrixReport Build(List<AuditRunRecord> runs, MatrixOptions? options = null)
    {
        options ??= new MatrixOptions();

        // Take the requested number and reverse to chronological
        var selected = runs
            .Where(r => r.ModuleScores.Count > 0)
            .Take(options.MaxScans)
            .Reverse()
            .ToList();

        if (selected.Count == 0)
        {
            return new MatrixReport(
                [],
                [],
                new MatrixSummary(0, 0, 0, 0, 0, 0, 0, DateTimeOffset.MinValue, DateTimeOffset.MinValue));
        }

        // Build columns
        var columns = selected.Select(r => new MatrixColumn(
            r.Id, r.Timestamp, r.OverallScore, r.Grade)).ToList();

        // Collect all module names across all selected runs
        var allModules = selected
            .SelectMany(r => r.ModuleScores)
            .Select(m => (m.ModuleName, m.Category))
            .Distinct()
            .ToList();

        // Apply module filter
        if (!string.IsNullOrWhiteSpace(options.ModuleFilter))
        {
            allModules = allModules
                .Where(m => m.ModuleName.Contains(options.ModuleFilter, StringComparison.OrdinalIgnoreCase) ||
                            m.Category.Contains(options.ModuleFilter, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        // Build rows
        var rows = new List<MatrixRow>();
        foreach (var (moduleName, category) in allModules)
        {
            var cells = new List<MatrixCell?>();
            foreach (var run in selected)
            {
                var modScore = run.ModuleScores
                    .FirstOrDefault(m => m.ModuleName == moduleName);
                if (modScore != null)
                {
                    cells.Add(new MatrixCell(
                        modScore.Score,
                        modScore.FindingCount,
                        modScore.CriticalCount,
                        modScore.WarningCount));
                }
                else
                {
                    cells.Add(null);
                }
            }

            // Calculate net change (first non-null to last non-null)
            var firstScore = cells.FirstOrDefault(c => c != null)?.Score;
            var lastScore = cells.LastOrDefault(c => c != null)?.Score;
            var netChange = (firstScore.HasValue && lastScore.HasValue)
                ? lastScore.Value - firstScore.Value
                : 0;

            var trend = (firstScore.HasValue && lastScore.HasValue)
                ? netChange > 2 ? "Improving"
                    : netChange < -2 ? "Declining"
                    : "Stable"
                : "Insufficient";

            rows.Add(new MatrixRow(moduleName, category, cells, netChange, trend));
        }

        // Sort
        if (options.SortByName)
            rows = rows.OrderBy(r => r.ModuleName).ToList();
        else
            rows = rows.OrderBy(r => r.NetChange).ToList(); // worst regressions first

        // Summary
        var improving = rows.Count(r => r.Trend == "Improving");
        var declining = rows.Count(r => r.Trend == "Declining");
        var stable = rows.Count(r => r.Trend == "Stable");

        var summary = new MatrixSummary(
            selected.Count,
            rows.Count,
            improving,
            declining,
            stable,
            selected.Max(r => r.OverallScore),
            selected.Min(r => r.OverallScore),
            selected.First().Timestamp,
            selected.Last().Timestamp);

        return new MatrixReport(columns, rows, summary);
    }
}
