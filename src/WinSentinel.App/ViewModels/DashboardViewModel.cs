using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.ViewModels;

public partial class DashboardViewModel : ObservableObject
{
    private readonly AuditEngine _engine = new();

    [ObservableProperty]
    private int _securityScore = -1;

    [ObservableProperty]
    private string _grade = "—";

    [ObservableProperty]
    private string _scoreColor = "#666666";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string _statusText = "Ready to scan";

    [ObservableProperty]
    private string _progressText = "";

    [ObservableProperty]
    private SecurityReport? _lastReport;

    public ObservableCollection<CategoryScore> CategoryScores { get; } = new();
    public ObservableCollection<Finding> RecentAlerts { get; } = new();

    [RelayCommand]
    private async Task RunFullAuditAsync()
    {
        IsScanning = true;
        StatusText = "Running security audit...";
        CategoryScores.Clear();
        RecentAlerts.Clear();

        var progress = new Progress<(string module, int current, int total)>(p =>
        {
            ProgressText = $"Scanning: {p.module} ({p.current}/{p.total})";
        });

        try
        {
            var report = await _engine.RunFullAuditAsync(progress);
            LastReport = report;

            SecurityScore = report.SecurityScore;
            Grade = SecurityScorer.GetGrade(report.SecurityScore);
            ScoreColor = SecurityScorer.GetScoreColor(report.SecurityScore);

            foreach (var result in report.Results)
            {
                var catScore = SecurityScorer.CalculateCategoryScore(result);
                CategoryScores.Add(new CategoryScore
                {
                    Category = result.Category,
                    Score = catScore,
                    Grade = SecurityScorer.GetGrade(catScore),
                    Color = SecurityScorer.GetScoreColor(catScore),
                    CriticalCount = result.CriticalCount,
                    WarningCount = result.WarningCount,
                    FindingCount = result.Findings.Count
                });
            }

            // Collect recent alerts (critical + warning)
            var alerts = report.Results
                .SelectMany(r => r.Findings)
                .Where(f => f.Severity >= Severity.Warning)
                .OrderByDescending(f => f.Severity)
                .ThenByDescending(f => f.Timestamp)
                .Take(20);

            foreach (var alert in alerts)
            {
                RecentAlerts.Add(alert);
            }

            StatusText = $"Scan complete — Score: {report.SecurityScore}/100 ({Grade})";
        }
        catch (Exception ex)
        {
            StatusText = $"Scan failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            ProgressText = "";
        }
    }
}

public class CategoryScore
{
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public string Grade { get; set; } = "";
    public string Color { get; set; } = "";
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int FindingCount { get; set; }
}
