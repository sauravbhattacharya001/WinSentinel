using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

public partial class DashboardPage : Page
{
    private readonly AuditHistoryService _historyService = new();

    public DashboardPage()
    {
        InitializeComponent();
        LoadTrendData();
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        ScanButton.IsEnabled = false;
        ScanProgress.Visibility = Visibility.Visible;
        ProgressText.Visibility = Visibility.Visible;
        NoAlertsText.Visibility = Visibility.Collapsed;

        var engine = new AuditEngine();
        engine.SetHistoryService(_historyService);

        var progress = new Progress<(string module, int current, int total)>(p =>
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"Scanning: {p.module}...";
                ProgressText.Text = $"Module {p.current} of {p.total}";
            });
        });

        try
        {
            var report = await engine.RunFullAuditAsync(progress);

            ScoreText.Text = $"{report.SecurityScore}";
            GradeText.Text = $"Grade: {SecurityScorer.GetGrade(report.SecurityScore)}";
            StatusText.Text = $"Scan complete — {report.TotalFindings} findings";

            // Category cards with trend indicators
            CategoryList.Items.Clear();
            var moduleTrends = _historyService.GetModuleHistory();
            var trendMap = moduleTrends.ToDictionary(t => t.ModuleName, t => t);

            foreach (var result in report.Results)
            {
                var catScore = SecurityScorer.CalculateCategoryScore(result);
                trendMap.TryGetValue(result.ModuleName, out var trend);
                var card = CreateCategoryCard(result, catScore, trend);
                CategoryList.Items.Add(card);
            }

            // Alerts
            AlertsList.Items.Clear();
            var alerts = report.Results
                .SelectMany(r => r.Findings)
                .Where(f => f.Severity >= Severity.Warning)
                .OrderByDescending(f => f.Severity)
                .Take(20);

            foreach (var alert in alerts)
            {
                AlertsList.Items.Add(CreateAlertItem(alert));
            }

            if (!alerts.Any())
            {
                NoAlertsText.Text = "✅ No critical issues or warnings found!";
                NoAlertsText.Visibility = Visibility.Visible;
            }

            // Update trend data after scan
            LoadTrendData();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
        }
        finally
        {
            ScanButton.IsEnabled = true;
            ScanProgress.Visibility = Visibility.Collapsed;
            ProgressText.Visibility = Visibility.Collapsed;
        }
    }

    private void LoadTrendData()
    {
        try
        {
            var trend = _historyService.GetTrend(30);

            if (trend.TotalScans == 0)
            {
                TrendSection.Visibility = Visibility.Collapsed;
                return;
            }

            TrendSection.Visibility = Visibility.Visible;

            // Score change text
            if (trend.PreviousScore.HasValue)
            {
                var change = trend.ScoreChange;
                var arrow = trend.ChangeDirection;
                var color = change > 0 ? "#4CAF50" : change < 0 ? "#F44336" : "#888888";
                var sign = change > 0 ? "+" : "";
                ScoreChangeText.Text = $"{arrow} {sign}{change} since last scan";
                ScoreChangeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
            }
            else
            {
                ScoreChangeText.Text = "";
            }

            // Render text-based trend chart
            TrendChartText.Text = RenderTextChart(trend);

            // Best/Worst/Average
            if (trend.BestScore.HasValue)
            {
                BestScoreText.Text = $"{trend.BestScore}/{trend.BestScoreGrade}";
                BestScoreDateText.Text = trend.BestScoreDate?.ToLocalTime().ToString("MMM dd, HH:mm") ?? "";
            }

            if (trend.WorstScore.HasValue)
            {
                WorstScoreText.Text = $"{trend.WorstScore}/{trend.WorstScoreGrade}";
                WorstScoreDateText.Text = trend.WorstScoreDate?.ToLocalTime().ToString("MMM dd, HH:mm") ?? "";
            }

            AvgScoreText.Text = $"{trend.AverageScore:F0}";
            TotalScansText.Text = $"{trend.TotalScans} scans";
        }
        catch
        {
            TrendSection.Visibility = Visibility.Collapsed;
        }
    }

    /// <summary>
    /// Render a simple text-based bar chart of score history.
    /// </summary>
    private static string RenderTextChart(ScoreTrendSummary trend)
    {
        if (trend.Points.Count == 0) return "No scan history available.";

        var sb = new StringBuilder();
        var points = trend.Points.TakeLast(15).ToList(); // Last 15 scans

        // Header
        sb.AppendLine("  Score History (last scans)");
        sb.AppendLine("  ─────────────────────────────────────────");

        foreach (var point in points)
        {
            var barLen = (int)(point.Score / 5.0); // Scale 0-100 to 0-20 chars
            var bar = new string('█', barLen);
            var pad = new string('░', 20 - barLen);
            var date = point.Timestamp.ToLocalTime().ToString("MM/dd HH:mm");
            sb.AppendLine($"  {date}  {bar}{pad}  {point.Score}/{point.Grade}");
        }

        return sb.ToString().TrimEnd();
    }

    private Border CreateCategoryCard(AuditResult result, int score, ModuleTrendInfo? trend)
    {
        var icon = score >= 80 ? "✅" : score >= 60 ? "⚠️" : "🔴";

        var border = new Border
        {
            Background = (Brush)Application.Current.Resources["CardBackground"],
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16),
            Margin = new Thickness(0, 0, 0, 8),
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var info = new StackPanel();
        info.Children.Add(new TextBlock
        {
            Text = $"{icon} {result.Category}",
            FontWeight = FontWeights.SemiBold,
            FontSize = 16,
            Foreground = (Brush)Application.Current.Resources["TextPrimary"]
        });

        var details = $"🔴 {result.CriticalCount} critical  •  🟡 {result.WarningCount} warnings  •  {result.Findings.Count} total findings";
        info.Children.Add(new TextBlock
        {
            Text = details,
            Foreground = (Brush)Application.Current.Resources["TextSecondary"],
            Margin = new Thickness(0, 4, 0, 0)
        });

        Grid.SetColumn(info, 0);
        grid.Children.Add(info);

        var scorePanel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };

        // Score with trend indicator
        var trendText = "";
        var trendColor = (Brush)Application.Current.Resources["TextSecondary"];
        if (trend != null && trend.PreviousScore.HasValue)
        {
            trendText = $" {trend.TrendIndicator}";
            if (trend.ScoreChange > 0)
                trendColor = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4CAF50"));
            else if (trend.ScoreChange < 0)
                trendColor = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44336"));
        }

        var scoreRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        scoreRow.Children.Add(new TextBlock
        {
            Text = $"{score}",
            FontSize = 28,
            FontWeight = FontWeights.Bold,
            Foreground = (Brush)Application.Current.Resources["TextPrimary"]
        });

        if (!string.IsNullOrEmpty(trendText))
        {
            scoreRow.Children.Add(new TextBlock
            {
                Text = trendText,
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Foreground = trendColor,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(4, 0, 0, 0)
            });
        }

        scorePanel.Children.Add(scoreRow);

        var gradeAndChange = SecurityScorer.GetGrade(score);
        if (trend != null && trend.PreviousScore.HasValue)
        {
            var sign = trend.ScoreChange > 0 ? "+" : "";
            gradeAndChange += $" ({sign}{trend.ScoreChange})";
        }

        scorePanel.Children.Add(new TextBlock
        {
            Text = gradeAndChange,
            HorizontalAlignment = HorizontalAlignment.Right,
            Foreground = (Brush)Application.Current.Resources["TextSecondary"]
        });

        Grid.SetColumn(scorePanel, 1);
        grid.Children.Add(scorePanel);

        border.Child = grid;
        return border;
    }

    private Border CreateAlertItem(Finding finding)
    {
        var icon = finding.Severity == Severity.Critical ? "🔴" : "🟡";

        var border = new Border
        {
            Background = (Brush)Application.Current.Resources["CardBackground"],
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(12),
            Margin = new Thickness(0, 0, 0, 6),
        };

        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = $"{icon} {finding.Title}",
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.Resources["TextPrimary"]
        });
        stack.Children.Add(new TextBlock
        {
            Text = finding.Description,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.Resources["TextSecondary"],
            Margin = new Thickness(0, 2, 0, 0)
        });

        if (finding.Remediation != null)
        {
            stack.Children.Add(new TextBlock
            {
                Text = $"💡 {finding.Remediation}",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0),
                FontStyle = FontStyles.Italic,
                Foreground = (Brush)Application.Current.Resources["TextSecondary"]
            });
        }

        border.Child = stack;
        return border;
    }
}
