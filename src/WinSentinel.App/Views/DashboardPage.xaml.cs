using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WinSentinel.App.ViewModels;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

public partial class DashboardPage : Page
{
    private readonly DashboardViewModel _vm = new();

    public DashboardPage()
    {
        InitializeComponent();
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        ScanButton.IsEnabled = false;
        ScanProgress.Visibility = Visibility.Visible;
        ProgressText.Visibility = Visibility.Visible;
        NoAlertsText.Visibility = Visibility.Collapsed;

        var engine = new AuditEngine();
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

            // Category cards
            CategoryList.Items.Clear();
            foreach (var result in report.Results)
            {
                var catScore = SecurityScorer.CalculateCategoryScore(result);
                var card = CreateCategoryCard(result, catScore);
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

    private Border CreateCategoryCard(AuditResult result, int score)
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
        scorePanel.Children.Add(new TextBlock
        {
            Text = $"{score}",
            FontSize = 28,
            FontWeight = FontWeights.Bold,
            HorizontalAlignment = HorizontalAlignment.Right,
            Foreground = (Brush)Application.Current.Resources["TextPrimary"]
        });
        scorePanel.Children.Add(new TextBlock
        {
            Text = SecurityScorer.GetGrade(score),
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
