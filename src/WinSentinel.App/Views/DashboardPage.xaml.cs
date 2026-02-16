using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using WinSentinel.App.ViewModels;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Windows.UI;

namespace WinSentinel.App.Views;

public sealed partial class DashboardPage : Page
{
    private readonly DashboardViewModel _vm = new();

    public DashboardPage()
    {
        this.InitializeComponent();
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
            DispatcherQueue.TryEnqueue(() =>
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
            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16),
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var info = new StackPanel();
        info.Children.Add(new TextBlock
        {
            Text = $"{icon} {result.Category}",
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            FontSize = 16
        });

        var details = $"🔴 {result.CriticalCount} critical  •  🟡 {result.WarningCount} warnings  •  {result.Findings.Count} total findings";
        info.Children.Add(new TextBlock
        {
            Text = details,
            Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
            Margin = new Thickness(0, 4, 0, 0)
        });

        Grid.SetColumn(info, 0);
        grid.Children.Add(info);

        var scorePanel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };
        scorePanel.Children.Add(new TextBlock
        {
            Text = $"{score}",
            FontSize = 28,
            FontWeight = Microsoft.UI.Text.FontWeights.Bold,
            HorizontalAlignment = HorizontalAlignment.Right
        });
        scorePanel.Children.Add(new TextBlock
        {
            Text = SecurityScorer.GetGrade(score),
            HorizontalAlignment = HorizontalAlignment.Right,
            Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"]
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
            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(12),
        };

        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = $"{icon} {finding.Title}",
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
        });
        stack.Children.Add(new TextBlock
        {
            Text = finding.Description,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
            Margin = new Thickness(0, 2, 0, 0)
        });

        if (finding.Remediation != null)
        {
            stack.Children.Add(new TextBlock
            {
                Text = $"💡 {finding.Remediation}",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0),
                FontStyle = Windows.UI.Text.FontStyle.Italic
            });
        }

        border.Child = stack;
        return border;
    }
}
