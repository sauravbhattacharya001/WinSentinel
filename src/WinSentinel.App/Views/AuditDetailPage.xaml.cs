using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WinSentinel.App.ViewModels;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

public partial class AuditDetailPage : Page
{
    private readonly AuditDetailViewModel _vm = new();

    public AuditDetailPage()
    {
        InitializeComponent();
    }

    public AuditDetailPage(string category) : this()
    {
        _vm.SetCategory(category);
        ModuleTitle.Text = $"🔍 {_vm.ModuleName}";
    }

    private async void RunButton_Click(object sender, RoutedEventArgs e)
    {
        RunButton.IsEnabled = false;
        ScanProgress.Visibility = Visibility.Visible;
        ModuleStatus.Text = $"Scanning {_vm.Category}...";
        FindingsList.Items.Clear();

        try
        {
            await _vm.RunAuditCommand.ExecuteAsync(null);

            ScoreText.Text = $"{_vm.Score}";
            GradeText.Text = $"Grade: {_vm.Grade}";
            ModuleStatus.Text = _vm.StatusText;

            foreach (var finding in _vm.Findings)
            {
                FindingsList.Items.Add(CreateFindingCard(finding));
            }
        }
        catch (Exception ex)
        {
            ModuleStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            RunButton.IsEnabled = true;
            ScanProgress.Visibility = Visibility.Collapsed;
        }
    }

    private Border CreateFindingCard(Finding finding)
    {
        var icon = finding.Severity switch
        {
            Severity.Critical => "🔴",
            Severity.Warning => "🟡",
            Severity.Info => "ℹ️",
            Severity.Pass => "✅",
            _ => "❓"
        };

        var border = new Border
        {
            Background = (Brush)Application.Current.Resources["CardBackground"],
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16),
            Margin = new Thickness(0, 0, 0, 8),
        };

        var stack = new StackPanel();

        // Title with severity
        stack.Children.Add(new TextBlock
        {
            Text = $"{icon} {finding.Title}",
            FontWeight = FontWeights.SemiBold,
            FontSize = 15,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.Resources["TextPrimary"]
        });

        // Severity badge
        stack.Children.Add(new TextBlock
        {
            Text = $"Severity: {finding.Severity}",
            Foreground = (Brush)Application.Current.Resources["TextSecondary"],
            FontSize = 12
        });

        // Description
        stack.Children.Add(new TextBlock
        {
            Text = finding.Description,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 0),
            Foreground = (Brush)Application.Current.Resources["TextPrimary"]
        });

        // Remediation
        if (!string.IsNullOrEmpty(finding.Remediation))
        {
            stack.Children.Add(new TextBlock
            {
                Text = $"💡 {finding.Remediation}",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 0),
                FontStyle = FontStyles.Italic,
                Foreground = (Brush)Application.Current.Resources["TextSecondary"]
            });
        }

        // Fix command
        if (!string.IsNullOrEmpty(finding.FixCommand))
        {
            var cmdBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(30, 255, 255, 255)),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(8, 4, 8, 4),
                Margin = new Thickness(0, 4, 0, 0)
            };

            cmdBorder.Child = new TextBlock
            {
                Text = $"🔧 {finding.FixCommand}",
                FontFamily = new FontFamily("Cascadia Mono, Consolas"),
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Foreground = (Brush)Application.Current.Resources["TextPrimary"]
            };

            stack.Children.Add(cmdBorder);
        }

        border.Child = stack;
        return border;
    }
}
