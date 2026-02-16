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
    private readonly FixEngine _fixEngine = new();

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

    private async void FixButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button fixButton || fixButton.Tag is not Finding finding)
            return;

        // Confirm before executing
        var needsAdmin = FixEngine.RequiresElevation(finding.FixCommand!);
        var confirmMsg = needsAdmin
            ? $"This fix requires administrator privileges and will trigger a UAC prompt.\n\nCommand:\n{finding.FixCommand}\n\nProceed?"
            : $"Execute this fix?\n\nCommand:\n{finding.FixCommand}\n\nProceed?";

        var confirmResult = MessageBox.Show(
            confirmMsg,
            $"Fix: {finding.Title}",
            MessageBoxButton.YesNo,
            needsAdmin ? MessageBoxImage.Warning : MessageBoxImage.Question);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        // Update button state
        fixButton.IsEnabled = false;
        fixButton.Content = "⏳ Fixing...";

        try
        {
            var result = await _fixEngine.ExecuteFixAsync(finding);

            if (result.Success)
            {
                fixButton.Content = "✅ Fixed!";
                fixButton.Background = new SolidColorBrush(Color.FromRgb(39, 174, 96));

                var output = string.IsNullOrWhiteSpace(result.Output) ? "Fix applied successfully." : result.Output;
                MessageBox.Show(
                    $"Fix applied successfully!\n\n{output}",
                    "Fix Result",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                fixButton.Content = "❌ Failed";
                fixButton.Background = new SolidColorBrush(Color.FromRgb(231, 76, 60));
                fixButton.IsEnabled = true; // Allow retry

                MessageBox.Show(
                    $"Fix failed.\n\n{result.Error}",
                    "Fix Failed",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            fixButton.Content = "🔧 Fix";
            fixButton.IsEnabled = true;

            MessageBox.Show(
                $"Error running fix:\n{ex.Message}",
                "Fix Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
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

        // Title row with Fix button
        var titleRow = new Grid();
        titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var titleBlock = new TextBlock
        {
            Text = $"{icon} {finding.Title}",
            FontWeight = FontWeights.SemiBold,
            FontSize = 15,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.Resources["TextPrimary"],
            VerticalAlignment = VerticalAlignment.Center
        };
        Grid.SetColumn(titleBlock, 0);
        titleRow.Children.Add(titleBlock);

        // Add Fix button for findings with a FixCommand (Warning or Critical only)
        if (!string.IsNullOrEmpty(finding.FixCommand) &&
            (finding.Severity == Severity.Warning || finding.Severity == Severity.Critical))
        {
            var needsAdmin = FixEngine.RequiresElevation(finding.FixCommand);
            var fixButton = new Button
            {
                Content = needsAdmin ? "🛡️ Fix (Admin)" : "🔧 Fix",
                Tag = finding,
                Padding = new Thickness(12, 6, 12, 6),
                Margin = new Thickness(8, 0, 0, 0),
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Cursor = System.Windows.Input.Cursors.Hand,
                Background = finding.Severity == Severity.Critical
                    ? new SolidColorBrush(Color.FromRgb(231, 76, 60))
                    : new SolidColorBrush(Color.FromRgb(243, 156, 18)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                VerticalAlignment = VerticalAlignment.Center
            };

            // Apply rounded corners via template
            fixButton.Style = CreateFixButtonStyle(fixButton.Background);
            fixButton.Click += FixButton_Click;

            Grid.SetColumn(fixButton, 1);
            titleRow.Children.Add(fixButton);
        }

        stack.Children.Add(titleRow);

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

        // Fix command display
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

    /// <summary>
    /// Creates a style for fix buttons with rounded corners.
    /// </summary>
    private static Style CreateFixButtonStyle(Brush background)
    {
        var style = new Style(typeof(Button));

        var template = new ControlTemplate(typeof(Button));
        var borderFactory = new FrameworkElementFactory(typeof(Border));
        borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
        borderFactory.SetValue(Border.BackgroundProperty, background);
        borderFactory.SetValue(Border.PaddingProperty, new Thickness(12, 6, 12, 6));

        var contentFactory = new FrameworkElementFactory(typeof(ContentPresenter));
        contentFactory.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        contentFactory.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        borderFactory.AppendChild(contentFactory);

        template.VisualTree = borderFactory;
        style.Setters.Add(new Setter(Control.TemplateProperty, template));
        style.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));
        style.Setters.Add(new Setter(Control.FontWeightProperty, FontWeights.SemiBold));
        style.Setters.Add(new Setter(Control.CursorProperty, System.Windows.Input.Cursors.Hand));

        return style;
    }
}
