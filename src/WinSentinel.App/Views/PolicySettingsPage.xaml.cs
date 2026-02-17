using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WinSentinel.App.Services;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

/// <summary>
/// Policy settings page — configures agent threat response policies, notifications,
/// scan schedules, monitor modules, and user overrides via IPC.
/// </summary>
public partial class PolicySettingsPage : Page
{
    private AgentConnectionService? _agentService;
    private IpcAgentConfig? _currentConfig;
    private IpcPolicyData? _currentPolicy;
    private bool _isLoading = true;

    /// <summary>Threat categories for per-category settings.</summary>
    private static readonly string[] ThreatCategories = { "Process", "FileSystem", "EventLog", "Network" };

    /// <summary>Monitor module names matching the agent module names.</summary>
    private static readonly string[] MonitorModules =
    {
        "ProcessMonitor", "FileSystemMonitor", "EventLogMonitor", "NetworkMonitor", "ScheduledAudit"
    };

    /// <summary>Display-friendly module names.</summary>
    private static readonly Dictionary<string, string> ModuleDisplayNames = new()
    {
        ["ProcessMonitor"] = "⚙️ Process Monitor — WMI-based real-time process tracking",
        ["FileSystemMonitor"] = "📁 File System Monitor — Watches critical directories",
        ["EventLogMonitor"] = "📋 Event Log Monitor — Security/System/Defender logs",
        ["NetworkMonitor"] = "🌐 Network Monitor — TCP connections, ports, ARP",
        ["ScheduledAudit"] = "🔍 Scheduled Audit — Periodic full security scans"
    };

    public PolicySettingsPage()
    {
        InitializeComponent();
    }

    /// <summary>Set the agent connection for IPC config read/write.</summary>
    public void SetAgentService(AgentConnectionService agentService)
    {
        _agentService = agentService;
        _ = LoadFromAgentAsync();
    }

    // ══════════════════════════════════════════
    //  Loading from Agent
    // ══════════════════════════════════════════

    private async Task LoadFromAgentAsync()
    {
        _isLoading = true;

        if (_agentService == null || !_agentService.IsConnected)
        {
            ConnectionBanner.Visibility = Visibility.Visible;
            LoadDefaults();
            _isLoading = false;
            return;
        }

        ConnectionBanner.Visibility = Visibility.Collapsed;

        try
        {
            _currentConfig = await _agentService.GetConfigAsync();
            _currentPolicy = await _agentService.GetPolicyAsync();
        }
        catch
        {
            ConnectionBanner.Visibility = Visibility.Visible;
            ConnectionBannerText.Text = "⚠️ Failed to load settings from agent — showing defaults";
        }

        if (_currentConfig == null)
        {
            LoadDefaults();
            _isLoading = false;
            return;
        }

        // Apply config to UI
        LoadConfigToUI(_currentConfig, _currentPolicy);
        _isLoading = false;
    }

    private void LoadDefaults()
    {
        _currentConfig = new IpcAgentConfig
        {
            ScanIntervalHours = 4,
            RiskTolerance = "Medium",
            NotifyOnCriticalThreats = true,
            NotifyOnScanComplete = true,
            NotificationSound = true,
            NotifyCriticalOnly = false,
            MinimizeToTray = true,
        };
        _currentPolicy = new IpcPolicyData { RiskTolerance = "Medium" };
        LoadConfigToUI(_currentConfig, _currentPolicy);
    }

    private void LoadConfigToUI(IpcAgentConfig config, IpcPolicyData? policy)
    {
        // Risk tolerance
        var riskTolerance = policy?.RiskTolerance ?? config.RiskTolerance;
        RiskLow.IsChecked = riskTolerance == "Low";
        RiskMedium.IsChecked = riskTolerance == "Medium";
        RiskHigh.IsChecked = riskTolerance == "High";
        UpdateRiskDescription();

        // Per-category toggles
        BuildCategoryList(config);

        // User overrides
        BuildOverridesList(policy);

        // Notification settings
        NotifyToastCheck.IsChecked = config.NotifyOnCriticalThreats;
        NotifyCriticalOnlyCheck.IsChecked = config.NotifyCriticalOnly;
        NotifySoundCheck.IsChecked = config.NotificationSound;
        NotifyScanCompleteCheck.IsChecked = config.NotifyOnScanComplete;

        // Scan interval
        var hours = config.ScanIntervalHours;
        Scan1h.IsChecked = Math.Abs(hours - 1) < 0.1;
        Scan4h.IsChecked = Math.Abs(hours - 4) < 0.1;
        Scan8h.IsChecked = Math.Abs(hours - 8) < 0.1;
        Scan12h.IsChecked = Math.Abs(hours - 12) < 0.1;
        Scan24h.IsChecked = Math.Abs(hours - 24) < 0.1;
        if (!Scan1h.IsChecked!.Value && !Scan4h.IsChecked!.Value &&
            !Scan8h.IsChecked!.Value && !Scan12h.IsChecked!.Value && !Scan24h.IsChecked!.Value)
            Scan4h.IsChecked = true;

        // Auto-export
        AutoExportCheck.IsChecked = config.AutoExportAfterScan;
        SelectComboByContent(ExportFormatCombo, config.AutoExportFormat);
        ExportFormatPanel.Opacity = config.AutoExportAfterScan ? 1.0 : 0.5;
        ExportFormatPanel.IsEnabled = config.AutoExportAfterScan;

        // Monitor modules
        BuildMonitorModulesList(config);

        // System
        StartWithWindowsCheck.IsChecked = config.StartWithWindows;
        MinimizeToTrayCheck.IsChecked = config.MinimizeToTray;
    }

    // ══════════════════════════════════════════
    //  Category List
    // ══════════════════════════════════════════

    private void BuildCategoryList(IpcAgentConfig config)
    {
        CategoryList.Items.Clear();

        foreach (var cat in ThreatCategories)
        {
            var autoFixEnabled = config.CategoryAutoFix.GetValueOrDefault(cat, false);
            var defaultResponse = config.CategoryDefaultResponse.GetValueOrDefault(cat, "Alert");
            var rulesCount = _currentPolicy?.Rules.Count(r => r.Category == cat) ?? 0;

            var card = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x2E)),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16, 12, 16, 12),
                Margin = new Thickness(0, 0, 0, 8),
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Left side: category info
            var leftStack = new StackPanel();
            var icon = cat switch
            {
                "Process" => "⚙️",
                "FileSystem" => "📁",
                "EventLog" => "📋",
                "Network" => "🌐",
                _ => "❓"
            };

            leftStack.Children.Add(new TextBlock
            {
                Text = $"{icon} {cat}",
                FontSize = 16,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)Application.Current.Resources["TextPrimary"]
            });

            leftStack.Children.Add(new TextBlock
            {
                Text = $"{rulesCount} custom rule{(rulesCount == 1 ? "" : "s")}",
                FontSize = 12,
                Foreground = (Brush)Application.Current.Resources["TextSecondary"],
                Margin = new Thickness(0, 2, 0, 0)
            });

            Grid.SetColumn(leftStack, 0);
            grid.Children.Add(leftStack);

            // Right side: controls
            var rightStack = new StackPanel { Orientation = Orientation.Horizontal };

            // Auto-fix toggle
            var autoFixCb = new CheckBox
            {
                Content = "Auto-Fix",
                IsChecked = autoFixEnabled,
                Foreground = (Brush)Application.Current.Resources["TextPrimary"],
                FontSize = 13,
                Margin = new Thickness(0, 0, 16, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Tag = $"autofix|{cat}"
            };
            autoFixCb.Checked += CategorySetting_Changed;
            autoFixCb.Unchecked += CategorySetting_Changed;
            rightStack.Children.Add(autoFixCb);

            // Default response combo
            var responseLbl = new TextBlock
            {
                Text = "Default: ",
                Foreground = (Brush)Application.Current.Resources["TextSecondary"],
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 4, 0)
            };
            rightStack.Children.Add(responseLbl);

            var responseCombo = new ComboBox
            {
                Width = 100,
                FontSize = 13,
                Background = new SolidColorBrush(Color.FromRgb(0x2A, 0x2A, 0x4A)),
                Foreground = (Brush)Application.Current.Resources["TextPrimary"],
                BorderBrush = (Brush)Application.Current.Resources["CardBorder"],
                Tag = $"response|{cat}",
                VerticalAlignment = VerticalAlignment.Center
            };
            responseCombo.Items.Add(new ComboBoxItem { Content = "AutoFix" });
            responseCombo.Items.Add(new ComboBoxItem { Content = "Alert" });
            responseCombo.Items.Add(new ComboBoxItem { Content = "Log" });
            SelectComboByContent(responseCombo, defaultResponse);
            responseCombo.SelectionChanged += CategoryResponse_Changed;
            rightStack.Children.Add(responseCombo);

            Grid.SetColumn(rightStack, 1);
            grid.Children.Add(rightStack);

            card.Child = grid;
            CategoryList.Items.Add(card);
        }
    }

    // ══════════════════════════════════════════
    //  User Overrides List
    // ══════════════════════════════════════════

    private void BuildOverridesList(IpcPolicyData? policy)
    {
        OverridesList.Items.Clear();

        var overrides = policy?.UserOverrides ?? new List<IpcUserOverride>();

        NoOverridesText.Visibility = overrides.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        foreach (var ov in overrides)
        {
            var card = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x2E)),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16, 10, 16, 10),
                Margin = new Thickness(0, 0, 0, 6),
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Info
            var leftStack = new StackPanel();
            var actionIcon = ov.OverrideAction switch
            {
                "AlwaysIgnore" => "🔇",
                "AlwaysAutoFix" => "🔧",
                "AlwaysAlert" => "🔔",
                _ => "❓"
            };
            var actionLabel = ov.OverrideAction switch
            {
                "AlwaysIgnore" => "Always Ignore",
                "AlwaysAutoFix" => "Always Auto-Fix",
                "AlwaysAlert" => "Always Alert",
                _ => ov.OverrideAction
            };

            leftStack.Children.Add(new TextBlock
            {
                Text = $"{actionIcon} {ov.ThreatTitle}",
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)Application.Current.Resources["TextPrimary"]
            });

            var detailText = $"{actionLabel}";
            if (!string.IsNullOrEmpty(ov.Source)) detailText += $" • Source: {ov.Source}";
            detailText += $" • Created: {ov.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm}";

            leftStack.Children.Add(new TextBlock
            {
                Text = detailText,
                FontSize = 12,
                Foreground = (Brush)Application.Current.Resources["TextSecondary"],
                Margin = new Thickness(0, 2, 0, 0)
            });

            Grid.SetColumn(leftStack, 0);
            grid.Children.Add(leftStack);

            // Delete button
            var deleteBtn = new Button
            {
                Content = "🗑️",
                Style = (Style)Application.Current.Resources["QuickButton"],
                FontSize = 14,
                Padding = new Thickness(8, 4, 8, 4),
                Tag = ov.ThreatTitle,
                VerticalAlignment = VerticalAlignment.Center
            };
            deleteBtn.Click += DeleteOverride_Click;
            Grid.SetColumn(deleteBtn, 1);
            grid.Children.Add(deleteBtn);

            card.Child = grid;
            OverridesList.Items.Add(card);
        }
    }

    // ══════════════════════════════════════════
    //  Monitor Modules List
    // ══════════════════════════════════════════

    private void BuildMonitorModulesList(IpcAgentConfig config)
    {
        MonitorModulesList.Items.Clear();

        foreach (var moduleName in MonitorModules)
        {
            var isEnabled = !config.ModuleToggles.TryGetValue(moduleName, out var enabled) || enabled;
            var displayName = ModuleDisplayNames.GetValueOrDefault(moduleName, moduleName);

            var cb = new CheckBox
            {
                Content = displayName,
                IsChecked = isEnabled,
                Tag = moduleName,
                Foreground = (Brush)Application.Current.Resources["TextPrimary"],
                FontSize = 14,
                Margin = new Thickness(0, 0, 0, 8)
            };
            cb.Checked += ModuleToggle_Changed;
            cb.Unchecked += ModuleToggle_Changed;
            MonitorModulesList.Items.Add(cb);
        }
    }

    // ══════════════════════════════════════════
    //  Event Handlers
    // ══════════════════════════════════════════

    private void Risk_Changed(object sender, RoutedEventArgs e)
    {
        if (_isLoading) return;
        UpdateRiskDescription();
    }

    private void UpdateRiskDescription()
    {
        if (RiskLow.IsChecked == true)
        {
            RiskDescriptionText.Text = "🔒 Agent auto-fixes critical threats, alerts on everything else. Most aggressive response.";
            RiskDescriptionBox.Background = new SolidColorBrush(Color.FromArgb(40, 76, 175, 80));
        }
        else if (RiskHigh.IsChecked == true)
        {
            RiskDescriptionText.Text = "📋 Agent logs only, never auto-fixes. All threats are recorded but no automatic action is taken.";
            RiskDescriptionBox.Background = new SolidColorBrush(Color.FromArgb(40, 255, 152, 0));
        }
        else
        {
            RiskDescriptionText.Text = "⚖️ Agent alerts on critical+high threats, logs the rest. Balanced approach.";
            RiskDescriptionBox.Background = new SolidColorBrush(Color.FromArgb(40, 33, 150, 243));
        }
    }

    private void Settings_Changed(object sender, RoutedEventArgs e)
    {
        if (_isLoading) return;

        // Update auto-export panel opacity
        if (AutoExportCheck != null && ExportFormatPanel != null)
        {
            ExportFormatPanel.Opacity = AutoExportCheck.IsChecked == true ? 1.0 : 0.5;
            ExportFormatPanel.IsEnabled = AutoExportCheck.IsChecked == true;
        }
    }

    private void ScanInterval_Changed(object sender, RoutedEventArgs e)
    {
        if (_isLoading) return;
    }

    private void ExportFormat_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_isLoading) return;
    }

    private void CategorySetting_Changed(object sender, RoutedEventArgs e)
    {
        if (_isLoading) return;
    }

    private void CategoryResponse_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_isLoading) return;
    }

    private void ModuleToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_isLoading) return;
    }

    private void DeleteOverride_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string threatTitle && _currentPolicy != null)
        {
            _currentPolicy.UserOverrides.RemoveAll(o =>
                o.ThreatTitle.Equals(threatTitle, StringComparison.OrdinalIgnoreCase));
            BuildOverridesList(_currentPolicy);
            StatusText.Text = $"✓ Override for '{threatTitle}' removed (save to apply)";
        }
    }

    private void AddOverride_Click(object sender, RoutedEventArgs e)
    {
        // Create a simple inline add UI
        _currentPolicy ??= new IpcPolicyData();

        var dialog = new Window
        {
            Title = "Add User Override",
            Width = 450,
            Height = 300,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = Window.GetWindow(this),
            Background = (Brush)Application.Current.Resources["AppBackground"],
            ResizeMode = ResizeMode.NoResize
        };

        var stack = new StackPanel { Margin = new Thickness(24) };

        stack.Children.Add(new TextBlock
        {
            Text = "Threat Title:",
            Foreground = (Brush)Application.Current.Resources["TextPrimary"],
            FontSize = 14,
            Margin = new Thickness(0, 0, 0, 4)
        });

        var titleBox = new TextBox
        {
            Background = new SolidColorBrush(Color.FromRgb(0x2A, 0x2A, 0x4A)),
            Foreground = (Brush)Application.Current.Resources["TextPrimary"],
            BorderBrush = (Brush)Application.Current.Resources["CardBorder"],
            FontSize = 14,
            Padding = new Thickness(8, 6, 8, 6),
            Margin = new Thickness(0, 0, 0, 12)
        };
        stack.Children.Add(titleBox);

        stack.Children.Add(new TextBlock
        {
            Text = "Override Action:",
            Foreground = (Brush)Application.Current.Resources["TextPrimary"],
            FontSize = 14,
            Margin = new Thickness(0, 0, 0, 4)
        });

        var actionCombo = new ComboBox
        {
            Width = 200,
            HorizontalAlignment = HorizontalAlignment.Left,
            FontSize = 14,
            Background = new SolidColorBrush(Color.FromRgb(0x2A, 0x2A, 0x4A)),
            Foreground = (Brush)Application.Current.Resources["TextPrimary"],
            BorderBrush = (Brush)Application.Current.Resources["CardBorder"],
            Margin = new Thickness(0, 0, 0, 16)
        };
        actionCombo.Items.Add(new ComboBoxItem { Content = "Always Ignore", Tag = "AlwaysIgnore" });
        actionCombo.Items.Add(new ComboBoxItem { Content = "Always Auto-Fix", Tag = "AlwaysAutoFix" });
        actionCombo.Items.Add(new ComboBoxItem { Content = "Always Alert", Tag = "AlwaysAlert" });
        actionCombo.SelectedIndex = 0;
        stack.Children.Add(actionCombo);

        var btnStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var okBtn = new Button
        {
            Content = "Add",
            Style = (Style)Application.Current.Resources["AccentButton"],
            MinWidth = 80,
            Margin = new Thickness(0, 0, 8, 0)
        };
        var cancelBtn = new Button
        {
            Content = "Cancel",
            Style = (Style)Application.Current.Resources["QuickButton"],
            MinWidth = 80
        };

        okBtn.Click += (_, _) =>
        {
            var title = titleBox.Text.Trim();
            if (string.IsNullOrEmpty(title))
            {
                MessageBox.Show("Threat title is required.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var selectedAction = (actionCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "AlwaysIgnore";

            _currentPolicy!.UserOverrides.Add(new IpcUserOverride
            {
                ThreatTitle = title,
                OverrideAction = selectedAction,
                CreatedAt = DateTimeOffset.UtcNow
            });

            dialog.DialogResult = true;
            dialog.Close();
        };

        cancelBtn.Click += (_, _) => { dialog.Close(); };

        btnStack.Children.Add(okBtn);
        btnStack.Children.Add(cancelBtn);
        stack.Children.Add(btnStack);

        dialog.Content = stack;

        if (dialog.ShowDialog() == true)
        {
            BuildOverridesList(_currentPolicy);
            StatusText.Text = "✓ Override added (save to apply)";
        }
    }

    // ══════════════════════════════════════════
    //  Save / Reset
    // ══════════════════════════════════════════

    private async void SaveAll_Click(object sender, RoutedEventArgs e)
    {
        SaveButton.IsEnabled = false;
        StatusText.Text = "Saving...";

        try
        {
            var config = CollectConfigFromUI();
            var policy = CollectPolicyFromUI();

            if (_agentService != null && _agentService.IsConnected)
            {
                var savedConfig = await _agentService.SetConfigAsync(config);
                var savedPolicy = await _agentService.SetPolicyAsync(policy);

                if (savedConfig != null)
                    _currentConfig = savedConfig;
                if (savedPolicy != null)
                    _currentPolicy = savedPolicy;

                StatusText.Text = "✓ All settings saved to agent and persisted to disk";
                StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50));
            }
            else
            {
                StatusText.Text = "⚠️ Agent not connected — settings cannot be saved";
                StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x98, 0x00));
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"❌ Save failed: {ex.Message}";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0xF4, 0x43, 0x36));
        }
        finally
        {
            SaveButton.IsEnabled = true;
        }
    }

    private void ResetDefaults_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Reset all settings to defaults? This will not save until you click Save.",
            "Reset Settings",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            _isLoading = true;
            LoadDefaults();
            _isLoading = false;
            StatusText.Text = "✓ Settings reset to defaults (click Save to apply)";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x21, 0x96, 0xF3));
        }
    }

    // ══════════════════════════════════════════
    //  Collect UI State
    // ══════════════════════════════════════════

    private IpcAgentConfig CollectConfigFromUI()
    {
        var config = _currentConfig ?? new IpcAgentConfig();

        // Risk tolerance
        config.RiskTolerance = RiskLow.IsChecked == true ? "Low"
            : RiskHigh.IsChecked == true ? "High"
            : "Medium";

        // Scan interval
        config.ScanIntervalHours =
            Scan1h.IsChecked == true ? 1 :
            Scan8h.IsChecked == true ? 8 :
            Scan12h.IsChecked == true ? 12 :
            Scan24h.IsChecked == true ? 24 : 4;

        // Notifications
        config.NotifyOnCriticalThreats = NotifyToastCheck.IsChecked ?? true;
        config.NotifyCriticalOnly = NotifyCriticalOnlyCheck.IsChecked ?? false;
        config.NotificationSound = NotifySoundCheck.IsChecked ?? true;
        config.NotifyOnScanComplete = NotifyScanCompleteCheck.IsChecked ?? true;

        // Auto-export
        config.AutoExportAfterScan = AutoExportCheck.IsChecked ?? false;
        config.AutoExportFormat = GetComboSelectedContent(ExportFormatCombo) ?? "HTML";

        // System
        config.StartWithWindows = StartWithWindowsCheck.IsChecked ?? false;
        config.MinimizeToTray = MinimizeToTrayCheck.IsChecked ?? true;

        // Auto-fix based on risk tolerance
        config.AutoFixCritical = RiskLow.IsChecked == true;
        config.AutoFixWarnings = false;

        // Module toggles
        config.ModuleToggles.Clear();
        foreach (var item in MonitorModulesList.Items)
        {
            if (item is CheckBox cb && cb.Tag is string moduleName)
            {
                config.ModuleToggles[moduleName] = cb.IsChecked ?? true;
            }
        }

        // Per-category settings
        config.CategoryAutoFix.Clear();
        config.CategoryDefaultResponse.Clear();
        foreach (var item in CategoryList.Items)
        {
            if (item is Border border && border.Child is Grid grid)
            {
                foreach (var child in grid.Children)
                {
                    if (child is StackPanel sp)
                    {
                        foreach (var ctrl in sp.Children)
                        {
                            if (ctrl is CheckBox cb && cb.Tag is string autoFixTag && autoFixTag.StartsWith("autofix|"))
                            {
                                var cat = autoFixTag.Split('|')[1];
                                config.CategoryAutoFix[cat] = cb.IsChecked ?? false;
                            }
                            else if (ctrl is ComboBox combo && combo.Tag is string responseTag && responseTag.StartsWith("response|"))
                            {
                                var cat = responseTag.Split('|')[1];
                                config.CategoryDefaultResponse[cat] = GetComboSelectedContent(combo) ?? "Alert";
                            }
                        }
                    }
                }
            }
        }

        return config;
    }

    private IpcPolicyData CollectPolicyFromUI()
    {
        var policy = _currentPolicy ?? new IpcPolicyData();

        // Risk tolerance (sync with config)
        policy.RiskTolerance = RiskLow.IsChecked == true ? "Low"
            : RiskHigh.IsChecked == true ? "High"
            : "Medium";

        // Overrides are already managed in-memory via add/delete
        return policy;
    }

    // ══════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════

    private static void SelectComboByContent(ComboBox combo, string content)
    {
        foreach (var item in combo.Items)
        {
            if (item is ComboBoxItem ci && ci.Content?.ToString() == content)
            {
                combo.SelectedItem = ci;
                return;
            }
        }
        if (combo.Items.Count > 0)
            combo.SelectedIndex = 0;
    }

    private static string? GetComboSelectedContent(ComboBox combo)
    {
        return (combo.SelectedItem as ComboBoxItem)?.Content?.ToString();
    }
}
