using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using WinSentinel.App.Services;
using WinSentinel.App.ViewModels;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

public partial class ChatPage : Page
{
    private AgentConnectionService? _agentConnection;
    private readonly ChatAiService _localAdvisor = new();
    private readonly List<ChatMessage> _chatHistory = new();
    private bool _useAgent;

    private static readonly string ChatHistoryPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSentinel", "chat-history.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public ChatPage()
    {
        InitializeComponent();
        LoadChatHistory();
    }

    /// <summary>
    /// Set the agent connection service for IPC-based chat.
    /// Called from MainWindow when navigating to chat.
    /// </summary>
    public void SetAgentService(AgentConnectionService agentConnection)
    {
        _agentConnection = agentConnection;
        _useAgent = agentConnection.IsConnected;
        UpdateAgentBadge();

        // Subscribe to connection changes
        agentConnection.StatusChanged += OnConnectionStatusChanged;
    }

    private void OnConnectionStatusChanged(ConnectionStatus status)
    {
        Dispatcher.InvokeAsync(() =>
        {
            _useAgent = status == ConnectionStatus.Connected;
            UpdateAgentBadge();
        });
    }

    private void UpdateAgentBadge()
    {
        if (_useAgent)
        {
            AgentBadgeText.Text = "⚡ Agent Connected";
            AgentBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80));
            AgentBadge.Background = new SolidColorBrush(Color.FromArgb(26, 76, 175, 80));
        }
        else
        {
            AgentBadgeText.Text = "💬 Local Mode";
            AgentBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(255, 193, 7));
            AgentBadge.Background = new SolidColorBrush(Color.FromArgb(26, 255, 193, 7));
        }
    }

    private void LoadChatHistory()
    {
        try
        {
            if (File.Exists(ChatHistoryPath))
            {
                var json = File.ReadAllText(ChatHistoryPath);
                var history = JsonSerializer.Deserialize<List<ChatMessage>>(json, JsonOpts);
                if (history != null)
                {
                    // Load last 50 messages
                    var recent = history.TakeLast(50).ToList();
                    _chatHistory.AddRange(recent);
                    foreach (var msg in recent)
                    {
                        AddMessageBubble(msg);
                    }
                    return;
                }
            }
        }
        catch
        {
            // Ignore load errors, start fresh
        }

        // Default welcome message if no history
        var welcome = new ChatMessage
        {
            IsBot = true,
            Text = "👋 Hi! I'm WinSentinel, your security control plane.\n\n" +
                   "When connected to the agent, I have full access to:\n" +
                   "  • Live threat monitors & alerts\n" +
                   "  • Security audit engine\n" +
                   "  • Auto-remediation (kill, quarantine, block)\n" +
                   "  • Activity journal & history\n\n" +
                   "Type **help** to see all commands, or just ask me anything!",
            Category = "Help"
        };
        _chatHistory.Add(welcome);
        AddMessageBubble(welcome);
        SaveChatHistory();
    }

    private void SaveChatHistory()
    {
        try
        {
            var dir = Path.GetDirectoryName(ChatHistoryPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            // Keep only last 200 messages
            var toSave = _chatHistory.TakeLast(200).ToList();
            var json = JsonSerializer.Serialize(toSave, JsonOpts);
            File.WriteAllText(ChatHistoryPath, json);
        }
        catch
        {
            // Best-effort save
        }
    }

    private async void SendButton_Click(object sender, RoutedEventArgs e)
    {
        await SendMessageAsync();
    }

    private async void InputBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            await SendMessageAsync();
            e.Handled = true;
        }
    }

    private async void QuickAction_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string command)
        {
            InputBox.Text = command;
            await SendMessageAsync();
        }
    }

    private async void SuggestedAction_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string command)
        {
            InputBox.Text = command;
            await SendMessageAsync();
        }
    }

    private async Task SendMessageAsync()
    {
        var text = InputBox.Text?.Trim();
        if (string.IsNullOrEmpty(text)) return;

        // Add user bubble
        var userMsg = new ChatMessage { IsBot = false, Text = text };
        _chatHistory.Add(userMsg);
        AddMessageBubble(userMsg);
        InputBox.Text = "";

        SendButton.IsEnabled = false;
        InputBox.IsEnabled = false;

        // Add typing indicator
        var typingBorder = CreateTypingIndicator();
        MessageList.Items.Add(typingBorder);
        ScrollToBottom();

        try
        {
            ChatMessage botMsg;

            if (_useAgent && _agentConnection != null)
            {
                // Route through IPC to the running agent
                var response = await _agentConnection.SendChatAsync(text);

                if (response != null)
                {
                    botMsg = new ChatMessage
                    {
                        IsBot = true,
                        Text = response.Text,
                        Category = response.Category,
                        SecurityScore = response.SecurityScore,
                        ActionPerformed = response.ActionPerformed,
                        SuggestedActions = response.SuggestedActions
                            .Select(a => new ChatSuggestedAction { Label = a.Label, Command = a.Command })
                            .ToList()
                    };
                }
                else
                {
                    // Agent connection failed, fall back to local
                    _useAgent = false;
                    UpdateAgentBadge();

                    var localResponse = await _localAdvisor.GetResponseAsync(text);
                    botMsg = new ChatMessage { IsBot = true, Text = localResponse, Category = "General" };
                }
            }
            else
            {
                // Local mode — use SecurityAdvisor
                var localResponse = await _localAdvisor.GetResponseAsync(text);
                botMsg = new ChatMessage { IsBot = true, Text = localResponse, Category = "General" };
            }

            _chatHistory.Add(botMsg);

            // Remove typing indicator
            MessageList.Items.Remove(typingBorder);

            // Add rich bot bubble
            AddMessageBubble(botMsg);

            // Show suggested actions
            ShowSuggestedActions(botMsg.SuggestedActions);

            // Save history
            SaveChatHistory();
        }
        catch (Exception ex)
        {
            MessageList.Items.Remove(typingBorder);
            var errorMsg = new ChatMessage
            {
                IsBot = true,
                Text = $"❌ Error: {ex.Message}",
                Category = "Error"
            };
            _chatHistory.Add(errorMsg);
            AddMessageBubble(errorMsg);
            SaveChatHistory();
        }
        finally
        {
            SendButton.IsEnabled = true;
            InputBox.IsEnabled = true;
            InputBox.Focus();
        }
    }

    private void AddMessageBubble(ChatMessage msg)
    {
        var border = new Border
        {
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 10, 16, 10),
            MaxWidth = 650,
            HorizontalAlignment = msg.IsBot ? HorizontalAlignment.Left : HorizontalAlignment.Right,
            Margin = new Thickness(
                msg.IsBot ? 0 : 60, 0,
                msg.IsBot ? 60 : 0, 8)
        };

        // Style based on message category
        if (!msg.IsBot)
        {
            border.Background = new SolidColorBrush(Color.FromArgb(255, 0, 120, 212));
        }
        else
        {
            border.Background = msg.Category switch
            {
                "Error" => new SolidColorBrush(Color.FromArgb(30, 244, 67, 54)),
                "ActionConfirmation" => new SolidColorBrush(Color.FromArgb(30, 76, 175, 80)),
                "ThreatList" => new SolidColorBrush(Color.FromArgb(30, 255, 152, 0)),
                "Status" => new SolidColorBrush(Color.FromArgb(20, 33, 150, 243)),
                _ => (Brush)Application.Current.Resources["CardBackground"]
            };
        }

        var stackPanel = new StackPanel();

        // Score progress bar for status responses
        if (msg.IsBot && msg.SecurityScore.HasValue)
        {
            var score = msg.SecurityScore.Value;
            var scoreGrid = new Grid { Margin = new Thickness(0, 0, 0, 8) };

            var progressBorder = new Border
            {
                CornerRadius = new CornerRadius(4),
                Height = 8,
                Background = new SolidColorBrush(Color.FromArgb(40, 255, 255, 255))
            };
            scoreGrid.Children.Add(progressBorder);

            var progressFill = new Border
            {
                CornerRadius = new CornerRadius(4),
                Height = 8,
                Width = Math.Max(0, score * 5.5), // Scale to max width ~550
                HorizontalAlignment = HorizontalAlignment.Left,
                Background = new SolidColorBrush(score >= 80
                    ? Color.FromRgb(76, 175, 80)
                    : score >= 60
                        ? Color.FromRgb(255, 193, 7)
                        : Color.FromRgb(244, 67, 54))
            };
            scoreGrid.Children.Add(progressFill);

            stackPanel.Children.Add(scoreGrid);
        }

        // Message text
        var textBlock = new TextBlock
        {
            Text = msg.Text,
            TextWrapping = TextWrapping.Wrap,
            Foreground = msg.IsBot
                ? (Brush)Application.Current.Resources["TextPrimary"]
                : new SolidColorBrush(Colors.White),
            FontSize = 13.5
        };
        stackPanel.Children.Add(textBlock);

        // Action confirmation badge
        if (msg.IsBot && msg.ActionPerformed)
        {
            var actionBadge = new Border
            {
                CornerRadius = new CornerRadius(4),
                Background = new SolidColorBrush(Color.FromArgb(40, 76, 175, 80)),
                Padding = new Thickness(6, 2, 6, 2),
                Margin = new Thickness(0, 6, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Left
            };
            actionBadge.Child = new TextBlock
            {
                Text = "✓ Action completed",
                FontSize = 10,
                Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80))
            };
            stackPanel.Children.Add(actionBadge);
        }

        // Timestamp + source indicator
        var footerPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 4, 0, 0)
        };

        if (msg.IsBot)
        {
            var sourceText = new TextBlock
            {
                Text = _useAgent ? "⚡ Agent" : "💬 Local",
                FontSize = 9,
                Foreground = (Brush)Application.Current.Resources["TextSecondary"],
                Margin = new Thickness(0, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            footerPanel.Children.Add(sourceText);
        }

        var timeBlock = new TextBlock
        {
            Text = msg.Timestamp.ToLocalTime().ToString("HH:mm"),
            FontSize = 10,
            Foreground = msg.IsBot
                ? (Brush)Application.Current.Resources["TextSecondary"]
                : new SolidColorBrush(Color.FromArgb(180, 255, 255, 255))
        };
        footerPanel.Children.Add(timeBlock);
        stackPanel.Children.Add(footerPanel);

        border.Child = stackPanel;
        MessageList.Items.Add(border);
        ScrollToBottom();
    }

    private void ShowSuggestedActions(List<ChatSuggestedAction>? actions)
    {
        SuggestedActionsPanel.Children.Clear();

        if (actions == null || actions.Count == 0)
        {
            SuggestedActionsPanel.Visibility = Visibility.Collapsed;
            return;
        }

        foreach (var action in actions)
        {
            var btn = new Button
            {
                Content = action.Label,
                Tag = action.Command,
                Margin = new Thickness(4),
                Padding = new Thickness(10, 5, 10, 5),
                FontSize = 12,
                Cursor = System.Windows.Input.Cursors.Hand,
                Background = new SolidColorBrush(Color.FromArgb(30, 0, 120, 212)),
                Foreground = new SolidColorBrush(Color.FromRgb(100, 180, 255)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(60, 0, 120, 212)),
                BorderThickness = new Thickness(1)
            };
            btn.Click += SuggestedAction_Click;
            SuggestedActionsPanel.Children.Add(btn);
        }

        SuggestedActionsPanel.Visibility = Visibility.Visible;
    }

    private Border CreateTypingIndicator()
    {
        var stack = new StackPanel { Orientation = Orientation.Horizontal };
        stack.Children.Add(new TextBlock
        {
            Text = _useAgent ? "⚡ Agent thinking" : "🛡️ Analyzing",
            FontSize = 13,
            Foreground = (Brush)Application.Current.Resources["TextSecondary"],
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0)
        });
        stack.Children.Add(new ProgressBar
        {
            IsIndeterminate = true,
            Width = 80,
            Height = 6,
            VerticalAlignment = VerticalAlignment.Center
        });

        return new Border
        {
            Background = (Brush)Application.Current.Resources["CardBackground"],
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 10, 16, 10),
            HorizontalAlignment = HorizontalAlignment.Left,
            MaxWidth = 250,
            Margin = new Thickness(0, 0, 60, 8),
            Child = stack
        };
    }

    private void ScrollToBottom()
    {
        Dispatcher.InvokeAsync(() =>
        {
            ChatScroller.ScrollToEnd();
        });
    }
}
