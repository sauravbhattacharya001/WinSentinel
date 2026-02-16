using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using WinSentinel.App.ViewModels;

namespace WinSentinel.App.Views;

public partial class ChatPage : Page
{
    private readonly ChatViewModel _vm = new();

    public ChatPage()
    {
        InitializeComponent();

        // Display initial welcome message
        foreach (var msg in _vm.Messages)
        {
            AddMessageBubble(msg);
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

    private async Task SendMessageAsync()
    {
        var text = InputBox.Text?.Trim();
        if (string.IsNullOrEmpty(text)) return;

        // Add user bubble
        var userMsg = new ChatMessage { IsBot = false, Text = text };
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
            // Process through view model
            _vm.UserInput = text;
            await _vm.SendMessageCommand.ExecuteAsync(null);

            // Remove typing indicator
            MessageList.Items.Remove(typingBorder);

            // Get the last bot message
            var lastMsg = _vm.Messages.LastOrDefault(m => m.IsBot);
            if (lastMsg != null)
            {
                AddMessageBubble(lastMsg);
            }
        }
        catch (Exception ex)
        {
            MessageList.Items.Remove(typingBorder);
            AddMessageBubble(new ChatMessage { IsBot = true, Text = $"❌ Error: {ex.Message}" });
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
            Background = msg.IsBot
                ? (Brush)Application.Current.Resources["CardBackground"]
                : new SolidColorBrush(Color.FromArgb(255, 0, 120, 212)),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 10, 16, 10),
            MaxWidth = 600,
            HorizontalAlignment = msg.IsBot ? HorizontalAlignment.Left : HorizontalAlignment.Right,
            Margin = new Thickness(
                msg.IsBot ? 0 : 60, 0,
                msg.IsBot ? 60 : 0, 8)
        };

        var textBlock = new TextBlock
        {
            Text = msg.Text,
            TextWrapping = TextWrapping.Wrap,
            Foreground = msg.IsBot
                ? (Brush)Application.Current.Resources["TextPrimary"]
                : new SolidColorBrush(Colors.White)
        };

        border.Child = textBlock;
        MessageList.Items.Add(border);
        ScrollToBottom();
    }

    private Border CreateTypingIndicator()
    {
        return new Border
        {
            Background = (Brush)Application.Current.Resources["CardBackground"],
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 10, 16, 10),
            HorizontalAlignment = HorizontalAlignment.Left,
            MaxWidth = 200,
            Child = new ProgressBar
            {
                IsIndeterminate = true,
                Width = 100,
                Height = 8
            }
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
