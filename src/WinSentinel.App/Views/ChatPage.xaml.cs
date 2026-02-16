using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using WinSentinel.App.ViewModels;
using Windows.System;
using Windows.UI;

namespace WinSentinel.App.Views;

public sealed partial class ChatPage : Page
{
    private readonly ChatViewModel _vm = new();

    public ChatPage()
    {
        this.InitializeComponent();

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

    private async void InputBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
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
            InputBox.Focus(FocusState.Programmatic);
        }
    }

    private void AddMessageBubble(ChatMessage msg)
    {
        var border = new Border
        {
            Background = msg.IsBot
                ? (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"]
                : new SolidColorBrush(Color.FromArgb(255, 0, 120, 212)),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 10, 16, 10),
            MaxWidth = 600,
            HorizontalAlignment = msg.IsBot ? HorizontalAlignment.Left : HorizontalAlignment.Right,
            Margin = new Thickness(
                msg.IsBot ? 0 : 60, 0,
                msg.IsBot ? 60 : 0, 0)
        };

        var textBlock = new TextBlock
        {
            Text = msg.Text,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
            Foreground = msg.IsBot
                ? (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"]
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
            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 10, 16, 10),
            HorizontalAlignment = HorizontalAlignment.Left,
            MaxWidth = 200,
            Child = new ProgressRing
            {
                IsActive = true,
                Width = 20,
                Height = 20
            }
        };
    }

    private void ScrollToBottom()
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ChatScroller.ChangeView(null, ChatScroller.ScrollableHeight, null);
        });
    }
}
