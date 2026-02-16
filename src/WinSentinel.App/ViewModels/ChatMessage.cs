using CommunityToolkit.Mvvm.ComponentModel;

namespace WinSentinel.App.ViewModels;

/// <summary>
/// Represents a single chat message.
/// </summary>
public partial class ChatMessage : ObservableObject
{
    [ObservableProperty]
    private string _content = string.Empty;

    [ObservableProperty]
    private bool _isUser;

    [ObservableProperty]
    private DateTime _timestamp = DateTime.Now;

    [ObservableProperty]
    private bool _isLoading;

    public string TimestampText => Timestamp.ToString("h:mm tt");
}
