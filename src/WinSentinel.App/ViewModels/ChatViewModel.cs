using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using WinSentinel.App.Services;

namespace WinSentinel.App.ViewModels;

/// <summary>
/// ViewModel for the chat control plane page. Manages user input, message history,
/// and communication with the agent via <see cref="ChatAiService"/>.
/// </summary>
public partial class ChatViewModel : ObservableObject
{
    private readonly ChatAiService _aiService = new();

    [ObservableProperty]
    private string _userInput = "";

    [ObservableProperty]
    private bool _isBusy;

    public ObservableCollection<ChatMessage> Messages { get; } = new();

    public ChatViewModel()
    {
        Messages.Add(new ChatMessage
        {
            IsBot = true,
            Text = "👋 Hi! I'm WinSentinel, your Windows security advisor.\n\n" +
                   "**Commands:**\n" +
                   "  /scan — Run a full security audit\n" +
                   "  /score — Check your security score\n" +
                   "  /fix <issue> — Fix a specific finding\n" +
                   "  /fixall — Fix all warnings & critical issues\n" +
                   "  /history — View scan history\n" +
                   "  /help — See all commands\n\n" +
                   "Or just ask me anything about Windows security!"
        });
    }

    [RelayCommand]
    private async Task SendMessageAsync()
    {
        var input = UserInput?.Trim();
        if (string.IsNullOrEmpty(input)) return;

        // Add user message
        Messages.Add(new ChatMessage { IsBot = false, Text = input });
        UserInput = "";
        IsBusy = true;

        try
        {
            var response = await _aiService.GetResponseAsync(input);
            Messages.Add(new ChatMessage { IsBot = true, Text = response });
        }
        catch (Exception ex)
        {
            Messages.Add(new ChatMessage { IsBot = true, Text = $"❌ Error: {ex.Message}" });
        }
        finally
        {
            IsBusy = false;
        }
    }
}
