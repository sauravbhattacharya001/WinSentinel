using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Processes chat messages on the agent side with full context access.
/// Routes messages to individual <see cref="IChatCommand"/> implementations
/// via <see cref="CommandRouter"/>.
/// </summary>
public sealed class ChatHandler
{
    private readonly ILogger<ChatHandler> _logger;
    private readonly IpcServer _ipcServer;
    private readonly CommandRouter _router;
    private readonly ChatContext _chatContext;

    public ChatHandler(
        ILogger<ChatHandler> logger,
        AgentState state,
        AgentConfig config,
        AgentBrain brain,
        ThreatLog threatLog,
        IpcServer ipcServer)
    {
        _logger = logger;
        _ipcServer = ipcServer;

        _chatContext = new ChatContext
        {
            Logger = logger,
            State = state,
            Config = config,
            Brain = brain,
            ThreatLog = threatLog,
            IpcServer = ipcServer
        };

        // Register all commands. Order matters for CanHandle fallthrough —
        // more specific commands should appear before broader matchers.
        var commands = new IChatCommand[]
        {
            new HelpCommand(),
            new StatusCommand(),
            new MonitorsCommand(),
            new ThreatsCommand(),
            new TodaySummaryCommand(),
            new HistoryCommand(),
            new ScanCommand(),
            new FixCommand(),
            new BlockIpCommand(),
            new KillProcessCommand(),
            new QuarantineCommand(),
            new UndoCommand(),
            new IgnoreCommand(),
            new PolicyCommand(),
            new SetRiskCommand(),
            new MonitoringToggleCommand(),
            new ExportCommand(),
            new ExplainActionCommand(),
            new WhileAwayCommand(),
        };

        _router = new CommandRouter(commands, new FallbackCommand());
    }

    /// <summary>Wire up the IPC server's chat event.</summary>
    public void Initialize()
    {
        _ipcServer.ChatMessageReceived += HandleChatMessageAsync;
        _logger.LogInformation("ChatHandler initialized — agent chat is live");
    }

    /// <summary>Disconnect from IPC events.</summary>
    public void Shutdown()
    {
        _ipcServer.ChatMessageReceived -= HandleChatMessageAsync;
    }

    /// <summary>Process a chat message and return a rich response.</summary>
    public async Task<ChatResponsePayload> HandleChatMessageAsync(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return new ChatResponsePayload
            {
                Text = "Please type a message or command. Type **help** for available commands.",
                Category = ChatResponseCategory.General
            };

        var trimmed = input.Trim();
        _logger.LogDebug("Chat message received: {Message}", trimmed);

        try
        {
            var command = _router.Route(trimmed);
            return await command.ExecuteAsync(trimmed, _chatContext);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing chat message: {Message}", trimmed);
            return new ChatResponsePayload
            {
                Text = $"❌ Error processing command: {ex.Message}",
                Category = ChatResponseCategory.Error,
                SuggestedActions = { new SuggestedAction { Label = "📊 Status", Command = "status" } }
            };
        }
    }
}
