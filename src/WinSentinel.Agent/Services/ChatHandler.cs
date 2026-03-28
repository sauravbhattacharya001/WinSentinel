using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Processes chat messages on the agent side by routing through a pipeline
/// of <see cref="IChatCommand"/> implementations via <see cref="CommandRouter"/>.
/// </summary>
/// <remarks>
/// Each command is a self-contained class in the <c>Commands/</c> directory.
/// To add a new command, implement <see cref="IChatCommand"/> and register it
/// in <see cref="BuildCommandPipeline"/>. No changes to this file are needed.
/// </remarks>
public sealed class ChatHandler
{
    private readonly ILogger<ChatHandler> _logger;
    private readonly IpcServer _ipcServer;
    private readonly CommandRouter _router;
    private readonly ChatContext _context;

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

        _context = new ChatContext
        {
            State = state,
            Config = config,
            Brain = brain,
            ThreatLog = threatLog,
            IpcServer = ipcServer
        };

        _router = new CommandRouter(BuildCommandPipeline(), logger);
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
        {
            return new ChatResponsePayload
            {
                Text = "Please type a message or command. Type **help** for available commands.",
                Category = ChatResponseCategory.General
            };
        }

        _logger.LogDebug("Chat message received: {Message}", input.Trim());

        try
        {
            var result = await _router.RouteAsync(input, _context);

            // Should always return something (FallbackCommand is last), but guard anyway.
            return result ?? new ChatResponsePayload
            {
                Text = "Something went wrong routing your command. Try `help`.",
                Category = ChatResponseCategory.Error
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing chat message: {Message}", input.Trim());
            return new ChatResponsePayload
            {
                Text = $"❌ Error processing command: {ex.Message}",
                Category = ChatResponseCategory.Error,
                SuggestedActions = { new SuggestedAction { Label = "📊 Status", Command = "status" } }
            };
        }
    }

    /// <summary>
    /// Build the ordered command pipeline. Order matters — first match wins.
    /// <see cref="FallbackCommand"/> must always be last.
    /// </summary>
    private static List<IChatCommand> BuildCommandPipeline() =>
    [
        // Exact commands
        new HelpCommand(),
        new StatusCommand(),
        new MonitorsCommand(),
        new ThreatsCommand(),

        // Info & summaries
        new InfoCommands(),

        // Parameterized commands (scan, fix, block, kill, quarantine)
        new ScanCommand(),
        new FixCommand(),
        new ActionCommands(),

        // Settings (undo, ignore, policy, risk, pause/resume, export)
        new SettingsCommands(),

        // Catch-all — must be last
        new FallbackCommand(),
    ];
}
