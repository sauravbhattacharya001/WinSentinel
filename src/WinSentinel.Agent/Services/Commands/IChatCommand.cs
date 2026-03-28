using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// A self-contained chat command that knows its own triggers and how to execute.
/// Implementations are auto-discovered by <see cref="CommandRouter"/>.
/// </summary>
public interface IChatCommand
{
    /// <summary>
    /// Attempt to handle the given input. Returns null if this command doesn't match.
    /// </summary>
    Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context);
}
