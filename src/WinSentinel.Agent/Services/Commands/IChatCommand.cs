using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Represents a single chat command that the agent can execute.
/// Commands are auto-discovered and registered by the <see cref="CommandRouter"/>.
/// </summary>
public interface IChatCommand
{
    /// <summary>Exact trigger strings (lowercase) that route to this command.</summary>
    string[] Triggers { get; }

    /// <summary>
    /// Whether this command can handle the given input. Called after exact trigger
    /// matching fails, allowing prefix/regex/NLP matching.
    /// </summary>
    bool CanHandle(string input);

    /// <summary>Execute the command and return a chat response.</summary>
    Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context);
}
