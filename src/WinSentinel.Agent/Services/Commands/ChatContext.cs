using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Shared context passed to every chat command, providing access to
/// agent state, configuration, and services needed for command execution.
/// </summary>
public sealed class ChatContext
{
    public required AgentState State { get; init; }
    public required AgentConfig Config { get; init; }
    public required AgentBrain Brain { get; init; }
    public required ThreatLog ThreatLog { get; init; }
    public required IpcServer IpcServer { get; init; }
}
