using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Shared context passed to every command, giving access to agent services
/// without coupling commands to the DI container.
/// </summary>
public sealed class ChatContext
{
    public required ILogger Logger { get; init; }
    public required AgentState State { get; init; }
    public required AgentConfig Config { get; init; }
    public required AgentBrain Brain { get; init; }
    public required ThreatLog ThreatLog { get; init; }
    public required IpcServer IpcServer { get; init; }
}
