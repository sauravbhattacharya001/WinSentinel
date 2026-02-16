namespace WinSentinel.Agent;

/// <summary>
/// Interface for agent modules that run continuously within the agent service.
/// Each module is a self-contained monitoring/scanning plugin.
/// </summary>
public interface IAgentModule
{
    /// <summary>Display name of the module.</summary>
    string Name { get; }

    /// <summary>Whether this module is currently active.</summary>
    bool IsActive { get; }

    /// <summary>Start the module's background work.</summary>
    Task StartAsync(CancellationToken cancellationToken);

    /// <summary>Stop the module gracefully.</summary>
    Task StopAsync(CancellationToken cancellationToken);
}
