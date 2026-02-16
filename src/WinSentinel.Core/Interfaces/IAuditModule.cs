using WinSentinel.Core.Models;

namespace WinSentinel.Core.Interfaces;

/// <summary>
/// Interface for all security audit modules.
/// </summary>
public interface IAuditModule
{
    /// <summary>Module display name.</summary>
    string Name { get; }

    /// <summary>Module category (e.g., "Firewall", "Network").</summary>
    string Category { get; }

    /// <summary>Brief description of what this module checks.</summary>
    string Description { get; }

    /// <summary>Run the audit and return results.</summary>
    Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default);
}
