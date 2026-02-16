using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Interface for all security audit modules.
/// </summary>
public interface IAuditModule
{
    /// <summary>
    /// Human-readable name of this audit module.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Category for grouping (e.g., "Network", "System", "Accounts").
    /// </summary>
    string Category { get; }

    /// <summary>
    /// Execute the security audit and return results.
    /// </summary>
    Task<AuditResult> RunAuditAsync(CancellationToken ct = default);
}
