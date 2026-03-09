using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Base class for audit modules that handles boilerplate:
/// AuditResult creation, timing, and error handling.
/// Subclasses only need to implement <see cref="ExecuteAuditAsync"/>.
/// </summary>
public abstract class AuditModuleBase : IAuditModule
{
    /// <inheritdoc/>
    public abstract string Name { get; }

    /// <inheritdoc/>
    public abstract string Category { get; }

    /// <inheritdoc/>
    public abstract string Description { get; }

    /// <summary>
    /// Template method: creates the result, times the execution,
    /// and catches exceptions so subclasses don't need to.
    /// </summary>
    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            await ExecuteAuditAsync(result, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;  // Don't swallow cancellation
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    /// <summary>
    /// Override this to perform the actual audit checks.
    /// The <paramref name="result"/> is pre-configured with Name, Category, and StartTime.
    /// Exceptions are caught by the base class and recorded in <see cref="AuditResult.Error"/>.
    /// </summary>
    protected abstract Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken);
}
