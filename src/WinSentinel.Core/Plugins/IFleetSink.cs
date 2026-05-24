using WinSentinel.Core.Models;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Team-tier plugin contract for pushing an audit report to a central
/// fleet collector (cloud or self-hosted).
/// </summary>
public interface IFleetSink
{
    /// <summary>
    /// Upload <paramref name="report"/> to the configured fleet endpoint.
    /// Implementations are responsible for auth, retry, and serialization.
    /// </summary>
    Task UploadAsync(SecurityReport report, CancellationToken ct);
}
