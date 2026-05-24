using System.Threading;
using System.Threading.Tasks;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// A plugin that uploads a completed <see cref="SecurityReport"/> to a fleet
/// management backend (e.g. the WinSentinel Cloud Team tier endpoint).
/// </summary>
public interface IFleetSink
{
    Task UploadAsync(SecurityReport report, CancellationToken ct);
}
