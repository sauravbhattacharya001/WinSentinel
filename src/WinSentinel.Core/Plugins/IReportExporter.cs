using System.IO;
using System.Threading;
using System.Threading.Tasks;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// A plugin that knows how to serialize a <see cref="SecurityReport"/> into
/// some output format (PDF, DOCX, HTML, …). The Core ships JSON / Markdown
/// exporters directly; any exotic format is delivered as a signed plugin.
/// </summary>
public interface IReportExporter
{
    /// <summary>Short format token, e.g. <c>pdf</c>, <c>docx</c>, <c>html</c>. Case-insensitive.</summary>
    string Format { get; }

    /// <summary>
    /// Writes <paramref name="report"/> to <paramref name="output"/> in the
    /// plugin's native format. Must not close the stream.
    /// </summary>
    Task ExportAsync(SecurityReport report, Stream output, CancellationToken ct);
}
