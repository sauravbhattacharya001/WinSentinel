using WinSentinel.Core.Models;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Exports a <see cref="SecurityReport"/> to a stream in some format
/// (e.g. branded PDF, HTML, DOCX). Free core never implements this;
/// any concrete exporter ships as a signed Pro plugin.
/// </summary>
public interface IReportExporter
{
    /// <summary>
    /// Short format tag, e.g. <c>"pdf"</c>, <c>"html-branded"</c>.
    /// CLI surfaces this string when listing available exporters.
    /// </summary>
    string Format { get; }

    /// <summary>
    /// Serialize <paramref name="report"/> to <paramref name="output"/>.
    /// Implementations must not close the supplied stream.
    /// </summary>
    Task ExportAsync(SecurityReport report, Stream output, CancellationToken ct);
}
