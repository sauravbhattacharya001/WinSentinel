using System.Management;
using System.Runtime.Versioning;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Helper for executing WMI (Windows Management Instrumentation) queries.
/// All methods are safe to call on non-Windows targets (they short-circuit to empty results
/// at runtime via <see cref="OperatingSystem.IsWindows"/>), but compile-time the type is
/// marked as Windows-only so callers in cross-platform projects get the right diagnostic.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="ManagementObjectSearcher"/>, <see cref="ManagementObjectCollection"/>, and
/// every <see cref="ManagementBaseObject"/> returned by an enumeration are <see cref="IDisposable"/>
/// and must be disposed individually — otherwise the underlying WMI COM proxies and their
/// IWbemServices handles leak until process exit. This helper handles that disposal correctly
/// in all code paths, including when an exception or cancellation interrupts the enumeration.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class WmiHelper
{
    /// <summary>
    /// Execute a WMI query and materialize the entire result set as a list of property dictionaries.
    /// </summary>
    /// <param name="wql">The WQL query string. Must be non-empty.</param>
    /// <param name="scope">
    /// Optional WMI namespace path (e.g. <c>\\.\root\CIMV2</c> or
    /// <c>\\.\root\Microsoft\Windows\Storage</c>). When <see langword="null"/> the default
    /// namespace (<c>root\CIMV2</c>) is used.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token observed between rows. Cancellation interrupts the enumeration and
    /// throws <see cref="OperationCanceledException"/>; resources are still disposed.
    /// </param>
    /// <returns>
    /// A list of dictionaries — one per WMI instance — mapping property name to property value.
    /// Returns an empty list when not running on Windows.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="wql"/> is null or whitespace.</exception>
    /// <exception cref="OperationCanceledException">Thrown when <paramref name="cancellationToken"/> is cancelled.</exception>
    public static List<Dictionary<string, object?>> Query(
        string wql,
        string? scope = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(wql))
            throw new ArgumentException("WQL query must be non-empty.", nameof(wql));

        var results = new List<Dictionary<string, object?>>();
        if (!OperatingSystem.IsWindows())
            return results;

        foreach (var row in QueryStream(wql, scope, cancellationToken))
            results.Add(row);

        return results;
    }

    /// <summary>
    /// Execute a WMI query and stream rows lazily as property dictionaries.
    /// </summary>
    /// <remarks>
    /// Use this overload when the result set may be large (e.g. process or event-log enumerations).
    /// Each underlying <see cref="ManagementBaseObject"/> is disposed immediately after the
    /// dictionary copy is yielded; the searcher and collection are disposed when the enumerator
    /// is disposed (i.e. at the end of the <c>foreach</c> or on early break/exception).
    /// </remarks>
    /// <param name="wql">The WQL query string. Must be non-empty.</param>
    /// <param name="scope">Optional WMI namespace path.</param>
    /// <param name="cancellationToken">Cancellation token observed between rows.</param>
    /// <returns>An <see cref="IEnumerable{T}"/> of property dictionaries.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="wql"/> is null or whitespace.</exception>
    public static IEnumerable<Dictionary<string, object?>> QueryStream(
        string wql,
        string? scope = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(wql))
            throw new ArgumentException("WQL query must be non-empty.", nameof(wql));

        if (!OperatingSystem.IsWindows())
            yield break;

        using var searcher = scope != null
            ? new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql))
            : new ManagementObjectSearcher(wql);

        using var collection = searcher.Get();

        foreach (ManagementBaseObject obj in collection)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (var prop in obj.Properties)
                {
                    dict[prop.Name] = prop.Value;
                }
                yield return dict;
            }
            finally
            {
                obj.Dispose();
            }
        }
    }

    /// <summary>
    /// Get a single property from the first WMI result.
    /// </summary>
    /// <typeparam name="T">Expected property CLR type.</typeparam>
    /// <param name="wql">The WQL query string.</param>
    /// <param name="propertyName">Name of the property to extract from the first instance.</param>
    /// <param name="scope">Optional WMI namespace path.</param>
    /// <returns>
    /// The typed property value, or <see langword="default"/> when there are no results,
    /// the property is missing, the value is <see langword="null"/>, or the value cannot be
    /// converted to <typeparamref name="T"/>.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="wql"/> or <paramref name="propertyName"/> is null or whitespace.</exception>
    public static T? GetProperty<T>(string wql, string propertyName, string? scope = null)
    {
        if (string.IsNullOrWhiteSpace(propertyName))
            throw new ArgumentException("Property name must be non-empty.", nameof(propertyName));

        // Enumerate the stream and stop after the first row to avoid materializing the whole set.
        foreach (var row in QueryStream(wql, scope))
        {
            if (!row.TryGetValue(propertyName, out var value) || value is null)
                return default;

            if (value is T typed)
                return typed;

            // Best-effort conversion (e.g. WMI returns UInt32 but caller asked for int/long).
            try
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch (Exception ex) when (ex is InvalidCastException or FormatException or OverflowException)
            {
                return default;
            }
        }

        return default;
    }
}
