using System.Management;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Helper for WMI queries.
/// </summary>
public static class WmiHelper
{
    /// <summary>
    /// Execute a WMI query and return results as a list of dictionaries.
    /// </summary>
    public static List<Dictionary<string, object?>> Query(string wql, string? scope = null)
    {
        var results = new List<Dictionary<string, object?>>();

        using var searcher = scope != null
            ? new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql))
            : new ManagementObjectSearcher(wql);

        foreach (var obj in searcher.Get())
        {
            var dict = new Dictionary<string, object?>();
            foreach (var prop in obj.Properties)
            {
                dict[prop.Name] = prop.Value;
            }
            results.Add(dict);
        }

        return results;
    }

    /// <summary>
    /// Get a single property from the first WMI result.
    /// </summary>
    public static T? GetProperty<T>(string wql, string propertyName, string? scope = null)
    {
        var results = Query(wql, scope);
        if (results.Count > 0 && results[0].TryGetValue(propertyName, out var value) && value is T typed)
        {
            return typed;
        }
        return default;
    }
}
