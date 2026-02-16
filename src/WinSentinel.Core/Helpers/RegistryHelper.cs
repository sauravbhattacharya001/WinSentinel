using Microsoft.Win32;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Helper for Windows Registry operations.
/// </summary>
public static class RegistryHelper
{
    /// <summary>
    /// Read a registry value, returning default if not found.
    /// </summary>
    public static T? GetValue<T>(RegistryHive hive, string subKey, string valueName, T? defaultValue = default)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey);
            if (key == null) return defaultValue;

            var value = key.GetValue(valueName);
            if (value is T typed)
                return typed;

            // Try conversion
            if (value != null)
            {
                try
                {
                    return (T)Convert.ChangeType(value, typeof(T));
                }
                catch
                {
                    return defaultValue;
                }
            }

            return defaultValue;
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Enumerate sub-key names under a given registry path.
    /// </summary>
    public static string[] GetSubKeyNames(RegistryHive hive, string subKey)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey);
            return key?.GetSubKeyNames() ?? [];
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Enumerate value names under a given registry path.
    /// </summary>
    public static string[] GetValueNames(RegistryHive hive, string subKey)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey);
            return key?.GetValueNames() ?? [];
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Get all values under a registry key as name-value pairs.
    /// </summary>
    public static Dictionary<string, object?> GetAllValues(RegistryHive hive, string subKey)
    {
        var result = new Dictionary<string, object?>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey);
            if (key == null) return result;

            foreach (var name in key.GetValueNames())
            {
                result[name] = key.GetValue(name);
            }
        }
        catch { }
        return result;
    }
}
