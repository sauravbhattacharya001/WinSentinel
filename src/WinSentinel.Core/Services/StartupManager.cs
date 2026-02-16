using Microsoft.Win32;

namespace WinSentinel.Core.Services;

/// <summary>
/// Manages Windows startup registration for WinSentinel via registry Run key.
/// </summary>
public static class StartupManager
{
    private const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "WinSentinel";

    /// <summary>
    /// Check if WinSentinel is registered to start with Windows.
    /// </summary>
    public static bool IsRegistered()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, false);
            return key?.GetValue(AppName) != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Register WinSentinel to start with Windows.
    /// </summary>
    public static bool Register(string? exePath = null)
    {
        try
        {
            exePath ??= GetExecutablePath();
            if (string.IsNullOrEmpty(exePath)) return false;

            // Add --minimized flag so it starts in tray
            var command = $"\"{exePath}\" --minimized";

            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
            key?.SetValue(AppName, command, RegistryValueKind.String);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Unregister WinSentinel from Windows startup.
    /// </summary>
    public static bool Unregister()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
            if (key?.GetValue(AppName) != null)
            {
                key.DeleteValue(AppName, false);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Set startup registration based on the enabled flag.
    /// </summary>
    public static bool SetStartup(bool enabled, string? exePath = null)
    {
        return enabled ? Register(exePath) : Unregister();
    }

    private static string GetExecutablePath()
    {
        return Environment.ProcessPath ?? string.Empty;
    }
}
