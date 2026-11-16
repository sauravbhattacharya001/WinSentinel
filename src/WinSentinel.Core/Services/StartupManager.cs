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
    /// Returns false unless the value was verified written: a previous
    /// version returned true when <c>OpenSubKey</c> yielded null
    /// (<c>key?.SetValue</c> no-ops), reporting success for a registration
    /// that never landed — the read-back assert in the tests then failed
    /// instead. Opening the Run key can also fail transiently while the
    /// registry is under load, so retry briefly before giving up.
    /// </summary>
    public static bool Register(string? exePath = null)
    {
        exePath ??= GetExecutablePath();
        if (string.IsNullOrEmpty(exePath)) return false;

        // Add --minimized flag so it starts in tray
        var command = $"\"{exePath}\" --minimized";

        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
                if (key == null)
                {
                    Thread.Sleep(50);
                    continue;
                }

                key.SetValue(AppName, command, RegistryValueKind.String);
                return key.GetValue(AppName) is string written && written == command;
            }
            catch (IOException)
            {
                // Transient registry contention — retry.
                Thread.Sleep(50);
            }
            catch
            {
                return false;
            }
        }

        return false;
    }

    /// <summary>
    /// Unregister WinSentinel from Windows startup.
    /// Returns false unless the value was verified gone (same transient-open
    /// retry and read-back verification as <see cref="Register"/>).
    /// </summary>
    public static bool Unregister()
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
                if (key == null)
                {
                    Thread.Sleep(50);
                    continue;
                }

                if (key.GetValue(AppName) != null)
                {
                    key.DeleteValue(AppName, false);
                }

                return key.GetValue(AppName) == null;
            }
            catch (IOException)
            {
                // Transient registry contention — retry.
                Thread.Sleep(50);
            }
            catch
            {
                return false;
            }
        }

        return false;
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
