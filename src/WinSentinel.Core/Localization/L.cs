using System.Globalization;
using System.Resources;

namespace WinSentinel.Core.Localization;

/// <summary>
/// Localization helper — provides typed access to resource strings with format-arg support.
/// <para>
/// Usage:
/// <code>
/// var msg = L.Get("Firewall_ProfileDisabled", "Public");
/// // → "Windows Firewall (Public profile) is disabled. ..."
/// </code>
/// </para>
/// <para>
/// Override culture via <see cref="Culture"/> for testing or explicit language selection.
/// Defaults to <see cref="CultureInfo.CurrentUICulture"/>.
/// </para>
/// </summary>
public static class L
{
    private static readonly ResourceManager s_rm =
        new("WinSentinel.Core.Resources.Strings", typeof(L).Assembly);

    /// <summary>
    /// Override the culture used for string lookups.
    /// When null, <see cref="CultureInfo.CurrentUICulture"/> is used.
    /// </summary>
    public static CultureInfo? Culture { get; set; }

    /// <summary>
    /// Get a localized string by resource key, optionally formatted with arguments.
    /// Returns the key itself if the resource is not found (fail-open for missing translations).
    /// </summary>
    public static string Get(string key, params object[] args)
    {
        var culture = Culture ?? CultureInfo.CurrentUICulture;
        var value = s_rm.GetString(key, culture);

        if (value == null)
            return key; // Fail-open: show the key rather than crash

        return args.Length > 0
            ? string.Format(culture, value, args)
            : value;
    }

    /// <summary>
    /// Try to get a localized string. Returns false if the key doesn't exist.
    /// </summary>
    public static bool TryGet(string key, out string value, params object[] args)
    {
        var culture = Culture ?? CultureInfo.CurrentUICulture;
        var raw = s_rm.GetString(key, culture);

        if (raw == null)
        {
            value = key;
            return false;
        }

        value = args.Length > 0
            ? string.Format(culture, raw, args)
            : raw;
        return true;
    }
}
