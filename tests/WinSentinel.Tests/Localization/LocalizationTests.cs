using System.Collections;
using System.Globalization;
using System.Resources;
using WinSentinel.Core.Localization;

namespace WinSentinel.Tests.Localization;

/// <summary>
/// Tests for the <see cref="L"/> resource helper and the shipped translation
/// satellites. These guard the localization "hooks" promised in LOCALIZATION.md:
/// the en-US strings load, an explicit culture override works, format args are
/// honoured, missing keys fail open, and - most importantly - the shipped
/// <c>es</c> satellite stays in lock-step with the English base so a translator
/// (or a future English string addition) can't silently leave gaps.
/// </summary>
[Trait("Category", "BVT")]
public class LocalizationTests
{
    private const string CoreBaseName = "WinSentinel.Core.Resources.Strings";
    private const string CliBaseName = "WinSentinel.Cli.Resources.CliStrings";

    private static readonly CultureInfo Spanish = new("es");
    private static readonly CultureInfo English = new("en-US");

    private static ResourceManager CoreManager() =>
        new(CoreBaseName, typeof(L).Assembly);

    private static ResourceManager CliManager() =>
        new(CliBaseName, typeof(WinSentinel.Cli.CliParser).Assembly);

    /// <summary>Enumerate the resource keys actually present for a culture (no parent fallback).</summary>
    private static HashSet<string> KeysFor(ResourceManager rm, CultureInfo culture)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        // tryParents:false => only the keys defined in THIS culture's resource set.
        // NOTE: do NOT dispose the returned set - the ResourceManager caches and
        // reuses it for later GetString() calls; disposing it here would close the
        // shared set and make subsequent lookups throw ObjectDisposedException.
        var set = rm.GetResourceSet(culture, createIfNotExists: true, tryParents: false)
                  ?? throw new InvalidOperationException($"No resource set for {culture.Name}");
        foreach (DictionaryEntry entry in set)
            keys.Add((string)entry.Key);
        return keys;
    }

    [Fact]
    public void Get_DefaultCulture_ReturnsEnglishValue()
    {
        Assert.Equal("Critical", L.Get(CultureInfo.InvariantCulture, "Severity_Critical"));
    }

    [Fact]
    public void Get_SpanishCulture_ReturnsTranslatedValue()
    {
        // End-to-end proof the es satellite assembly is embedded and resolvable.
        Assert.Equal("Cr\u00edtico", L.Get(Spanish, "Severity_Critical"));
        Assert.Equal("Advertencia", L.Get(Spanish, "Severity_Warning"));
    }

    [Fact]
    public void Get_WithFormatArgs_FormatsUsingTheCulture()
    {
        // {0} placeholder is filled; English template.
        var msg = L.Get(English, "Firewall_ProfileDisabled", "Public");
        Assert.Contains("Public", msg);
        Assert.StartsWith("Windows Firewall (Public profile) is disabled", msg);
    }

    [Fact]
    public void Get_SpanishWithFormatArgs_KeepsPlaceholderSubstitution()
    {
        var msg = L.Get(Spanish, "Firewall_ProfileDisabled", "Public");
        Assert.Contains("Public", msg);
        Assert.Contains("Firewall de Windows", msg);
    }

    [Fact]
    public void Get_MissingKey_FailsOpenToTheKey()
    {
        const string bogus = "This_Key_Does_Not_Exist_123";
        Assert.Equal(bogus, L.Get(English, bogus));
    }

    [Fact]
    public void TryGet_KnownKey_ReturnsTrue()
    {
        var ok = L.TryGet("Severity_Critical", out var value);
        Assert.True(ok);
        Assert.False(string.IsNullOrWhiteSpace(value));
    }

    [Fact]
    public void TryGet_MissingKey_ReturnsFalseAndEchoesKey()
    {
        const string bogus = "Definitely_Missing_Key";
        var ok = L.TryGet(bogus, out var value);
        Assert.False(ok);
        Assert.Equal(bogus, value);
    }

    [Fact]
    public void CultureOverride_IsHonouredByParameterlessGet()
    {
        var previous = L.Culture;
        try
        {
            L.Culture = Spanish;
            Assert.Equal("Cr\u00edtico", L.Get("Severity_Critical"));
        }
        finally
        {
            L.Culture = previous; // never leak culture into other tests
        }
    }

    [Fact]
    public void EnglishBase_HasNoEmptyValues()
    {
        var rm = CoreManager();
        foreach (var key in KeysFor(rm, CultureInfo.InvariantCulture))
        {
            var value = rm.GetString(key, CultureInfo.InvariantCulture);
            Assert.False(string.IsNullOrWhiteSpace(value), $"English value for '{key}' is empty.");
        }
    }

    [Fact]
    public void SpanishSatellite_CoversEveryEnglishKey()
    {
        // The core drift guard: every English (base/invariant) key MUST have a
        // Spanish translation. If a contributor adds an English string and
        // forgets the es entry, this test fails with the exact missing keys.
        var rm = CoreManager();
        var englishKeys = KeysFor(rm, CultureInfo.InvariantCulture);
        var spanishKeys = KeysFor(rm, Spanish);

        var missing = englishKeys.Except(spanishKeys).OrderBy(k => k, StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0,
            "Spanish (es) satellite is missing translations for: " + string.Join(", ", missing));
    }

    [Fact]
    public void SpanishSatellite_HasNoExtraOrEmptyKeys()
    {
        // No stray keys (typo'd names that would never resolve) and no blank values.
        var rm = CoreManager();
        var englishKeys = KeysFor(rm, CultureInfo.InvariantCulture);
        var spanishKeys = KeysFor(rm, Spanish);

        var extra = spanishKeys.Except(englishKeys).OrderBy(k => k, StringComparer.Ordinal).ToList();
        Assert.True(extra.Count == 0,
            "Spanish (es) satellite has keys with no English counterpart: " + string.Join(", ", extra));

        foreach (var key in spanishKeys)
        {
            var value = rm.GetString(key, Spanish);
            Assert.False(string.IsNullOrWhiteSpace(value), $"Spanish value for '{key}' is empty.");
        }
    }

    [Fact]
    public void SpanishSatellite_PreservesFormatPlaceholders()
    {
        // A translation must keep the same {0},{1},... placeholders as the English
        // template, otherwise string.Format throws or silently drops an argument.
        var rm = CoreManager();
        foreach (var key in KeysFor(rm, CultureInfo.InvariantCulture))
        {
            var en = rm.GetString(key, CultureInfo.InvariantCulture) ?? "";
            var es = rm.GetString(key, Spanish) ?? "";
            Assert.Equal(MaxPlaceholderIndex(en), MaxPlaceholderIndex(es));
        }
    }

    /// <summary>Highest <c>{N}</c> index referenced in a format string, or -1 if none.</summary>
    private static int MaxPlaceholderIndex(string template)
    {
        var max = -1;
        foreach (System.Text.RegularExpressions.Match m in
                 System.Text.RegularExpressions.Regex.Matches(template, "\\{(\\d+)\\}"))
        {
            if (int.TryParse(m.Groups[1].Value, out var n) && n > max)
                max = n;
        }
        return max;
    }

    // ---- CLI string table (WinSentinel.Cli.Resources.CliStrings) ----

    [Fact]
    public void CliStrings_SpanishSatellite_CoversEveryEnglishKey()
    {
        // Same drift guard as the core table, for the CLI user-facing strings.
        var rm = CliManager();
        var englishKeys = KeysFor(rm, CultureInfo.InvariantCulture);
        var spanishKeys = KeysFor(rm, Spanish);

        var missing = englishKeys.Except(spanishKeys).OrderBy(k => k, StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0,
            "CLI Spanish (es) satellite is missing translations for: " + string.Join(", ", missing));

        var extra = spanishKeys.Except(englishKeys).OrderBy(k => k, StringComparer.Ordinal).ToList();
        Assert.True(extra.Count == 0,
            "CLI Spanish (es) satellite has keys with no English counterpart: " + string.Join(", ", extra));
    }

    [Fact]
    public void CliStrings_SpanishSatellite_PreservesFormatPlaceholders()
    {
        var rm = CliManager();
        foreach (var key in KeysFor(rm, CultureInfo.InvariantCulture))
        {
            var en = rm.GetString(key, CultureInfo.InvariantCulture) ?? "";
            var es = rm.GetString(key, Spanish) ?? "";
            Assert.Equal(MaxPlaceholderIndex(en), MaxPlaceholderIndex(es));
        }
    }

    [Fact]
    public void CliStrings_SpanishSatellite_ResolvesAtRuntime()
    {
        var rm = CliManager();
        Assert.Equal("Auditor\u00eda completada.", rm.GetString("App_AuditComplete", Spanish));
    }
}
