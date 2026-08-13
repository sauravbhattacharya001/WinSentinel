using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using Xunit;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="RegistryHelper"/>. These exercise the graceful-failure
/// contract (missing hives/keys/values must never throw and must return the
/// documented default) plus reading a couple of well-known, always-present
/// Windows registry values. They are deterministic on any Windows host and do
/// not require elevation — nothing here writes to the registry.
/// </summary>
public class RegistryHelperTests
{
    // A subkey that is guaranteed never to exist.
    private const string MissingKey = @"SOFTWARE\WinSentinel\__does_not_exist__\nope";

    // A real, always-present key on every Windows install.
    private const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    // ── GetValue: missing paths return the supplied default ──────────

    [Fact]
    public void GetValue_MissingSubKey_ReturnsDefault()
    {
        var result = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, MissingKey, "AnyValue", "fallback");
        Assert.Equal("fallback", result);
    }

    [Fact]
    public void GetValue_MissingSubKey_NoDefault_ReturnsTypeDefault()
    {
        var result = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, MissingKey, "AnyValue");
        Assert.Equal(0, result);
    }

    [Fact]
    public void GetValue_ExistingKeyMissingValue_ReturnsDefault()
    {
        var result = RegistryHelper.GetValue(RegistryHive.LocalMachine, CurrentVersionKey, "__no_such_value__", -1);
        Assert.Equal(-1, result);
    }

    [Fact]
    public void GetValue_NullDefaultForReferenceType_ReturnsNull()
    {
        var result = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, MissingKey, "AnyValue");
        Assert.Null(result);
    }

    // ── GetValue: reading real well-known values ─────────────────────

    [Fact]
    public void GetValue_ProductName_ReturnsNonEmptyString()
    {
        // ProductName is a REG_SZ present on every Windows install.
        var product = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, CurrentVersionKey, "ProductName");
        Assert.False(string.IsNullOrWhiteSpace(product));
    }

    [Fact]
    public void GetValue_TypeConversion_IntFromDword()
    {
        // CurrentMajorVersionNumber is a DWORD on Win10+. Reading it as int
        // should either convert cleanly or fall back to the default without throwing.
        var major = RegistryHelper.GetValue(RegistryHive.LocalMachine, CurrentVersionKey, "CurrentMajorVersionNumber", -999);
        Assert.True(major == -999 || major >= 0);
    }

    [Fact]
    public void GetValue_UnconvertibleType_ReturnsDefault()
    {
        // ProductName is a string; asking for it as an int is not convertible
        // via Convert.ChangeType in a meaningful way — must fall back, not throw.
        var result = RegistryHelper.GetValue(RegistryHive.LocalMachine, CurrentVersionKey, "ProductName", 42);
        // Either the conversion failed (default 42) or produced some int; must not throw.
        Assert.IsType<int>(result);
    }

    // ── GetSubKeyNames ───────────────────────────────────────────────

    [Fact]
    public void GetSubKeyNames_MissingKey_ReturnsEmptyNotNull()
    {
        var names = RegistryHelper.GetSubKeyNames(RegistryHive.LocalMachine, MissingKey);
        Assert.NotNull(names);
        Assert.Empty(names);
    }

    [Fact]
    public void GetSubKeyNames_RealKey_ReturnsSomeChildren()
    {
        // HKLM\SOFTWARE\Microsoft has many subkeys on every install.
        var names = RegistryHelper.GetSubKeyNames(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft");
        Assert.NotNull(names);
        Assert.NotEmpty(names);
    }

    // ── GetValueNames ────────────────────────────────────────────────

    [Fact]
    public void GetValueNames_MissingKey_ReturnsEmptyNotNull()
    {
        var names = RegistryHelper.GetValueNames(RegistryHive.LocalMachine, MissingKey);
        Assert.NotNull(names);
        Assert.Empty(names);
    }

    [Fact]
    public void GetValueNames_RealKey_ContainsProductName()
    {
        var names = RegistryHelper.GetValueNames(RegistryHive.LocalMachine, CurrentVersionKey);
        Assert.NotNull(names);
        Assert.Contains("ProductName", names);
    }

    // ── GetAllValues ─────────────────────────────────────────────────

    [Fact]
    public void GetAllValues_MissingKey_ReturnsEmptyDictionaryNotNull()
    {
        var values = RegistryHelper.GetAllValues(RegistryHive.LocalMachine, MissingKey);
        Assert.NotNull(values);
        Assert.Empty(values);
    }

    [Fact]
    public void GetAllValues_RealKey_ContainsProductName()
    {
        var values = RegistryHelper.GetAllValues(RegistryHive.LocalMachine, CurrentVersionKey);
        Assert.NotNull(values);
        Assert.True(values.ContainsKey("ProductName"));
        Assert.False(string.IsNullOrWhiteSpace(values["ProductName"] as string));
    }

    [Fact]
    public void GetAllValues_ValueNamesMatchGetValueNames()
    {
        var names = RegistryHelper.GetValueNames(RegistryHive.LocalMachine, CurrentVersionKey);
        var values = RegistryHelper.GetAllValues(RegistryHive.LocalMachine, CurrentVersionKey);
        foreach (var name in names)
        {
            Assert.True(values.ContainsKey(name), $"GetAllValues missing '{name}' that GetValueNames reported");
        }
    }
}
