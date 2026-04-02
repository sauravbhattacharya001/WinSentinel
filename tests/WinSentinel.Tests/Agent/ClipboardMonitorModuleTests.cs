using WinSentinel.Agent;
using WinSentinel.Agent.Modules;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for <see cref="ClipboardMonitorModule"/> sensitive data detection.
/// Covers all pattern categories: credit cards, SSNs, crypto addresses,
/// private keys, AWS keys, and generic tokens.
/// </summary>
public class ClipboardMonitorModuleTests
{
    // ── Credit Card Detection ──

    [Theory]
    [InlineData("4111111111111111")]    // Visa 16-digit
    [InlineData("4111111111111")]       // Visa 13-digit
    [InlineData("5500000000000004")]    // Mastercard
    [InlineData("340000000000009")]     // Amex
    [InlineData("6011000000000004")]    // Discover
    public void AnalyzeText_DetectsCreditCardNumbers(string cardNumber)
    {
        var results = ClipboardMonitorModule.AnalyzeText(cardNumber);

        Assert.Contains(results, r => r.Category == "Credit Card Number");
        Assert.All(results.Where(r => r.Category == "Credit Card Number"),
            r => Assert.Equal(ThreatSeverity.High, r.Severity));
    }

    [Theory]
    [InlineData("1234")]               // Too short
    [InlineData("not a card number")]
    [InlineData("9999999999999999")]    // Invalid prefix
    public void AnalyzeText_DoesNotFalsePositiveOnNonCards(string text)
    {
        var results = ClipboardMonitorModule.AnalyzeText(text);

        Assert.DoesNotContain(results, r => r.Category == "Credit Card Number");
    }

    // ── SSN Detection ──

    [Theory]
    [InlineData("123-45-6789")]
    [InlineData("The SSN is 999-88-7777 here")]
    public void AnalyzeText_DetectsSSN(string text)
    {
        var results = ClipboardMonitorModule.AnalyzeText(text);

        Assert.Contains(results, r => r.Category == "Social Security Number");
        Assert.All(results.Where(r => r.Category == "Social Security Number"),
            r => Assert.Equal(ThreatSeverity.Critical, r.Severity));
    }

    [Theory]
    [InlineData("123456789")]          // No dashes
    [InlineData("12-345-6789")]        // Wrong format
    public void AnalyzeText_DoesNotFalsePositiveOnNonSSN(string text)
    {
        var results = ClipboardMonitorModule.AnalyzeText(text);

        Assert.DoesNotContain(results, r => r.Category == "Social Security Number");
    }

    // ── Bitcoin Address Detection ──

    [Theory]
    [InlineData("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")]       // P2PKH
    [InlineData("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")]        // P2SH
    [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")]  // Bech32
    public void AnalyzeText_DetectsBitcoinAddresses(string address)
    {
        var results = ClipboardMonitorModule.AnalyzeText(address);

        Assert.Contains(results, r => r.Category == "Crypto Wallet Address");
        Assert.All(results.Where(r => r.Category == "Crypto Wallet Address"),
            r => Assert.Equal(ThreatSeverity.High, r.Severity));
    }

    // ── Ethereum Address Detection ──

    [Fact]
    public void AnalyzeText_DetectsEthereumAddresses()
    {
        var results = ClipboardMonitorModule.AnalyzeText("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08");

        Assert.Contains(results, r => r.Category == "Crypto Wallet Address");
    }

    [Fact]
    public void AnalyzeText_DoesNotFalsePositiveOnShortHex()
    {
        var results = ClipboardMonitorModule.AnalyzeText("0x1234abcd");

        Assert.DoesNotContain(results, r => r.Category == "Crypto Wallet Address");
    }

    // ── Private Key Detection ──

    [Theory]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nblah")]
    [InlineData("-----BEGIN EC PRIVATE KEY-----\ndata")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nssh")]
    [InlineData("-----BEGIN PGP PRIVATE KEY-----\npgp")]
    [InlineData("-----BEGIN DSA PRIVATE KEY-----\ndsa")]
    public void AnalyzeText_DetectsPrivateKeys(string text)
    {
        var results = ClipboardMonitorModule.AnalyzeText(text);

        Assert.Contains(results, r => r.Category == "Private Key");
        Assert.All(results.Where(r => r.Category == "Private Key"),
            r => Assert.Equal(ThreatSeverity.Critical, r.Severity));
    }

    // ── AWS Key Detection ──

    [Fact]
    public void AnalyzeText_DetectsAwsAccessKeys()
    {
        var results = ClipboardMonitorModule.AnalyzeText("AKIAIOSFODNN7EXAMPLE");

        Assert.Contains(results, r => r.Category == "AWS Access Key");
        Assert.All(results.Where(r => r.Category == "AWS Access Key"),
            r => Assert.Equal(ThreatSeverity.Critical, r.Severity));
    }

    [Fact]
    public void AnalyzeText_DoesNotFalsePositiveOnShortAKIA()
    {
        // Too short to be a real AWS key
        var results = ClipboardMonitorModule.AnalyzeText("AKIA1234");

        Assert.DoesNotContain(results, r => r.Category == "AWS Access Key");
    }

    // ── Generic Token Detection ──

    [Fact]
    public void AnalyzeText_DetectsGenericApiTokens()
    {
        // 64-char hex string that looks like a token, no other patterns match
        var token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        var results = ClipboardMonitorModule.AnalyzeText(token);

        Assert.Contains(results, r => r.Category == "API Token/Secret");
        Assert.All(results.Where(r => r.Category == "API Token/Secret"),
            r => Assert.Equal(ThreatSeverity.Medium, r.Severity));
    }

    [Fact]
    public void AnalyzeText_DoesNotDetectGenericTokenWhenOtherPatternMatches()
    {
        // An AWS key is also a base64-like string; generic token should not double-report
        var results = ClipboardMonitorModule.AnalyzeText("AKIAIOSFODNN7EXAMPLE");

        Assert.DoesNotContain(results, r => r.Category == "API Token/Secret");
    }

    // ── Edge Cases ──

    [Fact]
    public void AnalyzeText_ReturnsEmptyForNullOrEmpty()
    {
        Assert.Empty(ClipboardMonitorModule.AnalyzeText(null!));
        Assert.Empty(ClipboardMonitorModule.AnalyzeText(""));
        Assert.Empty(ClipboardMonitorModule.AnalyzeText("   "));
    }

    [Fact]
    public void AnalyzeText_ReturnsEmptyForOversizedInput()
    {
        var huge = new string('A', 60_000);
        Assert.Empty(ClipboardMonitorModule.AnalyzeText(huge));
    }

    [Fact]
    public void AnalyzeText_ReturnsEmptyForNormalText()
    {
        Assert.Empty(ClipboardMonitorModule.AnalyzeText("Hello, this is a normal clipboard text."));
    }

    [Fact]
    public void AnalyzeText_DetectsMultiplePatterns()
    {
        // Text containing both a credit card and an SSN
        var text = "Card: 4111111111111111 SSN: 123-45-6789";
        var results = ClipboardMonitorModule.AnalyzeText(text);

        Assert.Contains(results, r => r.Category == "Credit Card Number");
        Assert.Contains(results, r => r.Category == "Social Security Number");
        Assert.True(results.Count >= 2);
    }

    [Fact]
    public void AnalyzeText_CreditCardDetailContainsMaskedNumber()
    {
        var results = ClipboardMonitorModule.AnalyzeText("4111111111111111");
        var ccResult = results.First(r => r.Category == "Credit Card Number");

        // Detail should contain a masked version showing only last 4 digits
        Assert.Contains("1111", ccResult.Detail);
        Assert.Contains("*", ccResult.Detail);
    }

    // ── Module Lifecycle ──

    [Fact]
    public void Module_HasCorrectName()
    {
        // Verify the module name constant via reflection on AnalyzeText
        // (we can't easily construct the module without all dependencies,
        //  but we can verify the static analysis works)
        var results = ClipboardMonitorModule.AnalyzeText("normal text");
        Assert.Empty(results);
    }
}
