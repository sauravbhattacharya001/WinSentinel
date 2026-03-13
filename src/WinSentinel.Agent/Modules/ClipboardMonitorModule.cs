using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Modules;

/// <summary>
/// Clipboard security monitor that detects sensitive data patterns
/// (credit cards, SSNs, crypto wallet addresses, private keys, API tokens)
/// and can auto-clear the clipboard or alert the user.
/// Polls the clipboard at a configurable interval using Windows API.
/// </summary>
public partial class ClipboardMonitorModule : IAgentModule
{
    public string Name => "ClipboardMonitor";
    public bool IsActive { get; private set; }

    private readonly ILogger<ClipboardMonitorModule> _logger;
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;

    /// <summary>Last clipboard content hash to avoid duplicate alerts.</summary>
    private int _lastContentHash;

    /// <summary>How often to check the clipboard (ms).</summary>
    private const int PollIntervalMs = 2000;

    /// <summary>Auto-clear clipboard when sensitive data is detected.</summary>
    public bool AutoClearOnDetection { get; set; } = false;

    /// <summary>How long (seconds) before auto-clearing. 0 = immediate.</summary>
    public int AutoClearDelaySeconds { get; set; } = 30;

    public ClipboardMonitorModule(ILogger<ClipboardMonitorModule> logger, ThreatLog threatLog, AgentConfig config)
    {
        _logger = logger;
        _threatLog = threatLog;
        _config = config;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (IsActive) return Task.CompletedTask;
        if (!_config.IsModuleEnabled(Name)) return Task.CompletedTask;

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _monitorTask = Task.Run(() => MonitorLoop(_cts.Token), _cts.Token);
        IsActive = true;
        _logger.LogInformation("[ClipboardMonitor] Started — polling every {Interval}ms", PollIntervalMs);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (!IsActive) return;
        IsActive = false;
        _cts?.Cancel();
        if (_monitorTask != null)
        {
            try { await _monitorTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken); }
            catch (OperationCanceledException ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] ClipboardMonitorModule: {ex.GetType().Name} - {ex.Message}"); }
            catch (TimeoutException ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] ClipboardMonitorModule: {ex.GetType().Name} - {ex.Message}"); }
        }
        _cts?.Dispose();
        _logger.LogInformation("[ClipboardMonitor] Stopped");
    }

    private async Task MonitorLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollIntervalMs, ct);
                CheckClipboard();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ClipboardMonitor] Error checking clipboard");
            }
        }
    }

    private void CheckClipboard()
    {
        // Must run clipboard operations on STA thread
        string? text = null;
        var thread = new Thread(() =>
        {
            try
            {
                if (IsClipboardTextAvailable())
                    text = GetClipboardText();
            }
            catch { /* clipboard locked by another app */ }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(1000);

        if (string.IsNullOrWhiteSpace(text)) return;

        var hash = text.GetHashCode();
        if (hash == _lastContentHash) return;
        _lastContentHash = hash;

        var detections = AnalyzeText(text);
        if (detections.Count == 0) return;

        foreach (var (category, severity, detail) in detections)
        {
            var threat = new ThreatEvent
            {
                Source = Name,
                Severity = severity,
                Title = $"Sensitive data in clipboard: {category}",
                Description = detail,
                AutoFixable = true,
                FixCommand = "Clear-Clipboard"
            };
            _threatLog.Add(threat);
            _logger.LogWarning("[ClipboardMonitor] Detected {Category} in clipboard", category);
        }

        if (AutoClearOnDetection)
        {
            if (AutoClearDelaySeconds > 0)
            {
                var token = _cts?.Token ?? CancellationToken.None;
                var expectedHash = hash;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(AutoClearDelaySeconds * 1000, token);
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogDebug("[ClipboardMonitor] Delayed auto-clear cancelled (module stopped)");
                        return;
                    }
                    // Re-check: only clear if clipboard still has the same content
                    if (_lastContentHash != expectedHash)
                    {
                        _logger.LogDebug("[ClipboardMonitor] Skipped auto-clear — clipboard content changed");
                        return;
                    }
                    ClearClipboard();
                    _logger.LogInformation("[ClipboardMonitor] Auto-cleared clipboard after {Delay}s", AutoClearDelaySeconds);
                }, token);
            }
            else
            {
                ClearClipboard();
                _logger.LogInformation("[ClipboardMonitor] Auto-cleared clipboard immediately");
            }
        }
    }

    /// <summary>Analyze text for sensitive data patterns.</summary>
    internal static List<(string Category, ThreatSeverity Severity, string Detail)> AnalyzeText(string text)
    {
        var results = new List<(string, ThreatSeverity, string)>();
        if (string.IsNullOrEmpty(text) || text.Length > 50_000) return results;

        // Credit card numbers (Visa, Mastercard, Amex, Discover)
        if (CreditCardRegex().IsMatch(text))
        {
            var match = CreditCardRegex().Match(text);
            var masked = MaskSensitive(match.Value, 4);
            results.Add(("Credit Card Number", ThreatSeverity.High,
                $"Detected credit card number pattern: {masked}. " +
                "Storing card numbers in clipboard is a security risk."));
        }

        // SSN (US Social Security Number)
        if (SsnRegex().IsMatch(text))
        {
            results.Add(("Social Security Number", ThreatSeverity.Critical,
                "Detected SSN pattern (XXX-XX-XXXX). " +
                "SSNs in the clipboard can be captured by malware."));
        }

        // Bitcoin addresses
        if (BitcoinRegex().IsMatch(text))
        {
            var match = BitcoinRegex().Match(text);
            var masked = MaskSensitive(match.Value, 6);
            results.Add(("Crypto Wallet Address", ThreatSeverity.High,
                $"Detected Bitcoin address: {masked}. " +
                "Clipboard-hijacking malware can replace crypto addresses."));
        }

        // Ethereum addresses
        if (EthereumRegex().IsMatch(text))
        {
            var match = EthereumRegex().Match(text);
            var masked = MaskSensitive(match.Value, 6);
            results.Add(("Crypto Wallet Address", ThreatSeverity.High,
                $"Detected Ethereum address: {masked}. " +
                "Clipboard-hijacking malware can replace crypto addresses."));
        }

        // Private keys (generic patterns)
        if (PrivateKeyRegex().IsMatch(text))
        {
            results.Add(("Private Key", ThreatSeverity.Critical,
                "Detected private key material (PEM/SSH/PGP). " +
                "Private keys in clipboard are extremely dangerous — any app can read them."));
        }

        // AWS access keys
        if (AwsKeyRegex().IsMatch(text))
        {
            results.Add(("AWS Access Key", ThreatSeverity.Critical,
                "Detected AWS access key pattern. " +
                "Cloud credentials in clipboard can lead to account compromise."));
        }

        // Generic API keys / tokens (long hex or base64 strings that look like secrets)
        if (GenericTokenRegex().IsMatch(text) && !results.Any())
        {
            // Only flag if nothing else was detected (avoid noise)
            if (text.Length < 200) // Short clipboard content that looks like a bare token
            {
                results.Add(("API Token/Secret", ThreatSeverity.Medium,
                    "Detected what appears to be an API token or secret key. " +
                    "Consider using a password manager instead of clipboard for secrets."));
            }
        }

        // Passwords from password managers (heuristic: high entropy short strings)
        // Skip this — too many false positives

        return results;
    }

    private static string MaskSensitive(string value, int showLast)
    {
        if (value.Length <= showLast) return new string('*', value.Length);
        return new string('*', value.Length - showLast) + value[^showLast..];
    }

    // ── Regex patterns (source-generated for performance) ──

    [GeneratedRegex(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", RegexOptions.Compiled)]
    private static partial Regex CreditCardRegex();

    [GeneratedRegex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled)]
    private static partial Regex SsnRegex();

    [GeneratedRegex(@"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{25,39}\b", RegexOptions.Compiled)]
    private static partial Regex BitcoinRegex();

    [GeneratedRegex(@"\b0x[0-9a-fA-F]{40}\b", RegexOptions.Compiled)]
    private static partial Regex EthereumRegex();

    [GeneratedRegex(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", RegexOptions.Compiled)]
    private static partial Regex PrivateKeyRegex();

    [GeneratedRegex(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled)]
    private static partial Regex AwsKeyRegex();

    [GeneratedRegex(@"^[A-Za-z0-9+/=_\-]{32,128}$", RegexOptions.Compiled | RegexOptions.Multiline)]
    private static partial Regex GenericTokenRegex();

    // ── Windows clipboard API (P/Invoke) ──

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsClipboardFormatAvailable(uint format);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    private const uint CF_UNICODETEXT = 13;

    private static bool IsClipboardTextAvailable() => IsClipboardFormatAvailable(CF_UNICODETEXT);

    private static string? GetClipboardText()
    {
        if (!OpenClipboard(IntPtr.Zero)) return null;
        try
        {
            var hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == IntPtr.Zero) return null;
            var ptr = GlobalLock(hData);
            if (ptr == IntPtr.Zero) return null;
            try { return Marshal.PtrToStringUni(ptr); }
            finally { GlobalUnlock(hData); }
        }
        finally { CloseClipboard(); }
    }

    private static void ClearClipboard()
    {
        var thread = new Thread(() =>
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                EmptyClipboard();
                CloseClipboard();
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(1000);
    }
}
