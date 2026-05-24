using System;
using System.IO;
using System.Text.Json;
using WinSentinel.Core.Licensing;

namespace WinSentinel.Cli;

/// <summary>
/// Handles the <c>winsentinel pro {status|activate|deactivate|start-trial|help}</c>
/// subcommand family. This is the user-facing surface for license management.
///
/// Output design: human-readable text by default, JSON when <c>--pro-format json</c>
/// is passed (CI/scripts). Exit codes:
/// <list type="bullet">
///   <item><c>0</c> \u2014 success, or status reports an active Pro / trial entitlement</item>
///   <item><c>1</c> \u2014 status reports no active entitlement (useful in CI gates)</item>
///   <item><c>2</c> \u2014 user error (bad key, missing arg, refused overwrite)</item>
/// </list>
/// </summary>
internal static class ProCommandHandler
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static int Handle(CliOptions options)
    {
        return options.ProAction switch
        {
            ProAction.Status => HandleStatus(options),
            ProAction.Activate => HandleActivate(options),
            ProAction.Deactivate => HandleDeactivate(options),
            ProAction.StartTrial => HandleStartTrial(options),
            ProAction.Help => HandleHelp(),
            _ => HandleHelp(),
        };
    }

    private static int HandleStatus(CliOptions options)
    {
        var status = LicenseManager.GetStatus(transientKey: options.TransientLicenseKey);

        if (string.Equals(options.ProFormat, "json", StringComparison.OrdinalIgnoreCase))
        {
            var payload = new
            {
                is_pro = status.IsPro,
                tier = status.Tier,
                state = status.State.ToString().ToLowerInvariant(),
                expires_at = status.ExpiresAt?.ToString("o"),
                days_remaining = status.DaysRemaining,
                key = status.Key,
                email = status.Email,
                message = status.Message,
                license_path = LicenseManager.DefaultLicensePath,
            };
            Console.WriteLine(JsonSerializer.Serialize(payload, JsonOpts));
            return status.IsPro ? 0 : 1;
        }

        Console.WriteLine();
        WriteBadge(status.IsPro ? "  PRO  " : " FREE ", status.IsPro ? ConsoleColor.Green : ConsoleColor.DarkGray);
        Console.WriteLine($"  Tier:       {status.Tier}");
        Console.WriteLine($"  State:      {status.State}");
        if (status.Key != null) Console.WriteLine($"  Key:        {status.Key}");
        if (status.Email != null) Console.WriteLine($"  Email:      {status.Email}");
        if (status.ExpiresAt is { } exp)
        {
            Console.WriteLine($"  Expires:    {exp:yyyy-MM-dd} ({status.DaysRemaining ?? 0} day(s) remaining)");
        }
        Console.WriteLine($"  License:    {LicenseManager.DefaultLicensePath}");
        Console.WriteLine();
        var original = Console.ForegroundColor;
        Console.ForegroundColor = status.IsPro ? ConsoleColor.Green : ConsoleColor.Yellow;
        Console.WriteLine("  " + status.Message);
        Console.ForegroundColor = original;
        Console.WriteLine();
        return status.IsPro ? 0 : 1;
    }

    private static int HandleActivate(CliOptions options)
    {
        var key = options.ProKey ?? options.TransientLicenseKey;
        if (string.IsNullOrWhiteSpace(key))
        {
            ConsoleFormatter.PrintError("`pro activate` requires a key. Usage: winsentinel pro activate WSP-XXXX-XXXX-XXXX");
            return 2;
        }

        if (!LicenseManager.TryNormalizeKey(key, out var normalized))
        {
            ConsoleFormatter.PrintError($"Invalid license key format: '{key}'. Expected WSP-XXXX-XXXX-XXXX (groups of 4 chars from 0-9 / A-Z without I,L,O,U).");
            return 2;
        }

        var tier = string.IsNullOrWhiteSpace(options.ProTier) ? "individual" : options.ProTier!;
        if (tier != "individual" && tier != "team")
        {
            ConsoleFormatter.PrintError($"Unknown tier '{tier}'. Use --pro-tier individual|team.");
            return 2;
        }

        // Default expiry: 1 year out (matches an annual purchase). The license server
        // will normally specify a different expiry in the signed envelope; this is the
        // local fallback for offline activations.
        var expiresAt = options.ProExpiresAt ?? DateTimeOffset.UtcNow.AddYears(1);
        var email = options.ProEmail ?? string.Empty;

        try
        {
            var record = LicenseManager.Activate(normalized, email, tier, expiresAt, options.ProEnvelope);
            var orig = Console.ForegroundColor;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  \u2713 License activated.");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"    Tier:    {record.Tier}");
            Console.WriteLine($"    Key:     {record.Key}");
            if (!string.IsNullOrEmpty(record.Email)) Console.WriteLine($"    Email:   {record.Email}");
            Console.WriteLine($"    Expires: {record.ExpiresAt:yyyy-MM-dd}");
            Console.WriteLine($"    Stored:  {LicenseManager.DefaultLicensePath}");
            if (record.Envelope == null)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine();
                Console.WriteLine("  Note: stored as offline-only (no signed envelope). The CLI will accept");
                Console.WriteLine("  this key until expiry. Pass --pro-envelope <file|json> to attach the");
                Console.WriteLine("  signed envelope from the license server for future refresh.");
            }
            Console.ForegroundColor = orig;
            Console.WriteLine();
            return 0;
        }
        catch (ArgumentException ex)
        {
            ConsoleFormatter.PrintError(ex.Message);
            return 2;
        }
    }

    private static int HandleDeactivate(CliOptions options)
    {
        var removed = LicenseManager.Deactivate();
        if (removed)
        {
            Console.WriteLine();
            Console.WriteLine("  License removed. You are back on the free tier.");
            Console.WriteLine();
            return 0;
        }
        Console.WriteLine();
        Console.WriteLine("  No license on this machine; nothing to deactivate.");
        Console.WriteLine();
        return 0;
    }

    private static int HandleStartTrial(CliOptions options)
    {
        try
        {
            var record = LicenseManager.StartTrial(options.ProEmail, force: options.Force);
            var orig = Console.ForegroundColor;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  \u2713 14-day Pro trial started.");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"    Expires: {record.ExpiresAt:yyyy-MM-dd}");
            Console.WriteLine($"    Stored:  {LicenseManager.DefaultLicensePath}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine();
            Console.WriteLine($"  Buy a license before expiry: {LicenseManager.UpgradeUrl}");
            Console.ForegroundColor = orig;
            Console.WriteLine();
            return 0;
        }
        catch (InvalidOperationException ex)
        {
            ConsoleFormatter.PrintError(ex.Message);
            Console.Error.WriteLine("  Re-run with --force to overwrite the existing license record.");
            return 2;
        }
    }

    private static int HandleHelp()
    {
        Console.WriteLine();
        Console.WriteLine("WinSentinel Pro \u2014 license management");
        Console.WriteLine();
        Console.WriteLine("USAGE");
        Console.WriteLine("  winsentinel pro [subcommand] [options]");
        Console.WriteLine();
        Console.WriteLine("SUBCOMMANDS");
        Console.WriteLine("  status                          Show current license / trial state (default)");
        Console.WriteLine("  activate <KEY>                  Persist a WSP-XXXX-XXXX-XXXX license key");
        Console.WriteLine("  deactivate                      Remove the persisted license");
        Console.WriteLine("  start-trial                     Start a 14-day local Pro trial");
        Console.WriteLine("  help                            Show this help");
        Console.WriteLine();
        Console.WriteLine("OPTIONS");
        Console.WriteLine("  --pro-email <addr>              Email to associate with the activation / trial");
        Console.WriteLine("  --pro-tier individual|team      Tier for `activate` (default: individual)");
        Console.WriteLine("  --pro-expires <ISO-8601>        Override expiry for `activate` (default: +1 year)");
        Console.WriteLine("  --pro-envelope <file|json>      Attach the signed wire envelope from the server");
        Console.WriteLine("  --pro-format text|json          Output format for `status` (default: text)");
        Console.WriteLine("  --force                         Overwrite an existing license on `start-trial`");
        Console.WriteLine();
        Console.WriteLine("GLOBAL");
        Console.WriteLine("  --license <KEY>                 Transient license override for this invocation");
        Console.WriteLine("                                  (works with ANY command; does NOT persist)");
        Console.WriteLine();
        Console.WriteLine("EXAMPLES");
        Console.WriteLine("  winsentinel pro status");
        Console.WriteLine("  winsentinel pro start-trial --pro-email me@example.com");
        Console.WriteLine("  winsentinel pro activate WSP-ABCD-EFGH-JKMN --pro-tier team --pro-email me@x.com");
        Console.WriteLine("  winsentinel --license WSP-ABCD-EFGH-JKMN --audit       # one-shot for CI");
        Console.WriteLine();
        Console.WriteLine($"Buy a license at {LicenseManager.UpgradeUrl}");
        Console.WriteLine();
        return 0;
    }

    private static void WriteBadge(string text, ConsoleColor bg)
    {
        var fg = Console.ForegroundColor;
        var bgOrig = Console.BackgroundColor;
        Console.BackgroundColor = bg;
        Console.ForegroundColor = bg == ConsoleColor.Green ? ConsoleColor.Black : ConsoleColor.White;
        Console.Write("  " + text + "  ");
        Console.BackgroundColor = bgOrig;
        Console.ForegroundColor = fg;
        Console.WriteLine();
    }
}
