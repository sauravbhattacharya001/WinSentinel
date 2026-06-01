using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Handles the <c>winsentinel why &lt;finding&gt;</c> command.
/// Explains a specific finding in detail: what it is, why it matters,
/// how to fix it, and which compliance frameworks it maps to.
/// </summary>
internal static class WhyCommandHandler
{
    public static async Task<int> HandleAsync(CliOptions options)
    {
        var query = options.WhyQuery;
        if (string.IsNullOrWhiteSpace(query))
        {
            ConsoleFormatter.PrintError("Usage: winsentinel why <finding-title-or-keyword>");
            ConsoleFormatter.PrintError("Example: winsentinel why \"BitLocker\"");
            ConsoleFormatter.PrintError("Example: winsentinel why UAC");
            return 3;
        }

        if (!options.Quiet)
            ConsoleFormatter.PrintBanner();

        // Run audit to get current findings
        var auditEngine = new AuditEngine();
        var report = await auditEngine.RunFullAuditAsync();

        // Collect all findings from all modules
        var allFindings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Module: m.ModuleName, Finding: f)))
            .ToList();

        // Search by title (case-insensitive contains)
        var matches = allFindings
            .Where(x => x.Finding.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
                     || x.Finding.Category.Contains(query, StringComparison.OrdinalIgnoreCase)
                     || (x.Finding.Description?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
            .ToList();

        if (matches.Count == 0)
        {
            ConsoleFormatter.PrintError($"No findings matched \"{query}\". Try a broader keyword.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Tip: Use part of a finding title, e.g.:");
            Console.WriteLine("    winsentinel why BitLocker");
            Console.WriteLine("    winsentinel why \"Firewall disabled\"");
            Console.WriteLine("    winsentinel why SMB");
            Console.ResetColor();
            return 1;
        }

        if (options.Json)
        {
            var jsonResults = matches.Select(m => new
            {
                title = m.Finding.Title,
                severity = m.Finding.Severity.ToString(),
                category = m.Finding.Category,
                module = m.Module,
                description = m.Finding.Description,
                whyItMatters = GetWhyItMatters(m.Finding),
                remediation = m.Finding.Remediation,
                fixCommand = m.Finding.FixCommand,
                compliance = GetComplianceMapping(m.Finding),
                riskIfIgnored = GetRiskIfIgnored(m.Finding)
            });
            var jsonOpts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() },
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
            var json = JsonSerializer.Serialize(jsonResults, jsonOpts);
            OutputHelper.WriteOutput(json, options.OutputFile);
            return 0;
        }

        // If multiple matches, show all with detail
        if (matches.Count > 1 && !options.Quiet)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  Found {matches.Count} matching findings for \"{query}\":");
            Console.ResetColor();
            Console.WriteLine();
        }

        foreach (var (module, finding) in matches)
        {
            PrintFindingExplanation(module, finding);
        }

        return 0;
    }

    private static void PrintFindingExplanation(string module, Finding finding)
    {
        // Header
        var sevColor = finding.Severity switch
        {
            Severity.Critical => ConsoleColor.Red,
            Severity.Warning => ConsoleColor.Yellow,
            Severity.Info => ConsoleColor.Cyan,
            _ => ConsoleColor.Green
        };

        Console.ForegroundColor = sevColor;
        Console.Write($"  [{finding.Severity.ToString().ToUpperInvariant()}] ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(finding.Title);
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Module: {module} | Category: {finding.Category}");
        Console.ResetColor();
        Console.WriteLine();

        // What is it
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  📋 What:");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"     {finding.Description}");
        Console.ResetColor();
        Console.WriteLine();

        // Why it matters
        var why = GetWhyItMatters(finding);
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ⚠️  Why it matters:");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"     {why}");
        Console.ResetColor();
        Console.WriteLine();

        // Risk if ignored
        var risk = GetRiskIfIgnored(finding);
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  🎯 Risk if ignored:");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"     {risk}");
        Console.ResetColor();
        Console.WriteLine();

        // How to fix
        if (!string.IsNullOrEmpty(finding.Remediation))
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  🔧 How to fix:");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"     {finding.Remediation}");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Fix command
        if (!string.IsNullOrEmpty(finding.FixCommand))
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  💻 Auto-fix command:");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"     {finding.FixCommand}");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("     (Run with: winsentinel --fix-all --modules <module>)");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Compliance mapping
        var compliance = GetComplianceMapping(finding);
        if (compliance.Length > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  📜 Compliance:");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Gray;
            foreach (var c in compliance)
            {
                Console.WriteLine($"     • {c}");
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        // Separator
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  " + new string('─', 60));
        Console.ResetColor();
        Console.WriteLine();
    }

    private static string GetWhyItMatters(Finding finding)
    {
        // Generate contextual explanation based on severity and category
        var category = finding.Category.ToLowerInvariant();
        var severity = finding.Severity;

        if (severity == Severity.Critical)
            return "This is a critical security gap that could be actively exploited. " +
                   "An attacker on your network (or malware that lands on this machine) can leverage this misconfiguration immediately.";

        if (severity == Severity.Warning)
            return "This weakens your security posture and increases the attack surface. " +
                   "While not immediately exploitable in isolation, it's a common link in attack chains.";

        if (severity == Severity.Info)
            return "This is a best-practice recommendation. Not fixing it won't cause immediate harm, " +
                   "but hardening this improves your overall defense-in-depth.";

        return "This check passed — your configuration meets the recommended baseline for this control.";
    }

    private static string GetRiskIfIgnored(Finding finding)
    {
        var title = finding.Title.ToLowerInvariant();
        var category = finding.Category.ToLowerInvariant();

        // Provide specific risk context based on common finding patterns
        if (title.Contains("bitlocker") || title.Contains("encryption"))
            return "Physical theft of this device exposes all data. A stolen laptop with no disk encryption = full data breach.";

        if (title.Contains("firewall") && title.Contains("disabled"))
            return "The machine accepts inbound connections from any source. Worms, lateral movement, and reconnaissance scans all succeed.";

        if (title.Contains("uac") || title.Contains("user account control"))
            return "Any program can silently elevate to admin. Malware doesn't need an exploit — it just runs.";

        if (title.Contains("smb") && title.Contains("v1"))
            return "SMBv1 is the protocol vector for WannaCry and EternalBlue. Known exploits exist in the wild.";

        if (title.Contains("rdp") || title.Contains("remote desktop"))
            return "Exposed RDP is the #1 ransomware entry point. Brute-force attacks against RDP run 24/7 on the internet.";

        if (title.Contains("defender") && (title.Contains("disabled") || title.Contains("off")))
            return "Real-time malware protection is gone. Downloaded malware executes without intervention.";

        if (title.Contains("update") || title.Contains("patch"))
            return "Unpatched systems have known CVEs with public exploits. Attackers scan for these automatically.";

        if (title.Contains("admin") || title.Contains("account"))
            return "Unnecessary admin accounts are lateral movement targets. Compromise one = own the machine.";

        if (title.Contains("powershell") && (title.Contains("unrestricted") || title.Contains("policy")))
            return "Attackers use PowerShell for fileless malware. Without execution policy + logging, attacks leave no trace.";

        if (title.Contains("password") && (title.Contains("never") || title.Contains("expire")))
            return "Passwords that never rotate accumulate in breach databases. Credential stuffing attacks succeed indefinitely.";

        // Generic fallback based on severity
        return finding.Severity switch
        {
            Severity.Critical => "Leaves the system vulnerable to known attack techniques with existing tooling.",
            Severity.Warning => "Increases likelihood of successful compromise if targeted.",
            Severity.Info => "Reduces defense-in-depth. Low individual risk but contributes to cumulative exposure.",
            _ => "No significant risk — this check is passing."
        };
    }

    private static string[] GetComplianceMapping(Finding finding)
    {
        var title = finding.Title.ToLowerInvariant();
        var category = finding.Category.ToLowerInvariant();
        var mappings = new List<string>();

        // Map common findings to compliance frameworks
        if (title.Contains("bitlocker") || title.Contains("encryption"))
        {
            mappings.Add("CIS Windows 11 L1: 18.10.9.1 — Require device encryption");
            mappings.Add("Essential Eight: Maturity Level 2 — Data encryption at rest");
            mappings.Add("HIPAA §164.312(a)(2)(iv) — Encryption and decryption");
        }
        else if (title.Contains("firewall"))
        {
            mappings.Add("CIS Windows 11 L1: 9.1.1-9.3.5 — Windows Firewall profiles");
            mappings.Add("SOC2 CC6.6 — System boundaries protection");
        }
        else if (title.Contains("uac") || title.Contains("user account control"))
        {
            mappings.Add("CIS Windows 11 L1: 2.3.17.1-6 — UAC settings");
            mappings.Add("Essential Eight: Restrict administrative privileges");
        }
        else if (title.Contains("smb"))
        {
            mappings.Add("CIS Windows 11 L1: 18.4.14.1 — SMB v1 disabled");
            mappings.Add("Essential Eight: Patch operating systems");
        }
        else if (title.Contains("rdp") || title.Contains("remote desktop"))
        {
            mappings.Add("CIS Windows 11 L1: 18.10.57.3.9 — RDP security settings");
            mappings.Add("SOC2 CC6.1 — Logical access security");
        }
        else if (title.Contains("defender") || title.Contains("antivirus"))
        {
            mappings.Add("CIS Windows 11 L1: 18.10.43 — Windows Defender settings");
            mappings.Add("Essential Eight: Anti-malware software");
            mappings.Add("SOC2 CC6.8 — Malicious software prevention");
        }
        else if (title.Contains("update") || title.Contains("patch"))
        {
            mappings.Add("CIS Windows 11 L1: 18.10.92 — Windows Update settings");
            mappings.Add("Essential Eight: Patch operating systems (within 48h for critical)");
            mappings.Add("SOC2 CC7.1 — Vulnerability management");
        }
        else if (title.Contains("powershell"))
        {
            mappings.Add("CIS Windows 11 L1: 18.10.88 — PowerShell settings");
            mappings.Add("Essential Eight: Configure Microsoft Office macro settings");
        }
        else if (title.Contains("password") || title.Contains("credential") || title.Contains("account"))
        {
            mappings.Add("CIS Windows 11 L1: 1.1-1.2 — Account/Password policies");
            mappings.Add("SOC2 CC6.1 — Access control");
            mappings.Add("HIPAA §164.312(d) — Person/entity authentication");
        }
        else if (category.Contains("network") || title.Contains("llmnr") || title.Contains("port"))
        {
            mappings.Add("CIS Windows 11 L1: 18.4 — Network settings");
            mappings.Add("SOC2 CC6.6 — Network security");
        }

        return mappings.ToArray();
    }
}
