using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintLineage(AuditResult result, CliOptions options)
    {
        if (result.Error != null)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ✗ Audit error: {result.Error}");
            Console.ResetColor();
            return;
        }

        var critical = result.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        var warnings = result.Findings.Where(f => f.Severity == Severity.Warning).ToList();
        var info = result.Findings.Where(f => f.Severity == Severity.Info).ToList();
        var passed = result.Findings.Where(f => f.Severity == Severity.Pass).ToList();

        // Summary bar
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ┌─────────────────────────────────────────────────────┐");
        Console.Write("  │  ");
        Console.ForegroundColor = critical.Count > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        var status = critical.Count > 0 ? "⚠ SUSPICIOUS CHAINS DETECTED" : "✓ NO CRITICAL LINEAGE ISSUES";
        Console.Write($"{status,-51}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("│");
        Console.WriteLine("  └─────────────────────────────────────────────────────┘");
        Console.ResetColor();
        Console.WriteLine();

        // Stats
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write("  Findings:  ");
        if (critical.Count > 0) { Console.ForegroundColor = ConsoleColor.Red; Console.Write($"● {critical.Count} critical  "); }
        if (warnings.Count > 0) { Console.ForegroundColor = ConsoleColor.Yellow; Console.Write($"● {warnings.Count} warning  "); }
        if (info.Count > 0) { Console.ForegroundColor = ConsoleColor.Cyan; Console.Write($"● {info.Count} info  "); }
        if (passed.Count > 0) { Console.ForegroundColor = ConsoleColor.Green; Console.Write($"● {passed.Count} pass  "); }
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine();

        // Critical findings
        foreach (var finding in critical)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ▸ CRITICAL: {finding.Title}");
            Console.ForegroundColor = ConsoleColor.Gray;
            foreach (var line in finding.Description.Split('\n'))
            {
                Console.WriteLine($"    {line.TrimEnd()}");
            }
            if (finding.Remediation != null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"    ↳ {finding.Remediation}");
            }
            if (finding.FixCommand != null)
            {
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine($"    $ {finding.FixCommand.Split('\n')[0]}");
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        // Warning findings
        foreach (var finding in warnings)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  ▸ WARNING: {finding.Title}");
            Console.ForegroundColor = ConsoleColor.Gray;
            foreach (var line in finding.Description.Split('\n'))
            {
                Console.WriteLine($"    {line.TrimEnd()}");
            }
            if (finding.Remediation != null)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"    ↳ {finding.Remediation}");
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        // Info findings
        foreach (var finding in info)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"  ▸ INFO: {finding.Title}");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"    {finding.Description}");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Pass findings
        foreach (var finding in passed)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ {finding.Title}");
            Console.ResetColor();
        }

        Console.WriteLine();

        // MITRE ATT&CK legend
        if (critical.Count > 0 || warnings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─── MITRE ATT&CK References ───");
            Console.WriteLine("  T1204.002 — User Execution: Malicious File");
            Console.WriteLine("  T1189     — Drive-by Compromise");
            Console.WriteLine("  T1105     — Ingress Tool Transfer");
            Console.WriteLine("  T1140     — Deobfuscate/Decode Files");
            Console.WriteLine("  T1218     — System Binary Proxy Execution");
            Console.WriteLine("  T1047     — Windows Management Instrumentation");
            Console.WriteLine("  T1543.003 — Windows Service Persistence");
            Console.WriteLine("  T1053.005 — Scheduled Task Persistence");
            Console.WriteLine("  T1059     — Command and Scripting Interpreter");
            Console.ResetColor();
        }

        Console.WriteLine();
        var elapsed = result.EndTime - result.StartTime;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Completed in {elapsed.TotalSeconds:F1}s");
        Console.ResetColor();
    }
}
