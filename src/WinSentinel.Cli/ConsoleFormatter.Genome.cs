namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintGenome(GenomeReport report)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🧬  Security Genome                   ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        if (report.Modules.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No module data found.");
            Console.ResetColor();
            return;
        }

        // Current genome string
        Console.WriteLine();
        Console.Write("  Genome: ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("[");
        foreach (var m in report.Modules)
        {
            Console.ForegroundColor = ScoreColor(m.Score);
            Console.Write(ScoreToBlock(m.Score));
        }
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("]");
        Console.ResetColor();
        Console.Write("  Score: ");
        WriteColored($"{report.OverallScore}/100", ScoreColor(report.OverallScore));
        Console.WriteLine();

        // Legend
        Console.WriteLine();
        Console.Write("  Legend: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("█");
        Console.ResetColor();
        Console.Write("≥80  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("▓");
        Console.ResetColor();
        Console.Write("≥60  ");
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.Write("▒");
        Console.ResetColor();
        Console.Write("≥40  ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("░");
        Console.ResetColor();
        Console.Write("<40  ");
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.Write("×");
        Console.ResetColor();
        Console.WriteLine("=mutated");

        // Module detail table
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  Module Breakdown:");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌─────────────────────────┬───────┬──────┬──────────┐");
        Console.WriteLine("  │ Module                  │ Score │ Gene │ Mutation │");
        Console.WriteLine("  ├─────────────────────────┼───────┼──────┼──────────┤");
        Console.ResetColor();

        foreach (var m in report.Modules)
        {
            var name = m.Name.Length > 23 ? m.Name[..23] : m.Name.PadRight(23);
            var gene = ScoreToBlock(m.Score);
            var mutation = m.Mutation switch
            {
                > 0 => $"+{m.Mutation}",
                < 0 => $"{m.Mutation}",
                _ => "  ─"
            };
            var mutColor = m.Mutation switch
            {
                > 0 => ConsoleColor.Green,
                < 0 => ConsoleColor.Red,
                _ => ConsoleColor.DarkGray
            };

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(name);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = ScoreColor(m.Score);
            Console.Write($"{m.Score,3}  ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │  ");
            Console.ForegroundColor = ScoreColor(m.Score);
            Console.Write($"{gene}   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("│ ");
            Console.ForegroundColor = mutColor;
            Console.Write($"{mutation,6}   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("│");
        }
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └─────────────────────────┴───────┴──────┴──────────┘");
        Console.ResetColor();

        // Stability score
        Console.WriteLine();
        Console.Write("  Stability: ");
        var stabColor = report.StabilityPercent >= 80 ? ConsoleColor.Green :
                        report.StabilityPercent >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;
        WriteColored($"{report.StabilityPercent}%", stabColor);
        Console.Write(" of modules unchanged  |  Mutations: ");
        WriteColored($"{report.MutationCount}", report.MutationCount == 0 ? ConsoleColor.Green : ConsoleColor.Yellow);
        Console.WriteLine();

        // Genome history timeline
        if (report.History.Count > 1)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  Genome Evolution:");
            Console.ResetColor();

            foreach (var h in report.History.TakeLast(10))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {h.Date:yyyy-MM-dd}  [");
                foreach (var g in h.Genes)
                {
                    Console.ForegroundColor = ScoreColor(g);
                    Console.Write(ScoreToBlock(g));
                }
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("]  ");
                Console.ForegroundColor = ScoreColor(h.OverallScore);
                Console.Write($"{h.OverallScore}/100");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        // Proactive recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  💡 Recommendations:");
            Console.ResetColor();
            foreach (var rec in report.Recommendations)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    → ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(rec);
            }
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    private static char ScoreToBlock(int score) => score switch
    {
        >= 80 => '█',
        >= 60 => '▓',
        >= 40 => '▒',
        _ => '░'
    };
}

// Data models for Genome
public class GenomeReport
{
    public List<GenomeModule> Modules { get; set; } = [];
    public int OverallScore { get; set; }
    public int StabilityPercent { get; set; }
    public int MutationCount { get; set; }
    public List<GenomeSnapshot> History { get; set; } = [];
    public List<string> Recommendations { get; set; } = [];
    public int LookbackDays { get; set; }
    public int RunsAnalyzed { get; set; }
}

public class GenomeModule
{
    public string Name { get; set; } = "";
    public int Score { get; set; }
    public int Mutation { get; set; }
}

public class GenomeSnapshot
{
    public DateTimeOffset Date { get; set; }
    public List<int> Genes { get; set; } = [];
    public int OverallScore { get; set; }
}
