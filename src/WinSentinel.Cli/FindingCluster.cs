using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public record FindingCluster
{
    public string Label { get; set; } = "";
    public List<(string Module, Finding Finding)> Items { get; set; } = [];
    public List<string> Modules { get; set; } = [];
    public Severity HighestSeverity { get; set; }
}
