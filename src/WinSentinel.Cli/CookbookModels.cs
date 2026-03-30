using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public record CookbookRecipe
{
    public string Module { get; init; } = "";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public Severity Severity { get; init; }
    public string? Remediation { get; init; }
    public string? FixCommand { get; init; }
    public string Effort { get; init; } = "";
}

public record CookbookRecipeGroup
{
    public string Category { get; init; } = "";
    public List<CookbookRecipe> Recipes { get; init; } = [];
    public Severity HighestSeverity { get; init; }
}
