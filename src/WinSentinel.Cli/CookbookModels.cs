using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

/// <summary>
/// A single remediation recipe from the security cookbook — a finding
/// paired with actionable fix instructions and effort estimate.
/// </summary>
public record CookbookRecipe
{
    /// <summary>Source audit module that produced the finding.</summary>
    public string Module { get; init; } = "";

    /// <summary>Finding title.</summary>
    public string Title { get; init; } = "";

    /// <summary>Human-readable description of the issue.</summary>
    public string Description { get; init; } = "";

    /// <summary>Severity of the finding.</summary>
    public Severity Severity { get; init; }

    /// <summary>Recommended remediation steps (prose).</summary>
    public string? Remediation { get; init; }

    /// <summary>Auto-fix command, if available.</summary>
    public string? FixCommand { get; init; }

    /// <summary>Estimated effort to fix (e.g., "Low", "Medium", "High").</summary>
    public string Effort { get; init; } = "";
}

/// <summary>
/// A group of related cookbook recipes sharing the same category.
/// </summary>
public record CookbookRecipeGroup
{
    /// <summary>Category name for this group of recipes.</summary>
    public string Category { get; init; } = "";

    /// <summary>Recipes in this category.</summary>
    public List<CookbookRecipe> Recipes { get; init; } = [];

    /// <summary>Highest severity among all recipes in the group.</summary>
    public Severity HighestSeverity { get; init; }
}
