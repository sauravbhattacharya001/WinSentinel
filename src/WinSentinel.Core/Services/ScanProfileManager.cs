using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Defines a named scan profile that controls which audit modules to run,
/// minimum severity threshold for reported findings, and optional tags
/// for organization.
/// </summary>
public class ScanProfile
{
    /// <summary>Unique name for this profile (case-insensitive).</summary>
    public string Name { get; set; } = "";

    /// <summary>Human-readable description of what this profile covers.</summary>
    public string Description { get; set; } = "";

    /// <summary>
    /// Module names to include. If empty, all modules are included.
    /// Matched case-insensitively against <see cref="IAuditModule.Name"/>.
    /// </summary>
    public List<string> IncludeModules { get; set; } = new();

    /// <summary>
    /// Module names to exclude. Applied after <see cref="IncludeModules"/>.
    /// Matched case-insensitively against <see cref="IAuditModule.Name"/>.
    /// </summary>
    public List<string> ExcludeModules { get; set; } = new();

    /// <summary>
    /// Minimum severity to include in results. Findings below this level
    /// are filtered out. Default is <see cref="Severity.Pass"/> (include everything).
    /// </summary>
    public Severity MinimumSeverity { get; set; } = Severity.Pass;

    /// <summary>
    /// Whether this is a built-in profile (cannot be deleted or overwritten).
    /// </summary>
    [JsonIgnore]
    public bool IsBuiltIn { get; set; }

    /// <summary>
    /// Optional tags for categorization (e.g., "privacy", "compliance", "quick").
    /// </summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>When this profile was created.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>When this profile was last modified.</summary>
    public DateTimeOffset? ModifiedAt { get; set; }
}

/// <summary>
/// Result of applying a scan profile: the filtered module list and any
/// post-processing applied to findings.
/// </summary>
public class ProfiledScanResult
{
    /// <summary>The profile that was applied.</summary>
    public string ProfileName { get; set; } = "";

    /// <summary>Modules that were selected by the profile.</summary>
    public List<string> SelectedModules { get; set; } = new();

    /// <summary>Modules that were excluded by the profile.</summary>
    public List<string> ExcludedModules { get; set; } = new();

    /// <summary>Total modules available before filtering.</summary>
    public int TotalAvailableModules { get; set; }

    /// <summary>The filtered security report.</summary>
    public SecurityReport Report { get; set; } = new();

    /// <summary>Findings removed by the minimum severity filter.</summary>
    public int FilteredFindingsCount { get; set; }
}

/// <summary>
/// Manages named scan profiles for targeted security auditing. Provides
/// built-in profiles (Quick, Full, Privacy, Network, Compliance) and
/// supports user-defined custom profiles with JSON persistence.
/// </summary>
/// <remarks>
/// <para>
/// Profiles control two aspects of a scan:
/// <list type="bullet">
///   <item><description>
///     <b>Module selection</b> — which audit modules to run (via include/exclude lists)
///   </description></item>
///   <item><description>
///     <b>Finding filter</b> — minimum severity threshold for reported findings
///   </description></item>
/// </list>
/// </para>
/// <para>
/// Example usage:
/// <code>
/// var manager = new ScanProfileManager();
/// var engine = new AuditEngine();
/// 
/// // Run a quick scan (critical checks only)
/// var modules = manager.SelectModules("Quick", engine.Modules);
/// var customEngine = new AuditEngine(modules);
/// var report = await customEngine.RunFullAuditAsync();
/// 
/// // Filter findings by profile severity threshold
/// var filtered = manager.FilterReport("Quick", report);
/// </code>
/// </para>
/// </remarks>
public class ScanProfileManager
{
    /// <summary>Maximum number of profiles (built-in + custom).</summary>
    public const int MaxProfiles = 50;

    /// <summary>Maximum profile name length.</summary>
    public const int MaxNameLength = 64;

    /// <summary>Maximum number of modules in include/exclude lists.</summary>
    public const int MaxModulesPerList = 50;

    /// <summary>Maximum number of tags per profile.</summary>
    public const int MaxTagsPerProfile = 20;

    private readonly Dictionary<string, ScanProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>
    /// Creates a new profile manager with built-in profiles registered.
    /// </summary>
    public ScanProfileManager()
    {
        RegisterBuiltInProfiles();
    }

    // ── Profile Access ───────────────────────────────────────────

    /// <summary>All registered profile names.</summary>
    public IReadOnlyList<string> ProfileNames
    {
        get { lock (_lock) return _profiles.Keys.ToList(); }
    }

    /// <summary>Number of registered profiles.</summary>
    public int Count
    {
        get { lock (_lock) return _profiles.Count; }
    }

    /// <summary>Gets a profile by name, or null if not found.</summary>
    public ScanProfile? GetProfile(string name)
    {
        lock (_lock)
            return _profiles.TryGetValue(name, out var p) ? p : null;
    }

    /// <summary>Returns true if a profile with the given name exists.</summary>
    public bool HasProfile(string name)
    {
        lock (_lock) return _profiles.ContainsKey(name);
    }

    /// <summary>Gets all profiles, optionally filtered by tag.</summary>
    public IReadOnlyList<ScanProfile> GetProfiles(string? tag = null)
    {
        lock (_lock)
        {
            var profiles = _profiles.Values.AsEnumerable();
            if (!string.IsNullOrEmpty(tag))
                profiles = profiles.Where(p =>
                    p.Tags.Any(t => t.Equals(tag, StringComparison.OrdinalIgnoreCase)));
            return profiles.ToList();
        }
    }

    /// <summary>Gets only the built-in profiles.</summary>
    public IReadOnlyList<ScanProfile> GetBuiltInProfiles()
    {
        lock (_lock) return _profiles.Values.Where(p => p.IsBuiltIn).ToList();
    }

    /// <summary>Gets only user-defined (custom) profiles.</summary>
    public IReadOnlyList<ScanProfile> GetCustomProfiles()
    {
        lock (_lock) return _profiles.Values.Where(p => !p.IsBuiltIn).ToList();
    }

    // ── Profile Management ───────────────────────────────────────

    /// <summary>
    /// Registers a new custom profile. Throws if a profile with the same
    /// name already exists or limits are exceeded.
    /// </summary>
    /// <param name="profile">The profile to register.</param>
    /// <returns>This manager for fluent chaining.</returns>
    public ScanProfileManager AddProfile(ScanProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ValidateProfile(profile);

        lock (_lock)
        {
            if (_profiles.Count >= MaxProfiles)
                throw new InvalidOperationException(
                    $"Maximum of {MaxProfiles} profiles reached.");
            if (_profiles.ContainsKey(profile.Name))
                throw new InvalidOperationException(
                    $"Profile '{profile.Name}' already exists. Use UpdateProfile to modify.");
            profile.IsBuiltIn = false;
            profile.CreatedAt = DateTimeOffset.UtcNow;
            _profiles[profile.Name] = profile;
        }
        return this;
    }

    /// <summary>
    /// Updates an existing custom profile. Cannot update built-in profiles.
    /// </summary>
    public void UpdateProfile(ScanProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ValidateProfile(profile);

        lock (_lock)
        {
            if (!_profiles.TryGetValue(profile.Name, out var existing))
                throw new KeyNotFoundException(
                    $"Profile '{profile.Name}' not found.");
            if (existing.IsBuiltIn)
                throw new InvalidOperationException(
                    $"Cannot modify built-in profile '{profile.Name}'.");
            profile.IsBuiltIn = false;
            profile.CreatedAt = existing.CreatedAt;
            profile.ModifiedAt = DateTimeOffset.UtcNow;
            _profiles[profile.Name] = profile;
        }
    }

    /// <summary>
    /// Removes a custom profile. Cannot remove built-in profiles.
    /// </summary>
    /// <returns>True if the profile was found and removed.</returns>
    public bool RemoveProfile(string name)
    {
        lock (_lock)
        {
            if (!_profiles.TryGetValue(name, out var profile))
                return false;
            if (profile.IsBuiltIn)
                throw new InvalidOperationException(
                    $"Cannot remove built-in profile '{name}'.");
            return _profiles.Remove(name);
        }
    }

    // ── Module Selection ─────────────────────────────────────────

    /// <summary>
    /// Filters a list of audit modules according to the named profile's
    /// include/exclude rules.
    /// </summary>
    /// <param name="profileName">The profile to apply.</param>
    /// <param name="allModules">All available audit modules.</param>
    /// <returns>The filtered list of modules to run.</returns>
    public IReadOnlyList<IAuditModule> SelectModules(
        string profileName,
        IReadOnlyList<IAuditModule> allModules)
    {
        var profile = GetProfileOrThrow(profileName);
        return SelectModules(profile, allModules);
    }

    /// <summary>
    /// Filters a list of audit modules according to the profile's
    /// include/exclude rules.
    /// </summary>
    public IReadOnlyList<IAuditModule> SelectModules(
        ScanProfile profile,
        IReadOnlyList<IAuditModule> allModules)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(allModules);

        IEnumerable<IAuditModule> result = allModules;

        // Apply include filter (if specified, only keep modules in the list)
        if (profile.IncludeModules.Count > 0)
        {
            var includeSet = new HashSet<string>(
                profile.IncludeModules, StringComparer.OrdinalIgnoreCase);
            result = result.Where(m => includeSet.Contains(m.Name));
        }

        // Apply exclude filter
        if (profile.ExcludeModules.Count > 0)
        {
            var excludeSet = new HashSet<string>(
                profile.ExcludeModules, StringComparer.OrdinalIgnoreCase);
            result = result.Where(m => !excludeSet.Contains(m.Name));
        }

        return result.ToList();
    }

    // ── Finding Filtering ────────────────────────────────────────

    /// <summary>
    /// Filters a security report's findings according to the profile's
    /// minimum severity threshold. Returns a new report with filtered findings.
    /// </summary>
    /// <param name="profileName">The profile to apply.</param>
    /// <param name="report">The original security report.</param>
    /// <returns>A new report with findings filtered by severity.</returns>
    public SecurityReport FilterReport(string profileName, SecurityReport report)
    {
        var profile = GetProfileOrThrow(profileName);
        return FilterReport(profile, report);
    }

    /// <summary>
    /// Filters a security report's findings according to the profile's
    /// minimum severity threshold.
    /// </summary>
    public SecurityReport FilterReport(ScanProfile profile, SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(report);

        if (profile.MinimumSeverity == Severity.Pass)
            return report; // No filtering needed

        var filtered = new SecurityReport
        {
            GeneratedAt = report.GeneratedAt,
            SecurityScore = report.SecurityScore,
            Results = report.Results.Select(r => new AuditResult
            {
                ModuleName = r.ModuleName,
                Category = r.Category,
                StartTime = r.StartTime,
                EndTime = r.EndTime,
                Success = r.Success,
                Error = r.Error,
                Findings = r.Findings
                    .Where(f => f.Severity >= profile.MinimumSeverity)
                    .ToList()
            }).ToList()
        };

        return filtered;
    }

    /// <summary>
    /// Applies a profile end-to-end: selects modules, runs the audit,
    /// and filters the resulting report. Returns a <see cref="ProfiledScanResult"/>
    /// with full metadata about what was selected and filtered.
    /// </summary>
    public ProfiledScanResult ApplyProfile(
        ScanProfile profile,
        IReadOnlyList<IAuditModule> allModules,
        SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(allModules);
        ArgumentNullException.ThrowIfNull(report);

        var selected = SelectModules(profile, allModules);
        var selectedNames = new HashSet<string>(
            selected.Select(m => m.Name), StringComparer.OrdinalIgnoreCase);
        var excludedNames = allModules
            .Where(m => !selectedNames.Contains(m.Name))
            .Select(m => m.Name)
            .ToList();

        var filtered = FilterReport(profile, report);
        int removedFindings = report.Results.Sum(r => r.Findings.Count) -
                              filtered.Results.Sum(r => r.Findings.Count);

        return new ProfiledScanResult
        {
            ProfileName = profile.Name,
            SelectedModules = selected.Select(m => m.Name).ToList(),
            ExcludedModules = excludedNames,
            TotalAvailableModules = allModules.Count,
            Report = filtered,
            FilteredFindingsCount = removedFindings
        };
    }

    // ── Serialization ────────────────────────────────────────────

    /// <summary>
    /// Serializes all custom (non-built-in) profiles to JSON.
    /// </summary>
    public string ExportCustomProfiles()
    {
        lock (_lock)
        {
            var customs = _profiles.Values
                .Where(p => !p.IsBuiltIn)
                .ToList();

            return JsonSerializer.Serialize(customs, new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() },
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            });
        }
    }

    /// <summary>
    /// Imports custom profiles from JSON. Existing custom profiles with
    /// the same name are overwritten. Built-in profiles cannot be overwritten.
    /// </summary>
    /// <param name="json">JSON array of <see cref="ScanProfile"/> objects.</param>
    /// <returns>Number of profiles imported.</returns>
    public int ImportCustomProfiles(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("JSON cannot be null or empty.", nameof(json));

        var profiles = JsonSerializer.Deserialize<List<ScanProfile>>(json,
            new JsonSerializerOptions
            {
                Converters = { new JsonStringEnumConverter() },
                PropertyNameCaseInsensitive = true
            })
            ?? throw new JsonException("Failed to deserialize profiles.");

        int count = 0;
        lock (_lock)
        {
            foreach (var profile in profiles)
            {
                ValidateProfile(profile);
                if (_profiles.TryGetValue(profile.Name, out var existing) && existing.IsBuiltIn)
                    continue; // Skip built-in profiles silently

                profile.IsBuiltIn = false;
                _profiles[profile.Name] = profile;
                count++;
            }
        }
        return count;
    }

    // ── Private Helpers ──────────────────────────────────────────

    private ScanProfile GetProfileOrThrow(string name)
    {
        lock (_lock)
        {
            if (!_profiles.TryGetValue(name, out var profile))
                throw new KeyNotFoundException($"Profile '{name}' not found.");
            return profile;
        }
    }

    private static void ValidateProfile(ScanProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.Name))
            throw new ArgumentException("Profile name cannot be empty.");
        if (profile.Name.Length > MaxNameLength)
            throw new ArgumentException(
                $"Profile name exceeds maximum length of {MaxNameLength}.");
        if (profile.IncludeModules.Count > MaxModulesPerList)
            throw new ArgumentException(
                $"Include list exceeds maximum of {MaxModulesPerList} modules.");
        if (profile.ExcludeModules.Count > MaxModulesPerList)
            throw new ArgumentException(
                $"Exclude list exceeds maximum of {MaxModulesPerList} modules.");
        if (profile.Tags.Count > MaxTagsPerProfile)
            throw new ArgumentException(
                $"Tags exceed maximum of {MaxTagsPerProfile}.");
    }

    private void RegisterBuiltInProfiles()
    {
        RegisterBuiltIn(new ScanProfile
        {
            Name = "Quick",
            Description = "Fast scan of critical security checks only. " +
                          "Runs firewall, antivirus, and system update modules.",
            IncludeModules = { "Firewall", "Defender", "Updates", "Account Security" },
            MinimumSeverity = Severity.Warning,
            Tags = { "quick", "essential" }
        });

        RegisterBuiltIn(new ScanProfile
        {
            Name = "Full",
            Description = "Comprehensive scan of all available audit modules " +
                          "with all severity levels reported.",
            IncludeModules = { }, // empty = all modules
            MinimumSeverity = Severity.Pass,
            Tags = { "full", "comprehensive" }
        });

        RegisterBuiltIn(new ScanProfile
        {
            Name = "Privacy",
            Description = "Privacy-focused scan checking browser settings, " +
                          "telemetry, data collection, and privacy configurations.",
            IncludeModules = { "Privacy", "Browser Security", "App Security" },
            MinimumSeverity = Severity.Info,
            Tags = { "privacy", "data-protection" }
        });

        RegisterBuiltIn(new ScanProfile
        {
            Name = "Network",
            Description = "Network security scan covering firewall rules, " +
                          "open ports, DNS settings, and network exposure.",
            IncludeModules = { "Firewall", "Network" },
            MinimumSeverity = Severity.Info,
            Tags = { "network", "firewall" }
        });

        RegisterBuiltIn(new ScanProfile
        {
            Name = "CriticalOnly",
            Description = "Runs all modules but only reports critical findings. " +
                          "Use for quick status checks when you only care about urgent issues.",
            IncludeModules = { },
            MinimumSeverity = Severity.Critical,
            Tags = { "critical", "urgent" }
        });
    }

    private void RegisterBuiltIn(ScanProfile profile)
    {
        profile.IsBuiltIn = true;
        profile.CreatedAt = DateTimeOffset.MinValue; // Built-in, no creation date
        _profiles[profile.Name] = profile;
    }
}
