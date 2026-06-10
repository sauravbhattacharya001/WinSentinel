using System;
using System.Text.Json;

namespace WinSentinel.Cli;

/// <summary>
/// Pure request-construction helpers for <see cref="FleetCommandHandler"/>.
///
/// The fleet commands talk to the Pro control plane (<c>api.winsentinel.ai/fleet</c>).
/// Everything that decides <em>what</em> to send — which endpoint to hit, how the
/// dispatch payload is shaped, how a node/module filter is normalized, and how a
/// JSON field is read back out of a response — lives here so it can be unit-tested
/// without an <see cref="System.Net.Http.HttpClient"/>, a live Worker, or a license.
///
/// This deliberately holds <b>no</b> I/O, no <c>Console.*</c>, no clock, and no
/// network. <see cref="FleetCommandHandler"/> keeps the HTTP plumbing and rendering;
/// this class keeps the decisions.
/// </summary>
public static class FleetRequestBuilder
{
    /// <summary>Default control plane base URL when nothing overrides it.</summary>
    public const string DefaultEndpoint = "https://api.winsentinel.ai/fleet";

    /// <summary>Environment variable that overrides the default endpoint.</summary>
    public const string EndpointEnvVar = "WINSENTINEL_FLEET_ENDPOINT";

    /// <summary>Sentinel meaning "every node" when no <c>--nodes</c> filter is given.</summary>
    public const string AllNodes = "all";

    public static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Resolve the fleet API base URL with precedence:
    /// explicit <paramref name="optionEndpoint"/> (e.g. <c>--fleet-endpoint</c>) &gt;
    /// environment variable <paramref name="envEndpoint"/> &gt; <see cref="DefaultEndpoint"/>.
    /// A trailing slash is always trimmed so callers can safely do <c>$"{endpoint}/status"</c>.
    /// </summary>
    public static string ResolveEndpoint(string? optionEndpoint, string? envEndpoint)
    {
        if (!string.IsNullOrWhiteSpace(optionEndpoint))
            return optionEndpoint.TrimEnd('/');

        if (!string.IsNullOrWhiteSpace(envEndpoint))
            return envEndpoint.TrimEnd('/');

        return DefaultEndpoint;
    }

    /// <summary>
    /// Reads the live environment for <see cref="EndpointEnvVar"/> and resolves the
    /// endpoint. The only impure entry point; tests call <see cref="ResolveEndpoint"/>.
    /// </summary>
    public static string ResolveEndpointFromEnvironment(string? optionEndpoint) =>
        ResolveEndpoint(optionEndpoint, Environment.GetEnvironmentVariable(EndpointEnvVar));

    /// <summary>
    /// Normalize a node-target filter (the <c>--nodes</c> value). Null / empty /
    /// whitespace collapses to <see cref="AllNodes"/>. A comma-separated list is
    /// trimmed per entry, empties dropped, de-duplicated case-insensitively while
    /// preserving first-seen order, then re-joined with <c>,</c>. A literal
    /// "all" (any case) collapses back to <see cref="AllNodes"/>.
    /// </summary>
    public static string NormalizeTargets(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return AllNodes;

        var parts = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            return AllNodes;

        var seen = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordered = new System.Collections.Generic.List<string>();
        foreach (var p in parts)
        {
            if (string.Equals(p, AllNodes, StringComparison.OrdinalIgnoreCase))
                return AllNodes;
            if (seen.Add(p))
                ordered.Add(p);
        }

        return ordered.Count == 0 ? AllNodes : string.Join(',', ordered);
    }

    /// <summary>
    /// Build the JSON body POSTed to <c>/commands/dispatch</c> for <c>fleet scan-all</c>.
    /// <paramref name="modules"/> is passed through verbatim (null means "all modules");
    /// targets are normalized via <see cref="NormalizeTargets"/>.
    /// </summary>
    public static string BuildScanPayload(string? targets, string? modules)
    {
        var payload = new
        {
            command = "scan",
            targets = NormalizeTargets(targets),
            modules,
            priority = "normal",
        };
        return JsonSerializer.Serialize(payload, JsonOpts);
    }

    /// <summary>
    /// Build the JSON body POSTed to <c>/commands/dispatch</c> for <c>fleet push-policy</c>.
    /// <paramref name="policyJson"/> must already be a valid JSON document — it is parsed
    /// and embedded as the <c>policy</c> field. Throws <see cref="JsonException"/> if the
    /// policy text is not valid JSON (callers surface this as a user error).
    /// </summary>
    public static string BuildPushPolicyPayload(string? targets, string policyJson)
    {
        if (policyJson is null)
            throw new ArgumentNullException(nameof(policyJson));

        var policy = JsonSerializer.Deserialize<JsonElement>(policyJson);
        var payload = new
        {
            command = "push-policy",
            targets = NormalizeTargets(targets),
            policy,
        };
        return JsonSerializer.Serialize(payload, JsonOpts);
    }

    /// <summary>
    /// Read a property off a JSON object as a display string, regardless of the
    /// underlying JSON value kind (string passed through, number/bool stringified,
    /// objects/arrays returned as raw text). Missing properties and JSON null both
    /// return <paramref name="fallback"/>.
    /// </summary>
    public static string GetJsonString(JsonElement element, string property, string fallback)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(property, out var val))
        {
            return val.ValueKind switch
            {
                JsonValueKind.Null => fallback,
                JsonValueKind.String => val.GetString() ?? fallback,
                JsonValueKind.Number => val.ToString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => val.GetRawText(),
            };
        }
        return fallback;
    }

    /// <summary>
    /// True when the dispatch path should be used (scan / push-policy). Pure helper so the
    /// handler's switch and the tests agree on which actions are "dispatch" verbs.
    /// </summary>
    public static bool IsDispatchAction(FleetAction action) =>
        action is FleetAction.ScanAll or FleetAction.PushPolicy;
}
