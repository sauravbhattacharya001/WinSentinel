using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using WinSentinel.Core.Licensing;

namespace WinSentinel.Cli;

/// <summary>
/// Fleet sub-action enumeration for <c>winsentinel fleet {status|scan-all|push-policy|nodes|help}</c>.
/// </summary>
public enum FleetAction
{
    Help,
    Status,
    ScanAll,
    PushPolicy,
    Nodes,
    Commands,
}

/// <summary>
/// Handles <c>winsentinel fleet</c> commands — Pro-only fleet orchestration.
/// These commands communicate with the WinSentinel fleet control plane API
/// to manage remote agents across an organization's machines.
///
/// All fleet commands require an active Pro license. Without one, users see
/// a friendly upgrade message explaining the Free → Pro path.
/// </summary>
internal static class FleetCommandHandler
{
    // Request shaping (endpoint resolution, payload bodies, JSON field reads) lives in
    // FleetRequestBuilder so it is unit-testable without HTTP. This class keeps the
    // HttpClient plumbing and console rendering.

    public static async Task<int> HandleAsync(CliOptions options)
    {
        // ─── Pro license gate ───────────────────────────────────────────
        var licenseStatus = LicenseManager.GetStatus(transientKey: options.TransientLicenseKey);
        if (!licenseStatus.IsPro)
        {
            PrintUpgradeMessage();
            return 1;
        }

        return options.FleetAction switch
        {
            FleetAction.Status => await HandleStatus(options, licenseStatus),
            FleetAction.ScanAll => await HandleScanAll(options, licenseStatus),
            FleetAction.PushPolicy => await HandlePushPolicy(options, licenseStatus),
            FleetAction.Nodes => await HandleNodes(options, licenseStatus),
            FleetAction.Commands => await HandleCommands(options, licenseStatus),
            FleetAction.Help => HandleHelp(),
            _ => HandleHelp(),
        };
    }

    // ─── Status ─────────────────────────────────────────────────────────────

    private static async Task<int> HandleStatus(CliOptions options, LicenseStatus status)
    {
        var endpoint = GetEndpoint(options);
        using var client = CreateClient(status);

        try
        {
            var response = await client.GetAsync($"{endpoint}/status");
            if (!response.IsSuccessStatusCode)
            {
                WriteError($"Fleet API returned {(int)response.StatusCode}: {response.ReasonPhrase}");
                return 1;
            }

            var body = await response.Content.ReadAsStringAsync();

            if (options.Json)
            {
                Console.WriteLine(body);
            }
            else
            {
                var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  ╔══════════════════════════════════════╗");
                Console.WriteLine("  ║       FLEET STATUS                   ║");
                Console.WriteLine("  ╚══════════════════════════════════════╝");
                Console.ResetColor();
                Console.WriteLine();

                WriteField("  License Tier", status.Tier ?? "pro");
                WriteField("  Nodes Online", GetJsonString(root, "nodesOnline", "0"));
                WriteField("  Nodes Total", GetJsonString(root, "nodesTotal", "0"));
                WriteField("  Last Sync", GetJsonString(root, "lastSync", "never"));
                WriteField("  Fleet Health", GetJsonString(root, "health", "unknown"));
                Console.WriteLine();

                if (root.TryGetProperty("alerts", out var alerts) && alerts.GetArrayLength() > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("  ⚠ Active Alerts:");
                    Console.ResetColor();
                    foreach (var alert in alerts.EnumerateArray())
                    {
                        Console.WriteLine($"    • {alert.GetString()}");
                    }
                    Console.WriteLine();
                }
            }

            return 0;
        }
        catch (HttpRequestException ex)
        {
            WriteError($"Cannot reach fleet API at {endpoint}: {ex.Message}");
            WriteHint("Ensure your fleet control plane is running and reachable.");
            return 1;
        }
    }

    // ─── Scan All ───────────────────────────────────────────────────────────

    private static async Task<int> HandleScanAll(CliOptions options, LicenseStatus status)
    {
        var endpoint = GetEndpoint(options);
        using var client = CreateClient(status);

        try
        {
            var json = FleetRequestBuilder.BuildScanPayload(options.FleetTargetNodes, options.ModulesFilter);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"{endpoint}/commands/dispatch", content);

            if (!response.IsSuccessStatusCode)
            {
                var errBody = await response.Content.ReadAsStringAsync();
                WriteError($"Fleet API returned {(int)response.StatusCode}: {errBody}");
                return 1;
            }

            var body = await response.Content.ReadAsStringAsync();

            if (options.Json)
            {
                Console.WriteLine(body);
            }
            else
            {
                var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("  ✓ ");
                Console.ResetColor();
                Console.WriteLine("Scan command dispatched to fleet.");

                WriteField("  Command ID", GetJsonString(root, "commandId", "n/a"));
                WriteField("  Targets", GetJsonString(root, "targetCount", "all"));
                WriteField("  Status", GetJsonString(root, "status", "pending"));
                Console.WriteLine();
                Console.WriteLine("  Use `winsentinel fleet status` to monitor progress.");
            }

            return 0;
        }
        catch (HttpRequestException ex)
        {
            WriteError($"Cannot reach fleet API at {endpoint}: {ex.Message}");
            return 1;
        }
    }

    // ─── Push Policy ────────────────────────────────────────────────────────

    private static async Task<int> HandlePushPolicy(CliOptions options, LicenseStatus status)
    {
        var endpoint = GetEndpoint(options);
        using var client = CreateClient(status);

        if (string.IsNullOrWhiteSpace(options.FleetPolicyFile))
        {
            WriteError("No policy file specified. Use: winsentinel fleet push-policy --file <path>");
            return 2;
        }

        string policyJson;
        try
        {
            policyJson = System.IO.File.ReadAllText(options.FleetPolicyFile);
            // Validate it's valid JSON
            JsonDocument.Parse(policyJson);
        }
        catch (Exception ex)
        {
            WriteError($"Cannot read policy file '{options.FleetPolicyFile}': {ex.Message}");
            return 2;
        }

        try
        {
            var json = FleetRequestBuilder.BuildPushPolicyPayload(options.FleetTargetNodes, policyJson);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"{endpoint}/commands/dispatch", content);

            if (!response.IsSuccessStatusCode)
            {
                var errBody = await response.Content.ReadAsStringAsync();
                WriteError($"Fleet API returned {(int)response.StatusCode}: {errBody}");
                return 1;
            }

            var body = await response.Content.ReadAsStringAsync();

            if (options.Json)
            {
                Console.WriteLine(body);
            }
            else
            {
                var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("  ✓ ");
                Console.ResetColor();
                Console.WriteLine("Policy push dispatched to fleet.");

                WriteField("  Command ID", GetJsonString(root, "commandId", "n/a"));
                WriteField("  Targets", GetJsonString(root, "targetCount", "all"));
                WriteField("  Policy", System.IO.Path.GetFileName(options.FleetPolicyFile));
                Console.WriteLine();
            }

            return 0;
        }
        catch (HttpRequestException ex)
        {
            WriteError($"Cannot reach fleet API at {endpoint}: {ex.Message}");
            return 1;
        }
    }

    // ─── Nodes ──────────────────────────────────────────────────────────────

    private static async Task<int> HandleNodes(CliOptions options, LicenseStatus status)
    {
        var endpoint = GetEndpoint(options);
        using var client = CreateClient(status);

        try
        {
            var response = await client.GetAsync($"{endpoint}/nodes");
            if (!response.IsSuccessStatusCode)
            {
                WriteError($"Fleet API returned {(int)response.StatusCode}: {response.ReasonPhrase}");
                return 1;
            }

            var body = await response.Content.ReadAsStringAsync();

            if (options.Json)
            {
                Console.WriteLine(body);
            }
            else
            {
                var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                if (!root.TryGetProperty("nodes", out var nodes) || nodes.GetArrayLength() == 0)
                {
                    Console.WriteLine();
                    Console.WriteLine("  No nodes registered in the fleet yet.");
                    Console.WriteLine("  Run `winsentinel agent start` on target machines to register them.");
                    Console.WriteLine();
                    return 0;
                }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  Fleet Nodes:");
                Console.ResetColor();
                Console.WriteLine("  ──────────────────────────────────────────────────────────────");
                Console.WriteLine($"  {"ID",-12} {"Hostname",-20} {"Status",-10} {"Last Seen",-20} {"Score",-6}");
                Console.WriteLine("  ──────────────────────────────────────────────────────────────");

                foreach (var node in nodes.EnumerateArray())
                {
                    var id = GetJsonString(node, "id", "?");
                    var hostname = GetJsonString(node, "hostname", "unknown");
                    var nodeStatus = GetJsonString(node, "status", "offline");
                    var lastSeen = GetJsonString(node, "lastSeen", "never");
                    var score = GetJsonString(node, "score", "-");

                    var statusColor = nodeStatus == "online" ? ConsoleColor.Green :
                                      nodeStatus == "stale" ? ConsoleColor.Yellow :
                                      ConsoleColor.Red;

                    Console.Write($"  {id,-12} {hostname,-20} ");
                    Console.ForegroundColor = statusColor;
                    Console.Write($"{nodeStatus,-10} ");
                    Console.ResetColor();
                    Console.WriteLine($"{lastSeen,-20} {score,-6}");
                }

                Console.WriteLine();
            }

            return 0;
        }
        catch (HttpRequestException ex)
        {
            WriteError($"Cannot reach fleet API at {endpoint}: {ex.Message}");
            return 1;
        }
    }

    // ─── Commands (dispatch history) ──────────────────────────────────────────

    /// <summary>
    /// <c>winsentinel fleet commands</c> — list the remote-command dispatch history and
    /// each command's reported outcome. This is the read side of the closed remote-command
    /// loop: an admin dispatches (scan-all / push-policy), the agent executes and reports
    /// completed/failed, and this view shows what actually happened across the fleet.
    /// Supports <c>--nodes &lt;id&gt;</c>, <c>--fleet-status &lt;state&gt;</c>, and <c>--limit N</c>.
    /// </summary>
    private static async Task<int> HandleCommands(CliOptions options, LicenseStatus status)
    {
        var endpoint = GetEndpoint(options);

        // Build the query path first — a bad --fleet-status is a user error we surface
        // before opening a socket.
        string path;
        try
        {
            path = FleetRequestBuilder.BuildCommandHistoryPath(
                options.FleetTargetNodes, options.FleetStatusFilter, options.FleetLimit);
        }
        catch (ArgumentException ex)
        {
            WriteError(ex.Message);
            return 2;
        }

        using var client = CreateClient(status);

        try
        {
            var response = await client.GetAsync($"{endpoint}{path}");
            if (!response.IsSuccessStatusCode)
            {
                WriteError($"Fleet API returned {(int)response.StatusCode}: {response.ReasonPhrase}");
                return 1;
            }

            var body = await response.Content.ReadAsStringAsync();

            if (options.Json)
            {
                Console.WriteLine(body);
                return 0;
            }

            var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("commands", out var commands) ||
                commands.ValueKind != JsonValueKind.Array || commands.GetArrayLength() == 0)
            {
                Console.WriteLine();
                Console.WriteLine("  No dispatched commands match that filter yet.");
                Console.WriteLine("  Dispatch one with `winsentinel fleet scan-all` or `fleet push-policy`.");
                Console.WriteLine();
                return 0;
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Command Dispatch History:");
            Console.ResetColor();
            Console.WriteLine("  ──────────────────────────────────────────────────────────────────────");
            Console.WriteLine($"  {"Command ID",-14} {"Node",-12} {"Type",-14} {"Status",-12} {"Dispatched",-20}");
            Console.WriteLine("  ──────────────────────────────────────────────────────────────────────");

            foreach (var cmd in commands.EnumerateArray())
            {
                var id = GetJsonString(cmd, "id", "?");
                var node = GetJsonString(cmd, "nodeId", GetJsonString(cmd, "node_id", "-"));
                var type = GetJsonString(cmd, "commandType", GetJsonString(cmd, "type", "-"));
                var cmdStatus = GetJsonString(cmd, "status", "pending");
                var created = GetJsonString(cmd, "createdAt", GetJsonString(cmd, "created_at", "-"));

                var statusColor = cmdStatus switch
                {
                    "completed" => ConsoleColor.Green,
                    "failed" => ConsoleColor.Red,
                    "expired" => ConsoleColor.DarkGray,
                    "acknowledged" => ConsoleColor.Cyan,
                    _ => ConsoleColor.Yellow,
                };

                Console.Write($"  {id,-14} {node,-12} {type,-14} ");
                Console.ForegroundColor = statusColor;
                Console.Write($"{cmdStatus,-12} ");
                Console.ResetColor();
                Console.WriteLine($"{created,-20}");

                // Surface the agent-reported result line for terminal commands so operators
                // see *why* something failed without re-querying.
                var result = GetJsonString(cmd, "result", GetJsonString(cmd, "result_json", ""));
                if (!string.IsNullOrWhiteSpace(result) && result != "-")
                {
                    var oneLine = result.Replace("\r", " ").Replace("\n", " ").Trim();
                    if (oneLine.Length > 66) oneLine = oneLine.Substring(0, 63) + "...";
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"      └ {oneLine}");
                    Console.ResetColor();
                }
            }

            Console.WriteLine();
            return 0;
        }
        catch (HttpRequestException ex)
        {
            WriteError($"Cannot reach fleet API at {endpoint}: {ex.Message}");
            WriteHint("Ensure your fleet control plane is running and reachable.");
            return 1;
        }
    }

    // ─── Help ───────────────────────────────────────────────────────────────

    private static int HandleHelp()
    {
        Console.WriteLine(@"
  WinSentinel Fleet — Pro fleet orchestration commands

  USAGE:
    winsentinel fleet <command> [options]

  COMMANDS:
    status                  Show fleet-wide posture overview
    scan-all                Dispatch scan to all (or targeted) nodes
    push-policy --file <f>  Push a policy file to fleet nodes
    nodes                   List registered fleet nodes
    commands                Show command dispatch history & reported outcomes
    help                    Show this help

  OPTIONS:
    --nodes <filter>        Target specific nodes (comma-separated IDs or 'all')
    --modules <filter>      Limit scan to specific modules (for scan-all)
    --fleet-status <state>  Filter `commands` history (pending|acknowledged|completed|failed|expired)
    --limit <n>             Max rows for `commands` history (1-200, default 50)
    --endpoint <url>        Fleet API endpoint (default: api.winsentinel.ai)
    --json                  Output in JSON format
    --license <key>         Use transient license key

  ENVIRONMENT:
    WINSENTINEL_FLEET_ENDPOINT    Override default fleet API endpoint

  EXAMPLES:
    winsentinel fleet status
    winsentinel fleet scan-all --modules defender,firewall
    winsentinel fleet scan-all --nodes node-01,node-02
    winsentinel fleet push-policy --file cis-l1-policy.json
    winsentinel fleet nodes --json
    winsentinel fleet commands --fleet-status failed --limit 20
    winsentinel fleet commands --nodes node-01 --json

  NOTE: All fleet commands require an active WinSentinel Pro license.
  Use `winsentinel pro status` to check your license state.
");
        return 0;
    }

    // ─── Upgrade message ────────────────────────────────────────────────────

    private static void PrintUpgradeMessage()
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  ┌─────────────────────────────────────────────────────────────┐");
        Console.WriteLine("  │  Fleet commands require a WinSentinel Pro license.           │");
        Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine("  WinSentinel Free gives you full-power security auditing on a");
        Console.WriteLine("  single machine — all modules, all features, no limits.");
        Console.WriteLine();
        Console.WriteLine("  WinSentinel Pro adds fleet orchestration for organizations:");
        Console.WriteLine("    • Central control plane for all your machines");
        Console.WriteLine("    • Remote scan dispatch & policy push");
        Console.WriteLine("    • Fleet-wide posture dashboard & drift alerts");
        Console.WriteLine("    • Compliance rollups (CIS, SOC2, HIPAA)");
        Console.WriteLine("    • RBAC for security teams");
        Console.WriteLine();
        Console.WriteLine("  Pricing: $29/mo (25 nodes) · $79/mo (100 nodes) · Enterprise");
        Console.WriteLine();
        Console.WriteLine("  Start a 14-day trial:  winsentinel pro start-trial");
        Console.WriteLine("  Purchase:              https://winsentinel.ai/pricing");
        Console.WriteLine();
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private static string GetEndpoint(CliOptions options) =>
        FleetRequestBuilder.ResolveEndpointFromEnvironment(options.FleetEndpoint);

    private static HttpClient CreateClient(LicenseStatus status)
    {
        var client = new HttpClient();
        client.DefaultRequestHeaders.Add("X-License-Key", status.Key ?? "");
        client.DefaultRequestHeaders.Add("User-Agent", "WinSentinel-CLI/Fleet");
        client.Timeout = TimeSpan.FromSeconds(30);
        return client;
    }

    private static string GetJsonString(JsonElement element, string property, string fallback) =>
        FleetRequestBuilder.GetJsonString(element, property, fallback);

    private static void WriteField(string label, string value)
    {
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write($"{label}: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(value);
        Console.ResetColor();
    }

    private static void WriteError(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("  ✗ ");
        Console.ResetColor();
        Console.Error.WriteLine(msg);
    }

    private static void WriteHint(string msg)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  → {msg}");
        Console.ResetColor();
    }
}
