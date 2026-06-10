// SPDX-License-Identifier: Apache-2.0
using System.Text.Json;
using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Tests for <see cref="FleetRequestBuilder"/>, the pure request-construction layer
/// behind the Pro-only <c>winsentinel fleet</c> commands. Lifted out of
/// <c>FleetCommandHandler</c> on Day 19 so the decisions a fleet command makes —
/// which endpoint to hit, how the dispatch payload is shaped, how a node/module
/// filter is normalized, how a JSON field is read back — can be verified without
/// an <see cref="System.Net.Http.HttpClient"/>, a live control-plane Worker, or a
/// Pro license.
///
/// Why this matters: fleet commands are the revenue-gated surface. A malformed
/// dispatch body or a wrong endpoint precedence is a paying-customer bug, and
/// until now none of it had a single test.
/// </summary>
public class FleetRequestBuilderTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    // ─── ResolveEndpoint: precedence option > env > default ─────────────────

    [Fact]
    public void ResolveEndpoint_Falls_Back_To_Default_When_All_Null()
    {
        Assert.Equal(FleetRequestBuilder.DefaultEndpoint,
            FleetRequestBuilder.ResolveEndpoint(null, null));
    }

    [Fact]
    public void ResolveEndpoint_Uses_Env_When_No_Option()
    {
        Assert.Equal("https://env.example.com/fleet",
            FleetRequestBuilder.ResolveEndpoint(null, "https://env.example.com/fleet"));
    }

    [Fact]
    public void ResolveEndpoint_Option_Wins_Over_Env()
    {
        Assert.Equal("https://opt.example.com/fleet",
            FleetRequestBuilder.ResolveEndpoint("https://opt.example.com/fleet", "https://env.example.com/fleet"));
    }

    [Theory]
    [InlineData("https://x.example.com/fleet/", "https://x.example.com/fleet")]
    [InlineData("https://x.example.com/fleet///", "https://x.example.com/fleet")]
    [InlineData("https://x.example.com/fleet", "https://x.example.com/fleet")]
    public void ResolveEndpoint_Trims_Trailing_Slashes(string input, string expected)
    {
        Assert.Equal(expected, FleetRequestBuilder.ResolveEndpoint(input, null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ResolveEndpoint_Treats_Blank_Option_As_Unset(string blank)
    {
        // Blank option should fall through to env, then default.
        Assert.Equal("https://env.example.com/fleet",
            FleetRequestBuilder.ResolveEndpoint(blank, "https://env.example.com/fleet"));
        Assert.Equal(FleetRequestBuilder.DefaultEndpoint,
            FleetRequestBuilder.ResolveEndpoint(blank, blank));
    }

    [Fact]
    public void ResolveEndpointFromEnvironment_Reads_The_Env_Var()
    {
        var original = Environment.GetEnvironmentVariable(FleetRequestBuilder.EndpointEnvVar);
        try
        {
            Environment.SetEnvironmentVariable(FleetRequestBuilder.EndpointEnvVar, "https://fromenv.example.com/fleet/");
            Assert.Equal("https://fromenv.example.com/fleet",
                FleetRequestBuilder.ResolveEndpointFromEnvironment(null));

            // Explicit option still beats the env var.
            Assert.Equal("https://opt.example.com/fleet",
                FleetRequestBuilder.ResolveEndpointFromEnvironment("https://opt.example.com/fleet"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(FleetRequestBuilder.EndpointEnvVar, original);
        }
    }

    // ─── NormalizeTargets ───────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(",")]
    [InlineData(" , , ")]
    public void NormalizeTargets_Empty_Means_All(string? raw)
    {
        Assert.Equal(FleetRequestBuilder.AllNodes, FleetRequestBuilder.NormalizeTargets(raw));
    }

    [Theory]
    [InlineData("all")]
    [InlineData("ALL")]
    [InlineData("All")]
    [InlineData("node-01,all,node-02")]
    public void NormalizeTargets_Literal_All_Collapses_To_All(string raw)
    {
        Assert.Equal(FleetRequestBuilder.AllNodes, FleetRequestBuilder.NormalizeTargets(raw));
    }

    [Fact]
    public void NormalizeTargets_Trims_And_Drops_Empties()
    {
        Assert.Equal("node-01,node-02",
            FleetRequestBuilder.NormalizeTargets(" node-01 , , node-02 "));
    }

    [Fact]
    public void NormalizeTargets_Dedupes_Case_Insensitively_Preserving_Order()
    {
        // node-01 seen first wins its casing; the later NODE-01 duplicate is dropped.
        Assert.Equal("node-01,node-02",
            FleetRequestBuilder.NormalizeTargets("node-01,node-02,NODE-01,node-02"));
    }

    [Fact]
    public void NormalizeTargets_Single_Node_Passes_Through()
    {
        Assert.Equal("web-prod-7", FleetRequestBuilder.NormalizeTargets("web-prod-7"));
    }

    // ─── BuildScanPayload ───────────────────────────────────────────────────

    [Fact]
    public void BuildScanPayload_Has_Expected_Shape_With_Defaults()
    {
        var root = Parse(FleetRequestBuilder.BuildScanPayload(null, null));

        Assert.Equal("scan", root.GetProperty("command").GetString());
        Assert.Equal("all", root.GetProperty("targets").GetString());
        Assert.Equal("normal", root.GetProperty("priority").GetString());
        // null modules serialize as JSON null (camelCase property name).
        Assert.Equal(JsonValueKind.Null, root.GetProperty("modules").ValueKind);
    }

    [Fact]
    public void BuildScanPayload_Carries_Modules_And_Normalized_Targets()
    {
        var root = Parse(FleetRequestBuilder.BuildScanPayload(" node-01 , node-01 , node-02 ", "defender,firewall"));

        Assert.Equal("scan", root.GetProperty("command").GetString());
        Assert.Equal("node-01,node-02", root.GetProperty("targets").GetString());
        Assert.Equal("defender,firewall", root.GetProperty("modules").GetString());
    }

    [Fact]
    public void BuildScanPayload_Uses_CamelCase_Property_Names()
    {
        var json = FleetRequestBuilder.BuildScanPayload("all", "x");
        // Sanity: the serializer policy is camelCase, so no PascalCase keys leak.
        Assert.Contains("\"command\"", json);
        Assert.Contains("\"targets\"", json);
        Assert.DoesNotContain("\"Command\"", json);
        Assert.DoesNotContain("\"Targets\"", json);
    }

    // ─── BuildPushPolicyPayload ─────────────────────────────────────────────

    [Fact]
    public void BuildPushPolicyPayload_Embeds_Policy_Document()
    {
        const string policy = "{\"name\":\"CIS L1\",\"rules\":[{\"id\":\"defender\",\"required\":true}]}";
        var root = Parse(FleetRequestBuilder.BuildPushPolicyPayload("node-01", policy));

        Assert.Equal("push-policy", root.GetProperty("command").GetString());
        Assert.Equal("node-01", root.GetProperty("targets").GetString());

        var embedded = root.GetProperty("policy");
        Assert.Equal("CIS L1", embedded.GetProperty("name").GetString());
        Assert.Equal("defender", embedded.GetProperty("rules")[0].GetProperty("id").GetString());
        Assert.True(embedded.GetProperty("rules")[0].GetProperty("required").GetBoolean());
    }

    [Fact]
    public void BuildPushPolicyPayload_Defaults_Targets_To_All()
    {
        var root = Parse(FleetRequestBuilder.BuildPushPolicyPayload(null, "{\"k\":1}"));
        Assert.Equal("all", root.GetProperty("targets").GetString());
    }

    [Fact]
    public void BuildPushPolicyPayload_Throws_On_Invalid_Json()
    {
        Assert.Throws<JsonException>(() =>
            FleetRequestBuilder.BuildPushPolicyPayload("all", "{ not valid json "));
    }

    [Fact]
    public void BuildPushPolicyPayload_Throws_On_Null_Policy()
    {
        Assert.Throws<ArgumentNullException>(() =>
            FleetRequestBuilder.BuildPushPolicyPayload("all", null!));
    }

    // ─── GetJsonString ──────────────────────────────────────────────────────

    [Fact]
    public void GetJsonString_Returns_String_Value()
    {
        var el = Parse("{\"health\":\"green\"}");
        Assert.Equal("green", FleetRequestBuilder.GetJsonString(el, "health", "fallback"));
    }

    [Fact]
    public void GetJsonString_Stringifies_Numbers()
    {
        var el = Parse("{\"nodesOnline\":42}");
        Assert.Equal("42", FleetRequestBuilder.GetJsonString(el, "nodesOnline", "0"));
    }

    [Theory]
    [InlineData("{\"flag\":true}", "true")]
    [InlineData("{\"flag\":false}", "false")]
    public void GetJsonString_Stringifies_Booleans(string json, string expected)
    {
        Assert.Equal(expected, FleetRequestBuilder.GetJsonString(Parse(json), "flag", "fallback"));
    }

    [Fact]
    public void GetJsonString_Missing_Property_Returns_Fallback()
    {
        var el = Parse("{\"other\":1}");
        Assert.Equal("never", FleetRequestBuilder.GetJsonString(el, "lastSync", "never"));
    }

    [Fact]
    public void GetJsonString_Json_Null_Returns_Fallback()
    {
        var el = Parse("{\"lastSync\":null}");
        Assert.Equal("never", FleetRequestBuilder.GetJsonString(el, "lastSync", "never"));
    }

    [Fact]
    public void GetJsonString_Object_Value_Returns_Raw_Text()
    {
        var el = Parse("{\"meta\":{\"a\":1}}");
        var result = FleetRequestBuilder.GetJsonString(el, "meta", "fallback");
        // Raw text of a nested object — exact whitespace is implementation-defined,
        // so assert on the structural content rather than byte-equality.
        Assert.Contains("\"a\"", result);
        Assert.Contains("1", result);
    }

    [Fact]
    public void GetJsonString_NonObject_Root_Returns_Fallback()
    {
        // Defensive: handed an array instead of an object, don't throw.
        var el = Parse("[1,2,3]");
        Assert.Equal("fallback", FleetRequestBuilder.GetJsonString(el, "anything", "fallback"));
    }

    // ─── IsDispatchAction ───────────────────────────────────────────────────

    [Theory]
    [InlineData(FleetAction.ScanAll, true)]
    [InlineData(FleetAction.PushPolicy, true)]
    [InlineData(FleetAction.Status, false)]
    [InlineData(FleetAction.Nodes, false)]
    [InlineData(FleetAction.Help, false)]
    public void IsDispatchAction_Classifies_Verbs(FleetAction action, bool expected)
    {
        Assert.Equal(expected, FleetRequestBuilder.IsDispatchAction(action));
    }
}
