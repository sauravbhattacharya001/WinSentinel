namespace WinSentinel.Core.Plugins;

/// <summary>
/// Canonical plugin entitlement (capability) identifiers. These are the
/// string values referenced in <c>plugin.json</c> manifests under
/// <c>"entitlements"</c> and checked at load time by the plugin host.
///
/// <para><b>Convention:</b> all entitlements use dot-separated lowercase
/// with the pattern <c>winsentinel.{category}.{action}</c>.</para>
///
/// <para>Adding new entitlements is a semver-minor change. Removing or
/// redefining an entitlement is a semver-major breaking change.</para>
///
/// Issue: #198
/// </summary>
public static class PluginEntitlements
{
    // ─── Audit Module ──────────────────────────────────────────────
    /// <summary>Permission to register a custom audit module.</summary>
    public const string AuditModule = "winsentinel.audit.module";

    /// <summary>Permission to access audit results from other modules.</summary>
    public const string AuditRead = "winsentinel.audit.read";

    // ─── Monitor ───────────────────────────────────────────────────
    /// <summary>Permission to register a real-time monitor daemon.</summary>
    public const string MonitorDaemon = "winsentinel.monitor.daemon";

    // ─── Reporting ─────────────────────────────────────────────────
    /// <summary>Permission to register a report export format.</summary>
    public const string ReportExporter = "winsentinel.report.exporter";

    // ─── Compliance ────────────────────────────────────────────────
    /// <summary>Permission to register a compliance mapper/profile.</summary>
    public const string ComplianceMapper = "winsentinel.compliance.mapper";

    // ─── Fleet / Remote ────────────────────────────────────────────
    /// <summary>Permission to register a fleet telemetry sink.</summary>
    public const string FleetSink = "winsentinel.fleet.sink";

    // ─── Scheduling ────────────────────────────────────────────────
    /// <summary>Permission to register scheduled scan logic.</summary>
    public const string ScheduledScan = "winsentinel.scan.scheduled";

    // ─── System Access (elevated) ──────────────────────────────────
    /// <summary>Permission to read the Windows registry.</summary>
    public const string SystemRegistryRead = "winsentinel.system.registry.read";

    /// <summary>Permission to write the Windows registry (remediation).</summary>
    public const string SystemRegistryWrite = "winsentinel.system.registry.write";

    /// <summary>Permission to execute shell commands.</summary>
    public const string SystemExec = "winsentinel.system.exec";

    /// <summary>Permission to access the filesystem beyond the plugin's own directory.</summary>
    public const string SystemFileAccess = "winsentinel.system.file";

    /// <summary>Permission to make outbound network connections.</summary>
    public const string SystemNetwork = "winsentinel.system.network";

    // ─── UI / Notification ─────────────────────────────────────────
    /// <summary>Permission to send toast / system notifications.</summary>
    public const string Notify = "winsentinel.ui.notify";

    // ─── Storage ───────────────────────────────────────────────────
    /// <summary>Permission to persist data in the WinSentinel SQLite database.</summary>
    public const string StorageDb = "winsentinel.storage.db";

    /// <summary>All known entitlements for validation/display purposes.</summary>
    public static readonly string[] All =
    [
        AuditModule,
        AuditRead,
        MonitorDaemon,
        ReportExporter,
        ComplianceMapper,
        FleetSink,
        ScheduledScan,
        SystemRegistryRead,
        SystemRegistryWrite,
        SystemExec,
        SystemFileAccess,
        SystemNetwork,
        Notify,
        StorageDb,
    ];

    /// <summary>
    /// Returns true if the given entitlement string is a recognized value.
    /// Unknown entitlements should be rejected at plugin load time.
    /// </summary>
    public static bool IsKnown(string? entitlement)
        => !string.IsNullOrWhiteSpace(entitlement) && Array.IndexOf(All, entitlement) >= 0;

    /// <summary>
    /// Entitlements that grant system-level access. Plugins requesting these
    /// should trigger an elevated trust prompt.
    /// </summary>
    public static readonly string[] Elevated =
    [
        SystemRegistryWrite,
        SystemExec,
        SystemFileAccess,
        SystemNetwork,
    ];

    /// <summary>Returns true if the entitlement is considered elevated/dangerous.</summary>
    public static bool IsElevated(string? entitlement)
        => !string.IsNullOrWhiteSpace(entitlement) && Array.IndexOf(Elevated, entitlement) >= 0;
}
