using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine <b>Windows Recall</b> exposure in a
/// live <c>--audit</c> run: whether Recall snapshotting is disabled by policy
/// (<c>DisableAIDataAnalysis</c>), whether Recall is blocked from ever being
/// enabled (<c>AllowRecallEnablement</c>), and whether a Recall snapshot store
/// already exists on disk (captured screen content at rest).
///
/// <para>Windows Recall periodically captures full-screen snapshots into a local,
/// searchable database - effectively "screenshots of everything you did" - which
/// can include passwords, tokens, private messages and documents readable by
/// anyone with access to the profile. On a machine handling sensitive data this
/// is a real local data-exposure risk, which is why the hardened posture is to
/// keep it off by policy and to know if a snapshot store is already present.</para>
///
/// <para>This is the thin I/O layer for <see cref="WindowsRecallAnalyzer"/>: it
/// owns the reading of the HKLM <c>Policies\Microsoft\Windows\WindowsAI</c>
/// registry values and the best-effort filesystem probe for the snapshot store,
/// and delegates every pass/fail decision to the pure, unit-tested analyzer
/// (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="ScreenLockAudit"/> / <see cref="ScreenLockAnalyzer"/>). It reads
/// only local machine / current-user state, so it is single-machine and therefore
/// FREE / OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class WindowsRecallAudit : AuditModuleBase
{
    public override string Name => "Windows Recall Audit";
    public override string Category => WindowsRecallAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows Recall exposure - whether Recall snapshotting is disabled by policy " +
        "(DisableAIDataAnalysis), whether Recall is blocked from being enabled (AllowRecallEnablement), and " +
        "whether a Recall snapshot store already exists on disk - to reduce local screen-capture data exposure " +
        "that can include passwords, tokens and private data.";

    private const string WindowsAiPolicySubKey = @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in WindowsRecallAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local Windows Recall policy/registry state and probe for an on-disk snapshot store into the
    /// pure <see cref="WindowsRecallState"/>. Each policy value is a best-effort registry read whose
    /// absence maps to null so the analyzer applies the documented default semantics (Recall not disabled
    /// by policy = a Warning), never a false pass. The snapshot-store presence is a best-effort filesystem
    /// probe that never throws.
    /// </summary>
    internal static WindowsRecallState CollectState()
    {
        return new WindowsRecallState
        {
            DisableAiDataAnalysis = ReadDword(RegistryHive.LocalMachine, WindowsAiPolicySubKey, "DisableAIDataAnalysis"),
            AllowRecallEnablement = ReadDword(RegistryHive.LocalMachine, WindowsAiPolicySubKey, "AllowRecallEnablement"),
            SnapshotStorePresent = SnapshotStoreExists(),
        };
    }

    /// <summary>Best-effort read of a REG_DWORD as an int; null when missing/unreadable. Tolerates
    /// values stored as REG_SZ ("0"/"1") as well as REG_DWORD.</summary>
    private static int? ReadDword(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(hive, subKey, valueName, null);
            if (raw is null) return null;
            return raw is int i ? i : (int.TryParse(raw.ToString(), out var parsed) ? parsed : (int?)null);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Best-effort probe for a Recall snapshot store under the current user's local app data. Recall
    /// stores its snapshot database under <c>%LOCALAPPDATA%\CoreAIPlatform.*\UKP</c>; the presence of any
    /// such directory means captured screen content may exist at rest. Never throws - any I/O failure
    /// (permission, missing base dir) is treated as "not present" so the audit degrades to a safe default.
    /// </summary>
    private static bool SnapshotStoreExists()
    {
        try
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(localAppData) || !Directory.Exists(localAppData))
            {
                return false;
            }

            // The store lives under a CoreAIPlatform.<build> directory; match the family with a wildcard.
            foreach (var platformDir in Directory.EnumerateDirectories(localAppData, "CoreAIPlatform.*"))
            {
                var ukp = Path.Combine(platformDir, "UKP");
                if (Directory.Exists(ukp))
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }
}
