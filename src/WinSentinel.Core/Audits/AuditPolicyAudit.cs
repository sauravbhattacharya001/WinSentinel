using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces this machine's <b>Advanced Audit Policy</b> in a live
/// <c>--audit</c> run: whether the security-relevant audit subcategories (Logon,
/// Credential Validation, Process Creation, Audit Policy Change, User Account
/// Management) are actually recording the Success/Failure events that any
/// investigation - and <see cref="EventLogAudit"/> itself - depends on. A host can
/// be well configured yet forensically blind if these subcategories are set to
/// "No Auditing".
///
/// <para>This is the thin I/O layer for <see cref="AuditPolicyAnalyzer"/>: it shells
/// out to <c>auditpol /get /category:* /r</c> (the CSV report form) and delegates
/// every pass/fail decision to the pure, unit-tested analyzer (collector owns I/O,
/// analyzer owns decisions - the same split as
/// <see cref="DiagnosticsHardeningAudit"/> / <see cref="DiagnosticsHardeningAnalyzer"/>).
/// It reads only the local audit policy of this host, so it is single-machine and
/// therefore FREE / OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class AuditPolicyAudit : AuditModuleBase
{
    public override string Name => "Audit Policy Audit";
    public override string Category => AuditPolicyAnalyzer.Category;
    public override string Description =>
        "Checks this machine's advanced audit policy - whether the security-relevant subcategories (Logon, " +
        "Credential Validation, Process Creation, Audit Policy Change, User Account Management) are recording " +
        "the Success/Failure events an investigation relies on. Auditing turned off here leaves the host " +
        "forensically blind even when everything else is hardened.";

    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        // /r emits the machine-readable CSV report (header + one row per subcategory).
        var csv = await ShellHelper.RunCmdAsync("auditpol /get /category:* /r", QueryTimeout, cancellationToken)
            .ConfigureAwait(false);

        var state = AuditPolicyAnalyzer.ParseAuditpolCsv(csv);
        foreach (var finding in AuditPolicyAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }
}
