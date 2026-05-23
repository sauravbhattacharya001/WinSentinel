using System.Text.Json;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.DllSearchOrderHijackAdvisor;

namespace WinSentinel.Tests;

public class DllSearchOrderHijackAdvisorTests
{
    private static readonly DateTime Now = new DateTime(2026, 5, 23, 16, 0, 0, DateTimeKind.Utc);

    private static AdvisorContext Ctx(RiskAppetite risk = RiskAppetite.Balanced) =>
        new AdvisorContext { Risk = risk, NowOverride = Now };

    private static ModuleLoad Mod(
        string name = "mylib.dll",
        ModuleSource source = ModuleSource.System32,
        bool signed = true,
        bool signerTrusted = true,
        bool writableParent = false,
        bool shadowsSystem32 = false,
        bool phantom = false,
        string? fullPath = null) =>
        new ModuleLoad(
            ModuleName: name,
            FullPath: fullPath ?? $"C:\\Windows\\System32\\{name}",
            Source: source,
            IsSigned: signed,
            SignerTrusted: signerTrusted,
            ParentDirWritableByNonAdmin: writableParent,
            ShadowsSystem32Name: shadowsSystem32,
            AppDirSatisfiedPhantom: phantom);

    private static ProcessSnapshot Proc(
        string name = "app.exe",
        int pid = 1234,
        bool highPriv = false,
        bool autoStart = false,
        params ModuleLoad[] modules) =>
        new ProcessSnapshot(
            ProcessName: name,
            Pid: pid,
            ImagePath: $"C:\\Program Files\\App\\{name}",
            RunsAsHighPrivilege: highPriv,
            AutoStart: autoStart,
            LoadedModules: modules.Length == 0
                ? new List<ModuleLoad> { Mod("kernel32.dll") }
                : modules.ToList());

    [Fact]
    public void EmptyInput_NoDataGradeA()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var r = adv.Analyze(Array.Empty<ProcessSnapshot>(), Ctx());
        Assert.Equal(0, r.TotalProcesses);
        Assert.Equal("NO_DATA", r.Verdict);
        Assert.Equal("A", r.Grade);
        Assert.Single(r.Playbook);
        Assert.Equal(ActionPriority.P3, r.Playbook[0].Priority);
    }

    [Fact]
    public void HealthyFleet_GradeA()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var r = adv.Analyze(new[] { Proc("clean.exe", 1, false, false, Mod("ntdll.dll"), Mod("user32.dll")) }, Ctx());
        Assert.Equal("A", r.Grade);
        Assert.Equal("HEALTHY", r.Verdict);
        Assert.All(r.Assessments, a => Assert.Equal(ProcessVerdict.Healthy, a.Verdict));
    }

    [Fact]
    public void SystemDllNameCollision_ForcesGradeF()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var bad = Mod("user32.dll",
            source: ModuleSource.ApplicationDir,
            signed: false,
            signerTrusted: false,
            shadowsSystem32: true,
            fullPath: "C:\\Apps\\evil\\user32.dll");
        var r = adv.Analyze(new[] { Proc("victim.exe", 22, true, true, bad) }, Ctx());
        Assert.Equal("F", r.Grade);
        Assert.Equal("DLL_HIJACK_ABUSE_SUSPECTED", r.Verdict);
        var a = r.Assessments.Single();
        Assert.Equal(ProcessVerdict.QuarantineProcess, a.Verdict);
        Assert.Contains("SHADOWS_SYSTEM32_NAME", a.Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "QUARANTINE_SYSTEM32_NAME_COLLISIONS");
    }

    [Fact]
    public void PhantomDll_InPrivilegedProcess_ForcesF()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var phantom = Mod("wlbsctrl.dll",
            source: ModuleSource.ApplicationDir,
            signed: false,
            signerTrusted: false,
            writableParent: true,
            phantom: true,
            fullPath: "C:\\Users\\Public\\App\\wlbsctrl.dll");
        var r = adv.Analyze(new[] { Proc("svc.exe", 4, true, true, phantom) }, Ctx());
        Assert.Equal("F", r.Grade);
        var a = r.Assessments.Single();
        Assert.Contains("PHANTOM_DLL_SATISFIED_FROM_APPDIR", a.Reasons);
        Assert.Contains("LOAD_FROM_WRITABLE_PARENT", a.Reasons);
        Assert.Contains("AUTO_START_HIJACK_RISK", a.Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "REMOVE_PHANTOM_DLL_HIJACKS");
        Assert.Contains(r.Playbook, p => p.Id == "TIGHTEN_WRITABLE_APPLICATION_DIRECTORIES");
    }

    [Fact]
    public void CurrentDirectorySideload_FlaggedAndPlaybooked()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var sl = Mod("plugin.dll",
            source: ModuleSource.CurrentDirectory,
            signed: true,
            signerTrusted: true);
        var r = adv.Analyze(new[] { Proc("cli.exe", 99, false, false, sl) }, Ctx());
        Assert.Contains(r.Playbook, p => p.Id == "DISABLE_CURRENT_DIRECTORY_SEARCH");
        Assert.Contains("SIDELOAD_FROM_CURRENT_DIRECTORY",
            r.Assessments.Single().Reasons);
    }

    [Fact]
    public void KnownHijackTarget_OutsideSystem32_Flagged()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var ver = Mod("version.dll",
            source: ModuleSource.ApplicationDir,
            signed: true,
            signerTrusted: true,
            fullPath: "C:\\Program Files\\App\\version.dll");
        var r = adv.Analyze(new[] { Proc("app.exe", 50, false, false, ver) }, Ctx());
        Assert.Contains("KNOWN_HIJACK_TARGET", r.Assessments.Single().Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "REPLACE_KNOWN_HIJACK_TARGETS");
    }

    [Fact]
    public void UnsignedInPrivilegedProcess_Playbooked()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var u = Mod("custom.dll",
            source: ModuleSource.ApplicationDir,
            signed: false,
            signerTrusted: false);
        var r = adv.Analyze(new[] { Proc("daemon.exe", 7, true, false, u) }, Ctx());
        Assert.Contains(r.Playbook, p => p.Id == "BLOCK_UNSIGNED_IN_PRIVILEGED_PROCESSES");
        Assert.Contains("UNSIGNED_DLL_IN_PRIVILEGED_PROCESS",
            r.Assessments.Single().Reasons);
    }

    [Fact]
    public void UntrustedSigner_Playbooked()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var u1 = Mod("plug1.dll", source: ModuleSource.ApplicationDir,
            signed: true, signerTrusted: false);
        var u2 = Mod("plug2.dll", source: ModuleSource.ApplicationDir,
            signed: true, signerTrusted: false);
        var r = adv.Analyze(new[]
        {
            Proc("a.exe", 1, false, false, u1),
            Proc("b.exe", 2, false, false, u2),
        }, Ctx());
        Assert.Contains(r.Playbook, p => p.Id == "REVIEW_UNTRUSTED_SIGNERS");
        Assert.Contains(r.Insights, i => i.StartsWith("UNTRUSTED_SIGNER_CLUSTER"));
    }

    [Fact]
    public void CautiousAddsAuditWhenGradePoor()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var u = Mod("custom.dll", source: ModuleSource.ApplicationDir,
            signed: false, signerTrusted: false);
        var r = adv.Analyze(new[] { Proc("daemon.exe", 7, true, false, u) }, Ctx(RiskAppetite.Cautious));
        Assert.Contains(r.Playbook, p => p.Id == "SCHEDULE_DLL_LOAD_AUDIT");
    }

    [Fact]
    public void AggressiveTrimsHealthyFiller()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var ver = Mod("version.dll",
            source: ModuleSource.ApplicationDir,
            signed: true,
            signerTrusted: true);
        var r = adv.Analyze(new[] { Proc("app.exe", 50, false, false, ver) }, Ctx(RiskAppetite.Aggressive));
        Assert.DoesNotContain(r.Playbook, p => p.Id == "ALL_PROCESSES_HEALTHY");
    }

    [Fact]
    public void ToJson_ContainsSchemaKeys()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var r = adv.Analyze(new[] { Proc("clean.exe", 1, false, false, Mod("kernel32.dll")) }, Ctx());
        var json = adv.ToJson(r);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        foreach (var key in new[] { "TotalProcesses", "Verdict", "Grade",
                                    "Assessments", "Playbook", "Insights" })
        {
            Assert.True(root.TryGetProperty(key, out _), $"missing {key}");
        }
    }

    [Fact]
    public void ToMarkdown_NonEmpty()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var r = adv.Analyze(new[] { Proc("clean.exe", 1, false, false, Mod("ntdll.dll")) }, Ctx());
        var md = adv.ToMarkdown(r);
        Assert.Contains("# DLL Search Order Hijack Report", md);
        Assert.Contains("## Processes", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
    }

    [Fact]
    public void ExtraHijackTargets_Honoured()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var custom = Mod("mycorp.dll", source: ModuleSource.ApplicationDir,
            signed: true, signerTrusted: true);
        var ctx = new AdvisorContext
        {
            NowOverride = Now,
            ExtraHijackTargets = new[] { "mycorp.dll" },
        };
        var r = adv.Analyze(new[] { Proc("app.exe", 1, false, false, custom) }, ctx);
        Assert.Contains("KNOWN_HIJACK_TARGET", r.Assessments.Single().Reasons);
    }

    [Fact]
    public void InputsNotMutated()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        var modules = new List<ModuleLoad> { Mod("kernel32.dll") };
        var procs = new List<ProcessSnapshot>
        {
            new ProcessSnapshot("a.exe", 1, "C:\\a.exe", false, false, modules),
        };
        adv.Analyze(procs, Ctx());
        Assert.Single(procs);
        Assert.Single(procs[0].LoadedModules);
    }

    [Fact]
    public void NullInput_Throws()
    {
        var adv = new DllSearchOrderHijackAdvisor();
        Assert.Throws<ArgumentNullException>(() => adv.Analyze(null!, Ctx()));
    }
}
