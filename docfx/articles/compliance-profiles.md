# Compliance Profiles

WinSentinel ships with four built-in compliance profiles that adapt security scoring to your environment. Different deployments have fundamentally different security requirements — a home laptop doesn't need the same controls as a PCI-DSS-regulated corporate workstation.

## How Profiles Work

When you apply a compliance profile, WinSentinel adjusts three things:

1. **Module weights** — Increases or decreases the importance of each audit module in the final score
2. **Severity overrides** — Reclassifies specific findings (e.g., SMB signing is Critical in enterprise but Info at home)
3. **Compliance threshold** — Sets the minimum score required to be considered "compliant"

The result is an **adjusted score** that reflects what actually matters for your environment.

## Built-in Profiles

### Home / Personal (`home`)

| Property | Value |
|----------|-------|
| **Threshold** | 60 |
| **Audience** | Home users, personal laptops, family computers |
| **Focus** | Basic hygiene: antivirus, firewall, updates |

**What changes:**
- Encryption weight reduced to 0.5× (BitLocker is uncommon at home)
- Event Log weight reduced to 0.3× (not relevant for personal use)
- Network/process modules de-emphasized
- Enterprise-only findings (SMB signing, LLMNR, audit policies) downgraded to Info
- Password expiration downgraded — NIST no longer recommends it for personal use

```powershell
winsentinel audit --profile home
```

### Developer Workstation (`developer`)

| Property | Value |
|----------|-------|
| **Threshold** | 70 |
| **Audience** | Software developers, DevOps engineers |
| **Focus** | Code protection, balanced security for dev workflows |

**What changes:**
- Encryption weight increased to 1.2× (protect source code and credentials)
- Browser security increased to 1.2× (devs browse many third-party sites)
- Process/startup modules relaxed (IDEs, Docker, webpack are expected)
- "Multiple Listening Services" downgraded to Info (local dev servers are normal)

```powershell
winsentinel audit --profile developer
```

### Enterprise / Corporate (`enterprise`)

| Property | Value |
|----------|-------|
| **Threshold** | 85 |
| **Audience** | Corporate workstations, managed endpoints |
| **Focus** | Full compliance: encryption, audit logging, network hardening |

**What changes:**
- Encryption weight increased to 1.5× — full disk encryption is required
- Event Log and Account Security both at 1.3× — audit logging is mandatory
- SMB signing, BitLocker, and audit policies elevated to **Critical**
- LLMNR enabled elevated to **Critical** (common lateral movement vector)
- Privacy/telemetry slightly de-emphasized vs. security controls

Suitable for environments subject to SOC 2, ISO 27001, or general corporate security policies.

```powershell
winsentinel audit --profile enterprise
```

### Server / Infrastructure (`server`)

| Property | Value |
|----------|-------|
| **Threshold** | 90 |
| **Audience** | Production servers, domain controllers, critical infrastructure |
| **Focus** | Maximum security, minimal attack surface |

**What changes:**
- Nearly all modules weighted at 1.3×–1.5×
- Browser security reduced to 0.3× (servers shouldn't have browsers)
- Privacy reduced to 0.5× (less relevant for servers)
- Multiple findings elevated to **Critical**: SMB signing, BitLocker, audit policies, LLMNR, NetBIOS, RDP, guest account, password policies
- Expects minimal services, full encryption, comprehensive logging

```powershell
winsentinel audit --profile server
```

## Profile Comparison

| Feature | Home | Developer | Enterprise | Server |
|---------|------|-----------|------------|--------|
| **Compliance Threshold** | 60 | 70 | 85 | 90 |
| **Encryption Emphasis** | Low (0.5×) | High (1.2×) | Critical (1.5×) | Critical (1.5×) |
| **Audit Logging** | Minimal (0.3×) | Low (0.5×) | Mandatory (1.3×) | Mandatory (1.5×) |
| **Network Hardening** | Relaxed (0.7×) | Moderate (0.8×) | Strict (1.2×) | Maximum (1.5×) |
| **BitLocker Required** | No | Recommended | **Critical** | **Critical** |
| **SMB Signing** | Info | Info | **Critical** | **Critical** |
| **LLMNR Disabled** | Info | Not overridden | **Critical** | **Critical** |
| **Severity Overrides** | 6 | 4 | 7 | 9 |

## Using Profiles

### CLI

```powershell
# Run audit with a specific profile
winsentinel audit --profile enterprise

# Compare your score across profiles
winsentinel audit --profile home
winsentinel audit --profile enterprise

# JSON output with compliance result
winsentinel audit --profile enterprise --format json --output compliance-report.json
```

### Programmatic (C#)

```csharp
using WinSentinel.Core.Services;

// Run audit
var scanner = new SecurityScanner();
var report = await scanner.RunFullAuditAsync();

// Apply compliance profile
var complianceService = new ComplianceProfileService();
var result = complianceService.ApplyProfile("enterprise", report);

Console.WriteLine($"Original Score: {result.OriginalScore} ({result.OriginalGrade})");
Console.WriteLine($"Adjusted Score: {result.AdjustedScore} ({result.AdjustedGrade})");
Console.WriteLine($"Compliant: {result.IsCompliant}");
Console.WriteLine($"Overrides Applied: {result.OverridesApplied}");
Console.WriteLine($"Modules Skipped: {result.ModulesSkipped}");

// Review applied overrides
foreach (var ov in result.AppliedOverrides)
{
    Console.WriteLine($"  {ov.FindingTitle}: {ov.OriginalSeverity} → {ov.NewSeverity} ({ov.Reason})");
}
```

### Understanding Results

A `ComplianceResult` includes:

| Field | Description |
|-------|-------------|
| `OriginalScore` | Raw security score before profile adjustments |
| `AdjustedScore` | Score after applying module weights and severity overrides |
| `IsCompliant` | Whether `AdjustedScore >= ComplianceThreshold` |
| `OverridesApplied` | Number of findings whose severity was changed |
| `ModulesSkipped` | Number of modules excluded by the profile |
| `ModuleScores` | Per-module breakdown with weights and override counts |
| `AppliedOverrides` | Details of every severity change made |
| `Recommendations` | Profile-specific security guidance |

## Custom Profiles

You can create custom compliance profiles by instantiating `ComplianceProfile` directly:

```csharp
var custom = new ComplianceProfile
{
    Name = "pci-dss",
    DisplayName = "PCI-DSS Workstation",
    Description = "Payment Card Industry Data Security Standard compliance",
    ComplianceThreshold = 90,
    ModuleWeights = new Dictionary<string, double>
    {
        ["Encryption"] = 2.0,           // Cardholder data protection
        ["Network Configuration"] = 1.5, // Network segmentation
        ["Account Security"] = 1.5,      // Access control
        ["Event Log"] = 1.5,             // Audit trails
    },
    SeverityOverrides = new Dictionary<string, SeverityOverride>
    {
        ["BitLocker Not Enabled"] = new(Severity.Critical, "PCI-DSS requires encryption of cardholder data at rest"),
    },
    Recommendations =
    [
        "Segment cardholder data environment from general network",
        "Implement file integrity monitoring on critical system files",
        "Retain audit logs for at least 12 months",
    ]
};
```

## Compliance Trend Tracking

WinSentinel can track compliance scores over time using the `ComplianceTrendTracker`. This lets you monitor drift, detect regressions, and demonstrate continuous compliance to auditors.

```powershell
# Run audit with trend tracking enabled
winsentinel audit --profile enterprise --track-trends
```

See the [API Reference](../api/index.md) for the full `ComplianceTrendTracker` API.
