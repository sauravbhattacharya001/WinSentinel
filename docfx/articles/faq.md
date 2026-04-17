# Frequently Asked Questions

## Installation & Setup

### Do I need administrator privileges to run WinSentinel?

Yes. Most audit modules inspect Windows security settings (Defender status, firewall rules, update policies) that require elevated access. Run `winsentinel` from an Administrator PowerShell or install the Windows Service, which runs as `LocalSystem` by default.

### Which Windows versions are supported?

WinSentinel targets **.NET 8.0 on Windows 10 (1903+) and Windows 11**. Server editions (2019, 2022) are also supported. Older Windows versions lack the required WMI/CIM classes and may produce incomplete audit results.

### Can I run WinSentinel on Windows Server Core?

Yes. The CLI and Service projects work on Server Core. The WPF-based `WinSentinel.App` desktop UI requires Desktop Experience. Use `WinSentinel.Cli` or the agent service for headless environments.

---

## Audit & Scoring

### What does the security score mean?

The score ranges from **0 to 100** and maps to letter grades:

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | A | Excellent — meets or exceeds most compliance benchmarks |
| 80–89 | B | Good — minor gaps, low risk |
| 70–79 | C | Fair — several findings that should be addressed |
| 60–69 | D | Poor — significant security gaps |
| 0–59 | F | Critical — immediate attention required |

Each audit module contributes a weighted portion based on the active compliance profile.

### Why does my score change between runs?

Scores reflect the *current* state of the machine. Windows Update status, Defender signature freshness, and network exposure all change over time. A score drop usually means a new update is available or a setting reverted (e.g., after a Windows feature update).

### How do I ignore a specific finding?

Add the finding ID to the `suppressions` array in your configuration file:

```json
{
  "suppressions": ["WS-FW-003", "WS-DEF-007"]
}
```

Suppressed findings still appear in verbose output but don't affect the score.

---

## Agent & Monitoring

### What's the difference between a one-shot audit and the agent?

- **One-shot** (`winsentinel audit`): Runs all modules once, prints results, and exits. Good for CI/CD pipelines and manual checks.
- **Agent** (`winsentinel agent start` or the Windows Service): Runs continuously, watching file integrity changes, event log entries, and scheduled re-audits. Fires alerts via the configured notification channel.

### How much CPU/memory does the agent use?

The agent is designed to be lightweight:
- **Idle**: ~15–30 MB RAM, near-zero CPU
- **During audit**: Brief spike to 50–100 MB, typically <5 seconds per full audit cycle
- **File watcher**: Adds ~5–10 MB depending on the number of watched directories

### Can I limit which directories the file integrity monitor watches?

Yes. Configure `fileIntegrity.paths` in your settings to scope monitoring to specific directories. Avoid watching very large trees (e.g., `C:\`) as it will increase resource usage.

---

## Compliance Profiles

### Which compliance frameworks are supported out of the box?

- **CIS** — Center for Internet Security Windows benchmarks
- **HIPAA** — Health Insurance Portability and Accountability Act technical safeguards
- **PCI-DSS** — Payment Card Industry Data Security Standard
- **SOC2** — Service Organization Control Type 2

You can also create custom profiles. See [Compliance Profiles](compliance-profiles.md) for details.

### Can I combine multiple compliance profiles?

Not directly. Each audit run uses one profile. However, you can run multiple audits with different profiles and compare results. A common pattern is to use a custom profile that merges requirements from multiple standards.

---

## Troubleshooting

### "Access Denied" errors during audit

Ensure you're running as Administrator. If using the Windows Service, verify the service account has the necessary permissions. Some audit modules also require specific group policy permissions — see [Troubleshooting](troubleshooting.md).

### Audit module shows "Skipped" status

A module is skipped when its prerequisites aren't met (e.g., the Windows Defender module skips if a third-party antivirus is the primary provider). Check the `reason` field in the JSON output for details.

### Agent won't start as a Windows Service

1. Verify .NET 8.0 runtime is installed: `dotnet --list-runtimes`
2. Check Windows Event Log → Application for error details
3. Ensure the service executable path is correct: `sc qc WinSentinel`
4. Try running the agent interactively first to catch configuration errors: `winsentinel agent start --foreground`
