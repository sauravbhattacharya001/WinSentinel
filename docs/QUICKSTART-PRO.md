# QUICKSTART: WinSentinel Pro Plugin

End-to-end guide for installing and using a Pro plugin on a fresh machine.

## Prerequisites

- Windows 10/11 (x64)
- .NET 8 SDK installed
- WinSentinel CLI ≥ v1.17.0

## 1. Install WinSentinel CLI

```bash
dotnet tool install -g WinSentinel.Cli
winsentinel --version
# → WinSentinel 1.17.x
```

## 2. Activate a License

### Option A: Start a free trial

```bash
winsentinel pro start-trial --email you@example.com
winsentinel pro status
# → Pro trial active, 14 days remaining.
```

### Option B: Activate with a purchased key

```bash
winsentinel pro activate WSP-XXXX-XXXX-XXXX --email you@example.com
winsentinel pro status
# → Pro individual active, 365 days remaining.
```

### Option C: Dev-mode test license (CI/testing only)

```bash
# Generate a test license
set WINSENTINEL_DEV_MODE=1
dotnet run --project tools/IssueTestLicense -- --tier individual --days 30 --output %APPDATA%\WinSentinel\license.json

# Verify
winsentinel pro status
# → Pro individual active, 30 days remaining.
```

## 3. Install the Pro PDF Plugin

### From a URL (e.g., GitHub Releases)

```bash
winsentinel plugin install https://github.com/sauravbhattacharya001/winsentinel-pro/releases/download/v1.0.0/WinSentinel.Pro.Pdf.dll
```

The CLI will:
1. Download the DLL
2. Read the embedded `plugin.json`
3. Display the publisher fingerprint
4. Prompt you to trust the publisher (if not already trusted)
5. Verify the Ed25519 signature
6. Copy to `%LOCALAPPDATA%\WinSentinel\plugins\`

### From a local file

```bash
winsentinel plugin install C:\path\to\WinSentinel.Pro.Pdf.dll
```

## 4. Verify Plugin Loaded

```bash
winsentinel plugin list
```

Expected output:
```
Plugin directory: C:\Users\you\AppData\Local\WinSentinel\plugins
allow_unsigned:   False

Trusted publishers:
  - WinSentinel (official) [official]
      key:         k7nKP5Ea…7cA=
      fingerprint: SHA256:ab:cd:ef:12:34:56:78:9a

Plugins:
  [Loaded] WinSentinel.Pro.Pdf.dll
      feature:   winsentinel-pro-pdf v1.0.0
      publisher: WinSentinel (official)  k7nKP5Ea…7cA=
      detail:    loaded 1 type(s)
```

## 5. Generate a PDF Report

```bash
winsentinel audit --format pdf --output report.pdf
```

Opens `report.pdf` — your security audit in a professional PDF format.

## 6. Search the Plugin Registry

```bash
# List all available plugins
winsentinel plugin search

# Search by keyword
winsentinel plugin search pdf

# Show details for a specific plugin
winsentinel plugin show winsentinel-pro-pdf
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `plugin is unsigned and allow_unsigned=false` | Download from official source, or enable dev mode: `winsentinel plugin trust --allow-unsigned` |
| `publisher 'X' is not trusted` | Run `winsentinel plugin trust <pubkey> --name <name>` with the key shown in the error |
| `current license does not cover entitlement 'pro'` | Activate a license: `winsentinel pro activate ...` or start trial |
| `signature does not match DLL hash` | DLL may be corrupted/tampered — re-download from official source |

## Security Model

- Plugins are Ed25519-signed by their publisher
- Each install verifies signature against SHA-256(dll bytes)
- Publisher keys must be explicitly trusted via `winsentinel plugin trust`
- Optional pinning: `winsentinel plugin trust --pin <pubkey> <featureId>` restricts a publisher to specific plugins
- Unsigned plugins are rejected by default (enable with `--allow-unsigned` for dev only)
