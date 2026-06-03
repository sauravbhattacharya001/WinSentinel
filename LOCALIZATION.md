# Localization Guide

WinSentinel supports community-contributed translations via standard .NET resource files (`.resx`).

## Architecture

| Layer | Resource file | Namespace |
|-------|--------------|-----------|
| Core (audit findings, severity labels, compliance terms) | `WinSentinel.Core/Resources/Strings.resx` | `WinSentinel.Core.Resources.Strings` |
| CLI (user-facing messages, commands, prompts) | `WinSentinel.Cli/Resources/CliStrings.resx` | `WinSentinel.Cli.Resources.CliStrings` |

The `L` helper class (`WinSentinel.Core.Localization.L`) provides format-string access:

```csharp
using WinSentinel.Core.Localization;

// Simple lookup
var msg = L.Get("Severity_Critical"); // → "Critical"

// With format args
var msg = L.Get("Firewall_ProfileDisabled", "Public");
// → "Windows Firewall (Public profile) is disabled. ..."
```

## Adding a New Language

1. Copy `Strings.resx` to `Strings.<locale>.resx` (e.g., `Strings.de.resx` for German, `Strings.ja.resx` for Japanese).
2. Translate all `<value>` elements. Keep `{0}`, `{1}`, etc. placeholders in the same positions.
3. Do the same for `CliStrings.resx` → `CliStrings.<locale>.resx`.
4. Build. The .NET SDK automatically embeds satellite assemblies for each locale.
5. Submit a PR.

### Example: Adding Spanish (es)

```
src/WinSentinel.Core/Resources/Strings.es.resx
src/WinSentinel.Cli/Resources/CliStrings.es.resx
```

## Testing a Translation

Set the `DOTNET_SYSTEM_GLOBALIZATION_UICULTURE` environment variable:

```powershell
$env:DOTNET_SYSTEM_GLOBALIZATION_UICULTURE = "es"
winsentinel --audit
```

Or in code:

```csharp
using WinSentinel.Core.Localization;
L.Culture = new System.Globalization.CultureInfo("es");
```

## Guidelines for Translators

- **Keep format placeholders** (`{0}`, `{1}`, etc.) in the correct order for the target language.
- **Keep technical terms** untranslated when appropriate (e.g., "BitLocker", "SMBv1", "AMSI", "UAC").
- **Match severity** — if the English says "Critical", the translation should convey equivalent urgency.
- **Don't translate registry paths or commands** — these are Windows internals.
- Prefer formal register for security recommendations.

## Shipped Locales

| Locale | Status |
|--------|--------|
| `en-US` | ✅ Default (embedded in main `.resx`) |

Community translations welcome! Open an issue or PR to add your language.
