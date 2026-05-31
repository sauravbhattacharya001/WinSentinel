# Creating WinSentinel Plugins

WinSentinel supports community plugins for custom audit modules, report
formats, monitoring daemons, compliance mappers, and more. Write your own
security checks, share them with the community, or keep them private for
your org's specific compliance needs.

Plugins live in their own repos/directories and load at runtime. No license
or paid tier is required — plugin loading is unconditional for all users.

This document is for **plugin authors**.

## How trust works (read this first)

Each WinSentinel install keeps a list of trusted Ed25519 public keys in
`%LOCALAPPDATA%\WinSentinel\trusted-publishers.json`. A plugin DLL loads
only if all of these are true:

1. Its embedded `plugin.json` declares a `publisher_key` (Ed25519 pubkey, base64).
2. That key is in the user's trusted set (the official WinSentinel project
   key is pre-trusted in official builds).
3. The DLL bytes' SHA-256 verifies against `manifest.signature` under that key.

Unsigned plugins are rejected by default. Users can opt in to loading
unsigned DLLs (`winsentinel plugin trust --allow-unsigned`); WinSentinel
emits a warning on startup whenever the plugin directory contains at
least one `.dll` while that flag is set (and always when the user runs
`winsentinel plugin list` — the trust dashboard), so plan on shipping
a signed build for end users.

## Repo skeleton

```
my-winsentinel-plugin/
├── MyWinSentinelPlugin.csproj
├── MyPlugin.cs
└── plugin.json
```

`MyWinSentinelPlugin.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="WinSentinel.Core" Version="1.16.*" />
  </ItemGroup>
  <ItemGroup>
    <EmbeddedResource Include="plugin.json" />
  </ItemGroup>
</Project>
```

`MyPlugin.cs`:

```csharp
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using WinSentinel.Core.Models;
using WinSentinel.Core.Plugins;

public sealed class MyPlugin : IWinSentinelPlugin, IReportExporter
{
    public string FeatureId => "my-html-report";
    public string Version   => "1.0.0";
    public string Format    => "html";

    private IPluginContext? _ctx;
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExportAsync(SecurityReport report, Stream output, CancellationToken ct)
    {
        _ctx?.Log("Exporting HTML report…", PluginLogLevel.Info);
        using var writer = new StreamWriter(output, leaveOpen: true);
        await writer.WriteLineAsync("<html><body><h1>WinSentinel</h1></body></html>");
    }
}
```

Implement `IWinSentinelPlugin` plus any of:
`IReportExporter`, `IMonitorDaemon`, `IFleetSink`, `IComplianceMapper`,
`IScheduledScan`. Multiple plugin types can live in one DLL.

## `plugin.json`

```json
{
  "featureId": "my-html-report",
  "version": "1.0.0",
  "minCoreVersion": "1.16.0",
  "publisher_name": "Acme Plugins",
  "publisher_key": "BASE64_ED25519_PUBLIC_KEY",
  "requiredEntitlement": "",
  "signature": "BASE64_ED25519_SIGNATURE_OF_SHA256_OF_DLL"
}
```

Field reference:

- `publisher_name` — informational; displayed in `winsentinel plugin list`.
- `publisher_key` — your Ed25519 public key (base64, 32 bytes decoded). The
  trust anchor.
- `requiredEntitlement` — **deprecated / ignored.** Retained for backward
  compatibility with existing manifests but no longer checked at load time.
  All plugins load unconditionally regardless of this field.
- `signature` — see below.

## Signing

1. Generate your publisher keypair ONCE, using WinSentinel's offline tool:

   ```pwsh
   git clone https://github.com/sauravbhattacharya001/WinSentinel
   cd WinSentinel
   dotnet run --project tools/GenerateKeypair
   ```

   The tool prints `public:` and `private:`. Copy the **private** key into
   your password manager immediately. It is never written to disk.

2. Build your plugin DLL with a placeholder `signature` in `plugin.json`.

3. After build, compute the signature and rewrite `plugin.json` before
   shipping. Pseudocode:

   ```csharp
   var dllBytes = File.ReadAllBytes("bin/Release/net8.0/MyPlugin.dll");
   var hash     = SHA256.HashData(dllBytes);
   var sig      = Convert.ToBase64String(Ed25519Sign(privateKey, hash));
   // overwrite signature field in the embedded plugin.json and re-pack.
   ```

   Real pipelines do this in CI with the private key held in a hardware
   security module / KMS — never in plain text.

## Install (end-user instructions to put in your README)

```pwsh
# 1. Trust your publisher key once.
winsentinel plugin trust <BASE64_PUBKEY> --name "Acme Plugins"

# 2. Drop the signed DLL into the plugin directory.
copy MyPlugin.dll "$env:LOCALAPPDATA\WinSentinel\plugins\"

# 3. Verify.
winsentinel plugin list
```

Override the plugin directory with the `WINSENTINEL_PLUGIN_DIR` env var.

## Why this design

Three reasons it works this way:

- **Code isolation.** Plugins live in their own repos and load via a
  collectible `AssemblyLoadContext`. The OSS core has zero coupling to any
  specific plugin implementation, so it stays readable + auditable.
- **Community extensibility.** Anyone can write and distribute plugins
  (custom audit modules, report formats, compliance mappers) without
  modifying the core. No license or paid tier is required.
- **Closed-source plugins on an MIT core.** Multi-publisher signing lets
  3rd-party vendors ship proprietary plugins without the MIT license touching
  their code, and lets ops teams ship internal-only plugins behind a forked
  embedded pubkey.

## See also

- [`plugin-key-setup.md`](./plugin-key-setup.md) — the WinSentinel project's
  OWN signing key (only relevant if you're forking the product or building
  the official `winsentinel-pro` release).
- `scripts/check-no-pro-code.ps1` — the CI guard that keeps Pro code OUT of
  the core repo.
