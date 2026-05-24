# WinSentinel Roadmap

Living document. Items are ordered roughly by impact, not commitment.

---

## Plugin architecture — known limitations and follow-up work

The v1 plugin host ships with the trust + extension model documented in
`docs/CREATING-PLUGINS.md`. These items are the known kinks we deliberately
deferred. Capture-only here; promote to issues when ready to work on one.

### Priority — address before broad plugin marketplace launch

- [ ] **Fingerprint UX in `winsentinel plugin trust`.** Bare base64 pubkey is
      copy-paste-friendly for attackers. Display SHA-256 fingerprint
      (`F3:AB:CD:…` first 16 bytes) prominently, prompt user to verify out-of-band.
      Optionally ship a curated "verified publishers" JSON with the build.
- [ ] **Lock entitlement vocabulary now.** `requiredEntitlement` is a string.
      Decide convention for future tiers (`pro`, `pro-team`, `pro-enterprise`)
      or per-feature (`feature.pdf-export`). Document in `CREATING-PLUGINS.md`
      so plugin authors don't paint themselves into a corner.
- [ ] **Narrow `IPluginContext` per interface kind.** Today a single context
      surface risks over-exposing audit data and license internals.
      `IReportExporter` only needs `(report, output)`; `IFleetSink` only needs
      `report`; nobody should see `LicenseManager`. Split the context or use
      role-typed accessors.

### High value — v1.x

- [ ] **Plugin load audit log.** Append to `%LOCALAPPDATA%\WinSentinel\plugin-load.log`
      every load/skip/reject with timestamp, featureId, publisher fingerprint,
      and reason. Forensics + debugging.
- [ ] **Plugin config story.** Decide once how plugins read user config
      (env vars, JSON file under `%LOCALAPPDATA%\WinSentinel\plugins-config\<featureId>.json`,
      or `IPluginContext.GetConfig(...)`). Document.
- [ ] **Machine-wide plugin directory.** Currently only scans `%LOCALAPPDATA%`
      (per-user). Add `%PROGRAMDATA%\WinSentinel\plugins\` for IT-deployed
      org-internal plugins. Document precedence.
- [ ] **Plugin ABI semver.** Extract plugin interfaces into a separate
      `WinSentinel.Plugin.Abi` NuGet package with strict semver, so core can
      evolve without silently breaking older plugins. Add `maxCoreVersion`
      to manifest until ABI package is ready.
- [ ] **Publisher revocation list.** When a publisher privkey leaks, every
      install in the wild keeps trusting forever. Ship a CRL distributed via
      WinSentinel auto-updates; PluginHost checks before loading.
- [ ] **Naughty-plugin test fixtures.** Cover misbehaving plugins:
      throws in `Initialize`, hangs in `ExportAsync`, loads conflicting
      DLL versions, exfils data. Today's tests only cover happy paths +
      signature/entitlement rejection.

### Bigger investments — v2

- [ ] **Out-of-process plugin host.** Real sandbox via separate process
      with named-pipe IPC and capability tokens. Today plugins run in-process
      with full CLR trust — a malicious or buggy plugin can read everything,
      crash the host, or reflectively replace BCL types. The biggest single
      security improvement we could make.
- [ ] **Capability declarations.** Manifest declares
      `requires: [filesystem_write, network, ...]`. Host enforces at load
      and at API-call time (refuses to satisfy undeclared capabilities).
      Inspired by Deno, Wasmer, Tauri permission models.
- [ ] **`winsentinel plugin search` + registry.** Static GitHub-Pages-hosted
      JSON of curated plugins so users don't have to google. First step
      toward a marketplace. Could be community-maintained, pull-request based.
- [ ] **`winsentinel plugin install <url>`.** End-to-end install flow:
      download, display fingerprint, prompt to trust publisher, install DLL.
      Beyond power-user adoption requires this.
- [ ] **Per-(publisher, featureId) trust pinning.** Trusting Acme's key today
      means trusting every future Acme plugin. Optional fine-grained pinning
      so each new plugin from a known publisher requires explicit re-trust.

### Architectural caveats (document, don't fix)

- **Plugin unloading is best-effort, not guaranteed.** `AssemblyLoadContext`
  collectibility breaks the moment a plugin object is referenced anywhere in
  core. Either don't promise unloading in the public docs, or enforce that
  plugins return POCOs only (no live references survive a plugin call).
  Until decided, treat plugin replacement as "restart required" in docs.
- **Plugin → plugin interaction is undefined and unsupported.** Composition
  only via core's interfaces. If two plugins want to talk to each other,
  that's a core API extension request.
- **`fork-and-embed-your-own-key` path is advanced-only.** Most org-internal
  use cases should ship the official build + run `winsentinel plugin trust
  <our-pubkey>` during onboarding. Make sure that path is bulletproof and
  well-documented. Don't market the fork path as primary.

---

## Release prep — blocks first end-to-end Pro plugin test

These are the gating items between today's state and "user installs official
WinSentinel build, sideloads a signed Pro plugin DLL, runs `winsentinel audit
--format pdf`, gets a PDF." Tracked separately because they're release
logistics, not architecture.

- [ ] **Tag v1.17.0 release once plugin-arch lands on main.** Existing NuGet
      publish workflow handles packaging; needs version bump + release tag.
- [ ] **Generate official Ed25519 publisher keypair.** Run
      `dotnet run --project tools/GenerateKeypair`. Privkey → password manager.
      Pubkey → replace `REPLACE_ME_PRODUCTION_ED25519_PUBLIC_KEY_BASE64` in
      `LicenseManager.OfficialPublisherPublicKeyBase64`. Re-release as v1.17.1
      (embedded pubkey changes the binary).
- [ ] **`tools/SignPlugin` helper.** GenerateKeypair exists but no signing
      helper. Add `dotnet run --project tools/SignPlugin -- <dll> <privkey-file>`
      that emits the base64 signature + writes the updated `plugin.json`.
      Required so plugin authors (including us shipping winsentinel-pro) can
      sign DLLs without writing C# every time.
- [ ] **Dev-mode license helper / test license issuance.**
      `LicenseManager.Activate` validates against an embedded license-signing
      pubkey. For testing without standing up Stripe → issuer pipeline:
      either (a) add `--allow-test-license` dev flag that accepts any
      well-formed envelope, or (b) ship a `tools/IssueTestLicense` helper
      that signs envelopes with a dev privkey. Pick one, ship it.
- [ ] **Confirm plugin interfaces are public in WinSentinel.Core NuGet.**
      `IWinSentinelPlugin`, `IReportExporter`, etc. must be public-visible so
      external plugin projects (winsentinel-pro, third-parties) can reference
      them via `dotnet add package WinSentinel.Core`. Verify after v1.17.0
      pack; fix if internal.
- [ ] **Stand up `winsentinel-pro` private repo.** Minimal scaffold:
      net8.0 classlib, references plugin interfaces, implements one Pro
      feature (PDF report exporter is a good first one — small, visible,
      easy to verify). Embedded `plugin.json` with `requiredEntitlement="pro"`.
      GitHub Actions workflow that builds → signs with privkey from repo
      secret → publishes signed DLL + manifest as a Release artifact.
- [ ] **End-to-end install test (manual, one-time).**
      `dotnet tool install -g WinSentinel.Cli` → `winsentinel pro activate
      --key <test-key>` → drop signed Pro DLL into `%LOCALAPPDATA%\WinSentinel\plugins\`
      → `winsentinel plugin list` shows it loaded → `winsentinel audit
      --format pdf --output report.pdf` produces a PDF. Document the steps
      in `docs/QUICKSTART-PRO.md` once the loop is verified.

---

## Non-plugin items

(Add other roadmap items as they come up. Keep this file curated, not a dumping ground.)
