# Plugin Signing Key Setup (WinSentinel project)

**Audience:** the WinSentinel founder. This is a one-time founder runbook for
generating the official **WinSentinel project** Ed25519 keypair — the key used
to sign the official `winsentinel-pro` plugin. Third-party publishers have
their own keys; see [`CREATING-PLUGINS.md`](./CREATING-PLUGINS.md).

## The two roles of an Ed25519 key

WinSentinel uses a **multi-publisher** trust model. Each WinSentinel install
maintains a list of trusted Ed25519 public keys in
`%LOCALAPPDATA%\WinSentinel\trusted-publishers.json`. A plugin DLL loads only
when its embedded `publisher_key` is in that list AND the manifest signature
verifies under that key.

This document is about ONE specific key in that list: the **official
WinSentinel project publisher key**, embedded in
`LicenseManager.OfficialPublisherPublicKeyBase64`. That constant decides
which plugins THIS BUILD auto-trusts out of the box. The official build
embeds the WinSentinel project's pubkey → only `winsentinel-pro` is
auto-trusted by default. If you fork WinSentinel and embed your own
pubkey instead, only YOUR signed plugins are auto-trusted — that's the
intended path for org-internal, closed-source plugin shops that don't want
their users to run `winsentinel plugin trust` manually.

> Recommended for everyone else: **leave the official key in place** and
> publish your own plugins with their own keys. Users add your key once via
> `winsentinel plugin trust <pubkey> --name "<your org>"`. This keeps the
> trust set explicit and auditable on the user's machine.

## Threat model

The private key of the WinSentinel project publisher key is the root of
trust for users who installed an official build and never touched their
`trusted-publishers.json`. An attacker with this private key can sign
arbitrary DLLs that vanilla installs will load and run with full process
privileges. Treat the private key like an EV code-signing key:
hardware-isolated, offline, never co-located with anything that touches
the public internet during signing.

## One-time generation

Run the offline tool from a clean machine:

```pwsh
dotnet run --project tools/GenerateKeypair
```

Output:

```
public:  <base64...>
private: <base64...>
```

The tool **never writes to disk**. It runs once, prints, and exits.

## Storage rules

- The **private key** goes into a password manager (1Password, Bitwarden,
  KeePass) IMMEDIATELY. Treat it like a root CA private key.
- DO NOT paste the private key into:
  - this repo (or any repo)
  - any chat / status / runs file
  - issue trackers, screen shares, screenshots, cloud notes
  - shell history / `Get-History` / `~/.bash_history`
- DO NOT keep the private key on the build machine longer than the
  signing session.
- If you lose the private key, there is no recovery — you'd ship a new
  version of the product that embeds a new pubkey.

## Embedding the public key

Replace the placeholder in
`src/WinSentinel.Core/Licensing/LicenseManager.cs`:

```csharp
public const string OfficialPublisherPublicKeyBase64 =
    "<your base64 public key>";
```

Commit, tag, release. From that release on, official-built installs will
auto-trust your project publisher key — `TrustedPublisherStore.Load()`
merges it into the in-memory trusted set at startup as
`auto_trusted: true`.

## Future signing pipeline (winsentinel-pro CI)

Sketch only:

1. Pro plugin CI builds `WinSentinelPro.dll`.
2. A protected CI step computes `sha256(dll)` and signs it with the
   project private key (pulled from a hardware-isolated secret store —
   e.g. GitHub Actions OIDC → AWS KMS hold-only-the-key model).
3. The resulting base64 signature is written into the DLL's embedded
   `plugin.json` along with `publisher_key` = official pubkey.
4. The signed DLL is published as a release artifact.
5. Users install by dropping it in `%LOCALAPPDATA%\WinSentinel\plugins\`.

CI never sees the raw private key — only signing operations through the
KMS interface. If the KMS credentials leak, rotate the key (which means
shipping a new product release that embeds the rotated pubkey).
