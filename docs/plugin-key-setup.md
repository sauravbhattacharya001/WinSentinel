# Plugin signing key — setup runbook

> **Audience:** the founder (or whoever owns the WinSentinel commercial
> release). Everyone else can ignore this file.
>
> **Status:** the production Ed25519 public key has **not** been generated
> yet. While the placeholder `REPLACE_ME_PRODUCTION_ED25519_PUBLIC_KEY_BASE64`
> is still embedded in the source, `PluginHost.LoadAll()` returns 0 and
> `LicenseVerifier.IsActivated` is always `false`. The free CLI works
> exactly as it does today; this is the safe default.

## Threat model

The private signing key is the single root of trust for the entire Pro
ecosystem:

- Anyone holding it can mint plugin DLLs that the official client will
  load with full reflection access.
- Anyone holding it can issue licenses that unlock paid entitlements.

Therefore:

- **The private key never lives in any git repository.** Not this one,
  not `winsentinel-pro`, not a gist, not a Slack message.
- **The private key never lives on a developer laptop in plaintext
  beyond the few seconds of initial generation.** Move it straight into
  a password manager.
- **The private key is never pasted into a chat or an LLM transcript.**

## One-time generation

Pick **one** of these two methods. Both produce the same kind of key — a
raw 32-byte Ed25519 keypair, base64-encoded.

### Option A — small dotnet tool (recommended)

A throwaway `tools/GenerateKeypair` project ships with this repo. It
prints both halves to stdout and exits without writing anything to disk.

```pwsh
cd tools/GenerateKeypair
dotnet run
```

Sample output (don't reuse these values — they're examples):

```
WinSentinel Ed25519 keypair (generated in-memory; nothing written to disk)
--------------------------------------------------------------------------
Public  (embed in source):  AAAA...AAAA
Private (store in password manager): BBBB...BBBB
```

### Option B — OpenSSL

If you'd rather not run the bundled tool:

```bash
openssl genpkey -algorithm ED25519 -out /tmp/k.pem
openssl pkey -in /tmp/k.pem -text -noout
# Then base64-encode the raw 32 bytes shown under "priv:" and "pub:".
shred -u /tmp/k.pem
```

## Where the halves go

| Half        | Destination                                                         |
| ----------- | ------------------------------------------------------------------- |
| **Public**  | Replace the placeholder constant `EmbeddedPublicKeyBase64` in:      |
|             | • `src/WinSentinel.Core/Plugins/PluginHost.cs`                      |
|             | • `src/WinSentinel.Core/Licensing/LicenseVerifier.cs`               |
|             | (both reference the same constant; updating `LicenseVerifier` is enough — `PluginHost` re-exports it.) |
| **Private** | Paste into 1Password / Bitwarden under "WinSentinel — plugin signing key". Tag it, add a description, and **share with no one** until you have to. |

Commit the public-key edit:

```pwsh
git add src/WinSentinel.Core/Plugins/PluginHost.cs `
        src/WinSentinel.Core/Licensing/LicenseVerifier.cs
git commit -m "chore(license): embed production Ed25519 public key"
git push origin main
```

## Using the private key from CI (private repo)

In the future `winsentinel-pro` repository:

1. Add the base64 private key as a **GitHub Actions secret**, e.g.
   `WINSENTINEL_SIGNING_KEY`. Restrict it to a single environment with
   manual reviewer approval if possible.
2. The plugin/license signing workflow reads it via
   `${{ secrets.WINSENTINEL_SIGNING_KEY }}` and pipes it into the signing
   tool. The tool consumes the value on stdin — it is never echoed back
   to logs.
3. Rotate the secret if there is ever any reason to think it might have
   leaked. Rotating means: generate a new keypair, update the embedded
   public key constant here, ship a new client release, re-sign all
   active plugins and outstanding licenses against the new key.

## Rotation checklist

- [ ] Generate new keypair (Option A or B above).
- [ ] Update `LicenseVerifier.EmbeddedPublicKeyBase64`.
- [ ] Bump core version (rotation is a breaking change for existing licenses).
- [ ] Replace the GitHub Actions secret in the private repo.
- [ ] Re-sign every shipping plugin DLL.
- [ ] Re-issue licenses to active customers.
- [ ] Destroy the old private key (delete the password-manager entry
      only **after** the new key is in production).
