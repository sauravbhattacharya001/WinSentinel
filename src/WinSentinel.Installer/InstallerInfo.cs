// This project is a placeholder for MSIX packaging.
// To create the actual MSIX installer:
//
// 1. Open WinSentinel.sln in Visual Studio 2022
// 2. Right-click solution → Add → New Project
// 3. Search for "Windows Application Packaging Project"
// 4. Set WinSentinel.App as the entry point application
// 5. Configure Package.appxmanifest with app identity
// 6. Build to produce .msix or .msixbundle
//
// For CI/CD, the release workflow produces a self-contained publish
// that can be distributed as a ZIP or converted to MSIX using MakeAppx.exe.

namespace WinSentinel.Installer;

public static class InstallerInfo
{
    public const string AppName = "WinSentinel";
    public const string Publisher = "CN=WinSentinel";
    public const string Description = "Windows Security Agent - Local-first security auditing";
}
