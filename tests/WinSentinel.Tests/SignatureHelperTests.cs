using System;
using System.IO;
using WinSentinel.Core.Helpers;
using Xunit;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="SignatureHelper"/>. These exercise the graceful-failure
/// contract of <see cref="SignatureHelper.HasAuthenticodeSignature"/>: any input
/// that cannot yield an Authenticode certificate (missing file, empty path,
/// unsigned content, a directory) must never throw and must return
/// <c>false</c>. They also confirm a genuinely signed, always-present Windows
/// system binary reports <c>true</c>. All cases are deterministic on any
/// Windows host and require no elevation - nothing here writes anywhere except
/// the per-test temp file it cleans up.
/// </summary>
public class SignatureHelperTests
{
    [Fact]
    public void HasAuthenticodeSignature_NonexistentFile_ReturnsFalse()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"ws_sig_missing_{Guid.NewGuid():N}.exe");
        Assert.False(File.Exists(missing));
        Assert.False(SignatureHelper.HasAuthenticodeSignature(missing));
    }

    [Fact]
    public void HasAuthenticodeSignature_EmptyPath_ReturnsFalse()
    {
        Assert.False(SignatureHelper.HasAuthenticodeSignature(string.Empty));
    }

    [Fact]
    public void HasAuthenticodeSignature_UnsignedFile_ReturnsFalse()
    {
        // A plain text file has no embedded Authenticode certificate.
        var path = Path.Combine(Path.GetTempPath(), $"ws_sig_unsigned_{Guid.NewGuid():N}.exe");
        File.WriteAllText(path, "this is not a signed binary");
        try
        {
            Assert.False(SignatureHelper.HasAuthenticodeSignature(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void HasAuthenticodeSignature_Directory_ReturnsFalse()
    {
        // Passing a directory must be handled gracefully, not throw.
        Assert.False(SignatureHelper.HasAuthenticodeSignature(Path.GetTempPath()));
    }

    [Fact]
    public void HasAuthenticodeSignature_SignedSystemBinary_ReturnsTrue()
    {
        // kernel32.dll ships Authenticode-signed on every supported Windows.
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var kernel32 = Path.Combine(system32, "kernel32.dll");
        if (!File.Exists(kernel32))
        {
            // Extremely unusual, but do not fail the suite on a nonstandard host.
            return;
        }

        Assert.True(SignatureHelper.HasAuthenticodeSignature(kernel32));
    }
}
