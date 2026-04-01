using System.Security.Cryptography.X509Certificates;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Shared Authenticode signature verification utility.
/// Consolidates the identical VerifyAuthenticodeSignature logic previously
/// duplicated in ProcessMonitorModule and NetworkMonitorModule.
/// </summary>
public static class SignatureHelper
{
    /// <summary>
    /// Check whether a file has a valid Authenticode signature.
    /// </summary>
    /// <param name="filePath">Absolute path to the executable.</param>
    /// <returns>True if the file has a certificate; false otherwise.</returns>
    public static bool HasAuthenticodeSignature(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return cert != null;
        }
        catch
        {
            return false;
        }
    }
}
