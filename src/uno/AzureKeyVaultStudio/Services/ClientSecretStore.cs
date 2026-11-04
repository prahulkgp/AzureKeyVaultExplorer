using System.Security.Cryptography;
using System.Text;

namespace AzureKeyVaultStudio.Services;

/// <summary>
/// Stores the service principal client secret outside of plain-text settings:
/// macOS login keychain, Windows DPAPI (current user). Other platforms are not supported.
/// </summary>
public static class ClientSecretStore
{
    private static string WindowsSecretPath => Path.Combine(Constants.LocalAppDataFolder, Constants.ClientSecretFileName);

    public static bool IsSupported => OperatingSystem.IsMacOS() || OperatingSystem.IsWindows();

    public static string? Get()
    {
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                var value = MacOSKeyChainService.GetPassword(Constants.ClientSecretKeychainServiceName, Constants.ClientSecretKeychainAccountName);
                return string.IsNullOrEmpty(value) ? null : value;
            }

            if (OperatingSystem.IsWindows())
            {
                if (!File.Exists(WindowsSecretPath))
                    return null;
                var data = ProtectedData.Unprotect(File.ReadAllBytes(WindowsSecretPath), null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(data);
            }
        }
        catch
        {
            // not found or not readable
        }

        return null;
    }

    public static void Set(string secret)
    {
        if (OperatingSystem.IsMacOS())
        {
            // Remove any existing item first so the native add succeeds (avoids the CLI fallback that passes the secret on argv).
            Delete();
            MacOSKeyChainService.SaveToKeychain(Constants.ClientSecretKeychainServiceName, Constants.ClientSecretKeychainAccountName, secret);
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(Constants.LocalAppDataFolder);
            var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(WindowsSecretPath, data);
            return;
        }

        throw new PlatformNotSupportedException("Storing a client secret is only supported on macOS and Windows.");
    }

    public static void Delete()
    {
        try
        {
            if (OperatingSystem.IsMacOS())
                MacOSKeyChainService.DeleteFromKeychain(Constants.ClientSecretKeychainServiceName, Constants.ClientSecretKeychainAccountName);
            else if (OperatingSystem.IsWindows() && File.Exists(WindowsSecretPath))
                File.Delete(WindowsSecretPath);
        }
        catch
        {
            // nothing to delete
        }
    }
}
