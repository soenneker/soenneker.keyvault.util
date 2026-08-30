using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.KeyVault.Util.Abstract;

/// <summary>
/// Reads and writes Key Vault secrets and imports PFX certificates.
/// </summary>
public interface IKeyVaultUtil
{
    /// <summary>
    /// Retrieves a secret from Azure Key Vault.
    /// </summary>
    /// <param name="name">The name of the secret.</param>
    /// <param name="cancellationToken"></param>
    /// <returns>The secret value or null if not found.</returns>
    [Pure]
    ValueTask<KeyVaultSecret?> GetSecret(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets a secret in Azure Key Vault.
    /// </summary>
    /// <param name="name">Name of the Key Vault value to target.</param>
    /// <param name="value">Secret value to store in Key Vault.</param>
    /// <param name="tags">Optional dictionary of tags to associate with the secret.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>A task that completes when the secret has been stored.</returns>
    ValueTask SetSecret(string name, string value, Dictionary<string, string>? tags = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Imports a certificate into Azure Key Vault.
    /// </summary>
    /// <param name="certificate">The certificate byte array.</param>
    /// <param name="password">The password for the certificate.</param>
    /// <param name="name">The name of the certificate.</param>
    /// <param name="subject">The subject of the certificate.</param>
    /// <param name="keyVaultUri">The destination Key Vault URI.</param>
    /// <param name="cancellationToken">Token used to cancel the import.</param>
    /// <returns>The imported non-exportable Key Vault certificate and policy.</returns>
    ValueTask<KeyVaultCertificateWithPolicy> ImportCertificate(byte[] certificate, string password, string name, string subject, string keyVaultUri, CancellationToken cancellationToken = default);

    /// <summary>
    /// Imports a PFX certificate into a specified Azure Key Vault with an explicit private-key exportability policy.
    /// </summary>
    /// <param name="certificate">The PFX certificate bytes.</param>
    /// <param name="password">The PFX password.</param>
    /// <param name="name">The Key Vault certificate name.</param>
    /// <param name="subject">The certificate subject used by the Key Vault policy.</param>
    /// <param name="keyVaultUri">The destination Key Vault URI.</param>
    /// <param name="exportable">Whether Key Vault may export the imported private key.</param>
    /// <param name="cancellationToken">Token used to cancel the import.</param>
    /// <returns>The imported Key Vault certificate and policy.</returns>
    ValueTask<KeyVaultCertificateWithPolicy> ImportCertificate(byte[] certificate, string password, string name, string subject, string keyVaultUri,
        bool exportable, CancellationToken cancellationToken = default);
}
