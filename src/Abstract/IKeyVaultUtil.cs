using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.KeyVault.Util.Abstract;

/// <summary>
/// A utility library for Azure Key Vault related operations
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
    /// <param name="name">The name of the secret.</param>
    /// <param name="value">The value of the secret.</param>
    /// <param name="tags">Optional dictionary of tags to associate with the secret.</param>
    /// <param name="cancellationToken"></param>
    ValueTask SetSecret(string name, string value, Dictionary<string, string>? tags = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Imports a certificate into Azure Key Vault.
    /// </summary>
    /// <param name="certificate">The certificate byte array.</param>
    /// <param name="password">The password for the certificate.</param>
    /// <param name="name">The name of the certificate.</param>
    /// <param name="subject">The subject of the certificate.</param>
    /// <param name="keyVaultUri">The Key Vault URI.</param>
    /// <param name="cancellationToken"></param>
    /// <returns>The imported Key Vault certificate with policy.</returns>
    ValueTask<KeyVaultCertificateWithPolicy> ImportCertificate(byte[] certificate, string password, string name, string subject, string keyVaultUri, CancellationToken cancellationToken = default);
}