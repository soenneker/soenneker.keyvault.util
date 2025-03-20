using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Serilog;
using Soenneker.Enums.DeployEnvironment;
using Soenneker.Extensions.Configuration;
using Soenneker.KeyVault.Util.Abstract;
using Soenneker.Extensions.String;

namespace Soenneker.KeyVault.Util;

///<inheritdoc cref="IKeyVaultUtil"/>
public class KeyVaultUtil : IKeyVaultUtil
{
    public Lazy<SecretClient> SecretClient = null!;

    public Lazy<CertificateClient> CertificateClient = null!;

    /// <summary> DI </summary>
    public KeyVaultUtil(IConfiguration configuration)
    {
        var tenantId = configuration.GetValueStrict<string>("Azure:TenantId");
        var clientId = configuration.GetValueStrict<string>("Azure:AppRegistration:Id");
        var clientSecret = configuration.GetValueStrict<string>("Azure:AppRegistration:Secret");
        var keyVaultUri = configuration.GetValueStrict<string>("Azure:KeyVault:Uri");
        DeployEnvironment deployEnvironment = DeployEnvironment.FromValue(configuration.GetValueStrict<string>("ASPNETCORE_ENVIRONMENT"));

        Initialize(tenantId, clientId, clientSecret, keyVaultUri, deployEnvironment);
    }

    public KeyVaultUtil(string tenantId, string clientId, string clientSecret, string keyVaultUri, DeployEnvironment deployEnvironment)
    {
        Initialize(tenantId, clientId, clientSecret, keyVaultUri, deployEnvironment);
    }

    /// <summary> Used in startup scenarios </summary>
    private void Initialize(string tenantId, string clientId, string clientSecret, string keyVaultUri, DeployEnvironment deployEnvironment)
    {
        var clientSecretCredential = new Lazy<ClientSecretCredential>(() =>
        {
            Log.Information("---- {name} Configuration ----", nameof(KeyVaultUtil));
            Log.Information("ASPNETCORE_ENVIRONMENT => {environment}", deployEnvironment);
            Log.Information("Azure:KeyVault:Uri => {url}", keyVaultUri);
            Log.Information("Azure:TenantId => {tenantId}", tenantId);
            Log.Information("Azure:AppRegistration:Id => {clientId}", clientId);
            Log.Information("Azure:AppRegistration:Secret => {clientSecret}", clientSecret.Mask());
            Log.Information("-------------------------------------");

            return new ClientSecretCredential(tenantId, clientId, clientSecret);
        }, true);

        SecretClient = new Lazy<SecretClient>(() =>
        {
            SecretClientOptions options = new()
            {
                Retry =
                {
                    Delay = TimeSpan.FromSeconds(2),
                    MaxDelay = TimeSpan.FromSeconds(16),
                    MaxRetries = 5,
                    Mode = RetryMode.Exponential
                }
            };

            return new SecretClient(new Uri(keyVaultUri), clientSecretCredential.Value, options);
        }, true);

        CertificateClient = new Lazy<CertificateClient>(() => new CertificateClient(new Uri(keyVaultUri), clientSecretCredential.Value), true);
    }

    public async ValueTask<KeyVaultSecret?> GetSecret(string name)
    {
        Log.Debug("Getting Key Vault key \"{name}\" ...", name);

        try
        {
            Response<KeyVaultSecret>? response = await SecretClient.Value.GetSecretAsync(name);
            return response.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            Log.Warning("Could not find secret \"{name}\" in Key Vault", name);
            return null;
        }
    }

    public async ValueTask SetSecret(string name, string value, Dictionary<string, string>? tags = null)
    {
        Log.Information("Setting Key Vault entry -> {name} ...", name);

        KeyVaultSecret secret = new(name, value);

        if (tags is not null)
        {
            foreach (KeyValuePair<string, string> tag in tags)
                secret.Properties.Tags[tag.Key] = tag.Value;
        }

        await SecretClient.Value.SetSecretAsync(secret);
    }

    public async ValueTask<KeyVaultCertificateWithPolicy> ImportCertificate(byte[] certificate, string password, string name, string subject,
        string keyVaultUri)
    {
        if (string.IsNullOrEmpty(password))
            throw new Exception("A password is required for PFX certificate import");

        Log.Information("Beginning to upload certificate to key vault {name}", keyVaultUri);

        var importOptions = new ImportCertificateOptions(name, certificate)
        {
            Policy = new CertificatePolicy(WellKnownIssuerNames.Self, subject)
            {
                // Required when setting a policy; if no policy required, Pfx is assumed.
                ContentType = CertificateContentType.Pkcs12,

                // Optionally mark the private key exportable.
                Exportable = true
            },
            Password = password
        };

        KeyVaultCertificateWithPolicy? certificatePolicy = (await CertificateClient.Value.ImportCertificateAsync(importOptions)).Value;

        Log.Debug("Finished uploading certificate to key vault");

        return certificatePolicy;
    }
}