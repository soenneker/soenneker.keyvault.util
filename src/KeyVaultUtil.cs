using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Serilog;
using Soenneker.Enums.DeployEnvironment;
using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Task;
using Soenneker.KeyVault.Util.Abstract;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.KeyVault.Util;

///<inheritdoc cref="IKeyVaultUtil"/>
public class KeyVaultUtil : IKeyVaultUtil
{
    private readonly Lazy<ClientSecretCredential> _clientSecretCredential;
    public readonly Lazy<SecretClient> SecretClient;
    private readonly Lazy<CertificateClient> _certificateClient;

    private readonly IConfiguration? _configuration;

    /// <summary> DI (Lazy Configuration Retrieval) </summary>
    public KeyVaultUtil(IConfiguration configuration)
    {
        _configuration = configuration;
        _clientSecretCredential = new Lazy<ClientSecretCredential>(InitializeCredential, true);
        SecretClient = new Lazy<SecretClient>(InitializeSecretClient, true);
        _certificateClient = new Lazy<CertificateClient>(InitializeCertificateClient, true);
    }

    public KeyVaultUtil(string tenantId, string clientId, string clientSecret, string keyVaultUri, DeployEnvironment deployEnvironment)
    {
        _clientSecretCredential = new Lazy<ClientSecretCredential>(() =>
        {
            LogConfiguration(tenantId, clientId, clientSecret, keyVaultUri, deployEnvironment);
            return new ClientSecretCredential(tenantId, clientId, clientSecret);
        }, true);

        SecretClient = new Lazy<SecretClient>(() => new SecretClient(new Uri(keyVaultUri), _clientSecretCredential.Value, new SecretClientOptions
        {
            Retry =
            {
                Delay = TimeSpan.FromSeconds(2),
                MaxDelay = TimeSpan.FromSeconds(16),
                MaxRetries = 5,
                Mode = RetryMode.Exponential
            }
        }), true);

        _certificateClient = new Lazy<CertificateClient>(() => new CertificateClient(new Uri(keyVaultUri), _clientSecretCredential.Value), true);
    }

    private ClientSecretCredential InitializeCredential()
    {
        var tenantId = _configuration!.GetValueStrict<string>("Azure:TenantId");
        var clientId = _configuration.GetValueStrict<string>("Azure:AppRegistration:Id");
        var clientSecret = _configuration.GetValueStrict<string>("Azure:AppRegistration:Secret");
        var keyVaultUri = _configuration.GetValueStrict<string>("Azure:KeyVault:Uri");
        DeployEnvironment deployEnvironment = DeployEnvironment.FromValue(_configuration.GetValueStrict<string>("ASPNETCORE_ENVIRONMENT"));

        LogConfiguration(tenantId, clientId, clientSecret, keyVaultUri, deployEnvironment);
        return new ClientSecretCredential(tenantId, clientId, clientSecret);
    }

    private SecretClient InitializeSecretClient()
    {
        var keyVaultUri = _configuration!.GetValueStrict<string>("Azure:KeyVault:Uri");
        return new SecretClient(new Uri(keyVaultUri), _clientSecretCredential.Value, new SecretClientOptions
        {
            Retry =
            {
                Delay = TimeSpan.FromSeconds(2),
                MaxDelay = TimeSpan.FromSeconds(16),
                MaxRetries = 5,
                Mode = RetryMode.Exponential
            }
        });
    }

    private CertificateClient InitializeCertificateClient()
    {
        var keyVaultUri = _configuration!.GetValueStrict<string>("Azure:KeyVault:Uri");
        return new CertificateClient(new Uri(keyVaultUri), _clientSecretCredential.Value);
    }

    private static void LogConfiguration(string tenantId, string clientId, string clientSecret, string keyVaultUri, DeployEnvironment deployEnvironment)
    {
        Log.Information("---- {name} Configuration ----", nameof(KeyVaultUtil));
        Log.Information("ASPNETCORE_ENVIRONMENT => {environment}", deployEnvironment);
        Log.Information("Azure:KeyVault:Uri => {url}", keyVaultUri);
        Log.Information("Azure:TenantId => {tenantId}", tenantId);
        Log.Information("Azure:AppRegistration:Id => {clientId}", clientId);
        Log.Information("Azure:AppRegistration:Secret => {clientSecret}", clientSecret.Mask());
        Log.Information("-------------------------------------");
    }

    public async ValueTask<KeyVaultSecret?> GetSecret(string name, CancellationToken cancellationToken = default)
    {
        Log.Debug("Getting Key Vault key \"{name}\" ...", name);

        try
        {
            Response<KeyVaultSecret>? response = await SecretClient.Value.GetSecretAsync(name, cancellationToken: cancellationToken).NoSync();
            return response.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            Log.Warning("Could not find secret \"{name}\" in Key Vault", name);
            return null;
        }
    }

    public async ValueTask SetSecret(string name, string value, Dictionary<string, string>? tags = null, CancellationToken cancellationToken = default)
    {
        Log.Information("Setting Key Vault entry -> {name} ...", name);

        KeyVaultSecret secret = new(name, value);

        if (tags is not null)
        {
            foreach (KeyValuePair<string, string> tag in tags)
                secret.Properties.Tags[tag.Key] = tag.Value;
        }

        await SecretClient.Value.SetSecretAsync(secret, cancellationToken).NoSync();
    }

    public async ValueTask<KeyVaultCertificateWithPolicy> ImportCertificate(byte[] certificate, string password, string name, string subject, string keyVaultUri, CancellationToken cancellationToken = default)
    {
        if (password.IsNullOrEmpty())
            throw new Exception("A password is required for PFX certificate import");

        Log.Information("Beginning to upload certificate to key vault {name}", keyVaultUri);

        var importOptions = new ImportCertificateOptions(name, certificate)
        {
            Policy = new CertificatePolicy(WellKnownIssuerNames.Self, subject)
            {
                ContentType = CertificateContentType.Pkcs12,
                Exportable = true
            },
            Password = password
        };

        KeyVaultCertificateWithPolicy? certificatePolicy = (await _certificateClient.Value.ImportCertificateAsync(importOptions, cancellationToken).NoSync()).Value;

        Log.Debug("Finished uploading certificate to key vault");

        return certificatePolicy;
    }
}
