using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Events;
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

/// <inheritdoc cref="IKeyVaultUtil"/>
public sealed class KeyVaultUtil : IKeyVaultUtil
{
    private static readonly SecretClientOptions _secretClientOptions = CreateSecretClientOptions();

    private readonly string? _tenantId;
    private readonly string? _clientId;
    private readonly string? _clientSecret;
    private readonly Uri? _keyVaultUri;

    private readonly Lazy<ClientSecretCredential> _clientSecretCredential;
    public readonly Lazy<SecretClient> SecretClient;
    private readonly Lazy<CertificateClient> _certificateClient;

    /// <summary>DI (config-backed)</summary>
    public KeyVaultUtil(IConfiguration configuration)
    {
        // Pull config ONCE (avoids repeated dictionary lookups and string allocations).
        _tenantId = configuration.GetValueStrict<string>("Azure:TenantId");
        _clientId = configuration.GetValueStrict<string>("Azure:AppRegistration:Id");
        _clientSecret = configuration.GetValueStrict<string>("Azure:AppRegistration:Secret");
        var keyVaultUriString = configuration.GetValueStrict<string>("Azure:KeyVault:Uri");
        _keyVaultUri = new Uri(keyVaultUriString, UriKind.Absolute);

        DeployEnvironment deployEnvironment = DeployEnvironment.FromValue(configuration.GetValueStrict<string>("Environment"));

        // Log once; gate expensive Mask()/formatting behind level check.
        LogConfigurationIfEnabled(_tenantId, _clientId, _clientSecret, keyVaultUriString, deployEnvironment);

        _clientSecretCredential = new Lazy<ClientSecretCredential>(CreateCredential, isThreadSafe: true);
        SecretClient = new Lazy<SecretClient>(CreateSecretClient, isThreadSafe: true);
        _certificateClient = new Lazy<CertificateClient>(CreateCertificateClient, isThreadSafe: true);
    }

    /// <summary>Manual (no IConfiguration)</summary>
    public KeyVaultUtil(string tenantId, string clientId, string clientSecret, string keyVaultUri, DeployEnvironment deployEnvironment)
    {
        _tenantId = tenantId;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _keyVaultUri = new Uri(keyVaultUri, UriKind.Absolute);

        LogConfigurationIfEnabled(_tenantId, _clientId, _clientSecret, keyVaultUri, deployEnvironment);

        _clientSecretCredential = new Lazy<ClientSecretCredential>(CreateCredential, isThreadSafe: true);
        SecretClient = new Lazy<SecretClient>(CreateSecretClient, isThreadSafe: true);
        _certificateClient = new Lazy<CertificateClient>(CreateCertificateClient, isThreadSafe: true);
    }

    private ClientSecretCredential CreateCredential() => new(_tenantId!, _clientId!, _clientSecret!);

    private SecretClient CreateSecretClient() => new(_keyVaultUri!, _clientSecretCredential.Value, _secretClientOptions);

    private CertificateClient CreateCertificateClient() => new(_keyVaultUri!, _clientSecretCredential.Value);

    private static SecretClientOptions CreateSecretClientOptions()
    {
        // Construct once and reuse; this is safe since we never mutate after creation.
        return new SecretClientOptions
        {
            Retry =
            {
                Delay = TimeSpan.FromSeconds(2),
                MaxDelay = TimeSpan.FromSeconds(16),
                MaxRetries = 5,
                Mode = RetryMode.Exponential
            }
        };
    }

    private static void LogConfigurationIfEnabled(string tenantId, string clientId, string clientSecret, string keyVaultUri,
        DeployEnvironment deployEnvironment)
    {
        if (!Log.IsEnabled(LogEventLevel.Information))
            return;

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
        if (Log.IsEnabled(LogEventLevel.Debug))
            Log.Debug("Getting Key Vault key \"{name}\" ...", name);

        try
        {
            Response<KeyVaultSecret> response = await SecretClient.Value.GetSecretAsync(name, cancellationToken: cancellationToken)
                                                                  .NoSync();

            return response.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            if (Log.IsEnabled(LogEventLevel.Warning))
                Log.Warning("Could not find secret \"{name}\" in Key Vault", name);

            return null;
        }
    }

    public async ValueTask SetSecret(string name, string value, Dictionary<string, string>? tags = null, CancellationToken cancellationToken = default)
    {
        if (Log.IsEnabled(LogEventLevel.Information))
            Log.Information("Setting Key Vault entry -> {name} ...", name);

        var secret = new KeyVaultSecret(name, value);

        if (tags is not null && tags.Count != 0)
        {
            // Avoid enumerator interface boxing by iterating KeyValuePair directly (Dictionary uses a struct enumerator).
            foreach (KeyValuePair<string, string> tag in tags)
                secret.Properties.Tags[tag.Key] = tag.Value;
        }

        await SecretClient.Value.SetSecretAsync(secret, cancellationToken)
                          .NoSync();
    }

    public async ValueTask<KeyVaultCertificateWithPolicy> ImportCertificate(byte[] certificate, string password, string name, string subject,
        string keyVaultUri, CancellationToken cancellationToken = default)
    {
        if (password.IsNullOrEmpty())
            throw new ArgumentException("A password is required for PFX certificate import", nameof(password));

        if (Log.IsEnabled(LogEventLevel.Information))
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

        KeyVaultCertificateWithPolicy certificatePolicy = (await _certificateClient.Value.ImportCertificateAsync(importOptions, cancellationToken)
                                                                                   .NoSync()).Value;

        if (Log.IsEnabled(LogEventLevel.Debug))
            Log.Debug("Finished uploading certificate to key vault");

        return certificatePolicy;
    }
}