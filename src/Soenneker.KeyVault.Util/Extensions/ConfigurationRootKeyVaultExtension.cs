using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Microsoft.Extensions.Configuration;
using Serilog;
using Soenneker.Enums.DeployEnvironment;
using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.Enumerable;
using Soenneker.Extensions.String;
using System.Diagnostics.Contracts;

namespace Soenneker.KeyVault.Util.Extensions;

/// <summary>
/// Rebuilds the configuration root to include Azure Key Vault if enabled. Returns the updated configuration for
/// accessing Key Vault entries.
/// </summary>
public static class ConfigurationRootKeyVaultExtension
{
    /// <summary>
    /// Rebuilds the configuration root to include Key Vault if needed. The returned configuration should be used to access Key Vault entries.
    /// </summary>
    [Pure]
    public static IConfigurationRoot AddKeyVault(this IConfigurationRoot configRoot, IConfigurationBuilder builder, string[]? args = null)
    {
        Log.Information("---- Key Vault Provider Configuration ----");

        var source = "config";

        if (args.Populated())
        {
            source = "command line arguments";
        }

        Log.Information("Source: {source}", source);

        DeployEnvironment? deployEnvironment = DeployEnvironment.FromName(configRoot["Environment"]);

        bool keyVaultEnabled = configRoot["Azure:KeyVault:Enabled"].ToBool();

        if (!keyVaultEnabled)
        {
            Log.Warning("Azure Key Vault is disabled in the configuration! ({environment})", deployEnvironment);
            Log.Information("------------------------------------------");
            return configRoot;
        }

        // Add the Azure Key Vault provider only if it's not already included. This ensures only explicitly configured keys are available.

        var tenantId = configRoot.GetValueStrict<string>("Azure:TenantId");
        var clientId = configRoot.GetValueStrict<string>("Azure:AppRegistration:Id");
        var clientSecret = configRoot.GetValueStrict<string>("Azure:AppRegistration:Secret");
        var keyVaultUri = configRoot.GetValueStrict<string>("Azure:KeyVault:Uri");

        var keyVaultUtil = new KeyVaultUtil(tenantId, clientId, clientSecret, keyVaultUri, deployEnvironment);

        builder.AddAzureKeyVault(keyVaultUtil.SecretClient.Value, new AzureKeyVaultConfigurationOptions());

        // Rebuild the configuration root to include the newly added Key Vault provider.
        configRoot = builder.Build();

        return configRoot;
    }
}
