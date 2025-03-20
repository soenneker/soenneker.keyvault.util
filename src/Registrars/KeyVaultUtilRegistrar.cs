using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.KeyVault.Util.Abstract;

namespace Soenneker.KeyVault.Util.Registrars;

/// <summary>
/// A utility library for Azure Key Vault related operations
/// </summary>
public static class KeyVaultUtilRegistrar
{
    /// <summary>
    /// Adds <see cref="IKeyVaultUtil"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddKeyVaultUtilAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<IKeyVaultUtil, KeyVaultUtil>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="IKeyVaultUtil"/> as a scoped service. <para/>
    /// </summary>
    public static IServiceCollection AddKeyVaultUtilAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<IKeyVaultUtil, KeyVaultUtil>();

        return services;
    }
}
