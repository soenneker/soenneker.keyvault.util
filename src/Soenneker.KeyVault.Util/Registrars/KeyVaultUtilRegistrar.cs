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
    /// <param name="services">Service collection that receives the registration.</param>
    /// <returns>The same service collection, so additional registrations can be chained.</returns>
    public static IServiceCollection AddKeyVaultUtilAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<IKeyVaultUtil, KeyVaultUtil>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="IKeyVaultUtil"/> as a scoped service. <para/>
    /// </summary>
    /// <param name="services">Service collection that receives the registration.</param>
    /// <returns>The same service collection, so additional registrations can be chained.</returns>
    public static IServiceCollection AddKeyVaultUtilAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<IKeyVaultUtil, KeyVaultUtil>();

        return services;
    }
}
