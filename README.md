[![](https://img.shields.io/nuget/v/soenneker.keyvault.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.keyvault.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.keyvault.util/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.keyvault.util/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.keyvault.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.keyvault.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.keyvault.util/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.keyvault.util/actions/workflows/codeql.yml)

# Soenneker.KeyVault.Util

A utility library for Azure Key Vault related operations.

## Install

```bash
dotnet add package Soenneker.KeyVault.Util
```

## Quick start

```csharp
using Soenneker.KeyVault.Util.Registrars;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var result = services.AddKeyVaultUtilAsSingleton();
```

Adds `IKeyVaultUtil` as a singleton service.

## What you get

- `IKeyVaultUtil` — A utility library for Azure Key Vault related operations.
- `ConfigurationRootKeyVaultExtension` — Rebuilds the configuration root to include Azure Key Vault if enabled. Returns the updated configuration for accessing Key Vault entries.
- `KeyVaultUtilRegistrar` — A utility library for Azure Key Vault related operations.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `IKeyVaultUtil.GetSecret(name, cancellationToken)` | Retrieves a secret from Azure Key Vault. | The secret value or null if not found. |
| `IKeyVaultUtil.SetSecret(name, value, tags, cancellationToken)` | Sets a secret in Azure Key Vault. | A task that completes when the secret has been stored. |
| `IKeyVaultUtil.ImportCertificate(certificate, password, name, subject, keyVaultUri, cancellationToken)` | Imports a certificate into Azure Key Vault. | The imported Key Vault certificate with policy. |
| `ConfigurationRootKeyVaultExtension.AddKeyVault(configRoot, builder, args)` | Rebuilds the configuration root to include Key Vault if needed. The returned configuration should be used to access Key Vault entries. | The resulting configuration Root. |
| `KeyVaultUtilRegistrar.AddKeyVaultUtilAsSingleton(services)` | Adds `IKeyVaultUtil` as a singleton service. | The same service collection, so additional registrations can be chained. |
| `KeyVaultUtilRegistrar.AddKeyVaultUtilAsScoped(services)` | Adds `IKeyVaultUtil` as a scoped service. | The same service collection, so additional registrations can be chained. |

## Practical notes

- Cancellation stops pending work; it does not undo work that has already completed.
