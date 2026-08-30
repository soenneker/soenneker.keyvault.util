[![](https://img.shields.io/nuget/v/soenneker.keyvault.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.keyvault.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.keyvault.util/build-and-test.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.keyvault.util/actions/workflows/build-and-test.yml)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.keyvault.util/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.keyvault.util/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.keyvault.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.keyvault.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.keyvault.util/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.keyvault.util/actions/workflows/codeql.yml)

# Soenneker.KeyVault.Util

Reads and writes Azure Key Vault secrets, imports PFX certificates, and can add Key Vault as a configuration provider.

## Install

```bash
dotnet add package Soenneker.KeyVault.Util
```

## Configuration

```json
{
  "Environment": "Development",
  "Azure": {
    "TenantId": "<tenant ID>",
    "AppRegistration": {
      "Id": "<application/client ID>",
      "Secret": "<client secret>"
    },
    "KeyVault": {
      "Uri": "https://my-vault.vault.azure.net/",
      "Enabled": true
    }
  }
}
```

The utility authenticates with `ClientSecretCredential`. Keep the client secret in a protected configuration source such as environment variables or a development secret store; do not commit it in application settings.

## Register and use secrets

```csharp
using Soenneker.KeyVault.Util.Abstract;
using Soenneker.KeyVault.Util.Registrars;

services.AddKeyVaultUtilAsSingleton();

KeyVaultSecret? secret = await keyVault.GetSecret(
    "ApiPassword",
    cancellationToken);

await keyVault.SetSecret(
    "ApiPassword",
    rotatedPassword,
    new Dictionary<string, string>
    {
        ["owner"] = "payments"
    },
    cancellationToken);
```

`GetSecret()` returns the latest enabled version and returns null only when Azure responds with 404. Authentication, authorization, throttling, and service failures propagate as `RequestFailedException`. `SetSecret()` creates a new secret version and applies the supplied tags.

## Import a PFX certificate

```csharp
byte[] pfx = await File.ReadAllBytesAsync("signing.pfx", cancellationToken);

KeyVaultCertificateWithPolicy imported = await keyVault.ImportCertificate(
    pfx,
    pfxPassword,
    name: "signing-certificate",
    subject: "CN=signing.example.com",
    keyVaultUri: "https://cert-vault.vault.azure.net/",
    cancellationToken);
```

The `keyVaultUri` argument is the destination for that import and may differ from the vault configured for secret operations. Private keys are non-exportable by default. Use the overload with `exportable: true` only when downstream key export is an explicit requirement.

## Add Key Vault to configuration

```csharp
IConfigurationRoot configuration = builder.Build();
configuration = configuration.AddKeyVault(builder, args);
```

When `Azure:KeyVault:Enabled` is true, `AddKeyVault()` adds the provider and rebuilds the configuration. Always use its returned root. When disabled, it returns the original root unchanged. Azure's configuration provider maps double hyphens in secret names to configuration delimiters, so `Database--Password` is read as `Database:Password`.
