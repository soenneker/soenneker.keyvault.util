using Soenneker.KeyVault.Util.Abstract;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.KeyVault.Util.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class KeyVaultUtilTests : HostedUnitTest
{
    private readonly IKeyVaultUtil _util;

    public KeyVaultUtilTests(Host host) : base(host)
    {
        _util = Resolve<IKeyVaultUtil>(true);
    }

    [Test]
    public void Default()
    {

    }
}
