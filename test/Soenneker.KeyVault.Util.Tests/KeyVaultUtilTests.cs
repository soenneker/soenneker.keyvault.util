using Soenneker.KeyVault.Util.Abstract;
using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.KeyVault.Util.Tests;

[Collection("Collection")]
public class KeyVaultUtilTests : FixturedUnitTest
{
    private readonly IKeyVaultUtil _util;

    public KeyVaultUtilTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
        _util = Resolve<IKeyVaultUtil>(true);
    }

    [Fact]
    public void Default()
    {

    }
}
