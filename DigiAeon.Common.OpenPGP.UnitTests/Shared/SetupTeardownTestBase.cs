namespace DigiAeon.Common.OpenPGP.UnitTests.Shared
{
    public abstract class SetupTeardownTestBase : IDisposable
    {
        protected string TemporaryTestDirectory { get; }

        protected SetupTeardownTestBase()
        {
            if (!Directory.Exists(Constants.TemporaryDirectory))
            {
                Directory.CreateDirectory(Constants.TemporaryDirectory);
            }

            TemporaryTestDirectory = Path.Combine(Constants.TemporaryDirectory, Guid.NewGuid().ToString());

            if (!Directory.Exists(TemporaryTestDirectory))
            {
                Directory.CreateDirectory(TemporaryTestDirectory);
            }
        }

        public void Dispose()
        {
            if (Directory.Exists(TemporaryTestDirectory))
            {
                Directory.Delete(TemporaryTestDirectory, true);
            }
        }
    }
}
