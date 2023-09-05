namespace DigiAeon.Common.OpenPGP.UnitTests.Shared
{
    public static class Constants
    {
        public static string TemporaryDirectory { get; }
        public static string ResourcesRootDirectory { get; }
        public static string TextChunkFilePath { get; }
        public static string DigiAeonPublicKeyPath { get; }
        public static string DigiAeonPrivateKeyPath { get; }
        public static string DigiAeonPrivateKeyPassPhrase { get; }
        public static string VendorPublicKeyPath { get; }
        public static string VendorPrivateKeyPath { get; }
        public static string VendorPrivateKeyPassPhrase { get; }

        static Constants()
        {
            var applicationBaseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            TemporaryDirectory = Path.Combine(applicationBaseDirectory, "Temp");
            ResourcesRootDirectory = Path.Combine(applicationBaseDirectory, "Resources");
            TextChunkFilePath = Path.Combine(ResourcesRootDirectory, "TextChunk.txt");

            DigiAeonPublicKeyPath = Path.Combine(ResourcesRootDirectory, "Test.DigiAeon_0x5B90FB2D_public.asc");
            DigiAeonPrivateKeyPath = Path.Combine(ResourcesRootDirectory, "Test.DigiAeon_0x5B90FB2D_SECRET.asc");
            DigiAeonPrivateKeyPassPhrase = "=72zS61ZTKh]!n9[FT#WzMCK0)(R=4";

            VendorPublicKeyPath = Path.Combine(ResourcesRootDirectory, "Test.Vendor_0xF3186E54_public.asc");
            VendorPrivateKeyPath = Path.Combine(ResourcesRootDirectory, "Test.Vendor_0xF3186E54_SECRET.asc");
            VendorPrivateKeyPassPhrase = "Sgyz=2>CX9%EJ0;qqBM27j0;GJw?Yz";
        }
    }
}
