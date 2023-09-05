using System.Text;

namespace DigiAeon.Common.OpenPGP.UnitTests.Shared
{
    public static class Constants
    {
        public static string TemporaryDirectory { get; }
        public static string ResourcesRootDirectory { get; }
        public static string TestFilePath { get; }
        public static Encoding TestFileEncoding { get; } = Encoding.Unicode;
        public static string TestEncryptedFileWithASCIIArmorPath { get; }
        public static string TestEncryptedFileWithoutASCIIArmorPath { get; }
        public static string DigiAeonPublicKeyPath { get; }
        public static string DigiAeonPrivateKeyPath { get; }
        public static string DigiAeonPrivateKeyPassPhrase { get; }
        public static string VendorPublicKeyPath { get; }
        public static string VendorPrivateKeyPath { get; }
        public static string VendorPrivateKeyPassPhrase { get; }
        public static string InvalidPublicKeyPath { get; }
        public static string InvalidPrivateKeyPath { get; }
        public static string InvalidPrivateKeyPassPhrase { get; }
        public static int ExpectedTimeoutInMillisecond { get; } = 10000;

        static Constants()
        {
            var applicationBaseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            TemporaryDirectory = Path.Combine(applicationBaseDirectory, "Temp");
            ResourcesRootDirectory = Path.Combine(applicationBaseDirectory, "Resources");
            TestFilePath = Path.Combine(ResourcesRootDirectory, "TestFile.txt");
            TestEncryptedFileWithASCIIArmorPath = Path.Combine(ResourcesRootDirectory, "Test.VenderEncryptedFileWithASCIIArmor.txt");
            TestEncryptedFileWithoutASCIIArmorPath = Path.Combine(ResourcesRootDirectory, "Test.VenderEncryptedFileWithoutASCIIArmor.txt");

            DigiAeonPublicKeyPath = Path.Combine(ResourcesRootDirectory, "Test.DigiAeon_0x5B90FB2D_public.asc");
            DigiAeonPrivateKeyPath = Path.Combine(ResourcesRootDirectory, "Test.DigiAeon_0x5B90FB2D_SECRET.asc");
            DigiAeonPrivateKeyPassPhrase = "=72zS61ZTKh]!n9[FT#WzMCK0)(R=4";

            VendorPublicKeyPath = Path.Combine(ResourcesRootDirectory, "Test.Vendor_0xF3186E54_public.asc");
            VendorPrivateKeyPath = Path.Combine(ResourcesRootDirectory, "Test.Vendor_0xF3186E54_SECRET.asc");
            VendorPrivateKeyPassPhrase = "Sgyz=2>CX9%EJ0;qqBM27j0;GJw?Yz";

            InvalidPublicKeyPath = Path.Combine(ResourcesRootDirectory, "Test.Invalid_0x355CF012_public.asc");
            InvalidPrivateKeyPath = Path.Combine(ResourcesRootDirectory, "Test.Invalid_0x355CF012_SECRET.asc");
            InvalidPrivateKeyPassPhrase = "}^l9Lhk^mVek!O.u<,M2HHO@cWLRo%";
        }
    }
}
