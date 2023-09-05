using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using DigiAeon.Common.OpenPGP.Interfaces;
using DigiAeon.Common.OpenPGP.UnitTests.Shared;

namespace DigiAeon.Common.OpenPGP.BenchmarkTests.Tests
{
    [SimpleJob(RunStrategy.ColdStart, targetCount: 1)]
    [MemoryDiagnoser]
    [GcServer(true)]
    public class DecryptLargeFileTests
    {
        private string _testFilePath = string.Empty;
        private string _encyptedFilePath = string.Empty;

        [GlobalSetup]
        public void Setup()
        {
            if (!Directory.Exists(Constants.TemporaryDirectory))
            {
                Console.WriteLine($"Creating {Constants.TemporaryDirectory}...");

                Directory.CreateDirectory(Constants.TemporaryDirectory);

                Console.WriteLine($"{Constants.TemporaryDirectory} created.");
            }

            _testFilePath = Path.Combine(Constants.TemporaryDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Retrieve text chunk
            var textChunk = File.ReadAllText(Constants.TextChunkFilePath);

            Console.WriteLine($"Creating {_testFilePath}...");
            // Create empty test file
            File.WriteAllText(_testFilePath, string.Empty);

            // Append test file with text check N time to create large file
            using (StreamWriter file = new(_testFilePath, append: true))
            {
                for (var i = 1; i <= 150000; i++)
                {
                    file.WriteLine(textChunk);
                }
            }
            Console.WriteLine($"Created {_testFilePath}.");

            var encryptByPublicKeyPath = Constants.VendorPublicKeyPath;
            var signByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            _encyptedFilePath = Path.Combine(Constants.TemporaryDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            IPgpService pgpService = new PGPService();

            Console.WriteLine($"Encrypting {_testFilePath} to {_encyptedFilePath}...");
            pgpService.EncryptFileAndSign(_testFilePath, _encyptedFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, true);
            Console.WriteLine($"Encryption finished.");
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            Console.WriteLine($"Deleting {_encyptedFilePath}...");
            File.Delete(_encyptedFilePath);
            Console.WriteLine($"Deleting {_encyptedFilePath}...");

            Console.WriteLine($"Deleting {_testFilePath}...");
            File.Delete(_testFilePath);
            Console.WriteLine($"Deleting {_testFilePath}...");
        }

        [Benchmark]
        public void Decrypt()
        {
            var verifyByPublicKeyPath = Constants.DigiAeonPublicKeyPath;
            var decryptByPrivateKeyPath = Constants.VendorPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(Constants.TemporaryDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            IPgpService pgpService = new PGPService();

            Console.WriteLine($"Decrypting {_encyptedFilePath} to {decryptedFilePath}...");
            pgpService.DecryptFileAndVerify(_encyptedFilePath, decryptedFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase);
            Console.WriteLine($"Decryption finished.");

            Console.WriteLine($"Deleting {decryptedFilePath}...");
            File.Delete(decryptedFilePath);
            Console.WriteLine($"Deleted {decryptedFilePath}...");
        }
    }
}