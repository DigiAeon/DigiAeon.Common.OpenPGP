using DigiAeon.Common.OpenPGP.Exceptions;
using DigiAeon.Common.OpenPGP.Interfaces;
using DigiAeon.Common.OpenPGP.UnitTests.Data;
using DigiAeon.Common.OpenPGP.UnitTests.Shared;

namespace DigiAeon.Common.OpenPGP.UnitTests.Tests
{
    public class EncyrptionDecryptionTests : SetupTeardownTestBase
    {
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void EncyrptionDecryption_ValidateKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKeyPath = Constants.VendorPublicKeyPath;
            var signByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKeyPath = Constants.DigiAeonPublicKeyPath;
            var decryptByPrivateKeyPath = Constants.VendorPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;

            // Act
            IPGPService pgpService = new PGPService();
            pgpService.EncryptFileAndSign(originalFilePath, encyptedFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, useASCIIArmor);
            pgpService.DecryptFileAndVerify(encyptedFilePath, decryptedFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase);

            // Assert
            Assert.True(FileHelper.AreSameTextFiles(originalFilePath, decryptedFilePath, originalFileEncoding));
        }

        [Theory]
        [ClassData(typeof(EncyrptionDecryptionInvalidKeyData))]
        public void EncyrptionDecryption_InvalidKeysWillFail(EncyrptionDecryptionInvalidKeyDataDetails data)
        {
            // Arrange
            var encryptByPublicKeyPath = data.EncryptByPublicKeyPath;
            var signByPrivateKeyPath = data.SignByPrivateKeyPath;
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKeyPath = data.VerifyPublicKeyPath;
            var decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;

            // Act & Assert
            IPGPService pgpService = new PGPService();
            Assert.Throws<PGPOperationException>(() =>
            {
                pgpService.EncryptFileAndSign(originalFilePath, encyptedFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, true);
                pgpService.DecryptFileAndVerify(encyptedFilePath, decryptedFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase);
            });
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task EncyrptionDecryptionAsync_ValidateKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKeyPath = Constants.VendorPublicKeyPath;
            var signByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKeyPath = Constants.DigiAeonPublicKeyPath;
            var decryptByPrivateKeyPath = Constants.VendorPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPGPService pgpService = new PGPService();
            await pgpService.EncryptFileAndSignAsync(originalFilePath, encyptedFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, useASCIIArmor, tokenSource.Token);
            await pgpService.DecryptFileAndVerifyAsync(encyptedFilePath, decryptedFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase, tokenSource.Token);

            // Assert
            Assert.True(FileHelper.AreSameTextFiles(originalFilePath, decryptedFilePath, originalFileEncoding));
        }

        [Theory]
        [ClassData(typeof(EncyrptionDecryptionInvalidKeyData))]
        public async Task EncyrptionDecryptionAsync_InvalidKeysWillFail(EncyrptionDecryptionInvalidKeyDataDetails data)
        {
            // Arrange
            var encryptByPublicKeyPath = data.EncryptByPublicKeyPath;
            var signByPrivateKeyPath = data.SignByPrivateKeyPath;
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKeyPath = data.VerifyPublicKeyPath;
            var decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;

            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPGPService pgpService = new PGPService();
            await Assert.ThrowsAsync<PGPOperationException>(async () =>
            {
                await pgpService.EncryptFileAndSignAsync(originalFilePath, encyptedFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, true, tokenSource.Token);
                await pgpService.DecryptFileAndVerifyAsync(encyptedFilePath, decryptedFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase, tokenSource.Token);
            });
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void EncyrptionDecryptionUsingKeyFileBytes_ValidateKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;

            // Act
            IPGPService pgpService = new PGPService();
            pgpService.EncryptFileAndSign(originalFilePath, encyptedFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, useASCIIArmor);
            pgpService.DecryptFileAndVerify(encyptedFilePath, decryptedFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase);

            // Assert
            Assert.True(FileHelper.AreSameTextFiles(originalFilePath, decryptedFilePath, originalFileEncoding));
        }

        [Theory]
        [ClassData(typeof(EncyrptionDecryptionInvalidKeyData))]
        public void EncyrptionDecryptionUsingKeyFileBytes_InvalidKeysWillFail(EncyrptionDecryptionInvalidKeyDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(data.EncryptByPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(data.SignByPrivateKeyPath);
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKey = File.ReadAllBytes(data.VerifyPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(data.DecryptByPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;

            // Act & Assert
            IPGPService pgpService = new PGPService();
            Assert.Throws<PGPOperationException>(() =>
            {
                pgpService.EncryptFileAndSign(originalFilePath, encyptedFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true);
                pgpService.DecryptFileAndVerify(encyptedFilePath, decryptedFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase);
            });
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task EncyrptionDecryptionUsingKeyFileBytesAsync_ValidateKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPGPService pgpService = new PGPService();
            await pgpService.EncryptFileAndSignAsync(originalFilePath, encyptedFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, useASCIIArmor, tokenSource.Token);
            await pgpService.DecryptFileAndVerifyAsync(encyptedFilePath, decryptedFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token);

            // Assert
            Assert.True(FileHelper.AreSameTextFiles(originalFilePath, decryptedFilePath, originalFileEncoding));
        }

        [Theory]
        [ClassData(typeof(EncyrptionDecryptionInvalidKeyData))]
        public async Task EncyrptionDecryptionUsingKeyFileBytesAsync_InvalidKeysWillFail(EncyrptionDecryptionInvalidKeyDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(data.EncryptByPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(data.SignByPrivateKeyPath);
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var encyptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var originalFilePath = Constants.TestFilePath;

            var verifyByPublicKey = File.ReadAllBytes(data.VerifyPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(data.DecryptByPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var decryptedFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            var originalFileEncoding = Constants.TestFileEncoding;

            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPGPService pgpService = new PGPService();
            await Assert.ThrowsAsync<PGPOperationException>(async () =>
            {
                await pgpService.EncryptFileAndSignAsync(originalFilePath, encyptedFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true, tokenSource.Token);
                await pgpService.DecryptFileAndVerifyAsync(encyptedFilePath, decryptedFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token);
            });
        }
    }
}
