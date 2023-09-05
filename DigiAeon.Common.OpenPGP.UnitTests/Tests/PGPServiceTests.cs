using DigiAeon.Common.OpenPGP.Exceptions;
using DigiAeon.Common.OpenPGP.Interfaces;
using DigiAeon.Common.OpenPGP.UnitTests.Data;
using DigiAeon.Common.OpenPGP.UnitTests.Shared;

namespace DigiAeon.Common.OpenPGP.UnitTests
{
    public class PgpServiceTests : SetupTeardownTestBase
    {
        #region -- EncryptFileAndSign --

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void EncryptFileAndSign_ValidKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKeyPath = Constants.VendorPublicKeyPath;
            var signByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act
            IPgpService pgpService = new PgpService();
            pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, useASCIIArmor);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignInvalidKeyData))]
        public void EncryptFileAndSign_InvalidKeysWillThrowException(EncryptFileAndSignInvalidDataKeyDetails data)
        {
            // Arrange
            var encryptByPublicKeyPath = data.EncryptByPublicKeyPath;
            var signByPrivateKeyPath = data.SignByPrivateKeyPath;
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = Assert.Throws<PGPOperationException>(() => pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, false));
            Assert.True(ex.OperationName == nameof(pgpService.EncryptFileAndSign));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignInvalidRequiredArgumentData))]
        public void EncryptFileAndSign_InvalidRequiredArgumentWillThrowException(EncryptFileAndSignInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            string encryptByPublicKeyPath = data.EncryptByPublicKeyPath ?? string.Empty;
            string signByPrivateKeyPath = data.SignByPrivateKeyPath ?? string.Empty;
            string signByPrivateKeyPassPhrase = string.Empty;
            string inputFilePath = data.InputFilePath ?? string.Empty;
            string outputFilePath = data.OutputFilePath ?? string.Empty;

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<ArgumentException>(() => pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, false));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignInvalidFileData))]
        public void EncryptFileAndSign_InvalidFileWillThrowException(EncryptFileAndSignInvalidFileDataDetails data)
        {
            // Arrange
            var encryptByPublicKeyPath = data.EncryptByPublicKeyPath;
            var signByPrivateKeyPath = data.SignByPrivateKeyPath;
            string signByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<FileNotFoundException>(() => pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, false));
        }

        #endregion

        #region -- EncryptFileAndSignAsync --

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task EncryptFileAndSignAsync_ValidateKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKeyPath = Constants.VendorPublicKeyPath;
            var signByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPgpService pgpService = new PgpService();
            await pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, useASCIIArmor, tokenSource.Token);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignInvalidKeyData))]
        public async Task EncryptFileAndSignAsync_InvalidKeysWillThrowException(EncryptFileAndSignInvalidDataKeyDetails data)
        {
            // Arrange
            var encryptByPublicKeyPath = data.EncryptByPublicKeyPath;
            var signByPrivateKeyPath = data.SignByPrivateKeyPath;
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = await Assert.ThrowsAsync<PGPOperationException>(() => pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, false, tokenSource.Token));
            Assert.True(ex.OperationName == nameof(pgpService.EncryptFileAndSignAsync));
        }

        [Fact]
        public async Task EncryptFileAndSignAsync_TokenCancellationWillThrowException()
        {
            // Arrange
            var encryptByPublicKeyPath = Constants.VendorPublicKeyPath;
            var signByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(0);

            // Act & Assert
            tokenSource.Cancel();

            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<OperationCanceledException>(() => 
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignInvalidRequiredArgumentData))]
        public async Task EncryptFileAndSignAsync_InvalidRequiredArgumentWillThrowException(EncryptFileAndSignInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            string encryptByPublicKeyPath = data.EncryptByPublicKeyPath ?? string.Empty;
            string signByPrivateKeyPath = data.SignByPrivateKeyPath ?? string.Empty;
            string signByPrivateKeyPassPhrase = string.Empty;
            string inputFilePath = data.InputFilePath ?? string.Empty;
            string outputFilePath = data.OutputFilePath ?? string.Empty;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<ArgumentException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignInvalidFileData))]
        public async Task EncryptFileAndSignAsync_InvalidFileWillThrowException(EncryptFileAndSignInvalidFileDataDetails data)
        {
            // Arrange
            var encryptByPublicKeyPath = data.EncryptByPublicKeyPath;
            var signByPrivateKeyPath = data.SignByPrivateKeyPath;
            string signByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyPath, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        #endregion

        #region -- EncryptFileAndSignAsync (Bytes) --

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task EncryptFileAndSignAsync_Bytes_ValidateKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPgpService pgpService = new PgpService();
            await pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, useASCIIArmor, tokenSource.Token);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignInvalidKeyData))]
        public async Task EncryptFileAndSignAsync_Bytes_InvalidKeysWillThrowException(EncryptFileAndSignInvalidDataKeyDetails data)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(data.EncryptByPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(data.SignByPrivateKeyPath);
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = await Assert.ThrowsAsync<PGPOperationException>(() => pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, false, tokenSource.Token));
            Assert.True(ex.OperationName == nameof(pgpService.EncryptFileAndSignAsync));
        }

        [Fact]
        public async Task EncryptFileAndSignAsync_Bytes_TokenCancellationWillThrowException()
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(0);

            // Act & Assert
            tokenSource.Cancel();

            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignBytesInvalidRequiredArgumentData))]
        public async Task EncryptFileAndSignAsync_Bytes_InvalidRequiredArgumentWillThrowException(EncryptFileAndSignBytesInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            string signByPrivateKeyPassPhrase = string.Empty;
            string inputFilePath = data.InputFilePath ?? string.Empty;
            string outputFilePath = data.OutputFilePath ?? string.Empty;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<ArgumentException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignBytesInvalidFileData))]
        public async Task EncryptFileAndSignAsync_Bytes_InvalidFileWillThrowException(EncryptFileAndSignBytesInvalidFileDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            string signByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        #endregion

        #region -- DecryptFileAndVerify --

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyValidData))]
        public void DecryptFileAndVerify_ValidateKeysWilWork(DecryptFileAndVerifyValidDataDetails data)
        {
            // Arrange
            var verifyByPublicKeyPath = Constants.VendorPublicKeyPath;
            var decryptByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = data.TestEncryptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act
            IPgpService pgpService = new PgpService();
            pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyInvalidKeyData))]
        public void DecryptFileAndVerify_InvalidKeysWillFail(DecryptFileAndVerifyInvalidDataKeyDetails data)
        {
            // Arrange
            var verifyByPublicKeyPath = data.VerifyPublicKeyPath;
            var decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var inputFilePath = data.EncyrptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = Assert.Throws<PGPOperationException>(() => pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase));
            Assert.True(ex.OperationName == nameof(pgpService.DecryptFileAndVerify));
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyInvalidRequiredArgumentData))]
        public void DecryptFileAndVerify_InvalidRequiredArgumentWillThrowException(DecryptFileAndVerifyInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            string verifyByPublicKeyPath = data.VerifyPublicKeyPath ?? string.Empty;
            string decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath ?? string.Empty;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            string inputFilePath = data.InputFilePath ?? string.Empty;
            string outputFilePath = data.OutputFilePath ?? string.Empty;

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<ArgumentException>(() =>
                pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyInvalidFileData))]
        public void DecryptFileAndVerify_InvalidFileWillThrowException(DecryptFileAndVerifyInvalidFileDataDetails data)
        {
            // Arrange
            var verifyByPublicKeyPath = data.VerifyPublicKeyPath;
            var decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<FileNotFoundException>(() =>
                pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase)
            );
        }

        #endregion

        #region -- DecryptFileAndVerifyAsync --

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyValidData))]
        public async Task DecryptFileAndVerifyAsync_ValidateKeysWilWork(DecryptFileAndVerifyValidDataDetails data)
        {
            // Arrange
            var verifyByPublicKeyPath = Constants.VendorPublicKeyPath;
            var decryptByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = data.TestEncryptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPgpService pgpService = new PgpService();
            await pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase, tokenSource.Token);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyInvalidKeyData))]
        public async Task DecryptFileAndVerifyAsync_InvalidKeysWillFail(DecryptFileAndVerifyInvalidDataKeyDetails data)
        {
            // Arrange
            var verifyByPublicKeyPath = data.VerifyPublicKeyPath;
            var decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var inputFilePath = data.EncyrptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = await Assert.ThrowsAsync<PGPOperationException>(() => pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase, tokenSource.Token));
            Assert.True(ex.OperationName == nameof(pgpService.DecryptFileAndVerifyAsync));
        }

        [Fact]
        public async Task DecryptFileAndVerifyAsync_ThrowOperationCancelledException()
        {
            // Arrange
            var verifyByPublicKeyPath = Constants.DigiAeonPublicKeyPath;
            var decryptByPrivateKeyPath = Constants.VendorPrivateKeyPath;
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(0);

            // Act & Assert
            tokenSource.Cancel();

            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyInvalidRequiredArgumentData))]
        public async Task DecryptFileAndVerifyAsync_InvalidRequiredArgumentWillThrowException(DecryptFileAndVerifyInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            string verifyByPublicKeyPath = data.VerifyPublicKeyPath ?? string.Empty;
            string decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath ?? string.Empty;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            string inputFilePath = data.InputFilePath ?? string.Empty;
            string outputFilePath = data.OutputFilePath ?? string.Empty;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<ArgumentException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyInvalidFileData))]
        public async Task DecryptFileAndVerifyAsync_InvalidFileWillThrowException(DecryptFileAndVerifyInvalidFileDataDetails data)
        {
            // Arrange
            var verifyByPublicKeyPath = data.VerifyPublicKeyPath;
            var decryptByPrivateKeyPath = data.DecryptByPrivateKeyPath;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyPath, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        #endregion

        #region -- DecryptFileAndVerifyAsync (Bytes) --

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyValidData))]
        public async Task DecryptFileAndVerifyAsync_Bytes_ValidateKeysWilWork(DecryptFileAndVerifyValidDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = data.TestEncryptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPgpService pgpService = new PgpService();
            await pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyInvalidKeyData))]
        public async Task DecryptFileAndVerifyAsync_Bytes_InvalidKeysWillFail(DecryptFileAndVerifyInvalidDataKeyDetails data)
        {
            // Arrange
            var verifyByPublicKey = File.ReadAllBytes(data.VerifyPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(data.DecryptByPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var inputFilePath = data.EncyrptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = await Assert.ThrowsAsync<PGPOperationException>(() => pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token));
            Assert.True(ex.OperationName == nameof(pgpService.DecryptFileAndVerifyAsync));
        }

        [Fact]
        public async Task DecryptFileAndVerifyAsync_Bytes_ThrowOperationCancelledException()
        {
            // Arrange
            var verifyByPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(0);

            // Act & Assert
            tokenSource.Cancel();

            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyBytesInvalidRequiredArgumentData))]
        public async Task DecryptFileAndVerifyAsync_Bytes_InvalidRequiredArgumentWillThrowException(DecryptFileAndVerifyBytesInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            string inputFilePath = data.InputFilePath ?? string.Empty;
            string outputFilePath = data.OutputFilePath ?? string.Empty;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<ArgumentException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyBytesInvalidFileData))]
        public async Task DecryptFileAndVerifyAsync_Bytes_InvalidFileWillThrowException(DecryptFileAndVerifyBytesInvalidFileDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        #endregion

        #region -- EncryptFileAndSignUsingKeyFileBytes --

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void EncryptFileAndSignUsingKeyFileBytes_ValidKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act
            IPgpService pgpService = new PgpService();
            pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, useASCIIArmor);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignUsingKeyFileBytesInvalidKeyData))]
        public void EncryptFileAndSignUsingKeyFileBytes_InvalidKeysWillThrowException(EncryptFileAndSignUsingKeyFileBytesInvalidDataKeyDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = Assert.Throws<PGPOperationException>(() => pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, false));
            Assert.True(ex.OperationName == nameof(pgpService.EncryptFileAndSign));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentData))]
        public void EncryptFileAndSignUsingKeyFileBytes_InvalidRequiredArgumentWillThrowException(EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            string signByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = data.OutputFilePath;

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<ArgumentException>(() => pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, false));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignUsingKeyFileBytesInvalidFileData))]
        public void EncryptFileAndSignUsingKeyFileBytes_InvalidFileWillThrowException(EncryptFileAndSignUsingKeyFileBytesInvalidFileDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            string signByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<FileNotFoundException>(() => pgpService.EncryptFileAndSign(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, false));
        }

        #endregion

        #region -- EncryptFileAndSignUsingKeyFileBytesAsync --

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task EncryptFileAndSignUsingKeyFileBytesAsync_ValidateKeysWillWork(bool useASCIIArmor)
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPgpService pgpService = new PgpService();
            await pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, useASCIIArmor, tokenSource.Token);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignUsingKeyFileBytesInvalidKeyData))]
        public async Task EncryptFileAndSignUsingKeyFileBytesAsync_InvalidKeysWillThrowException(EncryptFileAndSignUsingKeyFileBytesInvalidDataKeyDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            var signByPrivateKeyPassPhrase = data.SignByPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = await Assert.ThrowsAsync<PGPOperationException>(() => pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, false, tokenSource.Token));
            Assert.True(ex.OperationName == nameof(pgpService.EncryptFileAndSignAsync));
        }

        [Fact]
        public async Task EncryptFileAndSignUsingKeyFileBytesAsync_TokenCancellationWillThrowException()
        {
            // Arrange
            var encryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var signByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var signByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(0);

            // Act & Assert
            tokenSource.Cancel();

            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentData))]
        public async Task EncryptFileAndSignUsingKeyFileBytesAsync_InvalidRequiredArgumentWillThrowException(EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            string signByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = data.OutputFilePath;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<ArgumentException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(EncryptFileAndSignUsingKeyFileBytesInvalidFileData))]
        public async Task EncryptFileAndSignUsingKeyFileBytesAsync_InvalidFileWillThrowException(EncryptFileAndSignUsingKeyFileBytesInvalidFileDataDetails data)
        {
            // Arrange
            var encryptByPublicKey = data.EncryptByPublicKey;
            var signByPrivateKey = data.SignByPrivateKey;
            string signByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                pgpService.EncryptFileAndSignAsync(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase, true, tokenSource.Token)
            );
        }

        #endregion

        #region -- DecryptFileAndVerifyUsingKeyFileBytes --

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyValidData))]
        public void DecryptFileAndVerifyUsingKeyFileBytes_ValidateKeysWilWork(DecryptFileAndVerifyValidDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = data.TestEncryptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act
            IPgpService pgpService = new PgpService();
            pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyUsingKeyFileBytesInvalidKeyData))]
        public void DecryptFileAndVerifyUsingKeyFileBytes_InvalidKeysWillFail(DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var inputFilePath = data.EncyrptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = Assert.Throws<PGPOperationException>(() => pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase));
            Assert.True(ex.OperationName == nameof(pgpService.DecryptFileAndVerify));
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentData))]
        public void DecryptFileAndVerifyUsingKeyFileBytes_InvalidRequiredArgumentWillThrowException(DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = data.OutputFilePath;

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<ArgumentException>(() =>
                pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyUsingKeyFileBytesInvalidFileData))]
        public void DecryptFileAndVerifyUsingKeyFileBytes_InvalidFileWillThrowException(DecryptFileAndVerifyUsingKeyFileBytesInvalidFileDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));

            // Act & Assert
            IPgpService pgpService = new PgpService();
            Assert.Throws<FileNotFoundException>(() =>
                pgpService.DecryptFileAndVerify(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase)
            );
        }

        #endregion

        #region -- DecryptFileAndVerifyUsingKeyFileBytesAsync --

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyValidData))]
        public async Task DecryptFileAndVerifyUsingKeyFileBytesAsync_ValidateKeysWilWork(DecryptFileAndVerifyValidDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase;
            var inputFilePath = data.TestEncryptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act
            IPgpService pgpService = new PgpService();
            await pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token);

            // Assert
            Assert.True(File.Exists(outputFilePath));
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyUsingKeyFileBytesInvalidKeyData))]
        public async Task DecryptFileAndVerifyUsingKeyFileBytesAsync_InvalidKeysWillFail(DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            var decryptByPrivateKeyPassPhrase = data.DecryptByPrivateKeyPassPhrase;
            var inputFilePath = data.EncyrptedFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            var ex = await Assert.ThrowsAsync<PGPOperationException>(() => pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token));
            Assert.True(ex.OperationName == nameof(pgpService.DecryptFileAndVerifyAsync));
        }

        [Fact]
        public async Task DecryptFileAndVerifyUsingKeyFileBytesAsync_ThrowOperationCancelledException()
        {
            // Arrange
            var verifyByPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath);
            var decryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath);
            var decryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase;
            var inputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(0);

            // Act & Assert
            tokenSource.Cancel();

            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentData))]
        public async Task DecryptFileAndVerifyUsingKeyFileBytesAsync_InvalidRequiredArgumentWillThrowException(DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = data.OutputFilePath;
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<ArgumentException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        [Theory]
        [ClassData(typeof(DecryptFileAndVerifyUsingKeyFileBytesInvalidFileData))]
        public async Task DecryptFileAndVerifyUsingKeyFileBytesAsync_InvalidFileWillThrowException(DecryptFileAndVerifyUsingKeyFileBytesInvalidFileDataDetails data)
        {
            // Arrange
            var verifyByPublicKey = data.VerifyPublicKey;
            var decryptByPrivateKey = data.DecryptByPrivateKey;
            string decryptByPrivateKeyPassPhrase = string.Empty;
            var inputFilePath = data.InputFilePath;
            var outputFilePath = Path.Combine(TemporaryTestDirectory, FileHelper.GenerateUniqueFileName(".txt"));
            var tokenSource = new CancellationTokenSource(Constants.ExpectedTimeoutInMillisecond);

            // Act & Assert
            IPgpService pgpService = new PgpService();
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                pgpService.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase, tokenSource.Token)
            );
        }

        #endregion
    }
}
