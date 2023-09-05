using Microsoft.Win32.SafeHandles;
using DigiAeon.Common.OpenPGP.Exceptions;
using DigiAeon.Common.OpenPGP.Interfaces;
using DigiAeon.Common.OpenPGP.Shared;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace DigiAeon.Common.OpenPGP
{
    public class PGPService : IPGPService, ITrackingDisposable
    {
        private bool _disposed;

        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, string encryptByPublicKeyPath, string signByPrivateKeyFilePath, string signByPrivateKeyPassPhrase, bool useASCIIArmor)
        {
            ValidateEncryptFileAndSignParameters(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyFilePath);

            try
            {
                PGPProcessor.GetInstance(File.ReadAllBytes(encryptByPublicKeyPath), File.ReadAllBytes(signByPrivateKeyFilePath), signByPrivateKeyPassPhrase)
                    .EncryptFileAndSign(inputFilePath, outputFilePath, armor: useASCIIArmor, withIntegrityCheck: true);
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(EncryptFileAndSign), ex);
            }
        }

        public Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, string encryptByPublicKeyPath, string signByPrivateKeyFilePath, string signByPrivateKeyPassPhrase, bool useASCIIArmor, CancellationToken cancellationToken) => Track(async () =>
        {
            ValidateEncryptFileAndSignParameters(inputFilePath, outputFilePath, encryptByPublicKeyPath, signByPrivateKeyFilePath);

            try
            {
                var pgp = PGPProcessor.GetInstance(File.ReadAllBytes(encryptByPublicKeyPath), File.ReadAllBytes(signByPrivateKeyFilePath), signByPrivateKeyPassPhrase);

                cancellationToken.ThrowIfCancellationRequested();

                await pgp.EncryptFileAndSignAsync(inputFilePath, outputFilePath, armor: useASCIIArmor, withIntegrityCheck: true).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(EncryptFileAndSignAsync), ex);
            }
        });

        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, byte[]? encryptByPublicKey, byte[]? signByPrivateKey, string signByPrivateKeyPassPhrase, bool useASCIIArmor)
        {
            ValidateEncryptFileAndSignParameters(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey);

            try
            {
                PGPProcessor.GetInstance(encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase)
                    .EncryptFileAndSign(inputFilePath, outputFilePath, armor: useASCIIArmor, withIntegrityCheck: true);
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(EncryptFileAndSign), ex);
            }
        }

        public Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, byte[]? encryptByPublicKey, byte[]? signByPrivateKey, string signByPrivateKeyPassPhrase, bool useASCIIArmor, CancellationToken cancellationToken) => Track(async () =>
        {
            ValidateEncryptFileAndSignParameters(inputFilePath, outputFilePath, encryptByPublicKey, signByPrivateKey);

            try
            {
                var pgp = PGPProcessor.GetInstance(encryptByPublicKey, signByPrivateKey, signByPrivateKeyPassPhrase);

                cancellationToken.ThrowIfCancellationRequested();

                await pgp.EncryptFileAndSignAsync(inputFilePath, outputFilePath, armor: useASCIIArmor, withIntegrityCheck: true).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(EncryptFileAndSignAsync), ex);
            }
        });

        private void ValidateEncryptFileAndSignParameters(string inputFilePath, string outputFilePath, string encryptByPublicKeyPath, string signByPrivateKeyFilePath)
        {
            ValidationHelper.ValidateForRequiredArgument(inputFilePath, nameof(inputFilePath));
            ValidationHelper.ValidateIfFileExists(inputFilePath);

            ValidationHelper.ValidateForRequiredArgument(outputFilePath, nameof(outputFilePath));

            ValidationHelper.ValidateForRequiredArgument(encryptByPublicKeyPath, nameof(encryptByPublicKeyPath));
            ValidationHelper.ValidateIfFileExists(encryptByPublicKeyPath);

            ValidationHelper.ValidateForRequiredArgument(signByPrivateKeyFilePath, nameof(signByPrivateKeyFilePath));
            ValidationHelper.ValidateIfFileExists(signByPrivateKeyFilePath);
        }

        private void ValidateEncryptFileAndSignParameters(string inputFilePath, string outputFilePath, byte[]? encryptByPublicKey, byte[]? signByPrivateKey)
        {
            ValidationHelper.ValidateForRequiredArgument(inputFilePath, nameof(inputFilePath));
            ValidationHelper.ValidateIfFileExists(inputFilePath);

            ValidationHelper.ValidateForRequiredArgument(outputFilePath, nameof(outputFilePath));

            ValidationHelper.ValidateForRequiredArgument(encryptByPublicKey, nameof(encryptByPublicKey));

            ValidationHelper.ValidateForRequiredArgument(signByPrivateKey, nameof(signByPrivateKey));
        }

        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, string verifyByPublicKeyPath, string decryptByPrivateKeyFilePath, string decryptByPrivateKeyPassPhrase)
        {
            ValidateDecryptFileAndVerifyParameters(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyFilePath);

            try
            {
                PGPProcessor.GetInstance(File.ReadAllBytes(verifyByPublicKeyPath), File.ReadAllBytes(decryptByPrivateKeyFilePath), decryptByPrivateKeyPassPhrase)
                    .DecryptFileAndVerify(inputFilePath, outputFilePath);
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(DecryptFileAndVerify), ex);
            }
        }

        public Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, string verifyByPublicKeyPath, string decryptByPrivateKeyFilePath, string decryptByPrivateKeyPassPhrase, CancellationToken cancellationToken) => Track(async () =>
        {
            ValidateDecryptFileAndVerifyParameters(inputFilePath, outputFilePath, verifyByPublicKeyPath, decryptByPrivateKeyFilePath);

            try
            {
                var pgp = PGPProcessor.GetInstance(File.ReadAllBytes(verifyByPublicKeyPath), File.ReadAllBytes(decryptByPrivateKeyFilePath), decryptByPrivateKeyPassPhrase);

                cancellationToken.ThrowIfCancellationRequested();

                await pgp.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(DecryptFileAndVerifyAsync), ex);
            }
        });


        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, byte[]? verifyByPublicKey, byte[]? decryptByPrivateKey, string decryptByPrivateKeyPassPhrase)
        {
            ValidateDecryptFileAndVerifyParameters(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey);

            try
            {
                PGPProcessor.GetInstance(verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase)
                    .DecryptFileAndVerify(inputFilePath, outputFilePath);
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(DecryptFileAndVerify), ex);
            }
        }

        public Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, byte[]? verifyByPublicKey, byte[]? decryptByPrivateKey, string decryptByPrivateKeyPassPhrase, CancellationToken cancellationToken) => Track(async () =>
        {
            ValidateDecryptFileAndVerifyParameters(inputFilePath, outputFilePath, verifyByPublicKey, decryptByPrivateKey);

            try
            {
                var pgp = PGPProcessor.GetInstance(verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase);

                cancellationToken.ThrowIfCancellationRequested();

                await pgp.DecryptFileAndVerifyAsync(inputFilePath, outputFilePath).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(DecryptFileAndVerifyAsync), ex);
            }
        });

        public Task<Stream> DecryptFileAndVerifyAsync(string inputFilePath, byte[]? verifyByPublicKey, byte[]? decryptByPrivateKey, string decryptByPrivateKeyPassPhrase, CancellationToken cancellationToken) => Track(async () =>
        {
            ValidateDecryptFileAndVerifyParameters(inputFilePath, verifyByPublicKey, decryptByPrivateKey);

            try
            {
                var pgp = PGPProcessor.GetInstance(verifyByPublicKey, decryptByPrivateKey, decryptByPrivateKeyPassPhrase);

                cancellationToken.ThrowIfCancellationRequested();

                var stream = await pgp.DecryptFileAndVerifyAsync(inputFilePath).ConfigureAwait(false);
                return stream;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PGPOperationException(nameof(DecryptFileAndVerifyAsync), ex);
            }
        });

        private void ValidateDecryptFileAndVerifyParameters(string inputFilePath, string outputFilePath, string verifyByPublicKeyPath, string decryptByPrivateKeyFilePath)
        {
            ValidationHelper.ValidateForRequiredArgument(inputFilePath, nameof(inputFilePath));
            ValidationHelper.ValidateIfFileExists(inputFilePath);

            ValidationHelper.ValidateForRequiredArgument(outputFilePath, nameof(outputFilePath));

            ValidationHelper.ValidateForRequiredArgument(verifyByPublicKeyPath, nameof(verifyByPublicKeyPath));
            ValidationHelper.ValidateIfFileExists(verifyByPublicKeyPath);

            ValidationHelper.ValidateForRequiredArgument(decryptByPrivateKeyFilePath, nameof(decryptByPrivateKeyFilePath));
            ValidationHelper.ValidateIfFileExists(decryptByPrivateKeyFilePath);
        }

        private void ValidateDecryptFileAndVerifyParameters(string inputFilePath, string outputFilePath, byte[]? verifyByPublicKey, byte[]? decryptByPrivateKey)
        {
            ValidationHelper.ValidateForRequiredArgument(inputFilePath, nameof(inputFilePath));
            ValidationHelper.ValidateIfFileExists(inputFilePath);

            ValidationHelper.ValidateForRequiredArgument(outputFilePath, nameof(outputFilePath));

            ValidationHelper.ValidateForRequiredArgument(verifyByPublicKey, nameof(verifyByPublicKey));

            ValidationHelper.ValidateForRequiredArgument(decryptByPrivateKey, nameof(decryptByPrivateKey));
        }

        private void ValidateDecryptFileAndVerifyParameters(string inputFilePath, byte[]? verifyByPublicKey, byte[]? decryptByPrivateKey)
        {
            ValidationHelper.ValidateForRequiredArgument(inputFilePath, nameof(inputFilePath));
            ValidationHelper.ValidateIfFileExists(inputFilePath);

            ValidationHelper.ValidateForRequiredArgument(verifyByPublicKey, nameof(verifyByPublicKey));

            ValidationHelper.ValidateForRequiredArgument(decryptByPrivateKey, nameof(decryptByPrivateKey));
        }

        private readonly TrackingDisposer _disposer;

        public PGPService() => _disposer = new TrackingDisposer(this);

        protected virtual void FinishDispose() { }

        protected virtual Task FinishDisposeAsync()
        => Task.CompletedTask;

        Task ITrackingDisposable.FinishDisposeAsync()
        {
            FinishDispose();
            return FinishDisposeAsync();
        }

        public void Dispose()
        => _disposer.Dispose();

        protected Task Track(Func<Task> func)
        => _disposer.Track(func, out var result)
            ? result
            : throw new ObjectDisposedException(nameof(PGPService));

        protected Task<TResult> Track<TResult>(Func<Task<TResult>> func)
        => _disposer.Track(func, out var result)
            ? result
            : throw new ObjectDisposedException(nameof(PGPService));
    }
}
