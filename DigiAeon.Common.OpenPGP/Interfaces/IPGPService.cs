﻿namespace DigiAeon.Common.OpenPGP.Interfaces
{
    public interface IPGPService : IDisposable
    {
        void EncryptFileAndSign(string inputFilePath, string outputFilePath, string encryptByPublicKeyFilePath, string signByPrivateKeyFilePath, string signByPrivateKeyPassPhrase, bool useASCIIArmor);

        Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, string encryptByPublicKeyFilePath, string signByPrivateKeyFilePath, string signByPrivateKeyPassPhrase, bool useASCIIArmor, CancellationToken cancellationToken);

        void DecryptFileAndVerify(string inputFilePath, string outputFilePath, string verifyByPublicKeyFilePath, string decryptByPrivateKeyFilePath, string decryptByPrivateKeyPassPhrase);

        Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, string verifyByPublicKeyFilePath, string decryptByPrivateKeyFilePath, string decryptByPrivateKeyPassPhrase, CancellationToken cancellationToken);

        void EncryptFileAndSign(string inputFilePath, string outputFilePath, byte[] encryptByPublicKey, byte[] signByPrivateKey, string signByPrivateKeyPassPhrase, bool useASCIIArmor);

        Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, byte[] encryptByPublicKey, byte[] signByPrivateKey, string signByPrivateKeyPassPhrase, bool useASCIIArmor, CancellationToken cancellationToken);

        void DecryptFileAndVerify(string inputFilePath, string outputFilePath, byte[] verifyByPublicKey, byte[] decryptByPrivateKey, string decryptByPrivateKeyPassPhrase);

        Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, byte[] verifyByPublicKey, byte[] decryptByPrivateKey, string decryptByPrivateKeyPassPhrase, CancellationToken cancellationToken);

        Task<Stream> DecryptFileAndVerifyAsync(string inputFilePath, byte[] publicPgpKey, byte[] privatePgpKey, string privatePgpKeyPassphrase, CancellationToken cancellationToken);
    }
}
