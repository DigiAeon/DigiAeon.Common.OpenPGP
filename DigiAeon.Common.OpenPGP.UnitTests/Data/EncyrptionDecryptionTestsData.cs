using DigiAeon.Common.OpenPGP.UnitTests.Shared;

namespace DigiAeon.Common.OpenPGP.UnitTests.Data
{
    public class EncyrptionDecryptionInvalidKeyDataDetails
    {
        public string EncryptByPublicKeyPath { get; set; }
        public string SignByPrivateKeyPath { get; set; }
        public string SignByPrivateKeyPassPhrase { get; set; }
        public string VerifyPublicKeyPath { get; set; }
        public string DecryptByPrivateKeyPath { get; set; }
        public string DecryptByPrivateKeyPassPhrase { get; set; }
    }

    public class EncyrptionDecryptionInvalidKeyData : TheoryData<EncyrptionDecryptionInvalidKeyDataDetails>
    {
        public EncyrptionDecryptionInvalidKeyData()
        {
            // Use of invalid private key during encryption
            Add(new EncyrptionDecryptionInvalidKeyDataDetails
            {
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                SignByPrivateKeyPath = Constants.InvalidPrivateKeyPath,
                SignByPrivateKeyPassPhrase = Constants.InvalidPrivateKeyPassPhrase,
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath,
                DecryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase
            });

            // Use of invalid private key during decryption
            Add(new EncyrptionDecryptionInvalidKeyDataDetails
            {
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath,
                SignByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase,
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.InvalidPrivateKeyPath,
                DecryptByPrivateKeyPassPhrase = Constants.InvalidPrivateKeyPassPhrase
            });

            // Use of invalid public and private key during encryption
            Add(new EncyrptionDecryptionInvalidKeyDataDetails
            {
                EncryptByPublicKeyPath = Constants.InvalidPublicKeyPath,
                SignByPrivateKeyPath = Constants.InvalidPrivateKeyPath,
                SignByPrivateKeyPassPhrase = Constants.InvalidPrivateKeyPassPhrase,
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath,
                DecryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase
            });

            // Use of invalid public and private key during decryption
            Add(new EncyrptionDecryptionInvalidKeyDataDetails
            {
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath,
                SignByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase,
                VerifyPublicKeyPath = Constants.InvalidPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.InvalidPrivateKeyPath,
                DecryptByPrivateKeyPassPhrase = Constants.InvalidPrivateKeyPassPhrase
            });
        }
    }
}
