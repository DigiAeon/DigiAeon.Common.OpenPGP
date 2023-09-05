using Org.BouncyCastle.Bcpg.OpenPgp;
using DigiAeon.Common.OpenPGP.Interfaces;

namespace DigiAeon.Common.OpenPGP
{
    internal class KeyStores : IKeyStores
    {
        public PgpPublicKey PublicKeyForEncryption { get; }
        public List<PgpPublicKey> PublicKeysForVerification { get; }
        public PgpPrivateKey PrivateKey { get; }
        public PgpSecretKey SecretKey { get; }
        public PgpSecretKeyRingBundle SecretKeys { get; }

        private readonly string _passPhrase;

        /// <summary>
        /// Initializes a new instance of the EncryptionKeys class.
        /// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
        /// The data is encrypted with the recipients public key and signed with your private key.
        /// </summary>
        /// <param name="publicKey">The key used to encrypt the data</param>
        /// <param name="privateKey">The key used to sign the data.</param>
        /// <param name="passPhrase">The password required to access the private key</param>
        /// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
        public KeyStores(byte[]? publicKey, byte[]? privateKey, string passPhrase)
        {
            if (publicKey == null)
                throw new ArgumentException(nameof(publicKey));

            if (privateKey == null)
                throw new ArgumentException(nameof(privateKey));

            if (passPhrase == null)
                throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");

            var publicKeys = ReadPublicKeys(publicKey);

            PublicKeyForEncryption = publicKeys.EncyptionPublicKey;
            PublicKeysForVerification = publicKeys.VerificationPublicKeys;
            SecretKeys = ReadSecretKeys(privateKey);
            SecretKey = ReadSecretKey(SecretKeys);
            PrivateKey = ReadPrivateKey(passPhrase);
            _passPhrase = passPhrase;
        }

        private PgpSecretKeyRingBundle ReadSecretKeys(byte[] privateKey)
        {
            using (Stream privateKeyStream = new MemoryStream(privateKey))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyStream))
            {
                return new PgpSecretKeyRingBundle(inputStream);
            }

            throw new Exception("Can't find secret key bundle.");
        }

        private PgpSecretKey ReadSecretKey(PgpSecretKeyRingBundle secretKeys)
        {
            var key = GetFirstSecretKey(secretKeys);

            if (key != null)
            {
                return key;
            }

            throw new Exception("Can't find signing key in key ring.");
        }

        /// <summary>
        /// Return the first key we can use to encrypt.
        /// Note: A file can contain multiple keys (stored in "key rings")
        /// </summary>
        private PgpSecretKey? GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                var key = kRing.GetSecretKeys()
                    .Cast<PgpSecretKey>()
                    .FirstOrDefault(k => k.IsSigningKey);

                if (key != null)
                {
                    return key;
                }
            }

            return null;
        }

        private (PgpPublicKey EncyptionPublicKey, List<PgpPublicKey> VerificationPublicKeys) ReadPublicKeys(byte[] publicKey)
        {
            using (Stream publicKeyStream = new MemoryStream(publicKey))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(publicKeyStream))
            {
                var publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                
                return GetPublicKeys(publicKeyRingBundle);
            }

            throw new Exception("No encryption key found in public key ring.");
        }

        private (PgpPublicKey EncyptionPublicKey, List<PgpPublicKey> VerificationPublicKeys) GetPublicKeys(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            var keys = publicKeyRingBundle
                .GetKeyRings()
                .Cast<PgpPublicKeyRing>()
                .SelectMany(x => x.GetPublicKeys().Cast<PgpPublicKey>())
                .ToList();

            // Public key can have master key and one or more sub keys with each having multiple abilities like encryption, sign, verification can be used to verify signature
            // and both master key and sub key can have an ability to encrypt the data
            // so, it's wish to consider all keys for verification as PgpPublicKey doesn't have property like IsVerificationKey
            // This is obviously assuming that key without verification ability cannot verify!
            return (keys.FirstOrDefault(x => x.IsEncryptionKey), keys);
        }

        private PgpPrivateKey ReadPrivateKey(string passPhrase)
        {
            var privateKey = SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());

            if (privateKey != null)
            {
                return privateKey;
            }

            throw new Exception("No private key found in secret key.");
        }

        public PgpPrivateKey FindSecretKey(long keyId)
        {
            PgpSecretKey pgpSecKey = SecretKeys.GetSecretKey(keyId);

            return pgpSecKey?.ExtractPrivateKey(_passPhrase.ToCharArray());
        }
    }
}
