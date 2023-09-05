using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Collections.Generic;

namespace DigiAeon.Common.OpenPGP.Interfaces
{
    internal interface IKeyStores
    {
        PgpPublicKey PublicKeyForEncryption { get; }
        List<PgpPublicKey> PublicKeysForVerification { get; }
        PgpPrivateKey PrivateKey { get; }
        PgpSecretKey SecretKey { get; }
        PgpPrivateKey FindSecretKey(long keyId);
    }
}