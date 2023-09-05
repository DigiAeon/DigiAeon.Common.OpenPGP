using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using DigiAeon.Common.OpenPGP.Exceptions;
using DigiAeon.Common.OpenPGP.Interfaces;

namespace DigiAeon.Common.OpenPGP
{
    internal enum PGPFileType
    {
        Binary,
        Text,
        UTF8
    }

    internal class PGPProcessor
    {
        #region Constants & Private Variables

        private const int BufferSize = 0x10000;

        private readonly IKeyStores _encryptionKeys;

        #endregion Constants & Private Variables

        #region Constructors

        private PGPProcessor(IKeyStores encryptionKeys)
        {
            _encryptionKeys = encryptionKeys;
        }

        internal static PGPProcessor GetInstance(byte[]? publicKey, byte[]? privateKey, string passPhrase)
        {
            return new PGPProcessor(new KeyStores(publicKey, privateKey, passPhrase));
        }

        #endregion Constructors

        #region Public Properties

        public CompressionAlgorithmTag CompressionAlgorithm { get; set; } = CompressionAlgorithmTag.Uncompressed;

        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; } = SymmetricKeyAlgorithmTag.TripleDes;

        public PGPFileType FileType { get; set; } = PGPFileType.Binary;

        public HashAlgorithmTag HashAlgorithmTag { get; set; } = HashAlgorithmTag.Sha1;

        #endregion Public Properties

        #region EncryptFileAndSign

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, bool armor = true, bool withIntegrityCheck = true)
        {
            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        await OutputEncryptedAsync(inputFilePath, armoredOutputStream, withIntegrityCheck);
                    }
                }
                else
                {
                    await OutputEncryptedAsync(inputFilePath, outputStream, withIntegrityCheck);
                }
            }
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, bool armor = true, bool withIntegrityCheck = true)
        {
            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputEncrypted(inputFilePath, armoredOutputStream, withIntegrityCheck);
                    }
                }
                else
                {
                    OutputEncrypted(inputFilePath, outputStream, withIntegrityCheck);
                }
            }
        }

        #endregion EncryptFileAndSign

        #region DecryptFileAndVerify

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath)
        {
            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream outStream = File.Create(outputFilePath))
            {
                await DecryptStreamAndVerifyAsync(inputStream, outStream);
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified file path</param>
        public async Task<Stream> DecryptFileAndVerifyAsync(string inputFilePath)
        {
            using (Stream inputStream = File.OpenRead(inputFilePath))
            {
                Stream outStream = new MemoryStream();
                await DecryptStreamAndVerifyAsync(inputStream, outStream);
                outStream.Position = 0; // reset it back to the start
                return outStream;
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath)
        {
            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream outStream = File.Create(outputFilePath))
            {
                DecryptAndVerify(inputStream, outStream);
            }
        }

        #endregion DecryptFileAndVerify

        #region DecryptStreamAndVerify

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        public async Task<Stream> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream)
        {
            ValidateStreamPosition(inputStream);

            await DecryptAndVerifyAsync(inputStream, outputStream);

            return outputStream;
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        public Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream)
        {
            ValidateStreamPosition(inputStream);

            DecryptAndVerify(inputStream, outputStream);

            return outputStream;
        }

        private void ValidateStreamPosition(Stream inputStream)
        {
            if (inputStream.Position != 0)
            {
                throw new PGPOperationException("Incorrect input stream position.");
            }
        }

        #endregion DecryptStreamAndVerify

        #region OutputEncryptedAsync

        private async Task OutputEncryptedAsync(string inputFilePath, Stream outputStream, bool withIntegrityCheck)
        {
            await OutputEncryptedAsync(new FileInfo(inputFilePath), outputStream, withIntegrityCheck);
        }

        private async Task OutputEncryptedAsync(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
                    {
                        using (FileStream inputFileStream = inputFile.OpenRead())
                        {
                            await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator);
                        }
                    }
                }
            }
        }

        #endregion OutputEncryptedAsync

        #region OutputEncrypted

        private void OutputEncrypted(string inputFilePath, Stream outputStream, bool withIntegrityCheck)
        {
            OutputEncrypted(new FileInfo(inputFilePath), outputStream, withIntegrityCheck);
        }

        private void OutputEncrypted(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
                    {
                        using (FileStream inputFileStream = inputFile.OpenRead())
                        {
                            WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                        }
                    }
                }
            }
        }

        #endregion OutputEncrypted

        #region DecryptAndVerify

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        private async Task DecryptAndVerifyAsync(Stream inputStream, Stream outputStream)
        {
            var outputBytes = DecryptVerifyAndGetOutputBytes(inputStream);

            await outputStream.WriteAsync(outputBytes, 0, outputBytes.Length);
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        private void DecryptAndVerify(Stream inputStream, Stream outputStream)
        {
            var outputBytes = DecryptVerifyAndGetOutputBytes(inputStream);

            outputStream.Write(outputBytes, 0, outputBytes.Length);
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <returns>Output message bytes</returns>
        private byte[] DecryptVerifyAndGetOutputBytes(Stream inputStream)
        {
            byte[]? outputBytes = null;
            var streamsToClose = new List<Stream>();

            try
            {
                // load stream into factory
                var decoderStream = PgpUtilities.GetDecoderStream(inputStream);

                // Track stream for dispose
                streamsToClose.Add(decoderStream);

                PgpObjectFactory decoderStreamFactory = new PgpObjectFactory(decoderStream);
                PgpObject pgpObj = decoderStreamFactory.NextPgpObject();

                // first object may be a pgp marker... skip it
                var encryptedDataList = (pgpObj is PgpEncryptedDataList)
                                    ? pgpObj as PgpEncryptedDataList
                                    : decoderStreamFactory.NextPgpObject() as PgpEncryptedDataList;

                // retrieve encrypted data and private key
                var (privateKey, publicKeyEncryptedData) = RetrievePublicKeyEncryptedDataAndPrivateKey(encryptedDataList);

                // private key not found
                if (privateKey == null)
                {
                    throw new PGPOperationException("Failed to retrieve Private Key for decryption.");
                }

                // decrypt the encrypted data using the private key
                PgpObjectFactory? plainTextFactory = null;
                var plainTextStream = publicKeyEncryptedData.GetDataStream(privateKey);

                // Track stream for dispose
                streamsToClose.Add(plainTextStream);

                plainTextFactory = new PgpObjectFactory(plainTextStream);

                PgpOnePassSignatureList? onePassSignatureList = null;
                PgpSignatureList? signatureList = null;
                PgpCompressedData? compressedData = null;

                PgpObject message = plainTextFactory.NextPgpObject();

                using (MemoryStream ms = new MemoryStream())
                {
                    while (message != null)
                    {
                        // pre-process compressed data
                        if (message is PgpCompressedData compData)
                        {
                            compressedData = compData;

                            var compressedDataStream = compressedData.GetDataStream();

                            // Track stream for dispose
                            streamsToClose.Add(compressedDataStream);

                            plainTextFactory = new PgpObjectFactory(compressedDataStream);

                            message = plainTextFactory.NextPgpObject();
                        }

                        if (message is PgpLiteralData ltData)
                        {
                            // process Literal Data to Text Data
                            PgpLiteralData literalData = ltData;

                            using (Stream stream = literalData.GetInputStream())
                            {
                                stream.CopyTo(ms);
                            }
                        }
                        else if (message is PgpOnePassSignatureList ops)
                        {
                            onePassSignatureList = ops;
                        }
                        else if (message is PgpSignatureList)
                        {
                            signatureList = message as PgpSignatureList;
                        }
                        else
                        {
                            throw new PGPOperationException("Unknown message type.");
                        }

                        message = plainTextFactory.NextPgpObject();
                    }

                    // check if signature exists
                    if (onePassSignatureList == null || signatureList == null || onePassSignatureList.Count <= 0)
                    {
                        throw new PGPOperationException("Verification failed. Signatures not found.");
                    }

                    // check content exists
                    if (ms == null || ms.Length <= 0)
                    {
                        throw new PGPOperationException("Content not found.");
                    }

                    // copy content to byte array
                    outputBytes = ms.ToArray();
                }

                var publicKeys = _encryptionKeys.PublicKeysForVerification;
                if (publicKeys == null || publicKeys.Count == 0)
                {
                    throw new PGPOperationException("No public key not found for verification.");
                }

                // Verify signature
                VerifySignature(onePassSignatureList, signatureList, publicKeys, outputBytes);

                return outputBytes;
            }
            finally
            {
                // Safe close stream in reverse order
                try
                {
                    streamsToClose.Reverse();

                    foreach (var stream in streamsToClose)
                    {
                        if (stream?.CanRead == true)
                        {
                            stream.Dispose();
                        }
                    }
                }
                catch { }
            }
        }

        private (PgpPrivateKey privateKey, PgpPublicKeyEncryptedData publicKeyEncryptedData) RetrievePublicKeyEncryptedDataAndPrivateKey(PgpEncryptedDataList encryptedDataList)
        {
            PgpPrivateKey? key = null;
            PgpPublicKeyEncryptedData? data = null;

            foreach (PgpPublicKeyEncryptedData publicKeyED in encryptedDataList.GetEncryptedDataObjects())
            {
                key = _encryptionKeys.FindSecretKey(publicKeyED.KeyId);

                if (key != null)
                {
                    data = publicKeyED;
                    break;
                }
            }

            if (key == null)
            {
                throw new PGPOperationException("Secret key for message not found.");
            }

            return (key, data);
        }

        private void VerifySignature(PgpOnePassSignatureList onePassSignatureList, PgpSignatureList signatureList, List<PgpPublicKey> publicKeys, byte[] outputBytes)
        {
            // try to verify each OPS
            for (int i = 0; i < onePassSignatureList.Count; i++)
            {
                PgpOnePassSignature ops = onePassSignatureList[i];

                var matchingPublicKey = publicKeys.FirstOrDefault(x => x.KeyId == ops.KeyId);

                if (matchingPublicKey == null)
                {
                    throw new PGPOperationException("Matching public key not found for verification.");
                }

                // get matching Signature
                PgpSignature signature = null;
                for (int j = 0; j < signatureList.Count; j++)
                {
                    PgpSignature s = signatureList[j];
                    if (s.KeyId == ops.KeyId)
                    {
                        signature = s;
                        break;
                    }
                }

                if (signature == null)
                {
                    throw new SignatureException("Matching signature not found for verification.");
                }

                // verify Signature
                ops.InitVerify(matchingPublicKey);
                ops.Update(outputBytes);

                if (!ops.Verify(signature))
                {
                    throw new SignatureException("Signature verification failed.");
                }
            }
        }

        #endregion DecryptAndVerify

        #region WriteOutputAndSignAsync

        private async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
        {
            byte[] buf = new byte[BufferSize];
            int length;
            
            while ((length = await inputFilePath.ReadAsync(buf, 0, buf.Length)) > 0)
            {
                await literalOut.WriteAsync(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            
            signatureGenerator.Generate().Encode(compressedOut);
        }

        #endregion WriteOutputAndSignAsync

        #region WriteOutputAndSign

        private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
        {
            int length;
            byte[] buf = new byte[BufferSize];
            
            while ((length = inputFilePath.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            
            signatureGenerator.Generate().Encode(compressedOut);
        }

        #endregion WriteOutputAndSign

        #region ChainEncryptedOut

        private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck)
        {
            var encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

            encryptedDataGenerator.AddMethod(_encryptionKeys.PublicKeyForEncryption);

            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        #endregion ChainEncryptedOut

        #region ChainCompressedOut

        private Stream ChainCompressedOut(Stream encryptedOut)
        {
            if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
            {
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                return compressedDataGenerator.Open(encryptedOut);
            }
            else
            {
                return encryptedOut;
            }
        }

        #endregion ChainCompressedOut

        #region ChainLiteralOut

        private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            var pgpLiteralDataGenerator = new PgpLiteralDataGenerator();

            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file.Name, file.Length, DateTime.UtcNow);
        }

        private char FileTypeToChar()
        {
            switch (FileType)
            {
                case PGPFileType.UTF8:
                    return PgpLiteralData.Utf8;

                case PGPFileType.Text:
                    return PgpLiteralData.Text;

                default:
                    return PgpLiteralData.Binary;
            }
        }

        #endregion ChainLiteralOut

        #region Shared Helper Methods

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
        {
            var tag = _encryptionKeys.SecretKey.PublicKey.Algorithm;
            var pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);

            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, _encryptionKeys.PrivateKey);

            var userId = _encryptionKeys.SecretKey.PublicKey.GetUserIds().ToList().FirstOrDefault();

            if (userId != null)
            {
                var subPacketGenerator = new PgpSignatureSubpacketGenerator();

                subPacketGenerator.SetSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
            }

            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

            return pgpSignatureGenerator;
        }

        #endregion Shared Helper Methods
    }
}
