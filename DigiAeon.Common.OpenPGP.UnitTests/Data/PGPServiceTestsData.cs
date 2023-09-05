using DigiAeon.Common.OpenPGP.UnitTests.Shared;
using Xunit;

namespace DigiAeon.Common.OpenPGP.UnitTests.Data
{
    #region -- EncryptFileAndSign --

    public class EncryptFileAndSignInvalidDataKeyDetails
    {
        public string EncryptByPublicKeyPath { get; set; } = string.Empty;
        public string SignByPrivateKeyPath { get; set; } = string.Empty;
        public string SignByPrivateKeyPassPhrase { get; set; } = string.Empty;
    }

    public class EncryptFileAndSignInvalidKeyData : TheoryData<EncryptFileAndSignInvalidDataKeyDetails>
    {
        public EncryptFileAndSignInvalidKeyData()
        {
            Add(new EncryptFileAndSignInvalidDataKeyDetails
            {
                EncryptByPublicKeyPath = Constants.DigiAeonPrivateKeyPath, // Invalid public key
                SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath,
                SignByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase
            });

            Add(new EncryptFileAndSignInvalidDataKeyDetails
            {
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                SignByPrivateKeyPath = Constants.DigiAeonPublicKeyPath, // Invalid private key
                SignByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase
            });

            Add(new EncryptFileAndSignInvalidDataKeyDetails
            {
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath,
                SignByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase // Invalid pass phrase
            });
        }
    }

    public class EncryptFileAndSignUsingKeyFileBytesInvalidDataKeyDetails
    {
        public byte[]? EncryptByPublicKey { get; set; }
        public byte[]? SignByPrivateKey { get; set; }
        public string SignByPrivateKeyPassPhrase { get; set; } = string.Empty;
    }

    public class EncryptFileAndSignUsingKeyFileBytesInvalidKeyData : TheoryData<EncryptFileAndSignUsingKeyFileBytesInvalidDataKeyDetails>
    {
        public EncryptFileAndSignUsingKeyFileBytesInvalidKeyData()
        {
            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidDataKeyDetails
            {
                EncryptByPublicKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath), // Invalid public key
                SignByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath),
                SignByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase
            });

            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidDataKeyDetails
            {
                EncryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath),
                SignByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath), // Invalid private key
                SignByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase
            });

            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidDataKeyDetails
            {
                EncryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath),
                SignByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath),
                SignByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase // Invalid pass phrase
            });
        }
    }

    public class EncryptFileAndSignInvalidRequiredArgumentDataDetails
    {
        public string? InputFilePath { get; set; }
        public string? OutputFilePath { get; set; }
        public string? EncryptByPublicKeyPath { get; set; }
        public string? SignByPrivateKeyPath { get; set; }
    }

    public class EncryptFileAndSignInvalidRequiredArgumentData : TheoryData<EncryptFileAndSignInvalidRequiredArgumentDataDetails>
    {
        public EncryptFileAndSignInvalidRequiredArgumentData()
        {
            foreach (var emptyString in new[] { "", " ", null })
            {
                Add(new EncryptFileAndSignInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = emptyString,
                    OutputFilePath = @"C:\Temp\testoutput.txt",
                    EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                    SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath
                });

                Add(new EncryptFileAndSignInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = Constants.TestFilePath,
                    OutputFilePath = emptyString,
                    EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                    SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath
                });

                Add(new EncryptFileAndSignInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = Constants.TestFilePath,
                    OutputFilePath = @"C:\Temp\testoutput.txt",
                    EncryptByPublicKeyPath = emptyString,
                    SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath
                });

                Add(new EncryptFileAndSignInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = Constants.TestFilePath,
                    OutputFilePath = @"C:\Temp\testoutput.txt",
                    EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                    SignByPrivateKeyPath = emptyString
                });
            }
        }
    }

    public class EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails
    {
        public string InputFilePath { get; set; } = string.Empty;
        public string OutputFilePath { get; set; } = string.Empty;
        public byte[]? EncryptByPublicKey { get; set; }
        public byte[]? SignByPrivateKey { get; set; }
    }

    public class EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentData : TheoryData<EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails>
    {
        public EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentData()
        {
            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = " ",
                OutputFilePath = @"C:\Temp\testoutput.txt",
                EncryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath),
                SignByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath)
            });

            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = Constants.TestFilePath,
                OutputFilePath = " ",
                EncryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath),
                SignByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath)
            });

            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = Constants.TestFilePath,
                OutputFilePath = @"C:\Temp\testoutput.txt",
                EncryptByPublicKey = null,
                SignByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath)
            });

            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = Constants.TestFilePath,
                OutputFilePath = @"C:\Temp\testoutput.txt",
                EncryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath),
                SignByPrivateKey = null
            });
        }
    }

    public class EncryptFileAndSignInvalidFileDataDetails
    {
        public string InputFilePath { get; set; } = string.Empty;
        public string EncryptByPublicKeyPath { get; set; } = string.Empty;
        public string SignByPrivateKeyPath { get; set; } = string.Empty;
    }

    public class EncryptFileAndSignInvalidFileData : TheoryData<EncryptFileAndSignInvalidFileDataDetails>
    {
        public EncryptFileAndSignInvalidFileData()
        {
            Add(new EncryptFileAndSignInvalidFileDataDetails
            {
                InputFilePath = Constants.TestFilePath + ".txt",
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath
            });

            Add(new EncryptFileAndSignInvalidFileDataDetails
            {
                InputFilePath = Constants.TestFilePath,
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath + ".txt",
                SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath
            });

            Add(new EncryptFileAndSignInvalidFileDataDetails
            {
                InputFilePath = Constants.TestFilePath,
                EncryptByPublicKeyPath = Constants.VendorPublicKeyPath,
                SignByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath + ".txt"
            });
        }
    }

    public class EncryptFileAndSignUsingKeyFileBytesInvalidFileDataDetails
    {
        public string InputFilePath { get; set; } = string.Empty;
        public byte[]? EncryptByPublicKey { get; set; }
        public byte[]? SignByPrivateKey { get; set; }
    }

    public class EncryptFileAndSignUsingKeyFileBytesInvalidFileData : TheoryData<EncryptFileAndSignUsingKeyFileBytesInvalidFileDataDetails>
    {
        public EncryptFileAndSignUsingKeyFileBytesInvalidFileData()
        {
            Add(new EncryptFileAndSignUsingKeyFileBytesInvalidFileDataDetails
            {
                InputFilePath = Constants.TestFilePath + ".txt",
                EncryptByPublicKey = File.ReadAllBytes(Constants.VendorPublicKeyPath),
                SignByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath)
            });
        }
    }

    #endregion

    #region -- DecryptFileAndVerify --

    public class DecryptFileAndVerifyValidDataDetails
    {
        public string TestEncryptedFilePath { get; set; } = string.Empty;
    }

    public class DecryptFileAndVerifyValidData : TheoryData<DecryptFileAndVerifyValidDataDetails>
    {
        public DecryptFileAndVerifyValidData()
        {
            Add(new DecryptFileAndVerifyValidDataDetails
            {
                TestEncryptedFilePath = Constants.TestEncryptedFileWithASCIIArmorPath
            });

            Add(new DecryptFileAndVerifyValidDataDetails
            {
                TestEncryptedFilePath = Constants.TestEncryptedFileWithoutASCIIArmorPath
            });
        }
    }

    public class DecryptFileAndVerifyInvalidDataKeyDetails
    {
        public string EncyrptedFilePath { get; set; } = string.Empty;
        public string VerifyPublicKeyPath { get; set; } = string.Empty;
        public string DecryptByPrivateKeyPath { get; set; } = string.Empty;
        public string DecryptByPrivateKeyPassPhrase { get; set; } = string.Empty;
    }

    public class DecryptFileAndVerifyInvalidKeyData : TheoryData<DecryptFileAndVerifyInvalidDataKeyDetails>
    {
        public DecryptFileAndVerifyInvalidKeyData()
        {
            Add(new DecryptFileAndVerifyInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestFilePath, // Invalid input file
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath,
                DecryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase
            });

            Add(new DecryptFileAndVerifyInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKeyPath = Constants.DigiAeonPrivateKeyPath, // Invalid public key
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath,
                DecryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase
            });

            Add(new DecryptFileAndVerifyInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.DigiAeonPrivateKeyPath, // Invalid private key
                DecryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase
            });

            Add(new DecryptFileAndVerifyInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath,
                DecryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase // Invalid pass phrase
            });
        }
    }

    public class DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails
    {
        public string EncyrptedFilePath { get; set; } = string.Empty;
        public byte[]? VerifyPublicKey { get; set; }
        public byte[]? DecryptByPrivateKey { get; set; }
        public string DecryptByPrivateKeyPassPhrase { get; set; } = string.Empty;
    }

    public class DecryptFileAndVerifyUsingKeyFileBytesInvalidKeyData : TheoryData<DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails>
    {
        public DecryptFileAndVerifyUsingKeyFileBytesInvalidKeyData()
        {
            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestFilePath, // Invalid input file
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath),
                DecryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath),
                DecryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase
            });

            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath), // Invalid public key
                DecryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath),
                DecryptByPrivateKeyPassPhrase = Constants.VendorPrivateKeyPassPhrase
            });

            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath),
                DecryptByPrivateKey = File.ReadAllBytes(Constants.DigiAeonPrivateKeyPath), // Invalid private key
                DecryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase
            });

            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidDataKeyDetails
            {
                EncyrptedFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath),
                DecryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath),
                DecryptByPrivateKeyPassPhrase = Constants.DigiAeonPrivateKeyPassPhrase // Invalid pass phrase
            });
        }
    }

    public class DecryptFileAndVerifyInvalidRequiredArgumentDataDetails
    {
        public string? InputFilePath { get; set; }
        public string? OutputFilePath { get; set; }
        public string? VerifyPublicKeyPath { get; set; }
        public string? DecryptByPrivateKeyPath { get; set; }
    }

    public class DecryptFileAndVerifyInvalidRequiredArgumentData : TheoryData<DecryptFileAndVerifyInvalidRequiredArgumentDataDetails>
    {
        public DecryptFileAndVerifyInvalidRequiredArgumentData()
        {
            foreach (var emptyString in new[] { "", " ", null })
            {
                Add(new DecryptFileAndVerifyInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = emptyString,
                    OutputFilePath = @"C:\Temp\testoutput.txt",
                    VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                    DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath
                });

                Add(new DecryptFileAndVerifyInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                    OutputFilePath = emptyString,
                    VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                    DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath
                });

                Add(new DecryptFileAndVerifyInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                    OutputFilePath = @"C:\Temp\testoutput.txt",
                    VerifyPublicKeyPath = emptyString,
                    DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath
                });

                Add(new DecryptFileAndVerifyInvalidRequiredArgumentDataDetails
                {
                    InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                    OutputFilePath = @"C:\Temp\testoutput.txt",
                    VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                    DecryptByPrivateKeyPath = emptyString
                });
            }
        }
    }

    public class DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails
    {
        public string InputFilePath { get; set; } = string.Empty;
        public string OutputFilePath { get; set; } = string.Empty;
        public byte[]? VerifyPublicKey { get; set; }
        public byte[]? DecryptByPrivateKey { get; set; }
    }

    public class DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentData : TheoryData<DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails>
    {
        public DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentData()
        {
            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = " ",
                OutputFilePath = @"C:\Temp\testoutput.txt",
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath),
                DecryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath)
            });

            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                OutputFilePath = " ",
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath),
                DecryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath)
            });

            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                OutputFilePath = @"C:\Temp\testoutput.txt",
                VerifyPublicKey = null,
                DecryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath)
            });

            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidRequiredArgumentDataDetails
            {
                InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                OutputFilePath = @"C:\Temp\testoutput.txt",
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath),
                DecryptByPrivateKey = null
            });
        }
    }

    public class DecryptFileAndVerifyInvalidFileDataDetails
    {
        public string InputFilePath { get; set; } = string.Empty;
        public string VerifyPublicKeyPath { get; set; } = string.Empty;
        public string DecryptByPrivateKeyPath { get; set; } = string.Empty;
    }

    public class DecryptFileAndVerifyInvalidFileData : TheoryData<DecryptFileAndVerifyInvalidFileDataDetails>
    {
        public DecryptFileAndVerifyInvalidFileData()
        {
            Add(new DecryptFileAndVerifyInvalidFileDataDetails
            {
                InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath + ".txt",
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath
            });

            Add(new DecryptFileAndVerifyInvalidFileDataDetails
            {
                InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath + ".txt",
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath
            });

            Add(new DecryptFileAndVerifyInvalidFileDataDetails
            {
                InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath,
                VerifyPublicKeyPath = Constants.DigiAeonPublicKeyPath,
                DecryptByPrivateKeyPath = Constants.VendorPrivateKeyPath + ".txt"
            });
        }
    }

    public class DecryptFileAndVerifyUsingKeyFileBytesInvalidFileDataDetails
    {
        public string InputFilePath { get; set; } = string.Empty;
        public byte[]? VerifyPublicKey { get; set; }
        public byte[]? DecryptByPrivateKey { get; set; }
    }

    public class DecryptFileAndVerifyUsingKeyFileBytesInvalidFileData : TheoryData<DecryptFileAndVerifyUsingKeyFileBytesInvalidFileDataDetails>
    {
        public DecryptFileAndVerifyUsingKeyFileBytesInvalidFileData()
        {
            Add(new DecryptFileAndVerifyUsingKeyFileBytesInvalidFileDataDetails
            {
                InputFilePath = Constants.TestEncryptedFileWithASCIIArmorPath + ".txt",
                VerifyPublicKey = File.ReadAllBytes(Constants.DigiAeonPublicKeyPath),
                DecryptByPrivateKey = File.ReadAllBytes(Constants.VendorPrivateKeyPath)
            });
        }
    }

    #endregion
}
