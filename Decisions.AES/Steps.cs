using System;  
using System.IO;  
using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;
using DecisionsFramework.Design.Flow;

namespace Zitac.AES.Steps;

[AutoRegisterMethodsOnClass(true, "Encryption", "AES")]
    class AesEncryption
    {
        public string CreateKey(){
            byte[] Key = CreateAES().Key;   
            return Convert.ToBase64String(Key);
        }

        static Aes CreateAES() {
            using (Aes newAes = Aes.Create()){
                newAes.Mode = CipherMode.CBC;
                newAes.Padding = PaddingMode.Zeros;
                newAes.BlockSize = 128;
                newAes.KeySize = 256;
               return newAes;
            }
        }
        public string EncryptString(string plainText, string Key)
        {
            // Check arguments.
            byte[] byteKey = Convert.FromBase64String(Key);

                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            byte[] IV;
            using (Aes aesAlg = CreateAES())
            {
                aesAlg.Key = byteKey;
                IV = aesAlg.IV;


                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            encrypted = IV.Concat(encrypted).ToArray();
            // Return the encrypted bytes from the memory stream.
            return Convert.ToBase64String(encrypted);
        }

        public string DecryptString(string cipherString, string Key)
        {
            byte[] byteKey = Convert.FromBase64String(Key);
            byte[] cipherIV = Convert.FromBase64String(cipherString);
            byte[] IV = cipherIV.Take(16).ToArray();
            byte[] cipherText = cipherIV.Skip(16).ToArray();
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (byteKey == null || byteKey.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = CreateAES())
            {
                aesAlg.Key = byteKey;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                
                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext.Trim('\0');
        }
    }
