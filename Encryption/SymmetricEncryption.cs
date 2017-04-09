using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Encryption
{
    public class SymmetricEncryption
    {
        public static byte[] CreateKey()
        {
            var salt = new byte[512 / 8];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(salt);
            }
            return salt;
        }

        private static (byte[] hmac, byte[] aes) GreateComplexKey(byte[] key)
        {
            var hmacKey = key;
            var aesKey = key.Where((elem, idx) => idx % 2 == 0).ToArray();

            return ValueTuple.Create(hmacKey, aesKey);
        }

        public static EncryptedData Encrypt(byte[] key, byte[] data)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (key.Length != 512 / 8)
                throw new ArgumentOutOfRangeException($"{nameof(key)} must have a length of 512bit.");

            var resultStream = new MemoryStream();
            var complexKey = GreateComplexKey(key);

            byte[] iv;
            byte[] hmacHashData;

            using (var hmac = HMAC.Create(nameof(HMACSHA512)))
            {
                hmac.Key = complexKey.hmac;
                using (var aes = Aes.Create())
                {
                    aes.Key = complexKey.aes;
                    aes.GenerateIV();

                    iv = aes.IV;

                    using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (var hmacStream = new CryptoStream(resultStream, hmac, CryptoStreamMode.Write))
                    using (var aesStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(data))
                    {
                        plainStream.CopyTo(aesStream);
                    }
                }
                hmacHashData = hmac.Hash;
            }

            var hmacOverall = HMAC.Create(nameof(HMACSHA512));
            hmacOverall.Key = complexKey.hmac;
            var hmacOverallHash = hmacOverall.ComputeHash(hmacHashData.Concat(iv).Concat(complexKey.aes).Concat(hmacHashData).ToArray());

            var encryptedData = resultStream.ToArray();

#if DEBUG

            string Preview(byte[] b) => Convert.ToBase64String(b).Substring(0, 12);

            Console.Out.WriteLine("--------Encrypt------------");
            Console.Out.WriteLine("hmacOverall       " + Preview(hmacHashData));
            Console.Out.WriteLine("hmacOverallHash:  " + Preview(hmacOverallHash));
            Console.Out.WriteLine("encryptedData.Iv: " + Preview(iv));
            Console.Out.WriteLine("complexKey.aes:   " + Preview(complexKey.aes));
            Console.Out.WriteLine("complexKey.hmac:  " + Preview(complexKey.hmac));
            Console.Out.WriteLine("encryptedData:    " + Preview(encryptedData));
            Console.Out.WriteLine("plainData:        " + Preview(data));
#endif
            
            return new EncryptedData
            {
                Data = encryptedData,
                Iv = iv,
                Hmac = hmacOverallHash
            };
        }

        public static byte[] Decrypt(byte[] key, EncryptedData encryptedData)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));

            if (key.Length != 512 / 8)
                throw new ArgumentOutOfRangeException($"{nameof(key)} must have a length of 512bit.");

            var complexKey = GreateComplexKey(key);

            var resultStream = new MemoryStream();

            byte[] hmacHashData;
            using (var hmac = HMAC.Create(nameof(HMACSHA512)))
            {
                hmac.Key = complexKey.hmac;
                using (var aes = Aes.Create())
                {
                    aes.Key = complexKey.aes;
                    aes.IV = encryptedData.Iv;

                    using (var encryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    using (var hmacStream = new CryptoStream(aesStream, hmac, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(encryptedData.Data))
                    {
                        plainStream.CopyTo(hmacStream);
                    }
                }
                hmacHashData = hmac.Hash;
            }

            var hmacOverall = HMAC.Create(nameof(HMACSHA512));
            hmacOverall.Key = complexKey.hmac;
            var hmacOverallHash = hmacOverall.ComputeHash(hmacHashData.Concat(encryptedData.Iv).Concat(complexKey.aes).Concat(hmacHashData).ToArray());

            var decryptedData = resultStream.ToArray();

#if DEBUG
            string Preview(byte[] b) => Convert.ToBase64String(b).Substring(0, 12);

            Console.Out.WriteLine("--------Decrypt------------");
            Console.Out.WriteLine("hmacOverall       " + Preview(hmacHashData));
            Console.Out.WriteLine("hmacOverallHash:  " + Preview(hmacOverallHash));
            Console.Out.WriteLine("encryptedData.Iv: " + Preview(encryptedData.Iv));
            Console.Out.WriteLine("complexKey.aes:   " + Preview(complexKey.aes));
            Console.Out.WriteLine("complexKey.hmac:  " + Preview(complexKey.hmac));
            Console.Out.WriteLine("decryptedData:    " + Preview(decryptedData));
#endif

            if (!encryptedData.Hmac.SequenceEqual(hmacOverallHash))
                throw new CryptographicException("HMACSHA512 not identical");
            
            return decryptedData;
        }
    }
}