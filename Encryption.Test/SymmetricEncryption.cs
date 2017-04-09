using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using NUnit.Framework;

namespace Encryption.Test
{
    [TestFixture]
    public class SymmetricEncryptionTest
    {
        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Thread.CurrentThread.CurrentUICulture = new CultureInfo("en-us");
        }

        [Test]
        public void Encrypt()
        {
            var key  = Encryption.SymmetricEncryption.CreateKey();

            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var msg = Encryption.SymmetricEncryption.Encrypt(key, plainMsg);
        }

        [Test]
        public void Decrypt()
        {
            var key  = Encryption.SymmetricEncryption.CreateKey();

            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var msgEncrypted = Encryption.SymmetricEncryption.Encrypt(key, plainMsg);
            var msgPlain = Encryption.SymmetricEncryption.Decrypt(key, msgEncrypted);

            var decryptedMsg = Encoding.UTF8.GetString(msgPlain);
            Assert.That(plainMsg,Is.EqualTo(decryptedMsg));
        }

        [Test]
        [TestCase(TampertEnum.EncryptedData)]
        [TestCase(TampertEnum.Key)]
        [TestCase(TampertEnum.Iv)]
        [TestCase(TampertEnum.Hmac)]
        public void Decrypt_Fail(TampertEnum tampert)
        {
            var key = Encryption.SymmetricEncryption.CreateKey();

            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var msgEncrypted = Encryption.SymmetricEncryption.Encrypt(key, plainMsg);

            switch (tampert)
            {
                case TampertEnum.EncryptedData:
                    msgEncrypted.Data[msgEncrypted.Data.Length / 2] ^= msgEncrypted.Data[msgEncrypted.Data.Length / 2];
                    break;
                case TampertEnum.Key:
                    key[key.Length / 2] ^= key[key.Length / 2];
                    break;
                case TampertEnum.Iv:
                    msgEncrypted.Iv[msgEncrypted.Iv.Length / 2] ^= msgEncrypted.Iv[msgEncrypted.Iv.Length / 2];
                    break;
                case TampertEnum.Hmac:
                    msgEncrypted.Hmac[msgEncrypted.Hmac.Length / 2] ^= msgEncrypted.Hmac[msgEncrypted.Hmac.Length / 2];
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(tampert), tampert, null);
            }

            var expection = Assert.Throws<CryptographicException>(() => 
                Encryption.SymmetricEncryption.Decrypt(key, msgEncrypted));
        }

        public enum TampertEnum
        {
            EncryptedData,
            Key,
            Iv,
            Hmac
        }
    }
}
