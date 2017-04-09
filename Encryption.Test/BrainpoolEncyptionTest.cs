using System.Globalization;
using System.Text;
using System.Threading;
using NUnit.Framework;

namespace Encryption.Test
{
    [TestFixture]
    public class BrainpoolEncyptionTest
    {
        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Thread.CurrentThread.CurrentUICulture = new CultureInfo("en-us");
        }

        [Test]
        public void EncryptForSelfUse()
        {
            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var aliceKeyPair = Brainpooler.CreateKeyPair(true);

            byte[] data;

            {
                var derivePurposeOnlyKeyPair = Brainpooler.CreateKeyPair(false);

                var salt = Hash.CreateSalt();
                var secret = Brainpooler.DeriveSecret(aliceKeyPair, derivePurposeOnlyKeyPair, salt);

                var encryptedData = SymmetricEncryption.Encrypt(secret, plainMsg);

                var envelope = Envelope.Create(encryptedData, salt, true);
                var signedData = Brainpooler.SignData(aliceKeyPair, envelope.EncryptedDataProto);
                envelope.Signature = signedData;
                envelope.PublicKeyPairRecipient = derivePurposeOnlyKeyPair;
                data = envelope.ToProtoBuf();
            }

            {
                var envelope = Envelope.FromProtoBuf(data);

                var isVerifed = Brainpooler.VerifyData(aliceKeyPair, envelope.EncryptedDataProto, envelope.Signature);
                Assert.That(isVerifed, Is.True);

                var secret = Brainpooler.DeriveSecret(aliceKeyPair, envelope.PublicKeyPairRecipient, envelope.KeyDerivationSalt);
                var decryptedData = SymmetricEncryption.Decrypt(secret, EncryptedData.FromProtoBuf(envelope.EncryptedDataProto));
                var result = Encoding.UTF8.GetString(decryptedData);

                Assert.That(result,Is.EqualTo(plainMsg));
            }
        }
    }
}