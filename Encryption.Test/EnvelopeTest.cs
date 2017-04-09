using System.Linq;
using System.Text;
using NUnit.Framework;

namespace Encryption.Test
{
    [TestFixture]
    public class EnvelopeNoMetaTest
    {
        [Test]
        public void Test_Simple()
        {
            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var aliceKeyPair = Brainpooler.CreateKeyPair(true);
            var bobKeyPair = Brainpooler.CreateKeyPair(true);
            
            var env = EnvelopeNoMeta.Encrypt(aliceKeyPair, bobKeyPair.ExportPublicKey(), plainMsg);

            var wire = env.ToProtoBuf();
            var envelopeFromWire = EnvelopeNoMeta.FromProtoBuf(wire);

            byte[] plainData;
            bool result = envelopeFromWire.TryDecrypt(bobKeyPair, envelopeFromWire, out plainData);
            Assert.That(result);

            var decryptedMsg = Encoding.UTF8.GetString(plainData);
            Assert.That(plainMsg, Is.EqualTo(decryptedMsg));
        }

        [Test]
        public void Test_Simple_NoResult()
        {
            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var aliceKeyPair = Brainpooler.CreateKeyPair(true);
            var bobKeyPair = Brainpooler.CreateKeyPair(true);
            var eveKeyPair = Brainpooler.CreateKeyPair(true);
            
            var env = EnvelopeNoMeta.Encrypt(aliceKeyPair, eveKeyPair.ExportPublicKey(), plainMsg);

            var wire = env.ToProtoBuf();
            var envelopeFromWire = EnvelopeNoMeta.FromProtoBuf(wire);

            byte[] plainData;
            bool result = envelopeFromWire.TryDecrypt(bobKeyPair, envelopeFromWire, out plainData);
            Assert.That(result, Is.False);
            Assert.That(plainData,Is.Null);
        }
    }

    [TestFixture]
    public class EnvelopeTest
    {
        [Test]
        public void Encrypt_SelfUsage()
        {
            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var aliceKeyPair = Brainpooler.CreateKeyPair(true);

            var envelope = Envelope.Encrypt(aliceKeyPair, plainMsg);

            var wire = envelope.ToProtoBuf();
            var envelopeFromWire = Envelope.FromProtoBuf(wire);

            var decrypted = Envelope.Decrypt(aliceKeyPair, envelopeFromWire);
            var decryptedMsg = Encoding.UTF8.GetString(decrypted);

            Assert.That(plainMsg, Is.EqualTo(decryptedMsg));
        }

        [Test]
        public void Encrypt_ToOtherParty()
        {
            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var aliceKeyPair = Brainpooler.CreateKeyPair(true);
            var bobKeyPair = Brainpooler.CreateKeyPair(true);

            var envelope = Envelope.Encrypt(aliceKeyPair, bobKeyPair.ExportPublicKey(), plainMsg);

            var wire = envelope.ToProtoBuf();
            var envelopeFromWire = Envelope.FromProtoBuf(wire);

            var decrypted = Envelope.Decrypt(bobKeyPair, envelopeFromWire);

            var decryptedMsg = Encoding.UTF8.GetString(decrypted);

            Assert.That(plainMsg, Is.EqualTo(decryptedMsg));
        }
    }
}