using System.Text;
using NUnit.Framework;

namespace Encryption.Test
{
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