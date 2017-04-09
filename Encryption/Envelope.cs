using System.Security.Cryptography;
using ProtoBuf;

namespace Encryption
{
    [ProtoContract]
    public class Envelope : ProtoBase<Envelope>
    {
        [ProtoMember(1)]
        public byte[] EncryptedDataProto { get; private set; }

        [ProtoMember(2)]
        public KeyPair PublicKeyPairRecipient { get; set; }

        [ProtoMember(3)]
        public KeyPair PublicKeyPairSender { get; set; }

        [ProtoMember(4)]
        public byte[] KeyDerivationSalt { get; private set; }

        [ProtoMember(5)]
        public byte[] Signature { get; set; }

        [ProtoMember(6)]
        public bool IsForSelfUsage { get; set; }

        public static Envelope Create(EncryptedData encryptedData, byte[] keyDerivationSalt, bool isForSelfUsage)
        {
            return new Envelope
            {
                EncryptedDataProto = encryptedData.ToProtoBuf(),
                KeyDerivationSalt = keyDerivationSalt,
                IsForSelfUsage = isForSelfUsage,
            };
        }

        public static Envelope Encrypt(KeyPair privateKeyPair, byte[] plainData)
        {
            var derivePurposeOnlyKeyPair = Brainpooler.CreateKeyPair(false);

            return Encrypt(privateKeyPair, derivePurposeOnlyKeyPair, plainData, true);
        }


        public static Envelope Encrypt(KeyPair privateKeyPair, KeyPair publicKeyPair, byte[] plainData, bool isSelfUsage = false)
        {
            var salt = Hash.CreateSalt();
            var secret = Brainpooler.DeriveSecret(privateKeyPair, publicKeyPair, salt);

            var encryptedData = SymmetricEncryption.Encrypt(secret, plainData);

            var envelope = Envelope.Create(encryptedData, salt, isSelfUsage);
            var signedData = Brainpooler.SignData(privateKeyPair, envelope.EncryptedDataProto);
            envelope.Signature = signedData;

            envelope.PublicKeyPairRecipient = publicKeyPair;
            envelope.PublicKeyPairSender = privateKeyPair.ExportPublicKey();

            return envelope;
        }

        public static byte[] Decrypt(KeyPair privateKeyPair, Envelope envelope)
        {
            var isVerifed = Brainpooler.VerifyData(envelope.PublicKeyPairSender, envelope.EncryptedDataProto, envelope.Signature);
            if (!isVerifed)
                throw new CryptographicException("Signature couldn't be verified.");

            var keyPairToDeriveSecret = envelope.IsForSelfUsage ? envelope.PublicKeyPairRecipient : envelope.PublicKeyPairSender;
            var secret = Brainpooler.DeriveSecret(privateKeyPair, keyPairToDeriveSecret, envelope.KeyDerivationSalt);
            var decryptedData = SymmetricEncryption.Decrypt(secret, EncryptedData.FromProtoBuf(envelope.EncryptedDataProto));
            return decryptedData;
        }
    }
}