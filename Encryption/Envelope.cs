using System;
using System.Security.Cryptography;
using ProtoBuf;

namespace Encryption
{
    [ProtoContract]
    public class EnvelopeNoMeta : ProtoBase<EnvelopeNoMeta>, IEnvelopeNoMeta
    {
        [ProtoMember(1)]
        public byte[] EncryptedDataProto { get; private set; }

        [ProtoMember(2)]
        public KeyPair PublicKeyPairSender { get; set; }

        [ProtoMember(3)]
        public byte[] KeyDerivationSalt { get; private set; }

        public static EnvelopeNoMeta Encrypt(KeyPair privateKeyPair, KeyPair publicPublicKey, byte[] plainData)
        {
            var envelope = Envelope.Encrypt(privateKeyPair, publicPublicKey, plainData);

            var derivePurposeOnlyKeyPair = Brainpooler.CreateKeyPair(true);
            var mantle = Envelope.Encrypt(derivePurposeOnlyKeyPair, publicPublicKey, envelope.ToProtoBuf());

            return EnvelopeNoMeta.Create(mantle);
        }

        private static EnvelopeNoMeta Create(Envelope mantle)
        {
            return new EnvelopeNoMeta
            {
                EncryptedDataProto = mantle.EncryptedDataProto,
                PublicKeyPairSender = mantle.PublicKeyPairSender,
                KeyDerivationSalt = mantle.KeyDerivationSalt,
            };
        }

        public bool TryDecrypt(KeyPair privateKeyPair, IEnvelopeNoMeta envelopeNoMeta, out byte[] plainData)
        {
            try
            {
                var decryptedData = Envelope.DecryptedData(privateKeyPair, envelopeNoMeta, envelopeNoMeta.PublicKeyPairSender);
                plainData =  Envelope.Decrypt(privateKeyPair, Envelope.FromProtoBuf(decryptedData));
                return true;
            }
            catch
            {
                plainData = null;
                return false;
            }
        }
    }

    public interface IEnvelopeNoMeta
    {
        byte[] EncryptedDataProto { get; }
        KeyPair PublicKeyPairSender { get; set; }
        byte[] KeyDerivationSalt { get;  }
        byte[] ToProtoBuf();
    }

    [ProtoContract]
    public class Envelope : ProtoBase<Envelope>, IEnvelopeNoMeta
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
            // Bug: EC reuse, for signing and encryption!
            var signedData = Brainpooler.SignData(privateKeyPair, envelope.EncryptedDataProto);
            envelope.Signature = signedData;

            envelope.PublicKeyPairRecipient = publicKeyPair;
            envelope.PublicKeyPairSender = privateKeyPair.ExportPublicKey();

            return envelope;
        }

        public static byte[] Decrypt(KeyPair privateKeyPair, Envelope envelope)
        {
            VerifyData(envelope);

            var keyPairToDeriveSecret = envelope.IsForSelfUsage ? envelope.PublicKeyPairRecipient : envelope.PublicKeyPairSender;
            return DecryptedData(privateKeyPair, envelope, keyPairToDeriveSecret);
        }

        internal static byte[] DecryptedData(KeyPair privateKeyPair, IEnvelopeNoMeta envelope, KeyPair keyPairToDeriveSecret)
        {
            var secret = Brainpooler.DeriveSecret(privateKeyPair, keyPairToDeriveSecret, envelope.KeyDerivationSalt);
            var decryptedData = SymmetricEncryption.Decrypt(secret, EncryptedData.FromProtoBuf(envelope.EncryptedDataProto));
            return decryptedData;
        }

        internal static void VerifyData(Envelope envelope)
        {
            var isVerifed = Brainpooler.VerifyData(envelope.PublicKeyPairSender, envelope.EncryptedDataProto, envelope.Signature);
            if (!isVerifed)
                throw new CryptographicException("Signature couldn't be verified.");
        }
    }


}