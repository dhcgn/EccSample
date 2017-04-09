using System.Security.Cryptography;

namespace Encryption
{
    public class Brainpooler
    {
        private static ECCurve brainpoolP320R1 = ECCurve.NamedCurves.brainpoolP320r1;

        /// <summary>
        /// brainpoolP320r1 is NitroKey HSM compatible.
        /// </summary>
        public string NamedCurve => brainpoolP320R1.ToString();

        public static KeyPair CreateKeyPair(bool includePrivateParameters)
        {
            var ecDsa = ECDsa.Create(brainpoolP320R1);
            var exportParameters = ecDsa.ExportParameters(includePrivateParameters);

            return KeyPair.CreateFromECParameters(exportParameters);
        }

        public static byte[] DeriveSecret(KeyPair privateKeyPair, KeyPair publicKeyPair, byte[] salt)
        {
            var dhPrivate = ECDiffieHellman.Create(privateKeyPair.CreateECParameters());
            var dhPublic = ECDiffieHellman.Create(publicKeyPair.CreateECParameters());

            var secretPrepend = SHA512.Create().ComputeHash(salt);
            var secretAppend = secretPrepend;
            
            return dhPrivate.DeriveKeyFromHash(dhPublic.PublicKey, HashAlgorithmName.SHA512, secretPrepend, secretAppend);
        }

        public static byte[] SignData(KeyPair privateKeyPair, byte[] data)
        {
            var ecDsa = ECDsa.Create(brainpoolP320R1);
            ecDsa.ImportParameters(privateKeyPair.CreateECParameters());
            return ecDsa.SignData(data, HashAlgorithmName.SHA512);
        }

        public static bool VerifyData(KeyPair signedKeyPair, byte[] data, byte[] signature)
        {
            var ecDsa = ECDsa.Create(brainpoolP320R1);
            ecDsa.ImportParameters(signedKeyPair.CreateECParameters());
            return ecDsa.VerifyData(data,signature, HashAlgorithmName.SHA512);
        }
    }
}