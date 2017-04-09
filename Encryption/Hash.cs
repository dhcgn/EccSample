using System.Security.Cryptography;

namespace Encryption
{
    public class Hash
    {
        public static byte[] CreateSalt()
        {
            var salt = new byte[512 / 8];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(salt);
            }
            return salt;
        }
    }
}