using System.IO;
using ProtoBuf;

namespace Encryption
{
    [ProtoContract]
    public class EncryptedData : ProtoBase<EncryptedData>
    {
        [ProtoMember(1)]
        public byte[] Data { get; set; }

        [ProtoMember(2)]
        public byte[] Iv { get; set; }

        [ProtoMember(3)]
        public byte[] Hmac { get; set; }
    }

    public class ProtoBase<T>
    {
        public byte[] ToProtoBuf()
        {
            var protoStream = new MemoryStream();
            Serializer.Serialize(protoStream, this);
            return protoStream.ToArray();
        }

        public static T FromProtoBuf(byte[] data)
        {
            var protoStream = new MemoryStream(data);
            return Serializer.Deserialize<T>(protoStream);
        }
    }
}