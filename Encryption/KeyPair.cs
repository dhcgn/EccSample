﻿using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using ProtoBuf;

namespace Encryption
{
    [ProtoContract]
    public class KeyPair : ProtoBase<KeyPair>
    {
        /// <summary>
        /// Stellt den privaten Schlüssel D für den ECC-Algorithmus (Elliptic Curve Cryptography) dar.
        /// </summary>
        [JsonProperty("PrivateKey")]
        [ProtoMember(1)]
        public byte[] D { get; private set; }

        /// <summary>
        /// Stellt den öffentlichen Schlüssel Q für den ECC-Algorithmus (Elliptic Curve Cryptography) dar.
        /// </summary>
        [JsonProperty("PublicKeyX")]
        [ProtoMember(2)]
        public byte[] Qx { get; private set; }

        /// <summary>
        /// Stellt den öffentlichen Schlüssel Q für den ECC-Algorithmus (Elliptic Curve Cryptography) dar.
        /// </summary>
        [JsonProperty("PublicKeyY")]
        [ProtoMember(3)]
        public byte[] Qy { get; private set; }
       
        public bool InculdePrivateKey => D != null;

        [JsonIgnore]
        public string ToJson => JsonConvert.SerializeObject(this);

        public string ToArmor()
        {
            var base64 = Convert.ToBase64String(this.ToProtoBuf());
            var typeName = this.InculdePrivateKey ? "PRIVATE" : "PUBLIC";
            var start = $"-----BEGIN {typeName} KEY BLOCK-----";
            var end = $"-----END {typeName} BLOCK-----";

            var content = Regex.Replace(base64, $".{{{start.Length}}}", "$0\n");

            return start+"\r\n" + content + "\r\n"+end;
        }

        public static KeyPair FromJson(string json)
        {
            var keyPair = JsonConvert.DeserializeObject<KeyPair>(json);
            return keyPair;
        }

        public KeyPair ExportPublicKey()
        {
            return new KeyPair
            {
                Qx = this.Qx,
                Qy = this.Qy,
            };
        }

        public static KeyPair CreateFromECParameters(ECParameters exportParameters)
        {
            return new KeyPair
            {
                Qx = exportParameters.Q.X,
                Qy = exportParameters.Q.Y,
                D = exportParameters.D
            };
        }

        public ECParameters CreateECParameters()
        {
            var ecParameters = new ECParameters
            {
                Q = new ECPoint
                {
                    X = Qx,
                    Y = Qy
                },
                D = D,
                Curve = ECCurve.NamedCurves.brainpoolP320r1
            };
            ecParameters.Validate();

            return ecParameters;
        }
    }
}