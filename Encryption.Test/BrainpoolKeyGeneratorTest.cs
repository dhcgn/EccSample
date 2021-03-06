﻿using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using NUnit.Framework;

namespace Encryption.Test
{
    [TestFixture]
    public class BrainpoolerTest
    {
        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Thread.CurrentThread.CurrentUICulture = new CultureInfo("en-us");
        }

        [Test]
       
        public void SignDataAndVerifyData()
        {
            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var keyPair = Brainpooler.CreateKeyPair(true);

            var signature1 = Brainpooler.SignData(keyPair, plainMsg);
            var signature2 = Brainpooler.SignData(keyPair, plainMsg);

            Assert.That(signature1,Is.Not.EquivalentTo(signature2), "Signature #1 and #2 are NOT equal");

            Assert.That(Brainpooler.VerifyData(keyPair.ExportPublicKey(), plainMsg, signature1), "Signature of #1 is valid");
            Assert.That(Brainpooler.VerifyData(keyPair.ExportPublicKey(), plainMsg, signature2), "Signature of #2 is valid");
        }

        [Test]
        [TestCase(true, Description = "Include Private Key")]
        [TestCase(false, Description = "Include no Private Key")]
        public void CreateKeyPair(bool includePrivateParameters)
        {
            var keyPair = Brainpooler.CreateKeyPair(includePrivateParameters);

            Console.Out.WriteLine($"----------- json ({keyPair.ToJson.Length})------------");
            Console.Out.WriteLine(keyPair.ToJson);
            Console.Out.WriteLine($"----------- raw ({Convert.ToBase64String(keyPair.ToProtoBuf()).Length})------------");
            Console.Out.WriteLine(Convert.ToBase64String(keyPair.ToProtoBuf()));
            Console.Out.WriteLine($"----------- armor ({keyPair.ToArmor().Length})------------");
            Console.Out.WriteLine(keyPair.ToArmor());
        }

        [Test]
        [TestCase(true, Description = "Include Private Key")]
        [TestCase(false, Description = "Include no Private Key")]
        public void CreateKeyPair_FromJson(bool includePrivateParameters)
        {
            var keyPair = Brainpooler.CreateKeyPair(includePrivateParameters);
            var fromJson = KeyPair.FromJson(keyPair.ToJson);

            Console.Out.WriteLine(fromJson.ToJson);
        }

        [Test]
        public void DeriveSecret()
        {
            var alice = Brainpooler.CreateKeyPair(true);
            var bob = Brainpooler.CreateKeyPair(true);

            var salt = Hash.CreateSalt();
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(salt);
            }

            var derivedSecret1 = Brainpooler.DeriveSecret(alice, bob.ExportPublicKey(), salt);
            var derivedSecret2 = Brainpooler.DeriveSecret(bob, alice.ExportPublicKey(), salt);

            Console.Out.WriteLine($"derivedSecret length: {derivedSecret1?.Length * 8} bit");

            Console.Out.WriteLine($"derivedSecret1 : {Convert.ToBase64String(derivedSecret1).Substring(0, 16)} ...");
            Console.Out.WriteLine($"derivedSecret2 : {Convert.ToBase64String(derivedSecret2).Substring(0, 16)} ...");

            Assert.That(derivedSecret1, Has.Length.GreaterThan(0));
            Assert.That(derivedSecret2, Has.Length.GreaterThan(0));

            Assert.That(derivedSecret1, Is.EquivalentTo(derivedSecret2));
        }
    }
}