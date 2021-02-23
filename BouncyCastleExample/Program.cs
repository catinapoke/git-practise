using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace BouncyCastleExample
{
    internal class Program
    {
        /**
        * A simple utility class that Generates a RSA PgpPublicKey/PgpSecretKey pair.
        * <p>
        * usage: RsaKeyRingGenerator [-a] identity passPhrase</p>
        * <p>
        * Where identity is the name to be associated with the public key. The keys are placed
        * in the files pub.[asc|bpg] and secret.[asc|bpg].</p>
        */
        private const string secretKeyFile = "secret.asc";
        private const string publicKeyFile = "pub.asc";

        private const string msgFile = "msg.txt";
        private const string encryptedMsgFile = "crypted.txt";
        private const string decryptedMsgFile = "decrypted.txt";

        public static int Main(
                string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("pgpTest KeyId passPhrase");
                Console.WriteLine("msg.txt - message for encryption");
                Console.WriteLine("crypted.txt - encrypted message");
                Console.WriteLine("decrypted.txt - decrypted message from crypted.txt");
                return 0;
            }
            string identity = args[0]; 
            string passPhrase = args[1];

            // Генерация ключей
            GenerateRSAKeyPair(identity, passPhrase);
            // Тестирование шифрования
            TestPGPkeysFromFile(publicKeyFile, secretKeyFile, passPhrase);
            return 0;
        }

        private static void TestPGPkeysFromFile(string publicKeyFile, string secretKeyFilem, string passPhrase)
        {
            Stream publicStream = File.OpenRead(publicKeyFile);
            Stream secretStream = File.OpenRead(secretKeyFilem);
            TestPGPKeys(secretStream, publicStream, passPhrase.ToCharArray());
        }

        private static void TestPGPKeys(Stream secretKeyStream, Stream publicKeyStream, char[] passPhrase)
        {
            PgpSecretKey secretKey = ReadSecretKey(secretKeyStream);
            PgpPublicKey publicKey = ReadPublicKey(publicKeyStream);
            PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(passPhrase);

            Stream stream;

            byte[] inBytes = new byte[64]; // = Encoding.ASCII.GetBytes("hello world");

            // Считывание сообщения для шифрования
            stream = File.OpenRead(msgFile);
            stream.Read(inBytes);
            stream.Close();

            IBufferedCipher c = CipherUtilities.GetCipher("RSA");

            // Шифрование c помощью публичного ключа
            c.Init(true, publicKey.GetKey());
            byte[] outBytes = c.DoFinal(inBytes);

            // Зашифрованное сообщение
            stream = File.Create(encryptedMsgFile);
            stream.Write(outBytes, 0, outBytes.Length);
            stream.Close();

            // Дешифрование с помощью приватного ключа
            c.Init(false, privateKey.Key);
            outBytes = c.DoFinal(outBytes);

            // Дешифрованное сообщение
            stream = File.Create(decryptedMsgFile);
            stream.Write(outBytes, 0, outBytes.Length);
            stream.Close();
        }

        private static void GenerateRSAKeyPair(string identity, string passPhrase)
        {
            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");

            kpg.Init(new RsaKeyGenerationParameters(
                BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 25));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            Stream out1, out2;
            out1 = File.Create(secretKeyFile);
            out2 = File.Create(publicKeyFile);

            ExportKeyPair(out1, out2, kp.Public, kp.Private, identity, passPhrase.ToCharArray(), true);

            out1.Close();
            out2.Close();
        }

        private static void ExportKeyPair(
                Stream secretOut,
                Stream publicOut,
                AsymmetricKeyParameter publicKey,
                AsymmetricKeyParameter privateKey,
                string identity,
                char[] passPhrase,
                bool armor)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                publicKey,
                privateKey,
                DateTime.UtcNow,
                identity,
                SymmetricKeyAlgorithmTag.Cast5,
                passPhrase,
                null,
                null,
                new SecureRandom()
                );

            secretKey.Encode(secretOut);

            if (armor)
            {
                secretOut.Close();
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            if (armor)
            {
                publicOut.Close();
            }
        }

        internal static PgpPublicKey ReadPublicKey(Stream input)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        internal static PgpSecretKey ReadSecretKey(Stream input)
        {
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }
    }
}