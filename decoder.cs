using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace opisafaggot
{
    class Program
    {
        // use "C:\\path\\to\\stuff" for Windows
        // use "/path/to/stuff" for Linux/Mac
        static string inputDir = "/path/to/stuff/asc";
        static string outputDir = "/path/to/stuff/decrypted";
        static string md5Dir = "/path/to/stuff/asc_md5";
        static string passwordsTxt = "/path/to/stuff/passwords.txt";

        static void Main(string[] args)
        {
            string[] passwords = File.ReadAllLines(passwordsTxt);

            if (!Directory.Exists(outputDir))
                Directory.CreateDirectory(outputDir);
            
            for (int i = 1; i <= 61; i++)
            {
                string input = Path.Combine(inputDir, String.Format("{0}.aes", i));
                string output = Path.Combine(outputDir, String.Format("{0}.png", i));
                string md5File = Path.Combine(md5Dir, String.Format("{0}.txt", i));
                string md5 = File.ReadAllLines(md5File)[3].Split(' ')[0];

                if (File.Exists(input))
                {
                    DecryptFile(input, output, passwords[i + 2], md5);
                }
                else
                {
                    Console.WriteLine("\"{0}\" doesn't exist!", input);
                }
            }
        }

        static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged AES = new AesManaged())
                {
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        static void DecryptFile(string input, string output, string password, string hash)
        {
            Console.WriteLine("Decrypting \"{0}\" to \"{1}\" with password \"{2}\"", input, output, password);

            byte[] bytesToBeDecrypted = File.ReadAllBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

            Console.WriteLine("MD5 verified: {0}", VerifyMD5(hash, bytesDecrypted));

            File.WriteAllBytes(output, bytesDecrypted);
        }

        static bool VerifyMD5(string hash, byte[] bytesDecrypted)
        {
            byte[] computed = MD5.Create().ComputeHash(bytesDecrypted);
            string computedHash = BitConverter.ToString(computed).Replace("-", string.Empty).ToLower();
            return (hash == computedHash);
        }
    }
}
