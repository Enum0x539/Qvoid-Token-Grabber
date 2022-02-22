using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Builder.Miscellaneous
{
    internal class Utils
    {
        public static Color Spectrum(int mode, float time = 0f)
        {
            time = time == 0f ? (float)((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() % 62830) / 2000.0) : time;
            return Color.FromArgb(255,
                   (int)((Math.Sin(time + (mode / Math.PI)) * .5f + .5f) * 255.0f),
                   (int)((Math.Sin(time + (mode / Math.PI) + 2 * Math.PI / 3) * .5f + .5f) * 255.0f),
                   (int)((Math.Sin(time + (mode / Math.PI) + 4 * Math.PI / 3) * .5f + .5f) * 255.0f));
        }
    }

    public class Encryption
    {
        public static string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                    builder.Append(bytes[i].ToString("x2"));

                return builder.ToString();
            }
        }

        public static string SHA256CheckSum(string filePath)
        {
            using (SHA256 SHA256 = SHA256Managed.Create())
            {
                try
                {
                    using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        return Convert.ToBase64String(SHA256.ComputeHash(fileStream));
                }
                catch { return null; }
            }
        }

        private static byte[] StringToByteArray(string hex)
        {
            //Haha belongs to the Shabak
            return (from x in Enumerable.Range(0, hex.Length)
                    where x % 2 == 0
                    select Convert.ToByte(hex.Substring(x, 2), 16)).ToArray<byte>();
        }

        public static string StrXOR(string input, byte key, bool encrypt)
        {
            Thread.Sleep(20);

            string output = string.Empty;
            if (encrypt)
            {
                foreach (char c in input)
                    output += (c ^ key).ToString("X2");
            }
            else
            {
                try
                {
                    byte[] strBytes = StringToByteArray(input);
                    foreach (byte b in strBytes)
                        output += (char)(b ^ key);
                }
                catch
                {
                    return string.Empty;
                }
            }

            return output;
        }

        public static string GenerateKey()
        {
            return "IndexOutOfRangeException%__@LIORLUBMAN@__%IndexOutOfRangeException";
        }

        public static string GenerateKey(int size, bool lowerCase, int seed = 0)
        {
            Random r = new Random();
            if (seed != 0)
                r = new Random(seed);

            string output = "";

            for (int i = 0; i < size; ++i)
            {
                int[] rs = { r.Next('0', '9' + 1), r.Next('a', 'z' + 1), r.Next('A', 'Z' + 1) };
                output += (char)rs[r.Next(3)];
            }

            return lowerCase ? output.ToLower() : output.ToUpper();
        }

        public static string Base64Encode(string plainText)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));
        }

        public static string Base64Decode(string base64EncodedData)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64EncodedData));
        }

        public static string StrXOR(string input, bool encrypt, int Length = 1000)
        {
            Thread.Sleep(20);

            string key = string.Empty;
            string output = string.Empty;
            if (encrypt)
            {
                key = GenerateKey(Length, false);
                output = key;
                for (int i = 0; i < input.Length; ++i)
                    output += (input[i] ^ key[i % key.Length]).ToString("X2");
            }
            else
            {
                try
                {
                    key = input.Remove(Length);
                    byte[] strBytes = StringToByteArray(input.Substring(Length));
                    for (int i = 0; i < strBytes.Length; ++i)
                        output += (char)(strBytes[i] ^ key[i % key.Length]);
                }
                catch
                {
                    return string.Empty;
                }
            }

            return output;
        }

        public static string StrXOR(string input, string key, bool encrypt)
        {
            Thread.Sleep(20);

            if (key.Length == 0)
                return string.Empty;

            string output = string.Empty;
            if (encrypt)
            {
                for (int i = 0; i < input.Length; ++i)
                    output += (input[i] ^ key[i % key.Length]).ToString("X2");
            }
            else
            {
                try
                {
                    byte[] strBytes = StringToByteArray(input);
                    for (int i = 0; i < strBytes.Length; ++i)
                        output += (char)(strBytes[i] ^ key[i % key.Length]);
                }
                catch
                {
                    return string.Empty;
                }
            }

            return output;
        }

        public static string ROT13(string value)
        {
            char[] array = value.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                int number = (int)array[i];

                if (number >= 'a' && number <= 'z')
                {
                    if (number > 'm')
                        number -= 13;
                    else
                        number += 13;
                }
                else if (number >= 'A' && number <= 'Z')
                {
                    if (number > 'M')
                        number -= 13;
                    else
                        number += 13;
                }

                array[i] = (char)number;
            }
            return new string(array);
        }
    }

    public class Managment
    {
        private static string _Id;
        private static int _UniqueSeed = 0;

        static public string DiskId()
        {
            if (!String.IsNullOrEmpty(_Id))
                return _Id;

            try
            {
                ManagementObject _Disk = new ManagementObject(@"win32_logicaldisk.deviceid=""c:""");
                _Disk.Get();

                _Id = $"{_Disk["VolumeSerialNumber"]}";
            }
            catch { _Id = "9SB42HS"; }

            return DiskId();
        }

        static public int UniqueSeed()
        {
            if (_UniqueSeed != 0)
                return _UniqueSeed;

            DiskId();

            int seed = 0;
            foreach (char i in _Id)
                seed += (int)Char.GetNumericValue(i);

            _UniqueSeed = seed;
            return seed;
        }
    }
}
