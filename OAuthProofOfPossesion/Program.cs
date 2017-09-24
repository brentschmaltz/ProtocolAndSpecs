using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace OAuthProofOfPossesion
{
    class Program
    {
        static void Main(string[] args)
        {
            var tokenHandler = new HttpRequestTokenHandler();
            var parameters = new Dictionary<string, string>
            {
                { "b", "bar" },
                { "a", "foo" },
                { "c", "duck"}
            };

            var parameterMap = tokenHandler.CalculateQueryParameter(parameters);
            var json = parameterMap.ToString(Newtonsoft.Json.Formatting.None, null);

            Console.WriteLine($"Query parameter json: {json}");

            var nv = new NameValueCollection();
            nv.Add("Content-Type", @"application/json");
            nv.Add("Etag", "742-3u8f34-3r2nvv3");
            var headerMap = tokenHandler.CalculateHeaderList(nv);
            var jsonHeader = headerMap.ToString(Newtonsoft.Json.Formatting.None, null);
            Console.WriteLine($"Header json: {jsonHeader}");

            Console.WriteLine("Press a key to close.");
            Console.ReadKey();
        }
    }

    public class HttpRequestToken
    {
        public int TimeStamp { get; set; }
        public string Method { get; set; }
        public string HostUrl { get; set; }
        public string HostUrlPath { get; set; }
        public HttpUrlQueryParameterMap QueryParameterMap {get;set;}
        public HttpUrlQueryParameterMap RequestHeaderMap { get; set; }
        public string RequestBodyHash { get; set; }
    }

    public class HttpUrlQueryParameterMap
    {
        public JArray QueryParameters { get; set; }
        public string Base64UrlHash { get; set; }
    }

    public class HttpRequestTokenHandler
    {
        public JObject CalculateQueryParameter(Dictionary<string,string> queryParameters)
        {
            var stringBuilder = new StringBuilder();
            var keyArray = new JArray();
            var parameterArray = new JArray();
            int count = 1;
            foreach (var parameter in queryParameters)
            {
                keyArray.Add(parameter.Key);
                stringBuilder.Append(WebUtility.UrlEncode(parameter.Key));
                stringBuilder.Append("=");
                stringBuilder.Append(WebUtility.UrlEncode(parameter.Value));
                if (count++ < queryParameters.Count)
                    stringBuilder.Append("&");
            }
            var parameterString = stringBuilder.ToString();
            var hashAlg = SHA256.Create();
            var hash = hashAlg.ComputeHash(Encoding.UTF8.GetBytes(parameterString));
            var utf8Encoding = Encoding.UTF8.GetString(hash);
            var base64UrlEncoding = Base64UrlEncoder.Encode(hash);
            var base64Endcoding =  Convert.ToBase64String(hash);
            parameterArray.Add(keyArray);
            parameterArray.Add(base64UrlEncoding);
            var json = new JObject();
            json.Add("q", parameterArray);

            return json;
        }

        public JObject CalculateHeaderList(NameValueCollection headers)
        {
            var stringBuilder = new StringBuilder();
            var keyArray = new JArray();
            var headerArray = new JArray();
            int count = 1;
            foreach (var key in headers.AllKeys)
            {
                keyArray.Add(key.ToLower());
                stringBuilder.Append($"{key.ToLower()}: {headers[key]}");
                if (count++ < headers.AllKeys.Length)
                    stringBuilder.AppendLine();
            }

            var headerString = stringBuilder.ToString();
            var hashAlg = SHA256.Create();
            var hash = hashAlg.ComputeHash(Encoding.UTF8.GetBytes(headerString));
            var base64UrlEncoding = Base64UrlEncoder.Encode(hash);
            headerArray.Add(keyArray);
            headerArray.Add(base64UrlEncoding);
            var json = new JObject();
            json.Add("h", headerArray);

            return json;
        }
    }
}
