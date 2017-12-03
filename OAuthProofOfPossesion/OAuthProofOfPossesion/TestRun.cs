using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.S2S;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OAuthProofOfPossesion
{
    public class TestRun
    {
        internal static readonly DateTime JwtBaselineTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Creates a Signed Pop authenticator.
        /// </summary>
        /// <param name="httpRequestData"><see cref="SignedHttpRequestData"/>.</param>
        /// <returns>Signed pop authenticator.</returns>
        public string CreatePopAuthenticatorWithWilson(SignedHttpRequestData httpRequestData)
        {
            long ts = (long)(DateTime.UtcNow - JwtBaselineTime).TotalSeconds;
            var cryptoFactory = httpRequestData.SigningCredentials.CryptoProviderFactory ?? httpRequestData.SigningCredentials.Key.CryptoProviderFactory;
            var hash = cryptoFactory.CreateHashAlgorithm(httpRequestData.SigningCredentials.Digest);
            string pathHash = Base64UrlEncoder.Encode(hash.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.AbsolutePath.TrimEnd('/'))));
            string queryHash = Base64UrlEncoder.Encode(hash.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.Query.TrimStart('?'))));

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.SetDefaultTimesOnTokenCreation = false;
            var jwtToken = tokenHandler.CreateJwtSecurityToken(null, null, null, null, null, null, httpRequestData.SigningCredentials);
            jwtToken.Header["x5t"] = Base64UrlEncoder.Encode((httpRequestData.SigningCredentials.Key as X509SecurityKey).Certificate.GetCertHash());
            jwtToken.Payload["at"] = httpRequestData.AppToken;
            jwtToken.Payload["ts"] = ts;
            jwtToken.Payload["m"] = httpRequestData.RequestMethod;
            jwtToken.Payload["p#S256"] = pathHash;
            jwtToken.Payload["q#S256"] = queryHash;
            jwtToken.Payload[httpRequestData.PayloadTokenType] = httpRequestData.PayloadToken;

            return tokenHandler.WriteToken(jwtToken);
        }

        /// <summary>
        /// Creates a Signed Pop authenticator.
        /// </summary>
        /// <param name="httpRequestData"><see cref="SignedHttpRequestData"/>.</param>
        /// <returns>Signed pop authenticator.</returns>
        public string CreatePopAuthenticator(SignedHttpRequestData httpRequestData)
        {
            var cryptoFactory = httpRequestData.SigningCredentials.CryptoProviderFactory ?? httpRequestData.SigningCredentials.Key.CryptoProviderFactory;
            var hashAlgorithm = cryptoFactory.CreateHashAlgorithm(httpRequestData.SigningCredentials.Digest);
            var signatureProvider = cryptoFactory.CreateForSigning(httpRequestData.SigningCredentials.Key, httpRequestData.SigningCredentials.Algorithm);

            try
            {
                long ts = (long)(DateTime.UtcNow - JwtBaselineTime).TotalSeconds;           
                string pathHash = Base64UrlEncoder.Encode(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.AbsolutePath.TrimEnd('/'))));
                string queryHash = Base64UrlEncoder.Encode(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.Query.TrimStart('?'))));

                var header = new JObject
                {
                    { "typ", "JWT" },
                    { "alg", "RS256" },
                    { "x5t", Base64UrlEncoder.Encode((httpRequestData.SigningCredentials.Key as X509SecurityKey).Certificate.GetCertHash()) }
                };

                var payload = new JObject
                {
                    {"at", httpRequestData.AppToken},
                    {"ts", ts},
                    {"m", httpRequestData.RequestMethod},
                    {"p#S256", pathHash},
                    {"q#S256", queryHash},
                    {httpRequestData.PayloadTokenType, httpRequestData.PayloadToken }
                };

                var message = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Formatting.None))) + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToString(Formatting.None)));
                return message + "." + Base64UrlEncoder.Encode(signatureProvider.Sign(Encoding.UTF8.GetBytes(message)));
            }
            finally
            {
                cryptoFactory.ReleaseHashAlgorithm(hashAlgorithm);
                cryptoFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// Creates a Signed Pop authenticator.
        /// </summary>
        /// <param name="httpRequestData"><see cref="SignedHttpRequestData"/>.</param>
        /// <returns>Signed pop authenticator.</returns>
        public string CreatePopAuthenticator(SignedHttpRequestData httpRequestData, SignatureProvider signatureProvider, HashAlgorithm hashAlgorithm, string encodedHeader)
        {
            long ts = (long)(DateTime.UtcNow - JwtBaselineTime).TotalSeconds;
            string pathHash = Base64UrlEncoder.Encode(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.AbsolutePath.TrimEnd('/'))));
            string queryHash = Base64UrlEncoder.Encode(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.Query.TrimStart('?'))));

            var payload = new JObject
            {
                {"at", httpRequestData.AppToken},
                {"ts", ts},
                {"m", httpRequestData.RequestMethod},
                {"p#S256", pathHash},
                {"q#S256", queryHash},
                {httpRequestData.PayloadTokenType, httpRequestData.PayloadToken }
            };

            var message = encodedHeader + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToString(Formatting.None)));
            return message + "." + Base64UrlEncoder.Encode(signatureProvider.Sign(Encoding.UTF8.GetBytes(message)));
        }

        /// <summary>
        /// Creates a Signed Pop authenticator.
        /// </summary>
        /// <param name="httpRequestData"><see cref="SignedHttpRequestData"/>.</param>
        /// <returns>Signed pop authenticator.</returns>
        public string CreatePopAuthenticatorStringBuilder(SignedHttpRequestData httpRequestData, SignatureProvider signatureProvider, HashAlgorithm hash, string encodedHeader)
        {
            long ts = (long)(DateTime.UtcNow - JwtBaselineTime).TotalSeconds;
            string pathHash = Base64TokenEncode(hash.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.AbsolutePath.TrimEnd('/'))));
            string queryHash = Base64TokenEncode(hash.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.Query.TrimStart('?'))));
            var sb = new StringBuilder();
            sb.Append("{\"at\":");
            sb.Append(httpRequestData.AppToken);
            sb.Append("\"ts\":");
            sb.Append(ts);
            sb.Append("\"m\":");
            sb.Append("\"p#S256\":");
            sb.Append(pathHash);
            sb.Append("\"q#S256\":");
            sb.Append(queryHash);
            sb.Append("\"");
            sb.Append(httpRequestData.PayloadTokenType);
            sb.Append("\": \"");
            sb.Append(httpRequestData.PayloadToken);
            sb.Append("\"}");

            var message = encodedHeader + Base64TokenEncode(Encoding.UTF8.GetBytes(sb.ToString()));
            return message + "." + Base64TokenEncode(signatureProvider.Sign(Encoding.UTF8.GetBytes(message)));
        }

        /// <summary>
        /// Creates a Signed Pop authenticator.
        /// </summary>
        /// <param name="httpRequestData"><see cref="SignedHttpRequestData"/>.</param>
        /// <returns>Signed pop authenticator.</returns>
        public string CreatePopAuthenticatorStringCat(SignedHttpRequestData httpRequestData, SignatureProvider signatureProvider, HashAlgorithm hash, string encodedHeader)
        {
            long ts = (long)(DateTime.UtcNow - JwtBaselineTime).TotalSeconds;
            string pathHash = Base64TokenEncode(hash.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.AbsolutePath.TrimEnd('/'))));
            string queryHash = Base64TokenEncode(hash.ComputeHash(Encoding.UTF8.GetBytes(httpRequestData.Request.Query.TrimStart('?'))));

            var message = encodedHeader + Base64TokenEncode(Encoding.UTF8.GetBytes("{\"at\":" + httpRequestData.AppToken + "\"ts\":" + ts + "\"m\": \"p#S256\":" + pathHash + "\"q#S256\":" + queryHash + "\"" + httpRequestData.PayloadTokenType + "\": \"" + httpRequestData.PayloadToken + "\"}"));
            return message + "." + Base64TokenEncode(signatureProvider.Sign(Encoding.UTF8.GetBytes(message)));
        }

        /// <summary>
        /// Base64 encodes given data with appropriate transforms.
        /// </summary>
        /// <param name="data">Data to encode.</param>
        /// <returns>Corresponding encoded string.</returns>
        private static string Base64TokenEncode(byte[] data)
        {
            string text = Convert.ToBase64String(data);
            text = text.Split('=')[0];
            text = text.Replace('+', '-');
            return text.Replace('/', '_');
        }

    }
}
