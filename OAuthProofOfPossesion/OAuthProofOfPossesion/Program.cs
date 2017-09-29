//------------------------------------------------------------------------------
//
// Copyright (c) Brent Schmaltz.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace OAuthProofOfPossesion
{
    class Program
    {
        private static ConfigurationManager<OpenIdConnectConfiguration> _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(Authority + ".well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());

        // S2SMiddleTier metadata
        public const string MiddleTierAddress = "http://localhost:38273/";
        public const string MiddleTierClientId = "2d149917-123d-4ba3-8774-327b875f5540";
        public const string MiddleTierEndpoint = MiddleTierAddress + "api/AccessTokenProtected/ProtectedApi";
        public const string MiddleTierTennant = "add29489-7269-41f4-8841-b63c95564420";
        public const string MiddleTierThumbprint = "8BDD5C76F165FA88C5A73E978D0522C47F934C90";

        // public constants related to this site: S2SWebSite
        public const string Address = "http://localhost:38272/";
        public const string Authority = "https://login.microsoftonline.com/cyrano.onmicrosoft.com/";
        public const string ClientId = "905a5e2a-ebf5-4b70-8eb0-fd26303b6a5f";
        public const string RedirectUri = Address;
        public const string Resource = "http://S2SBackend";
        public const string Thumbprint = "5C346E0642C1113812C7775F0CB5336D8DFAFC4B";

        static void Main(string[] args)
        {
            var config = _configManager.GetConfigurationAsync().Result;
            var appTokenResponse = GetAppToken(Authority);
            var principal = TokenHandler.ValidateToken(
                                appTokenResponse.AccessToken,
                                new TokenValidationParameters
                                {
                                    ValidIssuer = config.Issuer,
                                    ValidAudience = Resource,
                                    IssuerSigningKeys = config.SigningKeys
                                },
                                out SecurityToken token
                            );

            var popAppTokenResponse = GetPopAppToken(Authority);
        }

        public static OAuthTokenResponse GetAppToken(string authority)
        {
            string resource = "http://S2SBackend";
            var cert = CryptoUtils.FindCertificate(StoreName.My, StoreLocation.LocalMachine, MiddleTierThumbprint);
            var config = _configManager.GetConfigurationAsync().Result;
            var audience = string.Format(@"https://sts.windows.net/{0}/", MiddleTierTennant);
            var jwt = CryptoUtils.CreateClientAssertion(MiddleTierClientId, audience, new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256));
            var client = new HttpClient();
            var request = new HttpRequestMessage
            {
                Content = new FormUrlEncodedContent(GetAppTokenParameters(jwt)),
                Method = HttpMethod.Post,
                RequestUri = new Uri(config.TokenEndpoint)
            };

            var response = client.SendAsync(request).Result;
            if (response.IsSuccessStatusCode)
                return OAuthTokenResponse.Create(response.Content.ReadAsStringAsync().Result);

            throw new OAuthTokenResponseException(response.ToString());
        }

        public static Dictionary<string, string> GetAppTokenParameters(string assertion)
        {
            return new Dictionary<string, string>
            {
                {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
                {"client_assertion", assertion},
                {"grant_type", "client_credentials"},
                {"resource", Resource}
            };
        }


//  To obtain a proof-of-possession protected token, an extension of the client credential flow is used. 
//	POST https://login.microsoftonline.com/consumers/oauth2/v2.0/token
//	grant_type=client_credentials&//  client_id=2f600644-04bb-460c-93a5-e525d00118b2&//  scope=5d344dd6-5fa0-4eee-83fc-98d688c96864/.default&//  request=eyJhbGci...
//	The request parameter is a signed JWT Request based on Open ID Connect. It will contain the proof-of-possession key. 
//	{//      "typ":"JWT",//      "alg":"RS256",//      "x5t":"B2J4nSsaX6R5VjjuTjGlHV9S6_U"//  }//  .//  {//      "aud":"https://login.microsoftonline.com/consumers/oauth2/v2.0/token"//      "iss":"2f600644-04bb-460c-93a5-e525d00118b2"//      "iat":1489707630,//      "exp":1489711230,//      "pop_jwk":{"kty":"RSA","n":"0vx7agoebGcQSu5JsGY4Hc5n9y...","e":"AQAB","alg":"RS256","kid":"1"}//  }//.//[Signature with registered app key]

        public static Dictionary<string, string> GetPopAppTokenParameters(string assertion, string clientId)
        {
            return new Dictionary<string, string>
            {
                {"grant_type", "client_credentials"},
                {"clientId", clientId },
                //{"scope", "95af3226-0b0c-42ab-abac-2ea26bd0e6a8/.default" },
                {"resource", Resource },
                {"request", assertion}
            };
        }		

        public static OAuthTokenResponse GetPopAppToken(string authority)
        {
            var cert = CryptoUtils.FindCertificate(StoreName.My, StoreLocation.LocalMachine, MiddleTierThumbprint);
            var config = _configManager.GetConfigurationAsync().Result;
            var audience = string.Format(@"https://logon.microsoftonline.com/{0}/auth2/token", MiddleTierTennant);
            var jwt = CryptoUtils.CreateClientAssertionWithPOP(MiddleTierClientId, audience, CryptoUtils.CreateRsaSecurityKey(), new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256));
            var jwtToken = new JwtSecurityToken(jwt);
            var client = new HttpClient();
            var request = new HttpRequestMessage
            {
                Content = new FormUrlEncodedContent(GetPopAppTokenParameters(jwt, MiddleTierClientId)),
                Method = HttpMethod.Post,
                RequestUri = new Uri(config.TokenEndpoint)
            };

            var response = client.SendAsync(request).Result;
            if (response.IsSuccessStatusCode)
                return OAuthTokenResponse.Create(response.Content.ReadAsStringAsync().Result);

            throw new OAuthTokenResponseException(response.ToString());
        }

        public static JwtSecurityTokenHandler TokenHandler
        {
            get
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.InboundClaimTypeMap.Clear();
                return tokenHandler;
            }
        }
    }
}
