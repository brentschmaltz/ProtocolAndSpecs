using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace OAuthProofOfPossesion
{
    class Program
    {
        private ConfigurationManager<OpenIdConnectConfiguration> _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(Authority + ".well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
        private OpenIdConnectProtocolValidator _protocolValidator = new OpenIdConnectProtocolValidator();
        private JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();

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
        public const string Thumbprint = "5C346E0642C1113812C7775F0CB5336D8DFAFC4B";

        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
        }

        private static X509Certificate2 FindCertificate(StoreName storeName, StoreLocation storeLocation, string thumbprint)
        {
            X509Store x509Store = new X509Store(storeName, storeLocation);
            x509Store.Open(OpenFlags.ReadOnly);
            try
            {
                foreach (var cert in x509Store.Certificates)
                {
                    if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return cert;
                    }
                }

                throw new ArgumentException($"S2SWebsite communicates with AzureAD using a Certificate with thumbprint: '{thumbprint}'. SAL_SDK includes '<ROOT>\\src\\Certs\\S2SWebSite.pfx' that needs to be imported into 'LocalComputer\\Personal' (password is: S2SWebSite).{1}'<ROOT>\\src\\ToolsAndScripts\\AddPfxToCertStore.ps1' can be used install certs.{1}Make sure to open the powershell window as an administrator.");
            }
            finally
            {
                if (x509Store != null)
                {
                    x509Store.Close();
                }
            }
        }

        public string GetAppToken(string authority)
        {
            string resource = "http://S2SBackend";
            var cert = FindCertificate(StoreName.My, StoreLocation.LocalMachine, MiddleTierThumbprint);

            var config = _configManager.GetConfigurationAsync().Result;
            // This token represents an access token between the two services.
            // Ideally it would be obtained once and refreshed, using the refresh token, when expired.

            var audience = string.Format(@"https://sts.windows.net/{0}/", MiddleTierTennant);
            var jwt = CryptoUtils.CreateClientAssertion(MiddleTierClientId, MiddleTierClientId, MiddleTierClientId, audience, new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256));
            var jwtToken = new JwtSecurityToken(jwt);
            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, config.TokenEndpoint);
            request.Method = HttpMethod.Post;
            request.Content = new FormUrlEncodedContent(GetTokenParameters(jwt, resource));
            var response = client.SendAsync(request).Result;
            if (response.IsSuccessStatusCode)
            {
                string responseString = response.Content.ReadAsStringAsync().Result;
            }

            return string.Empty;
            //var authenticationResult = authenticationContext.AcquireTokenAsync(resource, clientCred).Result;
            //return authenticationResult.AccessToken;
        }

        public Dictionary<string, string> GetTokenParameters(string assertion, string resource)
        {
            return new Dictionary<string, string>
            {
                {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                {"client_assertion", assertion },
                { "grant_type", "client_credentials" },
                { "resource", resource }
            };

            // public const string ClientAssertionType = "client_assertion_type" == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
            // public const string ClientAssertion = "client_assertion";
            // public const string GrantType = "grant_type";
            // public const string Resource = "resource";
            //return parameters;
        }

        //        var authenticationContext = new AuthenticationContext(authority, false, null);
        //        var clientAssertion = new ClientAssertionCertificate(MiddleTierClientId, cert);
        // var clientCred = new ClientAssertion(MiddleTierClientId, jwt);

        public static string GetPopAppToken(string authority)
        {
            //string resource = "http://S2SBackend";

            //var client = new HttpClient();
            //var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            //request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            //var response = client.SendAsync(request).Result;


            //var cert = FindCertificate(StoreName.My, StoreLocation.LocalMachine, MiddleTierThumbprint);
            //var authenticationContext = new AuthenticationContext(authority, false, null);
            //var clientAssertion = new ClientAssertionCertificate(clientId, cert);

            //// This token represents an access token between the two services.
            //// Ideally it would be obtained once and refreshed, using the refresh token, when expired.

            //var authenticationResult = authenticationContext.AcquireTokenAsync(resource, clientAssertion).Result;
            //return authenticationResult.AccessToken;

            return string.Empty;
        }
    }

}


}
