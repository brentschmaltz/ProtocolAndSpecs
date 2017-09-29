//-------------------------------------------------------------------------------------------------
// <copyright file="StringUtils.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Microsoft.IdentityModel.S2S
{
    /// <summary>
    /// Crypto utilities
    /// </summary>
    public static class CryptoUtils
    {
        // TODO - add overload for keySize.
        // TODO - should this be in IM.Tokens.CryptoProvider?
        public static RsaSecurityKey CreateRsaSecurityKey()
        {
            // NETSTANDARD1_6 has RSA.Create(int) - which is xplat use RSACryptoServiceProvider for NET451 and NET45 
            var rsa = new RSACryptoServiceProvider(2048);
            var parameters = rsa.ExportParameters(false);
            return new RsaSecurityKey(parameters);
        }

        public static string CreatePopRequest(string clientId, string issuer, string audience, RsaSecurityKey popKey, SigningCredentials signingCredentials)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var modulus = Base64UrlEncoder.Encode(popKey.Parameters.Modulus);
            var exponent = Base64UrlEncoder.Encode(popKey.Parameters.Exponent);
            var claimValue = $"\"kty\":\"RSA\", \"n\":\"{modulus}\",\"e\"{exponent}\",\"alg\":\"RS256\",\"kid\":\"1\"";
            var subject = new ClaimsIdentity(new Claim[] { new Claim("pop_jwk", claimValue) });

            var jwt = tokenHandler.CreateEncodedJwt(issuer, audience, subject, DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(1), DateTime.UtcNow, signingCredentials);
            return jwt;
        }

        public static string CreateClientAssertion(string clientId, string issuer, string subject, string audience, SigningCredentials signingCredentials)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var identity = new ClaimsIdentity(new Claim[] { new Claim("sub", subject) });
            var jwt = tokenHandler.CreateJwtSecurityToken(issuer, audience, identity, DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(1), DateTime.UtcNow, signingCredentials);
            jwt.Header["x5t"] = Base64UrlEncoder.Encode((signingCredentials.Key as X509SecurityKey).Certificate.GetCertHash());
            jwt.Header["kid"] = Base64UrlEncoder.Encode((signingCredentials.Key as X509SecurityKey).Certificate.GetCertHash());

            return tokenHandler.WriteToken(jwt);
        }

    }
}