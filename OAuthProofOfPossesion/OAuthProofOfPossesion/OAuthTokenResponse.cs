//------------------------------------------------------------------------------
//
// Copyright (c) Bre3nt Schmaltz.
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

using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json;

namespace OAuthProofOfPossesion
{

    /// <summary>
    /// Represents an user profile supplied from AAD Graph.
    /// </summary>
    [JsonObject]
    public class OAuthTokenResponse
    {
        /// <summary>
        /// Deserializes the JSON string into an <see cref="OAuthTokenResponse"/> object.
        /// </summary>
        /// <param name="json">JSON string representing an <see cref="OAuthTokenResponse"/>.</param>
        /// <returns>a populated <see cref="OAuthTokenResponse"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="json"/> is null or empty.</exception>
        public static OAuthTokenResponse Create(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            return new OAuthTokenResponse(json);
        }

        /// <summary>
        /// Serializes the <see cref="OAuthTokenResponse"/> object to a JSON string.
        /// </summary>
        /// <param name="configuration"><see cref="OpenIdConnectConfiguration"/> object to serialize.</param>
        /// <returns>JSON representation of <see cref="OAuthTokenResponse"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="tokenResponse"/> is null.</exception>
        public static string Serialize(OAuthTokenResponse tokenResponse)
        {
            if (tokenResponse == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenResponse));

            return JsonConvert.SerializeObject(tokenResponse);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OAuthTokenResponse"/>.
        /// </summary>
        public OAuthTokenResponse()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OAuthTokenResponse"/> from a JSON string.
        /// </summary>
        /// <param name="json">JSON string representing an <see cref="OAuthTokenResponse"/>.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="json"/> is null or empty.</exception>
        public OAuthTokenResponse(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            JsonConvert.PopulateObject(json, this);
        }

        /// <summary>
        /// Gets or sets the 'access_token'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "access_token", Required = Required.Default)]
        public string AccessToken { get; set; }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public virtual IDictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets or sets 'expires_in'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "expires_in", Required = Required.Default)]
        public string ExpiresIn { get; set; }

        /// <summary>
        /// Gets or sets the 'expires_on'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "expires_on", Required = Required.Default)]
        public string ExpiresOn { get; set; }

        /// <summary>
        /// Gets or sets the 'ext_expires_in'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "ext_expires_in", Required = Required.Default)]
        public string ExtExpiresIn { get; set; }

        /// <summary>
        /// Gets or sets the 'not_before'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "not_before", Required = Required.Default)]
        public string NotBefore { get; set; }

        /// <summary>
        /// Gets the collection of 'resource'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "resource", Required = Required.Default)]
        public string Resource { get; set; }

        /// <summary>
        /// Gets or sets the 'token_type'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "token_type", Required = Required.Default)]
        public string TokenType { get; set; }

        /// <summary>
        /// Gets or sets the 'userType'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "userType", Required = Required.Default)]
        public string UserType { get; set; }
    }
}
