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
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json;

namespace OAuthProofOfPossesion
{
    /// <summary>
    /// Represents an user profile supplied from AAD Graph.
    /// </summary>
    [JsonObject]
    public class AadGraphUserProfile
    {
        /// <summary>
        /// Deserializes the JSON string into an <see cref="AadGraphUserProfile"/> object.
        /// </summary>
        /// <param name="json">JSON string representing an <see cref="AadGraphUserProfile"/>.</param>
        /// <returns>a populated <see cref="AadGraphUserProfile"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="json"/> is null or empty.</exception>
        public static AadGraphUserProfile Create(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            return new AadGraphUserProfile(json);
        }

        /// <summary>
        /// Serializes the <see cref="AadGraphUserProfile"/> object to a JSON string.
        /// </summary>
        /// <param name="userProfile"><see cref="AadGraphUserProfile"/> object to serialize.</param>
        /// <returns>JSON representation of <see cref="AadGraphUserProfile"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="userProfile"/> is null.</exception>
        public static string Serialize(AadGraphUserProfile userProfile)
        {
            if (userProfile == null)
                throw LogHelper.LogArgumentNullException(nameof(userProfile));

            return JsonConvert.SerializeObject(userProfile);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="AadGraphUserProfile"/>.
        /// </summary>
        public AadGraphUserProfile()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="AadGraphUserProfile"/> from a JSON string.
        /// </summary>
        /// <param name="json">JSON string representing an <see cref="AadGraphUserProfile"/>.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="json"/> is null or empty.</exception>
        public AadGraphUserProfile(string json)
        {
            if(string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            JsonConvert.PopulateObject(json, this);
        }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public virtual IDictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        //"odata.metadata":"https://graph.windows.net/add29489-7269-41f4-8841-b63c95564420/$metadata#directoryObjects/Microsoft.WindowsAzure.ActiveDirectory.User/@Element",
        //"odata.type":"Microsoft.WindowsAzure.ActiveDirectory.User",
        //"assignedLicenses":[],
        //"assignedPlans":[],
        //"country":null,
        //"department":null,
        //"dirSyncEnabled":null,
        //"facsimileTelephoneNumber":null,
        //"givenName":"User",
        //"immutableId":null,
        //"jobTitle":null,
        //"lastDirSyncTime":null,
        //"mail":null,
        //"mailNickname":"User1",
        //"mobile":null,
        //"otherMails":[],
        //"passwordPolicies":"None",
        //"passwordProfile":null,
        //"physicalDeliveryOfficeName":null,
        //"postalCode":null,
        //"preferredLanguage":null,
        //"provisionedPlans":[],
        //"provisioningErrors":[],
        //"proxyAddresses":[],
        //"state":null,
        //"streetAddress":null,
        //"surname":"1",
        //"telephoneNumber":null,
        //"usageLocation":null,
        //"userPrincipalName":"User1@Cyrano.onmicrosoft.com",
        //"userType":"Member"

        /// <summary>
        /// Gets or sets the 'accountEnabled'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "accountEnabled", Required = Required.Default)]
        public bool AccountEnabled { get; set; }

        /// <summary>
        /// Gets or sets 'city'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "city", Required = Required.Default)]
        public string City { get; set; }

        /// <summary>
        /// Gets or sets the 'displayName'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "displayName", Required = Required.Default)]
        public string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the 'objectId'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "objectId", Required = Required.Default)]
        public string ObjectId { get; set; }

        /// <summary>
        /// Gets or sets the 'objectType'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "objectType", Required = Required.Default)]
        public string ObjectType { get; set; }

        /// <summary>
        /// Gets the collection of 'provisionedPlans'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "provisionedPlans", Required = Required.Default)]
        public ICollection<string> ProvisionedPlans { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'userPrincipalName'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "userPrincipalName", Required = Required.Default)]
        public string UserPrincipalName { get; set; }

        /// <summary>
        /// Gets or sets the 'userType'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "userType", Required = Required.Default)]
        public string UserType { get; set; }
    }
}
