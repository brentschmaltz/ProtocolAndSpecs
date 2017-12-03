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
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using static System.Net.WebUtility;
using System.Net;
using System.Collections.Generic;

namespace OAuthProofOfPossesion
{
    /// <summary>
    /// Crypto utilities
    /// </summary>
    public static class CryptoUtils
    {
        public static X509Certificate2 FindCertificate(StoreName storeName, StoreLocation storeLocation, string thumbprint)
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
    }
}