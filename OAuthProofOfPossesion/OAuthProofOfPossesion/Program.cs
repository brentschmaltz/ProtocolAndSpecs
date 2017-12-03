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
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.S2S;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OAuthProofOfPossesion
{
    class Program
    {
        public const string Thumbprint = "8BDD5C76F165FA88C5A73E978D0522C47F934C90";
        public const string AccessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiIyZDE0OTkxNy0xMjNkLTRiYTMtODc3NC0zMjdiODc1ZjU1NDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hZGQyOTQ4OS03MjY5LTQxZjQtODg0MS1iNjNjOTU1NjQ0MjAvIiwiaWF0IjoxNDY3NDk3MDU1LCJuYmYiOjE0Njc0OTcwNTUsImV4cCI6MTQ2NzUwMDk1NSwiYWNyIjoiMSIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiI5MDVhNWUyYS1lYmY1LTRiNzAtOGViMC1mZDI2MzAzYjZhNWYiLCJhcHBpZGFjciI6IjIiLCJmYW1pbHlfbmFtZSI6IjEiLCJnaXZlbl9uYW1lIjoiVXNlciIsImlwYWRkciI6IjUwLjQ2LjE1OS41MyIsIm5hbWUiOiJVc2VyMSIsIm9pZCI6ImQxYWQ5Y2U3LWIzMjItNDIyMS1hYjc0LTFlMTAxMWUxYmJjYiIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiBXcml0ZURhdGEiLCJzdWIiOiJNQVM2Y05OallPVUtqRXpLbzViY3NsUHJ6LWhoMXNGUjR1RHlaNkxZQ1gwIiwidGlkIjoiYWRkMjk0ODktNzI2OS00MWY0LTg4NDEtYjYzYzk1NTY0NDIwIiwidW5pcXVlX25hbWUiOiJVc2VyMUBDeXJhbm8ub25taWNyb3NvZnQuY29tIiwidXBuIjoiVXNlcjFAQ3lyYW5vLm9ubWljcm9zb2Z0LmNvbSIsInZlciI6IjEuMCJ9.llJNEvD5pIUL-eEDtUQhlXdOa9Wuklks_vQkJzlW2hM6WKEj_1_uZhh2bbjEGMB1HwlZXEjKatLc40mR56oSZrdGhz38TlN7Mxu3G7z4kisiJzIrz7p-Jj-R124y1IwKPHNv5dky0evZ0K84TUx6g3nU06y2FbqyO99TR2YqHTwjYbgYy5oXIIHgEgKGnXtZq61nODWSLiJis3-49R3YNKdt8GxcJuPYS_EYdFilTT9vye7akJZtPhMhmcQPQen3GsgJz80UGQk-OkPrmdXYtdWmgtd0-JHb3GnenCGhB6jaLUTkCH0GCi3R4QnTSxlQI2wuEB2b6lNz9lDqSpGVUg";
        public const string AppToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJodHRwOi8vUzJTQmFja2VuZCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2FkZDI5NDg5LTcyNjktNDFmNC04ODQxLWI2M2M5NTU2NDQyMC8iLCJpYXQiOjE0Njc0OTczMzAsIm5iZiI6MTQ2NzQ5NzMzMCwiZXhwIjoxNDY3NTAxMjMwLCJhcHBpZCI6IjJkMTQ5OTE3LTEyM2QtNGJhMy04Nzc0LTMyN2I4NzVmNTU0MCIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2FkZDI5NDg5LTcyNjktNDFmNC04ODQxLWI2M2M5NTU2NDQyMC8iLCJvaWQiOiI5MTkxOTZmNi0zOGZkLTQ2ZjMtODY4Ni1hNDllMjk0NGIyNzciLCJzdWIiOiI5MTkxOTZmNi0zOGZkLTQ2ZjMtODY4Ni1hNDllMjk0NGIyNzciLCJ0aWQiOiJhZGQyOTQ4OS03MjY5LTQxZjQtODg0MS1iNjNjOTU1NjQ0MjAiLCJ2ZXIiOiIxLjAifQ.QLOroZZY53Gj97VuI2X66dxZ6vDIfJlDBwsDTAMJR8FcugucpWTyMtkCm9JcOHOb78lBwaMTJlOwUcb7qrwRrtjkxGCI3hUw-LBPREqM-AowlrUk1ORvB4CV7zDqH6m6s0LL91I3JpQEhMsQxo1OfcYyDR-vKJ5ybprYUgMIKmPeqGbUMLYDCwO9-0efl3LCdyI3FRlcbDg1960z2OlgmbFSlpQiT4bDDHszx1W0G0mJjO8Ypkfh3z_aBBoclkSR34lV_htJlCcW0CM7dopOzHACljCiJWgDh_q5pULLIWeGnYFKLtJZR7wSKp18a-k28xT_S1fgMqFooZ0r-5i3kA";

        static void Main(string[] args)
        {
            var cert = CryptoUtils.FindCertificate(StoreName.My, StoreLocation.LocalMachine, Thumbprint);
            var signingCredentials = new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);
            var requestData = new SignedHttpRequestData
            {
                AppToken = AppToken,
                PayloadToken = AccessToken,
                PayloadTokenType = "PFT",
                Request = new Uri("https://a.com/b/c?d=e"),
                RequestMethod = "GET",
                SigningCredentials = new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256)
            };


            var header = new JObject
            {
                { "typ", "JWT" },
                { "alg", "RS256" },
                { "x5t", Base64UrlEncoder.Encode((signingCredentials.Key as X509SecurityKey).Certificate.GetCertHash()) }
            };

            var encodedHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Formatting.None))) + ".";
            var cryptoFactory = signingCredentials.CryptoProviderFactory ?? signingCredentials.Key.CryptoProviderFactory;
            var hashAlgorithm = cryptoFactory.CreateHashAlgorithm(signingCredentials.Digest);
            var signatureProvider = cryptoFactory.CreateForSigning(signingCredentials.Key, signingCredentials.Algorithm);

            var results = new double[5];
            results[0] = 0;
            results[1] = 0;
            results[2] = 0;
            results[3] = 0;
            results[4] = 0;

            var numberOfIterations = 1500;
            var totalIterations = 0;
            var totalLoops = 6;
            Console.WriteLine($"Start test: iterations per loop: {numberOfIterations}.");
            for (int loops = 0; loops < totalLoops; loops++)
            {
                Console.WriteLine($"Start    loop: {loops+1} of {totalLoops}.");
                PerfTest(results, numberOfIterations, requestData, signatureProvider, hashAlgorithm, encodedHeader);
                Console.WriteLine($"Finished loop: {loops+1} of {totalLoops}.");
                totalIterations += numberOfIterations;
            }

            Console.WriteLine($"Results ===================================");
            Console.WriteLine($"Wilson:        '{results[0]}', Iterations: '{totalIterations}'.");
            Console.WriteLine($"JObject:       '{results[1]}', Iterations: '{totalIterations}'.");
            Console.WriteLine($"Fixed Crypto:  '{results[2]}', Iterations: '{totalIterations}'.");
            Console.WriteLine($"StringBuilder: '{results[3]}', Iterations: '{totalIterations}'.");
            Console.WriteLine($"StringCat:     '{results[4]}', Iterations: '{totalIterations}'.");
            Console.WriteLine("Press any key.");
            Console.ReadKey();
        }

        static void PerfTest(double[] results, int numberOfIterations, SignedHttpRequestData requestData, SignatureProvider signatureProvider, HashAlgorithm hashAlgorithm, string encodedHeader)
        {
            RunTests(results, requestData, numberOfIterations, 0, null, null, null);
            RunTests(results, requestData, numberOfIterations, 2, signatureProvider, hashAlgorithm, encodedHeader);
            RunTests(results, requestData, numberOfIterations, 1, null, null, null);
            RunTests(results, requestData, numberOfIterations, 3, signatureProvider, hashAlgorithm, encodedHeader);
            RunTests(results, requestData, numberOfIterations, 4, signatureProvider, hashAlgorithm, encodedHeader);
            RunTests(results, requestData, numberOfIterations, 3, signatureProvider, hashAlgorithm, encodedHeader);
            RunTests(results, requestData, numberOfIterations, 1, null, null, null);
            RunTests(results, requestData, numberOfIterations, 0, null, null, null);
            RunTests(results, requestData, numberOfIterations, 4, signatureProvider, hashAlgorithm, encodedHeader);
            RunTests(results, requestData, numberOfIterations, 2, signatureProvider, hashAlgorithm, encodedHeader);
        }

        public static double RunTests(double[] results, SignedHttpRequestData requestData, int numberOfIterations, int test, SignatureProvider signatureProvider, HashAlgorithm hashAlgorithm, string encodedHeader)
        {
            Stopwatch sw = Stopwatch.StartNew();
            if (test == 0)
            {
                for (int i = 0; i < numberOfIterations; i++)
                {
                    var testRun = new TestRun();
                    testRun.CreatePopAuthenticatorWithWilson(requestData);
                }
            }
            else if (test == 1)
            {
                for (int i = 0; i < numberOfIterations; i++)
                {
                    var testRun = new TestRun();
                    testRun.CreatePopAuthenticator(requestData);
                }
            }
            else if (test == 2)
            {
                for (int i = 0; i < numberOfIterations; i++)
                {
                    var testRun = new TestRun();
                    testRun.CreatePopAuthenticator(requestData, signatureProvider, hashAlgorithm, encodedHeader);
                }
            }
            else if (test == 3)
            {
                for (int i = 0; i < numberOfIterations; i++)
                {
                    var testRun = new TestRun();
                    testRun.CreatePopAuthenticatorStringBuilder(requestData, signatureProvider, hashAlgorithm, encodedHeader);
                }
            }
            else if (test == 4)
            {
                for (int i = 0; i < numberOfIterations; i++)
                {
                    var testRun = new TestRun();
                    testRun.CreatePopAuthenticatorStringCat(requestData, signatureProvider, hashAlgorithm, encodedHeader);
                }
            }

            sw.Stop();
            results[test] += sw.Elapsed.TotalMilliseconds;
            return sw.Elapsed.TotalMilliseconds;
        }
    }
}
