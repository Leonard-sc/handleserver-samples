using Newtonsoft.Json.Linq;
using OpenSSL.Crypto;
using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace pubprivkeyauth
{
    public class Session
    {
        public async Task DoHandleWork()
        {
            string pathToPrivateKeyPemFile = @"path_to_private_key";
            string adminId = "admin_handle";
            string prefix = "prefix_to_work_with";
            string ip = "primary_server_ip";
            int port = 8000;

            var sessionId = await SetupSession(pathToPrivateKeyPemFile, adminId, ip, port);

            if (sessionId != "")
            {
                // Update an existing handle
                await UpdateHandleRecord(prefix + "/1", sessionId, ip, port);
                // Create a new handle
                await CreateHandleRecord(prefix + "/2", sessionId, adminId, ip, port);
                // Delete a handle
                await DeleteHandleRecord(prefix + "/2", sessionId, ip, port);
            }
            else
            {
                System.Console.WriteLine("Could not establish session");
            }
        }

        private async Task<string> SetupSession(string keyFile, string authId, string ip, int port)
        {
            string baseUrl = string.Format("https://{0}:{1}", ip, port.ToString());

            using (var client = new HttpClient())
            {
                try
                {
                    client.BaseAddress = new Uri(baseUrl);
                    client.DefaultRequestHeaders.Clear();
                    client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                    // HTTP POST
                    var response = await client.PostAsync("/api/sessions/", null);
                    var json = JObject.Parse(await response.Content.ReadAsStringAsync());

                    // Build authorisation header using JSON response
                    client.DefaultRequestHeaders.Add("Authorization", CreateAuthorizationHeaderFromJson(json, keyFile, authId));

                    // Send another request with a correctly signed Authorization header
                    var response2 = await client.PutAsync("/api/sessions/this", null);

                    var json2 = JObject.Parse(await response2.Content.ReadAsStringAsync());
                    if (json2["authenticated"].Value<String>() != null)
                    {
                        return json2["sessionId"].Value<String>();
                    }
                    else
                    {
                        return "";
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    return "";
                }
            }
        }

        private JObject GetEmailValue(JArray handle)
        {
            for (int i = 0; i < handle.Count; ++i)
            {
                JObject item = (JObject)handle[i];
                if ((string)item["index"] == "2")
                {
                    return (JObject)handle[i];
                }
            }

            return null;
        }


        private async Task<JObject> GetHandleRecord(string handle, string ip, int port)
        {
            using (var client = new HttpClient())
            {
                try
                {
                    string baseUrl = string.Format("https://{0}:{1}", ip, port.ToString()); //'+ '/api/handles/' + handle

                    client.BaseAddress = new Uri(baseUrl);
                    client.DefaultRequestHeaders.Clear();
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    var response = await client.PostAsync("/api/handles/" + handle, null);
                    var json = JObject.Parse(await response.Content.ReadAsStringAsync());

                    return json;
                }
                catch (Exception ex)
                {
                    return null;
                }
            }
        }

        private async Task<string> CreateHandleRecord(string handle, string sessionId, string authId, string ip, int port)
        {
            string result = "";

            DateTime currentDate = DateTime.Now;
            String currentDateFormat = currentDate.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

            JArray handleValues = new JArray();

            handleValues.Add(JObject.Parse(string.Format(@"{{""index"": {0}, ""ttl"": {1}, ""type"": ""{2}"", ""timestamp"": ""{3}"", ""data"": {{""value"": ""{4}"", ""format"": ""{5}""}}}}", "1", "86400", "URL", currentDateFormat, "http://www.ribaenterprises.com", "string")));
            handleValues.Add(JObject.Parse(string.Format(@"{{""index"": {0}, ""ttl"": {1}, ""type"": ""{2}"", ""timestamp"": ""{3}"", ""data"": {{""value"": ""{4}"", ""format"": ""{5}""}}}}", "2", "86400", "EMAIL", currentDateFormat, "info@ribaenterprises.com", "string")));
            handleValues.Add(JObject.Parse(string.Format(@"{{""index"": {0}, ""ttl"": {1}, ""type"": ""{2}"", ""timestamp"": ""{3}"", ""data"": {{""value"": {{""index"": {4}, ""handle"": ""{5}"", ""permissions"": ""{6}""}}, ""format"": ""{7}""}}}}", "100", "86400", "HS_ADMIN", currentDateFormat, "200", authId, "011111110011", "admin")));

            JObject handleRecord = new JObject();
            handleRecord["handle"] = handle;
            handleRecord["values"] = handleValues;
            handleRecord["responseCode"] = 1;

            using (var client = new HttpClient())
            {
                string baseUrl = string.Format("https://{0}:{1}", ip, port.ToString()); //'+ '/api/handles/' + handle

                client.BaseAddress = new Uri(baseUrl);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("Authorization", string.Format(@"Handle version=""0"", sessionId=""{0}""", sessionId));

                string body = Newtonsoft.Json.JsonConvert.SerializeObject(handleRecord);
                var response = await client.PutAsync("/api/handles/" + handle, new StringContent(body, Encoding.UTF8, "application/json"));
                var json = JObject.Parse(await response.Content.ReadAsStringAsync());

                result = json.ToString();
            }

            return result;
        }

        private async Task<string> UpdateHandleRecord(string handle, string sessionId, string ip, int port)
        {
            string result = "";

            // Get the handle record
            JObject handleRecord = await GetHandleRecord(handle, ip, port);
            Console.WriteLine(handleRecord.ToString());

            // Do some updates on the handle
            JObject emailValue = GetEmailValue((JArray)handleRecord["values"]);

            if (emailValue == null)
            {
                // Add new email item
                DateTime currentDate = DateTime.Now;
                string currentDateFormat = currentDate.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

                string updatedRecord = string.Format(@"{{""index"": {0}, ""ttl"": {1}, ""type"": ""{2}"", ""timestamp"": ""{3}"", ""data"": {{""value"": ""{4}"", ""format"": ""{5}""}}}}", "2", "86400", "EMAIL", currentDateFormat, "info@thenbs.com", "string");
                ((JArray)handleRecord["values"]).Add(JObject.Parse(updatedRecord));
            }
            else
            {
                emailValue["data"]["value"] = "info@theNBS.com";
                Console.WriteLine(handleRecord.ToString());
            }

            using (var client = new HttpClient())
            {
                string baseUrl = string.Format("https://{0}:{1}", ip, port.ToString()); //'+ '/api/handles/' + handle

                client.BaseAddress = new Uri(baseUrl);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("Authorization", string.Format(@"Handle version=""0"", sessionId=""{0}""", sessionId));

                string body = Newtonsoft.Json.JsonConvert.SerializeObject(handleRecord);
                var response = await client.PutAsync("/api/handles/" + handle, new StringContent(body, Encoding.UTF8, "application/json"));
                var json = JObject.Parse(await response.Content.ReadAsStringAsync());
                result = json.ToString();
            }

            return result;
        }

        private async Task<string> DeleteHandleRecord(string handle, string sessionId, string ip, int port)
        {
            string result = "";

            using (var client = new HttpClient())
            {
                string baseUrl = string.Format("https://{0}:{1}", ip, port.ToString()); //'+ '/api/handles/' + handle

                client.BaseAddress = new Uri(baseUrl);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("Authorization", string.Format(@"Handle version=""0"", sessionId=""{0}""", sessionId));

                var response = await client.DeleteAsync("/api/handles/" + handle);
                var json = JObject.Parse(await response.Content.ReadAsStringAsync());
                result = json.ToString();
            }

            return result;
        }

        private string CreateAuthorizationHeaderFromJson(JToken json, string keyFile, string authId)
        {
            // Unpick number once (nonce) and session id from server response (this is the challenge)
            byte[] serverNonceBytes = Convert.FromBase64String(json["nonce"].Value<String>());
            string sessionId = json["sessionId"].Value<String>();

            // Generate a client number once (cnonce)
            byte[] clientNonceBytes = GenerateClientNonceBytes();
            string clientNonceString = Convert.ToBase64String(clientNonceBytes);

            // Our response has to be the signature of server nonce + client nonce
            byte[] combinedNonceBytes = serverNonceBytes.Concat(clientNonceBytes).ToArray();
            byte[] signatureBytes = SignBytesDsa(combinedNonceBytes, keyFile);
            string signatureString = Convert.ToBase64String(signatureBytes);

            // Build the authorisation header to send with the request
            // Use SHA1 for DSA keys; SHA256 can be used for RSA keys
            string authorizationHeaderString = BuildComplexAuthorizationString(signatureString, "HS_PUBKEY", "SHA1", sessionId, clientNonceString, authId);

            return authorizationHeaderString;
        }

        private byte[] SignBytesDsa(byte[] byteArray, string pathToPrivateKeyPemFile) {
            // Use this method for DSA keys
            string key = System.IO.File.ReadAllText(pathToPrivateKeyPemFile);

            // Import the key
            CryptoKey d = CryptoKey.FromPrivateKey(key, null);
            var dsaKey = d.GetDSA();

            // Create a digest of nonce + cnonce
            // This only seems to work with SHA1 (SHA256 gives us a 401 error)
            var sha = SHA1.Create();
            var digest = sha.ComputeHash(byteArray);

            // Digitally sign the digest with our private key
            // The corresponding public key is in our admin handle on the server
            var sig = dsaKey.Sign(digest);

            // Signature bytes from a DSA key need to be DER-encoded
            // This signature is in two parts (r and s)
            Asn1InputStream bIn = new Asn1InputStream(new MemoryStream(sig));
            DerSequence seq = bIn.ReadObject() as DerSequence;

            return seq.GetDerEncoded();
        }

        private string BuildComplexAuthorizationString(string signatureString, string typeString, string alg, string sessionId, string clientNonceString, string authId)
        {
            string result = string.Format(@"Handle version=""0"", sessionId=""{0}"", cnonce=""{1}"", id=""{2}"", type=""{3}"", alg=""{4}"", signature=""{5}""",
                sessionId, clientNonceString, authId, typeString, alg, signatureString);

            return result;
        }

        private byte[] GenerateClientNonceBytes()
        {
            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();

            var data = new byte[16];
            random.GetNonZeroBytes(data);

            return data;
        }
    }
}
