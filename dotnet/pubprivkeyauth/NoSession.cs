using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace pubprivkeyauth
{
    class NoSession
    {
        public async Task DoHandleWork()
        {
            string pathToPrivateKeyPemFile = @"path_to_private_key";
            string adminId = "admin_handle";
            string prefix = "prefix_to_work_with";
            string ip = "primary_handle_server";
            int port = 8000;

            // Update an existing handle
            await UpdateHandleRecord(prefix + "/1", pathToPrivateKeyPemFile, adminId, ip, port);
            // Create a new handle
            await CreateHandleRecord(prefix + "/3", pathToPrivateKeyPemFile, adminId, ip, port);
            // Delete a handle
            await DeleteHandleRecord(prefix + "/3", pathToPrivateKeyPemFile, adminId, ip, port);
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

        private async Task<string> CreateHandleRecord(string handle, string keyFile, string authId, string ip, int port)
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

                // First request to get challenge
                string body = Newtonsoft.Json.JsonConvert.SerializeObject(handleRecord);
                var response = await client.PutAsync("/api/handles/" + handle, new StringContent(body, Encoding.UTF8, "application/json"));

                // Build authorization header to response to the server's challenge
                client.DefaultRequestHeaders.Add("Authorization", CreateAuthorisationHeader(response, keyFile, authId));

                var response2 = await client.PutAsync("/api/handles/" + handle, new StringContent(body, Encoding.UTF8, "application/json"));
                var json = JObject.Parse(await response2.Content.ReadAsStringAsync());

                result = json.ToString();
            }

            return result;
        }

        private async Task<string> UpdateHandleRecord(string handle, string keyFile, string authId, string ip, int port)
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

                // First request to get challenge
                string body = Newtonsoft.Json.JsonConvert.SerializeObject(handleRecord);
                var response = await client.PutAsync("/api/handles/" + handle, new StringContent(body, Encoding.UTF8, "application/json"));

                // Build authorization header to response to the server's challenge
                client.DefaultRequestHeaders.Add("Authorization", CreateAuthorisationHeader(response, keyFile, authId));

                var response2 = await client.PutAsync("/api/handles/" + handle, new StringContent(body, Encoding.UTF8, "application/json"));
                var json = JObject.Parse(await response2.Content.ReadAsStringAsync());
                result = json.ToString();
            }

            return result;
        }

        private async Task<string> DeleteHandleRecord(string handle, string keyFile, string authId, string ip, int port)
        {
            string result = "";

            using (var client = new HttpClient())
            {
                string baseUrl = string.Format("https://{0}:{1}", ip, port.ToString()); //'+ '/api/handles/' + handle

                client.BaseAddress = new Uri(baseUrl);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                // First request to get challenge
                var response = await client.DeleteAsync("/api/handles/" + handle);

                // Build authorization header to response to the server's challenge
                client.DefaultRequestHeaders.Add("Authorization", CreateAuthorisationHeader(response, keyFile, authId));

                var response2 = await client.DeleteAsync("/api/handles/" + handle);
                var json = JObject.Parse(await response2.Content.ReadAsStringAsync());
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

        private string CreateAuthorisationHeader(HttpResponseMessage response, string keyFile, string authId)
        {
            // Unpick number once (nonce) and session id from server response (this is the challenge)
            string authenticateHeader = response.Headers.WwwAuthenticate.ToString();
            Dictionary<string, string> authenticateHeaderDict = parseAuthenticateHeader(authenticateHeader);

            byte[] serverNonceBytes = Convert.FromBase64String(authenticateHeaderDict["nonce"]);
            string sessionId = authenticateHeaderDict["sessionId"];

            // Generate a client number once (cnonce)
            byte[] clientNonceBytes = GenerateClientNonceBytes();
            string clientNonceString = Convert.ToBase64String(clientNonceBytes);

            // Our response has to be the signature of server nonce + client nonce
            byte[] combinedNonceBytes = serverNonceBytes.Concat(clientNonceBytes).ToArray();
            byte[] signatureBytes = SignBytesDsa(combinedNonceBytes, keyFile);
            string signatureString = Convert.ToBase64String(signatureBytes);

            // Build the authorisation header to send with the request
            string authorizationHeaderString = BuildComplexAuthorizationString(signatureString, "HS_PUBKEY", "SHA1", sessionId, clientNonceString, authId);

            return authorizationHeaderString;
        }

        private byte[] SignBytesRsa(byte[] byteArray, string pathToPrivateKeyPemFile)
        {
            // TODO if/when we have an RSA key - Steps are 

            // Import RSA key

            // Create PKCS1 (v1.5) signer

            // Create SHA256 digest of byte array

            // Sign digest

            throw new NotImplementedException();
        }

        private byte[] SignBytesDsa(byte[] byteArray, string pathToPrivateKeyPemFile)
        {
            // Create a digest of nonce + cnonce
            // This only seems to work with SHA1 (SHA256 gives us a 401 error)
            var sha = SHA1.Create();
            var digest = sha.ComputeHash(byteArray);

            // Read DSA key
            DsaKeyParameters keyParameters;
            using (var fileStream = System.IO.File.OpenText(pathToPrivateKeyPemFile))
            {
                var pemReader = new PemReader(fileStream);
                keyParameters = (DsaKeyParameters)pemReader.ReadObject();
            }

            // Create DSA signer
            DsaSigner sig = new DsaSigner();
            sig.Init(true, keyParameters);

            // Digitally sign the digest with our private key
            // The corresponding public key is in our admin handle on the server
            var signature = sig.GenerateSignature(digest);

            // Signature bytes from a DSA key need to be DER-encoded
            // This signature is in two parts (r and s)
            DerSequence seq = new DerSequence(new Asn1Encodable[2] { new DerInteger(signature[0]), new DerInteger(signature[1]) });
            var encode = seq.GetEncoded();
            var derEncode = seq.GetDerEncoded();


            return seq.GetDerEncoded();
        }

        private string BuildComplexAuthorizationString(string signatureString, string typeString, string alg, string sessionId, string clientNonceString, string authId)
        {
            string result = string.Format(@"Handle version=""0"", sessionId=""{0}"", cnonce=""{1}"", id=""{2}"", type=""{3}"", alg=""{4}"", signature=""{5}""",
                sessionId, clientNonceString, authId, typeString, alg, signatureString);

            return result;
        }

        private Dictionary<string, string> parseAuthenticateHeader(string authenticateHeader)
        {
            var result = new Dictionary<string, string>();
            var tokens = authenticateHeader.Split(new char[] { ',' });

            foreach (var token in tokens)
            {
                int firstEquals = token.IndexOf("=");
                var key = token.Substring(0, firstEquals).Trim();

                // quick and dirty parsing of the expected WWW-Authenticate headers
                if (key == "Basic realm") continue;

                if (key == "Handle sessionId") key = "sessionId";

                var value = token.Substring(firstEquals + 1).Trim(new char[] { '"' });
                result.Add(key, value);
            }

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
