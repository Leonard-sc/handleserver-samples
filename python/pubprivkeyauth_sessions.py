import os
import json
import base64
import requests
from datetime import datetime

# RSA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# DSA
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA1
from Crypto.Random import random
from Crypto.Util.asn1 import DerSequence


def main():
    path_to_private_key_pem_file = 'path_to_private_key'
    admin_id = 'admin_handle'
    prefix = 'prefix_to_work_with'
    ip = 'primary_handle_server'
    port = 8000

    session_id = setup_session(path_to_private_key_pem_file, admin_id, ip, port)

    if session_id != '':
        # Update an existing handle
        update_handle_record(prefix + '/1', session_id, ip, port)
        # Create a new handle
        create_handle_record(prefix + '/2', session_id, admin_id, ip, port)
        # Delete a handle
        delete_handle_record(prefix + '/2', session_id, ip, port)
    else:
        print 'Could not establish session'


def setup_session(key_file, auth_id, ip, port):
    headers = {
        'Content-Type': 'application/json;charset=UTF-8'
    }

    url = 'https://' + ip + ':' + str(port) + '/api/sessions/'
    # Turn off certificate verification as most handle servers have self-signed certificates
    r = requests.post(url, verify=False)

    # Response JSON has sessionId and nonce
    json_response = r.json()

    # Build the authorisation header that will response to the server challenge
    headers['Authorization'] = create_authorisation_header_from_json(json_response, key_file, auth_id)

    # Send the request again with a valid correctly signed Authorization header
    r2 = requests.put(url + 'this', headers=headers, verify=False)
    print r2.status_code, r2.reason

    json_response2 = r2.json()
    if json_response2['authenticated']:
        return json_response2['sessionId']
    else:
        return ""


def get_email_value(handle):
    for x in range(0, len(handle)):
        item = handle[x]
        if item['index'] == 2:
            return handle[x]

    return None


def get_handle_record(handle, ip, port):
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle
    # Turn off certificate verification as most handle servers have self-signed certificates
    r = requests.get(url, verify=False)
    handle_record = r.json()

    return handle_record


def update_handle_record(handle, session_id, ip, port):
    # Get the handle record
    handle_record = get_handle_record(handle, ip, port)
    print handle_record

    # Do some updates on the handle
    email_value = get_email_value(handle_record['values'])
    if email_value is None:
        # Add new email item
        current_date = datetime.now()
        current_date_format = unicode(current_date.strftime('%Y-%m-%dT%H:%M:%SZ'))
        handle_record['values'].append({u'index': 2, u'ttl': 86400, u'type': u'EMAIL', u'timestamp': current_date_format, u'data': {u'value': u'info@thenbs.com', u'format': u'string'}})
    else:
        email_value['data']['value'] = u'info@theNBS.com'
    print handle_record

    # Update the handle server
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': 'Handle version="0", sessionId="' + session_id + '"'
    }
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle
    body = json.dumps(handle_record)

    # Send the request using our authenticated session
    r = requests.put(url, headers=headers, verify=False, data=body)
    print r.status_code, r.reason

    return r


def create_handle_record(handle, session_id, auth_id, ip, port):
    current_date = datetime.now()
    current_date_format = unicode(current_date.strftime('%Y-%m-%dT%H:%M:%SZ'))
    handle_record = {u'values': [
        {u'index': 1, u'ttl': 86400, u'type': u'URL', u'timestamp': current_date_format, u'data': {u'value': u'http://www.ribaenterprises.com', u'format': u'string'}},
        {u'index': 2, u'ttl': 86400, u'type': u'EMAIL', u'timestamp': current_date_format, u'data': {u'value': u'info@ribaenterprises.com', u'format': u'string'}},
        {u'index': 100, u'ttl': 86400, u'type': u'HS_ADMIN', u'timestamp': current_date_format, u'data': {u'value': {u'index': 200, u'handle': unicode(auth_id), u'permissions': u'011111110011'}, u'format': u'admin'}}
    ], u'handle': unicode(handle), u'responseCode': 1}

    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': 'Handle version="0", sessionId="' + session_id + '"'
    }
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle
    body = json.dumps(handle_record)

    # Send the request using our authenticated session
    r = requests.put(url, headers=headers, verify=False, data=body)
    print r.status_code, r.reason

    return r


def delete_handle_record(handle, session_id, ip, port):
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': 'Handle version="0", sessionId="' + session_id + '"'
    }
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle

    # Send the request with our authenticated session
    r = requests.delete(url, headers=headers, verify=False)
    print r.status_code, r.reason

    return r


def create_authorisation_header_from_json(json, key_file, auth_id):
    # Unpick number once (nonce) and session id from server response (this is the challenge)
    server_nonce_bytes = base64.b64decode(json['nonce'])
    session_id = json['sessionId']

    # Generate a client number once (cnonce)
    client_nonce_bytes = generate_client_nonce_bytes()
    client_nonce_string = base64.b64encode(client_nonce_bytes)

    # Our response has to be the signature of server nonce + client nonce
    combined_nonce_bytes = server_nonce_bytes + client_nonce_bytes
    signature_bytes = sign_bytes_dsa(combined_nonce_bytes, key_file)
    signature_string = base64.b64encode(signature_bytes)

    # Build the authorisation header to send with the request
    # Use SHA1 for DSA keys; SHA256 can be used for RSA keys
    authorization_header_string = build_complex_authorization_string(signature_string, 'HS_PUBKEY', 'SHA1',
                                                                     session_id, client_nonce_string, auth_id)

    return authorization_header_string


def sign_bytes_rsa(byte_array, path_to_private_key_pem_file):
    # Use this method for RSA keys
    key = open(path_to_private_key_pem_file, 'r').read()
    rsa_key = RSA.importKey(key)

    signer = PKCS1_v1_5.new(rsa_key)
    buf = buffer(byte_array)

    digest = SHA256.new(buf)
    digest.update(buffer(byte_array))

    sign = signer.sign(digest)

    return sign


def sign_bytes_dsa(byte_array, path_to_private_key_pem_file):
    # Use this method for DSA keys
    key = open(path_to_private_key_pem_file, 'r').read()
    # Import the key
    dsa_key = DSA.importKey(key)

    # Create a digest of nonce + cnonce
    # This only seems to work with SHA1 (SHA256 gives us a 401 error)
    buf = buffer(byte_array)
    digest = SHA1.new(buf).digest()

    # Digitally sign the digest with our private key
    # The corresponding public key is in our admin handle on the server
    k = random.StrongRandom().randint(1, dsa_key.q-1)
    sign = dsa_key.sign(digest, k)

    # Signature bytes from a DSA key need to be DER-encoded
    # This signature is in two parts (r and s)
    seq = DerSequence()
    seq.append(sign[0])
    seq.append(sign[1])

    return seq.encode()


def build_complex_authorization_string(signature_string, type_string, alg, session_id, client_nonce_string, auth_id):
    result = ('Handle ' +
              'version="0", ' +
              'sessionId="' + session_id + '", '
              'cnonce="' + client_nonce_string + '", '
              'id="' + auth_id + '", '
              'type="' + type_string + '", '
              'alg="' + alg + '", '
              'signature="' + signature_string + '"')

    return result


def generate_client_nonce_bytes():
    return bytearray(os.urandom(16))


if __name__ == '__main__':
    main()
