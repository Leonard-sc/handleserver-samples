# Python samples

### pubprivkeyauth.py
Shows how to use an RSA or a DSA key to authenticate requests to the handle server - to create, update and delete handles.

In order to use the sample, you must convert your private key to PEM format using the hdl-convert-key tool. This will convert your key to either an RSA or a DSA PEM. The Python code then shows how to hash and sign the server nonce and client nonce with the key.

The code requires the following Python packages:

* pycrypto
* requests

This sample is based on a [sample written by Ben Hadden](http://www.handle.net/mail-archive/handle-info/msg00727.html).

### pubprivkeyauth_sessions.py
Same as above, but demonstrates how to authenticate a session and then use the session id in subsequent requests to the handle server API.
