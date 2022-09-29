import cbor2, os, base64

def atrun():
    # Gibt an dass es sich um einen ed25510 Public Key hadelt
    options = 4
    subSignatures = 5
    pubKeyType = 1
    ed25519PubKey = 0
    pubKey = 2
    pubKeySig = 3

    # Das Paket wird fertiggestellt
    body = {
        options:[], subSignatures:[],
        pubKeyType:ed25519PubKey,
        pubKey:os.urandom(32),
        #pubKeySig:os.urandom(64),
    }

    return b"a" + cbor2.encoder.dumps(body)


for i in range(10):
    print(base64.b64encode(atrun()).decode())