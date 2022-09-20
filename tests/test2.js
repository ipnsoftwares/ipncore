const _sodium = require('libsodium-wrappers');
const { Node } = require('../node');
const crypto = require('crypto');
const { dprintinfo } = require('../debug');



(async() => {
    await _sodium.ready;
    const sodium = _sodium;

    var destpubk = '4d1363e238850ff3802e6ade30cc91cf8053769536a6ace6b41f7c0143c2a5fc';

    var k = sodium.crypto_sign_seed_keypair(crypto.createHash('sha256').update('key2').digest());
    var r = Node(sodium, k, []);
    console.log(Buffer.from(k.publicKey).toString('hex'))

    // Es wird versucht eine Verbindung mit dem Peer herzustellen
    r.addPeerClientConnection("ws://127.0.0.1:8089", [], () => {
        
    });

    // Es wird eine Verbindung zum 2ten Node aufgebaut
    r.addPeerClientConnection("ws://127.0.0.1:8080", [], () => {
        // Die Route wird im Netzwerk gesucht
        setTimeout(() => {
            r.initAddressRoute(destpubk, (res) => {
                if(!res) {
                    console.log('No route found');
                    return;
                }
                setTimeout(() => {
                    console.log('GO')
                    r.getAddressRawEndPoint(destpubk, (er, o) => { console.log('DONE'); })
                }, 50);
            }, 2);
        }, 2000);
    });
})();

