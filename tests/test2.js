const { init_crypto, convert_addr_to_pkey } = require('../crypto');
const _sodium = require('libsodium-wrappers');
const { Node } = require('../node');
const figlet = require('figlet');
const crypto = require('crypto');



(async() => {
    await _sodium.ready;
    const sodium = _sodium;

    // Die Krypto funktionen werden vorbereitet
    init_crypto(() => {
        // Der Testseed wird erzeugt
        const plainSeed = crypto.createHash('sha256').update('key2').digest();

        // Das Sodium Schlüsselpaar wird aus dem Seed erstellt
        var k = sodium.crypto_sign_seed_keypair(plainSeed);

        // Die Einstellungen werden erzeugt
        const configs = { key_height:1 };

        // Das Nodeobjekt wird erzeugt
        Node(sodium, [], plainSeed, configs, (noder) => {
            // Die Primäre Node Adresse wird angezeigt
            console.log(Buffer.from(k.publicKey).toString('hex'))

            // Es wird versucht eine Verbindung mit dem Peer herzustellen
            noder.addPeerClientConnection("ws://127.0.0.1:8089", [], () => {});

            // Es wird eine Verbindung zum 2ten Node aufgebaut
            noder.addPeerClientConnection("ws://127.0.0.1:8080", [], () => {
                // Die Route wird im Netzwerk gesucht
                setTimeout(() => {
                    var destpubk = convert_addr_to_pkey('ipn130gw2g2czyzgc8a2fs82g0kkkngw7u9ygc64ecnqtmengd87exps0w6p39').toString('hex');
                    noder.initAddressRoute(destpubk, (res) => {
                        if(!res) {
                            console.log('No route found');
                            return;
                        }

                        const sock = crypto.createHash('sha256').update('d').digest('hex');
                        console.log('SOCK_CREATION');
                        const testSocket = noder.createNewLocalSocket(sock, (error, sockObj) => {
                            sockObj.onRecived((data, source, sport) => {
                                console.log(data, 'from:', source, sport);
                            });

                            sockObj.write('hallo welt', destpubk, sock, (r) => {
                            });
                        });
                    }, 2);
                }, 2000);
            });
        });
    });
})();