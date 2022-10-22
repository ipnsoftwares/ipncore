const { createSystemSharedMemoryAPI } = require('../src/ipclib');
const { init_crypto } = require('../src/crypto');
const _sodium = require('libsodium-wrappers');
const { Node } = require('../src/node');
const crypto = require('crypto');



(async() => {
    await _sodium.ready;
    const sodium = _sodium;

    // Die Krypto Funktionen werden geladen
    init_crypto(() => {
        // Der Testseed wird erzeugt
        const plainSeed = crypto.createHash('sha256').update('key4').digest();

        // Das Sodium Schlüsselpaar wird aus dem Seed erstellt
        const k = sodium.crypto_sign_seed_keypair(plainSeed);

        // Die Einstellungen werden erzeugt
        const configs = { key_height:1 };

        // Der Node wird gestartet
        Node(sodium, [], plainSeed, configs, (node) => {
            // Die Lokale Adresse wird angezeigt
            console.log(Buffer.from(k.publicKey).toString('hex'))

            // Die Lokale API wird gestartet
            createSystemSharedMemoryAPI(node.api, (error) => {
                // Es wird geprüft ob ein Fehler augetreten ist
                if(error !== null) { console.log(error); return; }

                // Es wird eine neue Server Instanz gestartet
                node.addNewWSServer(8089);

                // Es wird versucht eine Verbindung herzustellen
                node.addPeerClientConnection('ws://127.0.0.1:8081')
            });
        });
    });
})();
