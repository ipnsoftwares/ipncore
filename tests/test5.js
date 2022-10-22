const { createSystemSharedMemoryAPI } = require('../ipclib');
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
        const plainSeed = crypto.createHash('sha256').update(Buffer.from('key5')).digest();

        // Das Sodium Schlüsselpaar wird aus dem Seed erstellt
        const k = sodium.crypto_sign_seed_keypair(plainSeed);

        // Die Einstellungen werden erzeugt
        const configs = { key_height:1 };

        // Der Node wird gestartet
        Node(sodium, [], plainSeed, configs, (node) => {
            // Die Lokale Adresse wird angezeigt
            console.log(Buffer.from(k.publicKey).toString('hex'))

            // Es wird eine neue Server Instanz gestartet
            node.addNewWSServer(8089);
        });
    });
})();
