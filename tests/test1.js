const _sodium = require('libsodium-wrappers');
const { init_crypto } = require('../crypto');
const { Node } = require('../node');
const crypto = require('crypto');



(async() => {
    await _sodium.ready;
    const sodium = _sodium;

    init_crypto(() => {
        // Der Testseed wird erzeugt
        const plainSeed = crypto.createHash('sha256').update('key1').digest();

        // Das Sodium Schlüsselpaar wird aus dem Seed erstellt
        var k = sodium.crypto_sign_seed_keypair(plainSeed);

        // Die Einstellungen werden erzeugt
        const configs = { key_height:1 };

        var k = sodium.crypto_sign_seed_keypair(plainSeed);

        // Der Node wird erzeugt
        Node(sodium, [], plainSeed, configs, (node) => {
            console.log(Buffer.from(k.publicKey).toString('hex'))
            node.addPeerClientConnection('ws://127.0.0.1:8081')
            node.addPeerClientConnection('ws://127.0.0.1:8089')
            node.addNewWSServer(8080);
        });
    });
})();

