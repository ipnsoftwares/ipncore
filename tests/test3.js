const _sodium = require('libsodium-wrappers');
const { init_crypto } = require('../crypto');
const { Node } = require('../node');
const crypto = require('crypto');


(async() => {
    await _sodium.ready;
    const sodium = _sodium;
    init_crypto(() => {
        // Der Testseed wird erzeugt
        const plainSeed = crypto.createHash('sha256').update('key3').digest();

        // Das Sodium Schlüsselpaar wird aus dem Seed erstellt
        var k = sodium.crypto_sign_seed_keypair(plainSeed);

        // Die Einstellungen werden erzeugt
        const configs = { key_height:1 };

        // Der Node wird gestartet
        Node(sodium, [], plainSeed, configs, (node) => {
            node.addNewWSServer(8081);

            // Es wird ein Testsocket erstellt
            const testSocket = node.createNewLocalSocket(crypto.createHash('sha256').update('d').digest('hex'), (error, sockObj) => {
                sockObj.onRecived((data, source, sport) => {
                    sockObj.write("hallo welt zurück", source, sport, (r) => {

                    });
                });
            });
        });
    });
})();

