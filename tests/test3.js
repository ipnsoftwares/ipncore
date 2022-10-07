const _sodium = require('libsodium-wrappers');
const { init_crypto } = require('../crypto');
const { Node } = require('../node');
const crypto = require('crypto');


(async() => {
    await _sodium.ready;
    const sodium = _sodium;
    init_crypto(() => {
        var k = sodium.crypto_sign_seed_keypair(crypto.createHash('sha256').update('key3').digest());
        var n = Node(sodium, k);
        n.addNewWSServer(8081);

        // Es wird ein Testsocket erstellt
        const testSocket = n.createNewLocalSocket(crypto.createHash('sha256').update('d').digest('hex'), (error, sockObj) => {
            sockObj.onRecived((data, source, sport) => {
                sockObj.write("hallo welt zurück", source, sport, (r) => {

                });
            });
        });
    });
})();

