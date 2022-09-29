const _sodium = require('libsodium-wrappers');
const { Node } = require('../node');
const crypto = require('crypto');


(async() => {
    await _sodium.ready;
    const sodium = _sodium;

    var k = sodium.crypto_sign_seed_keypair(crypto.createHash('sha256').update('key3').digest());
    console.log(Buffer.from(k.publicKey).toString('hex'))
    var n = Node(sodium, k);
    n.addNewWSServer(8081);

    // Es wird ein Testsocket erstellt
    const testSocket = n.createNewLocalSocket(crypto.createHash('sha256').update('d').digest('hex'), (error, sockObj) => {
        sockObj.onRecived((data, source, sport) => {
            console.log(data, 'from:', source, sport);
            sockObj.write("hallo welt zurück", source, sport, (r) => {

            });
        });
    });
})();

