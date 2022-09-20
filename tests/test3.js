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
})();

