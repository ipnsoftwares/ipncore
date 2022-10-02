const _sodium = require('libsodium-wrappers');
const { Node } = require('../node');
const crypto = require('crypto');



(async() => {
    await _sodium.ready;
    const sodium = _sodium;
    sodium.crypto_sign_ed25519_pk_to_curve25519()

    var k = sodium.crypto_sign_seed_keypair(crypto.createHash('sha256').update('key1').digest());
    var n = Node(sodium, k);
    console.log(Buffer.from(k.publicKey).toString('hex'))
    n.addPeerClientConnection('ws://127.0.0.1:8081')
    n.addNewWSServer(8080);
})();

