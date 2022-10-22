const _sodium = require('libsodium-wrappers');
const crypto = require('crypto');





(async() => {
    await _sodium.ready;
    const sodium = _sodium;

    const secure_hash = "00000000000000000003eb0af166671faf063bfafe85f89b638838c267db3e3f";

    while(true) {
        const kp = sodium.crypto_sign_keypair();
        const a = Buffer.from(kp.publicKey);
        const h = crypto.createHash('sha256').update(Buffer.from([...a, ...Buffer.from(secure_hash, 'hex')])).digest('hex');
        if(h.startsWith('00') === true) {
            console.log('publickey_pow_proof_hash:', h);
            return;
        }
    }
})();
