const { binary_to_base58 } = require('base58-js');
const _sodium = require('libsodium-wrappers');
const crypto = require('crypto');
const cbor = require('cbor');


// Erstellt einen Hash aus einem Dict
const getHashFromDict = (jsonDict) => {
    const ordered = Object.keys(jsonDict).sort().reduce((obj, key) => { obj[key] = jsonDict[key]; return obj; },{});
    const hash = crypto.createHash('sha256').update(cbor.encode(ordered)).digest();
    return hash;
}

// Erstellt eine Zufällige SessionID ab
const createRandomSessionId = () => {
    return binary_to_base58(crypto.randomBytes(14)).toUpperCase();
};

// Speichert alle verfügbaren Verfahren ein
const CRYPTO_ALGO = {
    ed25519:'ed25519',
    secp256k1:'secp256k1',
    frost_ed25519:'frost_ed25519',
};

// Speichert das Sodium Modell ab
let _crypto_sodium_modul = null;

// Initalisiert alle Librarys
const init_crypto = (callback) => {
    if(_crypto_sodium_modul === null) {
        _sodium.ready
        .then((e) => {
            _crypto_sodium_modul = e;
            callback(true);
        });
    }
};

// Erstellt ein Schlüsselpaar aus einem Seed
const crypto_sign_seed_keypair = (crypto_algo, priv_key_bytes) => {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { throw new Error('no_crypto_lib_loaded'); }

    // Das Schlüsselpaar wird erstellt
    switch(crypto_algo) {
        case CRYPTO_ALGO.ed25519:
            var cobj = _crypto_sodium_modul.crypto_sign_seed_keypair(priv_key_bytes);
            return { publicKey:Buffer.from(cobj.publicKey), privateKey:Buffer.from(cobj.privateKey), keyType:CRYPTO_ALGO.ed25519 };
        case CRYPTO_ALGO.secp256k1:
            var cobPub = secp256k1.getPublicKey(priv_key_bytes, true);
            return { publicKey:Buffer.from(cobPub), privateKey:Buffer.from(priv_key_bytes), keyType:CRYPTO_ALGO.secp256k1 };
        case CRYPTO_ALGO.frost_ed25519:
            throw new Error('disabeld');
        default:
            throw new Error('unkown_algo');
    }
};

// Signiert einen Datensatz
const crypto_sign_message = (crypto_algo, message, priv_key_bytes) => {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { throw new Error('no_crypto_lib_loaded'); }

    // Das Schlüsselpaar wird erstellt
    switch(crypto_algo) {
        case CRYPTO_ALGO.ed25519:
            return Buffer.from(_crypto_sodium_modul.crypto_sign_detached(new Uint8Array(message), new Uint8Array(priv_key_bytes)));
        case CRYPTO_ALGO.secp256k1:
            return Buffer.from(secp256k1.signSync(new Uint8Array(message), new Uint8Array(message)));
        default:
            throw new Error('unkown_algo');
    }
}

// Überprüft ob eine Signatur korrekt ist
const crypto_verify_sig = (crypto_algo, message, sig, public_key) => {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { throw new Error('no_crypto_lib_loaded'); }

    // Das Schlüsselpaar wird erstellt
    switch(crypto_algo) {
        case CRYPTO_ALGO.ed25519:
            return _crypto_sodium_modul.crypto_sign_verify_detached(new Uint8Array(sig), new Uint8Array(message), new Uint8Array(public_key));
        case CRYPTO_ALGO.secp256k1:
            return secp256k1.verify(new Uint8Array(sig), new Uint8Array(message), new Uint8Array(public_key));
        default:
            throw new Error('unkown_algo');
    }
}


module.exports = {
    initCrypto:init_crypto,
    getHashFromDict:getHashFromDict,
    createRandomSessionId:createRandomSessionId,
    eccdsa:{
        crypto_algo:CRYPTO_ALGO,
        crypto_sign_seed_keypair:crypto_sign_seed_keypair,
        crypto_sign_message:crypto_sign_message,
        crypto_verify_sig:crypto_verify_sig
    }
}