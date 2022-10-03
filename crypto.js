const { binary_to_base58 } = require('base58-js');
const _sodium = require('libsodium-wrappers');
const crypto = require('crypto');
const { SHA3 } = require('sha3');
const cbor = require('cbor');



// Speichert das Sodium Modell ab
let _crypto_sodium_modul = null;

// Speichert alle verfügbaren Verfahren ein
const CRYPTO_ALGO = {
    ed25519:'ed25519',
    secp256k1:'secp256k1',
    frost_ed25519:'frost_ed25519',
};

// Erstellt einen Hash aus einem Dict
function getHashFromDict(jsonDict) {
    const ordered = Object.keys(jsonDict).sort().reduce((obj, key) => { obj[key] = jsonDict[key]; return obj; },{});
    const hashx = crypto.createHash('sha256').update(cbor.encode(ordered)).digest();
    const hash = new SHA3(384);
    return hash.digest();
};

// Erstellt eine Zufällige SessionID ab
function createRandomSessionId() {
    return binary_to_base58(crypto.randomBytes(14)).toUpperCase();
};

// Initalisiert alle Librarys
function init_crypto(callback) {
    if(_crypto_sodium_modul === null) {
        _sodium.ready
        .then((e) => {
            _crypto_sodium_modul = e;
            callback(true);
        });
    }
};

// Erstellt ein Schlüsselpaar aus einem Seed
function crypto_sign_seed_keypair(crypto_algo, priv_key_bytes) {
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
function crypto_sign_message(crypto_algo, message, priv_key_bytes) {
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
};

// Überprüft ob eine Signatur korrekt ist
function crypto_verify_sig(crypto_algo, message, sig, public_key) {
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
};

// Entschlüsselt einen Datensatz
function decrypt_data(dataset, callback) {

};

// Verschlüsselt einen Datensatz
function encrypt_data(dataset, callback) {

};

// Wird verwendet um eine Shared Secret zu ersstellen
function compute_shared_secret(privKey, pubKey, callback) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { callback('no_crypto_lib_loaded'); return; }

    // Es wird geprüft ob es sich um einen ED25519 PublicKey handelt
    if(pubKey.length !== 32) { callback('invalid_public_key'); return; }

    // Es wird geprüft ob es sich um einen ED25519 PrivateKey handelt
    if(privKey.length !== 64) { callback('invalid_private_key'); return; }

    // Es wird versucht aus dem Öffentlichen ED25519 Schlüssel einen Curve25519 Schlüssel zu erzeugen
    const curve25519PublicKey = _crypto_sodium_modul.crypto_sign_ed25519_pk_to_curve25519(new Uint8Array(pubKey));

    // Es wird versucht aus dem Privaten ED25519 Schlüssel einen Curve25519 Schlüssel zu erzeugen
    const curve25519PrivateKey = _crypto_sodium_modul.crypto_sign_ed25519_sk_to_curve25519(new Uint8Array(privKey));

    // Aus dem Öffentlichen Curve25519 Schlüssel sowie aus dem Privaten Curve25519 Schlüsel wird eine DH-Schlüssel erzeugt
    const computedDhSecrtKey = _crypto_sodium_modul.crypto_scalarmult(curve25519PrivateKey, curve25519PublicKey);

    // Der Schlüssel wird als Buffer zurückgegeben
    callback(null, Buffer.from(computedDhSecrtKey));
};


module.exports = {
    initCrypto:init_crypto,
    getHashFromDict:getHashFromDict,
    createRandomSessionId:createRandomSessionId,
    compute_shared_secret:compute_shared_secret,
    decrypt_data:decrypt_data,
    encrypt_data:encrypt_data,
    eccdsa:{
        crypto_algo:CRYPTO_ALGO,
        crypto_sign_seed_keypair:crypto_sign_seed_keypair,
        crypto_sign_message:crypto_sign_message,
        crypto_verify_sig:crypto_verify_sig
    }
}