const { readJsonObjFromBytesSecure } = require('./lpckg');
const { sha256 } = require('@noble/hashes/sha256');
const { binary_to_base58 } = require('base58-js');
const { hkdf } = require('@noble/hashes/hkdf');
const _sodium = require('libsodium-wrappers');
const { bech32 } = require('bech32');
const crypto = require('crypto');
const { SHA3 } = require('sha3');
const cbor = require('cbor');


// Speichert das Sodium Modell ab
let _crypto_sodium_modul = null;

// Erstellt einen Hash aus einem Dict
function get_hash_from_dict(jsonDict) {
    // Die Inahlte des Objektes werden Sortiert
    const ordered = Object.keys(jsonDict).sort().reduce((obj, key) => { obj[key] = jsonDict[key]; return obj; },{});

    // Es wird ein Hash aus dem Sortierten Objekt erstellt
    const hash = new SHA3(384);
    hash.update(cbor.encode(ordered));

    // Das Hash wird zurückgegeben
    return hash.digest();
};

// Erstellt eine Zufällige SessionID ab
function create_random_session_id() {
    return binary_to_base58(crypto.randomBytes(14)).toUpperCase();
};

// Initalisiert alle Librarys
function init_crypto(callback) {
    if(_crypto_sodium_modul === null) {
        _sodium.ready
        .then(() => {
            _crypto_sodium_modul = _sodium;
            callback(true);
        });
    }
};

// Signiert einen Hashwert
function sign_digest(digest, priv_key_bytes) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { throw new Error('no_crypto_lib_loaded'); }

    // Die Signatur wird erstellt
    return Buffer.from(_crypto_sodium_modul.crypto_sign_detached(new Uint8Array(digest), new Uint8Array(priv_key_bytes)));
};

// Überprüft die Signatur eines Hashwertes
function verify_digest_sig(digest, sig, public_key) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { throw new Error('no_crypto_lib_loaded'); }
    return _crypto_sodium_modul.crypto_sign_verify_detached(new Uint8Array(sig), new Uint8Array(digest), new Uint8Array(public_key));
};

// Entschlüsselt einen Datensatz
function decrypt_data(sharedSeecret, chiperText, callback) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { throw new Error('no_crypto_lib_loaded'); }

    // Es wird versucht das Paket mittels CBOR einzulesen
    const readedPackage = cbor.decode(chiperText);

    // Es wird versucht die Daten zu entschlüsseln
    const decrypted = Buffer.from(_crypto_sodium_modul.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(null, readedPackage.c, readedPackage.m, null, readedPackage.n, sharedSeecret));
    
    // Die Daten werden zurückgegeben
    callback(null, decrypted);
};

// Verschlüsselt einen Datensatz
function encrypt_data(sharedSeecret, plainPackage, callback) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { throw new Error('no_crypto_lib_loaded'); }

    // Die Zufällige Nocne wird erzeugt
    const randNonce = _crypto_sodium_modul.randombytes_buf(24);

    // Die Daten werden verschlüsselt
    const chiperText = _crypto_sodium_modul.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(plainPackage, null, null, randNonce, sharedSeecret);

    // Die Daten werden zurückgegeben
    callback(null, cbor.encode({ c:chiperText.ciphertext, m:chiperText.mac, n:randNonce }));
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

// Verschlüsselt ein Paket / Frame Asymmetrisch
function encrypt_package_asymmetric(privKey, pubKey, ipnPackage, callback) {
    // Der DH-Schlüssel wird erzeugt
    compute_shared_secret(privKey, pubKey, (error, key) => {
        // Es wird geprüft ob ein Fehler aufgetreten ist
        if(error !== null) { callback(error); return; }

        // Das Paket wird mittels CBOR in Bytes umgewandelt
        const encodedPackage = cbor.encode(ipnPackage);

        // Der Datensatz wird Verschlüsselt und zurückgegeben
        encrypt_data(key, encodedPackage, callback);
    });
};

// Verschlüsselt ein Paket / Frame Symetrich
function encrypt_package_symmetric(sharedSeecret, ipnPackage, callback) {
    // Das Paket wird mittels CBOR in Bytes umgewandelt
    const encodedPackage = cbor.encode(ipnPackage);

    // Der Datensatz wird Verschlüsselt und zurückgegeben
    encrypt_data(sharedSeecret, encodedPackage, callback);
};

// Entschlüsselt ein Paket / Frame Symetrisch
function decrypt_package_symmetric(sharedSeecret, ipnPackage, callback) {
    // Der Datensatz wird entschlüsselt
    decrypt_data(sharedSeecret, ipnPackage, (error, result) => {
        // Es wird geprüft ob ein Fehler aufgetreten ist
        if(error !== null) { callback(error); return; }

        // Es wird versucht das JSON Paket einzulesen
        readJsonObjFromBytesSecure(result, (error, result) => {
            // Es wird geprüft ob die Daten korrekt sind
            if(error !== null) { callback(error); return; }

            // Das Paket wird zurückgegeben
            callback(null, result);
        });
    });
};

// Wird verwendet um ein neues Schlüsselpaar zu erstellen
function generate_ed25519_keypair() {
    return _crypto_sodium_modul.crypto_sign_keypair();
};

// Leitet einen Schlüssel von einem Master Schlüssel ab
function create_deterministic_keypair(masterSeed, path) {
    // Aus dem Pfad wird ein SHA256 Hash erzeugt
    const h1b = sha256.create().update(Uint8Array.from(Buffer.from(path))).digest();

    // Es wird versucht den Schlüssel abzuleiten
    const dervKey = hkdf(sha256, Uint8Array.from(masterSeed), h1b, path, 32);

    // Aus dem Abgeleiteten Schlüssel wird ein Schlüsselpaar erstellt
    const keyPair = _crypto_sodium_modul.crypto_sign_seed_keypair(dervKey);

    // Das Ergebniss wird zurückgegeben
    return keyPair;
};

// Wandelt einen PublicKey in eine Adresse um
function convert_pkey_to_addr(publicKey) {
    let wordedPubKey = bech32.toWords(Buffer.from(publicKey));
    return bech32.encode('ipn', wordedPubKey);
};

// Wandelt eine Adresse in einen PublicKey um
function convert_addr_to_pkey(addressString) {
    let decoded = bech32.decode(addressString);
    let unworded = bech32.fromWords(decoded.words);
    return Buffer.from(unworded);
};

// Verschlüsselt einen Datensatz Anonym
function encrypt_anonymous(bufferData, recipPubKey, callback) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { callback('no_crypto_lib_loaded'); return; }

    // Aus dem Öffentlichen Schlüssel wird Curve25519 Schlüssel erzeugt
    const curve25519PublicKey = _crypto_sodium_modul.crypto_sign_ed25519_pk_to_curve25519(Uint8Array.from(recipPubKey));

    // Der Datensatz wird verschlüsselt
    const cipher = _crypto_sodium_modul.crypto_box_seal(Uint8Array.from(bufferData), curve25519PublicKey);

    // Der Datensatz wird zurückgegeben
    callback(null, Buffer.from(cipher));
};

// Entschlüsselt einen Datensatz Anonym
function decrypt_anonymous(bufferData, recipPrivKey, recipiPubKey, callback) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { callback('no_crypto_lib_loaded'); return; }

    // Aus dem Öffentlichen ED25519 Schlüssel wird ein Curve25519 Schlüssel erstellt
    const curve25519PublicKey = _crypto_sodium_modul.crypto_sign_ed25519_pk_to_curve25519(Uint8Array.from(recipiPubKey));

    // Aus dem Privaten ED25519 Schlüssel wird ein Curve25519 Schlüssel erstellt
    const curve25519PrivateKey = _crypto_sodium_modul.crypto_sign_ed25519_sk_to_curve25519(Uint8Array.from(recipPrivKey));

    // Der Datensatz wird verschlüsselt
    const palin = _crypto_sodium_modul.crypto_box_seal_open(Uint8Array.from(bufferData), curve25519PublicKey, curve25519PrivateKey);

    // Der Datensatz wird zurückgegeben
    callback(null, Buffer.from(palin));
};

// Verschlüsselt ein Paket Anonym
function encrypt_anonymous_package(packageData, recipPubKey, callback) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { callback('no_crypto_lib_loaded'); return; }

    // Das Paket wird mittels CBOR in Bytes umgewandelt und dann verschlüsselt
    encrypt_anonymous(cbor.encode(packageData), recipPubKey, (error, result) => callback(error, result));
};

// Entschlüsselt ein Paket Anonym
function decrypt_anonymous_package(chiperText, recipPrivKey, recipiPubKey, callback) {
    // Es wird geprüft ob Sodium Initalisiert wurde
    if(_crypto_sodium_modul === null) { callback('no_crypto_lib_loaded'); return; }

    // Die Daten werden entschlüsselt
    decrypt_anonymous(chiperText, recipPrivKey, recipiPubKey, (error, decrypted) => {
        // Es wird geprüft ob ein Fehler aufgetreten ist
        if(error !== null) { callback(error); return; }

        // Es wird versucht das Paket einzulesen
        readJsonObjFromBytesSecure(decrypted, (error, result) => {
            // Es wird geprüft ob ein Fehler aufgetreten ist
            if(error !== null) { callback(error); return; }

            // Das Ergebnis wird zurückgegeeben
            callback(null, result);
        });
    });
};


// Die Funktionen werden exportiert
module.exports = {
    create_deterministic_keypair:create_deterministic_keypair,
    encrypt_package_asymmetric:encrypt_package_asymmetric,
    decrypt_package_symmetric:decrypt_package_symmetric,
    encrypt_anonymous_package:encrypt_anonymous_package,
    encrypt_package_symmetric:encrypt_package_symmetric,
    decrypt_anonymous_package:decrypt_anonymous_package,
    create_random_session_id:create_random_session_id,
    generate_ed25519_keypair:generate_ed25519_keypair,
    compute_shared_secret:compute_shared_secret,
    convert_pkey_to_addr:convert_pkey_to_addr,
    convert_addr_to_pkey:convert_addr_to_pkey,
    get_hash_from_dict:get_hash_from_dict,
    verify_digest_sig:verify_digest_sig,
    encrypt_anonymous:encrypt_anonymous,
    decrypt_anonymous:decrypt_anonymous,
    decrypt_data:decrypt_data,
    encrypt_data:encrypt_data,
    sign_digest:sign_digest,
    init_crypto:init_crypto,
}
