const crypto = require('crypto');



// Erzeugt einen 256 Bit swiftyHash
function computeSwiftyH(value) {
    // Es wird geprüft ob der Wert vorhanden ist
    if(value === undefined || value === null) {}
    if(typeof value !== 'object') {}
    if(Buffer.isBuffer(value) !== true) {}

    // Die PreImages werden erstellt
    let pre_image = crypto.createHash('sha512').update(value).digest();

    // Es wird ein HMAC erstellt
    let hmac_hash = crypto.createHash('sha384').update(pre_image).digest();

    // Der Finale Hash wird zurückgegeben
    return crypto.createHash('sha256').update(hmac_hash).digest();
};


// Erzeugt einen 256 Bit swifty UltraCrypto Hash
function computeSwiftyXh(value) {
    // Es wird geprüft ob der Wert vorhanden ist
    if(value === undefined || value === null) {}
    if(typeof value !== 'object') {}
    if(Buffer.isBuffer(value) !== true) {}

    // Die PreImages werden erstellt
    let pre_image = crypto.createHash('sha512').update(value).digest().reverse();

    // Es wird ein HMAC erstellt
    let hmac_hash = crypto.createHash('sha384').update(pre_image).digest();

    // Der Finale Hash wird zurückgegeben
    return crypto.createHash('sha256').update(hmac_hash).digest().reverse();
};
