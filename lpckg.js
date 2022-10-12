const consensus = require('./consensus');
const cbor = require('cbor');



// Versucht Bytes in ein Paket / Frame umzuwandeln
function readJsonObjFromBytesSecure(byteObj, callback) {
    // Es wird geprüft ob die Datentypen korrekt sind
    if(Buffer.isBuffer(byteObj) === false) { callback('IO_READING_ERROR:A'); return; }

    // Es wird geprüft ob die Callabale Funktion vorhanden ist
    if(callback === undefined || callback === null) { console.log('readJsonObjFromBytesSecure::ABORTED_NO_CALLBACK'); return; }

    // Es wird geprüft ob die Größe des Paketes mindestens 1 Byte beträgt
    if(byteObj.length < 1) { callback('IO_READING_ERROR'); return; }

    // Die Daten werden sicher Verarbeitet
    try { 
        // Das Paket wird eingelesen
        const enc = cbor.decode(byteObj);

        // Es wird geprüft ob mindestens 1 Wert vorhanden ist
        if(Object.keys(enc).length === 0) { callback('IO_READING_ERROR:INVALID_DATA'); return; }

        // Das eingelesene Paket wird eingelesen
        callback(null, enc); 
    }
    catch(error) { 
        callback(`IO_READING_ERROR:${error}`);
    }
};

// Gibt an ob es sich um ein gültiges Layer 1 Paket handelt
function isValidateHelloPackageLayerOne(packageObject) {
    // Es wird geprüft ob das Baispaket korrekt ist
    if(validateLayerOneBasePackage(packageObject) !== true) return false;

    // Speichert alle gültigen Felder ab
    const allowedFields = ['pkey', 'protf', 'version', 'sfunctions', 'type', 'locport', 'sig'];

    // Es wird geprüft ob alle gültigen Feder vorhanden sind
    for(const otem of Object.keys(packageObject)) { if(allowedFields.includes(otem) === false) { return false; } }
    for(const otem of allowedFields) { if(Object.keys(packageObject).includes(otem) === false) { return false; } }

    // Es wird geprüft ob es sich um ein Register Node Package handelt
    if(packageObject.type !== 'regnde') return false;

    // Es wird geprüft ob die Datentypen der einzelnenen Angaben korrekt sind
    if(Buffer.isBuffer(packageObject.pkey) !== true) return false;
    if(packageObject.pkey.length !== 32) return false;

    // Es wird geprüft ob es sich bei den Funktionen um ein Array handelt
    if(Array.isArray(packageObject.protf) !== true) return false;

    // Es wird geprüft ob es sich um gültige Einträge handelt
    for(const otem of packageObject.protf) { if(typeof otem !== 'string') return false; }

    // Es handelt sich um ein gültiges HelloPackage
    return true;
};

// Gibt an ob es sich um ein gültiges Layer 1 Basispaket besteht
function validateLayerOneBasePackage(packageObj) {
    // Es wird geprüft ob es sich um ein Objekt handelt
    if(typeof packageObj !== 'object') return false;

    // Es wird geprüft ob die Daten korrekt sin
    if(packageObj.sig === undefined) return false;

    // Es wird geprüft ob eine Version vorhanden ist
    if(packageObj.version === undefined) return false;

    // Es wird geprüft ob ein Typ vorhanden ist
    if(packageObj.type === undefined) return false;

    // Es wird geprüft ob es sich bei der Signatur um ein 64 Byte Buffer handelt
    if(Buffer.isBuffer(packageObj.sig) !== true) return false;

    // Es wird geprüft ob es sich bei der Version um einen Integer handelt
    if(Number.isInteger(packageObj.version) !== true) return false;

    // Es wird geprüft ob es sich bei dem Typen um einen String handelt
    if(typeof packageObj.type !== 'string') return false;

    // Es werden alle Weiteren Felder geprüft, ingesamt dürfen es nur 32 Einträge sein

    // Es handelt sich um ein korrektes Basispaket
    return true;
};

// Erzeugt ein nicht signiertes Layer 2 Paket
function createLayerTwoPackage(peerVersion, frame, calgo='ed25519') {
    if(peerVersion < consensus.smallest_version) return null;
    return { type:'pstr', version:consensus.version , frame:frame };
};

// Gibt an ob es sich um ein Layer 3 Paket handelt
function verifyLayerThreePackage(packageData, extraAllowed=[]) {
    if(packageData.hasOwnProperty('type') === false) return false;
    if(packageData.type !== 'nxt' && packageData.type !== 'str' && packageData.type === 'dtgr' && packageData.type === 'rwp') {
        if(extraAllowed.includes(packageData.type) === false) return false
    }
    if(packageData.hasOwnProperty('body') === false) return false;
    if(packageData.body.hasOwnProperty('sport') === false) return false;
    if(packageData.body.hasOwnProperty('dport') === false) return false;
    if(packageData.body.hasOwnProperty('data') === false) return false;
    return true;
};

// Wird verwendet um die Basis eines Layer 2 Paketes zu prüfen
function verifyFirstSecondLayerPackageBase(packageObject) {
    // Es wird geprüft ob das Baispaket korrekt ist
    if(validateLayerOneBasePackage(packageObject) !== true) return false;

    // Speichert alle gültigen Felder ab
    const allowedFields = ['frame', 'sig', 'version', 'type'], allowedFrameFields = ['destination', 'source', 'ssig', 'body'];

    // Es wird geprüft ob alle gültigen Feder vorhanden sind
    for(const otem of Object.keys(packageObject)) { if(allowedFields.includes(otem) === false) { return false; } }
    for(const otem of allowedFields) { if(Object.keys(packageObject).includes(otem) === false) { return false; } }

    // Es wird geprüft ob es sich bei dem Frame um ein Objekt handelt
    if(typeof packageObject.frame !== 'object') return false;

    // Es werden alle Framefelder überprüft
    for(const otem of Object.keys(packageObject.frame)) { if(allowedFrameFields.includes(otem) === false) { return false; } }
    for(const otem of allowedFrameFields) { if(Object.keys(packageObject.frame).includes(otem) === false) { return false; } }

    // Die Datentypen werden geprüft
    if(typeof packageObject.frame.body !== 'object') return false;
    if(typeof packageObject.frame.source !== 'string') return false;
    if(typeof packageObject.frame.destination !== 'string') return false;
    if(Buffer.isBuffer(packageObject.frame.ssig) !== true) return false;

    // Es wird geprüft ob die Body Daten vorhanden sind
    if(packageObject.frame.body.hasOwnProperty('pbody') !== true) return false;
    if(packageObject.frame.body.hasOwnProperty('ebody') !== true) return false;

    // Es wird geprüft ob es sich bei dem EBody um ein Buffer handelt
    if(Buffer.isBuffer(packageObject.frame.body.ebody) !== true) return false;

    // Es wird geprüft ob die Daten des Plain Boddys korrekt sind
    if(packageObject.frame.body.pbody !== null) {
        if(typeof packageObject.frame.body.pbody !== 'object') return false;
    }

    // Es handelt sich um ein Korrektes Paket
    return true;
};


// Die Module werden Exportiert
module.exports = {
    createLayerTwoPackage:createLayerTwoPackage,
    verifyLayerThreePackage:verifyLayerThreePackage,
    readJsonObjFromBytesSecure:readJsonObjFromBytesSecure,
    validateLayerOneBasePackage:validateLayerOneBasePackage,
    isValidateHelloPackageLayerOne:isValidateHelloPackageLayerOne,
    verifyFirstSecondLayerPackageBase:verifyFirstSecondLayerPackageBase,
}