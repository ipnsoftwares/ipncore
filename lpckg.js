const consensus = require('./consensus');



// Gibt an ob es sich um ein gültiges Layer 1 Paket handelt
function isValidateHelloPackageLayerOne(packageObject) {
    // Es wird geprüft ob das Paket angegeben wurde
    if(packageObject === undefined || packageObject === null) return false;

    // Es wird geprüft ob es sich um ein Objekt handelt
    if(typeof packageObject !== 'object') return false;

    // Die einzelenen Schlüssels des Objektes werden abgerufen
    const extractedObjectKeys = Object.keys(packageObject);

    // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
    let _innerFieldsFound = [];
    if(extractedObjectKeys.length >= 256) _innerFieldsFound.push('to_big_data');
    if(packageObject.pkey === undefined) _innerFieldsFound.push('pkey');
    if(packageObject.protf === undefined) _innerFieldsFound.push('portf');
    if(packageObject.version === undefined) _innerFieldsFound.push('version');
    if(packageObject.sfunctions === undefined) _innerFieldsFound.push('sfunctions');
    if(_innerFieldsFound.length !== 0) { return false; }

    // Es handelt sich um ein gültiges HelloPackage
    return true;
};

// Gibt an ob es sich um ein gültiges Layer 1 Basispaket besteht
function validateLayerOneBasePackage(packageObj) {

};

// Erzeugt ein nicht signiertes Layer 2 Paket
function createLayerTwoPackage(peerVersion, frame, calgo='ed25519') {
    if(peerVersion < consensus.smallest_version) return null;
    return { crypto_algo:calgo, type:'pstr', version:consensus.version , frame:frame };
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


// Die Module werden Exportiert
module.exports = {
    createLayerTwoPackage:createLayerTwoPackage,
    verifyLayerThreePackage:verifyLayerThreePackage,
    validateLayerOneBasePackage:validateLayerOneBasePackage,
    isValidateHelloPackageLayerOne:isValidateHelloPackageLayerOne
}