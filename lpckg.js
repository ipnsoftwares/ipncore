const consensus = require('./consensus');


// Gibt an ob es sich um ein gültiges Layer 1 Paket handelt
function isValidateHelloPackageLayerOne(packageObject) {
    // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
    let _innerFieldsFound = [];
    if(Object.keys(packageObject).length >= 256) _innerFieldsFound.push('to_big_data');
    if(packageObject.hasOwnProperty('pkey') !== true) _innerFieldsFound.push('pkey');
    if(packageObject.hasOwnProperty('protf') !== true) _innerFieldsFound.push('portf');
    if(packageObject.hasOwnProperty('version') !== true) _innerFieldsFound.push('version');
    if(packageObject.hasOwnProperty('sfunctions') !== true) _innerFieldsFound.push('sfunctions');
    if(_innerFieldsFound.length !== 0) { return _innerFieldsFound; }

    // Es wird geprüft ob die Datentypen der Datenfelder korrekt sind

    // Es handelt sich um ein gültiges Paket
    return true;
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


module.exports = {
    createLayerTwoPackage:createLayerTwoPackage,
    verifyLayerThreePackage:verifyLayerThreePackage,
    isValidateHelloPackageLayerOne:isValidateHelloPackageLayerOne
}