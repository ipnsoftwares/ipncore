const consensus = require('./consensus');


// Erzeugt ein nicht signiertes Layer 2 Paket
function createLayerTwoPackage (peerVersion, frame, calgo='ed25519') {
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
    verifyLayerThreePackage:verifyLayerThreePackage
}