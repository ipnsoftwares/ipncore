const consensus = require('./consensus');


// Erzeugt ein nicht signiertes Layer 2 Paket
const createLayerTwoPackage = (peerVersion, frame, calgo='ed25519') => {
    if(peerVersion < consensus.smallest_version) return null;
    return { crypto_algo:calgo, type:'pstr', version:consensus.version , frame:frame };
};



module.exports = {
    createLayerTwoPackage:createLayerTwoPackage
}