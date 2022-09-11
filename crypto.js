const crypto = require('crypto');
const cbor = require('cbor');


// Erstellt einen Hash aus einem Dict
const getHashFromDict = (jsonDict) => {
    const ordered = Object.keys(jsonDict).sort().reduce((obj, key) => { obj[key] = jsonDict[key]; return obj; },{});
    const hash = crypto.createHash('sha256').update(cbor.encode(ordered)).digest();
    return hash;
}

// Wandelt einen HEX-PublicKey in eine Bech32m Adresse um
const convertHexPublicKeyToBech32m = (publicKey) => {
    console.log()
    console.log('XXXXX', Buffer.from(publicKey,))
    console.log()
    return `ipn${Buffer.from(publicKey).toString('hex')}`
};

// Wandelt eine Bech32m Adresse in einen Öffentlichen Schlüssel um
const convertBech32mAddressToPKey = (bech32Address) => {
    return Buffer.from(bech32Address.substring(3), 'hex');
};




module.exports = { getHashFromDict:getHashFromDict, convertHexPublicKeyToBech32m:convertHexPublicKeyToBech32m, convertBech32mAddressToPKey:convertBech32mAddressToPKey }