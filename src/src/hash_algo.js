const crypto = require('crypto');


// Wird verwendet um Bitcoin Blöcke zu erstelllen
function sha256dBTC(byteValue) {
    const shaUnit = crypto.createHash('sha256').update(byteValue);
    return crypto.createHash('sha256').update(shaUnit.digest()).digest().reverse().toString('hex');
};


// Die Module werden exportiert
module.exports = {
    sha256dBTC:{ "name":"sha256d_bitcoin", compute:sha256dBTC }
}