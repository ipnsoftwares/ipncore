const { SHA3 } = require('sha3');


// Wird verwendet um neue Coins zu Generieren
class CoinbaseInput {
    constructor() {}

    // Gibt das Input als RAW Daten aus
    getRawData() {
        return `0000000000000000000000000000000000000000000000000000000000000000ffffffff`
    }
}

// Wird verendet um ein Unspent Output zu übertragen
class TxInput {
    constructor(txId, outputHight) {
        // Die Parameter werden überprüft
        if(typeof blockHight !== 'number' || blockHight < 0);

        // Die Parameter werden abgeseichert
        this.outputHight = outputHight;
        this.txId = txId;
    }

    // Gibt das Input als RAW Daten aus
    getRawData() {
        const fixed_length_hight = this.outputHight.toString(16).toUpperCase().padStart(4, 0);
        return `${this.txId}${fixed_length_hight}`;
    }
}

// Stellt einen nicht Ausgegeben Wert dar
class UnspentOutput {
    constructor(reciver_address, amount) {
        this.reciver_address = reciver_address;
        this.amount = amount;
    }

    // Gibt das Input als RAW Daten aus
    getRawData() {
        const hexed_amount = this.amount.toString(16);
        const amount_len_hex = hexed_amount.length.toString(16).toUpperCase().padStart(4, 0);
        return `${amount_len_hex}${hexed_amount}${this.reciver_address}`;
    }
}

// Die Klassen werden Exportiert
module.exports = {
    UnspentOutput:UnspentOutput,
    CoinbaseInput:CoinbaseInput,
    TxInput:TxInput 
};