const { CoinbaseInput, UnspentOutput } = require('./utxos');
const { SHA3 } = require('sha3');



// Wird für eine Vollständig neue Transaktion verwendet
class CoinbaseTransaction {
    constructor(blockHight, inputs, outputs) {
        this.blockHight = blockHight;
        this.outputs = outputs;
        this.inputs = inputs;
    };

    // Gibt die Transaktion als RAW Bytes aus
    getRawData() {
        // Es werden alle Eingänge abgerufen
        let totalInputHexStringed = '';
        for(const otem of this.inputs) { totalInputHexStringed += otem.getRawData(); }
        const hexed_total_inputs = this.inputs.length.toString(16);
        const total_inputs_hex_len = hexed_total_inputs.toString(16).toUpperCase().padStart(2, 0);

        // Es werden alle ausgänge abgerufen
        let totalRawHexString = '';
        for(const otem of this.outputs) { totalRawHexString += otem.getRawData(); }
        const hexed_total_output = this.outputs.length.toString(16);
        const total_output_hex_len = hexed_total_output.toString(16).toUpperCase().padStart(2, 0);

        // Die Daten werden zusammengeführt
        return`01000000${hexed_total_inputs}${total_inputs_hex_len}${totalInputHexStringed}${hexed_total_output}${total_output_hex_len}${totalRawHexString}`;
    };

    // Erzeugt einen Hash aus der Coinbase Transaktion
    computeHash() {
        const hash = new SHA3(256).update(Buffer.from(this.getRawData(), 'ascii').reverse()).digest('hex');
        return hash;
    };

    // Gibt die Transaktion so aus, dass sie in die Datenbank gechrieben werden kann
    toDbElement() {
        // Die Inputs werden vorbereitet
        let prepared_inputs = [];
        for(const otem of this.inputs) prepared_inputs.push(Buffer.from(otem.getRawData(), 'hex'));

        // Die Outputs werden vorbereitet
        let prepared_outputs = [];
        for(const otem of this.outputs) prepared_outputs.push(Buffer.from(otem.getRawData(), 'hex'));

        // Die Outputs werden vorbereitet
        return {
            0:1,
            1:this.blockHight,
            2:prepared_inputs,
            3:prepared_outputs
        }
    }
}


// Wird verwendet um Transaktionen aus der Datenbank einzuelesen
function readDbTransactionElement(tx_db_element) {
    // Es wird geprüft ob es sich um eine Coinbase Transaktion handelt
    if(tx_db_element[0] === 1) {
        // Die Blockhöhe wird eingelesen
        let nBlock = tx_db_element[1];

        // Die Eingänge werden eingelesen
        transactions_inputs = [];
        for(const tx_input of tx_db_element[2]) {
            if("0000000000000000000000000000000000000000000000000000000000000000ffffffff" === tx_input.toString('hex')) transactions_inputs.push(new CoinbaseInput());
            else {
                console.log('INVALID_INPUT_FOR_COINBASE_TRANSACTION');
                return;
            }
        }

        // Die Ausgänge werden eingelesen
        transactions_outputs = [];
        for(const tx_output of tx_db_element[3]) {
            // Die Länge der Bytes für den Betrag werden ermittelt
            let amount_hex_byte_len = parseInt(tx_output.toString('hex').slice(0, 4), 16);

            // Der Betrag wird ausgelesen
            let readed_amount = parseInt(tx_output.toString('hex').slice(4, amount_hex_byte_len + 4), 16);

            // Die Adresse wird Extrahiert
            let extracted_address = tx_output.toString('hex').slice(amount_hex_byte_len + 4);

            // Der ausgang wird Zusammengebaut
            let rebuilded_output = new UnspentOutput(extracted_address, readed_amount);

            // Die Daten werden der Liste hinzugefügt
            transactions_outputs.push(rebuilded_output);
        }

        // Die Transaktionen werden zusammengebaut
        let rebuilded_cbtx = new CoinbaseTransaction(nBlock, transactions_inputs, transactions_outputs);

        // Die Transaktion wird zurückgegeben
        return rebuilded_cbtx;
    }
    else {
        console.log('Unkown tx element');
        return;
    }
};


// Exportiert die Klassen
module.exports = {
    readDbTransactionElement:readDbTransactionElement,
    CoinbaseTransaction:CoinbaseTransaction 
}