class Mempool {
    constructor() {
        this.tx_pool = new Map();
    }

    // Wird verwendet um eine neue Transaktion in dem Mempool hinzuzufügen
    addTransaction(tx) {

    };

    // Gibt X Transaktionen aus, die Transaktioenen dürfen die Insgesamte Größe von X Byts nicht überschreiten
    getAllUseableTransactions() {

    };
}



module.exports = { Mempool:Mempool };