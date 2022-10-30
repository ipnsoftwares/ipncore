const { CoinbaseTransaction, readDbTransactionElement } = require('./transaction');
const { CoinbaseInput, UnspentOutput } = require('./utxos');
const { computeMerkleRoot } = require('./merkle');
const { Coin } = require('./coin');
const crypto = require('crypto');
const cbor = require('cbor');



// Wandelt ein 32 Bit Integer in Bytes um
const toBytesInt32 = (num) => {
    const arr = new ArrayBuffer(4);
    const view = new DataView(arr);
    view.setUint32(0, num, false);
    return Buffer.from(arr);
};


// Wird verwendet um die Difficulty (das Target) in eine kleine Bit reihenfolge umzuwandeln
function targetToBits(target) {
    // Die Anzahl der Nullen am Ende wird Ermittelt
    let endZeros = 0;
    for(const otem of Buffer.from(target, 'hex').reverse()) {
        if(otem == 0) endZeros +=1; else break;
    }

    // Die 0 am Anfang werden Entfernt
    let clear_target = target.replace(/^0+/, '').split('').reverse().join('').replace(/^0+/, '').split('').reverse().join('').padStart(6, 0);

    // Das Target Bit wird vorbereitet
    let byted_target = Buffer.from(clear_target, 'hex');

    // Die Gesamtlänge des Targets wird ermittelt
    let target_len = byted_target.length + endZeros;
    let target_len_bytes = new Buffer.allocUnsafe(1);
    target_len_bytes.writeUInt8(target_len, 0);

    // Die Daten werden zurückgegeben
    let temp = Buffer.from([...target_len_bytes, ...byted_target]).toString('hex');
    return temp; 
};


// Wird verwendet um einen neuen Proof of Work Block zu erstellen
class CandidatePoWBlock {
    constructor(prv_block_hash, transactions_ids, target_bits, hash_algo, timestamp, nonce=0) {
        this.transactions_ids = transactions_ids;
        this.prv_block_hash = prv_block_hash;
        this.target_bits = target_bits;
        this.timestamp = timestamp;
        this.hash_algo = hash_algo;
        this.nonce = nonce;
    };

    // Setzt die Aktuelle Nonce
    setNonce(cnonce) {
        this.nonce = cnonce;
    };

    // Dreht die Nonce um eins nach oben
    nonceAdd() {
        if(this.nonce +1 >= 2147483647) return false;
        this.nonce += 1;
        return true;
    };

    // Berechnet den MerkleRoot des Blocks
    computeMerkleRoot() {
        // Die Transaktions IDS werden Reverst
        const reversed = [];
        for(const otem of this.transactions_ids) reversed.push(otem)
        const a = computeMerkleRoot(this.hash_algo, reversed.reverse());
        return a;
    };

    // Gibt das Blocktemplate aus
    blockTemplate() {
        // Der neue Block wird erstellt
        const block_version = "01000000";

        // Der Previous Block wird umgewandelt
        let prev_block = Buffer.from(this.prv_block_hash, 'hex').reverse().toString('hex');

        // Die Zeit wird umgewandelt
        let timestamp = toBytesInt32(this.timestamp).reverse().toString('hex');

        // Der Merkelroot wird vorbereitet
        let merkle_root = Buffer.from(this.computeMerkleRoot(), 'hex').reverse().toString('hex');

        // Die Daten des Block Templates werden zurückgegeebn
        return `${block_version}${prev_block}${merkle_root}${timestamp}${this.target_bits}`;
    };

    // Gibt den Vollständigen Blockheader aus
    blockHeader() {
        // Block Template Header
        const blockTemplate_header = this.blockTemplate();

        // Wandelt die Nonce um
        const nonce = Buffer.from(this.nonce.toString(16).padStart(8, 0), 'hex').reverse().toString('hex');

        // Gibt den Vollständig String zurück
        return `${blockTemplate_header}${nonce}`;
    };

    // Gibt den Aktuellen Blockckhash aus
    getCandidateBlockHash() {
        let hash = this.hash_algo.compute(Buffer.from(this.blockHeader(), 'hex'));
        return hash;
    };

    // Gibt den Vollständigen Hash des Blocks aus
    blockHash(withZeroX=true) {
        const final = crypto.createHash('sha256').update(this.getCandidateBlockHash()).digest('hex');
        if(withZeroX === true) return `0x${final}`;
        else return `${final}`;
    };
};


// Fertiger Block
class PoWBlock {
    // Ließt ein Datenbankelement ein
    static loadFromDbElements(prevBlockHash, hash_algo, txElements, headerElements) {
        // Es wird versucht die Headerdaten mittels CBOR einzulesen
        let decoded_headerd = cbor.decode(headerElements);

        // Die headerdaten werden eingelesen
        let block_timestamp = parseInt(decoded_headerd[0].toString('hex'), 16);
        let target_bits = decoded_headerd[1].toString('hex');
        let nonce = parseInt(decoded_headerd[2].toString('hex'), 16);

        // Es wird versucht die Transaktionen mittels CBOR einzulesen
        let decoded_tx_elements = cbor.decode(txElements);

        // Die Transaktionen werden eingelesen
        let parsed_transactions = [];
        for(const tx_item of decoded_tx_elements) parsed_transactions.push(readDbTransactionElement(tx_item));

        // Der Block wird nachgebaut
        return new PoWBlock(prevBlockHash, parsed_transactions, target_bits, hash_algo, block_timestamp, nonce);
    };

    constructor(prv_block_hash, transactions, target_bits, hash_algo, timestamp, nonce) {
        this.prv_block_hash = prv_block_hash;
        this.transactions = transactions;
        this.target_bits = target_bits;
        this.timestamp = timestamp;
        this.hash_algo = hash_algo;
        this.nonce = nonce;
    };

    // Gibt die Target Bits aus
    targetBits() {
        return `0x${this.target_bits}`
    };

    // Berechnet den MerkleRoot des Blocks
    computeMerkleRoot() {
        // Die Transaktions IDS werden Reverst
        const reversed = [];
        for(const otem of this.transactions) reversed.push(otem.computeHash());
        const a = computeMerkleRoot(this.hash_algo, reversed.reverse());
        return a;
    };

    // Gibt den Vollständigen Blockheader aus
    blockHeader() {
        // Der neue Block wird erstellt
        const block_version = "01000000";

        // Der Previous Block wird umgewandelt
        let prev_block = Buffer.from(this.prv_block_hash, 'hex').reverse().toString('hex');

        // Die Zeit wird umgewandelt
        let timestamp = toBytesInt32(this.timestamp).reverse().toString('hex');

        // Der Merkelroot wird vorbereitet
        let merkle_root = Buffer.from(this.computeMerkleRoot(), 'hex').reverse().toString('hex');

        // Block Template Header
        let blockTemplate_header = `${block_version}${prev_block}${merkle_root}${timestamp}${this.target_bits}`;

        // Wandelt die Nonce um
        const nonce = Buffer.from(this.nonce.toString(16).padStart(8, 0), 'hex').reverse().toString('hex');

        // Gibt den Vollständig String zurück
        return `${blockTemplate_header}${nonce}`;
    };

    // Gibt den Hash des Arbeitsnachweises aus
    workProofHash() {
        return this.hash_algo.compute(Buffer.from(this.blockHeader(), 'hex'))
    };

    // Gibt die Anzahl neu Geschaffenen Coins aus
    coinbaseCreatedCoins() {
        return this.transactions[0];
    };

    // Gibt den Vollständigen Hash des Blocks aus
    blockHash(withZeroX=true) {
        const final = crypto.createHash('sha256').update(this.workProofHash()).digest('hex');
        if(withZeroX === true) return `0x${final}`;
        else return `${final}`;
    };

    // Gibt die Transaktionen für die Datenbank aus
    txDbElement() {
        // Die Transaktionen werden abgearbeitet
        let prepared_txns = [];
        for(const otem of this.transactions) prepared_txns.push(otem.toDbElement())

        // Die Daten werden zurückgegeben
        return cbor.encode(prepared_txns);
    };

    // Gibt die Header Daten für die Datenbank aus
    txDbHeaderElement() {
        // Das Objekt wird gebaut
        let build_obj = {
            0:this.timestamp.toString(16),
            1:this.target_bits,
            2:this.nonce.toString(16),
            3:this.computeMerkleRoot()
        };

        // Gibt das erstellt Objekt zurück
        return cbor.encode(build_obj);
    };
};


// Wird verwendet um einen Genesis Mining Block zu erstellen
function mineGenesisPoWBlock(reciver_address, target, coin, hash_algo) {
    // Der Betrag für den Aktuellen Block wird abgerufen
    let current_reward = coin.current_reward;

    // Die Genesis Transaktion für den Empfänger wird erstellt
    let new_input = new CoinbaseInput();
    let new_output = new UnspentOutput(reciver_address, current_reward);
    let genesis_coinbase_tx = new CoinbaseTransaction(0, [new_input], [new_output]);

    // Aus dem Target werden die Target Bits abgeleitet
    const target_bits = targetToBits(target);

    // Der Block wird gebaut
    let new_block = new CandidatePoWBlock('0000000000000000000000000000000000000000000000000000000000000000', [genesis_coinbase_tx.computeHash()], target_bits, hash_algo, Date.now());

    var pow = require('./consensus/pow/consensus');
    const multi_thread_miner = new pow(3);
    multi_thread_miner.startMine(target, new_block.blockTemplate(), (error, found_nonce) => {
        // Es wird geprüft ob ein Fehler aufgetreten ist
        if(error !== null) {
            console.log(error);
            return;
        }

        // Die Nonce des Blocks wird angepasst
        new_block.setNonce(found_nonce);

        // Die Gefundenen Daten werden angezeigt
        console.log('Block timestamp        :', new_block.timestamp);
        console.log('Block proof            :', new_block.getCandidateBlockHash());
        console.log('Block nonce            :', found_nonce);
        console.log('Block target bits      :', new_block.target_bits);
        console.log('Block tempalte         :', new_block.blockTemplate());
        console.log('Block header           :', new_block.blockHeader());
    });
};


// Der Genesisblock wird erzeugt
const test_coin = new Coin(8, "3eecf85c306b5c", 110700, 800);
//mineGenesisPoWBlock('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '00000ffff0000000000000000000000000000000000000000000000000000000', test_coin, sha256dBTC)


// Exportiert die Klassen
module.exports = {
    mineGenesisPoWBlock:mineGenesisPoWBlock,
    CandidatePoWBlock:CandidatePoWBlock,
    targetToBits:targetToBits,
    PoWBlock:PoWBlock 
};