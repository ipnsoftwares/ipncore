const { CoinbaseInput, UnspentOutput } = require('./utxos')
const { CoinbaseTransaction } = require('./transaction');
const { targetToBits, PoWBlock } = require('./block');
const BlockcahinDatabase = require('./dbchain');
const { Mempool } = require('./mempool');
const bigInt = require("big-integer");



class Blockchain {
    constructor(genesis_block, coin, chainparms) {
        // Es wird geprüft ob es sich um einen gültigen Genesisblock handelt
        if(genesis_block.prv_block_hash !== '0000000000000000000000000000000000000000000000000000000000000000') {
            console.log('INVLAID_GENESIS_BLOCK', genesis_block);
            return;
        }

        // Die Chainparms werden eingelesen
        this.main_parms = chainparms['$'];

        // Speichert die Parameter ab welche zum Betrieb des Peers benötigt werden
        this.blockchain_db = new BlockcahinDatabase(genesis_block, chainparms['$']);
        this.genesis_block = genesis_block;
        this.chainparms = chainparms;
        this.mempool = new Mempool();
        this.coin = coin;
        this.blocks = [];
        this.db = null;

        // Speichert die Consensus Funktionen sowie Parameter ab
        this.new_candidate_block = this.main_parms.candidate_block_type;

        // Speichert das Aktuelle Target ab
        this.current_target = this.main_parms.target;

        // Speichert den Aktuellen Miner ab
        this.miner = null;
    };

    // Fügt der Kette neue Blöcke hinzu
    async addBlocks(...block) {
        // Es wird geprüft ob die Nonce des Blocks korrekt ist, wenn ja wird der Block abgespeichert
        for await(const block_obj of block){
            // Es wird geprüft ob die Schwierigkeit erfüllt wurde
            if((bigInt(block_obj.workProofHash(), 16) < bigInt(this.current_target, 16)) !== true) {
                console.log('INVALID_BLOCK_NOT_ACCEPTED');
                continue; 
            }

            // Der Block wird der Datenabnk hinzugefügt
            this.blocks.push(block_obj);
            await this.blockchain_db.addBlock(block_obj);
        }
    };

    // Gibt einen Spiziellen Block aus
    getBlock(hight) {
        if(hight === 0) { return this.genesis_block; }
    };

    // Gibt den Letzten Block aus
    getLastBlock() {
        // Es wird geprüft ob der in der Aktuellen Blockliste ein Block vorhanden ist
        let resolved = null;
        if(this.blocks.length === 0) resolved = this.genesis_block;
        else resolved = this.blocks.at(-1);
        return resolved;
    };

    // Gibt den Hash des Ersten Blocks aus
    hashOfFirstBlock() {
        // Der Hash des Genesisblock wird zurückgegeben
        return this.genesis_block.blockHash();
    };

    // Gibt die Mining Vorlage für den Aktuellen Block aus
    getBlockTemplate(reciverPublicKeyHash) {
        // Die Genesis Transaktion für den Empfänger wird erstellt
        let new_input = new CoinbaseInput();
        let new_output = new UnspentOutput(reciverPublicKeyHash, this.coin.current_reward);
        let genesis_coinbase_tx = new CoinbaseTransaction(1, [new_input], [new_output]);

        // Aus dem Target werden die Target Bits abgeleitet
        let target_bits = targetToBits(this.current_target);

        // Der letzte Block wird abgerufen
        let last_block = this.getLastBlock();

        // Es wird ein neuer Candidate Block erstellt
        let new_candidate_block = new this.new_candidate_block(last_block.blockHash(false), [genesis_coinbase_tx.computeHash()], target_bits, this.main_parms.pow_hash_algo, Date.now());

        // Der Block wird zurückgegeben
        return { cblock:new_candidate_block, txns:[genesis_coinbase_tx] };
    };

    // Startet den Mining Vorgang
    startMiner(reciverPublicKeyHash, threads=2, total=null, callback=null) {
        // Es wird geprüft ob bereits ein neuer Miner vorhanden ist
        if(this.miner !== null) return;

        // Es wird ein neuer MultiThread Miner erstellt
        this.miner = new this.main_parms.mt_miner(threads);

        // Speichert alle Blöcke ab
        let current_round = 0;

        // Diese Funktion wird ausgeführt um den Mining Vorgang durchzuführen
        const ___mine = () => {
            // Der Aktuelle Template Block wird abgerufen
            let c_template = this.getBlockTemplate(reciverPublicKeyHash);
            let current_template_block = c_template.cblock;

            // Der Mining vorgang wird gestartet
            this.miner.startMine(this.current_target, current_template_block.blockTemplate(), (error, found_nonce) => {
                // Es wird geprüft ob ein Fehler aufgetreten ist
                if(error !== null) {
                    console.log(error);
                    return;
                }

                // Die Nonce des Blocks wird angepasst
                current_template_block.setNonce(found_nonce);

                // Es wird geprüft ob der Block die Aktuelle Diff erfüllt
                if((bigInt(current_template_block.getCandidateBlockHash(), 16) < bigInt(this.current_target, 16)) !== true) {
                    console.log('INVALID_BLOCK_NOT_ACCEPTED');
                    return; 
                }

                // Die Gefundenen Daten werden angezeigt
                console.log(current_template_block.blockHash(), `0x${current_template_block.target_bits}`, current_template_block.blockHeader());

                // Das Finale Blockobjekt wird erstellt
                let final_block = new PoWBlock(current_template_block.prv_block_hash, c_template.txns, current_template_block.target_bits, current_template_block.hash_algo, current_template_block.timestamp, found_nonce);

                // Es wird geprüft ob es sich um einen gültigen Block handelt
                if(final_block.blockHash() !== current_template_block.blockHash()) {
                    console.log('INVALID_BLOCK_WAS_DROPPED');
                }

                // Es wird eine Runde hochgezählt
                current_round += 1;

                // Der Block wird der Kette Hinzugefügt
                this.addBlocks(final_block).then(() => {
                    // Der nächste Block wird abgeabut
                    if(total !== null) {
                        if(total != current_round) {
                            ___mine();
                        }
                        else {
                            if(callback !== null) callback(null, final_block);
                        }
                    }
                    else {
                        ___mine();
                        if(callback !== null) callback(null, final_block);
                    }
                });
            });
        };

        // Started den Miningvorgang
        ___mine();
    };

    // Wird verwendet um die Blockchain Datenbank zu laden
    loadBlockchainDatabase(file_path, callback) {
        // Die Datenbank wird geladen
        this.blockchain_db.loadDatabase().then((result) => {
            // Der Block wird in die Liste der Aktuellen Blöcke aufgenommen
            this.blocks.push(this.blockchain_db.current_block);

            // Der Vorgang wurde erfolgreich durchgeführt
            callback(result);
        })
        .catch((c) => {
            console.log(c);
            callback(c);
        })
    };

    // Gibt die Aktuelle Blocköhe an
    blockHight() {
        // Die Aktuelle Blockhöhe wird ausgegeben
        return 1 + this.blocks.length;
    };

    // Gibt die Anzahl aller im Moment exestierenden Blöcke an
    getCurrentSupply() {
        // Es wird eine Liste aus den Cacheblöcken sowie den
        let total_list = [this.genesis_block, ...this.blocks];
    };

    // Gibt an, ob das Objekt einsatzbereit ist
    useable() {
        return this.db !== null;
    };
}


// Das Blockchain Objekt wird exportiert
module.exports = {
    Blockchain:Blockchain
}