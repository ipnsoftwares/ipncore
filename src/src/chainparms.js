const { CandidatePoWBlock, PoWBlock } = require('./block');
const { CoinbaseInput, UnspentOutput } = require('./utxos')
const { CoinbaseTransaction } = require('./transaction');
const { Blockchain } = require('./chain');
const { sha256dBTC } = require('./hash_algo');
const { Coin } = require('./coin');



// Erstellt den Genesis Block
function generateGenesisMainnetBlock(bits, timestamp, nonce, hash_algo, reciver, coin) {
    // Der Betrag für den Aktuellen Block wird abgerufen
    let current_reward = coin.current_reward;

    // Die Genesis Transaktion für den Empfänger wird erstellt
    let new_input = new CoinbaseInput();
    let new_output = new UnspentOutput(reciver, current_reward);
    let genesis_coinbase_tx = new CoinbaseTransaction(0, [new_input], [new_output]);

    // Der Block wird gebaut
    let new_block = new CandidatePoWBlock('0000000000000000000000000000000000000000000000000000000000000000', [genesis_coinbase_tx.computeHash()], bits, hash_algo, timestamp, nonce);

    // Das Finale Blockobjekt wird erstellt
    let final_block = new PoWBlock(new_block.prv_block_hash, [genesis_coinbase_tx], bits, hash_algo, timestamp, nonce);

    // Der neue Block wird zurückgegeben
    return final_block;
};

// Erstellt die Rickchain # Hauptnetzwerk
function RickcoinMainnet(callback) {
    // Gibt die Basisparameter der Aktuellen Blockchain an
    let diff_adjust = 0;                                                                                            // Gibt an, aller wieviel Blöcke das Halvening Durchgeführt werden soll
    let block_time_ms = 0;                                                                                          // Gibt die Blockzeit an (3 Minuten) weialnge es im Schnitt dauern soll bist ein neuer Block erstellt wird
    let halvening_period = 0;                                                                                       // Gibt die Anzahl der Blöcke an, wann das Halvening durchgeführt werden soll
    let hash_algo = sha256dBTC;                                                                                     // Gibt den zu verwendeten Mining Algorithmus an
    let rickcoin = new Coin(8, "3eecf85c306b5c", 110700, 800);                                                      // Gibt den Coin an, welcher verwendet werden soll
    let start_pow_target = "00000ffff0000000000000000000000000000000000000000000000000000000";                      // Gibt Startschwierigkeit für das Mining an

    // Gibt die Netzwerkparameter an, welche verwendet werden um Verbindungen mit anderen Node herzustellen
    let transaction_header = "";
    let block_header = "";

    // Gibt die Statischen Parameter, Forks, etc an
    const chainparms = {
        // Speichert allgemeine Parameter ab
        "$":{
            target:start_pow_target,
            diff_adjust:diff_adjust,
            pow_hash_algo:hash_algo,
            block_header:block_header,
            finally_block_tpye:PoWBlock,
            block_time_ms:block_time_ms,
            tx_header:transaction_header,
            halvening_period:halvening_period,
            candidate_block_type:CandidatePoWBlock,
            mt_miner:require('./consensus/pow/consensus'),
        },
    };

    // Der Genesis Block wird gebaut
    let genesis_block = generateGenesisMainnetBlock("1e00ffff", 1666840060139, 716128880, hash_algo, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", rickcoin);

    // Es wird geprüft ob es sich den Zulässigen Block handelt
    if(genesis_block.blockHash() !== '0x61d8f67f6d561df970d11d00e8380717302a3256f02e3bde76ff8ca7de6cf43a') {
        console.log('INVALID_GENESIS_BLOCK');
    }

    // Das Chain Objekt wird start_target
    let chain_object = new Blockchain(genesis_block, rickcoin, chainparms);

    // Das Chain Objekt wird zurückgegeben
    callback(null, chain_object);
};


// Exportiert die einzelenen Funktionen
module.exports = {
    mainnet:RickcoinMainnet
}