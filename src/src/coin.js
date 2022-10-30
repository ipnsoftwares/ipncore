var bigInt = require("big-integer");
const { SHA3 } = require('sha3');


// Stellt einnen Coin dar
class Coin {
    constructor(decimal, max, halv_at_block, start_block_reward, genesis_suply=null) {
        this.current_reward = start_block_reward * (bigInt(1) * (bigInt(10)**bigInt(decimal)));
        this.halv_at_block = BigInt(`0x${halv_at_block}`);
        this.decimal = decimal;
        this.max = max;
    };

    // Überprüft ob der Reward für den Block XYZ Korrekt ist
    validate_block_reward(amont, hight) {

    };

    // Set Reward Hight
    halveReward() {
        this.current_reward = Math.floor(this.current_reward / 2)
    };

    // Gibt die Anzahl aller Coins aus
    total_supply(hight=null) {

    };
}


// 1 177,119,999.98782301 Mortys
// 1 Morty = 100.000.000 Jerrys


// Exportiert die Klasse
module.exports = { Coin:Coin }