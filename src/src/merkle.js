// Erstellt einen Merkle Root
const computeMerkleRoot = (hashAlgo, txids) => {
    // Speichert die Ergebnisse ab
    let result = [];

    // Der Vorgang wird durchgeführt
    while (txids.length > 0) {
        let one = txids.pop();

        if(txids.length != 0) {
            let two = txids.pop();
            var ent_data = [Buffer.from(one, 'hex').reverse().toString('hex'), Buffer.from(two, 'hex').reverse().toString('hex')].join(''); 
        }
        else {
            var ent_data = [Buffer.from(one, 'hex').reverse().toString('hex'), Buffer.from(one, 'hex').reverse().toString('hex')].join(''); 
        }

        result.push(hashAlgo.compute(Buffer.from(ent_data, 'hex')));
        if(txids.length === 0) break
    }

    // Es wird geprüft ob nurnoch ein Eintrag auf der Liste liegt
    if(result.length === 1) return result[0]

    // Der Vorgang wird wiederholt
    console.log(result.reverse())
    return computeMerkleRoot(hashAlgo, result.reverse());
}


// Exportiert die Klasse
module.exports = {
    computeMerkleRoot:computeMerkleRoot 
};