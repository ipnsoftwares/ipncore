//add this script in myWorker.js file
const {parentPort, workerData} = require("worker_threads");
const { sha256dBTC } = require('../../hash_algo');
const bigInt = require("big-integer");



// Speichert den Akuellen Zusatand ab
const current_state = {
    process_data:null
}

// Wird Asynchrone ausgeführt
async function worker() {
    // Speichert alle wichtigen Daten für den Vorgang
    let cnonce = workerData.start, found = false, last_hash = null, cround = 0, reval_hash = null;

    // Wird ausgeführt um einen Hash zu finden
    async function winner() {
        // Es wird geprüft ob ein Prozess vorhanden ist
        if(current_state.process_data !== null) {
            // Es wird versucht einen Block zu Minen
            try{
                let wasRunn = true;
                while(current_state.process_data !== null && cnonce <= workerData.end && found === false && cround < 10000) {
                    // Wandelt die Nonce um
                    var nonce = Buffer.from(cnonce.toString(16).padStart(8, 0), 'hex').reverse().toString('hex');

                    // Fügt die Daten zusammen
                    if(current_state.process_data === null) { console.log('ABORTED'); return; }
                    var merged_data = `${current_state.process_data.block_header}${nonce}`;

                    // Es wird ein Hash aus dem Wert erzeugt
                    reval_hash = sha256dBTC.compute(Buffer.from(merged_data, 'hex'));
                    if(reval_hash === last_hash) {
                        console.log(reval_hash, 'error', cnonce, merged_data);
                        return;
                    }

                    // Der Letze Hash wird gesetzt
                    last_hash = reval_hash;

                    // Es wird geprüft ob es ein gültiger Wer ist
                    if(current_state.process_data === null) { console.log('ABORTED'); return; }
                    if(bigInt(reval_hash, 16) < bigInt(current_state.process_data.target, 16)) {
                        parentPort.postMessage({ cmd:'found_hash', nonce:cnonce });
                        if(current_state.process_data === null) { console.log('ABORTED'); return; }
                        current_state.process_data = null;
                        found = true;
                        return; 
                    }

                    // Die Nonce wird hochgezählt
                    cnonce += 1;
                    cround += 1;
                }

                if(cround === 10000) {
                    wasRunn = false;
                    cround = 0;
                }

                if(wasRunn !== false) {
                    console.log('ABORTED'); return;
                }
            }
            catch(e) {
                console.log(e);
            }
        }
        else {
            console.log('CLEARED');
        }
    }

    // Prüft ob ein Auftrag vorhanden ist, wenn nicht wird der Thread wartend gehalten
    async function checker() {
        if(current_state.process_data !== null) {
            await winner();
        }
        setTimeout(checker);
    }

    // Der Checker wird gestartet
    setTimeout(checker);
}

// Dem Hauptprozess wird mitgeteilt dass der Vorgang erfolgreich war
parentPort.on('message', (data) => {
    if(typeof data === 'object') {
        if(data.cmd === 'start') {
            current_state.process_data = data;
        }
    }
    else if(typeof data === 'string') {
        if(data === 'CLEAR') {
            current_state.process_data = null;
        }
    }
});

// Die Worker Schleife wird gestartet
worker().then(()=>null);

// Es wird Signalisiert das der Thread gestattet wurde
parentPort.postMessage('STARTED');