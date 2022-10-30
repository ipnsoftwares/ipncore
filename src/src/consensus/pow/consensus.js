const { Worker } = require('worker_threads');


// Proof of Work Consensus Object
class ProofOfWorkConsensus {
    constructor(threads, miner_algo) {
        this.miner_algo = miner_algo;
        this.running_workers = [];
        this.threads = threads;
        this.has_proc = false;
    };

    // Signalisiert allen Workern dass sie die Arbeit einstellen können
    clearCurrentProcess() {
        for(const oft of this.running_workers) { oft.postMessage('CLEAR'); }
    };

    // Signalisiert den Miner Threads dass sie mit einer neuen Arbeit beginnen sollen
    signalNewBlock(target, block_header) {
        for(const worker of this.running_workers) { worker.postMessage({ cmd:'start', block_header:block_header, target:target }); }
    };

    // Startet den Mining vorgang
    startMine(target, block_header, callback) {
        // Die Ranges werden ermittelt
        let max_value = 2147483647 - 1;
        let totaled = Math.floor(max_value/ this.threads);
        let start = 0, end = totaled, found = false;

        // Die Miner Threads werden gestartet
        for (let i = 0; i < this.threads; i++) {
            // Der Worker wird gestartet
            let pushData = { start:start, end:end, i:i};

            const worker = new Worker('./src/consensus/pow/btc_sha256d_miner.js', { workerData:pushData });
            worker.on('message', (resolve) => {
                if(typeof resolve === 'string') {
                    if(resolve === 'STARTED') {
                        worker.postMessage({ cmd:'start', block_header:block_header, target:target })
                    }
                }
                else {
                    if(resolve.cmd === 'found_hash') {
                        if(found !== true) {
                            // Die gefundenene Nonce wird zurückgegeben
                            callback(null, resolve.nonce);

                            // Den Arbeitern wird Signalisiert dass sie die Arbeit einstellen können
                            this.clearCurrentProcess();
                            found = true;
                        }
                    }
                }
            });
            worker.on('error', (reject) => {
                console.log(reject);
            });

            // Der Worker wird Registriert
            this.running_workers.push(worker);

            if(this.has_proc === false) {
                this.has_proc = true;
            }

            // Die Werte werden nach oben gezählt
            start += totaled;
            if(i=== 0) start += 1
            end += totaled;
        }
    };
}


// Die Minig Klasse wird Exportiert
module.exports = ProofOfWorkConsensus;