// Wird als Map für Rouing vorgänge verwedndet
class ProcessRoutingMap {
    constructor() {
        this.session_process_ids = new Map();
        this.session_functions = new Map();
        this.session_pkey_link = new Map();
    };

    // Erstellt einen neuen Vorgang für eine Spizielle Adresse
    async setUpProcess(processId, publicKey, closeEvent, responseEvent) {
        // Es wird geprüft ob der Prozess bereits hinzugefügt wurde
        const arvid = await this.hasOpenProcess(processId);
        if(arvid === true) return false;

        // Es wird geprüft ob der Öffentliche Schlüssel beretis gesucht wird
        const pkvid = await this.hasOpenProcessForAddress(publicKey);
        if(pkvid === undefined) return false;

        // Der neue Vorgang wird hinzugefügt
        this.session_functions.set(processId, { closeEvent:closeEvent, responseEvent:responseEvent });

        // Der Prozess wird dem Öffentlichen Schlüssel zugeordnet
        this.session_pkey_link.set(publicKey, processId);

        // Der Vorgang wurde erfolgreich durchgeführt
        console.log('SET_UP_PROCESS #1', processId);
        return true;
    };

    // Gibt an, ob es einen Offenen Vorgang für diese Adresse gibt
    async hasOpenProcessForAddress(publicKey) {
        const avoid = await this.session_pkey_link.get(publicKey);
        if(avoid === undefined) return false;
        return true;
    };

    // Gibt an ob der Prozess bekannt ist
    async hasOpenProcess(processId) {
        const avoid = await this.session_functions.get(processId);
        if(avoid === undefined) return false;
        return true;
    };

    // Signalisiert dass eine Node Verbindung getretnnt wurde
    async removePeerSession(requestSendPeerSessionId) {
        // Es werden alle Sitzungen durchgearbeitet
        for(const otem of this.session_process_ids.keys()) {
            let preoc = this.session_process_ids.get(otem);
            if(preoc === undefined) continue;
            console.log(preoc)
        }
    };

    // Fügt einen Peer hinzu von welchem ein Request Paket gesendet wurde
    setRequestPeerToProcess(processId, requestSendPeerSessionId) {
        // Es wird geprüft ob der Prozess vorhanden ist
        const atrovid = this.session_functions.get(processId);
        if(atrovid === undefined) return false;

        // Es wird geprüft ob die Sitzung diesem Prozess zugeordnet wurde
        const btrovid = this.session_process_ids.get(requestSendPeerSessionId);
        if(btrovid !== undefined) {
            // Es wird geprüft ob die Sitzung dem Process beretis zugeordnet wurde
            if(btrovid.includes(processId) == true) return false;

            // Der Vorgang wird hinzugefügt
            btrovid.push(processId)
            this.session_process_ids.set(btrovid);
            console.log('OUTPUT_TO_PROC_ADD #1', processId, requestSendPeerSessionId);
        }
        else {
            // Der Vorgang wird vollständig neu Hinzugefügt
            this.session_process_ids.set(requestSendPeerSessionId, [ processId ]);
            console.log('OUTPUT_TO_PROC_ADD #2', processId, requestSendPeerSessionId);
        }

        // Der Vorgang wurde erfolgreich druchgeführt
        return true;
    };

    // Entfernt einen Peer von einem Request Vorgang
    deleteRequestPeerToProcess(processId, requestSendPeerSessionId) {

    };
};



// Die Klassen werden Exportiert
module.exports = {
    ProcessRoutingMap:ProcessRoutingMap
}