// Wird als Map für Rouing vorgänge verwedndet
class ProcessRoutingMap {
    constructor() {
        this.session_process_recive_ids = new Map();
        this.session_process_send_ids = new Map();
        this.process_setup_timestamp = new Map();
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

        // Die Aktuelle Zeit wird abgespeichert
        this.process_setup_timestamp.set(processId, Date.now());

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
        for(const otem of this.session_process_send_ids.keys()) {
            let preoc = this.session_process_send_ids.get(otem);
            if(preoc === undefined) continue;
            console.log(preoc)
        }
    };

    // Es werden alle Sitzungen eines Prozesses abgerufen von welchen ein Paket empfangen wurde
    getAllInputSessionForProcess(processId) {
        // Es wird geprüft ob der Prozess vorhanden ist
        const atrovid = this.session_functions.get(processId);
        if(atrovid === undefined) return false;

        // Es werden alle Verbindungen herausgefiltert
        const filtered_connections = [];
        for(const otem of this.session_process_recive_ids.keys()) {
            // Die Daten werden abgerufen
            const item = this.session_process_recive_ids.get(otem);
            if(item === undefined) continue;

            // Es wird geprüft ob die SessionId vorhanden ist
            if(item.includes(processId) === true) {
                if(filtered_connections.includes(otem) === false) filtered_connections.push(otem);
            }
        }

        // Die Daten werden zurückgegeben
        return filtered_connections;
    };

    // Es werden alle Sitzungen eines Prozesses abgerufen an welche ein Paket gesendet wurde
    getAllOutputSessionForProcess(processId) {
        // Es wird geprüft ob der Prozess vorhanden ist
        const atrovid = this.session_functions.get(processId);
        if(atrovid === undefined) return false;

        // Es werden alle Verbindungen herausgefiltert
        const filtered_connections = [];
        for(const otem of this.session_process_send_ids.keys()) {
            // Die Daten werden abgerufen
            const item = this.session_process_send_ids.get(otem);
            if(item === undefined) continue;

            // Es wird geprüft ob die SessionId vorhanden ist
            if(item.includes(processId) === true) {
                if(filtered_connections.includes(otem) === false) filtered_connections.push(otem);
            }
        }

        // Die Daten werden zurückgegeben
        return filtered_connections;
    };

    // Fügt einen Peer hinzu von welchem ein Request Paket gesendet wurde
    setRequestPeerToProcess(processId, requestSendPeerSessionId, sendOrRecived='send') {
        // Es wird geprüft ob der Prozess vorhanden ist
        const atrovid = this.session_functions.get(processId);
        if(atrovid === undefined) return false;

        // Es wird geprüft ob es sich um einen Sendevorgang handelt
        if(sendOrRecived === 'send') {
            // Es wird geprüft ob die Sitzung diesem Prozess zugeordnet wurde
            const btrovid = this.session_process_send_ids.get(requestSendPeerSessionId);
            if(btrovid !== undefined) {
                // Es wird geprüft ob die Sitzung dem Process beretis zugeordnet wurde
                if(btrovid.includes(processId) == true) return false;

                // Der Vorgang wird hinzugefügt
                btrovid.push(processId)
                this.session_process_send_ids.set(btrovid);
                console.log('OUTPUT_TO_PROC_ADD #1', processId, requestSendPeerSessionId);
            }
            else {
                // Der Vorgang wird vollständig neu Hinzugefügt
                this.session_process_send_ids.set(requestSendPeerSessionId, [ processId ]);
                console.log('OUTPUT_TO_PROC_ADD #2', processId, requestSendPeerSessionId);
            }
        }
        else{
            // Es wird geprüft ob es sich um einen Sendevorgang handelt
            if(sendOrRecived !== 'recived') { return false; }

            // Es wird geprüft ob die Sitzung diesem Prozess zugeordnet wurde
            const btrovid = this.session_process_recive_ids.get(requestSendPeerSessionId);
            if(btrovid !== undefined) {
                // Es wird geprüft ob die Sitzung dem Process beretis zugeordnet wurde
                if(btrovid.includes(processId) == true) return false;

                // Der Vorgang wird hinzugefügt
                btrovid.push(processId)
                this.session_process_recive_ids.set(btrovid);
                console.log('INPUT_TO_PROC_ADD #1', processId, requestSendPeerSessionId);
            }
            else {
                // Der Vorgang wird vollständig neu Hinzugefügt
                this.session_process_recive_ids.set(requestSendPeerSessionId, [ processId ]);
                console.log('INPUT_TO_PROC_ADD #2', processId, requestSendPeerSessionId);
            }
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