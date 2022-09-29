const consensus = require('./consensus');
const { v4: uuidv4 } = require('uuid');
const cbor = require('cbor');
const net = require('net');
const fs = require('fs');



// Bereitet den Shared Memory für die API auf Systemebene vor
const createSystemSharedMemoryAPI = (callback) => {
    // Wird verwendet um den eigentlichen Socket zu starten
    const _SOCKET_INNER = (path) => {
        // Gibt die Socket Funktionen aus
        const socketFunctions = {};

        // Wird verwendet um neue Verbindungen entgegen zu nehmen
        var unixServer = net.createServer(function(client) {
            // Es wird eine ID erstellt, welche
            const current_session_id = uuidv4();

            // Gibt an ob das HelloPackage von der gegenseite Empfangen wurde
            let recivedPackageFromProcess = false;

            // Wird ausgeführt wenn die Verbindung geschlossen wurde
            client.on('close', function() {
                console.log('Connection closed');
            });

            // Wird ausgeführt nachdem ein Paket empfangen wurde
            client.on('data', function(data) {
                console.log('Received: ' + data);
            });

            // Das HelloPackage wird gebaut
            const convertedCborPackage = cbor.encode({
                sid:current_session_id,
                v:consensus.version,
            });

            // Dem Client wird eine SessionID zugewiesen
            client.write(convertedCborPackage, (r) => {
                console.log('SENDET');
            });
        });

        // Der Unixserver wird gelistet
        unixServer.listen(`${consensus.socket_paths.unix_socket_none_root_path}none_root.sock`, (e) => {
            // Der API Socket wurde erfolgreich erstellt
            callback(null, socketFunctions);
        });
    };

    // Es wird geprüft ob es sich um ein Apple System handelt
    if (process.platform == 'darwin') {
        // Es wird geprüft ob der Ordner bereits exestiert
        if (fs.existsSync(consensus.socket_paths.unix_socket_none_root_path)) {
            // Der Socket wird gestartet
            _SOCKET_INNER(consensus.socket_paths.unix_socket_none_root_path);
        }
        else {
            // Das Verzeichniss wird erstellt
            fs.mkdirSync(consensus.socket_paths.unix_socket_none_root_path);

            // Der Socket wird gestartet
            _SOCKET_INNER(consensus.socket_paths.unix_socket_none_root_path);
        }
    }
    // Es wird geprüft ob es sich um ein Windows System handelt
    else if(process.platform == 'win32'){
        console.log("Window OS")
    }
    // Es wird geprüft ob es sich um ein Linux System handelt
    else if(process.platform == 'linux') {
        // Es wird geprüft ob der Ordner bereits exestiert
        if (fs.existsSync(consensus.socket_paths.unix_socket_none_root_path)) {
            // Der Socket wird gestartet
            _SOCKET_INNER(consensus.socket_paths.unix_socket_none_root_path);
        }
        else {
            // Das Verzeichniss wird erstellt
            fs.mkdirSync(consensus.socket_paths.unix_socket_none_root_path);

            // Der Socket wird gestartet
            _SOCKET_INNER(consensus.socket_paths.unix_socket_none_root_path);
        }
    }
    // Es handelt sich um ein unbekanntes System
    else{
        console.log("Other os")
    }
};


// Die Module werden exportiert
module.exports = {
    createSystemSharedMemoryAPI:createSystemSharedMemoryAPI 
};


///// Test
createSystemSharedMemoryAPI((error, callback) => {

});