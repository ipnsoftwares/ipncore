const consensus = require('./consensus');
const { v4 } = require('uuid');
const cbor = require('cbor');
const net = require('net');
const fs = require('fs');



// Wird verwendet um alle Node Verbindungen abzurufen
function fetchAllKnownAddressRoutes(nodeObj, client, pid, callback) {
    // Das Basispaket wird gebaut
    const basePackage = { pid:pid };

    // Wird als Interrupt Funktion ausgeführt
    var interrupt = null;

    // Wird verwendet um zu bestätigten dass das Paket von der gegenseite Empfangen wurde
    const interruptPackage = () => interrupt();

    // Es werden alle Verbindungen abgerufen
    nodeObj.getAllKnownAddressRoutes(false, (r) => {
        // Der Gegenseite wird mitgeteilt wieviele Pakete als nächstes eintreffen werden
        if(r.length === 0) {
            client.write(cbor.encode({ ...basePackage, total:r.length }), (r) => {
                callback(true);
                return;
            });
            return;
        }

        let cItem = 0;

        // Wird verwendet um das einzelne Paket zu versenden
        const _sendfnc = () => {
            if(r.length === 0) {
                callback(true);
                return;
            }

            // Der Aktuelle Eintrag wird abgerufen
            const currentValue = r.pop();

            // Das Paket wird versendet
            interrupt = _sendfnc;
            const atra = { ...basePackage, item:cItem, value:currentValue };
            client.write(cbor.encode(atra), (r) => { cItem += 1; });
        };

        // Der Gegenseite wird mitgeteilt wieiviele Verbindungen verfügbar sind
        interrupt = _sendfnc;
        client.write(cbor.encode({ ...basePackage, total:r.length }), (r) => {});
    });

    // Die Interrupt Funktion wird zurückgegeben
    return interruptPackage;
};

// Wird verwendet um alle Node Verbindungen abzurufen
function fetchAllNodeConnections(nodeObj, client, pid, callback) {
    // Das Basispaket wird gebaut
    const basePackage = { pid:pid };

    // Wird als Interrupt Funktion ausgeführt
    var interrupt = null;

    // Wird verwendet um zu bestätigten dass das Paket von der gegenseite Empfangen wurde
    const interruptPackage = () => interrupt();

    // Speichert das Aktuelle Paket ab
    let currentPackage = 0;

    // Es werden alle Verbindungen abgerufen
    nodeObj.getAllConnections(false, (r) => {
        // Der Gegenseite wird mitgeteilt wieviele Pakete als nächstes eintreffen werden
        if(r.length === 0) {
            client.write(cbor.encode({ ...basePackage, total:r.length }), (r) => {
                callback(true);
                return;
            });
            return;
        }

        // Wird verwendet um das einzelne Paket zu versenden
        const _sendfnc = () => {
            if(r.length === 0) {
                callback(true);
                return;
            }

            // Der Aktuelle Eintrag wird abgerufen
            const currentValue = r.pop();

            // Das Paket wird versendet
            interrupt = _sendfnc;
            client.write(cbor.encode({ ...basePackage, item:currentPackage, value:currentValue }), (r) => { currentPackage += 1; });
        };

        // Der Gegenseite wird mitgeteilt wieiviele Verbindungen verfügbar sind
        interrupt = _sendfnc;
        client.write(cbor.encode({ ...basePackage, total:r.length }), (r) => { });
    });

    // Die Interrupt Funktion wird zurückgegeben
    return interruptPackage;
};

// Wird als Verbindungssocket zwischen 2 Verbindungen verwendet
function initRequestConnection(nodeObj, client) {
    // Speichert die ProcessID ab
    const openProcessId = v4();

    // Speicher die Zustände der Verbindung ab
    let isInited = false, hasHelloPackageFromProcessRecived = false, helloPackageSend = false;

    // Speichert die Enterrup Funktion ab
    let currentEnterruptFunction = null;

    // Nimt eintreffende Pakete entgegen
    const enterIncommingPackages = (decodedPackage) => {
        // Es wird geprüft ob ein Typ angegeben wurde
        if(decodedPackage.type === undefined) {
            console.log('INVALID_PACKAGE');
            client.destroy();
            return;
        }

        // Es wird geprüft ob es sich um ein Request Paket handelt # Get all node peers
        if(decodedPackage.type === 'start_request' && decodedPackage.request === 'get_all_node_peers' && currentEnterruptFunction === null) {
            currentEnterruptFunction = fetchAllNodeConnections(nodeObj, client, openProcessId, (r) => {
                client.destroy();
            });
        }
        // Es wird geprüft ob es sich um ein Request handelt # 
        else if(decodedPackage.type === 'start_request' && decodedPackage.request === 'get_all_known_routes' && currentEnterruptFunction === null) {
            currentEnterruptFunction = fetchAllKnownAddressRoutes(nodeObj, client, openProcessId, (r) => {
                client.destroy();
            });
        }
        // Es wird geprüft ob es sich um ein bestätigungspaket handelt
        else if(decodedPackage.type === 'response') {
            if(currentEnterruptFunction !== null) {
                currentEnterruptFunction();
            }
        }
        else {
            console.log(decodedPackage)
        }
    };

    // Wird verwendet um die Verbindung zu Initaliseiren
    const initConnections = (decodedPackage) => {
        // Es wird geprüft ob das Hello Package bereits gesendet wurde
        if(helloPackageSend !== true) { client.destroy(); return; }

        // Es wird geprüft ob die Prozess ID übereinstimmt
        if(decodedPackage.pid !== openProcessId) {
            console.log('DROPED');
            return;
        }

        // Das Done Paket wird versendet
        client.write(Buffer.from('d', 'ascii'), (error) => { 
            hasHelloPackageFromProcessRecived = decodedPackage;
            isInited = true;
        });
    };

    // Nimmt eintreffende Pakete entgegen
    client.on('data', (data) => {
        // Es wird geprüft ob die Verbindung bereits Initalisiert wurde
        if(isInited === true && hasHelloPackageFromProcessRecived !== false) {
            try{ enterIncommingPackages(cbor.decode(data)); }
            catch(E) { console.log(E); client.destroy(); return; }
        }
        else {
            try{ initConnections(cbor.decode(data)); }
            catch(E) { console.log(E); client.destroy(); return; }
        }
    });

    // Das Hello Package wird an die Verbindung gesendet
    client.write(cbor.encode({ version:consensus.version, lang:"js", root:false, pid:openProcessId }), (error) => {
        helloPackageSend = true;
    });
};

// Bereitet den Shared Memory für die API auf Systemebene vor
const createSystemSharedMemoryAPI = (nodeObj, callback) => {
    // Wird verwendet um den eigentlichen Socket zu starten
    const _SOCKET_INNER = (requestSocketPath, socketIoPath) => {
        // Gibt die Socket Funktionen aus
        const socketFunctions = {};

        // Wird für Request Anfragen verwendet
        var requestSocket = net.createServer((client) => {
            initRequestConnection(nodeObj, client);
        });

        // Wird für Sockets verwendet
        var socketIoSocket = net.createServer((client) => {

        });

        // Der UnixSocket für die Request Anfragen wird erstellt
        requestSocket.listen(requestSocketPath, (e) => {
            socketIoSocket.listen(socketIoPath, (x) => {
                callback(null, socketFunctions);
            })
        });
    };

    // Es wird geprüft ob es sich um ein Apple System handelt
    if (process.platform == 'darwin') {
        // Es wird geprüft ob der Ordner bereits exestiert
        if (fs.existsSync(consensus.socket_paths.unix_socket_none_root_path)) {
            // Der Socket wird gestartet
            _SOCKET_INNER(`${consensus.socket_paths.unix_socket_none_root_path}none_root.sock`, `${consensus.socket_paths.unix_socket_none_root_path}none_root_sock_io.sock`);
        }
        else {
            // Das Verzeichniss wird erstellt
            fs.mkdirSync(consensus.socket_paths.unix_socket_none_root_path);

            // Der Socket wird gestartet
            _SOCKET_INNER(`${consensus.socket_paths.unix_socket_none_root_path}none_root.sock`, `${consensus.socket_paths.unix_socket_none_root_path}none_root_sock_io.sock`);
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

