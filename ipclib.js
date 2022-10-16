const consensus = require('./consensus');
const { v4 } = require('uuid');
const cbor = require('cbor');
const net = require('net');
const fs = require('fs');



// Wird verwendet um ein GET-Request zu Verarbeiten
function processGetRequest(nodeObj, duplexSocketObject, command, procid, callback) {
    // Sendet den eigentlichen Datensatz ab
    const SEND_DATA = (finalResponse) => {
        // Das Paket wird mittels CBOR umgewanldet
        const dataPacakge = cbor.encode(finalResponse);

        // Es wird geprüft ob das Paket die größe von X Bytes überschreitet, wenn ja wird das Paket aufgeteilt
        if(dataPacakge.length >= 4096) {
            // Das Paket wird aufgeteilt
            let arr = [];
            for (let index = 0; index < dataPacakge.length; index += 4096) { arr.push(dataPacakge.subarray(index, index + 4096)); }

            // Wird ausgeführt nachdem bestätigt wurde dass das Paket versendet wurde
            const packageRecivedConfirmation = () => {
                // Es wird geprüft ob noch ein weiteres Paket zum versenden übrig ist
                if(arr.length > 0) {
                    const fetchedObj = arr.pop(0)
                    if(arr.length === 0) duplexSocketObject.write(cbor.encode({ "type":"response", "process_id":procid, "data":fetchedObj, "isframe":true, "final":true, "reman":arr.length }), packageRecivedConfirmation);
                    else duplexSocketObject.write(cbor.encode({ "type":"response", "process_id":procid, "data":fetchedObj, "isframe":true, "final":false, "reman":arr.length }), packageRecivedConfirmation);
                }
                else {
                    console.log('DONE');
                }
            };

            // Das Paket wird im ganzen an die Gegenseite übertragen
            duplexSocketObject.write(cbor.encode({ "type":"response", "process_id":procid, "data":arr.pop(), "isframe":true, "final":false, "reman":arr.length }), packageRecivedConfirmation);
        }
        else {
            // Das Paket wird im ganzen an die Gegenseite übertragen
            duplexSocketObject.write(cbor.encode(finalResponse), () => { });
        }
    };

    // Es wird geprüft ob es sich um ein Zulässigen befehl handelt
    if(command === 'get_all_connected_nodes') {
        // Der Gegenseite wird der Empfang des Paketes bestätigt
        callback();

        // Es werden alle Node Verbindungen abgerufen
        nodeObj.getAllConnections(false, (error, result) => {
            // Die Daten werden zusammengefasst
            const finalResponse = { "type":"response", "process_id":procid, "data":result, "isframe":false, "final":true, "reman":0 }

            // Das Paket wird mittels CBOR umgewandelt und versendet
            SEND_DATA(finalResponse)
        });
    }
    else if(command === 'get_all_known_routes') {
        // Der Gegenseite wird der Empfang des Paketes bestätigt
        callback();

        // Es werden alle Node Verbindungen abgerufen
        nodeObj.getAllKnownAddressRoutes(false, (error, result) => {
            // Die Daten werden zusammengefasst
            const finalResponse = { "type":"response", "process_id":procid, "data":result, "isframe":false, "final":true, "reman":0 }

            // Das Paket wird mittels CBOR umgewandelt und versendet
            SEND_DATA(finalResponse)
        });
    }
    else if(command === 'get_all_local_addresses') {
        // Der Gegenseite wird der Empfang des Paketes bestätigt
        callback();

        // Es werden alle Node Verbindungen abgerufen
        nodeObj.getAllLocalAddresses(false, (error, result) => {
            // Die Daten werden zusammengefasst
            const finalResponse = { "type":"response", "process_id":procid, "data":result, "isframe":false, "final":true, "reman":0 }

            // Das Paket wird mittels CBOR umgewandelt und versendet
            SEND_DATA(finalResponse)
        });
    }
    else if(command === 'get_new_post_process_id') {

    }
    else if(command === 'get_new_socket_id') {

    }
    else {
        // Die Verbindung wird geschlossen, es handelt sich um einen Unbekannten befehl
        console.log('UNKOWN_COMMAND', command);
    }
};

// Wird verwendet um ein POST-Request zu Verarbeiten
function processPostRequest(nodeObj, duplexSocketObject, command, procid, args, callback) {

};

// Wird verwendet um Socket Vorgänge zu Verarbeiten
function processSocket(nodeObj, duplexSocketObject, socketId, data) {

};

// Führt 2 Duplex Verbindungen zusammen
function mergeDuplexSocketConnections(nodeObj, inputSocket, outputSocket, procId) {
    // Speichert die Enterrupt Funktion für das Aktuell gesendete Paket ab
    let currentEnterruptFunction = null;

    // Wird verwendet um ein Paket zu versenden
    const INSIDE_SOCKET_SEND_DATA = (dataPackage, callbackSend) => {
        // Es wird eine While Schleife gestartet, diese wird solange ausgeführt bis das Paket erfolgreich versendet wurde

        // Das Paket wird gesendet
        currentEnterruptFunction = () => {
            currentEnterruptFunction = null;
            callbackSend();
        };

        // Der Datensatz wird gesendet
        inputSocket.write(dataPackage, () => {});
    };

    // Schleißt die Verbindung aufgrund eines Fehlers
    const CLOSE_CONNECTION_THEN_ERROR = () => {

    };

    // Wird als DuplexObjekt verwendet
    const duplexProcSockObject = {
        write:INSIDE_SOCKET_SEND_DATA,
        kill:CLOSE_CONNECTION_THEN_ERROR
    };

    // Nimmt eintreffende Pakete der ausgehenden Verbindung entgegen
    const OUTSOCKET_ENTER_PACKAGE = (data, pckCallback) => {
        // Es wird versucht den Datensatz einzulesen
        const readedData = cbor.decode(data);

        // Es wird geprüft ob das Datenfeld vorhanden ist
        if(readedData.data === undefined) {
            console.log('INVALID_DATA');
            return;
        }

        // Es wird geprüft ob es sich um ein Objekt handelt
        if(typeof readedData.data !== 'object') {
            console.log('INVALID_PACKAGE');
            return;
        }

        // Es wird geprüft ob ein Pakettyp angegeben wurde
        if(readedData.data.type === undefined) {
            console.log('INVALID_PACKAGE');
            return;
        }

        // Es wird geprüft ob es sich um ein GET-Request handelt
        if(readedData.data.type === 'get') {
            // Es wird geprüft ob die Restlichen Datenfelder vorhanden sind
            if(readedData.data.cmd === undefined || readedData.data.process_id === undefined) {
                console.log('INVALID_PACKAGE');
                return;
            }

            // Der Request wird weiterverbeitet
            processGetRequest(nodeObj, duplexProcSockObject, readedData.data.cmd, readedData.data.process_id, () => { pckCallback(); });
        }
        // Es wird geprüft ob es sich um ein POST-Request handelt
        else if(readedData.data.type === 'post') {

        }
        // Es wird geprüft ob es sich um ein Socket Vorgang handelt
        else if(readedData.data.type === 'socket') {

        }
        // Es handelt sich um ein Unbeaknnten Modus
        else {
            console.log('UNKOWN_DATA_TYPE');
        }
    };

    // Wird als Objekt für das DuplexObjekt verwendet
    const duplexObject = {
        inio:{
            recived:(data) => {
                // Es wird geprüft ob es sich um ein Bestätigungspaket handelt
                if(Buffer.from("d", 'ascii').equals(data) !== true) {
                    // Die Verbindungen werden geschlossen, es handelt sich um ein ungültiges Paket
                    console.log('CLOSE_CONNECTION_INVALID_CONNECTION');
                    return;
                }

                // Es wird geprüft ob eine Enterrupt Funktion vorhanden ist
                if(currentEnterruptFunction === null) {
                    // Die Verbindungen werden geschlossen, es handelt sich um ein ungültiges Paket
                    console.log('CLOSE_CONNECTION_INVALID_CONNECTION');
                    return;
                }

                // Dem Aktuell Sendenden Vorgang wird Signalisiert dass die Daten erfolgreich entgegengenommen wurden
                currentEnterruptFunction();
            }
        },
        outio:{
            recived:(data) => {
                // Es wird geprüft ob es sich um ein bestätigungs Paket handelt, wenn ja wird der Vorgang beendet
                if(Buffer.from("d", 'ascii').equals(data) === true) {
                    console.log('INVALD_PACKAGE');
                    return;
                }

                // Das Paket wird Lokal weiterverbeitet
                OUTSOCKET_ENTER_PACKAGE(data, () => {
                    // Der Gegenseite wird mitgeteilt dass das Paket erfolgreich empfangen wurde
                    outputSocket.write(Buffer.from("d", 'ascii'), (e) => {
                        // Es wird geprüft ob bei dem Versenden des Paketes ein fehler aufgetreten ist, wenn ja wird der Vorgang abgebrrochen
                        if(e !== undefined) {
                            console.log(e);
                            return;
                        }
                    });
                });
            }
        } 
    };

    // Die Objekt Funktionen werden zurückgegeben
    return duplexObject;
};

// Wird als Multi Duplex Socket Verwendet
function createDuplexSocket(nodeObj, filepath, callback) {
    // Speichert alle Wartendenden Eingehende Vorgänge ab
    let openIncommingWaitingProcesses = new Map();

    // Nimmt neue Verbindungen entgegen
    var socketIoSocket = net.createServer((client) => {
        // Speichert die Funktion ab, welche Eintreffende Pakete entgegen nimmt
        let duplexConnectionFunctions = null;

        // Speichert ab, ob die Verbindung bereits Initalisiert wurde
        let initStep = 0, sessionType = null;

        // Nimmt eintreffende Pakete entgegen
        client.on('data', (data) => {
            // Es wird geprüft ob die Verbindung bereis Initalisiert wurde
            if(initStep === 0) {
                // Es wird versucht das Paket mittels CBOR einzulesen
                let readedPackage = cbor.decode(data);

                // Es wird geprüft ob die Benötitgen Felder vorhanden sind
                if(readedPackage.mode === undefined || readedPackage.type === undefined) { client.destroy(); return; }

                // Es wird geprüft ob es sich um eine ein oder eine ausgehende Verbindung handelt
                if(readedPackage.mode === 'register_new_socket' && readedPackage.type === 'out') {
                    // Es wird eine neue SessionID sowie ProzessID erzeugt
                    const inSid = v4(), procId = v4();

                    // Der Vorgang wird zwischengespeichert
                    openIncommingWaitingProcesses.set(procId, {
                        isid:inSid, mergeDuplex:(socket, ducallback) => {
                            // Es wird geprüft ob der Ausgehende Socket sich gerade im Modus 1 befindet
                            if(initStep !== 1) { socket.destroy(); client.destroy(); return; }

                            // Die beiden Sockets werden zusammen geführt
                            const ioFunctions = mergeDuplexSocketConnections(nodeObj, socket, client, procId);

                            // Die Socket Funktionen für die Eingehenden Daten wird zurückgegeben
                            ducallback(ioFunctions.inio);

                            // Der Eintrag wird aus der Liste entfertn
                            openIncommingWaitingProcesses.delete(procId);

                            // Speichert die Funktionen ab
                            duplexConnectionFunctions = ioFunctions.outio;

                            // Setzt den Modus auf 2
                            initStep = 2;
                        }
                    });

                    // Der Sitzungstyp wird festgelegt
                    sessionType = "out";

                    // Der Gegenseite wird das Antwort Paket mitgeteilt
                    client.write(cbor.encode({ version:consensus.version, lang:"js", root:false, pid:procId, isid:inSid }), (error) => {
                        // Der Vorgang wird auf 1 gesetzt, es wird 1 Sekundelang auf eine eingehende Verbindung gewartet
                        initStep = 1;
                    });
                }
                else if(readedPackage.mode === 'register_new_socket' && readedPackage.type === 'in') {
                    // Es wird geprüft ob die benötigten Angaben vorhanden sind
                    if(readedPackage.pid === undefined || readedPackage.isid === undefined) {
                        console.log('INVALID_REQUEST_PACKAGE');
                        client.destroy();
                        return;
                    }

                    // Es wird geprüft ob es einen Wartenden Vorgang unter der Nachfolgenden ID gibt
                    const fetchedProcess = openIncommingWaitingProcesses.get(readedPackage.pid);
                    if(fetchedProcess === undefined) {
                        console.log('UNKOWN_PROCESS');
                        client.destroy();
                        return;
                    }

                    // Der Sitzungstyp wird festgeleget
                    sessionType = "in";

                    // Die Eingehende Verbindung wird mit der Ausgehenden Verbindung zusammengeführt
                    fetchedProcess.mergeDuplex(client, (sockIo) => {
                        // Der Gegenseite wird über die eingehende Verbindung mitgeteilt dass der Duplex Socket vollkommen fertigestellt wurde
                        client.write(Buffer.from('d', 'ascii'), (error) => {
                            // Speichert die Aktuellen Socket Funktionen ab
                            duplexConnectionFunctions = sockIo;

                            // Setzt den Modus des Sockets auf 2
                            initStep = 2;
                        });
                    });
                }
                else {
                    console.log('UNKOWN_LIB_MODE');
                    client.destroy();
                    return;
                }
            }
            else if(initStep === 2) {
                // Es wird geprüft ob die Duplex Funktionen vorhanden sind
                if(duplexConnectionFunctions === null) { client.destroy(); return; }

                // Das Eintreffende Paket wird übergeben
                duplexConnectionFunctions.recived(data, () => {
                    // Der Gegenseite wird Signalisiert dass das Paket empfangen wurde
                    client.write(Buffer.from("d", 'ascii'), (r) => {
                        // Es wird geprüft ob ein Fehler aufgetreten ist
                    })
                });
            }
            else {
                console.log('UNKOWN_MODE');
            }
        });

        // Wird bei einem Fehler ausgeführt

        // Wird ausgeführt wenn die Verbindung getrennt wurde
    });

    // Der Duplex Socket IO Socket wird erstellt
    socketIoSocket.listen(filepath, (x) => {
        callback(null, socketIoSocket);
    })
};

// Bereitet den Shared Memory für die API auf Systemebene vor
const createSystemSharedMemoryAPI = (nodeObj, callback) => {
    // Wird verwendet um den eigentlichen Socket zu starten
    const _SOCKET_INNER = (socketIoPath) => {
        // Wird wird verwendet um Socket Verbindungen zu verarbeiten
        createDuplexSocket(nodeObj, socketIoPath, (error, result) => {
            console.log('API_END_POINT_STARTED');
            callback(null);
        });
    };

    // Es wird geprüft ob es sich um ein Apple System handelt
    if (process.platform == 'darwin') {
        // Es wird geprüft ob der Ordner bereits exestiert
        if (fs.existsSync(consensus.socket_paths.unix_socket_none_root_path)) {
            // Die Pfade werden erstellt
            const noneRootSockIoPath = `${consensus.socket_paths.unix_socket_none_root_path}none_root_sock_io.sock`;

            // Es wird geprüft ob der None Root Socket IO vorhanden ist
            if (fs.existsSync(noneRootSockIoPath)) {
                try { fs.unlinkSync(noneRootSockIoPath); }
                catch (error) { callback(error); return; }
            }

            // Der Socket wird gestartet
            _SOCKET_INNER(noneRootSockIoPath);
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