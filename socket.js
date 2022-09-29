const events = require('events');




// Gibt alle  Verfügabren Sockettypen an
const SocketTypes = {
    RAW:0,
    DATAGRAMM:1,
    SESSION:2,
    STREAM:3,
    IPTUN:4,
};

// Layer 2 Socket
const Layer2Socket = (localNodeObject, localNodePrivKey, socketType, remoteAddress, localPort, remotePort, socketCreatedCallback) => {
    // Verwaltet alle Events
    const eventManager = new events.EventEmitter();

    // Wird verwendet um einen RAW oder Datagramm Socket zu erstellen
    const _CREATE_RAW_DTGRM_SOCKET = () => {
        // Nimmt ein Paket entgegen
        const _enterPackage = (packageFrame, addressRawEp, callback) => {
            // Es wird geprüft ob die Adresse Empfänger
            if(Buffer.from(localNodePrivKey.publicKey).toString('hex') !== packageFrame.destination) {
                console.log('UNKOWN_DESTINATION_SOCKET_ADDRESS');
            }

            // Es wird geprüft ob der Absender korrekt ist, sofern vorhanden
            if(remoteAddress !== null) {
                if(remoteAddress !== packageFrame.source) {
                    console.log('UNKOWN_SOURCE');
                }
            }

            // Das Layer3 Frame wird extrahiert
            const layer3Frame = packageFrame.body.ebody.body;

            // Es wird geprüft ob der Empfänger Port mit dem Aktuellen Port übereinstimmt
            if(localPort !== layer3Frame.dport) {
                console.log('DROP');
                return;
            }

            // Es wird geprüft ob der Absenderport, sofern vorhanden, korrekt ist
            if(remotePort !== null) {
                if(remotePort !== layer3Frame.sport) {
                    console.log('DROP_SOURCE_PORT');
                    return;
                }
            }

            // Das Event das ein Paket eingegangen ist, wird ausgeführt
            eventManager.emit('recived', layer3Frame.data, packageFrame.source, layer3Frame.sport);

            // Das Paket wurde erfolgreich verabeitet
            callback(true);
        };

        // Wird verwendet um ein Paket zu versenden
        const _writeData = (data, reciverAddress, reciverPort, callback) => {
            // Es wird versucht den RawAddressEp abzurufen
            localNodeObject.getAddressRawEndPoint(reciverAddress, (rerro, robj) => {
                // Es wird geprüft ob der AddressRawEp abgerufen werden konnte
                if(rerro !== null) { callback(rerro); return; }
                
                // Die SocketIO Funktion wird abgerufen
                robj.socket.getSocketIo(localPort, reciverPort, (sockIo) => {
                    // Das Paket wird an die gegenseite gesendet
                    sockIo.sendData(data, (state) => { callback(state); });
                });
            });
        };

        // Die Socket Funktionen werden zurückgegeben
        socketCreatedCallback(null, {
            onRecived:(cb) => {
                eventManager.on('recived', (a, r, t) => {
                    cb(a, r, t);
                });
             },
            write:(data, reciverAddress, reciverPort, callback) => _writeData(data, reciverAddress, reciverPort, callback) 
        });

        // Das Objekt wird zurückgegeben
        return {
            enterPackage:_enterPackage
        };
    };

    // Es wird ein RAW Socket erzeugt
    return _CREATE_RAW_DTGRM_SOCKET();
};

// Erzeugt einen neuen Socket ohne Spezifischen Address EndPunkt
const createLocalSocket = (localNode, localNodePrivKey, socketType, localPort, callback) => {
    return Layer2Socket(localNode, localNodePrivKey, socketType, null, localPort, null, (rerr, robj) => {
        callback(null, robj);
    });
};


// Die Module werden exportiert
module.exports= {
    createLocalSocket:createLocalSocket,
    Socket:Layer2Socket, SockTypes:SocketTypes 
};