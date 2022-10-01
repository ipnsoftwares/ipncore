const { getHashFromDict, createRandomSessionId, eccdsa } = require('./crypto');
const { dprintok, dprinterror, colors } = require('./debug');
const { WebSocketServer, WebSocket } = require('ws');
const { v4: uuidv4, v4 } = require('uuid');
const consensus = require('./consensus');
const cbor = require('cbor');



// Stellt eine Verbindung dar
const wsConnection = (localeNodeObject, wsConnObject, sourceAddress, incomming=false, sfunctions=[], clrqfunctions=[], callbackAfterConnected=null, connectionClosedCallback=null) => {
    // Speichert die Aktuelle SessionID dieser Verbindung ab
    let _currentSessionId = createRandomSessionId();

    // Gibt die Startzeit der Verbindung an
    var _connectionStartTime = Date.now();

    // Gibt die Zeit an, wann die Verbindung final fertigestellt wurde
    var _connectionInitalFinalTime = null;

    // Gibt alle Offenen Ping Voränge an
    var _openPingProcesses = {};

    // Speichert die letzten 2048 Ping Voränge für diesen Socket
    var _lastPingResults = [];

    // Speichert alle Funktionen der Gegenseite ab
    var _peerFunctions = [];

    // Speichert alle Protkollfunktionen des Peers ab
    var _peerProtFunctions = [];

    // Gibt den Öffentlichen Schlüssel der Gegenseite an
    var _destinationPublicKey = null;

    // Gibt an ob die Verbindung Registriert wurde
    var _connectionIsInited = false;

    // Speichert den PingPong Timer ab
    var _pingPongTimer = null;

    // Gibt an ob die Verbindung aufgebaut ist
    var _isConnected = true;

    // Speichert den Timer für den Initaliserungsvorgang ab
    var _initTimer = null;

    // Speichert die Ping Zeit des letzten Ping Vorganges ab
    var _lastPing = 0;

    // Speichert die version der gegenseite ab
    var _peerVersion = null;

    // Gibt an wieviele Pakete gesendet und Empfangen wurden
    var _recivedPackages = 0, _sendPackages = 0, _recivedPackageBytes = 0, _sendPackagesBytes = 0, _errorRecivedPackages = 0, _errorRecivedPackageBytes = 0, _prate = 0;

    // Wird verwendet um Pakete an die gegenseite zu senden
    const _SNED_SESSION_BASED_PACKAGES = (signatedPackage, callback) => {
        // Speichert die Aktuelle Uhrzeit ab
        const currentTime = Date.now();

        // Das Paket wird mittels CBOR Umgewandelt
        const convertedCborPackage = cbor.encode(signatedPackage);

        // Das Paket wird Verschlüsselt


        // Das Paket wird versendet
        wsConnObject.send(convertedCborPackage, (serr) => {
            // Es wird geprüft ob die Daten gesendet werden konnten
            if(serr === undefined) {
                // Es wird ermittelt wielange es gedauert hat bis das Paket versendet wurde
                let curation = Date.now() - currentTime;

                // Es wird geprüft ob das übertragen des Paketes länger als 0 ms gedauert hat
                if(curation === 0) _prate = curation;
                else _prate = convertedCborPackage.length / curation;

                // Das Paket wurde erfolgreich versendet
                dprintok(10, ['Packet with'], [colors.FgMagenta, convertedCborPackage.length], ['bytes is transmitted via websocket connection'], [colors.FgMagenta, _currentSessionId]);
                _sendPackagesBytes += convertedCborPackage.length;
                _sendPackages += 1;
                callback(true);
            }
            else {
                callback(false);
            }
        })
    };

    // Speichert alle Objekt funktionen ab
    const _WS_SOCKET_FUNCTIONS = {
        sendPackage:(package, callback) => _SNED_SESSION_BASED_PACKAGES(package, callback),
        defaultTTL:consensus.defaults.ip_based_transport_session_default_ttl,
        getPeerPublicKey:() => _destinationPublicKey,
        getPeerIPAddressUrl:() => sourceAddress,
        totalRXPackages:() => _recivedPackages,
        getPeerFunctions:() => _peerFunctions,
        totalTXPackages:() => _sendPackages,
        sessionId:() => _currentSessionId,
        close:() => wsConnObject.close(),
        peerVersion:() => _peerVersion,
        isConnected:() => _isConnected,
        isIncomming:() => incomming,
        sendRate:() => _prate,
        getPingTime:() => {
            if(_lastPing === 0) {
                const r_ = _connectionInitalFinalTime - _connectionStartTime;
                return r_;
            }
            else {
                return _lastPing;
            }
        },
        getInitialTime:() => {
            if(_connectionInitalFinalTime === null) { return null; }
            else { return _connectionInitalFinalTime - _connectionStartTime; } 
        },
    };

    // Prüft ob die Signatur eines Paketes korrekt ist
    const _VERIFY_PACKAGE_SIGNATURE = (pacakge) => {
        // Es wird geprüft ob der Öffentliche Schlüssel, die Signatur sowie der Algo vorhanden sind
        if(pacakge.hasOwnProperty('pkey') !== true) return false;
        if(pacakge.hasOwnProperty('sig') !== true) return false;

        // Sollte bereits ein Sitzungsschlüssel vorhanden sein, so werden diese Verglichen, sollten die Schlüssel nicht Identisch sein, wird der Vorgang abgebrochen
        if(_destinationPublicKey !== null) {
            if(_destinationPublicKey !== pacakge.pkey) {
                dprinterror(10, ['It is a corrupt connection, connection'], [colors.FgMagenta, _currentSessionId], ['was closed for security reasons']);
                wsConnObject.close();
                return;
            }
        }

        // Das Paketobjekt wird geklont
        let clonedObj = JSON.parse(JSON.stringify(pacakge));

        // Es wird geprüft ob die Länge des Öffentlichen Schlüssels korrekt ist
        if(pacakge.pkey.length !== 64) return false;

        // Es wird geprüft ob die Länge der Signatur korrekt ist
        if(pacakge.sig.length !== 128) return false;

        // Es wird versucht den Öffentlichen Schlüssel sowie die Signatur zu Dekodieren
        try{ var decodedPublicKey = Buffer.from(pacakge.pkey, 'hex'), decodedSignature = Buffer.from(pacakge.sig, 'hex'); }
        catch(e) { dprinterror(10, e); return false; }

        // Die Signatur wird geprüft
        delete clonedObj.sig, clonedObj.pkey;
        if(localeNodeObject.crypto.ed25519.verify_sig(decodedSignature, getHashFromDict(clonedObj), decodedPublicKey)) return false;

        // Es wird geprüft ob die Signatur korrekt ist
        return true;
    };

    // Wird aller 5 Sekunden ausgeführt und führt einen Ping innerhalb der Aktuellen Verbindung durch
    const _PING_PONG_TIMER = () => {
        // Es wird ein Zufälliger Wert erzeugt
        const pingPackageID = uuidv4();

        // Das Pingpaket wird an die gegenseite übermittelt
        wsConnObject.ping(pingPackageID, () => { _openPingProcesses[pingPackageID] = Date.now(); });
    };

    // Wird ausgeführt, nachdem die Verbindung erfolgreich hergestellt wurde
    const _CALL_AFTER_SUCCS_CONNECTED = () => {
        // Alle Verfügbaren Funktionen beider Nodes werden ermittelt
        var supportedFunctions = [];
        for(const x of clrqfunctions) {
            for(const t of _peerFunctions) { if (x === t) supportedFunctions.push(x); } 
        }

        // Die Zeit wann die Initalisierung fertigestellt wurde wird gesetzt
        _connectionInitalFinalTime = Date.now();

        // Die Verbindung wird fertiggestellt
        _connectionIsInited = true;

        // Die Verbindung wird registriert
        localeNodeObject.registerConnection(_WS_SOCKET_FUNCTIONS, _peerProtFunctions, (result) => {
            if(result !== true) {
                dprinterror(10, ['An internal error has occurred, the connection'], [colors.FgMagenta, _currentSessionId], ['is closed for security reasons.'])
                _connectionIsInited = false;
                wsConnObject.close();
                return; 
            }

            // Es wird Signalisiert dass eine Verbindung aufgebaut wurde
            if(!incomming) { if(callbackAfterConnected !== null) callbackAfterConnected(); }

            // Die Dienste der Verbindung werden gestartet
            if(!incomming) localeNodeObject.startClientServices(_WS_SOCKET_FUNCTIONS, supportedFunctions);

            // Wird als Timer ausgeführt
            if(_pingPongTimer === null) { _pingPongTimer = setTimeout(_PING_PONG_TIMER, 1000); }
        });
    };

    // Wird verwendet um ein HelloPackage an die gegenseite zu senden
    const _SEND_HELLO_PACKAGE_TO_PEER = (callback) => {
        // Das HelloPackage wird gebaut
        const helloPackage = { version:consensus.version, type:"regnde", sfunctions:sfunctions, protf:['prot_full_relay'] };

        // Der Hash des Dicts wird Signiert
        const cryptoSig = localeNodeObject.signAndReturnPubKeyAndSig(getHashFromDict(helloPackage));

        // Das Finale Paket wird gebaut
        const finalHelloPackage = Object.assign(helloPackage, { pkey:Buffer.from(cryptoSig.pkey).toString('hex'), sig:Buffer.from(cryptoSig.sig).toString('hex') });

        // Das Paket wird mittels CBOR umgewandelt
        const cborConvertedPackage = cbor.encode(finalHelloPackage);

        // Das Paket wird an die Gegenseite gesendet
        wsConnObject.send(cborConvertedPackage, () => {
            _sendPackages += 1;
            callback(); 
        });
    };

    // Wird verwendetet um REGISTER-NODE Pakete zu verarbeiteten
    const _ENTER_REGISTER_NODE_PACKAGE = (package_data) => {
        // Es wird geprüft ob das Peer bereits Initalisiert wurde
        if (_destinationPublicKey !== null || _connectionIsInited !== false) {
            dprinterror(10, ['An internal error has occurred, the connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['is closed for security reasons.']);
            wsConnObject.close();
            return; 
        }

        // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
        var _innerFieldsFound = true;
        if(Object.keys(package_data).length >= 256) _innerFieldsFound = false;
        if(package_data.hasOwnProperty('pkey') !== true) _innerFieldsFound = 'pkey';
        if(package_data.hasOwnProperty('protf') !== true) _innerFieldsFound = 'protf';
        if(package_data.hasOwnProperty('version') !== true) _innerFieldsFound = 'version';
        if(package_data.hasOwnProperty('sfunctions') !== true) _innerFieldsFound = 'sfunctions';
        if(_innerFieldsFound !== true) {
            dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
            wsConnObject.close();
            return; 
        }

        // Es wird geprüft ob es sich um eine Zulässige Version handelt
        if(package_data.version < consensus.sversion) {
            wsConnObject.close();
        }

        // Es wird geprüft ob sich das Programm im Main Modus befindet, wenn ja werden alle Tesnet Keys blockiert
        if(consensus.is_mainnet === true) {
            if(consensus.main_blocked_public_keys.includes(package_data.pkey)) {
                wsConnObject.close();
            }
        }

        // Die Version der gegenseite wird abgespeichert
        _peerVersion = package_data.version;

        // Der Öffentliche Schlüssel wird geschrieben
        _destinationPublicKey = package_data.pkey;
        
        // Sofern vorhanden wird der Init Timer gestoppt
        if(_initTimer !== null) { clearTimeout(_initTimer); _initTimer = null; }

        // Es werden alle Node Funktionen gepürft und abgespeichert
        for(let i = 0; i<package_data.sfunctions.length; i++) {
            if (typeof package_data.sfunctions[i] !== 'string') {
                dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
                wsConnObject.close();
                return;
            }
            _peerFunctions.push(package_data.sfunctions[i]);
        }

        // Es werden alle Protokollfunktionen gepfrüft und abgespeichert
        for(let i = 0; i<package_data.protf.length; i++) {
            if (typeof package_data.protf[i] !== 'string') {
                dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
                wsConnObject.close();
                return;
            }
            _peerProtFunctions.push(package_data.protf[i]);
        }

        // Das HelloPackage wird an die gegenseite gesendet, sofern es sich um eine Ausgehdene Verbindung handelt
        if(!incomming) _SEND_HELLO_PACKAGE_TO_PEER(() => _CALL_AFTER_SUCCS_CONNECTED());
        else _CALL_AFTER_SUCCS_CONNECTED();
    };

    // Wird ausgeführt wenn die Verbindung geschlossen wurde
    const _CLOSE_CONNECTION = () => {
        // Es wird geprüft ob die Verbindung aufgebaut ist
        if(!_isConnected) return;

        // Speichert ab dass die Verbindung geschlossen wurde
        _isConnected = false;

        // Alle Timer werden gestoppt
        if(_pingPongTimer !== null) clearTimeout(_pingPongTimer);
        if(_initTimer !== null) clearTimeout(_initTimer);

        // Es wird geprüft ob die Verbindung Initalisiert wurde
        if(_connectionIsInited) {
            localeNodeObject.unregisterConnection(_WS_SOCKET_FUNCTIONS, (result) => {
                dprintok(10, ['The initialized connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['was closed']);
                if(connectionClosedCallback !== null) { connectionClosedCallback(); return; }
            });
        }
        else {
            dprintok(10, ['The uninitialized connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['was closed']);
        }
    };

    // Nimt Pakete bei einer nicht Initalisierten Verbindung entgegen
    const _ENTER_PACKAGE_ON_NOT_INITED_CONNECTION = (jsonEncodedPackage) => {
        // Es wird geprüft ob der Öffentliche Schlüssel sowie die Signatur vorhanden ist
        if(!_VERIFY_PACKAGE_SIGNATURE(jsonEncodedPackage)) {
            dprinterror(10, ['A packet with an invalid signature was received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
            _errorRecivedPackageBytes += message.length;
            _errorRecivedPackages += 1;
            wsConnObject.close(); 
        }

        // Es wird geprüft ob ein Pakettyp angegeben wurde
        if(jsonEncodedPackage.hasOwnProperty('type') !== true) {
            dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
            wsConnObject.close();
            return;
        }

        // Der Pakettyp wird ermittelt
        switch (jsonEncodedPackage.type) {
            case "regnde":
                _ENTER_REGISTER_NODE_PACKAGE(jsonEncodedPackage);
                break;
            default:
                dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                wsConnObject.close();
                return; 
        }
    };

    // Nimt Pakete bei einer Initalisierten Verbindung entgegen
    const _ENTER_PACKAGE_ON_INITED_CONNECTION = (jsonEncodedPackage) => {
        // Es wird versucht die Daten zu entschlüssen
        

        // Es wird geprüft ob der Öffentliche Schlüssel sowie die Signatur vorhanden ist
        if(!_VERIFY_PACKAGE_SIGNATURE(jsonEncodedPackage)) {
            dprinterror(10, ['A packet with an invalid signature was received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
            _errorRecivedPackageBytes += message.length;
            _errorRecivedPackages += 1;
            wsConnObject.close(); 
        }

        // Es wird geprüft ob ein Pakettyp angegeben wurde
        if(jsonEncodedPackage.hasOwnProperty('type') !== true) {
            dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
            wsConnObject.close();
            return;
        }

        // Der Pakettyp wird ermittelt
        switch (jsonEncodedPackage.type) {
            case "pstr":
                if (!_connectionIsInited) {
                    dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                    wsConnObject.close();
                    return; 
                }
                localeNodeObject.enterNextLayerPackage(jsonEncodedPackage, _WS_SOCKET_FUNCTIONS);
                break;
            case "req":
                if (!_connectionIsInited) {
                    dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                    wsConnObject.close();
                    return; 
                }
                localeNodeObject.enterCommandPackage(jsonEncodedPackage, _WS_SOCKET_FUNCTIONS);
                break;
            case "rreq":
                if (!_connectionIsInited) {
                    dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                    wsConnObject.close();
                    return; 
                }
                localeNodeObject.enterRoutingRegRespPackage(jsonEncodedPackage, _WS_SOCKET_FUNCTIONS);
                break;
            case "rrr":
                if (!_connectionIsInited) {
                    dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                    wsConnObject.close();
                    return; 
                }
                localeNodeObject.enterRoutingRegRespPackage(jsonEncodedPackage, _WS_SOCKET_FUNCTIONS);
                break;
            case "resp":
                if (!_connectionIsInited) {
                    dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                    wsConnObject.close();
                    return; 
                }
                localeNodeObject.enterResponsePackage(jsonEncodedPackage, _WS_SOCKET_FUNCTIONS);
                break;
            default:
                dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                wsConnObject.close();
                return; 
        }
    };

    // Nimmt eintreffende Pakete entgegen
    wsConnObject.on('message', (message) => {
        // Debug Print
        dprintok(10, ['Data packet with'], [colors.FgMagenta, message.length], ['bytes received via the websocket connection'], [colors.FgMagenta, _currentSessionId]);

        // Das Eintreffende Paket wird geparst
        try {
            var _readedPackage = cbor.decode(message)
            _recivedPackageBytes += message.length;
            _recivedPackages += 1;
        }
        catch(E) {
            dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
            _errorRecivedPackageBytes += message.length;
            _errorRecivedPackages += 1;
            wsConnObject.close(); 
        }

        // Es wird geprüft ob die Verbindung bereits Initaliseirt wurde
        if(_connectionIsInited) _ENTER_PACKAGE_ON_INITED_CONNECTION(_readedPackage);
        else _ENTER_PACKAGE_ON_NOT_INITED_CONNECTION(_readedPackage);
    });

    // Wird ausgeführt, wenn die Verbindung geschlossen wurde
    wsConnObject.on('close', () => _CLOSE_CONNECTION());

    // Wird ausgeführt, nachdem das Pong Paket empfangen wurde
    wsConnObject.on('pong', (packageInnerValue) => {
        // Es wird geprüft ob die Verbindung besteht
        if(!_isConnected) return;

        // Es wird versucht die Aktuelle ID einzulesen
        try{
            const readedID = Buffer.from(packageInnerValue).toString('utf8');

            // Es wird geprüft ob es einen passenden Offenen Ping Vorgang gibt
            if(_openPingProcesses.hasOwnProperty(readedID)) {
                const sendTime = _openPingProcesses[readedID];
                const currentTime = Date.now();
                const totalPingTime = currentTime - sendTime;
                if(_lastPing !== totalPingTime) {
                    if(_lastPingResults.length > 2048) _lastPingResults.pop();
                    _lastPingResults.push(totalPingTime);
                    _lastPing = totalPingTime;
                }
            }
        }
        catch(e) {
            dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
        }

        // Der Ping Timer wird neugestartet
        _pingPongTimer = setTimeout(_PING_PONG_TIMER, 2575);
    });

    // Wird als Timeout Timer verwendet
    const timeOutTimer = () => {
        // Es wird geprüft ob die Initalisierungsvorgang durchgeführt wurde
        if (_destinationPublicKey === null || _connectionIsInited === false) {
            dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
            wsConnObject.close();
            return; 
        }
    };

    // Es wird geprüft ob das HelloPackage versendet werden soll
    if(incomming === true) {
        // Das Paket wird an die gegenseite gesendet
        _SEND_HELLO_PACKAGE_TO_PEER(() => {
            // Der Inital Time wird gestartet
            _initTimer = setTimeout(timeOutTimer, 2575);
        });
    }
    else {
        // Der Init Timer wird gestartet
        _initTimer = setTimeout(timeOutTimer, 2575);
    }

    // Gibt die Kernfunktionen zurück
    return { isInited:() => _connectionIsInited, close:() => _CLOSE_CONNECTION }
}


// Baut eine ausgehende Verbindung auf
const wsConnectTo = (localeNodeObject, serverUrl, sfunctions=[], accepted_functions=['boot_node'], callback=null, connectionClosedCallback=null) => {
    // Das Websocket Objekt wird vorbereitet
    const ws = new WebSocket(serverUrl);

    // Speichert das Inited Objekt ab
    var _initedObject = null;

    // Wird ausgeführt wenn die Verbindung hergestellt wurde
    ws.on('open', () => {
        dprintok(10, ['New outgoing websocket connection established with'], [colors.FgMagenta, serverUrl]);
        _initedObject = wsConnection(localeNodeObject, ws, serverUrl, false, sfunctions, accepted_functions, callback, connectionClosedCallback);
    });

    // Wird bei einem Fehler ausgeführt
    ws.on('error', () => {
        if(_initedObject !== null) { _initedObject.close(); }
        else { if(connectionClosedCallback !== null) { connectionClosedCallback(); } }
    });
}


// Erstellt einen neuen Lokalen Server
const wsServer = (localeNodeObject, localPort, sfunctions=[]) => {
    // Der Webserver wird gestartet
    const wss = new WebSocketServer({ port: localPort });

    // Nimmt neue Verbindungen entgegen
    wss.on('connection', (ws, req) => {
        // Die Adresse des Clients wird ermittelt
        const newUrlAddress = `ws://${req.socket.remoteAddress}@${req.socket.remotePort}`

        // Debug
        dprintok(10, ['Accepted new incoming websocket connection from'], [colors.FgMagenta, req.socket.remoteAddress]);

        // Die Verbindung wird erstellt
        wsConnection(localeNodeObject, ws, newUrlAddress, true, sfunctions);
    });

    // Gibt das Serverobjekt zurück
    dprintok(10, ['New websocket server created on'], [colors.FgMagenta, localPort])
    return { close:() => {} };
}


// Exportiert alle Funktionen
module.exports = { wsConnection:wsConnection, wsConnectTo:wsConnectTo, wsServer:wsServer }