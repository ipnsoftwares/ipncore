const { get_hash_from_dict, create_random_session_id, encrypt_data, compute_shared_secret, sign_digest, verify_digest_sig, decrypt_data } = require('./crypto');
const { isNodeOnPCLaptopOrEmbeddedLinuxSystem, parsIpAddress } = require('./utils');
const { isValidateHelloPackageLayerOne } = require('./lpckg');
const { dprintok, dprinterror, colors } = require('./debug');
const { WebSocketServer, WebSocket } = require('ws');
const consensus = require('./consensus');
const { v4 } = require('uuid');
const cbor = require('cbor');



// Stellt eine Verbindung dar
const wsConnection = (socketKeyPair, localeNodeObject, wsConnObject, sourceAddress, incomming=false, sfunctions=[], clrqfunctions=[], callbackAfterConnected=null, connectionClosedCallback=null) => {
    // Speichert die Aktuelle SessionID dieser Verbindung ab
    let _currentSessionId = create_random_session_id();

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

    // Speichert den DH-Schlüssel der Sitzung ab
    var _sessionSharedSecret = null;

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

    // Speichert die Remote Adresse der Gegenseite ab
    var _peerRemoteEp = null;

    // Gibt an wieviele Pakete gesendet und Empfangen wurden
    var _recivedPackages = 0, _sendPackages = 0, _recivedPackageBytes = 0, _sendPackagesBytes = 0, _errorRecivedPackages = 0, _errorRecivedPackageBytes = 0, _prate = 0;

    // Wird verwendet um Pakete an die gegenseite zu senden
    const _SNED_SESSION_BASED_PACKAGES = (signatedPackage, callback) => {
        // Speichert die Aktuelle Uhrzeit ab
        const currentTime = Date.now();

        // Das Paket wird mittels CBOR Umgewandelt
        const convertedCborPackage = cbor.encode(signatedPackage);

        // Es wird geprüft ob das Paket die Maxiaml größe Überschreitet
        if(convertedCborPackage.length > consensus.max_package_byte_size) {
            console.log('PACKAGE_DROPED');
            wsConnObject.close();
            return;
        }

        // Wird asugeführt nachdem das Paket versendet wurde
        const _out_send_fnc = (serr) => {
            // Es wird geprüft ob die Daten gesendet werden konnten
            if(serr === undefined) {
                // Es wird ermittelt wielange es gedauert hat bis das Paket versendet wurde
                let curation = Date.now() - currentTime;

                // Es wird geprüft ob das übertragen des Paketes länger als 0 ms gedauert hat
                if(curation <= 0) _prate = 1;
                else _prate = convertedCborPackage.length / curation;

                // Das Paket wurde erfolgreich versendet
                dprintok(10, ['Packet with'], [colors.FgMagenta, convertedCborPackage.length], ['bytes is transmitted via websocket connection'], [colors.FgMagenta, _currentSessionId]);
                _ADD_PACKAGE_SEND(convertedCborPackage);
                callback(true);
            }
            else { callback(false); }
        };

        // Es wird geprüft ob die Sitzung Initalisiert wurde, wenn ja wird das Paket verschlüsselt bevor es versendet wird
        if(_connectionIsInited === true) {
            // Der Datensatz wird verschlüsselt
            encrypt_data(_sessionSharedSecret, convertedCborPackage, (error, chiperedPackage) => {
                // Es wird geprüft ob bei dem versuch den Datensatz zu verschlüsseln ein Fehler aufgetreten ist
                if(error !== null) {
                    callback('crypto_error');
                    wsConnObject.close();
                    return;
                }

                // Das Verschlüsselte Paket wird versendet
                wsConnObject.send(chiperedPackage, _out_send_fnc);
            });
        }
        else {
            // Das Paket wird versendet
            wsConnObject.send(convertedCborPackage, _out_send_fnc);
        }
    };

    // Wird Verwendet um ein Sitzungspaket zu versenden
    const _SEND_UNSIGNATED_RAW_PACKAGE = (rawPackage, callback) => {
        // Das Basispaket wird gebaut
        const baseRAWPackage = { version:consensus.version, ...rawPackage };

        // Der Hash des Paketes wird Signiert
        const packageSignature = sign_digest(get_hash_from_dict(baseRAWPackage), socketKeyPair.privateKey);

        // Die Signatur wird dem Paket hinzugefügt
        const finallyObjPackage = { ...baseRAWPackage, sig:packageSignature };

        // Das Paket wird an die gegenseite übertragen
        _SNED_SESSION_BASED_PACKAGES(finallyObjPackage, callback);
    };

    // Wird verwendet um zu Signalisieren das X Bytes empfangen wurden
    const _ADD_PACKAGE_RECIVED = (packageData) => {
        if(Buffer.isBuffer(packageData) === false) { wsConnObject.close(); return; }
        _recivedPackageBytes += packageData.length;
        _recivedPackages += 1;
    };

    // Wird verwendet um zu Signaliseren das X Bytes fehlerhaft empfangen wurden
    const _ADD_PACKAGE_RECIVED_INVALID = (packageData) => {
        if(Buffer.isBuffer(packageData) === false) { wsConnObject.close(); return; }
        _errorRecivedPackageBytes += packageData.length;
        _errorRecivedPackages += 1;
    };

    // Wird verwendet um zu Signaliseren das X Bytes versendet wurden
    const _ADD_PACKAGE_SEND = (packageData) => {
        if(Buffer.isBuffer(packageData) === false) { wsConnObject.close(); return; }
        _sendPackagesBytes += packageData.length;
        _sendPackages += 1;
    };

    // Wird verwendet um eine Eingehende Verbindung zu Injoinen
    const _JOIN_INCOMMING_CONNECTION = (connectionObj, callbf) => {

    };

    // Speichert alle Objekt funktionen ab
    const _WS_SOCKET_FUNCTIONS = {
        joinIncommingConnection:(connectionObj, callbf) =>_JOIN_INCOMMING_CONNECTION(connectionObj, callbf),
        sendUnsigRawPackage:(rawPackage, callback) => _SEND_UNSIGNATED_RAW_PACKAGE(rawPackage, callback),
        defaultTTL:consensus.defaults.ip_based_transport_session_default_ttl,
        totalRXErrorBytes:() => _errorRecivedPackageBytes,
        totalRXErrorPackages:() => _errorRecivedPackages,
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

    // Wird aller 5 Sekunden ausgeführt und führt einen Ping innerhalb der Aktuellen Verbindung durch
    const _PING_PONG_TIMER = () => {
        // Es wird geprüft ob noch eine Verbindung mit dem Peer besteht
        if(_isConnected !== true) {
            return;
        }

        // Es wird ein Zufälliger Wert erzeugt
        const pingPackageID = v4();

        // Das Pingpaket wird an die gegenseite übermittelt
        wsConnObject.ping(pingPackageID, () => { _openPingProcesses[pingPackageID] = Date.now(); });
    };

    // Wird ausgeführt, nachdem die Verbindung erfolgreich hergestellt wurde
    const _CALL_AFTER_SUCCS_CONNECTED = () => {
        // Es wird geprüft ob der Remoteschlüssel angegeben wurde
        if(_destinationPublicKey === null) { wsConnObject.close(); return; }

        // Es wird geprüft ob der DH-Schlüssel vorhanden ist
        if(_sessionSharedSecret === null) { wsConnObject.close(); return; }

        // Alle Verfügbaren Funktionen beider Nodes werden ermittelt
        var supportedFunctions = [];
        for(const x of clrqfunctions) {
            for(const t of _peerFunctions) { if (x === t) supportedFunctions.push(x); } 
        }

        // Es wird geprüft ob die Verbindung mit dem Peer hergestellt ist
        if(_isConnected !== true) { wsConnObject.close(); return; }

        // Die Zeit wann die Initalisierung fertigestellt wurde wird gesetzt
        _connectionInitalFinalTime = Date.now();

        // Die Verbindung wird fertiggestellt
        _connectionIsInited = true;

        // Die Verbindung wird registriert
        localeNodeObject.registerConnection(_WS_SOCKET_FUNCTIONS, _peerProtFunctions, (result) => {
            // Es wird geprüft ob der Vorgang erfolgreich durchgeführt werden konnte
            if(result !== true) {
                dprinterror(10, ['An internal error has occurred, the connection'], [colors.FgMagenta, _currentSessionId], ['is closed for security reasons.'])
                _connectionIsInited = false;
                wsConnObject.close();
                return; 
            }

            // Es wird geprüft ob eiene Verbindung aufrgabut ist
            if(_isConnected !== true) { wsConnObject.close(); return; }

            // Die Dienste der Verbindung werden gestartet
            if(!incomming) localeNodeObject.startClientServices(_WS_SOCKET_FUNCTIONS, supportedFunctions);

            // Es wird Signalisiert dass eine Verbindung aufgebaut wurde
            if(!incomming) { if(callbackAfterConnected !== null) callbackAfterConnected(); }

            // Wird als Timer ausgeführt
            if(_pingPongTimer === null) { _pingPongTimer = setTimeout(_PING_PONG_TIMER, 1000); }

            // Es wird geprüft ob es sich um eine Eingehende Verbindung handelt
            if(incomming === true && isNodeOnPCLaptopOrEmbeddedLinuxSystem() === true) {
                // Es wird geprüft ob der Client einen Port für p2p Verbindungen angegeben hat
                if(_peerRemoteEp !== null) {
                    console.log('INCOMMING_CONNECTION_P2P_FUNCTION_NOT_IMPLEMENTED');
                }
            }
        });
    };

    // Wird verwendet um ein HelloPackage an die gegenseite zu senden
    const _SEND_HELLO_PACKAGE_TO_PEER = (callback) => {
        // Das HelloPackage wird gebaut
        let helloPackage = null;
        if(isNodeOnPCLaptopOrEmbeddedLinuxSystem() === true) {
            if(!incomming) {
                const availPort = localeNodeObject.localServerPorts('ws');
                if(availPort !== null) helloPackage = { type:"regnde", sfunctions:sfunctions, protf:['prot_full_relay'], pkey:Buffer.from(socketKeyPair.publicKey), port:{ type:'ws', ep:availPort.port } }; 
                else helloPackage = { type:"regnde", sfunctions:sfunctions, protf:['prot_full_relay'], pkey:Buffer.from(socketKeyPair.publicKey), port:null }; 
            }
            else {
                helloPackage = { type:"regnde", sfunctions:sfunctions, protf:['prot_full_relay'], pkey:Buffer.from(socketKeyPair.publicKey), locport:null }; 
            }
        }
        else {
            helloPackage = { type:"regnde", sfunctions:sfunctions, protf:['prot_full_relay'], pkey:Buffer.from(socketKeyPair.publicKey), locport:null }; 
        }

        // Es wird geprüft ob die Verbindung mit der Gegenseite noch besteht
        if(_isConnected !== true) {
            console.log('ABORTED_CONNECTION_CLOSED');
            return;
        }

        // Das Paket wird gesendet
        _SEND_UNSIGNATED_RAW_PACKAGE(helloPackage, (state) => callback(state));
    };

    // Wird verwendetet um REGISTER-NODE Pakete zu verarbeiteten
    const _ENTER_PEER_HELLO_PACKAGE = (package_data) => {
        // Es wird geprüft ob ein Paket angegeben wurde
        if(package_data === undefined || package_data === null) {
            dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob es sich um ein Hello Package handelt
        if(isValidateHelloPackageLayerOne(package_data) !== true) {
            dprinterror(10, ['An internal error has occurred, the connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['is closed for security reasons.']);
            _ADD_PACKAGE_RECIVED_INVALID(package_data);
            wsConnObject.close();
            return; 
        }

        // Es wird geprüft ob das Peer bereits Initalisiert wurde
        if(_destinationPublicKey !== null || _connectionIsInited !== false) {
            dprinterror(10, ['An internal error has occurred, the connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['is closed for security reasons.']);
            _ADD_PACKAGE_RECIVED_INVALID(package_data);
            wsConnObject.close();
            return; 
        }

        // Es wird geprüft ob es sich um ein gültiges HelloPackage handelt
        const pacakgeValidationState = isValidateHelloPackageLayerOne(package_data);
        if(pacakgeValidationState !== true) {
            dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
            _ADD_PACKAGE_RECIVED_INVALID(package_data);
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob es sich um eine Zulässige Version handelt
        if(package_data.version < consensus.sversion) {
            dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
            _ADD_PACKAGE_RECIVED_INVALID(package_data);
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob sich das Programm im Main Modus befindet, wenn ja werden alle Tesnet Keys blockiert
        if(consensus.is_mainnet === true) {
            if(consensus.main_blocked_public_keys.includes(package_data.pkey)) {
                dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
                _ADD_PACKAGE_RECIVED_INVALID(package_data);
                wsConnObject.close();
                return;
            }
        }

        // Es wird geprüft ob die Signatur korrekt ist
        let clonedPackageObj = { ...package_data };
        delete clonedPackageObj.sig;
        if(verify_digest_sig(get_hash_from_dict(clonedPackageObj), package_data.sig, package_data.pkey) !== true) {
            dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
            _ADD_PACKAGE_RECIVED_INVALID(package_data);
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob es sich um eine Eingehene Verbindung handelt, wenn ja wird geprüft ob die gegenseite einen Port angegeben hat
        if(incomming === true && isNodeOnPCLaptopOrEmbeddedLinuxSystem() === true) {
            // Es wird geprüft ob ein Port vorhanden ist
            if(package_data.port !== null) {
                // Es wird versucht eine Verbindung herzustellen
                if(package_data.port.type === 'ws') {
                    // Ließt die Adresse der gegenseite aus
                    _peerRemoteEp = package_data.port;
                }
            }
        }

        // Es wird geprüft ob die Verbindung mit dem Peer noch besteht, wenn nicht wird der Vorgang abgebrochen
        if(_isConnected !== true) {
            console.log('ABORTED_CONNECTION_CLOSED');
            return;
        }

        // Die Version der gegenseite wird abgespeichert
        _peerVersion = package_data.version;

        // Der Öffentliche Schlüssel wird geschrieben
        _destinationPublicKey = Buffer.from(package_data.pkey).toString('hex');

        // Sofern vorhanden wird der Init Timer gestoppt
        if(_initTimer !== null) { clearTimeout(_initTimer); _initTimer = null; }

        // Es werden alle Node Funktionen gepürft und abgespeichert
        for(let i = 0; i<package_data.sfunctions.length; i++) {
            if (typeof package_data.sfunctions[i] !== 'string') {
                dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
                _ADD_PACKAGE_RECIVED_INVALID(package_data);
                wsConnObject.close();
                return;
            }
            _peerFunctions.push(package_data.sfunctions[i]);
        }

        // Es werden alle Protokollfunktionen gepfrüft und abgespeichert
        for(let i = 0; i<package_data.protf.length; i++) {
            if (typeof package_data.protf[i] !== 'string') {
                dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
                _ADD_PACKAGE_RECIVED_INVALID(package_data);
                wsConnObject.close();
                return;
            }
            _peerProtFunctions.push(package_data.protf[i]);
        }

        // Der DH-Schlüssel für die Sitzung wird erzeut
        compute_shared_secret(Buffer.from(socketKeyPair.privateKey),  Buffer.from(package_data.pkey), (error, result) => {
            // Es wird geprüft ob ein fehler aufgetreten ist
            if(error !== null) {
                dprinterror(10, ['An invalid packet was received via the websocket connection'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['the connection is closed for security reasons.']);
                _ADD_PACKAGE_RECIVED_INVALID(package_data);
                wsConnObject.close();
                return;
            }

            // Es wird geprüft ob die Verbindung mit der Gegenseite besteht
            if(_isConnected !== true) {
                console.log('ABORTED_CONNECTION_CLOSED');
                return;
            }

            // Der DH-Schlüssel wird abgespeichert
            _sessionSharedSecret = result;

            // Das HelloPackage wird an die gegenseite gesendet, sofern es sich um eine Ausgehdene Verbindung handelt
            if(!incomming) {
                // Der Gegenseite wird das HalloPackage zugesendet
                _SEND_HELLO_PACKAGE_TO_PEER((state) => {
                    // Es wird geprüft ob der Vorgang erfolgreich druchgeführt werden konnte
                    if(state !== true) {
                        console.log('ABORTED_CONNECTION_CLOSED');
                        return;
                    }

                    // Die Verbindung wird fertigestellt
                    _CALL_AFTER_SUCCS_CONNECTED();
                });
            }
            else {
                // Die Verbindung wird fertigestellt
                _CALL_AFTER_SUCCS_CONNECTED();
            }
        });
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
    const _ENTER_PACKAGE_ON_NOT_INITED_CONNECTION = (message) => {
        // Es wird geprüft ob ein Paket angegeben wurde
        if(message === undefined || message === null) {
            dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob es sich um einen Buffer handelt
        if(Buffer.isBuffer(message) !== true) {
            dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
            wsConnObject.close();
            return;
        }

        // Das Eintreffende Paket wird versucht einzulesen
        try{ var encodedObject = cbor.decode(message); }
        catch(E) {
            dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
            _ADD_PACKAGE_RECIVED_INVALID(message);
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob es sich um ein HelloPackage handelt
        if(isValidateHelloPackageLayerOne(encodedObject) !== true) {
            dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
            _ADD_PACKAGE_RECIVED_INVALID(message);
            wsConnObject.close();
            return;
        }

        // Das HelloPackage wird weiterverarbeitet
        _ENTER_PEER_HELLO_PACKAGE(encodedObject);
    };

    // Nimt Pakete bei einer Initalisierten Verbindung entgegen
    const _ENTER_PACKAGE_ON_INITED_CONNECTION = (plainMessage) => {
        // Das Paket wird entschlüsselt
        decrypt_data(_sessionSharedSecret, plainMessage, (error, decryptedResult) => {
            // Das Eintreffende Paket wird geparst
            try { var jsonEncodedPackage = cbor.decode(decryptedResult); }
            catch(E) {
                dprinterror(10, ['An error occurred in session'], [colors.FgMagenta, _currentSessionId], [E]);
                _ADD_PACKAGE_RECIVED_INVALID(plainMessage);
                wsConnObject.close();
                return;
            }

            // Das Basis Layer 1 Paket wird geprüft

            // Es wird geprüft ob die Signatur des Paketes korrekt ist

            // Es wird geprüft ob ein Pakettyp angegeben wurde
            if(jsonEncodedPackage.hasOwnProperty('type') !== true) {
                dprinterror(10, ['Invalid packet received in session'], [colors.FgMagenta, _currentSessionId, colors.Reset, ','], ['session will be closed for security reasons.']);
                wsConnObject.close();
                return;
            };

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
            };
        });
    };

    // Nimmt eintreffende Pakete entgegen
    wsConnObject.on('message', (message) => {
        // Es wird geprüft ob ein Datensatz verfügbar ist
        if(message === undefined || message === null) {
            console.log('INVALID_DATA_RECIVED::CONNECTION_CLOSED');
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob es sich um ein Buffer handelt
        if(Buffer.isBuffer(message) !== true) {
            console.log('INVALID_DATA_RECIVED::INVALID_DATA_TYPE');
            _ADD_PACKAGE_RECIVED_INVALID(message);
            wsConnObject.close();
            return;
        }

        // Es wird Signalisiert das ein Paket empfangen wurde
        _ADD_PACKAGE_RECIVED(message);

        // Es wird geprüft ob mindestens 64 Bytes empfangen wurden
        if(message.length < 64) {
            console.log('INVALID_DATA_RECIVED_TO_SMALL');
            _ADD_PACKAGE_RECIVED_INVALID(message);
            wsConnObject.close();
            return;
        }

        // Es wird geprüft ob das Paket eine Maximalgröße überschritten wurde
        if(message.length > consensus.maximal_package_size) {
            console.log('PACKAGE_SIZE_TO_BIG_DROPED');
            _ADD_PACKAGE_RECIVED_INVALID(message);
            wsConnObject.close();
            return;
        }

        // Debug Print
        dprintok(10, ['Data packet with'], [colors.FgMagenta, message.length], ['bytes received via the websocket connection'], [colors.FgMagenta, _currentSessionId]);

        // Es wird geprüft ob die Verbindung bereits Initaliseirt wurde
        if(_connectionIsInited === true) _ENTER_PACKAGE_ON_INITED_CONNECTION(message);
        else _ENTER_PACKAGE_ON_NOT_INITED_CONNECTION(message);
    });

    // Wird ausgeführt, wenn die Verbindung geschlossen wurde
    wsConnObject.on('close', () => _CLOSE_CONNECTION());

    // Wird ausgeführt, nachdem das Pong Paket empfangen wurde
    wsConnObject.on('pong', (packageInnerValue) => {
        // Es wird geprüft ob die Verbindung besteht
        if(!_isConnected) return;

        try{
            // Es wird versucht die Aktuelle ID einzulesen
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
};

// Baut eine ausgehende Verbindung auf
const wsConnectTo = (socketKeyPair, localeNodeObject, serverUrl, sfunctions=[], accepted_functions=['boot_node'], callback=null, connectionClosedCallback=null) => {
    // Das Websocket Objekt wird vorbereitet
    const ws = new WebSocket(serverUrl, ['ABC']);

    // Speichert das Inited Objekt ab
    var _initedObject = null;

    // Wird ausgeführt wenn die Verbindung hergestellt wurde
    ws.on('open', () => {
        dprintok(10, ['New outgoing websocket connection established with'], [colors.FgMagenta, serverUrl]);
        _initedObject = wsConnection(socketKeyPair, localeNodeObject, ws, serverUrl, false, sfunctions, accepted_functions, callback, connectionClosedCallback);
    });

    // Wird bei einem Fehler ausgeführt
    ws.on('error', () => {
        if(_initedObject !== null) { _initedObject.close(); }
        else { if(connectionClosedCallback !== null) { connectionClosedCallback(); } }
    });
};

// Erstellt einen neuen Lokalen Server
const wsServer = (socketKeyPair, localeNodeObject, localPort, localIp, sslcert=null, sfunctions=[]) => {
    // Es wird ein ID für deas Serverobjekt erzeugt
    const objId = v4();

    // Der Webserver wird gestartet
    const wss = new WebSocketServer({ port: localPort, maxPayload:consensus.maximal_package_size });

    // Nimmt neue Verbindungen entgegen
    wss.on('connection', (ws, req) => {
        // Es wird ermittelt ob es sich um eine IPv4 oder IPv6 Adresse handelt
        const parsedPeerIpAddress = parsIpAddress(req.socket.remoteAddress);
        if(parsedPeerIpAddress === null) { return; }

        // Die Adresse des Clients wird ermittelt
        const varEpIp = (parsedPeerIpAddress.ver === 'ipv4') ? parsedPeerIpAddress.adr : `[${parsedPeerIpAddress.adr}]`;
        const newUrlAddress = `ws://${varEpIp}:${req.socket.remotePort}`

        // Es wird geprüft ob der Client einen Vorgangsheader angegeben hat
        if(req.headers.hasOwnProperty('sec-websocket-protocol') === true) {
            // Es wird geprüft ob es sich um einen gültigen Vorgangsheader handelt
            const sockWebsockProt = req.headers['sec-websocket-protocol'].split(',');

            // Es wird geprüft ob es sich um gültige Angaben handelt
            for(const otem of sockWebsockProt) {

            };
        }

        // Debug
        dprintok(10, ['Accepted new incoming websocket connection from'], [colors.FgMagenta, req.socket.remoteAddress]);

        // Die Verbindung wird erstellt
        wsConnection(socketKeyPair, localeNodeObject, ws, newUrlAddress, true, sfunctions);
    });

    // Gibt das Serverobjekt zurück
    dprintok(10, ['New websocket server created on'], [colors.FgMagenta, localPort], ['with id'], [colors.FgCyan, objId]);
    return {
        _id:objId,
        type:'ws',
        port:localPort,
        ip:(localIp === null) ? '*' : localIp, 
        startedSince:Date.now(),
        keyPair:socketKeyPair,
        close:() => {

        },
    };
};


// Exportiert alle Funktionen
module.exports = {
    wsConnectTo:wsConnectTo,
    wsServer:wsServer 
};