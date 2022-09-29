const { dprinterror, dprintok, colors, dprintwarning, dprintinfo } = require('./debug');
const { getHashFromDict } = require('./crypto');
const consensus = require('./consensus');
const crypto = require('crypto');


// Gibt alle möglichen Statuse an
const ADR_EP_STATES = {
    NO_ACTIVE_ROUTES_FROZEN:0,          // Keine Aktiven Routen verfügbar, alle Sockets werden eingefroren und neue Verbindungsanfragen werden in den Wartemodus versetzt
    KILLING_SOCKETS:1,                  // Alle Sockets werden geschlossen, neue Socketanfragen werden abgelehent
    CLOSED:2,                           // Die Adresse muss neu Initalisiert werden, da keine Routen mehr Verfügbar sind
    OPEN:3,                             // Gibt an dass das Objekt verwendet werden kann
    ABORTED:4,                          // Gibt an das der Initalisierungsvorgang fehgeschlagen ist
    INITING:5                           // Gibt an dass das Objekt sich in der Vobereitung befindet
};

// Stellt einen Address to Adress RAW EndPoint dar
const addressRawEndPoint = async (rawFunctions, routeEP, localNodePrivateKey, sourcePrivateKey, destinationPublicKey, crypto_functions, socketConfig, rcb, outRouteEp=true) => {
    // Es wird geprüft ob eine Route verfügbar ist
    if(!(await routeEP.isUseable())) { return 'unkown_route_for_address'; }

    // Speichert Offene Ping Vorgänge ab
    const _openPingProcesses = new Map();

    // Speichert alle Offenen Sockets ab
    const _openSockets = new Map();

    // Speichert den Aktuellen Stauts ab
    let objectState = ADR_EP_STATES.INITING;

    // Speichert alle offene Sendevorägnge ab
    let openPackageSendProcess = [];

    // Speichert ab, wann das letzte Paket versendet wurde
    let lastPackageSendSuccs = null;

    // Wird verwendet um allen Vorägngen zu Signalisieren dass derzeit keine Routen mehr Verfügbar sind, alle Sockets werden geschlossen
    const _NO_ROUTES_EVENTS = (cb) => {
        console.log(_openPingProcesses, _openSockets)

        // Es werden alle Offenen Ping Vorgänge geschlossen
        for(const otem of Array.from(_openPingProcesses)) {
            const objtemp = _openPingProcesses.get(otem);
            if(objtemp === null) continue;
            objtemp.close();
        };

        // Es werden alle Offenen Sockets geschlossen
        for(const otem of Array.from(_openSockets.keys())) {

        };

        cb();
    };

    // Wird ausgeführt wenn keine Peer für diese Adresse verüfgbar ist
    routeEP.registerEvent('allRoutesForAddressClosed', () => {
        // Dem Objekt wird Signalisiert dass keine Route verfüfbar ist
        objectState = ADR_EP_STATES.KILLING_SOCKETS;

        // Der Callback vorgang wird aufgerufen
        _NO_ROUTES_EVENTS(() => {
            // Dem Objekt wird Signalisiert dass es erfolgreich geschlossen wurde
            objectState = ADR_EP_STATES.CLOSED;
        });
    });

    // Signiert ein Paket mit dem Lokalen Schlüssel
    const _SIGN_DIGEST_WLSKEY = (pk, digestValue) => {
        const sig = crypto_functions.ed25519.sign(digestValue, pk.privateKey);
        return { sig:sig, pkey:pk.publicKey }
    };

    // Signiert ein PreBuilded Object und gibt ein Fertiges Objekt aus
    const _SIGN_PRE_PACKAGE = (prePackage) => {
        // Das Paket wird Signiert
        const packageSig = _SIGN_DIGEST_WLSKEY(localNodePrivateKey, getHashFromDict(prePackage));

        // Das Finale Paket wird Signiert
        return Object.assign(prePackage, { pkey:Buffer.from(packageSig.pkey).toString('hex'), sig:Buffer.from(packageSig.sig).toString('hex') });
    };

    // Signiert ein Frame und fügt den Empfänger sowie den Absender hinzu
    const _COMPLETE_UNSIGNATED_FRAME = (encryptedFrameData, clearFrameData={}) => {
        // Es wird ein Zufällige Nonce erstellt
        const randomNocne = crypto.randomBytes(24);

        // Die Daten zum verschlüssel werden verschlüsselt
        const encryptedData = encryptedFrameData;

        // Das Paket wird vorbereitet
        const preLayer2Frame = {
            crypto_algo:'ed25519_salsa20_poly1305',
            source:Buffer.from(sourcePrivateKey.publicKey).toString('hex'),
            destination:destinationPublicKey,
            body:{ nonce:randomNocne.toString('base64'), ebody:encryptedData, pbody:clearFrameData } 
        };

        // Das Paket wird Signiert
        const packageSig = _SIGN_DIGEST_WLSKEY(sourcePrivateKey, getHashFromDict(preLayer2Frame));

        // Das Finale Paket wird Signiert
        return { ...preLayer2Frame, ssig:Buffer.from(packageSig.sig).toString('hex') };
    };

    // Wird verwendet um ein nicht Signiertes Frame zu Signieren und abzusenden
    const _SEND_COMPLETED_LAYER2_FRAME = (sigantedFrame, socketobj=null, callback=null) => {
        // Das Layer 1 Paket wird gebaut
        const prePackage = { crypto_algo:'ed25519', type:'pstr', version:consensus.version, frame:sigantedFrame };

        // Das Paket wird Signiert
        const signatedPackage = _SIGN_PRE_PACKAGE(prePackage);

        // Es wird ein neuer Sendevorgang erzeugt
        const sendProcess = crypto.randomBytes(24).toString('hex');

        // Der Aktuelle Sendevorgang wird zwischengespeichert
        openPackageSendProcess.push(sendProcess);

        // Versendet das eigentliche Paket
        const _SEND_PACKAGE = (sockoob) => {
            // Das Paket wird an den Übergebenen Socket gesendet
            sockoob.enterPackage(signatedPackage, (r, porcTime) => {
                // Es wird geprüft ob der Vorgang erfolreich war
                if(r !== true) {
                    // Der Offene Vorgang wird entfernt
                    openPackageSendProcess = openPackageSendProcess.filter((ele) => { return ele != sendProcess; });

                    // Der Vorgang wird abgerbrochen
                    callback(false);
                    return; 
                }

                // Die Zeit wann das Paket versende wurde wird gesetzt
                const currentTimeStamp = Date.now();
                if(lastPackageSendSuccs !== null) {
                    if(currentTimeStamp > lastPackageSendSuccs) { lastPackageSendSuccs = currentTimeStamp; }
                }
                else { lastPackageSendSuccs = currentTimeStamp; }

                // Dem Routingmanager wird Signalisiert, wann das Paket empfangen wurde
                routeEP.signalPackageSend(sigantedFrame.source, sockoob, Date.now())
                .then(() => {
                    // Der Vorgang wird entfernt
                    openPackageSendProcess = openPackageSendProcess.filter((ele) => { return ele != sendProcess; });

                    // Der Vorgang wurde erfolgreich fertigestellt
                    callback(r, sockoob.cttl, porcTime, sockoob.sessionId());
                });
            });
        };

        // Es wird geprüft ob ein Socketobjekt angegeben wurde, wenn nicht wird geprüft ob die Primäre Route bekannt ist
        if(socketobj !== null) { _SEND_PACKAGE(socketobj); }
        else {
            // Es wird geprüft wie der Objektstatus ist, sollte er nicht Offen sein, wird der Vorgang abgebrochen
            if(objectState !== ADR_EP_STATES.OPEN) {
                // Der Vorgang wird entfernt
                openPackageSendProcess = openPackageSendProcess.filter((ele) => { return ele != sendProcess; });

                // Der Vorgang wird abgebrochen, der socket wurde noch nicht Vollständig eingerichtet oder ist nicht mehr bereit
                callback('no_route_avail');
                return;
            }

            // Es wird versucht die Schnellste Route zu ermitteln
            routeEP.getOptimalRouteEndPoint().then((optmusRoute) => {
                // Es wird geprüft ob der Vorgang erfolgreich durchgeführt werden konnte
                if(optmusRoute === null) {
                    // Der Vorgang wird entfernt
                    openPackageSendProcess = openPackageSendProcess.filter((ele) => { return ele != sendProcess; });

                    // Der Vorgang konnte nicht fertigestellt werden
                    callback('no_route_avail');
                    return; 
                }

                // Das Paket wird gesendet
                _SEND_PACKAGE(optmusRoute);
            })
        }
    };

    // wird verwendet um eintreffende Pakete entgegen zu nehemen
    const _ENTER_INCOMMING_PACKAGE = (package, connObj, packageInCallback=null) => {
        // Es wird geprüft ob der Absender korrekt ist
        if(package.source !== destinationPublicKey.toString('hex')) {
            if(packageInCallback !== null) { packageInCallback(false); }
            console.log('SECURITY_ERROR_PACAKGE_DROPED');
            return;
        }

        // Die Verschlüsselten Bodydaten werden entschlüsselt
        const decryptedBodyData = package.body.ebody;

        // Es wird geprüft ob ein Pakettyp angegeben wurde
        if(decryptedBodyData.hasOwnProperty('type') === false) {
            if(packageInCallback !== null) { packageInCallback(false); }
            return;
        }

        // Es wird geprüft ob ein RAW Socket auf dieser Verbindung liegt, wenn ja wird das Paket an den RAW Socket weitergegeben

        // Es wird geprüft ob es sich um ein Pong Paket handelt
        if(decryptedBodyData.type === 'pong') {
            if(packageInCallback !== null) { packageInCallback(true); }

            // Es wird ein Hash aus dem packRHash erstellt
            const packRDHash = crypto.createHash('sha256').update(Buffer.from(decryptedBodyData.packRHash, 'hex')).digest('hex');

            // Es wird geprüft ob es einen bekannten offenen Vorgang gibt
            const fetchedOpenPingProcess = _openPingProcesses.get(packRDHash);
            if(fetchedOpenPingProcess !== undefined) { fetchedOpenPingProcess.callResponse(connObj); }
            else { console.log('PONG_PACKAGE_DROPED'); }
        }

        // Es wird geprüft ob es sich um ein Datagram handelt

        // Es wird geprüft ob es sich um eine Sitzung handelt

        else {
            if(packageInCallback !== null) { packageInCallback(false); }
            return;
        }
    };

    // Startet einen Ping vorgang
    const _START_PING_PROCESS = (bodySize, socketobj, strict, callback) => {
        // Es wird ein zufälliger Wert erzeugt
        const randomByteValues = crypto.randomBytes(bodySize);

        // Das Frame wird erstellt
        const baseFrame = { type:'ping', rdata:randomByteValues.toString('base64'), strict:strict };
        const finallyFrame = _COMPLETE_UNSIGNATED_FRAME(baseFrame);

        // Aus dem RandomHash werden 2 hashes erzeugt
        const frstRandHash = crypto.createHash('sha256').update(randomByteValues).digest();
        const secRandHash = crypto.createHash('sha256').update(frstRandHash).digest('hex');

        // Speichert den Aktuellen Timer ab, welcher wartet bis die Ablaufzeit abgelaufen ist
        let _OPEN_WAIT_RESPONSE_TIMER = null;

        // Gibt die Zeit an, wielange es gedauert hat, bis es eine Antwort für den Ping gab
        let _PING_PACKAGE_SEND_TIME = null;

        // Speichert die SessionID ab, an welche das Paket übertragen wurde
        let _SEND_OVER_SESSION_ID = null;

        // Wird als Timer ausgeführt, wenn die Zeit abgelaufen ist, der Vorgang wird zerstört
        const _TIMER_FUNCTION_PROC = () => {
            if(_openPingProcesses.delete(secRandHash) === true) {
                routeEP.signalLossPackage(_SEND_OVER_SESSION_ID)
                .then(() => {
                    callback(false, null, Buffer.from(secRandHash, 'hex').toString('base64'));
                })
            }
        };

        // Wird aufgerufen, wenn eine Antwort für den Ping eingetroffen ist
        const _RESPONSE = (connObj) => {
            // Es wird geprüft ob der Vorgang geöffnet ist
            if(_openPingProcesses.get(secRandHash) === undefined) {
                console.log('PONG_PACKAGE_DROPED');
                return;
            }

            // Sofern vorhanden wird der Timer gestoppt
            if(_OPEN_WAIT_RESPONSE_TIMER !== null) { clearTimeout(_OPEN_WAIT_RESPONSE_TIMER); _OPEN_WAIT_RESPONSE_TIMER = null; }

            // Der Vorgang wird gelöscht
            _openPingProcesses.delete(secRandHash);

            // Die benötigte Zeit wird ermittelt
            const pingreqTime = Date.now() - _PING_PACKAGE_SEND_TIME;

            // Dem Cache wird die neue Pingzeit für diese Route mitgeteilt
            routeEP.avarageInitPingTime(destinationPublicKey, connObj.sessionId(), pingreqTime)
            .then(() => {
                callback(true, pingreqTime, Buffer.from(secRandHash, 'hex').toString('base64'));
            });
        };

        // Beendet den Ping Vorgang Manuell
        const _CLOSE = () => {
            if(_openPingProcesses.delete(secRandHash) === true) {
                if(_OPEN_WAIT_RESPONSE_TIMER !== null) { clearTimeout(_OPEN_WAIT_RESPONSE_TIMER); _OPEN_WAIT_RESPONSE_TIMER = null; }
                dprintwarning(10, ['The ping process'], [colors.FgRed, getHashFromDict(finallyFrame).toString('base64')], ['was forced to end.']);
                callback(false, null, Buffer.from(secRandHash, 'hex').toString('base64'));
            }
        };

        // Speichert den Ping Vorgang ab
        _openPingProcesses.set(secRandHash, { callResponse:_RESPONSE, close:_CLOSE });

        // Das Ping Paket wird versendet
        dprintinfo(10, ['The ping packet'], [colors.FgRed, getHashFromDict(baseFrame).toString('base64')], ['is sent']);
        _SEND_COMPLETED_LAYER2_FRAME(finallyFrame, socketobj, (state, tttl, ptime, sendSessionId) => {
            // Es wird geprüft ob der Ping Vorgang erfolgreich durchgeführt wurde
            if(state !== true) {
                // Der Vorgang wird gelöscht
                _openPingProcesses.delete(secRandHash);
                callback(false, state, Buffer.from(secRandHash, 'hex').toString('base64'));
                return;
            }

            // Speichert die SessionID ab, an welche das Paket gesendet wurde
            _SEND_OVER_SESSION_ID = sendSessionId;

            // Speichert die Zeit ab, wann das Paket empfangen wurde
            _PING_PACKAGE_SEND_TIME = Date.now();

            // Der Timer für diesen Ping wird gestartet
            _OPEN_WAIT_RESPONSE_TIMER = setTimeout(_TIMER_FUNCTION_PROC, tttl);

            // Log
            dprintinfo(10, ['The ping packet'], [colors.FgRed, getHashFromDict(baseFrame).toString('base64')], ['sent in'], [colors.FgMagenta, ptime], ['ms, ttl ='], [colors.FgMagenta, tttl]);
        });
    };

    // Führt den Initaliserungsping aus, die 2 Schnellsten Routen werden ermittelt
    const _FETCH_FASTED_ROUTES_PING = async (cbrt) => {
        // Die Schnellsten Routen werden vom Routing Manager abgerufen
        let froutes = await routeEP.getBestRoutes();

        // Gibt an ob das erste Paket empfangen wurde
        let firstRongRecives = null, currentPackage = 0, totalSuccs = 0, notResolved = 0;

        // Es wird geprüft ob Routen mit einem InitPing abgerufen werden konnten, wenn nicht werden alle bekannten Routen abgerufen
        if(froutes === null) {
            // Es konnten eine Routen mit InitPingTime ermittelt werden
            froutes = await routeEP.getAllPeers();

            // Es wird geprüft ob alternative Routen abgerufen werden konnten
            if(froutes === null) { cbrt('no_routes_for_address'); return; }
        }

        // Das Paket wird an die einzelenen Nodes gesendet
        for(const routeItem of froutes) {
            _START_PING_PROCESS(consensus.routingPingPackage, routeItem, true, (state, pTime, procHash) => {
                // Es wird ein Vorgang raufgezählt
                currentPackage += 1;

                // Es wird geprüft ob der Vorgang erfolgreich durchgeführt werden konnte
                if(state === true) {
                    // Es wird geprüft ob es sich um das erste Paket handelt
                    if(firstRongRecives === null) {
                        // Die Paketanzahl wird hochgezählt
                        totalSuccs += 1;

                        // Die Aktuelle Zeit wird ermittelt
                        firstRongRecives = Date.now();

                        // Das Objekt wird als Einsatzfähug Makiert
                        objectState = ADR_EP_STATES.OPEN;

                        // Der Vorgang wurde erfolgreich durchgeführt
                        cbrt(true, pTime, firstRongRecives, procHash);
                    }
                }
            });

            // Es wird geprüft ob bereits eine Antwort empfangen wurde, wenn ja wird der Vorgang abgebrochen
            if(firstRongRecives !== null) break;
        }
    };

    // Wird verwendet um ein Layer 3 Paket zu versenden
    const _GET_SOCKET_IO_FUNCTIONS = (localport, destport, callback) => {
        // Wird verwendet um ein Layer 3 Paket zu versenden
        const _SEND_LAYER_THREE_SOCKET_PACKAGE = (data, pckret) => {
            // Das Basispaket wird gebaut
            const layer3Frame = { sport:localport, dport:destport, data:data };

            // Das Frame wird erstellt
            const finallyFrame = _COMPLETE_UNSIGNATED_FRAME({ type:'nxt', body:layer3Frame });

            // Es wird versucht das Paket abzusenden
            _SEND_COMPLETED_LAYER2_FRAME(finallyFrame, null, pckret);
        };

        // Das Objekt wird zurückgegeben
        callback({ sendData:_SEND_LAYER_THREE_SOCKET_PACKAGE });
    };

    // Gibt die Basis Funktionen zurück
    const _BASE_FUNCTIONS = {
        getState:() => objectState,
        socket:{
            getSocketIo:(localport, destport, callback) => _GET_SOCKET_IO_FUNCTIONS(localport, destport, callback)
        },
        ping:{
            ssingle:(callb, bsize=96, strict=false) => _START_PING_PROCESS(bsize, null, strict, callb),
        }, 
    };

    // Es wird geprüft ob eine Route für die Adresse vorhanden ist
    routeEP.isUseable().then(async (r) => {
        // Es wird geprüft ob der Vorgang genutzt werden kann
        if(r !== true) { rcb('no_routes_avail'); return; }

        // Die Routing Sychnronisierung wird durchgeführt
        await _FETCH_FASTED_ROUTES_PING((froutes) => {
            // Es wird geprüft ob der Vorgang erfolgreich durchgeführt werden konnte
            if(froutes !== true) { rcb('no_fast_routes_avail'); return; }

            // Der Status des Paketes wird auf geöffnet gesetzt
            objectState = ADR_EP_STATES.OPEN;

            // Der Vorgang wurde erfolgreich druchgeführt
            rcb(null, _BASE_FUNCTIONS);
        });
    });

    // Es wird versucht die Primäre
    return { 
        enterPackage:_ENTER_INCOMMING_PACKAGE,
        routeEp:() => _BASE_FUNCTIONS
    };
};


module.exports = { addressRawEndPoint:addressRawEndPoint, bfunctions:null };