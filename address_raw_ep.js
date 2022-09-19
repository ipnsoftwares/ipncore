const { dprinterror, dprintok, colors, dprintwarning } = require('./debug');
const { getHashFromDict } = require('./crypto');
const consensus = require('./consensus');
const crypto = require('crypto');


// Gibt alle möglichen Statuse an
const ADR_EP_STATES = {
    NO_ACTIVE_ROUTES_FROZEN:0,          // Keine Aktiven Routen verfügbar, alle Sockets werden eingefroren und neue Verbindungsanfragen werden in den Wartemodus versetzt
    KILLING_SOCKETS:1,                  // Alle Sockets werden geschlossen, neue Socketanfragen werden abgelehent
    REINIT:2,                           // Die Adresse muss neu Initalisiert werden, da keine Routen mehr Verfügbar sind
    OPEN:3,                             // Gibt an dass das Objekt verwendet werden kann
    ABORTED:4,                          // Gibt an das der Initalisierungsvorgang fehgeschlagen ist
};

// Stellt einen Address to Adress RAW EndPoint dar
const addressRawEndPoint = async (rawFunctions, routeEP, localNodePrivateKey, sourcePrivateKey, destinationPublicKey, crypto_functions, socketConfig, rcb) => {
    // Es wird geprüft ob eine Route verfügbar ist
    if(!await routeEP.isUseable()) { return 'unkown_route_for_address'; }

    // Speichert die Primäre sowie falls vorhanden sie Sekundäre Route ab
    let primaryRoute = null, secondaryRoute = null;

    // Speichert den SYNC Route Timer ab
    let syncRouteTimer = null;

    // Gibt an in welchem Zustand sich das Objekt befindet
    let objectState = null;

    // Speichert den Timer ab, welcher ein ReRoute durchführt
    let reRouteTimer = null;

    // Speichert Offene Ping Vorgänge ab
    const _openPingProcesses = new Map();

    // Speichert alle Verfügbaren Sockets ab
    const _openEndPointSockets = new Map();

    // Zerstört das Gesamte Objekt
    const _DESTROY_OBJECT = () => {

    };

    // Wird verwendet um alle Sockets einzufrieren
    const _FROZE_ALL_SOCKETS = () => {
        console.log('FROZE_ALLE_SOCKETS');
    };

    // Wird verwendet um alle Sockets zu schließen
    const _CLOSE_ALL_SOCKETS = (reason=null, callback=null) => {
        console.log('CLOSE_ALL_SOCKETS')
    };

    // Wird verwenet um die Aktuell Verfügbaren Peers abzurufen
    const _FETCH_FASTED_PEERS = (rbackAfterFetch) => {
        // Es wird geprüft in welchem Status sich das Objekt befindet, der Status muss NULL sein
        if(objectState !== null) {
            // Der Vorgang wird abgebrochen, das Objekt wurde bereits Initalisiert
            return;
        }

        // Es werden die Schnellsten Peers, sortiert nach Route Init Time abgerufen
        routeEP.getAllPeers()
        .then((r) => {
            // Es wird geprüft ob es passende EndPunkte gibt
            if(r.length === 0) { rbackAfterFetch(false); return; }

            // Es werden die 4 Schnellsten Peers herausgesucht
            if(r.length > 2) { searchedPeers = r.subarray(0, 4); }
            else { searchedPeers = r; }

            // Die Pakete werden an die Peers gesendet
            let currentResponse = 0, hasReturned = false, failedReturns = 0, dopedReturns = 0;
            for(const otem of searchedPeers) {
                // An den Peer wird ein Ping Paket gesendet
                _START_PING_PROCESS(64, otem, (rstae, rtime, pingid) => {
                    // Es wird geprüft ob der Vorgang erfolgreich war
                    if(rstae !== true) {
                        // Der Fehlercounter wird hochgezählt
                        failedReturns += 1;

                        // Es wird geprüft, weiviele Pakete fehlgeschalgen sind zu senden
                        if(failedReturns === searchedPeers.length && hasReturned == false) {
                            // Der Eintrag wird als returned markiert
                            hasReturned = true;

                            // Das Callback wird aufgerufen
                            rbackAfterFetch(false);
                        }

                        // Der Vorgang wird beendet
                        return;
                    }

                    // Es wird Signalisiert das 1 Paket empfangen wurde
                    currentResponse += 1;

                    // Debug Log
                    dprintok(10, ['Pong packet'], [colors.FgMagenta, pingid], ['received']);

                    // Es wird geprüft ob es sich um die erste oder zweite Antwort handelt
                    if(primaryRoute === null && secondaryRoute === null) {
                        // Die Primäre Route wird abgespeichert
                        primaryRoute = { ep:otem, ping:rtime, ftime:Date.now() };

                        // Es wird Signalisiert dass der Vorgang erfolgreich durchgeführt wurde
                        if(hasReturned !== true && currentResponse == 1) {
                            // Es wird Signalisiert dass eine Antwort empfangen wurde
                            hasReturned = true;

                            // Die Callback Funktion wird aufgerufen
                            rbackAfterFetch(true);
                            return;
                        }
                    }
                    else if(primaryRoute !== null && secondaryRoute === null) {
                        // Die Primäre Route wird abgespeichert
                        secondaryRoute = { ep:otem, ping:rtime, ftime:Date.now() };

                        // Es wird Signalisiert dass der Vorgang erfolgreich durchgeführt wurde
                        if(hasReturned !== true && currentResponse == 1) {
                            // Es wird Signalisiert dass eine Antwort empfangen wurde
                            hasReturned = true;

                            // Die Callback Funktion wird aufgerufen
                            rbackAfterFetch(true);
                            return;
                        }
                    }
                    else {
                        // Weiteren Pakete werden verworfen, da bereits 2 Routen ermittelt wurden
                        dprintok(10, ['Pong packet'], [colors.FgMagenta, pingid], ['received and droped, has always a primary and secondary route.']);
                        dopedReturns += 1;
                    }
                });
            }
        });
    };

    // Wird aller 5 Sekunden als Timer ausgeführt und Aktuallisiert die Verbindungen nach geschwindigkeit
    const _SYNC_ROUTE_PROCESS_TIME = () => {
        // Es wird geprüft wie der Status des Objektes ist
        if(objectState === ADR_EP_STATES.OPEN) {
            // Es wird geprüft wann das letztemal Daten Empfangen und gesendet wurden
            
        }
    };

    // Wird als ReRoute ausgeführt um eine neue Route für den Vorgang zu Initaliseren
    const _REROUTE_ADDRESS = (callback) => {
        // Es wird geprüft ob Peers verfügbar sind, wenn ja wird ein Routing Prozess gestartet
        if(rawFunctions.totalPeers() >= 1) {
            // Es wird geprüft ob die
            callback(false);
            return;
        }

        // Es sind keine Peers verfügbar
        callback(false);
    };

    // Wird ausgeführt, wenn keine Route mehr Verfügbar ist
    const _NO_ROUTE_AVAIL_EVENT = async () => {
        // Der Aktuelle Stauts des Objektes wird geändert
        objectState = ADR_EP_STATES.NO_ACTIVE_ROUTES_FROZEN;

        // Alle Sockets werden eingefroren
        _FROZE_ALL_SOCKETS();

        // Die Routen werden geleert
        primaryRoute = null;
        secondaryRoute = null;

        // Der SYNC Timer wird gestoppt
        if(syncRouteTimer !== null) { clearTimeout(syncRouteTimer); syncRouteTimer = null; }

        // Debug Meldung
        dprinterror(10, ['There is no active route available for address'], [colors.FgYellow, destinationPublicKey, colors.Reset, '.'])

        // Speichert ab, wann der Prozess begonnen hat
        const procstime = Date.now();

        // Es wird ein Timer gestartet, welcher 5 Sekunden wartet bis er versucht eine neue Route zu Initalisieren
        reRouteTimer = setTimeout(() => {
            // Speichert ab, der wievielste Vorgang es ist
            let currentProccs = 0;

            // Der ReRoute vorgang wird durchgeführt
            const _rpt = () => {
                _REROUTE_ADDRESS((state) => {
                    // Es wird ein Vorgang hochgezählt
                    currentProccs += 1;

                    // Es wird geprüft ob der Vorgang durchgeführt werden konnte
                    if(state === true) {

                    }
                    else {
                        // Es wird geprüft ob es Offene Sockets gibt
                        if(new Array(_openEndPointSockets.keys()).length > 0) {
                            // Es wird geprüft ob es sich um den 4ten Versuch handelt, wenn ja werden alle Offenen Vorgänge geschlossen
                            if(currentProccs >= 4) {
                                // Der Vorgang wird endgültig abgebrochen, es werden alle Socket verbindungen geschlossen
                                _CLOSE_ALL_SOCKETS(null, () => {
                                    // Das Objekt wird in den REINIT Modus versetzt
                                    objectState = ADR_EP_STATES.REINIT;

                                    // Der Vorgang wird neugestartet
                                    reRouteTimer = setTimeout(_rpt);
                                });
                            }
                            else {
                                // Der Vorgang wird neugestartet
                                reRouteTimer = setTimeout(_rpt);
                            }
                        }
                        else {
                            // Der Vorgang wird neugestartet
                            reRouteTimer = setTimeout(_rpt);
                        }
                    }
                });
            };
            _rpt();
        }, 5000);
    };

    // Wird ausgeführt wenn keine Peer für diese Adresse verüfgbar ist
    routeEP.registerEvent('onDeleteRoute', async (addrPublicKey, deletedSessionId) => {
        // Es wird geprüft ob die 

        // Wird ausgeführt wenn die Primäre Route geschlossen wurde
        const _CLOSED_PRIM_ROUTE = async () => {
            if(primaryRoute !== null && primaryRoute.ep.sessionId === deletedSessionId) {
                // Debug Meldung
                dprintwarning(10, ['The primary route'], [colors.FgMagenta, deletedSessionId], ['for address'], [colors.FgYellow, addrPublicKey], ['has been closed.'])

                // Es wird geprüft ob eine Sekundäre Verbindung verfügbar ist
                if(secondaryRoute !== null) {
                    // Die Primäre Route wird durch die Sekundäre Route ausgetauscht
                    dprintok(10, ['The secondary route'], [colors.FgMagenta, secondaryRoute.ep.sessionId], ['for the address'], [colors.FgYellow, addrPublicKey], ['was used as the primary route.'])
                    primaryRoute = secondaryRoute;
                    secondaryRoute = null;
                }
                else await _NO_ROUTE_AVAIL_EVENT();
            }
        };

        // Wird ausgeführt wenn die Sekundäre Route geschlossen wurde
        const _CLOSED_SEC_ROUTE = async () => {
            if(secondaryRoute !== null && secondaryRoute.ep.sessionId === deletedSessionId) {
                // Debug Meldung
                dprintwarning(10, ['The secondary route'], [colors.FgMagenta, deletedSessionId], ['for address'], [colors.FgYellow, addrPublicKey], ['has been closed.'])

                // Die Alternative Route wird entfernt
                secondaryRoute = null;
            }
            else {
                if(primaryRoute !== null && primaryRoute.ep.sessionId) await _CLOSED_PRIM_ROUTE();
            }
        };

        // Es wird geprüft um welche Sitzung es sich handelt
        if(primaryRoute !== null && primaryRoute.ep.sessionId === deletedSessionId) await _CLOSED_PRIM_ROUTE();
        else await _CLOSED_SEC_ROUTE();
    });

    // Wir ausgeführt sobald ein Peer für diese Verbindung verfügbar ist
    routeEP.registerEvent('onAddNewRoute', async () => {
        // Es wird geprüft ob derzeit ein Peer verfügbar ist, wenn nicht wird ein Ping an den Aktuellen Peer gesendet
        console.log('ADD_EP');
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

        // Es wird geprüft ob ein Socketobjekt angegeben wurde, wenn nicht wird geprüft ob die Primäre Route bekannt ist
        if(socketobj !== null) {
            // Das Paket wird an den Übergebenen Socket gesendet
            socketobj.enterPackage(signatedPackage, (r) => callback(r));
        }
        else {
            // Es wird geprüft ob eine Primäre Verbindung verfügbar ist
            if(primaryRoute !== null) {
                // Das Paket wird an die Primäre Verbindung gesendet
                primaryRoute.ep.enterPackage(signatedPackage, (r) => callback(r));
            }
            else {
                // Es wird geprüft ob eine Alternative Sekundäre verbindung verfügbar ist, wenn nicht wird der Vorgang abgebrochen
            }
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
            if(fetchedOpenPingProcess !== undefined) { fetchedOpenPingProcess.callResponse(); }
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
    const _START_PING_PROCESS = (bodySize, socketobj=null, callback) => {
        // Es wird ein zufälliger Wert erzeugt
        const randomByteValues = crypto.randomBytes(bodySize);

        // Das Frame wird erstellt
        const finallyFrame = _COMPLETE_UNSIGNATED_FRAME({ type:'ping', rdata:randomByteValues.toString('base64') });

        // Aus dem RandomHash werden 2 hashes erzeugt
        const frstRandHash = crypto.createHash('sha256').update(randomByteValues).digest();
        const secRandHash = crypto.createHash('sha256').update(frstRandHash).digest('hex');

        // Speichert den Aktuellen Timer ab, welcher wartet bis die Ablaufzeit abgelaufen ist
        let _OPEN_WAIT_RESPONSE_TIMER = null;

        // Gibt die Zeit an, wielange es gedauert hat, bis es eine Antwort für den Ping gab
        let _PING_PACKAGE_SEND_TIME = null;

        // Wird als Timer ausgeführt, wenn die Zeit abgelaufen ist
        const _TIMER_FUNCTION_PROC = () => {
            // Der Vorgang wird gelöscht
            _openPingProcesses.delete(secRandHash);
            callback(false, null, Buffer.from(secRandHash, 'hex').toString('base64'));
        };

        // Wird aufgerufen, wenn eine Antwort für den Ping eingetroffen ist
        const _RESPONSE = () => {
            // Es wird geprüft ob der Vorgang geöffnet ist
            if(_openPingProcesses.get(secRandHash) === undefined) { console.log('PONG_PACKAGE_DROPED'); return; }

            // Sofern vorhanden wird der Timer gestoppt
            if(_TIMER_FUNCTION_PROC !== null) { clearTimeout(_OPEN_WAIT_RESPONSE_TIMER); _OPEN_WAIT_RESPONSE_TIMER = null; }

            // Der Vorgang wird gelöscht
            _openPingProcesses.delete(secRandHash);

            // Es wird Signalisiert dass ein Pong Paket empfangen wurde
            callback(true, Date.now() - _PING_PACKAGE_SEND_TIME, Buffer.from(secRandHash, 'hex').toString('base64'));
        };

        // Speichert den Ping Vorgang ab
        _openPingProcesses.set(secRandHash, { callResponse:_RESPONSE });

        // Das Ping Paket wird versendet
        _SEND_COMPLETED_LAYER2_FRAME(finallyFrame, socketobj, (state) => {
            // Es wird geprüft ob der Ping Vorgang erfolgreich durchgeführt wurde
            if(state !== true) {
                _openPingProcesses.delete(secRandHash);
                callback(false, 'package_sending_error', Buffer.from(secRandHash, 'hex').toString('base64'));
                return;
            }

            // Speichert die Zeit ab, wann das Paket empfangen wurde
            _PING_PACKAGE_SEND_TIME = Date.now();

            // Der Timer für diesen Ping wird gestartet
            _OPEN_WAIT_RESPONSE_TIMER = setTimeout(_TIMER_FUNCTION_PROC, 30000);
        });
    };

    // Wird verwendet um einen neuen Socket zu Registrieren
    const _REGISTER_NEW_SOCKET = (localEndPoint) => {

    };

    // Wird verwendet um den Aktuellen Stauts des Objekts auszugeben
    const _GET_OBJECT_STATE = () => {

    };

    // Gibt einen RAW Socket aus
    const _GET_RAW_SOCKET = () => {

    }

    // Gibt die Basis Funktionen zurück
    const _BASE_FUNCTIONS = {
        createNewSocket:_REGISTER_NEW_SOCKET,                   // Erzeugt einen neuen Socket
        getRawSocket:_GET_RAW_SOCKET,                           // Erzeugt einen neuen RAW-Socket
        getState:_GET_OBJECT_STATE,                             // Gibt den Aktuellen Status des Objektes aus
        ping:{
            
        },
        routes:{
            getPrimaryRoute:() => primaryRoute,                 // Gibt die Primäre Route aus
            getSecondaryRoute:() => secondaryRoute              // Gibt die Sekundäre Route aus
        }
    };

    // Es werden alle Verfügbaren Routen Initalisiert
    _FETCH_FASTED_PEERS((r) => {
        // Es wird geprüft ob der Vorgang erfolgreich durchgeführt wurde
        if(r === true) {
            // Der Aktuelle Status wird festgelegt
            objectState = ADR_EP_STATES.OPEN;

            // Der Auto Syncing Timer wird gestartet
            syncRouteTimer = setTimeout(_SYNC_ROUTE_PROCESS_TIME, 5000);

            // Es wird Signalisiert dass der Vorgang erfolgreich durchgeführt wurde
            rcb(null, _BASE_FUNCTIONS); 
        }
        else {
            // Der Aktuelle Stauts wird festgelegt
            objectState = ADR_EP_STATES.ABORTED;

            // Es konnte keine Route Initalisiert werden
            rcb('no_route_available'); 
        }
    });

    // Es wird versucht die Primäre
    return { enterPackage:_ENTER_INCOMMING_PACKAGE };
};


module.exports = { addressRawEndPoint:addressRawEndPoint }
