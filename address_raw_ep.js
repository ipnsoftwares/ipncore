const { dprinterror, dprintok, colors } = require('./debug');
const { getHashFromDict } = require('./crypto');
const consensus = require('./consensus');
const crypto = require('crypto');



// Stellt einen Address to Adress RAW EndPoint dar
const addressRawEndPoint = async (rawFunctions, routeEP, localNodePrivateKey, sourcePrivateKey, destinationPublicKey, crypto_functions, socketConfig, rcb) => {
    // Es wird geprüft ob eine Route verfügbar ist
    if(!await routeEP.isUseable()) { return 'unkown_route_for_address'; }

    // Speichert die Primäre Route ab
    let primaryRoute = null;

    // Speichert die Sekundären Routen ab
    let secondaryRoutes = [];

    // Speichert den SYNC Route Timer ab
    let syncRouteTimer = null;

    // Speichert Offene Ping Vorgänge ab
    const _openPingProcesses = new Map();

    // Gibt an in welchem Zustand sich das Objekt befindet
    const _objectState = null;

    // Wird verwenet um die Aktuell Verfügbaren Peers abzurufen
    const _FETCH_FASTED_PEERS = (rbackAfterFetch) => {
        routeEP.getAllPeers()
        .then((r) => {
            // Es wird geprüft ob es passende EndPunkte gibt
            if(r.length === 0) { rbackAfterFetch(false); return; }

            // Es wird geprüft ob alternative Verbindungen vorhanden sind, wenn ja wird der Vorgang abgebrochen, es dürfen keine Peers mehr Vorhanden sein
            secondaryRoutes = [];

            // Es werden die 2 Schnellsten Peers herausgesucht
            if(r.length > 2) { searchedPeers = r.subarray(0, 2); }
            else { searchedPeers = r; }

            // Die Pakete werden an die Peers gesendet
            let currentResponse = 0, hasReturned = false, failedReturns = 0;
            for(const otem of searchedPeers) {
                // An den Peer wird ein Ping Paket gesendet
                _START_PING_PROCESS(512, otem, (rstae, rtime, pingid) => {
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

                    // Es wird geprüft ob es sich um die erste Antwort handelt
                    if(currentResponse === 1 && hasReturned === false) {
                        // Debug Log
                        dprintok(10, ['Pong packet'], [colors.FgMagenta, pingid], ['received']);

                        // Es wird Signalisiert dass eine Antwort empfangen wurde
                        hasReturned = true;

                        // Die Primäre Route wird abgespeichert
                        primaryRoute = { ep:otem, ping:rtime, ftime:Date.now() };

                        // Es wird Signalisiert dass der Vorgang erfolgreich durchgeführt wurde
                        rbackAfterFetch(true);
                    }
                    else {
                        // Debug Log
                        dprintok(10, ['Pong packet'], [colors.FgMagenta, pingid], ['received']);

                        // Die Verbindung wird hinzugefügt
                        secondaryRoutes.push({ ep:otem, ping:rtime, ftime:Date.now(), lastSend:Date.now() });
                    }
                });
            }
        });
    };

    // Wird aller 30 Sekunden als Timer ausgeführt und Aktuallisiert die Verbindungen nach geschwindigkeit
    const _SYNC_ROUTE_PROCESS_TIME = () => {
        // Alle Verfügbaren Peers werden in einer Liste zusammengefasst
        let newTempList = [];
        if(primaryRoute !== null) newTempList.push(primaryRoute);
        newTempList = newTempList + secondaryRoutes;

        // Es wird geprüft ob ein Peer verfügbar ist
        if(newTempList.length === 0) return;

        // Es werden alle Peers geprüft wann sie das letztemal
        for(const peeritem of newTempList) {
            // Es wird geprüft ob es länger als 30 Sekunden her ist dass ein Paket gesendet oder Empfangen wurde
            if(peeritem) {

            }
        }
    };

    // Wird ausgeführt wenn keine Peer für diese Adresse verüfgbar ist
    routeEP.registerEvent('onDeleteRoute', async (addrPublicKey, deletedSessionId) => {
        // Es wird geprüft um welceh Sitzung es sich handelt
        if(primaryRoute.ep.sessionId === deletedSessionId) {
            // Debug Log
            dprintok(10, ['Session'], [colors.FgMagenta, primaryRoute.ep.sessionId], ['has been removed as the primary route from end point'], [colors.FgYellow, addrPublicKey, colors.Reset, '.']);

            // Sollte eine Alternative Route vorhanden sein, wird die Primäre Route durch die alternativen Route ersetzt, sollte keine Route vorhanden sein, wird ein Routing Request gestartet
            if(secondaryRoutes.length > 0) {
                // Die Primäre Route wird durch die erste Sekundäre Route ersetzt
                const retrivedEp = secondaryRoutes.pop();
                dprintok(10, ['The Primary Route'], [colors.FgMagenta, primaryRoute.ep.sessionId], ['has been replaced by the Secondary Route'], [colors.FgMagenta, retrivedEp.ep.sessionId, colors.Reset, '.']);
                primaryRoute = retrivedEp;
            }
            else {
                // Die Primäre Route wird entfernt
                dprinterror(10, ['There is no longer a route for the endpoint'], [colors.FgYellow, addrPublicKey, colors.Reset, ', all sockets are frozed.']);
                if(syncRouteTimer !== null) clearTimeout(syncRouteTimer);
                primaryRoute = null;
            }
        }
        else {
            // Die Sekundäre Route wird herausgefiltert
            secondaryRoutes = secondaryRoutes.filter(function(ele){
                if(ele.ep.sessionId === deletedSessionId) dprintok(10, ['Session'], [colors.FgMagenta, primaryRoute.ep.sessionId], ['has been removed as route from end point'], [colors.FgYellow, addrPublicKey, colors.Reset, '.']); 
                return ele.ep.sessionId != deletedSessionId; 
            });
        }
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

    // Gibt die Basis Funktionen zurück
    const _BASE_FUNCTIONS = {

    };

    // Es werden alle Verfügbaren Routen Initalisiert
    _FETCH_FASTED_PEERS((r) => {
        // Es wird geprüft ob der Vorgang erfolgreich durchgeführt wurde
        if(r === true) {
            // Der Auto Syncing Timer wird gestartet
            syncRouteTimer = setTimeout(_SYNC_ROUTE_PROCESS_TIME, 5000);

            // Es wird Signalisiert dass der Vorgang erfolgreich durchgeführt wurde
            rcb(null, _BASE_FUNCTIONS); 
        }
        else {
            // Es konnte keine Route Initalisiert werden
            rcb('no_route_available'); 
        }
    });

    // Es wird versucht die Primäre
    return { enterPackage:_ENTER_INCOMMING_PACKAGE };
};


module.exports = { addressRawEndPoint:addressRawEndPoint }
