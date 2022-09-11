const { getHashFromDict } = require('./crypto');
const crypto = require('crypto');



// Stellt einen Address to Adress RAW EndPoint dar
const addressRawEndPoint = async (rawFunctions, routeEP, localNodePrivateKey, sourcePrivateKey, destinationPublicKey, crypto_functions, rcb) => {
    // Es wird geprüft ob eine Route verfügbar ist
    if(! await routeEP.isUseable()) { return 'unkown_route_for_address'; }

    // Speichert alle Offenen Vorgänge ab
    var _openSYNCProcesses = new Map();

    // Speichert die Schnellste Primäre Route ab
    var _fastedRoute = null;

    // Speichert die Sekundären Routen ab
    var _secondRouteOne = null, _secondRouteTwo = null;

    // Speichert ab, wann das letzte SYNC Paket gesendet wurde
    var _lastSyncProcess = null;

    // Wird als Timer ausgeführt um die Verbinddung zu überwachen
    var _sessionDocTimer = null;

    // Gibt an ob der letzte SYNC Vorgang erfolgreich war
    var _lastSYNCSucc = false;

    // Speichert die Routen für diese Adresse ab
    var _syncedRoutes = [];

    // Gibt die Schnellste Verfügbare Route aus
    const _GET_FASTET_AVAILABLE_ROUTE = () => {

    };

    // Gibt die Maximale Wartezeit für ein Paket an
    const _MAX_TIMEOUT_PER_REQUEST = () => {
        if(_fastedRoute !== null) {
            if(!_lastSYNCSucc) return 5000;
            else return _fastedRoute.total * 3;
        }
        return 120000;
    };

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

    // Signiert ein Frame
    const _SIGN_FRAME = (unsignedFrame) => {
        // Das Paket wird Signiert
        const packageSig = _SIGN_DIGEST_WLSKEY(sourcePrivateKey, getHashFromDict(unsignedFrame));

        // Das Finale Paket wird Signiert
        return Object.assign(unsignedFrame, { source:Buffer.from(packageSig.pkey).toString('hex'), ssig:Buffer.from(packageSig.sig).toString('hex') });
    };

    // Send Signated Layer 2 Frame
    const _SEND_SIGNATED_LAYER2_FRAME = (sock, sigantedFrame, callback) => {
        // Das Layer 1 Paket wird gebaut
        const prePackage = { crypto_algo:'ed25519', type:'pstr', version:10000000, frame:sigantedFrame };

        // Das Paket wird Signiert
        const signatedPackage = _SIGN_PRE_PACKAGE(prePackage);

        // Das Paket wird versendet
        sock.enterPackage(signatedPackage, () => callback(true, sock.sessionId));
    };

    // Sendet ein SYNC Paket an die 3 Schnellsten Verbindungen
    const _SEND_SYNC_PACKAGE_TO_FASTEST_PEERS = (callback) => {
        // Die RandomID für diesen Vorgang wird erzeugt
        const randID = crypto.randomBytes(32).toString('hex');

        // Das Layer2 Frame wird gebaut
        const preLayer2Frame = { type:'sync', destination:destinationPublicKey, crypto_algo:'ed25519', ron:randID }

        // Das Layer2 Frame wird Signiert
        const signatedFrame = _SIGN_FRAME(preLayer2Frame);

        // Speichert den Sync Vorgang ab
        _openSYNCProcesses.set(randID, {
            stime:Date.now(),
            timeoutTimer:null,
            open:true, timeout:false,
            cb:(reval=true) => { callback(reval); }
        });

        (async() => {
            // Es wird geprüft ob es möglich ist diese Route zu nutzen
            if(!await routeEP.isUseable()) {
                // Es wird geprüft ob Mindestens 1 Peer Verfügbar ist
                if(rawFunctions.totalPeers() >= 1) {
                    // Es wird versucht die Route neu zu Initalisieren
                    rawFunctions.initAddressRoute(destinationPublicKey, (r) => callback(r));
                    return;
                }

                // Es sind keine Peers und Routen für diese Adresse verfügbar
                callback(false);
                return;
            }

            // Die Verfügbaren Peers werden abgerufen
            const availFastedPingPeers = await routeEP.getAllPeers();

            // Das Paket wird an alle Peers welche die Route kennen versendet
            for(const otem of availFastedPingPeers) {
                // Das Paket wird an den asugewählten Peer gesendet
                _SEND_SIGNATED_LAYER2_FRAME(otem, signatedFrame, (result, sessionId) => {
                    console.log('PACKAGE_SEND_TO', signatedFrame.destination, sessionId);
                })
            }

            // Der Timer wird gestartet und prüft nach 2 Minuten ob eine Route Verfügabr ist
            const timer = setTimeout(() => {
                // Es wird geprüft ob der Eintrag vorhanden ist, wenn nicht wurde er beretis beendet
                const repo = _openSYNCProcesses.get(randID);
                if(repo !== undefined) {
                    if(repo.open === true && repo.timeout === false) {
                        var overRepo = repo;
                        _lastSYNCSucc = false;
                        overRepo.open = false;
                        overRepo.timeout = true;
                        _openSYNCProcesses.set(randID, overRepo);
                        callback(false);
                    }
                }

                // Der Timer wurde grundlos ausgeführt
                console.log('ZERO_TIMER_CALLED');
            }, _MAX_TIMEOUT_PER_REQUEST());

            // Der Timer wird in die Verbindung geschrieben
            _openSYNCProcesses.set(randID, {... await _openSYNCProcesses.get(randID), timeoutTimer:timer });
        })();
    };

    // Nimt RSYNC Pakete Entgegen
    const _ENTER_RSYNC_PACKAGE = (packageFrame, connObj) => {
        // Es wird geprüft ob es einen Passenden Offenen Vorgang gibt
        const retrivedProc = _openSYNCProcesses.get(packageFrame.rron);
        if(retrivedProc === undefined) {
            console.log('UNOWN_SYNC_PROCESS_PACKAGE_DROPED');
            return;
        }

        // Die Benötigte Zeit für diesen Vorgang wird ermittelt
        const totalSyncProcMsTime = Date.now() - retrivedProc.stime;

        // Der Prozess wird geschlossen 
        if(retrivedProc.open === true) {
            _openSYNCProcesses.set(packageFrame.rron, Object.assign(retrivedProc, { open:false }));
            if(retrivedProc.timeoutTimer !== null) clearTimeout(retrivedProc.timeoutTimer);
        }

        // Es werden alle derzeit verfügabren Peers abgerufen
    };

    // wird verwendet um eintreffende Pakete entgegen zu nehemen
    const _ENTER_INCOMMING_PACKAGE = (package, connObj) => {
        // Das Paket wird nach typ verarbeitet
        switch(package.type) {
            case 'rsync':
                // Das Paket wird an die RSYNC Funktion übergeben
                _ENTER_RSYNC_PACKAGE(package, connObj);

                // Der Vorgang wurde erfolgreich abgeschlossen
                return;
            case 'dtrgrm':
                break
            case 'sess':
                break;
            default:
                console.log('UNKOWN_PACKAGE_TYPE_PACKAGE_DROPED');
                return;
        }
    };

    // Diese Funktion wird als Timer ausgeführt und überprüft ob die Routen noch exestend sind
    const _SESSION_DOC = () => {
        // Es wird geprüft ob bereits eine Zeit bekannt ist, wann das letzte Paket empfangen wurde, wenn nicht wird der Vorgang abgebrochenn
        if(_lastSyncProcess === null) {
            console.log('ABORTED_INTERNAL_ERROR');
            return;
        }

        // Es wird geprüft ob es länger als 100ms her ist das ein Paket empfangen wurde, wenn ja wird ein SYNC Vorgang durchgeführt
        if(Date.now() - _lastSyncProcess >= 5000) {
            _SEND_SYNC_PACKAGE_TO_FASTEST_PEERS((result) => {
                // Es sind keine Routen verfügabr
                if(!result) {
                    _lastSyncProcess = Date.now();
                    console.log('NO_PEERS_FOR_ROUTE_AVAILABLE', destinationPublicKey); 
                }

                // Der Timer wird neugestartet
                clearTimeout(_sessionDocTimer);
                _sessionDocTimer = setTimeout(_SESSION_DOC, 1);
            });

            // Es wird auf gewartet bis auf den SYNC Vorgang geantwortet wurde
            return;
        }

        // Der Vorgang wird neugestartet
        _sessionDocTimer = setTimeout(_SESSION_DOC, 1);
    };

    // Das Funktionsobjekt wird zurückgegeben
    const useableFunctions = {

    };

    // Es wird ermittelt, welche der Routen die Schnellste ist
    _SEND_SYNC_PACKAGE_TO_FASTEST_PEERS((r) => {
        // Es wird geprüft ob der Vorgang durchgeführt werden konnte
        if(!r) {
            console.log('INIT_ERROR', r);
            return;
        }

        // Der SessionDOC wird gestartet
        _sessionDocTimer = setTimeout(_SESSION_DOC, 1);

        // Das Objekt wird zurückgegeben
        rcb(null, useableFunctions);
    });

    // Es wird versucht die Primäre
    return { enterPackage:_ENTER_INCOMMING_PACKAGE };
};


module.exports = { addressRawEndPoint:addressRawEndPoint }