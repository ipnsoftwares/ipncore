const { getHashFromDict } = require('./crypto');
const { dprinterror } = require('./debug');
const crypto = require('crypto');



// Stellt einen Address to Adress RAW EndPoint dar
const addressRawEndPoint = async (rawFunctions, routeEP, localNodePrivateKey, sourcePrivateKey, destinationPublicKey, crypto_functions, socketConfig, rcb) => {
    // Es wird geprüft ob eine Route verfügbar ist
    if(!await routeEP.isUseable()) { return 'unkown_route_for_address'; }

    // Speichert alle Sockets ab
    let _openSocketList = [];

    // Speichert Offene Ping Vorgänge ab
    const _openPingProcesses = new Map();

    // Gibt an ob die Adresse verfügbar ist
    let _peerIsAvailable = true, _waitTimerForReRsyncRoute = null;

    // Wird verwendet um die Route für die Adresse neu zu Initalisieren
    const _ATCH_SCANN = () => {
        // Es wird geprüft ob ein Peer Verfügbar ist, wenn ja wird der Vorgang abgebrochen
        if(_peerIsAvailable === true) { return; }
        
    };

    // Wird ausgeführt wenn keine Peer für diese Adresse verüfgbar ist
    routeEP.registerEvent('NoAvailableConnections', async () => {
        // Es wird geprüft ob der Aktuelle Status der Verbindung, verwendetbar ist, wenn nicht wird der vorgang abgebrochen
        if(_peerIsAvailable === true) {
            // Das Objekt wird eingeforen
            _peerIsAvailable = false;
            console.log('NO_ROUTE_FOR_ADDRESS_AVAILABLE');

            // Alle Sockets werden Pausiert
            for(const otem of _openSocketList) {}

            // Es wird ein Timer gestartet, dieser Time wird in 5 Sekunden ausgeführt um zu versuchen die Route neu anzufordern
            _waitTimerForReRsyncRoute = setTimeout(_ATCH_SCANN, 5000);
        }
    });

    // Wir ausgeführt sobald ein Peer für diese Verbindung verfügbar ist
    routeEP.registerEvent('AvailableConnections', async () => {
        // Es wird geprüft ob bereits ein Peer verfügbar ist, wenn ja wird der Vorgang Ignoriert
        if(_peerIsAvailable === false) {
            clearTimeout(_waitTimerForReRsyncRoute);
            _waitTimerForReRsyncRoute = null;
            _peerIsAvailable = true;
            console.log('ROUTE_FOR_ADDRESS_AVAILABLE');
        }
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
    const _SEND_COMPLETED_LAYER2_FRAME = (sigantedFrame, callback=null) => {
        // Das Layer 1 Paket wird gebaut
        const prePackage = { crypto_algo:'ed25519', type:'pstr', version:10000000, frame:sigantedFrame };

        // Das Paket wird Signiert
        const signatedPackage = _SIGN_PRE_PACKAGE(prePackage);

        // Das Paket wird versendet
        routeEP.getFastedEndPoint((s, r) => {
            // Es wird geprüft ob eine Verbindung gefunden wurde
            if(s !== null) {
                dprinterror(10, ['Error by sending ping package for raw address ep', s]);
                return;
            }

            // Das Paket wird an den Peer gesendet
            r.enterPackage(signatedPackage, (r) => {
                console.log('PACKAGE_SEND');
                if(callback !== undefined && callback !== null) { callback(r); }
            });
        });
        //sock.enterPackage(signatedPackage, () => callback(true, sock.sessionId));
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
    const _START_PING_PROCESS = (bodySize, callback) => {
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
            callback(false);
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
            callback(true, Date.now() - _PING_PACKAGE_SEND_TIME);
        };

        // Speichert den Ping Vorgang ab
        _openPingProcesses.set(secRandHash, { callResponse:_RESPONSE });

        // Das Ping Paket wird versendet
        _SEND_COMPLETED_LAYER2_FRAME(finallyFrame, (state) => {
            // Speichert die Zeit ab, wann das Paket empfangen wurde
            _PING_PACKAGE_SEND_TIME = Date.now();

            // Der Timer für diesen Ping wird gestartet
            _OPEN_WAIT_RESPONSE_TIMER = setTimeout(_TIMER_FUNCTION_PROC, 30000);
        });
    };

    // Gibt die Basis Funktionen zurück
    const _BASE_FUNCTIONS = {

    };

    // Der Pingprozess wird gestartet
    _START_PING_PROCESS((1024*2.5), (done, statics) => {
        rcb(null, _BASE_FUNCTIONS);
    });

    // Es wird versucht die Primäre
    return { enterPackage:_ENTER_INCOMMING_PACKAGE };
};


module.exports = { addressRawEndPoint:addressRawEndPoint }
