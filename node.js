const { get_hash_from_dict, generate_ed25519_keypair, verify_digest_sig, sign_digest, create_deterministic_keypair, convert_pkey_to_addr } = require('./crypto');
const { dprintok, dprinterror, dprintinfo, colors } = require('./debug');
const { isNodeOnPCLaptopOrEmbeddedLinuxSystem } = require('./utils');
const { createLocalSocket, SockTypes } = require('./socket');
const { addressRawEndPoint } = require('./address_raw_ep');
const { verifyLayerThreePackage } = require('./lpckg');
const { routingManager } = require('./routing_man');
const { wsConnectTo, wsServer } = require('./wss');
const consensus = require('./consensus');
const { log } = require('console');
const crypto = require('crypto');
const URL = require("url").URL;



// Prüft eine URL
const stringIsAValidUrl = (s) => {
    try { const rUrl = new URL(s); return rUrl; }
    catch (err) { return false; }
};


// Das Node Objekt
const Node = (sodium, localPrivateKeyPair, localNodeFunctions=['boot_node'], privateSeed=null, nodeSettings=null, nodeCallback) => {
    // Speichert alle Nodes ab, welche bei einer neuen oder bei bestehenden ausgehenden Verbindung Informiert werden wollen
    let _notifyPeerByNewOutPeerConnection = [];

    // Speichert alle Ausgehenden Verbindungsadressen ab
    let _openOutEndPointConnectionTypes = {};

    // Speichert die Öffentlichen Schlüssel aller FullRelayNodes ab
    let _fullRelayNodes = [];

    // Speichert die Öffentlichen Schlüssel aller Verbundenen Nodes ab
    let _peerPubKeys = [];

    // Speichert alle Offnenen Routing Request vorgänge ab
    let _openAddressRouteRequestsPack = new Map();

    // Speichert das Primäre Schlüsselpaar ab
    let _localPrimaryKeyPair = null; 

    // Speichert alle Offenen RAWEndPoints ab
    const _openRawEndPoints = new Map();

    // Speichert alle Verbindungen und ihre Kernfunktionen ab
    const _openConnectionPeers = new Map()

    // Speichert alle Dienste einer Verbindung ab
    const _openPeerServices = new Map();

    // Speichert alle Serversockets ab
    const _serverSockets = new Map();

    // Speichert alle Offenen Sockets ab
    const _openSockets = new Map();

    // Speichert alle Schlüsselpaar ab
    const _localKeyPairs = new Map();

    // Speichert alle Bekannten Routen ab
    const _rManager = routingManager();

    // Gibt alle Crypto Funktionen an
    const CRYPTO_FUNCTIONS = {
        ed25519: {
            verify_sig:(sig, msg, pkey) => { return sodium.crypto_sign_verify_detached(sig, msg, pkey); },
            sign:(msg, skey) => { return sodium.crypto_sign_detached(msg, skey); }
        },
        secp256k1: { },
        nist256p1: { },
    };

    // Die Standardschlüssel werden erzeugt
    if(nodeSettings !== null) {
        // Der Masterkey wird erstellt
        let temp = create_deterministic_keypair(privateSeed, `0/0/MASTER_KEY`);
        temp.dpkhash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(temp.publicKey).digest()).digest();
        dprintinfo(10, ['Node Master Address ='], [colors.FgCyan, convert_pkey_to_addr(temp.publicKey)]);
        _localPrimaryKeyPair = temp;

        // Die weiteren Subkeys werden erstellt
        let cerelm = 0;
        while (cerelm != nodeSettings.key_height) {
            let determenstc = create_deterministic_keypair(privateSeed, `0/0/${cerelm}`);
            determenstc.dpkhash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(determenstc.publicKey).digest()).digest();
            _localKeyPairs.set(Buffer.from(determenstc.publicKey).toString('hex'), determenstc);
            cerelm += 1;
        }
    }

    // Signiert ein Paket mit dem Lokalen Schlüssel
    const _SIGN_DIGEST_WLSKEY = (digestValue) => {
        const sig = CRYPTO_FUNCTIONS.ed25519.sign(digestValue, localPrivateKeyPair.privateKey);
        return { sig:sig, pkey:localPrivateKeyPair.publicKey }
    };

    // Signiert ein PreBuilded Object und gibt ein Fertiges Objekt aus
    const _SIGN_PRE_PACKAGE = (prePackage) => {
        // Das Paket wird Signiert
        const packageSig = _SIGN_DIGEST_WLSKEY(get_hash_from_dict(prePackage));

        // Das Finale Paket wird Signiert
        return Object.assign(prePackage, { pkey:Buffer.from(packageSig.pkey).toString('hex'), sig:Buffer.from(packageSig.sig).toString('hex') });
    };

    // Startet den BOOT_NODE_REQUEST
    const _START_BOOT_NODE_PEER_REQUEST = (connObj) => {
        // Es wird geprüft ob es bereits einen Offenen Vorgang für diesen Public Key gibt
        var currentOpenElement = _openPeerServices.get(connObj.getPeerPublicKey())
        if(currentOpenElement !== undefined) {
            // Alle Einträge werden abgearbeitet
            for(const otem of currentOpenElement) {
                if(otem.type === 'boot_node_client') {
                    console.log('BOOT_NODE_ALWAYS_STARTED');
                    return;
                }
            }

            // Die bereits vorhandene Liste wird verwendet
            var openProcList = currentOpenElement;
        } else { var openProcList = []; }

        // Es wird ein neuer Eintrag in die Liste hinzugefügt
        openProcList.push({ type:"boot_node_client" });
        _openPeerServices.set(connObj.getPeerPublicKey(), openProcList);

        // Der Gegenseite wird mitgeteilt das der BootNode vorgang gestartet werden soll
        connObj.sendUnsigRawPackage({ type:'req', 'cmd':'boot_node_client_start' }, (result) => {
            if(!result) { connObj.close(); return; }
        });
    };

    // Es werden alle Verbindungen abgerufen und an die gegenseite Übermittelt
    const _TRANSMIT_PEER_ENDPOINTS = (connObj) => {
        // Die Einzelnen EndPunkte werden extrahiert
        dprintok(10, ['Session'], [colors.FgMagenta, connObj.sessionId()], ['was registered for'], [colors.FgYellow, 'OUTBOUND_PERR_ENDPOINT_BRODCASTING']);
        for(const otem of Object.keys(_openOutEndPointConnectionTypes)) {
            // Es wird geprüft ob es sich um die Adresse des Aktuellen Nodes handelt
            if(otem === connObj.getPeerIPAddressUrl()) continue;

            // Das Aktuelle Item wird abgespeichert
            const rotem = { ep:otem, conf:_openOutEndPointConnectionTypes[otem] };

            // Der Gegenseite wird mitgeteilt das der BootNode vorgang gestartet werden soll
            connObj.sendUnsigRawPackage({ type:'resp', 'cmd':'boot_node_endpoint', data:rotem }, (result) => {
                if(!result) { connObj.close(); return; }
                console.log('NODE_ENDPOINT_TRANSMITTED', connObj.getPeerPublicKey(), rotem.ep);
            });
        }
    };

    // Nimt eintreffende Peer Response Pakete entgegeen
    const _ENTER_PEER_ENDPOINT_PACKAGE = (ep, connObj) => {
        // Es wird geprüft ob die Funktion für diesen Node Aktiviert wurde
        const servicesElement = _openPeerServices.get(connObj.getPeerPublicKey());
        if(servicesElement === undefined) { console.log('UNRESOLVED_PEER_RESPONSE_RETRIVED'); connObj.close(); }

        // Es wird geprüft ob der Boot Node Client dienst gestartet wurde
        let bootNodeClientServiceOpen = false;
        for(const otem of servicesElement) {
            if(otem.type === 'boot_node_client') { bootNodeClientServiceOpen = true; break; }
        }
        if(!bootNodeClientServiceOpen) { console.log('UNRESOLVED_PEER_RESPONSE_RETRIVED'); connObj.close(); }

        // Es wird geprüft ob bereits eine Verbindung mit diesem Node / Peer aufgebaut wurde
        if(_openOutEndPointConnectionTypes.hasOwnProperty(ep.eo)) {
            console.log('IGNORED_NODE_ENDPOINT_ALWAYS_CONNECTED');
            return;
        }

        // Es wird eine Verbindung mit diesem Node hergestellt
        if(ep.conf.prot === 'ws:' || ep.conf.prot === 'wss:') {
            console.log('RETRIVED_NEW_NODE_ENDPOINT', connObj.getPeerPublicKey(), ep.ep);
            addPeerClientConnection(ep.ep);
        }
    };

    // Startet den BOOT_NODE_PEER_SENDER Service
    const _START_SEND_BOOT_NODE_PEER_RESPONSE = (connObj) => {
        // Es wird geprüft ob es bereits einen Offenen Vorgang für diesen Public Key gibt
        var currentOpenElement = _openPeerServices.get(connObj.getPeerPublicKey())
        if(currentOpenElement !== undefined) {
            // Alle Einträge werden abgearbeitet
            for(const otem of currentOpenElement) {
                if(otem.type === 'boot_node_server') {
                    console.log('BOOT_NODE_ALWAYS_STARTED');
                    return;
                }
            }

            // Die bereits vorhandene Liste wird verwendet
            var openProcList = currentOpenElement;
        } else { var openProcList = []; }

        // Es wird ein neuer Eintrag in die Liste hinzugefügt
        openProcList.push({ type:"boot_node_server" });
        _openPeerServices.set(connObj.getPeerPublicKey(), openProcList);

        // Der Öffentliche Schlüssel des Nodes wird abgspeichert
        if(!_notifyPeerByNewOutPeerConnection.includes(connObj.getPeerPublicKey())) _notifyPeerByNewOutPeerConnection.push(connObj.getPeerPublicKey());

        // Die Daten werden der gegenseite mitgeteilt
        _TRANSMIT_PEER_ENDPOINTS(connObj);
    };

    // Gibt ein Schlüsselpaar zurück, sofern es sich um einen Lokalen Schlüssel handelt
    const _GET_KEYPAIR_THEN_PUBKEY_KNWON = (pubKey) => {
        if(Buffer.from(localPrivateKeyPair.publicKey).toString('hex') === pubKey) return localPrivateKeyPair;
        if(_localPrimaryKeyPair !== null) {
            if(Buffer.from(_localPrimaryKeyPair.publicKey).toString('hex') === pubKey) return _localPrimaryKeyPair;
        }

        // Es wird geprüft ob der Eintrag vorhanden ist
        const reelm = _localKeyPairs.get(pubKey);
        if(reelm === undefined) return false;
        return reelm;
    };

    // Gibt ein Schlüsselpaar zurück, sofern es sich um einen Lokalen Schlüssel handelt
    const _GET_KEYPAIR_THEN_PUBKEYH_KNWON = (pubKeyHash) => {
        if(crypto.createHash('sha256').update(crypto.createHash('sha256').update(Buffer.from(localPrivateKeyPair.publicKey)).digest()).digest('hex') === pubKeyHash) return localPrivateKeyPair;
        return null;
    };

    // Wird verwendet um einen Privaten Schlüssel auf Basis des Masterkeys zu erstellen
    const _GENERATE_KEYPAIR_FROM_MKEY = (safe=true) => {

    };

    // Erzeugt einen neues Schlüsselpaar, welches nicht gespeichert wird
    const _GENERATE_RANDOM_KEYPAIR = () => {

    };

    // Wird verwendet um einen neue Verbindung zu Registrieren
    const _REGISTER_NEW_CONNECTION = (connObj, pprotFnc, callback) => {
        // Es wird geprüft ob es sich um ein Objekt handelt
        if(typeof connObj !== 'object') { callback(true); return; }

        // Es wird geprüft ob es bereits eine Verbindung mit dem Peer gibt
        if(_peerPubKeys.includes(connObj.getPeerPublicKey())) { callback(false); return; }

        // Der Öffentliche Schlüssel des nodes wird hinzugefügt
        _peerPubKeys.push(connObj.getPeerPublicKey());
        _openConnectionPeers.set(connObj.getPeerPublicKey(), connObj);

        // Es wird geprüft ob die Verbindung ein oder ausgehend ist
        if(connObj.isIncomming() === true) {
            dprintok(10, ['Incoming connection from'], [colors.FgMagenta, connObj.getPeerIPAddressUrl()], ['with session ID'], [colors.FgMagenta, connObj.sessionId()], ['completed in'], [colors.FgMagenta, connObj.getInitialTime()], ['ms']);
        }
        else {
            dprintok(10, ['Outbound connection with'], [colors.FgMagenta, connObj.getPeerIPAddressUrl()], ['with session ID'], [colors.FgMagenta, connObj.sessionId()], ['completed in'], [colors.FgMagenta, connObj.getInitialTime()], ['ms']);
        }

        // Es werden alle bekannten Protokoll Funktionen Aktiviert
        for(const protItem of pprotFnc) {
            switch(protItem) {
                // Es handelt sich um einen Full Node
                case 'prot_full_relay':
                    // Es wird geprüft ob die Node bereits alls FullNode registriert ist
                    if(_fullRelayNodes.hasOwnProperty(connObj.getPeerPublicKey())) break;

                    // Der Öffentliche Schlüssel wird registriert
                    _fullRelayNodes.push(connObj.getPeerPublicKey());
                    dprintinfo(10, ['Peer'], [colors.FgYellow, connObj.getPeerPublicKey()], ['on session'], [colors.FgMagenta, connObj.sessionId()], ['was registered as a'], [colors.FgMagenta, 'FullyNode']);
                    break
                // Gibt an dass der Peer alle Bitcoin Funktionen unterstützt
                case 'prot_btc_services':
                    console.log('REGISTERED_AS_SUPPORTING_BITCOIN_SERVICES', connObj.getPeerPublicKey());
                    break;
                // Gibt an dass der Peer alle IPFS Funktionen unterstützt
                case 'prot_ipf_services':
                    console.log('REGISTERED_AS_SUPPORTING_IPFS_SERVICES', connObj.getPeerPublicKey());
                    break;
                // Es handelt sich um eine Unbekannte Protokoll Funktion
                default:
                    log('UNKOWN_PROTOCOL_FUNCTION_IGNORED', protItem);
                    break;
            }
        }

        // Die Basisfunktionen für das Routing werden erzeugt
        const routingFunctions = {
            sendRawPackage:connObj.sendUnsigRawPackage,
            isConnected:connObj.isConnected,
            pingTime:connObj.getPingTime,
            sessionId:connObj.sessionId,
            defaultTTL:connObj.defaultTTL,
            isIncomming:connObj.isIncomming,
            peerVersion:connObj.peerVersion,
            sendRate:connObj.sendRate,
            type:"ws",
        };

        // Die Route wird im Routing Manager Hinzugefügt
        (async() => {
            try {
                const nodeEPAddResult = await _rManager.addNodeEP(connObj.sessionId(), routingFunctions);
                if(nodeEPAddResult !== true) { console.log('INVALID_RESULT_FROM_ROUTING_UNIT_BY_ADDING_EP'); callback(false); return; }
                const addressEP = await _rManager.addRoute(connObj.sessionId(), connObj.getPeerPublicKey(), connObj.getPingTime());
                if(addressEP !== true) { console.log('INVALID_RESULT_FROM_ROUTING_UNIT_BY_ADDING_ADDRESS'); callback(false); return; }
            }
            catch(e) { console.log(e); callback(false); return; }

            // Der Vorgang wurde erfolgreich durchgeführt
            callback(true);
        })();
    };

    // Wird verwendet um eine Registrierte Verbindung zu Entfernen
    const _UNREGISTER_CONNECTION = (connObj, callback) => {
        // Es wird geprüft ob es eine Verbindung mit diesem Node gibt
        if(!_peerPubKeys.includes(connObj.getPeerPublicKey())) { callback(false); return; }

        // Der Log das die Verbindung geschlossen wurde wird angezeigt
        if(connObj.isIncomming() === true) {
            dprintok(10, ['Incoming connection from'], [colors.FgMagenta, connObj.getPeerIPAddressUrl()], ['with session ID'], [colors.FgMagenta, connObj.sessionId()], ['closed']);
        }
        else {
            dprintok(10, ['Outbound connection with'], [colors.FgMagenta, connObj.getPeerIPAddressUrl()], ['with session ID'], [colors.FgMagenta, connObj.sessionId()], ['closed']);
        }

        // Es werden alle Dienste der Verbindung beendet
        const openProcs = _openPeerServices.get(connObj.getPeerPublicKey());
        if(openProcs !== undefined) {
            // Es werden alle Offenene Dienste gestoppt
            let foundProcs = [];
            for(const otem of openProcs) {
                // Sollte der Dienst einen Timer haben, wird dieser angehalten
                if(otem.hasOwnProperty('timer')) clearTimeout(otem.timer);
                foundProcs.push(otem.type);
            }

            // Es werden alle Dienste entfernt
            dprintok(10, ['All services for session'], [colors.FgMagenta, connObj.sessionId()], ['have been terminated.'])
            _openPeerServices.delete(connObj.getPeerPublicKey());
        }

        // Der Aktuelle Vorgang wird Asynchrone durchgeführt
        (async() => {
            // Es wird geprüft ob der Node benachrichtigt werden möchte, sollten dies der Fall sein, wird die Benachrichtigung entfernt
            if(_notifyPeerByNewOutPeerConnection.includes(connObj.getPeerPublicKey())) {
                _notifyPeerByNewOutPeerConnection = _notifyPeerByNewOutPeerConnection.filter(function(value, index, arr){ 
                    return value != connObj.getPeerPublicKey();
                });
            }

            // Die Verbindung wird aus den Offenenen Verbindingen heraus entfernt
            _openConnectionPeers.delete(connObj.getPeerPublicKey());

            // Der Öffentliche Schlüssels des Peers wird entfernt
            _peerPubKeys = _peerPubKeys.filter(function(ele){
                return ele != connObj.getPeerPublicKey();
            });

            // Der Peer wird als FullyNode entfernt
            _fullRelayNodes = _fullRelayNodes.filter(function(ele){
                if(ele === connObj.getPeerPublicKey()) dprintinfo(10, ['Peer'], [colors.FgYellow, connObj.getPeerPublicKey()], ['on session'], [colors.FgMagenta, connObj.sessionId()], ['was unregistered as a'], [colors.FgMagenta, 'FullyNode']);
                return ele != connObj.getPeerPublicKey();
            });

            // Der NodeEP wird entfernt, mit ihm werden alle Routen entfernt
            try {
                const nodeEPAddResult = await _rManager.delNodeEP(connObj.sessionId());
                if(nodeEPAddResult !== true) { console.log('INVALID_RESULT_FROM_ROUTING_UNIT_BY_ADDING_EP'); callback(false); return; }
            }
            catch(e) { console.log(e); callback(false); return; }

            // Der Vorgang wurde erfolgreich durchgeführt
            callback(true);
        })();
    };

    // Startet die Dienste eine Peers
    const _START_PEER_SERVICES = (connObj, cfunction) => {
        // Die Verfügbaren Funktionen werden gestartet
        for(const otem of cfunction) {
            switch(otem) {
                // Gibt an, dass es sich um einen BootNode handelt
                case 'boot_node':
                    _START_BOOT_NODE_PEER_REQUEST(connObj);
                    break
                // Es handelt sich um eine Unbekannte funktion
                default:
                    log('Ignored function');
                    break;
            }
        }
    };

    // Nimmt befehlspakete entgegen
    const _ENTER_CMD_PACKAGES = (package, connObj) => {
        /// Es wird geprüft ob die benötigten Datenfelder vorhanden sind
        if(!package.hasOwnProperty('cmd')) { console.log('Invalid command package'); connObj.close(); return; }
        switch(package.cmd) {
            case 'boot_node_client_start':
                // Es wird geprüft ob die Funktion unterstützt wird
                if(!localNodeFunctions.includes('boot_node')) { console.log('Invalid command package'); connObj.close(); return; }

                // Der Vorgang wird gestartet
                _START_SEND_BOOT_NODE_PEER_RESPONSE(connObj);

                // Das Paket wird gelöscht
                delete package;
        }
    };

    // Nimmt eintreffende Response Pakete entgegen
    const _ENTER_RESPONSE_PACKAGES = (package, connObj) => {
        // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
        if(!package.hasOwnProperty('cmd')) { connObj.close(); console.log('AT4TR'); return; }
        if(!package.hasOwnProperty('data')) { connObj.close(); console.log('AT5TR'); return; }
        if(!package.data.hasOwnProperty('ep')) { connObj.close(); console.log('AT6TR'); return; }
        if(!package.data.hasOwnProperty('conf')) { connObj.close(); console.log('AT7TR'); return; }
        if(!package.data.conf.hasOwnProperty('tor')) { connObj.close(); console.log('AT8TR'); return; }

        // Es wird geprüft ob es sich um einen gültigen Response befehl handelt
        switch(package.cmd) {
            case 'boot_node_endpoint':
                _ENTER_PEER_ENDPOINT_PACKAGE(package.data, connObj);
                break
            default:
                console.log('INVALID_RESPONSE_RETRIVED_UNKOWN_COMMAND');
                connObj.close();
                return;
        }
    };

    // Prüft ob die Signatur eines Paketes korrekt ist
    const _VERIFY_FRAME_SIGNATURE = (sigantedFrame) => {
        // Es wird geprüft ob der Öffentliche Schlüssel, die Signatur sowie der Algo vorhanden sind
        if(sigantedFrame.hasOwnProperty('source') !== true) return false;
        if(sigantedFrame.hasOwnProperty('ssig') !== true) return false;

        // Es wird geprüt ob der Verschlüsselungsalgorrytmus korrekt ist
        const splitedValues = sigantedFrame.crypto_algo.split('_');
        if(splitedValues.length === 0) return false;

        // Das Paketobjekt wird geklont
        let clonedObj = JSON.parse(JSON.stringify(sigantedFrame));

        // Es wird geprüft ob die Länge des Öffentlichen Schlüssels korrekt ist
        if(sigantedFrame.source.length !== 64) return false;

        // Es wird geprüft ob die Länge der Signatur korrekt ist
        if(sigantedFrame.ssig.length !== 128) return false;

        // Es wird versucht den Öffentlichen Schlüssel sowie die Signatur zu Dekodieren
        try{ var decodedPublicKey = Buffer.from(sigantedFrame.source, 'hex'), decodedSignature = Buffer.from(sigantedFrame.ssig, 'hex'); }
        catch(e) { console.log(e); return false; }

        // Die Signatur wird geprüft
        delete clonedObj.ssig, clonedObj.pkey;
        if(verify_digest_sig(get_hash_from_dict(clonedObj), decodedSignature, decodedPublicKey) === false) return false;

        // Es wird geprüft ob die Signatur korrekt ist
        return true;
    };

    // Signiert ein Frame
    const _SIGN_FRAME = (unsignedFrame) => {
        // Das Paket wird Signiert
        const packageSig = _SIGN_DIGEST_WLSKEY(get_hash_from_dict(unsignedFrame));

        // Das Finale Paket wird Signiert
        return Object.assign(unsignedFrame, { source:Buffer.from(packageSig.pkey).toString('hex'), ssig:Buffer.from(packageSig.sig).toString('hex') });
    };

    // Nimmt Pakete für Lokale Sockets entgegen
    const _ENTER_LOCAL_SOCKET_PACKAGES = (layertpackage, connObj, sdeph, callback) => {
        // Es wird geprüft ob es einen Offenen Lokalen Port gibt, welcher auf diese Verbindung wartet
        const retrivedSocketEp = _openSockets.get(layertpackage.body.ebody.body.dport);
        if(retrivedSocketEp !== undefined) {
            // Es wird geprüft ob es für den Absender Port in Kombination mit dem Empfänger Port ein Socket vorhanden ist
            const retrivedDestSocketEp = retrivedSocketEp.get(layertpackage.body.ebody.body.dport);
            if(retrivedDestSocketEp !== undefined) {
                // Das Paket wird an den Socket übergeben
                retrivedDestSocketEp.enterPackage(layertpackage, connObj, null, (r) => callback(r))
            }
            else {
                // Es wird geprüft ob es einen Universalen Lokalen Port gibt, wenn ja wird ein RAW Ep Abgerufen und mit dem Paket an den Socket übergeben
                const retrivLocSock = retrivedSocketEp.get('*');
                if(retrivLocSock === undefined) {
                    console.log('UNKOWN_SOCKET')
                    callback(false);
                    return; 
                }

                // Es wird versucht den Address Raw EP abzurufen
                getAddressRawEndPoint(layertpackage.source, (adrEpError, adrEpObj) => {
                    // Es wird geprüft ob ein fehler aufgetreten ist
                    if(adrEpError !== null) {
                        callback(adrEpError);
                        return;
                    }

                    // Das Paket wird an den Socket übergeben
                    retrivLocSock.enterPackage(layertpackage, adrEpObj, (state) => callback(state));
                });
            }
        }
        else {
            // Es gibt keinen Lokalen Socket welcher auf diese Verbindung wartet, dass Paket wird verworfen
            console.log('UNKOWN_SOCKET_A', layertpackage.body.sport);
            callback(false);
        }
    };

    // Verarbeitet Pakete welche für den Aktuellen Node bestimmt sind
    const _ENTER_LOCAL_LAYER2_PACKAGE = (packageFrame, connObj, retrivedKeyPair, callback) => {
        // Der Paketinhalt wird entschlüsselt
        const decryptedPackage = packageFrame.body.ebody;

        // Es wird geprüft ob ein Pakettyp vorhanden ist
        if(decryptedPackage.hasOwnProperty('type') === false) { callback(false); return; }

        // Aus der Empfänger Adresse sowie der Absender Adresse wird ein Hash erstellt
        const endPointHash = crypto.createHash('sha256')
        .update(Buffer.from(packageFrame.source, 'hex'))
        .update(Buffer.from(retrivedKeyPair.publicKey))
        .digest('hex');

        // Es wird geprüft ob es sich um ein Ping Paket handelt
        if(decryptedPackage.type === 'ping') {
            // Es wird ein Hash aus den Zufälligen Daten erstellt
            const packageRandomHash = crypto.createHash('sha256').update(Buffer.from(decryptedPackage.rdata, 'base64')).digest('hex');

            // Der Strict Wert wird ermittelt
            const strictMode = decryptedPackage.strict;

            // Es wird eine Zufällige Nonce erstellt, mit dieser Nonce werden die Daten verschlüsselt
            const randomValue = crypto.randomBytes(24);

            // Das Frame wird Signiert
            const signatedFrame = _SIGN_FRAME({
                crypto_algo:'ed25519_salsa20_poly1305',
                source:Buffer.from(retrivedKeyPair.publicKey).toString('hex'),
                destination:packageFrame.source,
                body:{
                    nonce:randomValue.toString('base64'),
                    ebody:{
                        type:'pong', sptnt:30000,
                        packRHash:packageRandomHash 
                    },
                    pbody:{}
                }
            });

            // Es wird geprüft ob es sich um ein Striktes Paket handelt, wenn ja wird es über die Verbindung zurückgesendet, über die es Empfangen wurde
            if(strictMode === true) {
                // Das Paket wird direkt zurück an den Absender gesendet
                connObj.sendUnsigRawPackage({ type:'pstr',frame:signatedFrame }, (r) => {
                    // Dem Routing Manager wird Siganlisiert dass das Paket erfolgreich übertragen wurden
                    _rManager.signalPackageTransferedToPKey(packageFrame.destination, packageFrame.source, connObj).then(() => {
                        dprintinfo(10, ['Ping'], [colors.FgRed, get_hash_from_dict(decryptedPackage).toString('base64')], ['returned successfully.']);
                        callback(r);
                    })
                });
            }
            else {
                // Das Paket wird an den Routing Manager übergeben
                _rManager.enterOutgoingLayer2Packages(packageFrame.source, signatedFrame, (r) => {
                    dprintinfo(10, ['Ping'], [colors.FgRed, get_hash_from_dict(decryptedPackage).toString('base64')], ['returned successfully.']);
                    callback(r);
                }, 1);
            }

            // Die Aufgabe wurde erfolgreich fertigestellt
            return;
        }
        // Das Paket wird weiterverabeitet
        else {
            // Es wird versucht den RawEP abzurufen
            const openEP = _openRawEndPoints.get(endPointHash);

            // Es wird geprüft ob es sich um ein Pon Paket handelt, wenn ja wird es direkt weitergegeben
            if(decryptedPackage.type === 'pong') {
                // Es wird geprüft ob der EndPunkt vorhanden ist
                if(openEP === undefined) { callback(false); return; }

                // Das Paket wird an den Lokalen EndPunt übergeben
                openEP.enterPackage(packageFrame, connObj, (r) => {
                    if(r === true) callback();
                    else callback(false);
                });

                // Der Vorgang wird beendet
                return;
            }

            // Es wird geprüft ob es sich um ein gültiges Layer 3 Paket handelt
            if(verifyLayerThreePackage(decryptedPackage) === false) { callback(false); return; }

            // Das Paket wird weiterverabeitet
            _ENTER_LOCAL_SOCKET_PACKAGES(packageFrame, connObj, endPointHash, callback);
        }
    };

    // Nimt eintreffende Pakete entgegen
    const _ENTER_RECIVED_SECOND_LAYER_PACKAGES = (package, connObj) => {
        // Es wird geprüft ob die Datenfelder vorhanden sind
        if(!package.hasOwnProperty('frame')) { connObj.close(); console.log('AT6TR1'); return; }
        if(!package.frame.hasOwnProperty('destination')) { connObj.close(); console.log('AT6TR3'); return; }
        if(!package.frame.hasOwnProperty('source')) { connObj.close(); console.log('AT6TR4'); return; }
        if(!package.frame.hasOwnProperty('ssig')) { connObj.close(); console.log('AT6TR5'); return; }
        if(!package.frame.hasOwnProperty('body')) { connObj.close(); console.log('AT6TR6'); return; }
        if(!package.frame.body.hasOwnProperty('nonce')) { connObj.close(); console.log('AT6TR7'); return; }
        if(!package.frame.body.hasOwnProperty('pbody')) { connObj.close(); console.log('AT6TR8'); return; }
        if(!package.frame.body.hasOwnProperty('ebody')) { connObj.close(); console.log('AT6TR9'); return; }

        // Es wird geprüft ob die Frame Signatur korrekt ist
        if(!_VERIFY_FRAME_SIGNATURE(package.frame)) {
            console.log('INVALID_FRAME_SIGANTURE_PACKAGE_DROPED');
            return;
        }

        // Log
        dprintok(10, ['Package'], [colors.FgRed, get_hash_from_dict(package.frame).toString('base64')], ['recived over'], [colors.FgMagenta, connObj.sessionId()], ['from ', colors.FgYellow, package.frame.source]);

        // Es wird geprüft ob es sich bei dem Empfänger um eine Lokale Adresse handelt, wenn nicht wird das Paket an den Routing Manager übergeben
        const fKeyPair = _GET_KEYPAIR_THEN_PUBKEY_KNWON(package.frame.destination);
        if(fKeyPair !== null && fKeyPair !== false) {
            // Es wird geprüft ob es für die Quelle eine Route gibt
            _rManager.hasRoutes(package.frame.source, connObj.sessionId())
            .then(async (r) => {
                // Sollte die Route nicht bekannt sein, so wird sie dem Routing Manager hinzugefügt
                if(!r) { await _rManager.addRoute(connObj.sessionId(), package.frame.source, null, 60000); }

                // Der Routing Manager wird Signalisiert das ein Paket emfpangen wurde
                await _rManager.signalPackageReciveFromPKey(package.frame.source, package.frame.destination, connObj);

                // Das Paket wird Lokal weiter verarbeitet
                _ENTER_LOCAL_LAYER2_PACKAGE(package.frame, connObj, fKeyPair, (packageState) => {

                });
            })
        }
        else {
            // Das Paket wird an die Routing Unit übergeben
            _rManager.enterIncommingLayer2Packages(package.frame.source, package.frame.destination, package.frame, connObj);
        }
    };

    // Sendet ein Routing Response an einen Peer
    const _SEND_ROUTING_RESPONSE = (oneTimeAddressRequest, foundAddress, timeout, connObj, procId, retrLocalKeyPair, callback) => {
        // Es wird ein OpenRouteResponseSessionPackage gebaut
        const openRouteSessionPackage = { crypto_algo:'ed25519', type:'rrr', version:consensus.version, orn:oneTimeAddressRequest, addr:foundAddress, timeout:timeout };

        // Aus dem OneTime Value und der Adresse wird ein Hash erstellt
        const decodedProcId = Buffer.from(procId, 'hex');
        const addrSig = sign_digest(decodedProcId, retrLocalKeyPair.privateKey);

        // Das Finale Paket wird gebaut
        const finalPackage = Object.assign(openRouteSessionPackage, { addrsig:Buffer.from(addrSig).toString('hex') });

        // Das Paket wird Signiert
        const signatedPackage = _SIGN_PRE_PACKAGE(finalPackage);

        // Das Paket wird an die gegenseite gesendet
        connObj.sendUnsigRawPackage(signatedPackage, () => {
            callback(true); 
        });
    };

    // Nimmt eintreffende Routing Request Pakete entgegen
    const _ENTER_ROUTING_REG_RESP_PACKAGE = (package, connObj) => {
        // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
        if(!package.hasOwnProperty('timeout')) { connObj.close(); console.log('AT1TZ'); return; }
        if(!package.hasOwnProperty('orn')) { connObj.close(); console.log('AT3TZ'); return; }

        // Es wird geprüft ob die Ablaufzeit korrekt ist
        if(package.timeout <= 0) { connObj.close(); console.log('AT7TZ'); return; }
        if(package.timeout > 120000) { connObj.close(); console.log('AT8TZ', package); return; }

        // Es wird geprüft ob die Timeout grenze erreicht wurde
        const toutTime = package.timeout - connObj.getPingTime();
        if(toutTime <= 0) { console.log('PACKAGE_DROPED_TIMEOUT'); return; }

        // Speichert die Aktuelle Startzeit des Prozzeses ab
        const processStartingTime = Date.now();

        // Gibt an, wieviele Antworten Maximal erlaubt sind
        const maxRequestesForCurrentPorcessAllowed = 3;

        // Es wird geprüft ob es sich um eine Anfrage oder eine Antwort handelt
        if(package.type === 'rreq') {
            // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
            if(!package.hasOwnProperty('addrh')) { connObj.close(); console.log('AT2TZ'); return; }

            // Es wird geprüft ob die Länge des Addresses Hashes sowie des Einaml Schlüssels korrekt sind
            if(package.addrh.length !== 64) { connObj.close(); console.log('AT5TZ'); return; }
            if(package.orn.length !== 64) { connObj.close(); console.log('AT6TZ'); return; }

            // Es wird geprüft ob der Vorgang bereits bekannt ist
            const reqProcId = crypto.createHash('sha256').update(package.orn).update(package.addrh).digest('hex');
            const basedReqProcId = Buffer.from(reqProcId, 'hex').toString('base64');
            const resolvedOpenProcs = _openAddressRouteRequestsPack.get(reqProcId);
            if(resolvedOpenProcs !== undefined) {
                // Es wird geprüft ob der Prozess beretis abgeschlossen wurde
                if(resolvedOpenProcs.operationIsOpen !== true) {
                    console.log('PACKAGE_DROPED_PROCESS_ALWAYS_CLOSED', finalProcId);
                    return;
                }

                // Dem Vorgang wird signalisiert dass eine Antwort eingetroffen ist
                resolvedOpenProcs.retrvPackage(toutTime, connObj, package)
                .catch((c) => { console.log('UNKOWN_INTERNALL_ERROR_BY_RUNNING_ROUTE_RESPONSE_ADDING', c); return; });
                return;
            }

            // Es wird geprüft ob es sich bei der gesuchten Adresse um die Adresse des Aktuellen Nodes handelt, wenn nicht wird eine Anfrage an das Netzwerk gestellt sofern Peers vorhanden sind
            const retivedKeyPair = _GET_KEYPAIR_THEN_PUBKEYH_KNWON(package.addrh);
            if(retivedKeyPair !== null) {
                // Debug Print
                dprintok(10, ['A routing request was received through session'], [colors.FgMagenta, connObj.sessionId()], ['with process id'], [colors.FgCyan, basedReqProcId]);

                // Wird ausgeführt sollte eine Antwort eingetroffen sein, in dem fall wird das Paket verworfen, da die Anfrage bereits beantwortet wurde
                const _AFTER_RECIVCE_RESPONSE = async (newTime, nconnobj, orpackage) => {
                    // Der Aktuelle Vorgang wird abgerufen
                    const tempResolvObj = _openAddressRouteRequestsPack.get(reqProcId);
                    if(tempResolvObj === undefined) { console.log('PACKAGE_FOR_UNKOWN_PROCESS_DROPED'); return; }

                    // Es wird geprüft ob dieses Paket bereits empfangen wurde
                    if(tempResolvObj.recivedPackageHashes.includes(get_hash_from_dict(orpackage)) === true) {
                        console.log('PACKAGE_DROPED_ALWAYS_RECIVED_THIS_PACKAGE');
                        return;
                    }

                    // Der Pakethash wird dem Vorgang hinzugefügt
                    tempResolvObj.recivedPackageHashes.push(get_hash_from_dict(orpackage));

                    // Es wird geprüft ob von diesem Peer bereits ein Paket Empfangen wurde
                    let totalPeersRecived = 0;
                    for(const otem of tempResolvObj.peers) {
                        totalPeersRecived += 1;
                        if(otem.ep.sessionId() === nconnobj.sessionId() && otem.ep.send !== false) {
                            console.log('PACKAGE_DROPED_FOR_CONNECTION');
                            return;
                        }
                        if(totalPeersRecived > 3) break;
                    }

                    // Es wird geprüft ob bereits 3 Pakete beantwortet wurden, wenn ja wird der Vorgang abgebrochen
                    if(totalPeersRecived >= maxRequestesForCurrentPorcessAllowed) {
                        dprinterror(10, ['Routing request process packet'], [colors.FgMagenta, basedReqProcId], ['was discarded, the process has already been answered.']);
                        return;
                    }

                    // Es wird Signalisiert das ein Paket von der Aktuellen Verbindung empfangen wurde
                    tempResolvObj.peers.push({ send:false, recive:true, ep:nconnobj });
                    _openAddressRouteRequestsPack.set(reqProcId, tempResolvObj);

                    // Die Aktuelle TTL wird neu berechnet
                    var preTTL = Date.now() - processStartingTime;
                    if(preTTL < 0) preTTL = 0;
                    var newTTL = newTime - preTTL;

                    // Das Antwortpaket wird an den Aktuellen Peer zurückgesendet
                    _SEND_ROUTING_RESPONSE(package.orn, Buffer.from(retivedKeyPair.publicKey).toString('hex'), newTTL, nconnobj, reqProcId, retivedKeyPair, (r) => {
                        // Es wird Signalisiert dass das Paket an den Peer gesendet wurde
                        const tempRObj = _openAddressRouteRequestsPack.get(reqProcId);
                        if(tempRObj !== undefined) {
                            let foundElement = false;
                            for(const otem of tempRObj.peers) {
                                if(otem.ep.sessionId() === nconnobj.sessionId()) {
                                    otem.send = { tstamp:Date.now() };
                                    foundElement == true;
                                }
                            }
                        }

                        // Der Eintrag wird geupdated
                        if(_openAddressRouteRequestsPack.get(reqProcId) !== undefined) _openAddressRouteRequestsPack.set(reqProcId, tempRObj);

                        // Debug Log
                        dprintok(10, ['The routing response packet for event'], [colors.FgCyan, basedReqProcId], ['was transferred to session'], [colors.FgMagenta, nconnobj.sessionId(),]);
                    });
                };

                // Wird als Timer ausgeführt wenn die Wartezeit abgelaufen ist, wenn ja wird der Vorgang aus dem Cache entfernt und in die LongDB geschrieben
                const _TIMER_LOCAL_ADDRESS_RESP = () => {
                    dprintinfo(10, ['The routing request process'], [colors.FgCyan, basedReqProcId], ['has ended.'])
                    _openAddressRouteRequestsPack.delete(reqProcId);
                };

                // Der Vorgang wird zwischengespeichert
                _openAddressRouteRequestsPack.set(reqProcId, {
                    procOpened:Date.now(),
                    procClosed:null,
                    operationIsOpen:true,
                    aborted:false,
                    retrvPackage:_AFTER_RECIVCE_RESPONSE,
                    peers:[ { send:false, recive:true, ep:connObj } ],
                    recivedPackageHashes:[get_hash_from_dict(package)]
                });

                // Der Time wird gestartet
                setTimeout(_TIMER_LOCAL_ADDRESS_RESP, 120000);

                // Die Aktuelle TTL wird neu berechnet
                var preTTL = Date.now() - processStartingTime;
                if(preTTL < 0) preTTL = 0;
                var newTTL = toutTime - preTTL;

                // Das Antwortpaket wird an den Aktuellen Peer zurückgesendet
                _SEND_ROUTING_RESPONSE(package.orn, Buffer.from(retivedKeyPair.publicKey).toString('hex'), newTTL, connObj, reqProcId, retivedKeyPair, (r) => {
                    // Es wird Signalisiert dass das Paket an den Peer gesendet wurde
                    const tempRObj = _openAddressRouteRequestsPack.get(reqProcId);
                    if(tempRObj !== undefined) {
                        let foundElement = false;
                        for(const otem of tempRObj.peers) {
                            if(otem.ep.sessionId() === connObj.sessionId()) {
                                otem.send = { tstamp:Date.now() };
                                foundElement == true;
                            }
                        }
                    }

                    // Der Eintrag wird geupdated
                    if(_openAddressRouteRequestsPack.get(reqProcId) !== undefined) _openAddressRouteRequestsPack.set(reqProcId, tempRObj);

                    // Debug Log
                    dprintok(10, ['The routing response packet for event'], [colors.FgCyan, basedReqProcId], ['was transferred to session'], [colors.FgMagenta, connObj.sessionId(),]);
                });
            }
            else (async() => {
                // Wird ausgeführt sollte eine Antwort eingetroffen sein
                const _AFTER_RECIVCE_RESPONSE = async (rpackage, connObjX) => {
                    // Es wird geprüft ob der Vorgang noch geöffnet ist
                    let totalEndPoints = _openAddressRouteRequestsPack.get(reqProcId);
                    if(totalEndPoints === undefined) {
                        console.log('SENDING_RESPONSE_ABORTED_NO_AVAIL_PROCESS');
                        return;
                    }

                    // Es wird geprüft ob das Antwortpaket von dieser Verbindung angefordert wurde, wenn ja wird Signalisiert dass ein Paket empfangen wurde
                    let hasFoundPeerFromRecive = false;
                    for(let otem of totalEndPoints.peers) {
                        if(otem.ep.sessionId() === connObjX.sessionId()) {
                            // Es wird geprüft ob ein Requestpaket an diese Verbindung gesendet wurde
                            if(otem.sendRequest === true) {
                                // Es wurd geprüft ob bereits ein Responsepaket von dieser Verindung empfangen wurde
                                if(otem.reciveResponse === false) {
                                    // Das Update des Eintrages wird vorbereitet
                                    otem.reciveResponse = true;
                                    otem.recive = true;
                                    let updatedPeersList = [];
                                    for(let notem of totalEndPoints.peers) {
                                        if(notem.ep.sessionId() == connObjX.sessionId()) updatedPeersList.push(otem);
                                        else updatedPeersList.push(notem);
                                    }

                                    // Die Daten werdne geupdatet
                                    dprintok(10, ['The routing request process'], [colors.FgCyan, basedReqProcId], ['was terminated with a response after'], [colors.FgMagenta, Date.now()-processStartingTime], ['ms.']);
                                    const updatedProcValue = Object.assign(totalEndPoints, { peers:updatedPeersList, operationIsOpen:false, procClosed:Date.now() });
                                    _openAddressRouteRequestsPack.set(reqProcId, updatedProcValue);
                                    hasFoundPeerFromRecive = true;
                                }
                                else {
                                    console.log('DROP_PACKAGE_HAS_ALWAYS_A_RESPONSE_RECIVED', connObjX.sessionId());
                                    return;
                                }
                            }
                            else {
                                console.log('DROP_PACKAGE_HAS_NOT_SEND_REQUEST_TO_CONNECTION', connObj.sessionId());
                                return;
                            }
                        }
                    }

                    // Es wird geprüft ob Mindestens ein Peer gefunden wurde
                    if(hasFoundPeerFromRecive !== true) {
                        console.log('PACKAGE_DROPED_THIS_NODE_HAS_NOT_REQUESTED', finalProcId);
                        return;
                    }

                    // Es werden alle Peers abgerufen welche noch keine Antwort erhalten haben
                    var extractedPeersTs = [];
                    if(totalEndPoints !== undefined) {
                        for(let otem of totalEndPoints.peers) {
                            if(otem.reciveRequest === true) {
                                if(otem.sendResponse === false) { extractedPeersTs.push(otem); }
                            }
                        }
                    }

                    // Wird verwendet um das Response Paket weiterzuleiten
                    const _FORWARD_RESPONSE_PACKAGE = () => {
                        // Es wird geprüft ob weitere Peers verfügbar sind
                        if(extractedPeersTs.length === 0) {
                            console.log('FINAL');
                            return;
                        }

                        // Die Aktuell Verfügbaren Verbindungen werden nach geschwindigkeit Sortiert
                        extractedPeersTs = extractedPeersTs.sort((a, b) => a.getPingTime() - b.getPingTime());

                        // Der Erste Peer wird aus der Liste extrahiert
                        const firstExtractedPeer = extractedPeersTs.pop();

                        // Es wird ermittelt wielange es gedauert hat
                        const procTTL = Date.now() - processStartingTime;
                        const newPackageTTL = rpackage.timeout - connObjX.getPingTime() - procTTL;

                        // Es wird ein OpenRouteSessionPackage gebaut
                        const openRouteSessionPackage = { crypto_algo:'ed25519', type:'rrr', version:consensus.version, orn:rpackage.orn, addr:rpackage.addr, addrsig:rpackage.addrsig, timeout:newPackageTTL };

                        // Das Paket wird abgesendet
                        firstExtractedPeer.ep.sendUnsigRawPackage(openRouteSessionPackage, (r) => {
                            dprintok(10, ['The routing response packet for event'], [colors.FgCyan, basedReqProcId], ['was sent to session'], [colors.FgMagenta, connObj.sessionId(), colors.Reset, '.']);
                        });
                    };

                    // Das Paket wird an die Peers weitergeleitet
                    _FORWARD_RESPONSE_PACKAGE();
                };

                // Der Vorgang wird registriert
                _openAddressRouteRequestsPack.set(reqProcId, {
                    procOpened:processStartingTime, procClosed:null, operationIsOpen:true, aborted:false, retrvPackage:_AFTER_RECIVCE_RESPONSE, peers:[
                        { send:false, recive:true, sendResponse:false, sendRequest:false, reciveRequest:true, reciveResponse:false, first:true, ep:connObj, entryAddTimestamp:Date.now() }
                    ]
                });

                // Wird als Timer ausgeführt
                const _TIMER_FUNCTION = () => {
                    // Es wird geprüft ob der Vorgang noch Vorhanden ist
                    const retrProc = _openAddressRouteRequestsPack.get(reqProcId);
                    if(retrProc === undefined) { console.log('UNKOWN_TIMER_PROCESS_CALL_ABORTED'); return; }

                    // Es wird geprüft ob es eine Antwort auf dieses Paket gab
                    if(retrProc.operationIsOpen === true) { dprintok(10, ['The routing request process'], [colors.FgCyan, basedReqProcId], ['was terminated without a response.']); }
                    else { dprintinfo(10, ['Routing request process'], [colors.FgCyan, basedReqProcId], ['was closed successfully.']); }

                    // Der Vorgang wird entfernt
                    _openAddressRouteRequestsPack.delete(reqProcId);
                };

                // Wird aufgerufen nachdem ein Paket an eine Sitzung übergeben wurde
                const _ENTER_SEND_PACKAGE_SESSION_ID = (ep) => {
                    // Der Aktuelle Prozess wird abgerufen
                    let tempObj = _openAddressRouteRequestsPack.get(reqProcId);
                    if(tempObj !== undefined) {
                        for(const otem of tempObj.peers) {
                            if(otem.ep.sessionId() === ep.sessionId()) {
                                console.log('UPDATE', otem);
                                return;
                            }
                        }

                        // Wenn kein Passender Eintrag gefunden wurde, wird ein neuer Hinzugefügt
                        dprintok(10, ['The routing request packet for operation'], [colors.FgCyan, Buffer.from(reqProcId, 'hex').toString('base64')], ['was forwarded to session'], [colors.FgMagenta, connObj.sessionId()]);
                        tempObj.peers.push({ send:true, recive:false, sendResponse:false, sendRequest:true, reciveRequest:false, reciveResponse:false, first:false, ep:ep, entryAddTimestamp:Date.now() });
                        _openAddressRouteRequestsPack.set(reqProcId, tempObj);
                    }
                };

                // Gibt an ob die ID korrekt ist
                const _IS_KNOWN_SESSION = (sessionId) => {
                    // Der Aktuelle Request vorgang wird abgerufen
                    const tobj = _openAddressRouteRequestsPack.get(reqProcId);
                    if(tobj === undefined) return null;

                    // Es wird geprüft ob an die Session bereits ein Paket gesendet wurde oder eine Request Anfrage von diesem Node entfangen wurde
                    for(const otem of tobj.peers) {
                        if(otem.ep.sessionId() === sessionId) {
                            if(otem.sendRequest === true || otem.reciveRequest === true || otem.reciveResponse === true || otem.sendResponse === true) return true;
                        }
                    }

                    // An diese Session wurde dieser Vorgang noch nicht weitergeleitet
                    return false;
                };

                // Wird ausgeführt wenn das erste Paket versendet wurde
                const _FIRST_PACKAGE_WAS_SEND = (state, ep) => {
                    if(state === true) { _ENTER_SEND_PACKAGE_SESSION_ID(ep); setTimeout(_TIMER_FUNCTION, toutTime); }
                    else { console.log('ABORTED_NO_PEERS_AVAIL_TO_FORWARD_ADDRESS_ROUTE_REQUEST'); }
                };

                // Es wird geprüft ob es Peers gibt welche die gesuchte Adresse bereits kennen
                let retrivedOnlyPeersList = [];
                const retrivedOnlyPeers = _rManager.hasGetRouteForPkeyHash(package.addrh);
                if(retrivedOnlyPeers !== false) {
                    const retrivedConnection = _openConnectionPeers.get(retrivedOnlyPeers);
                    if(retrivedConnection !== undefined) { retrivedOnlyPeersList.push(retrivedOnlyPeers); }
                }

                // Das Paket wird im Netzwerk gebrodcastet
                _BRODCAST_ADDRESS_ROUTE_REQUEST_PACKAGE(package.addrh, toutTime, connObj, processStartingTime, package.orn, _IS_KNOWN_SESSION, _ENTER_SEND_PACKAGE_SESSION_ID, _FIRST_PACKAGE_WAS_SEND, retrivedOnlyPeersList);
            })();
        }
        else if(package.type === 'rrr') {
            // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
            if(!package.hasOwnProperty('addrsig')) { connObj.close(); console.log('AT2TZX1'); return; }
            if(!package.hasOwnProperty('addr')) { connObj.close(); console.log('AT2TZX2',); return; }
            if(!package.hasOwnProperty('orn')) { connObj.close(); console.log('AT2TZX3'); return; }

            // Es wird geprüft ob die Länge des Addresses Hashes sowie des Einaml Schlüssels korrekt sind
            if(package.addrsig.length !== 128) { connObj.close(); console.log('AT5TZ'); return; }
            if(package.addr.length !== 64) { connObj.close(); console.log('AT5TZ'); return; }
            if(package.orn.length !== 64) { connObj.close(); console.log('AT6TZ'); return; }

            // Es wird ein Doppelter Hash aus der Adresse wird erzeugt
            const plainBytes = Buffer.from(package.addr, 'hex');
            const firstHash = crypto.createHash('sha256').update(plainBytes).digest();
            const doubleHash = crypto.createHash('sha256').update(firstHash).digest('hex');

            // Aus der VorgangsID sowie dem Double Hash der Adressen werden mittels Hash zusammengeführt
            const finalProcId = crypto.createHash('sha256').update(package.orn).update(doubleHash).digest('hex');

            // Es wird geprüft ob die Signatur korrekt ist
            if(verify_digest_sig(Buffer.from(finalProcId, 'hex'), Buffer.from(package.addrsig, 'hex'), Buffer.from(package.addr, 'hex')) === false) {
                console.log('INVALID_ADDRESS_SIGNATURE_PACKAGE_DROPED', package);
                return;
            }

            // Es wird geprüft ob der Vorang geöffnet ist
            let openProcess = _openAddressRouteRequestsPack.get(finalProcId);
            if(openProcess === undefined) { console.log('ROUTING_RESPONSE_PACKAGE_DROPED'); return; }

            // Es wird geprüft ob es bereits ein Antwortpaket für diesen Vorgang gab
            if(openProcess.operationIsOpen !== true) {
                console.log('DROP_PACKAGE_REQUEST_ALWASY_RETRIVED', connObj.sessionId());
                return;
            }

            // Dem Vorgang wird signalisiert dass eine Antwort eingetroffen ist
            openProcess.retrvPackage(package, connObj)
            .catch((c) => { console.log('UNKOWN_INTERNALL_ERROR_BY_RUNNING_ROUTE_RESPONSE_ADDING', c); return; })
        }
        else { connObj.close(); console.log('INVALID_ROUTING_REG_RESP_PACKAGE'); return; }
    };

    // Sendet ein AddressRouteRequestPackage an alle Netzwerkteilnehmer
    const _BRODCAST_ADDRESS_ROUTE_REQUEST_PACKAGE = (addressHash, timeout, sourceConnection, processStartingTime, randSessionId, isKnownSession, enterSendPackageSessionId, firstPackageSendCallback, onlyPeers=[], callback=null) => {
        // Es werden alle Verfügabren Peers abgerufen
        var retrivedPeers = [];
        if(onlyPeers.length > 0) {
            // Es werden alle Peers an welche das Paket gesendet werden soll, extrahiert
            for(const otem of onlyPeers) {
                const obj = _openConnectionPeers.get(otem);
                if(obj === undefined) continue;
                if(sourceConnection !== undefined && sourceConnection !== null) {
                    if(obj.sessionId() !== sourceConnection.sessionId()) { retrivedPeers.push(obj); }
                }
                else {
                    retrivedPeers.push(obj); 
                }
            }
        }
        else {
            // Es werden alle Peers verarbeitet, alle Peers außer der Aktuelle Peer über welchen die Anfrage Empfangen wurde, erhalten ein Request Routing Paket
            for(const otem of _openConnectionPeers.keys()) {
                const obj = _openConnectionPeers.get(otem);
                if(obj === undefined) continue;
                if(sourceConnection !== undefined && sourceConnection !== null) {
                    if(obj.sessionId() !== sourceConnection.sessionId()) { retrivedPeers.push(obj); }
                }
                else {
                    retrivedPeers.push(obj);
                }
            }
        }

        // Es wird geprüft ob eien Verfüugbare Verbindung gefunden wurde
        if(retrivedPeers.length === 0) {
            console.log('ROUTING_REQUEST_PACKAGE_DROPTED_NO_AVAILABLE_PEERS');
            return;
        }

        // Es wird geprüft ob mehr als 8 Mögliche peers Verfügar sind, wenn ja werden die 8 Schenellsten und Zufärlässigsten Peers ausgewählt
        if(retrivedPeers.length > 8) { retrivedPeers = retrivedPeers.sort((a, b) => a.getPingTime() - b.getPingTime()).slice(0, 8); }

        // Wird hintereinander ausgeführt bis alle Pakete versendet wurden
        var istFirstPackageWasSend = true;
        const _PACKAGE_SEND_LOOP_FUNCTION = () => {
            // Es wird geprüft ob weitere Peers verfügbar sind
            if(retrivedPeers.length === 0) {
                if(callback !== null) callback();
                return;
            }

            // Die Aktuell Verfügbaren Verbindungen werden nach geschwindigkeit Sortiert
            retrivedPeers = retrivedPeers.sort((a, b) => a.getPingTime() - b.getPingTime());

            // Der Erste Peer wird aus der Liste extrahiert
            const firstExtractedPeer = retrivedPeers.pop();

            // Es wird geprüft ob an diese Sitzung bereits etwas gesendet wurde
            if(isKnownSession !== undefined && isKnownSession !== null) {
                if(isKnownSession(firstExtractedPeer.sessionId()) === true) { _PACKAGE_SEND_LOOP_FUNCTION(); return; }
            }

            // Es wird ermittelt wielange es gedauert hat
            const procTTL = Date.now() - processStartingTime;
            const newPackageTTL = timeout - procTTL;

            // Es wird ein OpenRouteSessionPackage gebaut, Consensus(ARTEMIS, INIP001, CLEAR-REQUEST)
            const openRouteSessionPackage = { crypto_algo:'ed25519', type:'rreq', version:consensus.version, orn:randSessionId, addrh:addressHash, timeout:newPackageTTL };

            // Das Paket wird an diesen Peer gesendet
            firstExtractedPeer.sendUnsigRawPackage(openRouteSessionPackage, () => {
                if(istFirstPackageWasSend === true) {
                    firstPackageSendCallback(true, firstExtractedPeer);
                    istFirstPackageWasSend = false;
                }
                else {
                    enterSendPackageSessionId(firstExtractedPeer);
                }

                // Das Paket wird an den nächsten Peer gesendet
                _PACKAGE_SEND_LOOP_FUNCTION();
            });
        };

        // Das versenden der Daten wird gestartet
        _PACKAGE_SEND_LOOP_FUNCTION();
    };

    // Gibt Lokal Verfügbare Server Ports aus
    const _GET_LOCAL_SERVER_PORTS = (protc) => {
        // Es werden alle Sockets abgerufen
        for(const otem of _serverSockets.keys()) {
            const ritem = _serverSockets.get(otem);
            if(ritem.type === protc) {
                if(ritem.ip === '*') return ritem;
            }
        }

        // Es wurde kein Passender Socket gefunden
        return null;
    };

    // Stellt alle Websocket Funktionen bereit
    const _SOCKET_FUNCTIONS = {
        signAndReturnPubKeyAndSig:(digestValue) => _SIGN_DIGEST_WLSKEY(digestValue),
        enterRoutingRegRespPackage:_ENTER_ROUTING_REG_RESP_PACKAGE,
        enterNextLayerPackage:_ENTER_RECIVED_SECOND_LAYER_PACKAGES,
        enterResponsePackage:_ENTER_RESPONSE_PACKAGES,
        registerConnection:_REGISTER_NEW_CONNECTION,
        unregisterConnection:_UNREGISTER_CONNECTION,
        startClientServices:_START_PEER_SERVICES,
        enterCommandPackage:_ENTER_CMD_PACKAGES,
        localServerPorts:_GET_LOCAL_SERVER_PORTS,
        crypto:CRYPTO_FUNCTIONS
    };

    // Stellt alle Node Funktionen bereit
    const _RAW_FUNCTIONS = {
        addPeerClientConnection:(serverURL, accepted_functions, cb, reconnectTime) => addPeerClientConnection(serverURL, accepted_functions, cb, reconnectTime),
        initAddressRoute:(publicKey, callback, timeout) => initAddressRoute(publicKey, callback, timeout),
        totalPeers:() => _peerPubKeys.length,
    };

    // Speichert die Standardeinstellungen für Adress EndPoints ab
    const _DEFAULT_ADDRESS_RAW_EP = {
        autFetchRoutePing: true,
    };

    // Stellt alle API Funktionen bereit
    const _API_FUNCTIONS = {

    };

    // Wir verwendet um einen Websocket Server zu erstellen (Ip / Tor)
    const addNewWSServer = (localPort, localIp=null, isTor=false) => {
        // Erzeugt ein neues Websocket Server objekt
        const serverObj = wsServer(localPrivateKeyPair, _SOCKET_FUNCTIONS, localPort, localIp, localNodeFunctions);

        // Das Serverobjekt wird abgespeichert
        _serverSockets.set(serverObj._id, serverObj);
    };

    // Wird verwendet um eine Webserver verbindung herzustellen
    const addPeerClientConnection = (serverURL, accepted_functions=['boot_node'], cb=null, reconnectTime=5000, overTor=false) => {
        // Die URL wird geprüft
        const readedURL = stringIsAValidUrl(serverURL);
        if(readedURL === false) { console.log('INVALID_URL'); return; }

        // Es wird geprüft ob bereits eine Verbindung mit dem Peer (Node) aufgebaut wurde
        if(Object.keys(_openOutEndPointConnectionTypes).hasOwnProperty(readedURL.toString())) {
            console.log('SKIPPED_CONNECTION_ENDOINT_ALRADY_CONNECTED', readedURL.toString());
            return;
        }

        // Gibt alle MetaDaten der Verbindung aus
        const connectionMetaData = { ep:readedURL.toString(), prot:readedURL.protocol, tor:false };

        // Es wird geprüft um welches Protokoll es sich handelt
        if(readedURL.protocol === 'ws:' || readedURL.protocol === 'wss:') {
            // Wird ausgeführt wenn die Verbindung aufgebaut wurde
            const _FNC_OPEN_CONNECTION = () => {
                _openOutEndPointConnectionTypes[readedURL.toString()] = connectionMetaData;
                if(cb !== null) { cb(); }
            };

            // Wird aufgerufen wenn die Verbindung geschlossen wurde
            const _FNC_CLOSED_CONNECTION = () => {
                if(reconnectTime !== null) {
                    console.log('CONNECTION_CLOSED_TRY_RECONNECT', readedURL.toString());
                    setTimeout(() =>  addPeerClientConnection(serverURL, accepted_functions, null, reconnectTime), reconnectTime);
                }
            };

            // Die Verbindung wird hergestellt
            wsConnectTo(localPrivateKeyPair, _SOCKET_FUNCTIONS, readedURL.toString(), localNodeFunctions, accepted_functions, _FNC_OPEN_CONNECTION, _FNC_CLOSED_CONNECTION);
        }
    };

    // Wird verwendet um eine Adressroute abzufagen
    const initAddressRoute = (publicKey, callback=null, maxRecivingResponses=1, timeout=consensus.ttl_for_routing_request) => {
        // Es wird geprüft ob es sich um die Lokale Adresse handelt, wenn ja wird der Vorgang abgerbrochen!
        if(Buffer.from(localPrivateKeyPair.publicKey).toString('hex') === publicKey) {
            callback('aborted_is_local_address');
            return;
        }

        // Speichert den Aktuelle Timer ab
        var currentWaitTimer = null;

        // Wird verwendet um das Netwerk nach einer gewissen Adresse abzufragen
        const NETWORK_ADDRESS_ROUTE_SCANN = async () => {
            // Speichert die Aktuelle Zeit ab
            const currentTimestamp = Date.now();

            // Es wird ein DoubbleHash aus dem PublicKey erzeugt
            const plainBytes = Buffer.from(publicKey, 'hex');
            const firstHash = crypto.createHash('sha256').update(plainBytes).digest();
            const doubleHash = crypto.createHash('sha256').update(firstHash).digest('hex');

            // Es wird eine Zufällige ID für das Paket erzuegt
            const randSessionId = crypto.randomBytes(32).toString('hex');

            // Die VorgangsID wird erzeugt (Die VorgangsID besteht aus einem SHA256 Hash, welcher sich aus der RandomID sowie dem Addresshahs zusammensetzt)
            const finalProcId = crypto.createHash('sha256').update(randSessionId).update(doubleHash).digest('hex');
            const finalProcIdBased = Buffer.from(finalProcId, 'hex').toString('base64');

            // Log Entry
            dprintok(10, ['The address'], [colors.FgMagenta, publicKey], ['is searched in the network.'])

            // Speichert ab wieviele Response Insgesamt Empfangen wurden
            let recivedResponses = 0;

            // Speichert ab wann das erste Paket versendet wurde
            let firstPackageTime = null;

            // Wird aufgerufen wenn die Wartezeit abgelaufen ist
            const TIMEOUT_FNC = () => {
                // Es wird geprüft ob der Vorgang Geöffnet ist
                const currentOpenProcess = _openAddressRouteRequestsPack.get(finalProcId);
                if(currentOpenProcess !== undefined) {
                    // Es wird geprüft ob der Vorgang noch geöffnet ist, wenn ja wird geprüft ob mindestens eine Antwort empfangen wurde
                    if(currentOpenProcess.operationIsOpen && recivedResponses === 0) {
                        dprinterror(10, ['Routing request process'], [colors.FgCyan, finalProcIdBased], ['was closed without a response.']);
                        callback(false);
                    }
                    else {
                        dprintinfo(10, ['Routing request process'], [colors.FgCyan, finalProcIdBased], ['was closed with'], [colors.FgYellow, recivedResponses], ['reponses.']);
                    }

                    // Der Vorgang wird geschlossen und der Timer wird gelöscht
                    _openAddressRouteRequestsPack.delete(finalProcId);
                    clearTimeout(currentWaitTimer);
                    currentWaitTimer = null;
                }
            };

            // Wird verwenet wenn ein Paket versendet wurde
            const PACKAGE_SEND_EVENT = (ep) => {
                // Der Aktuelle Prozess wird abgerufen
                let tempObj = _openAddressRouteRequestsPack.get(finalProcId);
                if(tempObj !== undefined) {
                    for(const otem of tempObj.peers) {
                        if(otem.ep.sessionId() === ep.sessionId()) {
                            console.log('UPDATE', otem);
                            return;
                        }
                    }

                    // Wenn kein Passender Eintrag gefunden wurde, wird ein neuer Hinzugefügt
                    tempObj.peers.push({ send:true, recive:false, sendResponse:false, sendRequest:true, reciveRequest:false, reciveResponse:false, first:false, ep:ep, entryAddTimestamp:Date.now() });
                    _openAddressRouteRequestsPack.set(finalProcId, tempObj);
                }
            };

            // Wird verwedet wenn das erste Paket versendet wurde
            const FIRST_PACKAGE_SEND_EVENT = (state, ep) => {
                if(state === true) {
                    currentWaitTimer = setTimeout(TIMEOUT_FNC, timeout);
                    firstPackageTime = Date.now();
                    PACKAGE_SEND_EVENT(ep); 
                }
                else { console.log('ABORTED_NO_PEERS_AVAIL_TO_SEND_ADDRESS_ROUTE_REQUEST'); }
            };

            // Speichert die Funktion ab welche aufgerufen wird wenn eine Antwort eingetrofen ist
            const ENTER_RESOLVED_PACKAGE_OBJ = {
                procOpened:Date.now(), procClosed:null, operationIsOpen:true, aborted:false, peers:[],
                retrvPackage:async (package, cEpObj) => {
                    // Es wird geprüft ob die Adresse übereinstimmt
                    if(firstHash.toString('hex') !== crypto.createHash('sha256').update(Buffer.from(package.addr, 'hex')).digest('hex')) {
                        console.log('PACKAGE_DROPED_INVALID_SIGANTURE', Buffer.from(finalProcId, 'hex').toString('base64'));
                        return;
                    }

                    // Es wird geprüft ob der Vorgang noch geöffnet ist
                    let totalEndPoints = _openAddressRouteRequestsPack.get(finalProcId);
                    if(totalEndPoints === undefined) {
                        console.log('SENDING_RESPONSE_ABORTED_NO_AVAIL_PROCESS', Buffer.from(finalProcId, 'hex').toString('base64'));
                        return;
                    }

                    // Es wird geprüft ob die Maximale Mänge an Paketen empfangen wurde
                    if(recivedResponses >= maxRecivingResponses) {
                        console.log('PACKAGE_DROPED_ROUTE_REQUEST_MAXIMUM_RESPONSES_RECIVE', Buffer.from(finalProcId, 'hex').toString('base64'));
                        return;
                    }

                    // Es wird geprüft ob das Antwortpaket von dieser Verbindung angefordert wurde
                    let hasFoundRecivedPeerData = false;
                    for(let otem of totalEndPoints.peers) {
                        if(otem.ep.sessionId() === cEpObj.sessionId()) {
                            // Es wird geprüft ob ein Requestpaket an diese Verbindung gesendet wurde
                            if(otem.sendRequest === true) {
                                // Es wurd geprüft ob bereits ein Responsepaket von dieser Verindung empfangen wurde
                                if(otem.reciveResponse === false) {
                                    // Das ändern wird vorbereitet
                                    otem.reciveResponse = true;
                                    otem.recive = true;
                                    let updatedPeersList = [];
                                    for(let notem of totalEndPoints.peers) {
                                        if(notem.ep.sessionId() == cEpObj.sessionId()) updatedPeersList.push(otem);
                                        else updatedPeersList.push(notem);
                                    }

                                    // Die Änderungen werden gespeichert
                                    const updatedProcValue = Object.assign(totalEndPoints, { peers:updatedPeersList });
                                    _openAddressRouteRequestsPack.set(finalProcId, updatedProcValue);
                                    hasFoundRecivedPeerData = true;
                                }
                                else {
                                    console.log('DROP_PACKAGE_HAS_ALWAYS_A_RESPONSE_RECIVED', Buffer.from(finalProcId, 'hex').toString('base64'));
                                    return;
                                }
                            }
                            else {
                                console.log('DROP_PACKAGE_HAS_NOT_SEND_REQUEST_TO_CONNECTION', Buffer.from(finalProcId, 'hex').toString('base64'));
                                return;
                            }
                        }
                    }

                    // Es wird geprüft ob Mindestens ein Peer gefunden wurde
                    if(hasFoundRecivedPeerData !== true) {
                        console.log('PACKAGE_DROPED_THIS_NODE_HAS_NOT_REQUESTED', Buffer.from(finalProcId, 'hex').toString('base64'));
                        return; 
                    }

                    // Es wird geprüft ob die RandSessinID übereinstimmt
                    if(randSessionId !== package.orn) {
                        console.log('INVALID_PACKAGE_SESSION_ID', Buffer.from(finalProcId, 'hex').toString('base64'));
                        return; 
                    }

                    // Die Route wird für die Aktuelle Verbindung registriert
                    await _rManager.addRoute(cEpObj.sessionId(), package.addr, Date.now() - firstPackageTime, 60000);

                    // Der Recive Response Counter wird hochgezählt
                    recivedResponses += 1;

                    // Debug
                    dprintok(10, ['Response'], [colors.FgYellow, recivedResponses, colors.Reset, '/', colors.FgYellow, maxRecivingResponses], ['for routing process'], [colors.FgCyan, finalProcIdBased], ['after'], [colors.FgMagenta, Date.now() - currentTimestamp], ['ms received via session'], [colors.FgMagenta, cEpObj.sessionId()]);

                    // Es wird geprüft ob die Maximale Anzhal der geforderten Antworten eingetroffen ist
                    if(recivedResponses >= maxRecivingResponses && ENTER_RESOLVED_PACKAGE_OBJ.operationIsOpen === true) {
                        dprintinfo(10, ['The routing process'], [colors.FgMagenta, cEpObj.sessionId()], ['was completed after'], [colors.FgMagenta, Date.now() - currentTimestamp], ['ms, further packets are discarded.']);
                        const updatedProcValue = Object.assign(totalEndPoints, { operationIsOpen:false, procClosed:Date.now() });
                        _openAddressRouteRequestsPack.set(finalProcId, updatedProcValue);
                        ENTER_RESOLVED_PACKAGE_OBJ.operationIsOpen = false;
                    }

                    // Es wird geprüft ob der Vorgang erfolgreich fertigestellt wurde
                    if(recivedResponses > 1) return; 

                    // Die Route für die Adresse wurde erfolgreich Initalisiert
                    if(callback !== null) callback(true);
                }
            };

            // Die VorgangsID wird abgespeichert
            _openAddressRouteRequestsPack.set(finalProcId, ENTER_RESOLVED_PACKAGE_OBJ);

            // Das Paket wird an alle im Netzwerk gebrodcastet
            _BRODCAST_ADDRESS_ROUTE_REQUEST_PACKAGE(doubleHash, timeout, null, currentTimestamp, randSessionId, null, PACKAGE_SEND_EVENT, FIRST_PACKAGE_SEND_EVENT, []);
        };

        // Führt die Wichtigsten Dinge in einem asychronen Codeblock aus
        (async() => {
            // Es wird geprüft ob die Adresse dem Routing Manager bekannt ist, wenn nicht wird ein Routing Request Package gesendet
            if(await _rManager.hasRoutes(publicKey)) {
                // Der Routing End Point wird zurückgegeben, sollte kein Routing EP zurückgegeben werden wird die Adress eim Netzwerk gesucht
                const routingEP = await _rManager.getAddressRoute(publicKey);
                if(routingEP === null) {
                    // Die Route konnte nicht gefunden werden, dass Netwzerk wird nach dieser Adresse abgefragt
                    await NETWORK_ADDRESS_ROUTE_SCANN();
                    return;
                }
                else {
                    // Der Routing EndPunkt wird zurückgegeben
                    callback(true);
                    return;
                }
            }
            else {
                // Die Adresse wird im gesamten Netzwerk gesucht
                await NETWORK_ADDRESS_ROUTE_SCANN();
                return;
            }
        })();
    };

    // Gibt einen RAW EndPoint zurück
    const getAddressRawEndPoint = (destPublicKey, callback=null, addressRawEpConfig=_DEFAULT_ADDRESS_RAW_EP) => {
        (async() => {
            // Aus der Empfänger Adresse sowie der Absender Adresse wird ein Hash erstellt
            const endPointHash = crypto.createHash('sha256')
            .update(Buffer.from(destPublicKey, 'hex'))
            .update(Buffer.from(localPrivateKeyPair.publicKey))
            .digest('hex');

            // Es wird geprüft ob es bereits einen Offenen RAW Address EndPoint gibt
            const openEP = await _openRawEndPoints.get(endPointHash);
            if(openEP !== undefined) {
                callback(null, openEP.routeEp());
                return; 
            }

            // Es wird gepüft ob es eine Route für diese Adresse gibt
            const routeEP = await _rManager.getAddressRouteEP(destPublicKey);
            if(routeEP === false) {
                callback('NO_ADDRESS_ROUTE');
                return;
            }

            // Das AddressRawEndPoint Objekt wird erstellt
            const ipeResult = await addressRawEndPoint(_RAW_FUNCTIONS, routeEP, localPrivateKeyPair, destPublicKey, CRYPTO_FUNCTIONS, addressRawEpConfig, (error, arep) => {
                // Es wird geprüft ob ein Fehler aufgetreten ist
                if(error !== undefined && error !== null) {
                    _openRawEndPoints.delete(endPointHash);
                    return;
                }

                // Die Verbindung wird zurückgegeben
                callback(null, arep);
            });

            // Der Vorgang wird registriert
            _openRawEndPoints.set(endPointHash, ipeResult);
        })();
    };

    // Erstellt einen neuen Lokalen Socket
    const createNewLocalSocket = (localPort, callback, sockType=SockTypes.RAW) => {
        // Es wird geprüft ob es bereits einen eintrag für diesen Socket gibt
        const localSocketEntry = _openSockets.get(localPort);
        if(localSocketEntry !== undefined) { callback('PORT_ALWAYS_USED'); return; }

        // Die RAW Funktion werden erweitert
        const modfifRAWFunctions = {
            ..._RAW_FUNCTIONS,
            getAddressRawEndPoint:(destPublicKey, callback, addressRawEpConfig=_DEFAULT_ADDRESS_RAW_EP) => {
                return getAddressRawEndPoint(destPublicKey, callback, addressRawEpConfig);
            }
        }

        // Der Neue Socket wird erzeugt
        const newEntry = new Map();
        newEntry.set('*', createLocalSocket(modfifRAWFunctions, localPrivateKeyPair, sockType, localPort, (error, sockobj) => {
            // Es wird geprüft ob ein Fehler aufgetreten ist
            if(error !== null) { callback(error); return; }

            // Die Callback Funktion wird aufgerufen
            callback(null, sockobj);
        }));

        // Der Socket wird abgespeichert
        _openSockets.set(localPort, newEntry);
    };

    // Wird als Objekt Funktionen verwendet
    const _OBJ_FUNCTIONS = {
        apiFunctions:_API_FUNCTIONS,
        addNewWSServer:addNewWSServer,
        initAddressRoute:initAddressRoute,
        createNewLocalSocket:createNewLocalSocket,
        getAddressRawEndPoint:getAddressRawEndPoint,
        addPeerClientConnection:addPeerClientConnection,
    };

    // Das Objekt wird zurückgegben
    if(nodeCallback !== undefined && nodeCallback !== null) { nodeCallback(_OBJ_FUNCTIONS); }
    return _OBJ_FUNCTIONS
}

// Die Module werden Exportiert
module.exports = { Node:Node }
