const { get_hash_from_dict, decrypt_anonymous_package, encrypt_anonymous_package, verify_digest_sig, sign_digest, create_deterministic_keypair, convert_pkey_to_addr, double_sha3_compute, compute_shared_secret } = require('./crypto');
const { verifyLayerThreePackage, verifyFirstSecondLayerPackageBase, isValidateRoutingRequestOrResponsePackage, isValidateRoutingRequestPackage, isValidateRoutingResponsePackage } = require('./lpckg');
const { dprintok, dprinterror, dprintinfo, colors } = require('./debug');
const { isNodeOnPCLaptopOrEmbeddedLinuxSystem } = require('./utils');
const { createLocalSocket, SockTypes } = require('./socket');
const { addressRawEndPoint } = require('./address_raw_ep');
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
const Node = (sodium, localNodeFunctions=['boot_node'], privateSeed=null, nodeSettings=null, nodeCallback) => {
    // Speichert alle Nodes ab, welche bei einer neuen oder bei bestehenden ausgehenden Verbindung Informiert werden wollen
    let _notifyPeerByNewOutPeerConnection = [];

    // Speichert alle Ausgehenden Verbindungsadressen ab
    let _openOutEndPointConnectionTypes = {};

    // Speichert die Öffentlichen Schlüssel aller FullRelayNodes ab
    let _fullRelayNodes = [];

    // Speichert die Öffentlichen Schlüssel aller Verbundenen Nodes ab
    let _peerPubKeys = [];

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
        _localPrimaryKeyPair = { ...temp,  nhash:double_sha3_compute(temp.publicKey)};

        // Die weiteren Subkeys werden erstellt
        let cerelm = 0;
        while (cerelm != nodeSettings.key_height) {
            let determenstc = create_deterministic_keypair(privateSeed, `0/0/${cerelm}`);
            determenstc.dpkhash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(determenstc.publicKey).digest()).digest();
            _localKeyPairs.set(Buffer.from(determenstc.publicKey).toString('hex'), { ...determenstc, nhash:double_sha3_compute(determenstc.publicKey) });
            cerelm += 1;
        }
    }

    // Startet den BOOT_NODE_REQUEST
    const _START_BOOT_NODE_PEER_REQUEST = async (connObj) => {
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
        }
        else { var openProcList = []; }

        // Es wird ein neuer Eintrag in die Liste hinzugefügt
        openProcList.push({ type:"boot_node_client" });
        _openPeerServices.set(connObj.getPeerPublicKey(), openProcList);

        // Der Gegenseite wird mitgeteilt das der BootNode vorgang gestartet werden soll
        connObj.sendUnsigRawPackage({ type:'req', 'cmd':'boot_node_client_start' }, (result) => {
            if(!result) { connObj.close(); return; }
        });
    };

    // Es werden alle Verbindungen abgerufen und an die gegenseite Übermittelt
    const _TRANSMIT_PEER_ENDPOINTS = async (connObj) => {
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
    const _ENTER_PEER_ENDPOINT_PACKAGE = async (ep, connObj) => {
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
    const _START_SEND_BOOT_NODE_PEER_RESPONSE = async (connObj) => {
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
        await _TRANSMIT_PEER_ENDPOINTS(connObj);
    };

    // Gibt ein Schlüsselpaar zurück, sofern es sich um einen Lokalen Schlüssel handelt
    const _GET_KEYPAIR_THEN_PUBKEY_KNWON = async (pubKey) => {
        // Es wird geprüft ob es sich um den Primären Schlüssel handelt
        if(_localPrimaryKeyPair !== null) {
            if(Buffer.from(_localPrimaryKeyPair.publicKey).toString('hex') === pubKey) return _localPrimaryKeyPair;
        }

        // Es wird geprüft ob der Eintrag vorhanden ist
        const reelm = _localKeyPairs.get(pubKey);
        if(reelm === undefined) return false;
        return reelm;
    };

    // Gibt ein Schlüsselpaar zurück, sofern es sich um einen Lokalen Schlüssel handelt
    const _GET_KEYPAIR_THEN_PUBKEYH_KNWON = async (pubKeyHash) => {
        // Es wird geprüft ob es sich um den Primären Schlüssel handelt
        if(_localPrimaryKeyPair !== null) {
            if(Buffer.compare(_localPrimaryKeyPair.nhash, pubKeyHash) === 0) return _localPrimaryKeyPair;
        }

        // Es werden alle Schlüsselpaar durchsucht um zu prüfen ob es einen Identischen Wert gibt
        for(const otem of _localKeyPairs.keys()) {
            const sockKPair = _localKeyPairs.get(otem);

            // Es wird geprüft ob es sich um einen String handelt
            if(Buffer.compare(sockKPair.nhash, pubKeyHash) === 0) return sockKPair;
        }

        // Es wurde kein Ergebniss gefunden
        return null;
    };

    // Wird verwendet um einen neue Verbindung zu Registrieren
    const _REGISTER_NEW_CONNECTION = async (connObj, pprotFnc, callback) => {
        // Es wird geprüft ob es sich um ein Objekt handelt
        if(typeof connObj !== 'object') { await callback(true); return; }

        // Es wird geprüft ob es bereits eine Verbindung mit dem Peer gibt
        if(_peerPubKeys.includes(connObj.getPeerPublicKey())) { await callback(false); return; }

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
            baseIo:connObj,
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
        try {
            const nodeEPAddResult = await _rManager.addNodeEP(connObj.sessionId(), routingFunctions);
            if(nodeEPAddResult !== true) { console.log('INVALID_RESULT_FROM_ROUTING_UNIT_BY_ADDING_EP'); await callback(false); return; }
            const addressEP = await _rManager.addRoute(connObj.sessionId(), connObj.getPeerPublicKey(), connObj.getPingTime());
            if(addressEP !== true) { console.log('INVALID_RESULT_FROM_ROUTING_UNIT_BY_ADDING_ADDRESS'); await callback(false); return; }
        }
        catch(e) { console.log(e); callback(false); return; }

        // Der Vorgang wurde erfolgreich durchgeführt
        await callback(true);
    };

    // Wird verwendet um eine Registrierte Verbindung zu Entfernen
    const _UNREGISTER_CONNECTION = async (connObj, callback) => {
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
    const _START_PEER_SERVICES = async (connObj, cfunction) => {
        // Die Verfügbaren Funktionen werden gestartet
        for(const otem of cfunction) {
            switch(otem) {
                // Gibt an, dass es sich um einen BootNode handelt
                case 'boot_node':
                    await _START_BOOT_NODE_PEER_REQUEST(connObj);
                    break
                // Es handelt sich um eine Unbekannte funktion
                default:
                    log('Ignored function');
                    break;
            }
        }
    };

    // Nimmt befehlspakete entgegen
    const _ENTER_CMD_PACKAGES = async (package, connObj) => {
        /// Es wird geprüft ob die benötigten Datenfelder vorhanden sind
        if(!package.hasOwnProperty('cmd')) { console.log('Invalid command package'); connObj.close(); return; }
        switch(package.cmd) {
            case 'boot_node_client_start':
                // Es wird geprüft ob die Funktion unterstützt wird
                if(!localNodeFunctions.includes('boot_node')) { console.log('Invalid command package'); connObj.close(); return; }

                // Der Vorgang wird gestartet
                await _START_SEND_BOOT_NODE_PEER_RESPONSE(connObj);

                // Das Paket wird gelöscht
                delete package;
        }
    };

    // Nimmt eintreffende Response Pakete entgegen
    const _ENTER_RESPONSE_PACKAGES = async (package, connObj) => {
        // Es wird geprüft ob die benötigten Datenfelder vorhanden sind
        if(!package.hasOwnProperty('cmd')) { connObj.close(); console.log('AT4TR'); return; }
        if(!package.hasOwnProperty('data')) { connObj.close(); console.log('AT5TR'); return; }
        if(!package.data.hasOwnProperty('ep')) { connObj.close(); console.log('AT6TR'); return; }
        if(!package.data.hasOwnProperty('conf')) { connObj.close(); console.log('AT7TR'); return; }
        if(!package.data.conf.hasOwnProperty('tor')) { connObj.close(); console.log('AT8TR'); return; }

        // Es wird geprüft ob es sich um einen gültigen Response befehl handelt
        switch(package.cmd) {
            case 'boot_node_endpoint':
                await _ENTER_PEER_ENDPOINT_PACKAGE(package.data, connObj);
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

        // Das Paketobjekt wird geklont
        let clonedObj = { ...sigantedFrame };

        // Es wird geprüft ob die Länge des Öffentlichen Schlüssels korrekt ist
        if(sigantedFrame.source.length !== 64) return false;

        // Es wird geprüft ob die Länge der Signatur korrekt ist
        if(sigantedFrame.ssig.length !== 64) return false;

        // Die Signatur wird geprüft
        delete clonedObj.ssig, clonedObj.pkey;
        if(verify_digest_sig(get_hash_from_dict(clonedObj), sigantedFrame.ssig, Buffer.from(sigantedFrame.source, 'hex')) === false) return false;

        // Es wird geprüft ob die Signatur korrekt ist
        return true;
    };

    // Signiert ein Frame
    const _SIGN_FRAME = (privKey, unsignedFrame) => {
        // Das Paket wird Signiert
        const packageSig = sign_digest(get_hash_from_dict(unsignedFrame), privKey.privateKey);

        // Das Finale Paket wird Signiert
        return Object.assign(unsignedFrame, { source:Buffer.from(privKey.publicKey).toString('hex'), ssig:packageSig });
    };

    // Nimmt Pakete für Lokale Sockets entgegen
    const _ENTER_LOCAL_SOCKET_PACKAGES = async (layertpackage, connObj, sdeph, callback) => {
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
    const _ENTER_LOCAL_LAYER2_PACKAGE = async (packageFrame, connObj, retrivedKeyPair, callback) => {
        // Der Paketinhalt wird entschlüsselt
        decrypt_anonymous_package(packageFrame.body.ebody, retrivedKeyPair.privateKey, retrivedKeyPair.publicKey, async (error, decryptedPackage) => {
            // Es wird geprüft ob ein Fehler aufgetreten ist
            if(error !== null) { callback(error); return; }

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

                // Die Pong Daten werden verschlüsselt
                const pongData = { type:'pong', sptnt:30000, packRHash:packageRandomHash };

                // Die Pong Daten werden verschlüsselt
                encrypt_anonymous_package(pongData, Buffer.from(packageFrame.source, 'hex'), (error, result) => {
                    // Das Frame wird Signiert
                    const signatedFrame = _SIGN_FRAME(retrivedKeyPair, {
                        source:Buffer.from(retrivedKeyPair.publicKey).toString('hex'),
                        destination:packageFrame.source,
                        body:{
                            ebody:result,
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
                });
            }
            // Das Paket wird weiterverabeitet
            else {
                // Es wird versucht den RawEP abzurufen
                const openEP = _openRawEndPoints.get(endPointHash);

                // Es wird geprüft ob es sich um ein Pong Paket handelt, wenn ja wird es direkt weitergegeben
                if(decryptedPackage.type === 'pong') {
                    // Es wird geprüft ob der EndPunkt vorhanden ist
                    if(openEP === undefined) { callback(false); return; }

                    // Das Paket wird an den Lokalen EndPunt übergeben
                    openEP.enterPackage({ ...packageFrame, body:{ ebody:decryptedPackage } }, connObj, (r) => {
                        if(r === true) callback(true);
                        else callback(false);
                    });

                    // Der Vorgang wird beendet
                    return;
                }

                // Es wird geprüft ob es sich um ein gültiges Layer 3 Paket handelt
                if(verifyLayerThreePackage(decryptedPackage) === false) { callback(false); return; }

                // Das Paket wird weiterverabeitet
                await _ENTER_LOCAL_SOCKET_PACKAGES({ ...packageFrame, body:{ ebody:decryptedPackage } }, connObj, endPointHash, () => {
                    callback(true);
                });
            }
        });
    };

    // Nimt eintreffende Pakete entgegen
    const _ENTER_RECIVED_SECOND_LAYER_PACKAGES = async (package, connObj) => {
        // Es wird geprüft ob es sich um ein Gültiges Layer 2 Paket handelt
        if(verifyFirstSecondLayerPackageBase(package) !== true) {
            console.log('INVALID_SECOND_LAYER_PACKAGE', package.frame);
            return;
        }

        // Es wird geprüft ob die Frame Signatur korrekt ist
        if(_VERIFY_FRAME_SIGNATURE(package.frame) !== true) {
            console.log('INVALID_FRAME_SIGANTURE_PACKAGE_DROPED', package.frame);
            return;
        }

        // Log
        dprintok(10, ['Package'], [colors.FgRed, get_hash_from_dict(package.frame).toString('base64')], ['recived over'], [colors.FgMagenta, connObj.sessionId()], ['from ', colors.FgYellow, package.frame.source]);

        // Es wird geprüft ob es sich bei dem Empfänger um eine Lokale Adresse handelt, wenn nicht wird das Paket an den Routing Manager übergeben
        const fKeyPair = await _GET_KEYPAIR_THEN_PUBKEY_KNWON(package.frame.destination);
        if(fKeyPair !== null && fKeyPair !== false) {
            // Es wird geprüft ob es für die Quelle eine Route gibt
            const rootCheck = await _rManager.hasRoutes(package.frame.source, connObj.sessionId());
            if(rootCheck !== true) { await _rManager.addRoute(connObj.sessionId(), package.frame.source, null, 60000); }

            // Der Routing Manager wird Signalisiert das ein Paket emfpangen wurde
            await _rManager.signalPackageReciveFromPKey(package.frame.source, package.frame.destination, connObj);

            // Das Paket wird Lokal weiter verarbeitet
            await _ENTER_LOCAL_LAYER2_PACKAGE(package.frame, connObj, fKeyPair, async (packageState) => {
                // Es wird geprüft ob das Paket erfolgreich verarbeitet wurde
                if(packageState !== true) {  }
            });
        }
        else {
            // Das Paket wird an die Routing Unit übergeben
            _rManager.enterIncommingLayer2Packages(package.frame.source, package.frame.destination, package.frame, connObj);
        }
    };

    // Nimmt eintreffende Routing Request Pakete entgegen
    const _ENTER_ROUTING_REG_RESP_PACKAGE = async (package, connObj) => {
        // Es wird geprüft ob es sich um korrektes Routing Request oder Routing Response Package handelt
        if(isValidateRoutingRequestOrResponsePackage(package) !== true) {
            console.log('INVALID_PACKAGE', package);
            return;
        }

        // Speichert die Zeit ab, wann das Paket empfangen wurde
        const package_recived_date = Date.now();

        // Es wird geprüft ob es sich um ein Request oder ein Response Paket handelt
        if(package.type === 'rreq') {
            // Es wird geprüft ob es sich um ein gültiges Routing Request Package handelt
            if(isValidateRoutingRequestPackage(package) !== true) {
                console.log('INVALID_PACKAGE', package);
                return;
            }

            // Die Prozess Id wird erstellt
            const comparedData = Buffer.from([ ...package.saddr, ...package.phantom_key ]);
            const hashedData = double_sha3_compute(comparedData);

            // Es wird geprüft ob die Session Signatur korrekt ist
            if(verify_digest_sig(hashedData, package.rsigs.proc, package.proc_sid) !== true) {
                console.log('INVALID_PACKAGE', package);
                return;
            }

            // Das Objekt wird Dupliziert um die PhantomKey Signtur zu überprüfen
            const clonedObj = { ...package }; delete clonedObj.rsigs; delete clonedObj.ttl; delete clonedObj.sig; delete clonedObj.version;

            // Es wird geprüft ob die Phantom Signatur korrekt ist
            if(verify_digest_sig( get_hash_from_dict(clonedObj), package.rsigs.phantom, package.phantom_key) !== true) {
                console.log('INVALID_PACKAGE', clonedObj, package);
                return;
            }

            // Die Ablaufzeit wird angepasst
            const modifyed_ttl = package.ttl - connObj.getPingTime();

            // Es wird geprüft ob es sich um eine Lokale Adresse handelt, wenn ja wird das Paket beantwortet
            const retrivedKeyPair = await _GET_KEYPAIR_THEN_PUBKEYH_KNWON(package.saddr);
            if(retrivedKeyPair !== null) {
                // Es wird versucht die Optionen zu Entschlüsseln
                decrypt_anonymous_package(package.options, retrivedKeyPair.privateKey, retrivedKeyPair.publicKey, (decryp_error, decrypted_result) => {
                    // Es wird geprüft ob ein Fehler aufgetreten ist
                    if(decryp_error !== null) {
                        console.log('INVALID_ROUTING_PACKGE_OPTIONS_INVALID');
                        return;
                    }

                    // Es wird versucht den PhantomKey nachzubilden
                    compute_shared_secret(retrivedKeyPair.privateKey, package.proc_sid, (retrived_error, shared_secret) => {
                        // Es wird geprüft ob ein Fehler aufgetreten ist
                        if(retrived_error !== null) {
                            console.log('RETRIVED_PCKG');
                            return;
                        }

                        // Aus dem DH Schlüssel wird ein neues Schlüsselpaar abgeleitet
                        const phantomKeyPair = create_deterministic_keypair(shared_secret, "0/0/0");

                        // Es wird geprüft ob die Schlüssel Identisch sind
                        if(Buffer.compare(Buffer.from(phantomKeyPair.publicKey), Buffer.from(package.phantom_key)) !== 0) {
                            console.log('INVALID_RETRO');
                            return;
                        }

                        // Die Anfrage wird an den Routing Manager übergeben um den Vorgang zu beantworten
                        _rManager.enterIncommingAddressSearchRequestProcessDataLocal(package.proc_sid, package.rsigs.proc, package.saddr, retrivedKeyPair, decrypted_result, package_recived_date, phantomKeyPair, package.start_ttl, connObj).catch((e) => { });
                    });
                });
            }
            else {
                // Das Paket wird an den Routing Manager übergeben
                await _rManager.enterIncommingAddressSearchRequestProcessDataForward(package.proc_sid, package.rsigs.proc, package.phantom_key, package.rsigs.phantom, package.saddr, modifyed_ttl, package.start_ttl, package.options, package_recived_date, connObj);
            }
        }
        else if(package.type === 'rrr') {
            // Die Antwort wird an den Routing Manager übergeben

        }
        else {
            // Es handelt sich um ein Unbeaknntes Paket, es ist ein Unbekannter Fehler aufgetreten
            console.log('INTERNAL_ERROR');
            return;
        }
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
        // Listet alle Verbindungen auf
        getAllConnections:(root, callback) => {
            // Es werden alle Verbindungen abgerufen und verarbeitet
            let retrived = [];
            for(const otem of _openConnectionPeers.keys()) {
                const tempItem = _openConnectionPeers.get(otem);
                if(tempItem !== undefined) retrived.push({
                    version: tempItem.peerVersion(),
                    session_id:`0x${tempItem.sessionId()}`,
                    connected_since:`${tempItem.connectedSince()}`,
                    enabeld_services: tempItem.protFunctions(),
                    end_point:{ type: tempItem.type(), addr: tempItem.getPeerIPAddressUrl() },
                    io_data:{ send_bytes: tempItem.rxBytes(), recive_bytes: tempItem.txBytes() },
                });
            }

            // Die Daten werden zurückgegben
            callback(null, retrived);
        },
        // Listet alle bekannten Routen auf
        getAllKnownAddressRoutes:(root, callback) => {
            _rManager.listRoutes().then((ritem) => {
                // Die Daten werden abgerufen und verarbeitet
                let retrived = [];
                for(const tempItem of ritem) {
                    retrived.push({
                        address:tempItem,
                    }); 
                }

                // Die Daten werden zurückgegben
                callback(null, retrived);
            });
        },
        // Listet alle Lokalen Adressen auf
        getAllLocalAddresses:(root, callback) => {
            let retrived = [ convert_pkey_to_addr(Buffer.from(_localPrimaryKeyPair.publicKey)) ];
            for(const otem of _localKeyPairs.keys()) { retrived.push(convert_pkey_to_addr(Buffer.from(otem, 'hex'))); }
            callback(null, retrived);
        }
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
            wsConnectTo(_localPrimaryKeyPair, _SOCKET_FUNCTIONS, readedURL.toString(), localNodeFunctions, accepted_functions, _FNC_OPEN_CONNECTION, _FNC_CLOSED_CONNECTION);
        }
    };

    // Wird verwendet um eine Adressroute abzufagen
    const initAddressRoute = (publicKey, callback=null, maxRecivingResponses=1, timeout=consensus.ttl_for_routing_request) => {
        // Es wird geprüft ob es sich um die Lokale Adresse handelt, wenn ja wird der Vorgang abgerbrochen!
        if(Buffer.from(_localPrimaryKeyPair.publicKey).toString('hex') === publicKey) {
            callback('aborted_is_local_address');
            return;
        }

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
                // Es wird über den Routing Manager eine Anfrage an das Netzwerk gestellt um die Route zu ermitteln
                await _rManager.searchAddressRoute(publicKey, null, async (state, rtime) => {

                });
            }
        })();
    };

    // Gibt einen RAW EndPoint zurück
    const getAddressRawEndPoint = (destPublicKey, callback=null, addressRawEpConfig=_DEFAULT_ADDRESS_RAW_EP) => {
        (async() => {
            // Aus der Empfänger Adresse sowie der Absender Adresse wird ein Hash erstellt
            const endPointHash = crypto.createHash('sha256')
            .update(Buffer.from(destPublicKey, 'hex'))
            .update(Buffer.from(_localPrimaryKeyPair.publicKey))
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
                callback('NO_ADDRESS_ROUTE_FOUND');
                return;
            }

            // Das AddressRawEndPoint Objekt wird erstellt
            const ipeResult = await addressRawEndPoint(_RAW_FUNCTIONS, routeEP, _localPrimaryKeyPair, destPublicKey, CRYPTO_FUNCTIONS, addressRawEpConfig, (error, arep) => {
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
        newEntry.set('*', createLocalSocket(modfifRAWFunctions, _localPrimaryKeyPair, sockType, localPort, (error, sockobj) => {
            // Es wird geprüft ob ein Fehler aufgetreten ist
            if(error !== null) { callback(error); return; }

            // Die Callback Funktion wird aufgerufen
            callback(null, sockobj);
        }));

        // Der Socket wird abgespeichert
        _openSockets.set(localPort, newEntry);
    };

    // Wird als Objekt Funktionen verwendet
    if(isNodeOnPCLaptopOrEmbeddedLinuxSystem() === true) {
        // Wir verwendet um einen Websocket Server zu erstellen (Ip / Tor)
        const addNewWSServer = (localPort, localIp=null, isTor=false, privKeyPath=null) => {
            // Erzeugt ein neues Websocket Server objekt
            const serverObj = wsServer(_localPrimaryKeyPair, _SOCKET_FUNCTIONS, localPort, localIp, localNodeFunctions);

            // Das Serverobjekt wird abgespeichert
            _serverSockets.set(serverObj._id, serverObj);
        };

        // Wird als Steuerobjekt verwendet, sobald es sich um ein PC oder Laptop handelt
        const _OBJ_FUNCTIONS = {
            apiFunctions:_API_FUNCTIONS,
            addNewWSServer:addNewWSServer,
            initAddressRoute:initAddressRoute,
            createNewLocalSocket:createNewLocalSocket,
            getAddressRawEndPoint:getAddressRawEndPoint,
            addPeerClientConnection:addPeerClientConnection,
            api:_API_FUNCTIONS
        };
    
        // Das Objekt wird zurückgegben
        if(nodeCallback !== undefined && nodeCallback !== null) { nodeCallback(_OBJ_FUNCTIONS); }
        return _OBJ_FUNCTIONS
    }
    else {
        throw new Error('Unsupported host');
    }
}

// Die Module werden Exportiert
module.exports = { Node:Node }
