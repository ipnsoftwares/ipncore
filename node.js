const { verifyLayerThreePackage, verifyFirstSecondLayerPackageBase, isValidateRoutingRequestOrResponsePackage, isValidateRoutingRequestPackage, isValidateRoutingResponsePackage } = require('./lpckg');
const { get_hash_from_dict, decrypt_anonymous_package, encrypt_anonymous_package, verify_digest_sig, sign_digest, create_deterministic_keypair, convert_pkey_to_addr } = require('./crypto');
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
    const _GET_KEYPAIR_THEN_PUBKEYH_KNWON = (pubKeyHash) => {
        // Es wird geprüft ob es sich um den Primären Schlüssel handelt
        if(_localPrimaryKeyPair !== null) {
            if(Buffer.from(_localPrimaryKeyPair.dpkhash).toString('hex') === pubKeyHash) return _localPrimaryKeyPair;
        }

        // Es werden alle Schlüsselpaar durchsucht um zu prüfen ob es einen Identischen Wert gibt
        for(const otem of _localKeyPairs.keys()) {
            const sockKPair = _localKeyPairs.get(otem);

            // Es wird geprüft ob es sich um einen String handelt
            if(sockKPair.dpkhash.toString('hex') === pubKeyHash) return sockKPair;
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

    /**
     * @deprecated Replaced by Artemis Protocol
    */
    // Sendet ein Routing Response an einen Peer
    const _SEND_ROUTING_RESPONSE = async (oneTimeAddressRequest, timeout, connObj, procId, retrLocalKeyPair, callback) => {
        // Es wird ein OpenRouteResponseSessionPackage gebaut
        const openRouteSessionPackage = {
            type:'rrr',                                         // Gibt an dass es sich um ein Routing Request Package handelt
            version:consensus.version,                          // Gibt die Aktuelle Versions des Nodes an
            orn:oneTimeAddressRequest,                          // Gibt den OneTimeRequest wert an
            addr:Buffer.from(retrLocalKeyPair.publicKey),       // Gibt die Gefundende Adresse an
            timeout:timeout                                     // Gibt an, wann das Paket abläuft
        };

        // Aus dem OneTime Value und der Adresse wird ein Hash erstellt
        const decodedProcId = Buffer.from(procId, 'hex');
        const addrSig = sign_digest(decodedProcId, retrLocalKeyPair.privateKey);

        // Das Finale Paket wird gebaut
        const finalPackage = Object.assign(openRouteSessionPackage, { addrsig:Buffer.from(addrSig).toString('hex') });

        // Das Paket wird an die gegenseite gesendet
        connObj.sendUnsigRawPackage(finalPackage, () => {
            callback(true); 
        });
    };

    // Nimmt eintreffende Routing Request Pakete entgegen
    const _ENTER_ROUTING_REG_RESP_PACKAGE = async (package, connObj) => {
        // Es wird geprüft ob es sich um korrektes Routing Request oder Routing Response Package handelt
        if(isValidateRoutingRequestOrResponsePackage(package) !== true) {
            console.log('INVALID_PACKAGE');
            return;
        }

        // Es wird geprüft ob die Timeout grenze erreicht wurde
        const toutTime = package.timeout - connObj.getPingTime();
        if(toutTime <= 0) {
            console.log('PACKAGE_DROPED_TIMEOUT');
            return; 
        }

        // Speichert die Aktuelle Startzeit des Prozzeses ab
        const processStartingTime = Date.now();

        // Gibt an, wieviele Antworten Maximal erlaubt sind
        const maxRequestesForCurrentPorcessAllowed = 3;

        // Es wird geprüft ob es sich um eine Anfrage oder eine Antwort handelt
        if(package.type === 'rreq') {
            // Es wird geprüft ob es sich um ein Routing Request Package handelt
            if(isValidateRoutingRequestPackage(package) !== true) {
                console.log('PACKAGE_DROPED_INVALID_PACKAGE');
                return; 
            }

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
                await resolvedOpenProcs.retrvPackage(package, connObj)
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

                    // Es wird geprüft ob bereits 1 Pakete beantwortet wurden, wenn ja wird der Vorgang abgebrochen
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
                    await _SEND_ROUTING_RESPONSE(package.orn, newTTL, nconnobj, reqProcId, retivedKeyPair, (r) => {
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
                await _SEND_ROUTING_RESPONSE(package.orn, newTTL, connObj, reqProcId, retivedKeyPair, (r) => {
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
            else {
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
                        console.log('PACKAGE_DROPED_THIS_NODE_HAS_NOT_REQUESTED', reqProcId);
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
                    const _FORWARD_RESPONSE_PACKAGE = (rpackage, connObjX) => {
                        console.log('FORWARD', rpackage)

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
                        const openRouteSessionPackage = { type:'rrr', version:consensus.version, orn:rpackage.orn, addr:rpackage.addr, addrsig:rpackage.addrsig, timeout:newPackageTTL };

                        // Das Paket wird abgesendet
                        firstExtractedPeer.ep.sendUnsigRawPackage(openRouteSessionPackage, (r) => {
                            dprintok(10, ['The routing response packet for event'], [colors.FgCyan, basedReqProcId], ['was sent to session'], [colors.FgMagenta, connObj.sessionId(), colors.Reset, '.']);
                        });
                    };

                    // Das Paket wird an die Peers weitergeleitet
                    _FORWARD_RESPONSE_PACKAGE(rpackage, connObjX);
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
                _BRODCAST_ADDRESS_ROUTE_REQUEST_PACKAGE(package.addrh, toutTime, connObj, processStartingTime, package.orn, _IS_KNOWN_SESSION, _ENTER_SEND_PACKAGE_SESSION_ID, _FIRST_PACKAGE_WAS_SEND, retrivedOnlyPeersList)
                .catch((E) => {});
            }
        }
        else if(package.type === 'rrr') {
            // Es wird geprüft ob es sich um ein Routing Response Paket handelt
            if(isValidateRoutingResponsePackage(package) !== true) {
                console.log('PACKAGE_DROPED_INVALID_PACKAGE');
                return; 
            }

            // Es wird ein Doppelter Hash aus der Adresse wird erzeugt
            const firstHash = crypto.createHash('sha256').update(package.addr).digest();
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
            await openProcess.retrvPackage(package, connObj)
        }
        else {
            connObj.close();
            console.log('UNKOWN_ERROR');
            return; 
        }
    };

    /**
     * @deprecated Replaced by Artemis Protocol
    */
    // Sendet ein AddressRouteRequestPackage an alle Netzwerkteilnehmer
    const _BRODCAST_ADDRESS_ROUTE_REQUEST_PACKAGE = async (addressHash, timeout, sourceConnection, processStartingTime, randSessionId, isKnownSession, enterSendPackageSessionId, firstPackageSendCallback, onlyPeers=[], callback=null) => {
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
        const _PACKAGE_SEND_LOOP_FUNCTION = async () => {
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
                if(isKnownSession(firstExtractedPeer.sessionId()) === true) { await _PACKAGE_SEND_LOOP_FUNCTION(); return; }
            }

            // Es wird ermittelt wielange es gedauert hat
            const procTTL = Date.now() - processStartingTime;
            const newPackageTTL = timeout - procTTL;

            // Es wird ein OpenRouteSessionPackage gebaut, Consensus(ARTEMIS, INIP001, CLEAR-REQUEST)
            const openRouteSessionPackage = {
                type:'rreq',
                version:consensus.version,
                orn:randSessionId, 
                addrh:addressHash,
                timeout:newPackageTTL
            };

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
                _PACKAGE_SEND_LOOP_FUNCTION().catch((E) => {});
            });
        };

        // Das versenden der Daten wird gestartet
        await _PACKAGE_SEND_LOOP_FUNCTION();
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
                await _rManager.searchAddressRoute(publicKey, async (state, rtime) => {

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
