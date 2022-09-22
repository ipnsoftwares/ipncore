const { dprintok, dprinterror, dprintinfo, colors } = require('./debug');
const { getHashFromDict } = require('./crypto');
const consensus = require('./consensus');
const EventEmitter = require('events');
const crypto = require('crypto');



// Routing Manager
const routingManager = (signWithNodeKey) => {
    // Speichert alle Sitzungen ab
    var sessionEndPoints = new Map();

    // Speichert alle Routen ab
    var pkeyToSessionEP = new Map();

    // Speichert ab, wann eine Adresse zuletzt ein Paket empfangen hat
    var publicKeyLastRecivedSendPackageTime = new Map();

    // Speichert elle Publickey Hashes ab
    var publicKeyHashEPs = new Map();

    // Speichert alle Routen für IDs ab
    var idToPkey = new Map();

    // Speichert alle EndPoints ab
    var openEndPoints = new Map();

    // Speichert ab, wann eine Adresse wegen nicht Nutzung gelöscht werden soll
    var deleteAddressRoute = new Map();

    // Speichert ab, wann der Eintrag hinzugefügt wurde
    var addressSessionAddedTime = new Map();

    // Speichert ab, wielange es bei der Adresse gedauert hat bis sie auf ein Routing Request geantwortet hat
    var initPingTime = new Map();

    // Speichert ab, wieoft die InitZeit Justiert wurde
    var justedInitPingTime = new Map();

    // Speichert alle Fehlgeschlagenen Vorgänge ab
    var losstPackagesOnRoutes = new Map();

    // Speichert ab wann das letztemal ein Paket von der Adresse XYZ Empfangen wurde
    var lastPackageRecivedFromAddress = new Map();

    // Speichert ab wann das letzte Paket an die Adresse XYZ über die Sitzung XYZ gesendet wurde
    var lastPackageSendToAddress = new Map();

    // Wird verwendet um eine Route hinzuzufügen
    const _addRotute = async (sessionId, publicKey, routeInitTime, autoDeleteTime=null) => {
        // Es wird ein Zeitstempel für den Vorgang erzeugt
        const processTimestamp = Date.now();

        // Die SessionID wird dem PublicKey zugeordnet
        const rRoutesForPublicKey = await pkeyToSessionEP.get(publicKey);
        if(rRoutesForPublicKey !== undefined && rRoutesForPublicKey !== null) {
            rRoutesForPublicKey.push(sessionId);
            pkeyToSessionEP.set(publicKey, rRoutesForPublicKey);
        }
        else {
            pkeyToSessionEP.set(publicKey, [ sessionId ]);
        }

        // Der PublicKey wird der SessionID zugeordnet
        const rRoutesForID = await idToPkey.get(sessionId);
        if(rRoutesForID !== undefined && rRoutesForID !== null) {
            rRoutesForID.push(publicKey);
            idToPkey.set(sessionId, rRoutesForID);
        }
        else {
            idToPkey.set(sessionId, [ publicKey ]);
        }

        // Die Addresse wird dem Doubble Hash zugeordnet
        const plainBytes = Buffer.from(publicKey, 'hex');
        const firstHash = crypto.createHash('sha256').update(plainBytes).digest();
        publicKeyHashEPs.set(crypto.createHash('sha256').update(firstHash).digest('hex'), publicKey);

        // Die Route wurde erfolgreich hinzugefügt
        dprintok(10, ['Address route'], [colors.FgYellow, publicKey], ['has been added to session'], [colors.FgMagenta, sessionId]);

        // Es wird geprüft ob ein autoDeleteTime eintrag vorhanden ist
        if(autoDeleteTime !== null) {
            // Es wird geprüft ob der Eintrag bereits bekannt ist
            if(await deleteAddressRoute.get(publicKey) !== undefined) {
                await deleteAddressRoute.get(publicKey).set(sessionId, autoDeleteTime); 
            }
            else {
                // Der Eintrag wird hinzugefügt
                const newEntry = new Map();
                newEntry.set(sessionId, autoDeleteTime);
                deleteAddressRoute.set(publicKey, newEntry);
            }
        }

        // Es wird geprüft ob eine Route Init Time angegeben wurde
        if(routeInitTime !== undefined && routeInitTime !== null) { await _avarageInitPingTime(publicKey, sessionId, routeInitTime); }

        // Die Zeit wann der Eintrag der Cache hinzugefügt wurde, wird hinzugefügt
        if(await addressSessionAddedTime.get(publicKey) !== undefined) { await addressSessionAddedTime.get(publicKey).set(sessionId, processTimestamp); }
        else {
            const newEntry = new Map();
            newEntry.set(sessionId, processTimestamp);
            addressSessionAddedTime.set(publicKey, newEntry);
        }

        // Die Operation ist abgeschlossen
        return true;
    };

    // Wird verwendet um eine Route zu entfernen
    const _delRoute = async (publicKey, sessionID=null) => {
        // Es wird nach allen Routen für diesen PublicKey gesucht
        var routesByPublicKey = await pkeyToSessionEP.get(publicKey);
        if(routesByPublicKey === undefined || routesByPublicKey === null){
            console.log(publicKey, sessionID, 'no');
            return false;
        }

        // Es werden alle Einträge Entfernt welche mit diesem PublicKey in verbindung stehen abgerufen
        for(const oitem of routesByPublicKey) {
            // Sollte eine SessionID angegeben wurden sein, wird geprütft ob es sich um diese handelt
            if(sessionID !== null) { if(sessionID !== oitem) { continue; } }

            // Die ID's zum dem PublicKey wird abgerufen
            const tempIdToPublicKey = idToPkey.get(oitem);
            if(tempIdToPublicKey == undefined || tempIdToPublicKey === null) continue;

            // Der Öffentliche Schlüssel wird aus der Sitzung entfernt
            const filteredArray = tempIdToPublicKey.filter(function(ele){ return ele != publicKey; });
            if(filteredArray.length === 0) { idToPkey.delete(oitem); }
            else { idToPkey.set(oitem, filteredArray); }

            // Es wird geprüft ob es einen Eintrag für AutoDeleting gibt
            if(await deleteAddressRoute.get(publicKey) !== undefined) {
                // Es wird geprüft ob es für diese Sitzung einen eintrag gibt
                if(await deleteAddressRoute.get(publicKey).get(oitem) !== undefined) {
                    await deleteAddressRoute.get(publicKey).delete(oitem);
                    if(Array.from(deleteAddressRoute.get(publicKey).keys()).length === 0) deleteAddressRoute.delete(publicKey);
                }
            }

            // Der Eintrag wielange der Routing Vorgang gedauert hat, wird gelöscht
            if(await initPingTime.get(publicKey) !== undefined) {
                // Es wird geprüft ob es für diese Sitzung einen eintrag gibt
                if(await initPingTime.get(publicKey).get(oitem) !== undefined) {
                    await initPingTime.get(publicKey).delete(oitem);
                    if(Array.from(initPingTime.get(publicKey).keys()).length === 0) initPingTime.delete(publicKey);
                }
            }

            // Die Zeit wann der Eintrag hinzugefügt wurde, wird entfernt
            if(await addressSessionAddedTime.get(publicKey) !== undefined) {
                // Es wird geprüft ob es für diese Sitzung einen eintrag gibt
                if(await addressSessionAddedTime.get(publicKey).get(oitem) !== undefined) {
                    await addressSessionAddedTime.get(publicKey).delete(oitem);
                    if(Array.from(addressSessionAddedTime.get(publicKey).keys()).length === 0) addressSessionAddedTime.delete(publicKey);
                }
            }

            // Debug Eintrag
            dprintok(10, ['Address route'], [colors.FgYellow, publicKey], ['has been deleted from session'], [colors.FgMagenta, oitem]);

            // Die Sitzungs wird aus dem Öffentlichen Schlüssel entfernt
            const pkeyToSessionId = await pkeyToSessionEP.get(publicKey);
            pkeyToSessionEP.set(publicKey, pkeyToSessionId.filter(function(ele){ return ele != oitem; }));
            if(await pkeyToSessionEP.get(publicKey).length === 0) {
                // Es wird geprüft ob einen AddressRawEndPoint für diese Adresse gibt
                const addressRawEP = await openEndPoints.get(publicKey);
                if(addressRawEP !== undefined) { addressRawEP.events.allRoutesForAddressClosed(); }

                // Die Adresse wurde erfolgreich gelöscht
                pkeyToSessionEP.delete(publicKey);

                // Die Addres zuordnung wird dem PublicKey enzogen
                const plainBytes = Buffer.from(publicKey, 'hex');
                const firstHash = crypto.createHash('sha256').update(plainBytes).digest();
                publicKeyHashEPs.delete(crypto.createHash('sha256').update(firstHash).digest('hex'));
            }
        }

        // Die Route / Routen wurde erfolgreich entfernt
        return true;
    };

    // Fügt einen Peer End hinzu
    const _addNodeEP = async (sessionId, endPoint) => {
        // Es wird geprüft ob die SessionId bereits bekannt ist
        const sessionEPResult = sessionEndPoints.get(sessionId);
        if(sessionEPResult !== undefined && sessionEPResult !== null) return false;

        // Die SessionID wird Registriert
        dprintok(10, ['Session'], [colors.FgMagenta, sessionId], ['was registered in the routing manager']);
        sessionEndPoints.set(sessionId, endPoint);
        return true;
    };

    // Wird verwendet um alle Routen für einen Node zu entfernen
    const _delNodeEP = async (sessionId) => {
        // Es wird geprüft ob die SessionId bekannt ist
        const sessionEPResult = sessionEndPoints.get(sessionId);
        if(sessionEPResult === undefined || sessionEPResult === null) return false;

        // Es werden alle Einträge welche dieser SessionID zugeordnet sind gelöscht
        const sIdToPkeyResult = idToPkey.get(sessionId);
        if(sIdToPkeyResult !== undefined && sIdToPkeyResult !== null) {
            for(const pkey of sIdToPkeyResult) {
                await _delRoute(pkey, sessionId); 
            }
        }

        // Alle Routen für diese Sitzungen wurden entfernt
        dprintok(10, ['Session'], [colors.FgMagenta, sessionId], ['was unregistered from the routing manager']);
        sessionEndPoints.delete(sessionId);
        return true;
    };

    // Wird verwendet um alle bekannten Routen aufzulisten
    const _listRoutes = async () => {

    };

    // Gibt an ob es eine Route für diesen Key gibt
    const _hasRoute = async (publicKey, sessionId) => {
        // Es wird geprüft ob der Öffenliche Schlüssel für diesen Vorgang bekannt ist
        for(const otem of pkeyToSessionEP.keys()) {
            // Es wird geprüft ob der PublicKey übereinstimmt
            if(otem === publicKey) {
                const valtu = pkeyToSessionEP.get(publicKey);
                if(valtu === undefined) continue;
                if(valtu.includes(sessionId)) return true;
            }
        }

        // Es wurde keine Route gefunden
        return false;
    };

    // Gibt die Verlustrate einer Verbindung an
    const _getLossRate = async (publicKey, sessionId) => {

    };

    // Gibt alle möglichen Peers für eine Route aus
    const _getAllRouteEndPoints = async (publicKey) => {
        // Es werden alle verfügbaren Sitzungen, welche eine Route für diesen PublicKey kennen abgerufen
        const tsid = pkeyToSessionEP.get(publicKey);
        if(tsid === undefined) return [];

        // Es werden alle Einträge aus dem Cache abgerufen
        var returnValue = [];
        for(const otem of tsid){ returnValue.push(sessionEndPoints.get(otem)); };

        // Die TTL für die Peers wird ermittelt
        let optimizedPeers = [];
        for(const peerItem of returnValue) {
            // Es wird versucht die Aktuelle InitPingTime für die Verbindung abzurufen
            const cip = await initPingTime.get(publicKey);
            if(cip !== undefined) {
                // Es wird geprüft ob es einen Eintrag für die Aktuelle Sitzung gibt
                const sip = await cip.get(peerItem.sessionId());
                if(sip !== undefined) {
                    // Die Aktuelle TTL wird erechnet
                    let prepTTL = sip * 3;
                    if(prepTTL > peerItem.defaultTTL) prepTTL = peerItem.defaultTTL;

                    // Der Peer wird hinzugefügt
                    optimizedPeers.push({ ...peerItem, cttl:prepTTL, httl:true });

                    // Der Nächste Eintrag wird abgearbeitet
                    continue;
                }
            }

            // Es konnte keine InitPingTime für den Vorgang ermittelt werden, die Standard TTL wird verwendet
            optimizedPeers.push({ ...peerItem, cttl:optimizedPeers.defaultTTL, httl:false });
        };

        // Es wird ermittelt, wielange die Route bereits bekannt ist
        let finalReturnValues = [];
        for(const iot of optimizedPeers) {
            const cto = await addressSessionAddedTime.get(publicKey);
            if(cto !== undefined) {
                const tro = await cto.get(iot.sessionId());
                if(tro !== undefined) { finalReturnValues.push({ ...iot, csince:tro, hsince:true }); }
            }
            else { finalReturnValues.push({ ...iot, csince:null, hsince:false }); }
        };

        // Die Paket Sende Funktion wird überarbeitet
        let fcklTotalReturnValue = [];
        for(const obj of finalReturnValues) {
            // Die EnterPackage funktion wird überarbeitet
            const newObj = {
                ...obj,
                enterPackage:(package, calb) => {
                    // Das Paket wird versendet
                    const sendStartTime = Date.now();
                    dprintok(10, ['Packet'], [colors.FgRed, getHashFromDict(package).toString('base64')], ['is sent to'], [colors.FgYellow, publicKey], ['via session'], [colors.FgMagenta, obj.sessionId()]);
                    obj.enterPackage(package, (r) => {
                        const procTime = Date.now() - sendStartTime;
                        dprintok(10, ['Packet'], [colors.FgRed, getHashFromDict(package).toString('base64')], ['was sent'], [colors.FgYellow, publicKey], ['in ', colors.FgMagenta, procTime, ' ms'], ['via session'], [colors.FgMagenta, obj.sessionId()]);
                        calb(r, procTime);
                    });
                }};
            fcklTotalReturnValue.push(newObj);
        };

        // Es wird ermittelt, wann die letzten Pakete empfangen wurde
        let nopLastReturn = [];
        for(const obj of fcklTotalReturnValue) {
            nopLastReturn.push({ ...obj, lastRecive:null });
        };

        // Die Verlustrate der einzelnen Verbindungen wird ermittelt
        let finalLastReturn = [];
        for(const obj of nopLastReturn) {
            finalLastReturn.push({ ...obj, lossRate:null });
        };

        // Die Ermitelten Peers werden zurückgegeben
        return finalLastReturn;
    };

    // Gibt die Schenllsten Routen für eine Verbindung aus
    const _getFastedRouteEndPoints = async (publicKey) => {
        // Es wird versucht alle Verfügbaren Routen abzurufen
        const returnValue = await _getAllRouteEndPoints(publicKey);
        if(returnValue === null) return null;
        if(returnValue.length === 0) return null;

        // Es werden alle Verbindungen ohne Connect Since Time oder TTL extrahiert
        let filteredPeers = returnValue.filter((o) => { return o.httl === true && o.hsince === true; });

        // Die Verbindungen werden nach Socket PingTime sortiert
        const socketPingTimeSortedPeers = filteredPeers.sort((a,b) => a.pingTime() - b.pingTime());

        // Die Verbindungen werden nach TTL sortiert
        const routePingTimeSortedPeers = socketPingTimeSortedPeers.sort((a,b) => a.cttl - b.cttl);

        // Die Verbindungen werden nach Lange der Bekanntheit Sortiert
        const endPointRoutes = routePingTimeSortedPeers.sort((a,b) => a.csince + b.csince);

        // Es wird geprüft ob eine EndPoint Route vorhanden ist
        if(endPointRoutes.length === 0) return null;

        // Die Sortierten Verbindungen werden zurückgegeben
        return endPointRoutes;
    };

    // Signalisiert das ein Zusammenhängender Sende und Lesevorgang gescheitert ist
    const _signalLossPackage = async (publicKey, sessionId) => {
        // Es wird Signalisiert, dass das Paket nicht versendet werden konnte
        if(await losstPackagesOnRoutes.get(publicKey) !== undefined) {
            await losstPackagesOnRoutes.get(publicKey).set(sessionId, Date.now()); 
        }
        else {
            const newEntry = new Map();
            newEntry.set(sessionId, Date.now());
            losstPackagesOnRoutes.set(publicKey, newEntry);
        }

        // Es wird geprüft ob es sich um die dritte Lost Meldung hintereinadner handelt, wenn ja wird die Route für diesen EndPunkt gelöscht
        console.log('PACKAGE_LOSS');
    };

    // Gibt die Optimalste Route für eine Verbindung aus
    const _getOptimalRouteForAddress = async (publicKey) => {
        // Es werden die Schnellsten Route abgerufen
        const fastedRoutes = await _getFastedRouteEndPoints(publicKey);
        if(fastedRoutes === null) return null;

        // Die Verbindungen werden nach der Package Loss Rate Sortiert
        let unlostedConnections = [], sortedConnections = [];
        for(const otem of fastedRoutes) {
            // Es wird geprüft ob es für die Verbindung eine LossRate gibt
        }

        // Es wird geprüft, von welcher der Verbindungen zuletzt ein Paket einging

        // Es wird ein Gesamtscore für die Verbindung ermittelt, nach diesem Score werden die Verbindungen sortiert

        // Die erste Verbindung wird ausgegeben
        return fastedRoutes[0];
    };

    // Gibt besten Route für die Verbindung aus
    const _getBestRoutes = async (publicKey) => {
        // Es werden die Schnellsten Route abgerufen
        const fastedRoutes = await _getFastedRouteEndPoints(publicKey);
        if(fastedRoutes === null) return null;

        // Die ersten X Routen (consensus.js::routeingMaxPeers)
        let fetchedOptimalRoutes = [];
        for(const otem of fastedRoutes) {
            fetchedOptimalRoutes.push(otem);
            if(fetchedOptimalRoutes.length === consensus.routeingMaxPeers) break;
        }

        // Die erste Verbindung wird ausgegeben
        return fetchedOptimalRoutes;
    };

    // Gibt die InitPing Zeit einer Route aus
    const _getInitPingTime = (publicKey, sessionId) => {
        const fro = initPingTime.get(publicKey);
        if(fro !== undefined) {
            const frx = fro.get(sessionId);
            if(frx === undefined) return null;
            return frx;
        }
        else {
            return null;
        }
    };

    // Gibt einen Routing Endpoint aus
    const _getRoutingEndPoint = async (publicKey) => {
        // Es wird geprüft ob es sich um einen bekannten PublicKey mit einer zugehörigen Sitzung handelt
        const sessionIds = pkeyToSessionEP.get(publicKey);
        if(sessionIds === undefined) return false;
        if(sessionIds.length === 0) return false;

        // Speichert den eventEmitter ab
        const eventEmitter = new EventEmitter();

        // Diese Funktion gibt an ob die Route für diese Adresse verfügbar ist
        const _ADDRESS_ROUTE_IS_AVAIL = async () => {
            const tsid = await _getOptimalRouteForAddress(publicKey);
            if(tsid === null) return false;
            return true;
        };

        // Wird als Funktionen zurückgegeben
        const _OBJ_FUNCTIONS = {
            getInitPingTimeForSession:async (sessionId) => _getInitPingTime(publicKey, sessionId),
            signalLossPackage:async (sessionId) => await _signalLossPackage(publicKey, sessionId),
            getOptimalRouteEndPoint:async () => await _getOptimalRouteForAddress(publicKey),
            registerEvent:(eventName, listner) => eventEmitter.on(eventName, listner),
            getFastedEndPoints:async () => await _getFastedRouteEndPoints(publicKey),
            getAllPeers:async () => await _getAllRouteEndPoints(publicKey),
            getBestRoutes:async () => await _getBestRoutes(publicKey),
            avarageInitPingTime:_avarageInitPingTime,
            isUseable:_ADDRESS_ROUTE_IS_AVAIL,
        };

        // Der Vorgang wird registriert
        openEndPoints.set(publicKey, {
            usedPeerPublicKeys:[],
            obj:_OBJ_FUNCTIONS,
            events:{
                allRoutesForAddressClosed:() => eventEmitter.emit('allRoutesForAddressClosed'),
            } 
        });

        // Das Objekt wird zurückgegeben
        return _OBJ_FUNCTIONS;
    };

    // Wird verwendet um die Init Time einer Route anzupassen
    const _avarageInitPingTime = async (publicKey, sessionId, pingTime) => {
        // Es wird geprüft ob der Eintrag bereits bekannt ist
        const resolvedObj = await initPingTime.get(publicKey);
        if(resolvedObj !== undefined) {
            await initPingTime.get(publicKey).set(sessionId, pingTime);
            dprintok(10, ['The routing ping for address'], [colors.FgYellow, publicKey], ['on session'], [colors.FgMagenta, sessionId], ['was set to'], [colors.FgYellow, pingTime], ['ms.']);
        }
        else {
            const newEntry = new Map();
            newEntry.set(sessionId, pingTime);
            initPingTime.set(publicKey, newEntry);
            dprintok(10, ['The routing ping for address'], [colors.FgYellow, publicKey], ['on session'], [colors.FgMagenta, sessionId], ['is'], [colors.FgYellow, pingTime], ['ms.']);
        }
    };

    // Signalisiert dass ein Paket an eine bestimmte Adresse erfolgreich übertragen wurde
    const _signalPackageTransferedToPKey = async (publicKey, destPubKey, connObj, timestamp=Date.now()) => {

    };

    // Signalisiert das ein Paket von einer bestimmten Adresse Empangen wurde
    const _signalPackageReciveFromPKey = async (publicKey, destiPubKey, connObj, timestamp=Date.now()) => {
        // Dem Cache wird Siganlisiert wann zuletzt ein Paket empfangen wurde
        if(await lastPackageRecivedFromAddress.get(publicKey) !== undefined) { await lastPackageRecivedFromAddress.get(publicKey).set(connObj.sessionId(), timestamp); }
        else {
            const newEntry = new Map();
            newEntry.set(connObj.sessionId(), timestamp);
            lastPackageRecivedFromAddress.set(publicKey, newEntry);
        }

        // Es wird Signalisiert der WV Vorgang der Signalisierung das ist
        const currentValue = await justedInitPingTime.get(publicKey);
        if(currentValue !== undefined) {
            const cint = await currentValue.get(connObj.sessionId());
            if(cint !== undefined) { (await justedInitPingTime.get(publicKey)).set(connObj.sessionId(), cint + 1); }
            else {
                const newEntry = new Map();
                newEntry.set(connObj.sessionId(), 1);
                justedInitPingTime.set(publicKey, newEntry);
            }
        }
        else {
            const newEntry = new Map();
            newEntry.set(connObj.sessionId(), 1);
            justedInitPingTime.set(publicKey, newEntry);
        }

        // Debug Log
        dprintinfo(10, ['Incoming packet from'], [colors.FgYellow, publicKey], ['to'], [colors.FgYellow, destiPubKey], ['was received.']);

        // Der Vorgang wurde erfolgreich durchgeführt
        return true;
    };

    // Gibt die Schnellste SessionID für diese Verbindung an, sollte keine Verbindung vorhanden sein wird eine leere liste zurück gegegeben
    const _hasRouteByHashAndGetSessions = (publicKeyHash) => {
        // Der Eitnrag wird abgerufen
        const resolved = publicKeyHashEPs.get(publicKeyHash);
        if(resolved === undefined) return false;
        return resolved;
    };

    // Nimmt Eintreffende Pakete entgegen
    const _enterIncommingLayer2Packages = (source, destination, framePackage, connObj) => {
        // Es wird geprüft ob es sich bei der Empfänger Adresse um eine bekannte Adresse handelt
        const endPointSession = pkeyToSessionEP.get(destination);
        if(endPointSession === undefined) {
            console.log('PACKAGE_DROPED_UNKOWN_DESTINATION');
            return;
        }

        // Speichert die Zeit ab, wann das Paket empfangen wurde
        const packageInTime = Date.now();

        // Synchroner Codebereich, wird zum versenden des Paketes verwendet
        const _SYNC_STEP = () => {
            // Speichert ab, wann der PublicKey zuletzt ein Paket empfangen hat
            publicKeyLastRecivedSendPackageTime.set(source, Date.now());

            // Die Daten werden an die erste Verbindung gesendet
            const firstConnection = sessionEndPoints.get(endPointSession[0]);

            // Das Layer 1 Paket wird gebaut
            const prePackage = { crypto_algo:'ed25519', type:'pstr', version:consensus.version, frame:framePackage };

            // Das Paket wird Signiert
            const signatedPackage = signWithNodeKey(prePackage);

            // Seichert die Aktuelle Uhrzeit ab
            const cts = Date.now();

            // Das Paket wird versendet
            firstConnection.enterPackage(signatedPackage, () => {
                dprintinfo(10, ['Packet'], [colors.FgRed, getHashFromDict(framePackage).toString('base64')], ['was successfully forwarded from'], [colors.FgMagenta, connObj.sessionId()], ['to'], [colors.FgMagenta, firstConnection.sessionId()], ['in'], [colors.FgYellow, Date.now() - cts, colors.Reset, ' ms.'])
            })
        };

        // Dem Cache wird Signalisiert dass Soebend ein Paket von dieser Adresse Empfangen wurde
        _signalPackageReciveFromPKey(source, destination, connObj, packageInTime)
        .then(async () => {
            // Es wird geprüft ob die Absender Adresse bekannt ist
            if(pkeyToSessionEP.get(source) === undefined) {
                await _addRotute(connObj.sessionId(), source); 
            }

            // Next
            _SYNC_STEP();
        })
    };

    // Nimmt Pakete entgegen welche versendet werden sollen
    const _enterOutgoingLayer2Packages = (destination, framePackage, callbackSend, revalp=1, directEpObjectToSend=null) => {
        // Es wird geprüft ob es sich bei der Empfänger Adresse um eine bekannte Adresse handelt
        const endPointSession = pkeyToSessionEP.get(destination);
        console.log(destination)
        if(endPointSession === undefined) {
            console.log('PACKAGE_DROPED_UNKOWN_DESTINATION');
            return;
        }

        // Es wird geprüft ob mindestens eine EndPointSession vorhanden ist
        if(endPointSession.length < 1) {
            // Der Vorgang wird abgebrochen, es ist keine Verbindung verfügbar
            console.log('DROPED_NO_PEER_AVAILABLE');
            callbackSend(false);
            return
        }

        (async() => {
            // Die Daten werden an den Schnellsten Node gesendet
            let firstConnection;
            if(directEpObjectToSend !== null) { firstConnection = directEpObjectToSend; }
            else { firstConnection = sessionEndPoints.get(endPointSession[0]); }

            // Es wird geprüft ob die Verbindung abgerufen werden konnte
            if(firstConnection === undefined) {
                console.log('NO_CONNECTION');
                // Es wird versucht den Vorgang zu wiederholen, nachdem dritten Versuch wird der Vorgang abgebrochen
                return;
            }

            // Das Layer 1 Paket wird gebaut
            const prePackage = { crypto_algo:'ed25519', type:'pstr', version:consensus.version, frame:framePackage };

            // Das Paket wird Signiert
            const signatedPackage = signWithNodeKey(prePackage);

            // Das Paket wird versendet
            firstConnection.enterPackage(signatedPackage, () => {
                console.log('PACKAGE_SEND_TO', destination, endPointSession[0]);
                if(callbackSend !== undefined) {
                    callbackSend(true);
                }
            })
        })();
    };

    // Wird von einem Timer ausgeführt und überwacht alle Routen, Routen welche länger als 2 Minuten nicht verwendet wurden, werden entfernt sofern es sich nicht um Peer Root Adressen handelt
    const _ROUTING_MAN_THR_TIMER = async () => {
        // Es werden alle Adressen abgerufen welche eine Ablaufzeit besitzen
        const cobjKeys = deleteAddressRoute.keys();

        // Die Aktuelle Zeit wird ermittelt
        const ctstamp = Date.now();

        // Die Einzelnen Schlüssel werden abgerufen
        for(const otem of cobjKeys) {
            // Es werden alle Sitzungen für diese Adresse abgerufen
            const tempSessions = await deleteAddressRoute.get(otem);
            if(tempSessions === undefined) continue;

            // Die Einzelnen Sitzungen werden abgearbeitet
            for(const xtem of tempSessions.keys()) {
                // Es wird ermittelt wielange der Eintrag im Cache ohne Antwort leben darf
                const tmpsobj = await tempSessions.get(xtem);
                if(tmpsobj === undefined) continue;

                // Es wird ermittelt wann der Eintrag hinzugefügt wurde
                const addedValue = await addressSessionAddedTime.get(otem);
                if(addedValue === undefined) continue;
                const currentSessionValue = await addedValue.get(xtem);
                if(currentSessionValue === undefined) continue;
                if(ctstamp - currentSessionValue >= tmpsobj) {
                    // Es wird geprüft ob ein Paket Empfangen wurde
                    const lrec = lastPackageRecivedFromAddress.get(otem);
                    if(lrec !== undefined) {
                        // Es wird geprüft ob ein Eintrag für die Sitzung vorhanden ist
                        const tro = lrec.get(xtem);
                        if(tro !== undefined) {
                            if(ctstamp - tro >= tmpsobj) _delRoute(otem, xtem);
                        }
                        else _delRoute(otem, xtem);
                    }
                    else _delRoute(otem, xtem);
                }
            }
        }

        // Der Time wird neugestartet
        setTimeout(_ROUTING_MAN_THR_TIMER, 10);
    };

    // Der Routing Timer wird gestartet
    setTimeout(_ROUTING_MAN_THR_TIMER, 10);

    // Das Routing Manager Objekt wird zurückgegeben
    return {
        addRoute:_addRotute,
        delRoute:_delRoute,
        hasRoutes:_hasRoute,
        delNodeEP:_delNodeEP,
        addNodeEP:_addNodeEP,
        listRoutes:_listRoutes,
        getAddressRouteEP:_getRoutingEndPoint,
        hasGetRouteForPkeyHash:_hasRouteByHashAndGetSessions,
        signalPackageReciveFromPKey:_signalPackageReciveFromPKey,
        enterOutgoingLayer2Packages:_enterOutgoingLayer2Packages,
        enterIncommingLayer2Packages:_enterIncommingLayer2Packages,
    };
};


module.exports = { routingManager:routingManager }