const { dprintok, dprinterror, dprintinfo, colors } = require('./debug');
const { createLayerTwoPackage } = require('./lpckg');
const { get_hash_from_dict } = require('./crypto');
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

    // Speichert ab, weiviele Pakete versendet wurden
    var totalSendPackages = new Map();

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
            // Es wird ein neuer Eintrag hinzugefügt
            const newEntry = new Map();
            newEntry.set(sessionId, processTimestamp);
            addressSessionAddedTime.set(publicKey, newEntry);

            // Es wird geprüft ob einen AddressRawEndPoint für diese Adresse gibt, wenn ja wird diesem Signalisiert dass eine Verbindung verfügbar ist
            const addressRawEP = await openEndPoints.get(publicKey);
            if(addressRawEP !== undefined) addressRawEP.events.routeForAddressAvailable(); 
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

    // Gibt an, wieviele Pakete bereits an diese Verbindung gesendet wurden
    const _getTotalPackagesSendToPKeyAndSession = async (publicKey, sessionId) => {
        let resolved = await totalSendPackages.get(publicKey) ;
        if(resolved === undefined) return null;
        const reso = resolved.get(sessionId);
        if(reso === undefined) return null;
        return reso;
    };

    // Gibt an, wieviele Pakete für diese Verbindung verloren gegangen sind
    const _getLosstPackagesForAddressAndSession = async (publicKey, sessionId) => {
        // Es wird Signalisiert, dass das Paket nicht versendet werden konnte
        if(await losstPackagesOnRoutes.get(publicKey) !== undefined) {
            const v = await losstPackagesOnRoutes.get(publicKey).get(sessionId);
            return v;
        }

        // Es wurde kein Paketverlust gemeldet
        return null;
    };

    // Gibt die Verlustrate einer Verbindung an
    const _getLossRateForAddressAndSession = async (publicKey, sessionId) => {
        // Die insgesamt gesendeten Pakete werden ermittelt
        const totalSend = await _getTotalPackagesSendToPKeyAndSession(publicKey, sessionId);
        if(totalSend === null) return 0;

        // Die Anazhl der Verlorengegenangen Pakete wird ermittelt
        const totalLosstPackages = await _getLosstPackagesForAddressAndSession(publicKey, sessionId);
        if(totalLosstPackages === null) return 0;
        if(totalLosstPackages === 0) return 0;

        // Die Verlustrate wird berechnet
        return ((totalLosstPackages / totalSendPackages) * 100);
    };

    // Gibt an, wann das letzte Paket für diese Verbindung gesendet wurde
    const _lastPackageWasSendForAddrAndSession = async (publicKey, sessionId) => {
        const f = await lastPackageSendToAddress.get(publicKey);
        if(f === undefined) return null;
        const d = await f.get(sessionId);
        if(d === undefined) return null;
        return d;
    };

    // Gibt an, wann das letzte Paket für diese Verbindung empfangen wurde
    const _lastPackageWasReciveForAddressAndSession = async (publicKey, sessionId) => {
        // Dem Cache wird Siganlisiert wann zuletzt ein Paket empfangen wurde
        if(await lastPackageRecivedFromAddress.get(publicKey) !== undefined) {
            const atelv = await lastPackageRecivedFromAddress.get(publicKey).get(sessionId); 
            if(atelv === undefined) return null;
            return atelv;
        }

        // Es wurde kein Eintrag gefunden
        return null;
    };

    // Gibt alle möglichen Peers für eine Route aus
    const _getAllRouteEndPoints = async (publicKey) => {
        // Es werden alle verfügbaren Sitzungen, welche eine Route für diesen PublicKey kennen abgerufen
        const tsid = pkeyToSessionEP.get(publicKey);
        if(tsid === undefined) return [];

        // Es werden alle Einträge aus dem Cache abgerufen
        var returnValue = [];
        for(const otem of tsid){ returnValue.push(sessionEndPoints.get(otem)); };

        // Die Verlustrate der einzelnen Verbindungen wird ermittelt
        let lossRate = [];
        for(const obj of returnValue) {
            const arivedLosstRate = await _getLossRateForAddressAndSession(publicKey, obj.sessionId());
            lossRate.push({ ...obj, lossRate:arivedLosstRate });
        };

        // Die TTL für die Peers wird ermittelt
        let optimizedPeers = [];
        for(const peerItem of lossRate) {
            // Es wird versucht die Aktuelle InitPingTime für die Verbindung abzurufen
            const cip = await initPingTime.get(publicKey);
            if(cip !== undefined) {
                // Es wird geprüft ob es einen Eintrag für die Aktuelle Sitzung gibt
                const sip = await cip.get(peerItem.sessionId());
                if(sip !== undefined) {
                    // Die Aktuelle TTL wird erechnet
                    let prepTTL = Math.ceil(sip * 1.5);
                    if(prepTTL > peerItem.defaultTTL) prepTTL = peerItem.defaultTTL;

                    // Der Peer wird hinzugefügt
                    optimizedPeers.push({ ...peerItem, cttl:prepTTL, httl:true, ottl:sip });

                    // Der Nächste Eintrag wird abgearbeitet
                    continue;
                }
            }

            // Es konnte keine InitPingTime für den Vorgang ermittelt werden, die Standard TTL wird verwendet
            optimizedPeers.push({ ...peerItem, cttl:peerItem.defaultTTL, httl:false });
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
                    dprintok(10, ['Packet'], [colors.FgRed, get_hash_from_dict(package).toString('base64')], ['is sent to'], [colors.FgYellow, publicKey], ['via session'], [colors.FgMagenta, obj.sessionId()]);
                    obj.enterPackage(package, (r) => {
                        const procTime = Date.now() - sendStartTime;
                        dprintok(10, ['Packet'], [colors.FgRed, get_hash_from_dict(package).toString('base64')], ['was sent'], [colors.FgYellow, publicKey], ['in ', colors.FgMagenta, procTime, ' ms'], ['via session'], [colors.FgMagenta, obj.sessionId()]);
                        calb(r, procTime);
                    });
                }};
            fcklTotalReturnValue.push(newObj);
        };

        // Es wird ermittelt, wann die letzten Pakete empfangen wurde
        let nopLastReturn = [];
        for(const obj of fcklTotalReturnValue) {
            const lastSend = await _lastPackageWasSendForAddrAndSession(publicKey, obj.sessionId());
            const lastRecive = await _lastPackageWasReciveForAddressAndSession(publicKey, obj.sessionId());
            nopLastReturn.push({ ...obj, lastRecive:lastRecive, lastSend:lastSend });
        };

        // Die Verbindungen werden nach Socket PingTime sortiert
        const socketPingTimeSortedPeers = nopLastReturn.sort((a, b) => a.pingTime() - b.pingTime());

        // Die Verbindungen werden nach TTL sortiert
        const routePingTimeSortedPeers = socketPingTimeSortedPeers.sort((a, b) => a.cttl - b.cttl);

        // Die Verbindungen werden nach Lange der Bekanntheit Sortiert
        const endPointRoutes = routePingTimeSortedPeers.sort((a, b) => a.csince + b.csince);

        // Die Ermitelten Peers werden zurückgegeben
        return endPointRoutes;
    };

    // Signalisiert das ein Zusammenhängender Sende und Lesevorgang gescheitert ist
    const _signalLossPackage = async (publicKey, sessionId) => {
        // Es wird Signalisiert, dass das Paket nicht versendet werden konnte
        if(await losstPackagesOnRoutes.get(publicKey) !== undefined) {
            const value = await losstPackagesOnRoutes.get(publicKey).get(sessionId);
            await losstPackagesOnRoutes.get(publicKey).set(sessionId, value + 1); 
        }
        else {
            const newEntry = new Map();
            newEntry.set(sessionId, 1);
            losstPackagesOnRoutes.set(publicKey, newEntry);
        }

        // Es wird geprüft ob es sich um die dritte Lost Meldung hintereinadner handelt, wenn ja wird die Route für diesen EndPunkt gelöscht
        console.log('PACKAGE_LOSS');
    };

    // Gibt besten Route für die Verbindung aus
    const _getBestRoutes = async (publicKey, options=null) => {
        // Es werden die Schnellsten Route abgerufen
        const fastedRoutes = await _getAllRouteEndPoints(publicKey);
        if(fastedRoutes === null) return null;

        // Die Verbindungen werden nach zuletzt versendet sortiert
        let notSendedConnections = [], sendedConnections = [];
        for(const otem of fastedRoutes) {
            if(otem.lastSend === null) notSendedConnections.push(otem);
            else sendedConnections.push(otem);
        }

        // Es wird geprüft ob eine Verbindung verfügbar ist
        if(notSendedConnections === null && sendedConnections === null) return null;

        // Die Verbindungen werden nach zuletzt empfangen Paketen sortiert
        let notRecivedConnections = [], recivedConnections = [];
        for(const otem of ((notSendedConnections.length > 0) ? notSendedConnections : sendedConnections)) {
            if(otem.lastRecive === null) notRecivedConnections.push(otem);
            else recivedConnections.push(otem);
        }

        // Es wird geprüft ob eine Verbindung verfügbar ist
        if(notRecivedConnections === null && recivedConnections === null) return null;

        // Es wird geprüft ob es nicht genutzte verbindungen gibt, wenn ja werden diese Verbindung bevorzugt ausgewählt
        if(notRecivedConnections.length > 0) {
            return ((notRecivedConnections.length > 0) ? notRecivedConnections : recivedConnections);
        }

        // Die Verbindungen werden nach am Längsten bestehenden und am längste nicht Versendet sortiert
        const c_best_routes = recivedConnections.sort((a, b) => a.lastRecive - b.lastRecive);
        return c_best_routes;
    };

    // Gibt die Optimalste Route für eine Verbindung aus
    const _getOptimalRouteForAddress = async (publicKey, options=null) => {
        // Die besten Routen für die Adresse werden abgerufen
        const best_routes_return = await _getBestRoutes(publicKey, options);
        if(best_routes_return === undefined || best_routes_return === null) return null;

        // Die erste Verbindung wird zurückgegeben
        const optimal_route =  best_routes_return[0];
        dprintinfo(10, ['Connection selected for sending package'], [colors.FgMagenta, optimal_route.sessionId()]);
        return optimal_route;
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
            signalPackageSend:async (soruce, connobj, timest=Date.now()) => await _signalPackageTransferedToPKey(soruce, publicKey, connobj, timest),
            getInitPingTimeForSession:async (sessionId) => _getInitPingTime(publicKey, sessionId),
            signalLossPackage:async (sessionId) => await _signalLossPackage(publicKey, sessionId),
            getOptimalRouteEndPoint:async () => await _getOptimalRouteForAddress(publicKey),
            registerEvent:(eventName, listner) => eventEmitter.on(eventName, listner),
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
                routeForAddressAvailable:() => eventEmitter.emit('routeForAddressAvailable')
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
        // Dem Cache wird Siganlisiert wann zuletzt ein Paket empfangen wurde
        if(await lastPackageSendToAddress.get(destPubKey) !== undefined) { await lastPackageSendToAddress.get(destPubKey).set(connObj.sessionId(), timestamp); }
        else {
            const newEntry = new Map();
            newEntry.set(connObj.sessionId(), timestamp);
            lastPackageSendToAddress.set(destPubKey, newEntry);
        }

        // Es wird Signalisiert der WV Vorgang der Signalisierung das ist
        const currentValue = await totalSendPackages.get(destPubKey);
        if(currentValue !== undefined) {
            const cint = await currentValue.get(connObj.sessionId());
            if(cint !== undefined) { (await totalSendPackages.get(destPubKey)).set(connObj.sessionId(), cint + 1); }
            else {
                const newEntry = new Map();
                newEntry.set(connObj.sessionId(), 1);
                totalSendPackages.set(destPubKey, newEntry);
            }
        }
        else {
            const newEntry = new Map();
            newEntry.set(connObj.sessionId(), 1);
            totalSendPackages.set(destPubKey, newEntry);
        }

        // Debug Log
        dprintinfo(10, ['Outgoing packet from'], [colors.FgYellow, publicKey], ['to'], [colors.FgYellow, destPubKey], ['was send']);

        // Der Vorgang wurde erfolgreich durchgeführt
        return true;
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
        dprintinfo(10, ['Incoming packet from'], [colors.FgYellow, publicKey], ['to'], [colors.FgYellow, destiPubKey], ['was received']);

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
                dprintinfo(10, ['Packet'], [colors.FgRed, get_hash_from_dict(framePackage).toString('base64')], ['was successfully forwarded from'], [colors.FgMagenta, connObj.sessionId()], ['to'], [colors.FgMagenta, firstConnection.sessionId()], ['in'], [colors.FgYellow, Date.now() - cts, colors.Reset, ' ms.'])
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
        // Die Besten Routen für das Ziel werden abgerufen
        _getBestRoutes(destination).then((best_routes) => {
            // Es wird geprüft ob eine Route verfügbar ist
            if(best_routes === null) {
                console.log('PACKAGE_DROPED_UNKOWN_DESTINATION');
                return;
            }

            // Speichert ab, die wieviele Senderounde das ist
            let currentSendRound = 0;

            // Wird verwendet um das eigentliche Paket abzusenden
            const _spckfnc = () => {
                // Es wird geprüft ob noch ein Eintrag vorhanden ist
                if(best_routes.length === 0) {
                    callbackSend('no_routes_avail');
                    return;
                }

                // Es wird eine Runde nach oben gezählt
                currentSendRound += 1;

                // Der erste eintrag wird ausgewählt
                const fextracted = best_routes.pop();

                // Das Paket wird gebaut und Signiert
                const unsignatedPackage = createLayerTwoPackage(fextracted.peerVersion(), framePackage);
                const signatedPackage = signWithNodeKey(unsignatedPackage);

                // Es wird geprüft ob die Verbindung mit diesem Peer besteht
                if(fextracted.isConnected() !== true) _spckfnc();

                // Das Paket wird an den Peer gesendet
                fextracted.enterPackage(signatedPackage, (sendOk) => {
                    if(sendOk === true) {
                        _signalPackageTransferedToPKey(framePackage.soruce, destination, fextracted).then(() => {
                            callbackSend(true);
                        });
                    }
                    else {
                        if(best_routes.length === currentSendRound) {
                            callbackSend(false);
                            return;
                        }
                        else {
                            _spckfnc();
                        }
                    }
                });
            };

            // Es wird versucht das Paket abzsuenden
            _spckfnc();
        });
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
        signalPackageTransferedToPKey:_signalPackageTransferedToPKey
    };
};


module.exports = { routingManager:routingManager }