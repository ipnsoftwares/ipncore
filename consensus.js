const os = require('os');

// Gibt die kleins Mögliche Version an
const smallest_version = 10000000;

// Speichert die Aktuelle Version ab
const current_version = 10000000;

// Speichert das Aktuelle Netzwerk ab
const current_network = 'IPN';

// Gib die Standard TTL für Tor-Verbindungen an
const tor_based_transport_session_default_ttl = 120000;

// Gib die Standard TTL für I2P-Verbindungen an
const i2p_based_transport_session_default_ttl = 120000;

// Gib die Standard TTL für IP-Verbindungen an
const ip_based_transport_session_default_ttl = 10000;

// Speichert die Größe des Routing Ping Paketes ab
const routing_ping_package = 96;

// Gibt an, wieivele Routen zurückgeggeben werden sollen, wenn die Schnellste Routen ermittelt werden
const routeing_max_peers = 2;

// Speichert ab, aller wieviel MS ein ReRouting durchgeführt werden soll
const re_routing_time = 15000;

// Gibt an, wielange ein Routing Request mmaximal gültig ist
const ttl_for_routing_request = 120000;

// Speichert die Maxiamle größe für Layer 1 Pakete ab
const max_package_byte_size = 1200000;

// Gibt den Pfad des Unix Sockets für die Root freie API an
const unix_socket_none_root_path = `${os.tmpdir()}/${current_network.toLowerCase()}/`;

// Gibt den Pfad des Unix Sockets für die Root API an
const unix_socket_root_path = `${os.tmpdir()}/${current_network.toLowerCase()}/`;

// Speichert die GitHub Url für die Bootnoding Listen ab
const github_bootnode_list_url = 'https://raw.githubusercontent.com/fluffelpuff/ipn-github-bootnoding/main/';

// Speichert die Maximale größe für ein Paket ab
const maximal_package_size = 262553;

// Speichert ab, ob es sich um eine Testversion handelt
const is_mainnet = false;

// Speichert die DNS-Server ab, welche verwendet werden sollen um Anfragen an das Internet zu stellen
const dns_servers = [
    "8.8.8.8",
    "1.1.1.1"
];

// Gibt einzelne INIPS an, welche unterstützt werden
const active_inips = [
    1,                                                  // INIP001 - Artemis Routing Protkoll (Einfaches Routing Protokoll)
    2,                                                  // INIP002 - IP-Basierte Kommunikation über Websockets
    3,                                                  // INIP003 - Bootnode Protokoll, ermöglicht das einwählen in das IPN-Netzwerk
    4,                                                  // INIP004 - Kryptographische Standards
    5,                                                  // INIP005 - Layer 1 und Layer 2 Pakete
    6,                                                  // INIP006
    7,                                                  // INIP007
    8,                                                  // INIP008
    9,                                                  // INIP009
    10,                                                 // INIP010
    11,                                                 // INIP011
    12,                                                 // INIP012 - Bitcoin Unterstützung

];

// Speichert alle IP-Adressen der Bootnodes
const bootnode_public_ip_addresses = [
];

// Speichert alle DNS-Adressen der Bootnodes
const bootnode_public_dns_names = [   
];

// Speichert alle PublicKeys ab, welche im Mainnet Blockiert werden
const main_blocked_public_keys = [
    "4d1363e238850ff3802e6ade30cc91cf8053769536a6ace6b41f7c0143c2a5fc",
    "cfbfa2a334a8640f8ee91bfa120775ba37e667c06aa2a35ae4b1cd42ec893b0a",
    "97e5364e527ed7625b37f71c35f515a68d506aaf7b202e511a290ded3115419e",
    "a581555d777cf7ee303a52a18212a2a1b7b534e730da50b5901d4f9c53e76bca",
];

// Die Variabeln werden Export
module.exports = {
    bootnode_public_ip_addresses:bootnode_public_ip_addresses,
    bootnode_public_dns_names:bootnode_public_dns_names,
    main_blocked_public_keys:main_blocked_public_keys,
    github_bootnode_list_url:github_bootnode_list_url,
    ttl_for_routing_request:ttl_for_routing_request,
    max_package_byte_size:max_package_byte_size,
    maximal_package_size:maximal_package_size,
    routing_ping_package:routing_ping_package,
    routeing_max_peers:routeing_max_peers,
    re_routing_time:re_routing_time,
    active_inips:active_inips,
    sversion:smallest_version,
    version:current_version,
    network:current_network,
    dns_servers:dns_servers,
    is_mainnet:is_mainnet,
    defaults:{
        ip_based_transport_session_default_ttl:ip_based_transport_session_default_ttl,
        tor_based_transport_session_default_ttl:tor_based_transport_session_default_ttl,
        i2p_based_transport_session_default_ttl:i2p_based_transport_session_default_ttl
    },
    socket_paths:{
        unix_socket_none_root_path:unix_socket_none_root_path,
        unix_socket_root_path:unix_socket_root_path
    }
}