// Gibt die kleins Mögliche Version an
const smallest_version = 10000000;

// Speichert die Aktuelle Version ab
const current_version = 10000000;

// Speichert das Aktuelle Netzwerk ab
const current_network = 'IPN';

// Gibt den Pfad des Unix Sockets für die Root freie API an
const unix_socket_none_root_osx_path = `$TMPDIR/${current_network.toLowerCase()}/none_root_socket`;
const unix_socket_none_root_path = `$TMPDIR/${current_network.toLowerCase()}/none_root_socket`;

// Gibt den Pfad des Unix Sockets für die Root API an
const unix_socket_root_osx_path = `$TMPDIR/${current_network.toLowerCase()}/root_socket`;
const unix_socket_root_path = `$TMPDIR/${current_network.toLowerCase()}/root_socket`;

// Speichert ab, ob es sich um eine Testversion handelt
const is_mainnet = false;

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
    sversion:smallest_version,
    version:current_version,
    network:current_network,
    is_mainnet:is_mainnet,
    bootnode_public_ip_addresses:bootnode_public_ip_addresses,
    bootnode_public_dns_names:bootnode_public_dns_names,
    main_blocked_public_keys:main_blocked_public_keys,
    socket_paths:{
        unix_socket_none_root_osx_path:unix_socket_none_root_osx_path,
        unix_socket_none_root_path:unix_socket_none_root_path,
        unix_socket_root_osx_path:unix_socket_root_osx_path,
        unix_socket_root_path:unix_socket_root_path
    }
}