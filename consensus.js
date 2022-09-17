// Speichert die Aktuelle Version ab
const current_version = 10000000;

// Speichert das Aktuelle Netzwerk ab
const current_network = 'IPN';

// Speichert ab, ob es sich um eine Testversion handelt
const is_main_net = false;

// Speichert alle IP-Adressen der Bootnodes
const bootnode_public_ip_addresses = [
];

// Speichert alle DNS-Adressen der Bootnodes
const bootnode_public_dns_names = [   
];

// Speichert alle PublicKeys ab, welche im Mainnet Blockiert werden
const main_blocked_public_keys = [
    Buffer.from('4d1363e238850ff3802e6ade30cc91cf8053769536a6ace6b41f7c0143c2a5fc', 'hex'),
    Buffer.from('cfbfa2a334a8640f8ee91bfa120775ba37e667c06aa2a35ae4b1cd42ec893b0a', 'hex'),
    Buffer.from('97e5364e527ed7625b37f71c35f515a68d506aaf7b202e511a290ded3115419e', 'hex'),
    Buffer.from('a581555d777cf7ee303a52a18212a2a1b7b534e730da50b5901d4f9c53e76bca', 'hex'),
];

// Die Variabeln werden Export
module.exports = {
    version:current_version,
    network:current_network,
    is_main_net:is_main_net,
    bootnode_public_ip_addresses:bootnode_public_ip_addresses,
    bootnode_public_dns_names:bootnode_public_dns_names,
    main_blocked_public_keys:main_blocked_public_keys
}