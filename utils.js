const ipaddr = require('ipaddr.js');

// Gibt die Einheit der Datengröße aus
function getDataUnit(bdata) {

};

// Gibt an ob es sich um NodeJS auf einem PC handelt
function isNodeOnPCLaptopOrEmbeddedLinuxSystem() {
    if(typeof window === undefined) return false;
    if(typeof process === 'object') return true;
    return false;
};

// Parst eine IP-Adresse
function parsIpAddress(ipStr) {
    let remoteAddress = ipStr;
    if (ipaddr.isValid(remoteAddress)) {
        var addr = ipaddr.parse(remoteAddress);
        if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) remoteAddress = addr.toIPv4Address().toString();
    }
    const ver = ipaddr.parse(remoteAddress).kind();
    return { adr:remoteAddress, ver:ver };
}


module.exports = {
    isNodeOnPCLaptopOrEmbeddedLinuxSystem:isNodeOnPCLaptopOrEmbeddedLinuxSystem,
    parsIpAddress:parsIpAddress,
    getDataUnit:getDataUnit
}