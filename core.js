const consensus = require('./consensus');
const os = require('os');



// Wird verwendet um alle Einstellungen, Datenbanken usw auf Geräteebene zu laden
const _LOAD_DEVICE_CORE_SETTINGS_OS_LEVEL = (cmdlineArgs, service, callback) => {

};

// Wird verwendet um alle Einstellungen, Datenbanken usw auf Annwendungsebene zu laden
const _LOAD_DEVICE_CORE_SETTINGS_APP_LEVEL = (configs) => {

};

// Wird verwendet um alle Einstellungen, Datenbanken usw auf Webseiten ebene zu laden
const _LOAD_DEVICE_CORE_SETTINGS_WEBSITE_LEVEL = (configs) => {

};


// Expoert die Funktionen
module.exports = {
    loadAppSettings:_LOAD_DEVICE_CORE_SETTINGS_APP_LEVEL,
    loadDeviceSettings:_LOAD_DEVICE_CORE_SETTINGS_OS_LEVEL,
    loadWebsiteSettings:_LOAD_DEVICE_CORE_SETTINGS_WEBSITE_LEVEL
}