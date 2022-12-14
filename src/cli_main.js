#!/usr/bin/env node

const consensus = require('./consensus');
const figlet = require('figlet');


// Main Function
function main() {
    // Es wird geprüft ob der aktuelle Benutzer Root rechte hat

    // Die Sitzung wurde erfolgreich Initalisiert
    figlet('IPN', function(err, data) {
        console.log('IPN');
        if (err) { return; }
    });
}


// Prüft ob es sich um ein Module handelt, wenn nicht wird der Vorgang mit einem Fehler abgebrochen
if (require.main === module) main();