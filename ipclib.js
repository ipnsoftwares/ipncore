const net = require('net'), fs = require('fs'), consensus = require('./consensus');



// Bereitet den Shared Memory für die API auf Systemebene vor
const createSystemSharedMemoryAPI = (callback) => {
    // Es wird geprüft ob es sich um einen Windows oder Unix System handelt
    if (process.platform == 'darwin') {
        console.log("Mac OS");
    }
    else if(process.platform == 'win32'){
        console.log("Window OS")
    }
    else if(process.platform == 'android') {
        console.log("Android OS")
    }
    else if(process.platform == 'linux') {
        console.log("Linux OS")
    }
    else{
        console.log("Other os")
    }

    // Der SharedMemory Server wird gestartet
    let hostAPIEndPoint = net.createServer(function(client) {

    });

    // Wird verwendet um den SharedMemory zu beenden
    const closeSharedMemory = () => {

    };

    // Die Steuerfunktionen werden zurückgegeben
    return { closeSharedMemory:closeSharedMemory };
};



// Die Module werden exportiert
module.exports = {
    createSystemSharedMemoryAPI:createSystemSharedMemoryAPI 
};