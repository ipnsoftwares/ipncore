if (require.main === module) () => {
    const core = require('./core');

    // Es wird geprüft ob es sich um einen Windows, Mac, Linux, oder BSD PC handelt

    // Es wird geprüft ob es sich um eine gültige Architektur handelt

    // Es wird geprüft ob es sich um ein Zulässiges Deviart handelt

    // Die Einstellungen werden geladen
    core.loadDeviceSettings([], true, (configs) => {

    });
}
else {
    // Es handelt sich um eine Library
}



var test = new Map();
test.set('a', new Map());

console.log(test.get('a').get('b'))
test.get('a').set('b', 320);
console.log(test.get('a').get('b'))