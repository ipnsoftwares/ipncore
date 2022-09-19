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



const m = require('ip6addr');
const k = m.parse('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
const t = k.toString({ format: k.kind().replace('ip', '') });
console.log(t)
