const moment = require('moment');

// Controls
const Reset = "\x1b[0m";
const Bright = "\x1b[1m";
const Dim = "\x1b[2m";
const Underscore = "\x1b[4m";
const Blink = "\x1b[5m";
const Reverse = "\x1b[7m";
const Hidden = "\x1b[8m";

// Foreground Colors
const FgBlack = "\x1b[30m";
const FgRed = "\x1b[31m";
const FgGreen = "\x1b[32m";
const FgYellow = "\x1b[33m";
const FgBlue = "\x1b[34m";
const FgMagenta = "\x1b[35m";
const FgCyan = "\x1b[36m";
const FgWhite = "\x1b[37m";

// Background Colors
const BgBlack = "\x1b[40m";
const BgRed = "\x1b[41m";
const BgGreen = "\x1b[42m";
const BgYellow = "\x1b[43m";
const BgBlue = "\x1b[44m";
const BgMagenta = "\x1b[45m";
const BgCyan = "\x1b[46m";
const BgWhite = "\x1b[47m";


// Zeigt die Print Meldung an
const dprintok = (level, ...elements) => {
    let prints = [];
    for(const otem of elements) {
        var bonds = '';
        for(const xtem of otem) { bonds += xtem; }
        bonds += `${Reset}`;
        prints.push(bonds);
    }
    const tempTime = moment().format('yyyy-mm-dd:hh:mm:ss');
    console.log(`${FgGreen}${tempTime}${Reset}`, ...prints);
};

// Zeigt eine Fehlermeldung an
const dprinterror = (level, ...elements) => {
    let prints = [];
    for(const otem of elements) {
        var bonds = '';
        for(const xtem of otem) { bonds += xtem; }
        bonds += `${Reset}`;
        prints.push(bonds);
    }
    const tempTime = moment().format('yyyy-mm-dd:hh:mm:ss');
    console.log(`${FgRed}${tempTime}${Reset}`, ...prints);
};

// Zeigt eine Info an
const dprintinfo = (level, ...elements) => {
    let prints = [];
    for(const otem of elements) {
        var bonds = '';
        for(const xtem of otem) { bonds += xtem; }
        bonds += `${Reset}`;
        prints.push(bonds);
    }
    const tempTime = moment().format('yyyy-mm-dd:hh:mm:ss');
    console.log(`${FgCyan}${tempTime}${Reset}`, ...prints);
};

// Zeigt eine Warnung an
const dpwarning = (level, ...elements) => {
    let prints = [];
    for(const otem of elements) {
        var bonds = '';
        for(const xtem of otem) { bonds += xtem; }
        bonds += `${Reset}`;
        prints.push(bonds);
    }
    const tempTime = moment().format('yyyy-mm-dd:hh:mm:ss');
    console.log(`${FgYellow}${tempTime}${Reset}`, ...prints);
};



module.exports = {
    dprintok:dprintok,
    dprinterror:dprinterror,
    dprintinfo:dprintinfo,
    dprintwarning:dpwarning,
    colors: {
        Reset:Reset,
        Bright:Bright,
        Dim:Dim,
        Underscore:Underscore,
        Blink:Blink,
        Reverse:Reverse,
        Hidden:Hidden,
        FgBlack:FgBlack,
        FgRed:FgRed,
        FgGreen:FgGreen,
        FgYellow:FgYellow,
        FgBlue:FgBlue,
        FgMagenta:FgMagenta,
        FgCyan:FgCyan,
        FgWhite:FgWhite,
        BgBlack:BgBlack,
        BgRed:BgRed,
        BgGreen:BgGreen,
        BgYellow:BgYellow,
        BgBlue:BgBlue,
        BgMagenta:BgMagenta,
        BgCyan:BgCyan,
        BgWhite:BgWhite
    }
};
