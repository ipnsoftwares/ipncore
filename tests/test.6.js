const secp256k1 = require('@vulpemventures/secp256k1-zkp');


(async () => {
    // secp256k1 returns a Promise that must be resolved before using the exported methods
    const ar = await secp256k1();
    console.log('Ts')
    console.log(ar)
})();