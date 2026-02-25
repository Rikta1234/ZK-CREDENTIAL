const circomlib = require("circomlibjs");

async function run() {
    const poseidon = await circomlib.buildPoseidon();
    const F = poseidon.F;

    const x1 = 10;
    const x2 = 12;
    const r = 5;

    const x = x1 + x2;

    const hash = poseidon([x, r]);

    console.log(F.toString(hash));
}

run();