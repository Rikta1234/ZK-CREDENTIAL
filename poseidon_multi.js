const circomlibjs = require("circomlibjs");

async function run() {
    const poseidon = await circomlibjs.buildPoseidon();

    const inputs = [10, 12, 3, 1, 5];

    const hash = poseidon(inputs);
    const F = poseidon.F;

    console.log(F.toString(hash));
}

run();