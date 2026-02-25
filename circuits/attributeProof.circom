pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template AttributeProof() {

    // PRIVATE inputs
    signal input x1;
    signal input x2;
    signal input r;

    // PUBLIC inputs
    signal input threshold;
    signal input commitment;

    // reconstruct attribute
    signal x;
    x <== x1 + x2;

    // commitment check
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== x;
    poseidon.inputs[1] <== r;

    commitment === poseidon.out;

    // predicate check
    component gt = GreaterThan(32);
    gt.in[0] <== x;
    gt.in[1] <== threshold;

    signal output valid;
    valid <== gt.out;
}

component main = AttributeProof();