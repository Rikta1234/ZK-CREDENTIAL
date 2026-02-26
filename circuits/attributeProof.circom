pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

template MultiAttributeProof(n) {

    signal input attrs[n];
    signal input r;
    signal input commitment;
    signal input weights[n];
    signal input threshold;

    signal sums[n+1];
    sums[0] <== 0;

    for (var i = 0; i < n; i++) {
        sums[i+1] <== sums[i] + attrs[i] * weights[i];
    }

    signal sum;
    sum <== sums[n];

    component guard1 = Num2Bits(64);
    guard1.in <== sum;

    component guard2 = Num2Bits(64);
    guard2.in <== threshold;

    component cmp = GreaterThan(64);
    cmp.in[0] <== sum;
    cmp.in[1] <== threshold - 1;
    cmp.out === 1;

    component hash = Poseidon(n+1);
    for (var i = 0; i < n; i++) {
        hash.inputs[i] <== attrs[i];
    }
    hash.inputs[n] <== r;

    // keep commented for now
    // hash.out === commitment;
}

component main = MultiAttributeProof(2);
component main = MultiAttributeProof(4);
component main = MultiAttributeProof(8);
   