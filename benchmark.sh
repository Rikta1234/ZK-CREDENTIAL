#!/bin/bash

echo "=============================="
echo "   ZK Credential Benchmark"
echo "=============================="

echo ""
echo " Witness generation time:"
time node build/attributeProof_js/generate_witness.js \
build/attributeProof_js/attributeProof.wasm \
input.json \
build/witness.wtns

echo ""
echo " Proof generation time:"
time snarkjs groth16 prove \
build/circuit.zkey \
build/witness.wtns \
proof.json \
public.json

echo ""
echo " Verification time:"
time snarkjs groth16 verify \
build/verification_key.json \
public.json \
proof.json

echo ""
echo " Proof size:"
du -h proof.json

echo ""
echo " Witness size:"
du -h build/witness.wtns

echo ""
echo " Benchmark complete"