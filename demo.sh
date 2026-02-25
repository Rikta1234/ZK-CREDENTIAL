#!/bin/bash

echo "=============================="
echo " ZK Collusion Resistance Demo "
echo "=============================="

echo ""
echo "🏦 Generating Bank witness..."
node build/attributeProof_js/generate_witness.js \
build/attributeProof_js/attributeProof.wasm \
bank.json \
build/witness_bank.wtns

echo "🏦 Generating Bank proof..."
snarkjs groth16 prove build/circuit.zkey \
build/witness_bank.wtns \
proof_bank.json public_bank.json

echo "🏦 Verifying Bank proof..."
snarkjs groth16 verify build/verification_key.json \
public_bank.json proof_bank.json


echo ""
echo "🛡 Generating Insurance witness..."
node build/attributeProof_js/generate_witness.js \
build/attributeProof_js/attributeProof.wasm \
insurance.json \
build/witness_insurance.wtns

echo "🛡 Generating Insurance proof..."
snarkjs groth16 prove build/circuit.zkey \
build/witness_insurance.wtns \
proof_insurance.json public_insurance.json

echo "🛡 Verifying Insurance proof..."
snarkjs groth16 verify build/verification_key.json \
public_insurance.json proof_insurance.json


echo ""
echo "🔍 Comparing proofs for unlinkability..."
diff proof_bank.json proof_insurance.json

echo ""
echo "✅ Demo Complete"