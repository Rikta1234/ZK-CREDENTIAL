use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use num_bigint::BigUint;


// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

/// Convert a u64 into an ark-bn254 Fr field element.
pub fn u64_to_fr(n: u64) -> Fr {
    Fr::from(n)
}

/// Convert a byte string (e.g. verifier_id) into a single Fr
/// by interpreting its SHA-256 hash as a little-endian integer mod q.
pub fn bytes_to_fr(data: &[u8]) -> Fr {
    let hash = Sha256::digest(data);
    Fr::from_le_bytes_mod_order(&hash)
}

/// Serialise an Fr element to a decimal string (matches circom/snarkjs json format).
pub fn fr_to_decimal(f: &Fr) -> String {
    f.into_bigint().to_string()
}

/// Parse a decimal string back into Fr.
pub fn decimal_to_fr(s: &str) -> Fr {
    let bu = BigUint::from_str(s).unwrap_or_else(|_| panic!("invalid Fr decimal string: {s}"));
    let bytes = bu.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

// ---------------------------------------------------------------------------
// Additive secret sharing in  Fr
// ---------------------------------------------------------------------------

/// Sample x1 ←$ Fr, set x2 = x - x1.
/// Returns (x1, x2)  s.t.  x1 + x2 = x  in Fr.
pub fn generate_shares(x: &Fr) -> (Fr, Fr) {
    let mut rng = rand::thread_rng();
    // sample a random 253-bit integer and reduce mod q
    let r_bytes: [u8; 32] = rng.gen();
    let x1 = Fr::from_le_bytes_mod_order(&r_bytes);
    let x2 = *x - x1;
    (x1, x2)
}

/// Sample a fresh random Fr element (used for blinding / nonce).
pub fn random_fr() -> Fr {
    let mut rng = rand::thread_rng();
    let r_bytes: [u8; 32] = rng.gen();
    Fr::from_le_bytes_mod_order(&r_bytes)
}

// ---------------------------------------------------------------------------
// MiMC helpers (simple implementation for BN254)
// ---------------------------------------------------------------------------







/// Simple MiMC round: (x + key)^7 + x
fn mimc_round(x: Fr, key: Fr) -> Fr {
    let mut y = x + key;
    y = y.pow([7]);
    y + x
}

/// MiMC hash for two inputs: MiMC(MiMC(a, key), b) with key=0
pub fn mimc2(a: &Fr, b: &Fr) -> Fr {
    let key = Fr::from(0u64);
    let mut h = mimc_round(*a, key);
    h = mimc_round(h, *b);
    h
}

/// MiMC hash for three inputs: MiMC(MiMC(MiMC(a, key), b), c) with key=0
pub fn mimc3(a: &Fr, b: &Fr, c: &Fr) -> Fr {
    let key = Fr::from(0u64);
    let mut h = mimc_round(*a, key);
    h = mimc_round(h, *b);
    h = mimc_round(h, *c);
    h
}

// ---------------------------------------------------------------------------
// Public commitment helpers
// ---------------------------------------------------------------------------

/// C_attr = MiMC( x, r )   where x = x1 + x2 in Fr.
pub fn compute_base_commitment(x: &Fr, r: &Fr) -> Fr {
    mimc2(x, r)
}

/// SC_attr = MiMC( C_attr, nonce, verifier_domain )
pub fn compute_session_commitment(c: &Fr, nonce: &Fr, domain: &Fr) -> Fr {
    mimc3(c, nonce, domain)
}

// ---------------------------------------------------------------------------
// Ed25519 signing
// ---------------------------------------------------------------------------

/// Compute the message to sign:  SHA-256( cred_id || C_age || C_income )
pub fn credential_message(cred_id: &str, c_parts: &[&Fr]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(cred_id.as_bytes());
    for c in c_parts {
        h.update(fr_to_decimal(c).as_bytes());
    }
    h.finalize().to_vec()
}

/// Generate a fresh Ed25519 signing keypair.
pub fn generate_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    use rand::rngs::OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Sign a message with an Ed25519 key; return hex string of signature.
pub fn sign_message(sk: &ed25519_dalek::SigningKey, msg: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let sig = sk.sign(msg);
    hex::encode(sig.to_bytes())
}

/// Encode an Ed25519 verifying (public) key as a hex string.
pub fn pk_to_hex(vk: &ed25519_dalek::VerifyingKey) -> String {
    hex::encode(vk.to_bytes())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_reconstruction() {
        let x = u64_to_fr(22);
        let (x1, x2) = generate_shares(&x);
        assert_eq!(x1 + x2, x);
    }

    #[test]
    fn test_commitment_determinism() {
        let x = u64_to_fr(22);
        let r = u64_to_fr(12345);
        let c1 = compute_base_commitment(&x, &r);
        let c2 = compute_base_commitment(&x, &r);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_session_commitment_changes_per_nonce() {
        let c = compute_base_commitment(&u64_to_fr(22), &u64_to_fr(99));
        let domain = bytes_to_fr(b"BANK_A");
        let n1 = u64_to_fr(1111);
        let n2 = u64_to_fr(2222);
        let sc1 = compute_session_commitment(&c, &n1, &domain);
        let sc2 = compute_session_commitment(&c, &n2, &domain);
        assert_ne!(sc1, sc2, "Different nonces must give different session commits");
    }

    #[test]
    fn test_round_trip_decimal() {
        let f = u64_to_fr(600_000);
        let s = fr_to_decimal(&f);
        let f2 = decimal_to_fr(&s);
        assert_eq!(f, f2);
    }

    #[test]
    fn test_signing() {
        let (sk, vk) = generate_keypair();
        let msg = b"hello hackathon";
        let sig_hex = sign_message(&sk, msg);
        assert!(!sig_hex.is_empty());
        // verify the signature bytes parse cleanly
        let sig_bytes = hex::decode(&sig_hex).unwrap();
        assert_eq!(sig_bytes.len(), 64);
        let _ = pk_to_hex(&vk);
    }
}
